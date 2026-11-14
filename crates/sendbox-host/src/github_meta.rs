//! Machine-wide cache for the official GitHub Meta document.
//!
//! Every `github.com`-delegating session needs one validated Meta response.
//! Fetching it per session and per gateway exhausted GitHub's anonymous limit
//! of 60 requests per hour per IP address. Sessions sharing a runtime state
//! root now reuse one file-locked cache: at most one conditional request per
//! refresh interval, failure backoff, and bounded last-good reuse.

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use sendbox_egress::github_meta::{
    GitHubMetaError, GitHubMetaResponse, GitHubMetaScope, GitHubMetaSeed, MAX_SEED_BYTES,
    META_MAX_CLOCK_SKEW, META_REFRESH_INTERVAL, META_REQUEST_TIMEOUT, unix_now,
};
use sendbox_egress::github_meta_client::fetch_official_github_meta;
use sendbox_egress::runtime::RuntimePolicyDocument;
use sendbox_security::fs::{ExclusiveLock, PRIVATE_FILE_MODE, SecureRoot};
use serde::{Deserialize, Serialize};

use crate::HostError;

const CACHE_FILE: &str = "github-meta.json";
const LOCK_FILE: &str = "github-meta.lock";
const CACHE_SCHEMA_VERSION: u32 = 1;
const MAX_CACHE_BYTES: u64 = MAX_SEED_BYTES as u64 + 4096;
const FAILURE_BACKOFF_SECS: u64 = 60;
const MAX_RATE_LIMIT_BACKOFF_SECS: u64 = 60 * 60;
/// A reused last-good seed must outlive guest boot plus one bounded execution.
const MIN_FALLBACK_VALIDITY: Duration = Duration::from_secs(15 * 60);
const LOCK_WAIT: Duration = Duration::from_secs(3 * META_REQUEST_TIMEOUT.as_secs());
const LOCK_POLL: Duration = Duration::from_millis(100);

/// `document` is always stored as freshly validated; the file-level attempt
/// and error describe the latest refresh and are overlaid onto issued seeds.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheFile {
    schema_version: u32,
    document: Option<GitHubMetaSeed>,
    last_attempt_unix_seconds: u64,
    last_error: Option<GitHubMetaError>,
}

impl CacheFile {
    fn seed(&self) -> Option<GitHubMetaSeed> {
        self.document.clone().map(|mut seed| {
            seed.last_attempt_unix_seconds = self.last_attempt_unix_seconds;
            seed.last_error.clone_from(&self.last_error);
            seed
        })
    }

    fn fresh(&self, now: u64) -> bool {
        self.document.as_ref().is_some_and(|document| {
            document.validated_unix_seconds <= now.saturating_add(META_MAX_CLOCK_SKEW.as_secs())
                && now.saturating_sub(document.validated_unix_seconds)
                    < META_REFRESH_INTERVAL.as_secs()
        })
    }

    fn retry_at(&self) -> Option<u64> {
        let backoff = self
            .last_attempt_unix_seconds
            .saturating_add(FAILURE_BACKOFF_SECS);
        match self.last_error.as_ref()? {
            GitHubMetaError::RateLimited {
                reset_unix_seconds: Some(reset),
            } => Some(
                (*reset).clamp(
                    backoff,
                    self.last_attempt_unix_seconds
                        .saturating_add(MAX_RATE_LIMIT_BACKOFF_SECS),
                ),
            ),
            _ => Some(backoff),
        }
    }
}

/// Returns the seed a session's gateways need, or `None` when its egress
/// policy does not delegate to GitHub Meta.
pub(crate) async fn session_seed(
    egress: Option<&RuntimePolicyDocument>,
    state_root: &Path,
) -> Result<Option<GitHubMetaSeed>, HostError> {
    let Some(policy) = egress else {
        return Ok(None);
    };
    let invalid =
        |error: sendbox_egress::policy::PolicyError| HostError::Invalid(error.to_string());
    if !policy.github_meta_enabled().map_err(invalid)? {
        return Ok(None);
    }
    if !policy.github_meta_source_permitted().map_err(invalid)? {
        return Err(GitHubMetaError::PolicyDenied.into());
    }
    obtain_seed(state_root, |etag| async move {
        fetch_official_github_meta(etag.as_deref()).await
    })
    .await
    .map(Some)
}

async fn obtain_seed<F, Fut>(state_root: &Path, fetch: F) -> Result<GitHubMetaSeed, HostError>
where
    F: FnOnce(Option<String>) -> Fut,
    Fut: Future<Output = Result<GitHubMetaResponse, GitHubMetaError>>,
{
    let root = SecureRoot::open(state_root)?;
    let _lock = lock(&root).await?;
    let now = unix_now()?;
    let mut cache = read_cache(&root, now).unwrap_or(CacheFile {
        schema_version: CACHE_SCHEMA_VERSION,
        document: None,
        last_attempt_unix_seconds: 0,
        last_error: None,
    });
    if cache.fresh(now) {
        return Ok(cache.seed().expect("a fresh cache has a document"));
    }
    if let Some(error) = &cache.last_error
        && cache.retry_at().is_some_and(|retry_at| now < retry_at)
    {
        return fallback(&cache, now, error.clone());
    }
    let etag = cache
        .document
        .as_ref()
        .and_then(|document| document.etag.clone());
    let outcome = fetch(etag)
        .await
        .and_then(|response| accept(response, cache.document.as_ref(), now));
    cache.last_attempt_unix_seconds = now;
    match outcome {
        Ok(document) => {
            cache.document = Some(document);
            cache.last_error = None;
            persist(&root, &cache);
            Ok(cache.seed().expect("a refreshed cache has a document"))
        }
        Err(error) => {
            cache.last_error = Some(error.clone());
            persist(&root, &cache);
            fallback(&cache, now, error)
        }
    }
}

async fn lock(root: &SecureRoot) -> Result<ExclusiveLock, HostError> {
    let deadline = tokio::time::Instant::now() + LOCK_WAIT;
    loop {
        if let Some(lock) = root.try_lock_exclusive(LOCK_FILE)? {
            return Ok(lock);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(HostError::Invalid(format!(
                "another SendBox process held the GitHub Meta cache lock for {}s",
                LOCK_WAIT.as_secs()
            )));
        }
        tokio::time::sleep(LOCK_POLL).await;
    }
}

fn accept(
    response: GitHubMetaResponse,
    previous: Option<&GitHubMetaSeed>,
    now: u64,
) -> Result<GitHubMetaSeed, GitHubMetaError> {
    let document = match response {
        GitHubMetaResponse::Modified { body, etag } => GitHubMetaSeed {
            body,
            etag,
            validated_unix_seconds: now,
            last_attempt_unix_seconds: now,
            last_error: None,
        },
        GitHubMetaResponse::NotModified => GitHubMetaSeed {
            validated_unix_seconds: now,
            last_attempt_unix_seconds: now,
            last_error: None,
            ..previous
                .cloned()
                .ok_or(GitHubMetaError::UnexpectedNotModified)?
        },
    };
    document.validate(now)?;
    Ok(document)
}

fn fallback(
    cache: &CacheFile,
    now: u64,
    error: GitHubMetaError,
) -> Result<GitHubMetaSeed, HostError> {
    let Some(seed) = cache.seed().filter(|seed| {
        seed.remaining_validity(now)
            .is_ok_and(|remaining| remaining >= MIN_FALLBACK_VALIDITY)
    }) else {
        return Err(error.into());
    };
    eprintln!(
        "sendbox: GitHub Meta refresh failed ({error}); reusing the shared copy validated {} minutes ago",
        now.saturating_sub(seed.validated_unix_seconds) / 60
    );
    Ok(seed)
}

fn read_cache(root: &SecureRoot, now: u64) -> Option<CacheFile> {
    let bytes = match root.read_bounded(CACHE_FILE, MAX_CACHE_BYTES) {
        Ok(bytes) => bytes,
        Err(sendbox_security::SecurityError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return None;
        }
        Err(error) => {
            eprintln!("sendbox: ignoring unreadable GitHub Meta cache: {error}");
            return None;
        }
    };
    let mut cache = match serde_json::from_slice::<CacheFile>(&bytes) {
        Ok(cache) if cache.schema_version == CACHE_SCHEMA_VERSION => cache,
        Ok(_) | Err(_) => {
            eprintln!("sendbox: ignoring an invalid GitHub Meta cache");
            return None;
        }
    };
    // A tampered or truncated document must never become a grant; keep only
    // whole documents, even when they are too old to reuse.
    if cache.document.as_ref().is_some_and(|document| {
        GitHubMetaScope::parse(&document.body).is_err()
            || document.validated_unix_seconds > now.saturating_add(META_MAX_CLOCK_SKEW.as_secs())
    }) {
        eprintln!("sendbox: discarding an invalid cached GitHub Meta document");
        cache.document = None;
    }
    Some(cache)
}

fn persist(root: &SecureRoot, cache: &CacheFile) {
    let result = serde_json::to_vec(cache)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            root.write_atomic(CACHE_FILE, &bytes, MAX_CACHE_BYTES, PRIVATE_FILE_MODE)
                .map_err(|error| error.to_string())
        });
    if let Err(error) = result {
        eprintln!("sendbox: updating the shared GitHub Meta cache failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn document(website: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "verifiable_password_authentication": false,
            "web": ["203.0.113.0/24"], "api": ["2001:db8::/32"], "git": ["203.0.113.1"],
            "domains": {"website": [website]}
        }))
        .unwrap()
    }

    fn modified(website: &str, etag: &str) -> Result<GitHubMetaResponse, GitHubMetaError> {
        Ok(GitHubMetaResponse::Modified {
            body: document(website),
            etag: Some(etag.to_owned()),
        })
    }

    async fn never(_: Option<String>) -> Result<GitHubMetaResponse, GitHubMetaError> {
        panic!("the shared cache must not contact GitHub here")
    }

    fn age_cache(root: &Path, validated_ago: u64) {
        let path = root.join(CACHE_FILE);
        let mut cache: CacheFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let validated = unix_now().unwrap() - validated_ago;
        let document = cache.document.as_mut().unwrap();
        document.validated_unix_seconds = validated;
        document.last_attempt_unix_seconds = validated;
        cache.last_attempt_unix_seconds = validated;
        std::fs::write(&path, serde_json::to_vec(&cache).unwrap()).unwrap();
    }

    #[tokio::test]
    async fn sessions_share_one_fetch_per_refresh_interval_and_revalidate_by_etag() {
        let root = tempfile::tempdir().unwrap();
        let first = obtain_seed(root.path(), |etag| async move {
            assert_eq!(etag, None);
            modified("one.github.test", "\"v1\"")
        })
        .await
        .unwrap();
        for _ in 0..3 {
            assert_eq!(obtain_seed(root.path(), never).await.unwrap(), first);
        }
        assert_eq!(
            std::fs::metadata(root.path().join(CACHE_FILE))
                .map(
                    |metadata| std::os::unix::fs::PermissionsExt::mode(&metadata.permissions())
                        & 0o777
                )
                .unwrap(),
            0o600
        );

        age_cache(root.path(), META_REFRESH_INTERVAL.as_secs());
        let revalidated = obtain_seed(root.path(), |etag| async move {
            assert_eq!(etag.as_deref(), Some("\"v1\""));
            Ok(GitHubMetaResponse::NotModified)
        })
        .await
        .unwrap();
        assert_eq!(revalidated.body, first.body);
        assert!(revalidated.validated_unix_seconds >= first.validated_unix_seconds);
        assert!(revalidated.last_error.is_none());
    }

    #[tokio::test]
    async fn rate_limited_refresh_reuses_last_good_and_backs_off_until_reset() {
        let root = tempfile::tempdir().unwrap();
        obtain_seed(root.path(), |_| async {
            modified("one.github.test", "\"v1\"")
        })
        .await
        .unwrap();
        age_cache(root.path(), 2 * META_REFRESH_INTERVAL.as_secs());
        let reset = unix_now().unwrap() + 600;
        let limited = GitHubMetaError::RateLimited {
            reset_unix_seconds: Some(reset),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let error = limited.clone();
        let degraded = obtain_seed(root.path(), move |_| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err(error)
        })
        .await
        .unwrap();
        assert_eq!(degraded.last_error, Some(limited));
        assert!(GitHubMetaScope::parse(&degraded.body).is_ok());
        assert_eq!(obtain_seed(root.path(), never).await.unwrap(), degraded);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn without_a_usable_last_good_the_failure_is_surfaced_and_backed_off() {
        let root = tempfile::tempdir().unwrap();
        let limited = GitHubMetaError::RateLimited {
            reset_unix_seconds: None,
        };
        let error = limited.clone();
        let failure = obtain_seed(root.path(), move |_| async move { Err(error) })
            .await
            .unwrap_err();
        assert!(matches!(&failure, HostError::GitHubMeta(error) if *error == limited));
        assert!(matches!(
            obtain_seed(root.path(), never).await,
            Err(HostError::GitHubMeta(error)) if error == limited
        ));

        let root = tempfile::tempdir().unwrap();
        obtain_seed(root.path(), |_| async {
            modified("one.github.test", "\"v1\"")
        })
        .await
        .unwrap();
        let nearly_expired =
            sendbox_egress::github_meta::META_MAX_STALENESS - MIN_FALLBACK_VALIDITY / 2;
        age_cache(root.path(), nearly_expired.as_secs());
        assert!(matches!(
            obtain_seed(root.path(), |_| async {
                Err(GitHubMetaError::HttpStatus(503))
            })
            .await,
            Err(HostError::GitHubMeta(GitHubMetaError::HttpStatus(503)))
        ));
    }

    #[tokio::test]
    async fn invalid_or_tampered_documents_never_become_seeds() {
        let root = tempfile::tempdir().unwrap();
        let malformed = obtain_seed(root.path(), |_| async {
            Ok(GitHubMetaResponse::Modified {
                body: b"{malformed".to_vec(),
                etag: None,
            })
        })
        .await;
        assert!(matches!(
            malformed,
            Err(HostError::GitHubMeta(GitHubMetaError::InvalidDocument(_)))
        ));
        assert!(matches!(
            obtain_seed(root.path(), |_| async {
                Ok(GitHubMetaResponse::NotModified)
            })
            .await,
            Err(HostError::GitHubMeta(GitHubMetaError::InvalidDocument(_)))
        ));

        let root = tempfile::tempdir().unwrap();
        obtain_seed(root.path(), |_| async {
            modified("one.github.test", "\"v1\"")
        })
        .await
        .unwrap();
        let path = root.path().join(CACHE_FILE);
        let mut cache: CacheFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        cache.document.as_mut().unwrap().body = b"{\"tampered\":true}".to_vec();
        std::fs::write(&path, serde_json::to_vec(&cache).unwrap()).unwrap();
        let refetched = obtain_seed(root.path(), |etag| async move {
            assert_eq!(etag, None);
            modified("two.github.test", "\"v2\"")
        })
        .await
        .unwrap();
        assert_eq!(refetched.body, document("two.github.test"));
    }
}
