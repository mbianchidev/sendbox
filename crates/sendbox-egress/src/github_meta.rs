//! Validated, expiring destination grants from GitHub's official Meta API.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditEvent, AuditSink};
use crate::domain;
use crate::policy::PolicyEngine;

pub const GITHUB_META_URL: &str = "https://api.github.com/meta";
pub const GITHUB_META_API_VERSION: &str = "2022-11-28";
pub const MAX_META_BYTES: usize = 2 * 1024 * 1024;
pub const META_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub const META_MAX_STALENESS: Duration = Duration::from_secs(24 * 60 * 60);
pub const META_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NETWORK_ENTRIES: usize = 16_384;
const MAX_DOMAIN_ENTRIES: usize = 4096;

// The documented destination fields, plus shared_ingress published by the API.
// Unknown fields fail validation instead of silently omitting new destinations
// or mistaking a future key/identity field for a network grant.
const NETWORK_FIELDS: &[&str] = &[
    "hooks",
    "web",
    "shared_ingress",
    "api",
    "git",
    "github_enterprise_importer",
    "packages",
    "pages",
    "importer",
    "actions",
    "actions_macos",
    "codespaces",
    "dependabot",
    "copilot",
];
const DOMAIN_FIELDS: &[&str] = &[
    "website",
    "codespaces",
    "copilot",
    "packages",
    "storage",
    "actions",
];

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum GitHubMetaError {
    #[error("GitHub Meta response exceeds its byte or entry limit")]
    LimitExceeded,
    #[error("invalid GitHub Meta document: {0}")]
    InvalidDocument(&'static str),
    #[error("GitHub Meta contains an invalid or unrestricted IP/CIDR")]
    InvalidNetwork,
    #[error("GitHub Meta contains an invalid domain pattern")]
    InvalidDomain,
    #[error("GitHub Meta returned 304 without a validated cached response")]
    UnexpectedNotModified,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("GitHub Meta HTTP request failed with status {0}")]
    HttpStatus(u16),
    #[error("GitHub Meta refresh timed out")]
    Timeout,
    #[error("GitHub Meta refresh is denied by network policy")]
    PolicyDenied,
    #[error("GitHub Meta DNS resolution failed")]
    Resolution,
    #[error("GitHub Meta transport failed during {0}")]
    Transport(&'static str),
    #[error("GitHub Meta TLS roots are unavailable or invalid")]
    TlsRoots,
    #[error("GitHub Meta response has invalid headers or framing")]
    InvalidResponse,
    #[error("GitHub Meta provenance publication failed")]
    Publication,
    #[error("GitHub Meta refresh is already in progress")]
    RefreshInProgress,
}

#[derive(Debug, Clone)]
pub struct GitHubMetaScope {
    pub domains: Vec<String>,
    pub networks: Vec<IpNet>,
    pub sha256: String,
}

impl GitHubMetaScope {
    pub fn parse(bytes: &[u8]) -> Result<Self, GitHubMetaError> {
        if bytes.len() > MAX_META_BYTES {
            return Err(GitHubMetaError::LimitExceeded);
        }
        let document: Value = serde_json::from_slice(bytes)
            .map_err(|_| GitHubMetaError::InvalidDocument("expected JSON"))?;
        let object = document
            .as_object()
            .ok_or(GitHubMetaError::InvalidDocument("expected an object"))?;
        if !object
            .get("verifiable_password_authentication")
            .is_some_and(Value::is_boolean)
        {
            return Err(GitHubMetaError::InvalidDocument(
                "missing authentication metadata",
            ));
        }
        let mut networks = BTreeSet::new();
        let mut network_count = 0;
        for (field, value) in object {
            if NETWORK_FIELDS.contains(&field.as_str()) {
                for literal in strings(value)? {
                    network_count += 1;
                    if network_count > MAX_NETWORK_ENTRIES {
                        return Err(GitHubMetaError::LimitExceeded);
                    }
                    let network = literal
                        .parse::<IpNet>()
                        .or_else(|_| literal.parse::<IpAddr>().map(IpNet::from))
                        .map_err(|_| GitHubMetaError::InvalidNetwork)?;
                    if network.prefix_len() == 0 {
                        return Err(GitHubMetaError::InvalidNetwork);
                    }
                    networks.insert(network.trunc());
                }
            } else if !matches!(
                field.as_str(),
                "domains"
                    | "verifiable_password_authentication"
                    | "ssh_keys"
                    | "ssh_key_fingerprints"
                    | "commit_signing_keys"
            ) {
                return Err(GitHubMetaError::InvalidDocument(
                    "unrecognized top-level field",
                ));
            }
        }
        for required in ["web", "api", "git"] {
            if object
                .get(required)
                .and_then(Value::as_array)
                .is_none_or(|values| values.is_empty())
            {
                return Err(GitHubMetaError::InvalidDocument(
                    "missing core network field",
                ));
            }
        }
        let published_domains = object
            .get("domains")
            .and_then(Value::as_object)
            .ok_or(GitHubMetaError::InvalidDocument("missing domains object"))?;
        let mut domains = BTreeSet::new();
        let mut domain_count = 0;
        let mut add_domains = |value: &Value| -> Result<(), GitHubMetaError> {
            for name in strings(value)? {
                domain_count += 1;
                if domain_count > MAX_DOMAIN_ENTRIES {
                    return Err(GitHubMetaError::LimitExceeded);
                }
                let pattern =
                    domain::normalize_pattern(name).map_err(|_| GitHubMetaError::InvalidDomain)?;
                if pattern.parse::<IpAddr>().is_ok() {
                    return Err(GitHubMetaError::InvalidDomain);
                }
                domains.insert(pattern);
            }
            Ok(())
        };
        for (field, value) in published_domains {
            if DOMAIN_FIELDS.contains(&field.as_str()) {
                add_domains(value)?;
            } else {
                if !matches!(field.as_str(), "actions_inbound" | "artifact_attestations") {
                    return Err(GitHubMetaError::InvalidDocument(
                        "unrecognized domain field",
                    ));
                }
                let nested = value.as_object().ok_or(GitHubMetaError::InvalidDocument(
                    "expected a nested domain object",
                ))?;
                for (key, value) in nested {
                    match (field.as_str(), key.as_str()) {
                        ("actions_inbound", "full_domains" | "wildcard_domains")
                        | ("artifact_attestations", "services") => add_domains(value)?,
                        ("artifact_attestations", "trust_domain") if value.is_string() => {}
                        _ => {
                            return Err(GitHubMetaError::InvalidDocument(
                                "unrecognized domain field",
                            ));
                        }
                    }
                }
            }
        }
        if networks.is_empty() || domains.is_empty() {
            return Err(GitHubMetaError::InvalidDocument("empty destination scope"));
        }
        Ok(Self {
            domains: domains.into_iter().collect(),
            networks: networks.into_iter().collect(),
            sha256: Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        })
    }
}

fn strings(value: &Value) -> Result<Vec<&str>, GitHubMetaError> {
    let values = value.as_array().ok_or(GitHubMetaError::InvalidDocument(
        "expected a destination array",
    ))?;
    if values.len() > MAX_NETWORK_ENTRIES {
        return Err(GitHubMetaError::LimitExceeded);
    }
    values
        .iter()
        .map(|value| {
            value.as_str().ok_or(GitHubMetaError::InvalidDocument(
                "destination entries must be strings",
            ))
        })
        .collect()
}

pub enum GitHubMetaResponse {
    Modified { body: Vec<u8>, etag: Option<String> },
    NotModified,
}

/// Trusted control-plane transport. Production always uses the fixed official
/// HTTPS client; injection lets embedders and tests keep the same owner and
/// refresh semantics without doing network I/O in policy compilation.
#[async_trait::async_trait]
pub trait GitHubMetaClient: Send + Sync {
    async fn fetch(
        &self,
        policy: &PolicyEngine,
        etag: Option<&str>,
    ) -> Result<GitHubMetaResponse, GitHubMetaError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubMetaState {
    Pending,
    Fresh,
    Degraded,
    Unavailable,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitHubMetaPublishedScope {
    pub sha256: String,
    pub domains: Vec<String>,
    pub networks: Vec<String>,
}

/// Published grants are subject to the configured deny, address, port, DNS,
/// origin-reservation and transport controls. An expired scope is diagnostic
/// evidence only, never an effective grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitHubMetaStatus {
    pub source: &'static str,
    pub api_version: &'static str,
    pub state: GitHubMetaState,
    pub grants_active: bool,
    pub revision: u64,
    pub refresh_interval_seconds: u64,
    pub max_staleness_seconds: u64,
    pub last_attempt_unix_seconds: Option<u64>,
    pub last_success_unix_seconds: Option<u64>,
    pub expires_unix_seconds: Option<u64>,
    pub etag: Option<String>,
    pub last_error: Option<GitHubMetaError>,
    pub published_scope: Option<GitHubMetaPublishedScope>,
}

#[derive(Clone)]
struct Snapshot {
    scope: Arc<GitHubMetaScope>,
    validated_at: Instant,
    validated_unix_seconds: u64,
    etag: Option<String>,
}

#[derive(Clone, Default)]
struct State {
    snapshot: Option<Snapshot>,
    revision: u64,
    last_attempt_unix_seconds: Option<u64>,
    last_error: Option<GitHubMetaError>,
}

#[derive(Default)]
pub struct GitHubMeta {
    state: RwLock<State>,
    refresh: tokio::sync::Mutex<()>,
}

impl GitHubMeta {
    pub(crate) fn clear(&self) {
        let mut state = self.state.write().expect("GitHub Meta state poisoned");
        state.snapshot = None;
        state.last_attempt_unix_seconds = None;
        state.last_error = None;
    }

    pub async fn refresh_once(
        &self,
        client: &dyn GitHubMetaClient,
        policy: &PolicyEngine,
        audit: &dyn AuditSink,
    ) -> Result<(), GitHubMetaError> {
        let _refresh = self
            .refresh
            .try_lock()
            .map_err(|_| GitHubMetaError::RefreshInProgress)?;
        let etag = self
            .state
            .read()
            .expect("GitHub Meta state poisoned")
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.etag.clone());
        let response =
            tokio::time::timeout(META_REQUEST_TIMEOUT, client.fetch(policy, etag.as_deref()))
                .await
                .map_err(|_| GitHubMetaError::Timeout)
                .and_then(|response| response)
                .and_then(|response| self.prepare_response(response));
        if let Err(error) = &response {
            let mut state = self.state.write().expect("GitHub Meta state poisoned");
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(time) => {
                    state.last_attempt_unix_seconds = Some(time.as_secs());
                    state.last_error = Some(error.clone());
                }
                Err(_) => {
                    state.last_attempt_unix_seconds = None;
                    state.last_error = Some(GitHubMetaError::Clock);
                }
            }
        }
        let status = match &response {
            Ok(candidate) => Self::describe(candidate),
            Err(_) => self.status(),
        };
        if let Err(error) = audit.record_github_meta(status) {
            eprintln!("sendbox: publishing GitHub Meta provenance failed: {error}");
            self.clear();
            self.state
                .write()
                .expect("GitHub Meta state poisoned")
                .last_error = Some(GitHubMetaError::Publication);
            audit.record(AuditEvent::GitHubMeta {
                status: Box::new(self.status()),
            });
            return Err(GitHubMetaError::Publication);
        }
        let candidate = response?;
        *self.state.write().expect("GitHub Meta state poisoned") = candidate;
        Ok(())
    }

    pub fn status(&self) -> GitHubMetaStatus {
        let state = self.state.read().expect("GitHub Meta state poisoned");
        Self::describe(&state)
    }

    fn describe(state: &State) -> GitHubMetaStatus {
        let active = state
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.validated_at.elapsed() < META_MAX_STALENESS);
        let health = match (&state.snapshot, active, state.last_error.is_some()) {
            (None, _, false) => GitHubMetaState::Pending,
            (None, _, true) => GitHubMetaState::Unavailable,
            (Some(_), false, _) => GitHubMetaState::Expired,
            (Some(_), true, false) => GitHubMetaState::Fresh,
            (Some(_), true, true) => GitHubMetaState::Degraded,
        };
        GitHubMetaStatus {
            source: GITHUB_META_URL,
            api_version: GITHUB_META_API_VERSION,
            state: health,
            grants_active: active,
            revision: state.revision,
            refresh_interval_seconds: META_REFRESH_INTERVAL.as_secs(),
            max_staleness_seconds: META_MAX_STALENESS.as_secs(),
            last_attempt_unix_seconds: state.last_attempt_unix_seconds,
            last_success_unix_seconds: state.snapshot.as_ref().map(|s| s.validated_unix_seconds),
            expires_unix_seconds: state
                .snapshot
                .as_ref()
                .map(|s| s.validated_unix_seconds + META_MAX_STALENESS.as_secs()),
            etag: state.snapshot.as_ref().and_then(|s| s.etag.clone()),
            last_error: state.last_error.clone(),
            published_scope: state.snapshot.as_ref().map(|s| GitHubMetaPublishedScope {
                sha256: s.scope.sha256.clone(),
                domains: s.scope.domains.clone(),
                networks: s.scope.networks.iter().map(ToString::to_string).collect(),
            }),
        }
    }

    pub(crate) fn view(&self) -> (u64, Option<Arc<GitHubMetaScope>>) {
        let state = self.state.read().expect("GitHub Meta state poisoned");
        match &state.snapshot {
            Some(snapshot) if snapshot.validated_at.elapsed() < META_MAX_STALENESS => {
                (state.revision, Some(Arc::clone(&snapshot.scope)))
            }
            _ => (0, None),
        }
    }

    #[cfg(test)]
    pub(crate) fn install_response(
        &self,
        response: GitHubMetaResponse,
    ) -> Result<(), GitHubMetaError> {
        let candidate = self.prepare_response(response)?;
        *self.state.write().expect("GitHub Meta state poisoned") = candidate;
        Ok(())
    }

    fn prepare_response(&self, response: GitHubMetaResponse) -> Result<State, GitHubMetaError> {
        let parsed = match response {
            GitHubMetaResponse::Modified { body, etag } => {
                if etag.as_ref().is_some_and(|etag| !valid_etag(etag)) {
                    return Err(GitHubMetaError::InvalidResponse);
                }
                Some((Arc::new(GitHubMetaScope::parse(&body)?), etag))
            }
            GitHubMetaResponse::NotModified => None,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GitHubMetaError::Clock)?
            .as_secs();
        let mut state = self
            .state
            .read()
            .expect("GitHub Meta state poisoned")
            .clone();
        let revision = state
            .revision
            .checked_add(1)
            .ok_or(GitHubMetaError::LimitExceeded)?;
        let (scope, etag) = match parsed {
            Some(parsed) => parsed,
            None => {
                let previous = state
                    .snapshot
                    .as_ref()
                    .filter(|snapshot| snapshot.etag.is_some())
                    .ok_or(GitHubMetaError::UnexpectedNotModified)?;
                (Arc::clone(&previous.scope), previous.etag.clone())
            }
        };
        state.snapshot = Some(Snapshot {
            scope,
            validated_at: Instant::now(),
            validated_unix_seconds: now,
            etag,
        });
        state.revision = revision;
        state.last_attempt_unix_seconds = Some(now);
        state.last_error = None;
        Ok(state)
    }
}

pub(crate) fn valid_etag(etag: &str) -> bool {
    let opaque = etag.strip_prefix("W/").unwrap_or(etag);
    etag.len() <= 512
        && opaque
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .is_some_and(|value| {
                value
                    .bytes()
                    .all(|byte| byte == 0x21 || (0x23..=0x7e).contains(&byte))
            })
}

/// Owned by the gateway alongside its brokers, with no detached task or disk
/// cache. Expiry is also checked on every policy view, not just on this timer.
pub(crate) async fn run_refresh(
    engine: Arc<PolicyEngine>,
    client: Arc<dyn GitHubMetaClient>,
    audit: Arc<dyn AuditSink>,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let metadata = engine
        .github_meta()
        .expect("refresh requires a GitHub grant");
    let mut timer = tokio::time::interval_at(
        Instant::now() + META_REFRESH_INTERVAL,
        META_REFRESH_INTERVAL,
    );
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            _ = timer.tick() => {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => return Ok(()),
                    result = metadata.refresh_once(client.as_ref(), &engine, audit.as_ref()) => {
                        if result == Err(GitHubMetaError::Publication) {
                            return Err(std::io::Error::other(GitHubMetaError::Publication));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "verifiable_password_authentication": false,
            "ssh_keys": ["not-a-destination.invalid"],
            "commit_signing_keys": ["also-not-a-destination.invalid"],
            "web": ["203.0.113.0/24"],
            "api": ["2001:db8:1234::/48"],
            "git": ["203.0.113.1"],
            "shared_ingress": ["203.0.113.2/32"],
            "domains": {
                "website": ["*.github.test", "assets.github.test"],
                "actions_inbound": {
                    "full_domains": ["runner.github.test"],
                    "wildcard_domains": ["*.storage.test"]
                },
                "artifact_attestations": {
                    "trust_domain": "identity-not-a-destination.invalid",
                    "services": ["signing.github.test"]
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn parses_only_published_network_and_endpoint_fields() {
        let scope = GitHubMetaScope::parse(&fixture()).unwrap();
        assert_eq!(
            scope.domains,
            [
                "*.github.test",
                "*.storage.test",
                "assets.github.test",
                "runner.github.test",
                "signing.github.test"
            ]
        );
        assert_eq!(scope.networks.len(), 4);
        assert!(
            scope
                .networks
                .contains(&"2001:db8:1234::/48".parse().unwrap())
        );
        assert!(scope.networks.contains(&"203.0.113.1/32".parse().unwrap()));
    }

    #[test]
    fn rejects_unknown_fields_even_when_empty() {
        let mut document: Value = serde_json::from_slice(&fixture()).unwrap();
        document["domains"]["future_destinations"] = serde_json::json!({});
        assert!(GitHubMetaScope::parse(&serde_json::to_vec(&document).unwrap()).is_err());
    }

    #[test]
    fn rejects_invalid_conditional_validator_without_installing_a_scope() {
        let metadata = GitHubMeta::default();
        for etag in ["", "unquoted", "\"embedded\"quote\"", "\"line\r\nbreak\""] {
            assert_eq!(
                metadata.install_response(GitHubMetaResponse::Modified {
                    body: fixture(),
                    etag: Some(etag.to_owned()),
                }),
                Err(GitHubMetaError::InvalidResponse)
            );
            assert!(!metadata.status().grants_active);
        }
    }

    #[test]
    fn rejects_malformed_unbounded_and_incomplete_destination_scopes() {
        for (path, value) in [
            ("/web", serde_json::json!(["0.0.0.0/0"])),
            ("/api", serde_json::json!(["::/0"])),
            ("/git", serde_json::json!(["not-a-cidr"])),
            ("/web", serde_json::json!([])),
            (
                "/domains/website",
                serde_json::json!(["https://unrelated.test/path"]),
            ),
            ("/domains/website", serde_json::json!(["*.*.test"])),
            ("/domains/website", serde_json::json!(["*.test.."])),
            ("/domains/website", serde_json::json!([123])),
        ] {
            let mut document: Value = serde_json::from_slice(&fixture()).unwrap();
            *document.pointer_mut(path).unwrap() = value;
            assert!(
                GitHubMetaScope::parse(&serde_json::to_vec(&document).unwrap()).is_err(),
                "{path}"
            );
        }
        assert!(matches!(
            GitHubMetaScope::parse(&vec![b' '; MAX_META_BYTES + 1]),
            Err(GitHubMetaError::LimitExceeded)
        ));
        let mut document: Value = serde_json::from_slice(&fixture()).unwrap();
        document["actions"] = serde_json::json!(vec!["203.0.113.1"; MAX_NETWORK_ENTRIES + 1]);
        assert!(matches!(
            GitHubMetaScope::parse(&serde_json::to_vec(&document).unwrap()),
            Err(GitHubMetaError::LimitExceeded)
        ));
        let mut document: Value = serde_json::from_slice(&fixture()).unwrap();
        document["domains"]["website"] =
            serde_json::json!(vec!["fixture.test"; MAX_DOMAIN_ENTRIES + 1]);
        assert!(matches!(
            GitHubMetaScope::parse(&serde_json::to_vec(&document).unwrap()),
            Err(GitHubMetaError::LimitExceeded)
        ));
    }

    fn engine() -> Arc<PolicyEngine> {
        Arc::new(
            PolicyEngine::compile(
                &serde_json::from_value(serde_json::json!({
                    "default_action": "deny", "allowed_domains": ["github.com"],
                    "blocked_domains": [], "allow_dns": true
                }))
                .unwrap(),
            )
            .unwrap(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn conditional_revalidation_renews_only_a_previously_valid_snapshot() {
        let engine = engine();
        let metadata = engine.github_meta().unwrap();
        assert_eq!(
            metadata.install_response(GitHubMetaResponse::NotModified),
            Err(GitHubMetaError::UnexpectedNotModified)
        );
        metadata
            .install_response(GitHubMetaResponse::Modified {
                body: fixture(),
                etag: Some("\"fixture\"".to_owned()),
            })
            .unwrap();
        let previous = metadata.status();
        tokio::time::advance(META_MAX_STALENESS / 2).await;
        metadata
            .install_response(GitHubMetaResponse::NotModified)
            .unwrap();
        tokio::time::advance(META_MAX_STALENESS / 2).await;
        assert!(metadata.status().grants_active);
        assert_eq!(metadata.status().published_scope, previous.published_scope);
        assert_ne!(metadata.status().revision, previous.revision);
    }

    struct BlockingClient {
        calls: AtomicUsize,
        dropped: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl GitHubMetaClient for BlockingClient {
        async fn fetch(
            &self,
            _policy: &PolicyEngine,
            _etag: Option<&str>,
        ) -> Result<GitHubMetaResponse, GitHubMetaError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(GitHubMetaResponse::Modified {
                    body: fixture(),
                    etag: Some("\"fixture\"".to_owned()),
                });
            }
            struct DropProbe(Arc<AtomicUsize>);
            impl Drop for DropProbe {
                fn drop(&mut self) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }
            let _probe = DropProbe(Arc::clone(&self.dropped));
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_refresh_is_hourly_bounded_and_cancelled_without_orphans() {
        let engine = engine();
        let client = Arc::new(BlockingClient {
            calls: AtomicUsize::new(0),
            dropped: Arc::new(AtomicUsize::new(0)),
        });
        let audit = Arc::new(crate::audit::CollectingAuditSink::new());
        engine
            .github_meta()
            .unwrap()
            .refresh_once(client.as_ref(), &engine, audit.as_ref())
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_refresh(
            Arc::clone(&engine),
            Arc::clone(&client) as Arc<_>,
            audit,
            cancel.clone(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(META_REFRESH_INTERVAL - Duration::from_secs(1)).await;
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(client.calls.load(Ordering::SeqCst), 2);
        cancel.cancel();
        task.await.unwrap().unwrap();
        assert_eq!(client.dropped.load(Ordering::SeqCst), 1);
        tokio::time::advance(META_REFRESH_INTERVAL).await;
        assert_eq!(client.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn hung_refresh_reports_timeout_without_extending_its_lease() {
        let engine = engine();
        let client = BlockingClient {
            calls: AtomicUsize::new(0),
            dropped: Arc::new(AtomicUsize::new(0)),
        };
        let audit = crate::audit::CollectingAuditSink::new();
        let metadata = engine.github_meta().unwrap();
        metadata
            .refresh_once(&client, &engine, &audit)
            .await
            .unwrap();
        let before = metadata.status();
        assert_eq!(
            metadata.refresh_once(&client, &engine, &audit).await,
            Err(GitHubMetaError::Timeout)
        );
        assert_eq!(
            metadata.status().last_success_unix_seconds,
            before.last_success_unix_seconds
        );
        assert_eq!(metadata.status().revision, before.revision);
        assert_eq!(metadata.status().state, GitHubMetaState::Degraded);
        assert_eq!(client.dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_provenance_publication_revokes_the_derived_scope() {
        struct BrokenAudit;
        impl AuditSink for BrokenAudit {
            fn record(&self, _event: AuditEvent) {}
            fn record_github_meta(&self, _status: GitHubMetaStatus) -> std::io::Result<()> {
                Err(std::io::Error::other("generated publication failure"))
            }
        }
        let engine = engine();
        let client = BlockingClient {
            calls: AtomicUsize::new(0),
            dropped: Arc::new(AtomicUsize::new(0)),
        };
        let metadata = engine.github_meta().unwrap();
        assert_eq!(
            metadata.refresh_once(&client, &engine, &BrokenAudit).await,
            Err(GitHubMetaError::Publication)
        );
        assert!(!metadata.status().grants_active);
        assert!(!engine.evaluate_domain_name("assets.github.test").unwrap());
    }

    #[tokio::test]
    async fn scope_is_published_before_it_can_authorize_a_connection() {
        struct PublicationCheck<'a>(&'a PolicyEngine);
        impl AuditSink for PublicationCheck<'_> {
            fn record(&self, _event: AuditEvent) {}
            fn record_github_meta(&self, status: GitHubMetaStatus) -> std::io::Result<()> {
                assert!(status.grants_active);
                assert!(!self.0.evaluate_domain_name("assets.github.test").unwrap());
                Ok(())
            }
        }
        let engine = engine();
        let client = BlockingClient {
            calls: AtomicUsize::new(0),
            dropped: Arc::new(AtomicUsize::new(0)),
        };
        engine
            .github_meta()
            .unwrap()
            .refresh_once(&client, &engine, &PublicationCheck(&engine))
            .await
            .unwrap();
        assert!(engine.evaluate_domain_name("assets.github.test").unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_refreshes_cannot_overwrite_a_newer_snapshot() {
        let engine = engine();
        let client = Arc::new(BlockingClient {
            calls: AtomicUsize::new(1),
            dropped: Arc::new(AtomicUsize::new(0)),
        });
        let task_engine = Arc::clone(&engine);
        let task_client = Arc::clone(&client);
        let task = tokio::spawn(async move {
            task_engine
                .github_meta()
                .unwrap()
                .refresh_once(
                    task_client.as_ref(),
                    &task_engine,
                    &crate::audit::NullAuditSink,
                )
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(
            engine
                .github_meta()
                .unwrap()
                .refresh_once(client.as_ref(), &engine, &crate::audit::NullAuditSink,)
                .await,
            Err(GitHubMetaError::RefreshInProgress)
        );
        assert_eq!(client.calls.load(Ordering::SeqCst), 2);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(client.dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_refresh_retains_last_good_only_until_its_monotonic_expiry() {
        struct FailingClient;
        #[async_trait::async_trait]
        impl GitHubMetaClient for FailingClient {
            async fn fetch(
                &self,
                _policy: &crate::policy::PolicyEngine,
                _etag: Option<&str>,
            ) -> Result<GitHubMetaResponse, GitHubMetaError> {
                Err(GitHubMetaError::HttpStatus(503))
            }
        }
        let raw = serde_json::from_value(serde_json::json!({
            "default_action": "deny",
            "allowed_domains": ["github.com"],
            "blocked_domains": [],
            "allow_dns": true
        }))
        .unwrap();
        let engine = crate::policy::PolicyEngine::compile(&raw).unwrap();
        let metadata = engine.github_meta().unwrap();
        metadata
            .install_response(GitHubMetaResponse::Modified {
                body: fixture(),
                etag: Some("\"fixture\"".to_owned()),
            })
            .unwrap();
        let previous = engine.snapshot();
        let audit = crate::audit::CollectingAuditSink::new();
        assert!(
            metadata
                .refresh_once(&FailingClient, &engine, &audit)
                .await
                .is_err()
        );
        assert_eq!(metadata.status().state, GitHubMetaState::Degraded);
        assert!(previous.is_current());
        tokio::time::advance(META_MAX_STALENESS).await;
        assert_eq!(metadata.status().state, GitHubMetaState::Expired);
        assert!(!metadata.status().grants_active);
        assert!(!previous.is_current());
        assert!(!engine.evaluate_domain_name("api.github.test").unwrap());
        assert!(engine.evaluate_domain_name("github.com").unwrap());
        assert_eq!(audit.len(), 1);
    }
}
