//! Validated, expiring destination grants from GitHub's official Meta API.
//!
//! The host owns the only network fetch (see [`crate::github_meta_client`])
//! and shares one cached response across sessions. Gateways install that
//! host-supplied [`GitHubMetaSeed`] after re-validating it and never contact
//! GitHub themselves.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::time::Instant;

use crate::audit::{AuditEvent, AuditSink};
use crate::domain;

pub const GITHUB_META_URL: &str = "https://api.github.com/meta";
pub const GITHUB_META_API_VERSION: &str = "2022-11-28";
pub const MAX_META_BYTES: usize = 2 * 1024 * 1024;
/// Upper bound for one serialized seed: the base64 body plus small metadata.
pub const MAX_SEED_BYTES: usize = 3 * 1024 * 1024;
/// How long the host reuses a validated response before revalidating it.
pub const META_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub const META_MAX_STALENESS: Duration = Duration::from_secs(24 * 60 * 60);
pub const META_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Tolerated host/guest clock disagreement for a seed's validation time.
pub const META_MAX_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);
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

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum GitHubMetaError {
    #[error("GitHub Meta response exceeds its byte or entry limit")]
    LimitExceeded,
    #[error("invalid GitHub Meta document: {0}")]
    InvalidDocument(String),
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
    #[error(
        "GitHub Meta request hit GitHub's anonymous API rate limit (60 requests per hour per IP address){}",
        rate_limit_reset(.reset_unix_seconds)
    )]
    RateLimited { reset_unix_seconds: Option<u64> },
    #[error("GitHub Meta refresh timed out")]
    Timeout,
    #[error("GitHub Meta refresh is denied by network policy")]
    PolicyDenied,
    #[error("GitHub Meta DNS resolution failed")]
    Resolution,
    #[error("GitHub Meta transport failed during {0}")]
    Transport(String),
    #[error("GitHub Meta TLS roots are unavailable or invalid")]
    TlsRoots,
    #[error("GitHub Meta response has invalid headers or framing")]
    InvalidResponse,
    #[error("GitHub Meta provenance publication failed")]
    Publication,
    #[error("GitHub Meta delegation requires a host-validated seed")]
    MissingSeed,
    #[error("GitHub Meta seed is expired or validated in the future")]
    ExpiredSeed,
}

fn rate_limit_reset(reset_unix_seconds: &Option<u64>) -> String {
    reset_unix_seconds.map_or_else(String::new, |reset| {
        format!("; it resets at Unix time {reset}")
    })
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
            .map_err(|_| GitHubMetaError::InvalidDocument("expected JSON".to_owned()))?;
        let object = document
            .as_object()
            .ok_or_else(|| GitHubMetaError::InvalidDocument("expected an object".to_owned()))?;
        if !object
            .get("verifiable_password_authentication")
            .is_some_and(Value::is_boolean)
        {
            return Err(GitHubMetaError::InvalidDocument(
                "missing authentication metadata".to_owned(),
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
                    "unrecognized top-level field".to_owned(),
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
                    "missing core network field".to_owned(),
                ));
            }
        }
        let published_domains = object
            .get("domains")
            .and_then(Value::as_object)
            .ok_or_else(|| GitHubMetaError::InvalidDocument("missing domains object".to_owned()))?;
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
                        "unrecognized domain field".to_owned(),
                    ));
                }
                let nested = value.as_object().ok_or_else(|| {
                    GitHubMetaError::InvalidDocument("expected a nested domain object".to_owned())
                })?;
                for (key, value) in nested {
                    match (field.as_str(), key.as_str()) {
                        ("actions_inbound", "full_domains" | "wildcard_domains")
                        | ("artifact_attestations", "services") => add_domains(value)?,
                        ("artifact_attestations", "trust_domain") if value.is_string() => {}
                        _ => {
                            return Err(GitHubMetaError::InvalidDocument(
                                "unrecognized domain field".to_owned(),
                            ));
                        }
                    }
                }
            }
        }
        if networks.is_empty() || domains.is_empty() {
            return Err(GitHubMetaError::InvalidDocument(
                "empty destination scope".to_owned(),
            ));
        }
        Ok(Self {
            domains: domains.into_iter().collect(),
            networks: networks.into_iter().collect(),
            sha256: hex_sha256(bytes),
        })
    }
}

fn strings(value: &Value) -> Result<Vec<&str>, GitHubMetaError> {
    let values = value.as_array().ok_or_else(|| {
        GitHubMetaError::InvalidDocument("expected a destination array".to_owned())
    })?;
    if values.len() > MAX_NETWORK_ENTRIES {
        return Err(GitHubMetaError::LimitExceeded);
    }
    values
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                GitHubMetaError::InvalidDocument("destination entries must be strings".to_owned())
            })
        })
        .collect()
}

pub enum GitHubMetaResponse {
    Modified { body: Vec<u8>, etag: Option<String> },
    NotModified,
}

/// One whole official Meta response validated by the host's shared cache.
/// The guest re-validates every field before any grant becomes effective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubMetaSeed {
    #[serde(with = "base64_body")]
    pub body: Vec<u8>,
    pub etag: Option<String>,
    /// Last successful fetch or conditional revalidation, in host Unix time.
    pub validated_unix_seconds: u64,
    pub last_attempt_unix_seconds: u64,
    /// Set when the host's latest revalidation failed and this is last-good.
    pub last_error: Option<GitHubMetaError>,
}

impl GitHubMetaSeed {
    /// Checks the validator, freshness bound and complete document.
    pub fn validate(&self, now_unix_seconds: u64) -> Result<GitHubMetaScope, GitHubMetaError> {
        if self.etag.as_deref().is_some_and(|etag| !valid_etag(etag)) {
            return Err(GitHubMetaError::InvalidResponse);
        }
        self.remaining_validity(now_unix_seconds)?;
        GitHubMetaScope::parse(&self.body)
    }

    /// Time left before the 24-hour staleness bound, measured from the host's
    /// validation time. Future validation times are tolerated within skew.
    pub fn remaining_validity(&self, now_unix_seconds: u64) -> Result<Duration, GitHubMetaError> {
        if self.validated_unix_seconds
            > now_unix_seconds.saturating_add(META_MAX_CLOCK_SKEW.as_secs())
        {
            return Err(GitHubMetaError::ExpiredSeed);
        }
        META_MAX_STALENESS
            .checked_sub(Duration::from_secs(
                now_unix_seconds.saturating_sub(self.validated_unix_seconds),
            ))
            .filter(|remaining| !remaining.is_zero())
            .ok_or(GitHubMetaError::ExpiredSeed)
    }

    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex_sha256(&self.body)
    }
}

mod base64_body {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(body: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(body))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > super::MAX_SEED_BYTES {
            return Err(D::Error::custom("GitHub Meta seed body exceeds its limit"));
        }
        STANDARD.decode(encoded).map_err(D::Error::custom)
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn unix_now() -> Result<u64, GitHubMetaError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| GitHubMetaError::Clock)
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
    // Absolute deadline: a freshly booted guest cannot backdate an Instant.
    expires_at: Instant,
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
}

impl GitHubMeta {
    pub(crate) fn clear(&self) {
        let mut state = self.state.write().expect("GitHub Meta state poisoned");
        state.snapshot = None;
        state.last_attempt_unix_seconds = None;
        state.last_error = None;
    }

    /// Validates a host-supplied seed and atomically publishes its status
    /// before it can authorize anything. An invalid seed leaves any previous
    /// snapshot untouched until its own expiry.
    pub fn install_seed(
        &self,
        seed: &GitHubMetaSeed,
        audit: &dyn AuditSink,
    ) -> Result<(), GitHubMetaError> {
        let candidate = self.prepare_seed(seed);
        if let Err(error) = &candidate {
            let mut state = self.state.write().expect("GitHub Meta state poisoned");
            match unix_now() {
                Ok(now) => {
                    state.last_attempt_unix_seconds = Some(now);
                    state.last_error = Some(error.clone());
                }
                Err(clock) => {
                    state.last_attempt_unix_seconds = None;
                    state.last_error = Some(clock);
                }
            }
        }
        let status = match &candidate {
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
        let candidate = candidate?;
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
            .is_some_and(|snapshot| Instant::now() < snapshot.expires_at);
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
            Some(snapshot) if Instant::now() < snapshot.expires_at => {
                (state.revision, Some(Arc::clone(&snapshot.scope)))
            }
            _ => (0, None),
        }
    }

    fn prepare_seed(&self, seed: &GitHubMetaSeed) -> Result<State, GitHubMetaError> {
        let now = unix_now()?;
        let scope = Arc::new(seed.validate(now)?);
        let remaining = seed.remaining_validity(now)?;
        let mut state = self
            .state
            .read()
            .expect("GitHub Meta state poisoned")
            .clone();
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(GitHubMetaError::LimitExceeded)?;
        state.snapshot = Some(Snapshot {
            scope,
            expires_at: Instant::now() + remaining,
            validated_unix_seconds: seed.validated_unix_seconds,
            etag: seed.etag.clone(),
        });
        state.last_attempt_unix_seconds = Some(seed.last_attempt_unix_seconds);
        state.last_error = seed.last_error.clone();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyEngine;

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

    fn seed(validated_unix_seconds: u64) -> GitHubMetaSeed {
        GitHubMetaSeed {
            body: fixture(),
            etag: Some("\"fixture\"".to_owned()),
            validated_unix_seconds,
            last_attempt_unix_seconds: validated_unix_seconds,
            last_error: None,
        }
    }

    fn engine() -> PolicyEngine {
        PolicyEngine::compile(
            &serde_json::from_value(serde_json::json!({
                "default_action": "deny", "allowed_domains": ["github.com"],
                "blocked_domains": [], "allow_dns": true
            }))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn seed_body_round_trips_exactly_through_its_wire_encoding() {
        let mut original = seed(unix_now().unwrap());
        original.body.extend_from_slice(b" \n");
        let encoded = serde_json::to_vec(&original).unwrap();
        let decoded: GitHubMetaSeed = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.sha256_hex(), original.sha256_hex());
    }

    #[test]
    fn rejects_invalid_validators_stale_and_future_seeds_without_installing_a_scope() {
        let now = unix_now().unwrap();
        let mut invalid = Vec::new();
        for etag in ["", "unquoted", "\"embedded\"quote\"", "\"line\r\nbreak\""] {
            let mut candidate = seed(now);
            candidate.etag = Some(etag.to_owned());
            invalid.push((candidate, GitHubMetaError::InvalidResponse));
        }
        invalid.push((
            seed(now - META_MAX_STALENESS.as_secs()),
            GitHubMetaError::ExpiredSeed,
        ));
        invalid.push((
            seed(now + META_MAX_CLOCK_SKEW.as_secs() + 60),
            GitHubMetaError::ExpiredSeed,
        ));
        for (candidate, expected) in invalid {
            let metadata = GitHubMeta::default();
            let audit = crate::audit::CollectingAuditSink::new();
            assert_eq!(metadata.install_seed(&candidate, &audit), Err(expected));
            assert!(!metadata.status().grants_active);
            assert_eq!(metadata.status().state, GitHubMetaState::Unavailable);
            assert_eq!(audit.len(), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn seed_expires_from_host_validation_time_not_guest_install_time() {
        let engine = engine();
        let metadata = engine.github_meta().unwrap();
        let validated =
            unix_now().unwrap() - (META_MAX_STALENESS - META_REFRESH_INTERVAL).as_secs();
        metadata
            .install_seed(&seed(validated), &crate::audit::NullAuditSink)
            .unwrap();
        let installed = engine.snapshot();
        assert_eq!(metadata.status().state, GitHubMetaState::Fresh);
        assert_eq!(
            metadata.status().expires_unix_seconds,
            Some(validated + META_MAX_STALENESS.as_secs())
        );
        assert!(engine.evaluate_domain_name("assets.github.test").unwrap());
        tokio::time::advance(META_REFRESH_INTERVAL - Duration::from_secs(5)).await;
        assert!(installed.is_current());
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(metadata.status().state, GitHubMetaState::Expired);
        assert!(!installed.is_current());
        assert!(!engine.evaluate_domain_name("assets.github.test").unwrap());
        assert!(engine.evaluate_domain_name("github.com").unwrap());
    }

    #[test]
    fn last_good_seed_reports_the_hosts_failed_revalidation() {
        let engine = engine();
        let now = unix_now().unwrap();
        let mut candidate = seed(now - 7200);
        candidate.last_attempt_unix_seconds = now;
        candidate.last_error = Some(GitHubMetaError::RateLimited {
            reset_unix_seconds: Some(now + 600),
        });
        let metadata = engine.github_meta().unwrap();
        metadata
            .install_seed(&candidate, &crate::audit::NullAuditSink)
            .unwrap();
        let status = metadata.status();
        assert_eq!(status.state, GitHubMetaState::Degraded);
        assert!(status.grants_active);
        assert_eq!(status.last_attempt_unix_seconds, Some(now));
        assert_eq!(status.last_error, candidate.last_error);
        assert!(engine.evaluate_domain_name("assets.github.test").unwrap());
    }

    #[test]
    fn failed_provenance_publication_revokes_the_derived_scope() {
        struct BrokenAudit;
        impl AuditSink for BrokenAudit {
            fn record(&self, _event: AuditEvent) {}
            fn record_github_meta(&self, _status: GitHubMetaStatus) -> std::io::Result<()> {
                Err(std::io::Error::other("generated publication failure"))
            }
        }
        let engine = engine();
        let metadata = engine.github_meta().unwrap();
        assert_eq!(
            metadata.install_seed(&seed(unix_now().unwrap()), &BrokenAudit),
            Err(GitHubMetaError::Publication)
        );
        assert!(!metadata.status().grants_active);
        assert!(!engine.evaluate_domain_name("assets.github.test").unwrap());
    }

    #[test]
    fn scope_is_published_before_it_can_authorize_a_connection() {
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
        engine
            .github_meta()
            .unwrap()
            .install_seed(&seed(unix_now().unwrap()), &PublicationCheck(&engine))
            .unwrap();
        assert!(engine.evaluate_domain_name("assets.github.test").unwrap());
    }
}
