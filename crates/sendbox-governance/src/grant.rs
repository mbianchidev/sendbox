use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    CONTRACT_VERSION, GovernanceError, GrantId, PrincipalId, ProjectId, ServiceId, SessionRef,
    binding::GovernanceBinding, digest::Sha256Digest, profile::ProfileRef,
};

const MAX_PATH_BYTES: usize = 2048;
const MAX_PREFIX_BYTES: usize = 256;
const KNOWN_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// A request for one brokered credential service for one admitted session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub principal: PrincipalId,
    pub project: ProjectId,
    pub session: SessionRef,
    pub binding: GovernanceBinding,
    pub service: ServiceId,
    pub methods: BTreeSet<String>,
    pub path_prefixes: Vec<String>,
    pub max_ttl_seconds: u64,
}

/// An expiring, revocable authorization for one session to use one brokered
/// service. Grants carry no credential material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialGrant {
    pub contract_version: u32,
    pub grant_id: GrantId,
    pub principal: PrincipalId,
    pub project: ProjectId,
    pub session: SessionRef,
    pub binding_sha256: Sha256Digest,
    pub profile: ProfileRef,
    pub service: ServiceId,
    pub methods: BTreeSet<String>,
    pub path_prefixes: Vec<String>,
    pub issued_at_unix: u64,
    pub lease_expires_at_unix: u64,
    pub max_expires_at_unix: u64,
    pub generation: u64,
}

/// What the enforcement point presents for every upstream request. All fields
/// come from trusted host state; none are taken from the workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestContext {
    pub grant_id: GrantId,
    pub principal: PrincipalId,
    pub project: ProjectId,
    pub session: SessionRef,
    pub binding_sha256: Sha256Digest,
    pub service: ServiceId,
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedRequest {
    pub grant_id: GrantId,
    pub generation: u64,
    pub profile: ProfileRef,
    pub lease_expires_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow(AllowedRequest),
    Deny { reason: DenyReason },
}

impl Decision {
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow(_))
    }
}

/// Stable denial reasons recorded in audit evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    UnknownGrant,
    Revoked,
    Expired,
    LeaseExpired,
    PrincipalMismatch,
    ProjectMismatch,
    SessionMismatch,
    BindingMismatch,
    StalePolicy,
    ServiceNotGranted,
    MethodNotGranted,
    PathNotGranted,
    InvalidPath,
    AuthorityUnavailable,
}

impl DenyReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownGrant => "unknown_grant",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::LeaseExpired => "lease_expired",
            Self::PrincipalMismatch => "principal_mismatch",
            Self::ProjectMismatch => "project_mismatch",
            Self::SessionMismatch => "session_mismatch",
            Self::BindingMismatch => "binding_mismatch",
            Self::StalePolicy => "stale_policy",
            Self::ServiceNotGranted => "service_not_granted",
            Self::MethodNotGranted => "method_not_granted",
            Self::PathNotGranted => "path_not_granted",
            Self::InvalidPath => "invalid_path",
            Self::AuthorityUnavailable => "authority_unavailable",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    SessionCompleted,
    SessionCancelled,
    SessionFailed,
    OperatorRevoked,
    PolicyChanged,
}

impl RevocationReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SessionCompleted => "session_completed",
            Self::SessionCancelled => "session_cancelled",
            Self::SessionFailed => "session_failed",
            Self::OperatorRevoked => "operator_revoked",
            Self::PolicyChanged => "policy_changed",
        }
    }
}

impl CredentialGrant {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(GovernanceError::UnsupportedContract(self.contract_version));
        }
        if self.methods.is_empty() || self.path_prefixes.is_empty() {
            return Err(GovernanceError::InvalidGrant(
                "grants require at least one method and path prefix".to_owned(),
            ));
        }
        for method in &self.methods {
            validate_method(method)?;
        }
        for prefix in &self.path_prefixes {
            validate_path_prefix(prefix)?;
        }
        if self.lease_expires_at_unix > self.max_expires_at_unix
            || self.issued_at_unix >= self.max_expires_at_unix
        {
            return Err(GovernanceError::InvalidGrant(
                "grant expiry is inconsistent".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn validate_method(method: &str) -> Result<(), GovernanceError> {
    if KNOWN_METHODS.contains(&method) {
        Ok(())
    } else {
        Err(GovernanceError::InvalidGrant(format!(
            "method `{}` must be one of {}",
            method.chars().take(16).collect::<String>(),
            KNOWN_METHODS.join(", ")
        )))
    }
}

/// A grant path prefix: absolute, segment-normalized, printable ASCII, without
/// query, fragment, percent-encoding, or a trailing slash.
pub fn validate_path_prefix(prefix: &str) -> Result<(), GovernanceError> {
    let valid = prefix.len() <= MAX_PREFIX_BYTES
        && prefix.starts_with('/')
        && (prefix == "/" || !prefix.ends_with('/'))
        && normalized_path(prefix);
    if valid {
        Ok(())
    } else {
        Err(GovernanceError::InvalidGrant(format!(
            "path prefix `{}` must be an absolute normalized path without query, encoding, or trailing slash",
            prefix.chars().take(64).collect::<String>()
        )))
    }
}

/// Validates an upstream request path (without query) presented for
/// authorization. Encoded separators and dot segments are rejected so that a
/// prefix check cannot be bypassed by upstream path normalization.
pub fn validate_request_path(path: &str) -> Result<(), DenyReason> {
    if path.len() <= MAX_PATH_BYTES && path.starts_with('/') && normalized_path(path) {
        Ok(())
    } else {
        Err(DenyReason::InvalidPath)
    }
}

/// Segment-aware prefix match: `/v1/messages` matches `/v1/messages` and
/// `/v1/messages/count_tokens`, but not `/v1/messagesx`.
#[must_use]
pub fn path_permitted(prefixes: &[String], path: &str) -> bool {
    validate_request_path(path).is_ok()
        && prefixes.iter().any(|prefix| {
            prefix == "/"
                || path == prefix
                || path
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

fn normalized_path(path: &str) -> bool {
    path.bytes()
        .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#' | b'%' | b'\\'))
        && path[1..].split('/').enumerate().all(|(index, segment)| {
            segment != "." && segment != ".." && (index == 0 || !segment.is_empty())
        })
        && !path.contains("//")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_matching_is_segment_aware() {
        let prefixes = vec!["/v1/messages".to_owned()];
        assert!(path_permitted(&prefixes, "/v1/messages"));
        assert!(path_permitted(&prefixes, "/v1/messages/count_tokens"));
        assert!(!path_permitted(&prefixes, "/v1/messagesx"));
        assert!(!path_permitted(&prefixes, "/v1/models"));
        assert!(!path_permitted(&prefixes, "/v1/messages/../admin"));
        assert!(!path_permitted(&prefixes, "/v1/messages/%2e%2e/admin"));
        assert!(!path_permitted(&prefixes, "/v1/messages//x"));
        assert!(!path_permitted(&prefixes, "/v1/messages?x=1"));
        assert!(path_permitted(&["/".to_owned()], "/anything"));
    }

    #[test]
    fn prefixes_and_methods_are_validated() {
        assert!(validate_path_prefix("/v1/messages").is_ok());
        assert!(validate_path_prefix("/v1/messages/").is_err());
        assert!(validate_path_prefix("v1").is_err());
        assert!(validate_path_prefix("/v1/%2f").is_err());
        assert!(validate_path_prefix("/v1/./x").is_err());
        assert!(validate_method("POST").is_ok());
        assert!(validate_method("post").is_err());
        assert!(validate_method("CONNECT").is_err());
    }

    #[test]
    fn decisions_serialize_with_stable_codes() {
        let json = serde_json::to_string(&Decision::Deny {
            reason: DenyReason::StalePolicy,
        })
        .unwrap();
        assert_eq!(json, r#"{"decision":"deny","reason":"stale_policy"}"#);
    }
}
