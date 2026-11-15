//! HTTP wire types of a shared governance service (`/v1`) that a SendBox host
//! and the service must agree on. Grant, request, and decision bodies reuse
//! the contract types directly.

use serde::{Deserialize, Serialize};

use crate::{
    GovernanceBinding, GovernanceError, PrincipalId, RevocationReason, ServiceId, SessionRef,
    digest::Sha256Digest, exception::PolicyException,
};

/// Media type of error responses (RFC 9457).
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerKind {
    /// A person.
    User,
    /// A machine identity, such as a managed runner.
    Worker,
}

/// `GET /v1/whoami`: the identity the service authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerIdentity {
    pub principal: PrincipalId,
    pub kind: CallerKind,
    pub operator: bool,
}

/// `POST /v1/sessions:admit` body. The binding principal must be the
/// authenticated caller; it is a claim, never a source of identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAdmissionRequest {
    pub session: SessionRef,
    pub binding: GovernanceBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAdmission {
    pub session: SessionRef,
    pub binding_sha256: Sha256Digest,
    pub admitted_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionOutcome {
    Completed,
    Cancelled,
    Failed,
}

impl SessionOutcome {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub const fn revocation_reason(self) -> RevocationReason {
        match self {
            Self::Completed => RevocationReason::SessionCompleted,
            Self::Cancelled => RevocationReason::SessionCancelled,
            Self::Failed => RevocationReason::SessionFailed,
        }
    }
}

/// `POST /v1/sessions/{session}:end` body. Ending a session revokes its grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEnd {
    pub outcome: SessionOutcome,
}

/// `POST /v1/grants/{grant}:revoke` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeGrantRequest {
    pub reason: RevocationReason,
}

/// `GET /v1/exceptions` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionList {
    pub exceptions: Vec<PolicyException>,
}

/// `POST /v1/tokens` body: exchange an identity-provider login for a
/// service token that a host can store. Omitted fields take the service's
/// defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// `POST /v1/tokens` response. `token` is shown once and never stored by the
/// service; `Debug` redacts it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedToken {
    pub id: String,
    pub token: String,
    pub principal: PrincipalId,
    pub expires_at_unix: u64,
}

impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedToken")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .field("principal", &self.principal)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// How a brokered request ended, as reported by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportedOutcome {
    /// The upstream response was relayed in full.
    Succeeded,
    /// The request was refused or failed before an uncertain upstream effect.
    Failed,
    /// The stream was cut after the request reached the upstream, so its
    /// external effect cannot be confirmed.
    Unknown,
}

impl ReportedOutcome {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

const MAX_METHOD_BYTES: usize = 16;
const MAX_REASON_BYTES: usize = 64;
const MAX_REPORTED_PATH_BYTES: usize = 2048;

/// `POST /v1/grants/{grant}:outcome` body: the redacted end of one brokered
/// stream. It never carries headers, query strings, or bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestOutcomeReport {
    pub service: ServiceId,
    pub method: String,
    /// Path without query; may be invalid when the host refused it.
    pub path: String,
    pub outcome: ReportedOutcome,
    /// The host relay's reason code, such as `complete` or `grant_lapsed`.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub duration_ms: u64,
}

impl RequestOutcomeReport {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        let token = |value: &str, limit: usize, allowed: fn(u8) -> bool| {
            !value.is_empty() && value.len() <= limit && value.bytes().all(allowed)
        };
        if !token(&self.method, MAX_METHOD_BYTES, |byte| {
            byte.is_ascii_uppercase()
        }) {
            return Err(GovernanceError::Encoding(
                "outcome method must be 1-16 uppercase ASCII letters".to_owned(),
            ));
        }
        if !token(&self.reason, MAX_REASON_BYTES, |byte| {
            byte.is_ascii_lowercase() || byte == b'_'
        }) {
            return Err(GovernanceError::Encoding(
                "outcome reason must be 1-64 lowercase ASCII letters or underscores".to_owned(),
            ));
        }
        if self.path.len() > MAX_REPORTED_PATH_BYTES
            || self.path.bytes().any(|byte| !byte.is_ascii_graphic())
        {
            return Err(GovernanceError::Encoding(
                "outcome path must be at most 2048 printable ASCII bytes".to_owned(),
            ));
        }
        if self
            .status
            .is_some_and(|status| !(100..=599).contains(&status))
        {
            return Err(GovernanceError::Encoding(
                "outcome status must be an HTTP status code".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> RequestOutcomeReport {
        RequestOutcomeReport {
            service: ServiceId::new("anthropic").unwrap(),
            method: "POST".to_owned(),
            path: "/v1/messages".to_owned(),
            outcome: ReportedOutcome::Unknown,
            reason: "aborted_uncertain".to_owned(),
            status: Some(200),
            request_bytes: 10,
            response_bytes: 20,
            duration_ms: 30,
        }
    }

    #[test]
    fn outcome_reports_are_bounded_and_redacted() {
        assert!(report().validate().is_ok());
        for broken in [
            RequestOutcomeReport {
                method: "post".to_owned(),
                ..report()
            },
            RequestOutcomeReport {
                reason: "Bad Reason".to_owned(),
                ..report()
            },
            RequestOutcomeReport {
                path: "/v1/messages body".to_owned(),
                ..report()
            },
            RequestOutcomeReport {
                status: Some(42),
                ..report()
            },
        ] {
            assert!(broken.validate().is_err(), "{broken:?}");
        }
    }

    #[test]
    fn issued_tokens_never_print_their_secret() {
        let issued = IssuedToken {
            id: "ab".repeat(16),
            token: "sbf_secret-value".to_owned(),
            principal: PrincipalId::new("oidc:alice@example.com").unwrap(),
            expires_at_unix: 1,
        };
        assert!(!format!("{issued:?}").contains("secret-value"));
    }
}
