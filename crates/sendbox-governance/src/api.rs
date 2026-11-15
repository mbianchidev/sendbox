//! HTTP wire types of a shared governance service (`/v1`) that a SendBox host
//! and the service must agree on. Grant, request, and decision bodies reuse
//! the contract types directly.

use serde::{Deserialize, Serialize};

use crate::{
    GovernanceBinding, PrincipalId, RevocationReason, SessionRef, digest::Sha256Digest,
    exception::PolicyException,
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
