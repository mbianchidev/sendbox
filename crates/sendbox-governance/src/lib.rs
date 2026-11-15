#![forbid(unsafe_code)]
//! Shared governance contract for SendBox.
//!
//! This crate is deliberately free of runtime, I/O, and transport code so a
//! session host and a separate governance service can share one definition of
//! identities, signed policy profiles, session bindings, and credential
//! grants. It never holds credential material.

pub mod authority;
pub mod binding;
pub mod digest;
pub mod grant;
pub mod identity;
pub mod profile;

use thiserror::Error;

pub use authority::{
    AuthorityFuture, Clock, CurrentProfile, GrantAuthority, LocalAuthorityLimits,
    LocalGrantAuthority, RevisionSource, SystemClock,
};
pub use binding::{AuthorityRef, GovernanceBinding};
pub use digest::{Sha256Digest, canonical_digest};
pub use grant::{
    AllowedRequest, CredentialGrant, Decision, DenyReason, GrantRequest, RequestContext,
    RevocationReason, path_permitted, validate_request_path,
};
pub use identity::{GrantId, PrincipalId, ProfileId, ProjectId, ServiceId, SessionRef};
pub use profile::{
    BROKERED_CREDENTIAL_PLACEHOLDER, Ceiling, CeilingAction, CredentialProvider,
    CredentialServiceProfile, GovernanceProfile, PROFILE_FORMAT, PROFILE_VERSION, ProfileRef,
    ProviderInjection, RuntimeKind,
};

/// Wire and digest version shared with external governance services.
pub const CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GovernanceError {
    #[error("invalid {kind} identifier `{value}`")]
    InvalidIdentifier { kind: &'static str, value: String },
    #[error("invalid SHA-256 digest `{0}`")]
    InvalidDigest(String),
    #[error("invalid governance profile: {0}")]
    InvalidProfile(String),
    #[error("governance profile `{id}` revision {revision} is not yet valid")]
    ProfileNotYetValid { id: String, revision: u64 },
    #[error("governance profile `{id}` revision {revision} has expired")]
    ProfileExpired { id: String, revision: u64 },
    #[error("unsupported governance contract version {0}")]
    UnsupportedContract(u32),
    #[error("invalid governance binding: {0}")]
    InvalidBinding(String),
    #[error("invalid credential grant: {0}")]
    InvalidGrant(String),
    #[error("credential grant denied: {0}")]
    Denied(&'static str),
    #[error("governance authority unavailable: {0}")]
    AuthorityUnavailable(String),
    #[error("governance encoding: {0}")]
    Encoding(String),
}
