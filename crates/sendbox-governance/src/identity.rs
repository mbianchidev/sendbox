//! Validated identifiers shared by the session runtime and a governance service.
//!
//! Every identifier is an opaque, bounded, printable-ASCII string with a fixed
//! grammar so that it can be compared byte-for-byte, logged without escaping,
//! and embedded in canonical JSON without normalization surprises.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::GovernanceError;

const MAX_PRINCIPAL_BYTES: usize = 160;
const MAX_PROJECT_BYTES: usize = 160;
const MAX_PROFILE_ID_BYTES: usize = 64;
const MAX_SERVICE_ID_BYTES: usize = 32;
const GRANT_ID_BYTES: usize = 16;

macro_rules! string_identifier {
    ($name:ident, $validate:path, $what:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, GovernanceError> {
                let value = value.into();
                if $validate(&value) {
                    Ok(Self(value))
                } else {
                    Err(GovernanceError::InvalidIdentifier {
                        kind: $what,
                        value: printable_prefix(&value),
                    })
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_identifier!(PrincipalId, valid_principal, "principal");
string_identifier!(ProjectId, valid_project, "project");
string_identifier!(ProfileId, valid_profile_id, "profile");
string_identifier!(ServiceId, valid_service_id, "service");
string_identifier!(SessionRef, valid_session_ref, "session");
string_identifier!(GrantId, valid_grant_id, "grant");
string_identifier!(ExceptionId, valid_grant_id, "exception");

impl PrincipalId {
    /// Identity of a local operating-system account. Increment 1 uses this for
    /// every session; a shared governance service authenticates its own
    /// principals and never accepts this kind from a workload.
    #[must_use]
    pub fn local_user(uid: u32) -> Self {
        Self(format!("local-user:{uid}"))
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        self.0.split_once(':').map_or("", |(kind, _)| kind)
    }
}

impl ProjectId {
    /// Project identity derived from a GitHub `owner/repository` pair.
    pub fn github(owner: &str, repository: &str) -> Result<Self, GovernanceError> {
        Self::new(format!(
            "github:{}/{}",
            owner.to_ascii_lowercase(),
            repository.to_ascii_lowercase()
        ))
    }

    /// Project identity for a workspace without a resolvable repository.
    #[must_use]
    pub fn from_canonical_path(path: &[u8]) -> Self {
        Self(format!("path-sha256:{}", lower_hex(&Sha256::digest(path))))
    }
}

impl SessionRef {
    #[must_use]
    pub fn from_session_id(session: sendbox_core::SessionId) -> Self {
        Self(session.to_string())
    }
}

impl GrantId {
    #[must_use]
    pub fn from_bytes(bytes: [u8; GRANT_ID_BYTES]) -> Self {
        Self(lower_hex(&bytes))
    }
}

impl ExceptionId {
    #[must_use]
    pub fn from_bytes(bytes: [u8; GRANT_ID_BYTES]) -> Self {
        Self(lower_hex(&bytes))
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn printable_prefix(value: &str) -> String {
    value
        .chars()
        .take(48)
        .map(|character| {
            if character.is_ascii_graphic() {
                character
            } else {
                '?'
            }
        })
        .collect()
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_principal(value: &str) -> bool {
    let Some((kind, rest)) = value.split_once(':') else {
        return false;
    };
    value.len() <= MAX_PRINCIPAL_BYTES
        && !kind.is_empty()
        && kind.len() <= 32
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        && !rest.is_empty()
        && rest.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'+' | b'-' | b':')
        })
}

fn valid_project(value: &str) -> bool {
    if value.len() > MAX_PROJECT_BYTES {
        return false;
    }
    if let Some(digest) = value.strip_prefix("path-sha256:") {
        return is_lower_hex(digest, 64);
    }
    let Some(repository) = value.strip_prefix("github:") else {
        return false;
    };
    let Some((owner, name)) = repository.split_once('/') else {
        return false;
    };
    let segment = |segment: &str| {
        !segment.is_empty()
            && segment.len() <= 100
            && !segment.starts_with('.')
            && segment.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
    };
    segment(owner) && segment(name)
}

fn valid_profile_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_PROFILE_ID_BYTES
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_service_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_SERVICE_ID_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_session_ref(value: &str) -> bool {
    is_lower_hex(value, 32)
}

fn valid_grant_id(value: &str) -> bool {
    is_lower_hex(value, GRANT_ID_BYTES * 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_enforce_their_grammar() {
        assert!(PrincipalId::new("local-user:501:alice").is_ok());
        assert!(PrincipalId::new("oidc:alice@example.com").is_ok());
        assert!(PrincipalId::new("alice").is_err());
        assert!(PrincipalId::new("Local:alice").is_err());
        assert!(PrincipalId::new("local-user:alice bob").is_err());

        assert!(ProjectId::new("github:octo/api").is_ok());
        assert!(ProjectId::new("github:Octo/api").is_err());
        assert!(ProjectId::new("github:octo/../api").is_err());
        assert!(ProjectId::new("github:octo").is_err());
        assert_eq!(
            ProjectId::github("Octo", "API").unwrap().as_str(),
            "github:octo/api"
        );
        assert!(ProjectId::from_canonical_path(b"/work/app").as_str().len() == 76);

        assert!(ServiceId::new("anthropic").is_ok());
        assert!(ServiceId::new("Anthropic").is_err());
        assert!(ServiceId::new("1openai").is_err());
        assert!(ProfileId::new("acme.default-v2").is_ok());
        assert!(ProfileId::new("").is_err());

        assert!(GrantId::new("00".repeat(16)).is_ok());
        assert_eq!(
            ExceptionId::from_bytes([0xab; 16]).as_str(),
            "ab".repeat(16)
        );
        assert!(ExceptionId::new("AB".repeat(16)).is_err());
        assert!(GrantId::new("0".repeat(31)).is_err());
        assert!(SessionRef::new("AB".repeat(16)).is_err());
    }

    #[test]
    fn deserialization_rejects_invalid_identifiers() {
        assert!(serde_json::from_str::<ServiceId>("\"openai\"").is_ok());
        assert!(serde_json::from_str::<ServiceId>("\"open ai\"").is_err());
    }
}
