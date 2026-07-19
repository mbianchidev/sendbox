use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::SecretStoreError;

pub const MAX_SECRET_NAME_BYTES: usize = 128;
pub const MAX_SECRET_VALUE_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretName(String);

impl SecretName {
    pub fn new(value: impl Into<String>) -> Result<Self, SecretStoreError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SecretStoreError::InvalidName(
                "name cannot be empty".to_owned(),
            ));
        }
        if value.len() > MAX_SECRET_NAME_BYTES {
            return Err(SecretStoreError::InvalidName(format!(
                "name exceeds {MAX_SECRET_NAME_BYTES} UTF-8 bytes"
            )));
        }
        if value.chars().any(char::is_control) {
            return Err(SecretStoreError::InvalidName(
                "name cannot contain control characters".to_owned(),
            ));
        }
        if value.nfc().collect::<String>() != value {
            return Err(SecretStoreError::InvalidName(
                "name must use NFC Unicode normalization".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SecretName").field(&self.0).finish()
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for SecretName {
    type Err = SecretStoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, SecretStoreError> {
        let value = value.into();
        if value.len() > MAX_SECRET_VALUE_BYTES {
            return Err(SecretStoreError::ValueTooLarge {
                maximum: MAX_SECRET_VALUE_BYTES,
            });
        }
        Ok(Self(Zeroizing::new(value)))
    }

    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl TryFrom<&str> for SecretValue {
    type Error = SecretStoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.as_bytes().to_vec())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordVersion {
    SwiftLegacy,
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    pub name: SecretName,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub version: RecordVersion,
}

pub struct Secret {
    pub metadata: SecretMetadata,
    pub value: SecretValue,
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Secret")
            .field("metadata", &self.metadata)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

pub trait SecretStore: Send + Sync {
    fn store(
        &self,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError>;
    fn update(
        &self,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError>;
    fn retrieve(&self, name: &SecretName) -> Result<Secret, SecretStoreError>;
    fn delete(&self, name: &SecretName) -> Result<(), SecretStoreError>;
    fn list(&self) -> Result<Vec<SecretMetadata>, SecretStoreError>;
    fn exists(&self, name: &SecretName) -> Result<bool, SecretStoreError>;
    fn migrate(&self, name: &SecretName) -> Result<SecretMetadata, SecretStoreError>;
}

pub(crate) fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_reject_controls_non_normalized_and_long_inputs() {
        assert!(SecretName::new("").is_err());
        assert!(SecretName::new("bad\0name").is_err());
        assert!(SecretName::new("e\u{301}").is_err());
        assert!(SecretName::new("a".repeat(MAX_SECRET_NAME_BYTES + 1)).is_err());
        assert_eq!(
            SecretName::new("TOKEN_日本語").expect("valid").as_str(),
            "TOKEN_日本語"
        );
    }

    #[test]
    fn secret_values_are_always_redacted() {
        let value = SecretValue::try_from("super-secret").expect("value");
        assert_eq!(format!("{value}"), "[REDACTED]");
        assert_eq!(format!("{value:?}"), "SecretValue([REDACTED])");
        assert!(!format!("{value:?}").contains("super-secret"));
    }

    #[test]
    fn secret_debug_redacts_nested_value() {
        let secret = Secret {
            metadata: SecretMetadata {
                name: SecretName::new("TOKEN").expect("name"),
                created_at_unix_ms: 1,
                updated_at_unix_ms: 2,
                version: RecordVersion::V1,
            },
            value: SecretValue::try_from("never-format-me").expect("value"),
        };
        assert!(!format!("{secret:?}").contains("never-format-me"));
    }
}
