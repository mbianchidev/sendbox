use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::GovernanceError;

/// A SHA-256 digest that serializes as 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse_hex(value: &str) -> Result<Self, GovernanceError> {
        let invalid = || GovernanceError::InvalidDigest(value.chars().take(16).collect());
        if value.len() != 64 {
            return Err(invalid());
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(pair).map_err(|_| invalid())?;
            if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
                return Err(invalid());
            }
            bytes[index] = u8::from_str_radix(text, 16).map_err(|_| invalid())?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Sha256Digest({self})")
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse_hex(&value).map_err(serde::de::Error::custom)
    }
}

/// Digest of the RFC 8785 canonical JSON form of `value`.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<Sha256Digest, GovernanceError> {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| GovernanceError::Encoding(error.to_string()))?;
    Ok(Sha256Digest::of(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_is_lowercase_and_strict() {
        let digest = Sha256Digest::of(b"sendbox");
        let text = digest.to_string();
        assert_eq!(Sha256Digest::parse_hex(&text).unwrap(), digest);
        assert!(Sha256Digest::parse_hex(&text.to_ascii_uppercase()).is_err());
        assert!(Sha256Digest::parse_hex(&text[..62]).is_err());
    }

    #[test]
    fn canonical_digest_ignores_key_order() {
        let first: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":[2,3]}"#).unwrap();
        let second: serde_json::Value = serde_json::from_str(r#"{"b":[2,3],"a":1}"#).unwrap();
        assert_eq!(
            canonical_digest(&first).unwrap(),
            canonical_digest(&second).unwrap()
        );
    }
}
