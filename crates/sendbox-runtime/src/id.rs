use std::{fmt, str::FromStr};

use crate::{IdentifierKind, RuntimeError};

const MAX_IDENTIFIER_BYTES: usize = 128;

macro_rules! identifier {
    ($name:ident, $kind:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, RuntimeError> {
                let value = value.into();
                validate_identifier(&value, $kind)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = RuntimeError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = RuntimeError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

identifier!(RuntimeId, IdentifierKind::Runtime);
identifier!(ContainerId, IdentifierKind::Container);

fn validate_identifier(value: &str, kind: IdentifierKind) -> Result<(), RuntimeError> {
    let reason = if value.is_empty() {
        Some("must not be empty")
    } else if value.len() > MAX_IDENTIFIER_BYTES {
        Some("must not exceed 128 bytes")
    } else if !value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        Some("must start with an ASCII alphanumeric character")
    } else if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Some("may contain only ASCII alphanumeric characters, `.`, `_`, and `-`")
    } else {
        None
    };

    match reason {
        Some(reason) => Err(RuntimeError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
            reason,
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{ContainerId, RuntimeId};

    #[test]
    fn identifiers_validate_their_external_form() {
        assert!(RuntimeId::new("apple-container_1.0").is_ok());
        assert!(ContainerId::new("").is_err());
        assert!(ContainerId::new("-leading").is_err());
        assert!(ContainerId::new("contains/slash").is_err());
        assert!(ContainerId::new("a".repeat(129)).is_err());
    }
}
