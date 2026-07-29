#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};

mod glob;

pub use glob::glob_matches;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const SHA256_DIGEST_BYTES: usize = 32;
pub const TERMINAL_INPUT_CHUNK_BYTES: usize = 4 * 1024;
pub const TERMINAL_INPUT_WINDOW_CREDITS: u16 = 64;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BoundaryPlanDigest([u8; SHA256_DIGEST_BYTES]);

impl BoundaryPlanDigest {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SHA256_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Debug for BoundaryPlanDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BoundaryPlanDigest")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for BoundaryPlanDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId([u8; 16]);

impl SessionId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    IncompatibleConfiguration,
    InvalidPath,
    InvalidValue,
    InvalidYaml,
    Io,
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IncompatibleConfiguration => "incompatible_configuration",
            Self::InvalidPath => "invalid_path",
            Self::InvalidValue => "invalid_value",
            Self::InvalidYaml => "invalid_yaml",
            Self::Io => "io",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub path: String,
    pub message: String,
}

impl Diagnostic {
    #[must_use]
    pub fn new(code: DiagnosticCode, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFailure {
    diagnostics: Vec<Diagnostic>,
}

impl ValidationFailure {
    #[must_use]
    pub fn new(diagnostics: Vec<Diagnostic>) -> Self {
        Self { diagnostics }
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

impl fmt::Display for ValidationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            if index > 0 {
                formatter.write_str("\n")?;
            }
            write!(
                formatter,
                "{:?} at {}: {}",
                diagnostic.code, diagnostic.path, diagnostic.message
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationFailure {}

#[cfg(test)]
mod tests {
    use super::BoundaryPlanDigest;

    #[test]
    fn boundary_plan_digest_has_stable_hex_encoding() {
        let digest = BoundaryPlanDigest::from_bytes([0xab; 32]);
        assert_eq!(digest.to_string(), "ab".repeat(32));
        assert_eq!(digest.as_bytes(), &[0xab; 32]);
    }
}
