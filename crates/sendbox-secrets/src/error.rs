use std::io;

use thiserror::Error;

use crate::SecretName;

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("secret access denied")]
    AccessDenied,
    #[error("secret already exists: {0}")]
    AlreadyExists(SecretName),
    #[error("corrupt secret record: {0}")]
    Corrupt(String),
    #[error("insecure secret store: {0}")]
    InsecureStore(String),
    #[error("invalid secret name: {0}")]
    InvalidName(String),
    #[error("secret not found: {0}")]
    NotFound(SecretName),
    #[error("secret value exceeds {maximum} bytes")]
    ValueTooLarge { maximum: usize },
    #[error("secret store I/O failed during {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("keychain operation failed with status {0}")]
    Keychain(i32),
    #[error("migration requires explicit user authorization")]
    MigrationNotAuthorized,
}

impl SecretStoreError {
    #[cfg(target_os = "linux")]
    pub(crate) fn io(operation: &'static str, source: io::Error) -> Self {
        if source.kind() == io::ErrorKind::PermissionDenied {
            Self::AccessDenied
        } else {
            Self::Io { operation, source }
        }
    }
}
