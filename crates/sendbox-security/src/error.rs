use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{operation} failed for {path}: {primary}; cleanup also failed: {cleanup}")]
    Cleanup {
        operation: &'static str,
        path: PathBuf,
        primary: String,
        cleanup: String,
    },
    #[error("invalid relative path {0}")]
    InvalidPath(PathBuf),
    #[error("unsupported file type at {0}")]
    UnsupportedFileType(PathBuf),
    #[error("file owner mismatch at {path}: expected uid {expected}, found {actual}")]
    OwnerMismatch {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("size limit exceeded for {path}: limit {limit} bytes")]
    SizeLimit { path: PathBuf, limit: u64 },
    #[error("unsupported persisted format {format} version {version}")]
    UnsupportedVersion { format: &'static str, version: u16 },
    #[error("malformed {format}: {detail}")]
    Malformed {
        format: &'static str,
        detail: String,
    },
    #[error("integrity verification failed: {0}")]
    Integrity(String),
    #[error("policy verification failed: {0}")]
    Policy(String),
    #[error("platform does not support secure descriptor-relative persistence")]
    UnsupportedPlatform,
}

pub type SecurityResult<T> = Result<T, SecurityError>;

pub(crate) fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> SecurityError {
    SecurityError::Io {
        operation,
        path: path.into(),
        source,
    }
}
