use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("Git guard policy is invalid: {0}")]
    InvalidPolicy(String),
    #[error("Git invocation is invalid: {0}")]
    InvalidInvocation(String),
    #[error("Git {operation} denied: {reason}")]
    Denied {
        operation: &'static str,
        reason: String,
    },
    #[error("Git repository identity is unsupported or ambiguous")]
    AmbiguousRepository,
    #[error("Git repository state could not be resolved safely: {0}")]
    UnresolvedState(String),
    #[error("trusted Git binary `{path}` is invalid: {reason}")]
    InvalidGitBinary { path: PathBuf, reason: String },
    #[error("Git guard policy file `{path}` is invalid: {reason}")]
    InvalidPolicyFile { path: PathBuf, reason: String },
    #[error("Git probe timed out")]
    ProbeTimeout,
    #[error("Git probe output exceeded the configured limit")]
    ProbeOutputLimit,
    #[error("Git process failed: {0}")]
    Process(#[from] io::Error),
}

impl GuardError {
    pub(crate) fn denied(operation: crate::Operation, reason: impl Into<String>) -> Self {
        Self::Denied {
            operation: operation.as_str(),
            reason: reason.into(),
        }
    }
}
