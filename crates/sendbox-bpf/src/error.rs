use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    Unavailable,
    PermissionDenied,
    RelocationFailure,
    LoadFailure,
    AttachFailure,
    DecodeFailure,
    Timeout,
    UnsupportedHost,
    InvalidInput,
    Internal,
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("{stage}: {message}")]
pub struct BpfError {
    pub kind: DiagnosticKind,
    pub stage: &'static str,
    pub message: String,
    pub action: String,
}

impl BpfError {
    pub fn new(
        kind: DiagnosticKind,
        stage: &'static str,
        message: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            stage,
            message: message.into(),
            action: action.into(),
        }
    }
}
