use std::fmt;

use serde::Serialize;

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

#[derive(Debug, Eq, PartialEq)]
pub struct SpikeError {
    pub kind: DiagnosticKind,
    pub stage: &'static str,
    pub message: String,
    pub action: String,
}

impl SpikeError {
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

    pub fn report(&self) -> DiagnosticReport<'_> {
        DiagnosticReport {
            schema_version: 1,
            status: "error",
            kind: self.kind,
            stage: self.stage,
            message: &self.message,
            action: &self.action,
        }
    }
}

impl fmt::Display for SpikeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.stage, self.message)
    }
}

impl std::error::Error for SpikeError {}

#[derive(Serialize)]
pub struct DiagnosticReport<'a> {
    pub schema_version: u8,
    pub status: &'static str,
    pub kind: DiagnosticKind,
    pub stage: &'static str,
    pub message: &'a str,
    pub action: &'a str,
}
