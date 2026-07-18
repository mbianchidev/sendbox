#![forbid(unsafe_code)]

pub mod diagnostic;
pub mod event;
pub mod loader;
pub mod preflight;

use serde::Serialize;

pub fn deterministic_json<T: Serialize>(value: &T) -> Result<String, diagnostic::SpikeError> {
    serde_json::to_string(value).map_err(|error| {
        diagnostic::SpikeError::new(
            diagnostic::DiagnosticKind::Internal,
            "json",
            format!("failed to serialize deterministic JSON: {error}"),
            "report this serialization failure",
        )
    })
}
