use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuestError {
    #[error("invalid bootstrap material: {0}")]
    Bootstrap(String),
    #[error("bootstrap material was already consumed")]
    BootstrapConsumed,
    #[error("bootstrap material exceeds the {0}-byte limit")]
    BootstrapTooLarge(usize),
    #[error("artifact manifest is invalid: {0}")]
    Manifest(String),
    #[error("artifact verification failed for {path}: {detail}")]
    Artifact { path: String, detail: String },
    #[error("runtime state is invalid: {0}")]
    Runtime(String),
    #[error("startup state transition from {from} to {to} is not allowed")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("required platform control {0} was not verified")]
    ControlNotVerified(String),
    #[error("service configuration is invalid: {0}")]
    ServiceConfig(String),
    #[error("service {service} failed: {detail}")]
    Service { service: String, detail: String },
    #[error("protocol failed: {0}")]
    Protocol(String),
    #[error("I/O failed while {context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
}

impl GuestError {
    pub fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io { context, source }
    }
}

impl From<sendbox_protocol::ProtocolError> for GuestError {
    fn from(error: sendbox_protocol::ProtocolError) -> Self {
        Self::Protocol(error.to_string())
    }
}
