use std::{error::Error, fmt};

use sendbox_protocol::ProtocolError;
use sendbox_runtime::RuntimeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("configuration validation failed: {0}")]
    Configuration(String),
    #[error("run plan is invalid: {0}")]
    InvalidPlan(String),
    #[error("runtime capability validation failed: {0}")]
    RuntimeCapabilities(String),
    #[error("runtime operation failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("guest protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("guest service failed: {0}")]
    Guest(String),
    #[error("secret resolution failed for `{reference}`: {message}")]
    Secret { reference: String, message: String },
    #[error("output delivery failed: {0}")]
    Output(String),
    #[error("agent run was cancelled")]
    Cancelled,
    #[error("guest readiness timed out")]
    ReadinessTimedOut,
    #[error("cleanup failed after successful execution")]
    CleanupAfterSuccess,
}

#[derive(Debug)]
pub struct CleanupFailure {
    pub step: &'static str,
    pub error: AgentError,
}

#[derive(Debug)]
pub struct RunFailure {
    pub primary: AgentError,
    pub cleanup: Vec<CleanupFailure>,
}

impl fmt::Display for RunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.primary)?;
        if !self.cleanup.is_empty() {
            write!(
                formatter,
                " ({} cleanup operation(s) failed)",
                self.cleanup.len()
            )?;
        }
        Ok(())
    }
}

impl Error for RunFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}
