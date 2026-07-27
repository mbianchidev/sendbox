use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialBrokerError {
    #[error("credential broker configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("credential broker request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("credential broker request timed out")]
    RequestTimeout,
    #[error("credential broker request was cancelled")]
    Cancelled,
    #[error("credential broker I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("credential policy rejected the request: {0}")]
    Policy(#[from] sendbox_secrets::CredentialPolicyError),
    #[error("credential secret lookup failed: {0}")]
    Secret(#[from] sendbox_secrets::SecretStoreError),
    #[error("upstream request failed: {0}")]
    Upstream(String),
    #[error("GitHub metadata is invalid: {0}")]
    InvalidGitHubMetadata(String),
    #[error("GitHub command failed: {0}")]
    GitHubCommand(String),
    #[error("GitHub repository credentials are not authorized: {0}")]
    GitHubAuthorization(String),
    #[error("runtime process failed: {0}")]
    Runtime(#[from] sendbox_runtime::RuntimeError),
}
