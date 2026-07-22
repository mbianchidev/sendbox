use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FrameError {
    #[error("MCP frame exceeds configured maximum of {max} bytes")]
    FrameTooLarge { max: usize },
    #[error("MCP Content-Length header exceeds configured maximum of {max} bytes")]
    HeaderTooLarge { max: usize },
    #[error("MCP Content-Length framing has an invalid header: {0}")]
    InvalidHeader(String),
    #[error("MCP stream ended with an incomplete frame")]
    IncompleteFrame,
    #[error("MCP framing mode could not be determined")]
    UndeterminedMode,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JsonRpcError {
    #[error("MCP frame is not valid UTF-8")]
    InvalidUtf8,
    #[error("MCP frame is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("MCP JSON-RPC batches are not supported")]
    BatchUnsupported,
    #[error("MCP JSON-RPC message must be an object")]
    NotObject,
    #[error("MCP JSON-RPC version must be exactly 2.0")]
    InvalidVersion,
    #[error("MCP JSON-RPC message has an invalid shape: {0}")]
    InvalidShape(String),
    #[error("MCP JSON-RPC id must be a string, null, or an integer")]
    InvalidId,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read MCP configuration {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid MCP JSON configuration {path}: {message}")]
    InvalidJson { path: PathBuf, message: String },
    #[error("invalid MCP server '{server}' in {path}: {message}")]
    InvalidServer {
        path: PathBuf,
        server: String,
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("MCP command is not exactly approved")]
    CommandNotApproved,
    #[error("MCP process launch failed: {0}")]
    Launch(String),
    #[error("MCP process I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    JsonRpc(#[from] JsonRpcError),
    #[error("MCP tool policy rejected malformed request: {0}")]
    Policy(String),
    #[error("MCP client disconnected")]
    ClientDisconnected,
    #[error("MCP output remained saturated past the configured deadline")]
    OutputSaturated,
    #[error("MCP broker was cancelled")]
    Cancelled,
    #[error("MCP child exited before the client stream completed")]
    ChildExited,
    #[error("MCP child cleanup failed: {0}")]
    Cleanup(String),
    #[error("MCP task failed: {0}")]
    Task(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ObservationError {
    #[error("invalid MCP observation event: {0}")]
    InvalidEvent(String),
    #[error(transparent)]
    JsonRpc(#[from] JsonRpcError),
}
