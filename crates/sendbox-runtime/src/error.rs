use std::{fmt, io, path::PathBuf};

use thiserror::Error;

use crate::{ControlEndpointKind, LifecycleState, RuntimeId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierKind {
    Runtime,
    Container,
}

impl fmt::Display for IdentifierKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime => formatter.write_str("runtime"),
            Self::Container => formatter.write_str("container"),
        }
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("invalid {kind} identifier `{value}`: {reason}")]
    InvalidIdentifier {
        kind: IdentifierKind,
        value: String,
        reason: &'static str,
    },
    #[error("runtime `{runtime}` is unavailable: {reason}")]
    Unavailable { runtime: RuntimeId, reason: String },
    #[error("operation was cancelled")]
    Cancelled,
    #[error("runtime operation timed out")]
    TimedOut,
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: LifecycleState,
        to: LifecycleState,
    },
    #[error("duplicate lifecycle transition to {state:?}")]
    DuplicateTransition { state: LifecycleState },
    #[error("required runtime capabilities are unavailable: {missing}")]
    MissingCapabilities { missing: String },
    #[error("invalid control channel request: {reason}")]
    InvalidControlChannel { reason: String },
    #[error("control transport {endpoint:?} is unavailable: {reason}")]
    TransportUnavailable {
        endpoint: ControlEndpointKind,
        reason: String,
    },
    #[error("the provisioned control channel has already accepted its stream")]
    ControlChannelAlreadyAccepted,
    #[error("runtime exec is restricted to bootstrap and control operations")]
    WorkloadExecRequiresGuestBroker,
    #[error("invalid command: {reason}")]
    InvalidCommand { reason: String },
    #[error("program `{name}` could not be resolved")]
    ProgramNotFound { name: String },
    #[error("program resolver returned non-absolute path `{path}` for `{name}`")]
    ResolverReturnedRelative { name: String, path: PathBuf },
    #[error("invalid working directory `{path}`: {reason}")]
    InvalidWorkingDirectory { path: PathBuf, reason: String },
    #[error("failed to inspect working directory `{path}`: {source}")]
    WorkingDirectoryIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to spawn {diagnostic}: {source}")]
    Spawn {
        diagnostic: String,
        #[source]
        source: io::Error,
    },
    #[error("process I/O failed for {stream}: {source}")]
    ProcessIo {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to wait for process: {0}")]
    Wait(#[source] io::Error),
    #[error("process task failed: {0}")]
    ProcessTask(String),
    #[error("signal {signal} is unsupported on this platform")]
    UnsupportedSignal { signal: String },
    #[error("process group handling is unsupported on this platform")]
    UnsupportedProcessGroup,
    #[error("failed to signal process group {process_group} with {signal}: {source}")]
    Signal {
        process_group: i32,
        signal: String,
        #[source]
        source: io::Error,
    },
    #[error("output sequence space was exhausted")]
    OutputSequenceExhausted,
    #[error("injected failure in `{operation}`: {message}")]
    Injected { operation: String, message: String },
    #[error("{0}")]
    Provider(String),
}
