#![forbid(unsafe_code)]

mod error;
mod orchestrator;
mod plan;
mod protocol;
mod traits;

pub use error::{AgentError, CleanupFailure, RunFailure};
pub use orchestrator::{AgentOrchestrator, AgentReport, AgentState};
pub use plan::{
    AgentRequest, EnvironmentIntent, GuestCommand, MountIntent, RunPlan, SecretReference,
    WorkspaceIntent,
};
pub use protocol::{ProtocolGuestConnector, ProtocolGuestExecution, ProtocolGuestSession};
pub use traits::{
    AgentSignal, BoxFuture, GuestConnectionConfiguration, GuestConnector, GuestEvent,
    GuestExecution, GuestLaunchRequest, GuestSecretEnvelope, GuestSession, GuestTerminal,
    NoSignals, OutputSink, SecretEnvelope, SecretResolver, SignalSource,
};
