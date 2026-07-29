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
    AgentSignal, BoxFuture, CollectedSafeOutputs, GuestConnectionConfiguration, GuestConnector,
    GuestEvent, GuestExecution, GuestLaunchRequest, GuestPackageReport, GuestSecretEnvelope,
    GuestSession, GuestTerminal, GuestTerminalSize, HostTerminalCommand, NoSignals, NoTerminal,
    OutputSink, SecretEnvelope, SecretResolver, SignalSource, TerminalSource,
};
