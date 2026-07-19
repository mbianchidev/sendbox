#![forbid(unsafe_code)]

mod cancellation;
mod capability;
mod cleanup;
mod clock;
mod error;
mod id;
mod lifecycle;
mod output;
mod process;
mod provider;
mod unavailable;

pub use cancellation::CancellationToken;
pub use capability::{RuntimeCapabilities, RuntimeCapability};
pub use cleanup::{
    CleanupFailure, CleanupReport, CleanupStep, CleanupTransaction, OperationFailure,
};
pub use clock::{Clock, MonotonicTime, SystemClock};
pub use error::{IdentifierKind, RuntimeError};
pub use id::{ContainerId, RuntimeId};
pub use lifecycle::{LifecycleState, LifecycleStateMachine, LifecycleTransitionError};
pub use output::{
    OutputEvent, OutputLoss, OutputStats, OutputStream, OutputSubscription, VecOutputSubscription,
};
pub use process::{
    CapturedOutput, CommandArgument, CommandSpec, EnvironmentVariable, ExitStatus, ProcessOptions,
    ProcessOutcome, ProcessRunner, ProcessSignal, Program, ProgramResolver, RunningProcess,
    SearchPathResolver, TerminationReason,
};
pub use provider::{
    BoxFuture, CreateRequest, ExecRequest, InitializeRequest, PreflightReport, PreflightRequest,
    RuntimeHealth, RuntimeProvider, RuntimeSignal, RuntimeStatus, StartRequest, StopRequest,
};
pub use unavailable::UnavailableRuntimeProvider;
