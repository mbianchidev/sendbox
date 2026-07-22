#![forbid(unsafe_code)]

mod cancellation;
mod capability;
mod channel;
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
pub use channel::{
    BootstrapDelivery, BootstrapMaterial, ChannelLifetime, ChannelOwnership, ControlChannelRequest,
    ControlEndpointKind, ControlStream, GuestAddress, HostAddress, MAX_READINESS_TIMEOUT,
    MIN_BOOTSTRAP_BYTES, MIN_READINESS_TIMEOUT, ProvisionedControlChannel,
    ProvisionedControlChannelDescriptor,
};
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
    BoxFuture, CreateRequest, ExecPurpose, ExecRequest, InitializeRequest, PreflightReport,
    PreflightRequest, RuntimeEnvironment, RuntimeHealth, RuntimeLabel, RuntimeMount,
    RuntimeProvider, RuntimeResources, RuntimeSignal, RuntimeStatus, StartRequest, StopRequest,
};
pub use unavailable::UnavailableRuntimeProvider;
