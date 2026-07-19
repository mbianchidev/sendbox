use std::{future::Future, path::PathBuf, pin::Pin, time::Duration};

use crate::{
    CancellationToken, CommandSpec, ContainerId, LifecycleState, OutputSubscription,
    ProcessOutcome, RuntimeCapabilities, RuntimeError, RuntimeId,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct InitializeRequest {
    pub state_directory: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct PreflightRequest {
    pub required_capabilities: RuntimeCapabilities,
}

#[derive(Debug, Clone)]
pub struct PreflightReport {
    pub available_capabilities: RuntimeCapabilities,
    pub missing_capabilities: RuntimeCapabilities,
}

impl PreflightReport {
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.missing_capabilities.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct CreateRequest {
    pub container_id: ContainerId,
    pub image: String,
}

#[derive(Debug, Clone, Default)]
pub struct StartRequest {
    pub attach_standard_streams: bool,
}

#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub command: CommandSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSignal {
    Interrupt,
    Terminate,
    Kill,
    Hangup,
    User1,
    User2,
}

#[derive(Debug, Clone, Copy)]
pub struct StopRequest {
    pub grace: Duration,
}

impl Default for StopRequest {
    fn default() -> Self {
        Self {
            grace: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHealth {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub lifecycle: LifecycleState,
    pub health: RuntimeHealth,
}

/// Object-safe asynchronous contract implemented by runtime adapters.
///
/// Implementations are `Send + Sync`, and callers may invoke methods concurrently
/// for different containers. Calls that mutate the same container must be
/// serialized or rejected by the implementation; they must never observe a
/// partially applied lifecycle transition. `status`, `capabilities`, and output
/// consumption may run concurrently with lifecycle operations. Every asynchronous
/// operation receives an explicit cancellation token. Dropping its future is not
/// a successful operation and implementations must use compensation cleanup for
/// resources created before the drop.
pub trait RuntimeProvider: Send + Sync {
    fn runtime_id(&self) -> &RuntimeId;

    fn capabilities(&self) -> RuntimeCapabilities;

    fn initialize<'a>(
        &'a self,
        request: InitializeRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>>;

    fn preflight<'a>(
        &'a self,
        request: PreflightRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<PreflightReport, RuntimeError>>;

    fn create<'a>(
        &'a self,
        request: CreateRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ContainerId, RuntimeError>>;

    fn start<'a>(
        &'a self,
        container: &'a ContainerId,
        request: StartRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>>;

    fn status<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<RuntimeStatus, RuntimeError>>;

    fn exec<'a>(
        &'a self,
        container: &'a ContainerId,
        request: ExecRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ProcessOutcome, RuntimeError>>;

    fn attach<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn OutputSubscription>, RuntimeError>>;

    fn signal<'a>(
        &'a self,
        container: &'a ContainerId,
        signal: RuntimeSignal,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>>;

    fn stop<'a>(
        &'a self,
        container: &'a ContainerId,
        request: StopRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>>;

    fn cleanup<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<CleanupReport, RuntimeError>>;
}

use crate::CleanupReport;
