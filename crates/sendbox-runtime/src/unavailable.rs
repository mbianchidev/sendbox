use crate::{
    BoxFuture, CancellationToken, CleanupReport, ContainerId, CreateRequest, ExecRequest,
    InitializeRequest, OutputSubscription, PreflightReport, PreflightRequest, ProcessOutcome,
    RuntimeCapabilities, RuntimeError, RuntimeId, RuntimeProvider, RuntimeSignal, RuntimeStatus,
    StartRequest, StopRequest,
};

#[derive(Debug)]
pub struct UnavailableRuntimeProvider {
    runtime_id: RuntimeId,
    reason: String,
}

impl UnavailableRuntimeProvider {
    #[must_use]
    pub fn new(runtime_id: RuntimeId, reason: impl Into<String>) -> Self {
        Self {
            runtime_id,
            reason: reason.into(),
        }
    }

    fn error(&self) -> RuntimeError {
        RuntimeError::Unavailable {
            runtime: self.runtime_id.clone(),
            reason: self.reason.clone(),
        }
    }
}

impl RuntimeProvider for UnavailableRuntimeProvider {
    fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::default()
    }

    fn initialize<'a>(
        &'a self,
        _request: InitializeRequest,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }

    fn preflight<'a>(
        &'a self,
        _request: PreflightRequest,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<PreflightReport, RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }

    fn create<'a>(
        &'a self,
        _request: CreateRequest,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ContainerId, RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }

    fn start<'a>(
        &'a self,
        _container: &'a ContainerId,
        _request: StartRequest,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }

    fn status<'a>(
        &'a self,
        _container: &'a ContainerId,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<RuntimeStatus, RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }

    fn exec<'a>(
        &'a self,
        _container: &'a ContainerId,
        _request: ExecRequest,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ProcessOutcome, RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }

    fn attach<'a>(
        &'a self,
        _container: &'a ContainerId,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn OutputSubscription>, RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }

    fn signal<'a>(
        &'a self,
        _container: &'a ContainerId,
        _signal: RuntimeSignal,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }

    fn stop<'a>(
        &'a self,
        _container: &'a ContainerId,
        _request: StopRequest,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }

    fn cleanup<'a>(
        &'a self,
        _container: &'a ContainerId,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<CleanupReport, RuntimeError>> {
        let error = self.error();
        Box::pin(async move { Err(error) })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        CancellationToken, InitializeRequest, RuntimeId, RuntimeProvider,
        UnavailableRuntimeProvider,
    };

    #[tokio::test]
    async fn unavailable_provider_has_no_capabilities_and_structured_errors() {
        let provider = UnavailableRuntimeProvider::new(
            RuntimeId::new("not-installed").expect("runtime ID"),
            "runtime executable is not installed",
        );
        assert!(provider.capabilities().is_empty());
        let error = provider
            .initialize(
                InitializeRequest {
                    state_directory: PathBuf::from("."),
                },
                &CancellationToken::new(),
            )
            .await
            .expect_err("unavailable");
        assert!(matches!(error, crate::RuntimeError::Unavailable { .. }));
    }
}
