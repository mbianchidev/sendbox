#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, VecDeque},
    fmt, fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use sendbox_runtime::{
    BoxFuture, CancellationToken, CleanupReport, Clock, CommandArgument, CommandSpec, ContainerId,
    ControlChannelRequest, ControlEndpointKind, ControlStream, CreateRequest, ExecPurpose,
    ExecRequest, GuestAddress, HostAddress, InitializeRequest, LifecycleState,
    LifecycleStateMachine, LifecycleTransitionError, MonotonicTime, OutputEvent, OutputStream,
    OutputSubscription, PreflightReport, PreflightRequest, ProcessOutcome, Program,
    ProvisionedControlChannel, ProvisionedControlChannelDescriptor, RuntimeCapabilities,
    RuntimeCapability, RuntimeError, RuntimeHealth, RuntimeId, RuntimeProvider, RuntimeSignal,
    RuntimeStatus, StartRequest, StopRequest, VecOutputSubscription,
};
use tempfile::TempDir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCommand {
    pub operation: String,
    pub container: Option<ContainerId>,
}

#[derive(Debug, Clone, Default)]
pub struct CommandRecorder {
    commands: Arc<Mutex<Vec<RecordedCommand>>>,
}

impl CommandRecorder {
    pub fn record(&self, operation: impl Into<String>, container: Option<ContainerId>) {
        self.commands
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(RecordedCommand {
                operation: operation.into(),
                container,
            });
    }

    #[must_use]
    pub fn commands(&self) -> Vec<RecordedCommand> {
        self.commands
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
}

#[derive(Debug, Clone, Default)]
pub struct FailureInjector {
    failures: Arc<Mutex<BTreeMap<String, VecDeque<String>>>>,
}

impl FailureInjector {
    pub fn fail_next(&self, operation: impl Into<String>, message: impl Into<String>) {
        self.failures
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .entry(operation.into())
            .or_default()
            .push_back(message.into());
    }

    pub fn check(&self, operation: &str) -> Result<(), RuntimeError> {
        let message = self
            .failures
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get_mut(operation)
            .and_then(VecDeque::pop_front);
        match message {
            Some(message) => Err(RuntimeError::Injected {
                operation: operation.to_owned(),
                message,
            }),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Default)]
pub struct ManualClock {
    nanos: AtomicU64,
}

impl ManualClock {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nanos: AtomicU64::new(0),
        }
    }

    pub fn advance(&self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let _ = self
            .nanos
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(nanos))
            });
    }

    pub fn set(&self, time: MonotonicTime) {
        let nanos = u64::try_from(time.as_duration().as_nanos()).unwrap_or(u64::MAX);
        self.nanos.store(nanos, Ordering::Release);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::from_duration(Duration::from_nanos(self.nanos.load(Ordering::Acquire)))
    }
}

#[derive(Debug)]
pub struct TempResource {
    directory: TempDir,
}

impl TempResource {
    pub fn new() -> Result<Self, std::io::Error> {
        tempfile::Builder::new()
            .prefix("sendbox-test-")
            .tempdir()
            .map(|directory| Self { directory })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    pub fn create_directory(&self, relative: impl AsRef<Path>) -> Result<PathBuf, std::io::Error> {
        let path = self.path().join(relative);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    pub fn create_file(
        &self,
        relative: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
    ) -> Result<PathBuf, std::io::Error> {
        let path = self.path().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, contents)?;
        Ok(path)
    }
}

pub struct FakeRuntime {
    runtime_id: RuntimeId,
    capabilities: RuntimeCapabilities,
    lifecycle: LifecycleStateMachine,
    container: Mutex<Option<ContainerId>>,
    created_container: Mutex<Option<ContainerId>>,
    recorder: CommandRecorder,
    failures: FailureInjector,
    control_stream: Mutex<Option<Box<dyn ControlStream>>>,
}

impl fmt::Debug for FakeRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeRuntime")
            .field("runtime_id", &self.runtime_id)
            .field("capabilities", &self.capabilities)
            .field("lifecycle", &self.lifecycle)
            .finish_non_exhaustive()
    }
}

impl FakeRuntime {
    pub fn new(capabilities: RuntimeCapabilities) -> Result<Self, RuntimeError> {
        Ok(Self {
            runtime_id: RuntimeId::new("fake-runtime")?,
            capabilities,
            lifecycle: LifecycleStateMachine::default(),
            container: Mutex::new(None),
            created_container: Mutex::new(None),
            recorder: CommandRecorder::default(),
            failures: FailureInjector::default(),
            control_stream: Mutex::new(None),
        })
    }

    #[must_use]
    pub fn recorder(&self) -> CommandRecorder {
        self.recorder.clone()
    }

    #[must_use]
    pub fn failure_injector(&self) -> FailureInjector {
        self.failures.clone()
    }

    pub fn set_control_stream(&self, stream: Box<dyn ControlStream>) {
        *self
            .control_stream
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(stream);
    }

    pub fn set_created_container_id(&self, container: ContainerId) {
        *self
            .created_container
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(container);
    }

    fn before(
        &self,
        operation: &str,
        container: Option<&ContainerId>,
        cancellation: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        if cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        self.recorder.record(operation, container.cloned());
        self.failures.check(operation)
    }

    fn transition(&self, next: LifecycleState) -> Result<(), RuntimeError> {
        self.lifecycle
            .transition(next)
            .map(|_| ())
            .map_err(transition_error)
    }

    fn ensure_container(&self, container: &ContainerId) -> Result<(), RuntimeError> {
        let stored = self
            .container
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if stored.as_ref() == Some(container) {
            Ok(())
        } else {
            Err(RuntimeError::Provider(format!(
                "unknown fake container `{container}`"
            )))
        }
    }
}

impl RuntimeProvider for FakeRuntime {
    fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        self.capabilities.clone()
    }

    fn initialize<'a>(
        &'a self,
        _request: InitializeRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            self.before("initialize", None, cancellation)?;
            self.transition(LifecycleState::Initialized)
        })
    }

    fn preflight<'a>(
        &'a self,
        request: PreflightRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<PreflightReport, RuntimeError>> {
        Box::pin(async move {
            self.before("preflight", None, cancellation)?;
            Ok(PreflightReport {
                available_capabilities: self.capabilities.clone(),
                missing_capabilities: request
                    .required_capabilities
                    .missing_from(&self.capabilities),
            })
        })
    }

    fn create<'a>(
        &'a self,
        request: CreateRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ContainerId, RuntimeError>> {
        Box::pin(async move {
            self.before("create", Some(&request.container_id), cancellation)?;
            if request.image.is_empty() {
                return Err(RuntimeError::Provider(
                    "fake runtime image must not be empty".to_owned(),
                ));
            }
            self.transition(LifecycleState::Created)?;
            let container = self
                .created_container
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take()
                .unwrap_or(request.container_id);
            *self
                .container
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(container.clone());
            Ok(container)
        })
    }

    fn start<'a>(
        &'a self,
        container: &'a ContainerId,
        _request: StartRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            self.before("start", Some(container), cancellation)?;
            self.ensure_container(container)?;
            self.transition(LifecycleState::Running)
        })
    }

    fn provision_control_channel<'a>(
        &'a self,
        request: ControlChannelRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ProvisionedControlChannel>, RuntimeError>> {
        Box::pin(async move {
            self.before(
                "provision_control_channel",
                Some(&request.container_id),
                cancellation,
            )?;
            self.ensure_container(&request.container_id)?;
            request.validate()?;
            let required = transport_capability(request.endpoint_kind);
            if !self
                .capabilities
                .contains(RuntimeCapability::TransportProvisioning)
                || !self.capabilities.contains(required)
            {
                return Err(RuntimeError::TransportUnavailable {
                    endpoint: request.endpoint_kind,
                    reason: "fake runtime does not advertise the requested transport".to_owned(),
                });
            }
            let stream = self
                .control_stream
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take()
                .ok_or_else(|| {
                    RuntimeError::Provider("no fake control stream configured".to_owned())
                })?;
            let descriptor = fake_descriptor(&request)?;
            Ok(Box::new(FakeProvisionedControlChannel {
                descriptor,
                stream: Some(stream),
                cleaned: false,
                recorder: self.recorder.clone(),
                failures: self.failures.clone(),
                container: request.container_id,
            }) as Box<dyn ProvisionedControlChannel>)
        })
    }

    fn status<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<RuntimeStatus, RuntimeError>> {
        Box::pin(async move {
            self.before("status", Some(container), cancellation)?;
            self.ensure_container(container)?;
            Ok(RuntimeStatus {
                lifecycle: self.lifecycle.current(),
                health: RuntimeHealth::Healthy,
            })
        })
    }

    fn exec<'a>(
        &'a self,
        container: &'a ContainerId,
        request: ExecRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ProcessOutcome, RuntimeError>> {
        Box::pin(async move {
            self.before("exec", Some(container), cancellation)?;
            self.ensure_container(container)?;
            if request.purpose == ExecPurpose::Workload {
                return Err(RuntimeError::WorkloadExecRequiresGuestBroker);
            }
            if self.lifecycle.current() != LifecycleState::Running {
                return Err(RuntimeError::Provider(
                    "fake runtime is not running".to_owned(),
                ));
            }
            Ok(ProcessOutcome::successful(
                b"fake stdout\n".to_vec(),
                Vec::new(),
            ))
        })
    }

    fn attach<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn OutputSubscription>, RuntimeError>> {
        Box::pin(async move {
            self.before("attach", Some(container), cancellation)?;
            self.ensure_container(container)?;
            let subscription = VecOutputSubscription::new([OutputEvent::Data {
                stream: OutputStream::Stdout,
                global_sequence: 1,
                stream_sequence: 1,
                bytes: b"fake attached output\n".to_vec(),
                dropped_before: None,
            }]);
            Ok(Box::new(subscription) as Box<dyn OutputSubscription>)
        })
    }

    fn signal<'a>(
        &'a self,
        container: &'a ContainerId,
        _signal: RuntimeSignal,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            self.before("signal", Some(container), cancellation)?;
            self.ensure_container(container)
        })
    }

    fn stop<'a>(
        &'a self,
        container: &'a ContainerId,
        _request: StopRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            self.before("stop", Some(container), cancellation)?;
            self.ensure_container(container)?;
            self.transition(LifecycleState::Stopped)
        })
    }

    fn cleanup<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<CleanupReport, RuntimeError>> {
        Box::pin(async move {
            self.before("cleanup", Some(container), cancellation)?;
            self.ensure_container(container)?;
            if self.lifecycle.current() == LifecycleState::Cleaned {
                return Ok(CleanupReport::default());
            }
            if self.lifecycle.current() != LifecycleState::Cleaning {
                self.transition(LifecycleState::Cleaning)?;
            }
            self.transition(LifecycleState::Cleaned)?;
            Ok(CleanupReport::default())
        })
    }
}

fn transport_capability(kind: ControlEndpointKind) -> RuntimeCapability {
    match kind {
        ControlEndpointKind::Vsock => RuntimeCapability::VsockControlChannel,
        ControlEndpointKind::PublishedUnixSocket => RuntimeCapability::PublishedUnixControlChannel,
        ControlEndpointKind::InheritedStdio => RuntimeCapability::InheritedStdioControlChannel,
        ControlEndpointKind::InheritedFileDescriptor => {
            RuntimeCapability::InheritedFileDescriptorControlChannel
        }
        ControlEndpointKind::RuntimeExecStdio => RuntimeCapability::RuntimeExecStdioControlChannel,
        ControlEndpointKind::Unavailable => RuntimeCapability::TransportProvisioning,
    }
}

fn fake_descriptor(
    request: &ControlChannelRequest,
) -> Result<ProvisionedControlChannelDescriptor, RuntimeError> {
    let (host_address, guest_address) = match request.endpoint_kind {
        ControlEndpointKind::Vsock => (
            HostAddress::Vsock { cid: 2, port: 7000 },
            GuestAddress::Vsock { cid: 3, port: 7000 },
        ),
        ControlEndpointKind::PublishedUnixSocket => (
            HostAddress::UnixSocket(PathBuf::from("/tmp/sendbox-fake.sock")),
            GuestAddress::UnixSocket(PathBuf::from("/run/sendbox/control.sock")),
        ),
        ControlEndpointKind::InheritedStdio => (HostAddress::Stdio, GuestAddress::Stdio),
        ControlEndpointKind::InheritedFileDescriptor => (
            HostAddress::FileDescriptor(3),
            GuestAddress::FileDescriptor(3),
        ),
        ControlEndpointKind::RuntimeExecStdio => (
            HostAddress::Stdio,
            GuestAddress::RuntimeDefined("fake-runtime-exec-stdio".to_owned()),
        ),
        ControlEndpointKind::Unavailable => {
            return Err(RuntimeError::TransportUnavailable {
                endpoint: request.endpoint_kind,
                reason: "unavailable endpoint has no descriptor".to_owned(),
            });
        }
    };
    Ok(ProvisionedControlChannelDescriptor {
        endpoint_kind: request.endpoint_kind,
        host_address,
        guest_address,
        ownership: request.ownership,
        lifetime: request.lifetime,
    })
}

struct FakeProvisionedControlChannel {
    descriptor: ProvisionedControlChannelDescriptor,
    stream: Option<Box<dyn ControlStream>>,
    cleaned: bool,
    recorder: CommandRecorder,
    failures: FailureInjector,
    container: ContainerId,
}

impl ProvisionedControlChannel for FakeProvisionedControlChannel {
    fn descriptor(&self) -> &ProvisionedControlChannelDescriptor {
        &self.descriptor
    }

    fn accept<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ControlStream>, RuntimeError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            self.recorder
                .record("accept_control_channel", Some(self.container.clone()));
            self.failures.check("accept_control_channel")?;
            self.stream
                .take()
                .ok_or(RuntimeError::ControlChannelAlreadyAccepted)
        })
    }

    fn cleanup<'a>(
        &'a mut self,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            if self.cleaned {
                return Ok(());
            }
            self.recorder
                .record("cleanup_control_channel", Some(self.container.clone()));
            self.failures.check("cleanup_control_channel")?;
            self.stream.take();
            self.cleaned = true;
            Ok(())
        })
    }
}

fn transition_error(error: LifecycleTransitionError) -> RuntimeError {
    match error {
        LifecycleTransitionError::Duplicate { state } => {
            RuntimeError::DuplicateTransition { state }
        }
        LifecycleTransitionError::Invalid { from, to } => {
            RuntimeError::InvalidTransition { from, to }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConformanceScenario {
    pub initialize: InitializeRequest,
    pub create: CreateRequest,
    pub start: StartRequest,
    pub exec: ExecRequest,
    pub signal: Option<RuntimeSignal>,
}

pub async fn run_runtime_conformance(
    provider: &dyn RuntimeProvider,
    scenario: RuntimeConformanceScenario,
) -> Result<(), RuntimeError> {
    let cancellation = CancellationToken::new();
    provider
        .initialize(scenario.initialize, &cancellation)
        .await?;
    let capabilities = provider.capabilities();
    let preflight = provider
        .preflight(
            PreflightRequest {
                required_capabilities: capabilities.clone(),
            },
            &cancellation,
        )
        .await?;
    if !preflight.is_compatible() {
        return Err(RuntimeError::Provider(
            "provider rejected its own advertised capabilities".to_owned(),
        ));
    }

    let container = provider.create(scenario.create, &cancellation).await?;
    provider
        .start(&container, scenario.start, &cancellation)
        .await?;
    let status = provider.status(&container, &cancellation).await?;
    if status.lifecycle != LifecycleState::Running {
        return Err(RuntimeError::Provider(format!(
            "provider reported {:?} after start",
            status.lifecycle
        )));
    }
    if capabilities.contains(RuntimeCapability::Exec) {
        let outcome = provider
            .exec(&container, scenario.exec, &cancellation)
            .await?;
        if !outcome.status.success {
            return Err(RuntimeError::Provider(
                "conformance exec did not succeed".to_owned(),
            ));
        }
    }
    if capabilities.contains(RuntimeCapability::StreamedIo) {
        let mut subscription = provider.attach(&container, &cancellation).await?;
        let _ = subscription.next(&cancellation).await?;
    }
    if capabilities.contains(RuntimeCapability::Signals)
        && let Some(signal) = scenario.signal
    {
        provider.signal(&container, signal, &cancellation).await?;
    }
    provider
        .stop(&container, StopRequest::default(), &cancellation)
        .await?;
    let cleanup = provider.cleanup(&container, &cancellation).await?;
    if !cleanup.is_complete() {
        return Err(RuntimeError::Provider(
            "provider cleanup did not complete".to_owned(),
        ));
    }
    Ok(())
}

pub fn fake_conformance_scenario(
    state_directory: PathBuf,
) -> Result<RuntimeConformanceScenario, RuntimeError> {
    Ok(RuntimeConformanceScenario {
        initialize: InitializeRequest { state_directory },
        create: CreateRequest {
            container_id: ContainerId::new("conformance-container")?,
            image: "fake:image".to_owned(),
            hostname: "conformance-container".to_owned(),
            resources: sendbox_runtime::RuntimeResources {
                cpus: 1,
                memory_bytes: 256 * 1024 * 1024,
            },
            mounts: Vec::new(),
            environment: Vec::new(),
            working_directory: PathBuf::from("/"),
            dns_servers: Vec::new(),
            labels: Vec::new(),
        },
        start: StartRequest {
            attach_standard_streams: true,
        },
        exec: ExecRequest {
            command: CommandSpec {
                arguments: vec![CommandArgument::plain("conformance")],
                ..CommandSpec::new(Program::Absolute(PathBuf::from(
                    "/conformance/fake-program",
                )))
            },
            purpose: ExecPurpose::BootstrapControl,
        },
        signal: Some(RuntimeSignal::Interrupt),
    })
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use sendbox_runtime::{Clock, RuntimeCapabilities, RuntimeCapability};

    use super::{
        FakeRuntime, ManualClock, TempResource, fake_conformance_scenario, run_runtime_conformance,
    };

    #[test]
    fn manual_clock_advances_deterministically() {
        let clock = ManualClock::new();
        clock.advance(Duration::from_millis(25));
        assert_eq!(clock.now().as_duration(), Duration::from_millis(25));
    }

    #[tokio::test]
    async fn fake_runtime_passes_reusable_conformance_suite() {
        let runtime = Arc::new(
            FakeRuntime::new(RuntimeCapabilities::from([
                RuntimeCapability::Lifecycle,
                RuntimeCapability::Exec,
                RuntimeCapability::StreamedIo,
                RuntimeCapability::Signals,
            ]))
            .expect("fake runtime"),
        );
        let resources = TempResource::new().expect("temporary resources");
        run_runtime_conformance(
            runtime.as_ref(),
            fake_conformance_scenario(resources.path().to_path_buf()).expect("scenario"),
        )
        .await
        .expect("conformance");

        let operations = runtime
            .recorder()
            .commands()
            .into_iter()
            .map(|command| command.operation)
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            [
                "initialize",
                "preflight",
                "create",
                "start",
                "status",
                "exec",
                "attach",
                "signal",
                "stop",
                "cleanup",
            ]
        );
    }
}
