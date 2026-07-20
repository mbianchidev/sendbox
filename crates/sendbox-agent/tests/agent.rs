use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use proptest::prelude::*;
use sendbox_agent::{
    AgentError, AgentOrchestrator, AgentRequest, AgentSignal, AgentState, BoxFuture,
    EnvironmentIntent, GuestCommand, GuestConnectionConfiguration, GuestConnector, GuestEvent,
    GuestExecution, GuestLaunchRequest, GuestSession, GuestTerminal, NoSignals, OutputSink,
    ProtocolGuestConnector, RunPlan, SecretEnvelope, SecretReference, SecretResolver, SignalSource,
};
use sendbox_config::SandboxConfiguration;
use sendbox_core::SessionId;
use sendbox_protocol::{
    BootstrapSecret, Capability, CapabilitySet, Event, EventKind, FrameLimits, GuestHandshake,
    HandshakeConfig, Message, Request, Response, ResponseStatus, VersionRange,
};
use sendbox_runtime::{
    CancellationToken, ControlStream, ExecPurpose, ExecRequest, OutputStream, RuntimeCapabilities,
    RuntimeCapability, RuntimeError, RuntimeProvider,
};
use sendbox_testkit::{FakeRuntime, TempResource};

fn runtime_capabilities() -> RuntimeCapabilities {
    RuntimeCapabilities::from([
        RuntimeCapability::Lifecycle,
        RuntimeCapability::TransportProvisioning,
        RuntimeCapability::BrokeredExec,
        RuntimeCapability::PublishedUnixControlChannel,
    ])
}

fn configuration(project_path: PathBuf) -> SandboxConfiguration {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/example-sandbox.yaml");
    let mut configuration = SandboxConfiguration::load(path).expect("example configuration");
    configuration.project_path = project_path;
    configuration.secrets = vec!["TOKEN".to_owned()];
    configuration
}

fn request(resources: &TempResource, session_id: SessionId) -> AgentRequest {
    AgentRequest {
        session_id,
        state_directory: resources.path().join("state"),
        image: "fake:image".to_owned(),
        guest_workspace: PathBuf::from("/workspace"),
        command: GuestCommand {
            program: "/usr/bin/agent".to_owned(),
            arguments: vec!["run".to_owned()],
            working_directory: "/workspace".to_owned(),
        },
        environment: vec![EnvironmentIntent {
            name: "SEND_BOX".to_owned(),
            value: "1".to_owned(),
        }],
        mounts: Vec::new(),
        bootstrap_reference: SecretReference::new("bootstrap").expect("reference"),
        readiness_timeout: Duration::from_secs(1),
    }
}

fn plan(
    resources: &TempResource,
    capabilities: &RuntimeCapabilities,
    session_id: SessionId,
) -> RunPlan {
    RunPlan::compile(
        &configuration(resources.path().to_path_buf()),
        request(resources, session_id),
        capabilities,
    )
    .expect("run plan")
}

#[derive(Debug, Default)]
struct FakeSecrets;

impl SecretResolver for FakeSecrets {
    fn resolve<'a>(
        &'a self,
        reference: &'a SecretReference,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<SecretEnvelope, AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(AgentError::Cancelled);
            }
            let bytes = if reference.as_str() == "bootstrap" {
                vec![7; 32]
            } else {
                format!("envelope:{}", reference.as_str()).into_bytes()
            };
            Ok(SecretEnvelope::new(reference.clone(), bytes))
        })
    }
}

#[derive(Debug, Default)]
struct RecordingOutput {
    events: Mutex<Vec<(OutputStream, Vec<u8>)>>,
    fail: bool,
}

impl RecordingOutput {
    fn failing() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail: true,
        }
    }
}

impl OutputSink for RecordingOutput {
    fn write<'a>(
        &'a self,
        stream: OutputStream,
        bytes: &'a [u8],
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async move {
            if self.fail {
                return Err(AgentError::Output("sink is saturated".to_owned()));
            }
            self.events
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((stream, bytes.to_vec()));
            Ok(())
        })
    }
}

struct FakeConnector {
    capabilities: CapabilitySet,
    events: Mutex<Option<VecDeque<Result<GuestEvent, AgentError>>>>,
}

impl FakeConnector {
    fn successful() -> Self {
        Self {
            capabilities: CapabilitySet::from([
                Capability::Exec,
                Capability::StreamedIo,
                Capability::Health,
            ]),
            events: Mutex::new(Some(VecDeque::from([
                Ok(GuestEvent::Output {
                    stream: OutputStream::Stdout,
                    bytes: b"ok\n".to_vec(),
                }),
                Ok(GuestEvent::Terminal(GuestTerminal::Exited { code: 0 })),
            ]))),
        }
    }

    fn service_death() -> Self {
        Self {
            capabilities: CapabilitySet::from([
                Capability::Exec,
                Capability::StreamedIo,
                Capability::Health,
            ]),
            events: Mutex::new(Some(VecDeque::from([Err(AgentError::Guest(
                "guest service died".to_owned(),
            ))]))),
        }
    }
}

impl GuestConnector for FakeConnector {
    fn connect<'a>(
        &'a self,
        _stream: Box<dyn ControlStream>,
        _configuration: GuestConnectionConfiguration,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestSession>, AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(AgentError::Cancelled);
            }
            Ok(Box::new(FakeGuestSession {
                capabilities: self.capabilities.clone(),
                events: self
                    .events
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .take()
                    .expect("single connection"),
            }) as Box<dyn GuestSession>)
        })
    }
}

struct FakeGuestSession {
    capabilities: CapabilitySet,
    events: VecDeque<Result<GuestEvent, AgentError>>,
}

impl GuestSession for FakeGuestSession {
    fn negotiated_capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    fn start<'a>(
        &'a mut self,
        _request: GuestLaunchRequest<'a>,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestExecution>, AgentError>> {
        let events = std::mem::take(&mut self.events);
        Box::pin(async move {
            Ok(Box::new(FakeExecution {
                events,
                cancelled: false,
            }) as Box<dyn GuestExecution>)
        })
    }

    fn cleanup<'a>(
        &'a mut self,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async { Ok(()) })
    }
}

struct FakeExecution {
    events: VecDeque<Result<GuestEvent, AgentError>>,
    cancelled: bool,
}

impl GuestExecution for FakeExecution {
    fn next_event<'a>(
        &'a mut self,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<GuestEvent, AgentError>> {
        Box::pin(async move {
            self.events
                .pop_front()
                .unwrap_or_else(|| Err(AgentError::Guest("event stream ended".to_owned())))
        })
    }

    fn cancel<'a>(
        &'a mut self,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async move {
            self.cancelled = true;
            Ok(())
        })
    }
}

struct OneSignal(Mutex<Option<AgentSignal>>);

impl SignalSource for OneSignal {
    fn next_signal<'a>(&'a self) -> BoxFuture<'a, Option<AgentSignal>> {
        Box::pin(async move {
            self.0
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take()
        })
    }
}

async fn fake_run(
    connector: Arc<dyn GuestConnector>,
    output: Arc<dyn OutputSink>,
    signals: Arc<dyn SignalSource>,
    runtime: Arc<FakeRuntime>,
) -> Result<sendbox_agent::AgentReport, sendbox_agent::RunFailure> {
    let resources = TempResource::new().expect("resources");
    resources.create_directory("state").expect("state");
    let (host, _guest) = tokio::io::duplex(4096);
    runtime.set_control_stream(Box::new(host));
    let plan = plan(
        &resources,
        &runtime.capabilities(),
        SessionId::from_bytes([1; 16]),
    );
    AgentOrchestrator::new(runtime, Arc::new(FakeSecrets), connector, output, signals)
        .run(&plan, &CancellationToken::new())
        .await
}

#[tokio::test]
async fn authenticated_vertical_slice_launches_through_guest_and_cleans_up() {
    let resources = TempResource::new().expect("resources");
    resources.create_directory("state").expect("state");
    let capabilities = runtime_capabilities();
    let runtime = Arc::new(FakeRuntime::new(capabilities.clone()).expect("runtime"));
    let session_id = SessionId::from_bytes([3; 16]);
    let plan = plan(&resources, &capabilities, session_id);
    let (host, guest) = tokio::io::duplex(16 * 1024);
    runtime.set_control_stream(Box::new(host));
    let guest_task = tokio::spawn(async move {
        let guest_capabilities = CapabilitySet::from([
            Capability::Exec,
            Capability::StreamedIo,
            Capability::Signals,
            Capability::Health,
        ]);
        let configuration = HandshakeConfig::new(
            session_id,
            VersionRange::default(),
            guest_capabilities,
            CapabilitySet::default(),
            FrameLimits::default(),
            BootstrapSecret::new([7; 32]).expect("bootstrap"),
        )
        .expect("handshake config");
        let mut handshake = GuestHandshake::new(configuration);
        let connection = handshake.establish(guest).await.expect("guest handshake");
        let (mut reader, mut writer) = connection.into_parts();
        let message = reader.receive().await.expect("launch request");
        let Message::Request(Request {
            request_id,
            operation,
            payload,
        }) = message
        else {
            panic!("expected launch request");
        };
        assert_eq!(operation, "agent.launch");
        assert!(
            payload
                .windows(b"TOKEN".len())
                .any(|window| window == b"TOKEN")
        );
        writer
            .send(&Message::Event(Event {
                stream_id: request_id,
                kind: EventKind::StandardOutput,
                payload: b"guest output\n".to_vec(),
            }))
            .await
            .expect("output");
        writer
            .send(&Message::Response(Response {
                request_id,
                status: ResponseStatus::Ok,
                payload: serde_json::to_vec(&GuestTerminal::Exited { code: 0 }).expect("terminal"),
            }))
            .await
            .expect("terminal response");
    });
    let output = Arc::new(RecordingOutput::default());
    let report = AgentOrchestrator::new(
        runtime.clone(),
        Arc::new(FakeSecrets),
        Arc::new(ProtocolGuestConnector),
        output.clone(),
        Arc::new(NoSignals),
    )
    .run(&plan, &CancellationToken::new())
    .await
    .expect("agent run");
    guest_task.await.expect("guest task");

    assert_eq!(report.terminal, GuestTerminal::Exited { code: 0 });
    assert_eq!(
        output
            .events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .as_slice(),
        [(OutputStream::Stdout, b"guest output\n".to_vec())]
    );
    let operations = runtime
        .recorder()
        .commands()
        .into_iter()
        .map(|command| command.operation)
        .collect::<Vec<_>>();
    assert!(!operations.iter().any(|operation| operation == "exec"));
    assert_eq!(
        operations,
        [
            "preflight",
            "initialize",
            "create",
            "start",
            "provision_control_channel",
            "accept_control_channel",
            "cleanup_control_channel",
            "stop",
            "cleanup",
        ]
    );
}

#[tokio::test]
async fn runtime_workload_exec_is_rejected() {
    let runtime = FakeRuntime::new(runtime_capabilities()).expect("runtime");
    let error = runtime
        .exec(
            &sendbox_runtime::ContainerId::new("missing").expect("container"),
            ExecRequest {
                command: sendbox_runtime::CommandSpec::new(sendbox_runtime::Program::Absolute(
                    PathBuf::from("/bin/true"),
                )),
                purpose: ExecPurpose::Workload,
            },
            &CancellationToken::new(),
        )
        .await
        .expect_err("workload exec rejected");
    assert!(matches!(
        error,
        RuntimeError::Provider(_) | RuntimeError::WorkloadExecRequiresGuestBroker
    ));
}

#[tokio::test]
async fn service_death_and_output_backpressure_are_primary_errors_with_cleanup() {
    for (connector, output, expected) in [
        (
            Arc::new(FakeConnector::service_death()) as Arc<dyn GuestConnector>,
            Arc::new(RecordingOutput::default()) as Arc<dyn OutputSink>,
            "guest service died",
        ),
        (
            Arc::new(FakeConnector::successful()) as Arc<dyn GuestConnector>,
            Arc::new(RecordingOutput::failing()) as Arc<dyn OutputSink>,
            "sink is saturated",
        ),
    ] {
        let runtime = Arc::new(FakeRuntime::new(runtime_capabilities()).expect("runtime"));
        let failure = fake_run(connector, output, Arc::new(NoSignals), runtime.clone())
            .await
            .expect_err("run must fail");
        assert!(failure.primary.to_string().contains(expected));
        assert!(
            runtime
                .recorder()
                .commands()
                .iter()
                .any(|command| command.operation == "cleanup")
        );
    }
}

#[tokio::test]
async fn signal_cancellation_is_idempotent_and_cleanup_failures_do_not_replace_primary() {
    let runtime = Arc::new(FakeRuntime::new(runtime_capabilities()).expect("runtime"));
    runtime
        .failure_injector()
        .fail_next("cleanup_control_channel", "unlink failed");
    let failure = fake_run(
        Arc::new(FakeConnector::successful()),
        Arc::new(RecordingOutput::default()),
        Arc::new(OneSignal(Mutex::new(Some(AgentSignal::Interrupt)))),
        runtime,
    )
    .await
    .expect_err("cancelled run");
    assert!(matches!(failure.primary, AgentError::Cancelled));
    assert!(
        failure
            .cleanup
            .iter()
            .any(|cleanup| cleanup.step == "control channel cleanup")
    );
}

#[tokio::test]
async fn runtime_cleanup_failures_are_reported_after_success() {
    let runtime = Arc::new(FakeRuntime::new(runtime_capabilities()).expect("runtime"));
    runtime.failure_injector().fail_next("stop", "stop failed");
    runtime
        .failure_injector()
        .fail_next("cleanup", "cleanup failed");
    let failure = fake_run(
        Arc::new(FakeConnector::successful()),
        Arc::new(RecordingOutput::default()),
        Arc::new(NoSignals),
        runtime,
    )
    .await
    .expect_err("cleanup failure");
    assert!(matches!(failure.primary, AgentError::CleanupAfterSuccess));
    assert_eq!(failure.cleanup.len(), 2);
}

#[tokio::test]
async fn wrong_guest_capabilities_fail_before_launch() {
    let runtime = Arc::new(FakeRuntime::new(runtime_capabilities()).expect("runtime"));
    let connector = Arc::new(FakeConnector {
        capabilities: CapabilitySet::from([Capability::Exec]),
        events: Mutex::new(Some(VecDeque::new())),
    });
    let failure = fake_run(
        connector,
        Arc::new(RecordingOutput::default()),
        Arc::new(NoSignals),
        runtime,
    )
    .await
    .expect_err("capability failure");
    assert!(failure.primary.to_string().contains("omitted"));
}

#[tokio::test]
async fn wrong_protocol_session_fails_readiness_and_cleans_up() {
    let resources = TempResource::new().expect("resources");
    resources.create_directory("state").expect("state");
    let capabilities = runtime_capabilities();
    let runtime = Arc::new(FakeRuntime::new(capabilities.clone()).expect("runtime"));
    let plan = plan(&resources, &capabilities, SessionId::from_bytes([11; 16]));
    let (host, guest) = tokio::io::duplex(4096);
    runtime.set_control_stream(Box::new(host));
    let guest_task = tokio::spawn(async move {
        let configuration = HandshakeConfig::new(
            SessionId::from_bytes([12; 16]),
            VersionRange::default(),
            CapabilitySet::from([Capability::Exec, Capability::StreamedIo, Capability::Health]),
            CapabilitySet::default(),
            FrameLimits::default(),
            BootstrapSecret::new([7; 32]).expect("bootstrap"),
        )
        .expect("config");
        let mut handshake = GuestHandshake::new(configuration);
        let _ = handshake.establish(guest).await;
    });
    let failure = AgentOrchestrator::new(
        runtime.clone(),
        Arc::new(FakeSecrets),
        Arc::new(ProtocolGuestConnector),
        Arc::new(RecordingOutput::default()),
        Arc::new(NoSignals),
    )
    .run(&plan, &CancellationToken::new())
    .await
    .expect_err("session mismatch");
    guest_task.await.expect("guest task");
    assert!(matches!(failure.primary, AgentError::Protocol(_)));
    assert!(
        runtime
            .recorder()
            .commands()
            .iter()
            .any(|command| command.operation == "cleanup")
    );
}

#[tokio::test]
async fn readiness_timeout_is_distinct_from_transport_loss() {
    let resources = TempResource::new().expect("resources");
    resources.create_directory("state").expect("state");
    let capabilities = runtime_capabilities();
    let runtime = Arc::new(FakeRuntime::new(capabilities.clone()).expect("runtime"));
    let session_id = SessionId::from_bytes([14; 16]);
    let mut agent_request = request(&resources, session_id);
    agent_request.readiness_timeout = Duration::from_millis(10);
    let plan = RunPlan::compile(
        &configuration(resources.path().to_path_buf()),
        agent_request,
        &capabilities,
    )
    .expect("plan");
    let (host, _silent_guest) = tokio::io::duplex(4096);
    runtime.set_control_stream(Box::new(host));
    let failure = AgentOrchestrator::new(
        runtime.clone(),
        Arc::new(FakeSecrets),
        Arc::new(ProtocolGuestConnector),
        Arc::new(RecordingOutput::default()),
        Arc::new(NoSignals),
    )
    .run(&plan, &CancellationToken::new())
    .await
    .expect_err("readiness timeout");
    assert!(matches!(failure.primary, AgentError::ReadinessTimedOut));
    assert!(
        runtime
            .recorder()
            .commands()
            .iter()
            .any(|command| command.operation == "cleanup_control_channel")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn protocol_connector_authenticates_over_unix_stream() {
    use tokio::net::{UnixListener, UnixStream};

    let resources = TempResource::new().expect("resources");
    let socket_path = resources.path().join("agent.sock");
    let listener = UnixListener::bind(&socket_path).expect("listener");
    let session_id = SessionId::from_bytes([13; 16]);
    let guest_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let configuration = HandshakeConfig::new(
            session_id,
            VersionRange::default(),
            CapabilitySet::from([Capability::Exec, Capability::StreamedIo, Capability::Health]),
            CapabilitySet::default(),
            FrameLimits::default(),
            BootstrapSecret::new([7; 32]).expect("bootstrap"),
        )
        .expect("config");
        GuestHandshake::new(configuration)
            .establish(stream)
            .await
            .expect("guest handshake")
    });
    let stream = UnixStream::connect(&socket_path).await.expect("connect");
    let session = ProtocolGuestConnector
        .connect(
            Box::new(stream),
            GuestConnectionConfiguration {
                session_id,
                capabilities: CapabilitySet::from([
                    Capability::Exec,
                    Capability::StreamedIo,
                    Capability::Signals,
                    Capability::Health,
                ]),
                required_capabilities: CapabilitySet::from([
                    Capability::Exec,
                    Capability::StreamedIo,
                    Capability::Health,
                ]),
                bootstrap_secret: vec![7; 32],
            },
            &CancellationToken::new(),
        )
        .await
        .expect("host handshake");
    assert!(session.negotiated_capabilities().contains(Capability::Exec));
    drop(session);
    let _ = guest_task.await.expect("guest task");
}

#[tokio::test]
async fn failures_at_runtime_boundaries_trigger_available_cleanup() {
    for operation in [
        "preflight",
        "initialize",
        "create",
        "start",
        "provision_control_channel",
        "accept_control_channel",
    ] {
        let runtime = Arc::new(FakeRuntime::new(runtime_capabilities()).expect("runtime"));
        runtime
            .failure_injector()
            .fail_next(operation, "fault injection");
        let failure = fake_run(
            Arc::new(FakeConnector::successful()),
            Arc::new(RecordingOutput::default()),
            Arc::new(NoSignals),
            runtime.clone(),
        )
        .await
        .expect_err("injected failure");
        assert!(failure.primary.to_string().contains("fault injection"));
        let operations = runtime.recorder().commands();
        if matches!(
            operation,
            "start" | "provision_control_channel" | "accept_control_channel"
        ) {
            assert!(
                operations
                    .iter()
                    .any(|command| command.operation == "cleanup")
            );
        }
    }
}

#[test]
fn plan_rejects_missing_transport_and_prefers_vsock() {
    let resources = TempResource::new().expect("resources");
    let session = SessionId::from_bytes([5; 16]);
    let missing = RuntimeCapabilities::from([
        RuntimeCapability::Lifecycle,
        RuntimeCapability::TransportProvisioning,
        RuntimeCapability::BrokeredExec,
    ]);
    assert!(
        RunPlan::compile(
            &configuration(resources.path().to_path_buf()),
            request(&resources, session),
            &missing
        )
        .is_err()
    );

    let with_vsock = RuntimeCapabilities::from([
        RuntimeCapability::Lifecycle,
        RuntimeCapability::TransportProvisioning,
        RuntimeCapability::BrokeredExec,
        RuntimeCapability::PublishedUnixControlChannel,
        RuntimeCapability::VsockControlChannel,
    ]);
    let plan = plan(&resources, &with_vsock, session);
    assert_eq!(
        plan.endpoint_kind(),
        sendbox_runtime::ControlEndpointKind::Vsock
    );
}

proptest! {
    #[test]
    fn state_transition_table_is_deterministic(from in 0_usize..13, to in 0_usize..13) {
        let states = [
            AgentState::Planned,
            AgentState::Preflighted,
            AgentState::Initialized,
            AgentState::Created,
            AgentState::Started,
            AgentState::ChannelProvisioned,
            AgentState::GuestReady,
            AgentState::SecretsResolved,
            AgentState::Running,
            AgentState::Stopping,
            AgentState::Cleaning,
            AgentState::Completed,
            AgentState::Failed,
        ];
        let first = states[from].can_transition_to(states[to]);
        let second = states[from].can_transition_to(states[to]);
        prop_assert_eq!(first, second);
        prop_assert!(!states[from].can_transition_to(states[from]));
    }
}
