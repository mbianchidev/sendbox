use std::{
    collections::{BTreeMap, VecDeque},
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
use sendbox_boundary::{
    Architecture, ArtifactIdentity, ArtifactKind, BOUNDARY_PLAN_FORMAT, BOUNDARY_PLAN_VERSION,
    BoundaryPlan, CommandDeclaration, ControlTransport, EnvironmentDeclaration, HostPlatform,
    MountDeclaration, OperatingSystem, ProviderDeclaration, ResourceDeclaration,
    SignedBoundaryPlan, TrustDeclaration, VerifiedBoundaryPlan, WorkloadIdentity, select_runtime,
    sha256_hex,
};
use sendbox_config::SandboxConfiguration;
use sendbox_core::{BoundaryPlanDigest, SessionId};
use sendbox_protocol::{
    BootstrapSecret, Capability, CapabilitySet, Event, EventKind, FrameLimits, GuestHandshake,
    HandshakeConfig, LaunchRequestV2, Message, PACKAGE_REPORT_OPERATION,
    PACKAGE_REPORT_SCHEMA_VERSION, PackageReportRequestV1, PackageReportResponseV1, Request,
    Response, ResponseStatus, VersionRange,
};
use sendbox_runtime::{
    CancellationToken, ControlStream, ExecPurpose, ExecRequest, OutputStream, RuntimeCapabilities,
    RuntimeCapability, RuntimeError, RuntimeProvider,
};
use sendbox_secrets::{
    EnvelopeBinding, EnvelopeCipher, RecipientRole, ReplayGuard, SecretName, SessionKeyMaterial,
};
use sendbox_security::provenance::SigningKeyMaterial;
use sendbox_testkit::{FakeRuntime, TempResource};

const IMAGE_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn plan_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}

fn runtime_capabilities() -> RuntimeCapabilities {
    RuntimeCapabilities::from([
        RuntimeCapability::Lifecycle,
        RuntimeCapability::TransportProvisioning,
        RuntimeCapability::BrokeredExec,
        RuntimeCapability::PublishedUnixControlChannel,
    ])
}

fn interactive_runtime_capabilities() -> RuntimeCapabilities {
    RuntimeCapabilities::from([
        RuntimeCapability::Lifecycle,
        RuntimeCapability::TransportProvisioning,
        RuntimeCapability::BrokeredExec,
        RuntimeCapability::InteractiveTerminal,
        RuntimeCapability::PublishedUnixControlChannel,
    ])
}

fn negotiated_agent_capabilities() -> CapabilitySet {
    sendbox_protocol::agent_host_capabilities()
        .intersection(&sendbox_protocol::agent_guest_capabilities())
}

fn configuration(project_path: PathBuf) -> SandboxConfiguration {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/example-sandbox.yaml");
    let mut configuration = SandboxConfiguration::load(path).expect("example configuration");
    configuration.project_path = project_path;
    configuration.secrets = vec!["TOKEN".to_owned()];
    configuration
}

fn request(resources: &TempResource, session_id: SessionId) -> AgentRequest {
    let configuration = configuration(resources.path().to_path_buf());
    request_for_configuration(resources, session_id, &configuration)
}

fn request_for_configuration(
    resources: &TempResource,
    session_id: SessionId,
    configuration: &SandboxConfiguration,
) -> AgentRequest {
    let image = format!("registry.example/sendbox-test@{IMAGE_DIGEST}");
    let guest_workspace = PathBuf::from("/workspace");
    let command = GuestCommand {
        program: "/usr/bin/agent".to_owned(),
        arguments: vec!["run".to_owned()],
        working_directory: "/workspace".to_owned(),
    };
    let environment = vec![EnvironmentIntent {
        name: "SEND_BOX".to_owned(),
        value: "1".to_owned(),
        sensitive: false,
    }];
    let mounts = Vec::new();
    AgentRequest {
        boundary_plan: verified_boundary_plan(
            configuration,
            session_id,
            &image,
            &guest_workspace,
            &command,
            &environment,
            &mounts,
        ),
        session_id,
        state_directory: resources.path().join("state"),
        image,
        guest_workspace,
        command,
        environment,
        mounts,
        bootstrap_reference: SecretReference::new("bootstrap").expect("reference"),
        readiness_timeout: Duration::from_secs(1),
        interactive: false,
    }
}

fn verified_boundary_plan(
    configuration: &SandboxConfiguration,
    session_id: SessionId,
    image: &str,
    guest_workspace: &std::path::Path,
    command: &GuestCommand,
    environment: &[EnvironmentIntent],
    mounts: &[sendbox_agent::MountIntent],
) -> VerifiedBoundaryPlan {
    let now = plan_time();
    let configuration_bytes = serde_json::to_vec(configuration).expect("configuration JSON");
    let policy_bytes = serde_json::to_vec(&configuration.policy).expect("policy JSON");
    let selection = select_runtime(
        sendbox_config::RuntimeProvider::Kata,
        HostPlatform {
            operating_system: OperatingSystem::Linux,
            architecture: Architecture::X86_64,
        },
    )
    .expect("runtime selection");
    let boundary = BoundaryPlan {
        format: BOUNDARY_PLAN_FORMAT.to_owned(),
        version: BOUNDARY_PLAN_VERSION,
        session_id,
        created_at_unix: now,
        expires_at_unix: now + 600,
        selection,
        configuration_sha256: sha256_hex(&configuration_bytes),
        policy_sha256: sha256_hex(&policy_bytes),
        trust: TrustDeclaration {
            trust_root_id: "test-root".to_owned(),
            minimum_release_sequence: 1,
            host_version: "0.1.0".to_owned(),
            guest_version: "0.1.0".to_owned(),
        },
        workload: WorkloadIdentity::OciImage {
            reference: image.to_owned(),
            digest: IMAGE_DIGEST.to_owned(),
        },
        provider: ProviderDeclaration::Kata {
            executable: PathBuf::from("/usr/bin/nerdctl"),
            runtime_handler: "io.containerd.kata.v2".to_owned(),
            namespace: "sendbox".to_owned(),
            address: None,
            snapshotter: None,
            configuration_path: None,
            transport: ControlTransport::RuntimeExecStdio,
        },
        command: CommandDeclaration {
            program: command.program.clone(),
            arguments: command.arguments.clone(),
            working_directory: command.working_directory.clone(),
        },
        workspace: MountDeclaration {
            source: configuration.project_path.clone(),
            destination: guest_workspace.to_path_buf(),
            writable: true,
        },
        mounts: mounts
            .iter()
            .map(|mount| MountDeclaration {
                source: mount.source.clone(),
                destination: mount.destination.clone(),
                writable: mount.writable,
            })
            .collect(),
        environment: environment
            .iter()
            .map(|entry| EnvironmentDeclaration {
                name: entry.name.clone(),
                value_sha256: sha256_hex(entry.value.as_bytes()),
                sensitive: entry.sensitive,
            })
            .collect(),
        secrets: configuration.secrets.clone(),
        artifacts: vec![
            ArtifactIdentity {
                kind: ArtifactKind::RuntimeExecutable,
                path: PathBuf::from("/usr/bin/nerdctl"),
                sha256: "11".repeat(32),
            },
            ArtifactIdentity {
                kind: ArtifactKind::GuestBundleManifest,
                path: PathBuf::from("/opt/sendbox/manifest.json"),
                sha256: "22".repeat(32),
            },
            ArtifactIdentity {
                kind: ArtifactKind::TrustRoot,
                path: PathBuf::from("/etc/sendbox/trust-root.pub"),
                sha256: "33".repeat(32),
            },
        ],
        resources: ResourceDeclaration {
            cpus: u32::try_from(configuration.resources.cpus).expect("CPU count"),
            memory_bytes: u64::try_from(configuration.resources.memory_mb).expect("memory")
                * 1024
                * 1024,
        },
        features: BTreeMap::new(),
    };
    let key = SigningKeyMaterial::generate().expect("signing key");
    let fingerprint = key.identity("test", None, 0, None).fingerprint.clone();
    SignedBoundaryPlan::sign(boundary, &key, now)
        .expect("signed boundary")
        .verify(&fingerprint, now)
        .expect("verified boundary")
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
        plan_time(),
    )
    .expect("run plan")
}

fn safe_outputs_plan(
    resources: &TempResource,
    capabilities: &RuntimeCapabilities,
    session_id: SessionId,
) -> RunPlan {
    let mut configuration = configuration(resources.path().to_path_buf());
    configuration.github.forward_auth = false;
    configuration.github.ssh_key_path = None;
    configuration.github.safe_outputs.enabled = true;
    configuration.github.safe_outputs.write_token_env = "HOST_ONLY_WRITE_TOKEN".to_owned();
    configuration.github.safe_outputs.allowed_repositories = vec!["example/repository".to_owned()];
    configuration.github.safe_outputs.create_issue.enabled = true;
    let mut request = request(resources, session_id);
    request.boundary_plan = verified_boundary_plan(
        &configuration,
        session_id,
        &request.image,
        &request.guest_workspace,
        &request.command,
        &request.environment,
        &request.mounts,
    );
    RunPlan::compile(&configuration, request, capabilities, plan_time()).expect("Safe Outputs plan")
}

fn package_plan(
    resources: &TempResource,
    capabilities: &RuntimeCapabilities,
    session_id: SessionId,
) -> RunPlan {
    let mut configuration = configuration(resources.path().to_path_buf());
    configuration.policy.packages.enabled = true;
    configuration.policy.packages.registries =
        vec![sendbox_policy::PackageRegistryPolicy::default()];
    RunPlan::compile(
        &configuration,
        request_for_configuration(resources, session_id, &configuration),
        capabilities,
        plan_time(),
    )
    .expect("package run plan")
}

fn interactive_plan(
    resources: &TempResource,
    capabilities: &RuntimeCapabilities,
    session_id: SessionId,
) -> Result<RunPlan, AgentError> {
    let mut request = request(resources, session_id);
    request.interactive = true;
    RunPlan::compile(
        &configuration(resources.path().to_path_buf()),
        request,
        capabilities,
        plan_time(),
    )
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
            capabilities: negotiated_agent_capabilities(),
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
            capabilities: negotiated_agent_capabilities(),
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

/// Records what the orchestrator forwarded and releases the workload once the
/// expected number of commands has arrived, so assertions never race the
/// orchestrator's deliberately unbiased input/output selection.
struct TerminalLog {
    launch_terminal: Mutex<Option<Option<sendbox_agent::GuestTerminalSize>>>,
    commands: Mutex<Vec<String>>,
    expected: usize,
    drained: tokio::sync::watch::Sender<bool>,
}

impl TerminalLog {
    fn record(&self, command: &sendbox_agent::HostTerminalCommand) {
        let rendered = match command {
            sendbox_agent::HostTerminalCommand::Input(bytes) => {
                format!("input:{}", String::from_utf8_lossy(bytes))
            }
            sendbox_agent::HostTerminalCommand::InputEof => "eof".to_owned(),
            sendbox_agent::HostTerminalCommand::Resize { columns, rows } => {
                format!("resize:{columns}x{rows}")
            }
        };
        let mut commands = self
            .commands
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        commands.push(rendered);
        if commands.len() >= self.expected {
            let _ = self.drained.send(true);
        }
    }
}

/// Replays a fixed command script, then parks forever. Parking rather than
/// returning `None` keeps the orchestrator's terminal branch alive, which is
/// what a real host terminal does.
struct ScriptedTerminal {
    commands: Mutex<VecDeque<sendbox_agent::HostTerminalCommand>>,
}

impl sendbox_agent::TerminalSource for ScriptedTerminal {
    fn next_command<'a>(
        &'a self,
    ) -> sendbox_agent::BoxFuture<'a, Option<sendbox_agent::HostTerminalCommand>> {
        Box::pin(async move {
            let next = self
                .commands
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .pop_front();
            match next {
                Some(command) => Some(command),
                None => std::future::pending().await,
            }
        })
    }
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
                terminal: None,
                exit_gate: None,
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
    terminal: Option<Arc<TerminalLog>>,
    /// Holds the workload alive until the host terminal script is drained, so
    /// interactive assertions do not race the orchestrator's unbiased select.
    exit_gate: Option<tokio::sync::watch::Receiver<bool>>,
}

impl GuestExecution for FakeExecution {
    fn next_event<'a>(
        &'a mut self,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<GuestEvent, AgentError>> {
        Box::pin(async move {
            if let Some(event) = self.events.pop_front() {
                return event;
            }
            if let Some(gate) = self.exit_gate.as_mut() {
                let _ = gate.wait_for(|drained| *drained).await;
                return Ok(GuestEvent::Terminal(GuestTerminal::Exited { code: 0 }));
            }
            Err(AgentError::Guest("event stream ended".to_owned()))
        })
    }

    fn send_terminal<'a>(
        &'a mut self,
        command: sendbox_agent::HostTerminalCommand,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async move {
            match self.terminal.as_ref() {
                Some(log) => {
                    log.record(&command);
                    Ok(())
                }
                None => Err(AgentError::Guest(
                    "terminal input requires an interactive launch".to_owned(),
                )),
            }
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

struct InteractiveConnector {
    log: Arc<TerminalLog>,
    events: Mutex<Option<VecDeque<Result<GuestEvent, AgentError>>>>,
    exit_gate: tokio::sync::watch::Receiver<bool>,
}

impl GuestConnector for InteractiveConnector {
    fn connect<'a>(
        &'a self,
        _stream: Box<dyn ControlStream>,
        _configuration: GuestConnectionConfiguration,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestSession>, AgentError>> {
        Box::pin(async move {
            Ok(Box::new(InteractiveSession {
                capabilities: negotiated_agent_capabilities(),
                log: Arc::clone(&self.log),
                exit_gate: self.exit_gate.clone(),
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

struct InteractiveSession {
    capabilities: CapabilitySet,
    log: Arc<TerminalLog>,
    events: VecDeque<Result<GuestEvent, AgentError>>,
    exit_gate: tokio::sync::watch::Receiver<bool>,
}

impl GuestSession for InteractiveSession {
    fn negotiated_capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    fn start<'a>(
        &'a mut self,
        request: GuestLaunchRequest<'a>,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestExecution>, AgentError>> {
        *self
            .log
            .launch_terminal
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(request.terminal.clone());
        let events = std::mem::take(&mut self.events);
        let log = Arc::clone(&self.log);
        let exit_gate = self.exit_gate.clone();
        Box::pin(async move {
            Ok(Box::new(FakeExecution {
                events,
                cancelled: false,
                terminal: Some(log),
                exit_gate: Some(exit_gate),
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
    let plan = package_plan(&resources, &capabilities, session_id);
    let expected_policy_digest = plan.policy_digest();
    let expected_boundary_digest = plan.boundary_plan_digest();
    let (host, guest) = tokio::io::duplex(16 * 1024);
    runtime.set_control_stream(Box::new(host));
    let guest_task = tokio::spawn(async move {
        let configuration = HandshakeConfig::new(
            session_id,
            VersionRange::default(),
            sendbox_protocol::agent_guest_capabilities(),
            sendbox_protocol::agent_guest_required_capabilities(),
            FrameLimits::default(),
            BootstrapSecret::new([7; 32]).expect("bootstrap"),
            expected_boundary_digest,
        )
        .expect("handshake config");
        let mut handshake = GuestHandshake::new(configuration);
        let connection = handshake.establish(guest).await.expect("guest handshake");
        let (mut reader, mut writer) = connection.into_parts();
        writer
            .send(&Message::Event(Event {
                stream_id: 0,
                kind: EventKind::Lifecycle,
                payload: br#"{"state":"ready","services":[{"id":"exec","mandatory":true,"healthy":true}]}"#
                    .to_vec(),
            }))
            .await
            .expect("readiness");
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
        let launch: LaunchRequestV2 = serde_json::from_slice(&payload).expect("launch payload");
        assert!(
            !payload
                .windows(b"envelope:TOKEN".len())
                .any(|window| window == b"envelope:TOKEN")
        );
        assert_eq!(launch.secrets.len(), 1);
        let secret = &launch.secrets[0];
        assert_eq!(secret.reference, "TOKEN");
        assert_eq!(secret.policy_digest, expected_policy_digest);
        assert_eq!(launch.boundary_plan_digest, expected_boundary_digest);
        assert_eq!(secret.boundary_plan_digest, expected_boundary_digest);
        let material = SessionKeyMaterial::new([7; 32]).expect("secret material");
        let cipher = EnvelopeCipher::new(&material, session_id).expect("secret cipher");
        let binding = EnvelopeBinding {
            session_id,
            recipient: RecipientRole::Guest,
            secret_name: SecretName::new("TOKEN").expect("secret name"),
            sequence: secret.sequence,
            expires_at_unix_ms: secret.expires_at_unix_ms,
            policy_digest: secret.policy_digest,
            boundary_plan_digest: expected_boundary_digest,
        };
        let decrypted = cipher
            .open(&secret.envelope, &binding, &ReplayGuard::default(), 0)
            .expect("decrypt secret");
        assert_eq!(decrypted.expose_secret(), b"envelope:TOKEN");
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
                payload: serde_json::to_vec(&sendbox_protocol::TerminalResultV2 {
                    schema_version: sendbox_protocol::OPERATION_SCHEMA_VERSION,
                    terminal: sendbox_protocol::TerminalStateV1::Exited {
                        exit_code: Some(0),
                        signal: None,
                    },
                    cleanup_complete: true,
                })
                .expect("terminal"),
            }))
            .await
            .expect("terminal response");
        let message = reader.receive().await.expect("package report request");
        let Message::Request(Request {
            request_id,
            operation,
            payload,
        }) = message
        else {
            panic!("expected package report request");
        };
        assert_eq!(request_id, 2);
        assert_eq!(operation, PACKAGE_REPORT_OPERATION);
        let report_request: PackageReportRequestV1 =
            serde_json::from_slice(&payload).expect("report request");
        report_request.validate().expect("valid report request");
        let report_json = r#"{"schema_version":1,"proxy_enabled":true,"records":[],"allowed":0,"denied":0,"quarantined":0}"#;
        let sha256 = format!("sha256:{}", sha256_hex(report_json.as_bytes()));
        writer
            .send(&Message::Response(Response {
                request_id,
                status: ResponseStatus::Ok,
                payload: serde_json::to_vec(&PackageReportResponseV1 {
                    schema_version: PACKAGE_REPORT_SCHEMA_VERSION,
                    report_json: report_json.to_owned(),
                    sha256,
                })
                .expect("report response"),
            }))
            .await
            .expect("package report response");
        assert!(matches!(
            reader.receive().await.expect("graceful close"),
            Message::GracefulClose(_)
        ));
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
        report.package_report.expect("package report").json,
        br#"{"schema_version":1,"proxy_enabled":true,"records":[],"allowed":0,"denied":0,"quarantined":0}"#
    );
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
async fn safe_outputs_collection_follows_terminal_cleanup_without_forwarding_write_auth() {
    let resources = TempResource::new().expect("resources");
    resources.create_directory("state").expect("state");
    let capabilities = runtime_capabilities();
    let runtime = Arc::new(FakeRuntime::new(capabilities.clone()).expect("runtime"));
    let session_id = SessionId::from_bytes([0x51; 16]);
    let plan = safe_outputs_plan(&resources, &capabilities, session_id);
    let expected_boundary_digest = plan.boundary_plan_digest();
    let (host, guest) = tokio::io::duplex(16 * 1024);
    runtime.set_control_stream(Box::new(host));
    let guest_task = tokio::spawn(async move {
        let configuration = HandshakeConfig::new(
            session_id,
            VersionRange::default(),
            sendbox_protocol::agent_guest_capabilities(),
            sendbox_protocol::agent_guest_required_capabilities(),
            FrameLimits::default(),
            BootstrapSecret::new([7; 32]).expect("bootstrap"),
            expected_boundary_digest,
        )
        .expect("handshake config");
        let mut handshake = GuestHandshake::new(configuration);
        let connection = handshake.establish(guest).await.expect("guest handshake");
        let (mut reader, mut writer) = connection.into_parts();
        writer
            .send(&Message::Event(Event {
                stream_id: 0,
                kind: EventKind::Lifecycle,
                payload: br#"{"state":"ready","services":[{"id":"exec","mandatory":true,"healthy":true},{"id":"safe_outputs","mandatory":true,"healthy":true}]}"#
                    .to_vec(),
            }))
            .await
            .expect("readiness");
        let Message::Request(Request {
            request_id,
            operation,
            payload,
        }) = reader.receive().await.expect("launch")
        else {
            panic!("expected launch request");
        };
        assert_eq!(operation, "agent.launch");
        assert!(
            !payload
                .windows(b"HOST_ONLY_WRITE_TOKEN".len())
                .any(|window| window == b"HOST_ONLY_WRITE_TOKEN")
        );
        assert!(
            !payload
                .windows(b"host-write-token-value".len())
                .any(|window| window == b"host-write-token-value")
        );
        let launch: LaunchRequestV2 = serde_json::from_slice(&payload).expect("launch payload");
        assert!(
            launch
                .secrets
                .iter()
                .all(|secret| secret.reference != "HOST_ONLY_WRITE_TOKEN")
        );
        writer
            .send(&Message::Response(Response {
                request_id,
                status: ResponseStatus::Ok,
                payload: serde_json::to_vec(&sendbox_protocol::TerminalResultV2 {
                    schema_version: sendbox_protocol::OPERATION_SCHEMA_VERSION,
                    terminal: sendbox_protocol::TerminalStateV1::Exited {
                        exit_code: Some(0),
                        signal: None,
                    },
                    cleanup_complete: true,
                })
                .expect("terminal"),
            }))
            .await
            .expect("terminal response");

        let Message::Request(Request {
            request_id,
            operation,
            payload,
        }) = reader.receive().await.expect("collection request")
        else {
            panic!("expected Safe Outputs collection request");
        };
        assert_eq!(request_id, 3);
        assert_eq!(operation, sendbox_protocol::SAFE_OUTPUTS_COLLECT_OPERATION);
        let request: sendbox_protocol::SafeOutputsCollectRequestV1 =
            serde_json::from_slice(&payload).expect("collection payload");
        assert_eq!(request.boundary_plan_digest, expected_boundary_digest);
        writer
            .send(&Message::Response(Response {
                request_id,
                status: ResponseStatus::Ok,
                payload: serde_json::to_vec(
                    &sendbox_protocol::SafeOutputsCollectionV1::new(
                        b"{\"accepted\":true}\n",
                        b"{\"seal\":true}",
                    )
                    .expect("collection"),
                )
                .expect("collection response"),
            }))
            .await
            .expect("collection response");
        assert!(matches!(
            reader.receive().await.expect("graceful close"),
            Message::GracefulClose(_)
        ));
    });

    let report = AgentOrchestrator::new(
        runtime,
        Arc::new(FakeSecrets),
        Arc::new(ProtocolGuestConnector),
        Arc::new(RecordingOutput::default()),
        Arc::new(NoSignals),
    )
    .run(&plan, &CancellationToken::new())
    .await
    .expect("agent run");
    guest_task.await.expect("guest task");
    let collection = report.safe_outputs.expect("Safe Outputs collection");
    assert_eq!(collection.artifact, b"{\"accepted\":true}\n");
    assert_eq!(collection.seal, b"{\"seal\":true}");
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
async fn closed_signal_source_does_not_starve_guest_events() {
    let runtime = Arc::new(FakeRuntime::new(runtime_capabilities()).expect("runtime"));
    let report = fake_run(
        Arc::new(FakeConnector::successful()),
        Arc::new(RecordingOutput::default()),
        Arc::new(OneSignal(Mutex::new(None))),
        runtime,
    )
    .await
    .expect("run");
    assert_eq!(report.terminal, GuestTerminal::Exited { code: 0 });
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
    let boundary_plan_digest = plan.boundary_plan_digest();
    let (host, guest) = tokio::io::duplex(4096);
    runtime.set_control_stream(Box::new(host));
    let guest_task = tokio::spawn(async move {
        let configuration = HandshakeConfig::new(
            SessionId::from_bytes([12; 16]),
            VersionRange::default(),
            sendbox_protocol::agent_guest_capabilities(),
            sendbox_protocol::agent_guest_required_capabilities(),
            FrameLimits::default(),
            BootstrapSecret::new([7; 32]).expect("bootstrap"),
            boundary_plan_digest,
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
        plan_time(),
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
    let boundary_plan_digest = BoundaryPlanDigest::from_bytes([0xa1; 32]);
    let guest_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let configuration = HandshakeConfig::new(
            session_id,
            VersionRange::default(),
            sendbox_protocol::agent_guest_capabilities(),
            sendbox_protocol::agent_guest_required_capabilities(),
            FrameLimits::default(),
            BootstrapSecret::new([7; 32]).expect("bootstrap"),
            boundary_plan_digest,
        )
        .expect("config");
        let connection = GuestHandshake::new(configuration)
            .establish(stream)
            .await
            .expect("guest handshake");
        let (_reader, mut writer) = connection.into_parts();
        writer
            .send(&Message::Event(Event {
                stream_id: 0,
                kind: EventKind::Lifecycle,
                payload: br#"{"state":"ready","services":[{"id":"exec","mandatory":true,"healthy":true}]}"#
                    .to_vec(),
            }))
            .await
            .expect("readiness");
    });
    let stream = UnixStream::connect(&socket_path).await.expect("connect");
    let session = ProtocolGuestConnector
        .connect(
            Box::new(stream),
            GuestConnectionConfiguration {
                session_id,
                boundary_plan_digest,
                capabilities: sendbox_protocol::agent_host_capabilities(),
                required_capabilities: sendbox_protocol::agent_host_required_capabilities(),
                safe_outputs_required: false,
                bootstrap_secret: vec![7; 32],
                policy_digest: [9; 32],
            },
            &CancellationToken::new(),
        )
        .await
        .expect("host handshake");
    assert!(session.negotiated_capabilities().contains(Capability::Exec));
    drop(session);
    guest_task.await.expect("guest task");
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
            &missing,
            plan_time(),
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

#[test]
fn guest_launch_debug_redacts_envelopes_and_environment_values() {
    let command = GuestCommand {
        program: "/usr/bin/agent".to_owned(),
        arguments: Vec::new(),
        working_directory: "/workspace".to_owned(),
    };
    let environment = [EnvironmentIntent {
        name: "TOKEN".to_owned(),
        value: "raw-environment-secret".to_owned(),
        sensitive: true,
    }];
    let request = GuestLaunchRequest {
        command: &command,
        environment: &environment,
        secrets: vec![sendbox_agent::GuestSecretEnvelope {
            reference: "TOKEN",
            envelope: b"raw-envelope-secret",
        }],
        terminal: None,
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains("raw-environment-secret"));
    assert!(!debug.contains("raw-envelope-secret"));
}

#[tokio::test]
async fn cleanup_uses_the_provider_returned_container_id() {
    let resources = TempResource::new().expect("resources");
    resources.create_directory("state").expect("state");
    let runtime = Arc::new(FakeRuntime::new(runtime_capabilities()).expect("runtime"));
    let actual = sendbox_runtime::ContainerId::new("provider-container").expect("container");
    runtime.set_created_container_id(actual.clone());
    let (host, _guest) = tokio::io::duplex(4096);
    runtime.set_control_stream(Box::new(host));
    let plan = plan(
        &resources,
        &runtime.capabilities(),
        SessionId::from_bytes([15; 16]),
    );
    let report = AgentOrchestrator::new(
        runtime.clone(),
        Arc::new(FakeSecrets),
        Arc::new(FakeConnector::successful()),
        Arc::new(RecordingOutput::default()),
        Arc::new(NoSignals),
    )
    .run(&plan, &CancellationToken::new())
    .await
    .expect("run");
    assert_eq!(report.terminal, GuestTerminal::Exited { code: 0 });
    for operation in runtime
        .recorder()
        .commands()
        .into_iter()
        .filter(|command| matches!(command.operation.as_str(), "start" | "stop" | "cleanup"))
    {
        assert_eq!(operation.container.as_ref(), Some(&actual));
    }
}

async fn interactive_run(
    commands: VecDeque<sendbox_agent::HostTerminalCommand>,
    expected_commands: usize,
    events: VecDeque<Result<GuestEvent, AgentError>>,
) -> (
    Arc<TerminalLog>,
    Result<sendbox_agent::AgentReport, sendbox_agent::RunFailure>,
) {
    let resources = TempResource::new().expect("resources");
    resources.create_directory("state").expect("state");
    let capabilities = interactive_runtime_capabilities();
    let runtime = Arc::new(FakeRuntime::new(capabilities.clone()).expect("runtime"));
    let (host, _guest) = tokio::io::duplex(4096);
    runtime.set_control_stream(Box::new(host));
    let plan = interactive_plan(&resources, &capabilities, SessionId::from_bytes([9; 16]))
        .expect("interactive run plan");
    assert!(plan.interactive());
    let (drained, exit_gate) = tokio::sync::watch::channel(false);
    let log = Arc::new(TerminalLog {
        launch_terminal: Mutex::new(None),
        commands: Mutex::new(Vec::new()),
        expected: expected_commands,
        drained,
    });
    let connector = Arc::new(InteractiveConnector {
        log: Arc::clone(&log),
        events: Mutex::new(Some(events)),
        exit_gate,
    });
    let report = AgentOrchestrator::new(
        runtime,
        Arc::new(FakeSecrets),
        connector,
        Arc::new(RecordingOutput::default()),
        Arc::new(NoSignals),
    )
    .with_terminal(
        sendbox_agent::GuestTerminalSize {
            columns: 120,
            rows: 40,
            term: "xterm-256color".to_owned(),
            separate_stderr: false,
        },
        Arc::new(ScriptedTerminal {
            commands: Mutex::new(commands),
        }),
    )
    .run(&plan, &CancellationToken::new())
    .await;
    (log, report)
}

#[tokio::test]
async fn interactive_run_requests_a_terminal_and_forwards_input_before_output() {
    let (log, report) = interactive_run(
        VecDeque::from([
            sendbox_agent::HostTerminalCommand::Input(b"ls\r".to_vec()),
            sendbox_agent::HostTerminalCommand::Resize {
                columns: 100,
                rows: 30,
            },
        ]),
        2,
        VecDeque::from([Ok(GuestEvent::Output {
            stream: OutputStream::Stdout,
            bytes: b"ls\r\n".to_vec(),
        })]),
    )
    .await;

    report.expect("interactive run succeeds");
    let launch = log
        .launch_terminal
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone()
        .expect("launch observed")
        .expect("terminal requested");
    assert_eq!(launch.columns, 120);
    assert_eq!(launch.rows, 40);
    assert_eq!(launch.term, "xterm-256color");
    assert_eq!(
        *log.commands
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()),
        vec!["input:ls\r".to_owned(), "resize:100x30".to_owned()]
    );
}

#[tokio::test]
async fn interactive_run_stops_forwarding_input_after_end_of_file() {
    let (log, report) = interactive_run(
        VecDeque::from([
            sendbox_agent::HostTerminalCommand::InputEof,
            sendbox_agent::HostTerminalCommand::Input(b"ignored".to_vec()),
        ]),
        1,
        VecDeque::new(),
    )
    .await;

    report.expect("interactive run succeeds");
    assert_eq!(
        *log.commands
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()),
        vec!["eof".to_owned()]
    );
}

#[tokio::test]
async fn headless_run_never_requests_a_terminal() {
    let runtime = Arc::new(FakeRuntime::new(runtime_capabilities()).expect("runtime"));
    let report = fake_run(
        Arc::new(FakeConnector::successful()),
        Arc::new(RecordingOutput::default()),
        Arc::new(NoSignals),
        runtime,
    )
    .await;

    report.expect("headless run succeeds");
}

#[test]
fn interactive_plan_requires_the_runtime_terminal_capability() {
    let resources = TempResource::new().expect("resources");
    resources.create_directory("state").expect("state");
    let error = interactive_plan(
        &resources,
        &runtime_capabilities(),
        SessionId::from_bytes([11; 16]),
    )
    .expect_err("interactive plan is rejected");

    match error {
        AgentError::RuntimeCapabilities(message) => {
            assert!(
                message.contains("InteractiveTerminal"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn headless_plan_does_not_require_the_runtime_terminal_capability() {
    let resources = TempResource::new().expect("resources");
    resources.create_directory("state").expect("state");
    let plan = plan(
        &resources,
        &runtime_capabilities(),
        SessionId::from_bytes([12; 16]),
    );

    assert!(!plan.interactive());
}
