use std::sync::{Arc, Mutex};

use sendbox_protocol::{
    AGENT_LAUNCH_OPERATION, BootstrapSecret, Capability, CloseCode, Event, EventKind, FrameLimits,
    GracefulClose, GuestHandshake, HandshakeConfig, HealthResponseV2, INTERACTIVE_LAUNCH_OPERATION,
    INTERACTIVE_LAUNCH_OPERATION_V2, InteractiveLaunchRequestV1, InteractiveLaunchRequestV2,
    LaunchRequestV2, Message, OPERATION_SCHEMA_VERSION, ProtocolErrorCode, ProtocolErrorMessage,
    Request, Response, ResponseStatus, TerminalInputCreditV1, TerminalResultV2, TerminalSizeV1,
    SAFE_OUTPUTS_COLLECT_OPERATION, SAFE_OUTPUTS_OPERATION_SCHEMA_VERSION,
    SafeOutputsCollectRequestV1, SafeOutputsCollectionV1, TerminalStateV1, VersionRange,
    agent_guest_capabilities, agent_guest_required_capabilities,
};
use sendbox_secrets::{
    EnvelopeBinding, EnvelopeCipher, RecipientRole, ReplayGuard, SecretName, SessionKeyMaterial,
};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf,
};
use tokio::net::UnixStream;

use crate::GuestError;
use crate::broker::BrokerClientConfiguration;
use crate::runtime::{ReadinessSnapshot, RuntimeSession};
use crate::safe_outputs::SafeOutputsHandle;
use crate::service::ReadinessGate;
use crate::state::{StartupState, StartupStateMachine};

pub fn handshake_config(
    session_id: sendbox_core::SessionId,
    bootstrap_secret: BootstrapSecret,
    boundary_plan_digest: sendbox_core::BoundaryPlanDigest,
) -> Result<HandshakeConfig, GuestError> {
    HandshakeConfig::new(
        session_id,
        VersionRange::default(),
        agent_guest_capabilities(),
        agent_guest_required_capabilities(),
        FrameLimits::default(),
        bootstrap_secret,
        boundary_plan_digest,
    )
    .map_err(GuestError::from)
}

pub(crate) struct GuestSecretDecryptor {
    session_id: sendbox_core::SessionId,
    boundary_plan_digest: sendbox_core::BoundaryPlanDigest,
    cipher: EnvelopeCipher,
    replay_guard: ReplayGuard,
}

impl GuestSecretDecryptor {
    pub(crate) fn new(
        session_id: sendbox_core::SessionId,
        material: &[u8],
        boundary_plan_digest: sendbox_core::BoundaryPlanDigest,
    ) -> Result<Self, GuestError> {
        let material = SessionKeyMaterial::new(material.to_vec())
            .map_err(|error| GuestError::Protocol(format!("prepare secret key: {error}")))?;
        let cipher = EnvelopeCipher::new(&material, session_id).map_err(|error| {
            GuestError::Protocol(format!("derive secret envelope key: {error}"))
        })?;
        Ok(Self {
            session_id,
            boundary_plan_digest,
            cipher,
            replay_guard: ReplayGuard::default(),
        })
    }
}

pub(crate) struct ProtocolServices {
    state: Arc<Mutex<StartupStateMachine>>,
    service_readiness: Arc<ReadinessGate>,
    runtime: Arc<RuntimeSession>,
    readiness: ReadinessSnapshot,
    broker: Option<BrokerClientConfiguration>,
    secret_decryptor: GuestSecretDecryptor,
    safe_outputs: Option<SafeOutputsHandle>,
}

impl ProtocolServices {
    pub(crate) fn new(
        state: Arc<Mutex<StartupStateMachine>>,
        service_readiness: Arc<ReadinessGate>,
        runtime: Arc<RuntimeSession>,
        readiness: ReadinessSnapshot,
        broker: Option<BrokerClientConfiguration>,
        secret_decryptor: GuestSecretDecryptor,
        safe_outputs: Option<SafeOutputsHandle>,
    ) -> Self {
        Self {
            state,
            service_readiness,
            runtime,
            readiness,
            broker,
            secret_decryptor,
            safe_outputs,
        }
    }
}

pub(crate) async fn serve_authenticated<S>(
    stream: S,
    config: HandshakeConfig,
    services: ProtocolServices,
) -> Result<(), GuestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if services.state.lock().expect("state mutex").state() != StartupState::Ready
        || !services.service_readiness.verified_live()
    {
        return Err(GuestError::Protocol(
            "authenticated readiness requested before local readiness".to_owned(),
        ));
    }

    let mut handshake = GuestHandshake::new(config);
    let connection = handshake.establish(stream).await?;
    if services.safe_outputs.is_some()
        && !connection
            .negotiated()
            .capabilities
            .contains(Capability::SafeOutputs)
    {
        return Err(GuestError::Protocol(
            "Safe Outputs capability was not negotiated".to_owned(),
        ));
    }
    let (mut reader, mut writer) = connection.into_parts();
    if !services.service_readiness.verified_live()
        || services
            .safe_outputs
            .as_ref()
            .is_some_and(|safe_outputs| !safe_outputs.verified_live())
    {
        return Err(GuestError::Protocol(
            "mandatory service failed during authenticated handshake".to_owned(),
        ));
    }
    let readiness_payload = serde_json::to_vec(&services.readiness)
        .map_err(|error| GuestError::Protocol(format!("encoding readiness: {error}")))?;
    writer
        .send(&Message::Event(Event {
            stream_id: 0,
            kind: EventKind::Lifecycle,
            payload: readiness_payload,
        }))
        .await?;

    loop {
        match reader.receive().await? {
            Message::Request(request) if request.operation == AGENT_LAUNCH_OPERATION => {
                launch(
                    request,
                    &mut reader,
                    &mut writer,
                    &services,
                    LaunchMode::Headless,
                )
                .await?;
            }
            Message::Request(request) if request.operation == INTERACTIVE_LAUNCH_OPERATION => {
                launch(
                    request,
                    &mut reader,
                    &mut writer,
                    &services,
                    LaunchMode::InteractiveV1,
                )
                .await?;
            }
            Message::Request(request) if request.operation == INTERACTIVE_LAUNCH_OPERATION_V2 => {
                launch(
                    request,
                    &mut reader,
                    &mut writer,
                    &services,
                    LaunchMode::InteractiveV2,
                )
                .await?;
            }
            Message::Request(request) if request.operation == SAFE_OUTPUTS_COLLECT_OPERATION => {
                collect_safe_outputs(request, &mut writer, &services).await?;
            }
            Message::Request(request) => {
                let response =
                    handle_request(request, &services.service_readiness, &services.readiness)?;
                writer.send(&Message::Response(response)).await?;
            }
            Message::GracefulClose(close) => {
                writer
                    .send(&Message::GracefulClose(GracefulClose {
                        code: CloseCode::Shutdown,
                        reason: format!("guest closing after {}", close.reason),
                    }))
                    .await?;
                return Ok(());
            }
            Message::Cancellation(_) => {
                writer
                    .send(&Message::ProtocolError(ProtocolErrorMessage {
                        code: ProtocolErrorCode::InvalidState,
                        detail: "no active operation can be cancelled".to_owned(),
                    }))
                    .await?;
            }
            other => {
                writer
                    .send(&Message::ProtocolError(ProtocolErrorMessage {
                        code: ProtocolErrorCode::InvalidState,
                        detail: format!("unexpected application message {}", other.kind() as u8),
                    }))
                    .await?;
            }
        }
    }
}

fn handle_request(
    request: Request,
    service_readiness: &ReadinessGate,
    readiness: &ReadinessSnapshot,
) -> Result<Response, GuestError> {
    let (status, payload) = match request.operation.as_str() {
        "health" if service_readiness.verified_live() => (
            ResponseStatus::Ok,
            serde_json::to_vec(&HealthResponseV2 {
                schema_version: OPERATION_SCHEMA_VERSION,
                ready: true,
                broker_live: true,
                release_sequence: readiness.release_sequence,
            })
            .map_err(|error| GuestError::Protocol(format!("encoding health: {error}")))?,
        ),
        "health" => (
            ResponseStatus::Rejected,
            serde_json::to_vec(&HealthResponseV2 {
                schema_version: OPERATION_SCHEMA_VERSION,
                ready: false,
                broker_live: false,
                release_sequence: readiness.release_sequence,
            })
            .map_err(|error| GuestError::Protocol(format!("encoding health: {error}")))?,
        ),
        _ => (
            ResponseStatus::Rejected,
            br#"{"implemented":false,"reason":"operation-not-supported"}"#.to_vec(),
        ),
    };
    Ok(Response {
        request_id: request.request_id,
        status,
        payload,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchMode {
    Headless,
    InteractiveV1,
    InteractiveV2,
}

impl LaunchMode {
    const fn is_interactive(self) -> bool {
        !matches!(self, Self::Headless)
    }

    const fn uses_flow_control(self) -> bool {
        matches!(self, Self::InteractiveV2)
    }
}

async fn launch<S>(
    request: Request,
    host_reader: &mut sendbox_protocol::FramedReader<ReadHalf<S>>,
    host_writer: &mut sendbox_protocol::FramedWriter<WriteHalf<S>>,
    services: &ProtocolServices,
    mode: LaunchMode,
) -> Result<(), GuestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !services.service_readiness.verified_live()
        || services
            .safe_outputs
            .as_ref()
            .is_some_and(|safe_outputs| !safe_outputs.verified_live())
    {
        return send_rejection(
            host_writer,
            request.request_id,
            "mandatory-service-not-live",
        )
        .await;
    }
    let Some(broker) = services.broker.as_ref() else {
        return send_rejection(
            host_writer,
            request.request_id,
            "execution-broker-not-configured",
        )
        .await;
    };
    let (launch, terminal) = match mode {
        LaunchMode::Headless => {
            let launch: LaunchRequestV2 =
                serde_json::from_slice(&request.payload).map_err(|error| {
                    GuestError::Protocol(format!("decoding launch request: {error}"))
                })?;
            (launch, None)
        }
        LaunchMode::InteractiveV1 => {
            let envelope: InteractiveLaunchRequestV1 = serde_json::from_slice(&request.payload)
                .map_err(|error| {
                    GuestError::Protocol(format!("decoding interactive launch request: {error}"))
                })?;
            if let Err(error) = envelope.validate() {
                return send_rejection(host_writer, request.request_id, &error.to_string()).await;
            }
            (
                envelope.launch,
                Some((envelope.terminal, envelope.term, false, false)),
            )
        }
        LaunchMode::InteractiveV2 => {
            let envelope: InteractiveLaunchRequestV2 = serde_json::from_slice(&request.payload)
                .map_err(|error| {
                    GuestError::Protocol(format!(
                        "decoding flow-controlled interactive launch request: {error}"
                    ))
                })?;
            if let Err(error) = envelope.validate() {
                return send_rejection(host_writer, request.request_id, &error.to_string()).await;
            }
            (
                envelope.launch,
                Some((
                    envelope.terminal,
                    envelope.term,
                    envelope.separate_stderr,
                    true,
                )),
            )
        }
    };
    if launch.schema_version != OPERATION_SCHEMA_VERSION {
        return send_rejection(
            host_writer,
            request.request_id,
            "unsupported-operation-schema",
        )
        .await;
    }
    if launch.boundary_plan_digest != services.secret_decryptor.boundary_plan_digest {
        return send_rejection(
            host_writer,
            request.request_id,
            "boundary-plan-digest-mismatch",
        )
        .await;
    }
    let launch_permitted = {
        let mut machine = services.state.lock().expect("state mutex");
        if machine.permit_agent_launch().is_ok() {
            services.runtime.write_state(machine.state())?;
            true
        } else {
            false
        }
    };
    if !launch_permitted {
        return send_rejection(host_writer, request.request_id, "readiness-not-available").await;
    }

    let execution = build_execution_request(&launch, terminal, broker, &services.secret_decryptor)?;
    let stream = UnixStream::connect(&broker.socket_path)
        .await
        .map_err(|error| GuestError::io("connecting execution broker", error))?;
    let (read, mut write) = stream.into_split();
    send_broker_frame(
        &mut write,
        &sendbox_exec::service::ClientFrame::Execute {
            request: Box::new(execution.clone()),
        },
    )
    .await?;
    // A dedicated writer task owns the broker socket so the loop below never
    // blocks in send while broker output is still pending. Control frames use
    // their own channel and are always drained first, so bulk terminal input
    // can never delay a cancel.
    let (control_sender, mut control_receiver) = tokio::sync::mpsc::channel(BROKER_CONTROL_DEPTH);
    let (input_sender, mut input_receiver) = tokio::sync::mpsc::channel(BROKER_INPUT_DEPTH);
    let (eof_sender, mut eof_receiver) = tokio::sync::mpsc::channel(1);
    let (resize_sender, mut resize_receiver) =
        tokio::sync::watch::channel::<Option<sendbox_exec::service::ClientFrame>>(None);
    let writer_task = tokio::spawn(async move {
        let mut eof_pending = None;
        loop {
            if let Some(eof) = eof_pending.take() {
                if let Ok(control) = control_receiver.try_recv() {
                    eof_pending = Some(eof);
                    if send_broker_frame(&mut write, &control).await.is_err() {
                        return;
                    }
                    continue;
                }
                match input_receiver.try_recv() {
                    Ok(input) => {
                        eof_pending = Some(eof);
                        if send_broker_frame(&mut write, &input).await.is_err() {
                            return;
                        }
                        continue;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                    | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        if send_broker_frame(&mut write, &eof).await.is_err() {
                            return;
                        }
                        continue;
                    }
                }
            }
            let frame = tokio::select! {
                biased;
                control = control_receiver.recv() => match control {
                    Some(frame) => frame,
                    None => return,
                },
                eof = eof_receiver.recv() => {
                    eof_pending = eof;
                    continue;
                },
                changed = resize_receiver.changed() => match changed {
                    Ok(()) => resize_receiver
                        .borrow_and_update()
                        .clone()
                        .expect("resize notification always carries a frame"),
                    Err(_) => continue,
                },
                input = input_receiver.recv() => match input {
                    Some(frame) => frame,
                    None => continue,
                },
            };
            if send_broker_frame(&mut write, &frame).await.is_err() {
                return;
            }
        }
    });
    let mut input_ended = false;
    let result = run_execution_loop(
        &request,
        &execution,
        services,
        read,
        host_reader,
        host_writer,
        &control_sender,
        BrokerInputSenders {
            input: &input_sender,
            eof: &eof_sender,
            resize: &resize_sender,
        },
        mode,
        &mut input_ended,
    )
    .await;
    drop(control_sender);
    drop(input_sender);
    drop(eof_sender);
    drop(resize_sender);
    writer_task.abort();
    result
}

/// Queue depth for broker control frames (cancel, shutdown).
/// Terminal type handed to an interactive workload.
const TERM_ENVIRONMENT: &str = "TERM";

const BROKER_CONTROL_DEPTH: usize = 4;
/// Queue depth for the credited input window. EOF and resize use independent
/// reserved lanes.
const BROKER_INPUT_DEPTH: usize = sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS as usize;

/// How long a terminal input frame may wait for the broker writer before it is
/// dropped so the execution loop can keep draining broker output.
const INPUT_OFFER_BOUND: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Clone, Copy)]
struct BrokerInputSenders<'a> {
    input: &'a tokio::sync::mpsc::Sender<sendbox_exec::service::ClientFrame>,
    eof: &'a tokio::sync::mpsc::Sender<sendbox_exec::service::ClientFrame>,
    resize: &'a tokio::sync::watch::Sender<Option<sendbox_exec::service::ClientFrame>>,
}

#[allow(clippy::too_many_arguments)]
async fn run_execution_loop<S>(
    request: &Request,
    execution: &sendbox_exec::ExecutionRequest,
    services: &ProtocolServices,
    read: tokio::net::unix::OwnedReadHalf,
    host_reader: &mut sendbox_protocol::FramedReader<ReadHalf<S>>,
    host_writer: &mut sendbox_protocol::FramedWriter<WriteHalf<S>>,
    control_sender: &tokio::sync::mpsc::Sender<sendbox_exec::service::ClientFrame>,
    input_senders: BrokerInputSenders<'_>,
    mode: LaunchMode,
    input_ended: &mut bool,
) -> Result<(), GuestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut broker_reader = BufReader::new(read);
    let mut line = Vec::new();
    loop {
        tokio::select! {
            broker_frame = read_broker_frame(&mut broker_reader, &mut line) => {
                let frame = broker_frame?;
                line.clear();
                let Some(sendbox_exec::service::ServerFrame::Event { event }) = frame else {
                    return Err(GuestError::Protocol("execution broker disconnected before terminal".to_owned()));
                };
                match event {
                    sendbox_exec::ExecutionEvent::Started { .. } => {}
                    sendbox_exec::ExecutionEvent::Output { stream, data, .. } => {
                        let kind = match stream {
                            sendbox_exec::StreamKind::Stdout => EventKind::StandardOutput,
                            sendbox_exec::StreamKind::Stderr => EventKind::StandardError,
                        };
                        host_writer.send(&Message::Event(Event {
                            stream_id: request.request_id,
                            kind,
                            payload: data,
                        })).await?;
                    }
                    sendbox_exec::ExecutionEvent::TerminalInputCredit { credits, .. } => {
                        if !mode.uses_flow_control() {
                            return Err(GuestError::Protocol(
                                "execution broker emitted terminal input credit for a V1 launch"
                                    .to_owned(),
                            ));
                        }
                        let credit = TerminalInputCreditV1::new(credits).map_err(|error| {
                            GuestError::Protocol(format!(
                                "execution broker emitted invalid terminal input credit: {error}"
                            ))
                        })?;
                        let payload = serde_json::to_vec(&credit).map_err(|error| {
                            GuestError::Protocol(format!(
                                "encoding terminal input credit: {error}"
                            ))
                        })?;
                        host_writer.send(&Message::Event(Event {
                            stream_id: request.request_id,
                            kind: EventKind::TerminalInputCredit,
                            payload,
                        })).await?;
                    }
                    sendbox_exec::ExecutionEvent::Terminal { result, .. } => {
                        let terminal = terminal_result(result);
                        if let Some(safe_outputs) = &services.safe_outputs {
                            if !terminal.cleanup_complete {
                                return Err(GuestError::Protocol(
                                    "Safe Outputs cannot seal before execution cleanup completes"
                                        .to_owned(),
                                ));
                            }
                            safe_outputs.seal().await?;
                        }
                        let payload = serde_json::to_vec(&terminal)
                            .map_err(|error| GuestError::Protocol(format!("encoding terminal result: {error}")))?;
                        host_writer.send(&Message::Response(Response {
                            request_id: request.request_id,
                            status: ResponseStatus::Ok,
                            payload,
                        })).await?;
                        return Ok(());
                    }

                }
            }
            host_message = host_reader.receive() => {
                match host_message? {
                    Message::Cancellation(cancellation) if cancellation.request_id == request.request_id => {
                        let _ = control_sender.send(
                            sendbox_exec::service::ClientFrame::Cancel {
                                correlation_id: execution.correlation_id.clone(),
                            },
                        ).await;
                    }
                    Message::GracefulClose(_) => {
                        let _ = control_sender.send(
                            sendbox_exec::service::ClientFrame::GracefulShutdown,
                        ).await;
                    }
                    Message::Event(event) if event.kind.is_terminal_input() => {
                        if let Err(detail) = forward_terminal_event(
                            &event,
                            request,
                            execution,
                            input_senders,
                            mode,
                            input_ended,
                        ).await {
                            host_writer.send(&Message::ProtocolError(ProtocolErrorMessage {
                                code: ProtocolErrorCode::InvalidState,
                                detail,
                            })).await?;
                            return Err(GuestError::Protocol(
                                "invalid terminal event during execution".to_owned(),
                            ));
                        }
                    }
                    other => {
                        host_writer.send(&Message::ProtocolError(ProtocolErrorMessage {
                            code: ProtocolErrorCode::InvalidState,
                            detail: format!("unexpected message during execution {:?}", other.kind()),
                        })).await?;
                    }
                }
            }
        }
    }
}

async fn collect_safe_outputs<S>(
    request: Request,
    writer: &mut sendbox_protocol::FramedWriter<WriteHalf<S>>,
    services: &ProtocolServices,
) -> Result<(), GuestError>
where
    S: AsyncWrite + Unpin,
{
    let envelope: SafeOutputsCollectRequestV1 =
        serde_json::from_slice(&request.payload).map_err(|error| {
            GuestError::Protocol(format!("decoding Safe Outputs collection: {error}"))
        })?;
    if envelope.schema_version != SAFE_OUTPUTS_OPERATION_SCHEMA_VERSION
        || envelope.boundary_plan_digest != services.secret_decryptor.boundary_plan_digest
    {
        return Err(GuestError::Protocol(
            "Safe Outputs collection binding is invalid".to_owned(),
        ));
    }
    let safe_outputs = services.safe_outputs.as_ref().ok_or_else(|| {
        GuestError::Protocol("Safe Outputs collection was not configured".to_owned())
    })?;
    let collected = safe_outputs.collect().await?;
    let collection = SafeOutputsCollectionV1::new(&collected.artifact, &collected.seal)
        .map_err(|error| GuestError::Protocol(error.to_string()))?;
    let payload = serde_json::to_vec(&collection).map_err(|error| {
        GuestError::Protocol(format!("encoding Safe Outputs collection: {error}"))
    })?;
    writer
        .send(&Message::Response(Response {
            request_id: request.request_id,
            status: ResponseStatus::Ok,
            payload,
        }))
        .await?;
    Ok(())
}

/// Validates and queues one host terminal event.
///
/// Input bytes are never logged; failures report only the reason.
fn validate_terminal_input_payload(mode: LaunchMode, payload: &[u8]) -> Result<(), String> {
    if payload.is_empty() {
        return Err("terminal input chunk must not be empty".to_owned());
    }
    if mode.uses_flow_control() && payload.len() > sendbox_core::TERMINAL_INPUT_CHUNK_BYTES {
        return Err(format!(
            "terminal input chunk must contain 1..={} bytes",
            sendbox_core::TERMINAL_INPUT_CHUNK_BYTES
        ));
    }
    Ok(())
}

async fn forward_terminal_event(
    event: &Event,
    request: &Request,
    execution: &sendbox_exec::ExecutionRequest,
    input_senders: BrokerInputSenders<'_>,
    mode: LaunchMode,
    input_ended: &mut bool,
) -> Result<(), String> {
    if !mode.is_interactive() {
        return Err("terminal input is only accepted for an interactive launch".to_owned());
    }
    if event.stream_id != request.request_id {
        return Err("terminal event referenced an unknown stream".to_owned());
    }
    if *input_ended {
        return Err("terminal input was already ended".to_owned());
    }
    let correlation_id = execution.correlation_id.clone();
    match event.kind {
        EventKind::StandardInput => {
            validate_terminal_input_payload(mode, &event.payload)?;
            let frame = sendbox_exec::service::ClientFrame::Input {
                correlation_id,
                data: event.payload.clone(),
            };
            if mode.uses_flow_control() {
                match input_senders.input.try_send(frame) {
                    Ok(()) => Ok(()),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(
                        "terminal input credit invariant failed: broker writer queue is full"
                            .to_owned(),
                    ),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        Err("broker writer stopped".to_owned())
                    }
                }
            } else {
                if let Err(error) = input_senders
                    .input
                    .send_timeout(frame, INPUT_OFFER_BOUND)
                    .await
                {
                    let dropped = match error {
                        tokio::sync::mpsc::error::SendTimeoutError::Timeout(_) => {
                            "queue is saturated"
                        }
                        tokio::sync::mpsc::error::SendTimeoutError::Closed(_) => {
                            "broker writer stopped"
                        }
                    };
                    eprintln!("sendbox-guest: dropping terminal input: {dropped}");
                }
                Ok(())
            }
        }
        EventKind::StandardInputEof => {
            let frame = sendbox_exec::service::ClientFrame::InputEof { correlation_id };
            match input_senders.eof.try_send(frame) {
                Ok(()) => {
                    *input_ended = true;
                    Ok(())
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    Err("terminal end-of-file reservation is already occupied".to_owned())
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    Err("broker writer stopped".to_owned())
                }
            }
        }
        EventKind::TerminalResize => {
            let size: TerminalSizeV1 = serde_json::from_slice(&event.payload)
                .map_err(|error| format!("decoding terminal resize: {error}"))?;
            size.validate().map_err(|error| error.to_string())?;
            input_senders
                .resize
                .send(Some(sendbox_exec::service::ClientFrame::Resize {
                    correlation_id,
                    columns: size.columns,
                    rows: size.rows,
                }))
                .map_err(|_| "broker writer stopped".to_owned())
        }
        _ => Err("unsupported terminal event kind".to_owned()),
    }
}

fn build_execution_request(
    launch: &LaunchRequestV2,
    terminal: Option<(TerminalSizeV1, String, bool, bool)>,
    broker: &BrokerClientConfiguration,
    secret_decryptor: &GuestSecretDecryptor,
) -> Result<sendbox_exec::ExecutionRequest, GuestError> {
    let (executable_root, executable) = descriptor_path(&launch.program)?;
    let (cwd_root, cwd) = descriptor_path(&launch.working_directory)?;
    let timeout =
        sendbox_exec::ExecutionTimeout::new(std::time::Duration::from_millis(launch.timeout_ms))
            .map_err(|error| GuestError::Protocol(format!("invalid execution timeout: {error}")))?;
    let mut argv = Vec::with_capacity(launch.arguments.len() + 1);
    argv.push(launch.program.clone());
    argv.extend(launch.arguments.clone());
    let mut environment = decrypt_environment(launch, secret_decryptor)?;
    if let Some((_, term, _, _)) = terminal.as_ref() {
        // The host's terminal type is authoritative for an interactive run: a
        // stale configured TERM would make the workload render for the wrong
        // terminal on the operator's screen.
        environment.retain(|entry| entry.name != TERM_ENVIRONMENT);
        environment.push(sendbox_exec::EnvironmentEntry {
            name: TERM_ENVIRONMENT.to_owned(),
            value: term.clone(),
        });
    }
    Ok(sendbox_exec::ExecutionRequest {
        session_id: broker.session_id,
        authentication: broker.authentication.clone(),
        correlation_id: sendbox_exec::CorrelationId::new("agent-launch")
            .map_err(|error| GuestError::Protocol(error.to_string()))?,
        cancellation_id: None,
        executable: sendbox_exec::DescriptorPath {
            root: executable_root,
            relative: executable,
        },
        argv,
        cwd: sendbox_exec::DescriptorPath {
            root: cwd_root,
            relative: cwd,
        },
        environment,
        stdin: match terminal {
            None => sendbox_exec::StandardInput::Null,
            Some((size, _, separate_stderr, flow_controlled)) => {
                sendbox_exec::StandardInput::Terminal {
                    columns: size.columns,
                    rows: size.rows,
                    separate_stderr,
                    flow_controlled,
                }
            }
        },
        timeout,
        containment: sendbox_exec::ContainmentProfile {
            run_as: Some(broker.workload),
            ..sendbox_exec::ContainmentProfile::default()
        },
    })
}

fn decrypt_environment(
    launch: &LaunchRequestV2,
    secret_decryptor: &GuestSecretDecryptor,
) -> Result<Vec<sendbox_exec::EnvironmentEntry>, GuestError> {
    let mut names = std::collections::BTreeSet::new();
    let mut environment = Vec::with_capacity(launch.environment.len() + launch.secrets.len());
    for entry in &launch.environment {
        if !names.insert(entry.name.as_str()) {
            return Err(GuestError::Protocol(format!(
                "duplicate environment name {}",
                entry.name
            )));
        }
        environment.push(sendbox_exec::EnvironmentEntry {
            name: entry.name.clone(),
            value: entry.value.clone(),
        });
    }
    let now = unix_time_ms()?;
    for secret in &launch.secrets {
        if secret.boundary_plan_digest != secret_decryptor.boundary_plan_digest {
            return Err(GuestError::Protocol(format!(
                "secret {} carries a different boundary plan digest",
                secret.reference
            )));
        }
        if !names.insert(secret.reference.as_str()) {
            return Err(GuestError::Protocol(format!(
                "duplicate environment or secret name {}",
                secret.reference
            )));
        }
        let binding = EnvelopeBinding {
            session_id: secret_decryptor.session_id,
            recipient: RecipientRole::Guest,
            secret_name: SecretName::new(secret.reference.clone())
                .map_err(|error| GuestError::Protocol(format!("invalid secret name: {error}")))?,
            sequence: secret.sequence,
            expires_at_unix_ms: secret.expires_at_unix_ms,
            policy_digest: secret.policy_digest,
            boundary_plan_digest: secret_decryptor.boundary_plan_digest,
        };
        let value = secret_decryptor
            .cipher
            .open(
                &secret.envelope,
                &binding,
                &secret_decryptor.replay_guard,
                now,
            )
            .map_err(|error| GuestError::Protocol(format!("open secret envelope: {error}")))?;
        let value = String::from_utf8(value.expose_secret().to_vec()).map_err(|_| {
            GuestError::Protocol(format!(
                "secret {} is not valid UTF-8 for environment injection",
                secret.reference
            ))
        })?;
        environment.push(sendbox_exec::EnvironmentEntry {
            name: secret.reference.clone(),
            value,
        });
    }
    Ok(environment)
}

fn unix_time_ms() -> Result<u64, GuestError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| GuestError::Protocol(format!("read system time: {error}")))?
        .as_millis()
        .try_into()
        .map_err(|_| GuestError::Protocol("system time is out of range".to_owned()))
}

fn descriptor_path(
    absolute: &str,
) -> Result<(sendbox_exec::RootId, sendbox_exec::RelativePath), GuestError> {
    let path = std::path::Path::new(absolute);
    if !path.is_absolute() {
        return Err(GuestError::Protocol(
            "brokered executable and cwd paths must be absolute".to_owned(),
        ));
    }
    let (root, relative) = match path.strip_prefix("/workspace") {
        Ok(relative) => (sendbox_exec::RootId::Workspace, relative),
        Err(_) => (
            sendbox_exec::RootId::System,
            path.strip_prefix("/").expect("absolute path has root"),
        ),
    };
    let relative = if relative.as_os_str().is_empty() {
        "."
    } else {
        relative
            .to_str()
            .ok_or_else(|| GuestError::Protocol("execution path is not UTF-8".to_owned()))?
    };
    Ok((
        root,
        sendbox_exec::RelativePath::new(relative)
            .map_err(|error| GuestError::Protocol(error.to_string()))?,
    ))
}

fn terminal_result(result: sendbox_exec::ExecutionResult) -> TerminalResultV2 {
    use sendbox_exec::TerminalState;
    let terminal = match result.terminal {
        TerminalState::Exited(status) => TerminalStateV1::Exited {
            exit_code: status.exit_code,
            signal: status.signal,
        },
        TerminalState::Rejected { reason } => TerminalStateV1::Rejected { reason },
        TerminalState::LaunchFailed(failure) => TerminalStateV1::LaunchFailed {
            message: format!("{failure:?}"),
        },
        TerminalState::TimedOut => TerminalStateV1::TimedOut,
        TerminalState::Cancelled => TerminalStateV1::Cancelled,
        TerminalState::ClientDisconnected => TerminalStateV1::ClientDisconnected,
        TerminalState::OutputSaturated => TerminalStateV1::OutputSaturated,
        TerminalState::BrokerShutdown => TerminalStateV1::BrokerShutdown,
        TerminalState::SupervisorDied => TerminalStateV1::SupervisorDied,
    };
    TerminalResultV2 {
        schema_version: OPERATION_SCHEMA_VERSION,
        terminal,
        cleanup_complete: result.cleanup.is_complete(),
    }
}

async fn send_rejection<S>(
    writer: &mut sendbox_protocol::FramedWriter<WriteHalf<S>>,
    request_id: u64,
    reason: &str,
) -> Result<(), GuestError>
where
    S: AsyncWrite + Unpin,
{
    writer
        .send(&Message::Response(Response {
            request_id,
            status: ResponseStatus::Rejected,
            payload: serde_json::to_vec(&TerminalResultV2 {
                schema_version: OPERATION_SCHEMA_VERSION,
                terminal: TerminalStateV1::Rejected {
                    reason: reason.to_owned(),
                },
                cleanup_complete: false,
            })
            .map_err(|error| GuestError::Protocol(format!("encoding rejection: {error}")))?,
        }))
        .await?;
    Ok(())
}

async fn send_broker_frame(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    frame: &sendbox_exec::service::ClientFrame,
) -> Result<(), GuestError> {
    let encoded = serde_json::to_vec(frame)
        .map_err(|error| GuestError::Protocol(format!("encoding broker frame: {error}")))?;
    if encoded.len() > sendbox_exec::service::MAX_SERVICE_FRAME_BYTES {
        return Err(GuestError::Protocol(
            "broker frame exceeds limit".to_owned(),
        ));
    }
    writer
        .write_all(&encoded)
        .await
        .map_err(|error| GuestError::io("writing broker frame", error))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|error| GuestError::io("writing broker frame terminator", error))
}

async fn read_broker_frame<R>(
    reader: &mut BufReader<R>,
    line: &mut Vec<u8>,
) -> Result<Option<sendbox_exec::service::ServerFrame>, GuestError>
where
    R: AsyncRead + Unpin,
{
    let bytes = reader
        .read_until(b'\n', line)
        .await
        .map_err(|error| GuestError::io("reading broker frame", error))?;
    if bytes == 0 {
        return Ok(None);
    }
    if line.len() > sendbox_exec::service::MAX_SERVICE_FRAME_BYTES + 1 {
        return Err(GuestError::Protocol(
            "broker frame exceeds limit".to_owned(),
        ));
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    serde_json::from_slice(line)
        .map(Some)
        .map_err(|error| GuestError::Protocol(format!("decoding broker frame: {error}")))
}

#[cfg(test)]
mod tests {
    use rustix::process::{getgid, getuid};
    use sendbox_core::{BoundaryPlanDigest, SessionId};
    use sendbox_protocol::{HostHandshake, Message, Request};
    use tempfile::tempdir;

    use super::*;
    use crate::runtime::RuntimeIdentity;

    #[test]
    fn legacy_terminal_input_keeps_its_pre_v2_frame_size() {
        let payload = vec![b'x'; sendbox_core::TERMINAL_INPUT_CHUNK_BYTES + 1];
        validate_terminal_input_payload(LaunchMode::InteractiveV1, &payload)
            .expect("V1 input remains frame-bounded, not chunk-bounded");
        assert!(
            validate_terminal_input_payload(LaunchMode::InteractiveV2, &payload).is_err(),
            "V2 must enforce the credited chunk size"
        );
    }

    #[test]
    fn broker_writer_reserves_eof_and_coalesces_resizes() {
        let (input_sender, _input_receiver) = tokio::sync::mpsc::channel(BROKER_INPUT_DEPTH);
        let (eof_sender, _eof_receiver) = tokio::sync::mpsc::channel(1);
        let (resize_sender, resize_receiver) =
            tokio::sync::watch::channel::<Option<sendbox_exec::service::ClientFrame>>(None);
        let correlation_id =
            sendbox_exec::CorrelationId::new("queue-reservations").expect("correlation");

        for _ in 0..BROKER_INPUT_DEPTH {
            input_sender
                .try_send(sendbox_exec::service::ClientFrame::Input {
                    correlation_id: correlation_id.clone(),
                    data: vec![b'x'],
                })
                .expect("credited input");
        }
        assert!(matches!(
            input_sender.try_send(sendbox_exec::service::ClientFrame::Input {
                correlation_id: correlation_id.clone(),
                data: vec![b'x'],
            }),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_))
        ));
        eof_sender
            .try_send(sendbox_exec::service::ClientFrame::InputEof {
                correlation_id: correlation_id.clone(),
            })
            .expect("reserved end of file");
        resize_sender
            .send(Some(sendbox_exec::service::ClientFrame::Resize {
                correlation_id: correlation_id.clone(),
                columns: 80,
                rows: 24,
            }))
            .expect("first resize");
        resize_sender
            .send(Some(sendbox_exec::service::ClientFrame::Resize {
                correlation_id,
                columns: 120,
                rows: 40,
            }))
            .expect("replacement resize");
        assert!(matches!(
            resize_receiver.borrow().as_ref(),
            Some(sendbox_exec::service::ClientFrame::Resize {
                columns: 120,
                rows: 40,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn handshake_is_unreachable_before_local_readiness() {
        let temporary = tempdir().expect("temporary directory");
        let runtime = Arc::new(
            RuntimeSession::prepare(
                &temporary.path().join("run"),
                SessionId::from_bytes([3; 16]),
                RuntimeIdentity {
                    uid: getuid().as_raw(),
                    gid: getgid().as_raw(),
                },
            )
            .expect("runtime"),
        );
        let (guest, _host) = tokio::io::duplex(1024);
        let result = serve_authenticated(
            guest,
            handshake_config(
                SessionId::from_bytes([3; 16]),
                BootstrapSecret::new([9; 32]).expect("secret"),
                BoundaryPlanDigest::from_bytes([0x91; 32]),
            )
            .expect("config"),
            ProtocolServices::new(
                Arc::new(Mutex::new(StartupStateMachine::default())),
                ReadinessGate::test_ready(),
                runtime,
                ReadinessSnapshot {
                    session_id: SessionId::from_bytes([3; 16]),
                    state: StartupState::Ready,
                    release_sequence: 1,
                    controls: Vec::new(),
                    services: Vec::new(),
                    audit_events: Vec::new(),
                },
                None,
                GuestSecretDecryptor::new(
                    SessionId::from_bytes([3; 16]),
                    &[9; 32],
                    BoundaryPlanDigest::from_bytes([0x91; 32]),
                )
                .expect("secret decryptor"),
                None,
            ),
        )
        .await;
        assert!(matches!(result, Err(GuestError::Protocol(_))));
    }

    #[tokio::test]
    async fn authenticated_launch_requires_a_configured_broker() {
        let temporary = tempdir().expect("temporary directory");
        let session_id = SessionId::from_bytes([4; 16]);
        let boundary_plan_digest = BoundaryPlanDigest::from_bytes([0x92; 32]);
        let runtime = Arc::new(
            RuntimeSession::prepare(
                &temporary.path().join("run"),
                session_id,
                RuntimeIdentity {
                    uid: getuid().as_raw(),
                    gid: getgid().as_raw(),
                },
            )
            .expect("runtime"),
        );
        let mut machine = StartupStateMachine::default();
        for next in [
            StartupState::BootstrapConsumed,
            StartupState::ManifestVerified,
            StartupState::RuntimePrepared,
            StartupState::ServicesStarting,
            StartupState::ControlsVerified,
            StartupState::SelfTesting,
            StartupState::Ready,
        ] {
            machine.transition(next).expect("transition");
        }
        let state = Arc::new(Mutex::new(machine));
        let readiness = ReadinessSnapshot {
            session_id,
            state: StartupState::Ready,
            release_sequence: 1,
            controls: Vec::new(),
            services: Vec::new(),
            audit_events: Vec::new(),
        };
        let (host_stream, guest_stream) = tokio::io::duplex(16 * 1024);
        let guest = tokio::spawn(serve_authenticated(
            guest_stream,
            handshake_config(
                session_id,
                BootstrapSecret::new([8; 32]).expect("secret"),
                boundary_plan_digest,
            )
            .expect("guest config"),
            ProtocolServices::new(
                Arc::clone(&state),
                ReadinessGate::test_ready(),
                runtime,
                readiness,
                None,
                GuestSecretDecryptor::new(session_id, &[8; 32], boundary_plan_digest)
                    .expect("secret decryptor"),
                None,
            ),
        ));
        let mut host_handshake = HostHandshake::new(
            HandshakeConfig::new(
                session_id,
                VersionRange::default(),
                sendbox_protocol::agent_host_capabilities(),
                sendbox_protocol::agent_host_required_capabilities(),
                FrameLimits::default(),
                BootstrapSecret::new([8; 32]).expect("secret"),
                boundary_plan_digest,
            )
            .expect("host config"),
        );
        let connection = host_handshake
            .establish(host_stream)
            .await
            .expect("host handshake");
        let (mut reader, mut writer) = connection.into_parts();
        assert!(matches!(
            reader.receive().await.expect("readiness event"),
            Message::Event(Event {
                kind: EventKind::Lifecycle,
                ..
            })
        ));
        for request_id in [1, 2] {
            writer
                .send(&Message::Request(Request {
                    request_id,
                    operation: "agent.launch".to_owned(),
                    payload: Vec::new(),
                }))
                .await
                .expect("launch request");
            assert!(matches!(
                reader.receive().await.expect("launch response"),
                Message::Response(Response {
                    status: ResponseStatus::Rejected,
                    ..
                })
            ));
        }
        writer
            .send(&Message::GracefulClose(GracefulClose {
                code: CloseCode::Normal,
                reason: "test complete".to_owned(),
            }))
            .await
            .expect("close");
        assert!(matches!(
            reader.receive().await.expect("close response"),
            Message::GracefulClose(_)
        ));
        guest.await.expect("guest task").expect("guest protocol");
    }

    #[tokio::test]
    async fn broker_frame_read_resumes_after_the_read_future_is_cancelled() {
        use tokio::io::AsyncWriteExt;

        let (read, mut peer) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(read);
        let mut line = Vec::new();
        let encoded = serde_json::to_vec(&sendbox_exec::service::ServerFrame::ProtocolError {
            message: "fixture".to_owned(),
        })
        .expect("frame");
        let split = encoded.len() / 2;
        peer.write_all(&encoded[..split])
            .await
            .expect("partial frame");
        tokio::select! {
            biased;
            result = read_broker_frame(&mut reader, &mut line) => {
                panic!("partial frame unexpectedly completed: {result:?}");
            }
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(line, encoded[..split]);
        peer.write_all(&encoded[split..]).await.expect("frame rest");
        peer.write_all(b"\n").await.expect("frame terminator");
        assert!(matches!(
            read_broker_frame(&mut reader, &mut line)
                .await
                .expect("resumed frame"),
            Some(sendbox_exec::service::ServerFrame::ProtocolError { message })
                if message == "fixture"
        ));
    }
}
