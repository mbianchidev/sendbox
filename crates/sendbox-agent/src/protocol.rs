use crate::traits::HostTerminalCommand;
use sendbox_protocol::{
    AGENT_LAUNCH_OPERATION, BootstrapSecret, CapabilitySet, CloseCode, EnvironmentEntryV2, Event,
    EventKind, FrameLimits, GracefulClose, HandshakeConfig, HostHandshake,
    INTERACTIVE_LAUNCH_OPERATION_V2, INTERACTIVE_OPERATION_SCHEMA_VERSION_V2,
    InteractiveLaunchRequestV2, LaunchRequestV2, Message, OPERATION_SCHEMA_VERSION, Request,
    ResponseStatus, SecretEnvelopeV2, TerminalInputCreditV1, TerminalResultV2, TerminalSizeV1,
    SAFE_OUTPUTS_COLLECT_OPERATION, SAFE_OUTPUTS_OPERATION_SCHEMA_VERSION,
    SafeOutputsCollectRequestV1, SafeOutputsCollectionV1, TerminalStateV1, VersionRange,
};
use sendbox_runtime::{CancellationToken, ControlStream, OutputStream};
use sendbox_secrets::{
    EnvelopeBinding, EnvelopeCipher, RecipientRole, SecretName, SecretValue, SessionKeyMaterial,
};

use std::{
    collections::BTreeSet,
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    AgentError, BoxFuture, GuestConnectionConfiguration, GuestConnector, GuestEvent,
    GuestExecution, GuestLaunchRequest, GuestSession, GuestTerminal,
};

const REQUEST_ID: u64 = 1;
const SAFE_OUTPUTS_REQUEST_ID: u64 = 2;
const PROTOCOL_IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct ProtocolGuestConnector;

impl GuestConnector for ProtocolGuestConnector {
    fn connect<'a>(
        &'a self,
        stream: Box<dyn ControlStream>,
        configuration: GuestConnectionConfiguration,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestSession>, AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(AgentError::Cancelled);
            }
            let material = SessionKeyMaterial::new(configuration.bootstrap_secret.clone())
                .map_err(|error| AgentError::Guest(format!("prepare secret key: {error}")))?;
            let secret_cipher =
                EnvelopeCipher::new(&material, configuration.session_id).map_err(|error| {
                    AgentError::Guest(format!("derive secret envelope key: {error}"))
                })?;
            let handshake = HandshakeConfig::new(
                configuration.session_id,
                VersionRange::default(),
                configuration.capabilities,
                configuration.required_capabilities,
                FrameLimits::default(),
                BootstrapSecret::new(configuration.bootstrap_secret)?,
                configuration.boundary_plan_digest,
            )?;
            let mut host = HostHandshake::new(handshake);
            let connection = host.establish(stream).await?;
            let negotiated = connection.negotiated().capabilities.clone();
            let (mut reader, writer) = connection.into_parts();
            let readiness =
                protocol_io("receive guest readiness", cancellation, reader.receive()).await?;
            let Message::Event(readiness) = readiness else {
                return Err(AgentError::Guest(
                    "guest omitted authenticated operational readiness".to_owned(),
                ));
            };
            if readiness.kind != EventKind::Lifecycle {
                return Err(AgentError::Guest(
                    "guest readiness used an unexpected event kind".to_owned(),
                ));
            }
            validate_operational_readiness(&readiness.payload)?;
            Ok(Box::new(ProtocolGuestSession {
                negotiated,
                reader: Some(reader),
                writer: Some(writer),
                session_id: configuration.session_id,
                policy_digest: configuration.policy_digest,
                boundary_plan_digest: configuration.boundary_plan_digest,
                secret_cipher,
                next_secret_sequence: 1,
            }) as Box<dyn GuestSession>)
        })
    }
}

pub struct ProtocolGuestSession {
    negotiated: CapabilitySet,
    reader: Option<sendbox_protocol::FramedReader<tokio::io::ReadHalf<Box<dyn ControlStream>>>>,
    writer: Option<sendbox_protocol::FramedWriter<tokio::io::WriteHalf<Box<dyn ControlStream>>>>,
    session_id: sendbox_core::SessionId,
    policy_digest: [u8; 32],
    boundary_plan_digest: sendbox_core::BoundaryPlanDigest,
    secret_cipher: EnvelopeCipher,
    next_secret_sequence: u64,
}

impl GuestSession for ProtocolGuestSession {
    fn negotiated_capabilities(&self) -> &CapabilitySet {
        &self.negotiated
    }

    fn start<'a>(
        &'a mut self,
        request: GuestLaunchRequest<'a>,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestExecution>, AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(AgentError::Cancelled);
            }
            let secrets = seal_secrets(
                request.environment,
                request.secrets,
                self.session_id,
                self.policy_digest,
                self.boundary_plan_digest,
                &mut self.secret_cipher,
                &mut self.next_secret_sequence,
            )?;
            let launch = LaunchRequestV2 {
                schema_version: OPERATION_SCHEMA_VERSION,
                boundary_plan_digest: self.boundary_plan_digest,
                program: request.command.program.clone(),
                arguments: request.command.arguments.clone(),
                working_directory: request.command.working_directory.clone(),
                environment: request
                    .environment
                    .iter()
                    .map(|entry| EnvironmentEntryV2 {
                        name: entry.name.clone(),
                        value: entry.value.clone(),
                    })
                    .collect(),
                secrets,
                timeout_ms: 300_000,
            };
            let interactive = request.terminal.is_some();
            let (operation, payload) = match request.terminal.as_ref() {
                None => (
                    AGENT_LAUNCH_OPERATION,
                    serde_json::to_vec(&launch).map_err(|error| {
                        AgentError::Guest(format!("encode launch request: {error}"))
                    })?,
                ),
                Some(terminal) => {
                    let envelope = InteractiveLaunchRequestV2 {
                        schema_version: INTERACTIVE_OPERATION_SCHEMA_VERSION_V2,
                        launch,
                        terminal: TerminalSizeV1 {
                            columns: terminal.columns,
                            rows: terminal.rows,
                        },
                        term: terminal.term.clone(),
                        separate_stderr: terminal.separate_stderr,
                    };
                    envelope.validate().map_err(|error| {
                        AgentError::Guest(format!("invalid interactive launch request: {error}"))
                    })?;
                    (
                        INTERACTIVE_LAUNCH_OPERATION_V2,
                        serde_json::to_vec(&envelope).map_err(|error| {
                            AgentError::Guest(format!("encode interactive launch request: {error}"))
                        })?,
                    )
                }
            };
            let mut writer = self
                .writer
                .take()
                .ok_or_else(|| AgentError::Guest("guest session already started".to_owned()))?;
            protocol_io(
                "send guest launch request",
                cancellation,
                writer.send(&Message::Request(Request {
                    request_id: REQUEST_ID,
                    operation: operation.to_owned(),
                    payload,
                })),
            )
            .await?;
            let reader = self
                .reader
                .take()
                .ok_or_else(|| AgentError::Guest("guest session reader unavailable".to_owned()))?;
            Ok(Box::new(ProtocolGuestExecution {
                reader,
                writer: WriterHandle::spawn(writer),
                terminal: false,
                cancelled: false,
                interactive,
                flow_controlled: interactive,
                input: TerminalInputState::default(),
                boundary_plan_digest: self.boundary_plan_digest,
            }) as Box<dyn GuestExecution>)
        })
    }

    fn cleanup<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            if let Some(writer) = self.writer.as_mut() {
                protocol_io(
                    "send guest graceful close",
                    cancellation,
                    writer.send(&Message::GracefulClose(GracefulClose {
                        code: CloseCode::Shutdown,
                        reason: "agent cleanup".to_owned(),
                    })),
                )
                .await?;
            }
            Ok(())
        })
    }
}

fn seal_secrets(
    environment: &[crate::EnvironmentIntent],
    secrets: Vec<crate::GuestSecretEnvelope<'_>>,
    session_id: sendbox_core::SessionId,
    policy_digest: [u8; 32],
    boundary_plan_digest: sendbox_core::BoundaryPlanDigest,
    cipher: &mut EnvelopeCipher,
    next_sequence: &mut u64,
) -> Result<Vec<SecretEnvelopeV2>, AgentError> {
    let mut names = environment
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<BTreeSet<_>>();
    let now = unix_time_ms()?;
    let expires_at_unix_ms = now
        .checked_add(5 * 60 * 1_000)
        .ok_or_else(|| AgentError::Guest("secret envelope expiry overflowed".to_owned()))?;
    secrets
        .into_iter()
        .map(|secret| {
            if !names.insert(secret.reference.to_owned()) {
                return Err(AgentError::Guest(format!(
                    "duplicate environment or secret name {}",
                    secret.reference
                )));
            }
            let name = SecretName::new(secret.reference.to_owned())
                .map_err(|error| AgentError::Guest(format!("invalid secret name: {error}")))?;
            let value = SecretValue::new(secret.envelope.to_vec())
                .map_err(|error| AgentError::Guest(format!("invalid secret value: {error}")))?;
            let sequence = *next_sequence;
            *next_sequence = (*next_sequence).checked_add(1).ok_or_else(|| {
                AgentError::Guest("secret envelope sequence overflowed".to_owned())
            })?;
            let binding = EnvelopeBinding {
                session_id,
                recipient: RecipientRole::Guest,
                secret_name: name,
                sequence,
                expires_at_unix_ms,
                policy_digest,
                boundary_plan_digest,
            };
            let envelope = cipher
                .seal(&binding, &value)
                .map_err(|error| AgentError::Guest(format!("seal secret envelope: {error}")))?;
            Ok(SecretEnvelopeV2 {
                reference: secret.reference.to_owned(),
                sequence,
                expires_at_unix_ms,
                policy_digest,
                boundary_plan_digest,
                envelope,
            })
        })
        .collect()
}

fn unix_time_ms() -> Result<u64, AgentError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AgentError::Guest(format!("read system time: {error}")))?
        .as_millis()
        .try_into()
        .map_err(|_| AgentError::Guest("system time is out of range".to_owned()))
}

pub struct ProtocolGuestExecution {
    reader: sendbox_protocol::FramedReader<tokio::io::ReadHalf<Box<dyn ControlStream>>>,
    writer: WriterHandle,
    terminal: bool,
    cancelled: bool,
    interactive: bool,
    flow_controlled: bool,
    input: TerminalInputState,
    boundary_plan_digest: sendbox_core::BoundaryPlanDigest,
}

#[derive(Debug, Default)]
struct TerminalInputState {
    ended: bool,
    available: u16,
}

impl TerminalInputState {
    fn grant(&mut self, credits: u16) -> Result<(), AgentError> {
        self.available = self
            .available
            .checked_add(credits)
            .filter(|available| *available <= sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS)
            .ok_or_else(|| {
                AgentError::Guest("terminal input credit exceeds the negotiated window".to_owned())
            })?;
        Ok(())
    }

    fn require_open(&self) -> Result<(), AgentError> {
        if self.ended {
            return Err(AgentError::Guest(
                "terminal input was already ended".to_owned(),
            ));
        }
        Ok(())
    }

    fn consume(&mut self) -> Result<(), AgentError> {
        self.require_open()?;
        if self.available == 0 {
            return Err(AgentError::TerminalInput(
                "terminal input was produced without launcher credit".to_owned(),
            ));
        }
        self.available -= 1;
        Ok(())
    }

    fn end(&mut self) -> Result<(), AgentError> {
        self.require_open()?;
        self.ended = true;
        Ok(())
    }
}

/// Queue depth for control frames (cancellation, close). These must never
/// queue behind bulk terminal input.
const WRITER_CONTROL_DEPTH: usize = 4;

/// Queue depth for the credited input window plus its FIFO EOF reservation.
const WRITER_INPUT_DEPTH: usize = sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS as usize + 1;

struct WriterMessage {
    message: Message,
    ack: Option<tokio::sync::oneshot::Sender<Result<(), sendbox_protocol::ProtocolError>>>,
}

/// Owns the guest-facing `FramedWriter` on its own task.
///
/// The orchestrator loop must keep draining guest output while it forwards
/// keystrokes. If it awaited the socket write instead, a host stalled on its
/// own terminal and a guest stalled writing output would wedge each other:
/// neither side would read, and both would be blocked writing.
struct WriterHandle {
    control: tokio::sync::mpsc::Sender<WriterMessage>,
    input: tokio::sync::mpsc::Sender<WriterMessage>,
    resize: tokio::sync::watch::Sender<Option<Message>>,
    task: tokio::task::JoinHandle<()>,
}

impl WriterHandle {
    fn spawn(
        mut writer: sendbox_protocol::FramedWriter<tokio::io::WriteHalf<Box<dyn ControlStream>>>,
    ) -> Self {
        let (control, mut control_receiver) = tokio::sync::mpsc::channel(WRITER_CONTROL_DEPTH);
        let (input, mut input_receiver) =
            tokio::sync::mpsc::channel::<WriterMessage>(WRITER_INPUT_DEPTH);
        let (resize, mut resize_receiver) = tokio::sync::watch::channel::<Option<Message>>(None);
        let task = tokio::spawn(async move {
            loop {
                let queued = tokio::select! {
                    biased;
                    control = control_receiver.recv() => match control {
                        Some(queued) => queued,
                        None => return,
                    },
                    changed = resize_receiver.changed() => match changed {
                        Ok(()) => WriterMessage {
                            message: resize_receiver
                                .borrow_and_update()
                                .clone()
                                .expect("resize notification always carries a message"),
                            ack: None,
                        },
                        Err(_) => continue,
                    },
                    input = input_receiver.recv() => match input {
                        Some(queued) => queued,
                        None => continue,
                    },
                };
                let WriterMessage { message, ack } = queued;
                let result = writer.send(&message).await;
                let failed = result.is_err();
                if let Some(ack) = ack {
                    let _ = ack.send(result);
                } else if let Err(error) = result {
                    eprintln!("sendbox: forwarding terminal input to the guest failed: {error}");
                }
                if failed {
                    return;
                }
            }
        });
        Self {
            control,
            input,
            resize,
            task,
        }
    }

    /// Sends a control frame and waits for it to reach the socket, so callers
    /// keep the delivery guarantee they had when they owned the writer.
    async fn send_control(&self, message: Message) -> Result<(), AgentError> {
        let (ack, acked) = tokio::sync::oneshot::channel();
        self.control
            .send(WriterMessage {
                message,
                ack: Some(ack),
            })
            .await
            .map_err(|_| AgentError::Guest("guest connection writer stopped".to_owned()))?;
        acked
            .await
            .map_err(|_| AgentError::Guest("guest connection writer stopped".to_owned()))?
            .map_err(AgentError::Protocol)
    }

    /// Queues on the single input channel so terminal ordering is preserved:
    /// end of file must never overtake the keystrokes that precede it.
    fn queue_input(&self, message: Message) -> Result<(), AgentError> {
        match self.input.try_send(WriterMessage { message, ack: None }) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(AgentError::Guest(
                "terminal input credit invariant failed: guest writer queue is full".to_owned(),
            )),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(AgentError::Guest(
                "guest connection writer stopped".to_owned(),
            )),
        }
    }

    fn queue_resize(&self, message: Message) -> Result<(), AgentError> {
        self.resize
            .send(Some(message))
            .map_err(|_| AgentError::Guest("guest connection writer stopped".to_owned()))
    }
}

impl Drop for WriterHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl GuestExecution for ProtocolGuestExecution {
    fn next_event<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<GuestEvent, AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(AgentError::Cancelled);
            }
            if self.terminal {
                return Err(AgentError::Guest(
                    "event requested after terminal response".to_owned(),
                ));
            }
            let message = self.reader.receive().await?;
            match message {
                Message::Event(event) => match event.kind {
                    sendbox_protocol::EventKind::StandardOutput => Ok(GuestEvent::Output {
                        stream: OutputStream::Stdout,
                        bytes: event.payload,
                    }),
                    sendbox_protocol::EventKind::StandardError => Ok(GuestEvent::Output {
                        stream: OutputStream::Stderr,
                        bytes: event.payload,
                    }),
                    sendbox_protocol::EventKind::TerminalInputCredit => {
                        if !self.flow_controlled {
                            return Err(AgentError::Guest(
                                "terminal input credit arrived without a V2 interactive launch"
                                    .to_owned(),
                            ));
                        }
                        let credit: TerminalInputCreditV1 = serde_json::from_slice(&event.payload)
                            .map_err(|error| {
                                AgentError::Guest(format!("decode terminal input credit: {error}"))
                            })?;
                        credit.validate().map_err(|error| {
                            AgentError::Guest(format!("invalid terminal input credit: {error}"))
                        })?;
                        self.input.grant(credit.credits)?;
                        Ok(GuestEvent::TerminalInputCredit {
                            credits: credit.credits,
                        })
                    }
                    kind => Err(AgentError::Guest(format!(
                        "unexpected guest event kind {kind:?}"
                    ))),
                },
                Message::Response(response) if response.request_id == REQUEST_ID => {
                    self.terminal = true;
                    if response.status == ResponseStatus::Ok {
                        let terminal: TerminalResultV2 = serde_json::from_slice(&response.payload)
                            .map_err(|error| {
                                AgentError::Guest(format!("decode terminal response: {error}"))
                            })?;
                        Ok(GuestEvent::Terminal(map_terminal(terminal)))
                    } else {
                        Err(AgentError::Guest(format!(
                            "guest rejected launch with status {:?}",
                            response.status
                        )))
                    }
                }

                Message::ProtocolError(error) => Err(AgentError::Guest(format!(
                    "guest protocol error {:?}: {}",
                    error.code, error.detail
                ))),
                other => Err(AgentError::Guest(format!(
                    "unexpected guest message {:?}",
                    other.kind()
                ))),
            }
        })
    }

    fn collect_safe_outputs<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<crate::CollectedSafeOutputs, AgentError>> {
        Box::pin(async move {
            if !self.terminal {
                return Err(AgentError::Guest(
                    "Safe Outputs collection requires a terminal response".to_owned(),
                ));
            }
            let payload = serde_json::to_vec(&SafeOutputsCollectRequestV1 {
                schema_version: SAFE_OUTPUTS_OPERATION_SCHEMA_VERSION,
                boundary_plan_digest: self.boundary_plan_digest,
            })
            .map_err(|error| {
                AgentError::Guest(format!("encode Safe Outputs collection request: {error}"))
            })?;
            guest_io(
                "request Safe Outputs collection",
                cancellation,
                self.writer.send_control(Message::Request(Request {
                    request_id: SAFE_OUTPUTS_REQUEST_ID,
                    operation: SAFE_OUTPUTS_COLLECT_OPERATION.to_owned(),
                    payload,
                })),
            )
            .await?;
            let message = protocol_io(
                "receive Safe Outputs collection",
                cancellation,
                self.reader.receive(),
            )
            .await?;
            let Message::Response(response) = message else {
                return Err(AgentError::Guest(
                    "guest omitted the Safe Outputs collection response".to_owned(),
                ));
            };
            if response.request_id != SAFE_OUTPUTS_REQUEST_ID
                || response.status != ResponseStatus::Ok
            {
                return Err(AgentError::Guest(
                    "guest rejected Safe Outputs collection".to_owned(),
                ));
            }
            let collection: SafeOutputsCollectionV1 = serde_json::from_slice(&response.payload)
                .map_err(|error| {
                    AgentError::Guest(format!("decode Safe Outputs collection: {error}"))
                })?;
            let (artifact, seal) = collection
                .decode()
                .map_err(|error| AgentError::Guest(error.to_string()))?;
            Ok(crate::CollectedSafeOutputs { artifact, seal })
        })
    }

    fn send_terminal<'a>(
        &'a mut self,
        command: HostTerminalCommand,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async move {
            if !self.interactive {
                return Err(AgentError::Guest(
                    "terminal input requires an interactive launch".to_owned(),
                ));
            }
            if self.terminal {
                return Err(AgentError::Guest(
                    "terminal input requested after terminal response".to_owned(),
                ));
            }
            self.input.require_open()?;
            match command {
                HostTerminalCommand::Input(bytes) => {
                    if bytes.is_empty() || bytes.len() > sendbox_core::TERMINAL_INPUT_CHUNK_BYTES {
                        return Err(AgentError::TerminalInput(format!(
                            "one terminal input chunk must contain 1..={} bytes",
                            sendbox_core::TERMINAL_INPUT_CHUNK_BYTES
                        )));
                    }
                    let event = Event {
                        stream_id: REQUEST_ID,
                        kind: sendbox_protocol::EventKind::StandardInput,
                        payload: bytes,
                    };
                    if self.flow_controlled {
                        self.input.consume()?;
                    }
                    if let Err(error) = self.writer.queue_input(Message::Event(event)) {
                        if self.flow_controlled {
                            self.input
                                .grant(1)
                                .expect("returning one consumed credit cannot exceed the window");
                        }
                        return Err(error);
                    }
                    Ok(())
                }
                HostTerminalCommand::InputEof => {
                    let event = Event {
                        stream_id: REQUEST_ID,
                        kind: sendbox_protocol::EventKind::StandardInputEof,
                        payload: Vec::new(),
                    };
                    self.writer.queue_input(Message::Event(event))?;
                    self.input.end()?;
                    Ok(())
                }
                HostTerminalCommand::Resize { columns, rows } => {
                    let size = TerminalSizeV1::new(columns, rows).map_err(|error| {
                        AgentError::Guest(format!("invalid terminal size: {error}"))
                    })?;
                    let event = Event {
                        stream_id: REQUEST_ID,
                        kind: sendbox_protocol::EventKind::TerminalResize,
                        payload: serde_json::to_vec(&size).map_err(|error| {
                            AgentError::Guest(format!("encode terminal resize: {error}"))
                        })?,
                    };
                    self.writer.queue_resize(Message::Event(event))
                }
            }
        })
    }

    fn cancel<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async move {
            if self.cancelled {
                return Ok(());
            }
            if self.terminal {
                let _ = guest_io(
                    "close completed guest execution",
                    cancellation,
                    self.writer
                        .send_control(Message::GracefulClose(GracefulClose {
                            code: CloseCode::Normal,
                            reason: "execution complete".to_owned(),
                        })),
                )
                .await;
                self.cancelled = true;
                return Ok(());
            }
            guest_io(
                "send guest cancellation",
                cancellation,
                self.writer
                    .send_control(Message::Cancellation(sendbox_protocol::Cancellation {
                        request_id: REQUEST_ID,
                        reason: Some("agent cancellation".to_owned()),
                    })),
            )
            .await?;
            self.cancelled = true;
            Ok(())
        })
    }
}

fn validate_operational_readiness(payload: &[u8]) -> Result<(), AgentError> {
    let readiness: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|error| AgentError::Guest(format!("decode guest readiness: {error}")))?;
    let state_ready = readiness
        .get("state")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|state| state.eq_ignore_ascii_case("ready"));
    let broker_live = readiness
        .get("services")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| {
                service.get("id").and_then(serde_json::Value::as_str) == Some("exec")
                    && service
                        .get("mandatory")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                    && service.get("healthy").and_then(serde_json::Value::as_bool) == Some(true)
            })
        });
    if state_ready && broker_live {
        Ok(())
    } else {
        Err(AgentError::Guest(
            "guest readiness did not prove a live mandatory execution broker".to_owned(),
        ))
    }
}

fn map_terminal(result: TerminalResultV2) -> GuestTerminal {
    match result.terminal {
        TerminalStateV1::Exited {
            exit_code: Some(code),
            signal: None,
        } if result.cleanup_complete => GuestTerminal::Exited { code },
        TerminalStateV1::Exited {
            exit_code: _,
            signal: Some(signal),
        } if result.cleanup_complete => GuestTerminal::Signaled { signal },
        TerminalStateV1::Cancelled => GuestTerminal::Cancelled,
        terminal => GuestTerminal::Failed {
            message: format!(
                "broker terminal {terminal:?} (cleanup_complete={})",
                result.cleanup_complete
            ),
        },
    }
}

async fn protocol_io<T>(
    operation: &'static str,
    cancellation: &CancellationToken,
    future: impl Future<Output = Result<T, sendbox_protocol::ProtocolError>>,
) -> Result<T, AgentError> {
    guest_io(operation, cancellation, async move {
        future.await.map_err(AgentError::Protocol)
    })
    .await
}

async fn guest_io<T>(
    operation: &'static str,
    cancellation: &CancellationToken,
    future: impl Future<Output = Result<T, AgentError>>,
) -> Result<T, AgentError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(AgentError::Cancelled),
        result = tokio::time::timeout(PROTOCOL_IO_TIMEOUT, future) => {
            result.map_err(|_| AgentError::Guest(format!("{operation} timed out")))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal_event(kind: EventKind) -> Message {
        Message::Event(Event {
            stream_id: REQUEST_ID,
            kind,
            payload: Vec::new(),
        })
    }

    #[tokio::test]
    async fn the_credited_window_reserves_eof_and_coalesces_resizes() {
        let (control, _control) = tokio::sync::mpsc::channel(WRITER_CONTROL_DEPTH);
        let (input, mut receiver) = tokio::sync::mpsc::channel(WRITER_INPUT_DEPTH);
        let (resize, mut resize_receiver) = tokio::sync::watch::channel::<Option<Message>>(None);
        let writer = WriterHandle {
            control,
            input,
            resize,
            task: tokio::spawn(std::future::pending()),
        };

        for _ in 0..sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS {
            writer
                .queue_input(terminal_event(EventKind::StandardInput))
                .expect("credited input fits");
        }
        writer
            .queue_input(terminal_event(EventKind::StandardInputEof))
            .expect("end of file uses reserved capacity");

        for _ in 0..WRITER_INPUT_DEPTH {
            writer
                .queue_resize(terminal_event(EventKind::TerminalResize))
                .expect("coalesce resize");
        }
        resize_receiver
            .changed()
            .await
            .expect("resize notification");
        assert!(matches!(
            resize_receiver.borrow_and_update().as_ref(),
            Some(Message::Event(Event {
                kind: EventKind::TerminalResize,
                ..
            }))
        ));
        let error = writer
            .queue_input(terminal_event(EventKind::StandardInput))
            .expect_err("full queue must fail without blocking");
        assert!(
            error.to_string().contains("credit invariant"),
            "unexpected error: {error}"
        );

        for _ in 0..sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS {
            let queued = receiver.recv().await.expect("queued input");
            assert!(matches!(
                queued.message,
                Message::Event(Event {
                    kind: EventKind::StandardInput,
                    ..
                })
            ));
        }
        let eof = receiver.recv().await.expect("queued end of file");
        assert!(matches!(
            eof.message,
            Message::Event(Event {
                kind: EventKind::StandardInputEof,
                ..
            })
        ));
    }

    #[test]
    fn terminal_input_state_enforces_credit_end_of_file_and_the_window() {
        let mut input = TerminalInputState::default();
        assert!(input.consume().is_err(), "input must wait for credit");
        input
            .grant(sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS)
            .expect("initial window");
        assert!(input.grant(1).is_err(), "overgrant must fail");
        for _ in 0..sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS {
            input.consume().expect("consume credit");
        }
        input.end().expect("end of file needs no credit");
        assert!(input.consume().is_err(), "input after EOF must fail");
        assert!(input.end().is_err(), "duplicate EOF must fail");
    }

    #[test]
    fn broker_signal_terminal_is_preserved() {
        assert_eq!(
            map_terminal(TerminalResultV2 {
                schema_version: OPERATION_SCHEMA_VERSION,
                terminal: TerminalStateV1::Exited {
                    exit_code: None,
                    signal: Some(15),
                },
                cleanup_complete: true,
            }),
            GuestTerminal::Signaled { signal: 15 }
        );
    }
}
