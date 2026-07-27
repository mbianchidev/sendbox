use std::sync::{Arc, Mutex};

use sendbox_protocol::{
    AGENT_LAUNCH_OPERATION, BootstrapSecret, Capability, CloseCode, Event, EventKind, FrameLimits,
    GracefulClose, GuestHandshake, HandshakeConfig, HealthResponseV1, LaunchRequestV1, Message,
    OPERATION_SCHEMA_VERSION, ProtocolErrorCode, ProtocolErrorMessage, Request, Response,
    ResponseStatus, TerminalResultV1, TerminalStateV1, VersionRange,
};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf,
};
use tokio::net::UnixStream;

use crate::GuestError;
use crate::broker::BrokerClientConfiguration;
use crate::runtime::{ReadinessSnapshot, RuntimeSession};
use crate::service::ReadinessGate;
use crate::state::{StartupState, StartupStateMachine};

pub fn handshake_config(
    session_id: sendbox_core::SessionId,
    bootstrap_secret: BootstrapSecret,
) -> Result<HandshakeConfig, GuestError> {
    HandshakeConfig::new(
        session_id,
        VersionRange::default(),
        [
            Capability::Lifecycle,
            Capability::Exec,
            Capability::Audit,
            Capability::Health,
        ]
        .into(),
        [Capability::Lifecycle, Capability::Health].into(),
        FrameLimits::default(),
        bootstrap_secret,
    )
    .map_err(GuestError::from)
}

pub async fn serve_authenticated<S>(
    stream: S,
    config: HandshakeConfig,
    state: Arc<Mutex<StartupStateMachine>>,
    service_readiness: Arc<ReadinessGate>,
    runtime: Arc<RuntimeSession>,
    readiness: ReadinessSnapshot,
    broker: Option<BrokerClientConfiguration>,
) -> Result<(), GuestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if state.lock().expect("state mutex").state() != StartupState::Ready
        || !service_readiness.verified_live()
    {
        return Err(GuestError::Protocol(
            "authenticated readiness requested before local readiness".to_owned(),
        ));
    }

    let mut handshake = GuestHandshake::new(config);
    let connection = handshake.establish(stream).await?;
    let (mut reader, mut writer) = connection.into_parts();
    if !service_readiness.verified_live() {
        return Err(GuestError::Protocol(
            "mandatory service failed during authenticated handshake".to_owned(),
        ));
    }
    let readiness_payload = serde_json::to_vec(&readiness)
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
                    &state,
                    &service_readiness,
                    &runtime,
                    broker.as_ref(),
                )
                .await?;
            }
            Message::Request(request) => {
                let response = handle_request(request, &service_readiness, &readiness)?;
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
            serde_json::to_vec(&HealthResponseV1 {
                schema_version: OPERATION_SCHEMA_VERSION,
                ready: true,
                broker_live: true,
                release_sequence: readiness.release_sequence,
            })
            .map_err(|error| GuestError::Protocol(format!("encoding health: {error}")))?,
        ),
        "health" => (
            ResponseStatus::Rejected,
            serde_json::to_vec(&HealthResponseV1 {
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

async fn launch<S>(
    request: Request,
    host_reader: &mut sendbox_protocol::FramedReader<ReadHalf<S>>,
    host_writer: &mut sendbox_protocol::FramedWriter<WriteHalf<S>>,
    state: &Arc<Mutex<StartupStateMachine>>,
    service_readiness: &ReadinessGate,
    runtime: &RuntimeSession,
    broker: Option<&BrokerClientConfiguration>,
) -> Result<(), GuestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !service_readiness.verified_live() {
        return send_rejection(
            host_writer,
            request.request_id,
            "mandatory-service-not-live",
        )
        .await;
    }
    let Some(broker) = broker else {
        return send_rejection(
            host_writer,
            request.request_id,
            "execution-broker-not-configured",
        )
        .await;
    };
    let launch: LaunchRequestV1 = serde_json::from_slice(&request.payload)
        .map_err(|error| GuestError::Protocol(format!("decoding launch request: {error}")))?;
    if launch.schema_version != OPERATION_SCHEMA_VERSION {
        return send_rejection(
            host_writer,
            request.request_id,
            "unsupported-operation-schema",
        )
        .await;
    }
    let launch_permitted = {
        let mut machine = state.lock().expect("state mutex");
        if machine.permit_agent_launch().is_ok() {
            runtime.write_state(machine.state())?;
            true
        } else {
            false
        }
    };
    if !launch_permitted {
        return send_rejection(host_writer, request.request_id, "readiness-not-available").await;
    }

    let execution = build_execution_request(&launch, broker)?;
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
                    sendbox_exec::ExecutionEvent::Terminal { result, .. } => {
                        let payload = serde_json::to_vec(&terminal_result(result))
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
                        send_broker_frame(
                            &mut write,
                            &sendbox_exec::service::ClientFrame::Cancel {
                                correlation_id: execution.correlation_id.clone(),
                            },
                        ).await?;
                    }
                    Message::GracefulClose(_) => {
                        send_broker_frame(
                            &mut write,
                            &sendbox_exec::service::ClientFrame::GracefulShutdown,
                        ).await?;
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

fn build_execution_request(
    launch: &LaunchRequestV1,
    broker: &BrokerClientConfiguration,
) -> Result<sendbox_exec::ExecutionRequest, GuestError> {
    let (executable_root, executable) = descriptor_path(&launch.program)?;
    let (cwd_root, cwd) = descriptor_path(&launch.working_directory)?;
    let timeout =
        sendbox_exec::ExecutionTimeout::new(std::time::Duration::from_millis(launch.timeout_ms))
            .map_err(|error| GuestError::Protocol(format!("invalid execution timeout: {error}")))?;
    let mut argv = Vec::with_capacity(launch.arguments.len() + 1);
    argv.push(launch.program.clone());
    argv.extend(launch.arguments.clone());
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
        environment: launch
            .environment
            .iter()
            .map(|entry| sendbox_exec::EnvironmentEntry {
                name: entry.name.clone(),
                value: entry.value.clone(),
            })
            .collect(),
        stdin: sendbox_exec::StandardInput::Null,
        timeout,
        containment: sendbox_exec::ContainmentProfile {
            run_as: Some(broker.workload),
            ..sendbox_exec::ContainmentProfile::default()
        },
    })
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

fn terminal_result(result: sendbox_exec::ExecutionResult) -> TerminalResultV1 {
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
    TerminalResultV1 {
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
            payload: serde_json::to_vec(&TerminalResultV1 {
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
    use sendbox_core::SessionId;
    use sendbox_protocol::{HostHandshake, Message, Request};
    use tempfile::tempdir;

    use super::*;
    use crate::runtime::RuntimeIdentity;

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
            )
            .expect("config"),
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
        )
        .await;
        assert!(matches!(result, Err(GuestError::Protocol(_))));
    }

    #[tokio::test]
    async fn authenticated_launch_requires_a_configured_broker() {
        let temporary = tempdir().expect("temporary directory");
        let session_id = SessionId::from_bytes([4; 16]);
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
            handshake_config(session_id, BootstrapSecret::new([8; 32]).expect("secret"))
                .expect("guest config"),
            Arc::clone(&state),
            ReadinessGate::test_ready(),
            runtime,
            readiness,
            None,
        ));
        let mut host_handshake = HostHandshake::new(
            handshake_config(session_id, BootstrapSecret::new([8; 32]).expect("secret"))
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
