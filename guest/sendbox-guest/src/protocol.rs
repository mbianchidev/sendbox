use std::sync::{Arc, Mutex};

use sendbox_protocol::{
    BootstrapSecret, Capability, CloseCode, Event, EventKind, FrameLimits, GracefulClose,
    GuestHandshake, HandshakeConfig, Message, ProtocolErrorCode, ProtocolErrorMessage, Request,
    Response, ResponseStatus, VersionRange,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::GuestError;
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
            Message::Request(request) => {
                let response =
                    handle_request(request, &state, &service_readiness, &runtime, &readiness)?;
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
    state: &Arc<Mutex<StartupStateMachine>>,
    service_readiness: &ReadinessGate,
    runtime: &RuntimeSession,
    readiness: &ReadinessSnapshot,
) -> Result<Response, GuestError> {
    let (status, payload) = match request.operation.as_str() {
        "health" if service_readiness.verified_live() => (
            ResponseStatus::Ok,
            serde_json::to_vec(readiness)
                .map_err(|error| GuestError::Protocol(format!("encoding health: {error}")))?,
        ),
        "health" => (
            ResponseStatus::Rejected,
            br#"{"ready":false,"reason":"mandatory-service-not-live"}"#.to_vec(),
        ),
        "agent.launch" => {
            if !service_readiness.verified_live() {
                return Ok(Response {
                    request_id: request.request_id,
                    status: ResponseStatus::Rejected,
                    payload: br#"{"authorized":false,"reason":"mandatory-service-not-live"}"#
                        .to_vec(),
                });
            }
            let mut machine = state.lock().expect("state mutex");
            match machine.permit_agent_launch() {
                Ok(()) => {
                    runtime.write_state(machine.state())?;
                    (
                        ResponseStatus::Ok,
                        br#"{"authorized":true,"executed":false}"#.to_vec(),
                    )
                }
                Err(_) => (
                    ResponseStatus::Rejected,
                    br#"{"authorized":false,"reason":"readiness-not-available"}"#.to_vec(),
                ),
            }
        }
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
        )
        .await;
        assert!(matches!(result, Err(GuestError::Protocol(_))));
    }

    #[tokio::test]
    async fn authenticated_launch_is_permitted_once_after_readiness() {
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
            StartupState::ControlsVerified,
            StartupState::ServicesStarting,
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
        for (request_id, expected) in [(1, ResponseStatus::Ok), (2, ResponseStatus::Rejected)] {
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
                Message::Response(Response { status, .. }) if status == expected
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
}
