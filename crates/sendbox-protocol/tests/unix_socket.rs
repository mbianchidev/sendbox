#![cfg(unix)]

use sendbox_core::SessionId;
use sendbox_protocol::{
    BootstrapSecret, Cancellation, Capability, CloseCode, Event, EventKind, FrameLimits,
    GracefulClose, GuestHandshake, HandshakeConfig, HostHandshake, Message, Request, Response,
    ResponseStatus, VersionRange,
};
use tempfile::tempdir;
use tokio::net::{UnixListener, UnixStream};

const SECRET: [u8; 32] = [0xa5; 32];

fn config(session_id: SessionId) -> HandshakeConfig {
    HandshakeConfig::new(
        session_id,
        VersionRange::default(),
        [
            Capability::Lifecycle,
            Capability::Exec,
            Capability::StreamedIo,
            Capability::Signals,
            Capability::Health,
        ]
        .into(),
        [Capability::Lifecycle, Capability::Health].into(),
        FrameLimits::new(32 * 1024).expect("limits"),
        BootstrapSecret::new(SECRET).expect("secret"),
    )
    .expect("config")
}

#[tokio::test]
async fn unix_stream_proves_transport_adapter_and_cleans_up() {
    let directory = tempdir().expect("temporary directory");
    let socket_path = directory.path().join("protocol.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    let session_id = SessionId::from_bytes([0x22; 16]);

    let guest = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut handshake = GuestHandshake::new(config(session_id));
        let connection = handshake.establish(stream).await.expect("guest handshake");
        let (mut reader, mut writer) = connection.into_parts();

        assert!(matches!(
            reader.receive().await.expect("request"),
            Message::Request(Request { request_id: 9, .. })
        ));
        writer
            .send(&Message::Response(Response {
                request_id: 9,
                status: ResponseStatus::Ok,
                payload: b"started".to_vec(),
            }))
            .await
            .expect("response");
        writer
            .send(&Message::Event(Event {
                stream_id: 9,
                kind: EventKind::Lifecycle,
                payload: b"ready".to_vec(),
            }))
            .await
            .expect("event");
        assert!(matches!(
            reader.receive().await.expect("cancel"),
            Message::Cancellation(Cancellation { request_id: 9, .. })
        ));
        assert!(matches!(
            reader.receive().await.expect("close"),
            Message::GracefulClose(_)
        ));
        writer
            .send(&Message::GracefulClose(GracefulClose {
                code: CloseCode::Normal,
                reason: "guest closed".to_owned(),
            }))
            .await
            .expect("guest close");
    });

    let stream = UnixStream::connect(&socket_path).await.expect("connect");
    let mut handshake = HostHandshake::new(config(session_id));
    let connection = handshake.establish(stream).await.expect("host handshake");
    let (mut reader, mut writer) = connection.into_parts();
    writer
        .send(&Message::Request(Request {
            request_id: 9,
            operation: "lifecycle.start".to_owned(),
            payload: Vec::new(),
        }))
        .await
        .expect("request");
    assert!(matches!(
        reader.receive().await.expect("response"),
        Message::Response(Response {
            request_id: 9,
            status: ResponseStatus::Ok,
            ..
        })
    ));
    assert!(matches!(
        reader.receive().await.expect("event"),
        Message::Event(Event {
            stream_id: 9,
            kind: EventKind::Lifecycle,
            ..
        })
    ));
    writer
        .send(&Message::Cancellation(Cancellation {
            request_id: 9,
            reason: Some("test cancellation".to_owned()),
        }))
        .await
        .expect("cancel");
    writer
        .send(&Message::GracefulClose(GracefulClose {
            code: CloseCode::Normal,
            reason: "host closed".to_owned(),
        }))
        .await
        .expect("close");
    assert!(matches!(
        reader.receive().await.expect("guest close"),
        Message::GracefulClose(_)
    ));
    drop(reader);
    drop(writer);
    guest.await.expect("guest task");

    std::fs::remove_file(&socket_path).expect("remove socket");
    assert!(!socket_path.exists());
}
