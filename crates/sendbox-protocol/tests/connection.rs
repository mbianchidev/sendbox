use sendbox_core::SessionId;
use sendbox_protocol::{
    BootstrapSecret, Cancellation, Capability, CapabilitySet, CloseCode, Event, EventKind,
    FrameLimits, GracefulClose, GuestHandshake, HandshakeConfig, HostHandshake, Message, Request,
    Response, ResponseStatus, VersionRange,
};

const SECRET: [u8; 32] = [0x6c; 32];

fn config(session_id: SessionId) -> HandshakeConfig {
    HandshakeConfig::new(
        session_id,
        VersionRange::default(),
        [
            Capability::Lifecycle,
            Capability::Exec,
            Capability::StreamedIo,
            Capability::Health,
        ]
        .into(),
        [Capability::Lifecycle, Capability::Health].into(),
        FrameLimits::new(64 * 1024).expect("limits"),
        BootstrapSecret::new(SECRET).expect("secret"),
    )
    .expect("config")
}

#[tokio::test]
async fn in_memory_connection_is_bidirectional() {
    let session_id = SessionId::from_bytes([0x11; 16]);
    let (host_stream, guest_stream) = tokio::io::duplex(4096);
    let mut host = HostHandshake::new(config(session_id));
    let mut guest = GuestHandshake::new(config(session_id));
    let (host_connection, guest_connection) =
        tokio::join!(host.establish(host_stream), guest.establish(guest_stream));
    let (mut host_reader, mut host_writer) = host_connection.expect("host handshake").into_parts();
    let (mut guest_reader, mut guest_writer) =
        guest_connection.expect("guest handshake").into_parts();

    let host_task = tokio::spawn(async move {
        host_writer
            .send(&Message::Request(Request {
                request_id: 41,
                operation: "exec".to_owned(),
                payload: b"echo ok".to_vec(),
            }))
            .await
            .expect("send request");
        assert!(matches!(
            host_reader.receive().await.expect("response"),
            Message::Response(Response {
                request_id: 41,
                status: ResponseStatus::Ok,
                ..
            })
        ));
        assert!(matches!(
            host_reader.receive().await.expect("event"),
            Message::Event(Event {
                stream_id: 41,
                kind: EventKind::StandardOutput,
                ..
            })
        ));
        host_writer
            .send(&Message::Cancellation(Cancellation {
                request_id: 41,
                reason: None,
            }))
            .await
            .expect("send cancellation");
        host_writer
            .send(&Message::GracefulClose(GracefulClose {
                code: CloseCode::Normal,
                reason: "complete".to_owned(),
            }))
            .await
            .expect("send close");
    });

    let guest_task = tokio::spawn(async move {
        assert!(matches!(
            guest_reader.receive().await.expect("request"),
            Message::Request(Request { request_id: 41, .. })
        ));
        guest_writer
            .send(&Message::Response(Response {
                request_id: 41,
                status: ResponseStatus::Ok,
                payload: Vec::new(),
            }))
            .await
            .expect("send response");
        guest_writer
            .send(&Message::Event(Event {
                stream_id: 41,
                kind: EventKind::StandardOutput,
                payload: b"ok\n".to_vec(),
            }))
            .await
            .expect("send event");
        assert!(matches!(
            guest_reader.receive().await.expect("cancellation"),
            Message::Cancellation(Cancellation { request_id: 41, .. })
        ));
        assert!(matches!(
            guest_reader.receive().await.expect("close"),
            Message::GracefulClose(GracefulClose {
                code: CloseCode::Normal,
                ..
            })
        ));
    });

    let (host_result, guest_result) = tokio::join!(host_task, guest_task);
    host_result.expect("host task");
    guest_result.expect("guest task");
}

#[test]
fn capability_set_type_is_publicly_constructible() {
    let capabilities: CapabilitySet = [Capability::Mcp, Capability::Audit].into();
    assert!(capabilities.contains(Capability::Mcp));
}
