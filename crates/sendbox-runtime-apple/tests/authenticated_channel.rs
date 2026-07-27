#![cfg(unix)]

use sendbox_core::SessionId;
use sendbox_protocol::{
    BootstrapSecret, Capability, FrameLimits, GuestHandshake, HandshakeConfig, HostHandshake,
    Message, VersionRange,
};
use tokio::net::{UnixListener, UnixStream};

fn configuration(session_id: SessionId) -> HandshakeConfig {
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
        BootstrapSecret::new([0x5a; 32]).expect("secret"),
    )
    .expect("handshake config")
}

#[tokio::test]
async fn real_local_stream_preserves_authenticated_protocol_bytes() {
    let socket = std::path::PathBuf::from(format!(
        "apple-relay-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let listener = UnixListener::bind(&socket).expect("listener");
    let session_id = SessionId::from_bytes([0x31; 16]);

    let guest = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut handshake = GuestHandshake::new(configuration(session_id));
        let connection = handshake.establish(stream).await.expect("guest handshake");
        let (mut reader, mut writer) = connection.into_parts();
        assert!(matches!(
            reader.receive().await.expect("message"),
            Message::GracefulClose(_)
        ));
        writer
            .send(&Message::GracefulClose(sendbox_protocol::GracefulClose {
                code: sendbox_protocol::CloseCode::Normal,
                reason: "fixture complete".to_owned(),
            }))
            .await
            .expect("close");
    });

    let stream = UnixStream::connect(&socket).await.expect("connect");
    let mut handshake = HostHandshake::new(configuration(session_id));
    let connection = handshake.establish(stream).await.expect("host handshake");
    let (mut reader, mut writer) = connection.into_parts();
    writer
        .send(&Message::GracefulClose(sendbox_protocol::GracefulClose {
            code: sendbox_protocol::CloseCode::Normal,
            reason: "fixture complete".to_owned(),
        }))
        .await
        .expect("close");
    assert!(matches!(
        reader.receive().await.expect("guest close"),
        Message::GracefulClose(_)
    ));
    guest.await.expect("guest task");
    std::fs::remove_file(&socket).expect("remove socket");
}
