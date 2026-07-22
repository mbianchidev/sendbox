#![cfg(target_os = "macos")]

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sendbox_core::SessionId;
use sendbox_protocol::{
    BootstrapSecret, Capability, FrameLimits, HandshakeConfig, HostHandshake, Message, VersionRange,
};
use sendbox_runtime::{
    BootstrapDelivery, BootstrapMaterial, CancellationToken, ChannelLifetime, ChannelOwnership,
    ContainerId, ControlChannelRequest, ControlEndpointKind, CreateRequest, InitializeRequest,
    PreflightRequest, RuntimeProvider, StartRequest, StopRequest,
};
use sendbox_runtime_apple::{AppleRuntime, AppleRuntimeConfiguration};

#[tokio::test]
async fn configured_live_runtime_proves_authenticated_stdio_channel_and_cleanup() {
    if std::env::var("SENDBOX_APPLE_CONTAINER_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set SENDBOX_APPLE_CONTAINER_LIVE=1 on a prepared macOS arm64 host");
        return;
    }

    let bundle = required_path("SENDBOX_APPLE_CONTAINER_BUNDLE");
    let public_key = required_path("SENDBOX_APPLE_CONTAINER_PUBLIC_KEY");
    let trust_root_id = required("SENDBOX_APPLE_CONTAINER_TRUST_ROOT_ID");
    let image = required("SENDBOX_APPLE_CONTAINER_LIVE_IMAGE");
    let mut configuration = AppleRuntimeConfiguration::new(
        bundle,
        public_key,
        trust_root_id.clone(),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_VERSION"),
    );
    configuration.minimum_release_sequence =
        required("SENDBOX_APPLE_CONTAINER_MIN_RELEASE_SEQUENCE")
            .parse()
            .expect("minimum release sequence must be an integer");
    if let Ok(executable) = std::env::var("SENDBOX_APPLE_CONTAINER_EXECUTABLE") {
        configuration.executable = Some(PathBuf::from(executable));
    }
    let runtime = AppleRuntime::new(configuration).expect("runtime configuration");
    let cancellation = CancellationToken::new();
    runtime
        .preflight(
            PreflightRequest {
                required_capabilities: runtime.capabilities(),
            },
            &cancellation,
        )
        .await
        .expect("prepared live host must pass preflight without service mutation");

    let temporary = tempfile::tempdir_in(std::env::current_dir().expect("current directory"))
        .expect("runtime state");
    runtime
        .initialize(
            InitializeRequest {
                state_directory: temporary.path().join("state"),
            },
            &cancellation,
        )
        .await
        .expect("initialize");

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let container_id =
        ContainerId::new(format!("sendbox-apple-live-{}-{nonce}", std::process::id()))
            .expect("container id");
    let mut session_bytes = nonce.to_le_bytes();
    session_bytes[..4].copy_from_slice(&std::process::id().to_le_bytes());
    let session_id = SessionId::from_bytes(session_bytes);
    let secret = [0x6d_u8; 32];
    let bootstrap = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "session_id": session_id,
        "bootstrap_nonce": vec![0x37_u8; 32],
        "bootstrap_secret": secret,
        "host_version": env!("CARGO_PKG_VERSION"),
        "trust_root_id": trust_root_id,
        "manifest_path": "manifest.json",
        "minimum_release_sequence": required("SENDBOX_APPLE_CONTAINER_MIN_RELEASE_SEQUENCE")
            .parse::<u64>()
            .expect("minimum release sequence"),
        "required_controls": [],
        "required_services": [],
        "services": []
    }))
    .expect("bootstrap");

    let mut created = false;
    let mut channel = None;
    let primary = async {
        runtime
            .create(
                CreateRequest {
                    container_id: container_id.clone(),
                    image,
                },
                &cancellation,
            )
            .await?;
        created = true;
        runtime
            .start(&container_id, StartRequest::default(), &cancellation)
            .await?;
        let provisioned = runtime
            .provision_control_channel(
                ControlChannelRequest {
                    session_id,
                    container_id: container_id.clone(),
                    endpoint_kind: ControlEndpointKind::InheritedStdio,
                    ownership: ChannelOwnership::RuntimeLifecycle,
                    lifetime: ChannelLifetime::UntilRuntimeCleanup,
                    readiness_timeout: Duration::from_secs(30),
                    bootstrap_delivery: BootstrapDelivery::RuntimeInjection {
                        target: "/run/sendbox-bootstrap/bootstrap.json".to_owned(),
                    },
                    bootstrap_material: BootstrapMaterial::new(bootstrap)?,
                },
                &cancellation,
            )
            .await?;
        channel = Some(provisioned);
        let stream = channel
            .as_mut()
            .ok_or_else(|| {
                sendbox_runtime::RuntimeError::Provider("live channel was not retained".to_owned())
            })?
            .accept(&cancellation)
            .await?;
        let config = HandshakeConfig::new(
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
            BootstrapSecret::new(secret).expect("secret"),
        )
        .expect("handshake config");
        let mut handshake = HostHandshake::new(config);
        let connection = handshake.establish(stream).await.map_err(protocol_error)?;
        let (mut reader, mut writer) = connection.into_parts();
        if !matches!(
            reader.receive().await.map_err(protocol_error)?,
            Message::Event(_)
        ) {
            return Err(sendbox_runtime::RuntimeError::Provider(
                "live guest did not publish authenticated readiness".to_owned(),
            ));
        }
        writer
            .send(&Message::GracefulClose(sendbox_protocol::GracefulClose {
                code: sendbox_protocol::CloseCode::Normal,
                reason: "live qualification complete".to_owned(),
            }))
            .await
            .map_err(protocol_error)?;
        Ok::<(), sendbox_runtime::RuntimeError>(())
    }
    .await;

    let channel_cleanup = if let Some(channel) = channel.as_mut() {
        channel.cleanup(&cancellation).await
    } else {
        Ok(())
    };
    let stop = if created {
        runtime
            .stop(&container_id, StopRequest::default(), &cancellation)
            .await
    } else {
        Ok(())
    };
    let cleanup = runtime.cleanup(&container_id, &cancellation).await;

    primary.expect("live lifecycle and authenticated channel");
    channel_cleanup.expect("live channel cleanup");
    stop.expect("live stop");
    assert!(cleanup.expect("live cleanup").is_complete());
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be configured for the live gate"))
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(required(name))
}

fn protocol_error(error: sendbox_protocol::ProtocolError) -> sendbox_runtime::RuntimeError {
    sendbox_runtime::RuntimeError::Provider(format!("live authenticated channel failed: {error}"))
}
