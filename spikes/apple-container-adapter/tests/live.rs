use apple_container_adapter_spike::adapter::{
    AppleContainerAdapter, ContainerId, ContainerRequest, NetworkMapping, ResourceMapping,
    RuntimeAdapter,
};
use apple_container_adapter_spike::executable::ExecutableResolver;
use apple_container_adapter_spike::process::{ProcessControls, TokioProcessRunner};
use apple_container_adapter_spike::transport::SocketPublication;
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

#[tokio::test]
async fn opt_in_live_socket_and_lifecycle_probe() {
    if std::env::var("SENDBOX_APPLE_CONTAINER_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set SENDBOX_APPLE_CONTAINER_LIVE=1 for the mutating live probe");
        return;
    }
    if !cfg!(target_os = "macos") {
        eprintln!("skipped: the live Apple container probe requires macOS");
        return;
    }

    let report = ExecutableResolver::default().resolve(None);
    assert!(
        report.trusted,
        "live probe requires a trusted container executable: {:?}",
        report.reasons
    );
    let executable = report.resolved_path.expect("trusted executable path");
    let image = std::env::var("SENDBOX_APPLE_CONTAINER_LIVE_IMAGE")
        .expect("live probe requires an explicitly selected image");
    let arguments: Vec<String> = serde_json::from_str(
        &std::env::var("SENDBOX_APPLE_CONTAINER_LIVE_COMMAND_JSON")
            .expect("live probe requires explicit guest server argv JSON"),
    )
    .expect("live guest command must be a JSON string array");

    let controls = ProcessControls {
        timeout: Duration::from_secs(30),
        ..ProcessControls::default()
    };
    let adapter = AppleContainerAdapter::new(&executable, TokioProcessRunner, controls);
    let preflight = adapter.initialize().await.expect("live preflight");
    if !preflight
        .service_status
        .stdout
        .text
        .contains("\"status\":\"running\"")
    {
        eprintln!("skipped: the container service is not already running");
        return;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let id = ContainerId::parse(format!("sendbox-spike-{}-{nonce}", std::process::id()))
        .expect("generated container ID");
    let directory = tempdir().expect("temporary socket directory");
    let host_socket = directory.path().join("control.sock");
    let request = ContainerRequest {
        id: id.clone(),
        image,
        arguments,
        detached: true,
        environment: Vec::new(),
        mounts: Vec::new(),
        network: NetworkMapping::default(),
        resources: ResourceMapping::default(),
        kernel: None,
        transport: Some(
            SocketPublication::new(&host_socket, "/run/sendbox/control.sock")
                .expect("valid live socket publication"),
        ),
    };

    let live_result = run_live_probe(&adapter, &request, &host_socket).await;
    let mut stop_result = adapter.stop(&id, 5).await;
    if stop_result.is_err() {
        let _ = adapter.signal(&id, "KILL").await;
        stop_result = adapter.stop(&id, 1).await;
    }
    let cleanup_result = adapter.cleanup().await;
    let socket_cleanup_result = if host_socket.exists() {
        std::fs::remove_file(&host_socket)
    } else {
        Ok(())
    };

    assert!(
        stop_result.is_ok(),
        "live cleanup stop failed: {stop_result:?}"
    );
    assert!(
        cleanup_result.is_ok(),
        "live cleanup delete failed: {cleanup_result:?}"
    );
    assert!(
        socket_cleanup_result.is_ok(),
        "live socket cleanup failed: {socket_cleanup_result:?}"
    );
    assert!(!host_socket.exists(), "live host socket was not removed");
    assert!(live_result.is_ok(), "live probe failed: {live_result:?}");
}

async fn run_live_probe(
    adapter: &AppleContainerAdapter<TokioProcessRunner>,
    request: &ContainerRequest,
    host_socket: &std::path::Path,
) -> Result<(), String> {
    let output = adapter
        .run(request)
        .await
        .map_err(|error| error.to_string())?;
    if !output.status.success {
        return Err(format!(
            "container run failed: stdout={} stderr={}",
            output.stdout.text, output.stderr.text
        ));
    }

    for _ in 0..100 {
        if host_socket.exists() && UnixStream::connect(host_socket).is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("published host socket did not become connectable within 5 seconds".to_owned())
}
