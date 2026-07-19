#![cfg(unix)]

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use rustix::process::{Pid, Signal, kill_process, test_kill_process};
use sendbox_core::SessionId;
use sendbox_guest::GuestError;
use sendbox_guest::manifest::{
    ArtifactExpectation, ArtifactKind, ArtifactManifest, MANIFEST_DOMAIN, MANIFEST_SCHEMA_VERSION,
    SignedManifestEnvelope, encode_hex,
};
use sendbox_guest::platform::{ControlKind, ControlStatus, PlatformControls};
use sendbox_guest::protocol::handshake_config;
use sendbox_guest::runtime::RuntimeIdentity;
use sendbox_guest::service::{HealthCheck, RestartPolicy, ServiceId, ServiceSpec};
use sendbox_guest::supervisor::{SupervisorOptions, run};
use sendbox_protocol::{
    BootstrapSecret, CloseCode, Event, EventKind, GracefulClose, HostHandshake, Message, Request,
    Response, ResponseStatus,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

const SECRET: [u8; 32] = [0x5a; 32];
const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct VerifiedControls;

impl PlatformControls for VerifiedControls {
    fn apply_and_verify(&self, required: &[ControlKind]) -> Result<Vec<ControlStatus>, GuestError> {
        Ok(required
            .iter()
            .copied()
            .map(|control| ControlStatus {
                control,
                required: true,
                verified: true,
                detail: "verified by integration-test platform".to_owned(),
            })
            .collect())
    }

    fn self_test(&self, statuses: &[ControlStatus]) -> Result<(), GuestError> {
        if statuses.iter().all(|status| status.verified) {
            Ok(())
        } else {
            Err(GuestError::ControlNotVerified(
                "integration-test control".to_owned(),
            ))
        }
    }
}

struct Fixture {
    _temporary: TempDir,
    options: SupervisorOptions,
    session_id: SessionId,
    session_dir: PathBuf,
    service_pid: PathBuf,
    child_pid: PathBuf,
    audit_pid: PathBuf,
    identity: RuntimeIdentity,
}

impl Fixture {
    fn new(mode: &str, restart_count: u32, spawn_child: bool) -> Self {
        // Keep Darwin's fixed-size Unix socket path below SUN_LEN.
        let base = Path::new("/tmp")
            .canonicalize()
            .expect("canonical short temporary root");
        let temporary = tempfile::tempdir_in(base).expect("temporary directory");
        let artifact_root = temporary.path().join("artifacts");
        let runtime_root = temporary.path().join("run");
        let replay_root = temporary.path().join("replay");
        DirBuilder::new()
            .mode(0o700)
            .create(&artifact_root)
            .expect("artifact root");
        DirBuilder::new()
            .mode(0o700)
            .create(&runtime_root)
            .expect("runtime root");
        DirBuilder::new()
            .mode(0o700)
            .create(&replay_root)
            .expect("replay root");

        let binary_relative = PathBuf::from("bin/sendbox-guest");
        let binary = artifact_root.join(&binary_relative);
        fs::create_dir(artifact_root.join("bin")).expect("bin directory");
        fs::copy(env!("CARGO_BIN_EXE_sendbox-guest"), &binary).expect("copy guest binary");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o500)).expect("binary mode");
        let binary_bytes = fs::read(&binary).expect("binary bytes");
        let metadata = binary.metadata().expect("binary metadata");

        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let manifest = ArtifactManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            domain: MANIFEST_DOMAIN.to_owned(),
            trust_root_id: "integration-root".to_owned(),
            release_sequence: 12,
            minimum_accepted_sequence: 10,
            expected_host_version: "0.1.0".to_owned(),
            expected_guest_version: env!("CARGO_PKG_VERSION").to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            artifacts: vec![ArtifactExpectation {
                kind: ArtifactKind::ServiceBinary,
                path: binary_relative.clone(),
                sha256: encode_hex(&Sha256::digest(&binary_bytes)),
                mode: 0o500,
                uid: metadata.uid(),
                gid: metadata.gid(),
            }],
        };
        let payload = serde_json::to_string(&manifest).expect("manifest payload");
        let envelope = SignedManifestEnvelope {
            signature: encode_hex(&signing_key.sign(payload.as_bytes()).to_bytes()),
            payload,
        };
        fs::write(
            artifact_root.join("manifest.json"),
            serde_json::to_vec(&envelope).expect("manifest envelope"),
        )
        .expect("write manifest");

        let trust_root_file = temporary.path().join("trust-root");
        fs::write(&trust_root_file, signing_key.verifying_key().to_bytes())
            .expect("write trust root");
        fs::set_permissions(&trust_root_file, fs::Permissions::from_mode(0o444))
            .expect("trust-root mode");

        let session_id = SessionId::from_bytes([0x44; 16]);
        let session_dir = runtime_root.join(session_id.to_string());
        assert!(
            session_dir.join("control.sock").as_os_str().len() < 104,
            "integration socket path must fit Darwin sun_path"
        );
        let service_pid = temporary.path().join("service.pid");
        let child_pid = temporary.path().join("child.pid");
        let audit_pid = temporary.path().join("audit.pid");
        let audit_socket = temporary.path().join("audit.sock");
        let fixture_mode = if mode == "partial" { "crash" } else { mode };
        let mut args = vec![
            "service-run".to_owned(),
            "--mode".to_owned(),
            fixture_mode.to_owned(),
            "--log-lines".to_owned(),
            "500".to_owned(),
            "--pid-file".to_owned(),
            service_pid.display().to_string(),
        ];
        if fixture_mode == "crash" {
            args.extend([
                "--crash-after-ms".to_owned(),
                if mode == "partial" { "1" } else { "100" }.to_owned(),
            ]);
        }
        if spawn_child {
            args.extend([
                "--spawn-child".to_owned(),
                "--child-pid-file".to_owned(),
                child_pid.display().to_string(),
            ]);
        }
        let service = ServiceSpec {
            id: ServiceId::Exec,
            dependencies: if mode == "partial" {
                vec![ServiceId::Audit]
            } else {
                Vec::new()
            },
            executable: binary_relative,
            args,
            mandatory: true,
            restart: RestartPolicy {
                max_restarts: restart_count,
                backoff_ms: 10,
            },
            health: HealthCheck::ProcessAlive { delay_ms: 25 },
            graceful_shutdown_ms: 50,
            forced_shutdown_ms: 500,
            max_log_bytes: 4096,
        };
        let mut services = vec![service];
        let mut required_services = vec![ServiceId::Exec];
        if mode == "partial" {
            services.insert(
                0,
                ServiceSpec {
                    id: ServiceId::Audit,
                    dependencies: Vec::new(),
                    executable: PathBuf::from("bin/sendbox-guest"),
                    args: vec![
                        "service-run".to_owned(),
                        "--mode".to_owned(),
                        "healthy".to_owned(),
                        "--pid-file".to_owned(),
                        audit_pid.display().to_string(),
                        "--socket".to_owned(),
                        audit_socket.display().to_string(),
                    ],
                    mandatory: true,
                    restart: RestartPolicy::default(),
                    health: HealthCheck::UnixSocket {
                        path: audit_socket,
                        timeout_ms: 2_000,
                    },
                    graceful_shutdown_ms: 50,
                    forced_shutdown_ms: 500,
                    max_log_bytes: 4096,
                },
            );
            required_services.push(ServiceId::Audit);
        }
        let bootstrap_file = temporary.path().join("bootstrap.json");
        fs::write(
            &bootstrap_file,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "session_id": session_id,
                "bootstrap_nonce": [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
                "bootstrap_secret": SECRET,
                "host_version": "0.1.0",
                "trust_root_id": "integration-root",
                "manifest_path": "manifest.json",
                "minimum_release_sequence": 11,
                "required_controls": [ControlKind::Seccomp],
                "required_services": required_services,
                "services": services
            }))
            .expect("bootstrap"),
        )
        .expect("write bootstrap");
        fs::set_permissions(&bootstrap_file, fs::Permissions::from_mode(0o400))
            .expect("bootstrap mode");
        let runtime_metadata = runtime_root.metadata().expect("runtime metadata");
        let identity = RuntimeIdentity {
            uid: runtime_metadata.uid(),
            gid: runtime_metadata.gid(),
        };
        for path in [&bootstrap_file, &trust_root_file] {
            let metadata = path.metadata().expect("staged security file metadata");
            assert_eq!(
                (metadata.uid(), metadata.gid()),
                (identity.uid, identity.gid)
            );
        }

        Self {
            options: SupervisorOptions {
                bootstrap_file,
                trust_root_file,
                artifact_root,
                runtime_root,
                replay_root,
            },
            session_id,
            session_dir,
            service_pid,
            child_pid,
            audit_pid,
            identity,
            _temporary: temporary,
        }
    }

    fn identity(&self) -> RuntimeIdentity {
        self.identity
    }

    async fn wait_ready(&self, supervisor: &mut tokio::task::JoinHandle<Result<(), GuestError>>) {
        wait_for_path_or_exit(&self.session_dir.join("ready.json"), supervisor).await;
    }

    async fn connect(
        &self,
    ) -> (
        sendbox_protocol::FramedReader<tokio::io::ReadHalf<tokio::net::UnixStream>>,
        sendbox_protocol::FramedWriter<tokio::io::WriteHalf<tokio::net::UnixStream>>,
    ) {
        let stream = tokio::net::UnixStream::connect(self.session_dir.join("control.sock"))
            .await
            .expect("connect control socket");
        let mut handshake = HostHandshake::new(
            handshake_config(
                self.session_id,
                BootstrapSecret::new(SECRET).expect("secret"),
            )
            .expect("host handshake config"),
        );
        let connection = handshake.establish(stream).await.expect("host handshake");
        connection.into_parts()
    }
}

#[tokio::test]
async fn mandatory_broker_death_revokes_readiness_and_cleans_session() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = Fixture::new("healthy", 0, false);
    let options = fixture.options.clone();
    let identity = fixture.identity();
    let mut supervisor =
        tokio::spawn(async move { run(options, &VerifiedControls, identity).await });
    fixture.wait_ready(&mut supervisor).await;
    wait_for_path_or_exit(&fixture.service_pid, &mut supervisor).await;
    let (mut reader, mut writer) = fixture.connect().await;
    assert!(matches!(
        reader.receive().await.expect("readiness"),
        Message::Event(Event {
            kind: EventKind::Lifecycle,
            ..
        })
    ));
    let service_pid = read_pid(&fixture.service_pid);
    kill_process(service_pid, Signal::KILL).expect("kill mandatory service");
    if writer
        .send(&Message::Request(Request {
            request_id: 1,
            operation: "agent.launch".to_owned(),
            payload: Vec::new(),
        }))
        .await
        .is_ok()
    {
        match timeout(Duration::from_secs(2), reader.receive()).await {
            Ok(Ok(Message::Response(Response { status, .. }))) => {
                assert_ne!(status, ResponseStatus::Ok);
            }
            Ok(Ok(Message::GracefulClose(_))) | Ok(Err(_)) => {}
            Ok(Ok(other)) => panic!("unexpected post-death message: {other:?}"),
            Err(_) => panic!("post-death launch request was not resolved"),
        }
    }
    let result = timeout(PROCESS_TIMEOUT, supervisor)
        .await
        .expect("supervisor timeout")
        .expect("supervisor task");
    assert!(matches!(
        result,
        Err(GuestError::Service { ref service, .. }) if service == "exec"
    ));
    assert!(!fixture.session_dir.exists());
    assert!(test_kill_process(service_pid).is_err());
}

#[tokio::test]
async fn graceful_protocol_close_escalates_hung_group_and_leaves_no_children() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = Fixture::new("ignore-term", 0, true);
    let options = fixture.options.clone();
    let identity = fixture.identity();
    let mut supervisor =
        tokio::spawn(async move { run(options, &VerifiedControls, identity).await });
    fixture.wait_ready(&mut supervisor).await;
    wait_for_path_or_exit(&fixture.service_pid, &mut supervisor).await;
    wait_for_path_or_exit(&fixture.child_pid, &mut supervisor).await;
    let service_pid = read_pid(&fixture.service_pid);
    let child_pid = read_pid(&fixture.child_pid);
    let (mut reader, mut writer) = fixture.connect().await;
    assert!(matches!(
        reader.receive().await.expect("readiness"),
        Message::Event(_)
    ));
    writer
        .send(&Message::GracefulClose(GracefulClose {
            code: CloseCode::Normal,
            reason: "integration complete".to_owned(),
        }))
        .await
        .expect("close");
    assert!(matches!(
        reader.receive().await.expect("close response"),
        Message::GracefulClose(_)
    ));
    let result = timeout(PROCESS_TIMEOUT, supervisor)
        .await
        .expect("supervisor timeout")
        .expect("supervisor task");
    assert!(result.is_ok());
    assert!(!fixture.session_dir.exists());
    assert!(test_kill_process(service_pid).is_err());
    assert!(test_kill_process(child_pid).is_err());
}

#[tokio::test]
async fn mandatory_crash_and_protocol_disconnect_fail_closed() {
    let _guard = TEST_LOCK.lock().await;
    let crash_fixture = Fixture::new("crash", 0, false);
    let options = crash_fixture.options.clone();
    let identity = crash_fixture.identity();
    let mut crashed = tokio::spawn(async move { run(options, &VerifiedControls, identity).await });
    crash_fixture.wait_ready(&mut crashed).await;
    let result = timeout(PROCESS_TIMEOUT, crashed)
        .await
        .expect("crash timeout")
        .expect("crash task");
    assert!(matches!(
        result,
        Err(GuestError::Service { ref service, .. }) if service == "exec"
    ));
    assert!(!crash_fixture.session_dir.exists());

    let disconnect_fixture = Fixture::new("healthy", 0, false);
    let options = disconnect_fixture.options.clone();
    let identity = disconnect_fixture.identity();
    let mut disconnected =
        tokio::spawn(async move { run(options, &VerifiedControls, identity).await });
    disconnect_fixture.wait_ready(&mut disconnected).await;
    let (mut reader, writer) = disconnect_fixture.connect().await;
    assert!(matches!(
        reader.receive().await.expect("readiness"),
        Message::Event(_)
    ));
    drop(reader);
    drop(writer);
    let result = timeout(PROCESS_TIMEOUT, disconnected)
        .await
        .expect("disconnect timeout")
        .expect("disconnect task");
    assert!(matches!(result, Err(GuestError::Protocol(_))));
    assert!(!disconnect_fixture.session_dir.exists());
}

#[tokio::test]
async fn partial_startup_failure_terminates_already_started_services() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = Fixture::new("partial", 0, false);
    let options = fixture.options.clone();
    let identity = fixture.identity();
    let failed = tokio::spawn(async move { run(options, &VerifiedControls, identity).await });
    let result = timeout(PROCESS_TIMEOUT, failed)
        .await
        .expect("partial startup timeout")
        .expect("partial startup task");
    assert!(matches!(
        result,
        Err(GuestError::Service { ref service, .. }) if service == "exec"
    ));
    assert!(fixture.audit_pid.exists());
    assert!(test_kill_process(read_pid(&fixture.audit_pid)).is_err());
    assert!(!fixture.session_dir.exists());
}

async fn wait_for_path_or_exit(
    path: &Path,
    supervisor: &mut tokio::task::JoinHandle<Result<(), GuestError>>,
) {
    tokio::select! {
        () = async {
            while !path.exists() {
                sleep(Duration::from_millis(10)).await;
            }
        } => {}
        outcome = &mut *supervisor => {
            panic!(
                "supervisor exited before {} was published: {outcome:?}",
                path.display()
            );
        }
        () = sleep(PROCESS_TIMEOUT) => {
            let state = path
                .parent()
                .map(|parent| fs::read_to_string(parent.join("state.json")))
                .transpose();
            panic!("timed out waiting for {}; state={state:?}", path.display());
        }
    }
}

fn read_pid(path: &Path) -> Pid {
    let raw = fs::read_to_string(path)
        .expect("read PID")
        .trim()
        .parse::<i32>()
        .expect("parse PID");
    Pid::from_raw(raw).expect("valid PID")
}
