use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::GuestError;
use sendbox_git::TrustedExecutable;
use sendbox_mcp::audit::{
    BoundaryAuditEvent, BoundaryAuditSink, FileAuditSink, MAX_AUDIT_EVENT_BYTES, UnixAuditSink,
};
use sendbox_mcp::broker::{
    BrokerCancellation, BrokerConfiguration, BrokerDirection, BrokerObserver, StderrPolicy,
    StdioBroker, TokioProcessLauncher,
};
use sendbox_mcp::config::{ApprovedCommand, NATIVE_BROKER_PATH};
use sendbox_mcp::error::BrokerError;
use sendbox_mcp::framing::FramingMode;
use sendbox_mcp::observation::{
    Direction, ObservationEventV1, ObservationMetadata, ObservationParser, Transport,
};
use sendbox_mcp::runtime::{
    NATIVE_AUDIT_SOCKET_PATH, NATIVE_POLICY_PATH, OBSERVATION_ROOT,
    RuntimeObservationConfiguration, RuntimePolicyDocument,
};
use sendbox_mcp::safe_outputs::SAFE_OUTPUTS_MCP_PATH;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "execution-broker")]
use crate::service::{HealthCheck, RestartPolicy, ServiceId, ServiceSpec};

const BOUNDARY_ROOT: &str = "/run/sendbox-boundary";
const EXIT_DENIED: u8 = 126;

pub fn install(policy: &RuntimePolicyDocument, artifact_root: &Path) -> Result<(), GuestError> {
    install_with_paths(
        policy,
        &InstallPaths {
            root: PathBuf::from(BOUNDARY_ROOT),
            policy: PathBuf::from(NATIVE_POLICY_PATH),
            wrapper: PathBuf::from(NATIVE_BROKER_PATH),
            safe_outputs_wrapper: PathBuf::from(SAFE_OUTPUTS_MCP_PATH),
            guest_binary: artifact_root.join("bin/sendbox-guest"),
            observation_root: PathBuf::from(OBSERVATION_ROOT),
        },
        0,
    )
}

pub fn safe_outputs_writer_socket() -> Result<PathBuf, GuestError> {
    let policy = read_policy(Path::new(NATIVE_POLICY_PATH))?;
    policy
        .safe_outputs
        .map(|safe_outputs| safe_outputs.writer_socket)
        .ok_or_else(|| GuestError::Runtime("Safe Outputs is not configured".to_owned()))
}

pub async fn execute_current(arguments: &[String]) -> Result<i32, GuestError> {
    let policy = read_policy(Path::new(NATIVE_POLICY_PATH))?;
    let command = ApprovedCommand::from_argv(arguments)
        .map_err(|error| GuestError::Runtime(format!("invalid MCP server command: {error}")))?;
    let approved = policy
        .approved_commands()
        .map_err(|error| GuestError::Runtime(format!("invalid MCP runtime policy: {error}")))?;
    if !approved.contains(&command) {
        return Err(GuestError::Runtime(
            "MCP server command is not exactly approved".to_owned(),
        ));
    }
    let resolved = policy.resolve_stdio(&command).map_err(|error| {
        GuestError::Runtime(format!("MCP server policy resolution failed: {error}"))
    })?;

    let mut environment = policy.fixed_environment.clone();
    environment.extend(
        policy
            .inherited_environment_keys
            .iter()
            .filter_map(|key| std::env::var(key).ok().map(|value| (key.clone(), value))),
    );
    let launcher = TokioProcessLauncher::new(environment, Some(policy.workspace_root.clone()));
    let compiled = resolved.compile();
    let configuration = BrokerConfiguration {
        client_framing: FramingMode::Auto,
        server_framing: FramingMode::Auto,
        max_frame_bytes: usize::try_from(policy.tool_policy.max_frame_bytes)
            .map_err(|_| GuestError::Runtime("MCP frame limit is invalid".to_owned()))?,
        stderr_policy: StderrPolicy::Inherit,
        ..BrokerConfiguration::default()
    };
    let audit = Arc::new(UnixAuditSink::new(NATIVE_AUDIT_SOCKET_PATH));
    let mut broker = StdioBroker::new(
        launcher,
        approved,
        command.clone(),
        compiled,
        audit,
        configuration,
    );
    if let Some(observation) = &policy.observation {
        broker = broker.with_observer(Arc::new(FileObserver::open(
            observation,
            policy.workload_gid,
            command.executable(),
        )?));
    }

    let cancellation = BrokerCancellation::default();
    let signal_cancellation = cancellation.clone();
    let signal_task = tokio::spawn(async move {
        if wait_for_termination().await.is_ok() {
            signal_cancellation.cancel();
        }
    });
    let result = broker
        .run(tokio::io::stdin(), tokio::io::stdout(), cancellation)
        .await;
    signal_task.abort();
    let report =
        result.map_err(|error| GuestError::Runtime(format!("MCP broker failed: {error}")))?;
    Ok(report.child_status.code().unwrap_or_else(|| {
        report
            .child_status
            .signal()
            .map_or(1, |signal| 128 + signal)
    }))
}

#[must_use]
pub const fn denied_exit_code() -> u8 {
    EXIT_DENIED
}

async fn wait_for_termination() -> Result<(), std::io::Error> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    }
}

struct InstallPaths {
    root: PathBuf,
    policy: PathBuf,
    wrapper: PathBuf,
    safe_outputs_wrapper: PathBuf,
    guest_binary: PathBuf,
    observation_root: PathBuf,
}

fn install_with_paths(
    policy: &RuntimePolicyDocument,
    paths: &InstallPaths,
    expected_owner: u32,
) -> Result<(), GuestError> {
    policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid MCP runtime policy: {error}")))?;
    validate_layout(policy, paths)?;
    prepare_root(&paths.root, expected_owner, 0o755, "MCP boundary root")?;
    prepare_root(
        &paths.observation_root,
        expected_owner,
        0o755,
        "MCP log root",
    )?;

    let guest_binary = TrustedExecutable::verify(&paths.guest_binary)
        .map_err(|error| GuestError::Runtime(error.to_string()))?;
    validate_regular_file(
        guest_binary.path(),
        expected_owner,
        None,
        false,
        "MCP guest binary",
    )?;
    guest_binary
        .copy_to(&paths.wrapper, 0o555)
        .map_err(|error| GuestError::Runtime(error.to_string()))?;
    fs::set_permissions(&paths.wrapper, fs::Permissions::from_mode(0o555))
        .map_err(|error| GuestError::io("setting MCP broker wrapper mode", error))?;
    if policy.safe_outputs.is_some() {
        guest_binary
            .copy_to(&paths.safe_outputs_wrapper, 0o555)
            .map_err(|error| GuestError::Runtime(error.to_string()))?;
        fs::set_permissions(
            &paths.safe_outputs_wrapper,
            fs::Permissions::from_mode(0o555),
        )
        .map_err(|error| GuestError::io("setting Safe Outputs MCP wrapper mode", error))?;
    }

    let encoded = serde_json::to_vec(policy)
        .map_err(|error| GuestError::Runtime(format!("encoding MCP policy: {error}")))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&paths.policy)
        .map_err(|error| GuestError::io("creating MCP policy", error))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| GuestError::io("writing MCP policy", error))?;

    create_audit_log(&policy.audit_log_path, expected_owner)?;
    if let Some(observation) = &policy.observation {
        create_log(&observation.log_path, expected_owner, policy.workload_gid)?;
    }
    File::open(&paths.root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| GuestError::io("syncing MCP boundary root", error))
}

#[must_use]
#[cfg(feature = "execution-broker")]
pub fn audit_service() -> ServiceSpec {
    ServiceSpec {
        id: ServiceId::Audit,
        dependencies: Vec::new(),
        executable: PathBuf::from("bin/sendbox-guest"),
        args: vec![
            "mcp-audit".to_owned(),
            "--policy".to_owned(),
            NATIVE_POLICY_PATH.to_owned(),
        ],
        mandatory: true,
        restart: RestartPolicy::default(),
        health: HealthCheck::UnixSocket {
            path: PathBuf::from(NATIVE_AUDIT_SOCKET_PATH),
            timeout_ms: 30_000,
        },
        graceful_shutdown_ms: 5_000,
        forced_shutdown_ms: 2_000,
        max_log_bytes: 256 * 1024,
    }
}

pub async fn run_audit_service(policy_path: PathBuf) -> Result<(), GuestError> {
    let policy = read_policy(&policy_path)?;
    policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid MCP runtime policy: {error}")))?;
    validate_regular_file(
        &policy.audit_log_path,
        0,
        Some(0),
        false,
        "MCP boundary audit log",
    )?;
    let sink = Arc::new(
        FileAuditSink::open(&policy.audit_log_path)
            .map_err(|error| GuestError::Runtime(format!("opening MCP audit log: {error}")))?,
    );
    let socket_path = Path::new(NATIVE_AUDIT_SOCKET_PATH);
    remove_socket(socket_path)?;
    let listener = UnixListener::bind(socket_path)
        .map_err(|error| GuestError::io("binding MCP audit socket", error))?;
    std::os::unix::fs::chown(socket_path, Some(0), Some(policy.workload_gid))
        .map_err(|error| GuestError::io("assigning MCP audit socket", error))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o620))
        .map_err(|error| GuestError::io("setting MCP audit socket mode", error))?;

    let fatal = CancellationToken::new();
    let permits = Arc::new(Semaphore::new(64));
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| GuestError::io("installing MCP audit SIGTERM handler", error))?;
    loop {
        tokio::select! {
            () = fatal.cancelled() => {
                return Err(GuestError::Runtime(
                    "MCP audit writer failed closed".to_owned(),
                ));
            }
            _ = terminate.recv() => {
                remove_socket(socket_path)?;
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _) =
                    accepted.map_err(|error| GuestError::io("accepting MCP audit event", error))?;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    eprintln!("[sendbox-mcp-audit] connection capacity exceeded");
                    continue;
                };
                let sink = Arc::clone(&sink);
                let fatal = fatal.clone();
                tokio::spawn(async move {
                    let result = timeout(
                        Duration::from_secs(2),
                        handle_audit_client(stream, sink),
                    )
                    .await;
                    drop(permit);
                    if let Err(error) = result
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "MCP audit client timed out",
                            )
                        })
                        .and_then(|result| result)
                    {
                        eprintln!("[sendbox-mcp-audit] {error}");
                        if error.kind() == std::io::ErrorKind::Other {
                            fatal.cancel();
                        }
                    }
                });
            }
        }
    }
}

async fn handle_audit_client(
    mut stream: UnixStream,
    sink: Arc<FileAuditSink>,
) -> Result<(), std::io::Error> {
    let mut length = [0_u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(error) => return Err(error),
    }
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid audit length")
    })?;
    if length == 0 || length > MAX_AUDIT_EVENT_BYTES {
        stream.write_all(&[0]).await?;
        return Ok(());
    }
    let mut encoded = vec![0_u8; length];
    stream.read_exact(&mut encoded).await?;
    let event = match serde_json::from_slice::<BoundaryAuditEvent>(&encoded) {
        Ok(event) if event.schema_version == 1 => event,
        Ok(_) | Err(_) => {
            stream.write_all(&[0]).await?;
            return Ok(());
        }
    };
    sink.record(&event)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    stream.write_all(&[1]).await
}

fn remove_socket(path: &Path) -> Result<(), GuestError> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)
            .map_err(|error| GuestError::io("removing stale MCP audit socket", error)),
        Ok(_) => Err(GuestError::Runtime(
            "MCP audit socket path is occupied by an untrusted file".to_owned(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(GuestError::io("inspecting MCP audit socket", error)),
    }
}

fn create_audit_log(path: &Path, expected_owner: u32) -> Result<(), GuestError> {
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| GuestError::io("creating MCP boundary audit log", error))?;
    std::os::unix::fs::chown(path, Some(expected_owner), Some(expected_owner))
        .map_err(|error| GuestError::io("assigning MCP boundary audit log", error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| GuestError::io("setting MCP boundary audit log mode", error))?;
    log.sync_all()
        .map_err(|error| GuestError::io("syncing MCP boundary audit log", error))
}

fn validate_layout(policy: &RuntimePolicyDocument, paths: &InstallPaths) -> Result<(), GuestError> {
    if !paths.root.is_absolute()
        || paths.policy.parent() != Some(paths.root.as_path())
        || paths.wrapper.parent() != Some(paths.root.as_path())
        || paths.safe_outputs_wrapper.parent() != Some(paths.root.as_path())
        || paths.policy == paths.wrapper
        || paths.policy == paths.safe_outputs_wrapper
        || paths.wrapper == paths.safe_outputs_wrapper
        || !paths.guest_binary.is_absolute()
        || !paths.observation_root.is_absolute()
        || policy.audit_log_path.parent() != Some(paths.observation_root.as_path())
        || policy.observation.as_ref().is_some_and(|observation| {
            observation.log_path.parent() != Some(paths.observation_root.as_path())
                || observation.log_path == policy.audit_log_path
        })
    {
        return Err(GuestError::Runtime(
            "MCP installation paths are invalid".to_owned(),
        ));
    }
    if paths.policy.symlink_metadata().is_ok()
        || paths.wrapper.symlink_metadata().is_ok()
        || paths.safe_outputs_wrapper.symlink_metadata().is_ok()
    {
        return Err(GuestError::Runtime(
            "MCP policy or wrapper path already exists".to_owned(),
        ));
    }
    Ok(())
}

fn create_log(path: &Path, expected_owner: u32, workload_gid: u32) -> Result<(), GuestError> {
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o620)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| GuestError::io("creating MCP boundary log", error))?;
    std::os::unix::fs::chown(path, Some(expected_owner), Some(workload_gid))
        .map_err(|error| GuestError::io("assigning MCP boundary log", error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o620))
        .map_err(|error| GuestError::io("setting MCP boundary log mode", error))?;
    log.sync_all()
        .map_err(|error| GuestError::io("syncing MCP boundary log", error))
}

fn prepare_root(
    path: &Path,
    expected_owner: u32,
    mode: u32,
    description: &str,
) -> Result<(), GuestError> {
    if path.symlink_metadata().is_err() {
        fs::DirBuilder::new()
            .mode(mode)
            .create(path)
            .map_err(|error| GuestError::io("creating trusted MCP directory", error))?;
    }
    let metadata = path
        .symlink_metadata()
        .map_err(|error| GuestError::io("inspecting trusted MCP directory", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
    {
        return Err(GuestError::Runtime(format!("{description} is not trusted")));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| GuestError::io("setting trusted MCP directory mode", error))
}

fn validate_regular_file(
    path: &Path,
    expected_uid: u32,
    expected_gid: Option<u32>,
    allow_group_write: bool,
    description: &str,
) -> Result<(), GuestError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| GuestError::io("inspecting trusted MCP file", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || expected_gid.is_some_and(|gid| metadata.gid() != gid)
        || metadata.mode() & if allow_group_write { 0o002 } else { 0o022 } != 0
    {
        return Err(GuestError::Runtime(format!("{description} is not trusted")));
    }
    Ok(())
}

fn read_policy(path: &Path) -> Result<RuntimePolicyDocument, GuestError> {
    read_policy_with_owner(path, 0)
}

fn read_policy_with_owner(
    path: &Path,
    expected_owner: u32,
) -> Result<RuntimePolicyDocument, GuestError> {
    validate_regular_file(path, expected_owner, None, false, "MCP runtime policy")?;
    let bytes =
        fs::read(path).map_err(|error| GuestError::io("reading MCP runtime policy", error))?;
    let policy: RuntimePolicyDocument = serde_json::from_slice(&bytes)
        .map_err(|error| GuestError::Runtime(format!("decoding MCP runtime policy: {error}")))?;
    policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid MCP runtime policy: {error}")))?;
    Ok(policy)
}

struct FileObserver {
    file: Mutex<File>,
    configuration: RuntimeObservationConfiguration,
    command: String,
}

impl FileObserver {
    fn open(
        configuration: &RuntimeObservationConfiguration,
        workload_gid: u32,
        executable: &str,
    ) -> Result<Self, GuestError> {
        Self::open_with_owner(configuration, 0, workload_gid, executable)
    }

    fn open_with_owner(
        configuration: &RuntimeObservationConfiguration,
        expected_uid: u32,
        workload_gid: u32,
        executable: &str,
    ) -> Result<Self, GuestError> {
        validate_regular_file(
            &configuration.log_path,
            expected_uid,
            Some(workload_gid),
            true,
            "MCP observation log",
        )?;
        let file = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&configuration.log_path)
            .map_err(|error| GuestError::io("opening MCP observation log", error))?;
        let observer = Self {
            file: Mutex::new(file),
            configuration: configuration.clone(),
            command: executable.to_owned(),
        };
        observer
            .record(Direction::Spawn, executable.as_bytes().to_vec())
            .map_err(|error| GuestError::Runtime(format!("recording MCP server spawn: {error}")))?;
        Ok(observer)
    }

    fn record(&self, direction: Direction, payload: Vec<u8>) -> Result<(), BrokerError> {
        let event = ObservationEventV1::from_metadata(ObservationMetadata {
            timestamp_nanos: timestamp_nanos(),
            process_id: Some(std::process::id()),
            command: Some(self.command.clone()),
            transport: Transport::Stdio,
            direction,
            payload,
        })
        .map_err(|error| BrokerError::Io(std::io::Error::other(error)))?;
        let mut encoded = event
            .encode_line()
            .map_err(|error| BrokerError::Io(std::io::Error::other(error)))?;
        encoded.push('\n');
        let mut file = self
            .file
            .lock()
            .map_err(|_| BrokerError::Io(std::io::Error::other("observation log poisoned")))?;
        file.write_all(encoded.as_bytes())
            .map_err(BrokerError::Io)?;
        file.flush().map_err(BrokerError::Io)
    }
}

impl BrokerObserver for FileObserver {
    fn observe(&self, direction: BrokerDirection, payload: &[u8]) -> Result<(), BrokerError> {
        let json = std::str::from_utf8(payload)
            .map_err(|error| BrokerError::Io(std::io::Error::other(error)))?;
        let raw = if self.configuration.capture_payloads {
            json.to_owned()
        } else {
            ObservationParser::new(false)
                .parse_message(
                    json,
                    Transport::Stdio,
                    Some(std::process::id()),
                    Some(self.command.clone()),
                    timestamp_nanos(),
                )
                .map_err(|error| BrokerError::Io(std::io::Error::other(error)))?
                .raw
        };
        let direction = match direction {
            BrokerDirection::ToServer => Direction::ToServer,
            BrokerDirection::FromServer => Direction::FromServer,
        };
        self.record(
            direction,
            truncate_utf8(&raw, self.configuration.max_payload_bytes).into_bytes(),
        )
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn timestamp_nanos() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::PermissionsExt;

    use sendbox_mcp::observation::{MessageKind, ObservationParser};
    use sendbox_mcp::runtime::RUNTIME_POLICY_SCHEMA_VERSION;
    use sendbox_policy::{Action, ToolCallPolicy, ToolTransport};

    use super::*;

    #[test]
    fn truncation_preserves_utf8_boundaries() {
        assert_eq!(truncate_utf8("abé", 3), "ab");
        assert_eq!(truncate_utf8("abé", 4), "abé");
    }

    fn policy() -> RuntimePolicyDocument {
        RuntimePolicyDocument {
            schema_version: RUNTIME_POLICY_SCHEMA_VERSION,
            workspace_root: PathBuf::from("/workspace"),
            workload_uid: 1000,
            workload_gid: 1000,
            tool_policy: ToolCallPolicy {
                transport: ToolTransport::Stdio,
                default_action: Action::Deny,
                allowlist: vec!["read".to_owned()],
                denylist: Vec::new(),
                max_frame_bytes: 4096,
                server_command_patterns: Vec::new(),
                allowed_server_commands: vec![vec!["/bin/echo".to_owned()]],
                servers: BTreeMap::new(),
            },
            audit_log_path: PathBuf::from("/var/log/sendbox/boundary.log"),
            fixed_environment: BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]),
            inherited_environment_keys: BTreeSet::new(),
            observation: None,
            safe_outputs: None,
        }
    }

    #[test]
    fn installation_rejects_existing_wrapper() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("boundary");
        fs::create_dir(&root).expect("root");
        let wrapper = root.join("mcp-broker");
        fs::write(&wrapper, b"occupied").expect("wrapper");
        let result = validate_layout(
            &policy(),
            &InstallPaths {
                root: root.clone(),
                policy: root.join("mcp-policy.json"),
                wrapper,
                safe_outputs_wrapper: root.join("safe-outputs-mcp"),
                guest_binary: temp.path().join("sendbox-guest"),
                observation_root: temp.path().join("logs"),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn observation_records_denied_payloads_without_secret_arguments() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log_path = temp.path().join("mcp.log");
        fs::write(&log_path, b"").expect("log");
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o620)).expect("mode");
        let configuration = RuntimeObservationConfiguration {
            capture_payloads: false,
            max_payload_bytes: 4096,
            log_path: log_path.clone(),
        };
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let observer =
            FileObserver::open_with_owner(&configuration, uid, gid, "/usr/bin/mcp-server")
                .expect("observer");
        observer
            .observe(
                BrokerDirection::ToServer,
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","arguments":{"token":"secret-value"}}}"#,
            )
            .expect("observe");

        let log = fs::read_to_string(log_path).expect("observation log");
        assert!(!log.contains("secret-value"));
        let calls = ObservationParser::new(false).parse_log(&log);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].kind, MessageKind::Spawn);
        assert_eq!(calls[1].subject.as_deref(), Some("delete_file"));
    }

    #[test]
    fn runtime_policy_tampering_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("policy.json");
        let mut policy = policy();
        policy.schema_version = u32::MAX;
        fs::write(&path, serde_json::to_vec(&policy).expect("policy JSON")).expect("policy");
        let error = read_policy_with_owner(&path, rustix::process::getuid().as_raw())
            .expect_err("tampered policy must fail");
        assert!(error.to_string().contains("unsupported MCP runtime policy"));
    }
}
