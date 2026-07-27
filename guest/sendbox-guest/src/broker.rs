#![forbid(unsafe_code)]

use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;

use sendbox_core::SessionId;
#[cfg(target_os = "linux")]
use sendbox_exec::platform::linux::launcher::{LauncherProcessBackend, LauncherRoot};
#[cfg(target_os = "linux")]
use sendbox_exec::runtime::RuntimeDirectory;
#[cfg(target_os = "linux")]
use sendbox_exec::service::BrokerService;
#[cfg(target_os = "linux")]
use sendbox_exec::session::BrokerSession;
#[cfg(target_os = "linux")]
use sendbox_exec::{Broker, RequestLimits};
use sendbox_exec::{ExecutionUser, SessionAuthentication};
use sendbox_policy::CommandPolicy;
use serde::{Deserialize, Serialize};

use crate::GuestError;
use crate::service::{HealthCheck, RestartPolicy, ServiceId, ServiceSpec};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBrokerBootstrap {
    pub authentication: [u8; 32],
    pub runtime_parent: PathBuf,
    pub socket_path: PathBuf,
    pub launcher_path: PathBuf,
    pub cgroup_parent: PathBuf,
    pub workspace_root: PathBuf,
    pub system_root: PathBuf,
    pub workload_uid: u32,
    pub workload_gid: u32,
    pub command_policy: CommandPolicy,
}

#[derive(Clone)]
pub struct BrokerClientConfiguration {
    pub session_id: SessionId,
    pub authentication: SessionAuthentication,
    pub socket_path: PathBuf,
    pub workload: ExecutionUser,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerProcessConfiguration {
    session_id: SessionId,
    authentication: [u8; 32],
    runtime_parent: PathBuf,
    launcher_path: PathBuf,
    cgroup_parent: PathBuf,
    workspace_root: PathBuf,
    system_root: PathBuf,
    command_policy: CommandPolicy,
}

pub fn prepare(
    session_id: SessionId,
    session_dir: &Path,
    bootstrap: ExecutionBrokerBootstrap,
) -> Result<(BrokerClientConfiguration, ServiceSpec), GuestError> {
    if bootstrap.workload_uid == 0 || bootstrap.workload_gid == 0 {
        return Err(GuestError::Runtime(
            "brokered workloads must use a non-root uid and gid".to_owned(),
        ));
    }
    prepare_runtime_parent(&bootstrap.runtime_parent)?;
    let expected_socket = bootstrap
        .runtime_parent
        .join(session_id.to_string())
        .join(sendbox_exec::runtime::SOCKET_FILE_NAME);
    if bootstrap.socket_path != expected_socket {
        return Err(GuestError::Runtime(
            "execution broker socket path does not match its session runtime".to_owned(),
        ));
    }

    fn prepare_runtime_parent(path: &Path) -> Result<(), GuestError> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        if !path.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(|error| GuestError::io("creating broker runtime parent", error))?;
        }
        let metadata = path
            .symlink_metadata()
            .map_err(|error| GuestError::io("inspecting broker runtime parent", error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
        {
            return Err(GuestError::Runtime(
                "broker runtime parent must be a root-owned directory".to_owned(),
            ));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| GuestError::io("setting broker runtime parent mode", error))
    }
    let config_path = session_dir.join("broker.json");
    let encoded = serde_json::to_vec(&BrokerProcessConfiguration {
        session_id,
        authentication: bootstrap.authentication,
        runtime_parent: bootstrap.runtime_parent,
        launcher_path: bootstrap.launcher_path,
        cgroup_parent: bootstrap.cgroup_parent,
        workspace_root: bootstrap.workspace_root,
        system_root: bootstrap.system_root,
        command_policy: bootstrap.command_policy,
    })
    .map_err(|error| GuestError::Runtime(format!("encode broker configuration: {error}")))?;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(&config_path)
        .map_err(|error| GuestError::io("creating broker configuration", error))?;
    use std::io::Write;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| GuestError::io("writing broker configuration", error))?;

    Ok((
        BrokerClientConfiguration {
            session_id,
            authentication: SessionAuthentication::from_bytes(bootstrap.authentication),
            socket_path: bootstrap.socket_path,
            workload: ExecutionUser {
                uid: bootstrap.workload_uid,
                gid: bootstrap.workload_gid,
            },
        },
        ServiceSpec {
            id: ServiceId::Exec,
            dependencies: Vec::new(),
            executable: PathBuf::from("bin/sendbox-guest"),
            args: vec![
                "exec-broker".to_owned(),
                "--config".to_owned(),
                config_path.display().to_string(),
            ],
            mandatory: true,
            restart: RestartPolicy::default(),
            health: HealthCheck::UnixSocket {
                path: expected_socket,
                timeout_ms: 30_000,
            },
            graceful_shutdown_ms: 2_000,
            forced_shutdown_ms: 5_000,
            max_log_bytes: 64 * 1024,
        },
    ))
}

#[cfg(target_os = "linux")]
pub async fn run(config_path: PathBuf) -> Result<(), GuestError> {
    validate_config_file(&config_path)?;
    let bytes = fs::read(&config_path)
        .map_err(|error| GuestError::io("reading broker configuration", error))?;
    let config: BrokerProcessConfiguration = serde_json::from_slice(&bytes)
        .map_err(|error| GuestError::Runtime(format!("decode broker configuration: {error}")))?;
    fs::remove_file(&config_path)
        .map_err(|error| GuestError::io("removing consumed broker configuration", error))?;

    let session = Arc::new(BrokerSession::from_material(
        config.session_id,
        SessionAuthentication::from_bytes(config.authentication),
    ));
    let runtime = RuntimeDirectory::create(&config.runtime_parent, config.session_id, 0)
        .map_err(|error| GuestError::Runtime(format!("prepare broker runtime: {error}")))?;
    let listener = runtime
        .initialize(&session)
        .map_err(|error| GuestError::Runtime(format!("initialize broker runtime: {error}")))?;
    let backend = LauncherProcessBackend::new(
        config.launcher_path,
        vec![
            LauncherRoot {
                id: sendbox_exec::RootId::Workspace,
                path: config.workspace_root,
            },
            LauncherRoot {
                id: sendbox_exec::RootId::System,
                path: config.system_root,
            },
        ],
        config.cgroup_parent,
        Duration::from_secs(5),
    )
    .with_output_event_limit(Some(4096));
    let broker = Arc::new(Broker::new(
        session,
        sendbox_exec::CompiledCommandPolicy::compile(&config.command_policy)
            .map_err(|error| GuestError::Runtime(format!("compile command policy: {error}")))?,
        sendbox_exec::environment::EnvironmentPolicy::default(),
        RequestLimits::default(),
        backend,
    ));
    let service = BrokerService::new(broker);
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| GuestError::io("installing broker SIGTERM handler", error))?;
    let service_task = tokio::task::spawn_blocking(move || service.serve_once(&listener));
    tokio::select! {
        result = service_task => {
            result
                .map_err(|error| GuestError::Runtime(format!("broker service task failed: {error}")))?
                .map_err(|error| GuestError::Runtime(format!("broker service failed: {error}")))?;
            terminate.recv().await;
        }
        _ = terminate.recv() => {}
    }
    runtime
        .cleanup_after_listener_drop()
        .map_err(|error| GuestError::Runtime(format!("clean broker runtime: {error}")))
}

#[cfg(not(target_os = "linux"))]
pub async fn run(_config_path: PathBuf) -> Result<(), GuestError> {
    Err(GuestError::Runtime(
        "the production execution broker requires Linux".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn validate_config_file(path: &Path) -> Result<(), GuestError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| GuestError::io("inspecting broker configuration", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o7777 != 0o400
    {
        return Err(GuestError::Runtime(
            "broker configuration must be a root-owned 0400 regular file".to_owned(),
        ));
    }
    Ok(())
}
