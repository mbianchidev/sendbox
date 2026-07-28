#![forbid(unsafe_code)]

use std::fs;
#[cfg(any(target_os = "linux", test))]
use std::io;
use std::io::Write as _;
#[cfg(any(target_os = "linux", test))]
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::OpenOptionsExt;
#[cfg(any(target_os = "linux", test))]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(any(target_os = "linux", test))]
use rustix::fs::{Mode, OFlags, open};
use sendbox_bootstrap::RegistryProxyConfiguration;
use sendbox_core::SessionId;
#[cfg(any(target_os = "linux", test))]
use sendbox_egress::address::{AddressClass, classify};
use sendbox_egress::runtime::RuntimePolicyDocument;
use serde::{Deserialize, Serialize};

use crate::GuestError;
use crate::service::{HealthCheck, RestartPolicy, ServiceId, ServiceSpec};

#[cfg(target_os = "linux")]
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
#[cfg(target_os = "linux")]
const RESOLVER_STATE_FILE: &str = "egress-resolver-state.json";
#[cfg(any(target_os = "linux", test))]
const MAX_RESOLVER_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const MAX_CONTROL_BYTES: usize = 4096;
#[cfg(target_os = "linux")]
const GATEWAY_START_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(target_os = "linux")]
const GATEWAY_STOP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorProcessConfiguration {
    session_id: SessionId,
    policy: RuntimePolicyDocument,
    registry: Option<RegistryProxyConfiguration>,
    readiness_socket: PathBuf,
    workload_control_socket: PathBuf,
    trusted_control_socket: Option<PathBuf>,
    registry_control_socket: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayProcessConfiguration {
    policy: RuntimePolicyDocument,
    role: GatewayRole,
    upstream: SocketAddr,
    control_socket: PathBuf,
    control_token: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GatewayRole {
    Workload,
    Registry,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryProcessConfiguration {
    session_id: SessionId,
    registry: RegistryProxyConfiguration,
    control_socket: PathBuf,
    control_token: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "snake_case", deny_unknown_fields)]
enum ControlMessage {
    Hello { token: String },
    Bound { token: String },
    Start { token: String },
    Serving { token: String },
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolverState {
    upstream: SocketAddr,
    original: Vec<u8>,
}

#[cfg(any(target_os = "linux", test))]
struct ResolverPlan {
    target: PathBuf,
    mode: u32,
    original: Vec<u8>,
    replacement: Vec<u8>,
    upstream: SocketAddr,
}

pub fn prepare(
    session_dir: &Path,
    session_id: SessionId,
    policy: RuntimePolicyDocument,
    registry: Option<RegistryProxyConfiguration>,
) -> Result<ServiceSpec, GuestError> {
    policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid egress policy: {error}")))?;
    let readiness_socket = session_dir.join("egress-ready.sock");
    let workload_control_socket = session_dir.join("egress-workload-control.sock");
    let trusted_control_socket = registry
        .as_ref()
        .map(|_| session_dir.join("egress-trusted-control.sock"));
    let registry_control_socket = registry
        .as_ref()
        .map(|_| session_dir.join("registry-proxy-control.sock"));
    let config_path = session_dir.join("egress-supervisor.json");
    write_root_config(
        &config_path,
        &SupervisorProcessConfiguration {
            session_id,
            policy,
            registry,
            readiness_socket: readiness_socket.clone(),
            workload_control_socket,
            trusted_control_socket,
            registry_control_socket,
        },
    )?;
    Ok(ServiceSpec {
        id: ServiceId::Egress,
        dependencies: Vec::new(),
        executable: PathBuf::from("bin/sendbox-guest"),
        args: vec![
            "egress-supervisor".to_owned(),
            "--config".to_owned(),
            config_path.display().to_string(),
        ],
        mandatory: true,
        restart: RestartPolicy::default(),
        health: HealthCheck::UnixSocket {
            path: readiness_socket,
            timeout_ms: 30_000,
        },
        graceful_shutdown_ms: 20_000,
        forced_shutdown_ms: 5_000,
        max_log_bytes: 256 * 1024,
    })
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
enum ChildPlacement {
    Broker,
    Registry,
}

#[cfg(target_os = "linux")]
struct ControlledChild {
    role: &'static str,
    placement: ChildPlacement,
    child: tokio::process::Child,
    control: tokio::net::UnixStream,
    token: String,
    control_socket: PathBuf,
    reaped: bool,
}

#[cfg(target_os = "linux")]
pub async fn run_supervisor(config_path: PathBuf) -> Result<(), GuestError> {
    use sendbox_egress::linux::supervisor::{ArmedEgress, SupervisorConfig};
    use tokio_util::sync::CancellationToken;

    let config: SupervisorProcessConfiguration = read_root_config(&config_path)?;
    fs::remove_file(&config_path)
        .map_err(|error| GuestError::io("removing consumed egress configuration", error))?;
    config
        .policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid egress policy: {error}")))?;
    validate_runtime_paths(
        &config_path,
        &config.readiness_socket,
        &config.workload_control_socket,
        config.trusted_control_socket.as_deref(),
        config.registry_control_socket.as_deref(),
    )?;
    if config.registry.is_some() != config.policy.registry.is_some()
        || config.registry.is_some() != config.trusted_control_socket.is_some()
        || config.registry.is_some() != config.registry_control_socket.is_some()
    {
        return Err(GuestError::Runtime(
            "registry proxy and egress isolation configuration must be present together".to_owned(),
        ));
    }
    require_root_cgroup_namespace()?;

    let runtime_root = config_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| GuestError::Runtime("egress runtime root is unavailable".to_owned()))?;
    crate::secure_fs::open_directory_no_symlinks(runtime_root)?;
    let resolver = ResolverPlan::load(
        Path::new(RESOLV_CONF_PATH),
        &runtime_root.join(RESOLVER_STATE_FILE),
    )?;
    if let Some(registry) = &config.registry {
        prepare_registry_directories(registry)?;
    }

    let workload_token = random_token()?;
    let workload_config_path = config_path
        .parent()
        .expect("validated configuration has a parent")
        .join("egress-workload-gateway.json");
    write_root_config(
        &workload_config_path,
        &GatewayProcessConfiguration {
            policy: config.policy.clone(),
            role: GatewayRole::Workload,
            upstream: resolver.upstream,
            control_socket: config.workload_control_socket.clone(),
            control_token: workload_token.clone(),
        },
    )?;
    remove_socket_if_present(&config.workload_control_socket)?;

    let mut trusted_process = None;
    let mut registry_process = None;
    if let Some(registry) = &config.registry {
        let trusted_token = random_token()?;
        let trusted_config_path = config_path
            .parent()
            .expect("validated configuration has a parent")
            .join("egress-trusted-gateway.json");
        let trusted_control_socket = config
            .trusted_control_socket
            .clone()
            .expect("validated trusted control socket");
        write_root_config(
            &trusted_config_path,
            &GatewayProcessConfiguration {
                policy: config.policy.clone(),
                role: GatewayRole::Registry,
                upstream: resolver.upstream,
                control_socket: trusted_control_socket.clone(),
                control_token: trusted_token.clone(),
            },
        )?;
        remove_socket_if_present(&trusted_control_socket)?;
        trusted_process = Some((trusted_config_path, trusted_control_socket, trusted_token));

        let registry_token = random_token()?;
        let registry_config_path = config_path
            .parent()
            .expect("validated configuration has a parent")
            .join("registry-proxy.json");
        let registry_control_socket = config
            .registry_control_socket
            .clone()
            .expect("validated registry control socket");
        write_root_config(
            &registry_config_path,
            &RegistryProcessConfiguration {
                session_id: config.session_id,
                registry: registry.clone(),
                control_socket: registry_control_socket.clone(),
                control_token: registry_token.clone(),
            },
        )?;
        remove_socket_if_present(&registry_control_socket)?;
        registry_process = Some((
            registry_config_path,
            registry_control_socket,
            registry_token,
        ));
    }

    let executable = std::env::current_exe()
        .map_err(|error| GuestError::io("resolving guest executable", error))?;
    let mut children = Vec::new();
    match spawn_controlled(
        &executable,
        "egress-gateway",
        &workload_config_path,
        config.workload_control_socket.clone(),
        workload_token,
        "workload egress gateway",
        ChildPlacement::Broker,
    )
    .await
    {
        Ok(child) => children.push(child),
        Err(error) => return Err(error),
    }
    if let Some((path, socket, token)) = trusted_process {
        match spawn_controlled(
            &executable,
            "egress-gateway",
            &path,
            socket,
            token,
            "trusted registry gateway",
            ChildPlacement::Broker,
        )
        .await
        {
            Ok(child) => children.push(child),
            Err(error) => {
                let _ = stop_children(&mut children).await;
                return Err(error);
            }
        }
    }
    if let Some((path, socket, token)) = registry_process {
        match spawn_controlled(
            &executable,
            "registry-proxy",
            &path,
            socket,
            token,
            "registry proxy",
            ChildPlacement::Registry,
        )
        .await
        {
            Ok(child) => children.push(child),
            Err(error) => {
                let _ = stop_children(&mut children).await;
                return Err(error);
            }
        }
    }

    let mut supervisor_config = SupervisorConfig::new(
        config.policy.instance_id.clone(),
        config.policy.broker_mark,
        config.policy.connect_port,
    )
    .with_execution_delegation();
    supervisor_config
        .table_name
        .clone_from(&config.policy.table_name);
    if let Some(port) = config.policy.dns_port {
        supervisor_config = supervisor_config.with_dns_port(port);
    }
    if let Some(registry) = &config.policy.registry {
        supervisor_config = supervisor_config
            .with_registry_proxy(registry.proxy_port, registry.trusted_upstream_port);
    }
    let mut armed = match ArmedEgress::arm(supervisor_config) {
        Ok(armed) => armed,
        Err(error) => {
            let _ = stop_children(&mut children).await;
            return Err(GuestError::Runtime(format!(
                "arming production egress: {error}"
            )));
        }
    };
    for child in &children {
        let child_pid = child
            .child
            .id()
            .ok_or_else(|| GuestError::Runtime(format!("{} has no process ID", child.role)))?;
        let placement = match child.placement {
            ChildPlacement::Broker => armed.place_broker(child_pid),
            ChildPlacement::Registry => armed.place_registry(child_pid),
        };
        if let Err(error) = placement {
            let _ = stop_children(&mut children).await;
            let teardown = armed.teardown();
            return Err(GuestError::Runtime(format!(
                "placing {} in its egress cgroup: {error}; teardown: {teardown:?}",
                child.role
            )));
        }
    }
    let expected_parent = config
        .policy
        .execution_cgroup_parent(Path::new(sendbox_egress::runtime::DEFAULT_CGROUP_ROOT));
    if armed.execution_cgroup_parent() != expected_parent {
        let _ = stop_children(&mut children).await;
        let teardown = armed.teardown();
        return Err(GuestError::Runtime(format!(
            "armed execution cgroup parent drifted from signed policy; teardown: {teardown:?}"
        )));
    }

    async fn run_armed(
        config: &SupervisorProcessConfiguration,
        mut children: Vec<ControlledChild>,
        mut armed: ArmedEgress,
        resolver: ResolverPlan,
    ) -> Result<(), GuestError> {
        let mut failures = Vec::new();
        let mut resolver_installed = false;
        let readiness_cancel = CancellationToken::new();
        let mut readiness_task = None;

        let startup = async {
            for child in &mut children {
                write_control(
                    &mut child.control,
                    &ControlMessage::Start {
                        token: child.token.clone(),
                    },
                )
                .await?;
                expect_control(
                    &mut child.control,
                    ControlMessage::Serving {
                        token: child.token.clone(),
                    },
                )
                .await?;
            }
            Ok::<(), GuestError>(())
        }
        .await;
        if let Err(error) = startup {
            failures.push(error.to_string());
        } else if let Err(error) = resolver.install() {
            failures.push(error.to_string());
        } else {
            resolver_installed = true;
            match bind_readiness(&config.readiness_socket) {
                Ok(listener) => {
                    let cancel = readiness_cancel.clone();
                    readiness_task = Some(tokio::spawn(async move {
                        readiness_loop(listener, cancel).await
                    }));
                }
                Err(error) => failures.push(error.to_string()),
            }
        }

        if failures.is_empty() {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|error| GuestError::io("installing egress SIGTERM handler", error))?;
            let readiness = readiness_task.as_mut().expect("readiness task started");
            let mut health = tokio::time::interval(Duration::from_millis(100));
            'monitor: loop {
                tokio::select! {
                    _ = health.tick() => {
                        for child in &mut children {
                            match child.child.try_wait() {
                                Ok(Some(status)) => {
                                    child.reaped = true;
                                    failures.push(format!(
                                        "{} exited unexpectedly: {status}",
                                        child.role
                                    ));
                                    break 'monitor;
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    failures.push(format!(
                                        "checking {} status: {error}",
                                        child.role
                                    ));
                                    break 'monitor;
                                }
                            }
                        }
                    }
                    result = &mut *readiness => {
                        failures.push(match result {
                            Ok(Ok(())) => "egress readiness listener stopped unexpectedly".to_owned(),
                            Ok(Err(error)) => format!("egress readiness listener failed: {error}"),
                            Err(error) => format!("egress readiness task failed: {error}"),
                        });
                        break;
                    }
                    _ = terminate.recv() => break,
                }
            }
        }

        readiness_cancel.cancel();
        if let Some(task) = readiness_task {
            let _ = task.await;
        }
        if let Err(error) = remove_socket_if_present(&config.readiness_socket) {
            failures.push(error.to_string());
        }
        failures.extend(stop_children(&mut children).await);
        if resolver_installed && let Err(error) = resolver.restore() {
            failures.push(error.to_string());
        }
        let teardown = armed.teardown();
        failures.extend(
            teardown
                .into_iter()
                .map(|error| format!("tearing down egress: {error}")),
        );
        for child in &children {
            if let Err(error) = remove_socket_if_present(&child.control_socket) {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(GuestError::Runtime(failures.join("; ")))
        }
    }

    run_armed(&config, children, armed, resolver).await
}

#[cfg(target_os = "linux")]
async fn spawn_controlled(
    executable: &Path,
    subcommand: &'static str,
    config_path: &Path,
    control_socket: PathBuf,
    token: String,
    role: &'static str,
    placement: ChildPlacement,
) -> Result<ControlledChild, GuestError> {
    let mut child = tokio::process::Command::new(executable)
        .arg(subcommand)
        .arg("--config")
        .arg(config_path)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| GuestError::io(format!("spawning {role}"), error))?;
    let mut control =
        match connect_control(&control_socket, &mut child, role, GATEWAY_START_TIMEOUT).await {
            Ok(stream) => stream,
            Err(error) => {
                let _ = stop_process(role, &mut child, false).await;
                return Err(error);
            }
        };
    if let Err(error) = write_control(
        &mut control,
        &ControlMessage::Hello {
            token: token.clone(),
        },
    )
    .await
    {
        let _ = stop_process(role, &mut child, false).await;
        return Err(error);
    }
    if let Err(error) = expect_control(
        &mut control,
        ControlMessage::Bound {
            token: token.clone(),
        },
    )
    .await
    {
        let _ = stop_process(role, &mut child, false).await;
        return Err(error);
    }
    Ok(ControlledChild {
        role,
        placement,
        child,
        control,
        token,
        control_socket,
        reaped: false,
    })
}

#[cfg(target_os = "linux")]
async fn connect_control(
    path: &Path,
    child: &mut tokio::process::Child,
    role: &str,
    bound: Duration,
) -> Result<tokio::net::UnixStream, GuestError> {
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| GuestError::io(format!("checking {role} startup"), error))?
        {
            return Err(GuestError::Runtime(format!(
                "{role} exited before binding listeners: {status}"
            )));
        }
        match tokio::net::UnixStream::connect(path).await {
            Ok(stream) => return Ok(stream),
            Err(error) if tokio::time::Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(GuestError::io(
                    format!("connecting {role} control socket"),
                    error,
                ));
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn stop_children(children: &mut [ControlledChild]) -> Vec<String> {
    let mut failures = Vec::new();
    for child in children.iter_mut().rev() {
        if let Err(error) = stop_process(child.role, &mut child.child, child.reaped).await {
            failures.push(error.to_string());
        }
    }
    failures
}

#[cfg(target_os = "linux")]
async fn stop_process(
    role: &str,
    child: &mut tokio::process::Child,
    already_reaped: bool,
) -> Result<(), GuestError> {
    use rustix::process::{Pid, Signal, kill_process};

    if already_reaped {
        return Ok(());
    }
    if let Some(raw_pid) = child.id().and_then(|value| Pid::from_raw(value as i32)) {
        match kill_process(raw_pid, Signal::TERM) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => {
                return Err(GuestError::io(
                    format!("signalling {role}"),
                    io::Error::from(error),
                ));
            }
        }
    }
    match tokio::time::timeout(GATEWAY_STOP_TIMEOUT, child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(GuestError::io(format!("reaping {role}"), error)),
        Err(_) => {
            child
                .start_kill()
                .map_err(|error| GuestError::io(format!("killing {role}"), error))?;
            child
                .wait()
                .await
                .map(|_| ())
                .map_err(|error| GuestError::io(format!("reaping killed {role}"), error))
        }
    }
}

#[cfg(target_os = "linux")]
fn bind_readiness(path: &Path) -> Result<tokio::net::UnixListener, GuestError> {
    remove_socket_if_present(path)?;
    let listener = tokio::net::UnixListener::bind(path)
        .map_err(|error| GuestError::io("binding egress readiness socket", error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| GuestError::io("setting egress readiness socket mode", error))?;
    Ok(listener)
}

#[cfg(target_os = "linux")]
async fn readiness_loop(
    listener: tokio::net::UnixListener,
    cancel: tokio_util::sync::CancellationToken,
) -> io::Result<()> {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => {
                let (_stream, _) = accepted?;
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run_supervisor(_config_path: PathBuf) -> Result<(), GuestError> {
    Err(GuestError::Runtime(
        "production egress enforcement requires Linux".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
pub async fn run_gateway(config_path: PathBuf) -> Result<(), GuestError> {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;

    use sendbox_egress::audit::StderrJsonAuditSink;
    use sendbox_egress::connect_broker::{ConnectBrokerConfig, ConnectFrontend};
    use sendbox_egress::forwarding_resolver::{ForwardingResolver, ForwardingResolverConfig};
    use sendbox_egress::gateway::{Gateway, GatewayConfig, GatewayListeners};
    use sendbox_egress::linux::mark::MarkDialer;
    use sendbox_egress::policy::PolicyEngine;
    use tokio::net::UnixListener;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    let config: GatewayProcessConfiguration = read_root_config(&config_path)?;
    fs::remove_file(&config_path)
        .map_err(|error| GuestError::io("removing consumed gateway configuration", error))?;
    config
        .policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid gateway policy: {error}")))?;
    validate_control_token(&config.control_token)?;
    remove_socket_if_present(&config.control_socket)?;

    let (network_policy, connect_port, dns_port) = match config.role {
        GatewayRole::Workload => (
            &config.policy.network_policy,
            config.policy.connect_port,
            config.policy.dns_port,
        ),
        GatewayRole::Registry => {
            let registry = config.policy.registry.as_ref().ok_or_else(|| {
                GuestError::Runtime(
                    "trusted registry gateway requires registry egress policy".to_owned(),
                )
            })?;
            (
                &registry.upstream_network_policy,
                registry.trusted_upstream_port,
                None,
            )
        }
    };
    let dns_addr =
        dns_port.map(|port| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)));
    let connect_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, connect_port));
    let listeners = GatewayListeners::bind(dns_addr, connect_addr)
        .await
        .map_err(|error| GuestError::io("binding egress gateway listeners", error))?;
    let control_listener = UnixListener::bind(&config.control_socket)
        .map_err(|error| GuestError::io("binding gateway control socket", error))?;
    fs::set_permissions(&config.control_socket, fs::Permissions::from_mode(0o600))
        .map_err(|error| GuestError::io("setting gateway control socket mode", error))?;
    let (mut control, _) = timeout(GATEWAY_START_TIMEOUT, control_listener.accept())
        .await
        .map_err(|_| GuestError::Runtime("gateway control handshake timed out".to_owned()))?
        .map_err(|error| GuestError::io("accepting gateway control connection", error))?;
    expect_control(
        &mut control,
        ControlMessage::Hello {
            token: config.control_token.clone(),
        },
    )
    .await?;
    write_control(
        &mut control,
        &ControlMessage::Bound {
            token: config.control_token.clone(),
        },
    )
    .await?;
    expect_control(
        &mut control,
        ControlMessage::Start {
            token: config.control_token.clone(),
        },
    )
    .await?;

    let engine = Arc::new(
        PolicyEngine::compile(network_policy)
            .map_err(|error| GuestError::Runtime(format!("compile egress policy: {error}")))?,
    );
    let resolver = Arc::new(ForwardingResolver::new(
        ForwardingResolverConfig::new(config.upstream).with_socket_mark(config.policy.broker_mark),
    ));
    let gateway = Gateway::new(
        engine,
        resolver,
        Arc::new(MarkDialer::new(config.policy.broker_mark)),
        Arc::new(StderrJsonAuditSink),
        GatewayConfig {
            connect: ConnectBrokerConfig {
                frontend: ConnectFrontend::Socks5,
                ..ConnectBrokerConfig::default()
            },
            ..GatewayConfig::default()
        },
    );
    let cancellation = CancellationToken::new();
    let gateway_cancellation = cancellation.clone();
    let mut gateway_task =
        tokio::spawn(async move { gateway.serve(listeners, gateway_cancellation).await });
    tokio::task::yield_now().await;
    if gateway_task.is_finished() {
        return gateway_task
            .await
            .map_err(|error| GuestError::Runtime(format!("gateway task failed: {error}")))?
            .map_err(|error| GuestError::io("serving egress gateway", error));
    }
    write_control(
        &mut control,
        &ControlMessage::Serving {
            token: config.control_token,
        },
    )
    .await?;
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| GuestError::io("installing gateway SIGTERM handler", error))?;
    tokio::select! {
        result = &mut gateway_task => {
            result
                .map_err(|error| GuestError::Runtime(format!("gateway task failed: {error}")))?
                .map_err(|error| GuestError::io("serving egress gateway", error))
        }
        _ = terminate.recv() => {
            cancellation.cancel();
            gateway_task
                .await
                .map_err(|error| GuestError::Runtime(format!("gateway task failed: {error}")))?
                .map_err(|error| GuestError::io("stopping egress gateway", error))
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run_gateway(_config_path: PathBuf) -> Result<(), GuestError> {
    Err(GuestError::Runtime(
        "production egress gateway requires Linux".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
pub async fn run_registry_proxy(config_path: PathBuf) -> Result<(), GuestError> {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;

    use sendbox_exec::ResourceLimits;
    use sendbox_exec::platform::linux::{capabilities, rlimits, seccomp};
    use sendbox_policy::PackageEcosystem;
    use sendbox_registry::{
        FailClosedPackageProvenanceVerifier, NpmAdapter, RegistryProxy,
        RegistryProxyConfiguration as RuntimeRegistryConfiguration, ReqwestUpstreamClient,
    };
    use tokio::net::{TcpListener, UnixListener};
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    let config: RegistryProcessConfiguration = read_root_config(&config_path)?;
    fs::remove_file(&config_path)
        .map_err(|error| GuestError::io("removing consumed registry configuration", error))?;
    validate_control_token(&config.control_token)?;
    config
        .registry
        .policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid package policy: {error}")))?;
    let registry_policy = config
        .registry
        .policy
        .registries
        .iter()
        .find(|registry| registry.ecosystem == PackageEcosystem::Npm)
        .cloned()
        .ok_or_else(|| {
            GuestError::Runtime("registry proxy requires an npm registry policy".to_owned())
        })?;
    if config
        .registry
        .policy
        .registries
        .iter()
        .any(|registry| registry.ecosystem != PackageEcosystem::Npm)
    {
        return Err(GuestError::Runtime(
            "registry proxy received an unsupported non-npm registry".to_owned(),
        ));
    }
    let token = registry_policy
        .credential_secret
        .as_deref()
        .map(|reference| {
            config
                .registry
                .credentials
                .iter()
                .find(|credential| credential.secret_reference == reference)
                .map(|credential| credential.expose_to_registry_proxy().to_vec())
                .ok_or_else(|| {
                    GuestError::Runtime(
                        "registry credential is missing from authenticated bootstrap".to_owned(),
                    )
                })
        })
        .transpose()?;

    remove_socket_if_present(&config.control_socket)?;
    let listener = TcpListener::bind(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        config.registry.proxy_port,
    ))
    .await
    .map_err(|error| GuestError::io("binding registry proxy listener", error))?;
    let control_listener = UnixListener::bind(&config.control_socket)
        .map_err(|error| GuestError::io("binding registry proxy control socket", error))?;
    fs::set_permissions(&config.control_socket, fs::Permissions::from_mode(0o600))
        .map_err(|error| GuestError::io("setting registry control socket mode", error))?;

    rlimits::apply(&ResourceLimits {
        open_files: 256,
        processes: 64,
        core_bytes: 0,
        file_bytes: config.registry.policy.limits.max_download_bytes,
        address_space_bytes: 2 * 1024 * 1024 * 1024,
    })
    .map_err(|error| GuestError::Runtime(format!("applying registry resource limits: {error}")))?;
    capabilities::drop_to_user(config.registry.proxy_uid, config.registry.proxy_gid)
        .map_err(|error| GuestError::Runtime(format!("dropping registry privileges: {error}")))?;
    let denied_syscalls = ["execve", "execveat", "fork", "vfork"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    seccomp::install(seccomp::Profile::Command {
        additional_denied_syscalls: &denied_syscalls,
    })
    .map_err(|error| {
        GuestError::Runtime(format!("installing registry seccomp profile: {error}"))
    })?;

    let adapter = Arc::new(
        NpmAdapter::new(registry_policy, config.registry.policy.clone(), token)
            .map_err(|error| GuestError::Runtime(format!("configuring npm adapter: {error}")))?,
    );
    let socks_proxy = format!(
        "socks5h://127.0.0.1:{}",
        config.registry.trusted_upstream_port
    );
    let upstream = Arc::new(
        ReqwestUpstreamClient::new(
            &socks_proxy,
            Duration::from_secs(config.registry.policy.limits.request_timeout_secs),
        )
        .map_err(|error| GuestError::Runtime(format!("configuring registry upstream: {error}")))?,
    );
    let proxy = RegistryProxy::new(
        RuntimeRegistryConfiguration {
            base_url: format!("http://127.0.0.1:{}/", config.registry.proxy_port),
            cache_root: config.registry.cache_root.clone(),
            report_path: config.registry.report_path.clone(),
            session_id: config.session_id.to_string(),
            policy: config.registry.policy,
        },
        adapter,
        upstream,
        Arc::new(FailClosedPackageProvenanceVerifier),
    )
    .map_err(|error| GuestError::Runtime(format!("preparing registry proxy: {error}")))?;

    let (mut control, _) = timeout(GATEWAY_START_TIMEOUT, control_listener.accept())
        .await
        .map_err(|_| GuestError::Runtime("registry control handshake timed out".to_owned()))?
        .map_err(|error| GuestError::io("accepting registry control connection", error))?;
    expect_control(
        &mut control,
        ControlMessage::Hello {
            token: config.control_token.clone(),
        },
    )
    .await?;
    write_control(
        &mut control,
        &ControlMessage::Bound {
            token: config.control_token.clone(),
        },
    )
    .await?;
    expect_control(
        &mut control,
        ControlMessage::Start {
            token: config.control_token.clone(),
        },
    )
    .await?;

    let cancellation = CancellationToken::new();
    let serving_cancellation = cancellation.clone();
    let mut proxy_task =
        tokio::spawn(async move { proxy.serve(listener, serving_cancellation).await });
    tokio::task::yield_now().await;
    if proxy_task.is_finished() {
        return proxy_task
            .await
            .map_err(|error| GuestError::Runtime(format!("registry task failed: {error}")))?
            .map_err(|error| GuestError::Runtime(format!("serving registry proxy: {error}")));
    }
    write_control(
        &mut control,
        &ControlMessage::Serving {
            token: config.control_token,
        },
    )
    .await?;
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| GuestError::io("installing registry SIGTERM handler", error))?;
    tokio::select! {
        result = &mut proxy_task => {
            result
                .map_err(|error| GuestError::Runtime(format!("registry task failed: {error}")))?
                .map_err(|error| GuestError::Runtime(format!("serving registry proxy: {error}")))
        }
        _ = terminate.recv() => {
            cancellation.cancel();
            proxy_task
                .await
                .map_err(|error| GuestError::Runtime(format!("registry task failed: {error}")))?
                .map_err(|error| GuestError::Runtime(format!("stopping registry proxy: {error}")))
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run_registry_proxy(_config_path: PathBuf) -> Result<(), GuestError> {
    Err(GuestError::Runtime(
        "production registry proxy requires Linux".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn prepare_registry_directories(
    configuration: &RegistryProxyConfiguration,
) -> Result<(), GuestError> {
    let report_parent = configuration
        .report_path
        .parent()
        .ok_or_else(|| GuestError::Runtime("registry report path has no parent".to_owned()))?;
    for (name, path) in [
        ("package cache", configuration.cache_root.as_path()),
        ("package report", report_parent),
    ] {
        if !path.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(|error| GuestError::io(format!("creating {name} directory"), error))?;
        }
        crate::secure_fs::open_directory_no_symlinks(path)?;
        let metadata = path
            .symlink_metadata()
            .map_err(|error| GuestError::io(format!("inspecting {name} directory"), error))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(GuestError::Runtime(format!(
                "{} is not a trusted registry directory",
                path.display()
            )));
        }
        std::os::unix::fs::chown(
            path,
            Some(configuration.proxy_uid),
            Some(configuration.proxy_gid),
        )
        .map_err(|error| GuestError::io(format!("owning {name} directory"), error))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| GuestError::io(format!("securing {name} directory"), error))?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
impl ResolverPlan {
    #[cfg(target_os = "linux")]
    fn load(resolv_conf: &Path, state_path: &Path) -> Result<Self, GuestError> {
        Self::load_owned(resolv_conf, state_path, 0, 0)
    }

    #[cfg(test)]
    fn load_for_test(resolv_conf: &Path, state_path: &Path) -> Result<Self, GuestError> {
        let metadata = fs::metadata(resolv_conf)
            .map_err(|error| GuestError::io("inspecting resolver configuration", error))?;
        Self::load_owned(resolv_conf, state_path, metadata.uid(), metadata.gid())
    }

    fn load_owned(
        resolv_conf: &Path,
        state_path: &Path,
        required_uid: u32,
        required_gid: u32,
    ) -> Result<Self, GuestError> {
        let target = fs::canonicalize(resolv_conf)
            .map_err(|error| GuestError::io("resolving resolver configuration", error))?;
        let metadata = target
            .symlink_metadata()
            .map_err(|error| GuestError::io("inspecting resolver configuration", error))?;
        if !metadata.is_file()
            || metadata.uid() != required_uid
            || metadata.gid() != required_gid
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(GuestError::Runtime(
                "resolver configuration must resolve to a root-owned, non-writable regular file"
                    .to_owned(),
            ));
        }
        let current = read_bounded(
            &target,
            MAX_RESOLVER_BYTES,
            "reading resolver configuration",
        )?;
        let current_upstream = parse_upstream(&current)?;
        let state = if let Some(upstream) = current_upstream {
            let state = ResolverState {
                upstream,
                original: current.clone(),
            };
            persist_resolver_state(state_path, &state)?;
            state
        } else {
            read_resolver_state(state_path, required_uid, required_gid)?
        };
        validate_upstream(state.upstream)?;
        if state.original.len() > MAX_RESOLVER_BYTES {
            return Err(GuestError::Runtime(
                "persisted resolver configuration exceeds the size limit".to_owned(),
            ));
        }
        let replacement = rewrite_nameservers(&state.original)?;
        Ok(Self {
            target,
            mode: metadata.permissions().mode() & 0o777,
            original: state.original,
            replacement,
            upstream: state.upstream,
        })
    }

    fn install(&self) -> Result<(), GuestError> {
        replace_resolver_file(&self.target, &self.replacement, self.mode)
            .map_err(|error| GuestError::io("installing loopback resolver configuration", error))
    }

    fn restore(&self) -> Result<(), GuestError> {
        replace_resolver_file(&self.target, &self.original, self.mode)
            .map_err(|error| GuestError::io("restoring resolver configuration", error))
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_upstream(bytes: &[u8]) -> Result<Option<SocketAddr>, GuestError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| GuestError::Runtime("resolver configuration is not UTF-8".to_owned()))?;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(value) = fields.next() else {
            continue;
        };
        let Ok(ip) = value.parse::<IpAddr>() else {
            continue;
        };
        let upstream = SocketAddr::new(ip, 53);
        if validate_upstream(upstream).is_ok() {
            return Ok(Some(upstream));
        }
    }
    Ok(None)
}

#[cfg(any(target_os = "linux", test))]
fn validate_upstream(upstream: SocketAddr) -> Result<(), GuestError> {
    match classify(upstream.ip()) {
        AddressClass::Global | AddressClass::PrivateRfc1918 | AddressClass::UniqueLocalIpv6 => {
            Ok(())
        }
        class => Err(GuestError::Runtime(format!(
            "resolver upstream {} has unsupported address class {class:?}",
            upstream.ip()
        ))),
    }
}

#[cfg(any(target_os = "linux", test))]
fn rewrite_nameservers(bytes: &[u8]) -> Result<Vec<u8>, GuestError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| GuestError::Runtime("resolver configuration is not UTF-8".to_owned()))?;
    let mut output = String::new();
    let mut replaced = false;
    for line in text.lines() {
        if line
            .split_ascii_whitespace()
            .next()
            .is_some_and(|field| field == "nameserver")
        {
            if !replaced {
                output.push_str("nameserver 127.0.0.1\n");
                replaced = true;
            }
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if !replaced {
        output.insert_str(0, "nameserver 127.0.0.1\n");
    }
    Ok(output.into_bytes())
}

#[cfg(any(target_os = "linux", test))]
fn persist_resolver_state(path: &Path, state: &ResolverState) -> Result<(), GuestError> {
    let parent = path
        .parent()
        .ok_or_else(|| GuestError::Runtime("resolver state path has no parent".to_owned()))?;
    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| GuestError::io("creating resolver state directory", error))?;
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| GuestError::io("setting resolver state directory mode", error))?;
    let encoded = serde_json::to_vec(state)
        .map_err(|error| GuestError::Runtime(format!("encode resolver state: {error}")))?;
    atomic_replace(path, &encoded, 0o600)
        .map_err(|error| GuestError::io("persisting resolver state", error))
}

#[cfg(any(target_os = "linux", test))]
fn read_resolver_state(
    path: &Path,
    required_uid: u32,
    required_gid: u32,
) -> Result<ResolverState, GuestError> {
    validate_owned_file(path, 0o600, required_uid, required_gid)?;
    let bytes = read_bounded(path, MAX_RESOLVER_BYTES, "reading resolver state")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| GuestError::Runtime(format!("decode resolver state: {error}")))
}

#[cfg(any(target_os = "linux", test))]
fn read_bounded(path: &Path, limit: usize, context: &'static str) -> Result<Vec<u8>, GuestError> {
    let metadata = path
        .metadata()
        .map_err(|error| GuestError::io(context, error))?;
    if metadata.len() > limit as u64 {
        return Err(GuestError::Runtime(format!(
            "{} exceeds the {limit}-byte limit",
            path.display()
        )));
    }
    fs::read(path).map_err(|error| GuestError::io(context, error))
}

#[cfg(any(target_os = "linux", test))]
fn atomic_replace(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = parent.join(format!(".sendbox-resolver-{}-{suffix}", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(any(target_os = "linux", test))]
fn replace_resolver_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    match atomic_replace(path, bytes, mode) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::ResourceBusy => {
            overwrite_mounted_file(path, bytes)
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "linux", test))]
fn overwrite_mounted_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let descriptor = open(
        path,
        OFlags::WRONLY | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut file = fs::File::from(descriptor);
    file.write_all(bytes)?;
    file.sync_all()
}

fn write_root_config(path: &Path, value: &impl Serialize) -> Result<(), GuestError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| GuestError::Runtime(format!("encode egress configuration: {error}")))?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(path)
        .map_err(|error| GuestError::io("creating egress configuration", error))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| GuestError::io("writing egress configuration", error))
}

#[cfg(target_os = "linux")]
fn read_root_config<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, GuestError> {
    validate_root_file(path, 0o400)?;
    let bytes = read_bounded(path, MAX_RESOLVER_BYTES, "reading egress configuration")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| GuestError::Runtime(format!("decode egress configuration: {error}")))
}

#[cfg(target_os = "linux")]
fn validate_root_file(path: &Path, mode: u32) -> Result<(), GuestError> {
    validate_owned_file(path, mode, 0, 0)
}

#[cfg(any(target_os = "linux", test))]
fn validate_owned_file(
    path: &Path,
    mode: u32,
    required_uid: u32,
    required_gid: u32,
) -> Result<(), GuestError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| GuestError::io("inspecting root-owned file", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.gid() != required_gid
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(GuestError::Runtime(format!(
            "{} must be a trusted-owner {mode:04o} regular file",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_runtime_paths(
    config_path: &Path,
    readiness: &Path,
    workload_control: &Path,
    trusted_control: Option<&Path>,
    registry_control: Option<&Path>,
) -> Result<(), GuestError> {
    let parent = config_path
        .parent()
        .ok_or_else(|| GuestError::Runtime("egress configuration has no parent".to_owned()))?;
    if !config_path.is_absolute()
        || readiness.parent() != Some(parent)
        || workload_control.parent() != Some(parent)
        || readiness.file_name().and_then(|name| name.to_str()) != Some("egress-ready.sock")
        || workload_control.file_name().and_then(|name| name.to_str())
            != Some("egress-workload-control.sock")
        || trusted_control.is_some_and(|path| {
            path.parent() != Some(parent)
                || path.file_name().and_then(|name| name.to_str())
                    != Some("egress-trusted-control.sock")
        })
        || registry_control.is_some_and(|path| {
            path.parent() != Some(parent)
                || path.file_name().and_then(|name| name.to_str())
                    != Some("registry-proxy-control.sock")
        })
        || trusted_control.is_some() != registry_control.is_some()
    {
        return Err(GuestError::Runtime(
            "egress runtime paths must be fixed files beneath the authenticated session directory"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn random_token() -> Result<String, GuestError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| GuestError::Runtime(format!("generate gateway control token: {error}")))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(GuestError::Runtime(
            "gateway control token must not be all zero".to_owned(),
        ));
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(target_os = "linux")]
fn validate_control_token(token: &str) -> Result<(), GuestError> {
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GuestError::Runtime(
            "gateway control token is malformed".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn write_control(
    stream: &mut tokio::net::UnixStream,
    message: &ControlMessage,
) -> Result<(), GuestError> {
    use tokio::io::AsyncWriteExt;

    let mut encoded = serde_json::to_vec(message)
        .map_err(|error| GuestError::Runtime(format!("encode gateway control: {error}")))?;
    if encoded.len() >= MAX_CONTROL_BYTES {
        return Err(GuestError::Runtime(
            "gateway control frame exceeds its size limit".to_owned(),
        ));
    }
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .await
        .map_err(|error| GuestError::io("writing gateway control", error))
}

#[cfg(target_os = "linux")]
async fn read_control(stream: &mut tokio::net::UnixStream) -> Result<ControlMessage, GuestError> {
    use tokio::io::AsyncReadExt;

    let mut encoded = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|error| GuestError::io("reading gateway control", error))?;
        if read == 0 {
            return Err(GuestError::Runtime(
                "gateway control stream closed before a complete frame".to_owned(),
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        encoded.push(byte[0]);
        if encoded.len() >= MAX_CONTROL_BYTES {
            return Err(GuestError::Runtime(
                "gateway control frame exceeds its size limit".to_owned(),
            ));
        }
    }
    serde_json::from_slice(&encoded)
        .map_err(|error| GuestError::Runtime(format!("decode gateway control: {error}")))
}

#[cfg(target_os = "linux")]
async fn expect_control(
    stream: &mut tokio::net::UnixStream,
    expected: ControlMessage,
) -> Result<(), GuestError> {
    let actual = read_control(stream).await?;
    let matches = match (&actual, &expected) {
        (ControlMessage::Hello { token: actual }, ControlMessage::Hello { token: expected })
        | (ControlMessage::Bound { token: actual }, ControlMessage::Bound { token: expected })
        | (ControlMessage::Start { token: actual }, ControlMessage::Start { token: expected })
        | (
            ControlMessage::Serving { token: actual },
            ControlMessage::Serving { token: expected },
        ) => actual == expected,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(GuestError::Runtime(
            "gateway control handshake failed authentication or ordering".to_owned(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn remove_socket_if_present(path: &Path) -> Result<(), GuestError> {
    match path.symlink_metadata() {
        Ok(metadata)
            if metadata.file_type().is_socket() && metadata.uid() == 0 && metadata.gid() == 0 =>
        {
            fs::remove_file(path)
                .map_err(|error| GuestError::io("removing stale egress socket", error))
        }
        Ok(_) => Err(GuestError::Runtime(format!(
            "refusing to replace non-socket egress runtime path {}",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(GuestError::io("inspecting egress runtime socket", error)),
    }
}

#[cfg(target_os = "linux")]
fn require_root_cgroup_namespace() -> Result<(), GuestError> {
    let cgroup = fs::read_to_string("/proc/1/cgroup")
        .map_err(|error| GuestError::io("inspecting guest cgroup namespace", error))?;
    if cgroup
        .lines()
        .any(|line| line.split_once("::") == Some(("0", "/")))
    {
        Ok(())
    } else {
        Err(GuestError::Runtime(
            "egress enforcement requires the guest init cgroup namespace rooted at /".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_rewrite_preserves_non_nameserver_configuration() {
        let rewritten =
            rewrite_nameservers(b"search example.test\nnameserver 10.0.2.3\noptions ndots:1\n")
                .expect("rewrite");
        assert_eq!(
            rewritten,
            b"search example.test\nnameserver 127.0.0.1\noptions ndots:1\n"
        );
    }

    #[test]
    fn resolver_upstream_rejects_loopback_and_metadata() {
        assert_eq!(
            parse_upstream(b"nameserver 127.0.0.53\nnameserver 10.0.2.3\n")
                .expect("parse")
                .expect("upstream"),
            "10.0.2.3:53".parse::<SocketAddr>().unwrap()
        );
        assert!(
            parse_upstream(b"nameserver 169.254.169.254\n")
                .expect("parse")
                .is_none()
        );
    }

    #[test]
    fn persisted_original_recovers_a_crashed_loopback_rewrite() {
        let root = tempfile::tempdir().unwrap();
        let resolv = root.path().join("resolv.conf");
        let state = root.path().join("state/resolver.json");
        fs::write(&resolv, "nameserver 10.0.2.3\nsearch example.test\n").unwrap();
        fs::set_permissions(&resolv, fs::Permissions::from_mode(0o644)).unwrap();
        let first = ResolverPlan::load_for_test(&resolv, &state).expect("initial resolver");
        assert_eq!(first.upstream, "10.0.2.3:53".parse().unwrap());
        first.install().expect("install loopback");
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            "nameserver 127.0.0.1\nsearch example.test\n"
        );

        let recovered = ResolverPlan::load_for_test(&resolv, &state).expect("recover state");
        recovered.restore().expect("restore original");
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            "nameserver 10.0.2.3\nsearch example.test\n"
        );
    }
}
