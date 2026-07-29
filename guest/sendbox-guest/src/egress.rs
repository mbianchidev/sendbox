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
use std::str;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(any(target_os = "linux", test))]
use rustix::fs::{Mode, OFlags, open};
use sendbox_bootstrap::GatewayCredential;
#[cfg(any(target_os = "linux", test))]
use sendbox_egress::address::{AddressClass, classify};
use sendbox_egress::runtime::RuntimePolicyDocument;
use sendbox_mcp::runtime::RuntimePolicyDocument as McpRuntimePolicyDocument;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

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
    policy: RuntimePolicyDocument,
    mcp_policy: Option<McpRuntimePolicyDocument>,
    gateway_credentials: Vec<GatewayCredential>,
    readiness_socket: PathBuf,
    gateway_control_socket: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayProcessConfiguration {
    policy: RuntimePolicyDocument,
    mcp_policy: Option<McpRuntimePolicyDocument>,
    gateway_credentials: Vec<GatewayCredential>,
    upstream: SocketAddr,
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
    policy: RuntimePolicyDocument,
    mcp_policy: Option<McpRuntimePolicyDocument>,
    gateway_credentials: Vec<GatewayCredential>,
) -> Result<ServiceSpec, GuestError> {
    policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid egress policy: {error}")))?;
    let mcp_policy = mcp_policy.filter(|policy| policy.tool_policy.has_remote_servers());
    validate_mcp_gateway_configuration(&policy, mcp_policy.as_ref(), &gateway_credentials)?;
    let readiness_socket = session_dir.join("egress-ready.sock");
    let gateway_control_socket = session_dir.join("egress-gateway-control.sock");
    let config_path = session_dir.join("egress-supervisor.json");
    write_root_config(
        &config_path,
        &SupervisorProcessConfiguration {
            policy,
            mcp_policy,
            gateway_credentials,
            readiness_socket: readiness_socket.clone(),
            gateway_control_socket,
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
pub async fn run_supervisor(config_path: PathBuf) -> Result<(), GuestError> {
    use rustix::process::{Pid, Signal, kill_process};
    use sendbox_egress::linux::supervisor::{ArmedEgress, SupervisorConfig};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::process::{Child, Command};
    use tokio::time::{sleep, timeout};
    use tokio_util::sync::CancellationToken;

    let config: SupervisorProcessConfiguration = read_root_config(&config_path)?;
    fs::remove_file(&config_path)
        .map_err(|error| GuestError::io("removing consumed egress configuration", error))?;
    config
        .policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid egress policy: {error}")))?;
    validate_mcp_gateway_configuration(
        &config.policy,
        config.mcp_policy.as_ref(),
        &config.gateway_credentials,
    )?;
    validate_runtime_paths(
        &config_path,
        &config.readiness_socket,
        &config.gateway_control_socket,
    )?;
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
    let token = random_token()?;
    let gateway_config_path = config_path
        .parent()
        .expect("validated configuration has a parent")
        .join("egress-gateway.json");
    write_root_config(
        &gateway_config_path,
        &GatewayProcessConfiguration {
            policy: config.policy.clone(),
            mcp_policy: config.mcp_policy.clone(),
            gateway_credentials: config.gateway_credentials.clone(),
            upstream: resolver.upstream,
            control_socket: config.gateway_control_socket.clone(),
            control_token: token.clone(),
        },
    )?;
    remove_socket_if_present(&config.gateway_control_socket)?;
    let executable = std::env::current_exe()
        .map_err(|error| GuestError::io("resolving guest executable", error))?;
    let mut child = Command::new(executable)
        .arg("egress-gateway")
        .arg("--config")
        .arg(&gateway_config_path)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| GuestError::io("spawning egress gateway", error))?;

    let mut control = match connect_control(
        &config.gateway_control_socket,
        &mut child,
        GATEWAY_START_TIMEOUT,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            let _ = stop_gateway(&mut child, false).await;
            return Err(error);
        }
    };
    write_control(
        &mut control,
        &ControlMessage::Hello {
            token: token.clone(),
        },
    )
    .await?;
    expect_control(
        &mut control,
        ControlMessage::Bound {
            token: token.clone(),
        },
    )
    .await?;

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
    if let Some(port) = config.policy.mcp_gateway_port {
        supervisor_config = supervisor_config.with_mcp_gateway_port(port);
    }
    let mut armed = match ArmedEgress::arm(supervisor_config) {
        Ok(armed) => armed,
        Err(error) => {
            let _ = stop_gateway(&mut child, false).await;
            return Err(GuestError::Runtime(format!(
                "arming production egress: {error}"
            )));
        }
    };
    let child_pid = child
        .id()
        .ok_or_else(|| GuestError::Runtime("egress gateway has no process ID".to_owned()))?;
    if let Err(error) = armed.place_broker(child_pid) {
        let _ = stop_gateway(&mut child, false).await;
        let teardown = armed.teardown();
        return Err(GuestError::Runtime(format!(
            "placing egress gateway in broker cgroup: {error}; teardown: {teardown:?}"
        )));
    }
    let expected_parent = config
        .policy
        .execution_cgroup_parent(Path::new(sendbox_egress::runtime::DEFAULT_CGROUP_ROOT));
    if armed.execution_cgroup_parent() != expected_parent {
        let _ = stop_gateway(&mut child, false).await;
        let teardown = armed.teardown();
        return Err(GuestError::Runtime(format!(
            "armed execution cgroup parent drifted from signed policy; teardown: {teardown:?}"
        )));
    }

    async fn run_armed(
        config: &SupervisorProcessConfiguration,
        token: String,
        mut control: UnixStream,
        mut child: Child,
        mut armed: ArmedEgress,
        resolver: ResolverPlan,
    ) -> Result<(), GuestError> {
        let mut failures = Vec::new();
        let mut resolver_installed = false;
        let mut child_reaped = false;
        let readiness_cancel = CancellationToken::new();
        let mut readiness_task = None;

        let startup = async {
            write_control(
                &mut control,
                &ControlMessage::Start {
                    token: token.clone(),
                },
            )
            .await?;
            expect_control(
                &mut control,
                ControlMessage::Serving {
                    token: token.clone(),
                },
            )
            .await
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
            tokio::select! {
                status = child.wait() => {
                    child_reaped = true;
                    failures.push(match status {
                        Ok(status) => format!("egress gateway exited unexpectedly: {status}"),
                        Err(error) => format!("waiting for egress gateway: {error}"),
                    });
                }
                result = readiness => {
                    failures.push(match result {
                        Ok(Ok(())) => "egress readiness listener stopped unexpectedly".to_owned(),
                        Ok(Err(error)) => format!("egress readiness listener failed: {error}"),
                        Err(error) => format!("egress readiness task failed: {error}"),
                    });
                }
                _ = terminate.recv() => {}
            }
        }

        readiness_cancel.cancel();
        if let Some(task) = readiness_task {
            let _ = task.await;
        }
        if let Err(error) = remove_socket_if_present(&config.readiness_socket) {
            failures.push(error.to_string());
        }
        if let Err(error) = stop_gateway(&mut child, child_reaped).await {
            failures.push(error.to_string());
        }
        if resolver_installed && let Err(error) = resolver.restore() {
            failures.push(error.to_string());
        }
        let teardown = armed.teardown();
        failures.extend(
            teardown
                .into_iter()
                .map(|error| format!("tearing down egress: {error}")),
        );
        if let Err(error) = remove_socket_if_present(&config.gateway_control_socket) {
            failures.push(error.to_string());
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(GuestError::Runtime(failures.join("; ")))
        }
    }

    async fn connect_control(
        path: &Path,
        child: &mut Child,
        bound: Duration,
    ) -> Result<UnixStream, GuestError> {
        let deadline = tokio::time::Instant::now() + bound;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| GuestError::io("checking egress gateway startup", error))?
            {
                return Err(GuestError::Runtime(format!(
                    "egress gateway exited before binding listeners: {status}"
                )));
            }
            match UnixStream::connect(path).await {
                Ok(stream) => return Ok(stream),
                Err(error) if tokio::time::Instant::now() < deadline => {
                    let _ = error;
                    sleep(Duration::from_millis(10)).await;
                }
                Err(error) => {
                    return Err(GuestError::io(
                        "connecting egress gateway control socket",
                        error,
                    ));
                }
            }
        }
    }

    async fn stop_gateway(child: &mut Child, already_reaped: bool) -> Result<(), GuestError> {
        if already_reaped {
            return Ok(());
        }
        if let Some(raw_pid) = child.id().and_then(|value| Pid::from_raw(value as i32)) {
            match kill_process(raw_pid, Signal::TERM) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => {
                    return Err(GuestError::io(
                        "signalling egress gateway",
                        io::Error::from(error),
                    ));
                }
            }
        }
        match timeout(GATEWAY_STOP_TIMEOUT, child.wait()).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(GuestError::io("reaping egress gateway", error)),
            Err(_) => {
                child
                    .start_kill()
                    .map_err(|error| GuestError::io("killing egress gateway", error))?;
                child
                    .wait()
                    .await
                    .map(|_| ())
                    .map_err(|error| GuestError::io("reaping killed egress gateway", error))
            }
        }
    }

    fn bind_readiness(path: &Path) -> Result<UnixListener, GuestError> {
        remove_socket_if_present(path)?;
        let listener = UnixListener::bind(path)
            .map_err(|error| GuestError::io("binding egress readiness socket", error))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| GuestError::io("setting egress readiness socket mode", error))?;
        Ok(listener)
    }

    async fn readiness_loop(listener: UnixListener, cancel: CancellationToken) -> io::Result<()> {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                accepted = listener.accept() => {
                    let (_stream, _) = accepted?;
                }
            }
        }
    }

    run_armed(&config, token, control, child, armed, resolver).await
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
    use sendbox_egress::origin::OriginReservations;
    use sendbox_egress::policy::PolicyEngine;
    use sendbox_mcp::audit::UnixAuditSink;
    use sendbox_mcp::http_gateway::{
        ExactUpstreamClient, GatewayCredentialSet, HttpGateway, HttpGatewayError,
        OriginReservation, OriginResolution,
    };
    use sendbox_mcp::runtime::{HttpEndpoint, NATIVE_AUDIT_SOCKET_PATH};
    use tokio::net::{TcpListener, UnixListener};
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    let config: GatewayProcessConfiguration = read_root_config(&config_path)?;
    fs::remove_file(&config_path)
        .map_err(|error| GuestError::io("removing consumed gateway configuration", error))?;
    config
        .policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid gateway policy: {error}")))?;
    validate_mcp_gateway_configuration(
        &config.policy,
        config.mcp_policy.as_ref(),
        &config.gateway_credentials,
    )?;
    validate_control_token(&config.control_token)?;
    remove_socket_if_present(&config.control_socket)?;

    let dns_addr = config
        .policy
        .dns_port
        .map(|port| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)));
    let connect_addr = SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        config.policy.connect_port,
    ));
    let listeners = GatewayListeners::bind(dns_addr, connect_addr)
        .await
        .map_err(|error| GuestError::io("binding egress gateway listeners", error))?;
    let mcp_listener = match config.policy.mcp_gateway_port {
        Some(port) => Some(
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
                .await
                .map_err(|error| GuestError::io("binding HTTP MCP gateway listener", error))?,
        ),
        None => None,
    };
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
        PolicyEngine::compile(&config.policy.network_policy)
            .map_err(|error| GuestError::Runtime(format!("compile egress policy: {error}")))?,
    );
    let resolver = Arc::new(ForwardingResolver::new(
        ForwardingResolverConfig::new(config.upstream).with_socket_mark(config.policy.broker_mark),
    ));
    let reservations = Arc::new(
        OriginReservations::new(&config.policy.reserved_mcp_origins)
            .map_err(|error| GuestError::Runtime(format!("reserve MCP origins: {error}")))?,
    );
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
            origin_reservations: Arc::clone(&reservations),
            ..GatewayConfig::default()
        },
    );
    let http_gateway = match (config.mcp_policy, mcp_listener) {
        (Some(policy), Some(listener)) => {
            struct ReservationAdapter {
                reservations: Arc<OriginReservations>,
            }

            #[async_trait::async_trait]
            impl OriginReservation for ReservationAdapter {
                async fn reserve(
                    &self,
                    _server_id: &str,
                    endpoint: &HttpEndpoint,
                    resolution: &OriginResolution,
                ) -> Result<(), HttpGatewayError> {
                    self.reservations
                        .reserve_resolution(
                            &endpoint.host,
                            endpoint.port,
                            &resolution.aliases,
                            &resolution.addresses,
                        )
                        .map_err(|error| HttpGatewayError::Upstream(error.to_string()))
                }
            }

            let values = config
                .gateway_credentials
                .into_iter()
                .map(|credential| {
                    str::from_utf8(credential.expose_secret())
                        .map(|value| (credential.name.clone(), Zeroizing::new(value.to_owned())))
                        .map_err(|_| {
                            GuestError::Runtime(format!(
                                "gateway credential '{}' is not UTF-8",
                                credential.name
                            ))
                        })
                })
                .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
            let gateway_resolver = Arc::new(ForwardingResolver::new(
                ForwardingResolverConfig::new(config.upstream)
                    .with_socket_mark(config.policy.broker_mark),
            ));
            let upstream = Arc::new(ExactUpstreamClient::new(
                gateway_resolver,
                Arc::new(MarkDialer::new(config.policy.broker_mark)),
                Arc::new(ReservationAdapter {
                    reservations: Arc::clone(&reservations),
                }),
            ));
            let gateway = Arc::new(
                HttpGateway::new(
                    &policy,
                    GatewayCredentialSet::from_secret_values(values),
                    upstream,
                    Arc::new(UnixAuditSink::new(NATIVE_AUDIT_SOCKET_PATH)),
                )
                .map_err(|error| {
                    GuestError::Runtime(format!("configure HTTP MCP gateway: {error}"))
                })?,
            );
            Some((gateway, listener))
        }
        (None, None) => None,
        _ => {
            return Err(GuestError::Runtime(
                "HTTP MCP policy and listener configuration drifted".to_owned(),
            ));
        }
    };
    let cancellation = CancellationToken::new();
    let gateway_cancellation = cancellation.clone();
    let mut gateway_task =
        tokio::spawn(async move { gateway.serve(listeners, gateway_cancellation).await });
    let mut http_task = http_gateway.map(|(gateway, listener)| {
        let cancellation = cancellation.clone();
        tokio::spawn(async move { gateway.serve(listener, cancellation).await })
    });
    tokio::task::yield_now().await;
    if gateway_task.is_finished() {
        return gateway_task
            .await
            .map_err(|error| GuestError::Runtime(format!("gateway task failed: {error}")))?
            .map_err(|error| GuestError::io("serving egress gateway", error));
    }
    if http_task
        .as_ref()
        .is_some_and(tokio::task::JoinHandle::is_finished)
    {
        return http_task
            .take()
            .expect("HTTP task exists")
            .await
            .map_err(|error| GuestError::Runtime(format!("HTTP MCP task failed: {error}")))?
            .map_err(|error| GuestError::Runtime(format!("serving HTTP MCP gateway: {error}")));
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
    let result = tokio::select! {
        result = &mut gateway_task => {
            result
                .map_err(|error| GuestError::Runtime(format!("gateway task failed: {error}")))?
                .map_err(|error| GuestError::io("serving egress gateway", error))
        }
        result = async {
            match http_task.as_mut() {
                Some(task) => task.await,
                None => std::future::pending().await,
            }
        } => {
            result
                .map_err(|error| GuestError::Runtime(format!("HTTP MCP task failed: {error}")))?
                .map_err(|error| GuestError::Runtime(format!("serving HTTP MCP gateway: {error}")))
        }
        _ = terminate.recv() => {
            cancellation.cancel();
            let egress_result = gateway_task
                .await
                .map_err(|error| GuestError::Runtime(format!("gateway task failed: {error}")))?
                .map_err(|error| GuestError::io("stopping egress gateway", error));
            if let Some(task) = http_task {
                task.await
                    .map_err(|error| GuestError::Runtime(format!("HTTP MCP task failed: {error}")))?
                    .map_err(|error| {
                        GuestError::Runtime(format!("stopping HTTP MCP gateway: {error}"))
                    })?;
            }
            egress_result
        }
    };
    cancellation.cancel();
    result
}

#[cfg(not(target_os = "linux"))]
pub async fn run_gateway(_config_path: PathBuf) -> Result<(), GuestError> {
    Err(GuestError::Runtime(
        "production egress gateway requires Linux".to_owned(),
    ))
}

fn validate_mcp_gateway_configuration(
    egress: &RuntimePolicyDocument,
    mcp: Option<&McpRuntimePolicyDocument>,
    credentials: &[GatewayCredential],
) -> Result<(), GuestError> {
    let remote = mcp
        .map(|policy| {
            policy
                .validate()
                .map_err(|error| GuestError::Runtime(format!("invalid MCP policy: {error}")))?;
            policy
                .remote_servers()
                .map_err(|error| GuestError::Runtime(format!("invalid remote MCP policy: {error}")))
        })
        .transpose()?
        .unwrap_or_default();
    let remote_mcp_active = !remote.is_empty();
    let expected_origins = mcp
        .map(|policy| policy.tool_policy.remote_origins())
        .transpose()
        .map_err(|error| GuestError::Runtime(format!("invalid MCP origins: {error}")))?
        .unwrap_or_default();
    let configured_origins = egress
        .reserved_mcp_origins
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if configured_origins.len() != egress.reserved_mcp_origins.len()
        || configured_origins != expected_origins
        || egress.mcp_gateway_port.is_some() != remote_mcp_active
        || egress.deny_direct_ip != remote_mcp_active
    {
        return Err(GuestError::Runtime(
            "signed egress MCP reservations do not match the MCP policy".to_owned(),
        ));
    }
    let names = credentials
        .iter()
        .map(|credential| credential.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let expected_names = mcp
        .map(|policy| policy.tool_policy.gateway_secret_names())
        .unwrap_or_default();
    if names.len() != credentials.len() || names != expected_names {
        return Err(GuestError::Runtime(
            "gateway credentials do not exactly match the MCP policy".to_owned(),
        ));
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
    control: &Path,
) -> Result<(), GuestError> {
    let parent = config_path
        .parent()
        .ok_or_else(|| GuestError::Runtime("egress configuration has no parent".to_owned()))?;
    if !config_path.is_absolute()
        || readiness.parent() != Some(parent)
        || control.parent() != Some(parent)
        || readiness.file_name().and_then(|name| name.to_str()) != Some("egress-ready.sock")
        || control.file_name().and_then(|name| name.to_str()) != Some("egress-gateway-control.sock")
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
    use sendbox_core::SessionId;
    use sendbox_policy::{Action, McpHttpPolicy, McpServerPolicy, NetworkPolicy, ToolCallPolicy};

    fn mcp_gateway_policies() -> (RuntimePolicyDocument, McpRuntimePolicyDocument) {
        let tool_policy = ToolCallPolicy {
            servers: std::collections::BTreeMap::from([
                (
                    "alpha".to_owned(),
                    McpServerPolicy::StreamableHttp {
                        url: "https://alpha.example/mcp".to_owned(),
                        tools: Default::default(),
                        http: McpHttpPolicy::default(),
                    },
                ),
                (
                    "beta".to_owned(),
                    McpServerPolicy::StreamableHttp {
                        url: "https://beta.example/mcp".to_owned(),
                        tools: Default::default(),
                        http: McpHttpPolicy::default(),
                    },
                ),
            ]),
            ..ToolCallPolicy::default()
        };
        let egress = RuntimePolicyDocument::for_session_with_mcp(
            SessionId::from_bytes([42; 16]),
            NetworkPolicy {
                default_action: Action::Deny,
                allowed_domains: Vec::new(),
                blocked_domains: Vec::new(),
                allow_dns: true,
                max_connections: None,
                allowed_networks: Vec::new(),
                blocked_networks: Vec::new(),
                allowed_ports: Vec::new(),
                dns: Default::default(),
            },
            Some(&tool_policy),
        )
        .expect("egress policy");
        let mcp = McpRuntimePolicyDocument {
            schema_version: sendbox_mcp::runtime::RUNTIME_POLICY_SCHEMA_VERSION,
            workspace_root: PathBuf::from("/workspace"),
            workload_uid: 1000,
            workload_gid: 1000,
            tool_policy,
            audit_log_path: PathBuf::from(sendbox_mcp::runtime::DEFAULT_AUDIT_LOG_PATH),
            fixed_environment: Default::default(),
            inherited_environment_keys: Default::default(),
            observation: None,
        };
        (egress, mcp)
    }

    #[test]
    fn mcp_gateway_validation_accepts_reordered_reserved_origins() {
        let (mut egress, mcp) = mcp_gateway_policies();
        egress.reserved_mcp_origins.reverse();

        validate_mcp_gateway_configuration(&egress, Some(&mcp), &[])
            .expect("origin order must not affect policy equivalence");
    }

    #[test]
    fn mcp_gateway_validation_rejects_different_reserved_origins() {
        let (mut egress, mcp) = mcp_gateway_policies();
        egress.reserved_mcp_origins.pop();

        let error = validate_mcp_gateway_configuration(&egress, Some(&mcp), &[])
            .expect_err("origin drift must remain fail closed");
        assert!(
            error
                .to_string()
                .contains("signed egress MCP reservations do not match")
        );
    }

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
