//! Local/CI harness for the production egress crate.
//!
//! `probe` reports whether this host can enforce (Linux only) and is always
//! safe. `gateway` runs the shared DNS + CONNECT gateway from a policy file and
//! a fixture resolver, optionally placing itself into a cgroup and marking its
//! external sockets. The `raw-attempt` / `connect-attempt` / `caps-probe` /
//! `gateway-probe` subcommands are driven by the live network-namespace suite
//! (run as the agent or broker identity) to prove enforcement end to end.
//!
//! Every process invocation uses explicit argv; nothing is passed through a
//! shell.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use sendbox_egress::audit::StderrJsonAuditSink;
use sendbox_egress::connect_broker::{ConnectBrokerConfig, ConnectFrontend};
use sendbox_egress::connect_proto::{
    self, ConnectProtocol, ConnectRequest, ConnectStatus, ConnectTarget,
};
use sendbox_egress::dialer::{Dialer, DirectDialer};
use sendbox_egress::fixture_resolver::StaticResolver;
use sendbox_egress::forwarding_resolver::{ForwardingResolver, ForwardingResolverConfig};
use sendbox_egress::gateway::{Gateway, GatewayConfig, GatewayListeners};
use sendbox_egress::policy::PolicyEngine;
use sendbox_egress::resolver::{ResolvedAddress, ResolvedChain};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(about = "Production egress enforcement harness")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Report whether this host can enforce egress. Always safe; no mutation.
    Probe,
    /// Run the shared DNS + CONNECT gateway from a policy and fixture file.
    Gateway {
        /// Policy JSON file path (opened with O_NOFOLLOW before any transition).
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Fixture JSON file path (opened with O_NOFOLLOW before any transition).
        #[arg(long)]
        fixtures: Option<PathBuf>,
        /// Inherited descriptor number for the policy JSON (read via
        /// /proc/self/fd on Linux); preferred over a path in live mode.
        #[arg(long)]
        policy_fd: Option<i32>,
        /// Inherited descriptor number for the fixture JSON.
        #[arg(long)]
        fixtures_fd: Option<i32>,
        #[arg(long, default_value = "127.0.0.1:15053")]
        dns_listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:15080")]
        connect_listen: SocketAddr,
        /// Forward DNS to this upstream (real ForwardingResolver, SO_MARK
        /// applied) instead of the static fixture resolver.
        #[arg(long)]
        dns_upstream: Option<SocketAddr>,
        /// Write this process's pid to the given cgroup.procs path first.
        #[arg(long)]
        cgroup_procs: Option<PathBuf>,
        /// Set this SO_MARK on the broker's external (CONNECT) sockets.
        #[arg(long)]
        broker_mark: Option<u32>,
        /// Client-facing CONNECT front end.
        #[arg(long, value_enum, default_value_t = FrontendArg::Custom)]
        frontend: FrontendArg,
    },
    /// Attempt a single raw TCP connect or UDP send/verify, report JSON.
    RawAttempt {
        #[arg(long, value_enum)]
        protocol: RawProtocol,
        #[arg(long)]
        target: SocketAddr,
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
        #[arg(long)]
        cgroup_procs: Option<PathBuf>,
        /// Drop to this uid (all caps cleared, no_new_privs) before probing.
        #[arg(long)]
        drop_to_uid: Option<u32>,
        /// Set this SO_MARK on the probe socket (broker positive controls).
        #[arg(long)]
        socket_mark: Option<u32>,
    },
    /// Speak the CONNECT protocol to a broker and report the status.
    ConnectAttempt {
        #[arg(long)]
        broker: SocketAddr,
        #[arg(long)]
        target: String,
        #[arg(long)]
        port: u16,
        #[arg(long)]
        expected_ip: Option<IpAddr>,
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
        #[arg(long)]
        cgroup_procs: Option<PathBuf>,
        /// Drop to this uid (all caps cleared, no_new_privs) before probing.
        #[arg(long)]
        drop_to_uid: Option<u32>,
    },
    /// Report this process's capability sets from /proc/self/status as JSON.
    CapsProbe {
        #[arg(long)]
        cgroup_procs: Option<PathBuf>,
        /// Drop to this uid (all caps cleared, no_new_privs) before probing.
        #[arg(long)]
        drop_to_uid: Option<u32>,
    },
    /// Attempt to create a raw (AF_INET SOCK_RAW) socket; report created/denied.
    RawSocketProbe {
        #[arg(long)]
        cgroup_procs: Option<PathBuf>,
        /// Drop to this uid (all caps cleared, no_new_privs) before probing.
        #[arg(long)]
        drop_to_uid: Option<u32>,
    },
    /// Genuine readiness probe: real TCP connect + real DNS round trips.
    GatewayProbe {
        #[arg(long)]
        dns: SocketAddr,
        #[arg(long)]
        connect: SocketAddr,
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,
        #[arg(long)]
        cgroup_procs: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RawProtocol {
    Tcp,
    Udp,
}

/// Client-facing CONNECT front end selector.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum FrontendArg {
    Custom,
    Socks5,
}

impl FrontendArg {
    fn into_frontend(self) -> ConnectFrontend {
        match self {
            FrontendArg::Custom => ConnectFrontend::Custom,
            FrontendArg::Socks5 => ConnectFrontend::Socks5,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Probe => probe(),
        Commands::Gateway {
            policy,
            fixtures,
            policy_fd,
            fixtures_fd,
            dns_listen,
            connect_listen,
            dns_upstream,
            cgroup_procs,
            broker_mark,
            frontend,
        } => {
            // Capture config BEFORE any cgroup/namespace transition, via a
            // no-follow path open or an inherited descriptor, so a symlink swap
            // or predictable-path reopen after a transition cannot affect it.
            let policy_bytes = match load_config("policy", policy_fd, policy.as_deref()) {
                Ok(bytes) => bytes,
                Err(err) => {
                    eprintln!("{{\"error\":\"{err}\"}}");
                    return ExitCode::FAILURE;
                }
            };
            // The fixture file is only required when no DNS upstream is given.
            let fixtures_bytes =
                if dns_upstream.is_some() && fixtures.is_none() && fixtures_fd.is_none() {
                    Vec::new()
                } else {
                    match load_config("fixtures", fixtures_fd, fixtures.as_deref()) {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            eprintln!("{{\"error\":\"{err}\"}}");
                            return ExitCode::FAILURE;
                        }
                    }
                };
            join_cgroup_or_report(&cgroup_procs);
            run_gateway(
                &policy_bytes,
                &fixtures_bytes,
                dns_upstream,
                dns_listen,
                connect_listen,
                broker_mark,
                frontend.into_frontend(),
            )
        }
        Commands::RawAttempt {
            protocol,
            target,
            timeout_ms,
            cgroup_procs,
            drop_to_uid,
            socket_mark,
        } => {
            if let Some(code) = enter_identity(&cgroup_procs, drop_to_uid) {
                return code;
            }
            raw_attempt(protocol, target, timeout_ms, socket_mark)
        }
        Commands::ConnectAttempt {
            broker,
            target,
            port,
            expected_ip,
            timeout_ms,
            cgroup_procs,
            drop_to_uid,
        } => {
            if let Some(code) = enter_identity(&cgroup_procs, drop_to_uid) {
                return code;
            }
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            runtime.block_on(connect_attempt(
                broker,
                target,
                port,
                expected_ip,
                timeout_ms,
            ))
        }
        Commands::CapsProbe {
            cgroup_procs,
            drop_to_uid,
        } => {
            if let Some(code) = enter_identity(&cgroup_procs, drop_to_uid) {
                return code;
            }
            caps_probe()
        }
        Commands::RawSocketProbe {
            cgroup_procs,
            drop_to_uid,
        } => {
            if let Some(code) = enter_identity(&cgroup_procs, drop_to_uid) {
                return code;
            }
            raw_socket_probe()
        }
        Commands::GatewayProbe {
            dns,
            connect,
            timeout_ms,
            cgroup_procs,
        } => {
            join_cgroup_or_report(&cgroup_procs);
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            runtime.block_on(gateway_probe(dns, connect, timeout_ms))
        }
    }
}

/// Environment marker set on the re-executed (privilege-dropped) pass so it
/// does not re-place or re-drop.
const DROPPED_MARKER: &str = "SENDBOX_EGRESS_DROPPED";

/// Places this process into the target cgroup (as root) and, if a
/// `drop_to_uid` is requested, re-executes the identical argv under `setpriv`
/// with every capability set cleared and `no_new_privs` set. cgroup membership
/// is preserved across `execve`, so the dropped process stays in the agent
/// cgroup. Returns `Some(exit)` when the caller should exit (a re-exec was
/// attempted); `None` when the caller should proceed to run the probe.
fn enter_identity(cgroup_procs: &Option<PathBuf>, drop_to_uid: Option<u32>) -> Option<ExitCode> {
    if std::env::var_os(DROPPED_MARKER).is_some() {
        // Second pass: already placed and dropped in the first pass.
        return None;
    }
    join_cgroup_or_report(cgroup_procs);
    let uid = drop_to_uid?;
    Some(reexec_under_setpriv(uid))
}

/// Re-executes the current argv under `setpriv`, dropping to `uid` with all
/// capability sets cleared and `no_new_privs`. Only returns on error (a
/// successful `exec` replaces this process).
fn reexec_under_setpriv(uid: u32) -> ExitCode {
    use std::os::unix::process::CommandExt as _;
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!("{{\"error\":\"current_exe: {err}\"}}");
            return ExitCode::FAILURE;
        }
    };
    let uid = uid.to_string();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let error = std::process::Command::new("setpriv")
        .args([
            "--reuid",
            &uid,
            "--regid",
            &uid,
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "--",
        ])
        .arg(exe)
        .args(&args)
        .env(DROPPED_MARKER, "1")
        .exec();
    eprintln!("{{\"error\":\"setpriv exec failed: {error}\"}}");
    ExitCode::FAILURE
}

/// Attempts to create a raw (AF_INET SOCK_RAW) socket and reports whether it
/// was created or denied. An unprivileged process without CAP_NET_RAW is
/// denied, which is what keeps it from bypassing the IP-layer nftables filter.
#[cfg(target_os = "linux")]
fn raw_socket_probe() -> ExitCode {
    use socket2::{Domain, Protocol, Socket, Type};
    let outcome = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(_) => "created",
        Err(_) => "denied",
    };
    println!("{{\"raw_socket\":\"{outcome}\"}}");
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "linux"))]
fn raw_socket_probe() -> ExitCode {
    println!("{{\"raw_socket\":\"unsupported\"}}");
    ExitCode::SUCCESS
}

fn probe() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        use sendbox_egress::linux::nft::SystemNftRunner;
        use sendbox_egress::linux::preflight::Preflight;
        let report = Preflight::probe(&SystemNftRunner::default());
        println!("{}", report.to_json());
        ExitCode::SUCCESS
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!(
            "{{\"cgroup2_root\":null,\"cap_net_admin\":false,\"so_mark_settable\":false,\"nft_version\":null,\"nft_socket_cgroupv2\":false,\"platform\":\"non-linux\"}}"
        );
        ExitCode::SUCCESS
    }
}

/// Writes this process's pid to the given cgroup.procs path (self-placement),
/// printing any failure to stderr. A missing path is a no-op.
fn join_cgroup_or_report(cgroup_procs: &Option<PathBuf>) {
    if let Some(path) = cgroup_procs
        && let Err(err) = fs::write(path, format!("{}\n", std::process::id()))
    {
        eprintln!(
            "{{\"warning\":\"failed to join cgroup {}: {err}\"}}",
            path.display()
        );
    }
}

#[derive(Debug, Deserialize)]
struct FixtureAddress {
    ip: String,
    ttl_secs: u32,
}

#[derive(Debug, Deserialize)]
struct FixtureEntry {
    #[serde(default)]
    cname_chain: Vec<String>,
    final_name: String,
    addresses: Vec<FixtureAddress>,
}

fn parse_fixtures(bytes: &[u8]) -> Result<Arc<StaticResolver>, String> {
    let entries: HashMap<String, FixtureEntry> =
        serde_json::from_slice(bytes).map_err(|e| format!("parse fixtures: {e}"))?;
    let resolver = StaticResolver::new();
    for (queried, entry) in entries {
        let name = Name::from_str(&queried).map_err(|e| format!("bad name {queried}: {e}"))?;
        let final_name = Name::from_str(&entry.final_name)
            .map_err(|e| format!("bad final {}: {e}", entry.final_name))?;
        let mut cname_chain = Vec::new();
        for hop in &entry.cname_chain {
            cname_chain.push(Name::from_str(hop).map_err(|e| format!("bad hop {hop}: {e}"))?);
        }
        let mut addresses = Vec::new();
        for addr in &entry.addresses {
            let ip = addr
                .ip
                .parse()
                .map_err(|_| format!("bad ip {} for {queried}", addr.ip))?;
            addresses.push(ResolvedAddress {
                ip,
                ttl_secs: addr.ttl_secs,
            });
        }
        resolver.set(
            name,
            ResolvedChain {
                cname_chain,
                final_name,
                addresses,
            },
        );
    }
    Ok(Arc::new(resolver))
}

/// Loads a config file's bytes, preferring an inherited descriptor (`fd`) over
/// a filesystem path. A path open uses `O_NOFOLLOW` on the final component so a
/// symlinked config is refused; the bytes are read fully into memory so no
/// predictable path is reopened after a later cgroup/namespace transition.
fn load_config(kind: &str, fd: Option<i32>, path: Option<&Path>) -> Result<Vec<u8>, String> {
    if let Some(fd) = fd {
        return read_config_fd(fd).map_err(|e| format!("read {kind} fd {fd}: {e}"));
    }
    match path {
        Some(path) => {
            read_config_no_follow(path).map_err(|e| format!("read {kind} {}: {e}", path.display()))
        }
        None => Err(format!("either --{kind} or --{kind}-fd is required")),
    }
}

/// Opens `path` with `O_NOFOLLOW` (final component) and reads it fully.
fn read_config_no_follow(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Reads an inherited descriptor. On Linux this re-derives a handle to the exact
/// open file via `/proc/self/fd/N` (fd-backed, not an attacker-influenced path).
/// On other platforms inherited-fd config is unsupported.
#[cfg(target_os = "linux")]
fn read_config_fd(fd: i32) -> std::io::Result<Vec<u8>> {
    let mut file = fs::File::open(format!("/proc/self/fd/{fd}"))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(not(target_os = "linux"))]
fn read_config_fd(_fd: i32) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "inherited-fd config requires Linux",
    ))
}

fn run_gateway(
    policy_bytes: &[u8],
    fixtures_bytes: &[u8],
    dns_upstream: Option<SocketAddr>,
    dns_listen: SocketAddr,
    connect_listen: SocketAddr,
    broker_mark: Option<u32>,
    frontend: ConnectFrontend,
) -> ExitCode {
    let policy: sendbox_policy::NetworkPolicy = match serde_json::from_slice(policy_bytes) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("{{\"error\":\"parse policy: {err}\"}}");
            return ExitCode::FAILURE;
        }
    };
    let engine = match PolicyEngine::compile(&policy) {
        Ok(engine) => Arc::new(engine),
        Err(err) => {
            eprintln!("{{\"error\":\"compile policy: {err}\"}}");
            return ExitCode::FAILURE;
        }
    };
    let dialer = match select_dialer(broker_mark) {
        Ok(dialer) => dialer,
        Err(err) => {
            eprintln!("{{\"error\":\"{err}\"}}");
            return ExitCode::FAILURE;
        }
    };

    // A real forwarding resolver (with the broker SO_MARK) when an upstream is
    // configured, otherwise the static fixture resolver.
    match dns_upstream {
        Some(upstream) => {
            let mut config = ForwardingResolverConfig::new(upstream);
            if let Some(mark) = broker_mark {
                config = config.with_socket_mark(mark);
            }
            let resolver = Arc::new(ForwardingResolver::new(config));
            serve_gateway(
                engine,
                resolver,
                dialer,
                dns_listen,
                connect_listen,
                frontend,
            )
        }
        None => match parse_fixtures(fixtures_bytes) {
            Ok(resolver) => serve_gateway(
                engine,
                resolver,
                dialer,
                dns_listen,
                connect_listen,
                frontend,
            ),
            Err(err) => {
                eprintln!("{{\"error\":\"{err}\"}}");
                ExitCode::FAILURE
            }
        },
    }
}

fn serve_gateway<R: sendbox_egress::resolver::UpstreamResolver + 'static>(
    engine: Arc<PolicyEngine>,
    resolver: Arc<R>,
    dialer: Arc<dyn Dialer>,
    dns_listen: SocketAddr,
    connect_listen: SocketAddr,
    frontend: ConnectFrontend,
) -> ExitCode {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(async move {
        let dns_addr = engine.allow_dns().then_some(dns_listen);
        let listeners = match GatewayListeners::bind(dns_addr, connect_listen).await {
            Ok(listeners) => listeners,
            Err(err) => {
                eprintln!("{{\"error\":\"bind: {err}\"}}");
                return ExitCode::FAILURE;
            }
        };
        println!(
            "{{\"status\":\"listening\",\"dns\":{},\"connect\":\"{}\"}}",
            listeners
                .dns_addr()
                .map(|a| format!("\"{a}\""))
                .unwrap_or_else(|| "null".to_owned()),
            listeners.connect_addr()
        );
        let gateway_config = GatewayConfig {
            connect: ConnectBrokerConfig {
                frontend,
                ..ConnectBrokerConfig::default()
            },
            ..GatewayConfig::default()
        };
        let gateway = Gateway::new(
            engine,
            resolver,
            dialer,
            Arc::new(StderrJsonAuditSink),
            gateway_config,
        );
        let cancel = CancellationToken::new();
        match gateway.serve(listeners, cancel).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{{\"error\":\"serve: {err}\"}}");
                ExitCode::FAILURE
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn select_dialer(broker_mark: Option<u32>) -> Result<Arc<dyn Dialer>, String> {
    match broker_mark {
        Some(mark) => Ok(Arc::new(sendbox_egress::linux::mark::MarkDialer::new(mark))),
        None => Ok(Arc::new(DirectDialer)),
    }
}

#[cfg(not(target_os = "linux"))]
fn select_dialer(broker_mark: Option<u32>) -> Result<Arc<dyn Dialer>, String> {
    match broker_mark {
        Some(_) => Err("SO_MARK broker dialer requires Linux".to_owned()),
        None => Ok(Arc::new(DirectDialer)),
    }
}

fn raw_attempt(
    protocol: RawProtocol,
    target: SocketAddr,
    timeout_ms: u64,
    socket_mark: Option<u32>,
) -> ExitCode {
    let timeout = Duration::from_millis(timeout_ms);
    let outcome = match protocol {
        RawProtocol::Tcp => tcp_probe(target, timeout, socket_mark),
        RawProtocol::Udp => udp_probe(target, timeout, socket_mark),
    };
    println!("{{\"protocol\":\"{protocol:?}\",\"target\":\"{target}\",\"outcome\":\"{outcome}\"}}");
    ExitCode::SUCCESS
}

fn tcp_probe(target: SocketAddr, timeout: Duration, socket_mark: Option<u32>) -> &'static str {
    match socket_mark {
        Some(mark) => tcp_probe_marked(target, timeout, mark),
        None => match std::net::TcpStream::connect_timeout(&target, timeout) {
            Ok(_) => "connected",
            Err(_) => "blocked_or_unreachable",
        },
    }
}

fn udp_probe(target: SocketAddr, timeout: Duration, socket_mark: Option<u32>) -> &'static str {
    let socket = match socket_mark {
        Some(mark) => match bind_udp_marked(&target, mark) {
            Ok(socket) => socket,
            Err(kind) => return kind,
        },
        None => {
            let bind_addr = match target.ip() {
                IpAddr::V4(_) => "0.0.0.0:0",
                IpAddr::V6(_) => "[::]:0",
            };
            match std::net::UdpSocket::bind(bind_addr) {
                Ok(socket) => socket,
                Err(_) => return "local_error",
            }
        }
    };
    if socket.set_read_timeout(Some(timeout)).is_err() {
        return "local_error";
    }
    if let Err(err) = socket.send_to(b"sendbox-egress-probe", target) {
        return classify_udp_send_error(&err);
    }
    let mut buf = [0u8; 64];
    match socket.recv_from(&mut buf) {
        Ok(_) => "connected",
        Err(_) => "blocked_or_unreachable",
    }
}

#[cfg(target_os = "linux")]
fn tcp_probe_marked(target: SocketAddr, timeout: Duration, mark: u32) -> &'static str {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = match target {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
        Ok(socket) => socket,
        Err(_) => return "local_error",
    };
    if socket.set_mark(mark).is_err() {
        return "local_error";
    }
    match socket.connect_timeout(&target.into(), timeout) {
        Ok(()) => "connected",
        Err(_) => "blocked_or_unreachable",
    }
}

#[cfg(not(target_os = "linux"))]
fn tcp_probe_marked(_target: SocketAddr, _timeout: Duration, _mark: u32) -> &'static str {
    "local_error"
}

#[cfg(target_os = "linux")]
fn bind_udp_marked(target: &SocketAddr, mark: u32) -> Result<std::net::UdpSocket, &'static str> {
    use socket2::{Domain, Protocol, Socket, Type};
    let (domain, bind): (Domain, SocketAddr) = match target {
        SocketAddr::V4(_) => (Domain::IPV4, "0.0.0.0:0".parse().unwrap()),
        SocketAddr::V6(_) => (Domain::IPV6, "[::]:0".parse().unwrap()),
    };
    let socket =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|_| "local_error")?;
    socket.set_mark(mark).map_err(|_| "local_error")?;
    socket.bind(&bind.into()).map_err(|_| "local_error")?;
    Ok(socket.into())
}

#[cfg(not(target_os = "linux"))]
fn bind_udp_marked(_target: &SocketAddr, _mark: u32) -> Result<std::net::UdpSocket, &'static str> {
    Err("local_error")
}

fn classify_udp_send_error(err: &std::io::Error) -> &'static str {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        "blocked_or_unreachable"
    } else {
        "local_error"
    }
}

async fn connect_attempt(
    broker: SocketAddr,
    target: String,
    port: u16,
    expected_ip: Option<IpAddr>,
    timeout_ms: u64,
) -> ExitCode {
    let deadline = Duration::from_millis(timeout_ms);
    let connect_target = target
        .parse::<IpAddr>()
        .map(ConnectTarget::Ip)
        .unwrap_or_else(|_| ConnectTarget::Hostname(target.clone()));
    let request = ConnectRequest {
        protocol: ConnectProtocol::Tcp,
        port,
        target: connect_target,
        expected_ip,
    };
    let mut stream = match tokio::time::timeout(deadline, TcpStream::connect(broker)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            println!("{{\"outcome\":\"broker_unreachable\"}}");
            return ExitCode::FAILURE;
        }
    };
    if tokio::time::timeout(
        deadline,
        stream.write_all(&connect_proto::encode_request(&request)),
    )
    .await
    .is_err()
    {
        println!("{{\"outcome\":\"write_timeout\"}}");
        return ExitCode::FAILURE;
    }
    let mut status_bytes = [0u8; 2];
    if tokio::time::timeout(deadline, stream.read_exact(&mut status_bytes))
        .await
        .is_err()
    {
        println!("{{\"outcome\":\"read_timeout\"}}");
        return ExitCode::FAILURE;
    }
    let status = status_bytes[1];
    let status_name = status_name(status);
    if status == ConnectStatus::Ok as u8 {
        let payload = b"sendbox-egress-echo";
        let echoed = tokio::time::timeout(deadline, async {
            stream.write_all(payload).await?;
            let mut buf = vec![0u8; payload.len()];
            stream.read_exact(&mut buf).await?;
            Ok::<_, std::io::Error>(buf)
        })
        .await;
        let echo_ok = matches!(echoed, Ok(Ok(buf)) if buf == payload);
        println!("{{\"outcome\":\"ok\",\"status\":\"{status_name}\",\"echo_verified\":{echo_ok}}}");
        ExitCode::SUCCESS
    } else {
        println!("{{\"outcome\":\"denied\",\"status\":\"{status_name}\"}}");
        ExitCode::SUCCESS
    }
}

fn status_name(status: u8) -> &'static str {
    [
        ConnectStatus::Ok,
        ConnectStatus::PolicyDenied,
        ConnectStatus::ResolutionFailed,
        ConnectStatus::ConnectFailed,
        ConnectStatus::LimitExceeded,
        ConnectStatus::Malformed,
        ConnectStatus::UnsupportedProtocol,
        ConnectStatus::ExpectedIpMismatch,
        ConnectStatus::Timeout,
    ]
    .into_iter()
    .find(|s| *s as u8 == status)
    .map_or("unknown", ConnectStatus::as_str)
}

fn caps_probe() -> ExitCode {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let fields = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];
    let mut parts = Vec::with_capacity(fields.len());
    for field in fields {
        let value = status
            .lines()
            .find(|line| line.starts_with(field))
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("unavailable");
        parts.push(format!("\"{field}\":\"{value}\""));
    }
    println!("{{{}}}", parts.join(","));
    ExitCode::SUCCESS
}

async fn gateway_probe(dns: SocketAddr, connect: SocketAddr, timeout_ms: u64) -> ExitCode {
    let bound = Duration::from_millis(timeout_ms);
    let connect_ready = tokio::time::timeout(bound, TcpStream::connect(connect))
        .await
        .is_ok_and(|res| res.is_ok());

    let query_name =
        Name::from_str("sendbox-egress-readiness-probe.invalid.").expect("static probe name");
    let mut query = Message::new(4242, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(query_name, RecordType::A));
    let query_bytes = query.to_vec().unwrap_or_default();

    let dns_udp_ready = probe_dns_udp(dns, &query_bytes, bound).await;
    let dns_tcp_ready = probe_dns_tcp(dns, &query_bytes, bound).await;

    println!(
        "{{\"connect_ready\":{connect_ready},\"dns_udp_ready\":{dns_udp_ready},\"dns_tcp_ready\":{dns_tcp_ready}}}"
    );
    ExitCode::SUCCESS
}

async fn probe_dns_udp(target: SocketAddr, query_bytes: &[u8], bound: Duration) -> bool {
    let bind_addr = match target.ip() {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let Ok(socket) = tokio::net::UdpSocket::bind(bind_addr).await else {
        return false;
    };
    if tokio::time::timeout(bound, socket.send_to(query_bytes, target))
        .await
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 512];
    let Ok(Ok((len, _from))) = tokio::time::timeout(bound, socket.recv_from(&mut buf)).await else {
        return false;
    };
    Message::from_vec(&buf[..len]).is_ok()
}

async fn probe_dns_tcp(target: SocketAddr, query_bytes: &[u8], bound: Duration) -> bool {
    let Ok(Ok(mut stream)) = tokio::time::timeout(bound, TcpStream::connect(target)).await else {
        return false;
    };
    let len_prefix = match u16::try_from(query_bytes.len()) {
        Ok(len) => len.to_be_bytes(),
        Err(_) => return false,
    };
    if tokio::time::timeout(bound, async {
        stream.write_all(&len_prefix).await?;
        stream.write_all(query_bytes).await
    })
    .await
    .is_err()
    {
        return false;
    }
    let mut response_len_buf = [0u8; 2];
    if tokio::time::timeout(bound, stream.read_exact(&mut response_len_buf))
        .await
        .is_err()
    {
        return false;
    }
    let response_len = u16::from_be_bytes(response_len_buf) as usize;
    let mut response_buf = vec![0u8; response_len];
    if tokio::time::timeout(bound, stream.read_exact(&mut response_buf))
        .await
        .is_err()
    {
        return false;
    }
    Message::from_vec(&response_buf).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_follow_reads_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        fs::write(&path, b"{\"ok\":true}").unwrap();
        let bytes = read_config_no_follow(&path).unwrap();
        assert_eq!(bytes, b"{\"ok\":true}");
    }

    #[test]
    fn no_follow_refuses_a_symlinked_config() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        fs::write(&real, b"{\"secret\":true}").unwrap();
        let link = dir.path().join("link.json");
        symlink(&real, &link).unwrap();
        // O_NOFOLLOW must refuse to open a symlinked final component.
        let result = read_config_no_follow(&link);
        assert!(result.is_err(), "symlinked config must be refused");
    }

    #[test]
    fn load_config_requires_a_path_or_fd() {
        assert!(load_config("policy", None, None).is_err());
    }
}
