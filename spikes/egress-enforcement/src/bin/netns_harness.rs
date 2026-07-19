//! CLI for the opt-in Linux network namespace harness.
//!
//! `probe` is always safe to run anywhere and never mutates any state; it
//! reports a precise, machine-readable verdict on whether this environment
//! can run the live suite (Linux, root, `ip`/`nft`/`setpriv` present).
//!
//! `raw-attempt` performs a single raw TCP connect or UDP send/verify from
//! the current process and reports the outcome as JSON. It is designed to
//! be invoked via `setpriv --reuid <uid> --regid <uid> --clear-groups
//! --no-new-privs -- netns-harness raw-attempt ...` so the observed outcome
//! reflects the firewall treatment of that specific UID, which is exactly
//! what the integration test in `tests/live_netns.rs` needs to assert
//! "agent cannot bypass the broker" and "broker cannot reach metadata"
//! scenarios.
//!
//! Namespace/veth/nft setup and teardown are deliberately *not* CLI
//! subcommands here: the integration test drives those directly through
//! `egress_enforcement_spike::netns_harness` library calls so it can keep
//! precise control over ordering and assertions within one process.

use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use egress_enforcement_spike::connect_proto::{
    self, ConnectProtocol, ConnectRequest, ConnectStatus, ConnectTarget,
};
use egress_enforcement_spike::netns_harness::CapabilityReport;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[command(
    about = "Opt-in Linux network-namespace enforcement harness for the egress-enforcement spike"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Reports whether this environment can run the live suite. Always
    /// safe: performs no mutation.
    Probe,
    /// Attempts a single raw TCP connect or UDP send/verify from the
    /// current process/UID, and reports the outcome as JSON.
    RawAttempt {
        #[arg(long, value_enum)]
        protocol: RawProtocol,
        #[arg(long)]
        target: SocketAddr,
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
    },
    /// Speaks the CONNECT protocol to a loopback egress broker, requesting
    /// either a hostname or a literal IP target, and reports the resulting
    /// status. If the broker replies `Ok`, sends and verifies a short echo
    /// payload through the tunnel as end-to-end proof.
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
    },
    /// Reads `/proc/self/status` and reports the process's `Cap*`
    /// (inheritable/permitted/effective/bounding/ambient) capability sets
    /// as JSON. Intended to be run via the same capability-clearing
    /// `setpriv` invocation used for the agent/broker so the live suite
    /// can assert every set is actually zeroed, not merely that the UID
    /// changed.
    CapsProbe,
    /// Genuine readiness probe for a running `egress-gateway`: attempts a
    /// real TCP connect to the CONNECT port and real DNS queries (UDP and
    /// TCP) against the DNS port, and reports which succeeded as JSON. A
    /// query is only considered to have succeeded if a syntactically
    /// valid DNS message was decoded back — proving the broker actually
    /// decoded/processed the request through the DNS crate, not merely
    /// that some bytes came back on the socket. This is designed to be
    /// polled in a bounded loop by the live-suite harness (from inside the
    /// target namespace, as the agent UID) instead of relying on a fixed
    /// sleep, and to be run once more, non-polled, to fail loudly if the
    /// gateway process itself has already exited.
    GatewayProbe {
        #[arg(long)]
        dns: SocketAddr,
        #[arg(long)]
        connect: SocketAddr,
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum RawProtocol {
    Tcp,
    Udp,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Probe => {
            let report = CapabilityReport::probe();
            println!("{}", report.to_json());
            ExitCode::SUCCESS
        }
        Commands::RawAttempt {
            protocol,
            target,
            timeout_ms,
        } => raw_attempt(protocol, target, timeout_ms),
        Commands::ConnectAttempt {
            broker,
            target,
            port,
            expected_ip,
            timeout_ms,
        } => {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(err) => {
                    println!("{{\"outcome\":\"local_error\",\"detail\":\"{err}\"}}");
                    return ExitCode::FAILURE;
                }
            };
            runtime.block_on(connect_attempt(
                broker,
                target,
                port,
                expected_ip,
                timeout_ms,
            ))
        }
        Commands::CapsProbe => caps_probe(),
        Commands::GatewayProbe {
            dns,
            connect,
            timeout_ms,
        } => {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(err) => {
                    println!("{{\"outcome\":\"local_error\",\"detail\":\"{err}\"}}");
                    return ExitCode::FAILURE;
                }
            };
            runtime.block_on(gateway_probe(dns, connect, timeout_ms))
        }
    }
}

/// Reports the process's `/proc/self/status` `Cap*` fields as JSON. Each
/// field is a 16-hex-digit capability bitmask; `"0000000000000000"` means
/// that set is fully empty. Falls back to reporting `"unavailable"` for any
/// field that cannot be read (e.g. non-Linux, or a `/proc` without the
/// expected format) rather than panicking, since this must stay usable as
/// an honest diagnostic even outside a fully-featured Linux environment.
fn caps_probe() -> ExitCode {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
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
        let payload = b"sendbox-spike-echo";
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
    match status {
        s if s == ConnectStatus::Ok as u8 => "ok",
        s if s == ConnectStatus::PolicyDenied as u8 => "policy_denied",
        s if s == ConnectStatus::ResolutionFailed as u8 => "resolution_failed",
        s if s == ConnectStatus::ConnectFailed as u8 => "connect_failed",
        s if s == ConnectStatus::LimitExceeded as u8 => "limit_exceeded",
        s if s == ConnectStatus::Malformed as u8 => "malformed",
        s if s == ConnectStatus::UnsupportedProtocol as u8 => "unsupported_protocol",
        s if s == ConnectStatus::ExpectedIpMismatch as u8 => "expected_ip_mismatch",
        s if s == ConnectStatus::Timeout as u8 => "timeout",
        _ => "unknown",
    }
}

fn raw_attempt(protocol: RawProtocol, target: SocketAddr, timeout_ms: u64) -> ExitCode {
    let timeout = Duration::from_millis(timeout_ms);
    let outcome = match protocol {
        RawProtocol::Tcp => match std::net::TcpStream::connect_timeout(&target, timeout) {
            Ok(_) => "connected",
            Err(_) => "blocked_or_unreachable",
        },
        RawProtocol::Udp => udp_probe(target, timeout),
    };
    println!("{{\"protocol\":\"{protocol:?}\",\"target\":\"{target}\",\"outcome\":\"{outcome}\"}}");
    ExitCode::SUCCESS
}

/// UDP is connectionless, so a blocked destination and an unblocked-but-
/// silent destination can look identical from the client alone (both time
/// out). This probe is therefore only meaningful as a *differential*
/// signal: the harness always runs it once against a target that is known
/// to respond when reachable (a fixture echo/broker port) as a positive
/// control, and once against the scenario target, then compares outcomes.
///
/// One important wrinkle: unlike a blocked TCP SYN (which is simply never
/// answered, indistinguishable from "nothing is listening"), a netfilter
/// `OUTPUT` chain drop for a UDP socket can surface *synchronously* as an
/// `EPERM`/`PermissionDenied` error return from `sendto()` itself, rather
/// than as a timeout. That is itself the "blocked" signal — not an
/// unrelated local failure — and must be classified as
/// `blocked_or_unreachable`, not `local_error`.
fn udp_probe(target: SocketAddr, timeout: Duration) -> &'static str {
    let bind_addr = match target.ip() {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let Ok(socket) = std::net::UdpSocket::bind(bind_addr) else {
        return "local_error";
    };
    if socket.set_read_timeout(Some(timeout)).is_err() {
        return "local_error";
    }
    if let Err(err) = socket.send_to(b"sendbox-spike-probe", target) {
        return classify_udp_send_error(&err);
    }
    let mut buf = [0u8; 64];
    match socket.recv_from(&mut buf) {
        Ok(_) => "connected",
        Err(_) => "blocked_or_unreachable",
    }
}

/// Classifies a `sendto()` failure as either the firewall-block signal
/// (`blocked_or_unreachable`, for `EPERM`/`PermissionDenied`) or a genuine
/// local failure unrelated to the destination (`local_error`, everything
/// else). Extracted as a pure function so the mapping itself is unit
/// tested without depending on a real kernel/netfilter interaction.
fn classify_udp_send_error(err: &std::io::Error) -> &'static str {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        "blocked_or_unreachable"
    } else {
        "local_error"
    }
}

/// Genuine gateway readiness probe. Reports `{"connect_ready":bool,
/// "dns_udp_ready":bool,"dns_tcp_ready":bool}`. Each `*_ready` flag is only
/// `true` if a real protocol round-trip succeeded (a TCP connect for
/// `connect_ready`; a real encoded DNS query sent and a syntactically
/// valid DNS message decoded back for the DNS flags) — never a bare
/// "port accepted bytes" heuristic. The queried name is deliberately
/// outside any real policy/fixture so this is usable as a generic
/// liveness check independent of whatever policy the gateway was started
/// with: any well-formed response (including a denial/NXDOMAIN) proves
/// the broker decoded the query and is alive.
async fn gateway_probe(dns: SocketAddr, connect: SocketAddr, timeout_ms: u64) -> ExitCode {
    let bound = Duration::from_millis(timeout_ms);

    let connect_ready = tokio::time::timeout(bound, TcpStream::connect(connect))
        .await
        .is_ok_and(|res| res.is_ok());

    let query_name = Name::from_str("sendbox-gateway-readiness-probe.invalid.")
        .expect("static readiness probe name must parse");
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
    fn permission_denied_is_classified_as_blocked() {
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(classify_udp_send_error(&err), "blocked_or_unreachable");
    }

    #[test]
    fn other_errors_are_classified_as_local_error() {
        for kind in [
            std::io::ErrorKind::AddrNotAvailable,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::Other,
            std::io::ErrorKind::NotFound,
        ] {
            let err = std::io::Error::from(kind);
            assert_eq!(
                classify_udp_send_error(&err),
                "local_error",
                "kind {kind:?} must not be misclassified as blocked"
            );
        }
    }

    use egress_enforcement_spike::authorization::AuthorizationCache;
    use egress_enforcement_spike::connect_broker::{ConnectBroker, ConnectBrokerConfig};
    use egress_enforcement_spike::dns_broker::{DnsBroker, DnsBrokerConfig};
    use egress_enforcement_spike::fixture_resolver::StaticResolver;
    use egress_enforcement_spike::policy::{Action, NetworkPolicy, PolicyEngine};
    use std::sync::Arc;
    use tokio::net::{TcpListener, UdpSocket};

    fn deny_all_policy() -> NetworkPolicy {
        NetworkPolicy {
            default_action: Action::Deny,
            allowed_domains: vec![],
            blocked_domains: vec![],
            allowed_networks: vec![],
            blocked_networks: vec![],
            allowed_ports: vec![],
            max_concurrent_connections: 4,
            max_dns_ttl_secs: 30,
        }
    }

    /// Proves `probe_dns_udp`/`probe_dns_tcp`/the CONNECT-readiness check
    /// against a real running broker pair (not a bare echo fixture): a
    /// deny-all policy still produces a syntactically valid DNS response
    /// (the probe's whole point is to detect protocol-level liveness
    /// regardless of policy outcome), and a real CONNECT listener accepts
    /// the readiness TCP connect.
    #[tokio::test]
    async fn gateway_probe_helpers_detect_a_real_running_broker_pair() {
        let policy = Arc::new(PolicyEngine::compile(&deny_all_policy()).unwrap());
        let resolver = Arc::new(StaticResolver::new());
        let cache = Arc::new(AuthorizationCache::new());

        let dns_broker = DnsBroker::new(
            Arc::clone(&policy),
            Arc::clone(&resolver),
            Arc::clone(&cache),
            DnsBrokerConfig::default(),
        );
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_udp_addr = udp_socket.local_addr().unwrap();
        tokio::spawn(Arc::clone(&dns_broker).run_udp(udp_socket));
        let tcp_listener = TcpListener::bind(dns_udp_addr).await.unwrap();
        tokio::spawn(Arc::clone(&dns_broker).run_tcp(tcp_listener));

        let connect_broker =
            ConnectBroker::new(policy, resolver, cache, ConnectBrokerConfig::default());
        let connect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connect_addr = connect_listener.local_addr().unwrap();
        tokio::spawn(connect_broker.run(connect_listener));

        let query_name = Name::from_str("sendbox-gateway-readiness-probe.invalid.").unwrap();
        let mut query = Message::new(4242, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(query_name, RecordType::A));
        let query_bytes = query.to_vec().unwrap();

        let bound = Duration::from_secs(2);
        assert!(
            probe_dns_udp(dns_udp_addr, &query_bytes, bound).await,
            "UDP DNS probe must detect the real running DNS broker"
        );
        assert!(
            probe_dns_tcp(dns_udp_addr, &query_bytes, bound).await,
            "TCP DNS probe must detect the real running DNS broker"
        );

        let connect_ready = tokio::time::timeout(bound, TcpStream::connect(connect_addr))
            .await
            .is_ok_and(|res| res.is_ok());
        assert!(
            connect_ready,
            "CONNECT readiness check must detect the real running CONNECT broker"
        );
    }

    /// Negative control: with nothing listening at all, every probe must
    /// report not-ready rather than panicking or hanging past its bound.
    #[tokio::test]
    async fn gateway_probe_helpers_report_not_ready_with_nothing_listening() {
        // Reserve and then immediately release a port so nothing is bound.
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = reserved.local_addr().unwrap();
        drop(reserved);

        let query_bytes = vec![0u8; 12]; // Not even a full valid message; irrelevant, nothing listens.
        let bound = Duration::from_millis(200);
        assert!(!probe_dns_udp(addr, &query_bytes, bound).await);
        assert!(!probe_dns_tcp(addr, &query_bytes, bound).await);
        let connect_ready = tokio::time::timeout(bound, TcpStream::connect(addr))
            .await
            .is_ok_and(|res| res.is_ok());
        assert!(!connect_ready);
    }
}
