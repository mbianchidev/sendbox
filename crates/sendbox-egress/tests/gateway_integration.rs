//! Portable, end-to-end integration tests for the shared egress gateway.
//!
//! These run on macOS and Linux alike: they exercise the userspace policy and
//! broker behavior (DNS validation, rebinding defense, exfiltration budgets,
//! QTYPE allowlist, connection exhaustion, CONNECT semantics) without any
//! kernel enforcement. The Linux kernel-enforcement scenarios (identity spoof,
//! socket mark, sibling process, direct-egress bypass, metadata kernel drop)
//! live in the gated `live_netns` suite.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use sendbox_egress::audit::{AuditEvent, CollectingAuditSink};
use sendbox_egress::connect_broker::{ConnectBrokerConfig, ConnectFrontend};
use sendbox_egress::connect_proto::{
    self, ConnectProtocol, ConnectRequest, ConnectStatus, ConnectTarget,
};
use sendbox_egress::dialer::DirectDialer;
use sendbox_egress::fixture_resolver::StaticResolver;
use sendbox_egress::gateway::{Gateway, GatewayConfig, GatewayListeners};
use sendbox_egress::policy::PolicyEngine;
use sendbox_egress::resolver::{ResolvedAddress, ResolvedChain};
use sendbox_egress::socks5;
use sendbox_policy::{Action, DnsPolicy, DnsQueryBudget, DnsRecordType, NetworkPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

struct RunningGateway {
    dns_addr: Option<SocketAddr>,
    connect_addr: SocketAddr,
    authorizations: Arc<sendbox_egress::authorization::AuthorizationCache>,
    audit: Arc<CollectingAuditSink>,
    cancel: CancellationToken,
}

impl Drop for RunningGateway {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn start_gateway(policy: NetworkPolicy, resolver: Arc<StaticResolver>) -> RunningGateway {
    start_gateway_with(policy, resolver, GatewayConfig::default()).await
}

async fn start_gateway_with(
    policy: NetworkPolicy,
    resolver: Arc<StaticResolver>,
    config: GatewayConfig,
) -> RunningGateway {
    let engine = Arc::new(PolicyEngine::compile(&policy).unwrap());
    let allow_dns = engine.allow_dns();
    let audit = Arc::new(CollectingAuditSink::new());
    let gateway = Gateway::new(
        engine,
        resolver,
        Arc::new(DirectDialer),
        Arc::clone(&audit) as Arc<_>,
        config,
    );
    let dns_listen = allow_dns.then(|| "127.0.0.1:0".parse().unwrap());
    let listeners = GatewayListeners::bind(dns_listen, "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let dns_addr = listeners.dns_addr();
    let connect_addr = listeners.connect_addr();
    let authorizations = gateway.authorizations();
    let cancel = CancellationToken::new();
    let serve_cancel = cancel.clone();
    tokio::spawn(async move {
        let _ = gateway.serve(listeners, serve_cancel).await;
    });
    RunningGateway {
        dns_addr,
        connect_addr,
        authorizations,
        audit,
        cancel,
    }
}

async fn dns_query(dns_addr: SocketAddr, name: &str, record_type: RecordType) -> Message {
    let mut query = Message::new(1234, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
    let bytes = query.to_vec().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&bytes, dns_addr).await.unwrap();
    let mut buf = [0u8; 1024];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("dns response")
        .unwrap();
    Message::from_vec(&buf[..len]).unwrap()
}

async fn connect(
    connect_addr: SocketAddr,
    target: ConnectTarget,
    port: u16,
    expected_ip: Option<IpAddr>,
) -> (ConnectStatus, TcpStream) {
    let request = ConnectRequest {
        protocol: ConnectProtocol::Tcp,
        port,
        target,
        expected_ip,
    };
    let mut stream = TcpStream::connect(connect_addr).await.unwrap();
    stream
        .write_all(&connect_proto::encode_request(&request))
        .await
        .unwrap();
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    (status_from_byte(status[1]), stream)
}

fn status_from_byte(byte: u8) -> ConnectStatus {
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
    .find(|s| *s as u8 == byte)
    .expect("known status byte")
}

async fn spawn_echo(addr: &str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let bound = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    bound
}

fn base_policy() -> NetworkPolicy {
    NetworkPolicy {
        default_action: Action::Deny,
        allowed_domains: vec!["allowed.test".to_owned(), "*.allowed.test".to_owned()],
        blocked_domains: vec!["evil.allowed.test".to_owned()],
        allow_dns: true,
        max_connections: Some(4),
        allowed_networks: vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()],
        blocked_networks: vec![],
        allowed_ports: vec![],
        dns: DnsPolicy {
            max_ttl_secs: 30,
            ..DnsPolicy::default()
        },
    }
}

fn chain_to(name: &str, ip: IpAddr) -> ResolvedChain {
    ResolvedChain {
        cname_chain: vec![],
        final_name: Name::from_str(&format!("{name}.")).unwrap(),
        addresses: vec![ResolvedAddress { ip, ttl_secs: 30 }],
    }
}

#[tokio::test]
async fn brokered_allow_round_trips_and_reuses_dns_authorization() {
    let echo = spawn_echo("127.0.0.1:0").await;
    let resolver = Arc::new(StaticResolver::new());
    resolver.set(
        Name::from_str("allowed.test.").unwrap(),
        chain_to("allowed.test", echo.ip()),
    );
    let gw = start_gateway(base_policy(), resolver).await;

    let response = dns_query(gw.dns_addr.unwrap(), "allowed.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(gw.authorizations.is_authorized("allowed.test", echo.ip()));

    let (status, mut stream) = connect(
        gw.connect_addr,
        ConnectTarget::Hostname("allowed.test".to_owned()),
        echo.port(),
        None,
    )
    .await;
    assert_eq!(status, ConnectStatus::Ok);
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn dns_rebinding_to_loopback_is_refused_by_the_broker() {
    // The name is domain-allowed, but it resolves to loopback (a restricted
    // class with no explicit grant for this fixture name's address). The DNS
    // broker must refuse the answer, so no authorization is recorded.
    let resolver = Arc::new(StaticResolver::new());
    resolver.set(
        Name::from_str("rebind.allowed.test.").unwrap(),
        chain_to(
            "rebind.allowed.test",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        ),
    );
    let gw = start_gateway(base_policy(), resolver).await;
    let response = dns_query(gw.dns_addr.unwrap(), "rebind.allowed.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    assert!(
        gw.authorizations
            .authorized_addresses("rebind.allowed.test")
            .is_empty()
    );
}

#[tokio::test]
async fn metadata_address_in_dns_answer_is_refused() {
    let resolver = Arc::new(StaticResolver::new());
    resolver.set(
        Name::from_str("meta.allowed.test.").unwrap(),
        chain_to(
            "meta.allowed.test",
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        ),
    );
    let gw = start_gateway(base_policy(), resolver).await;
    let response = dns_query(gw.dns_addr.unwrap(), "meta.allowed.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn direct_ip_connect_to_metadata_is_policy_denied() {
    let resolver = Arc::new(StaticResolver::new());
    let mut policy = base_policy();
    policy.default_action = Action::Allow;
    let gw = start_gateway(policy, resolver).await;
    let (status, _s) = connect(
        gw.connect_addr,
        ConnectTarget::Ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
        80,
        None,
    )
    .await;
    assert_eq!(status, ConnectStatus::PolicyDenied);
}

#[tokio::test]
async fn unsupported_qtype_is_notimp() {
    let resolver = Arc::new(StaticResolver::new());
    let gw = start_gateway(base_policy(), resolver).await;
    let response = dns_query(gw.dns_addr.unwrap(), "allowed.test.", RecordType::TXT).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
}

#[tokio::test]
async fn excessive_qname_is_refused() {
    let mut policy = base_policy();
    policy.dns.max_qname_octets = 30;
    let resolver = Arc::new(StaticResolver::new());
    let gw = start_gateway(policy, resolver).await;
    let long = format!("{}.allowed.test.", "a".repeat(40));
    let response = dns_query(gw.dns_addr.unwrap(), &long, RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    assert!(
        gw.audit
            .events()
            .iter()
            .any(|e| matches!(e, AuditEvent::DnsStructuralRejected { .. }))
    );
}

#[tokio::test]
async fn dns_exfiltration_labels_are_budget_limited() {
    // A tight dynamic-label budget: after two distinct leftmost labels under
    // the allowed wildcard, a third distinct one is refused as exfiltration.
    let mut policy = base_policy();
    policy.default_action = Action::Allow;
    policy.allowed_domains = vec!["*.tunnel.test".to_owned()];
    policy.dns.budget = DnsQueryBudget {
        window_secs: 60,
        max_queries: 100,
        max_query_octets: 100_000,
        max_unique_names: 100,
        max_dynamic_labels: 2,
    };
    let resolver = Arc::new(StaticResolver::new());
    for label in ["aaa", "bbb", "ccc"] {
        resolver.set(
            Name::from_str(&format!("{label}.tunnel.test.")).unwrap(),
            chain_to(
                &format!("{label}.tunnel.test"),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            ),
        );
    }
    let gw = start_gateway(policy, resolver).await;
    let r1 = dns_query(gw.dns_addr.unwrap(), "aaa.tunnel.test.", RecordType::A).await;
    assert_eq!(r1.metadata.response_code, ResponseCode::NoError);
    let r2 = dns_query(gw.dns_addr.unwrap(), "bbb.tunnel.test.", RecordType::A).await;
    assert_eq!(r2.metadata.response_code, ResponseCode::NoError);
    let r3 = dns_query(gw.dns_addr.unwrap(), "ccc.tunnel.test.", RecordType::A).await;
    assert_eq!(r3.metadata.response_code, ResponseCode::Refused);
    assert!(
        gw.audit
            .events()
            .iter()
            .any(|e| matches!(e, AuditEvent::DnsRateLimited { .. }))
    );
}

#[tokio::test]
async fn connection_exhaustion_reports_limit_exceeded() {
    let echo = spawn_echo("127.0.0.1:0").await;
    let resolver = Arc::new(StaticResolver::new());
    resolver.set(
        Name::from_str("allowed.test.").unwrap(),
        chain_to("allowed.test", echo.ip()),
    );
    let mut policy = base_policy();
    policy.max_connections = Some(1);
    let gw = start_gateway(policy, resolver).await;

    // First connection holds the only permit open (live echo session).
    let (status_a, _held) = connect(
        gw.connect_addr,
        ConnectTarget::Hostname("allowed.test".to_owned()),
        echo.port(),
        None,
    )
    .await;
    assert_eq!(status_a, ConnectStatus::Ok);

    let (status_b, _s) = connect(
        gw.connect_addr,
        ConnectTarget::Hostname("allowed.test".to_owned()),
        echo.port(),
        None,
    )
    .await;
    assert_eq!(status_b, ConnectStatus::LimitExceeded);
}

#[tokio::test]
async fn udp_connect_request_is_unsupported() {
    let resolver = Arc::new(StaticResolver::new());
    let gw = start_gateway(base_policy(), resolver).await;
    let request = ConnectRequest {
        protocol: ConnectProtocol::Udp,
        port: 443,
        target: ConnectTarget::Hostname("allowed.test".to_owned()),
        expected_ip: None,
    };
    let mut stream = TcpStream::connect(gw.connect_addr).await.unwrap();
    stream
        .write_all(&connect_proto::encode_request(&request))
        .await
        .unwrap();
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    assert_eq!(
        status_from_byte(status[1]),
        ConnectStatus::UnsupportedProtocol
    );
}

#[tokio::test]
async fn expected_ip_mismatch_is_rejected() {
    let echo = spawn_echo("127.0.0.1:0").await;
    let resolver = Arc::new(StaticResolver::new());
    resolver.set(
        Name::from_str("allowed.test.").unwrap(),
        chain_to("allowed.test", echo.ip()),
    );
    let gw = start_gateway(base_policy(), resolver).await;
    let (status, _s) = connect(
        gw.connect_addr,
        ConnectTarget::Hostname("allowed.test".to_owned()),
        echo.port(),
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))),
    )
    .await;
    assert_eq!(status, ConnectStatus::ExpectedIpMismatch);
}

#[tokio::test]
async fn blocked_subdomain_is_refused_even_under_allowed_wildcard() {
    let resolver = Arc::new(StaticResolver::new());
    resolver.set(
        Name::from_str("evil.allowed.test.").unwrap(),
        chain_to(
            "evil.allowed.test",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        ),
    );
    let gw = start_gateway(base_policy(), resolver).await;
    let response = dns_query(gw.dns_addr.unwrap(), "evil.allowed.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn qtype_allowlist_restriction_refuses_aaaa() {
    let mut policy = base_policy();
    policy.dns.allowed_record_types = vec![DnsRecordType::A];
    let resolver = Arc::new(StaticResolver::new());
    let gw = start_gateway(policy, resolver).await;
    let response = dns_query(gw.dns_addr.unwrap(), "allowed.test.", RecordType::AAAA).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
}

#[tokio::test]
async fn socks5_gateway_connect_round_trips_end_to_end() {
    // The same shared gateway, configured with the SOCKS5 front end, must serve
    // a standard SOCKS5 CONNECT through the identical policy/pin/dial path.
    let echo = spawn_echo("127.0.0.1:0").await;
    let resolver = Arc::new(StaticResolver::new());
    resolver.set(
        Name::from_str("allowed.test.").unwrap(),
        chain_to("allowed.test", echo.ip()),
    );
    let config = GatewayConfig {
        connect: ConnectBrokerConfig {
            frontend: ConnectFrontend::Socks5,
            ..ConnectBrokerConfig::default()
        },
        ..GatewayConfig::default()
    };
    let gw = start_gateway_with(base_policy(), resolver, config).await;

    let mut stream = TcpStream::connect(gw.connect_addr).await.unwrap();
    // No-auth negotiation.
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);
    // CONNECT allowed.test:<echo port>.
    let host = b"allowed.test";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    // Reply: VER, REP, RSV, ATYP(=1), 4-byte addr, 2-byte port.
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], socks5::Socks5Reply::Succeeded as u8);
    let mut bound = [0u8; 6];
    stream.read_exact(&mut bound).await.unwrap();
    // The tunnel is now raw bytes: prove an echo round-trip.
    stream.write_all(b"socks-ping").await.unwrap();
    let mut buf = [0u8; 10];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"socks-ping");
}

#[tokio::test]
async fn socks5_gateway_refuses_udp_associate() {
    let resolver = Arc::new(StaticResolver::new());
    let config = GatewayConfig {
        connect: ConnectBrokerConfig {
            frontend: ConnectFrontend::Socks5,
            ..ConnectBrokerConfig::default()
        },
        ..GatewayConfig::default()
    };
    let gw = start_gateway_with(base_policy(), resolver, config).await;
    let mut stream = TcpStream::connect(gw.connect_addr).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    // UDP ASSOCIATE (0x03) must be refused with Command not supported.
    let mut request = vec![0x05, 0x03, 0x00, 0x01];
    request.extend_from_slice(&Ipv4Addr::new(127, 0, 0, 1).octets());
    request.extend_from_slice(&53u16.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], socks5::Socks5Reply::CommandNotSupported as u8);
}
