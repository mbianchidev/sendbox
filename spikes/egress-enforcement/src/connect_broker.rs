//! Egress CONNECT broker: accepts local client connections speaking the
//! bounded CONNECT protocol, enforces policy and DNS authorization, dials
//! the exact validated destination `SocketAddr` directly (never re-resolving
//! a hostname through the OS resolver), and copies bytes bidirectionally.
//!
//! Security-relevant properties:
//! - A client-declared hostname is resolved by the broker itself, through
//!   the same policy-aware resolver/authorization path the DNS broker uses;
//!   the client's optional `expected_ip` is only a consistency check and a
//!   mismatch is always rejected, never silently substituted.
//! - Direct-IP requests are governed exclusively by IP/address-class policy
//!   (`PolicyEngine::decide_direct_ip`), never by domain rules.
//! - UDP/QUIC is always denied; this broker only ever proxies TCP.
//! - A bounded semaphore enforces `max_concurrent_connections` before any
//!   dial is attempted.
//! - The handshake read is wrapped in a timeout to defend against
//!   slowloris-style peers.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::Name;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::authorization::AuthorizationCache;
use crate::connect_proto::{self, ConnectProtocol, ConnectStatus, ConnectTarget};
use crate::domain;
use crate::policy::{PolicyEngine, Protocol};
use crate::resolver::UpstreamResolver;

/// Bound on writing the `LimitExceeded` rejection status to a saturated
/// client. Deliberately short and applied inline in the accept loop (never
/// spawned) so a connection flood can, at worst, cost the accept loop this
/// much time per non-reading malicious peer — never unbounded task growth.
const REJECTION_WRITE_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct ConnectBrokerConfig {
    /// Overall bound on reading and parsing one request handshake.
    pub handshake_timeout: Duration,
    /// Bound on dialing the upstream destination.
    pub connect_timeout: Duration,
    /// Bound on a single fresh upstream resolution.
    pub resolve_timeout: Duration,
    /// Upper bound on the lifetime of one proxied session (from the moment
    /// the tunnel opens). Bounds resource hold time even if a peer never
    /// closes its side, independent of the half-close fix below.
    pub session_timeout: Duration,
}

impl Default for ConnectBrokerConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            resolve_timeout: Duration::from_secs(5),
            session_timeout: Duration::from_secs(300),
        }
    }
}

pub struct ConnectBroker<R: UpstreamResolver> {
    policy: Arc<PolicyEngine>,
    resolver: Arc<R>,
    authorizations: Arc<AuthorizationCache>,
    config: ConnectBrokerConfig,
    permits: Arc<Semaphore>,
}

impl<R: UpstreamResolver + 'static> ConnectBroker<R> {
    pub fn new(
        policy: Arc<PolicyEngine>,
        resolver: Arc<R>,
        authorizations: Arc<AuthorizationCache>,
        config: ConnectBrokerConfig,
    ) -> Arc<Self> {
        let permits = Arc::new(Semaphore::new(policy.max_concurrent_connections() as usize));
        Arc::new(Self {
            policy,
            resolver,
            authorizations,
            config,
            permits,
        })
    }

    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// Accepts connections and gates every one on the connection permit
    /// *before* spawning any task to handle it: the permit is acquired
    /// (`try_acquire_owned`) right here in the accept loop, and only a
    /// successful acquisition results in the full request-handling task
    /// being spawned. A saturated broker never spawns *any* task for the
    /// rejected connection — the `LimitExceeded` status is written inline,
    /// directly in the accept loop, bounded by a short (sub-second)
    /// timeout. This is deliberately *not* spawned: spawning even a
    /// short-lived, timeout-bounded task per rejection would let a
    /// sustained connection flood grow the number of in-flight tasks
    /// without bound, which is exactly the resource exhaustion the
    /// connection cap exists to prevent. Bounding the write inline instead
    /// means a flood can, at worst, backpressure the accept loop itself
    /// (each malicious non-reading rejected client costs at most one
    /// timeout's worth of accept-loop time) — it can never grow unbounded
    /// task or memory usage. A plain non-blocking `try_write` was
    /// considered but rejected: immediately after `accept`, the socket's
    /// write-readiness may not yet be established with the reactor on all
    /// platforms, so a bare `try_write` can spuriously fail to send even
    /// though the connection is healthy; the bounded async write awaits
    /// genuine writability instead.
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        loop {
            let (mut client, _peer) = listener.accept().await?;
            match Arc::clone(&self.permits).try_acquire_owned() {
                Ok(permit) => {
                    let broker = Arc::clone(&self);
                    tokio::spawn(async move {
                        let _ = broker.handle_client(client, permit).await;
                    });
                }
                Err(_) => {
                    let _ = timeout(
                        REJECTION_WRITE_TIMEOUT,
                        connect_proto::write_status(&mut client, ConnectStatus::LimitExceeded),
                    )
                    .await;
                }
            }
        }
    }

    /// Handles one already permit-gated client connection. `_permit` is
    /// held for the entire function (including the dial and the proxied
    /// session) and is only released when this function returns, whether
    /// by early rejection or after the session ends.
    pub async fn handle_client(
        &self,
        mut client: TcpStream,
        _permit: OwnedSemaphorePermit,
    ) -> io::Result<()> {
        let request = match timeout(
            self.config.handshake_timeout,
            connect_proto::decode_request(&mut client),
        )
        .await
        {
            Ok(Ok(request)) => request,
            Ok(Err(_)) => {
                let _ = connect_proto::write_status(&mut client, ConnectStatus::Malformed).await;
                return Ok(());
            }
            Err(_) => {
                let _ = connect_proto::write_status(&mut client, ConnectStatus::Timeout).await;
                return Ok(());
            }
        };

        if request.protocol != ConnectProtocol::Tcp {
            let _ =
                connect_proto::write_status(&mut client, ConnectStatus::UnsupportedProtocol).await;
            return Ok(());
        }

        let (target_ip, hostname_for_decision) = match &request.target {
            ConnectTarget::Hostname(host) => {
                match self.resolve_pinned(host, request.expected_ip).await {
                    Ok((normalized, ip)) => (ip, Some(normalized)),
                    Err(status) => {
                        let _ = connect_proto::write_status(&mut client, status).await;
                        return Ok(());
                    }
                }
            }
            ConnectTarget::Ip(ip) => {
                // A direct-IP target has no candidate set to check
                // `expected_ip` against beyond itself; a mismatch here is
                // simply the client contradicting its own request.
                if let Some(expected) = request.expected_ip
                    && expected != *ip
                {
                    let _ =
                        connect_proto::write_status(&mut client, ConnectStatus::ExpectedIpMismatch)
                            .await;
                    return Ok(());
                }
                (*ip, None)
            }
        };

        // Final, authoritative, port-aware decision immediately before
        // dialing. This is deliberately re-checked here (not merely
        // inferred from the domain-only/address-only checks performed
        // during resolution) so a hostname request can never bypass
        // `allowed_ports`/protocol constraints, and so the exact same
        // decision function governs both hostname and direct-IP targets at
        // the point of dial.
        let decision = match &hostname_for_decision {
            Some(name) => self
                .policy
                .decide_hostname(name, target_ip, request.port, Protocol::Tcp),
            None => self
                .policy
                .decide_direct_ip(target_ip, request.port, Protocol::Tcp),
        };
        if !decision.allowed {
            let _ = connect_proto::write_status(&mut client, ConnectStatus::PolicyDenied).await;
            return Ok(());
        }

        let dial_addr = SocketAddr::new(target_ip, request.port);
        let mut upstream =
            match timeout(self.config.connect_timeout, TcpStream::connect(dial_addr)).await {
                Ok(Ok(stream)) => stream,
                _ => {
                    let _ = connect_proto::write_status(&mut client, ConnectStatus::ConnectFailed)
                        .await;
                    return Ok(());
                }
            };

        connect_proto::write_status(&mut client, ConnectStatus::Ok).await?;

        // `copy_bidirectional` operates on the whole duplex streams (not
        // split read/write halves) and correctly propagates a half-close:
        // when one side's read direction hits EOF, it shuts down the
        // corresponding write half of the other stream, so a client that
        // finishes sending and half-closes still receives the upstream's
        // full response instead of the proxy silently deadlocking because
        // neither side ever observed the peer's FIN. The whole session is
        // additionally bounded by `session_timeout` so a peer that never
        // closes either direction cannot hold the permit/sockets forever.
        let _ = timeout(
            self.config.session_timeout,
            tokio::io::copy_bidirectional(&mut client, &mut upstream),
        )
        .await;
        Ok(())
    }

    /// Resolves `host` to an exact, policy-validated, pinned IP address,
    /// returning the normalized domain name alongside it so the caller can
    /// perform a final, port-aware `decide_hostname` check immediately
    /// before dialing. Prefers a live authorization already recorded by a
    /// prior DNS query; performs a fresh policy-aware resolution (and
    /// authorizes every validated address from it) whenever the cache is
    /// empty, or whenever a client-declared `expected_ip` is not already
    /// among the cached candidates — giving the resolver a chance to
    /// validate that specific address before giving up, rather than
    /// rejecting solely because it had not been queried yet. This exactly
    /// mirrors the DNS broker's validation so a hostname can never be
    /// connected to an address that was not itself validated.
    ///
    /// Address selection among multiple validated candidates:
    /// - `expected_ip` (already canonicalized by the CONNECT protocol
    ///   decoder) is used *only* as a filter into the validated candidate
    ///   set (cached, freshly resolved, or both) — if present in that set,
    ///   it is the address dialed; if a client supplies an `expected_ip`
    ///   that is not among the validated addresses, the request is
    ///   rejected rather than silently dialing a different address (the
    ///   client's claim is never substituted for validation, but it also
    ///   never overrides it).
    /// - Absent an `expected_ip`, selection is deterministic: the smallest
    ///   address in ascending `IpAddr` order (see
    ///   [`AuthorizationCache::authorized_addresses`]), not
    ///   resolver/hash-map iteration order.
    async fn resolve_pinned(
        &self,
        host: &str,
        expected_ip: Option<std::net::IpAddr>,
    ) -> Result<(String, std::net::IpAddr), ConnectStatus> {
        let normalized = domain::normalize_domain(host).map_err(|_| ConnectStatus::Malformed)?;

        match self.policy.evaluate_domain_name(&normalized) {
            Ok(true) => {}
            Ok(false) => return Err(ConnectStatus::PolicyDenied),
            Err(_) => return Err(ConnectStatus::Malformed),
        }

        let mut candidates = self.authorizations.authorized_addresses(&normalized);
        let expected_already_cached = expected_ip.is_some_and(|ip| candidates.contains(&ip));

        if candidates.is_empty() || (expected_ip.is_some() && !expected_already_cached) {
            let name =
                Name::from_ascii(format!("{normalized}.")).map_err(|_| ConnectStatus::Malformed)?;
            match timeout(self.config.resolve_timeout, self.resolver.resolve(&name)).await {
                Ok(Ok(resolved)) => {
                    for hop in resolved.names_to_validate() {
                        let hop_str = hop.to_utf8();
                        match self.policy.evaluate_domain_name(&hop_str) {
                            Ok(true) => {}
                            _ => return Err(ConnectStatus::PolicyDenied),
                        }
                    }

                    for addr in &resolved.addresses {
                        // Canonicalize before validation/authorization so
                        // an IPv4-mapped IPv6 literal from the resolver is
                        // recognized identically to its plain IPv4 form
                        // for policy purposes and for the
                        // authorization-cache key used later at dial time.
                        let ip = crate::address::canonicalize(addr.ip);
                        if self.policy.address_permitted(ip).allowed {
                            let ttl = self.policy.cap_ttl(addr.ttl_secs);
                            self.authorizations.authorize(
                                &normalized,
                                ip,
                                Duration::from_secs(u64::from(ttl)),
                            );
                            candidates.push(ip);
                        }
                    }
                    candidates.sort();
                    candidates.dedup();
                }
                Ok(Err(_)) | Err(_) => {
                    // Fresh resolution failed (or timed out). If cached
                    // candidates already exist — just not necessarily the
                    // client's specific `expected_ip` — fall through to
                    // the decision below on those; otherwise there is
                    // nothing to offer.
                    if candidates.is_empty() {
                        return Err(ConnectStatus::ResolutionFailed);
                    }
                }
            }
        }

        if candidates.is_empty() {
            return Err(ConnectStatus::PolicyDenied);
        }

        match expected_ip {
            Some(expected) if candidates.contains(&expected) => Ok((normalized, expected)),
            Some(_) => Err(ConnectStatus::ExpectedIpMismatch),
            // `candidates` is already sorted ascending (either directly
            // from `authorized_addresses`, or freshly sorted above), so
            // `candidates[0]` is the deterministic choice.
            None => Ok((normalized, candidates[0])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect_proto::ConnectRequest;
    use crate::fixture_resolver::StaticResolver;
    use crate::policy::{Action, NetworkPolicy};
    use crate::resolver::{ResolvedAddress, ResolvedChain};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn policy_engine(policy: NetworkPolicy) -> Arc<PolicyEngine> {
        Arc::new(PolicyEngine::compile(&policy).unwrap())
    }

    fn base_policy() -> NetworkPolicy {
        NetworkPolicy {
            default_action: Action::Deny,
            allowed_domains: vec!["allowed.example".to_owned()],
            blocked_domains: vec![],
            // Test fixtures bind to loopback; explicitly granting it here
            // mirrors how a real policy would need an explicit IP/CIDR
            // grant to reach a restricted address class. Tests that
            // exercise restricted-class denial use non-loopback or
            // metadata addresses instead (see policy.rs and dns_broker.rs).
            allowed_networks: vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()],
            blocked_networks: vec![],
            allowed_ports: vec![],
            max_concurrent_connections: 2,
            max_dns_ttl_secs: 30,
        }
    }

    async fn spawn_echo_fixture() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    /// Binds an echo fixture at an exact, caller-chosen address (used to
    /// put two fixtures for the same hostname's two candidate addresses on
    /// the same port, since a single CONNECT request only carries one
    /// port).
    async fn spawn_echo_fixture_at(addr: SocketAddr) {
        let listener = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    fn broker_with(
        policy: NetworkPolicy,
        resolver: Arc<StaticResolver>,
        config: ConnectBrokerConfig,
    ) -> Arc<ConnectBroker<StaticResolver>> {
        ConnectBroker::new(
            policy_engine(policy),
            resolver,
            Arc::new(AuthorizationCache::new()),
            config,
        )
    }

    fn broker_with_shared_cache(
        policy: NetworkPolicy,
        resolver: Arc<StaticResolver>,
        config: ConnectBrokerConfig,
    ) -> (Arc<ConnectBroker<StaticResolver>>, Arc<AuthorizationCache>) {
        let authorizations = Arc::new(AuthorizationCache::new());
        let broker = ConnectBroker::new(
            policy_engine(policy),
            resolver,
            Arc::clone(&authorizations),
            config,
        );
        (broker, authorizations)
    }

    async fn spawn_broker(broker: Arc<ConnectBroker<StaticResolver>>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(broker.run(listener));
        addr
    }

    #[tokio::test]
    async fn allows_hostname_connection_to_pinned_authorized_ip() {
        let fixture_addr = spawn_echo_fixture().await;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: fixture_addr.ip(),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(
            status,
            [connect_proto::PROTOCOL_VERSION, ConnectStatus::Ok as u8]
        );

        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn denies_hostname_not_covered_by_domain_policy() {
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("notallowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("notallowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;
        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Hostname("notallowed.example".to_owned()),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::PolicyDenied as u8);
    }

    #[tokio::test]
    async fn denies_direct_ip_not_covered_by_ip_policy() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;
        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::PolicyDenied as u8);
    }

    #[tokio::test]
    async fn direct_ip_allowed_when_explicitly_granted() {
        let fixture_addr = spawn_echo_fixture().await;
        let mut raw = base_policy();
        raw.allowed_networks
            .push(format!("{}/32", fixture_addr.ip()));
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(raw, resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;
        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Ip(fixture_addr.ip()),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::Ok as u8);
    }

    #[tokio::test]
    async fn expected_ip_mismatch_is_rejected_never_used_as_proof() {
        let fixture_addr = spawn_echo_fixture().await;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: fixture_addr.ip(),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;
        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        // Client lies about the expected IP; broker must reject rather than
        // connect to the client's claimed address.
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::ExpectedIpMismatch as u8);
    }

    #[tokio::test]
    async fn udp_protocol_is_always_denied() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;
        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Udp,
            port: 53,
            target: ConnectTarget::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::UnsupportedProtocol as u8);
    }

    #[tokio::test]
    async fn connection_limit_exhaustion_is_reported() {
        let fixture_addr = spawn_echo_fixture().await;
        let mut raw = base_policy();
        raw.max_concurrent_connections = 1;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: fixture_addr.ip(),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(raw, resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        let mut first = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        first
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut first_status = [0u8; 2];
        first.read_exact(&mut first_status).await.unwrap();
        assert_eq!(first_status[1], ConnectStatus::Ok as u8);

        let mut second = TcpStream::connect(broker_addr).await.unwrap();
        second
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut second_status = [0u8; 2];
        second.read_exact(&mut second_status).await.unwrap();
        assert_eq!(second_status[1], ConnectStatus::LimitExceeded as u8);
    }

    #[tokio::test]
    async fn malformed_frame_is_rejected_not_panicking() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;
        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        client.write_all(&[0xffu8; 4]).await.unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::Malformed as u8);
    }

    #[tokio::test]
    async fn slowloris_handshake_times_out() {
        let resolver = Arc::new(StaticResolver::new());
        let config = ConnectBrokerConfig {
            handshake_timeout: Duration::from_millis(150),
            ..Default::default()
        };
        let broker = broker_with(base_policy(), resolver, config);
        let broker_addr = spawn_broker(broker).await;
        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        // Send only the first byte, then stall well past the handshake
        // timeout without closing the connection.
        client
            .write_all(&[connect_proto::PROTOCOL_VERSION])
            .await
            .unwrap();
        let mut status = [0u8; 2];
        let read = timeout(Duration::from_secs(2), client.read_exact(&mut status)).await;
        assert!(
            read.is_ok(),
            "broker must respond instead of hanging forever"
        );
        assert_eq!(status[1], ConnectStatus::Timeout as u8);
    }

    #[tokio::test]
    async fn cancellation_mid_handshake_does_not_affect_other_clients() {
        let fixture_addr = spawn_echo_fixture().await;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: fixture_addr.ip(),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        // First client connects then disconnects mid-handshake (cancellation).
        {
            let mut cancelled = TcpStream::connect(broker_addr).await.unwrap();
            cancelled
                .write_all(&[connect_proto::PROTOCOL_VERSION])
                .await
                .unwrap();
            drop(cancelled);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A subsequent, well-formed client must still be served normally.
        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::Ok as u8);
    }

    #[tokio::test]
    async fn hostname_target_on_a_disallowed_port_is_denied_before_dial() {
        let fixture_addr = spawn_echo_fixture().await;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: fixture_addr.ip(),
                    ttl_secs: 30,
                }],
            },
        );
        let mut raw = base_policy();
        // Restrict to a port the fixture is *not* listening on; the domain
        // and address are otherwise fully allowed, so this isolates the
        // port/protocol check that must gate a hostname CONNECT.
        raw.allowed_ports = vec![crate::policy::PortRule {
            protocol: Protocol::Tcp,
            port: 9,
        }];
        let broker = broker_with(raw, resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;
        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(
            status[1],
            ConnectStatus::PolicyDenied as u8,
            "hostname CONNECT to a port outside allowed_ports must be denied before dial"
        );
    }

    #[tokio::test]
    async fn hostname_resolution_canonicalizes_ipv4_mapped_ipv6_addresses() {
        let fixture_addr = spawn_echo_fixture().await;
        let IpAddr::V4(fixture_v4) = fixture_addr.ip() else {
            panic!("fixture must bind an IPv4 loopback address for this test")
        };
        let resolver = Arc::new(StaticResolver::new());
        // The injectable resolver returns the fixture's address encoded as
        // an IPv4-mapped IPv6 literal.
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: IpAddr::V6(fixture_v4.to_ipv6_mapped()),
                    ttl_secs: 30,
                }],
            },
        );
        let (broker, authorizations) =
            broker_with_shared_cache(base_policy(), resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::Ok as u8);
        assert!(
            authorizations.is_authorized("allowed.example", IpAddr::V4(fixture_v4)),
            "authorization must be recorded under the canonical plain-IPv4 key"
        );
    }

    /// Reads all bytes until the peer half-closes (EOF), then writes back a
    /// fixed reply. This specifically exercises the "client sends then
    /// half-closes; server needs to observe EOF before replying" pattern
    /// that requires the proxy to propagate a half-close, not just copy
    /// bytes in both directions independently.
    async fn spawn_half_close_aware_fixture(reply: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let _ = stream.read_to_end(&mut buf).await;
                    let _ = stream.write_all(reply).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn proxy_propagates_half_close_instead_of_deadlocking() {
        const REPLY: &[u8] = b"reply-after-eof";
        let fixture_addr = spawn_half_close_aware_fixture(REPLY).await;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: fixture_addr.ip(),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::Ok as u8);

        client.write_all(b"hello").await.unwrap();
        // Half-close the client's write side; a correct proxy propagates
        // this to the upstream fixture so it sees EOF and replies.
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut received))
            .await
            .expect("proxy must propagate the half-close instead of hanging forever");
        read.unwrap();
        assert_eq!(received, REPLY);
    }

    #[tokio::test]
    async fn permit_is_acquired_before_handshake_read_saturated_client_needs_no_handshake() {
        let fixture_addr = spawn_echo_fixture().await;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: fixture_addr.ip(),
                    ttl_secs: 30,
                }],
            },
        );
        let mut raw = base_policy();
        raw.max_concurrent_connections = 1;
        let broker = broker_with(raw, resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        // Connection A completes a full legitimate CONNECT and then holds
        // the tunnel open (never closes), occupying the sole permit.
        let mut conn_a = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        conn_a
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status_a = [0u8; 2];
        conn_a.read_exact(&mut status_a).await.unwrap();
        assert_eq!(status_a[1], ConnectStatus::Ok as u8);

        // Connection B must receive LimitExceeded immediately, without
        // ever sending a single handshake byte — proving the permit is
        // checked before any read is attempted.
        let mut conn_b = TcpStream::connect(broker_addr).await.unwrap();
        let mut status_b = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), conn_b.read_exact(&mut status_b))
            .await
            .expect("saturated broker must respond immediately without waiting on a handshake")
            .unwrap();
        assert_eq!(status_b[1], ConnectStatus::LimitExceeded as u8);

        drop(conn_a);
    }

    #[tokio::test]
    async fn saturated_broker_handles_flood_of_rejections_without_unbounded_delay() {
        // Regression for the "rejection must not spawn a task per
        // connection" fix: floods a saturated broker with many concurrent
        // connections and asserts (a) every one is rejected with
        // `LimitExceeded` and (b) the whole flood completes quickly. The
        // previous (fixed) design spawned a 2-second-timeout-bounded task
        // per rejection; while individually bounded, an unbounded number
        // of concurrently in-flight rejection tasks is itself the
        // resource-exhaustion risk the connection cap exists to prevent.
        // The rewritten inline design performs the rejection write
        // directly in the accept loop and spawns nothing, so a flood of
        // readers should all be served promptly and the broker must
        // remain responsive to a legitimate connection afterward.
        let fixture_addr = spawn_echo_fixture().await;
        let mut raw = base_policy();
        raw.max_concurrent_connections = 1;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: fixture_addr.ip(),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(raw, resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        // Occupy the sole permit for the whole flood.
        let mut holder = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        holder
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut holder_status = [0u8; 2];
        holder.read_exact(&mut holder_status).await.unwrap();
        assert_eq!(holder_status[1], ConnectStatus::Ok as u8);

        const FLOOD_SIZE: usize = 250;
        let flood_started = std::time::Instant::now();
        let mut flood = tokio::task::JoinSet::new();
        for _ in 0..FLOOD_SIZE {
            flood.spawn(async move {
                let mut client = TcpStream::connect(broker_addr).await.unwrap();
                let mut status = [0u8; 2];
                tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut status))
                    .await
                    .expect("saturated broker must reject promptly under a flood")
                    .unwrap();
                status[1]
            });
        }
        let mut rejected = 0usize;
        while let Some(result) = flood.join_next().await {
            assert_eq!(result.unwrap(), ConnectStatus::LimitExceeded as u8);
            rejected += 1;
        }
        assert_eq!(rejected, FLOOD_SIZE);
        // Every rejection is a plain inline write with no per-connection
        // task or long timeout on the happy path (the reader is present),
        // so a large flood must complete in a small fraction of the
        // per-rejection bound, not grow linearly with `FLOOD_SIZE`.
        assert!(
            flood_started.elapsed() < Duration::from_secs(5),
            "flood of {FLOOD_SIZE} rejections took {:?}, suggesting unbounded per-connection cost",
            flood_started.elapsed()
        );

        // The broker must remain fully responsive afterward. Releasing the
        // permit requires the server-side task handling `holder` to notice
        // the peer disconnect and exit, which is asynchronous, so poll
        // briefly instead of asserting immediately after a bare `drop`.
        drop(holder);
        let reconnect_deadline = std::time::Instant::now() + Duration::from_secs(2);
        let after_status = loop {
            let mut after = TcpStream::connect(broker_addr).await.unwrap();
            after
                .write_all(&connect_proto::encode_request(&request))
                .await
                .unwrap();
            let mut status = [0u8; 2];
            tokio::time::timeout(Duration::from_secs(1), after.read_exact(&mut status))
                .await
                .expect("broker must keep responding after the flood")
                .unwrap();
            if status[1] == ConnectStatus::Ok as u8
                || std::time::Instant::now() > reconnect_deadline
            {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(
            after_status[1],
            ConnectStatus::Ok as u8,
            "broker did not become responsive again after the flood and permit release"
        );
    }

    #[tokio::test]
    async fn multi_address_hostname_selects_smallest_ip_deterministically_without_expected_ip() {
        // Two candidate addresses for the same hostname; only the smaller
        // (IPv4, which sorts before IPv6 in ascending `IpAddr` order) has a
        // real listener. If selection were not deterministically the
        // smallest, this would either connect to nothing or fail.
        let port = 18761;
        let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        spawn_echo_fixture_at(v4_addr).await;

        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("multi.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("multi.example.").unwrap(),
                addresses: vec![
                    ResolvedAddress {
                        ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        ttl_secs: 30,
                    },
                    ResolvedAddress {
                        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        ttl_secs: 30,
                    },
                ],
            },
        );
        let mut raw = base_policy();
        raw.allowed_domains.push("multi.example".to_owned());
        let broker = broker_with(raw, resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port,
            target: ConnectTarget::Hostname("multi.example".to_owned()),
            expected_ip: None,
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(
            status[1],
            ConnectStatus::Ok as u8,
            "must connect via the deterministically-selected (smaller) IPv4 address"
        );
    }

    #[tokio::test]
    async fn multi_address_hostname_honors_expected_ip_over_the_default_selection() {
        // Same two-candidate setup, but this time only the IPv6 candidate
        // (which would *not* be the default deterministic choice) has a
        // real listener, and the client explicitly requests it via
        // `expected_ip`.
        let port = 18762;
        let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
        spawn_echo_fixture_at(v6_addr).await;

        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("multi6.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("multi6.example.").unwrap(),
                addresses: vec![
                    ResolvedAddress {
                        ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        ttl_secs: 30,
                    },
                    ResolvedAddress {
                        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        ttl_secs: 30,
                    },
                ],
            },
        );
        let mut raw = base_policy();
        raw.allowed_domains.push("multi6.example".to_owned());
        let broker = broker_with(raw, resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port,
            target: ConnectTarget::Hostname("multi6.example".to_owned()),
            expected_ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(
            status[1],
            ConnectStatus::Ok as u8,
            "expected_ip must be honored when it is among the validated candidates"
        );
    }

    #[tokio::test]
    async fn multi_address_hostname_rejects_expected_ip_absent_from_validated_set() {
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("multi7.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("multi7.example.").unwrap(),
                addresses: vec![
                    ResolvedAddress {
                        ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        ttl_secs: 30,
                    },
                    ResolvedAddress {
                        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        ttl_secs: 30,
                    },
                ],
            },
        );
        let mut raw = base_policy();
        raw.allowed_domains.push("multi7.example".to_owned());
        let broker = broker_with(raw, resolver, ConnectBrokerConfig::default());
        let broker_addr = spawn_broker(broker).await;

        let mut client = TcpStream::connect(broker_addr).await.unwrap();
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 18763,
            target: ConnectTarget::Hostname("multi7.example".to_owned()),
            expected_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
        };
        client
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::ExpectedIpMismatch as u8);
    }
}
