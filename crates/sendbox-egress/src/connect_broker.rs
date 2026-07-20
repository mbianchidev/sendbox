//! Egress CONNECT broker: accepts local client connections speaking the
//! bounded CONNECT protocol, enforces policy and DNS authorization, dials the
//! exact validated destination `SocketAddr` through a [`Dialer`] (never
//! re-resolving a hostname through the OS resolver), and copies bytes
//! bidirectionally. Every decision emits a typed [`AuditEvent`].
//!
//! Security-relevant properties:
//! - A client-declared hostname is resolved by the broker itself, through the
//!   same policy-aware resolver/authorization path the DNS broker uses; the
//!   client's optional `expected_ip` is only a consistency check and a
//!   mismatch is always rejected, never silently substituted.
//! - Direct-IP requests are governed exclusively by IP/address-class policy
//!   (`PolicyEngine::decide_direct_ip`), never by domain rules.
//! - UDP/QUIC is always denied; this broker only ever proxies TCP.
//! - A bounded semaphore enforces `max_concurrent_connections` before any dial
//!   is attempted.
//! - The handshake read is wrapped in a timeout to defend against
//!   slowloris-style peers, and the whole session is bounded by
//!   `session_timeout` and stops cleanly on cancellation.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::rr::Name;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditEvent, AuditSink};
use crate::authorization::AuthorizationCache;
use crate::connect_proto::{self, ConnectProtocol, ConnectStatus, ConnectTarget};
use crate::dialer::Dialer;
use crate::dns_budget::DnsGuard;
use crate::domain;
use crate::policy::PolicyEngine;
use crate::resolver::UpstreamResolver;
use crate::socks5;
use sendbox_policy::{DnsRecordType, Protocol};

/// Bound on writing the `LimitExceeded` rejection status to a saturated
/// client, applied inline in the accept loop (never spawned) so a connection
/// flood cannot grow in-flight task count.
const REJECTION_WRITE_TIMEOUT: Duration = Duration::from_millis(250);

/// Which client-facing wire protocol the CONNECT broker speaks. Selected once
/// per broker instance from configuration; the broker never auto-detects the
/// protocol from the first bytes (which would be ambiguous and attacker
/// influenceable). A runtime chooses [`ConnectFrontend::Socks5`] when the agent
/// toolchain speaks standard SOCKS5 (e.g. `ALL_PROXY=socks5h://…`), and the
/// default [`ConnectFrontend::Custom`] for the crate's own bounded protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectFrontend {
    /// The crate's small, versioned, bounded CONNECT framing (default).
    #[default]
    Custom,
    /// Standard SOCKS5 (RFC 1928), no-auth, CONNECT only.
    Socks5,
}

#[derive(Debug, Clone)]
pub struct ConnectBrokerConfig {
    /// The client-facing wire protocol (default: the custom CONNECT framing).
    pub frontend: ConnectFrontend,
    /// Overall bound on reading and parsing one request handshake.
    pub handshake_timeout: Duration,
    /// Bound on dialing the upstream destination.
    pub connect_timeout: Duration,
    /// Bound on a single fresh upstream resolution.
    pub resolve_timeout: Duration,
    /// Upper bound on the lifetime of one proxied session.
    pub session_timeout: Duration,
}

impl Default for ConnectBrokerConfig {
    fn default() -> Self {
        Self {
            frontend: ConnectFrontend::Custom,
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
    guard: Arc<DnsGuard>,
    dialer: Arc<dyn Dialer>,
    audit: Arc<dyn AuditSink>,
    config: ConnectBrokerConfig,
    permits: Arc<Semaphore>,
}

impl<R: UpstreamResolver + 'static> ConnectBroker<R> {
    #[must_use]
    pub fn new(
        policy: Arc<PolicyEngine>,
        resolver: Arc<R>,
        authorizations: Arc<AuthorizationCache>,
        guard: Arc<DnsGuard>,
        dialer: Arc<dyn Dialer>,
        audit: Arc<dyn AuditSink>,
        config: ConnectBrokerConfig,
    ) -> Arc<Self> {
        let permits = Arc::new(Semaphore::new(policy.max_concurrent_connections() as usize));
        Arc::new(Self {
            policy,
            resolver,
            authorizations,
            guard,
            dialer,
            audit,
            config,
            permits,
        })
    }

    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// Accepts connections until cancelled, gating every one on the connection
    /// permit before spawning any task. A saturated broker writes
    /// `LimitExceeded` inline (bounded) and never spawns a task for the
    /// rejected connection.
    pub async fn run(
        self: Arc<Self>,
        listener: TcpListener,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        loop {
            let (mut client, _peer) = tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(()),
                result = listener.accept() => result?,
            };
            match Arc::clone(&self.permits).try_acquire_owned() {
                Ok(permit) => {
                    let broker = Arc::clone(&self);
                    let task_cancel = cancel.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            biased;
                            () = task_cancel.cancelled() => {}
                            result = broker.handle_client(client, permit) => {
                                let _ = result;
                            }
                        }
                    });
                }
                Err(_) => {
                    self.audit.record(AuditEvent::ConnectLimitExceeded);
                    // Write a frontend-appropriate rejection inline (bounded).
                    // For SOCKS the client has not negotiated yet, so there is
                    // no well-formed reply to send pre-handshake; closing the
                    // connection is the correct rejection.
                    if self.config.frontend == ConnectFrontend::Custom {
                        let _ = timeout(
                            REJECTION_WRITE_TIMEOUT,
                            connect_proto::write_status(&mut client, ConnectStatus::LimitExceeded),
                        )
                        .await;
                    }
                }
            }
        }
    }

    /// Handles one already permit-gated client connection by dispatching to the
    /// configured front end. `permit` is held for the entire session.
    pub async fn handle_client(
        &self,
        client: TcpStream,
        permit: OwnedSemaphorePermit,
    ) -> io::Result<()> {
        match self.config.frontend {
            ConnectFrontend::Custom => self.handle_custom(client, permit).await,
            ConnectFrontend::Socks5 => self.handle_socks5(client, permit).await,
        }
    }

    /// The crate's native bounded CONNECT protocol front end.
    async fn handle_custom(
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
                self.audit.record(AuditEvent::ConnectError {
                    detail: "malformed",
                });
                let _ = connect_proto::write_status(&mut client, ConnectStatus::Malformed).await;
                return Ok(());
            }
            Err(_) => {
                self.audit.record(AuditEvent::ConnectError {
                    detail: "handshake_timeout",
                });
                let _ = connect_proto::write_status(&mut client, ConnectStatus::Timeout).await;
                return Ok(());
            }
        };

        let label = target_label(&request.target);
        if request.protocol != ConnectProtocol::Tcp {
            self.audit.record(AuditEvent::ConnectUnsupportedProtocol {
                target: label,
                port: request.port,
            });
            let _ =
                connect_proto::write_status(&mut client, ConnectStatus::UnsupportedProtocol).await;
            return Ok(());
        }

        match self
            .authorize_and_dial(&request.target, request.port, request.expected_ip)
            .await
        {
            Ok(dial) => {
                connect_proto::write_status(&mut client, ConnectStatus::Ok).await?;
                self.audit.record(AuditEvent::ConnectAllowed {
                    target: label,
                    ip: dial.target_ip,
                    port: request.port,
                });
                self.proxy(client, dial.upstream).await;
            }
            Err(status) => {
                self.audit.record(AuditEvent::ConnectDenied {
                    target: label,
                    port: request.port,
                    status: status.as_str(),
                });
                let _ = connect_proto::write_status(&mut client, status).await;
            }
        }
        Ok(())
    }

    /// A standard SOCKS5 (RFC 1928) front end: no-auth negotiation, then a
    /// single request. Only `CONNECT` is honored; `BIND` and `UDP ASSOCIATE`
    /// are refused with `Command not supported` (this is how UDP/QUIC is denied
    /// at the SOCKS layer). The target/port flow through the exact same
    /// authorize/pin/dial path as the native protocol.
    async fn handle_socks5(
        &self,
        mut client: TcpStream,
        _permit: OwnedSemaphorePermit,
    ) -> io::Result<()> {
        match timeout(
            self.config.handshake_timeout,
            socks5::negotiate(&mut client),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                // `negotiate` already wrote the SOCKS rejection when applicable.
                self.audit.record(AuditEvent::ConnectError {
                    detail: "socks_negotiation",
                });
                return Ok(());
            }
            Err(_) => {
                self.audit.record(AuditEvent::ConnectError {
                    detail: "handshake_timeout",
                });
                return Ok(());
            }
        }

        let request = match timeout(
            self.config.handshake_timeout,
            socks5::read_request(&mut client),
        )
        .await
        {
            Ok(Ok(request)) => request,
            Ok(Err(socks5::Socks5Error::UnsupportedAddressType(_))) => {
                self.audit.record(AuditEvent::ConnectError {
                    detail: "socks_address_type",
                });
                let _ = socks5::write_failure(
                    &mut client,
                    socks5::Socks5Reply::AddressTypeNotSupported,
                )
                .await;
                return Ok(());
            }
            Ok(Err(_)) => {
                self.audit.record(AuditEvent::ConnectError {
                    detail: "socks_malformed",
                });
                let _ =
                    socks5::write_failure(&mut client, socks5::Socks5Reply::GeneralFailure).await;
                return Ok(());
            }
            Err(_) => {
                self.audit.record(AuditEvent::ConnectError {
                    detail: "handshake_timeout",
                });
                let _ =
                    socks5::write_failure(&mut client, socks5::Socks5Reply::GeneralFailure).await;
                return Ok(());
            }
        };

        let label = target_label(&request.target);
        if request.command != socks5::Socks5Command::Connect {
            self.audit.record(AuditEvent::ConnectUnsupportedProtocol {
                target: label,
                port: request.port,
            });
            let _ =
                socks5::write_failure(&mut client, socks5::Socks5Reply::CommandNotSupported).await;
            return Ok(());
        }

        match self
            .authorize_and_dial(&request.target, request.port, None)
            .await
        {
            Ok(dial) => {
                // RFC 1928 §6: BND.ADDR/BND.PORT is the address the proxy's
                // socket bound on its side of the upstream connection, *not* the
                // requested destination. Report the upstream socket's local
                // endpoint so a well-behaved SOCKS client learns the broker's
                // egress address rather than being told its own target back.
                let bound = dial
                    .upstream
                    .local_addr()
                    .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
                socks5::write_reply(&mut client, socks5::Socks5Reply::Succeeded, bound).await?;
                self.audit.record(AuditEvent::ConnectAllowed {
                    target: label,
                    ip: dial.target_ip,
                    port: request.port,
                });
                self.proxy(client, dial.upstream).await;
            }
            Err(status) => {
                self.audit.record(AuditEvent::ConnectDenied {
                    target: label,
                    port: request.port,
                    status: status.as_str(),
                });
                let _ = socks5::write_failure(&mut client, socks_reply_for_status(status)).await;
            }
        }
        Ok(())
    }

    /// Shared authorize + dial path used by both front ends. Resolves and pins
    /// a hostname (or validates a direct IP), makes the final port-aware policy
    /// decision, and dials the exact validated `SocketAddr` through the
    /// [`crate::dialer::Dialer`]. Returns the connected upstream and the pinned
    /// target IP, or the canonical [`ConnectStatus`] denial.
    async fn authorize_and_dial(
        &self,
        target: &ConnectTarget,
        port: u16,
        expected_ip: Option<IpAddr>,
    ) -> Result<AuthorizedDial, ConnectStatus> {
        let (target_ip, hostname_for_decision) = match target {
            ConnectTarget::Hostname(host) => match self.resolve_pinned(host, expected_ip).await {
                Ok((normalized, ip)) => (ip, Some(normalized)),
                Err(status) => return Err(status),
            },
            ConnectTarget::Ip(ip) => {
                if let Some(expected) = expected_ip
                    && expected != *ip
                {
                    return Err(ConnectStatus::ExpectedIpMismatch);
                }
                (*ip, None)
            }
        };

        let decision = match &hostname_for_decision {
            Some(name) => self
                .policy
                .decide_hostname(name, target_ip, port, Protocol::Tcp),
            None => self.policy.decide_direct_ip(target_ip, port, Protocol::Tcp),
        };
        if !decision.allowed {
            return Err(ConnectStatus::PolicyDenied);
        }

        let dial_addr = SocketAddr::new(target_ip, port);
        match self
            .dialer
            .dial(dial_addr, self.config.connect_timeout)
            .await
        {
            Ok(upstream) => Ok(AuthorizedDial {
                upstream,
                target_ip,
            }),
            Err(_) => Err(ConnectStatus::ConnectFailed),
        }
    }

    /// Copies bytes between the client and upstream until either side closes or
    /// the session timeout elapses. Cancellation is handled by the caller's
    /// `run` loop, which wraps the whole handler in a cancellation select.
    async fn proxy(&self, mut client: TcpStream, mut upstream: TcpStream) {
        let _ = timeout(
            self.config.session_timeout,
            tokio::io::copy_bidirectional(&mut client, &mut upstream),
        )
        .await;
    }

    /// Resolves `host` to an exact, policy-validated, pinned IP address.
    ///
    /// Prefers a live authorization already recorded by a prior DNS query. A
    /// fresh resolution is only performed when DNS is enabled
    /// (`allow_dns = true`); when `allow_dns = false` the broker relies solely
    /// on prior cached authorizations (there is no DNS broker exposed, so a
    /// hostname the cache does not already hold cannot be dialed). A fresh
    /// resolution runs the name through the *same* shared [`DnsGuard`] as the
    /// DNS broker — structural limits, the QTYPE allowlist, the response-record
    /// cap, and the deterministic exfiltration budget — and audits any denial
    /// or rate limit, so the CONNECT path can never be used to bypass the DNS
    /// controls.
    async fn resolve_pinned(
        &self,
        host: &str,
        expected_ip: Option<std::net::IpAddr>,
    ) -> Result<(String, std::net::IpAddr), ConnectStatus> {
        let normalized = domain::normalize_domain(host).map_err(|_| ConnectStatus::Malformed)?;

        // Structural QNAME limits (bounded, stateless) apply to every hostname.
        if let Err(limit) = self.guard.check_structure(&normalized) {
            self.audit.record(AuditEvent::DnsStructuralRejected {
                name: normalized.clone(),
                limit,
            });
            return Err(ConnectStatus::PolicyDenied);
        }

        match self.policy.evaluate_domain_name(&normalized) {
            Ok(true) => {}
            Ok(false) => return Err(ConnectStatus::PolicyDenied),
            Err(_) => return Err(ConnectStatus::Malformed),
        }

        let mut candidates = self.authorizations.authorized_addresses(&normalized);
        let expected_already_cached = expected_ip.is_some_and(|ip| candidates.contains(&ip));
        let need_fresh =
            candidates.is_empty() || (expected_ip.is_some() && !expected_already_cached);

        if need_fresh {
            if !self.policy.allow_dns() {
                // DNS is disabled: no DNS broker exists, so the only valid
                // authorizations are ones already cached. Refuse to resolve.
                if candidates.is_empty() {
                    return Err(ConnectStatus::ResolutionFailed);
                }
            } else {
                self.fresh_resolve(&normalized, &mut candidates).await?;
            }
        }

        if candidates.is_empty() {
            return Err(ConnectStatus::PolicyDenied);
        }

        match expected_ip {
            Some(expected) if candidates.contains(&expected) => Ok((normalized, expected)),
            Some(_) => Err(ConnectStatus::ExpectedIpMismatch),
            None => Ok((normalized, candidates[0])),
        }
    }

    /// Performs one guarded fresh resolution, appending every validated address
    /// to `candidates`. Charges the exfiltration budget, validates each CNAME
    /// hop, filters by the QTYPE allowlist and address-class policy, and caps
    /// the number of authorized addresses to the response-record limit.
    async fn fresh_resolve(
        &self,
        normalized: &str,
        candidates: &mut Vec<std::net::IpAddr>,
    ) -> Result<(), ConnectStatus> {
        // Charge the deterministic budget for this resolution (only reached for
        // domain-allowed names, matching the DNS broker).
        if let Err(limit) = self.guard.admit(normalized, Instant::now()) {
            self.audit.record(AuditEvent::DnsRateLimited {
                name: normalized.to_owned(),
                limit,
            });
            return Err(ConnectStatus::PolicyDenied);
        }

        let name =
            Name::from_ascii(format!("{normalized}.")).map_err(|_| ConnectStatus::Malformed)?;
        let resolved =
            match timeout(self.config.resolve_timeout, self.resolver.resolve(&name)).await {
                Ok(Ok(resolved)) => resolved,
                Ok(Err(_)) | Err(_) => {
                    if candidates.is_empty() {
                        return Err(ConnectStatus::ResolutionFailed);
                    }
                    return Ok(());
                }
            };

        for hop in resolved.names_to_validate() {
            let hop_str = hop.to_utf8();
            match self.policy.evaluate_domain_name(&hop_str) {
                Ok(true) => {}
                _ => return Err(ConnectStatus::PolicyDenied),
            }
        }

        // Collect validated (ip, ttl) pairs honoring the QTYPE allowlist and
        // address-class policy, then cap to the response-record limit before
        // authorizing, exactly like the DNS broker.
        let mut validated: Vec<(std::net::IpAddr, u32)> = Vec::new();
        for addr in &resolved.addresses {
            let ip = crate::address::canonicalize(addr.ip);
            let record_type = if ip.is_ipv4() {
                DnsRecordType::A
            } else {
                DnsRecordType::Aaaa
            };
            if !self.guard.record_type_allowed(record_type) {
                continue;
            }
            if !self.policy.address_permitted(ip).allowed {
                continue;
            }
            validated.push((ip, addr.ttl_secs));
        }
        validated.sort_by(|(a, _), (b, _)| a.cmp(b));
        validated.dedup_by(|(a, _), (b, _)| a == b);
        validated.truncate(self.guard.max_response_records());

        for (ip, ttl_secs) in validated {
            let ttl = self.policy.cap_ttl(ttl_secs);
            self.authorizations
                .authorize(normalized, ip, Duration::from_secs(u64::from(ttl)));
            candidates.push(ip);
        }
        candidates.sort();
        candidates.dedup();
        Ok(())
    }
}

fn target_label(target: &ConnectTarget) -> String {
    match target {
        ConnectTarget::Hostname(host) => host.clone(),
        ConnectTarget::Ip(ip) => ip.to_string(),
    }
}

/// A connected, policy-authorized upstream and its pinned target IP.
struct AuthorizedDial {
    upstream: TcpStream,
    target_ip: IpAddr,
}

/// Maps the canonical [`ConnectStatus`] denial to a deterministic SOCKS5 reply
/// code (RFC 1928 §6).
fn socks_reply_for_status(status: ConnectStatus) -> socks5::Socks5Reply {
    use socks5::Socks5Reply as Reply;
    match status {
        ConnectStatus::Ok => Reply::Succeeded,
        ConnectStatus::PolicyDenied | ConnectStatus::ExpectedIpMismatch => Reply::NotAllowed,
        ConnectStatus::ResolutionFailed => Reply::HostUnreachable,
        ConnectStatus::ConnectFailed => Reply::ConnectionRefused,
        ConnectStatus::UnsupportedProtocol => Reply::CommandNotSupported,
        ConnectStatus::Malformed | ConnectStatus::Timeout | ConnectStatus::LimitExceeded => {
            Reply::GeneralFailure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{CollectingAuditSink, NullAuditSink};
    use crate::connect_proto::ConnectRequest;
    use crate::dialer::DirectDialer;
    use crate::fixture_resolver::StaticResolver;
    use crate::resolver::{ResolvedAddress, ResolvedChain};
    use sendbox_policy::{Action, DnsPolicy, NetworkPolicy};
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
            allow_dns: true,
            max_connections: Some(2),
            allowed_networks: vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()],
            blocked_networks: vec![],
            allowed_ports: vec![],
            dns: DnsPolicy {
                max_ttl_secs: 30,
                ..DnsPolicy::default()
            },
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

    fn broker_with(
        policy: NetworkPolicy,
        resolver: Arc<StaticResolver>,
        config: ConnectBrokerConfig,
    ) -> Arc<ConnectBroker<StaticResolver>> {
        let guard = Arc::new(DnsGuard::from_policy(&policy.dns));
        ConnectBroker::new(
            policy_engine(policy),
            resolver,
            Arc::new(AuthorizationCache::new()),
            guard,
            Arc::new(DirectDialer),
            Arc::new(NullAuditSink),
            config,
        )
    }

    fn broker_with_audit(
        policy: NetworkPolicy,
        resolver: Arc<StaticResolver>,
        config: ConnectBrokerConfig,
        audit: Arc<CollectingAuditSink>,
    ) -> Arc<ConnectBroker<StaticResolver>> {
        let guard = Arc::new(DnsGuard::from_policy(&policy.dns));
        ConnectBroker::new(
            policy_engine(policy),
            resolver,
            Arc::new(AuthorizationCache::new()),
            guard,
            Arc::new(DirectDialer),
            audit,
            config,
        )
    }

    fn broker_with_shared_cache(
        policy: NetworkPolicy,
        resolver: Arc<StaticResolver>,
        config: ConnectBrokerConfig,
    ) -> (Arc<ConnectBroker<StaticResolver>>, Arc<AuthorizationCache>) {
        let authorizations = Arc::new(AuthorizationCache::new());
        let guard = Arc::new(DnsGuard::from_policy(&policy.dns));
        let broker = ConnectBroker::new(
            policy_engine(policy),
            resolver,
            Arc::clone(&authorizations),
            guard,
            Arc::new(DirectDialer),
            Arc::new(NullAuditSink),
            config,
        );
        (broker, authorizations)
    }

    async fn spawn_broker(
        broker: Arc<ConnectBroker<StaticResolver>>,
    ) -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        tokio::spawn(broker.run(listener, cancel.clone()));
        (addr, cancel)
    }

    async fn send_request(
        addr: SocketAddr,
        request: &ConnectRequest,
    ) -> (ConnectStatus, TcpStream) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(&connect_proto::encode_request(request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).await.unwrap();
        (status_from_byte(status[1]), stream)
    }

    fn status_from_byte(byte: u8) -> ConnectStatus {
        match byte {
            0 => ConnectStatus::Ok,
            1 => ConnectStatus::PolicyDenied,
            2 => ConnectStatus::ResolutionFailed,
            3 => ConnectStatus::ConnectFailed,
            4 => ConnectStatus::LimitExceeded,
            5 => ConnectStatus::Malformed,
            6 => ConnectStatus::UnsupportedProtocol,
            7 => ConnectStatus::ExpectedIpMismatch,
            8 => ConnectStatus::Timeout,
            _ => panic!("unknown status byte {byte}"),
        }
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
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(
            base_policy(),
            resolver,
            ConnectBrokerConfig::default(),
            Arc::clone(&audit),
        );
        let (addr, cancel) = spawn_broker(broker).await;

        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, mut stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::Ok);
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(
            audit
                .events()
                .iter()
                .any(|e| matches!(e, AuditEvent::ConnectAllowed { .. }))
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn denies_hostname_not_covered_by_domain_policy() {
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("denied.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("denied.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Hostname("denied.example".to_owned()),
            expected_ip: None,
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::PolicyDenied);
        cancel.cancel();
    }

    #[tokio::test]
    async fn denies_direct_ip_not_covered_by_ip_policy() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            expected_ip: None,
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::PolicyDenied);
        cancel.cancel();
    }

    #[tokio::test]
    async fn direct_ip_allowed_when_explicitly_granted() {
        let fixture_addr = spawn_echo_fixture().await;
        let mut policy = base_policy();
        policy.default_action = Action::Allow;
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(policy, resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Ip(fixture_addr.ip()),
            expected_ip: None,
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::Ok);
        cancel.cancel();
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
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))),
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::ExpectedIpMismatch);
        cancel.cancel();
    }

    #[tokio::test]
    async fn udp_protocol_is_always_denied_and_audited() {
        let resolver = Arc::new(StaticResolver::new());
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(
            base_policy(),
            resolver,
            ConnectBrokerConfig::default(),
            Arc::clone(&audit),
        );
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Udp,
            port: 443,
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::UnsupportedProtocol);
        assert!(
            audit
                .events()
                .iter()
                .any(|e| matches!(e, AuditEvent::ConnectUnsupportedProtocol { .. }))
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn connection_limit_exhaustion_is_reported() {
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
        let mut policy = base_policy();
        policy.max_connections = Some(1);
        let broker = broker_with(policy, resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;

        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        // Hold the sole permit open with a live session.
        let (status_a, _held) = send_request(addr, &request).await;
        assert_eq!(status_a, ConnectStatus::Ok);

        let (status_b, _stream) = send_request(addr, &request).await;
        assert_eq!(status_b, ConnectStatus::LimitExceeded);
        cancel.cancel();
    }

    #[tokio::test]
    async fn malformed_frame_is_rejected_not_panicking() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&[9, 9, 9, 9, 9]).await.unwrap();
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).await.unwrap();
        assert_eq!(status_from_byte(status[1]), ConnectStatus::Malformed);
        cancel.cancel();
    }

    #[tokio::test]
    async fn slowloris_handshake_times_out() {
        let resolver = Arc::new(StaticResolver::new());
        let config = ConnectBrokerConfig {
            handshake_timeout: Duration::from_millis(150),
            ..ConnectBrokerConfig::default()
        };
        let broker = broker_with(base_policy(), resolver, config);
        let (addr, cancel) = spawn_broker(broker).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        // Send only one byte, then stall.
        stream
            .write_all(&[connect_proto::PROTOCOL_VERSION])
            .await
            .unwrap();
        let mut status = [0u8; 2];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut status))
            .await
            .expect("must not hang");
        assert!(read.is_ok());
        assert_eq!(status_from_byte(status[1]), ConnectStatus::Timeout);
        cancel.cancel();
    }

    #[tokio::test]
    async fn hostname_target_on_a_disallowed_port_is_denied_before_dial() {
        let fixture_addr = spawn_echo_fixture().await;
        let mut policy = base_policy();
        policy.allowed_ports = vec![sendbox_policy::PortRule {
            protocol: Protocol::Tcp,
            port: 443,
        }];
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
        let broker = broker_with(policy, resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(), // not 443
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::PolicyDenied);
        cancel.cancel();
    }

    #[tokio::test]
    async fn hostname_resolution_canonicalizes_ipv4_mapped_ipv6_addresses() {
        let fixture_addr = spawn_echo_fixture().await;
        let IpAddr::V4(v4) = fixture_addr.ip() else {
            unreachable!("loopback fixture is IPv4");
        };
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: IpAddr::V6(v4.to_ipv6_mapped()),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::Ok);
        cancel.cancel();
    }

    #[tokio::test]
    async fn cancellation_stops_the_accept_loop() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(broker.run(listener, cancel.clone()));
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(matches!(result, Ok(Ok(Ok(())))));
    }

    #[tokio::test]
    async fn resolution_failure_reports_resolution_failed() {
        let resolver = Arc::new(StaticResolver::new());
        // allowed.example is domain-allowed but the resolver has no entry.
        let broker = broker_with(base_policy(), resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::ResolutionFailed);
        cancel.cancel();
    }

    #[tokio::test]
    async fn multi_address_hostname_selects_smallest_ip_deterministically() {
        // The reachable echo fixture binds 127.0.0.1; the resolver also
        // advertises a higher loopback address that is never dialed because
        // the broker deterministically pins the smallest validated address.
        // Only 127.0.0.1 is bound, so this is portable to macOS (which does
        // not route 127.0.0.2+ by default).
        let fixture_addr = spawn_echo_fixture().await;
        let low = fixture_addr.ip();
        assert_eq!(low, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let high = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));

        let mut policy = base_policy();
        policy.allowed_networks = vec!["127.0.0.0/8".to_owned()];
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![
                    ResolvedAddress {
                        ip: high,
                        ttl_secs: 30,
                    },
                    ResolvedAddress {
                        ip: low,
                        ttl_secs: 30,
                    },
                ],
            },
        );
        let (broker, cache) =
            broker_with_shared_cache(policy, resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::Ok);
        // The deterministic selection recorded the smaller address first.
        let cached = cache.authorized_addresses("allowed.example");
        assert_eq!(cached.first().copied(), Some(low));
        cancel.cancel();
    }

    #[tokio::test]
    async fn round_trips_ipv6_target_when_granted() {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let v6_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 16];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
        });
        let mut policy = base_policy();
        policy.default_action = Action::Allow;
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(policy, resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: v6_addr.port(),
            target: ConnectTarget::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            expected_ip: None,
        };
        let (status, _stream) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::Ok);
        cancel.cancel();
    }

    // ── SOCKS5 front end ─────────────────────────────────────────────────

    fn socks_config() -> ConnectBrokerConfig {
        ConnectBrokerConfig {
            frontend: ConnectFrontend::Socks5,
            ..ConnectBrokerConfig::default()
        }
    }

    async fn socks_negotiate(stream: &mut TcpStream) {
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
    }

    fn socks_connect_domain(host: &str, port: u16) -> Vec<u8> {
        let mut buf = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        buf.extend_from_slice(host.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    /// Sends an already-negotiated SOCKS request and returns the reply code
    /// plus the still-open stream (after consuming the bound address/port).
    async fn socks_request(addr: SocketAddr, request: &[u8]) -> (u8, TcpStream) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        socks_negotiate(&mut stream).await;
        stream.write_all(request).await.unwrap();
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        let addr_len = match head[3] {
            0x01 => 4,
            0x04 => 16,
            _ => 0,
        };
        let mut rest = vec![0u8; addr_len + 2];
        stream.read_exact(&mut rest).await.unwrap();
        (head[1], stream)
    }

    #[tokio::test]
    async fn socks5_hostname_connect_succeeds_and_round_trips() {
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
        let broker = broker_with(base_policy(), resolver, socks_config());
        let (addr, cancel) = spawn_broker(broker).await;
        let (rep, mut stream) = socks_request(
            addr,
            &socks_connect_domain("allowed.example", fixture_addr.port()),
        )
        .await;
        assert_eq!(rep, socks5::Socks5Reply::Succeeded as u8);
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        cancel.cancel();
    }

    #[tokio::test]
    async fn socks5_direct_ip_policy_denial() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(base_policy(), resolver, socks_config());
        let (addr, cancel) = spawn_broker(broker).await;
        // Direct IPv4 8.8.8.8, not covered by any network grant, default deny.
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
        request.extend_from_slice(&443u16.to_be_bytes());
        let (rep, _stream) = socks_request(addr, &request).await;
        assert_eq!(rep, socks5::Socks5Reply::NotAllowed as u8);
        cancel.cancel();
    }

    #[tokio::test]
    async fn socks5_udp_associate_and_bind_are_command_not_supported() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(base_policy(), resolver, socks_config());
        let (addr, cancel) = spawn_broker(broker).await;
        for command in [0x03u8, 0x02u8] {
            // UDP ASSOCIATE, then BIND
            let mut request = vec![0x05, command, 0x00, 0x01];
            request.extend_from_slice(&Ipv4Addr::new(127, 0, 0, 1).octets());
            request.extend_from_slice(&53u16.to_be_bytes());
            let (rep, _stream) = socks_request(addr, &request).await;
            assert_eq!(
                rep,
                socks5::Socks5Reply::CommandNotSupported as u8,
                "command {command:#x} must be refused"
            );
        }
        cancel.cancel();
    }

    #[tokio::test]
    async fn socks5_malformed_and_oversized_domain_are_rejected() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(base_policy(), resolver, socks_config());
        let (addr, cancel) = spawn_broker(broker).await;
        // Invalid character in the domain -> normalization fails -> Malformed.
        let (rep_bad, _s1) = socks_request(addr, &socks_connect_domain("in valid_host", 443)).await;
        assert_eq!(rep_bad, socks5::Socks5Reply::GeneralFailure as u8);
        // Oversized domain (255 bytes) exceeds the 253-octet RFC 1035 limit.
        let oversized = "a".repeat(255);
        let (rep_big, _s2) = socks_request(addr, &socks_connect_domain(&oversized, 443)).await;
        assert_eq!(rep_big, socks5::Socks5Reply::GeneralFailure as u8);
        cancel.cancel();
    }

    #[tokio::test]
    async fn socks5_saturation_closes_new_connections() {
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
        let mut policy = base_policy();
        policy.max_connections = Some(1);
        let broker = broker_with(policy, resolver, socks_config());
        let (addr, cancel) = spawn_broker(broker).await;

        // Connection A holds the only permit with a live proxied session.
        let (rep_a, _held) = socks_request(
            addr,
            &socks_connect_domain("allowed.example", fixture_addr.port()),
        )
        .await;
        assert_eq!(rep_a, socks5::Socks5Reply::Succeeded as u8);

        // Connection B is rejected pre-handshake: the saturated broker closes
        // it without servicing it, so its read observes EOF/closure rather than
        // hanging.
        let mut conn_b = TcpStream::connect(addr).await.unwrap();
        let mut resp = [0u8; 2];
        let read = tokio::time::timeout(Duration::from_secs(2), conn_b.read(&mut resp))
            .await
            .expect("saturated broker must not hang");
        match read {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("saturated SOCKS broker unexpectedly served {n} bytes"),
        }
        cancel.cancel();
    }

    /// A fixture that reports the peer address of the connection it accepts —
    /// which is exactly the broker's upstream socket local endpoint — then
    /// echoes, so the proxied session stays healthy briefly.
    async fn spawn_peer_reporting_fixture()
    -> (SocketAddr, tokio::sync::oneshot::Receiver<SocketAddr>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut stream, peer)) = listener.accept().await {
                let _ = tx.send(peer);
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });
        (addr, rx)
    }

    /// Like [`socks_request`] but decodes and returns the reply's BND address
    /// and port as a [`SocketAddr`].
    async fn socks_request_capture_bound(addr: SocketAddr, request: &[u8]) -> (u8, SocketAddr) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        socks_negotiate(&mut stream).await;
        stream.write_all(request).await.unwrap();
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        let ip = match head[3] {
            0x01 => {
                let mut o = [0u8; 4];
                stream.read_exact(&mut o).await.unwrap();
                IpAddr::V4(Ipv4Addr::from(o))
            }
            0x04 => {
                let mut o = [0u8; 16];
                stream.read_exact(&mut o).await.unwrap();
                IpAddr::V6(Ipv6Addr::from(o))
            }
            other => panic!("unexpected SOCKS ATYP {other:#x}"),
        };
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.unwrap();
        (head[1], SocketAddr::new(ip, u16::from_be_bytes(port)))
    }

    #[tokio::test]
    async fn socks5_success_reply_reports_upstream_local_endpoint() {
        // RFC 1928 §6: the success reply's BND.ADDR/BND.PORT is the broker's own
        // socket endpoint toward the upstream, not the requested destination.
        let (fixture_addr, peer_rx) = spawn_peer_reporting_fixture().await;
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
        let broker = broker_with(base_policy(), resolver, socks_config());
        let (addr, cancel) = spawn_broker(broker).await;
        let (rep, bound) = socks_request_capture_bound(
            addr,
            &socks_connect_domain("allowed.example", fixture_addr.port()),
        )
        .await;
        assert_eq!(rep, socks5::Socks5Reply::Succeeded as u8);
        let upstream_local = peer_rx.await.expect("fixture must report accepted peer");
        assert_eq!(
            bound, upstream_local,
            "BND.ADDR/BND.PORT must be the broker's upstream socket local endpoint"
        );
        assert_ne!(
            bound, fixture_addr,
            "BND must not echo the requested destination back to the client"
        );
        cancel.cancel();
    }

    // ── DNS-guard / allow_dns on the CONNECT resolution path (fix A) ─────

    #[tokio::test]
    async fn hostname_connect_denied_when_dns_disabled_and_not_cached() {
        // With DNS disabled there is no DNS broker, so a hostname with no prior
        // cached authorization cannot be resolved by the CONNECT broker.
        let mut policy = base_policy();
        policy.allow_dns = false;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(policy, resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, _s) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::ResolutionFailed);
        cancel.cancel();
    }

    #[tokio::test]
    async fn hostname_connect_uses_prior_cache_when_dns_disabled() {
        let fixture_addr = spawn_echo_fixture().await;
        let mut policy = base_policy();
        policy.allow_dns = false;
        let resolver = Arc::new(StaticResolver::new());
        let (broker, cache) =
            broker_with_shared_cache(policy, resolver, ConnectBrokerConfig::default());
        // Simulate a prior authorization (as if from an earlier DNS answer).
        cache.authorize(
            "allowed.example",
            fixture_addr.ip(),
            Duration::from_secs(30),
        );
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, _s) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::Ok);
        cancel.cancel();
    }

    #[tokio::test]
    async fn fresh_resolution_structural_limit_is_enforced_and_audited() {
        let mut policy = base_policy();
        policy.allowed_domains = vec!["*.allowed.example".to_owned()];
        policy.dns.max_qname_octets = 25;
        let resolver = Arc::new(StaticResolver::new());
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(
            policy,
            resolver,
            ConnectBrokerConfig::default(),
            Arc::clone(&audit),
        );
        let (addr, cancel) = spawn_broker(broker).await;
        let long_host = format!("{}.allowed.example", "a".repeat(40));
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Hostname(long_host),
            expected_ip: None,
        };
        let (status, _s) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::PolicyDenied);
        assert!(
            audit
                .events()
                .iter()
                .any(|e| matches!(e, AuditEvent::DnsStructuralRejected { .. }))
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn fresh_resolution_honors_qtype_allowlist() {
        // Only A is allowed; a hostname that resolves solely to an AAAA must be
        // rejected because the AAAA record type is filtered out.
        let mut policy = base_policy();
        policy.allowed_networks = vec!["2001:db8::/32".to_owned()];
        policy.dns.allowed_record_types = vec![DnsRecordType::A];
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("allowed.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("allowed.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(policy, resolver, ConnectBrokerConfig::default());
        let (addr, cancel) = spawn_broker(broker).await;
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, _s) = send_request(addr, &request).await;
        assert_eq!(status, ConnectStatus::PolicyDenied);
        cancel.cancel();
    }

    #[tokio::test]
    async fn fresh_resolution_is_rate_limited_by_the_shared_budget() {
        let mut policy = base_policy();
        policy.allowed_domains = vec!["*.allowed.example".to_owned()];
        policy.dns.budget.max_queries = 1;
        let resolver = Arc::new(StaticResolver::new());
        for label in ["a", "b"] {
            resolver.set(
                Name::from_str(&format!("{label}.allowed.example.")).unwrap(),
                ResolvedChain {
                    cname_chain: vec![],
                    final_name: Name::from_str(&format!("{label}.allowed.example.")).unwrap(),
                    addresses: vec![ResolvedAddress {
                        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        ttl_secs: 30,
                    }],
                },
            );
        }
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(
            policy,
            resolver,
            ConnectBrokerConfig::default(),
            Arc::clone(&audit),
        );
        let (addr, cancel) = spawn_broker(broker).await;
        // First fresh resolution consumes the sole budgeted query.
        let first = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 9,
            target: ConnectTarget::Hostname("a.allowed.example".to_owned()),
            expected_ip: None,
        };
        let _ = send_request(addr, &first).await;
        // The second distinct name's fresh resolution is over budget.
        let second = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 9,
            target: ConnectTarget::Hostname("b.allowed.example".to_owned()),
            expected_ip: None,
        };
        let (status, _s) = send_request(addr, &second).await;
        assert_eq!(status, ConnectStatus::PolicyDenied);
        assert!(
            audit
                .events()
                .iter()
                .any(|e| matches!(e, AuditEvent::DnsRateLimited { .. }))
        );
        cancel.cancel();
    }
}
