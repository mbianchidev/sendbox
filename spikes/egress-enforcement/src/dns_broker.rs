//! DNS broker: binds loopback UDP and TCP DNS listeners, decodes/encodes
//! messages through `hickory-proto`, resolves through an injectable
//! [`UpstreamResolver`], validates every CNAME hop, the final owner name, and
//! every returned address against policy, caps TTLs, and records an
//! expiring `(normalized name, IpAddr)` authorization for each validated
//! address.
//!
//! Design notes:
//! - Bounded message sizes: oversized UDP datagrams and TCP length-prefixed
//!   messages are dropped without ever being parsed.
//! - Bounded concurrency: an in-flight query semaphore prevents unbounded
//!   task growth from a flood of datagrams/connections.
//! - Bounded timeouts: upstream resolution is wrapped in a timeout so a
//!   stalled/malicious injectable resolver cannot hang the broker
//!   (slowloris-style resource exhaustion).
//! - No panics: every parse/resolve/encode failure is converted into either
//!   a dropped datagram or a well-formed DNS error response.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::authorization::AuthorizationCache;
use crate::policy::PolicyEngine;
use crate::resolver::{ResolveError, UpstreamResolver};

/// Maximum UDP datagram accepted before it is even parsed. Chosen well above
/// the classic 512-byte limit to tolerate EDNS0-sized queries while staying
/// far below what would let a single datagram exhaust memory.
pub const MAX_UDP_MESSAGE_BYTES: usize = 4096;
/// Maximum length-prefixed TCP DNS message accepted (protocol maximum is
/// 65535; kept intentionally at the protocol ceiling since TCP already has
/// its own flow control).
pub const MAX_TCP_MESSAGE_BYTES: usize = 65535;

#[derive(Debug, Clone)]
pub struct DnsBrokerConfig {
    pub max_udp_message_bytes: usize,
    pub max_tcp_message_bytes: usize,
    pub upstream_timeout: Duration,
    pub max_concurrent_queries: usize,
}

impl Default for DnsBrokerConfig {
    fn default() -> Self {
        Self {
            max_udp_message_bytes: MAX_UDP_MESSAGE_BYTES,
            max_tcp_message_bytes: MAX_TCP_MESSAGE_BYTES,
            upstream_timeout: Duration::from_secs(5),
            max_concurrent_queries: 64,
        }
    }
}

pub struct DnsBroker<R: UpstreamResolver> {
    policy: Arc<PolicyEngine>,
    resolver: Arc<R>,
    authorizations: Arc<AuthorizationCache>,
    config: DnsBrokerConfig,
    in_flight: Arc<Semaphore>,
}

impl<R: UpstreamResolver + 'static> DnsBroker<R> {
    pub fn new(
        policy: Arc<PolicyEngine>,
        resolver: Arc<R>,
        authorizations: Arc<AuthorizationCache>,
        config: DnsBrokerConfig,
    ) -> Arc<Self> {
        let in_flight = Arc::new(Semaphore::new(config.max_concurrent_queries));
        Arc::new(Self {
            policy,
            resolver,
            authorizations,
            config,
            in_flight,
        })
    }

    pub fn authorizations(&self) -> &Arc<AuthorizationCache> {
        &self.authorizations
    }

    /// Handles one already length-bounded DNS message and returns the
    /// encoded response, or `None` if the input could not even be parsed as
    /// a DNS message header (in which case there is nothing safe to reply
    /// to, mirroring how a real resolver drops unparsable garbage).
    ///
    /// This function is intentionally permit-agnostic: the in-flight
    /// concurrency cap is enforced by the caller (`run_udp`/`run_tcp`)
    /// *before* the request bytes are even read off the socket, not here,
    /// so a saturated broker rejects/drops new work at accept/receive time
    /// instead of accepting unbounded reads and only gating CPU-bound
    /// processing afterward.
    pub async fn handle_message(&self, request_bytes: &[u8]) -> Option<Vec<u8>> {
        let request = match Message::from_vec(request_bytes) {
            Ok(message) => message,
            Err(_) => return None,
        };

        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
        {
            return Some(encode_error(&request, ResponseCode::NotImp));
        }
        if request.queries.len() != 1 {
            return Some(encode_error(&request, ResponseCode::FormErr));
        }
        let query = request.queries[0].clone();
        if !matches!(query.query_type(), RecordType::A | RecordType::AAAA) {
            return Some(encode_error(&request, ResponseCode::NotImp));
        }

        match self
            .resolve_and_validate(query.name(), query.query_type())
            .await
        {
            Ok((answers, ttl)) => Some(encode_answer(&request, query, answers, ttl)),
            Err(code) => Some(encode_error(&request, code)),
        }
    }

    async fn resolve_and_validate(
        &self,
        name: &Name,
        query_type: RecordType,
    ) -> Result<(Vec<(Name, RData)>, u32), ResponseCode> {
        let original = match crate::domain::normalize_domain(&name.to_utf8()) {
            Ok(normalized) => normalized,
            Err(_) => return Err(ResponseCode::FormErr),
        };
        match self.policy.evaluate_domain_name(&original) {
            Ok(true) => {}
            Ok(false) => return Err(ResponseCode::Refused),
            Err(_) => return Err(ResponseCode::FormErr),
        }

        let resolved =
            match timeout(self.config.upstream_timeout, self.resolver.resolve(name)).await {
                Ok(Ok(chain)) => chain,
                Ok(Err(ResolveError::NxDomain(_))) => return Err(ResponseCode::NXDomain),
                Ok(Err(_)) => return Err(ResponseCode::ServFail),
                Err(_) => return Err(ResponseCode::ServFail),
            };

        for hop in resolved.names_to_validate() {
            let hop_str = hop.to_utf8();
            match self.policy.evaluate_domain_name(&hop_str) {
                Ok(true) => {}
                Ok(false) => return Err(ResponseCode::Refused),
                Err(_) => return Err(ResponseCode::FormErr),
            }
        }

        // Canonicalize every returned address (collapsing an IPv4-mapped
        // IPv6 literal to plain IPv4) before it is filtered by query type,
        // validated, authorized, or encoded, so a resolver cannot cause an
        // address to dodge policy or land in the wrong answer section
        // purely through its wire representation.
        let canonical_addresses: Vec<_> = resolved
            .addresses
            .iter()
            .map(|addr| crate::resolver::ResolvedAddress {
                ip: crate::address::canonicalize(addr.ip),
                ttl_secs: addr.ttl_secs,
            })
            .collect();

        let matching_addresses: Vec<_> = canonical_addresses
            .iter()
            .filter(|addr| match query_type {
                RecordType::A => addr.ip.is_ipv4(),
                RecordType::AAAA => addr.ip.is_ipv6(),
                _ => false,
            })
            .collect();

        for addr in &matching_addresses {
            if !self.policy.address_permitted(addr.ip).allowed {
                return Err(ResponseCode::Refused);
            }
        }

        // NODATA vs NXDOMAIN (RFC 2308): the resolver already confirmed the
        // name exists (it did not return `ResolveError::NxDomain` above).
        // If it simply has no record of the requested type, that is
        // NOERROR with an empty answer section, not NXDOMAIN — the
        // `answers` built below is naturally empty (aside from any CNAME
        // hops already followed) in that case, and is returned as `Ok`.
        let ttl = matching_addresses
            .iter()
            .map(|a| a.ttl_secs)
            .min()
            .unwrap_or(0);
        let capped_ttl = self.policy.cap_ttl(ttl);

        for addr in &matching_addresses {
            self.authorizations.authorize(
                &original,
                addr.ip,
                Duration::from_secs(u64::from(capped_ttl)),
            );
        }

        // Build (owner, rdata) pairs so every CNAME record in a multi-hop
        // chain carries its own true owner name, e.g. for
        // `a -> b -> c -> A`, the answer section must read
        // `a CNAME b`, `b CNAME c`, `c A ...` — not three records all
        // owned by `a`.
        let mut answers: Vec<(Name, RData)> = Vec::new();
        let mut owners = vec![name.clone()];
        owners.extend(resolved.cname_chain.iter().cloned());
        let mut targets = resolved.cname_chain.clone();
        targets.push(resolved.final_name.clone());
        for (owner, target) in owners.iter().zip(targets.iter()) {
            if owner != target {
                answers.push((owner.clone(), RData::CNAME(CNAME(target.clone()))));
            }
        }
        let final_owner = resolved.final_name.clone();
        for addr in &matching_addresses {
            let rdata = match addr.ip {
                std::net::IpAddr::V4(v4) => RData::A(A(v4)),
                std::net::IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
            };
            answers.push((final_owner.clone(), rdata));
        }

        Ok((answers, capped_ttl))
    }

    /// Runs the UDP DNS listener loop until the socket is closed or an
    /// unrecoverable I/O error occurs. Each datagram is bounded; the
    /// in-flight permit is acquired *before* spawning a task for it, and a
    /// saturated broker simply drops the datagram (appropriate for UDP)
    /// rather than queueing unbounded work.
    pub async fn run_udp(self: Arc<Self>, socket: UdpSocket) -> io::Result<()> {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; self.config.max_udp_message_bytes + 1];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await?;
            if len > self.config.max_udp_message_bytes {
                // Oversized datagram: dropped without being parsed.
                continue;
            }
            let Ok(permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
                // Saturated: drop rather than accumulate unbounded tasks.
                continue;
            };
            let request = buf[..len].to_vec();
            let broker = Arc::clone(&self);
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                let _permit = permit;
                if let Some(response) = broker.handle_message(&request).await {
                    let _ = socket.send_to(&response, peer).await;
                }
            });
        }
    }

    /// Runs the TCP DNS listener loop. The in-flight permit is acquired
    /// *before* spawning any task to handle a newly accepted connection —
    /// exactly like [`Self::run_udp`] — so a saturated broker never spawns
    /// a full connection-handling task for a connection it's going to
    /// reject anyway; it just lets the accepted socket drop immediately
    /// (there is no DNS-level "connection limit exceeded" response to
    /// write back, unlike the CONNECT broker's status byte protocol, so a
    /// silent close is the correct, protocol-appropriate rejection here).
    pub async fn run_tcp(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, _peer) = listener.accept().await?;
            let Ok(permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
                // Saturated: drop the connection without spawning a task.
                continue;
            };
            let broker = Arc::clone(&self);
            tokio::spawn(async move {
                let _permit = permit;
                let _ = broker.handle_tcp_connection(stream).await;
            });
        }
    }

    /// Reads and answers one already permit-gated TCP DNS connection. Each
    /// read is bounded by `read_deadline` to defend against slowloris-style
    /// peers that open a connection and trickle bytes.
    async fn handle_tcp_connection(&self, mut stream: TcpStream) -> io::Result<()> {
        let read_deadline = Duration::from_secs(10);
        let mut len_buf = [0u8; 2];
        timeout(read_deadline, stream.read_exact(&mut len_buf)).await??;
        let message_len = u16::from_be_bytes(len_buf) as usize;
        if message_len == 0 || message_len > self.config.max_tcp_message_bytes {
            return Ok(());
        }
        let mut message_buf = vec![0u8; message_len];
        timeout(read_deadline, stream.read_exact(&mut message_buf)).await??;

        if let Some(response) = self.handle_message(&message_buf).await {
            let len = u16::try_from(response.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes();
            timeout(read_deadline, stream.write_all(&len)).await??;
            timeout(read_deadline, stream.write_all(&response)).await??;
        }
        Ok(())
    }
}

fn encode_answer(
    request: &Message,
    query: Query,
    answers: Vec<(Name, RData)>,
    ttl: u32,
) -> Vec<u8> {
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NoError;
    response.add_query(query);
    for (owner, rdata) in answers {
        response.add_answer(Record::from_rdata(owner, ttl, rdata));
    }
    response.to_vec().unwrap_or_default()
}

fn encode_error(request: &Message, code: ResponseCode) -> Vec<u8> {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    for query in &request.queries {
        response.add_query(query.clone());
    }
    response.to_vec().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_resolver::StaticResolver;
    use crate::policy::{Action, NetworkPolicy};
    use crate::resolver::{ResolvedAddress, ResolvedChain};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    /// Delegates to an inner resolver after an artificial delay, so tests
    /// can deterministically hold the in-flight permit long enough to
    /// observe saturation behavior in a concurrent peer.
    struct DelayedResolver {
        inner: Arc<StaticResolver>,
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl UpstreamResolver for DelayedResolver {
        async fn resolve(
            &self,
            name: &Name,
        ) -> Result<crate::resolver::ResolvedChain, ResolveError> {
            tokio::time::sleep(self.delay).await;
            self.inner.resolve(name).await
        }
    }

    fn engine(mut policy: NetworkPolicy) -> Arc<PolicyEngine> {
        policy.max_concurrent_connections = 4;
        policy.max_dns_ttl_secs = if policy.max_dns_ttl_secs == 0 {
            30
        } else {
            policy.max_dns_ttl_secs
        };
        Arc::new(PolicyEngine::compile(&policy).unwrap())
    }

    fn allow_all_policy() -> NetworkPolicy {
        NetworkPolicy {
            default_action: Action::Allow,
            allowed_domains: vec![],
            blocked_domains: vec![],
            allowed_networks: vec![],
            blocked_networks: vec![],
            allowed_ports: vec![],
            max_concurrent_connections: 4,
            max_dns_ttl_secs: 30,
        }
    }

    fn broker_with(
        policy: NetworkPolicy,
        resolver: Arc<StaticResolver>,
    ) -> Arc<DnsBroker<StaticResolver>> {
        DnsBroker::new(
            engine(policy),
            resolver,
            Arc::new(AuthorizationCache::new()),
            DnsBrokerConfig::default(),
        )
    }

    fn query_bytes(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new(42, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
        message.to_vec().unwrap()
    }

    #[tokio::test]
    async fn resolves_and_authorizes_allowed_domain() {
        let resolver = Arc::new(StaticResolver::new());
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        resolver.set(
            Name::from_str("example.com.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("example.com.").unwrap(),
                addresses: vec![ResolvedAddress { ip, ttl_secs: 30 }],
            },
        );
        let broker = broker_with(allow_all_policy(), resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("example.com.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert!(broker.authorizations().is_authorized("example.com", ip));
    }

    #[tokio::test]
    async fn blocked_domain_is_refused_and_not_authorized() {
        let resolver = Arc::new(StaticResolver::new());
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        resolver.set(
            Name::from_str("evil.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("evil.example.").unwrap(),
                addresses: vec![ResolvedAddress { ip, ttl_secs: 30 }],
            },
        );
        let mut policy = allow_all_policy();
        policy.blocked_domains.push("evil.example".to_owned());
        let broker = broker_with(policy, resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("evil.example.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert!(!broker.authorizations().is_authorized("evil.example", ip));
    }

    #[tokio::test]
    async fn cname_hop_to_blocked_domain_is_refused() {
        let resolver = Arc::new(StaticResolver::new());
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        resolver.set(
            Name::from_str("good.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![Name::from_str("evil.example.").unwrap()],
                final_name: Name::from_str("evil.example.").unwrap(),
                addresses: vec![ResolvedAddress { ip, ttl_secs: 30 }],
            },
        );
        let mut policy = allow_all_policy();
        policy.blocked_domains.push("evil.example".to_owned());
        let broker = broker_with(policy, resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("good.example.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    }

    #[tokio::test]
    async fn rebinding_to_loopback_via_cname_is_refused() {
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("good.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("good.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(allow_all_policy(), resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("good.example.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    }

    #[tokio::test]
    async fn special_ranges_are_refused_via_direct_answers() {
        let addresses = [
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), // metadata
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),        // rfc1918
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),       // multicast
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)), // ULA
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), // link-local
        ];
        for ip in addresses {
            let resolver = Arc::new(StaticResolver::new());
            resolver.set(
                Name::from_str("good.example.").unwrap(),
                ResolvedChain {
                    cname_chain: vec![],
                    final_name: Name::from_str("good.example.").unwrap(),
                    addresses: vec![ResolvedAddress { ip, ttl_secs: 30 }],
                },
            );
            let broker = broker_with(allow_all_policy(), resolver);
            let record_type = if ip.is_ipv4() {
                RecordType::A
            } else {
                RecordType::AAAA
            };
            let response_bytes = broker
                .handle_message(&query_bytes("good.example.", record_type))
                .await
                .expect("response");
            let response = Message::from_vec(&response_bytes).unwrap();
            assert_eq!(
                response.metadata.response_code,
                ResponseCode::Refused,
                "expected {ip} refused"
            );
        }
    }

    #[tokio::test]
    async fn ttl_is_capped_before_authorization() {
        let resolver = Arc::new(StaticResolver::new());
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        resolver.set(
            Name::from_str("example.com.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("example.com.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip,
                    ttl_secs: 999_999,
                }],
            },
        );
        let mut policy = allow_all_policy();
        policy.max_dns_ttl_secs = 5;
        let broker = broker_with(policy, resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("example.com.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.answers[0].ttl, 5);
    }

    #[tokio::test]
    async fn nxdomain_upstream_is_reported_as_nxdomain() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(allow_all_policy(), resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("missing.example.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn malformed_bytes_are_dropped_without_panic() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(allow_all_policy(), resolver);
        let garbage = vec![0xffu8; 10];
        assert!(broker.handle_message(&garbage).await.is_none());
    }

    #[tokio::test]
    async fn oversized_udp_datagram_is_never_parsed() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(allow_all_policy(), resolver);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(Arc::clone(&broker).run_udp(socket));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let oversized = vec![0u8; broker.config.max_udp_message_bytes + 100];
        client.send_to(&oversized, local_addr).await.unwrap();

        // A well-formed follow-up query must still be served, proving the
        // oversized datagram did not wedge or crash the broker.
        let good_query = query_bytes("example.com.", RecordType::A);
        client.send_to(&good_query, local_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let response = Message::from_vec(&buf[..len]).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        handle.abort();
    }

    #[tokio::test]
    async fn multiple_questions_are_form_error() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(allow_all_policy(), resolver);
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str("a.example.").unwrap(),
            RecordType::A,
        ));
        message.add_query(Query::query(
            Name::from_str("b.example.").unwrap(),
            RecordType::A,
        ));
        let bytes = message.to_vec().unwrap();
        let response_bytes = broker.handle_message(&bytes).await.expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn nodata_is_noerror_with_empty_answers_not_nxdomain() {
        // The resolver confirms the name exists (it returns `Ok`, not
        // `ResolveError::NxDomain`) but only has an AAAA address; an A
        // query must be NOERROR with an empty answer section (NODATA per
        // RFC 2308), not NXDOMAIN.
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("v6-only.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("v6-only.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(allow_all_policy(), resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("v6-only.example.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn multi_hop_cname_chain_preserves_each_record_owner() {
        let resolver = Arc::new(StaticResolver::new());
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        resolver.set(
            Name::from_str("a.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![
                    Name::from_str("b.example.").unwrap(),
                    Name::from_str("c.example.").unwrap(),
                ],
                final_name: Name::from_str("d.example.").unwrap(),
                addresses: vec![ResolvedAddress { ip, ttl_secs: 30 }],
            },
        );
        let broker = broker_with(allow_all_policy(), resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("a.example.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 4);

        let owners: Vec<String> = response.answers.iter().map(|r| r.name.to_utf8()).collect();
        assert_eq!(
            owners,
            vec![
                "a.example.".to_owned(),
                "b.example.".to_owned(),
                "c.example.".to_owned(),
                "d.example.".to_owned(),
            ]
        );
        assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(response.answers[1].record_type(), RecordType::CNAME);
        assert_eq!(response.answers[2].record_type(), RecordType::CNAME);
        assert_eq!(response.answers[3].record_type(), RecordType::A);
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_answer_is_canonicalized_and_matches_a_query() {
        // A misbehaving/malicious injectable resolver returns the address
        // as an IPv4-mapped IPv6 literal; it must still be recognized and
        // answered as an A record after canonicalization, not silently
        // dropped as a query-type mismatch.
        let resolver = Arc::new(StaticResolver::new());
        let v4 = Ipv4Addr::new(203, 0, 113, 9);
        resolver.set(
            Name::from_str("mapped.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("mapped.example.").unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: IpAddr::V6(v4.to_ipv6_mapped()),
                    ttl_secs: 30,
                }],
            },
        );
        let broker = broker_with(allow_all_policy(), resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("mapped.example.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::A);
        assert!(
            broker
                .authorizations()
                .is_authorized("mapped.example", IpAddr::V4(v4))
        );
    }

    #[tokio::test]
    async fn saturated_tcp_capacity_rejects_new_connections_without_reading() {
        let resolver = Arc::new(StaticResolver::new());
        let config = DnsBrokerConfig {
            max_concurrent_queries: 1,
            ..DnsBrokerConfig::default()
        };
        let broker = DnsBroker::new(
            engine(allow_all_policy()),
            resolver,
            Arc::new(AuthorizationCache::new()),
            config,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(Arc::clone(&broker).run_tcp(listener));

        // Connection A occupies the sole in-flight permit by connecting and
        // never sending a complete length prefix, so `handle_tcp_connection`
        // stays parked in its bounded read waiting for more bytes.
        let _conn_a = TcpStream::connect(local_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Connection B must be rejected (closed immediately) because the
        // permit is acquired *before* any read; the server must never
        // attempt to read from B while saturated.
        let mut conn_b = TcpStream::connect(local_addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), conn_b.read(&mut buf))
            .await
            .expect("saturated broker must not hang; it must close immediately")
            .unwrap();
        assert_eq!(
            read, 0,
            "saturated broker must close the connection (EOF) rather than read/respond"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn saturated_udp_capacity_drops_rather_than_queues_datagrams() {
        let inner = Arc::new(StaticResolver::new());
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        inner.set(
            Name::from_str("example.com.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("example.com.").unwrap(),
                addresses: vec![ResolvedAddress { ip, ttl_secs: 30 }],
            },
        );
        let delay = Duration::from_millis(300);
        let resolver = Arc::new(DelayedResolver { inner, delay });
        let config = DnsBrokerConfig {
            max_concurrent_queries: 1,
            ..DnsBrokerConfig::default()
        };
        let broker = DnsBroker::new(
            engine(allow_all_policy()),
            resolver,
            Arc::new(AuthorizationCache::new()),
            config,
        );
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(Arc::clone(&broker).run_udp(socket));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = query_bytes("example.com.", RecordType::A);

        // First datagram occupies the sole permit for `delay`.
        client.send_to(&query, local_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Second datagram arrives while saturated; it must be dropped, not
        // queued for later processing once the permit frees up.
        client.send_to(&query, local_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let response = Message::from_vec(&buf[..len]).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);

        // If the second datagram had been queued instead of dropped, it
        // would be processed right after the first permit is released and
        // a second reply would arrive within roughly another `delay`.
        let second = tokio::time::timeout(
            delay + Duration::from_millis(300),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(
            second.is_err(),
            "a saturated datagram must be dropped, not eventually answered"
        );

        handle.abort();
    }
}
