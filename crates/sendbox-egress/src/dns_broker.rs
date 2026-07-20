//! DNS broker: binds loopback UDP and TCP DNS listeners, decodes/encodes
//! messages through `hickory-proto`, resolves through an injectable
//! [`UpstreamResolver`], validates every CNAME hop, the final owner name, and
//! every returned address against policy, enforces deterministic
//! query-exfiltration controls, caps TTLs, bounds the response size, and
//! records an expiring `(normalized name, IpAddr)` authorization for each
//! validated address. Every decision emits a typed [`AuditEvent`].
//!
//! Design notes:
//! - Bounded message sizes: oversized UDP datagrams and TCP length-prefixed
//!   messages are dropped without ever being parsed.
//! - Bounded concurrency: an in-flight query semaphore prevents unbounded
//!   task growth from a flood of datagrams/connections.
//! - Bounded timeouts: upstream resolution is wrapped in a timeout so a
//!   stalled/malicious resolver cannot hang the broker.
//! - Cancellation: the listener loops and their spawned handlers stop cleanly
//!   when the shared [`CancellationToken`] fires.
//! - No panics: every parse/resolve/encode failure is converted into either a
//!   dropped datagram or a well-formed DNS error response.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sendbox_policy::DnsRecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditEvent, AuditSink};
use crate::authorization::AuthorizationCache;
use crate::dns_budget::DnsGuard;
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
    guard: Arc<DnsGuard>,
    audit: Arc<dyn AuditSink>,
    config: DnsBrokerConfig,
    in_flight: Arc<Semaphore>,
}

/// Internal outcome of validating one query, so `handle_message` can emit the
/// right audit event alongside the encoded response.
enum QueryOutcome {
    Answered {
        answers: Vec<(Name, RData)>,
        ttl: u32,
        answer_count: usize,
        qtype: &'static str,
    },
    Denied {
        code: ResponseCode,
        reason: &'static str,
    },
}

impl<R: UpstreamResolver + 'static> DnsBroker<R> {
    #[must_use]
    pub fn new(
        policy: Arc<PolicyEngine>,
        resolver: Arc<R>,
        authorizations: Arc<AuthorizationCache>,
        guard: Arc<DnsGuard>,
        audit: Arc<dyn AuditSink>,
        config: DnsBrokerConfig,
    ) -> Arc<Self> {
        let in_flight = Arc::new(Semaphore::new(config.max_concurrent_queries));
        Arc::new(Self {
            policy,
            resolver,
            authorizations,
            guard,
            audit,
            config,
            in_flight,
        })
    }

    #[must_use]
    pub fn authorizations(&self) -> &Arc<AuthorizationCache> {
        &self.authorizations
    }

    /// Handles one already length-bounded DNS message and returns the encoded
    /// response, or `None` if the input could not even be parsed as a DNS
    /// message header (in which case there is nothing safe to reply to). The
    /// in-flight concurrency cap is enforced by the caller before the request
    /// bytes are even read off the socket.
    pub async fn handle_message(&self, request_bytes: &[u8]) -> Option<Vec<u8>> {
        let request = match Message::from_vec(request_bytes) {
            Ok(message) => message,
            Err(_) => {
                self.audit.record(AuditEvent::DnsMalformed);
                return None;
            }
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

        let qtype = match record_type_of(query.query_type()) {
            Some(record_type) if self.guard.record_type_allowed(record_type) => record_type,
            _ => {
                self.audit.record(AuditEvent::DnsUnsupportedQtype {
                    name: query.name().to_utf8(),
                    qtype: record_type_name(query.query_type()),
                });
                return Some(encode_error(&request, ResponseCode::NotImp));
            }
        };

        match self.resolve_and_validate(query.name(), qtype).await {
            QueryOutcome::Answered {
                answers,
                ttl,
                answer_count,
                qtype,
            } => {
                self.audit.record(AuditEvent::DnsAllowed {
                    name: query.name().to_utf8(),
                    qtype,
                    answers: answer_count,
                    ttl_secs: ttl,
                });
                Some(encode_answer(&request, query, answers, ttl))
            }
            QueryOutcome::Denied { code, reason } => {
                self.audit.record(AuditEvent::DnsDenied {
                    name: query.name().to_utf8(),
                    response_code: response_code_name(code),
                    reason,
                });
                Some(encode_error(&request, code))
            }
        }
    }

    async fn resolve_and_validate(&self, name: &Name, qtype: DnsRecordType) -> QueryOutcome {
        let original = match crate::domain::normalize_domain(&name.to_utf8()) {
            Ok(normalized) => normalized,
            Err(_) => {
                return QueryOutcome::Denied {
                    code: ResponseCode::FormErr,
                    reason: "qname failed normalization",
                };
            }
        };

        // Structural query-name limits (bounded, stateless) before anything
        // else. A refusal here also emits a structural-rejection audit event.
        if let Err(limit) = self.guard.check_structure(&original) {
            self.audit.record(AuditEvent::DnsStructuralRejected {
                name: original.clone(),
                limit,
            });
            return QueryOutcome::Denied {
                code: ResponseCode::Refused,
                reason: "qname violates a structural limit",
            };
        }

        match self.policy.evaluate_domain_name(&original) {
            Ok(true) => {}
            Ok(false) => {
                return QueryOutcome::Denied {
                    code: ResponseCode::Refused,
                    reason: "qname denied by domain policy",
                };
            }
            Err(_) => {
                return QueryOutcome::Denied {
                    code: ResponseCode::FormErr,
                    reason: "qname failed normalization",
                };
            }
        }

        // Only domain-allowed queries reach the upstream, so only they can
        // exfiltrate; the deterministic budget is charged here.
        if let Err(limit) = self.guard.admit(&original, Instant::now()) {
            self.audit.record(AuditEvent::DnsRateLimited {
                name: original.clone(),
                limit,
            });
            return QueryOutcome::Denied {
                code: ResponseCode::Refused,
                reason: "query exfiltration budget exceeded",
            };
        }

        let resolved =
            match timeout(self.config.upstream_timeout, self.resolver.resolve(name)).await {
                Ok(Ok(chain)) => chain,
                Ok(Err(ResolveError::NxDomain(_))) => {
                    return QueryOutcome::Denied {
                        code: ResponseCode::NXDomain,
                        reason: "upstream reports nxdomain",
                    };
                }
                Ok(Err(_)) | Err(_) => {
                    return QueryOutcome::Denied {
                        code: ResponseCode::ServFail,
                        reason: "upstream resolution failed",
                    };
                }
            };

        for hop in resolved.names_to_validate() {
            let hop_str = hop.to_utf8();
            match self.policy.evaluate_domain_name(&hop_str) {
                Ok(true) => {}
                Ok(false) => {
                    return QueryOutcome::Denied {
                        code: ResponseCode::Refused,
                        reason: "cname hop or owner denied by domain policy",
                    };
                }
                Err(_) => {
                    return QueryOutcome::Denied {
                        code: ResponseCode::FormErr,
                        reason: "cname hop failed normalization",
                    };
                }
            }
        }

        // Canonicalize every returned address before it is filtered by query
        // type, validated, authorized, or encoded.
        let canonical_addresses: Vec<_> = resolved
            .addresses
            .iter()
            .map(|addr| crate::resolver::ResolvedAddress {
                ip: crate::address::canonicalize(addr.ip),
                ttl_secs: addr.ttl_secs,
            })
            .collect();

        let want_ipv4 = matches!(qtype, DnsRecordType::A);
        let mut matching_addresses: Vec<_> = canonical_addresses
            .iter()
            .filter(|addr| addr.ip.is_ipv4() == want_ipv4)
            .copied()
            .collect();

        for addr in &matching_addresses {
            if !self.policy.address_permitted(addr.ip).allowed {
                return QueryOutcome::Denied {
                    code: ResponseCode::Refused,
                    reason: "resolved address is restricted by policy",
                };
            }
        }

        // Response-size limit: never emit more address records than the
        // policy permits. Truncating deterministically bounds amplification.
        if matching_addresses.len() > self.guard.max_response_records() {
            matching_addresses.truncate(self.guard.max_response_records());
        }

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
        // chain carries its own true owner name.
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
        let answer_count = matching_addresses.len();
        for addr in &matching_addresses {
            let rdata = match addr.ip {
                std::net::IpAddr::V4(v4) => RData::A(A(v4)),
                std::net::IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
            };
            answers.push((final_owner.clone(), rdata));
        }

        QueryOutcome::Answered {
            answers,
            ttl: capped_ttl,
            answer_count,
            qtype: dns_record_type_name(qtype),
        }
    }

    /// Runs the UDP DNS listener loop until cancelled, the socket closes, or
    /// an unrecoverable I/O error occurs. Each datagram is bounded; the
    /// in-flight permit is acquired before spawning a task, and a saturated
    /// broker drops the datagram (appropriate for UDP).
    pub async fn run_udp(
        self: Arc<Self>,
        socket: UdpSocket,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; self.config.max_udp_message_bytes + 1];
        loop {
            let (len, peer) = tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(()),
                result = socket.recv_from(&mut buf) => result?,
            };
            if len > self.config.max_udp_message_bytes {
                continue;
            }
            let Ok(permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
                continue;
            };
            let request = buf[..len].to_vec();
            let broker = Arc::clone(&self);
            let socket = Arc::clone(&socket);
            let task_cancel = cancel.clone();
            tokio::spawn(async move {
                let _permit = permit;
                tokio::select! {
                    biased;
                    () = task_cancel.cancelled() => {}
                    response = broker.handle_message(&request) => {
                        if let Some(response) = response {
                            let _ = socket.send_to(&response, peer).await;
                        }
                    }
                }
            });
        }
    }

    /// Runs the TCP DNS listener loop until cancelled. The in-flight permit is
    /// acquired before spawning any task; a saturated broker drops the
    /// connection.
    pub async fn run_tcp(
        self: Arc<Self>,
        listener: TcpListener,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        loop {
            let (stream, _peer) = tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(()),
                result = listener.accept() => result?,
            };
            let Ok(permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
                continue;
            };
            let broker = Arc::clone(&self);
            let task_cancel = cancel.clone();
            tokio::spawn(async move {
                let _permit = permit;
                tokio::select! {
                    biased;
                    () = task_cancel.cancelled() => {}
                    result = broker.handle_tcp_connection(stream) => {
                        let _ = result;
                    }
                }
            });
        }
    }

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

fn record_type_of(record_type: RecordType) -> Option<DnsRecordType> {
    match record_type {
        RecordType::A => Some(DnsRecordType::A),
        RecordType::AAAA => Some(DnsRecordType::Aaaa),
        _ => None,
    }
}

fn dns_record_type_name(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::Aaaa => "AAAA",
    }
}

fn record_type_name(record_type: RecordType) -> &'static str {
    match record_type {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::TXT => "TXT",
        RecordType::MX => "MX",
        RecordType::NS => "NS",
        RecordType::SOA => "SOA",
        RecordType::SRV => "SRV",
        RecordType::PTR => "PTR",
        _ => "other",
    }
}

fn response_code_name(code: ResponseCode) -> &'static str {
    match code {
        ResponseCode::NoError => "noerror",
        ResponseCode::FormErr => "formerr",
        ResponseCode::ServFail => "servfail",
        ResponseCode::NXDomain => "nxdomain",
        ResponseCode::NotImp => "notimp",
        ResponseCode::Refused => "refused",
        _ => "other",
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
    use crate::audit::{CollectingAuditSink, NullAuditSink};
    use crate::fixture_resolver::StaticResolver;
    use crate::resolver::{ResolvedAddress, ResolvedChain};
    use sendbox_policy::{Action, DnsPolicy, NetworkPolicy};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

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

    fn engine(policy: NetworkPolicy) -> Arc<PolicyEngine> {
        Arc::new(PolicyEngine::compile(&policy).unwrap())
    }

    fn allow_all_policy() -> NetworkPolicy {
        NetworkPolicy {
            default_action: Action::Allow,
            allowed_domains: vec![],
            blocked_domains: vec![],
            allow_dns: true,
            max_connections: Some(4),
            allowed_networks: vec![],
            blocked_networks: vec![],
            allowed_ports: vec![],
            dns: DnsPolicy {
                max_ttl_secs: 30,
                ..DnsPolicy::default()
            },
        }
    }

    fn broker_with(
        policy: NetworkPolicy,
        resolver: Arc<StaticResolver>,
    ) -> Arc<DnsBroker<StaticResolver>> {
        let guard = Arc::new(DnsGuard::from_policy(&policy.dns));
        DnsBroker::new(
            engine(policy),
            resolver,
            Arc::new(AuthorizationCache::new()),
            guard,
            Arc::new(NullAuditSink),
            DnsBrokerConfig::default(),
        )
    }

    fn broker_with_audit(
        policy: NetworkPolicy,
        resolver: Arc<StaticResolver>,
        audit: Arc<CollectingAuditSink>,
    ) -> Arc<DnsBroker<StaticResolver>> {
        let guard = Arc::new(DnsGuard::from_policy(&policy.dns));
        DnsBroker::new(
            engine(policy),
            resolver,
            Arc::new(AuthorizationCache::new()),
            guard,
            audit,
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
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(allow_all_policy(), resolver, Arc::clone(&audit));
        let response_bytes = broker
            .handle_message(&query_bytes("example.com.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert!(broker.authorizations().is_authorized("example.com", ip));
        assert!(matches!(
            audit.events().first(),
            Some(AuditEvent::DnsAllowed { .. })
        ));
    }

    #[tokio::test]
    async fn blocked_domain_is_refused_and_audited() {
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
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(policy, resolver, Arc::clone(&audit));
        let response_bytes = broker
            .handle_message(&query_bytes("evil.example.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert!(!broker.authorizations().is_authorized("evil.example", ip));
        assert!(matches!(
            audit.events().first(),
            Some(AuditEvent::DnsDenied { .. })
        ));
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
    async fn rebinding_to_loopback_via_answer_is_refused() {
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
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
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
        policy.dns.max_ttl_secs = 5;
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
    async fn malformed_bytes_are_dropped_and_audited() {
        let resolver = Arc::new(StaticResolver::new());
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(allow_all_policy(), resolver, Arc::clone(&audit));
        let garbage = vec![0xffu8; 10];
        assert!(broker.handle_message(&garbage).await.is_none());
        assert!(audit.events().contains(&AuditEvent::DnsMalformed));
    }

    #[tokio::test]
    async fn unsupported_qtype_is_notimp_and_audited() {
        let resolver = Arc::new(StaticResolver::new());
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(allow_all_policy(), resolver, Arc::clone(&audit));
        let response_bytes = broker
            .handle_message(&query_bytes("example.com.", RecordType::TXT))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
        assert!(matches!(
            audit.events().first(),
            Some(AuditEvent::DnsUnsupportedQtype { .. })
        ));
    }

    #[tokio::test]
    async fn qtype_outside_allowlist_is_refused() {
        // Restrict the allowlist to A only; an AAAA query must be NotImp.
        let mut policy = allow_all_policy();
        policy.dns.allowed_record_types = vec![DnsRecordType::A];
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(policy, resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("example.com.", RecordType::AAAA))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
    }

    #[tokio::test]
    async fn oversized_qname_is_refused_and_audited() {
        let mut policy = allow_all_policy();
        policy.dns.max_qname_octets = 20;
        let resolver = Arc::new(StaticResolver::new());
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(policy, resolver, Arc::clone(&audit));
        let long = format!("{}.example.com.", "a".repeat(40));
        let response_bytes = broker
            .handle_message(&query_bytes(&long, RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert!(matches!(
            audit.events().first(),
            Some(AuditEvent::DnsStructuralRejected { .. })
        ));
    }

    #[tokio::test]
    async fn dns_query_budget_rate_limits_and_audits() {
        let mut policy = allow_all_policy();
        policy.dns.budget.max_queries = 1;
        let resolver = Arc::new(StaticResolver::new());
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        resolver.set(
            Name::from_str("a.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("a.example.").unwrap(),
                addresses: vec![ResolvedAddress { ip, ttl_secs: 30 }],
            },
        );
        resolver.set(
            Name::from_str("b.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("b.example.").unwrap(),
                addresses: vec![ResolvedAddress { ip, ttl_secs: 30 }],
            },
        );
        let audit = Arc::new(CollectingAuditSink::new());
        let broker = broker_with_audit(policy, resolver, Arc::clone(&audit));
        let first = broker
            .handle_message(&query_bytes("a.example.", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            Message::from_vec(&first).unwrap().metadata.response_code,
            ResponseCode::NoError
        );
        let second = broker
            .handle_message(&query_bytes("b.example.", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            Message::from_vec(&second).unwrap().metadata.response_code,
            ResponseCode::Refused
        );
        assert!(
            audit
                .events()
                .iter()
                .any(|e| matches!(e, AuditEvent::DnsRateLimited { .. }))
        );
    }

    #[tokio::test]
    async fn response_record_cap_truncates_answer_section() {
        let mut policy = allow_all_policy();
        policy.dns.max_response_records = 1;
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_str("multi.example.").unwrap(),
            ResolvedChain {
                cname_chain: vec![],
                final_name: Name::from_str("multi.example.").unwrap(),
                addresses: vec![
                    ResolvedAddress {
                        ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        ttl_secs: 30,
                    },
                    ResolvedAddress {
                        ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)),
                        ttl_secs: 30,
                    },
                    ResolvedAddress {
                        ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 36)),
                        ttl_secs: 30,
                    },
                ],
            },
        );
        let broker = broker_with(policy, resolver);
        let response_bytes = broker
            .handle_message(&query_bytes("multi.example.", RecordType::A))
            .await
            .expect("response");
        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.answers.len(), 1);
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
        assert_eq!(response.answers[3].record_type(), RecordType::A);
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_answer_is_canonicalized_and_matches_a_query() {
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
        assert!(
            broker
                .authorizations()
                .is_authorized("mapped.example", IpAddr::V4(v4))
        );
    }

    #[tokio::test]
    async fn oversized_udp_datagram_is_never_parsed() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(allow_all_policy(), resolver);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(Arc::clone(&broker).run_udp(socket, cancel.clone()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let oversized = vec![0u8; broker.config.max_udp_message_bytes + 100];
        client.send_to(&oversized, local_addr).await.unwrap();

        let good_query = query_bytes("example.com.", RecordType::A);
        client.send_to(&good_query, local_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let response = Message::from_vec(&buf[..len]).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn cancellation_stops_udp_listener_loop() {
        let resolver = Arc::new(StaticResolver::new());
        let broker = broker_with(allow_all_policy(), resolver);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(Arc::clone(&broker).run_udp(socket, cancel.clone()));
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(matches!(result, Ok(Ok(Ok(())))));
    }

    #[tokio::test]
    async fn saturated_tcp_capacity_rejects_new_connections_without_reading() {
        let resolver = Arc::new(StaticResolver::new());
        let guard = Arc::new(DnsGuard::from_policy(&allow_all_policy().dns));
        let config = DnsBrokerConfig {
            max_concurrent_queries: 1,
            ..DnsBrokerConfig::default()
        };
        let broker = DnsBroker::new(
            engine(allow_all_policy()),
            resolver,
            Arc::new(AuthorizationCache::new()),
            guard,
            Arc::new(NullAuditSink),
            config,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(Arc::clone(&broker).run_tcp(listener, cancel.clone()));

        let _conn_a = TcpStream::connect(local_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut conn_b = TcpStream::connect(local_addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), conn_b.read(&mut buf))
            .await
            .expect("saturated broker must not hang; it must close immediately")
            .unwrap();
        assert_eq!(read, 0);

        cancel.cancel();
        let _ = handle.await;
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
        let guard = Arc::new(DnsGuard::from_policy(&allow_all_policy().dns));
        let config = DnsBrokerConfig {
            max_concurrent_queries: 1,
            ..DnsBrokerConfig::default()
        };
        let broker = DnsBroker::new(
            engine(allow_all_policy()),
            resolver,
            Arc::new(AuthorizationCache::new()),
            guard,
            Arc::new(NullAuditSink),
            config,
        );
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(Arc::clone(&broker).run_udp(socket, cancel.clone()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = query_bytes("example.com.", RecordType::A);

        client.send_to(&query, local_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.send_to(&query, local_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let response = Message::from_vec(&buf[..len]).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);

        let second = tokio::time::timeout(
            delay + Duration::from_millis(300),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(second.is_err());

        cancel.cancel();
        let _ = handle.await;
    }
}
