//! Bounded, fixed-upstream forwarding DNS resolver.
//!
//! [`ForwardingResolver`] is the production [`UpstreamResolver`]. It dials one
//! fixed upstream [`SocketAddr`] directly — it never re-resolves a hostname
//! through the OS resolver, so the enforced destination can never drift out
//! from under policy. Every response is bounded and validated:
//!
//! * The response header ID must equal the query ID, and the echoed question
//!   must match the query name and type; otherwise the answer is rejected.
//! * A query is sent over UDP first; if the response has the truncation bit
//!   set it is retried once over TCP.
//! * A missing UDP reply is retransmitted once on the same socket, halfway
//!   through the query budget. Retransmission never restarts that budget.
//! * The CNAME chain is followed only within the single returned message, to a
//!   bounded depth, with loop detection.
//! * The number of address records is capped.
//! * One per-query deadline bounds socket setup, both UDP attempts and any
//!   TCP fallback (the broker additionally bounds the whole `resolve` call).
//!
//! A and AAAA are queried concurrently and merged, since the
//! [`UpstreamResolver`] contract returns a name's full address set and the
//! broker filters by QTYPE afterward.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use sendbox_policy::DnsRecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use crate::resolver::{
    DnsOperation, DnsTransport, ResolveError, ResolvedAddress, ResolvedChain, UpstreamResolver,
};

/// Maximum CNAME hops followed within a single response before the chain is
/// rejected as abusive/looping.
pub const MAX_CNAME_DEPTH: usize = 16;
/// Maximum address records accepted from a single response.
pub const MAX_ADDRESS_RECORDS: usize = 64;
/// Maximum UDP response accepted before parsing.
pub const MAX_UDP_RESPONSE_BYTES: usize = 4096;
/// Maximum length-prefixed TCP response accepted.
pub const MAX_TCP_RESPONSE_BYTES: usize = 65535;

#[derive(Debug, Clone)]
pub struct ForwardingResolverConfig {
    /// Fixed upstream resolver address. Dialed directly; never re-resolved.
    pub upstream: SocketAddr,
    /// Total budget per QTYPE, including one UDP retransmission and TCP fallback.
    pub query_timeout: Duration,
    /// Optional `SO_MARK` applied to every upstream socket. In a Linux
    /// enforcement topology this is the broker mark, so the DNS broker's own
    /// upstream queries satisfy the same `socket cgroupv2 + meta mark` rule as
    /// the CONNECT broker's dials.
    pub socket_mark: Option<u32>,
}

impl ForwardingResolverConfig {
    #[must_use]
    pub fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            query_timeout: Duration::from_secs(3),
            socket_mark: None,
        }
    }

    /// Sets the `SO_MARK` applied to every upstream socket.
    #[must_use]
    pub fn with_socket_mark(mut self, mark: u32) -> Self {
        self.socket_mark = Some(mark);
        self
    }
}

pub struct ForwardingResolver {
    config: ForwardingResolverConfig,
    next_id: AtomicU16,
}

impl ForwardingResolver {
    #[must_use]
    pub fn new(config: ForwardingResolverConfig) -> Self {
        // Seed the ID counter with the low bits of the process id so
        // concurrent resolvers in separate processes do not lock-step.
        Self {
            config,
            next_id: AtomicU16::new((std::process::id() & 0xffff) as u16),
        }
    }

    fn next_id(&self) -> u16 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn query_type(
        &self,
        name: &Name,
        qtype: DnsRecordType,
    ) -> Result<SingleResult, ResolveError> {
        let result = async {
            let record_type = match qtype {
                DnsRecordType::A => RecordType::A,
                DnsRecordType::Aaaa => RecordType::AAAA,
            };
            let id = self.next_id();
            let mut message = Message::new(id, MessageType::Query, OpCode::Query);
            message.metadata.recursion_desired = true;
            message.add_query(Query::query(name.clone(), record_type));
            let query_bytes = message
                .to_vec()
                .map_err(|e| ResolveError::Upstream(format!("encode query: {e}")))?;

            let response = self.exchange(&query_bytes, id, name, record_type).await?;

            match response.metadata.response_code {
                ResponseCode::NoError => {}
                ResponseCode::NXDomain => return Ok(SingleResult::NxDomain),
                other => return Err(ResolveError::ResponseCode(u16::from(other))),
            }

            reconstruct(name, record_type, &response)
        }
        .await;
        result.map_err(|source| ResolveError::Query {
            upstream: self.config.upstream,
            qtype,
            source: Box::new(source),
        })
    }

    /// Performs a bounded UDP exchange, retrying over TCP if the response is
    /// truncated. Both transports share one absolute deadline.
    async fn exchange(
        &self,
        query_bytes: &[u8],
        id: u16,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Message, ResolveError> {
        let deadline = Instant::now() + self.config.query_timeout;
        let udp = self.exchange_udp(query_bytes, deadline).await?;
        validate_response(&udp, id, name, record_type)?;
        if udp.metadata.truncation {
            let tcp = self.exchange_tcp(query_bytes, deadline).await?;
            validate_response(&tcp, id, name, record_type)?;
            if tcp.metadata.truncation {
                return Err(ResolveError::InvalidResponse("truncated_tcp"));
            }
            return Ok(tcp);
        }
        Ok(udp)
    }

    async fn exchange_udp(
        &self,
        query_bytes: &[u8],
        deadline: Instant,
    ) -> Result<Message, ResolveError> {
        let bind_addr = match self.config.upstream.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = bounded_io(
            deadline,
            DnsTransport::Udp,
            DnsOperation::Bind,
            crate::dialer::bind_udp(bind_addr, self.config.socket_mark),
        )
        .await?;
        // Connect the UDP socket to the fixed upstream so the kernel only
        // delivers datagrams whose source is *exactly* the configured upstream
        // — the full address **and** port (the 4-tuple), not merely the same
        // IP. This is the primary anti-spoofing control; a reply forged from
        // the right IP but a different port is dropped by the kernel and never
        // seen here.
        bounded_io(
            deadline,
            DnsTransport::Udp,
            DnsOperation::Connect,
            socket.connect(self.config.upstream),
        )
        .await?;

        let mut buf = vec![0u8; MAX_UDP_RESPONSE_BYTES];
        let retry_at = deadline - self.config.query_timeout / 2;
        for attempt in 0..2 {
            if Instant::now() >= deadline {
                return Err(ResolveError::ExchangeTimeout {
                    transport: DnsTransport::Udp,
                    operation: DnsOperation::Receive,
                });
            }
            bounded_io(
                deadline,
                DnsTransport::Udp,
                DnsOperation::Send,
                socket.send(query_bytes),
            )
            .await?;
            let receive_deadline = if attempt == 0 { retry_at } else { deadline };
            let received = bounded_io(
                receive_deadline,
                DnsTransport::Udp,
                DnsOperation::Receive,
                socket.recv_from(&mut buf),
            )
            .await;
            let (len, from) = match received {
                Err(ResolveError::ExchangeTimeout { .. }) if attempt == 0 => continue,
                result => result?,
            };
            if from != self.config.upstream {
                return Err(ResolveError::InvalidResponse("udp_source_mismatch"));
            }
            return Message::from_vec(&buf[..len])
                .map_err(|_| ResolveError::InvalidResponse("udp_decode"));
        }
        Err(ResolveError::ExchangeTimeout {
            transport: DnsTransport::Udp,
            operation: DnsOperation::Receive,
        })
    }

    async fn exchange_tcp(
        &self,
        query_bytes: &[u8],
        deadline: Instant,
    ) -> Result<Message, ResolveError> {
        let mut stream = bounded_io(
            deadline,
            DnsTransport::Tcp,
            DnsOperation::Connect,
            crate::dialer::connect_tcp(
                self.config.upstream,
                deadline.saturating_duration_since(Instant::now()),
                self.config.socket_mark,
            ),
        )
        .await?;

        let len = u16::try_from(query_bytes.len())
            .map_err(|_| ResolveError::Upstream("query too large for tcp".to_owned()))?;
        bounded_io(deadline, DnsTransport::Tcp, DnsOperation::Send, async {
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(query_bytes).await
        })
        .await?;

        let mut len_buf = [0u8; 2];
        bounded_io(
            deadline,
            DnsTransport::Tcp,
            DnsOperation::ReadLength,
            stream.read_exact(&mut len_buf),
        )
        .await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;
        if response_len == 0 || response_len > MAX_TCP_RESPONSE_BYTES {
            return Err(ResolveError::InvalidResponse("tcp_response_length"));
        }
        let mut response_buf = vec![0u8; response_len];
        bounded_io(
            deadline,
            DnsTransport::Tcp,
            DnsOperation::ReadBody,
            stream.read_exact(&mut response_buf),
        )
        .await?;
        Message::from_vec(&response_buf).map_err(|_| ResolveError::InvalidResponse("tcp_decode"))
    }
}

async fn bounded_io<T>(
    deadline: Instant,
    transport: DnsTransport,
    operation: DnsOperation,
    exchange: impl Future<Output = io::Result<T>>,
) -> Result<T, ResolveError> {
    timeout_at(deadline, exchange)
        .await
        .map_err(|_| ResolveError::ExchangeTimeout {
            transport,
            operation,
        })?
        .map_err(|source| ResolveError::Transport {
            transport,
            operation,
            source,
        })
}

/// Per-type result before merging A and AAAA.
#[derive(Debug)]
enum SingleResult {
    NxDomain,
    Answer {
        cname_chain: Vec<Name>,
        final_name: Name,
        addresses: Vec<ResolvedAddress>,
    },
}

fn validate_response(
    response: &Message,
    id: u16,
    name: &Name,
    record_type: RecordType,
) -> Result<(), ResolveError> {
    if response.metadata.id != id {
        return Err(ResolveError::InvalidResponse("id_mismatch"));
    }
    if response.metadata.message_type != MessageType::Response {
        return Err(ResolveError::InvalidResponse("not_a_response"));
    }
    let question_ok = response
        .queries
        .iter()
        .any(|q| q.query_type() == record_type && names_equal(q.name(), name));
    if !question_ok {
        return Err(ResolveError::InvalidResponse("question_mismatch"));
    }
    Ok(())
}

fn names_equal(a: &Name, b: &Name) -> bool {
    a.to_ascii().eq_ignore_ascii_case(&b.to_ascii())
}

fn reconstruct(
    name: &Name,
    record_type: RecordType,
    response: &Message,
) -> Result<SingleResult, ResolveError> {
    // Follow the CNAME chain within the answer section, bounded and
    // loop-protected.
    let mut chain_targets: Vec<Name> = Vec::new();
    let mut current = name.clone();
    loop {
        let next = response.answers.iter().find_map(|record| {
            if record.record_type() == RecordType::CNAME
                && names_equal(&record.name, &current)
                && let RData::CNAME(cname) = &record.data
            {
                return Some(cname.0.clone());
            }
            None
        });
        match next {
            Some(target) => {
                if chain_targets.len() >= MAX_CNAME_DEPTH {
                    return Err(ResolveError::InvalidResponse("cname_chain_too_long"));
                }
                if names_equal(&target, name)
                    || chain_targets.iter().any(|t| names_equal(t, &target))
                {
                    return Err(ResolveError::InvalidResponse("cname_loop"));
                }
                current = target.clone();
                chain_targets.push(target);
            }
            None => break,
        }
    }

    let final_name = chain_targets
        .last()
        .cloned()
        .unwrap_or_else(|| name.clone());
    let cname_chain = if chain_targets.is_empty() {
        Vec::new()
    } else {
        chain_targets[..chain_targets.len() - 1].to_vec()
    };

    let mut addresses = Vec::new();
    for record in &response.answers {
        if record.record_type() != record_type || !names_equal(&record.name, &final_name) {
            continue;
        }
        let ip = match &record.data {
            RData::A(a) => IpAddr::V4(a.0),
            RData::AAAA(aaaa) => IpAddr::V6(aaaa.0),
            _ => continue,
        };
        addresses.push(ResolvedAddress {
            ip,
            ttl_secs: record.ttl,
        });
        if addresses.len() >= MAX_ADDRESS_RECORDS {
            break;
        }
    }

    Ok(SingleResult::Answer {
        cname_chain,
        final_name,
        addresses,
    })
}

#[async_trait]
impl UpstreamResolver for ForwardingResolver {
    async fn resolve(&self, name: &Name) -> Result<ResolvedChain, ResolveError> {
        let (a_result, aaaa_result) = tokio::join!(
            self.query_type(name, DnsRecordType::A),
            self.query_type(name, DnsRecordType::Aaaa)
        );

        let a = a_result?;
        let aaaa = aaaa_result?;

        // A and AAAA are merged only when their CNAME chain and final owner
        // name agree, because a CNAME is type-agnostic (it applies to every
        // type) so a well-formed pair must reach the same owner. Merging two
        // disagreeing chains would attribute one type's addresses to the other
        // type's owner and silently drop one chain's hop validation, so a
        // conflict is rejected outright rather than papered over. NXDOMAIN is a
        // name-level verdict; if exactly one type reports it, the other type's
        // fully-validated chain is used on its own.
        let (cname_chain, final_name, mut addresses) = match (a, aaaa) {
            (SingleResult::NxDomain, SingleResult::NxDomain) => {
                return Err(ResolveError::NxDomain(name.clone()));
            }
            (
                SingleResult::Answer {
                    cname_chain: a_chain,
                    final_name: a_final,
                    addresses: a_addr,
                },
                SingleResult::Answer {
                    cname_chain: q_chain,
                    final_name: q_final,
                    addresses: q_addr,
                },
            ) => {
                if !chains_agree(&a_chain, &a_final, &q_chain, &q_final) {
                    return Err(ResolveError::InvalidResponse("cname_chain_conflict"));
                }
                let mut addresses = a_addr;
                addresses.extend(q_addr);
                (a_chain, a_final, addresses)
            }
            (
                SingleResult::Answer {
                    cname_chain,
                    final_name,
                    addresses,
                },
                SingleResult::NxDomain,
            )
            | (
                SingleResult::NxDomain,
                SingleResult::Answer {
                    cname_chain,
                    final_name,
                    addresses,
                },
            ) => (cname_chain, final_name, addresses),
        };

        if addresses.len() > MAX_ADDRESS_RECORDS {
            addresses.truncate(MAX_ADDRESS_RECORDS);
        }

        Ok(ResolvedChain {
            cname_chain,
            final_name,
            addresses,
        })
    }
}

/// Returns true when two CNAME chains and their final owner names are
/// equivalent (case-insensitively, per DNS name comparison rules).
fn chains_agree(a_chain: &[Name], a_final: &Name, q_chain: &[Name], q_final: &Name) -> bool {
    names_equal(a_final, q_final)
        && a_chain.len() == q_chain.len()
        && a_chain
            .iter()
            .zip(q_chain.iter())
            .all(|(x, y)| names_equal(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, CollectingAuditSink};
    use crate::authorization::AuthorizationCache;
    use crate::connect_broker::ConnectBrokerConfig;
    use crate::connect_proto::{
        self, ConnectProtocol, ConnectRequest, ConnectStatus, ConnectTarget,
    };
    use crate::dialer::DirectDialer;
    use crate::gateway::{Gateway, GatewayConfig, GatewayListeners};
    use crate::policy::PolicyEngine;
    use crate::resolver::ResolveFailureKind;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME};
    use sendbox_policy::{Action, DnsPolicy, NetworkPolicy};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio_util::sync::CancellationToken;

    struct ColdGateway {
        upstream: UdpSocket,
        echo: TcpListener,
        connect: SocketAddr,
        authorizations: Arc<AuthorizationCache>,
        audit: Arc<CollectingAuditSink>,
        cancel: CancellationToken,
    }

    impl Drop for ColdGateway {
        fn drop(&mut self) {
            self.cancel.cancel();
        }
    }

    async fn cold_gateway(resolve_timeout: Duration) -> ColdGateway {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let policy = NetworkPolicy {
            default_action: Action::Deny,
            allowed_domains: vec![
                "allowed.example".to_owned(),
                "canonical.allowed.example".to_owned(),
            ],
            blocked_domains: vec![],
            allow_dns: true,
            max_connections: Some(2),
            allowed_networks: vec!["127.0.0.1/32".to_owned()],
            blocked_networks: vec![],
            allowed_ports: vec![],
            dns: DnsPolicy::default(),
        };
        let audit = Arc::new(CollectingAuditSink::new());
        let gateway = Gateway::new(
            Arc::new(PolicyEngine::compile(&policy).unwrap()),
            Arc::new(ForwardingResolver::new(ForwardingResolverConfig::new(
                upstream.local_addr().unwrap(),
            ))),
            Arc::new(DirectDialer),
            Arc::clone(&audit) as Arc<_>,
            GatewayConfig {
                connect: ConnectBrokerConfig {
                    resolve_timeout,
                    ..ConnectBrokerConfig::default()
                },
                ..GatewayConfig::default()
            },
        );
        let listeners = GatewayListeners::bind(
            Some("127.0.0.1:0".parse().unwrap()),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let connect = listeners.connect_addr();
        let authorizations = gateway.authorizations();
        let cancel = CancellationToken::new();
        let serving = cancel.clone();
        tokio::spawn(async move { gateway.serve(listeners, serving).await.unwrap() });
        ColdGateway {
            upstream,
            echo,
            connect,
            authorizations,
            audit,
            cancel,
        }
    }

    fn first_connect(fixture: &ColdGateway) -> tokio::task::JoinHandle<io::Result<u8>> {
        let address = fixture.connect;
        let port = fixture.echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await?;
            stream
                .write_all(&connect_proto::encode_request(&ConnectRequest {
                    protocol: ConnectProtocol::Tcp,
                    target: ConnectTarget::Hostname("allowed.example".to_owned()),
                    port,
                    expected_ip: None,
                }))
                .await?;
            let mut status = [0; 2];
            stream.read_exact(&mut status).await?;
            Ok(status[1])
        })
    }

    async fn answer_query(socket: &UdpSocket, bytes: &[u8], peer: SocketAddr, canonical: &str) {
        let query = Message::from_vec(bytes).unwrap();
        let canonical = Name::from_ascii(canonical).unwrap();
        let mut records = vec![Record::from_rdata(
            query.queries[0].name().clone(),
            60,
            RData::CNAME(CNAME(canonical.clone())),
        )];
        if query.queries[0].query_type() == RecordType::A {
            records.push(Record::from_rdata(
                canonical,
                60,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
        }
        socket
            .send_to(&answer_for(&query, records).to_vec().unwrap(), peer)
            .await
            .unwrap();
    }

    /// A tiny UDP DNS server that answers from a closure, for testing the
    /// forwarding resolver against real encoded/decoded messages.
    async fn spawn_udp_server<F>(responder: F) -> SocketAddr
    where
        F: Fn(&Message) -> Message + Send + Sync + 'static,
    {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let responder = Arc::new(responder);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(query) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let response = responder(&query);
                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });
        addr
    }

    fn answer_for(query: &Message, records: Vec<Record>) -> Message {
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.metadata.recursion_available = true;
        response.metadata.response_code = ResponseCode::NoError;
        for q in &query.queries {
            response.add_query(q.clone());
        }
        for record in records {
            response.add_answer(record);
        }
        response
    }

    async fn receive_query(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut bytes = vec![0; 4096];
        loop {
            match socket.try_recv_from(&mut bytes) {
                Ok((length, peer)) => {
                    bytes.truncate(length);
                    return (bytes, peer);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("fixture receive failed: {error}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "expected a DNS datagram without advancing the resolver clock"
            );
            tokio::task::yield_now().await;
        }
    }

    async fn finish<T>(task: tokio::task::JoinHandle<T>) -> T {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !task.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "resolver task did not finish at the expected virtual deadline"
            );
            tokio::task::yield_now().await;
        }
        task.await.expect("resolver task panicked")
    }

    async fn flush_io() {
        // Keep virtual time frozen while the reactor consumes loopback replies,
        // so advancing a timer does not outrun already-delivered network data.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn retransmits_a_lost_first_datagram_without_restarting_the_deadline() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(
            upstream.local_addr().unwrap(),
        ));
        let task = tokio::spawn(async move {
            resolver
                .query_type(
                    &Name::from_ascii("cold.example.").unwrap(),
                    DnsRecordType::A,
                )
                .await
        });
        let (first, peer) = receive_query(&upstream).await;
        tokio::time::advance(Duration::from_millis(1499)).await;
        assert_no_query(&upstream);
        tokio::time::advance(Duration::from_millis(1)).await;
        let (retry, retry_peer) = receive_query(&upstream).await;
        assert!(
            retry == first,
            "retransmission must preserve the question and ID"
        );
        assert_eq!(
            retry_peer, peer,
            "retransmission must preserve the UDP peer"
        );
        let query = Message::from_vec(&retry).unwrap();
        let response = answer_for(
            &query,
            vec![Record::from_rdata(
                Name::from_ascii("cold.example.").unwrap(),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
            )],
        );
        upstream
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
        assert!(matches!(
            finish(task).await.unwrap(),
            SingleResult::Answer { addresses, .. } if addresses.len() == 1
        ));
    }

    fn assert_no_query(socket: &UdpSocket) {
        assert!(
            socket
                .try_recv_from(&mut [0; 4096])
                .is_err_and(|error| { error.kind() == std::io::ErrorKind::WouldBlock }),
            "unexpected DNS retransmission"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn udp_blackhole_is_bounded_to_two_sends_and_one_deadline() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(address));
        let task = tokio::spawn(async move {
            resolver
                .query_type(
                    &Name::from_ascii("cold.example.").unwrap(),
                    DnsRecordType::A,
                )
                .await
        });
        let (first, peer) = receive_query(&upstream).await;
        tokio::time::advance(Duration::from_millis(1500)).await;
        assert!(receive_query(&upstream).await == (first, peer));
        tokio::time::advance(Duration::from_millis(1500)).await;
        let failure = finish(task).await.unwrap_err().diagnostic();
        assert_eq!(failure.kind, crate::resolver::ResolveFailureKind::Timeout);
        assert_eq!(failure.transport, Some(DnsTransport::Udp));
        assert_eq!(failure.operation, Some(DnsOperation::Receive));
        assert_eq!(failure.qtype, Some(DnsRecordType::A));
        assert_eq!(failure.upstream, Some(address));
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_no_query(&upstream);
    }

    #[tokio::test(start_paused = true)]
    async fn reply_before_retry_deadline_does_not_send_another_query() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(
            upstream.local_addr().unwrap(),
        ));
        let task = tokio::spawn(async move {
            resolver
                .query_type(
                    &Name::from_ascii("cold.example.").unwrap(),
                    DnsRecordType::A,
                )
                .await
        });
        let (bytes, peer) = receive_query(&upstream).await;
        tokio::time::advance(Duration::from_millis(1499)).await;
        let query = Message::from_vec(&bytes).unwrap();
        upstream
            .send_to(&answer_for(&query, vec![]).to_vec().unwrap(), peer)
            .await
            .unwrap();
        finish(task).await.unwrap();
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_no_query(&upstream);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_before_retry_drops_the_socket_and_stops_transmission() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(
            upstream.local_addr().unwrap(),
        ));
        let task = tokio::spawn(async move {
            resolver
                .query_type(
                    &Name::from_ascii("cold.example.").unwrap(),
                    DnsRecordType::A,
                )
                .await
        });
        receive_query(&upstream).await;
        tokio::time::advance(Duration::from_millis(1499)).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_no_query(&upstream);
    }

    #[tokio::test(start_paused = true)]
    async fn lost_aaaa_reply_retries_only_aaaa_and_preserves_the_a_answer() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(
            upstream.local_addr().unwrap(),
        ));
        let task = tokio::spawn(async move {
            resolver
                .resolve(&Name::from_ascii("cold.example.").unwrap())
                .await
        });
        let mut aaaa = None;
        for _ in 0..2 {
            let (bytes, peer) = receive_query(&upstream).await;
            let query = Message::from_vec(&bytes).unwrap();
            if query.queries[0].query_type() == RecordType::AAAA {
                aaaa = Some((bytes, peer));
            } else {
                let response = answer_for(
                    &query,
                    vec![Record::from_rdata(
                        Name::from_ascii("cold.example.").unwrap(),
                        60,
                        RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
                    )],
                );
                upstream
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        }
        flush_io().await;
        tokio::time::advance(Duration::from_millis(1500)).await;
        let retry = receive_query(&upstream).await;
        assert!(
            Some(&retry) == aaaa.as_ref(),
            "only the unanswered AAAA query may retry"
        );
        assert_no_query(&upstream);
        let response = answer_for(&Message::from_vec(&retry.0).unwrap(), vec![]);
        upstream
            .send_to(&response.to_vec().unwrap(), retry.1)
            .await
            .unwrap();
        let chain = finish(task).await.unwrap();
        assert_eq!(chain.addresses.len(), 1);
        assert_eq!(
            chain.addresses[0].ip,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_no_query(&upstream);
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_response_error_is_not_retried() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(
            upstream.local_addr().unwrap(),
        ));
        let task = tokio::spawn(async move {
            resolver
                .query_type(
                    &Name::from_ascii("cold.example.").unwrap(),
                    DnsRecordType::A,
                )
                .await
        });
        let (bytes, peer) = receive_query(&upstream).await;
        let mut response = answer_for(&Message::from_vec(&bytes).unwrap(), vec![]);
        response.metadata.response_code = ResponseCode::ServFail;
        upstream
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
        let failure = finish(task).await.unwrap_err().diagnostic();
        assert_eq!(
            failure.kind,
            crate::resolver::ResolveFailureKind::ResponseCode
        );
        assert_eq!(failure.response_code, Some(2));
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_no_query(&upstream);
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_body_cannot_restart_the_udp_deadline() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(address).await.unwrap();
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(address));
        let task = tokio::spawn(async move {
            resolver
                .query_type(
                    &Name::from_ascii("cold.example.").unwrap(),
                    DnsRecordType::A,
                )
                .await
        });
        let (bytes, peer) = receive_query(&upstream).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let mut response = answer_for(&Message::from_vec(&bytes).unwrap(), vec![]);
        response.metadata.truncation = true;
        upstream
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
        let (mut stream, _) =
            finish(tokio::spawn(async move { tcp.accept().await.unwrap() })).await;
        stream.write_all(&100u16.to_be_bytes()).await.unwrap();
        flush_io().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        let failure = finish(task).await.unwrap_err().diagnostic();
        assert_eq!(failure.kind, crate::resolver::ResolveFailureKind::Timeout);
        assert_eq!(failure.transport, Some(DnsTransport::Tcp));
        assert_eq!(failure.operation, Some(DnsOperation::ReadBody));
        assert_no_query(&upstream);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_during_tcp_fallback_closes_the_connection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(address).await.unwrap();
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(address));
        let task = tokio::spawn(async move {
            resolver
                .query_type(
                    &Name::from_ascii("cold.example.").unwrap(),
                    DnsRecordType::A,
                )
                .await
        });
        let (bytes, peer) = receive_query(&upstream).await;
        let mut response = answer_for(&Message::from_vec(&bytes).unwrap(), vec![]);
        response.metadata.truncation = true;
        upstream
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
        let (mut stream, _) =
            finish(tokio::spawn(async move { tcp.accept().await.unwrap() })).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        finish(tokio::spawn(async move {
            let mut bytes = Vec::new();
            stream
                .read_to_end(&mut bytes)
                .await
                .expect("cancelled TCP peer must close");
        }))
        .await;
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_no_query(&upstream);
    }

    #[tokio::test(start_paused = true)]
    async fn first_connect_recovers_lost_dns_without_priming_authorizations() {
        let fixture = cold_gateway(Duration::from_secs(5)).await;
        assert!(fixture.authorizations.is_empty());
        let client = first_connect(&fixture);
        let first = receive_query(&fixture.upstream).await;
        let second = receive_query(&fixture.upstream).await;
        assert!(fixture.authorizations.is_empty());
        tokio::time::advance(Duration::from_millis(1500)).await;
        for _ in 0..2 {
            let retry = receive_query(&fixture.upstream).await;
            assert!(
                retry == first || retry == second,
                "retry must preserve its original peer and question"
            );
            answer_query(
                &fixture.upstream,
                &retry.0,
                retry.1,
                "canonical.allowed.example.",
            )
            .await;
        }
        assert_eq!(finish(client).await.unwrap(), ConnectStatus::Ok as u8);
        assert_eq!(
            fixture
                .authorizations
                .authorized_addresses("allowed.example"),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn partial_a_answer_is_not_authorized_when_aaaa_times_out() {
        let fixture = cold_gateway(Duration::from_secs(5)).await;
        let client = first_connect(&fixture);
        for _ in 0..2 {
            let (bytes, peer) = receive_query(&fixture.upstream).await;
            if Message::from_vec(&bytes).unwrap().queries[0].query_type() == RecordType::A {
                answer_query(
                    &fixture.upstream,
                    &bytes,
                    peer,
                    "canonical.allowed.example.",
                )
                .await;
            }
        }
        flush_io().await;
        assert!(fixture.authorizations.is_empty());
        tokio::time::advance(Duration::from_millis(1500)).await;
        let (retry, _) = receive_query(&fixture.upstream).await;
        assert_eq!(
            Message::from_vec(&retry).unwrap().queries[0].query_type(),
            RecordType::AAAA
        );
        tokio::time::advance(Duration::from_millis(1500)).await;
        assert_eq!(
            finish(client).await.unwrap(),
            ConnectStatus::ResolutionFailed as u8
        );
        assert!(fixture.authorizations.is_empty());
        assert!(fixture.audit.events().iter().any(|event| matches!(
            event,
            AuditEvent::DnsResolutionFailed { source: "connect", failure, .. }
                if failure.kind == ResolveFailureKind::Timeout
                    && failure.qtype == Some(DnsRecordType::Aaaa)
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn broker_deadline_cancels_dns_before_retry_and_keeps_the_cache_empty() {
        let fixture = cold_gateway(Duration::from_secs(1)).await;
        let client = first_connect(&fixture);
        let first = receive_query(&fixture.upstream).await;
        let second = receive_query(&fixture.upstream).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            finish(client).await.unwrap(),
            ConnectStatus::ResolutionFailed as u8
        );
        for (bytes, peer) in [first, second] {
            answer_query(
                &fixture.upstream,
                &bytes,
                peer,
                "canonical.allowed.example.",
            )
            .await;
        }
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_no_query(&fixture.upstream);
        assert!(fixture.authorizations.is_empty());
        assert!(fixture.audit.events().iter().any(|event| matches!(
            event,
            AuditEvent::DnsResolutionFailed { failure, .. }
                if failure.kind == ResolveFailureKind::BrokerTimeout
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn gateway_cancellation_wins_the_retry_race_and_rejects_late_answers() {
        let fixture = cold_gateway(Duration::from_secs(5)).await;
        let client = first_connect(&fixture);
        let first = receive_query(&fixture.upstream).await;
        let second = receive_query(&fixture.upstream).await;
        tokio::time::advance(Duration::from_millis(1499)).await;
        fixture.cancel.cancel();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(finish(client).await.is_err());
        for (bytes, peer) in [first, second] {
            answer_query(
                &fixture.upstream,
                &bytes,
                peer,
                "canonical.allowed.example.",
            )
            .await;
        }
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_no_query(&fixture.upstream);
        assert!(fixture.authorizations.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn retry_does_not_authorize_a_denied_cname_or_dial_its_address() {
        let fixture = cold_gateway(Duration::from_secs(5)).await;
        let client = first_connect(&fixture);
        receive_query(&fixture.upstream).await;
        receive_query(&fixture.upstream).await;
        tokio::time::advance(Duration::from_millis(1500)).await;
        for _ in 0..2 {
            let (bytes, peer) = receive_query(&fixture.upstream).await;
            answer_query(&fixture.upstream, &bytes, peer, "denied.example.").await;
        }
        assert_eq!(
            finish(client).await.unwrap(),
            ConnectStatus::PolicyDenied as u8
        );
        assert!(fixture.authorizations.is_empty());
        assert!(
            timeout_at(Instant::now(), fixture.echo.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn udp_rejects_response_from_wrong_source_port() {
        // The configured upstream socket receives the query, but a *different*
        // socket — a distinct source port on the same loopback IP — sends the
        // reply. The resolver connects its UDP socket to the exact upstream
        // `SocketAddr`, so the kernel never delivers the wrong-port datagram and
        // resolution fails, rather than trusting a reply whose source port
        // differs from the upstream (an off-path spoofing vector that a
        // same-IP-only check would accept).
        let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_addr = upstream.local_addr().unwrap();
        let attacker = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        assert_ne!(upstream_addr.port(), attacker.local_addr().unwrap().port());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = upstream.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(query) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                // A perfectly well-formed answer, but sent from the wrong port.
                let response = answer_for(
                    &query,
                    vec![Record::from_rdata(
                        Name::from_str("example.com.").unwrap(),
                        60,
                        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                    )],
                );
                if let Ok(bytes) = response.to_vec() {
                    let _ = attacker.send_to(&bytes, peer).await;
                }
            }
        });
        let mut config = ForwardingResolverConfig::new(upstream_addr);
        config.query_timeout = Duration::from_millis(200);
        let resolver = ForwardingResolver::new(config);
        let result = resolver
            .resolve(&Name::from_str("example.com.").unwrap())
            .await;
        assert!(
            result.is_err(),
            "a reply from the wrong source port must be rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn resolves_a_record_directly() {
        let addr = spawn_udp_server(|query| {
            let qtype = query.queries[0].query_type();
            if qtype == RecordType::A {
                answer_for(
                    query,
                    vec![Record::from_rdata(
                        Name::from_str("example.com.").unwrap(),
                        60,
                        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                    )],
                )
            } else {
                answer_for(query, vec![])
            }
        })
        .await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let chain = resolver
            .resolve(&Name::from_str("example.com.").unwrap())
            .await
            .unwrap();
        assert!(chain.cname_chain.is_empty());
        assert_eq!(
            chain.addresses,
            vec![ResolvedAddress {
                ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                ttl_secs: 60,
            }]
        );
    }

    #[tokio::test]
    async fn follows_cname_chain_and_reports_hops() {
        let addr = spawn_udp_server(|query| {
            let qtype = query.queries[0].query_type();
            if qtype == RecordType::A {
                answer_for(
                    query,
                    vec![
                        Record::from_rdata(
                            Name::from_str("www.example.com.").unwrap(),
                            60,
                            RData::CNAME(CNAME(Name::from_str("cdn.example.net.").unwrap())),
                        ),
                        Record::from_rdata(
                            Name::from_str("cdn.example.net.").unwrap(),
                            60,
                            RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
                        ),
                    ],
                )
            } else {
                // A CNAME is type-agnostic, so the AAAA response follows the
                // same alias to the same owner (NODATA at the leaf).
                answer_for(
                    query,
                    vec![Record::from_rdata(
                        Name::from_str("www.example.com.").unwrap(),
                        60,
                        RData::CNAME(CNAME(Name::from_str("cdn.example.net.").unwrap())),
                    )],
                )
            }
        })
        .await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let chain = resolver
            .resolve(&Name::from_str("www.example.com.").unwrap())
            .await
            .unwrap();
        assert_eq!(
            chain.final_name,
            Name::from_str("cdn.example.net.").unwrap()
        );
        // The single intermediate hop is the final name itself (queried ->
        // final), so cname_chain excludes the final owner and is empty here.
        assert!(chain.cname_chain.is_empty());
        assert_eq!(chain.addresses.len(), 1);
    }

    #[tokio::test]
    async fn rejects_response_with_mismatched_id() {
        let addr = spawn_udp_server(|query| {
            let mut response = answer_for(
                query,
                vec![Record::from_rdata(
                    Name::from_str("example.com.").unwrap(),
                    60,
                    RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
                )],
            );
            response.metadata.id = query.metadata.id.wrapping_add(1);
            response
        })
        .await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let result = resolver
            .resolve(&Name::from_str("example.com.").unwrap())
            .await;
        assert_eq!(result.unwrap_err().diagnostic().detail, Some("id_mismatch"));
    }

    #[tokio::test]
    async fn nxdomain_from_both_types_is_reported() {
        let addr = spawn_udp_server(|query| {
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.metadata.response_code = ResponseCode::NXDomain;
            for q in &query.queries {
                response.add_query(q.clone());
            }
            response
        })
        .await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let result = resolver
            .resolve(&Name::from_str("missing.example.").unwrap())
            .await;
        assert!(matches!(result, Err(ResolveError::NxDomain(_))));
    }

    #[tokio::test]
    async fn detects_cname_loop() {
        let addr = spawn_udp_server(|query| {
            answer_for(
                query,
                vec![
                    Record::from_rdata(
                        Name::from_str("a.example.").unwrap(),
                        60,
                        RData::CNAME(CNAME(Name::from_str("b.example.").unwrap())),
                    ),
                    Record::from_rdata(
                        Name::from_str("b.example.").unwrap(),
                        60,
                        RData::CNAME(CNAME(Name::from_str("a.example.").unwrap())),
                    ),
                ],
            )
        })
        .await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let result = resolver
            .resolve(&Name::from_str("a.example.").unwrap())
            .await;
        assert_eq!(result.unwrap_err().diagnostic().detail, Some("cname_loop"));
    }

    #[tokio::test]
    async fn merges_a_and_aaaa_addresses() {
        let addr = spawn_udp_server(|query| {
            let qtype = query.queries[0].query_type();
            let record = if qtype == RecordType::A {
                Record::from_rdata(
                    Name::from_str("dual.example.").unwrap(),
                    60,
                    RData::A(A(Ipv4Addr::new(198, 51, 100, 5))),
                )
            } else {
                Record::from_rdata(
                    Name::from_str("dual.example.").unwrap(),
                    60,
                    RData::AAAA(AAAA(std::net::Ipv6Addr::new(
                        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
                    ))),
                )
            };
            answer_for(query, vec![record])
        })
        .await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let chain = resolver
            .resolve(&Name::from_str("dual.example.").unwrap())
            .await
            .unwrap();
        assert_eq!(chain.addresses.len(), 2);
        assert!(chain.addresses.iter().any(|a| a.ip.is_ipv4()));
        assert!(chain.addresses.iter().any(|a| a.ip.is_ipv6()));
    }

    #[tokio::test]
    async fn agreeing_a_and_aaaa_cname_chains_merge() {
        let addr = spawn_udp_server(|query| {
            // Both types follow the same CNAME to the same owner.
            let cname = Record::from_rdata(
                Name::from_str("www.example.").unwrap(),
                60,
                RData::CNAME(CNAME(Name::from_str("cdn.example.net.").unwrap())),
            );
            let leaf = if query.queries[0].query_type() == RecordType::A {
                Record::from_rdata(
                    Name::from_str("cdn.example.net.").unwrap(),
                    60,
                    RData::A(A(Ipv4Addr::new(203, 0, 113, 10))),
                )
            } else {
                Record::from_rdata(
                    Name::from_str("cdn.example.net.").unwrap(),
                    60,
                    RData::AAAA(AAAA(std::net::Ipv6Addr::new(
                        0x2001, 0xdb8, 0, 0, 0, 0, 0, 2,
                    ))),
                )
            };
            answer_for(query, vec![cname, leaf])
        })
        .await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let chain = resolver
            .resolve(&Name::from_str("www.example.").unwrap())
            .await
            .unwrap();
        assert_eq!(
            chain.final_name,
            Name::from_str("cdn.example.net.").unwrap()
        );
        assert_eq!(chain.addresses.len(), 2);
    }

    #[tokio::test]
    async fn conflicting_a_and_aaaa_cname_chains_are_rejected() {
        let addr = spawn_udp_server(|query| {
            // A and AAAA reach *different* owners — a well-formed pair never
            // does this (CNAME is type-agnostic), so the resolver must reject
            // the pair rather than merge and drop one chain's validation.
            let (target, ip) = if query.queries[0].query_type() == RecordType::A {
                (
                    "cdn-a.example.net.",
                    RData::A(A(Ipv4Addr::new(203, 0, 113, 11))),
                )
            } else {
                (
                    "cdn-b.example.net.",
                    RData::AAAA(AAAA(std::net::Ipv6Addr::new(
                        0x2001, 0xdb8, 0, 0, 0, 0, 0, 3,
                    ))),
                )
            };
            let cname = Record::from_rdata(
                Name::from_str("www.example.").unwrap(),
                60,
                RData::CNAME(CNAME(Name::from_str(target).unwrap())),
            );
            let leaf = Record::from_rdata(Name::from_str(target).unwrap(), 60, ip);
            answer_for(query, vec![cname, leaf])
        })
        .await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let result = resolver
            .resolve(&Name::from_str("www.example.").unwrap())
            .await;
        assert_eq!(
            result.unwrap_err().diagnostic().detail,
            Some("cname_chain_conflict")
        );
    }

    /// A UDP fixture that always truncates plus a TCP fixture that returns the
    /// full answer, both on the same port, so the resolver must fall back to
    /// TCP on the truncation bit.
    async fn spawn_truncating_dns_server(tcp_truncated: bool) -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = udp.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();

        // UDP half: echo the query header/question but set the truncation bit
        // and return no answers, forcing a TCP retry.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = udp.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(query) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.metadata.truncation = true;
                for q in &query.queries {
                    response.add_query(q.clone());
                }
                if let Ok(bytes) = response.to_vec() {
                    let _ = udp.send_to(&bytes, peer).await;
                }
            }
        });

        // TCP half: return the full answer.
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let n = u16::from_be_bytes(len_buf) as usize;
                    let mut msg = vec![0u8; n];
                    if stream.read_exact(&mut msg).await.is_err() {
                        return;
                    }
                    let Ok(query) = Message::from_vec(&msg) else {
                        return;
                    };
                    let records = if query.queries[0].query_type() == RecordType::A {
                        vec![Record::from_rdata(
                            Name::from_str("tcp-only.example.").unwrap(),
                            60,
                            RData::A(A(Ipv4Addr::new(198, 51, 100, 77))),
                        )]
                    } else {
                        vec![]
                    };
                    let mut response = Message::response(query.metadata.id, OpCode::Query);
                    response.metadata.truncation = tcp_truncated;
                    for q in &query.queries {
                        response.add_query(q.clone());
                    }
                    for record in records {
                        response.add_answer(record);
                    }
                    let bytes = response.to_vec().unwrap();
                    let prefix = (bytes.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&prefix).await;
                    let _ = stream.write_all(&bytes).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn truncated_udp_response_falls_back_to_tcp() {
        let addr = spawn_truncating_dns_server(false).await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let chain = resolver
            .resolve(&Name::from_str("tcp-only.example.").unwrap())
            .await
            .unwrap();
        assert_eq!(
            chain.addresses,
            vec![ResolvedAddress {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)),
                ttl_secs: 60,
            }]
        );
    }

    #[tokio::test]
    async fn tcp_response_with_truncation_still_set_is_rejected() {
        let addr = spawn_truncating_dns_server(true).await;
        let resolver = ForwardingResolver::new(ForwardingResolverConfig::new(addr));
        let failure = resolver
            .resolve(&Name::from_ascii("tcp-only.example.").unwrap())
            .await
            .unwrap_err()
            .diagnostic();
        assert_eq!(failure.detail, Some("truncated_tcp"));
    }
}
