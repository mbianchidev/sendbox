//! Shared egress gateway: colocates the DNS broker (loopback UDP + TCP) and
//! the CONNECT broker (loopback TCP) so they share one [`PolicyEngine`], one
//! resolver, one [`DnsGuard`], one audit sink, and — critically — one
//! [`AuthorizationCache`]. That single shared cache is what lets a CONNECT
//! request reuse an authorization the DNS broker already recorded.
//!
//! When the policy disables DNS (`allow_dns = false`) no DNS listener is bound
//! at all, matching the enforcement layer, which then installs no nftables DNS
//! accept rule either.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

use crate::audit::AuditSink;
use crate::authorization::AuthorizationCache;
use crate::connect_broker::{ConnectBroker, ConnectBrokerConfig};
use crate::dialer::Dialer;
use crate::dns_broker::{DnsBroker, DnsBrokerConfig};
use crate::dns_budget::DnsGuard;
use crate::policy::PolicyEngine;
use crate::resolver::UpstreamResolver;

/// Bound listeners for a gateway, plus the addresses they actually bound
/// (resolving any `:0` request to a concrete port). The supervisor reads these
/// concrete ports to render its nftables rules.
pub struct GatewayListeners {
    dns_udp: Option<UdpSocket>,
    dns_tcp: Option<TcpListener>,
    connect: TcpListener,
    dns_addr: Option<SocketAddr>,
    connect_addr: SocketAddr,
}

impl GatewayListeners {
    /// Binds the CONNECT listener always and the DNS listeners only when
    /// `dns_listen` is `Some` (i.e. the policy permits DNS). The DNS UDP and
    /// TCP sockets bind the same resolved address/port.
    pub async fn bind(
        dns_listen: Option<SocketAddr>,
        connect_listen: SocketAddr,
    ) -> io::Result<Self> {
        let (dns_udp, dns_tcp, dns_addr) = match dns_listen {
            Some(addr) => {
                let udp = UdpSocket::bind(addr).await?;
                let resolved = udp.local_addr()?;
                // Bind TCP on the exact resolved address so both share a port.
                let tcp = TcpListener::bind(resolved).await?;
                (Some(udp), Some(tcp), Some(resolved))
            }
            None => (None, None, None),
        };
        let connect = TcpListener::bind(connect_listen).await?;
        let connect_addr = connect.local_addr()?;
        Ok(Self {
            dns_udp,
            dns_tcp,
            connect,
            dns_addr,
            connect_addr,
        })
    }

    #[must_use]
    pub fn dns_addr(&self) -> Option<SocketAddr> {
        self.dns_addr
    }

    #[must_use]
    pub fn connect_addr(&self) -> SocketAddr {
        self.connect_addr
    }
}

/// Configuration for the two brokers a gateway runs.
#[derive(Debug, Clone, Default)]
pub struct GatewayConfig {
    pub dns: DnsBrokerConfig,
    pub connect: ConnectBrokerConfig,
}

/// The shared gateway. Holds the pieces every broker must share.
pub struct Gateway<R: UpstreamResolver> {
    engine: Arc<PolicyEngine>,
    resolver: Arc<R>,
    dialer: Arc<dyn Dialer>,
    audit: Arc<dyn AuditSink>,
    authorizations: Arc<AuthorizationCache>,
    guard: Arc<DnsGuard>,
    config: GatewayConfig,
}

impl<R: UpstreamResolver + 'static> Gateway<R> {
    #[must_use]
    pub fn new(
        engine: Arc<PolicyEngine>,
        resolver: Arc<R>,
        dialer: Arc<dyn Dialer>,
        audit: Arc<dyn AuditSink>,
        config: GatewayConfig,
    ) -> Self {
        let guard = Arc::new(DnsGuard::from_policy(engine.dns_policy()));
        let dns = engine.dns_policy();
        let capacity =
            AuthorizationCache::capacity_for(dns.budget.max_unique_names, dns.max_response_records);
        Self {
            engine,
            resolver,
            dialer,
            audit,
            authorizations: Arc::new(AuthorizationCache::with_capacity(capacity)),
            guard,
            config,
        }
    }

    #[must_use]
    pub fn authorizations(&self) -> Arc<AuthorizationCache> {
        Arc::clone(&self.authorizations)
    }

    /// Runs both brokers until the listeners fail or `cancel` fires. The DNS
    /// broker is only started if the policy allows DNS *and* DNS listeners
    /// were bound.
    pub async fn serve(
        &self,
        listeners: GatewayListeners,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        let connect_broker = ConnectBroker::new(
            Arc::clone(&self.engine),
            Arc::clone(&self.resolver),
            Arc::clone(&self.authorizations),
            Arc::clone(&self.guard),
            Arc::clone(&self.dialer),
            Arc::clone(&self.audit),
            self.config.connect.clone(),
        );

        let mut tasks = Vec::new();
        tasks.push(tokio::spawn(
            connect_broker.run(listeners.connect, cancel.clone()),
        ));

        if self.engine.allow_dns()
            && let (Some(udp), Some(tcp)) = (listeners.dns_udp, listeners.dns_tcp)
        {
            let dns_broker = DnsBroker::new(
                Arc::clone(&self.engine),
                Arc::clone(&self.resolver),
                Arc::clone(&self.authorizations),
                Arc::clone(&self.guard),
                Arc::clone(&self.audit),
                self.config.dns.clone(),
            );
            tasks.push(tokio::spawn(
                Arc::clone(&dns_broker).run_udp(udp, cancel.clone()),
            ));
            tasks.push(tokio::spawn(dns_broker.run_tcp(tcp, cancel.clone())));
        }

        // Wait for the first task to finish (an error, or a clean stop after
        // cancellation), then cancel the rest and drain them.
        let mut result = Ok(());
        if !tasks.is_empty() {
            let (first, _index, rest) = futures_select_all(tasks).await;
            result = match first {
                Ok(inner) => inner,
                Err(join_err) => Err(io::Error::other(format!(
                    "broker task panicked: {join_err}"
                ))),
            };
            cancel.cancel();
            for task in rest {
                let _ = task.await;
            }
        }
        result
    }
}

/// Minimal `select_all` over join handles without pulling in the `futures`
/// crate: polls each handle once per wakeup and returns the first ready one
/// with the remaining handles. Kept tiny and dependency-free.
async fn futures_select_all<T>(
    mut handles: Vec<tokio::task::JoinHandle<T>>,
) -> (
    Result<T, tokio::task::JoinError>,
    usize,
    Vec<tokio::task::JoinHandle<T>>,
) {
    use std::future::poll_fn;
    use std::task::Poll;

    let (result, index) = poll_fn(|cx| {
        for (index, handle) in handles.iter_mut().enumerate() {
            if let Poll::Ready(result) = std::pin::Pin::new(handle).poll(cx) {
                return Poll::Ready((result, index));
            }
        }
        Poll::Pending
    })
    .await;
    handles.remove(index);
    (result, index, handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NullAuditSink;
    use crate::connect_proto::{
        self, ConnectProtocol, ConnectRequest, ConnectStatus, ConnectTarget,
    };
    use crate::dialer::DirectDialer;
    use crate::fixture_resolver::StaticResolver;
    use crate::resolver::{ResolvedAddress, ResolvedChain};
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use sendbox_policy::{Action, DnsPolicy, NetworkPolicy};
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn allow_all_policy() -> NetworkPolicy {
        NetworkPolicy {
            default_action: Action::Allow,
            allowed_domains: vec![],
            blocked_domains: vec![],
            allow_dns: true,
            max_connections: Some(4),
            allowed_networks: vec!["127.0.0.0/8".to_owned()],
            blocked_networks: vec![],
            allowed_ports: vec![],
            dns: DnsPolicy {
                max_ttl_secs: 30,
                ..DnsPolicy::default()
            },
        }
    }

    #[tokio::test]
    async fn dns_authorization_is_reused_by_connect_through_shared_cache() {
        // Echo fixture the CONNECT tunnel will reach.
        let fixture = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture_addr = fixture.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = fixture.accept().await {
                let mut buf = [0u8; 8];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
        });

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
        let engine = Arc::new(PolicyEngine::compile(&allow_all_policy()).unwrap());
        let gateway = Gateway::new(
            engine,
            resolver,
            Arc::new(DirectDialer),
            Arc::new(NullAuditSink),
            GatewayConfig::default(),
        );

        let listeners = GatewayListeners::bind(
            Some("127.0.0.1:0".parse().unwrap()),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let dns_addr = listeners.dns_addr().unwrap();
        let connect_addr = listeners.connect_addr();
        let authorizations = gateway.authorizations();

        let cancel = CancellationToken::new();
        let serve_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            let _ = gateway.serve(listeners, serve_cancel).await;
        });

        // 1. DNS query records an authorization.
        let mut query = Message::new(99, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_str("allowed.example.").unwrap(),
            RecordType::A,
        ));
        let query_bytes = query.to_vec().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query_bytes, dns_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Message::from_vec(&buf[..len])
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::NoError
        );
        assert!(authorizations.is_authorized("allowed.example", fixture_addr.ip()));

        // 2. CONNECT reuses that authorization.
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: fixture_addr.port(),
            target: ConnectTarget::Hostname("allowed.example".to_owned()),
            expected_ip: None,
        };
        let mut stream = TcpStream::connect(connect_addr).await.unwrap();
        stream
            .write_all(&connect_proto::encode_request(&request))
            .await
            .unwrap();
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).await.unwrap();
        assert_eq!(status[1], ConnectStatus::Ok as u8);

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn no_dns_listener_when_allow_dns_is_false() {
        let mut policy = allow_all_policy();
        policy.allow_dns = false;
        let engine = Arc::new(PolicyEngine::compile(&policy).unwrap());
        assert!(!engine.allow_dns());
        let gateway = Gateway::new(
            engine,
            Arc::new(StaticResolver::new()),
            Arc::new(DirectDialer),
            Arc::new(NullAuditSink),
            GatewayConfig::default(),
        );
        // When DNS is disabled the caller binds no DNS listener.
        let listeners = GatewayListeners::bind(None, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert!(listeners.dns_addr().is_none());
        let connect_addr = listeners.connect_addr();
        let cancel = CancellationToken::new();
        let serve_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            let _ = gateway.serve(listeners, serve_cancel).await;
        });
        // The CONNECT listener is still up.
        assert!(TcpStream::connect(connect_addr).await.is_ok());
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(addr.is_loopback());
        cancel.cancel();
        let _ = handle.await;
    }
}
