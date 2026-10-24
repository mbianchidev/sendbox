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
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

use crate::audit::AuditSink;
use crate::authorization::AuthorizationCache;
use crate::connect_broker::{
    ConnectAuthorizationState, ConnectBroker, ConnectBrokerConfig, ConnectFrontend,
};
use crate::dialer::Dialer;
use crate::dns_broker::{DnsBroker, DnsBrokerConfig};
use crate::dns_budget::DnsGuard;
use crate::github_meta::{self, GitHubMetaClient};
use crate::github_meta_client::OfficialGitHubMetaClient;
use crate::origin::OriginReservations;
use crate::policy::PolicyEngine;
use crate::resolver::UpstreamResolver;

/// Bound listeners for a gateway, plus the addresses they actually bound
/// (resolving any `:0` request to a concrete port). The supervisor reads these
/// concrete ports to render its nftables rules.
pub struct GatewayListeners {
    dns_udp: Option<UdpSocket>,
    dns_tcp: Option<TcpListener>,
    connect: TcpListener,
    http_proxy: Option<TcpListener>,
    dns_addr: Option<SocketAddr>,
    connect_addr: SocketAddr,
    http_proxy_addr: Option<SocketAddr>,
}

impl GatewayListeners {
    const EPHEMERAL_DNS_BIND_ATTEMPTS: usize = 32;

    /// Binds the CONNECT listener always and the DNS listeners only when
    /// `dns_listen` is `Some` (i.e. the policy permits DNS). The DNS UDP and
    /// TCP sockets bind the same resolved address/port.
    pub async fn bind(
        dns_listen: Option<SocketAddr>,
        connect_listen: SocketAddr,
    ) -> io::Result<Self> {
        Self::bind_with_http_proxy(dns_listen, connect_listen, None).await
    }

    pub async fn bind_with_http_proxy(
        dns_listen: Option<SocketAddr>,
        connect_listen: SocketAddr,
        http_proxy_listen: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let (dns_udp, dns_tcp, dns_addr) = match dns_listen {
            Some(addr) => {
                let (udp, tcp, resolved) = Self::bind_dns_pair(addr).await?;
                (Some(udp), Some(tcp), Some(resolved))
            }
            None => (None, None, None),
        };
        let connect = TcpListener::bind(connect_listen).await?;
        let connect_addr = connect.local_addr()?;
        let http_proxy = match http_proxy_listen {
            Some(address) => Some(TcpListener::bind(address).await?),
            None => None,
        };
        let http_proxy_addr = http_proxy
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()?;
        Ok(Self {
            dns_udp,
            dns_tcp,
            connect,
            dns_addr,
            connect_addr,
            http_proxy,
            http_proxy_addr,
        })
    }

    async fn bind_dns_pair(addr: SocketAddr) -> io::Result<(UdpSocket, TcpListener, SocketAddr)> {
        let attempts = if addr.port() == 0 {
            Self::EPHEMERAL_DNS_BIND_ATTEMPTS
        } else {
            1
        };

        for _ in 0..attempts {
            let udp = UdpSocket::bind(addr).await?;
            let resolved = udp.local_addr()?;
            match TcpListener::bind(resolved).await {
                Ok(tcp) => return Ok((udp, tcp, resolved)),
                Err(error) if addr.port() == 0 && error.kind() == io::ErrorKind::AddrInUse => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "could not allocate a shared ephemeral DNS UDP/TCP port after {} attempts",
                Self::EPHEMERAL_DNS_BIND_ATTEMPTS
            ),
        ))
    }

    #[must_use]
    pub fn dns_addr(&self) -> Option<SocketAddr> {
        self.dns_addr
    }

    #[must_use]
    pub fn connect_addr(&self) -> SocketAddr {
        self.connect_addr
    }

    #[must_use]
    pub fn http_proxy_addr(&self) -> Option<SocketAddr> {
        self.http_proxy_addr
    }
}

/// Configuration for the two brokers a gateway runs.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub dns: DnsBrokerConfig,
    pub connect: ConnectBrokerConfig,
    pub origin_reservations: Arc<OriginReservations>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            dns: DnsBrokerConfig::default(),
            connect: ConnectBrokerConfig::default(),
            origin_reservations: Arc::new(OriginReservations::default()),
        }
    }
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
    metadata_client: Option<Arc<dyn GitHubMetaClient>>,
    metadata_prepared: AtomicBool,
}

struct GatewayRunGuard<'a> {
    engine: &'a PolicyEngine,
    authorizations: &'a AuthorizationCache,
    metadata_prepared: &'a AtomicBool,
    cancel: CancellationToken,
}

impl Drop for GatewayRunGuard<'_> {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.authorizations.clear();
        if let Some(metadata) = self.engine.github_meta() {
            metadata.clear();
        }
        self.metadata_prepared.store(false, Ordering::Release);
    }
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
            metadata_client: None,
            metadata_prepared: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn with_github_meta_client(mut self, client: Arc<dyn GitHubMetaClient>) -> Self {
        self.metadata_client = Some(client);
        self
    }

    fn metadata_client(&self) -> Arc<dyn GitHubMetaClient> {
        self.metadata_client.clone().unwrap_or_else(|| {
            Arc::new(OfficialGitHubMetaClient::new(
                Arc::clone(&self.resolver),
                Arc::clone(&self.dialer),
            ))
        })
    }

    /// Production calls this after cgroup/mark enforcement is armed and before
    /// publishing service readiness. A missing initial snapshot is an error.
    pub async fn prepare_github_meta(&self, cancel: &CancellationToken) -> io::Result<()> {
        let Some(metadata) = self.engine.github_meta() else {
            return Ok(());
        };
        if self.metadata_prepared.load(Ordering::Acquire) && metadata.view().1.is_some() {
            return Ok(());
        }
        let client = self.metadata_client();
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "GitHub Meta bootstrap cancelled")),
            result = metadata.refresh_once(client.as_ref(), &self.engine, self.audit.as_ref()) => {
                result.map_err(io::Error::other)?;
            }
        }
        self.metadata_prepared.store(true, Ordering::Release);
        Ok(())
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
        if let Err(error) = self.prepare_github_meta(&cancel).await {
            return if cancel.is_cancelled() {
                Ok(())
            } else {
                Err(error)
            };
        }
        let _guard = GatewayRunGuard {
            engine: &self.engine,
            authorizations: &self.authorizations,
            metadata_prepared: &self.metadata_prepared,
            cancel: cancel.clone(),
        };
        let connect_broker = ConnectBroker::new_with_authorization_state(
            Arc::clone(&self.engine),
            Arc::clone(&self.resolver),
            ConnectAuthorizationState::new(
                Arc::clone(&self.authorizations),
                Arc::clone(&self.config.origin_reservations),
            ),
            Arc::clone(&self.guard),
            Arc::clone(&self.dialer),
            Arc::clone(&self.audit),
            self.config.connect.clone(),
        );

        let mut tasks = tokio::task::JoinSet::new();
        if self.engine.github_meta().is_some() {
            tasks.spawn(github_meta::run_refresh(
                Arc::clone(&self.engine),
                self.metadata_client(),
                Arc::clone(&self.audit),
                cancel.clone(),
            ));
        }
        tasks.spawn(Arc::clone(&connect_broker).run(listeners.connect, cancel.clone()));
        if let Some(http_proxy) = listeners.http_proxy {
            tasks.spawn(connect_broker.run_with_frontend(
                http_proxy,
                cancel.clone(),
                ConnectFrontend::Http,
            ));
        }

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
            tasks.spawn(Arc::clone(&dns_broker).run_udp(udp, cancel.clone()));
            tasks.spawn(dns_broker.run_tcp(tcp, cancel.clone()));
        }

        // Wait for the first task to finish (an error, or a clean stop after
        // cancellation), then cancel the rest and drain them.
        let first = tasks
            .join_next()
            .await
            .expect("CONNECT broker is mandatory");
        let mut result = joined_broker(first);
        cancel.cancel();
        while let Some(joined) = tasks.join_next().await {
            if let Err(error) = joined_broker(joined) {
                if result.is_ok() {
                    result = Err(error);
                } else {
                    eprintln!("sendbox: additional egress task failure during shutdown: {error}");
                }
            }
        }
        result
    }
}

fn joined_broker(result: Result<io::Result<()>, tokio::task::JoinError>) -> io::Result<()> {
    result.map_err(|error| io::Error::other(format!("egress task failed: {error}")))?
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
