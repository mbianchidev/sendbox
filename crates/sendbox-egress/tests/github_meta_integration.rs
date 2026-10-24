use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use sendbox_egress::audit::{AuditEvent, CollectingAuditSink};
use sendbox_egress::connect_broker::{ConnectBrokerConfig, ConnectFrontend};
use sendbox_egress::connect_proto::{
    self, ConnectProtocol, ConnectRequest, ConnectStatus, ConnectTarget,
};
use sendbox_egress::dialer::{Dialer, DirectDialer};
use sendbox_egress::fixture_resolver::StaticResolver;
use sendbox_egress::gateway::{Gateway, GatewayConfig, GatewayListeners};
use sendbox_egress::github_meta::{
    GitHubMetaClient, GitHubMetaError, GitHubMetaResponse, GitHubMetaState,
};
use sendbox_egress::policy::PolicyEngine;
use sendbox_egress::resolver::{ResolvedAddress, ResolvedChain};
use sendbox_policy::NetworkPolicy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

struct FixtureClient {
    responses: Mutex<VecDeque<Result<GitHubMetaResponse, GitHubMetaError>>>,
    requests: Mutex<Vec<Option<String>>>,
}

impl FixtureClient {
    fn new(responses: Vec<Result<GitHubMetaResponse, GitHubMetaError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl GitHubMetaClient for FixtureClient {
    async fn fetch(
        &self,
        _policy: &PolicyEngine,
        etag: Option<&str>,
    ) -> Result<GitHubMetaResponse, GitHubMetaError> {
        self.requests.lock().unwrap().push(etag.map(str::to_owned));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected metadata request")
    }
}

fn policy() -> NetworkPolicy {
    serde_json::from_value(serde_json::json!({
        "default_action": "deny",
        "allowed_domains": ["github.com"],
        "blocked_domains": [],
        "allow_dns": true
    }))
    .unwrap()
}

fn metadata(
    domains: &[&str],
    v4: &str,
    v6: &str,
    etag: &str,
) -> Result<GitHubMetaResponse, GitHubMetaError> {
    Ok(GitHubMetaResponse::Modified {
        body: serde_json::to_vec(&serde_json::json!({
            "verifiable_password_authentication": false,
            "web": [v4], "api": [v6], "git": [v4],
            "domains": {"website": domains}
        }))
        .unwrap(),
        etag: Some(etag.to_owned()),
    })
}

struct FixtureDialer {
    echo: SocketAddr,
    calls: Mutex<Vec<SocketAddr>>,
}

#[async_trait::async_trait]
impl Dialer for FixtureDialer {
    async fn dial(&self, address: SocketAddr, deadline: Duration) -> io::Result<TcpStream> {
        self.calls.lock().unwrap().push(address);
        DirectDialer.dial(self.echo, deadline).await
    }
}

struct Harness {
    engine: Arc<PolicyEngine>,
    client: Arc<FixtureClient>,
    resolver: Arc<StaticResolver>,
    audit: Arc<CollectingAuditSink>,
    dialer: Arc<FixtureDialer>,
    dns: SocketAddr,
    connect: SocketAddr,
    http: SocketAddr,
    cancel: CancellationToken,
    gateway: tokio::task::JoinHandle<io::Result<()>>,
    echo: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start(
        raw: NetworkPolicy,
        frontend: ConnectFrontend,
        responses: Vec<Result<GitHubMetaResponse, GitHubMetaError>>,
    ) -> Self {
        let cancel = CancellationToken::new();
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dialer = Arc::new(FixtureDialer {
            echo: echo_listener.local_addr().unwrap(),
            calls: Mutex::new(Vec::new()),
        });
        let echo_cancel = cancel.clone();
        let echo = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    () = echo_cancel.cancelled() => break,
                    accepted = echo_listener.accept() => {
                        let (mut stream, _) = accepted.unwrap();
                        let cancel = echo_cancel.clone();
                        tasks.spawn(async move {
                            let (mut read, mut write) = stream.split();
                            tokio::select! {
                                () = cancel.cancelled() => {}
                                result = tokio::io::copy(&mut read, &mut write) => { result.unwrap(); }
                            }
                        });
                    }
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        let engine = Arc::new(PolicyEngine::compile(&raw).unwrap());
        let resolver = Arc::new(StaticResolver::new());
        let audit = Arc::new(CollectingAuditSink::new());
        let client = Arc::new(FixtureClient::new(responses));
        let gateway = Gateway::new(
            Arc::clone(&engine),
            Arc::clone(&resolver),
            Arc::clone(&dialer) as Arc<_>,
            Arc::clone(&audit) as Arc<_>,
            GatewayConfig {
                connect: ConnectBrokerConfig {
                    frontend,
                    ..ConnectBrokerConfig::default()
                },
                ..GatewayConfig::default()
            },
        )
        .with_github_meta_client(Arc::clone(&client) as Arc<_>);
        gateway.prepare_github_meta(&cancel).await.unwrap();
        let listeners = GatewayListeners::bind_with_http_proxy(
            Some("127.0.0.1:0".parse().unwrap()),
            "127.0.0.1:0".parse().unwrap(),
            Some("127.0.0.1:0".parse().unwrap()),
        )
        .await
        .unwrap();
        let dns = listeners.dns_addr().unwrap();
        let connect = listeners.connect_addr();
        let http = listeners.http_proxy_addr().unwrap();
        let gateway_cancel = cancel.clone();
        let gateway = tokio::spawn(async move { gateway.serve(listeners, gateway_cancel).await });
        Self {
            engine,
            client,
            resolver,
            audit,
            dialer,
            dns,
            connect,
            http,
            cancel,
            gateway,
            echo,
        }
    }

    fn resolve(&self, name: &str, ip: &str, alias: Option<&str>) {
        self.resolver.set(
            Name::from_ascii(format!("{name}.")).unwrap(),
            ResolvedChain {
                cname_chain: Vec::new(),
                final_name: Name::from_ascii(format!("{}.", alias.unwrap_or(name))).unwrap(),
                addresses: vec![ResolvedAddress {
                    ip: ip.parse().unwrap(),
                    ttl_secs: 300,
                }],
            },
        );
    }

    async fn query(&self, name: &str, record: RecordType, tcp: bool) -> Message {
        let mut query = Message::new(123, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), record));
        let bytes = query.to_vec().unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            let bytes = if tcp {
                let mut stream = TcpStream::connect(self.dns).await.unwrap();
                stream.write_u16(bytes.len() as u16).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                let length = stream.read_u16().await.unwrap();
                let mut bytes = vec![0; usize::from(length)];
                stream.read_exact(&mut bytes).await.unwrap();
                bytes
            } else {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                socket.send_to(&bytes, self.dns).await.unwrap();
                let mut response = vec![0; 4096];
                let (length, _) = socket.recv_from(&mut response).await.unwrap();
                response.truncate(length);
                response
            };
            Message::from_vec(&bytes).unwrap()
        })
        .await
        .unwrap()
    }

    async fn tunnel(&self, frontend: ConnectFrontend, host: &str, port: u16, allowed: bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let target = host
                .parse::<IpAddr>()
                .map(ConnectTarget::Ip)
                .unwrap_or_else(|_| ConnectTarget::Hostname(host.to_owned()));
            let mut stream = TcpStream::connect(if frontend == ConnectFrontend::Http {
                self.http
            } else {
                self.connect
            })
            .await
            .unwrap();
            match frontend {
                ConnectFrontend::Custom => {
                    stream
                        .write_all(&connect_proto::encode_request(&ConnectRequest {
                            protocol: ConnectProtocol::Tcp,
                            target,
                            port,
                            expected_ip: None,
                        }))
                        .await
                        .unwrap();
                    let mut reply = [0; 2];
                    stream.read_exact(&mut reply).await.unwrap();
                    assert_eq!(
                        reply[1],
                        if allowed {
                            ConnectStatus::Ok
                        } else {
                            ConnectStatus::PolicyDenied
                        } as u8,
                        "{host}:{port}"
                    );
                }
                ConnectFrontend::Socks5 => {
                    stream.write_all(&[5, 1, 0]).await.unwrap();
                    let mut reply = [0; 2];
                    stream.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply, [5, 0]);
                    let mut request = vec![5, 1, 0];
                    match target {
                        ConnectTarget::Ip(IpAddr::V4(ip)) => {
                            request.push(1);
                            request.extend(ip.octets());
                        }
                        ConnectTarget::Ip(IpAddr::V6(ip)) => {
                            request.push(4);
                            request.extend(ip.octets());
                        }
                        ConnectTarget::Hostname(name) => {
                            request.extend([3, name.len() as u8]);
                            request.extend(name.bytes());
                        }
                    }
                    request.extend(port.to_be_bytes());
                    stream.write_all(&request).await.unwrap();
                    let mut reply = [0; 10];
                    stream.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply[1], if allowed { 0 } else { 2 }, "{host}:{port}");
                }
                ConnectFrontend::Http => {
                    let host = if host.contains(':') {
                        format!("[{host}]")
                    } else {
                        host.to_owned()
                    };
                    let authority = format!("{host}:{port}");
                    stream
                        .write_all(
                            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                    let mut reply = Vec::new();
                    while !reply.ends_with(b"\r\n\r\n") {
                        reply.push(stream.read_u8().await.unwrap());
                        assert!(reply.len() < 8192);
                    }
                    let reply = String::from_utf8(reply).unwrap();
                    assert!(
                        reply.starts_with(if allowed {
                            "HTTP/1.1 200"
                        } else {
                            "HTTP/1.1 403"
                        }),
                        "{host}:{port}: {reply}"
                    );
                }
            }
            if allowed {
                stream.write_all(b"fixture").await.unwrap();
                let mut echoed = [0; 7];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"fixture");
            }
        })
        .await
        .unwrap();
    }

    async fn stop(self) {
        self.cancel.cancel();
        self.gateway.await.unwrap().unwrap();
        self.echo.await.unwrap();
        assert!(
            !self
                .engine
                .github_meta()
                .is_some_and(|metadata| metadata.status().grants_active)
        );
    }
}

#[tokio::test]
async fn failed_bootstrap_is_an_error_not_a_ready_exact_host_fallback() {
    let engine = Arc::new(PolicyEngine::compile(&policy()).unwrap());
    let audit = Arc::new(CollectingAuditSink::new());
    let gateway = Gateway::new(
        Arc::clone(&engine),
        Arc::new(StaticResolver::new()),
        Arc::new(DirectDialer),
        Arc::clone(&audit) as Arc<_>,
        GatewayConfig::default(),
    )
    .with_github_meta_client(Arc::new(FixtureClient::new(vec![Err(
        GitHubMetaError::HttpStatus(503),
    )])));
    let listeners = GatewayListeners::bind(None, "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert!(
        gateway
            .serve(listeners, CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(
        engine.github_meta().unwrap().status().state,
        GitHubMetaState::Unavailable
    );
    assert!(
        matches!(&audit.events()[0], AuditEvent::GitHubMeta { status }
        if !status.grants_active && status.last_error == Some(GitHubMetaError::HttpStatus(503)))
    );
}

#[tokio::test]
async fn metadata_scope_is_enforced_across_dns_native_socks_http_and_ip_families() {
    for frontend in [ConnectFrontend::Custom, ConnectFrontend::Socks5] {
        let mut raw = policy();
        raw.blocked_domains = vec!["blocked.github.test".to_owned()];
        raw.blocked_networks = vec!["203.0.113.9/32".to_owned()];
        raw.allowed_ports = vec![sendbox_policy::PortRule {
            protocol: sendbox_policy::Protocol::Tcp,
            port: 443,
        }];
        let h = Harness::start(
            raw,
            frontend,
            vec![metadata(
                &["*.github.test", "edge.cdn.test"],
                "203.0.113.0/24",
                "2001:db8:1234::/48",
                "\"v1\"",
            )],
        )
        .await;
        h.resolve("download.github.test", "203.0.113.1", Some("edge.cdn.test"));
        h.resolve("v6.github.test", "2001:db8:1234::1", None);
        h.resolve("blocked.github.test", "203.0.113.1", None);
        h.resolve("private.github.test", "10.0.0.1", None);
        h.resolve("google.test", "203.0.113.1", None);
        for (name, record, tcp) in [
            ("download.github.test", RecordType::A, false),
            ("v6.github.test", RecordType::AAAA, true),
        ] {
            let response = h.query(name, record, tcp).await;
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(!response.answers.is_empty());
        }
        for name in [
            "blocked.github.test",
            "private.github.test",
            "google.test",
            "notgithub.test",
        ] {
            assert_eq!(
                h.query(name, RecordType::A, false)
                    .await
                    .metadata
                    .response_code,
                ResponseCode::Refused
            );
        }
        for frontend in [frontend, ConnectFrontend::Http] {
            for host in [
                "download.github.test",
                "v6.github.test",
                "203.0.113.1",
                "2001:db8:1234::1",
            ] {
                h.tunnel(frontend, host, 443, true).await;
            }
            for host in [
                "blocked.github.test",
                "private.github.test",
                "google.test",
                "203.0.113.9",
                "::ffff:203.0.113.9",
                "203.0.114.1",
                "2001:db8:9999::1",
                "10.0.0.1",
                "fd00::1",
                "169.254.169.254",
                "100.100.100.200",
            ] {
                h.tunnel(frontend, host, 443, false).await;
            }
            h.tunnel(frontend, "203.0.113.1", 80, false).await;
        }
        assert!(
            h.dialer
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|address| address.ip().is_ipv6())
        );
        assert_eq!(h.client.requests.lock().unwrap().as_slice(), [None]);
        h.stop().await;
    }
}

#[tokio::test]
async fn wildcard_grants_keep_apex_exact_host_and_label_boundaries_on_every_frontend() {
    for frontend in [ConnectFrontend::Custom, ConnectFrontend::Socks5] {
        let mut raw = policy();
        raw.allowed_domains = vec!["*.tools.test".to_owned(), "exact.test".to_owned()];
        raw.blocked_domains = vec!["blocked.tools.test".to_owned()];
        let h = Harness::start(raw, frontend, Vec::new()).await;
        for host in [
            "a.tools.test",
            "nested.a.tools.test",
            "exact.test",
            "tools.test",
            "nottools.test",
            "tools.test.evil.test",
            "child.exact.test",
            "blocked.tools.test",
        ] {
            h.resolve(host, "203.0.113.1", None);
            let allowed = matches!(host, "a.tools.test" | "nested.a.tools.test" | "exact.test");
            assert_eq!(
                h.query(host, RecordType::A, false)
                    .await
                    .metadata
                    .response_code,
                if allowed {
                    ResponseCode::NoError
                } else {
                    ResponseCode::Refused
                }
            );
            h.tunnel(frontend, host, 443, allowed).await;
            h.tunnel(ConnectFrontend::Http, host, 443, allowed).await;
        }
        assert!(h.client.requests.lock().unwrap().is_empty());
        h.stop().await;
    }
}

#[tokio::test]
async fn refresh_retires_removed_domains_networks_and_cached_cname_authorizations() {
    let h = Harness::start(
        policy(),
        ConnectFrontend::Socks5,
        vec![
            metadata(
                &["*.github.test", "edge.cdn.test"],
                "203.0.113.0/24",
                "2001:db8:1234::/48",
                "\"v1\"",
            ),
            metadata(
                &["*.github.test", "new.test"],
                "198.51.100.0/24",
                "2001:db8:5678::/48",
                "\"v2\"",
            ),
            Ok(GitHubMetaResponse::Modified {
                body: b"{malformed".to_vec(),
                etag: Some("\"bad\"".to_owned()),
            }),
            Ok(GitHubMetaResponse::NotModified),
        ],
    )
    .await;
    h.resolve("download.github.test", "203.0.113.1", Some("edge.cdn.test"));
    h.resolve("new.test", "198.51.100.1", None);
    assert_eq!(
        h.query("download.github.test", RecordType::A, false)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    h.tunnel(ConnectFrontend::Socks5, "download.github.test", 443, true)
        .await;
    h.tunnel(ConnectFrontend::Http, "new.test", 443, false)
        .await;
    let metadata = h.engine.github_meta().unwrap();
    metadata
        .refresh_once(h.client.as_ref(), &h.engine, h.audit.as_ref())
        .await
        .unwrap();
    h.tunnel(ConnectFrontend::Socks5, "download.github.test", 443, false)
        .await;
    h.tunnel(ConnectFrontend::Http, "new.test", 443, true).await;
    h.tunnel(ConnectFrontend::Socks5, "203.0.113.1", 443, false)
        .await;
    h.tunnel(ConnectFrontend::Http, "198.51.100.1", 443, true)
        .await;
    h.tunnel(ConnectFrontend::Socks5, "2001:db8:1234::1", 443, false)
        .await;
    h.tunnel(ConnectFrontend::Http, "2001:db8:5678::1", 443, true)
        .await;
    let previous = metadata.status();
    assert!(
        metadata
            .refresh_once(h.client.as_ref(), &h.engine, h.audit.as_ref())
            .await
            .is_err()
    );
    assert_eq!(metadata.status().state, GitHubMetaState::Degraded);
    assert_eq!(metadata.status().published_scope, previous.published_scope);
    h.tunnel(ConnectFrontend::Http, "new.test", 443, true).await;
    metadata
        .refresh_once(h.client.as_ref(), &h.engine, h.audit.as_ref())
        .await
        .unwrap();
    assert_eq!(metadata.status().state, GitHubMetaState::Fresh);
    assert_eq!(
        h.client.requests.lock().unwrap().as_slice(),
        [
            None,
            Some("\"v1\"".to_owned()),
            Some("\"v2\"".to_owned()),
            Some("\"v2\"".to_owned()),
        ]
    );
    h.stop().await;
}

#[tokio::test]
async fn restarting_the_gateway_fetches_fresh_metadata_and_cannot_reuse_dns_pins() {
    let engine = Arc::new(PolicyEngine::compile(&policy()).unwrap());
    let client = Arc::new(FixtureClient::new(vec![
        metadata(
            &["old.test"],
            "203.0.113.0/24",
            "2001:db8:1234::/48",
            "\"old\"",
        ),
        metadata(
            &["new.test"],
            "198.51.100.0/24",
            "2001:db8:5678::/48",
            "\"new\"",
        ),
    ]));
    let gateway = Gateway::new(
        Arc::clone(&engine),
        Arc::new(StaticResolver::new()),
        Arc::new(DirectDialer),
        Arc::new(CollectingAuditSink::new()),
        GatewayConfig::default(),
    )
    .with_github_meta_client(Arc::clone(&client) as Arc<_>);
    let cache = gateway.authorizations();
    let mut previous_revision = 0;
    for name in ["old.test", "new.test"] {
        let cancel = CancellationToken::new();
        gateway.prepare_github_meta(&cancel).await.unwrap();
        assert!(engine.evaluate_domain_name(name).unwrap());
        let revision = engine.snapshot().revision();
        assert_ne!(revision, previous_revision);
        previous_revision = revision;
        assert!(cache.is_empty());
        cache.authorize_for_revision(
            name,
            "203.0.113.1".parse().unwrap(),
            Duration::from_secs(300),
            revision,
        );
        let listeners = GatewayListeners::bind(None, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (result, ()) = tokio::join!(gateway.serve(listeners, cancel.clone()), async {
            tokio::task::yield_now().await;
            cancel.cancel();
        });
        result.unwrap();
        assert!(cache.is_empty());
        assert!(!engine.github_meta().unwrap().status().grants_active);
    }

    assert_eq!(client.requests.lock().unwrap().as_slice(), [None, None]);
}

#[tokio::test]
async fn aborting_the_gateway_future_cancels_its_owned_refresh_and_scope() {
    let h = Harness::start(
        policy(),
        ConnectFrontend::Socks5,
        vec![metadata(
            &["fixture.test"],
            "203.0.113.0/24",
            "2001:db8:1234::/48",
            "\"fixture\"",
        )],
    )
    .await;
    tokio::task::yield_now().await;
    assert!(h.engine.github_meta().unwrap().status().grants_active);
    h.gateway.abort();
    assert!(h.gateway.await.unwrap_err().is_cancelled());
    assert!(h.cancel.is_cancelled());
    assert!(!h.engine.github_meta().unwrap().status().grants_active);
    h.echo.await.unwrap();
}
