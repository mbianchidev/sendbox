//! Fixed-origin HTTPS transport using the gateway's marked, exact-IP dialer.
//! No environment proxy, OS re-resolution, redirects, or credentials.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::rr::Name;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, ETAG, IF_NONE_MATCH};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::task::AbortOnDropHandle;

use crate::address::{canonicalize, classify};
use crate::dialer::Dialer;
use crate::dns_budget::DnsGuard;
use crate::github_meta::{
    GITHUB_META_API_VERSION, GitHubMetaClient, GitHubMetaError, GitHubMetaResponse, MAX_META_BYTES,
    META_REQUEST_TIMEOUT,
};
use crate::policy::PolicyEngine;
use crate::resolver::UpstreamResolver;
use sendbox_policy::DnsRecordType;

const META_HOST: &str = "api.github.com";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

pub struct OfficialGitHubMetaClient<R: UpstreamResolver> {
    resolver: Arc<R>,
    dialer: Arc<dyn Dialer>,
}

impl<R: UpstreamResolver> OfficialGitHubMetaClient<R> {
    #[must_use]
    pub fn new(resolver: Arc<R>, dialer: Arc<dyn Dialer>) -> Self {
        Self { resolver, dialer }
    }

    async fn fetch_inner(
        &self,
        policy: &PolicyEngine,
        etag: Option<&str>,
        tls: Arc<ClientConfig>,
    ) -> Result<GitHubMetaResponse, GitHubMetaError> {
        if !policy.github_meta_name_permitted(META_HOST) {
            return Err(GitHubMetaError::PolicyDenied);
        }
        let name = Name::from_ascii("api.github.com.").expect("fixed Meta hostname");
        let resolved = self
            .resolver
            .resolve(&name)
            .await
            .map_err(|_| GitHubMetaError::Resolution)?;
        let guard = DnsGuard::from_policy(policy.dns_policy());
        for name in resolved.names_to_validate() {
            let name = crate::domain::normalize_domain(&name.to_ascii())
                .map_err(|_| GitHubMetaError::Resolution)?;
            if !policy.github_meta_name_permitted(&name) || guard.check_structure(&name).is_err() {
                return Err(GitHubMetaError::PolicyDenied);
            }
        }
        let mut addresses = Vec::new();
        for address in resolved.addresses {
            let ip = canonicalize(address.ip);
            if classify(ip).is_restricted() || !policy.address_permitted(ip).allowed {
                return Err(GitHubMetaError::PolicyDenied);
            }
            let qtype = if ip.is_ipv4() {
                DnsRecordType::A
            } else {
                DnsRecordType::Aaaa
            };
            if guard.record_type_allowed(qtype) {
                addresses.push(ip);
            }
        }
        addresses.sort();
        addresses.dedup();
        addresses.truncate(guard.max_response_records());
        if addresses.is_empty() {
            return Err(GitHubMetaError::Resolution);
        }
        let mut last_error = GitHubMetaError::Transport("connect");
        for ip in addresses {
            let stream = match self
                .dialer
                .dial(SocketAddr::new(ip, 443), CONNECT_TIMEOUT)
                .await
            {
                Ok(stream) => stream,
                Err(_) => {
                    last_error = GitHubMetaError::Transport("connect");
                    continue;
                }
            };
            let tls = TlsConnector::from(Arc::clone(&tls))
                .connect(
                    ServerName::try_from(META_HOST).expect("fixed TLS name"),
                    stream,
                )
                .await
                .map_err(|_| GitHubMetaError::Transport("TLS verification"))?;
            return fetch_http(tls, etag).await;
        }
        Err(last_error)
    }
}

#[async_trait::async_trait]
impl<R: UpstreamResolver + 'static> GitHubMetaClient for OfficialGitHubMetaClient<R> {
    async fn fetch(
        &self,
        policy: &PolicyEngine,
        etag: Option<&str>,
    ) -> Result<GitHubMetaResponse, GitHubMetaError> {
        tokio::time::timeout(META_REQUEST_TIMEOUT, async {
            self.fetch_inner(policy, etag, tls_config()?).await
        })
        .await
        .map_err(|_| GitHubMetaError::Timeout)?
    }
}

fn tls_config() -> Result<Arc<ClientConfig>, GitHubMetaError> {
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() || native.certs.is_empty() {
        return Err(GitHubMetaError::TlsRoots);
    }
    let mut roots = RootCertStore::empty();
    for certificate in native.certs {
        roots
            .add(certificate)
            .map_err(|_| GitHubMetaError::TlsRoots)?;
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| GitHubMetaError::TlsRoots)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn fetch_http<T>(stream: T, etag: Option<&str>) -> Result<GitHubMetaResponse, GitHubMetaError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut request = Request::builder()
        .method("GET")
        .uri("/meta")
        .header("Host", META_HOST)
        .header("Accept", "application/vnd.github+json")
        .header("Accept-Encoding", "identity")
        .header("X-GitHub-Api-Version", GITHUB_META_API_VERSION)
        .header("User-Agent", concat!("sendbox/", env!("CARGO_PKG_VERSION")))
        .header("Connection", "close");
    if let Some(etag) = etag {
        request = request.header(IF_NONE_MATCH, etag);
    }
    let request = request
        .body(Empty::<Bytes>::new())
        .map_err(|_| GitHubMetaError::InvalidResponse)?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| GitHubMetaError::Transport("HTTP handshake"))?;
    let _driver = AbortOnDropHandle::new(tokio::spawn(connection));
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| GitHubMetaError::Transport("HTTP response"))?;
    if response.status() == StatusCode::NOT_MODIFIED {
        return if etag.is_some() {
            Ok(GitHubMetaResponse::NotModified)
        } else {
            Err(GitHubMetaError::UnexpectedNotModified)
        };
    }
    if response.status() != StatusCode::OK {
        return Err(GitHubMetaError::HttpStatus(response.status().as_u16()));
    }
    if response
        .headers()
        .get(CONTENT_ENCODING)
        .is_some_and(|encoding| encoding != "identity")
    {
        return Err(GitHubMetaError::InvalidResponse);
    }
    if let Some(length) = response.headers().get(CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|length| length.parse::<u64>().ok())
            .ok_or(GitHubMetaError::InvalidResponse)?;
        if length > MAX_META_BYTES as u64 {
            return Err(GitHubMetaError::LimitExceeded);
        }
    }
    if response.headers().get_all(ETAG).iter().count() > 1 {
        return Err(GitHubMetaError::InvalidResponse);
    }
    let etag = response
        .headers()
        .get(ETAG)
        .map(|etag| {
            etag.to_str()
                .ok()
                .filter(|etag| crate::github_meta::valid_etag(etag))
                .map(str::to_owned)
                .ok_or(GitHubMetaError::InvalidResponse)
        })
        .transpose()?;
    let body = Limited::new(response.into_body(), MAX_META_BYTES)
        .collect()
        .await
        .map_err(|_| GitHubMetaError::InvalidResponse)?
        .to_bytes()
        .to_vec();
    Ok(GitHubMetaResponse::Modified { body, etag })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_resolver::StaticResolver;
    use crate::resolver::{ResolvedAddress, ResolvedChain};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    #[ignore = "explicit anonymous HTTPS qualification against the official Meta API"]
    async fn live_official_meta_contract() {
        let addresses = tokio::net::lookup_host((META_HOST, 443))
            .await
            .unwrap()
            .map(|address| ResolvedAddress {
                ip: address.ip(),
                ttl_secs: 60,
            })
            .collect();
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            Name::from_ascii("api.github.com.").unwrap(),
            ResolvedChain {
                cname_chain: Vec::new(),
                final_name: Name::from_ascii("api.github.com.").unwrap(),
                addresses,
            },
        );
        let client = OfficialGitHubMetaClient::new(resolver, Arc::new(crate::dialer::DirectDialer));
        let GitHubMetaResponse::Modified { body, etag } =
            client.fetch(&policy(false), None).await.unwrap()
        else {
            panic!("an unconditional request must return a complete document")
        };
        let scope = crate::github_meta::GitHubMetaScope::parse(&body).unwrap();
        assert!(!scope.domains.is_empty() && !scope.networks.is_empty());
        assert!(
            scope
                .networks
                .iter()
                .any(|network| matches!(network, ipnet::IpNet::V6(_)))
        );
        eprintln!(
            "official Meta: {} domains, {} networks, SHA-256 {}, ETag {:?}",
            scope.domains.len(),
            scope.networks.len(),
            scope.sha256,
            etag
        );
    }

    async fn exchange(
        response: &[u8],
        etag: Option<&str>,
    ) -> (Result<GitHubMetaResponse, GitHubMetaError>, String) {
        let (client, mut server) = tokio::io::duplex(8192);
        let response = response.to_vec();
        let server = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(server.read_u8().await.unwrap());
            }
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
            String::from_utf8(request).unwrap()
        });
        let result = fetch_http(client, etag).await;
        (result, server.await.unwrap())
    }

    #[tokio::test]
    async fn fixed_request_is_anonymous_conditional_and_never_redirected() {
        let (response, request) = exchange(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nETag: \"fixture\"\r\n\r\n{}",
            Some("\"previous\""),
        )
        .await;
        assert!(
            matches!(response, Ok(GitHubMetaResponse::Modified { body, etag })
            if body == b"{}" && etag.as_deref() == Some("\"fixture\""))
        );
        let request = request.to_ascii_lowercase();
        assert!(request.starts_with("get /meta http/1.1\r\n"));
        assert!(request.contains("\r\nhost: api.github.com\r\n"));
        assert!(request.contains("\r\nif-none-match: \"previous\"\r\n"));
        assert!(request.contains("\r\nx-github-api-version: 2022-11-28\r\n"));
        assert!(!request.contains("authorization") && !request.contains("cookie"));
        let (redirect, _) = exchange(
            b"HTTP/1.1 302 Found\r\nLocation: https://unrelated.test/\r\nContent-Length: 0\r\n\r\n",
            None,
        )
        .await;
        assert!(matches!(redirect, Err(GitHubMetaError::HttpStatus(302))));
        let (uncached, _) = exchange(b"HTTP/1.1 304 Not Modified\r\n\r\n", None).await;
        assert!(matches!(
            uncached,
            Err(GitHubMetaError::UnexpectedNotModified)
        ));
        let (cached, _) = exchange(b"HTTP/1.1 304 Not Modified\r\n\r\n", Some("\"cached\"")).await;
        assert!(matches!(cached, Ok(GitHubMetaResponse::NotModified)));
    }

    #[tokio::test]
    async fn oversized_and_encoded_responses_are_rejected() {
        for headers in [
            format!("Content-Length: {}\r\n", MAX_META_BYTES + 1),
            "Content-Length: 0\r\nContent-Encoding: gzip\r\n".to_owned(),
        ] {
            let (response, _) =
                exchange(format!("HTTP/1.1 200 OK\r\n{headers}\r\n").as_bytes(), None).await;
            assert!(response.is_err());
        }
    }

    struct LocalDialer(SocketAddr);
    #[async_trait::async_trait]
    impl Dialer for LocalDialer {
        async fn dial(
            &self,
            address: SocketAddr,
            deadline: Duration,
        ) -> std::io::Result<TcpStream> {
            assert_eq!(address, "203.0.113.10:443".parse().unwrap());
            crate::dialer::DirectDialer.dial(self.0, deadline).await
        }
    }

    fn policy(blocked: bool) -> PolicyEngine {
        PolicyEngine::compile(
            &serde_json::from_value(serde_json::json!({
                "default_action": "deny",
                "allowed_domains": ["github.com"],
                "blocked_domains": if blocked { vec!["api.github.com"] } else { Vec::new() },
                "allow_dns": true
            }))
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn official_client_pins_dns_and_verifies_the_fixed_tls_identity() {
        for certificate_name in ["api.github.com", "lookalike.test"] {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec![certificate_name.to_owned()]).unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
                )
                .unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let client_tls = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dialer = Arc::new(LocalDialer(listener.local_addr().unwrap()));
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let accepted = TlsAcceptor::from(Arc::new(server)).accept(stream).await;
                if certificate_name != META_HOST {
                    assert!(accepted.is_err());
                    return;
                }
                let mut stream = accepted.unwrap();
                assert_eq!(stream.get_ref().1.server_name(), Some(META_HOST));
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
            });
            let resolver = Arc::new(StaticResolver::new());
            resolver.set(
                Name::from_ascii("api.github.com.").unwrap(),
                ResolvedChain {
                    cname_chain: Vec::new(),
                    final_name: Name::from_ascii("api.github.com.").unwrap(),
                    addresses: vec![ResolvedAddress {
                        ip: "203.0.113.10".parse().unwrap(),
                        ttl_secs: 300,
                    }],
                },
            );
            let client = OfficialGitHubMetaClient::new(resolver, dialer);
            let result = client
                .fetch_inner(&policy(false), None, Arc::new(client_tls))
                .await;
            assert_eq!(result.is_ok(), certificate_name == META_HOST);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn explicit_api_deny_prevents_the_control_plane_request() {
        let client = OfficialGitHubMetaClient::new(
            Arc::new(StaticResolver::new()),
            Arc::new(crate::dialer::DirectDialer),
        );
        let roots = RootCertStore::empty();
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        assert!(matches!(
            client
                .fetch_inner(&policy(true), None, Arc::new(config))
                .await,
            Err(GitHubMetaError::PolicyDenied)
        ));
    }
}
