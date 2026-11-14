//! Host-side fixed-origin HTTPS transport for the official Meta document.
//! System DNS, direct exact-IP dials and verified TLS; no environment proxy,
//! redirects, or credentials. Guests never call this: they install the
//! host's validated response.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, ETAG, IF_NONE_MATCH, RETRY_AFTER};
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::task::AbortOnDropHandle;

use crate::address::{canonicalize, classify};
use crate::dialer::{Dialer, DirectDialer};
use crate::github_meta::{
    GITHUB_META_API_VERSION, GitHubMetaError, GitHubMetaResponse, MAX_META_BYTES,
    META_REQUEST_TIMEOUT,
};

pub const META_HOST: &str = "api.github.com";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
// GitHub publishes resets at most an hour ahead; ignore implausible values.
const MAX_RATE_LIMIT_WAIT_SECS: u64 = 60 * 60;

/// Fetches the official Meta document once, conditionally when `etag` is set.
/// Restricted resolutions (private, link-local, metadata) are refused.
pub async fn fetch_official_github_meta(
    etag: Option<&str>,
) -> Result<GitHubMetaResponse, GitHubMetaError> {
    tokio::time::timeout(META_REQUEST_TIMEOUT, async {
        let tls = tls_config()?;
        let addresses = resolve_meta_host().await?;
        fetch_via(&addresses, &DirectDialer, tls, etag).await
    })
    .await
    .map_err(|_| GitHubMetaError::Timeout)?
}

async fn resolve_meta_host() -> Result<Vec<IpAddr>, GitHubMetaError> {
    let mut addresses = Vec::new();
    for address in tokio::net::lookup_host((META_HOST, 443))
        .await
        .map_err(|_| GitHubMetaError::Resolution)?
    {
        let ip = canonicalize(address.ip());
        if classify(ip).is_restricted() {
            return Err(GitHubMetaError::PolicyDenied);
        }
        addresses.push(ip);
    }
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(GitHubMetaError::Resolution);
    }
    Ok(addresses)
}

async fn fetch_via(
    addresses: &[IpAddr],
    dialer: &dyn Dialer,
    tls: Arc<ClientConfig>,
    etag: Option<&str>,
) -> Result<GitHubMetaResponse, GitHubMetaError> {
    for ip in addresses {
        let Ok(stream) = dialer
            .dial(SocketAddr::new(*ip, 443), CONNECT_TIMEOUT)
            .await
        else {
            continue;
        };
        let tls = TlsConnector::from(Arc::clone(&tls))
            .connect(
                ServerName::try_from(META_HOST).expect("fixed TLS name"),
                stream,
            )
            .await
            .map_err(|_| GitHubMetaError::Transport("TLS verification".to_owned()))?;
        return fetch_http(tls, etag).await;
    }
    Err(GitHubMetaError::Transport("connect".to_owned()))
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
        .map_err(|_| GitHubMetaError::Transport("HTTP handshake".to_owned()))?;
    let _driver = AbortOnDropHandle::new(tokio::spawn(connection));
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| GitHubMetaError::Transport("HTTP response".to_owned()))?;
    if response.status() == StatusCode::NOT_MODIFIED {
        return if etag.is_some() {
            Ok(GitHubMetaResponse::NotModified)
        } else {
            Err(GitHubMetaError::UnexpectedNotModified)
        };
    }
    if response.status() != StatusCode::OK {
        return Err(status_error(response.status(), response.headers()));
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

/// GitHub signals primary limits with `x-ratelimit-remaining: 0` and secondary
/// limits with `retry-after`, on either 403 or 429.
fn status_error(status: StatusCode, headers: &HeaderMap) -> GitHubMetaError {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
    };
    let exhausted = header("x-ratelimit-remaining") == Some(0);
    let retry_after = header(RETRY_AFTER.as_str());
    if !(status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN && (exhausted || retry_after.is_some())))
    {
        return GitHubMetaError::HttpStatus(status.as_u16());
    }
    let now = crate::github_meta::unix_now().ok();
    let reset_unix_seconds = retry_after
        .and_then(|seconds| now.map(|now| now.saturating_add(seconds)))
        .or_else(|| header("x-ratelimit-reset").filter(|_| exhausted))
        .filter(|reset| {
            now.is_none_or(|now| *reset <= now.saturating_add(MAX_RATE_LIMIT_WAIT_SECS))
        });
    GitHubMetaError::RateLimited { reset_unix_seconds }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    #[ignore = "explicit anonymous HTTPS qualification against the official Meta API"]
    async fn live_official_meta_contract() {
        let GitHubMetaResponse::Modified { body, etag } =
            fetch_official_github_meta(None).await.unwrap()
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
    async fn primary_and_secondary_rate_limits_carry_their_reset_time() {
        let now = crate::github_meta::unix_now().unwrap();
        let reset = now + 900;
        let (primary, _) = exchange(
            format!(
                "HTTP/1.1 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: {reset}\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
            None,
        )
        .await;
        assert_eq!(
            primary.err(),
            Some(GitHubMetaError::RateLimited {
                reset_unix_seconds: Some(reset)
            })
        );
        let (secondary, _) = exchange(
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Length: 0\r\n\r\n",
            None,
        )
        .await;
        assert!(matches!(
            secondary,
            Err(GitHubMetaError::RateLimited { reset_unix_seconds: Some(reset) })
                if (now + 60..=now + 61).contains(&reset)
        ));
        let (implausible, _) = exchange(
            b"HTTP/1.1 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 99999999999\r\nContent-Length: 0\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(
            implausible.err(),
            Some(GitHubMetaError::RateLimited {
                reset_unix_seconds: None
            })
        );
        let (forbidden, _) = exchange(
            b"HTTP/1.1 403 Forbidden\r\nX-RateLimit-Remaining: 12\r\nContent-Length: 0\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(forbidden.err(), Some(GitHubMetaError::HttpStatus(403)));
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

    #[tokio::test]
    async fn exact_ip_dial_verifies_the_fixed_tls_identity() {
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
            let dialer = LocalDialer(listener.local_addr().unwrap());
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
            let result = fetch_via(
                &["203.0.113.10".parse().unwrap()],
                &dialer,
                Arc::new(client_tls),
                None,
            )
            .await;
            assert_eq!(result.is_ok(), certificate_name == META_HOST);
            server.await.unwrap();
        }
    }
}
