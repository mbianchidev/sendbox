use std::{fmt, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use http::{HeaderName, HeaderValue, Method, StatusCode};
use sendbox_runtime::CancellationToken;
use sendbox_secrets::{SensitiveBytes, SensitiveUrl, TransformedRequest};
use tokio::net::lookup_host;
use zeroize::Zeroizing;

use crate::{BrokerLimits, CredentialBrokerError, UpstreamAddressPolicy, http1::strip_hop_by_hop};

pub struct UpstreamRequest {
    method: Method,
    url: SensitiveUrl,
    headers: Vec<(HeaderName, SensitiveBytes)>,
    body: SensitiveBytes,
    max_response_body_bytes: usize,
}

impl UpstreamRequest {
    pub(crate) fn from_transformed(
        request: TransformedRequest,
        max_response_body_bytes: usize,
    ) -> Self {
        Self {
            method: request.method,
            url: request.url,
            headers: request.headers,
            body: request.body,
            max_response_body_bytes,
        }
    }

    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    #[must_use]
    pub fn url(&self) -> &str {
        self.url.expose()
    }

    #[must_use]
    pub fn headers(&self) -> &[(HeaderName, SensitiveBytes)] {
        &self.headers
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.expose()
    }
}

impl fmt::Debug for UpstreamRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamRequest")
            .field("method", &self.method)
            .field("url", &"[REDACTED]")
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub struct UpstreamResponse {
    pub status: StatusCode,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    body: Zeroizing<Vec<u8>>,
}

impl UpstreamResponse {
    #[must_use]
    pub fn new(status: StatusCode, headers: Vec<(HeaderName, HeaderValue)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body: Zeroizing::new(body),
        }
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.as_ref()
    }

    #[must_use]
    pub(crate) fn into_parts(
        self,
    ) -> (
        StatusCode,
        Vec<(HeaderName, HeaderValue)>,
        Zeroizing<Vec<u8>>,
    ) {
        (self.status, self.headers, self.body)
    }
}

impl fmt::Debug for UpstreamResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamResponse")
            .field("status", &self.status)
            .field("headers", &"[REDACTED]")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

#[async_trait]
pub trait UpstreamResolver: Send + Sync {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SocketAddr>, CredentialBrokerError>;
}

#[derive(Debug, Default)]
pub struct SystemResolver;

#[async_trait]
impl UpstreamResolver for SystemResolver {
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SocketAddr>, CredentialBrokerError> {
        let addresses = tokio::select! {
            result = lookup_host((host, port)) => result?.collect::<Vec<_>>(),
            () = cancellation.cancelled() => return Err(CredentialBrokerError::Cancelled),
        };
        if addresses.is_empty() {
            return Err(CredentialBrokerError::Upstream(
                "upstream hostname resolved to no addresses".to_owned(),
            ));
        }
        Ok(addresses)
    }
}

#[async_trait]
pub trait UpstreamTransport: Send + Sync {
    async fn send(
        &self,
        request: &UpstreamRequest,
        limits: &BrokerLimits,
        address_policy: &UpstreamAddressPolicy,
        cancellation: &CancellationToken,
    ) -> Result<UpstreamResponse, CredentialBrokerError>;
}

pub struct PinnedHttpsTransport {
    resolver: Arc<dyn UpstreamResolver>,
}

impl fmt::Debug for PinnedHttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedHttpsTransport")
            .finish_non_exhaustive()
    }
}

impl Default for PinnedHttpsTransport {
    fn default() -> Self {
        Self::new(Arc::new(SystemResolver))
    }
}

impl PinnedHttpsTransport {
    #[must_use]
    pub fn new(resolver: Arc<dyn UpstreamResolver>) -> Self {
        Self { resolver }
    }
}

impl PinnedHttpsTransport {
    /// Resolves, classifies, and pins the upstream addresses, then builds a
    /// certificate-verifying HTTPS/1.1 client bound to exactly those addresses.
    async fn pinned_client(
        &self,
        request: &UpstreamRequest,
        address_policy: &UpstreamAddressPolicy,
        timeouts: ClientTimeouts,
        cancellation: &CancellationToken,
    ) -> Result<(reqwest::Client, url::Url), CredentialBrokerError> {
        let url = url::Url::parse(request.url()).map_err(|_| {
            CredentialBrokerError::Upstream("transformed upstream URL is invalid".to_owned())
        })?;
        if url.scheme() != "https" || url.port_or_known_default() != Some(443) {
            return Err(CredentialBrokerError::Upstream(
                "upstream URL must use verified HTTPS on port 443".to_owned(),
            ));
        }
        let host = url.host_str().ok_or_else(|| {
            CredentialBrokerError::Upstream("upstream URL has no hostname".to_owned())
        })?;
        let resolved = self.resolver.resolve(host, 443, cancellation).await?;
        let mut pinned = Vec::with_capacity(resolved.len());
        for address in resolved {
            let ip = address_policy.authorize(address.ip())?;
            pinned.push(SocketAddr::new(ip, 443));
        }
        pinned.sort_unstable();
        pinned.dedup();

        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .referer(false)
            .connect_timeout(timeouts.connect)
            .read_timeout(timeouts.read)
            .pool_max_idle_per_host(0)
            .danger_accept_invalid_certs(false)
            .danger_accept_invalid_hostnames(false)
            .tls_sni(true)
            .resolve_to_addrs(host, &pinned);
        if let Some(total) = timeouts.total {
            builder = builder.timeout(total);
        }
        let client = builder.build().map_err(|_| {
            CredentialBrokerError::Upstream(
                "could not initialize certificate-verifying HTTPS client".to_owned(),
            )
        })?;
        Ok((client, url))
    }

    async fn open_response(
        &self,
        request: &UpstreamRequest,
        address_policy: &UpstreamAddressPolicy,
        timeouts: ClientTimeouts,
        max_header_count: usize,
        max_header_bytes: usize,
        cancellation: &CancellationToken,
    ) -> Result<reqwest::Response, CredentialBrokerError> {
        let (client, url) = self
            .pinned_client(request, address_policy, timeouts, cancellation)
            .await?;
        let mut builder = client.request(request.method().clone(), url);
        for (name, value) in request.headers() {
            let mut header = HeaderValue::from_bytes(value.expose()).map_err(|_| {
                CredentialBrokerError::Upstream("transformed header value is invalid".to_owned())
            })?;
            header.set_sensitive(true);
            builder = builder.header(name, header);
        }
        builder = builder.body(request.body().to_vec());
        let response = tokio::select! {
            result = builder.send() => result.map_err(|error| {
                CredentialBrokerError::Upstream(format!(
                    "HTTPS request failed ({})",
                    reqwest_error_kind(&error)
                ))
            })?,
            () = cancellation.cancelled() => return Err(CredentialBrokerError::Cancelled),
        };
        let header_bytes = response
            .headers()
            .iter()
            .fold(0_usize, |total, (name, value)| {
                total
                    .saturating_add(name.as_str().len())
                    .saturating_add(value.as_bytes().len())
                    .saturating_add(4)
            });
        if response.headers().len() > max_header_count || header_bytes > max_header_bytes {
            return Err(CredentialBrokerError::Upstream(
                "upstream response headers exceed the configured limit".to_owned(),
            ));
        }
        Ok(response)
    }
}

#[derive(Debug, Clone, Copy)]
struct ClientTimeouts {
    connect: std::time::Duration,
    read: std::time::Duration,
    total: Option<std::time::Duration>,
}

#[async_trait]
impl UpstreamTransport for PinnedHttpsTransport {
    async fn send(
        &self,
        request: &UpstreamRequest,
        limits: &BrokerLimits,
        address_policy: &UpstreamAddressPolicy,
        cancellation: &CancellationToken,
    ) -> Result<UpstreamResponse, CredentialBrokerError> {
        let mut response = self
            .open_response(
                request,
                address_policy,
                ClientTimeouts {
                    connect: limits.upstream_connect_timeout,
                    read: limits.upstream_read_timeout,
                    total: Some(limits.upstream_total_timeout),
                },
                limits.max_header_count,
                limits.max_header_bytes,
                cancellation,
            )
            .await?;
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>();
        if response
            .content_length()
            .is_some_and(|length| length > request.max_response_body_bytes as u64)
        {
            return Err(sendbox_secrets::CredentialPolicyError::ResponseTooLarge.into());
        }
        let mut body = Zeroizing::new(Vec::new());
        loop {
            let chunk = tokio::select! {
                result = response.chunk() => result.map_err(|error| {
                    CredentialBrokerError::Upstream(format!(
                        "upstream response read failed ({})",
                        reqwest_error_kind(&error)
                    ))
                })?,
                () = cancellation.cancelled() => return Err(CredentialBrokerError::Cancelled),
            };
            let Some(chunk) = chunk else {
                break;
            };
            if body.len().saturating_add(chunk.len()) > request.max_response_body_bytes {
                return Err(sendbox_secrets::CredentialPolicyError::ResponseTooLarge.into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(UpstreamResponse {
            status: response.status(),
            headers: strip_hop_by_hop(&headers),
            body,
        })
    }
}

/// Limits for one streamed upstream exchange. The caller enforces the total
/// duration and body size while it forwards chunks.
#[derive(Debug, Clone)]
pub struct StreamingLimits {
    pub connect_timeout: std::time::Duration,
    pub idle_timeout: std::time::Duration,
    pub max_header_count: usize,
    pub max_header_bytes: usize,
}

/// A response body read incrementally, so long-lived event streams reach the
/// agent as they arrive instead of after completion.
#[async_trait]
pub trait ResponseBody: Send {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, CredentialBrokerError>;
}

pub struct StreamingResponse {
    pub status: StatusCode,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Box<dyn ResponseBody>,
}

impl fmt::Debug for StreamingResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamingResponse")
            .field("status", &self.status)
            .field("headers", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait StreamingTransport: Send + Sync {
    async fn open(
        &self,
        request: &UpstreamRequest,
        limits: &StreamingLimits,
        address_policy: &UpstreamAddressPolicy,
        cancellation: &CancellationToken,
    ) -> Result<StreamingResponse, CredentialBrokerError>;
}

struct ReqwestBody(reqwest::Response);

#[async_trait]
impl ResponseBody for ReqwestBody {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, CredentialBrokerError> {
        self.0
            .chunk()
            .await
            .map(|chunk| chunk.map(|bytes| bytes.to_vec()))
            .map_err(|error| {
                CredentialBrokerError::Upstream(format!(
                    "upstream response read failed ({})",
                    reqwest_error_kind(&error)
                ))
            })
    }
}

#[async_trait]
impl StreamingTransport for PinnedHttpsTransport {
    async fn open(
        &self,
        request: &UpstreamRequest,
        limits: &StreamingLimits,
        address_policy: &UpstreamAddressPolicy,
        cancellation: &CancellationToken,
    ) -> Result<StreamingResponse, CredentialBrokerError> {
        let response = self
            .open_response(
                request,
                address_policy,
                ClientTimeouts {
                    connect: limits.connect_timeout,
                    read: limits.idle_timeout,
                    total: None,
                },
                limits.max_header_count,
                limits.max_header_bytes,
                cancellation,
            )
            .await?;
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>();
        Ok(StreamingResponse {
            status: response.status(),
            headers: strip_hop_by_hop(&headers),
            body: Box::new(ReqwestBody(response)),
        })
    }
}

fn reqwest_error_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_builder() {
        "builder"
    } else {
        "transport"
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use http::Method;
    use sendbox_secrets::{
        BrokerRequest, CredentialInjection, CredentialPolicy, RedirectPolicy, SecretName,
        SecretValue,
    };

    use super::*;

    struct FixedResolver {
        addresses: Vec<SocketAddr>,
    }

    #[async_trait]
    impl UpstreamResolver for FixedResolver {
        async fn resolve(
            &self,
            _host: &str,
            _port: u16,
            _cancellation: &CancellationToken,
        ) -> Result<Vec<SocketAddr>, CredentialBrokerError> {
            Ok(self.addresses.clone())
        }
    }

    fn request() -> UpstreamRequest {
        let name = SecretName::new("EXAMPLE_TOKEN").expect("name");
        let policy = CredentialPolicy::new(
            "api.example.com",
            "/v1/",
            CredentialInjection::Bearer,
            [Method::GET],
            0,
            1024,
            RedirectPolicy::Deny,
            name,
        )
        .expect("policy");
        let transformed = policy
            .transform(
                BrokerRequest {
                    method: Method::GET,
                    url: url::Url::parse("https://api.example.com/v1/test").expect("url"),
                    headers: vec![],
                    body: vec![],
                },
                &SecretValue::try_from("token").expect("secret"),
            )
            .expect("transform");
        UpstreamRequest::from_transformed(transformed, 1024)
    }

    #[tokio::test]
    async fn restricted_dns_answers_are_rejected_before_connecting() {
        let transport = PinnedHttpsTransport::new(Arc::new(FixedResolver {
            addresses: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
                443,
            )],
        }));
        let error = transport
            .send(
                &request(),
                &BrokerLimits::default(),
                &UpstreamAddressPolicy::default(),
                &CancellationToken::new(),
            )
            .await
            .expect_err("metadata address");
        assert!(matches!(error, CredentialBrokerError::Upstream(_)));
    }

    #[test]
    fn restricted_addresses_require_exact_explicit_approval() {
        let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        assert!(
            UpstreamAddressPolicy::default()
                .authorize(metadata)
                .is_err()
        );
        assert_eq!(
            UpstreamAddressPolicy::allowing_restricted([metadata])
                .authorize(metadata)
                .expect("explicit approval"),
            metadata
        );
    }
}
