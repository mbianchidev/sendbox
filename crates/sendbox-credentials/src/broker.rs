use std::{fmt, net::SocketAddr, sync::Arc};

use http::{HeaderName, HeaderValue, Method, StatusCode, Uri};
use sendbox_runtime::CancellationToken;
use sendbox_secrets::{
    AuditSafeRequestMetadata, BrokerRequest, SecretName, SecretStore, SecretValue,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    BrokerAgentConfiguration, BrokerConfiguration, CredentialBrokerError, CredentialRule,
    UpstreamRequest, UpstreamResponse, UpstreamTransport,
    http1::{ParsedRequest, read_request, strip_hop_by_hop},
};

pub trait SecretResolver: Send + Sync {
    fn retrieve(&self, name: &SecretName) -> Result<SecretValue, CredentialBrokerError>;
}

impl<T> SecretResolver for T
where
    T: SecretStore,
{
    fn retrieve(&self, name: &SecretName) -> Result<SecretValue, CredentialBrokerError> {
        Ok(SecretStore::retrieve(self, name)?.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerAuditEvent {
    Request(AuditSafeRequestMetadata),
    Response {
        method: Method,
        target_host: String,
        path: String,
        status: StatusCode,
        response_body_bytes: usize,
    },
    Rejected {
        peer: SocketAddr,
        reason: &'static str,
    },
    ListenerFailure {
        reason: &'static str,
    },
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: BrokerAuditEvent);
}

#[derive(Debug, Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _event: BrokerAuditEvent) {}
}

pub struct CredentialBroker {
    configuration: BrokerConfiguration,
    secrets: Arc<dyn SecretResolver>,
    transport: Arc<dyn UpstreamTransport>,
    audit: Arc<dyn AuditSink>,
}

impl fmt::Debug for CredentialBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialBroker")
            .field("configuration", &self.configuration)
            .finish_non_exhaustive()
    }
}

impl CredentialBroker {
    #[must_use]
    pub fn new(
        configuration: BrokerConfiguration,
        secrets: Arc<dyn SecretResolver>,
        transport: Arc<dyn UpstreamTransport>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            configuration,
            secrets,
            transport,
            audit,
        }
    }

    pub async fn start(
        self,
    ) -> Result<(BrokerHandle, BrokerAgentConfiguration), CredentialBrokerError> {
        self.configuration.validate()?;
        let listener = TcpListener::bind(self.configuration.bind.socket_addr()).await?;
        let local_addr = listener.local_addr()?;
        let agent = BrokerAgentConfiguration::new(local_addr, &self.configuration.rules)?;
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(run_listener(listener, self, task_cancellation));
        Ok((
            BrokerHandle {
                local_addr,
                cancellation,
                task: Some(task),
            },
            agent,
        ))
    }
}

pub struct BrokerHandle {
    local_addr: SocketAddr,
    cancellation: CancellationToken,
    task: Option<JoinHandle<Result<(), CredentialBrokerError>>>,
}

impl fmt::Debug for BrokerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl BrokerHandle {
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(mut self) -> Result<(), CredentialBrokerError> {
        self.cancellation.cancel();
        let task = self.task.take().ok_or_else(|| {
            CredentialBrokerError::InvalidConfiguration(
                "credential broker task was already consumed".to_owned(),
            )
        })?;
        task.await.map_err(|error| {
            CredentialBrokerError::Upstream(format!("credential broker task failed: {error}"))
        })?
    }
}

impl Drop for BrokerHandle {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn run_listener(
    listener: TcpListener,
    broker: CredentialBroker,
    cancellation: CancellationToken,
) -> Result<(), CredentialBrokerError> {
    let broker = Arc::new(broker);
    let semaphore = Arc::new(Semaphore::new(broker.configuration.limits.max_connections));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (mut stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) => {
                        broker.audit.record(BrokerAuditEvent::ListenerFailure {
                            reason: "listener accept failure",
                        });
                        tokio::select! {
                            () = cancellation.cancelled() => break,
                            () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                        }
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    broker.audit.record(BrokerAuditEvent::Rejected {
                        peer,
                        reason: "concurrency limit reached",
                    });
                    let _ = write_error_response(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await;
                    continue;
                };
                let broker = Arc::clone(&broker);
                let connection_cancellation = cancellation.clone();
                connections.spawn(async move {
                    let result = handle_connection(
                        &mut stream,
                        peer,
                        &broker,
                        &connection_cancellation,
                        permit,
                    )
                    .await;
                    if let Err(error) = result {
                        broker.audit.record(BrokerAuditEvent::Rejected {
                            peer,
                            reason: rejection_reason(&error),
                        });
                        let status = error_status(&error);
                        let _ = write_error_response(&mut stream, status).await;
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if result.is_err() {
                    broker.audit.record(BrokerAuditEvent::ListenerFailure {
                        reason: "connection task failed",
                    });
                }
            }
        }
    }

    let drain = async { while connections.join_next().await.is_some() {} };
    if timeout(broker.configuration.limits.shutdown_timeout, drain)
        .await
        .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

async fn handle_connection(
    stream: &mut TcpStream,
    _peer: SocketAddr,
    broker: &CredentialBroker,
    cancellation: &CancellationToken,
    _permit: OwnedSemaphorePermit,
) -> Result<(), CredentialBrokerError> {
    let max_request_body = broker
        .configuration
        .rules
        .iter()
        .map(|rule| rule.policy().max_request_body_bytes())
        .max()
        .unwrap_or(0);
    let parsed = read_request(
        stream,
        &broker.configuration.limits,
        max_request_body,
        cancellation,
    )
    .await?;
    validate_host(&parsed, stream.local_addr()?)?;
    let (rule, upstream_url) = select_rule(&parsed, &broker.configuration.rules)?;
    let secret_name = rule.secret_name().clone();
    let secrets = Arc::clone(&broker.secrets);
    let secret = tokio::select! {
        result = tokio::task::spawn_blocking(move || secrets.retrieve(&secret_name)) => {
            result.map_err(|error| {
                CredentialBrokerError::Upstream(format!("secret lookup task failed: {error}"))
            })??
        }
        () = cancellation.cancelled() => return Err(CredentialBrokerError::Cancelled),
    };
    let response =
        forward_with_redirects(broker, rule, parsed, upstream_url, &secret, cancellation).await?;
    write_upstream_response(stream, response).await?;
    Ok(())
}

fn validate_host(
    request: &ParsedRequest,
    local_addr: SocketAddr,
) -> Result<(), CredentialBrokerError> {
    let host = request
        .headers
        .iter()
        .find(|(name, _)| name == http::header::HOST)
        .and_then(|(_, value)| value.to_str().ok())
        .ok_or(CredentialBrokerError::InvalidRequest(
            "Host header is not valid ASCII",
        ))?;
    let expected = local_addr.to_string();
    let localhost = format!("localhost:{}", local_addr.port());
    let loopback_alias_allowed =
        local_addr.ip().is_loopback() && host.eq_ignore_ascii_case(&localhost);
    if host != expected && !loopback_alias_allowed {
        return Err(CredentialBrokerError::InvalidRequest(
            "Host header does not match the credential broker listener",
        ));
    }
    Ok(())
}

fn select_rule<'a>(
    request: &ParsedRequest,
    rules: &'a [CredentialRule],
) -> Result<(&'a CredentialRule, Url), CredentialBrokerError> {
    let uri = request
        .target
        .parse::<Uri>()
        .map_err(|_| CredentialBrokerError::InvalidRequest("request target is invalid"))?;
    let path = uri.path();
    let rule = rules
        .iter()
        .find(|rule| {
            let prefix = rule.route_prefix();
            path == prefix || path.starts_with(&(prefix + "/"))
        })
        .ok_or(CredentialBrokerError::InvalidRequest(
            "request target does not match a credential rule",
        ))?;
    let route_prefix = rule.route_prefix();
    let remainder = request
        .target
        .get(route_prefix.len()..)
        .filter(|value| value.starts_with('/'))
        .ok_or(CredentialBrokerError::InvalidRequest(
            "credential route must be followed by the original upstream path",
        ))?;
    let upstream = Url::parse(&format!(
        "https://{}{}",
        rule.policy().target_host(),
        remainder
    ))
    .map_err(|_| CredentialBrokerError::InvalidRequest("upstream target is invalid"))?;
    Ok((rule, upstream))
}

async fn forward_with_redirects(
    broker: &CredentialBroker,
    rule: &CredentialRule,
    parsed: ParsedRequest,
    initial_url: Url,
    secret: &SecretValue,
    cancellation: &CancellationToken,
) -> Result<UpstreamResponse, CredentialBrokerError> {
    let original_headers = strip_hop_by_hop(&parsed.headers)
        .into_iter()
        .map(|(name, value)| (name, value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let mut method = parsed.method;
    let mut body = Zeroizing::new(parsed.body);
    let mut url = initial_url;

    for redirects in 0..=broker.configuration.limits.max_redirects {
        let transformed = rule.policy().transform(
            BrokerRequest {
                method: method.clone(),
                url: url.clone(),
                headers: original_headers.clone(),
                body: body.to_vec(),
            },
            secret,
        )?;
        broker
            .audit
            .record(BrokerAuditEvent::Request(transformed.audit.clone()));
        let request =
            UpstreamRequest::from_transformed(transformed, rule.policy().max_response_body_bytes());
        let response = timeout(
            broker.configuration.limits.upstream_total_timeout,
            broker.transport.send(
                &request,
                &broker.configuration.limits,
                &broker.configuration.address_policy,
                cancellation,
            ),
        )
        .await
        .map_err(|_| {
            CredentialBrokerError::Upstream(
                "upstream request exceeded the total timeout".to_owned(),
            )
        })??;
        validate_upstream_response(rule, &response, &broker.configuration.limits)?;
        if !response.status.is_redirection() {
            broker.audit.record(BrokerAuditEvent::Response {
                method,
                target_host: rule.policy().target_host().to_owned(),
                path: url.path().to_owned(),
                status: response.status,
                response_body_bytes: response.body().len(),
            });
            return Ok(response);
        }

        if redirects == broker.configuration.limits.max_redirects {
            return Err(CredentialBrokerError::Upstream(
                "upstream redirect limit was exceeded".to_owned(),
            ));
        }
        let location = single_location(&response.headers)?;
        let next = url.join(location).map_err(|_| {
            CredentialBrokerError::Upstream("upstream redirect location is invalid".to_owned())
        })?;
        rule.policy().authorize_redirect(&url, &next)?;
        apply_redirect_semantics(response.status, &mut method, &mut body)?;
        url = next;
    }
    Err(CredentialBrokerError::Upstream(
        "upstream redirect state is invalid".to_owned(),
    ))
}

fn validate_upstream_response(
    rule: &CredentialRule,
    response: &UpstreamResponse,
    limits: &crate::BrokerLimits,
) -> Result<(), CredentialBrokerError> {
    rule.policy()
        .validate_response_size(response.body().len())?;
    let header_bytes = response
        .headers
        .iter()
        .fold(0_usize, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
                .saturating_add(4)
        });
    if response.headers.len() > limits.max_header_count || header_bytes > limits.max_header_bytes {
        return Err(CredentialBrokerError::Upstream(
            "upstream response headers exceed the configured limit".to_owned(),
        ));
    }
    Ok(())
}

fn single_location(headers: &[(HeaderName, HeaderValue)]) -> Result<&str, CredentialBrokerError> {
    let mut locations = headers
        .iter()
        .filter(|(name, _)| name == http::header::LOCATION);
    let (_, value) = locations.next().ok_or_else(|| {
        CredentialBrokerError::Upstream("redirect response has no Location header".to_owned())
    })?;
    if locations.next().is_some() {
        return Err(CredentialBrokerError::Upstream(
            "redirect response has duplicate Location headers".to_owned(),
        ));
    }
    value.to_str().map_err(|_| {
        CredentialBrokerError::Upstream("redirect Location is not valid ASCII".to_owned())
    })
}

fn apply_redirect_semantics(
    status: StatusCode,
    method: &mut Method,
    body: &mut Zeroizing<Vec<u8>>,
) -> Result<(), CredentialBrokerError> {
    match status {
        StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => Ok(()),
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
            if *method == Method::GET || *method == Method::HEAD =>
        {
            Ok(())
        }
        StatusCode::SEE_OTHER => {
            if *method != Method::HEAD {
                *method = Method::GET;
            }
            body.clear();
            Ok(())
        }
        _ => Err(CredentialBrokerError::Upstream(
            "redirect status is unsafe for the request method".to_owned(),
        )),
    }
}

async fn write_upstream_response(
    stream: &mut TcpStream,
    response: UpstreamResponse,
) -> Result<(), CredentialBrokerError> {
    let (status, response_headers, body) = response.into_parts();
    let mut bytes = Vec::new();
    let reason = status.canonical_reason().unwrap_or("Upstream Response");
    bytes.extend_from_slice(format!("HTTP/1.1 {} {reason}\r\n", status.as_u16()).as_bytes());
    for (name, value) in strip_hop_by_hop(&response_headers) {
        if name != http::header::CONTENT_LENGTH {
            bytes.extend_from_slice(name.as_str().as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
    }
    bytes.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    bytes.extend_from_slice(b"connection: close\r\n\r\n");
    bytes.extend_from_slice(&body);
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn write_error_response(
    stream: &mut TcpStream,
    status: StatusCode,
) -> Result<(), CredentialBrokerError> {
    let reason = status.canonical_reason().unwrap_or("Request Failed");
    let body = format!("{reason}\n");
    let response = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        status.as_u16(),
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

fn error_status(error: &CredentialBrokerError) -> StatusCode {
    match error {
        CredentialBrokerError::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
        CredentialBrokerError::InvalidRequest(message)
            if message.contains("CONNECT credential injection") =>
        {
            StatusCode::METHOD_NOT_ALLOWED
        }
        CredentialBrokerError::InvalidRequest(message)
            if message.contains("body exceeds")
                || message.contains("Content-Length is too large") =>
        {
            StatusCode::PAYLOAD_TOO_LARGE
        }
        CredentialBrokerError::InvalidRequest(_) | CredentialBrokerError::Policy(_) => {
            StatusCode::BAD_REQUEST
        }
        CredentialBrokerError::Cancelled => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_GATEWAY,
    }
}

fn rejection_reason(error: &CredentialBrokerError) -> &'static str {
    match error {
        CredentialBrokerError::InvalidRequest(_) => "invalid HTTP request",
        CredentialBrokerError::RequestTimeout => "request read timeout",
        CredentialBrokerError::Cancelled => "broker shutdown",
        CredentialBrokerError::Policy(_) => "credential policy rejection",
        CredentialBrokerError::Secret(_) => "secret lookup failure",
        CredentialBrokerError::Upstream(_) => "upstream failure",
        CredentialBrokerError::Io(_) => "connection I/O failure",
        CredentialBrokerError::InvalidConfiguration(_)
        | CredentialBrokerError::InvalidGitHubMetadata(_)
        | CredentialBrokerError::GitHubCommand(_)
        | CredentialBrokerError::GitHubAuthorization(_)
        | CredentialBrokerError::Runtime(_) => "broker internal failure",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;
    use crate::{
        BrokerBind, BrokerLimits, CredentialRule, UpstreamAddressPolicy,
        upstream::UpstreamTransport,
    };
    use async_trait::async_trait;
    use sendbox_secrets::{CredentialInjection, CredentialPolicy, RedirectPolicy};

    struct StaticSecrets;

    impl SecretResolver for StaticSecrets {
        fn retrieve(&self, _name: &SecretName) -> Result<SecretValue, CredentialBrokerError> {
            SecretValue::try_from("test-token").map_err(Into::into)
        }
    }

    struct QueueTransport {
        responses: Mutex<VecDeque<UpstreamResponse>>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl UpstreamTransport for QueueTransport {
        async fn send(
            &self,
            request: &UpstreamRequest,
            _limits: &BrokerLimits,
            _address_policy: &UpstreamAddressPolicy,
            _cancellation: &CancellationToken,
        ) -> Result<UpstreamResponse, CredentialBrokerError> {
            assert!(request.url().starts_with("https://api.example.com/v1/"));
            assert!(!format!("{request:?}").contains("test-token"));
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.responses
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .pop_front()
                .ok_or_else(|| CredentialBrokerError::Upstream("missing test response".to_owned()))
        }
    }

    struct SlowTransport;

    #[async_trait]
    impl UpstreamTransport for SlowTransport {
        async fn send(
            &self,
            _request: &UpstreamRequest,
            _limits: &BrokerLimits,
            _address_policy: &UpstreamAddressPolicy,
            _cancellation: &CancellationToken,
        ) -> Result<UpstreamResponse, CredentialBrokerError> {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(UpstreamResponse::new(StatusCode::OK, vec![], Vec::new()))
        }
    }

    struct PanicsOnceTransport {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl UpstreamTransport for PanicsOnceTransport {
        async fn send(
            &self,
            _request: &UpstreamRequest,
            _limits: &BrokerLimits,
            _address_policy: &UpstreamAddressPolicy,
            _cancellation: &CancellationToken,
        ) -> Result<UpstreamResponse, CredentialBrokerError> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                panic!("injected connection task panic");
            }
            Ok(UpstreamResponse::new(
                StatusCode::OK,
                vec![],
                b"recovered".to_vec(),
            ))
        }
    }

    fn rule() -> CredentialRule {
        let name = SecretName::new("EXAMPLE_TOKEN").expect("name");
        let policy = CredentialPolicy::new(
            "api.example.com",
            "/v1/",
            CredentialInjection::Bearer,
            [Method::GET, Method::POST],
            1024,
            2048,
            RedirectPolicy::SameTarget,
            name.clone(),
        )
        .expect("policy");
        CredentialRule::new("api", name, policy).expect("rule")
    }

    fn configuration() -> BrokerConfiguration {
        BrokerConfiguration {
            bind: BrokerBind::LoopbackV4 { port: 0 },
            limits: BrokerLimits::default(),
            address_policy: UpstreamAddressPolicy::default(),
            rules: vec![rule()],
        }
    }

    async fn request(handle: &BrokerHandle, request: &str) -> Vec<u8> {
        let request = request.replace("PORT", &handle.local_addr().port().to_string());
        let mut stream = TcpStream::connect(handle.local_addr())
            .await
            .expect("connect");
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response)
            .await
            .expect("response");
        response
    }

    #[tokio::test]
    async fn listener_forwards_only_explicit_rule_paths() {
        let transport = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::from([UpstreamResponse::new(
                StatusCode::OK,
                vec![],
                b"ok".to_vec(),
            )])),
            calls: AtomicUsize::new(0),
        });
        let request_bytes =
            b"GET /credentials/api/v1/messages HTTP/1.1\r\nHost: localhost:PORT\r\n\r\n";

        let broker = CredentialBroker::new(
            configuration(),
            Arc::new(StaticSecrets),
            Arc::clone(&transport) as Arc<dyn UpstreamTransport>,
            Arc::new(NoopAuditSink),
        );
        let (handle, agent) = broker.start().await.expect("start");
        assert!(agent.requires_explicit_base_url);
        assert!(!agent.supports_connect);
        assert!(handle.local_addr().ip().is_loopback());
        let response = request(
            &handle,
            std::str::from_utf8(request_bytes).expect("request utf8"),
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"ok"));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 1);
        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn slowloris_request_times_out_without_forwarding() {
        let transport = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
        });
        let configuration = BrokerConfiguration {
            bind: BrokerBind::LoopbackV4 { port: 0 },
            limits: BrokerLimits {
                request_read_timeout: Duration::from_millis(30),
                ..BrokerLimits::default()
            },
            address_policy: UpstreamAddressPolicy::default(),
            rules: vec![rule()],
        };
        let broker = CredentialBroker::new(
            configuration,
            Arc::new(StaticSecrets),
            Arc::clone(&transport) as Arc<dyn UpstreamTransport>,
            Arc::new(NoopAuditSink),
        );
        let (handle, _) = broker.start().await.expect("start");
        let mut stream = TcpStream::connect(handle.local_addr())
            .await
            .expect("connect");
        stream
            .write_all(b"GET /credentials/api")
            .await
            .expect("write");
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response)
            .await
            .expect("response");
        assert!(response.starts_with(b"HTTP/1.1 408"));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 0);
        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn same_target_redirect_is_reauthorized_and_followed() {
        let transport = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::from([
                UpstreamResponse::new(
                    StatusCode::TEMPORARY_REDIRECT,
                    vec![(http::header::LOCATION, HeaderValue::from_static("/v1/next"))],
                    Vec::new(),
                ),
                UpstreamResponse::new(StatusCode::OK, vec![], b"done".to_vec()),
            ])),
            calls: AtomicUsize::new(0),
        });
        let broker = CredentialBroker::new(
            configuration(),
            Arc::new(StaticSecrets),
            Arc::clone(&transport) as Arc<dyn UpstreamTransport>,
            Arc::new(NoopAuditSink),
        );
        let (handle, _) = broker.start().await.expect("start");
        let response = request(
            &handle,
            "GET /credentials/api/v1/start HTTP/1.1\r\nHost: localhost:PORT\r\n\r\n",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"done"));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 2);
        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn cross_target_redirect_fails_before_second_request() {
        let transport = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::from([UpstreamResponse::new(
                StatusCode::TEMPORARY_REDIRECT,
                vec![(
                    http::header::LOCATION,
                    HeaderValue::from_static("https://evil.example/v1/next"),
                )],
                Vec::new(),
            )])),
            calls: AtomicUsize::new(0),
        });
        let broker = CredentialBroker::new(
            configuration(),
            Arc::new(StaticSecrets),
            Arc::clone(&transport) as Arc<dyn UpstreamTransport>,
            Arc::new(NoopAuditSink),
        );
        let (handle, _) = broker.start().await.expect("start");
        let response = request(
            &handle,
            "GET /credentials/api/v1/start HTTP/1.1\r\nHost: localhost:PORT\r\n\r\n",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 400"));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 1);
        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn custom_transport_cannot_bypass_response_or_time_limits() {
        let oversized = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::from([UpstreamResponse::new(
                StatusCode::OK,
                vec![],
                vec![0_u8; 2049],
            )])),
            calls: AtomicUsize::new(0),
        });
        let broker = CredentialBroker::new(
            configuration(),
            Arc::new(StaticSecrets),
            oversized,
            Arc::new(NoopAuditSink),
        );
        let (handle, _) = broker.start().await.expect("start");
        let response = request(
            &handle,
            "GET /credentials/api/v1/start HTTP/1.1\r\nHost: localhost:PORT\r\n\r\n",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 400"));
        handle.shutdown().await.expect("shutdown");

        let mut configuration = configuration();
        configuration.limits.upstream_total_timeout = Duration::from_millis(25);
        let broker = CredentialBroker::new(
            configuration,
            Arc::new(StaticSecrets),
            Arc::new(SlowTransport),
            Arc::new(NoopAuditSink),
        );
        let (handle, _) = broker.start().await.expect("start");
        let response = request(
            &handle,
            "GET /credentials/api/v1/start HTTP/1.1\r\nHost: localhost:PORT\r\n\r\n",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 502"));
        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn host_mismatch_and_connect_are_rejected() {
        let transport = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
        });
        let broker = CredentialBroker::new(
            configuration(),
            Arc::new(StaticSecrets),
            Arc::clone(&transport) as Arc<dyn UpstreamTransport>,
            Arc::new(NoopAuditSink),
        );
        let (handle, _) = broker.start().await.expect("start");
        let response = request(
            &handle,
            "GET /credentials/api/v1/start HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 400"));
        let response = request(
            &handle,
            "CONNECT api.example.com:443 HTTP/1.1\r\nHost: localhost:PORT\r\n\r\n",
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 405"));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 0);
        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn shutdown_cancels_incomplete_connections() {
        let transport = Arc::new(QueueTransport {
            responses: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
        });
        let broker = CredentialBroker::new(
            configuration(),
            Arc::new(StaticSecrets),
            transport,
            Arc::new(NoopAuditSink),
        );
        let (handle, _) = broker.start().await.expect("start");
        let mut stream = TcpStream::connect(handle.local_addr())
            .await
            .expect("connect");
        stream
            .write_all(b"GET /credentials/api")
            .await
            .expect("write");
        timeout(Duration::from_millis(250), handle.shutdown())
            .await
            .expect("shutdown timeout")
            .expect("shutdown");
    }

    #[tokio::test]
    async fn panicking_connection_task_does_not_stop_listener() {
        let transport = Arc::new(PanicsOnceTransport {
            calls: AtomicUsize::new(0),
        });
        let broker = CredentialBroker::new(
            configuration(),
            Arc::new(StaticSecrets),
            Arc::clone(&transport) as Arc<dyn UpstreamTransport>,
            Arc::new(NoopAuditSink),
        );
        let (handle, _) = broker.start().await.expect("start");
        let first = request(
            &handle,
            "GET /credentials/api/v1/start HTTP/1.1\r\nHost: localhost:PORT\r\n\r\n",
        )
        .await;
        assert!(first.is_empty());
        let second = request(
            &handle,
            "GET /credentials/api/v1/start HTTP/1.1\r\nHost: localhost:PORT\r\n\r\n",
        )
        .await;
        assert!(second.starts_with(b"HTTP/1.1 200"));
        assert!(second.ends_with(b"recovered"));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 2);
        handle.shutdown().await.expect("shutdown");
    }

    #[test]
    fn cross_target_redirect_is_denied() {
        let rule = rule();
        let error = rule
            .policy()
            .authorize_redirect(
                &Url::parse("https://api.example.com/v1/a").expect("from"),
                &Url::parse("https://evil.example/v1/a").expect("to"),
            )
            .expect_err("redirect");
        assert!(matches!(
            error,
            sendbox_secrets::CredentialPolicyError::TargetMismatch
                | sendbox_secrets::CredentialPolicyError::RedirectDenied
        ));
    }
}
