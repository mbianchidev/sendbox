use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use hickory_proto::rr::Name;
use http::header::{
    ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE,
    HOST, LOCATION, ORIGIN, SET_COOKIE, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::client::conn::{http1 as client_http1, http2 as client_http2};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use sendbox_egress::address::{AddressClass, canonicalize, classify};
use sendbox_egress::dialer::Dialer;
use sendbox_egress::resolver::UpstreamResolver;
use sendbox_policy::ToolTransport;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore, mpsc};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::audit::{BoundaryAuditEvent, BoundaryAuditSink};
use crate::error::AuditError;
use crate::jsonrpc::{MessageKind, ValidatedMessage, validate_message};
use crate::policy::{
    AuditDecision, AuditOutcome, CompiledToolPolicy, PolicyAction, resolve_http_server,
};
use crate::runtime::{
    DEFAULT_HTTP_GATEWAY_PORT, HttpEndpoint, RemoteServerRuntime, RuntimePolicyDocument,
    gateway_route,
};

pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
pub const COMPATIBILITY_PROTOCOL_VERSION: &str = "2025-06-18";

const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_SESSION_ID_BYTES: usize = 512;
const MAX_EVENT_ID_BYTES: usize = 512;
const STREAM_QUEUE_CAPACITY: usize = 8;
const HEADER_MISMATCH_CODE: i64 = -32_020;

#[derive(Debug, Error)]
pub enum HttpGatewayError {
    #[error("invalid HTTP MCP gateway configuration: {0}")]
    InvalidConfiguration(String),
    #[error("HTTP MCP gateway I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP MCP upstream transport failed: {0}")]
    Upstream(String),
    #[error("HTTP MCP gateway audit failed: {0}")]
    Audit(#[from] AuditError),
    #[error("HTTP MCP gateway stopped because a mandatory control failed: {0}")]
    Fatal(String),
}

pub struct GatewayCredentialSet {
    values: BTreeMap<String, Zeroizing<String>>,
}

impl fmt::Debug for GatewayCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayCredentialSet")
            .field("names", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl GatewayCredentialSet {
    #[must_use]
    pub fn new(values: BTreeMap<String, String>) -> Self {
        Self {
            values: values
                .into_iter()
                .map(|(name, value)| (name, Zeroizing::new(value)))
                .collect(),
        }
    }

    fn names(&self) -> BTreeSet<String> {
        self.values.keys().cloned().collect()
    }

    fn bearer(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(|value| value.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct OriginResolution {
    pub aliases: Vec<String>,
    pub addresses: Vec<IpAddr>,
}

#[async_trait]
pub trait OriginReservation: Send + Sync {
    async fn reserve(
        &self,
        server_id: &str,
        endpoint: &HttpEndpoint,
        resolution: &OriginResolution,
    ) -> Result<(), HttpGatewayError>;
}

#[derive(Debug, Default)]
pub struct NoopOriginReservation;

#[async_trait]
impl OriginReservation for NoopOriginReservation {
    async fn reserve(
        &self,
        _server_id: &str,
        _endpoint: &HttpEndpoint,
        _resolution: &OriginResolution,
    ) -> Result<(), HttpGatewayError> {
        Ok(())
    }
}

pub struct UpstreamRequest {
    pub server_id: String,
    pub endpoint: HttpEndpoint,
    pub remote: RemoteServerRuntime,
    pub method: Method,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

pub struct UpstreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Box<dyn UpstreamResponseBody>,
}

#[async_trait]
pub trait UpstreamResponseBody: Send {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, HttpGatewayError>;
}

#[async_trait]
pub trait UpstreamHttpClient: Send + Sync {
    async fn execute(&self, request: UpstreamRequest)
    -> Result<UpstreamResponse, HttpGatewayError>;
}

pub struct ExactUpstreamClient {
    resolver: Arc<dyn UpstreamResolver>,
    dialer: Arc<dyn Dialer>,
    reservation: Arc<dyn OriginReservation>,
}

impl fmt::Debug for ExactUpstreamClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactUpstreamClient")
            .finish_non_exhaustive()
    }
}

impl ExactUpstreamClient {
    #[must_use]
    pub fn new(
        resolver: Arc<dyn UpstreamResolver>,
        dialer: Arc<dyn Dialer>,
        reservation: Arc<dyn OriginReservation>,
    ) -> Self {
        Self {
            resolver,
            dialer,
            reservation,
        }
    }

    async fn execute_once(
        &self,
        request: &UpstreamRequest,
        endpoint: &HttpEndpoint,
    ) -> Result<UpstreamResponse, HttpGatewayError> {
        let resolution = self.resolve_endpoint(endpoint, &request.remote).await?;
        validate_resolved_addresses(endpoint, &request.remote, &resolution.addresses)?;
        self.reservation
            .reserve(&request.server_id, endpoint, &resolution)
            .await?;

        let connect_timeout = Duration::from_secs(request.remote.http.connect_timeout_seconds);
        let request_timeout = Duration::from_secs(request.remote.http.request_timeout_seconds);
        let mut last_error = None;
        for ip in &resolution.addresses {
            let address = SocketAddr::new(*ip, endpoint.port);
            let stream = match self.dialer.dial(address, connect_timeout).await {
                Ok(stream) => stream,
                Err(error) => {
                    last_error = Some(format!("dialing {address}: {error}"));
                    continue;
                }
            };
            let result = timeout(
                request_timeout,
                send_upstream_request(stream, request, endpoint),
            )
            .await;
            match result {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(error)) => last_error = Some(error.to_string()),
                Err(_) => last_error = Some("upstream request timed out".to_owned()),
            }
        }
        Err(HttpGatewayError::Upstream(last_error.unwrap_or_else(
            || "upstream resolution returned no dialable addresses".to_owned(),
        )))
    }

    async fn resolve_endpoint(
        &self,
        endpoint: &HttpEndpoint,
        remote: &RemoteServerRuntime,
    ) -> Result<OriginResolution, HttpGatewayError> {
        if let Ok(ip) = IpAddr::from_str(&endpoint.host) {
            return Ok(OriginResolution {
                aliases: Vec::new(),
                addresses: vec![canonicalize(ip)],
            });
        }
        let name = Name::from_ascii(&endpoint.host).map_err(|error| {
            HttpGatewayError::Upstream(format!(
                "invalid configured upstream DNS name '{}': {error}",
                endpoint.host
            ))
        })?;
        let resolved = timeout(
            Duration::from_secs(remote.http.connect_timeout_seconds),
            self.resolver.resolve(&name),
        )
        .await
        .map_err(|_| HttpGatewayError::Upstream("upstream DNS resolution timed out".to_owned()))?
        .map_err(|error| HttpGatewayError::Upstream(error.to_string()))?;
        let aliases = resolved
            .names_to_validate()
            .map(|name| name.to_ascii().trim_end_matches('.').to_ascii_lowercase())
            .collect::<Vec<_>>();
        let addresses = resolved
            .addresses
            .into_iter()
            .map(|address| canonicalize(address.ip))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(HttpGatewayError::Upstream(format!(
                "upstream DNS name '{}' returned no addresses",
                endpoint.host
            )));
        }
        Ok(OriginResolution { aliases, addresses })
    }
}

#[async_trait]
impl UpstreamHttpClient for ExactUpstreamClient {
    async fn execute(
        &self,
        request: UpstreamRequest,
    ) -> Result<UpstreamResponse, HttpGatewayError> {
        let mut endpoint = request.endpoint.clone();
        let normalized_redirects = request
            .remote
            .http
            .redirect_allowlist
            .iter()
            .map(|value| HttpEndpoint::parse(value).map(|endpoint| endpoint.normalized))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(HttpGatewayError::InvalidConfiguration)?;
        for redirect_count in 0..=request.remote.http.max_redirects {
            let response = self.execute_once(&request, &endpoint).await?;
            if !is_redirect(response.status) {
                return Ok(response);
            }
            if !request.remote.http.allow_redirects {
                return Err(HttpGatewayError::Upstream(
                    "upstream redirect was denied by policy".to_owned(),
                ));
            }
            if redirect_count == request.remote.http.max_redirects {
                return Err(HttpGatewayError::Upstream(
                    "upstream redirect limit exceeded".to_owned(),
                ));
            }
            if !matches!(
                response.status,
                StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT
            ) {
                return Err(HttpGatewayError::Upstream(
                    "only method-preserving HTTP 307 and 308 redirects are supported".to_owned(),
                ));
            }
            let location = single_header(&response.headers, LOCATION, "Location")?;
            let next = HttpEndpoint::parse(location).map_err(|error| {
                HttpGatewayError::Upstream(format!("invalid redirect: {error}"))
            })?;
            if !normalized_redirects.contains(&next.normalized) {
                return Err(HttpGatewayError::Upstream(
                    "upstream redirect target is not exactly allowlisted".to_owned(),
                ));
            }
            endpoint = next;
        }
        unreachable!("redirect loop is bounded")
    }
}

async fn send_upstream_request(
    stream: TcpStream,
    request: &UpstreamRequest,
    endpoint: &HttpEndpoint,
) -> Result<UpstreamResponse, HttpGatewayError> {
    if endpoint.scheme == "http" {
        return send_http1(stream, request, endpoint).await;
    }
    let tls = tls_config(&request.remote)?;
    let server_name = ServerName::try_from(endpoint.host.clone()).map_err(|error| {
        HttpGatewayError::Upstream(format!(
            "invalid TLS server name '{}': {error}",
            endpoint.host
        ))
    })?;
    let connector = TlsConnector::from(Arc::new(tls));
    let tls_stream = timeout(
        Duration::from_secs(request.remote.http.connect_timeout_seconds),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| HttpGatewayError::Upstream("upstream TLS handshake timed out".to_owned()))?
    .map_err(|error| {
        HttpGatewayError::Upstream(format!("upstream TLS handshake failed: {error}"))
    })?;
    match tls_stream.get_ref().1.alpn_protocol() {
        Some(b"h2") => send_http2(tls_stream, request, endpoint).await,
        None | Some(b"http/1.1") => send_http1(tls_stream, request, endpoint).await,
        Some(protocol) => Err(HttpGatewayError::Upstream(format!(
            "upstream negotiated unsupported ALPN protocol '{}'",
            String::from_utf8_lossy(protocol)
        ))),
    }
}

async fn send_http1<T>(
    stream: T,
    request: &UpstreamRequest,
    endpoint: &HttpEndpoint,
) -> Result<UpstreamResponse, HttpGatewayError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = client_http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| HttpGatewayError::Upstream(format!("HTTP/1 handshake failed: {error}")))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("sendbox HTTP MCP upstream HTTP/1 connection failed: {error}");
        }
    });
    let response = sender
        .send_request(build_upstream_request(request, endpoint)?)
        .await
        .map_err(|error| HttpGatewayError::Upstream(format!("HTTP/1 request failed: {error}")))?;
    Ok(convert_upstream_response(response))
}

async fn send_http2<T>(
    stream: T,
    request: &UpstreamRequest,
    endpoint: &HttpEndpoint,
) -> Result<UpstreamResponse, HttpGatewayError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) =
        client_http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .map_err(|error| {
                HttpGatewayError::Upstream(format!("HTTP/2 handshake failed: {error}"))
            })?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("sendbox HTTP MCP upstream HTTP/2 connection failed: {error}");
        }
    });
    let response = sender
        .send_request(build_upstream_request(request, endpoint)?)
        .await
        .map_err(|error| HttpGatewayError::Upstream(format!("HTTP/2 request failed: {error}")))?;
    Ok(convert_upstream_response(response))
}

fn build_upstream_request(
    request: &UpstreamRequest,
    endpoint: &HttpEndpoint,
) -> Result<Request<Full<Bytes>>, HttpGatewayError> {
    let uri = Uri::from_str(&endpoint.path)
        .map_err(|error| HttpGatewayError::Upstream(format!("invalid endpoint path: {error}")))?;
    let mut builder = Request::builder()
        .method(request.method.clone())
        .uri(uri)
        .header(HOST, endpoint.authority());
    let headers = builder.headers_mut().expect("request builder is valid");
    for (name, value) in &request.headers {
        if name != HOST {
            headers.append(name, value.clone());
        }
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(&request.body)))
        .map_err(|error| HttpGatewayError::Upstream(format!("building HTTP request: {error}")))
}

fn convert_upstream_response(response: Response<Incoming>) -> UpstreamResponse {
    let (parts, body) = response.into_parts();
    UpstreamResponse {
        status: parts.status,
        headers: parts.headers,
        body: Box::new(HyperResponseBody(body)),
    }
}

struct HyperResponseBody(Incoming);

#[async_trait]
impl UpstreamResponseBody for HyperResponseBody {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, HttpGatewayError> {
        loop {
            let Some(frame) = self.0.frame().await else {
                return Ok(None);
            };
            let frame = frame.map_err(|error| {
                HttpGatewayError::Upstream(format!("reading upstream response body: {error}"))
            })?;
            match frame.into_data() {
                Ok(data) => return Ok(Some(data)),
                Err(frame) if frame.is_trailers() => {
                    return Err(HttpGatewayError::Upstream(
                        "upstream response trailers are not supported".to_owned(),
                    ));
                }
                Err(_) => {}
            }
        }
    }
}

fn tls_config(remote: &RemoteServerRuntime) -> Result<ClientConfig, HttpGatewayError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        roots.add(certificate).map_err(|error| {
            HttpGatewayError::Upstream(format!("loading native TLS root: {error}"))
        })?;
    }
    for pem in &remote.http.tls.trust_roots_pem {
        let mut reader = io::Cursor::new(pem.as_bytes());
        let mut count = 0_usize;
        for certificate in rustls_pemfile::certs(&mut reader) {
            roots
                .add(certificate.map_err(|error| {
                    HttpGatewayError::InvalidConfiguration(format!(
                        "invalid PEM trust root for server '{}': {error}",
                        remote.id
                    ))
                })?)
                .map_err(|error| {
                    HttpGatewayError::InvalidConfiguration(format!(
                        "invalid TLS trust root for server '{}': {error}",
                        remote.id
                    ))
                })?;
            count += 1;
        }
        if count == 0 {
            return Err(HttpGatewayError::InvalidConfiguration(format!(
                "PEM trust root for server '{}' contains no certificates",
                remote.id
            )));
        }
    }
    if roots.is_empty() {
        let details = native
            .errors
            .into_iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(HttpGatewayError::Upstream(format!(
            "no trusted TLS roots are available{}",
            if details.is_empty() {
                String::new()
            } else {
                format!(": {details}")
            }
        )));
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn validate_resolved_addresses(
    endpoint: &HttpEndpoint,
    remote: &RemoteServerRuntime,
    addresses: &[IpAddr],
) -> Result<(), HttpGatewayError> {
    for address in addresses {
        let class = classify(*address);
        let plaintext_loopback = endpoint.scheme == "http"
            && remote.http.allow_plaintext_local
            && class == AddressClass::Loopback;
        let private_allowed = remote.http.allow_private_networks
            && matches!(
                class,
                AddressClass::Loopback
                    | AddressClass::LinkLocal
                    | AddressClass::PrivateRfc1918
                    | AddressClass::UniqueLocalIpv6
            );
        if class == AddressClass::Global || plaintext_loopback || private_allowed {
            continue;
        }
        return Err(HttpGatewayError::Upstream(format!(
            "upstream address {address} is in denied class {class:?}"
        )));
    }
    Ok(())
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

struct GatewayServer {
    remote: RemoteServerRuntime,
    policy: CompiledToolPolicy,
    concurrency: Arc<Semaphore>,
}

pub struct HttpGateway {
    servers: Arc<BTreeMap<String, GatewayServer>>,
    credentials: Arc<GatewayCredentialSet>,
    upstream: Arc<dyn UpstreamHttpClient>,
    audit: Arc<dyn BoundaryAuditSink>,
    sessions: Arc<Mutex<SessionRegistry>>,
    tool_headers: Arc<RwLock<ToolHeaderRegistry>>,
    fatal: CancellationToken,
}

impl fmt::Debug for HttpGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpGateway")
            .field("servers", &self.servers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl HttpGateway {
    pub fn new(
        policy: &RuntimePolicyDocument,
        credentials: GatewayCredentialSet,
        upstream: Arc<dyn UpstreamHttpClient>,
        audit: Arc<dyn BoundaryAuditSink>,
    ) -> Result<Self, HttpGatewayError> {
        policy
            .validate()
            .map_err(|error| HttpGatewayError::InvalidConfiguration(error.to_string()))?;
        let remotes = policy
            .remote_servers()
            .map_err(HttpGatewayError::InvalidConfiguration)?;
        if remotes.is_empty() {
            return Err(HttpGatewayError::InvalidConfiguration(
                "at least one remote MCP server is required".to_owned(),
            ));
        }
        let required_credentials = policy.tool_policy.gateway_secret_names();
        if credentials.names() != required_credentials {
            return Err(HttpGatewayError::InvalidConfiguration(
                "gateway credential names do not exactly match the signed MCP policy".to_owned(),
            ));
        }
        let mut servers = BTreeMap::new();
        for (id, remote) in remotes {
            let resolved = resolve_http_server(&policy.tool_policy, &id)
                .map_err(HttpGatewayError::InvalidConfiguration)?;
            servers.insert(
                id,
                GatewayServer {
                    concurrency: Arc::new(Semaphore::new(
                        usize::try_from(remote.http.max_concurrent_requests).map_err(|_| {
                            HttpGatewayError::InvalidConfiguration(
                                "HTTP concurrency limit cannot fit in memory".to_owned(),
                            )
                        })?,
                    )),
                    policy: resolved.compile(),
                    remote,
                },
            );
        }
        Ok(Self {
            servers: Arc::new(servers),
            credentials: Arc::new(credentials),
            upstream,
            audit,
            sessions: Arc::new(Mutex::new(SessionRegistry::default())),
            tool_headers: Arc::new(RwLock::new(ToolHeaderRegistry::default())),
            fatal: CancellationToken::new(),
        })
    }

    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        cancellation: CancellationToken,
    ) -> Result<(), HttpGatewayError> {
        let local = listener.local_addr()?;
        if !local.ip().is_loopback() || local.port() != DEFAULT_HTTP_GATEWAY_PORT {
            return Err(HttpGatewayError::InvalidConfiguration(format!(
                "HTTP MCP gateway must bind loopback port {DEFAULT_HTTP_GATEWAY_PORT}"
            )));
        }
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                () = self.fatal.cancelled() => {
                    return Err(HttpGatewayError::Fatal(
                        "an audit or stream control failed closed".to_owned(),
                    ));
                }
                accepted = listener.accept() => {
                    let (stream, peer) = accepted?;
                    if !peer.ip().is_loopback() {
                        eprintln!("sendbox HTTP MCP gateway rejected non-loopback peer {peer}");
                        continue;
                    }
                    let gateway = Arc::clone(&self);
                    tokio::spawn(async move {
                        let service = service_fn(move |request| {
                            let gateway = Arc::clone(&gateway);
                            async move {
                                Ok::<_, Infallible>(gateway.handle(request).await)
                            }
                        });
                        if let Err(error) = server_http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await
                        {
                            eprintln!("sendbox HTTP MCP downstream connection failed: {error}");
                        }
                    });
                }
            }
        }
    }

    pub async fn handle(&self, request: Request<Incoming>) -> Response<GatewayBody> {
        match self.handle_inner(request).await {
            Ok(response) => response,
            Err(problem) => {
                eprintln!("sendbox HTTP MCP request rejected: {}", problem.log_message);
                if problem.fatal {
                    self.fatal.cancel();
                }
                problem.into_response()
            }
        }
    }

    async fn handle_inner(
        &self,
        request: Request<Incoming>,
    ) -> Result<Response<GatewayBody>, HttpProblem> {
        validate_downstream_envelope(&request)?;
        let server_id = parse_gateway_route(request.uri())?;
        let server = self
            .servers
            .get(server_id)
            .ok_or_else(|| HttpProblem::not_found("unknown MCP gateway route"))?;
        validate_method(server.remote.transport, request.method())?;
        let permit = timeout(
            Duration::from_secs(server.remote.http.request_timeout_seconds),
            Arc::clone(&server.concurrency).acquire_owned(),
        )
        .await
        .map_err(|_| HttpProblem::unavailable("MCP server concurrency limit timed out"))?
        .map_err(|_| HttpProblem::fatal("MCP server concurrency control closed"))?;

        let started = Instant::now();
        let method = request.method().clone();
        let incoming_headers = request.headers().clone();
        let session_id = header_optional(&incoming_headers, "mcp-session-id")?;
        validate_session_headers(
            server.remote.transport,
            &method,
            session_id.as_deref(),
            &incoming_headers,
        )?;
        let mut response = match method {
            Method::POST => {
                self.handle_post(server, request, session_id.as_deref(), started)
                    .await
            }
            Method::GET => {
                self.handle_stream_method(server, request, session_id.as_deref(), false, started)
                    .await
            }
            Method::DELETE => {
                self.handle_stream_method(server, request, session_id.as_deref(), true, started)
                    .await
            }
            _ => Err(HttpProblem::method_not_allowed()),
        }?;
        response.body_mut().hold_permit(permit);
        Ok(response)
    }

    async fn handle_post(
        &self,
        server: &GatewayServer,
        request: Request<Incoming>,
        session_id: Option<&str>,
        started: Instant,
    ) -> Result<Response<GatewayBody>, HttpProblem> {
        require_media_type(request.headers(), "application/json")?;
        require_accept(request.headers(), true)?;
        reject_declared_oversize(request.headers(), server.remote.http.max_request_bytes)?;
        let headers = request.headers().clone();
        let body = collect_body(
            request.into_body(),
            server.remote.http.max_request_bytes,
            Duration::from_secs(server.remote.http.idle_timeout_seconds),
        )
        .await?;
        let message = validate_message(&body)
            .map_err(|error| HttpProblem::bad_request(format!("invalid JSON-RPC body: {error}")))?;
        validate_client_message_direction(server.remote.transport, &message)?;
        let value: Value = serde_json::from_slice(&body)
            .map_err(|error| HttpProblem::bad_request(format!("invalid JSON body: {error}")))?;
        let context = RequestContext::new(message, value, body);
        validate_request_metadata(server.remote.transport, &headers, &context)?;
        self.validate_compatibility_request(server, session_id, &context)
            .await?;
        validate_custom_tool_headers(&self.tool_headers, &server.remote.id, &headers, &context)
            .await?;

        match server.policy.evaluate_message(&context.message) {
            PolicyAction::Respond { response, decision } => {
                self.record_decision(
                    &decision,
                    session_id,
                    Some(context.body.len() as u64),
                    Some(response.len() as u64),
                    Some(StatusCode::FORBIDDEN),
                    started,
                )?;
                return Ok(json_response(StatusCode::FORBIDDEN, response));
            }
            PolicyAction::Drop(decision) => {
                self.record_decision(
                    &decision,
                    session_id,
                    Some(context.body.len() as u64),
                    Some(0),
                    Some(StatusCode::ACCEPTED),
                    started,
                )?;
                return Ok(empty_response(StatusCode::ACCEPTED));
            }
            PolicyAction::Terminate(reason) => {
                return Err(HttpProblem::bad_request(reason));
            }
            PolicyAction::Forward(decision) => {
                self.record_decision(
                    &decision,
                    session_id,
                    Some(context.body.len() as u64),
                    None,
                    None,
                    started,
                )?;
            }
        }

        let upstream_request = self.build_upstream_request(
            server,
            Method::POST,
            &headers,
            context.body.clone(),
            session_id,
        )?;
        let response = timeout(
            Duration::from_secs(server.remote.http.request_timeout_seconds),
            self.upstream.execute(upstream_request),
        )
        .await
        .map_err(|_| HttpProblem::bad_gateway("upstream MCP request timed out"))?
        .map_err(HttpProblem::from_upstream)?;
        self.process_post_response(server, context, session_id, response, started)
            .await
    }

    async fn handle_stream_method(
        &self,
        server: &GatewayServer,
        request: Request<Incoming>,
        session_id: Option<&str>,
        delete: bool,
        started: Instant,
    ) -> Result<Response<GatewayBody>, HttpProblem> {
        if !delete {
            require_accept(request.headers(), false)?;
        }
        reject_declared_oversize(request.headers(), 0)?;
        let headers = request.headers().clone();
        let body = collect_body(
            request.into_body(),
            0,
            Duration::from_secs(server.remote.http.idle_timeout_seconds),
        )
        .await?;
        if !body.is_empty() {
            return Err(HttpProblem::bad_request(
                "GET and DELETE MCP requests cannot contain a body",
            ));
        }
        if let Some(id) = session_id {
            self.sessions
                .lock()
                .await
                .require_session(&server.remote, id)?;
        }
        if let Some(last_event) = header_optional(&headers, "last-event-id")? {
            self.sessions
                .lock()
                .await
                .require_event(&server.remote, session_id, &last_event)?;
        }
        let method = if delete { Method::DELETE } else { Method::GET };
        let upstream_request =
            self.build_upstream_request(server, method, &headers, Vec::new(), session_id)?;
        let response = timeout(
            Duration::from_secs(server.remote.http.request_timeout_seconds),
            self.upstream.execute(upstream_request),
        )
        .await
        .map_err(|_| HttpProblem::bad_gateway("upstream MCP request timed out"))?
        .map_err(HttpProblem::from_upstream)?;
        if delete {
            if !matches!(
                response.status,
                StatusCode::OK | StatusCode::ACCEPTED | StatusCode::NO_CONTENT
            ) {
                return Err(HttpProblem::bad_gateway(
                    "upstream rejected MCP session deletion",
                ));
            }
            ensure_no_sensitive_response_headers(&response.headers)?;
            let response_body = collect_upstream_body(
                response.body,
                server.remote.http.max_response_bytes,
                Duration::from_secs(server.remote.http.idle_timeout_seconds),
            )
            .await?;
            if !response_body.is_empty() {
                return Err(HttpProblem::bad_gateway(
                    "upstream session deletion returned an unexpected body",
                ));
            }
            if let Some(id) = session_id {
                self.sessions.lock().await.remove(id);
            }
            let decision = transport_decision(
                &server.policy,
                "session/delete",
                AuditOutcome::Allowed,
                None,
            );
            self.record_decision(
                &decision,
                session_id,
                Some(0),
                Some(0),
                Some(response.status),
                started,
            )?;
            return Ok(empty_response(response.status));
        }
        if response.status != StatusCode::OK {
            return Err(HttpProblem::bad_gateway(
                "upstream GET stream did not return HTTP 200",
            ));
        }
        require_upstream_media_type(&response.headers, "text/event-stream")?;
        ensure_no_sensitive_response_headers(&response.headers)?;
        let downstream_headers = downstream_response_headers(&response.headers, true)?;
        let stream = self.spawn_sse_stream(
            server,
            None,
            session_id.map(str::to_owned),
            response.body,
            true,
            started,
        );
        Ok(streaming_response(
            response.status,
            downstream_headers,
            stream,
        ))
    }

    async fn process_post_response(
        &self,
        server: &GatewayServer,
        context: RequestContext,
        session_id: Option<&str>,
        response: UpstreamResponse,
        started: Instant,
    ) -> Result<Response<GatewayBody>, HttpProblem> {
        ensure_no_sensitive_response_headers(&response.headers)?;
        let response_session = header_optional(&response.headers, "mcp-session-id")?;
        self.validate_or_register_response_session(
            server,
            session_id,
            response_session.as_deref(),
            &context,
        )
        .await?;

        if context.message.kind == MessageKind::Notification
            || matches!(
                context.message.kind,
                MessageKind::Response | MessageKind::Error
            )
        {
            if response.status != StatusCode::ACCEPTED {
                return Err(HttpProblem::bad_gateway(
                    "upstream did not acknowledge MCP one-way message with HTTP 202",
                ));
            }
            let body = collect_upstream_body(
                response.body,
                server.remote.http.max_response_bytes,
                Duration::from_secs(server.remote.http.idle_timeout_seconds),
            )
            .await?;
            if !body.is_empty() {
                return Err(HttpProblem::bad_gateway(
                    "upstream HTTP 202 response contained a body",
                ));
            }
            return Ok(empty_response(StatusCode::ACCEPTED));
        }
        if response.status != StatusCode::OK {
            return Err(HttpProblem::bad_gateway(format!(
                "upstream MCP request returned unexpected HTTP status {}",
                response.status
            )));
        }
        match response_media_type(&response.headers)? {
            ResponseMediaType::Json => {
                let mut body = collect_upstream_body(
                    response.body,
                    server.remote.http.max_response_bytes,
                    Duration::from_secs(server.remote.http.idle_timeout_seconds),
                )
                .await?;
                body = self
                    .validate_and_transform_response(server, &context, &body, session_id)
                    .await?;
                let decision = transport_decision(
                    &server.policy,
                    "http/response",
                    AuditOutcome::Allowed,
                    None,
                );
                self.record_decision(
                    &decision,
                    session_id,
                    Some(context.body.len() as u64),
                    Some(body.len() as u64),
                    Some(response.status),
                    started,
                )?;
                let mut downstream = json_response(StatusCode::OK, body);
                downstream
                    .headers_mut()
                    .extend(downstream_response_headers(&response.headers, false)?);
                Ok(downstream)
            }
            ResponseMediaType::Sse => {
                let downstream_headers = downstream_response_headers(&response.headers, true)?;
                let stream = self.spawn_sse_stream(
                    server,
                    Some(context),
                    session_id.map(str::to_owned),
                    response.body,
                    false,
                    started,
                );
                Ok(streaming_response(
                    StatusCode::OK,
                    downstream_headers,
                    stream,
                ))
            }
        }
    }

    fn build_upstream_request(
        &self,
        server: &GatewayServer,
        method: Method,
        incoming: &HeaderMap,
        body: Vec<u8>,
        session_id: Option<&str>,
    ) -> Result<UpstreamRequest, HttpProblem> {
        let mut headers = HeaderMap::new();
        if method == Method::POST {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(
                ACCEPT,
                HeaderValue::from_static("application/json, text/event-stream"),
            );
        } else if method == Method::GET {
            headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        }
        for name in [
            "mcp-protocol-version",
            "mcp-method",
            "mcp-name",
            "mcp-session-id",
            "last-event-id",
        ] {
            if let Some(value) = incoming.get(name) {
                headers.insert(
                    HeaderName::from_static(name),
                    checked_header_value(value, name)?,
                );
            }
        }
        for (name, value) in incoming {
            if name.as_str().starts_with("mcp-param-") {
                headers.append(name, checked_header_value(value, name.as_str())?);
            }
        }
        if server.remote.transport == ToolTransport::StreamableHttp
            && let Some(value) = incoming.get("mcp-session-id")
        {
            let _ = value;
            headers.remove("mcp-session-id");
        }
        if let Some(session) = session_id
            && server.remote.transport == ToolTransport::StreamableHttp2025
        {
            headers.insert(
                HeaderName::from_static("mcp-session-id"),
                HeaderValue::from_str(session)
                    .map_err(|_| HttpProblem::bad_request("invalid MCP session ID"))?,
            );
        }
        if let Some(authorization) = &server.remote.http.authorization {
            let bearer = self
                .credentials
                .bearer(&authorization.bearer_secret)
                .ok_or_else(|| HttpProblem::fatal("required gateway credential is unavailable"))?;
            let value = HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|_| HttpProblem::fatal("gateway credential is not a valid HTTP value"))?;
            headers.insert(AUTHORIZATION, value);
        }
        Ok(UpstreamRequest {
            server_id: server.remote.id.clone(),
            endpoint: server.remote.endpoint.clone(),
            remote: server.remote.clone(),
            method,
            headers,
            body,
        })
    }

    async fn validate_compatibility_request(
        &self,
        server: &GatewayServer,
        session_id: Option<&str>,
        context: &RequestContext,
    ) -> Result<(), HttpProblem> {
        if server.remote.transport != ToolTransport::StreamableHttp2025 {
            return Ok(());
        }
        if context.method() == Some("initialize") && session_id.is_some() {
            return Err(HttpProblem::bad_request(
                "MCP initialization cannot supply a pre-existing session ID",
            ));
        }
        if let Some(id) = session_id {
            self.sessions
                .lock()
                .await
                .require_session(&server.remote, id)?;
        }
        if matches!(
            context.message.kind,
            MessageKind::Response | MessageKind::Error
        ) {
            let id = context
                .message
                .id
                .raw()
                .ok_or_else(|| HttpProblem::bad_request("MCP response is missing an id"))?;
            self.sessions
                .lock()
                .await
                .consume_server_request(&server.remote, session_id, id)?;
        }
        Ok(())
    }

    async fn validate_or_register_response_session(
        &self,
        server: &GatewayServer,
        request_session: Option<&str>,
        response_session: Option<&str>,
        context: &RequestContext,
    ) -> Result<(), HttpProblem> {
        match server.remote.transport {
            ToolTransport::StreamableHttp => {
                if response_session.is_some() {
                    return Err(HttpProblem::bad_gateway(
                        "modern upstream attempted to create a protocol session",
                    ));
                }
            }
            ToolTransport::StreamableHttp2025 => match response_session {
                Some(session) if context.method() == Some("initialize") => {
                    self.sessions
                        .lock()
                        .await
                        .register(&server.remote, session)?;
                }
                Some(session) if request_session == Some(session) => {}
                Some(_) => {
                    return Err(HttpProblem::bad_gateway(
                        "upstream MCP session ID changed unexpectedly",
                    ));
                }
                None => {}
            },
            ToolTransport::Stdio => unreachable!("gateway contains only remote servers"),
        }
        Ok(())
    }

    async fn validate_and_transform_response(
        &self,
        server: &GatewayServer,
        context: &RequestContext,
        body: &[u8],
        session_id: Option<&str>,
    ) -> Result<Vec<u8>, HttpProblem> {
        let message = validate_message(body).map_err(|error| {
            HttpProblem::bad_gateway(format!("upstream returned invalid JSON-RPC: {error}"))
        })?;
        validate_server_message_direction(server.remote.transport, &message, false)?;
        require_matching_response(context, &message)?;
        if context.method() == Some("tools/list") {
            let transformed = transform_tools_list(&server.policy, body)?;
            self.install_tool_headers(&server.remote.id, &transformed.rules)
                .await;
            for decision in &transformed.decisions {
                self.record_decision(
                    decision,
                    session_id,
                    None,
                    None,
                    Some(StatusCode::OK),
                    Instant::now(),
                )?;
            }
            return Ok(transformed.payload);
        }
        Ok(body.to_vec())
    }

    async fn install_tool_headers(
        &self,
        server_id: &str,
        rules: &BTreeMap<String, Vec<ToolHeaderRule>>,
    ) {
        let mut registry = self.tool_headers.write().await;
        registry
            .rules
            .retain(|(configured_server, _), _| configured_server != server_id);
        for (tool, headers) in rules {
            registry
                .rules
                .insert((server_id.to_owned(), tool.clone()), headers.clone());
        }
    }

    fn spawn_sse_stream(
        &self,
        server: &GatewayServer,
        context: Option<RequestContext>,
        session_id: Option<String>,
        body: Box<dyn UpstreamResponseBody>,
        standalone: bool,
        started: Instant,
    ) -> GatewayBody {
        let (sender, receiver) = mpsc::channel(STREAM_QUEUE_CAPACITY);
        let failure_sender = sender.clone();
        let cancellation = CancellationToken::new();
        let worker_cancel = cancellation.clone();
        let audit = Arc::clone(&self.audit);
        let sessions = Arc::clone(&self.sessions);
        let tool_headers = Arc::clone(&self.tool_headers);
        let policy = server.policy.clone();
        let remote = server.remote.clone();
        let fatal = self.fatal.clone();
        tokio::spawn(async move {
            let processor = SseProcessor {
                remote,
                policy,
                context,
                session_id,
                standalone,
                body,
                sender,
                cancellation: worker_cancel,
                audit,
                sessions,
                tool_headers,
                fatal,
                started,
            };
            if let Err(error) = processor.run().await {
                eprintln!("sendbox HTTP MCP SSE stream failed closed: {error}");
                let _ = failure_sender
                    .send(Err(GatewayBodyError(error.to_string())))
                    .await;
            }
        });
        GatewayBody::stream(receiver, cancellation)
    }

    fn record_decision(
        &self,
        decision: &AuditDecision,
        session_id: Option<&str>,
        request_bytes: Option<u64>,
        response_bytes: Option<u64>,
        status: Option<StatusCode>,
        started: Instant,
    ) -> Result<(), HttpProblem> {
        let mut event = BoundaryAuditEvent::from_decision(decision);
        event.session_id_hash = session_id.map(hash_sensitive_id);
        event.request_bytes = request_bytes;
        event.response_bytes = response_bytes;
        event.status = status.map(|status| status.as_u16());
        event.duration_ms = Some(elapsed_ms(started));
        self.audit.record(&event).map_err(HttpProblem::audit)
    }
}

#[derive(Debug)]
struct RequestContext {
    message: ValidatedMessage,
    value: Value,
    body: Vec<u8>,
}

impl RequestContext {
    fn new(message: ValidatedMessage, value: Value, body: Vec<u8>) -> Self {
        Self {
            message,
            value,
            body,
        }
    }

    fn method(&self) -> Option<&str> {
        self.message.method.as_deref()
    }
}

#[derive(Debug)]
struct HttpProblem {
    status: StatusCode,
    rpc_code: i64,
    rpc_message: String,
    log_message: String,
    id: Option<String>,
    fatal: bool,
}

impl HttpProblem {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, -32_600, message, None, false)
    }

    fn header_mismatch(message: impl Into<String>, id: Option<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            HEADER_MISMATCH_CODE,
            message,
            id,
            false,
        )
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, -32_601, message, None, false)
    }

    fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            -32_600,
            "HTTP method is not supported for this MCP transport",
            None,
            false,
        )
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            -32_003,
            message,
            None,
            false,
        )
    }

    fn bad_gateway(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, -32_003, message, None, false)
    }

    fn fatal(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            -32_603,
            message,
            None,
            true,
        )
    }

    fn audit(error: AuditError) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            -32_603,
            "mandatory boundary audit failed",
            None,
            true,
        )
        .with_log(format!("mandatory boundary audit failed: {error}"))
    }

    fn from_upstream(error: HttpGatewayError) -> Self {
        Self::bad_gateway("trusted MCP upstream transport failed").with_log(error.to_string())
    }

    fn new(
        status: StatusCode,
        rpc_code: i64,
        message: impl Into<String>,
        id: Option<String>,
        fatal: bool,
    ) -> Self {
        let message = message.into();
        Self {
            status,
            rpc_code,
            rpc_message: message.clone(),
            log_message: message,
            id,
            fatal,
        }
    }

    fn with_log(mut self, message: impl Into<String>) -> Self {
        self.log_message = message.into();
        self
    }

    fn into_response(self) -> Response<GatewayBody> {
        let id = self.id.as_deref().unwrap_or("null");
        let message = serde_json::to_string(&self.rpc_message)
            .expect("serializing a JSON error message cannot fail");
        let payload = format!(
            "{{\"error\":{{\"code\":{},\"message\":{message}}},\"id\":{id},\"jsonrpc\":\"2.0\"}}",
            self.rpc_code
        );
        json_response(self.status, payload.into_bytes())
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct GatewayBodyError(String);

pub enum GatewayBody {
    Full {
        value: Option<Bytes>,
        permit: Option<OwnedSemaphorePermit>,
    },
    Stream {
        receiver: mpsc::Receiver<Result<Bytes, GatewayBodyError>>,
        cancellation: CancellationToken,
        permit: Option<OwnedSemaphorePermit>,
    },
}

impl GatewayBody {
    fn full(value: impl Into<Bytes>) -> Self {
        Self::Full {
            value: Some(value.into()),
            permit: None,
        }
    }

    fn empty() -> Self {
        Self::Full {
            value: None,
            permit: None,
        }
    }

    fn stream(
        receiver: mpsc::Receiver<Result<Bytes, GatewayBodyError>>,
        cancellation: CancellationToken,
    ) -> Self {
        Self::Stream {
            receiver,
            cancellation,
            permit: None,
        }
    }

    fn hold_permit(&mut self, owned: OwnedSemaphorePermit) {
        match self {
            Self::Full { permit, .. } | Self::Stream { permit, .. } => {
                *permit = Some(owned);
            }
        }
    }
}

impl Body for GatewayBody {
    type Data = Bytes;
    type Error = GatewayBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Full { value, .. } => {
                Poll::Ready(value.take().map(|bytes| Ok(Frame::data(bytes))))
            }
            Self::Stream { receiver, .. } => Pin::new(receiver)
                .poll_recv(context)
                .map(|item| item.map(|result| result.map(Frame::data))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, Self::Full { value: None, .. })
    }
}

impl Drop for GatewayBody {
    fn drop(&mut self) {
        if let Self::Stream { cancellation, .. } = self {
            cancellation.cancel();
        }
    }
}

#[derive(Default)]
struct SessionRegistry {
    sessions: BTreeMap<String, SessionState>,
    stateless_events: BTreeMap<(String, String), Instant>,
    stateless_server_requests: BTreeMap<(String, String), Instant>,
}

struct SessionState {
    server_id: String,
    expires_at: Instant,
    events: BTreeMap<String, Instant>,
    server_requests: BTreeSet<String>,
}

impl SessionRegistry {
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, state| state.expires_at > now);
        self.stateless_events
            .retain(|_, expires_at| *expires_at > now);
        self.stateless_server_requests
            .retain(|_, expires_at| *expires_at > now);
        for state in self.sessions.values_mut() {
            state.events.retain(|_, expires_at| *expires_at > now);
        }
    }

    fn register(
        &mut self,
        remote: &RemoteServerRuntime,
        session_id: &str,
    ) -> Result<(), HttpProblem> {
        self.cleanup();
        validate_visible_identifier(session_id, MAX_SESSION_ID_BYTES, "MCP session ID")?;
        if self.sessions.contains_key(session_id) {
            return Err(HttpProblem::bad_gateway(
                "upstream attempted MCP session fixation or reuse",
            ));
        }
        let server_count = self
            .sessions
            .values()
            .filter(|state| state.server_id == remote.id)
            .count();
        if server_count
            >= usize::try_from(remote.http.max_sessions)
                .map_err(|_| HttpProblem::fatal("MCP session limit cannot fit in memory"))?
        {
            return Err(HttpProblem::unavailable(
                "configured MCP session limit has been reached",
            ));
        }
        self.sessions.insert(
            session_id.to_owned(),
            SessionState {
                server_id: remote.id.clone(),
                expires_at: Instant::now() + Duration::from_secs(remote.http.session_ttl_seconds),
                events: BTreeMap::new(),
                server_requests: BTreeSet::new(),
            },
        );
        Ok(())
    }

    fn require_session(
        &mut self,
        remote: &RemoteServerRuntime,
        session_id: &str,
    ) -> Result<(), HttpProblem> {
        self.cleanup();
        let state = self.sessions.get_mut(session_id).ok_or_else(|| {
            HttpProblem::bad_request("unknown or expired MCP compatibility session")
        })?;
        if state.server_id != remote.id {
            return Err(HttpProblem::bad_request(
                "MCP session cannot be reused across server policies",
            ));
        }
        state.expires_at = Instant::now() + Duration::from_secs(remote.http.session_ttl_seconds);
        Ok(())
    }

    fn remove(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    fn observe_event(
        &mut self,
        remote: &RemoteServerRuntime,
        session_id: Option<&str>,
        event_id: &str,
    ) -> Result<(), HttpProblem> {
        validate_visible_identifier(event_id, MAX_EVENT_ID_BYTES, "SSE event ID")?;
        self.cleanup();
        let expires = Instant::now() + Duration::from_secs(remote.http.session_ttl_seconds);
        match session_id {
            Some(session) => {
                self.require_session(remote, session)?;
                let state = self
                    .sessions
                    .get_mut(session)
                    .expect("session was validated");
                if state.events.len()
                    >= usize::try_from(remote.http.max_events)
                        .map_err(|_| HttpProblem::fatal("MCP event limit cannot fit in memory"))?
                    && !state.events.contains_key(event_id)
                {
                    return Err(HttpProblem::unavailable(
                        "configured MCP event registry limit has been reached",
                    ));
                }
                state.events.insert(event_id.to_owned(), expires);
            }
            None => {
                let key = (remote.id.clone(), event_id.to_owned());
                if self.stateless_events.len()
                    >= usize::try_from(remote.http.max_events)
                        .map_err(|_| HttpProblem::fatal("MCP event limit cannot fit in memory"))?
                    && !self.stateless_events.contains_key(&key)
                {
                    return Err(HttpProblem::unavailable(
                        "configured MCP event registry limit has been reached",
                    ));
                }
                self.stateless_events.insert(key, expires);
            }
        }
        Ok(())
    }

    fn require_event(
        &mut self,
        remote: &RemoteServerRuntime,
        session_id: Option<&str>,
        event_id: &str,
    ) -> Result<(), HttpProblem> {
        self.cleanup();
        let found = match session_id {
            Some(session) => {
                self.require_session(remote, session)?;
                self.sessions
                    .get(session)
                    .is_some_and(|state| state.events.contains_key(event_id))
            }
            None => self
                .stateless_events
                .contains_key(&(remote.id.clone(), event_id.to_owned())),
        };
        if !found {
            return Err(HttpProblem::bad_request(
                "Last-Event-ID was not observed for this MCP server and session",
            ));
        }
        Ok(())
    }

    fn register_server_request(
        &mut self,
        remote: &RemoteServerRuntime,
        session_id: Option<&str>,
        id: &str,
    ) -> Result<(), HttpProblem> {
        match session_id {
            Some(session) => {
                self.require_session(remote, session)?;
                let state = self
                    .sessions
                    .get_mut(session)
                    .expect("session was validated");
                if !state.server_requests.insert(id.to_owned()) {
                    return Err(HttpProblem::bad_gateway(
                        "duplicate outstanding MCP server request ID",
                    ));
                }
            }
            None => {
                let key = (remote.id.clone(), id.to_owned());
                if self.stateless_server_requests.contains_key(&key) {
                    return Err(HttpProblem::bad_gateway(
                        "duplicate outstanding stateless MCP server request ID",
                    ));
                }
                self.stateless_server_requests.insert(
                    key,
                    Instant::now() + Duration::from_secs(remote.http.session_ttl_seconds),
                );
            }
        }
        Ok(())
    }

    fn consume_server_request(
        &mut self,
        remote: &RemoteServerRuntime,
        session_id: Option<&str>,
        id: &str,
    ) -> Result<(), HttpProblem> {
        match session_id {
            Some(session) => {
                self.require_session(remote, session)?;
                let state = self
                    .sessions
                    .get_mut(session)
                    .expect("session was validated");
                if !state.server_requests.remove(id) {
                    return Err(HttpProblem::bad_request(
                        "MCP client response ID has no matching server request",
                    ));
                }
            }
            None => {
                if self
                    .stateless_server_requests
                    .remove(&(remote.id.clone(), id.to_owned()))
                    .is_none()
                {
                    return Err(HttpProblem::bad_request(
                        "MCP client response ID has no matching stateless server request",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct ToolHeaderRegistry {
    rules: BTreeMap<(String, String), Vec<ToolHeaderRule>>,
}

#[derive(Debug, Clone)]
struct ToolHeaderRule {
    header: HeaderName,
    path: Vec<String>,
    value_type: HeaderValueType,
}

#[derive(Debug, Clone, Copy)]
enum HeaderValueType {
    String,
    Integer,
    Boolean,
}

struct TransformedToolList {
    payload: Vec<u8>,
    rules: BTreeMap<String, Vec<ToolHeaderRule>>,
    decisions: Vec<AuditDecision>,
}

fn transform_tools_list(
    policy: &CompiledToolPolicy,
    payload: &[u8],
) -> Result<TransformedToolList, HttpProblem> {
    let filtered = policy
        .filter_tools_list_response(payload)
        .map_err(|error| {
            HttpProblem::bad_gateway(format!("invalid upstream tools/list response: {error}"))
        })?;
    let mut root: Value = serde_json::from_slice(&filtered.payload)
        .map_err(|error| HttpProblem::bad_gateway(format!("invalid tools/list JSON: {error}")))?;
    let tools = root
        .get_mut("result")
        .and_then(Value::as_object_mut)
        .and_then(|result| result.get_mut("tools"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| HttpProblem::bad_gateway("tools/list result.tools must be an array"))?;
    let mut rules = BTreeMap::new();
    let mut decisions = filtered.decisions;
    let mut valid_tools = Vec::with_capacity(tools.len());
    for tool in std::mem::take(tools) {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| HttpProblem::bad_gateway("tool definition is missing a name"))?
            .to_owned();
        let input_schema = tool
            .get("inputSchema")
            .ok_or_else(|| HttpProblem::bad_gateway("tool definition is missing inputSchema"))?;
        match compile_tool_header_rules(input_schema) {
            Ok(tool_rules) => {
                rules.insert(name, tool_rules);
                valid_tools.push(tool);
            }
            Err(reason) => {
                let mut decision = policy.evaluate_tool(&name);
                decision.outcome = AuditOutcome::Denied;
                decision.matched_rule = None;
                decision.reason = Some(format!(
                    "tool excluded because x-mcp-header schema is invalid: {reason}"
                ));
                decisions.push(decision);
            }
        }
    }
    *tools = valid_tools;
    let payload = serde_json::to_vec(&root)
        .map_err(|error| HttpProblem::bad_gateway(format!("encoding tools/list: {error}")))?;
    Ok(TransformedToolList {
        payload,
        rules,
        decisions,
    })
}

fn compile_tool_header_rules(input_schema: &Value) -> Result<Vec<ToolHeaderRule>, String> {
    let mut rules = Vec::new();
    let mut names = BTreeSet::new();
    compile_schema_node(input_schema, &mut Vec::new(), false, &mut names, &mut rules)?;
    Ok(rules)
}

fn compile_schema_node(
    value: &Value,
    path: &mut Vec<String>,
    is_property: bool,
    names: &mut BTreeSet<String>,
    rules: &mut Vec<ToolHeaderRule>,
) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "inputSchema nodes must be objects".to_owned())?;
    if let Some(extension) = object.get("x-mcp-header") {
        if !is_property {
            return Err("x-mcp-header must annotate a statically reachable property".to_owned());
        }
        let extension = extension
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "x-mcp-header must be a non-empty string".to_owned())?;
        let full_name = format!("mcp-param-{extension}");
        let header = HeaderName::from_str(&full_name)
            .map_err(|_| "x-mcp-header must use HTTP token syntax".to_owned())?;
        if !names.insert(header.as_str().to_owned()) {
            return Err("x-mcp-header names must be case-insensitively unique".to_owned());
        }
        let value_type = match object.get("type").and_then(Value::as_str) {
            Some("string") => HeaderValueType::String,
            Some("integer") => HeaderValueType::Integer,
            Some("boolean") => HeaderValueType::Boolean,
            _ => {
                return Err(
                    "x-mcp-header may only annotate string, integer, or boolean properties"
                        .to_owned(),
                );
            }
        };
        rules.push(ToolHeaderRule {
            header,
            path: path.clone(),
            value_type,
        });
    }
    if let Some(properties) = object.get("properties") {
        let properties = properties
            .as_object()
            .ok_or_else(|| "inputSchema properties must be an object".to_owned())?;
        for (name, property) in properties {
            path.push(name.clone());
            compile_schema_node(property, path, true, names, rules)?;
            path.pop();
        }
    }
    for (key, nested) in object {
        if matches!(key.as_str(), "x-mcp-header" | "properties") {
            continue;
        }
        if contains_header_extension(nested) {
            return Err(format!(
                "x-mcp-header under '{key}' is not statically reachable through properties"
            ));
        }
    }
    Ok(())
}

fn contains_header_extension(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key("x-mcp-header") || object.values().any(contains_header_extension)
        }
        Value::Array(values) => values.iter().any(contains_header_extension),
        _ => false,
    }
}

async fn validate_custom_tool_headers(
    registry: &RwLock<ToolHeaderRegistry>,
    server_id: &str,
    headers: &HeaderMap,
    context: &RequestContext,
) -> Result<(), HttpProblem> {
    let supplied = headers
        .iter()
        .filter(|(name, _)| name.as_str().starts_with("mcp-param-"))
        .map(|(name, value)| (name.as_str().to_owned(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    if context.method() != Some("tools/call") {
        if supplied.is_empty() {
            return Ok(());
        }
        return Err(HttpProblem::header_mismatch(
            "Mcp-Param headers are only valid on tools/call",
            context.message.id.raw().map(str::to_owned),
        ));
    }
    let tool = context
        .message
        .subject
        .as_deref()
        .ok_or_else(|| HttpProblem::bad_request("tools/call is missing params.name"))?;
    let registry = registry.read().await;
    let Some(rules) = registry.rules.get(&(server_id.to_owned(), tool.to_owned())) else {
        if supplied.is_empty() {
            return Ok(());
        }
        return Err(HttpProblem::header_mismatch(
            "Mcp-Param headers cannot be validated before a trusted tools/list definition",
            context.message.id.raw().map(str::to_owned),
        ));
    };
    let expected_names = rules
        .iter()
        .map(|rule| rule.header.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if supplied.keys().any(|name| !expected_names.contains(name)) {
        return Err(HttpProblem::header_mismatch(
            "request contains an unrecognized Mcp-Param header",
            context.message.id.raw().map(str::to_owned),
        ));
    }
    let arguments = context
        .value
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("arguments"));
    for rule in rules {
        let value = rule.path.iter().fold(arguments, |current, segment| {
            current
                .and_then(Value::as_object)
                .and_then(|object| object.get(segment))
        });
        match value {
            None | Some(Value::Null) => {
                if supplied.contains_key(rule.header.as_str()) {
                    return Err(HttpProblem::header_mismatch(
                        format!(
                            "{} must be omitted when its body value is absent",
                            rule.header
                        ),
                        context.message.id.raw().map(str::to_owned),
                    ));
                }
            }
            Some(value) => {
                let expected = header_body_value(value, rule.value_type).ok_or_else(|| {
                    HttpProblem::header_mismatch(
                        format!("{} body value has the wrong primitive type", rule.header),
                        context.message.id.raw().map(str::to_owned),
                    )
                })?;
                let actual = supplied.get(rule.header.as_str()).ok_or_else(|| {
                    HttpProblem::header_mismatch(
                        format!("required {} header is missing", rule.header),
                        context.message.id.raw().map(str::to_owned),
                    )
                })?;
                if decode_mirrored_header(actual, rule.header.as_str())? != expected {
                    return Err(HttpProblem::header_mismatch(
                        format!("{} does not match the request body", rule.header),
                        context.message.id.raw().map(str::to_owned),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn header_body_value(value: &Value, value_type: HeaderValueType) -> Option<String> {
    match value_type {
        HeaderValueType::String => value.as_str().map(str::to_owned),
        HeaderValueType::Boolean => value.as_bool().map(|value| value.to_string()),
        HeaderValueType::Integer => {
            let value = value.as_i64()?;
            (value.unsigned_abs() <= 9_007_199_254_740_991).then(|| value.to_string())
        }
    }
}

struct SseProcessor {
    remote: RemoteServerRuntime,
    policy: CompiledToolPolicy,
    context: Option<RequestContext>,
    session_id: Option<String>,
    standalone: bool,
    body: Box<dyn UpstreamResponseBody>,
    sender: mpsc::Sender<Result<Bytes, GatewayBodyError>>,
    cancellation: CancellationToken,
    audit: Arc<dyn BoundaryAuditSink>,
    sessions: Arc<Mutex<SessionRegistry>>,
    tool_headers: Arc<RwLock<ToolHeaderRegistry>>,
    fatal: CancellationToken,
    started: Instant,
}

impl SseProcessor {
    async fn run(mut self) -> Result<(), HttpGatewayError> {
        let mut decoder = SseDecoder::default();
        let mut total_bytes = 0_u64;
        let mut event_count = 0_u32;
        let mut final_response_seen = false;
        let idle = Duration::from_secs(self.remote.http.idle_timeout_seconds);
        loop {
            let chunk = tokio::select! {
                () = self.cancellation.cancelled() => return Ok(()),
                result = timeout(idle, self.body.next_chunk()) => {
                    result.map_err(|_| HttpGatewayError::Upstream("upstream SSE stream stalled".to_owned()))??
                }
            };
            let Some(chunk) = chunk else {
                for event in decoder.finish()? {
                    self.process_event(
                        event,
                        &mut total_bytes,
                        &mut event_count,
                        &mut final_response_seen,
                        idle,
                    )
                    .await?;
                }
                break;
            };
            for event in decoder.feed(&chunk)? {
                self.process_event(
                    event,
                    &mut total_bytes,
                    &mut event_count,
                    &mut final_response_seen,
                    idle,
                )
                .await?;
                if final_response_seen && !self.standalone {
                    return Ok(());
                }
            }
        }
        if self.context.is_some() && !final_response_seen {
            return Err(HttpGatewayError::Upstream(
                "upstream SSE stream ended before the matching JSON-RPC response".to_owned(),
            ));
        }
        Ok(())
    }

    async fn process_event(
        &mut self,
        mut event: SseEvent,
        total_bytes: &mut u64,
        event_count: &mut u32,
        final_response_seen: &mut bool,
        idle: Duration,
    ) -> Result<(), HttpGatewayError> {
        if event.comment_only {
            self.send(Bytes::from_static(b":\n\n"), idle).await?;
            return Ok(());
        }
        *event_count = event_count.saturating_add(1);
        if *event_count > self.remote.http.max_events {
            return Err(HttpGatewayError::Upstream(
                "upstream SSE event limit exceeded".to_owned(),
            ));
        }
        if let Some(id) = event.id.as_deref() {
            self.sessions
                .lock()
                .await
                .observe_event(&self.remote, self.session_id.as_deref(), id)
                .map_err(|problem| HttpGatewayError::Upstream(problem.log_message))?;
        }
        if !event.data.is_empty() {
            let message = validate_message(&event.data).map_err(|error| {
                HttpGatewayError::Upstream(format!("invalid JSON-RPC SSE event: {error}"))
            })?;
            validate_server_message_direction(self.remote.transport, &message, self.standalone)
                .map_err(|problem| HttpGatewayError::Upstream(problem.log_message))?;
            if message.kind == MessageKind::Request {
                let id = message.id.raw().ok_or_else(|| {
                    HttpGatewayError::Upstream(
                        "server-initiated MCP request is missing an id".to_owned(),
                    )
                })?;
                self.sessions
                    .lock()
                    .await
                    .register_server_request(&self.remote, self.session_id.as_deref(), id)
                    .map_err(|problem| HttpGatewayError::Upstream(problem.log_message))?;
            }
            if matches!(message.kind, MessageKind::Response | MessageKind::Error) {
                if let Some(context) = &self.context {
                    require_matching_response(context, &message)
                        .map_err(|problem| HttpGatewayError::Upstream(problem.log_message))?;
                    if context.method() == Some("tools/list") {
                        let transformed = transform_tools_list(&self.policy, &event.data)
                            .map_err(|problem| HttpGatewayError::Upstream(problem.log_message))?;
                        {
                            let mut registry = self.tool_headers.write().await;
                            registry
                                .rules
                                .retain(|(server, _), _| server != &self.remote.id);
                            for (tool, rules) in transformed.rules {
                                registry.rules.insert((self.remote.id.clone(), tool), rules);
                            }
                        }
                        for decision in transformed.decisions {
                            let mut audit = BoundaryAuditEvent::from_decision(&decision);
                            audit.session_id_hash =
                                self.session_id.as_deref().map(hash_sensitive_id);
                            audit.status = Some(StatusCode::OK.as_u16());
                            if let Err(error) = self.audit.record(&audit) {
                                self.fatal.cancel();
                                return Err(HttpGatewayError::Audit(error));
                            }
                        }
                        event.data = transformed.payload;
                    }
                } else if !self.standalone {
                    return Err(HttpGatewayError::Upstream(
                        "upstream SSE response has no matching request".to_owned(),
                    ));
                }
                *final_response_seen = true;
            }
        }
        let encoded = event.encode();
        *total_bytes = total_bytes.saturating_add(encoded.len() as u64);
        if *total_bytes
            > u64::try_from(self.remote.http.max_response_bytes).map_err(|_| {
                HttpGatewayError::InvalidConfiguration("negative response limit".to_owned())
            })?
        {
            return Err(HttpGatewayError::Upstream(
                "upstream SSE response byte limit exceeded".to_owned(),
            ));
        }
        self.send(Bytes::from(encoded), idle).await?;
        if *final_response_seen {
            let decision =
                transport_decision(&self.policy, "http/response", AuditOutcome::Allowed, None);
            let mut audit = BoundaryAuditEvent::from_decision(&decision);
            audit.session_id_hash = self.session_id.as_deref().map(hash_sensitive_id);
            audit.status = Some(StatusCode::OK.as_u16());
            audit.response_bytes = Some(*total_bytes);
            audit.duration_ms = Some(elapsed_ms(self.started));
            if let Err(error) = self.audit.record(&audit) {
                self.fatal.cancel();
                return Err(HttpGatewayError::Audit(error));
            }
        }
        Ok(())
    }

    async fn send(&mut self, bytes: Bytes, deadline: Duration) -> Result<(), HttpGatewayError> {
        tokio::select! {
            () = self.cancellation.cancelled() => Ok(()),
            result = timeout(deadline, self.sender.send(Ok(bytes))) => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Ok(()),
                Err(_) => Err(HttpGatewayError::Upstream(
                    "downstream SSE backpressure deadline exceeded".to_owned(),
                )),
            }
        }
    }
}

#[derive(Default)]
struct SseDecoder {
    buffer: Vec<u8>,
}

impl SseDecoder {
    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, HttpGatewayError> {
        self.buffer.extend_from_slice(bytes);
        self.decode(false)
    }

    fn finish(&mut self) -> Result<Vec<SseEvent>, HttpGatewayError> {
        self.decode(true)
    }

    fn decode(&mut self, finished: bool) -> Result<Vec<SseEvent>, HttpGatewayError> {
        let mut events = Vec::new();
        loop {
            let Some((end, separator)) = find_event_boundary(&self.buffer) else {
                break;
            };
            let raw = self.buffer.drain(..end).collect::<Vec<_>>();
            self.buffer.drain(..separator);
            events.push(parse_sse_event(&raw)?);
        }
        if finished && !self.buffer.is_empty() {
            let raw = std::mem::take(&mut self.buffer);
            events.push(parse_sse_event(&raw)?);
        }
        Ok(events)
    }
}

struct SseEvent {
    id: Option<String>,
    event: Option<String>,
    data: Vec<u8>,
    comment_only: bool,
}

impl SseEvent {
    fn encode(&self) -> Vec<u8> {
        if self.comment_only {
            return b":\n\n".to_vec();
        }
        let mut output = Vec::new();
        if let Some(id) = &self.id {
            output.extend_from_slice(b"id: ");
            output.extend_from_slice(id.as_bytes());
            output.push(b'\n');
        }
        if let Some(event) = &self.event {
            output.extend_from_slice(b"event: ");
            output.extend_from_slice(event.as_bytes());
            output.push(b'\n');
        }
        for line in self.data.split(|byte| *byte == b'\n') {
            output.extend_from_slice(b"data: ");
            output.extend_from_slice(line);
            output.push(b'\n');
        }
        output.push(b'\n');
        output
    }
}

fn find_event_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    let crlf = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| (position, 4));
    let lf = bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| (position, 2));
    match (crlf, lf) {
        (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
        (Some(boundary), None) | (None, Some(boundary)) => Some(boundary),
        (None, None) => None,
    }
}

fn parse_sse_event(raw: &[u8]) -> Result<SseEvent, HttpGatewayError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| HttpGatewayError::Upstream("SSE event is not valid UTF-8".to_owned()))?;
    let mut id = None;
    let mut event = None;
    let mut data = Vec::new();
    let mut comments = 0_usize;
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with(':') {
            comments += 1;
            continue;
        }
        let (field, value) = line.split_once(':').map_or((line, ""), |(field, value)| {
            (field, value.strip_prefix(' ').unwrap_or(value))
        });
        match field {
            "id" => {
                validate_visible_identifier(value, MAX_EVENT_ID_BYTES, "SSE event ID")
                    .map_err(|problem| HttpGatewayError::Upstream(problem.log_message))?;
                id = Some(value.to_owned());
            }
            "event" => event = Some(value.to_owned()),
            "data" => {
                if !data.is_empty() {
                    data.push(b'\n');
                }
                data.extend_from_slice(value.as_bytes());
            }
            "" | "retry" => {}
            _ => {}
        }
    }
    Ok(SseEvent {
        id,
        event,
        comment_only: comments > 0 && data.is_empty(),
        data,
    })
}

fn validate_downstream_envelope(request: &Request<Incoming>) -> Result<(), HttpProblem> {
    if request.uri().query().is_some() {
        return Err(HttpProblem::not_found(
            "MCP gateway routes do not accept query parameters",
        ));
    }
    if request.headers().contains_key(UPGRADE)
        || request
            .headers()
            .get(CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
    {
        return Err(HttpProblem::bad_request(
            "HTTP upgrades and WebSocket are not supported",
        ));
    }
    if request.headers().contains_key(CONTENT_ENCODING) {
        return Err(HttpProblem::bad_request(
            "compressed MCP request bodies are not supported",
        ));
    }
    if request.headers().contains_key(AUTHORIZATION) || request.headers().contains_key(COOKIE) {
        return Err(HttpProblem::bad_request(
            "downstream authorization and cookie headers are forbidden",
        ));
    }
    if let Some(origin) = header_optional(request.headers(), ORIGIN.as_str())? {
        let parsed = url::Url::parse(&origin).map_err(|_| {
            HttpProblem::new(
                StatusCode::FORBIDDEN,
                -32_600,
                "invalid Origin",
                None,
                false,
            )
        })?;
        if !parsed.host().is_some_and(|host| match host {
            url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
            url::Host::Ipv4(address) => address.is_loopback(),
            url::Host::Ipv6(address) => address.is_loopback(),
        }) {
            return Err(HttpProblem::new(
                StatusCode::FORBIDDEN,
                -32_600,
                "Origin is not a local gateway origin",
                None,
                false,
            ));
        }
    }
    if let Some(host) = header_optional(request.headers(), HOST.as_str())?
        && !matches!(
            host.as_str(),
            "127.0.0.1:15081" | "localhost:15081" | "[::1]:15081"
        )
    {
        return Err(HttpProblem::new(
            StatusCode::FORBIDDEN,
            -32_600,
            "Host does not identify the local MCP gateway",
            None,
            false,
        ));
    }
    Ok(())
}

fn parse_gateway_route(uri: &Uri) -> Result<&str, HttpProblem> {
    let path = uri.path();
    if path.contains('%') || path.ends_with('/') || path.contains("//") {
        return Err(HttpProblem::not_found("invalid MCP gateway route"));
    }
    let id = path
        .strip_prefix("/mcp/")
        .filter(|value| !value.is_empty())
        .filter(|value| !value.contains('/'))
        .ok_or_else(|| HttpProblem::not_found("invalid MCP gateway route"))?;
    if gateway_route(id) != path {
        return Err(HttpProblem::not_found("non-canonical MCP gateway route"));
    }
    Ok(id)
}

fn validate_method(transport: ToolTransport, method: &Method) -> Result<(), HttpProblem> {
    let allowed = match transport {
        ToolTransport::StreamableHttp => method == Method::POST,
        ToolTransport::StreamableHttp2025 => {
            matches!(*method, Method::POST | Method::GET | Method::DELETE)
        }
        ToolTransport::Stdio => false,
    };
    allowed
        .then_some(())
        .ok_or_else(HttpProblem::method_not_allowed)
}

fn validate_session_headers(
    transport: ToolTransport,
    method: &Method,
    session_id: Option<&str>,
    headers: &HeaderMap,
) -> Result<(), HttpProblem> {
    if transport == ToolTransport::StreamableHttp {
        if session_id.is_some() || headers.contains_key("last-event-id") {
            return Err(HttpProblem::bad_request(
                "modern Streamable HTTP does not use sessions or Last-Event-ID",
            ));
        }
        return Ok(());
    }
    if let Some(session) = session_id {
        validate_visible_identifier(session, MAX_SESSION_ID_BYTES, "MCP session ID")?;
    }
    if headers.contains_key("last-event-id") && *method != Method::GET {
        return Err(HttpProblem::bad_request(
            "Last-Event-ID is only valid on compatibility GET streams",
        ));
    }
    Ok(())
}

fn validate_client_message_direction(
    transport: ToolTransport,
    message: &ValidatedMessage,
) -> Result<(), HttpProblem> {
    if transport == ToolTransport::StreamableHttp
        && matches!(message.kind, MessageKind::Response | MessageKind::Error)
    {
        return Err(HttpProblem::bad_request(
            "modern Streamable HTTP clients cannot send JSON-RPC responses",
        ));
    }
    Ok(())
}

fn validate_server_message_direction(
    transport: ToolTransport,
    message: &ValidatedMessage,
    standalone: bool,
) -> Result<(), HttpProblem> {
    if transport == ToolTransport::StreamableHttp && message.kind == MessageKind::Request {
        return Err(HttpProblem::bad_gateway(
            "modern Streamable HTTP upstream sent a server-initiated request",
        ));
    }
    if standalone
        && transport == ToolTransport::StreamableHttp2025
        && matches!(message.kind, MessageKind::Response | MessageKind::Error)
    {
        return Err(HttpProblem::bad_gateway(
            "compatibility GET stream sent an unrelated JSON-RPC response",
        ));
    }
    Ok(())
}

fn validate_request_metadata(
    transport: ToolTransport,
    headers: &HeaderMap,
    context: &RequestContext,
) -> Result<(), HttpProblem> {
    let id = context.message.id.raw().map(str::to_owned);
    let protocol = header_required(headers, "mcp-protocol-version", id.clone())?;
    let expected_protocol = match transport {
        ToolTransport::StreamableHttp => MODERN_PROTOCOL_VERSION,
        ToolTransport::StreamableHttp2025 => COMPATIBILITY_PROTOCOL_VERSION,
        ToolTransport::Stdio => unreachable!("gateway contains only HTTP servers"),
    };
    if protocol != expected_protocol {
        return Err(HttpProblem::header_mismatch(
            format!("unsupported MCP protocol version; expected {expected_protocol}"),
            id,
        ));
    }
    if transport == ToolTransport::StreamableHttp {
        let body_protocol = context
            .value
            .get("params")
            .and_then(Value::as_object)
            .and_then(|params| params.get("_meta"))
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("io.modelcontextprotocol/protocolVersion"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                HttpProblem::header_mismatch(
                    "request body is missing _meta.io.modelcontextprotocol/protocolVersion",
                    context.message.id.raw().map(str::to_owned),
                )
            })?;
        if body_protocol != protocol {
            return Err(HttpProblem::header_mismatch(
                "MCP-Protocol-Version does not match the request body",
                context.message.id.raw().map(str::to_owned),
            ));
        }
        let method = context
            .method()
            .ok_or_else(|| HttpProblem::bad_request("MCP message is missing a method"))?;
        if header_required(
            headers,
            "mcp-method",
            context.message.id.raw().map(str::to_owned),
        )? != method
        {
            return Err(HttpProblem::header_mismatch(
                "Mcp-Method does not match the request body",
                context.message.id.raw().map(str::to_owned),
            ));
        }
        let requires_name = matches!(method, "tools/call" | "resources/read" | "prompts/get");
        match (requires_name, context.message.subject.as_deref()) {
            (true, Some(subject)) => {
                let header = headers.get("mcp-name").ok_or_else(|| {
                    HttpProblem::header_mismatch(
                        "required Mcp-Name header is missing",
                        context.message.id.raw().map(str::to_owned),
                    )
                })?;
                if decode_mirrored_header(header, "Mcp-Name")? != subject {
                    return Err(HttpProblem::header_mismatch(
                        "Mcp-Name does not match the request body",
                        context.message.id.raw().map(str::to_owned),
                    ));
                }
            }
            (true, None) => {
                return Err(HttpProblem::header_mismatch(
                    "request body is missing the value mirrored by Mcp-Name",
                    context.message.id.raw().map(str::to_owned),
                ));
            }
            (false, _) if headers.contains_key("mcp-name") => {
                return Err(HttpProblem::header_mismatch(
                    "Mcp-Name is not valid for this method",
                    context.message.id.raw().map(str::to_owned),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn require_matching_response(
    context: &RequestContext,
    response: &ValidatedMessage,
) -> Result<(), HttpProblem> {
    if !matches!(response.kind, MessageKind::Response | MessageKind::Error) {
        return Err(HttpProblem::bad_gateway(
            "upstream response is not a JSON-RPC response",
        ));
    }
    if response.id != context.message.id {
        return Err(HttpProblem::bad_gateway(
            "upstream JSON-RPC response ID does not match the request",
        ));
    }
    Ok(())
}

async fn collect_body(
    mut body: Incoming,
    maximum: i64,
    idle: Duration,
) -> Result<Vec<u8>, HttpProblem> {
    let maximum = usize::try_from(maximum)
        .map_err(|_| HttpProblem::fatal("configured request byte limit is invalid"))?;
    let mut output = Vec::new();
    loop {
        let frame = timeout(idle, body.frame())
            .await
            .map_err(|_| HttpProblem::bad_request("MCP request body stalled"))?;
        let Some(frame) = frame else {
            return Ok(output);
        };
        let frame =
            frame.map_err(|error| HttpProblem::bad_request(format!("reading body: {error}")))?;
        match frame.into_data() {
            Ok(data) => {
                if output.len().saturating_add(data.len()) > maximum {
                    return Err(HttpProblem::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        -32_600,
                        "MCP request body exceeds its configured limit",
                        None,
                        false,
                    ));
                }
                output.extend_from_slice(&data);
            }
            Err(frame) if frame.is_trailers() => {
                return Err(HttpProblem::bad_request(
                    "MCP request trailers are not supported",
                ));
            }
            Err(_) => {}
        }
    }
}

async fn collect_upstream_body(
    mut body: Box<dyn UpstreamResponseBody>,
    maximum: i64,
    idle: Duration,
) -> Result<Vec<u8>, HttpProblem> {
    let maximum = usize::try_from(maximum)
        .map_err(|_| HttpProblem::fatal("configured response byte limit is invalid"))?;
    let mut output = Vec::new();
    loop {
        let chunk = timeout(idle, body.next_chunk())
            .await
            .map_err(|_| HttpProblem::bad_gateway("upstream response body stalled"))?
            .map_err(HttpProblem::from_upstream)?;
        let Some(chunk) = chunk else {
            return Ok(output);
        };
        if output.len().saturating_add(chunk.len()) > maximum {
            return Err(HttpProblem::bad_gateway(
                "upstream response exceeds its configured byte limit",
            ));
        }
        output.extend_from_slice(&chunk);
    }
}

fn require_media_type(headers: &HeaderMap, expected: &str) -> Result<(), HttpProblem> {
    let value = header_optional(headers, CONTENT_TYPE.as_str())?.ok_or_else(|| {
        HttpProblem::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            -32_600,
            format!("Content-Type must be {expected}"),
            None,
            false,
        )
    })?;
    let media = value.split(';').next().unwrap_or_default().trim();
    if !media.eq_ignore_ascii_case(expected) {
        return Err(HttpProblem::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            -32_600,
            format!("Content-Type must be {expected}"),
            None,
            false,
        ));
    }
    Ok(())
}

fn require_upstream_media_type(headers: &HeaderMap, expected: &str) -> Result<(), HttpProblem> {
    let value =
        single_header(headers, CONTENT_TYPE, "Content-Type").map_err(HttpProblem::from_upstream)?;
    if !value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case(expected)
    {
        return Err(HttpProblem::bad_gateway(format!(
            "upstream Content-Type must be {expected}"
        )));
    }
    Ok(())
}

enum ResponseMediaType {
    Json,
    Sse,
}

fn response_media_type(headers: &HeaderMap) -> Result<ResponseMediaType, HttpProblem> {
    let value =
        single_header(headers, CONTENT_TYPE, "Content-Type").map_err(HttpProblem::from_upstream)?;
    match value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "application/json" => Ok(ResponseMediaType::Json),
        "text/event-stream" => Ok(ResponseMediaType::Sse),
        _ => Err(HttpProblem::bad_gateway(
            "upstream returned an unsupported MCP response Content-Type",
        )),
    }
}

fn require_accept(headers: &HeaderMap, both: bool) -> Result<(), HttpProblem> {
    let values = headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
        .collect::<BTreeSet<_>>();
    let valid =
        values.contains("text/event-stream") && (!both || values.contains("application/json"));
    valid.then_some(()).ok_or_else(|| {
        HttpProblem::bad_request(if both {
            "Accept must include application/json and text/event-stream"
        } else {
            "Accept must include text/event-stream"
        })
    })
}

fn reject_declared_oversize(headers: &HeaderMap, maximum: i64) -> Result<(), HttpProblem> {
    if let Some(length) = header_optional(headers, CONTENT_LENGTH.as_str())? {
        let length = length
            .parse::<i64>()
            .map_err(|_| HttpProblem::bad_request("invalid Content-Length"))?;
        if length > maximum {
            return Err(HttpProblem::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                -32_600,
                "MCP request body exceeds its configured limit",
                None,
                false,
            ));
        }
    }
    Ok(())
}

fn ensure_no_sensitive_response_headers(headers: &HeaderMap) -> Result<(), HttpProblem> {
    if headers.contains_key(SET_COOKIE)
        || headers.contains_key(CONTENT_ENCODING)
        || headers.contains_key(UPGRADE)
    {
        return Err(HttpProblem::bad_gateway(
            "upstream returned a forbidden hop-by-hop, cookie, upgrade, or encoding header",
        ));
    }
    Ok(())
}

fn downstream_response_headers(
    upstream: &HeaderMap,
    streaming: bool,
) -> Result<HeaderMap, HttpProblem> {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(if streaming {
            "text/event-stream"
        } else {
            "application/json"
        }),
    );
    if streaming {
        headers.insert(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-cache"),
        );
        headers.insert(
            HeaderName::from_static("x-accel-buffering"),
            HeaderValue::from_static("no"),
        );
    }
    for name in ["mcp-protocol-version", "mcp-session-id"] {
        if let Some(value) = upstream.get(name) {
            headers.insert(
                HeaderName::from_static(name),
                checked_header_value(value, name)?,
            );
        }
    }
    Ok(headers)
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: HeaderName,
    display: &str,
) -> Result<&'a str, HttpGatewayError> {
    let values = headers.get_all(&name);
    let mut iter = values.iter();
    let value = iter
        .next()
        .ok_or_else(|| HttpGatewayError::Upstream(format!("missing {display} header")))?;
    if iter.next().is_some() {
        return Err(HttpGatewayError::Upstream(format!(
            "duplicate {display} header"
        )));
    }
    value.to_str().map_err(|_| {
        HttpGatewayError::Upstream(format!("{display} header is not valid visible ASCII"))
    })
}

fn header_optional(headers: &HeaderMap, name: &str) -> Result<Option<String>, HttpProblem> {
    let values = headers.get_all(name);
    let mut iter = values.iter();
    let Some(value) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(HttpProblem::bad_request(format!("duplicate {name} header")));
    }
    let value = value
        .to_str()
        .map_err(|_| HttpProblem::bad_request(format!("invalid {name} header")))?;
    if value.len() > MAX_HEADER_VALUE_BYTES {
        return Err(HttpProblem::bad_request(format!(
            "{name} header exceeds its limit"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn header_required(
    headers: &HeaderMap,
    name: &str,
    id: Option<String>,
) -> Result<String, HttpProblem> {
    header_optional(headers, name)?.ok_or_else(|| {
        HttpProblem::header_mismatch(format!("required {name} header is missing"), id)
    })
}

fn checked_header_value(value: &HeaderValue, name: &str) -> Result<HeaderValue, HttpProblem> {
    let text = value
        .to_str()
        .map_err(|_| HttpProblem::bad_request(format!("invalid {name} header")))?;
    if text.len() > MAX_HEADER_VALUE_BYTES {
        return Err(HttpProblem::bad_request(format!(
            "{name} header exceeds its limit"
        )));
    }
    Ok(value.clone())
}

fn decode_mirrored_header(value: &HeaderValue, name: &str) -> Result<String, HttpProblem> {
    let value = value
        .to_str()
        .map_err(|_| HttpProblem::header_mismatch(format!("{name} is invalid"), None))?;
    if let Some(encoded) = value
        .strip_prefix("=?base64?")
        .and_then(|value| value.strip_suffix("?="))
    {
        let decoded = BASE64.decode(encoded).map_err(|_| {
            HttpProblem::header_mismatch(format!("{name} has invalid Base64 encoding"), None)
        })?;
        return String::from_utf8(decoded).map_err(|_| {
            HttpProblem::header_mismatch(format!("{name} Base64 is not UTF-8"), None)
        });
    }
    if value.starts_with("=?base64?") || value.ends_with("?=") {
        return Err(HttpProblem::header_mismatch(
            format!("{name} has a malformed Base64 sentinel"),
            None,
        ));
    }
    if value.trim() != value
        || value
            .bytes()
            .any(|byte| !(byte == b'\t' || (0x20..=0x7e).contains(&byte)))
    {
        return Err(HttpProblem::header_mismatch(
            format!("{name} requires Base64 sentinel encoding"),
            None,
        ));
    }
    Ok(value.to_owned())
}

fn validate_visible_identifier(
    value: &str,
    maximum: usize,
    description: &str,
) -> Result<(), HttpProblem> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(HttpProblem::bad_request(format!(
            "{description} must contain 1 to {maximum} visible ASCII bytes"
        )));
    }
    Ok(())
}

fn transport_decision(
    policy: &CompiledToolPolicy,
    method: &str,
    outcome: AuditOutcome,
    reason: Option<String>,
) -> AuditDecision {
    let identity = policy.identity();
    AuditDecision {
        server_id: identity.id.clone(),
        server_fingerprint: identity.fingerprint.clone(),
        transport: identity.transport,
        endpoint: identity.endpoint.clone(),
        method: method.to_owned(),
        tool: None,
        outcome,
        matched_rule: None,
        reason,
    }
}

fn hash_sensitive_id(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<GatewayBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header("cache-control", "no-store")
        .body(GatewayBody::full(body))
        .expect("static HTTP response is valid")
}

fn empty_response(status: StatusCode) -> Response<GatewayBody> {
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .body(GatewayBody::empty())
        .expect("static HTTP response is valid")
}

fn streaming_response(
    status: StatusCode,
    headers: HeaderMap,
    body: GatewayBody,
) -> Response<GatewayBody> {
    let mut response = Response::builder()
        .status(status)
        .body(body)
        .expect("static HTTP response is valid");
    response.headers_mut().extend(headers);
    response
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    use http_body_util::BodyExt as _;
    use sendbox_policy::{
        Action, McpHttpPolicy, McpServerPolicy, ServerToolPolicy, ToolCallPolicy,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn strict_routes_reject_ambiguous_encodings() {
        for invalid in [
            "/mcp/github/",
            "/mcp/github/other",
            "/mcp/%67ithub",
            "/mcp/github%2fother",
            "/other/github",
            "/mcp//github",
        ] {
            assert!(parse_gateway_route(&Uri::from_static(invalid)).is_err());
        }
        assert_eq!(
            parse_gateway_route(&Uri::from_static("/mcp/github")).unwrap(),
            "github"
        );
    }

    #[test]
    fn sse_decoder_handles_chunk_boundaries_and_comments() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.feed(b": keep").unwrap().is_empty());
        let first = decoder
            .feed(b"alive\n\ndata: {\"jsonrpc\":\"2.0\",")
            .unwrap();
        assert!(first[0].comment_only);
        let second = decoder.feed(b"\"id\":1,\"result\":{}}\n\n").unwrap();
        assert_eq!(second[0].data, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
    }

    #[test]
    fn x_mcp_header_rules_reject_unreachable_or_unsafe_annotations() {
        let valid = json!({
            "type": "object",
            "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"},
                "nested": {
                    "type": "object",
                    "properties": {
                        "count": {"type": "integer", "x-mcp-header": "Count"}
                    }
                }
            }
        });
        let rules = compile_tool_header_rules(&valid).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|rule| rule.header == "mcp-param-region"));

        let invalid = json!({
            "type": "object",
            "items": {"type": "string", "x-mcp-header": "Bad"}
        });
        assert!(compile_tool_header_rules(&invalid).is_err());
    }

    #[test]
    fn session_registry_rejects_fixation_and_cross_server_reuse() {
        let mut registry = SessionRegistry::default();
        let first = remote("first", ToolTransport::StreamableHttp2025);
        let second = remote("second", ToolTransport::StreamableHttp2025);
        registry.register(&first, "session-1").unwrap();
        assert!(registry.register(&first, "session-1").is_err());
        assert!(registry.require_session(&second, "session-1").is_err());
    }

    #[test]
    fn address_policy_denies_metadata_even_when_private_networks_are_enabled() {
        let mut remote = remote("remote", ToolTransport::StreamableHttp);
        remote.http.allow_private_networks = true;
        assert!(
            validate_resolved_addresses(
                &remote.endpoint,
                &remote,
                &[IpAddr::from([169, 254, 169, 254])]
            )
            .is_err()
        );
    }

    #[derive(Default)]
    struct MemoryAudit(StdMutex<Vec<BoundaryAuditEvent>>);

    impl BoundaryAuditSink for MemoryAudit {
        fn record(&self, event: &BoundaryAuditEvent) -> Result<(), AuditError> {
            self.0.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    fn remote(id: &str, transport: ToolTransport) -> RemoteServerRuntime {
        let endpoint = HttpEndpoint::parse("https://mcp.example.com/mcp").unwrap();
        RemoteServerRuntime {
            id: id.to_owned(),
            transport,
            fingerprint: "fingerprint".to_owned(),
            endpoint,
            gateway_url: format!("http://127.0.0.1:15081/mcp/{id}"),
            tools: ServerToolPolicy {
                default_action: Action::Deny,
                allowlist: vec!["read_*".to_owned()],
                denylist: Vec::new(),
            },
            http: McpHttpPolicy::default(),
        }
    }

    #[test]
    fn gateway_requires_exact_credential_partition() {
        let tool_policy = ToolCallPolicy {
            servers: BTreeMap::from([(
                "remote".to_owned(),
                McpServerPolicy::StreamableHttp {
                    url: "https://mcp.example.com/mcp".to_owned(),
                    tools: ServerToolPolicy {
                        default_action: Action::Deny,
                        allowlist: vec!["read_*".to_owned()],
                        denylist: Vec::new(),
                    },
                    http: McpHttpPolicy {
                        authorization: Some(sendbox_policy::HttpAuthorizationPolicy {
                            bearer_secret: "MCP_TOKEN".to_owned(),
                        }),
                        ..McpHttpPolicy::default()
                    },
                },
            )]),
            ..ToolCallPolicy::default()
        };
        let policy = RuntimePolicyDocument {
            schema_version: crate::runtime::RUNTIME_POLICY_SCHEMA_VERSION,
            workspace_root: "/workspace".into(),
            workload_uid: 1000,
            workload_gid: 1000,
            tool_policy,
            audit_log_path: "/var/log/sendbox/boundary.log".into(),
            fixed_environment: BTreeMap::new(),
            inherited_environment_keys: BTreeSet::new(),
            observation: None,
        };
        struct NeverClient;
        #[async_trait]
        impl UpstreamHttpClient for NeverClient {
            async fn execute(
                &self,
                _request: UpstreamRequest,
            ) -> Result<UpstreamResponse, HttpGatewayError> {
                panic!("not called")
            }
        }
        assert!(
            HttpGateway::new(
                &policy,
                GatewayCredentialSet::new(BTreeMap::new()),
                Arc::new(NeverClient),
                Arc::new(MemoryAudit::default()),
            )
            .is_err()
        );
    }

    #[derive(Clone, Default)]
    struct QueueClient {
        responses: Arc<StdMutex<VecDeque<FixtureResponse>>>,
        requests: Arc<StdMutex<Vec<CapturedRequest>>>,
    }

    struct FixtureResponse {
        status: StatusCode,
        headers: HeaderMap,
        chunks: VecDeque<Bytes>,
    }

    struct FixtureBody(VecDeque<Bytes>);

    struct CapturedRequest {
        server_id: String,
        method: Method,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl QueueClient {
        fn push_json(&self, status: StatusCode, payload: Value) {
            self.push(
                status,
                HeaderMap::from_iter([(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )]),
                [Bytes::from(
                    serde_json::to_vec(&payload).expect("fixture JSON encodes"),
                )],
            );
        }

        fn push(
            &self,
            status: StatusCode,
            headers: HeaderMap,
            chunks: impl IntoIterator<Item = Bytes>,
        ) {
            self.responses.lock().unwrap().push_back(FixtureResponse {
                status,
                headers,
                chunks: chunks.into_iter().collect(),
            });
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| CapturedRequest {
                    server_id: request.server_id.clone(),
                    method: request.method.clone(),
                    headers: request.headers.clone(),
                    body: request.body.clone(),
                })
                .collect()
        }
    }

    #[async_trait]
    impl UpstreamResponseBody for FixtureBody {
        async fn next_chunk(&mut self) -> Result<Option<Bytes>, HttpGatewayError> {
            Ok(self.0.pop_front())
        }
    }

    #[async_trait]
    impl UpstreamHttpClient for QueueClient {
        async fn execute(
            &self,
            request: UpstreamRequest,
        ) -> Result<UpstreamResponse, HttpGatewayError> {
            self.requests.lock().unwrap().push(CapturedRequest {
                server_id: request.server_id,
                method: request.method,
                headers: request.headers,
                body: request.body,
            });
            let fixture = self.responses.lock().unwrap().pop_front().ok_or_else(|| {
                HttpGatewayError::Upstream("test response queue is empty".to_owned())
            })?;
            Ok(UpstreamResponse {
                status: fixture.status,
                headers: fixture.headers,
                body: Box::new(FixtureBody(fixture.chunks)),
            })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gateway_enforces_modern_and_compatibility_http_end_to_end() {
        let client = QueueClient::default();
        let audit = Arc::new(MemoryAudit::default());
        let gateway = Arc::new(
            HttpGateway::new(
                &gateway_runtime_policy(),
                GatewayCredentialSet::new(BTreeMap::new()),
                Arc::new(client.clone()),
                audit,
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let server_cancel = cancellation.clone();
        let server_gateway = Arc::clone(&gateway);
        let server = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = server_cancel.cancelled() => return,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let gateway = Arc::clone(&server_gateway);
                        tokio::spawn(async move {
                            let service = service_fn(move |request| {
                                let gateway = Arc::clone(&gateway);
                                async move {
                                    Ok::<_, Infallible>(gateway.handle(request).await)
                                }
                            });
                            server_http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .await
                                .unwrap();
                        });
                    }
                }
            }
        });

        client.push_json(
            StatusCode::OK,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "read_report",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "region": {
                                        "type": "string",
                                        "x-mcp-header": "Region"
                                    }
                                }
                            }
                        },
                        {
                            "name": "delete_report",
                            "inputSchema": {"type": "object", "properties": {}}
                        }
                    ]
                }
            }),
        );
        let response = send_gateway(
            address,
            modern_request(
                "/mcp/modern",
                "tools/list",
                None,
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": modern_params(json!({}))
                }),
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK);
        let list: Value = serde_json::from_slice(&response.body).unwrap();
        let tools = list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "read_report");

        let before_denial = client.requests().len();
        let denied = send_gateway(
            address,
            modern_request(
                "/mcp/modern",
                "tools/call",
                Some("delete_report"),
                json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": modern_params(json!({
                        "name": "delete_report",
                        "arguments": {}
                    }))
                }),
            ),
        )
        .await;
        assert_eq!(denied.status, StatusCode::FORBIDDEN);
        assert_eq!(client.requests().len(), before_denial);

        let mut allowed_request = modern_request(
            "/mcp/modern",
            "tools/call",
            Some("read_report"),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": modern_params(json!({
                    "name": "read_report",
                    "arguments": {"region": "us-west1"}
                }))
            }),
        );
        allowed_request.headers_mut().insert(
            HeaderName::from_static("mcp-param-region"),
            HeaderValue::from_static("us-west1"),
        );
        client.push_json(
            StatusCode::OK,
            json!({"jsonrpc": "2.0", "id": 3, "result": {"ok": true}}),
        );
        let allowed = send_gateway(address, allowed_request).await;
        assert_eq!(allowed.status, StatusCode::OK);
        let captured = client.requests();
        assert_eq!(captured.last().unwrap().server_id, "modern");
        assert_eq!(
            captured.last().unwrap().headers["mcp-param-region"],
            "us-west1"
        );

        let mismatch = send_gateway(
            address,
            modern_request(
                "/mcp/modern",
                "tools/call",
                Some("wrong_name"),
                json!({
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": modern_params(json!({
                        "name": "read_report",
                        "arguments": {"region": "us-west1"}
                    }))
                }),
            ),
        )
        .await;
        assert_eq!(mismatch.status, StatusCode::BAD_REQUEST);
        let mismatch_body: Value = serde_json::from_slice(&mismatch.body).unwrap();
        assert_eq!(mismatch_body["error"]["code"], HEADER_MISMATCH_CODE);

        client.push(
            StatusCode::OK,
            HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            )]),
            [
                Bytes::from_static(
                    b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n",
                ),
                Bytes::from_static(
                    b"data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"done\":true}}\n\n",
                ),
            ],
        );
        let streamed = send_gateway(
            address,
            modern_request(
                "/mcp/modern",
                "ping",
                None,
                json!({
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "ping",
                    "params": modern_params(json!({}))
                }),
            ),
        )
        .await;
        assert_eq!(streamed.status, StatusCode::OK);
        assert!(
            String::from_utf8(streamed.body)
                .unwrap()
                .contains("\"done\":true")
        );

        let modern_get = send_gateway(
            address,
            request_with_headers(
                Method::GET,
                "/mcp/modern",
                [
                    (ACCEPT, HeaderValue::from_static("text/event-stream")),
                    (
                        HeaderName::from_static("mcp-protocol-version"),
                        HeaderValue::from_static(MODERN_PROTOCOL_VERSION),
                    ),
                ],
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(modern_get.status, StatusCode::METHOD_NOT_ALLOWED);

        let mut session_headers =
            HeaderMap::from_iter([(CONTENT_TYPE, HeaderValue::from_static("application/json"))]);
        session_headers.insert(
            HeaderName::from_static("mcp-session-id"),
            HeaderValue::from_static("session-1"),
        );
        client.push(
            StatusCode::OK,
            session_headers,
            [Bytes::from_static(
                b"{\"jsonrpc\":\"2.0\",\"id\":10,\"result\":{\"protocolVersion\":\"2025-06-18\"}}",
            )],
        );
        let initialized = send_gateway(
            address,
            compatibility_post(
                "/mcp/compat",
                json!({
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "initialize",
                    "params": {}
                }),
                None,
            ),
        )
        .await;
        assert_eq!(initialized.status, StatusCode::OK);
        assert_eq!(initialized.headers["mcp-session-id"], "session-1");

        client.push(
            StatusCode::OK,
            HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            )]),
            [Bytes::from_static(
                b"id: event-1\ndata: {\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"sampling/createMessage\",\"params\":{}}\n\n",
            )],
        );
        let compatibility_stream = send_gateway(
            address,
            request_with_headers(
                Method::GET,
                "/mcp/compat",
                [
                    (ACCEPT, HeaderValue::from_static("text/event-stream")),
                    (
                        HeaderName::from_static("mcp-protocol-version"),
                        HeaderValue::from_static(COMPATIBILITY_PROTOCOL_VERSION),
                    ),
                    (
                        HeaderName::from_static("mcp-session-id"),
                        HeaderValue::from_static("session-1"),
                    ),
                ],
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(compatibility_stream.status, StatusCode::OK);
        assert!(
            String::from_utf8(compatibility_stream.body)
                .unwrap()
                .contains("event-1")
        );

        client.push(StatusCode::ACCEPTED, HeaderMap::new(), []);
        let client_response = send_gateway(
            address,
            compatibility_post(
                "/mcp/compat",
                json!({
                    "jsonrpc": "2.0",
                    "id": 77,
                    "result": {"model": "approved"}
                }),
                Some("session-1"),
            ),
        )
        .await;
        assert_eq!(client_response.status, StatusCode::ACCEPTED);

        let cross_server = send_gateway(
            address,
            request_with_headers(
                Method::GET,
                "/mcp/compat-two",
                [
                    (ACCEPT, HeaderValue::from_static("text/event-stream")),
                    (
                        HeaderName::from_static("mcp-protocol-version"),
                        HeaderValue::from_static(COMPATIBILITY_PROTOCOL_VERSION),
                    ),
                    (
                        HeaderName::from_static("mcp-session-id"),
                        HeaderValue::from_static("session-1"),
                    ),
                ],
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(cross_server.status, StatusCode::BAD_REQUEST);

        client.push(StatusCode::NO_CONTENT, HeaderMap::new(), []);
        let deleted = send_gateway(
            address,
            request_with_headers(
                Method::DELETE,
                "/mcp/compat",
                [
                    (
                        HeaderName::from_static("mcp-protocol-version"),
                        HeaderValue::from_static(COMPATIBILITY_PROTOCOL_VERSION),
                    ),
                    (
                        HeaderName::from_static("mcp-session-id"),
                        HeaderValue::from_static("session-1"),
                    ),
                ],
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(deleted.status, StatusCode::NO_CONTENT);

        let expired = send_gateway(
            address,
            compatibility_post(
                "/mcp/compat",
                json!({"jsonrpc": "2.0", "id": 11, "method": "ping", "params": {}}),
                Some("session-1"),
            ),
        )
        .await;
        assert_eq!(expired.status, StatusCode::BAD_REQUEST);

        cancellation.cancel();
        server.await.unwrap();
    }

    struct GatewayResponse {
        status: StatusCode,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    async fn send_gateway(address: SocketAddr, request: Request<GatewayBody>) -> GatewayResponse {
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) = client_http1::handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        let response = sender.send_request(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        GatewayResponse {
            status,
            headers,
            body,
        }
    }

    fn modern_request(
        path: &str,
        method: &str,
        name: Option<&str>,
        body: Value,
    ) -> Request<GatewayBody> {
        let mut headers = vec![
            (CONTENT_TYPE, HeaderValue::from_static("application/json")),
            (
                ACCEPT,
                HeaderValue::from_static("application/json, text/event-stream"),
            ),
            (
                HeaderName::from_static("mcp-protocol-version"),
                HeaderValue::from_static(MODERN_PROTOCOL_VERSION),
            ),
            (
                HeaderName::from_static("mcp-method"),
                HeaderValue::from_str(method).unwrap(),
            ),
        ];
        if let Some(name) = name {
            headers.push((
                HeaderName::from_static("mcp-name"),
                HeaderValue::from_str(name).unwrap(),
            ));
        }
        request_with_headers(
            Method::POST,
            path,
            headers,
            serde_json::to_vec(&body).unwrap(),
        )
    }

    fn compatibility_post(
        path: &str,
        body: Value,
        session_id: Option<&str>,
    ) -> Request<GatewayBody> {
        let mut headers = vec![
            (CONTENT_TYPE, HeaderValue::from_static("application/json")),
            (
                ACCEPT,
                HeaderValue::from_static("application/json, text/event-stream"),
            ),
            (
                HeaderName::from_static("mcp-protocol-version"),
                HeaderValue::from_static(COMPATIBILITY_PROTOCOL_VERSION),
            ),
        ];
        if let Some(session_id) = session_id {
            headers.push((
                HeaderName::from_static("mcp-session-id"),
                HeaderValue::from_str(session_id).unwrap(),
            ));
        }
        request_with_headers(
            Method::POST,
            path,
            headers,
            serde_json::to_vec(&body).unwrap(),
        )
    }

    fn request_with_headers(
        method: Method,
        path: &str,
        headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
        body: Vec<u8>,
    ) -> Request<GatewayBody> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, "127.0.0.1:15081")
            .body(GatewayBody::full(body))
            .unwrap();
        request.headers_mut().extend(headers);
        request
    }

    fn modern_params(mut value: Value) -> Value {
        let object = value.as_object_mut().expect("params fixture is an object");
        object.insert(
            "_meta".to_owned(),
            json!({
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION
            }),
        );
        value
    }

    fn gateway_runtime_policy() -> RuntimePolicyDocument {
        let tools = ServerToolPolicy {
            default_action: Action::Deny,
            allowlist: vec!["read_*".to_owned()],
            denylist: vec!["delete_*".to_owned()],
        };
        RuntimePolicyDocument {
            schema_version: crate::runtime::RUNTIME_POLICY_SCHEMA_VERSION,
            workspace_root: "/workspace".into(),
            workload_uid: 1000,
            workload_gid: 1000,
            tool_policy: ToolCallPolicy {
                servers: BTreeMap::from([
                    (
                        "modern".to_owned(),
                        McpServerPolicy::StreamableHttp {
                            url: "https://modern.example.com/mcp".to_owned(),
                            tools: tools.clone(),
                            http: McpHttpPolicy::default(),
                        },
                    ),
                    (
                        "compat".to_owned(),
                        McpServerPolicy::StreamableHttp2025 {
                            url: "https://compat.example.com/mcp".to_owned(),
                            tools: tools.clone(),
                            http: McpHttpPolicy::default(),
                        },
                    ),
                    (
                        "compat-two".to_owned(),
                        McpServerPolicy::StreamableHttp2025 {
                            url: "https://compat-two.example.com/mcp".to_owned(),
                            tools,
                            http: McpHttpPolicy::default(),
                        },
                    ),
                ]),
                ..ToolCallPolicy::default()
            },
            audit_log_path: "/var/log/sendbox/boundary.log".into(),
            fixed_environment: BTreeMap::new(),
            inherited_environment_keys: BTreeSet::new(),
            observation: None,
        }
    }
}
