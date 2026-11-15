//! Host side of the brokered credential relay.
//!
//! The guest forwards one HTTP request per relay stream over the
//! authenticated control channel. This endpoint authorizes every request
//! against the session's grants, injects the provider credential that only
//! the host holds, streams the verified HTTPS response back under credit flow
//! control, and records redacted audit evidence. The workload never receives
//! the credential and cannot choose the upstream, identity, or secret.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use http::{HeaderName, Method};
use sendbox_governance::{CredentialProvider, CredentialServiceProfile, ProviderInjection};
use sendbox_protocol::relay::{
    CREDENTIAL_RELAY_CHUNK_BYTES, CREDENTIAL_RELAY_SCHEMA_VERSION, CREDENTIAL_RELAY_WINDOW_CHUNKS,
    CredentialRelayCreditV1, CredentialRelayEndV1, CredentialRelayHeaderV1,
    CredentialRelayOutcomeV1, CredentialRelayRequestV1, CredentialRelayResponseHeadV1,
    valid_credential_relay_stream,
};
use sendbox_protocol::{Event, EventKind};
use sendbox_runtime::CancellationToken;
use sendbox_secrets::{
    BrokerRequest, CredentialInjection, CredentialPolicy, RedirectPolicy, SecretName,
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    CredentialBrokerError, SecretResolver, StreamingLimits, StreamingTransport,
    UpstreamAddressPolicy, UpstreamRequest,
};

pub type RelayFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Hard cap for the policy-level buffered response limit; streamed responses
/// use the service limit instead.
const POLICY_RESPONSE_LIMIT: usize = 16 * 1024 * 1024;
const MAX_AUDIT_PATH_BYTES: usize = 256;

/// One brokered service as configured by the operator profile.
pub struct RelayService {
    id: String,
    provider: CredentialProvider,
    policy: CredentialPolicy,
    secret: SecretName,
    methods: Vec<Method>,
    path_prefixes: Vec<String>,
    max_request_bytes: usize,
    max_response_bytes: u64,
    max_duration: Duration,
    idle_timeout: Duration,
}

impl fmt::Debug for RelayService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayService")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("target", &self.policy.target_host())
            .finish_non_exhaustive()
    }
}

impl RelayService {
    pub fn from_profile(profile: &CredentialServiceProfile) -> Result<Self, CredentialBrokerError> {
        let invalid = |message: &str| {
            CredentialBrokerError::InvalidConfiguration(format!(
                "credential service `{}`: {message}",
                profile.id
            ))
        };
        let secret =
            SecretName::new(profile.secret.clone()).map_err(|error| invalid(&error.to_string()))?;
        let methods = profile
            .effective_methods()
            .iter()
            .map(|method| Method::from_bytes(method.as_bytes()).map_err(|_| invalid("bad method")))
            .collect::<Result<Vec<_>, _>>()?;
        let max_request_bytes = usize::try_from(profile.max_request_bytes)
            .map_err(|_| invalid("request limit is out of range"))?;
        let injection = match profile.provider.injection() {
            ProviderInjection::Bearer => CredentialInjection::Bearer,
            ProviderInjection::Header(name) => CredentialInjection::Header {
                name: HeaderName::from_static(name),
            },
        };
        let policy = CredentialPolicy::new(
            profile.provider.target_host(),
            "/",
            injection,
            methods.iter().cloned(),
            max_request_bytes,
            usize::try_from(profile.max_response_bytes)
                .unwrap_or(POLICY_RESPONSE_LIMIT)
                .min(POLICY_RESPONSE_LIMIT),
            RedirectPolicy::Deny,
            secret.clone(),
        )?;
        Ok(Self {
            id: profile.id.to_string(),
            provider: profile.provider,
            policy,
            secret,
            methods,
            path_prefixes: profile.effective_path_prefixes(),
            max_request_bytes,
            max_response_bytes: profile.max_response_bytes,
            max_duration: Duration::from_secs(profile.max_duration_seconds),
            idle_timeout: Duration::from_secs(profile.idle_timeout_seconds),
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn secret_name(&self) -> &SecretName {
        &self.secret
    }
}

/// Decision for one relay request. Implementations consult the grant
/// authority with identity taken from trusted host state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAuthorization {
    Allowed { grant: String, generation: u64 },
    Denied { reason: &'static str },
}

pub trait RelayAuthorizer: Send + Sync {
    fn authorize<'a>(
        &'a self,
        service: &'a str,
        method: &'a str,
        path: &'a str,
    ) -> RelayFuture<'a, RelayAuthorization>;
}

/// Delivers host-to-guest relay events over the authenticated channel.
pub trait RelayOutbound: Send + Sync {
    fn send(&self, event: Event) -> RelayFuture<'_, Result<(), CredentialBrokerError>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStreamOutcome {
    Complete,
    Denied,
    Failed,
    Aborted,
    /// Aborted after the request reached the upstream; it may have been
    /// processed and its external effects are not reversed.
    AbortedUncertain,
}

impl RelayStreamOutcome {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Denied => "denied",
            Self::Failed => "failed",
            Self::Aborted => "aborted",
            Self::AbortedUncertain => "aborted_uncertain",
        }
    }
}

/// Redacted audit evidence. Paths never include the query string and no
/// header, body, or credential is ever recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAuditEvent {
    Decision {
        stream: u64,
        service: String,
        method: String,
        path: String,
        allowed: bool,
        reason: &'static str,
        grant: Option<String>,
        generation: Option<u64>,
    },
    Outcome {
        stream: u64,
        service: String,
        method: String,
        path: String,
        outcome: RelayStreamOutcome,
        reason: &'static str,
        status: Option<u16>,
        request_bytes: u64,
        response_bytes: u64,
        duration_ms: u64,
    },
}

pub trait RelayAuditSink: Send + Sync {
    fn record(&self, event: RelayAuditEvent);
}

#[derive(Debug, Clone)]
pub struct RelayLimits {
    pub max_streams: usize,
    pub connect_timeout: Duration,
    pub max_header_count: usize,
    pub max_header_bytes: usize,
    pub address_policy: UpstreamAddressPolicy,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_streams: 8,
            connect_timeout: Duration::from_secs(10),
            max_header_count: 64,
            max_header_bytes: 32 * 1024,
            address_policy: UpstreamAddressPolicy::default(),
        }
    }
}

/// A violation that makes the relay channel itself untrustworthy. The caller
/// must fail the session rather than continue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("credential relay protocol violation: {0}")]
pub struct RelayProtocolError(pub &'static str);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayCloseReport {
    pub completed: usize,
    pub aborted: usize,
}

struct Receiving {
    service: Arc<RelayService>,
    request: CredentialRelayRequestV1,
    body: Zeroizing<Vec<u8>>,
    expected: usize,
}

/// Why a running stream was cancelled. The first cause recorded wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AbortCause {
    /// The guest ended the stream; it already knows, so no `End` is sent.
    Guest,
    /// The stream's grant lapsed and its revocation grace elapsed.
    GrantLapsed,
    /// The session is closing.
    Closing,
}

struct Running {
    service: String,
    cancel: CancellationToken,
    cause: Arc<OnceLock<AbortCause>>,
    credits: Arc<Semaphore>,
    sent: Arc<AtomicU64>,
    granted: u64,
}

enum StreamState {
    Receiving(Receiving),
    Running(Running),
}

#[derive(Default)]
struct EndpointState {
    streams: HashMap<u64, StreamState>,
    last_stream: u64,
    outbound: Option<Arc<dyn RelayOutbound>>,
}

struct Shared {
    services: BTreeMap<String, Arc<RelayService>>,
    authorizer: Arc<dyn RelayAuthorizer>,
    secrets: Arc<dyn SecretResolver>,
    transport: Arc<dyn StreamingTransport>,
    audit: Arc<dyn RelayAuditSink>,
    limits: RelayLimits,
    state: Mutex<EndpointState>,
    closed: AtomicBool,
    closing: CancellationToken,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, EndpointState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn outbound(&self) -> Option<Arc<dyn RelayOutbound>> {
        self.lock().outbound.clone()
    }

    fn finish(&self, stream: u64) {
        self.lock().streams.remove(&stream);
    }
}

pub struct RelayEndpoint {
    shared: Arc<Shared>,
    tasks: Mutex<JoinSet<()>>,
}

impl fmt::Debug for RelayEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayEndpoint")
            .field("services", &self.shared.services.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl RelayEndpoint {
    pub fn new(
        services: Vec<RelayService>,
        authorizer: Arc<dyn RelayAuthorizer>,
        secrets: Arc<dyn SecretResolver>,
        transport: Arc<dyn StreamingTransport>,
        audit: Arc<dyn RelayAuditSink>,
        limits: RelayLimits,
    ) -> Result<Self, CredentialBrokerError> {
        if services.is_empty() || limits.max_streams == 0 {
            return Err(CredentialBrokerError::InvalidConfiguration(
                "credential relay requires at least one service and stream".to_owned(),
            ));
        }
        let mut by_id = BTreeMap::new();
        for service in services {
            let id = service.id.clone();
            if by_id.insert(id.clone(), Arc::new(service)).is_some() {
                return Err(CredentialBrokerError::InvalidConfiguration(format!(
                    "credential service `{id}` is duplicated"
                )));
            }
        }
        Ok(Self {
            shared: Arc::new(Shared {
                services: by_id,
                authorizer,
                secrets,
                transport,
                audit,
                limits,
                state: Mutex::new(EndpointState::default()),
                closed: AtomicBool::new(false),
                closing: CancellationToken::new(),
            }),
            tasks: Mutex::new(JoinSet::new()),
        })
    }

    /// Connects the endpoint to the guest channel of a running workload.
    pub fn attach(&self, outbound: Arc<dyn RelayOutbound>) {
        self.shared.lock().outbound = Some(outbound);
    }

    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .spawn(task);
    }

    fn reply_end(&self, stream: u64, outcome: CredentialRelayOutcomeV1, reason: &'static str) {
        if let Some(outbound) = self.shared.outbound() {
            self.spawn(async move {
                let _ = outbound.send(end_event(stream, outcome, reason)).await;
            });
        }
    }

    /// Accepts one guest relay event without blocking. Per-request problems
    /// end only that stream; malformed channel use returns an error.
    pub fn handle(&self, event: Event) -> Result<(), RelayProtocolError> {
        let stream = event.stream_id;
        if !valid_credential_relay_stream(stream) {
            return Err(RelayProtocolError(
                "stream identifier is outside the relay range",
            ));
        }
        match event.kind {
            EventKind::CredentialRelayRequest => self.open(stream, &event.payload),
            EventKind::CredentialRelayRequestBody => self.body(stream, event.payload),
            EventKind::CredentialRelayEnd => {
                let end: CredentialRelayEndV1 = decode(&event.payload)?;
                end.validate()
                    .map_err(|_| RelayProtocolError("invalid stream end"))?;
                self.abort_stream(stream);
                Ok(())
            }
            EventKind::CredentialRelayCredit => {
                let credit: CredentialRelayCreditV1 = decode(&event.payload)?;
                credit
                    .validate()
                    .map_err(|_| RelayProtocolError("invalid credit"))?;
                self.credit(stream, credit.credits)
            }
            _ => Err(RelayProtocolError("event kind is not a guest relay event")),
        }
    }

    fn open(&self, stream: u64, payload: &[u8]) -> Result<(), RelayProtocolError> {
        let request: CredentialRelayRequestV1 = decode(payload)?;
        let mut state = self.shared.lock();
        if stream <= state.last_stream {
            return Err(RelayProtocolError("stream identifiers must increase"));
        }
        state.last_stream = stream;
        if request.validate().is_err() {
            drop(state);
            self.reply_end(stream, CredentialRelayOutcomeV1::Denied, "invalid_request");
            return Ok(());
        }
        if self.shared.closed.load(Ordering::SeqCst) {
            drop(state);
            self.reply_end(stream, CredentialRelayOutcomeV1::Denied, "session_closing");
            return Ok(());
        }
        if state.streams.len() >= self.shared.limits.max_streams {
            drop(state);
            self.reply_end(stream, CredentialRelayOutcomeV1::Denied, "too_many_streams");
            return Ok(());
        }
        let Some(service) = self.shared.services.get(&request.service).cloned() else {
            drop(state);
            self.shared.audit.record(RelayAuditEvent::Decision {
                stream,
                service: request.service.clone(),
                method: request.method.clone(),
                path: audit_path(&request.path),
                allowed: false,
                reason: "service_not_granted",
                grant: None,
                generation: None,
            });
            self.reply_end(
                stream,
                CredentialRelayOutcomeV1::Denied,
                "service_not_granted",
            );
            return Ok(());
        };
        let Ok(expected) = usize::try_from(request.body_bytes) else {
            drop(state);
            self.reply_end(
                stream,
                CredentialRelayOutcomeV1::Denied,
                "request_too_large",
            );
            return Ok(());
        };
        if expected > service.max_request_bytes {
            drop(state);
            self.reply_end(
                stream,
                CredentialRelayOutcomeV1::Denied,
                "request_too_large",
            );
            return Ok(());
        }
        let receiving = Receiving {
            service,
            request,
            body: Zeroizing::new(Vec::with_capacity(expected.min(64 * 1024))),
            expected,
        };
        if expected == 0 {
            drop(state);
            self.start(stream, receiving);
        } else {
            state
                .streams
                .insert(stream, StreamState::Receiving(receiving));
        }
        Ok(())
    }

    fn body(&self, stream: u64, bytes: Vec<u8>) -> Result<(), RelayProtocolError> {
        if bytes.is_empty() || bytes.len() > CREDENTIAL_RELAY_CHUNK_BYTES {
            return Err(RelayProtocolError("request body chunk size is invalid"));
        }
        let mut state = self.shared.lock();
        if stream > state.last_stream {
            return Err(RelayProtocolError("request body for an unopened stream"));
        }
        let Some(StreamState::Receiving(receiving)) = state.streams.get_mut(&stream) else {
            return Ok(());
        };
        if receiving.body.len().saturating_add(bytes.len()) > receiving.expected {
            state.streams.remove(&stream);
            drop(state);
            self.reply_end(
                stream,
                CredentialRelayOutcomeV1::Failed,
                "request_length_mismatch",
            );
            return Ok(());
        }
        receiving.body.extend_from_slice(&bytes);
        let mut bytes = Zeroizing::new(bytes);
        bytes.clear();
        if receiving.body.len() == receiving.expected {
            let Some(StreamState::Receiving(receiving)) = state.streams.remove(&stream) else {
                unreachable!("stream state was just matched");
            };
            drop(state);
            self.start(stream, receiving);
        }
        Ok(())
    }

    fn credit(&self, stream: u64, credits: u16) -> Result<(), RelayProtocolError> {
        let mut state = self.shared.lock();
        if stream > state.last_stream {
            return Err(RelayProtocolError("credit for an unopened stream"));
        }
        let Some(StreamState::Running(running)) = state.streams.get_mut(&stream) else {
            return Ok(());
        };
        let granted = running.granted.saturating_add(u64::from(credits));
        if granted > running.sent.load(Ordering::SeqCst) {
            return Err(RelayProtocolError("credit exceeds the stream window"));
        }
        running.granted = granted;
        running.credits.add_permits(usize::from(credits));
        Ok(())
    }

    fn abort_stream(&self, stream: u64) {
        if let Some(state) = self.shared.lock().streams.remove(&stream)
            && let StreamState::Running(running) = state
        {
            running.abort(AbortCause::Guest);
        }
    }

    fn start(&self, stream: u64, receiving: Receiving) {
        let cancel = CancellationToken::new();
        let cause = Arc::new(OnceLock::new());
        let credits = Arc::new(Semaphore::new(usize::from(CREDENTIAL_RELAY_WINDOW_CHUNKS)));
        let sent = Arc::new(AtomicU64::new(0));
        self.shared.lock().streams.insert(
            stream,
            StreamState::Running(Running {
                service: receiving.service.id.clone(),
                cancel: cancel.clone(),
                cause: Arc::clone(&cause),
                credits: Arc::clone(&credits),
                sent: Arc::clone(&sent),
                granted: 0,
            }),
        );
        let shared = Arc::clone(&self.shared);
        self.spawn(async move {
            let exchange = Exchange {
                shared: Arc::clone(&shared),
                stream,
                started: Instant::now(),
                service: receiving.service,
                request: receiving.request,
                cancel,
                cause,
                credits,
                sent,
            };
            exchange.run(receiving.body).await;
            shared.finish(stream);
        });
    }

    /// Ends streams of `services` that were authorized before their grant
    /// lapsed. Later requests are denied by the authorizer; streams already
    /// running get `grace` to finish before they are cancelled, and the guest
    /// is told the stream ended with `grant_lapsed`.
    pub fn expire_in_flight(&self, services: &[&str], grace: Duration) {
        let running = self
            .shared
            .lock()
            .streams
            .values()
            .filter_map(|stream| match stream {
                StreamState::Running(running) if services.contains(&running.service.as_str()) => {
                    Some((running.cancel.clone(), Arc::clone(&running.cause)))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if running.is_empty() {
            return;
        }
        let closing = self.shared.closing.clone();
        self.spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(grace) => {}
                () = closing.cancelled() => return,
            }
            for (cancel, cause) in running {
                let _ = cause.set(AbortCause::GrantLapsed);
                cancel.cancel();
            }
        });
    }

    /// Stops accepting requests, lets in-flight streams finish within
    /// `grace`, then aborts the rest. Aborted streams that already reached the
    /// upstream are reported as uncertain.
    pub async fn close(&self, grace: Duration) -> RelayCloseReport {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.shared.closing.cancel();
        let mut tasks = std::mem::take(
            &mut *self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut report = RelayCloseReport::default();
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(_)) => report.completed += 1,
                Ok(None) => break,
                Err(_) => {
                    let running = {
                        let mut state = self.shared.lock();
                        state.streams.drain().collect::<Vec<_>>()
                    };
                    for (_, stream) in running {
                        if let StreamState::Running(running) = stream {
                            running.abort(AbortCause::Closing);
                        }
                    }
                    while let Some(result) = tasks.join_next().await {
                        if result.is_ok() {
                            report.aborted += 1;
                        }
                    }
                    break;
                }
            }
        }
        self.shared.lock().outbound = None;
        report
    }
}

impl Running {
    fn abort(&self, cause: AbortCause) {
        let _ = self.cause.set(cause);
        self.cancel.cancel();
    }
}

struct Exchange {
    shared: Arc<Shared>,
    stream: u64,
    started: Instant,
    service: Arc<RelayService>,
    request: CredentialRelayRequestV1,
    cancel: CancellationToken,
    cause: Arc<OnceLock<AbortCause>>,
    credits: Arc<Semaphore>,
    sent: Arc<AtomicU64>,
}

struct Progress {
    contacted: bool,
    status: Option<u16>,
    response_bytes: u64,
}

enum Failure {
    Denied(&'static str),
    Failed(&'static str),
    Aborted,
}

impl Exchange {
    fn path(&self) -> &str {
        self.request
            .path
            .split_once('?')
            .map_or(self.request.path.as_str(), |(path, _)| path)
    }

    async fn run(self, body: Zeroizing<Vec<u8>>) {
        let request_bytes = body.len() as u64;
        let mut progress = Progress {
            contacted: false,
            status: None,
            response_bytes: 0,
        };
        let result = self.forward(body, &mut progress).await;
        let (outcome, reason, end) = match result {
            Ok(()) => (
                RelayStreamOutcome::Complete,
                "complete",
                Some((CredentialRelayOutcomeV1::Complete, "complete")),
            ),
            Err(Failure::Denied(reason)) => (
                RelayStreamOutcome::Denied,
                reason,
                Some((CredentialRelayOutcomeV1::Denied, reason)),
            ),
            Err(Failure::Failed(reason)) => (
                RelayStreamOutcome::Failed,
                reason,
                Some((CredentialRelayOutcomeV1::Failed, reason)),
            ),
            Err(Failure::Aborted) => {
                let reason = match self.cause.get() {
                    Some(AbortCause::GrantLapsed) => "grant_lapsed",
                    _ => "aborted",
                };
                (
                    if progress.contacted {
                        RelayStreamOutcome::AbortedUncertain
                    } else {
                        RelayStreamOutcome::Aborted
                    },
                    reason,
                    (self.cause.get() != Some(&AbortCause::Guest))
                        .then_some((CredentialRelayOutcomeV1::Aborted, reason)),
                )
            }
        };
        if let Some((outcome, reason)) = end
            && let Some(outbound) = self.shared.outbound()
        {
            let _ = outbound.send(end_event(self.stream, outcome, reason)).await;
        }
        self.shared.audit.record(RelayAuditEvent::Outcome {
            stream: self.stream,
            service: self.service.id.clone(),
            method: self.request.method.clone(),
            path: audit_path(self.path()),
            outcome,
            reason,
            status: progress.status,
            request_bytes,
            response_bytes: progress.response_bytes,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });
    }

    async fn forward(
        &self,
        body: Zeroizing<Vec<u8>>,
        progress: &mut Progress,
    ) -> Result<(), Failure> {
        let deadline = tokio::time::Instant::from_std(self.started + self.service.max_duration);
        let method = Method::from_bytes(self.request.method.as_bytes())
            .map_err(|_| Failure::Denied("method_not_granted"))?;
        let local_denial = if !self.service.methods.contains(&method) {
            Some("method_not_granted")
        } else if sendbox_governance::validate_request_path(self.path()).is_err() {
            Some("invalid_path")
        } else if !sendbox_governance::path_permitted(&self.service.path_prefixes, self.path()) {
            Some("path_not_granted")
        } else {
            None
        };
        let authorization = match local_denial {
            Some(reason) => RelayAuthorization::Denied { reason },
            None => tokio::select! {
                () = self.cancel.cancelled() => return Err(Failure::Aborted),
                authorization = self.shared.authorizer.authorize(
                    &self.service.id,
                    &self.request.method,
                    self.path(),
                ) => authorization,
            },
        };
        let (allowed, reason, grant, generation) = match &authorization {
            RelayAuthorization::Allowed { grant, generation } => {
                (true, "allowed", Some(grant.clone()), Some(*generation))
            }
            RelayAuthorization::Denied { reason } => (false, *reason, None, None),
        };
        self.shared.audit.record(RelayAuditEvent::Decision {
            stream: self.stream,
            service: self.service.id.clone(),
            method: self.request.method.clone(),
            path: audit_path(self.path()),
            allowed,
            reason,
            grant,
            generation,
        });
        if !allowed {
            return Err(Failure::Denied(reason));
        }

        let secrets = Arc::clone(&self.shared.secrets);
        let name = self.service.secret.clone();
        let secret = tokio::select! {
            () = self.cancel.cancelled() => return Err(Failure::Aborted),
            secret = tokio::task::spawn_blocking(move || secrets.retrieve(&name)) => secret
                .map_err(|_| Failure::Failed("credential_unavailable"))?
                .map_err(|_| Failure::Failed("credential_unavailable"))?,
        };
        let url = Url::parse(&format!(
            "https://{}{}",
            self.service.policy.target_host(),
            self.request.path
        ))
        .map_err(|_| Failure::Denied("invalid_path"))?;
        let headers = self
            .request
            .headers
            .iter()
            .filter(|header| self.service.provider.forwards_request_header(&header.name))
            .map(|header| {
                HeaderName::from_bytes(header.name.as_bytes())
                    .map(|name| (name, header.value.as_bytes().to_vec()))
                    .map_err(|_| Failure::Denied("invalid_request"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transformed = self
            .service
            .policy
            .transform(
                BrokerRequest {
                    method,
                    url,
                    headers,
                    body: body.to_vec(),
                },
                &secret,
            )
            .map_err(|_| Failure::Denied("request_rejected"))?;
        drop(secret);
        drop(body);
        let upstream = UpstreamRequest::from_transformed(transformed, usize::MAX);
        let limits = StreamingLimits {
            connect_timeout: self.shared.limits.connect_timeout,
            idle_timeout: self.service.idle_timeout,
            max_header_count: self.shared.limits.max_header_count,
            max_header_bytes: self.shared.limits.max_header_bytes,
        };
        progress.contacted = true;
        let mut response = tokio::select! {
            () = self.cancel.cancelled() => return Err(Failure::Aborted),
            () = tokio::time::sleep_until(deadline) => return Err(Failure::Failed("max_duration")),
            response = self.shared.transport.open(
                &upstream,
                &limits,
                &self.shared.limits.address_policy,
                &self.cancel,
            ) => response.map_err(|error| match error {
                CredentialBrokerError::Cancelled => Failure::Aborted,
                CredentialBrokerError::Upstream(message) if message.contains("address class") => {
                    Failure::Failed("upstream_address_denied")
                }
                _ => Failure::Failed("upstream_unavailable"),
            })?,
        };
        drop(upstream);
        progress.status = Some(response.status.as_u16());
        if response.status.is_redirection() {
            return Err(Failure::Failed("redirect_denied"));
        }
        let head = CredentialRelayResponseHeadV1 {
            schema_version: CREDENTIAL_RELAY_SCHEMA_VERSION,
            status: response.status.as_u16(),
            headers: response
                .headers
                .iter()
                .filter(|(name, _)| forwards_response_header(name))
                .filter_map(|(name, value)| {
                    value.to_str().ok().map(|value| CredentialRelayHeaderV1 {
                        name: name.as_str().to_owned(),
                        value: value.to_owned(),
                    })
                })
                .collect(),
        };
        head.validate()
            .map_err(|_| Failure::Failed("upstream_headers_invalid"))?;
        self.send(Event {
            stream_id: self.stream,
            kind: EventKind::CredentialRelayResponseHead,
            payload: serde_json::to_vec(&head).map_err(|_| Failure::Failed("encode_failed"))?,
        })
        .await?;

        loop {
            let chunk = tokio::select! {
                () = self.cancel.cancelled() => return Err(Failure::Aborted),
                () = tokio::time::sleep_until(deadline) => return Err(Failure::Failed("max_duration")),
                chunk = tokio::time::timeout(self.service.idle_timeout, response.body.next_chunk()) => {
                    chunk
                        .map_err(|_| Failure::Failed("idle_timeout"))?
                        .map_err(|_| Failure::Failed("upstream_read_failed"))?
                }
            };
            let Some(chunk) = chunk else {
                return Ok(());
            };
            progress.response_bytes = progress.response_bytes.saturating_add(chunk.len() as u64);
            if progress.response_bytes > self.service.max_response_bytes {
                return Err(Failure::Failed("response_too_large"));
            }
            for piece in chunk.chunks(CREDENTIAL_RELAY_CHUNK_BYTES) {
                let permit = tokio::select! {
                    () = self.cancel.cancelled() => return Err(Failure::Aborted),
                    () = tokio::time::sleep_until(deadline) => return Err(Failure::Failed("max_duration")),
                    permit = tokio::time::timeout(self.service.idle_timeout, self.credits.acquire()) => permit
                        .map_err(|_| Failure::Failed("credit_timeout"))?
                        .map_err(|_| Failure::Aborted)?,
                };
                permit.forget();
                self.sent.fetch_add(1, Ordering::SeqCst);
                self.send(Event {
                    stream_id: self.stream,
                    kind: EventKind::CredentialRelayResponseBody,
                    payload: piece.to_vec(),
                })
                .await?;
            }
        }
    }

    async fn send(&self, event: Event) -> Result<(), Failure> {
        let outbound = self.shared.outbound().ok_or(Failure::Aborted)?;
        tokio::select! {
            () = self.cancel.cancelled() => Err(Failure::Aborted),
            result = outbound.send(event) => result.map_err(|_| Failure::Aborted),
        }
    }
}

fn forwards_response_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "set-cookie" | "set-cookie2" | "content-length" | "transfer-encoding" | "connection"
    )
}

fn end_event(stream: u64, outcome: CredentialRelayOutcomeV1, reason: &'static str) -> Event {
    Event {
        stream_id: stream,
        kind: EventKind::CredentialRelayEnd,
        payload: serde_json::to_vec(&CredentialRelayEndV1::new(outcome, reason))
            .expect("relay end payloads always encode"),
    }
}

fn decode<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T, RelayProtocolError> {
    serde_json::from_slice(payload).map_err(|_| RelayProtocolError("malformed relay payload"))
}

fn audit_path(path: &str) -> String {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    if path.len() <= MAX_AUDIT_PATH_BYTES {
        return path.to_owned();
    }
    let mut end = MAX_AUDIT_PATH_BYTES;
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    path[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    use async_trait::async_trait;
    use http::StatusCode;
    use sendbox_governance::GovernanceProfile;
    use sendbox_protocol::relay::CREDENTIAL_RELAY_STREAM_BASE;
    use sendbox_secrets::SecretValue;
    use tokio::sync::mpsc;

    use super::*;
    use crate::{ResponseBody, StreamingResponse};

    const SECRET: &str = "sk-ant-live-0123456789abcdef";

    fn service(path_prefixes: &str) -> RelayService {
        let profile = GovernanceProfile::parse(
            format!(
                r#"
format: sendbox.governance-profile
version: 1
id: acme
revision: 1
not_before_unix: 0
expires_at_unix: 1000
ceiling:
  runtimes: [apple]
  commands: {{ default_action: deny }}
  network: {{ default_action: deny }}
credential_services:
  - id: anthropic
    provider: anthropic
    secret: SENDBOX_ANTHROPIC_API_KEY
    methods: [POST]
    path_prefixes: [{path_prefixes}]
    max_request_bytes: 64
    max_response_bytes: 4194304
    idle_timeout_seconds: 5
"#
            )
            .as_bytes(),
        )
        .expect("profile");
        RelayService::from_profile(&profile.credential_services[0]).expect("service")
    }

    struct Authorizer {
        decision: RelayAuthorization,
        calls: AtomicUsize,
    }

    impl RelayAuthorizer for Authorizer {
        fn authorize<'a>(
            &'a self,
            _service: &'a str,
            _method: &'a str,
            _path: &'a str,
        ) -> RelayFuture<'a, RelayAuthorization> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { self.decision.clone() })
        }
    }

    struct Secrets;

    impl SecretResolver for Secrets {
        fn retrieve(&self, _name: &SecretName) -> Result<SecretValue, CredentialBrokerError> {
            Ok(SecretValue::try_from(SECRET).expect("secret"))
        }
    }

    #[derive(Debug, Clone)]
    struct Captured {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    struct Chunks(VecDeque<Vec<u8>>, bool);

    #[async_trait]
    impl ResponseBody for Chunks {
        async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, CredentialBrokerError> {
            match self.0.pop_front() {
                Some(chunk) => Ok(Some(chunk)),
                None if self.1 => std::future::pending().await,
                None => Ok(None),
            }
        }
    }

    struct Transport {
        status: StatusCode,
        chunks: Vec<Vec<u8>>,
        stall: bool,
        captured: Mutex<Vec<Captured>>,
    }

    #[async_trait]
    impl StreamingTransport for Transport {
        async fn open(
            &self,
            request: &UpstreamRequest,
            _limits: &StreamingLimits,
            _address_policy: &UpstreamAddressPolicy,
            _cancellation: &CancellationToken,
        ) -> Result<StreamingResponse, CredentialBrokerError> {
            self.captured.lock().unwrap().push(Captured {
                method: request.method().to_string(),
                url: request.url().to_owned(),
                headers: request
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_owned(),
                            String::from_utf8_lossy(value.expose()).into_owned(),
                        )
                    })
                    .collect(),
                body: request.body().to_vec(),
            });
            Ok(StreamingResponse {
                status: self.status,
                headers: vec![
                    (
                        HeaderName::from_static("content-type"),
                        http::HeaderValue::from_static("text/event-stream"),
                    ),
                    (
                        HeaderName::from_static("set-cookie"),
                        http::HeaderValue::from_static("session=1"),
                    ),
                ],
                body: Box::new(Chunks(self.chunks.clone().into(), self.stall)),
            })
        }
    }

    struct Outbound(mpsc::UnboundedSender<Event>);

    impl RelayOutbound for Outbound {
        fn send(&self, event: Event) -> RelayFuture<'_, Result<(), CredentialBrokerError>> {
            let result = self
                .0
                .send(event)
                .map_err(|_| CredentialBrokerError::Cancelled);
            Box::pin(async move { result })
        }
    }

    #[derive(Default)]
    struct Audit(Mutex<Vec<RelayAuditEvent>>);

    impl RelayAuditSink for Audit {
        fn record(&self, event: RelayAuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    struct Harness {
        endpoint: RelayEndpoint,
        events: mpsc::UnboundedReceiver<Event>,
        authorizer: Arc<Authorizer>,
        transport: Arc<Transport>,
        audit: Arc<Audit>,
    }

    fn harness(decision: RelayAuthorization, transport: Transport) -> Harness {
        let authorizer = Arc::new(Authorizer {
            decision,
            calls: AtomicUsize::new(0),
        });
        let transport = Arc::new(transport);
        let audit = Arc::new(Audit::default());
        let endpoint = RelayEndpoint::new(
            vec![service("/v1/messages")],
            authorizer.clone(),
            Arc::new(Secrets),
            transport.clone(),
            audit.clone(),
            RelayLimits {
                max_streams: 2,
                ..RelayLimits::default()
            },
        )
        .expect("endpoint");
        let (sender, events) = mpsc::unbounded_channel();
        endpoint.attach(Arc::new(Outbound(sender)));
        Harness {
            endpoint,
            events,
            authorizer,
            transport,
            audit,
        }
    }

    fn transport(chunks: Vec<Vec<u8>>) -> Transport {
        Transport {
            status: StatusCode::OK,
            chunks,
            stall: false,
            captured: Mutex::new(Vec::new()),
        }
    }

    fn allowed() -> RelayAuthorization {
        RelayAuthorization::Allowed {
            grant: "00".repeat(16),
            generation: 1,
        }
    }

    fn request_event(stream: u64, path: &str, body: &[u8]) -> Vec<Event> {
        let request = CredentialRelayRequestV1 {
            schema_version: CREDENTIAL_RELAY_SCHEMA_VERSION,
            service: "anthropic".to_owned(),
            method: "POST".to_owned(),
            path: path.to_owned(),
            headers: vec![
                CredentialRelayHeaderV1 {
                    name: "content-type".to_owned(),
                    value: "application/json".to_owned(),
                },
                CredentialRelayHeaderV1 {
                    name: "x-api-key".to_owned(),
                    value: "agent-supplied".to_owned(),
                },
                CredentialRelayHeaderV1 {
                    name: "authorization".to_owned(),
                    value: "Bearer agent-supplied".to_owned(),
                },
                CredentialRelayHeaderV1 {
                    name: "anthropic-version".to_owned(),
                    value: "2023-06-01".to_owned(),
                },
            ],
            body_bytes: body.len() as u64,
        };
        let mut events = vec![Event {
            stream_id: stream,
            kind: EventKind::CredentialRelayRequest,
            payload: serde_json::to_vec(&request).unwrap(),
        }];
        if !body.is_empty() {
            events.push(Event {
                stream_id: stream,
                kind: EventKind::CredentialRelayRequestBody,
                payload: body.to_vec(),
            });
        }
        events
    }

    async fn next(events: &mut mpsc::UnboundedReceiver<Event>) -> Event {
        tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("relay event")
            .expect("open channel")
    }

    fn end(event: &Event) -> CredentialRelayEndV1 {
        assert_eq!(event.kind, EventKind::CredentialRelayEnd);
        serde_json::from_slice(&event.payload).unwrap()
    }

    fn assert_no_secret(harness: &Harness) {
        let audit = format!("{:?}", harness.audit.0.lock().unwrap());
        assert!(!audit.contains(SECRET));
        assert!(!audit.contains("agent-supplied"));
    }

    #[tokio::test]
    async fn allowed_requests_inject_the_host_credential_and_stream_back() {
        let stream = CREDENTIAL_RELAY_STREAM_BASE + 1;
        let mut harness = harness(allowed(), transport(vec![b"event: one\n\n".to_vec()]));
        for event in request_event(stream, "/v1/messages?beta=true", b"{\"x\":1}") {
            harness.endpoint.handle(event).unwrap();
        }
        let head = next(&mut harness.events).await;
        assert_eq!(head.kind, EventKind::CredentialRelayResponseHead);
        let head: CredentialRelayResponseHeadV1 = serde_json::from_slice(&head.payload).unwrap();
        assert_eq!(head.status, 200);
        assert!(
            head.headers
                .iter()
                .all(|header| header.name != "set-cookie")
        );
        let body = next(&mut harness.events).await;
        assert_eq!(body.payload, b"event: one\n\n");
        assert_eq!(
            end(&next(&mut harness.events).await).outcome,
            CredentialRelayOutcomeV1::Complete
        );

        let captured = harness.transport.captured.lock().unwrap()[0].clone();
        assert_eq!(captured.method, "POST");
        assert_eq!(
            captured.url,
            "https://api.anthropic.com/v1/messages?beta=true"
        );
        assert_eq!(captured.body, b"{\"x\":1}");
        let header = |name: &str| {
            captured
                .headers
                .iter()
                .filter(|(header, _)| header == name)
                .map(|(_, value)| value.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(header("x-api-key"), vec![SECRET.to_owned()]);
        assert!(header("authorization").is_empty());
        assert_eq!(header("anthropic-version"), vec!["2023-06-01".to_owned()]);

        harness.endpoint.close(Duration::from_secs(1)).await;
        let audit = harness.audit.0.lock().unwrap().clone();
        assert!(matches!(
            &audit[0],
            RelayAuditEvent::Decision { allowed: true, path, .. } if path == "/v1/messages"
        ));
        assert!(matches!(
            &audit[1],
            RelayAuditEvent::Outcome {
                outcome: RelayStreamOutcome::Complete,
                status: Some(200),
                ..
            }
        ));
        drop(audit);
        assert_no_secret(&harness);
    }

    #[tokio::test]
    async fn denials_never_contact_the_upstream() {
        let mut harness = harness(
            RelayAuthorization::Denied {
                reason: "stale_policy",
            },
            transport(Vec::new()),
        );
        let stream = CREDENTIAL_RELAY_STREAM_BASE;
        for event in request_event(stream, "/v1/messages", b"{}") {
            harness.endpoint.handle(event).unwrap();
        }
        let ended = end(&next(&mut harness.events).await);
        assert_eq!(ended.outcome, CredentialRelayOutcomeV1::Denied);
        assert_eq!(ended.reason, "stale_policy");

        for (offset, path) in ["/v1/files", "/v1/messages/../files"]
            .into_iter()
            .enumerate()
        {
            for event in request_event(stream + 1 + offset as u64, path, b"{}") {
                harness.endpoint.handle(event).unwrap();
            }
            let ended = end(&next(&mut harness.events).await);
            assert_eq!(ended.outcome, CredentialRelayOutcomeV1::Denied);
        }
        assert_eq!(harness.authorizer.calls.load(Ordering::SeqCst), 1);
        assert!(harness.transport.captured.lock().unwrap().is_empty());

        let mut oversized = request_event(stream + 10, "/v1/messages", &[b'x'; 65]);
        harness.endpoint.handle(oversized.remove(0)).unwrap();
        assert_eq!(
            end(&next(&mut harness.events).await).reason,
            "request_too_large"
        );

        let mut unknown = request_event(stream + 11, "/v1/messages", b"");
        let mut request: CredentialRelayRequestV1 =
            serde_json::from_slice(&unknown[0].payload).unwrap();
        request.service = "openai".to_owned();
        unknown[0].payload = serde_json::to_vec(&request).unwrap();
        harness.endpoint.handle(unknown.remove(0)).unwrap();
        assert_eq!(
            end(&next(&mut harness.events).await).reason,
            "service_not_granted"
        );
        harness.endpoint.close(Duration::from_secs(1)).await;
        assert_no_secret(&harness);
    }

    #[tokio::test]
    async fn response_chunks_require_guest_credit() {
        let chunks = vec![vec![b'a'; CREDENTIAL_RELAY_CHUNK_BYTES]; 20];
        let mut harness = harness(allowed(), transport(chunks));
        let stream = CREDENTIAL_RELAY_STREAM_BASE;
        for event in request_event(stream, "/v1/messages", b"{}") {
            harness.endpoint.handle(event).unwrap();
        }
        assert_eq!(
            next(&mut harness.events).await.kind,
            EventKind::CredentialRelayResponseHead
        );
        for _ in 0..CREDENTIAL_RELAY_WINDOW_CHUNKS {
            assert_eq!(
                next(&mut harness.events).await.kind,
                EventKind::CredentialRelayResponseBody
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), harness.events.recv())
                .await
                .is_err(),
            "the host must wait for credit"
        );
        let credit = |credits| Event {
            stream_id: stream,
            kind: EventKind::CredentialRelayCredit,
            payload: serde_json::to_vec(&CredentialRelayCreditV1::new(credits).unwrap()).unwrap(),
        };
        assert!(harness.endpoint.handle(credit(16)).is_ok());
        for _ in 0..4 {
            assert_eq!(
                next(&mut harness.events).await.kind,
                EventKind::CredentialRelayResponseBody
            );
        }
        assert_eq!(
            end(&next(&mut harness.events).await).outcome,
            CredentialRelayOutcomeV1::Complete
        );
        harness.endpoint.close(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn lapsed_grants_end_only_their_streams_and_guest_ends_are_not_echoed() {
        let transport = Transport {
            stall: true,
            ..transport(Vec::new())
        };
        let mut harness = harness(allowed(), transport);
        let stream = CREDENTIAL_RELAY_STREAM_BASE;
        for event in request_event(stream, "/v1/messages", b"{}") {
            harness.endpoint.handle(event).unwrap();
        }
        assert_eq!(
            next(&mut harness.events).await.kind,
            EventKind::CredentialRelayResponseHead
        );
        harness
            .endpoint
            .expire_in_flight(&["openai"], Duration::ZERO);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), harness.events.recv())
                .await
                .is_err(),
            "another service's lapse must not end this stream"
        );
        harness
            .endpoint
            .expire_in_flight(&["anthropic"], Duration::ZERO);
        let ended = end(&next(&mut harness.events).await);
        assert_eq!(ended.outcome, CredentialRelayOutcomeV1::Aborted);
        assert_eq!(ended.reason, "grant_lapsed");

        let guest_ended = stream + 1;
        for event in request_event(guest_ended, "/v1/messages", b"{}") {
            harness.endpoint.handle(event).unwrap();
        }
        assert_eq!(
            next(&mut harness.events).await.kind,
            EventKind::CredentialRelayResponseHead
        );
        harness
            .endpoint
            .handle(Event {
                stream_id: guest_ended,
                kind: EventKind::CredentialRelayEnd,
                payload: serde_json::to_vec(&CredentialRelayEndV1::new(
                    CredentialRelayOutcomeV1::Aborted,
                    "client_disconnected",
                ))
                .unwrap(),
            })
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), harness.events.recv())
                .await
                .is_err(),
            "a guest-initiated end is not echoed"
        );
        harness.endpoint.close(Duration::from_secs(1)).await;
        let reasons = harness
            .audit
            .0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                RelayAuditEvent::Outcome { reason, .. } => Some(*reason),
                RelayAuditEvent::Decision { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(reasons, ["grant_lapsed", "aborted"]);
    }

    #[tokio::test]
    async fn credit_beyond_the_window_and_misordered_streams_are_violations() {
        let transport = Transport {
            stall: true,
            ..transport(Vec::new())
        };
        let mut harness = harness(allowed(), transport);
        let stream = CREDENTIAL_RELAY_STREAM_BASE + 5;
        for event in request_event(stream, "/v1/messages", b"{}") {
            harness.endpoint.handle(event).unwrap();
        }
        assert_eq!(
            next(&mut harness.events).await.kind,
            EventKind::CredentialRelayResponseHead
        );
        let credit = Event {
            stream_id: stream,
            kind: EventKind::CredentialRelayCredit,
            payload: serde_json::to_vec(&CredentialRelayCreditV1::new(1).unwrap()).unwrap(),
        };
        assert!(harness.endpoint.handle(credit).is_err());
        assert!(
            harness
                .endpoint
                .handle(request_event(stream, "/v1/messages", b"").remove(0))
                .is_err()
        );
        assert!(
            harness
                .endpoint
                .handle(request_event(7, "/v1/messages", b"").remove(0))
                .is_err()
        );
        assert!(
            harness
                .endpoint
                .handle(Event {
                    stream_id: stream + 100,
                    kind: EventKind::CredentialRelayRequestBody,
                    payload: vec![1],
                })
                .is_err()
        );
        assert!(
            harness
                .endpoint
                .handle(Event {
                    stream_id: stream,
                    kind: EventKind::CredentialRelayResponseBody,
                    payload: vec![1],
                })
                .is_err()
        );

        let report = harness.endpoint.close(Duration::from_millis(50)).await;
        assert_eq!(report.aborted, 1);
        let audit = harness.audit.0.lock().unwrap().clone();
        assert!(audit.iter().any(|event| matches!(
            event,
            RelayAuditEvent::Outcome {
                outcome: RelayStreamOutcome::AbortedUncertain,
                ..
            }
        )));
        assert_eq!(
            end(&next(&mut harness.events).await).outcome,
            CredentialRelayOutcomeV1::Aborted
        );
    }

    #[tokio::test]
    async fn redirects_and_closed_sessions_are_refused() {
        let mut harness = harness(
            allowed(),
            Transport {
                status: StatusCode::TEMPORARY_REDIRECT,
                ..transport(Vec::new())
            },
        );
        let stream = CREDENTIAL_RELAY_STREAM_BASE;
        for event in request_event(stream, "/v1/messages", b"{}") {
            harness.endpoint.handle(event).unwrap();
        }
        assert_eq!(
            end(&next(&mut harness.events).await).reason,
            "redirect_denied"
        );
        let report = harness.endpoint.close(Duration::from_secs(1)).await;
        assert_eq!(report.aborted, 0);
        let (sender, mut events) = mpsc::unbounded_channel();
        harness.endpoint.attach(Arc::new(Outbound(sender)));
        harness
            .endpoint
            .handle(request_event(stream + 1, "/v1/messages", b"").remove(0))
            .unwrap();
        assert_eq!(end(&next(&mut events).await).reason, "session_closing");
    }
}
