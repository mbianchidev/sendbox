//! Guest side of the brokered credential relay.
//!
//! The trusted supervisor listens on a loopback port that the agent cgroup is
//! admitted to. Each HTTP request to `/<service>/<upstream path>` becomes one
//! relay stream over the authenticated control channel. The host broker adds
//! the provider credential; nothing in this module ever sees it. Responses are
//! written to the agent with chunked framing as they arrive, and every body
//! chunk written returns one credit to the host.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sendbox_bootstrap::CredentialRelayBootstrap;
use sendbox_credentials::BrokerLimits;
use sendbox_credentials::http1::{ParsedRequest, read_request, strip_hop_by_hop};
use sendbox_protocol::relay::{
    CREDENTIAL_RELAY_CHUNK_BYTES, CREDENTIAL_RELAY_SCHEMA_VERSION, CREDENTIAL_RELAY_STREAM_BASE,
    CREDENTIAL_RELAY_WINDOW_CHUNKS, CredentialRelayCreditV1, CredentialRelayEndV1,
    CredentialRelayHeaderV1, CredentialRelayOutcomeV1, CredentialRelayRequestV1,
    CredentialRelayResponseHeadV1,
};
use sendbox_protocol::{Event, EventKind};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};

use crate::GuestError;

const OUTBOUND_DEPTH: usize = 64;
const STREAM_DEPTH: usize = CREDENTIAL_RELAY_WINDOW_CHUNKS as usize + 4;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);
const END_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Credentials a workload might attach itself. They are dropped here and the
/// host additionally forwards only a provider allowlist.
const DROPPED_REQUEST_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "cookie",
    "forwarded",
    "x-forwarded-for",
];

pub(crate) struct CredentialRelay {
    port: u16,
    services: BTreeSet<String>,
    max_request_bytes: usize,
    outbound: mpsc::Sender<Event>,
    outbound_receiver: tokio::sync::Mutex<mpsc::Receiver<Event>>,
    streams: Mutex<HashMap<u64, mpsc::Sender<Event>>>,
    next_stream: AtomicU64,
    connections: Arc<Semaphore>,
}

impl CredentialRelay {
    /// Binds the loopback listener before readiness so a failed bind fails the
    /// session instead of silently leaving agents without a credential path.
    pub(crate) async fn bind(
        configuration: &CredentialRelayBootstrap,
    ) -> Result<(Arc<Self>, TcpListener), GuestError> {
        configuration
            .validate()
            .map_err(|error| GuestError::Bootstrap(error.to_string()))?;
        let listener = TcpListener::bind(("127.0.0.1", configuration.port))
            .await
            .map_err(|error| GuestError::io("binding credential relay listener", error))?;
        let max_request_bytes = usize::try_from(configuration.max_request_bytes).map_err(|_| {
            GuestError::Bootstrap("credential relay request limit is out of range".to_owned())
        })?;
        let streams = usize::try_from(configuration.max_streams).map_err(|_| {
            GuestError::Bootstrap("credential relay stream limit is out of range".to_owned())
        })?;
        let (outbound, outbound_receiver) = mpsc::channel(OUTBOUND_DEPTH);
        Ok((
            Arc::new(Self {
                port: configuration.port,
                services: configuration.services.iter().cloned().collect(),
                max_request_bytes,
                outbound,
                outbound_receiver: tokio::sync::Mutex::new(outbound_receiver),
                streams: Mutex::new(HashMap::new()),
                next_stream: AtomicU64::new(CREDENTIAL_RELAY_STREAM_BASE),
                connections: Arc::new(Semaphore::new(streams)),
            }),
            listener,
        ))
    }

    pub(crate) fn serve(self: &Arc<Self>, listener: TcpListener) -> tokio::task::JoinHandle<()> {
        let relay = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let relay = Arc::clone(&relay);
                tokio::spawn(async move { relay.connection(stream).await });
            }
        })
    }

    /// Next guest-to-host relay event for the execution loop to forward.
    pub(crate) async fn next_outbound(&self) -> Option<Event> {
        self.outbound_receiver.lock().await.recv().await
    }

    /// Routes one host-to-guest relay event to its connection. Events for a
    /// finished stream are discarded; a host that exceeds the credit window
    /// ends that stream.
    pub(crate) fn deliver(&self, event: Event) -> Result<(), String> {
        if !matches!(
            event.kind,
            EventKind::CredentialRelayResponseHead
                | EventKind::CredentialRelayResponseBody
                | EventKind::CredentialRelayEnd
        ) {
            return Err("host sent a guest-only credential relay event".to_owned());
        }
        let stream_id = event.stream_id;
        let ended = event.kind == EventKind::CredentialRelayEnd;
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(sender) = streams.get(&stream_id) else {
            return Ok(());
        };
        if sender.try_send(event).is_err() || ended {
            streams.remove(&stream_id);
        }
        Ok(())
    }

    /// Ends every open stream, for example when the workload terminated.
    pub(crate) fn abort_all(&self) {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    async fn connection(self: Arc<Self>, mut stream: TcpStream) {
        let Ok(_permit) = Arc::clone(&self.connections).try_acquire_owned() else {
            let _ = write_error(&mut stream, 503, "too_many_streams").await;
            return;
        };
        let limits = BrokerLimits {
            request_read_timeout: REQUEST_READ_TIMEOUT,
            ..BrokerLimits::default()
        };
        let cancellation = sendbox_runtime::CancellationToken::new();
        let parsed =
            match read_request(&mut stream, &limits, self.max_request_bytes, &cancellation).await {
                Ok(parsed) => parsed,
                Err(_) => {
                    let _ = write_error(&mut stream, 400, "invalid_request").await;
                    return;
                }
            };
        let request = match self.relay_request(&parsed) {
            Ok(request) => request,
            Err((status, reason)) => {
                let _ = write_error(&mut stream, status, reason).await;
                return;
            }
        };
        let stream_id = self.next_stream.fetch_add(1, Ordering::SeqCst);
        let (sender, mut frames) = mpsc::channel(STREAM_DEPTH);
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(stream_id, sender);
        let opened = self
            .send_request(stream_id, &request, &parsed.body)
            .await
            .is_ok();
        if opened {
            let reason = match self.respond(stream_id, &mut stream, &mut frames).await {
                Delivery::Complete | Delivery::HostEnded => None,
                Delivery::ClientGone => Some("client_disconnected"),
                Delivery::Abandoned => Some("relay_abandoned"),
            };
            if let Some(reason) = reason {
                // The host keeps the stream and its upstream connection open
                // until it learns the guest stopped reading.
                let _ = tokio::time::timeout(
                    END_SEND_TIMEOUT,
                    self.outbound.send(end_event(
                        stream_id,
                        CredentialRelayOutcomeV1::Aborted,
                        reason,
                    )),
                )
                .await;
            }
        } else {
            let _ = write_error(&mut stream, 502, "relay_unavailable").await;
        }
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&stream_id);
    }

    fn relay_request(
        &self,
        parsed: &ParsedRequest,
    ) -> Result<CredentialRelayRequestV1, (u16, &'static str)> {
        let host = parsed
            .headers
            .iter()
            .find(|(name, _)| name == http::header::HOST)
            .and_then(|(_, value)| value.to_str().ok())
            .ok_or((400, "invalid_host"))?;
        let loopback = [
            format!("127.0.0.1:{}", self.port),
            format!("localhost:{}", self.port),
        ];
        if !loopback
            .iter()
            .any(|expected| host.eq_ignore_ascii_case(expected))
        {
            return Err((400, "invalid_host"));
        }
        let target = parsed
            .target
            .strip_prefix('/')
            .ok_or((400, "invalid_request"))?;
        let split = target.find(['/', '?']).unwrap_or(target.len());
        let (service, remainder) = target.split_at(split);
        if !self.services.contains(service) {
            return Err((404, "service_not_configured"));
        }
        let path = if remainder.starts_with('/') {
            remainder.to_owned()
        } else {
            format!("/{remainder}")
        };
        let headers = strip_hop_by_hop(&parsed.headers)
            .into_iter()
            .filter(|(name, _)| !DROPPED_REQUEST_HEADERS.contains(&name.as_str()))
            .filter_map(|(name, value)| {
                value.to_str().ok().map(|value| CredentialRelayHeaderV1 {
                    name: name.as_str().to_owned(),
                    value: value.to_owned(),
                })
            })
            .collect();
        let request = CredentialRelayRequestV1 {
            schema_version: CREDENTIAL_RELAY_SCHEMA_VERSION,
            service: service.to_owned(),
            method: parsed.method.as_str().to_owned(),
            path,
            headers,
            body_bytes: parsed.body.len() as u64,
        };
        request.validate().map_err(|_| (400, "invalid_request"))?;
        Ok(request)
    }

    async fn send_request(
        &self,
        stream_id: u64,
        request: &CredentialRelayRequestV1,
        body: &[u8],
    ) -> Result<(), ()> {
        let payload = serde_json::to_vec(request).map_err(|_| ())?;
        self.outbound
            .send(Event {
                stream_id,
                kind: EventKind::CredentialRelayRequest,
                payload,
            })
            .await
            .map_err(|_| ())?;
        for chunk in body.chunks(CREDENTIAL_RELAY_CHUNK_BYTES) {
            self.outbound
                .send(Event {
                    stream_id,
                    kind: EventKind::CredentialRelayRequestBody,
                    payload: chunk.to_vec(),
                })
                .await
                .map_err(|_| ())?;
        }
        Ok(())
    }

    async fn respond(
        &self,
        stream_id: u64,
        client: &mut (impl AsyncWrite + Unpin),
        frames: &mut mpsc::Receiver<Event>,
    ) -> Delivery {
        let mut head_sent = false;
        while let Some(event) = frames.recv().await {
            match event.kind {
                EventKind::CredentialRelayResponseHead if !head_sent => {
                    let Ok(head) =
                        serde_json::from_slice::<CredentialRelayResponseHeadV1>(&event.payload)
                    else {
                        return Delivery::Abandoned;
                    };
                    if head.validate().is_err() {
                        let _ = write_error(client, 502, "invalid_upstream_response").await;
                        return Delivery::Abandoned;
                    }
                    if write_head(client, &head).await.is_err() {
                        return Delivery::ClientGone;
                    }
                    head_sent = true;
                }
                EventKind::CredentialRelayResponseBody if head_sent => {
                    if write_chunk(client, &event.payload).await.is_err() {
                        return Delivery::ClientGone;
                    }
                    let credit = CredentialRelayCreditV1::new(1)
                        .ok()
                        .and_then(|credit| serde_json::to_vec(&credit).ok());
                    if let Some(payload) = credit {
                        let _ = self
                            .outbound
                            .send(Event {
                                stream_id,
                                kind: EventKind::CredentialRelayCredit,
                                payload,
                            })
                            .await;
                    }
                }
                EventKind::CredentialRelayEnd => {
                    let end = serde_json::from_slice::<CredentialRelayEndV1>(&event.payload)
                        .ok()
                        .filter(|end| end.validate().is_ok());
                    return match (end, head_sent) {
                        (Some(end), true) if end.outcome == CredentialRelayOutcomeV1::Complete => {
                            if client.write_all(b"0\r\n\r\n").await.is_err() {
                                return Delivery::ClientGone;
                            }
                            let _ = client.shutdown().await;
                            Delivery::Complete
                        }
                        (_, true) => Delivery::HostEnded,
                        (Some(end), false) => {
                            let status = match end.outcome {
                                CredentialRelayOutcomeV1::Denied => 403,
                                _ => 502,
                            };
                            let _ = write_error(client, status, &end.reason).await;
                            Delivery::HostEnded
                        }
                        (None, false) => {
                            let _ = write_error(client, 502, "invalid_relay_end").await;
                            Delivery::HostEnded
                        }
                    };
                }
                _ => return Delivery::Abandoned,
            }
        }
        if !head_sent {
            let _ = write_error(client, 502, "relay_closed").await;
        }
        Delivery::Abandoned
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// The host completed the stream.
    Complete,
    /// The host ended the stream with a failure.
    HostEnded,
    /// The agent closed its connection before the stream ended.
    ClientGone,
    /// The guest stopped reading a stream the host may still be serving.
    Abandoned,
}

fn end_event(stream_id: u64, outcome: CredentialRelayOutcomeV1, reason: &str) -> Event {
    Event {
        stream_id,
        kind: EventKind::CredentialRelayEnd,
        payload: serde_json::to_vec(&CredentialRelayEndV1::new(outcome, reason))
            .unwrap_or_default(),
    }
}

async fn write_head(
    client: &mut (impl AsyncWrite + Unpin),
    head: &CredentialRelayResponseHeadV1,
) -> std::io::Result<()> {
    let status = http::StatusCode::from_u16(head.status)
        .map_err(|_| std::io::Error::other("invalid status"))?;
    let mut bytes = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Upstream Response")
    )
    .into_bytes();
    for header in &head.headers {
        bytes.extend_from_slice(header.name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(header.value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"transfer-encoding: chunked\r\nconnection: close\r\n\r\n");
    client.write_all(&bytes).await?;
    client.flush().await
}

async fn write_chunk(client: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> std::io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    client
        .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
        .await?;
    client.write_all(bytes).await?;
    client.write_all(b"\r\n").await?;
    client.flush().await
}

async fn write_error(
    client: &mut (impl AsyncWrite + Unpin),
    status: u16,
    reason: &str,
) -> std::io::Result<()> {
    let status = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::BAD_GATEWAY);
    let body = serde_json::json!({
        "type": "error",
        "error": {
            "type": "sendbox_credential_relay",
            "message": format!("SendBox credential broker: {reason}"),
            "reason": reason,
        }
    })
    .to_string();
    let response = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Error"),
        body.len()
    );
    client.write_all(response.as_bytes()).await?;
    client.shutdown().await
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    async fn relay() -> (Arc<CredentialRelay>, u16, tokio::task::JoinHandle<()>) {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("probe")
            .local_addr()
            .expect("address")
            .port();
        let (relay, listener) = CredentialRelay::bind(&CredentialRelayBootstrap {
            port,
            services: vec!["anthropic".to_owned()],
            max_streams: 4,
            max_request_bytes: 1024,
        })
        .await
        .expect("bind");
        let task = relay.serve(listener);
        (relay, port, task)
    }

    async fn next(relay: &CredentialRelay) -> Event {
        tokio::time::timeout(Duration::from_secs(5), relay.next_outbound())
            .await
            .expect("outbound event")
            .expect("open channel")
    }

    async fn send(port: u16, request: &str) -> TcpStream {
        let mut client = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        client
            .write_all(request.replace("{port}", &port.to_string()).as_bytes())
            .await
            .expect("request");
        client
    }

    async fn response(mut client: TcpStream) -> String {
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut bytes))
            .await
            .expect("response")
            .expect("read");
        String::from_utf8(bytes).expect("utf8")
    }

    fn host_event(stream_id: u64, kind: EventKind, payload: Vec<u8>) -> Event {
        Event {
            stream_id,
            kind,
            payload,
        }
    }

    #[tokio::test]
    async fn requests_become_relay_streams_without_agent_credentials() {
        let (relay, port, task) = relay().await;
        let client = send(
            port,
            "POST /anthropic/v1/messages?beta=true HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\ncontent-type: application/json\r\nx-api-key: agent-key\r\nauthorization: Bearer agent\r\ncontent-length: 2\r\n\r\n{}",
        )
        .await;
        let opened = next(&relay).await;
        assert_eq!(opened.kind, EventKind::CredentialRelayRequest);
        assert!(opened.stream_id >= CREDENTIAL_RELAY_STREAM_BASE);
        let request: CredentialRelayRequestV1 = serde_json::from_slice(&opened.payload).unwrap();
        assert_eq!(request.service, "anthropic");
        assert_eq!(request.path, "/v1/messages?beta=true");
        assert_eq!(request.body_bytes, 2);
        assert!(
            request
                .headers
                .iter()
                .all(|header| !matches!(header.name.as_str(), "x-api-key" | "authorization"))
        );
        let body = next(&relay).await;
        assert_eq!(body.kind, EventKind::CredentialRelayRequestBody);
        assert_eq!(body.payload, b"{}");

        let stream = opened.stream_id;
        let head = CredentialRelayResponseHeadV1 {
            schema_version: CREDENTIAL_RELAY_SCHEMA_VERSION,
            status: 200,
            headers: vec![CredentialRelayHeaderV1 {
                name: "content-type".to_owned(),
                value: "text/event-stream".to_owned(),
            }],
        };
        relay
            .deliver(host_event(
                stream,
                EventKind::CredentialRelayResponseHead,
                serde_json::to_vec(&head).unwrap(),
            ))
            .unwrap();
        relay
            .deliver(host_event(
                stream,
                EventKind::CredentialRelayResponseBody,
                b"data: hi\n\n".to_vec(),
            ))
            .unwrap();
        let credit = next(&relay).await;
        assert_eq!(credit.kind, EventKind::CredentialRelayCredit);
        relay
            .deliver(end_event(
                stream,
                CredentialRelayOutcomeV1::Complete,
                "complete",
            ))
            .unwrap();
        let text = response(client).await;
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("content-type: text/event-stream\r\n"));
        assert!(text.contains("transfer-encoding: chunked\r\n"));
        assert!(text.ends_with("a\r\ndata: hi\n\n\r\n0\r\n\r\n"), "{text:?}");
        task.abort();
    }

    #[tokio::test]
    async fn denials_unknown_services_and_foreign_hosts_fail_locally() {
        let (relay, port, task) = relay().await;
        let client = send(
            port,
            "GET /anthropic/v1/models HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n",
        )
        .await;
        let opened = next(&relay).await;
        relay
            .deliver(end_event(
                opened.stream_id,
                CredentialRelayOutcomeV1::Denied,
                "stale_policy",
            ))
            .unwrap();
        let text = response(client).await;
        assert!(text.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{text}");
        assert!(text.contains("\"reason\":\"stale_policy\""));

        let text = response(
            send(
                port,
                "GET /openai/v1/models HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
            )
            .await,
        )
        .await;
        assert!(text.starts_with("HTTP/1.1 404"), "{text}");
        let text = response(
            send(
                port,
                "GET /anthropic/v1/models HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            )
            .await,
        )
        .await;
        assert!(text.starts_with("HTTP/1.1 400"), "{text}");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), relay.next_outbound())
                .await
                .is_err(),
            "rejected requests must not reach the host"
        );

        let client = send(
            port,
            "GET /anthropic/v1/models HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
        )
        .await;
        let opened = next(&relay).await;
        relay.abort_all();
        assert!(response(client).await.starts_with("HTTP/1.1 502"));
        let abandoned = next(&relay).await;
        assert_eq!(abandoned.stream_id, opened.stream_id);
        assert_eq!(abandoned.kind, EventKind::CredentialRelayEnd);
        let abandoned: CredentialRelayEndV1 = serde_json::from_slice(&abandoned.payload).unwrap();
        assert_eq!(
            (abandoned.outcome, abandoned.reason.as_str()),
            (CredentialRelayOutcomeV1::Aborted, "relay_abandoned"),
            "the host must learn that the guest stopped reading"
        );
        assert!(
            relay
                .deliver(end_event(
                    opened.stream_id,
                    CredentialRelayOutcomeV1::Complete,
                    "complete"
                ))
                .is_ok()
        );
        assert!(
            relay
                .deliver(host_event(
                    opened.stream_id,
                    EventKind::CredentialRelayRequest,
                    Vec::new()
                ))
                .is_err()
        );
        task.abort();
    }
}
