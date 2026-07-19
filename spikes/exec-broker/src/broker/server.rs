//! The broker's accept loop and per-connection dispatch: authenticates each
//! peer via `SO_PEERCRED`, then further authenticates every `Execute`/
//! `Cancel` request against the single, broker-instance-wide
//! [`crate::session::Session`] (generated once at broker startup and
//! shared, via `Arc`, across every connection — see
//! [`crate::session::Session::generate`]) before it is ever registered
//! for correlation-id dedup or spawned. Approved `Execute` requests are
//! evaluated against the [`Policy`] and spawned as an independent,
//! cancellable execution via [`crate::broker::process::run_to_completion`].
//!
//! A single connection may have multiple executions in flight
//! concurrently (`Execute` does not block the connection from accepting a
//! `Cancel` for a different, or the same, correlation id), so all
//! [`ServerEvent`]s for a connection are funneled through one `mpsc`
//! channel into a single writer task, which is the sole owner of the
//! socket's write half.
//!
//! # Slow/non-reading clients cannot deadlock the broker
//!
//! Every socket write performed by the writer task is bounded by
//! [`WRITE_TIMEOUT`]. If a single write does not complete in time (the
//! client has stopped reading and the kernel socket buffer is full), the
//! writer task stops looping — which drops its `mpsc::Receiver` — and
//! notifies the connection handler via a one-shot "stalled" signal. The
//! handler then cancels every in-flight execution on this connection with
//! [`CancelReason::StreamStalled`] (distinct from
//! [`CancelReason::ClientDisconnected`], which covers a clean or
//! I/O-error read-side disconnect instead) and stops accepting further
//! requests on this connection. Critically, once the writer's receiver is
//! dropped, any `events.send(..).await` still in flight from a spawned
//! execution's [`run_to_completion`] task resolves immediately with an
//! error instead of blocking forever — this is what actually breaks the
//! deadlock chain (writer stuck on a write → event channel fills up →
//! `run_to_completion` blocks in `events.send` → the child's own
//! stdout/stderr drain tasks back up next), rather than any cleverness in
//! the event-producing side alone.
//!
//! [`run_to_completion`]: crate::broker::process::run_to_completion

#![forbid(unsafe_code)]

use crate::broker::framing::{read_message, write_message};
use crate::broker::process::{CancelReason, ProcessLimits, run_to_completion};
use crate::error::BrokerError;
use crate::launcher::{LauncherEnvelope, encode_envelope_for_launcher};
use crate::pgid_registry::PgidRegistry;
use crate::policy::Policy;
use crate::protocol::{ClientMessage, RejectionCode, ServerEvent};
use crate::session::Session;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, mpsc, oneshot, watch};

/// Maximum time a single socket write may take before the connection is
/// declared stalled. Chosen to comfortably exceed ordinary scheduling
/// jitter while still being short enough that a genuinely stuck client is
/// detected (and cleaned up) promptly rather than tying up broker
/// resources indefinitely.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared, immutable configuration for every connection the broker
/// accepts.
pub struct BrokerConfig {
    pub policy: Policy,
    /// Absolute path to the `exec-broker-launcher` binary the broker forks
    /// for every approved `Execute` request.
    pub launcher_binary: PathBuf,
    pub process_limits: ProcessLimits,
    /// Shared PGID registry the supervisor reads on broker death. `None`
    /// disables registration (e.g. when running the broker standalone,
    /// without a supervisor, for local testing).
    pub pgid_registry: Option<PgidRegistry>,
    /// The single session every connection authenticates every
    /// `Execute`/`Cancel` request against. Generated once at broker
    /// startup (see [`crate::session::Session::generate`]) and shared,
    /// unmodified in identity, across the lifetime of the broker
    /// instance; only its internal correlation-id-dedup set mutates.
    pub session: Arc<Session>,
}

/// Registers a spawned execution's cancellation handle so a later `Cancel`
/// message (or a connection-level shutdown/disconnect/stall) can reach
/// it.
type CancelHandles = Arc<Mutex<HashMap<String, oneshot::Sender<CancelReason>>>>;

/// Runs the accept loop until `shutdown` is signalled. Every in-flight
/// connection (and, transitively, every in-flight execution on it) is told
/// to stop with [`CancelReason::BrokerShutdown`] before this function
/// returns.
pub async fn serve(
    listener: tokio::net::UnixListener,
    expected_uid: u32,
    config: Arc<BrokerConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BrokerError> {
    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;

            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }

            accept_result = listener.accept() => {
                let (stream, _addr) = accept_result.map_err(BrokerError::Io)?;
                if crate::broker::socket::authenticate_peer(&stream, expected_uid).is_err() {
                    continue; // Unauthenticated peer: drop silently.
                }
                let config = Arc::clone(&config);
                let connection_shutdown = shutdown.clone();
                connections.spawn(handle_connection(stream, config, connection_shutdown));
            }
        }
    }

    // Stop accepting; every already-running connection observes the same
    // `shutdown` watch flip and winds down its own in-flight executions.
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_connection(
    stream: UnixStream,
    config: Arc<BrokerConfig>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (mut read_half, write_half) = stream.into_split();
    let (event_tx, mut event_rx) = mpsc::channel::<ServerEvent>(64);
    let cancel_handles: CancelHandles = Arc::new(Mutex::new(HashMap::new()));
    let (stalled_tx, mut stalled_rx) = oneshot::channel::<()>();

    let writer_task = tokio::spawn(async move {
        let mut write_half = write_half;
        let mut stalled_tx = Some(stalled_tx);
        while let Some(event) = event_rx.recv().await {
            match tokio::time::timeout(WRITE_TIMEOUT, write_message(&mut write_half, &event)).await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => {
                    // Either a hard I/O error or the write did not
                    // complete within `WRITE_TIMEOUT` (the client has
                    // stopped reading). Either way this connection's
                    // write side is unusable: stop looping (which drops
                    // `event_rx`, so any producer still awaiting
                    // `events.send(..)` unblocks immediately with an
                    // error instead of hanging) and tell the connection
                    // handler so it can cancel in-flight work with the
                    // correct, distinct reason.
                    if let Some(tx) = stalled_tx.take() {
                        let _ = tx.send(());
                    }
                    break;
                }
            }
        }
        let _ = write_half.shutdown().await;
    });

    loop {
        tokio::select! {
            biased;

            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    cancel_all(&cancel_handles, CancelReason::BrokerShutdown).await;
                    break;
                }
            }

            _ = &mut stalled_rx => {
                // The writer task detected a stuck/too-slow socket write
                // and has already stopped consuming events. Every
                // in-flight execution on this connection is cancelled
                // with a reason distinct from a clean disconnect, so a
                // client observing the outcome (or a test) can tell the
                // two apart.
                cancel_all(&cancel_handles, CancelReason::StreamStalled).await;
                break;
            }

            message = read_message::<ClientMessage, _>(&mut read_half) => {
                match message {
                    Ok(Some(ClientMessage::Execute { correlation_id, session_id, token, argv, cwd, env, timeout_ms })) => {
                        handle_execute(
                            correlation_id,
                            session_id,
                            token,
                            argv,
                            cwd,
                            env,
                            timeout_ms,
                            &config,
                            &event_tx,
                            &cancel_handles,
                        )
                        .await;
                    }
                    Ok(Some(ClientMessage::Cancel { correlation_id, session_id, token })) => {
                        if !config.session.authenticate_hex(&session_id, &token) {
                            let _ = event_tx
                                .send(ServerEvent::Rejected {
                                    correlation_id,
                                    code: RejectionCode::SessionUnauthorized,
                                    message: "session authentication failed".to_string(),
                                })
                                .await;
                        } else if let Some(handle) =
                            cancel_handles.lock().await.remove(&correlation_id)
                        {
                            let _ = handle.send(CancelReason::Cancelled);
                        } else {
                            // No in-flight execution under this
                            // correlation id on this connection — either
                            // it never existed, or it already completed
                            // (its entry is removed on completion; see
                            // the cleanup in `handle_execute`). Both are
                            // reported explicitly rather than silently
                            // doing nothing, so a caller cancelling a
                            // typo'd or already-finished correlation id
                            // gets an observable answer instead of
                            // guessing from silence.
                            let _ = event_tx
                                .send(ServerEvent::Rejected {
                                    correlation_id,
                                    code: RejectionCode::UnknownCorrelationId,
                                    message: "no in-flight execution for this correlation id \
                                              (never existed, or already completed)"
                                        .to_string(),
                                })
                                .await;
                        }
                    }
                    Ok(None) => {
                        // Clean disconnect at a message boundary.
                        cancel_all(&cancel_handles, CancelReason::ClientDisconnected).await;
                        break;
                    }
                    Err(_) => {
                        // Malformed/oversized frame or I/O error: treat the
                        // same as a disconnect for any in-flight work.
                        cancel_all(&cancel_handles, CancelReason::ClientDisconnected).await;
                        break;
                    }
                }
            }
        }
    }

    drop(event_tx);
    let _ = writer_task.await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_execute(
    correlation_id: String,
    session_id: String,
    token: String,
    argv: Vec<String>,
    cwd: String,
    env: std::collections::BTreeMap<String, String>,
    timeout_ms: u64,
    config: &Arc<BrokerConfig>,
    event_tx: &mpsc::Sender<ServerEvent>,
    cancel_handles: &CancelHandles,
) {
    // Authenticate *before* touching the correlation-id registry or
    // spawning anything: an unauthenticated request must have zero
    // observable side effects beyond the rejection itself.
    if !config.session.authenticate_hex(&session_id, &token) {
        let _ = event_tx
            .send(ServerEvent::Rejected {
                correlation_id,
                code: RejectionCode::SessionUnauthorized,
                message: "session authentication failed".to_string(),
            })
            .await;
        return;
    }

    // The session's correlation-id registry is shared, via `Arc`, across
    // every connection for the lifetime of the broker instance, so a
    // duplicate is detected regardless of which connection used it first.
    if !config.session.register_correlation_id(&correlation_id) {
        let _ = event_tx
            .send(ServerEvent::Rejected {
                correlation_id,
                code: RejectionCode::DuplicateCorrelationId,
                message: "correlation id already used on this session".to_string(),
            })
            .await;
        return;
    }

    let timeout = Duration::from_millis(timeout_ms);
    let validated = match config
        .policy
        .evaluate(&correlation_id, &argv, &cwd, &env, timeout)
    {
        Ok(validated) => validated,
        Err(code) => {
            let _ = event_tx
                .send(ServerEvent::Rejected {
                    correlation_id,
                    code,
                    message: format!("request denied by policy: {code:?}"),
                })
                .await;
            return;
        }
    };

    // The policy snapshot handed to the launcher is derived solely from
    // the broker's own trusted, already-canonicalized `Policy` — never
    // from anything the client supplied — so the launcher can
    // independently reconstruct and re-validate against the exact same
    // policy without trusting its own (nonexistent) CLI arguments.
    let envelope = LauncherEnvelope {
        validated,
        policy_snapshot: config.policy.snapshot(),
    };
    let stdin_payload = match encode_envelope_for_launcher(&envelope) {
        Ok(bytes) => bytes,
        Err(_) => {
            let _ = event_tx
                .send(ServerEvent::Rejected {
                    correlation_id,
                    code: RejectionCode::MalformedMessage,
                    message: "failed to encode launcher envelope".to_string(),
                })
                .await;
            return;
        }
    };

    // The envelope is the launcher's *only* input besides its inherited
    // stdio: no CLI arguments are passed, so there is no policy
    // configuration for a compromised or buggy launcher invocation to
    // disagree with the broker about. `run_to_completion` pipes
    // stdin/stdout/stderr for this command.
    let mut command = tokio::process::Command::new(&config.launcher_binary);
    command.process_group(0);

    let (cancel_tx, cancel_rx) = oneshot::channel();
    cancel_handles
        .lock()
        .await
        .insert(correlation_id.clone(), cancel_tx);

    let process_limits = config.process_limits;
    let events = event_tx.clone();
    let cancel_handles = Arc::clone(cancel_handles);
    let corr_for_cleanup = correlation_id.clone();
    let registry = config.pgid_registry.clone();
    tokio::spawn(async move {
        let _ = run_to_completion(
            command,
            correlation_id,
            stdin_payload,
            timeout,
            process_limits,
            events,
            cancel_rx,
            registry,
        )
        .await;
        cancel_handles.lock().await.remove(&corr_for_cleanup);
    });
}

async fn cancel_all(cancel_handles: &CancelHandles, reason: CancelReason) {
    let mut handles = cancel_handles.lock().await;
    for (_, handle) in handles.drain() {
        let _ = handle.send(reason);
    }
}
