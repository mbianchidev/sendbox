//! Spawning and supervising a single `contained-launcher` child process:
//! concurrent bounded draining of stdout/stderr, a process-group-wide
//! timeout, cooperative cancellation, and stall detection — all without
//! ever blocking the child on a slow or absent consumer.
//!
//! # Why this can never deadlock
//!
//! The child is placed in a brand-new process group
//! ([`tokio::process::Command::process_group`], `pgid == 0` meaning "equal
//! to the child's own pid"), which is what makes killing "the command and
//! everything it spawned" as a unit ([`nix::sys::signal::killpg`])
//! meaningful — this is sound only because `contained-launcher` applies the
//! [`crate::platform::SeccompProfile::Launcher`] filter to itself (and
//! therefore to every exec'd descendant), which denies `setsid`/`setpgid`,
//! so nothing under it can ever leave that process group.
//!
//! Each of stdout/stderr is drained by its own task in a tight read loop.
//! Once a stream's *retained/transmitted* byte cap
//! ([`ProcessLimits::max_stream_bytes`]) is reached, the task stops
//! constructing [`crate::protocol::ServerEvent::Stdout`]/`Stderr` events but
//! **keeps reading and discarding** from the pipe. This is the crucial
//! property that prevents deadlock: even if the client that would receive
//! those events is slow or has stopped reading entirely, this broker task
//! never blocks waiting on that client — it only ever blocks briefly on the
//! child's own pipe, which it always continues to drain. A child can
//! therefore never wedge itself against a full pipe buffer, no matter how
//! much output there is or how slowly (or never) the client consumes it.
//!
//! # Stall detection
//!
//! After the child's `wait()` resolves (the direct child has exited), it
//! is possible — if the target double-forked an orphaned grandchild that
//! inherited the write end of the stdout/stderr pipes — for the pipes to
//! never see EOF even though the process we spawned is gone. This module
//! bounds that wait with [`ProcessLimits::post_exit_drain_grace`]; if both
//! streams have not reached EOF within that grace period after the direct
//! child exits, the outcome becomes
//! [`crate::protocol::Outcome::StreamStalled`] and the whole process group
//! is killed (which reaches the orphaned grandchild too, since it cannot
//! have left the group).
//!
//! A second, distinct source of the same outcome is the *client*, not the
//! target, stalling: if the connection's writer task
//! (`crate::broker::server`) cannot deliver events within its own write
//! timeout, it signals cancellation with [`CancelReason::StreamStalled`],
//! which this module maps to the same [`crate::protocol::Outcome::StreamStalled`].
//!
//! # Bounding every event send
//!
//! Every `events.send(..)` performed by this module goes through
//! [`send_event_bounded`], which wraps the send in
//! [`ProcessLimits::event_send_timeout`]. This is not this module's
//! primary deadlock defense (dropping the receiver when the writer task
//! exits already unblocks any in-flight send immediately — see
//! `crate::broker::server`'s module docs) but a second, independent bound
//! so this task can never wait indefinitely on the event channel even if
//! the receiver is technically still alive but wedged for some other
//! reason.

#![forbid(unsafe_code)]

use crate::error::BrokerError;
use crate::pgid_registry::PgidRegistry;
use crate::protocol::{Outcome, RejectionCode, ServerEvent};
use base64::Engine as _;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// Bounds on per-stream draining behavior. Distinct from
/// [`crate::protocol::Limits`], which bounds the *request* shape.
#[derive(Debug, Clone, Copy)]
pub struct ProcessLimits {
    /// Maximum bytes of a single stream (stdout or stderr) that are ever
    /// forwarded to the client as [`ServerEvent::Stdout`]/`Stderr` events.
    /// Bytes beyond this are still read from the pipe (so the child is
    /// never blocked) but are discarded rather than transmitted.
    pub max_stream_bytes: usize,
    /// Size of each read/forward chunk.
    pub read_chunk_bytes: usize,
    /// Grace period, after the direct child has exited, to wait for both
    /// stream pipes to reach EOF before declaring
    /// [`Outcome::StreamStalled`] and killing the process group.
    pub post_exit_drain_grace: Duration,
    /// Maximum time a single `events.send(..)` may take. This is
    /// defense-in-depth alongside the connection handler's own writer
    /// timeout (see `crate::broker::server::WRITE_TIMEOUT`): if the event
    /// channel's receiver is still alive but backed up for longer than
    /// this, the send is abandoned and treated exactly like an
    /// already-detected stall, so this task can never block forever
    /// regardless of what the writer side is doing.
    pub event_send_timeout: Duration,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            max_stream_bytes: 1024 * 1024,
            read_chunk_bytes: 32 * 1024,
            post_exit_drain_grace: Duration::from_secs(2),
            event_send_timeout: Duration::from_secs(15),
        }
    }
}

/// Why an in-flight execution was asked to stop before it exited on its
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    Cancelled,
    ClientDisconnected,
    BrokerShutdown,
    /// The connection's writer task could not deliver events to the
    /// client (a write did not complete within its timeout, or hit an
    /// I/O error) — distinct from [`CancelReason::ClientDisconnected`],
    /// which is reserved for the read side observing a clean close or
    /// frame error.
    StreamStalled,
}

/// A single stream-drain event, forwarded from the reader tasks to the
/// supervising task, which translates it into a [`ServerEvent`].
enum DrainEvent {
    Stdout { data: Vec<u8>, truncated: bool },
    Stderr { data: Vec<u8>, truncated: bool },
    StdoutEof,
    StderrEof,
}

/// Spawns `command` (already configured by the caller — e.g. pointed at
/// the `exec-broker-launcher` binary with `.process_group(0)` set) and
/// drives it to completion, sending [`ServerEvent`]s tagged with
/// `correlation_id` to `events` as they occur.
///
/// `cancel` resolves when the client sends a `Cancel` for this correlation
/// id, disconnects, or the broker is shutting down; the caller wires that
/// up per in-flight execution.
///
/// If `registry` is given, the child's PGID is registered immediately
/// after a successful spawn and unregistered as part of cleanup, so the
/// supervisor can find and kill it if the broker itself dies first. See
/// [`crate::pgid_registry`] for the narrow spawn-before-registration race
/// this cannot fully close.
///
/// Returns the final [`Outcome`]. Every exit path kills the process group
/// and reaps the direct child before returning, so this function never
/// leaks a running process or a zombie.
// Each parameter is an independently-meaningful piece of per-execution
// state (not a natural grouping into one options struct given how
// differently each is produced/threaded by the caller); a single call site
// in `server.rs` constructs all of them together, so the extra parameter
// count is judged more readable here than an ad hoc bag-of-fields type.
#[allow(clippy::too_many_arguments)]
pub async fn run_to_completion(
    mut command: Command,
    correlation_id: String,
    stdin_payload: Vec<u8>,
    timeout: Duration,
    limits: ProcessLimits,
    events: mpsc::Sender<ServerEvent>,
    mut cancel: oneshot::Receiver<CancelReason>,
    registry: Option<PgidRegistry>,
) -> Result<Outcome, BrokerError> {
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            let outcome = Outcome::SpawnFailed {
                code: RejectionCode::SpawnFailed,
                message: err.to_string(),
            };
            let _ = send_event_bounded(
                &events,
                limits.event_send_timeout,
                ServerEvent::Completed {
                    correlation_id: correlation_id.clone(),
                    outcome: outcome.clone(),
                },
            )
            .await;
            return Ok(outcome);
        }
    };

    let pid = child.id().map(|raw| raw as i32).unwrap_or(0);

    // Register the PGID (equal to `pid`, since the caller sets
    // `.process_group(0)`) as early as possible. Everything between the
    // `spawn()` above and this call completing is the narrow,
    // documented race window described in `crate::pgid_registry`.
    //
    // A registration failure is treated as fatal rather than silently
    // ignored: if the supervisor's registry cannot record this PGID, the
    // supervisor cannot guarantee cleanup if the broker itself dies, so
    // this process is killed immediately rather than left running
    // untracked.
    if let Some(registry) = &registry
        && pid > 0
        && let Err(err) = registry.register(pid)
    {
        let _ = signal::killpg(Pid::from_raw(pid), Signal::SIGKILL);
        let _ = child.wait().await;
        let outcome = Outcome::SpawnFailed {
            code: RejectionCode::SpawnFailed,
            message: format!("failed to register process group with supervisor: {err}"),
        };
        let _ = send_event_bounded(
            &events,
            limits.event_send_timeout,
            ServerEvent::Completed {
                correlation_id: correlation_id.clone(),
                outcome: outcome.clone(),
            },
        )
        .await;
        return Ok(outcome);
    }

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        // Best-effort: if the launcher already exited (e.g. it failed its
        // own seccomp/rlimit setup before reading stdin) this write can
        // fail; that failure surfaces via the child's own exit status
        // instead of being treated as fatal here.
        let _ = stdin.write_all(&stdin_payload).await;
        let _ = stdin.shutdown().await;
    }

    let stdout = child
        .stdout
        .take()
        .expect("stdout was piped by this function");
    let stderr = child
        .stderr
        .take()
        .expect("stderr was piped by this function");

    let (drain_tx, mut drain_rx) = mpsc::channel::<DrainEvent>(32);
    let stdout_task = tokio::spawn(drain_stream(stdout, limits, drain_tx.clone(), true));
    let stderr_task = tokio::spawn(drain_stream(stderr, limits, drain_tx.clone(), false));
    drop(drain_tx);

    let _ = send_event_bounded(
        &events,
        limits.event_send_timeout,
        ServerEvent::Started {
            correlation_id: correlation_id.clone(),
            pid,
            pgid: pid,
        },
    )
    .await;

    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let deadline = Instant::now() + timeout;
    let mut post_exit_deadline: Option<Instant> = None;

    let outcome = loop {
        if stdout_done
            && stderr_done
            && let Some(status) = exit_status
        {
            break Outcome::Exited {
                exit_code: status.code(),
                signal: status.signal(),
            };
        }

        tokio::select! {
            biased;

            reason = &mut cancel => {
                match reason {
                    Ok(CancelReason::Cancelled) => break Outcome::Cancelled,
                    Ok(CancelReason::ClientDisconnected) => break Outcome::ClientDisconnected,
                    Ok(CancelReason::BrokerShutdown) => break Outcome::BrokerShutdown,
                    // The connection's writer task could not deliver
                    // events to the client at all; there is no point
                    // continuing to drain/forward output nobody can
                    // receive, so this maps to the same outcome as the
                    // orphaned-grandchild drain timeout above — from the
                    // client's perspective both mean "the output stream
                    // stalled and the process group was killed".
                    Ok(CancelReason::StreamStalled) => break Outcome::StreamStalled,
                    Err(_) => { /* sender dropped without firing: no cancellation requested */ }
                }
            }

            () = tokio::time::sleep_until(deadline), if exit_status.is_none() => {
                break Outcome::TimedOut;
            }

            () = sleep_until_option(post_exit_deadline), if post_exit_deadline.is_some() => {
                break Outcome::StreamStalled;
            }

            wait_result = child.wait(), if exit_status.is_none() => {
                match wait_result {
                    Ok(status) => {
                        if stdout_done && stderr_done {
                            break Outcome::Exited { exit_code: status.code(), signal: status.signal() };
                        }
                        exit_status = Some(status);
                        post_exit_deadline = Some(Instant::now() + limits.post_exit_drain_grace);
                    }
                    Err(err) => {
                        break Outcome::SpawnFailed {
                            code: RejectionCode::SpawnFailed,
                            message: format!("wait() failed: {err}"),
                        };
                    }
                }
            }

            drain_event = drain_rx.recv() => {
                match drain_event {
                    Some(DrainEvent::Stdout { data, truncated }) => {
                        let _ = send_event_bounded(&events, limits.event_send_timeout, ServerEvent::Stdout {
                            correlation_id: correlation_id.clone(),
                            data: base64::engine::general_purpose::STANDARD.encode(data),
                            truncated,
                        }).await;
                    }
                    Some(DrainEvent::Stderr { data, truncated }) => {
                        let _ = send_event_bounded(&events, limits.event_send_timeout, ServerEvent::Stderr {
                            correlation_id: correlation_id.clone(),
                            data: base64::engine::general_purpose::STANDARD.encode(data),
                            truncated,
                        }).await;
                    }
                    Some(DrainEvent::StdoutEof) => stdout_done = true,
                    Some(DrainEvent::StderrEof) => stderr_done = true,
                    None => {
                        // Both reader tasks finished (channel closed).
                        stdout_done = true;
                        stderr_done = true;
                    }
                }
            }
        }
    };

    // Every exit path funnels through here: kill the whole process group
    // (idempotent if the child already exited on its own) and reap it, so
    // this function never leaves a running process or zombie behind.
    if pid > 0 {
        let _ = signal::killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    let _ = child.wait().await;
    stdout_task.abort();
    stderr_task.abort();

    if let Some(registry) = &registry
        && pid > 0
        && let Err(err) = registry.unregister(pid)
    {
        // The process itself is already dead/reaped at this point; an
        // unregister failure here means the registry file may still
        // reference a stale PGID until the supervisor's own liveness
        // check prunes it. Not fatal to this execution's outcome, but
        // must not be silently swallowed.
        eprintln!("exec-broker: warning: failed to unregister pgid {pid}: {err}");
    }

    let _ = send_event_bounded(
        &events,
        limits.event_send_timeout,
        ServerEvent::Completed {
            correlation_id,
            outcome: outcome.clone(),
        },
    )
    .await;

    Ok(outcome)
}

/// Sends a single event with a bounded timeout, so a producer can never
/// block forever even if the connection's writer task is alive but stuck
/// (e.g. transiently, between a stall being detected and the connection
/// handler tearing everything down). This is defense-in-depth alongside
/// the writer task's own [`crate::broker::server`] write timeout and the
/// fact that dropping the receiver unblocks any in-flight send
/// immediately; a bounded send here additionally protects against the
/// receiver being alive-but-not-progressing for any other reason.
async fn send_event_bounded(
    events: &mpsc::Sender<ServerEvent>,
    timeout: Duration,
    event: ServerEvent,
) -> Result<(), ()> {
    match tokio::time::timeout(timeout, events.send(event)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(()),
    }
}

async fn sleep_until_option(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

async fn drain_stream(
    mut stream: impl AsyncRead + Unpin,
    limits: ProcessLimits,
    tx: mpsc::Sender<DrainEvent>,
    is_stdout: bool,
) {
    let mut sent_total = 0usize;
    let mut buf = vec![0u8; limits.read_chunk_bytes];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => {
                // A read error is treated the same as EOF: stop forwarding
                // and let the supervising task's timeout/wait paths decide
                // the final outcome.
                let _ = tx
                    .send(if is_stdout {
                        DrainEvent::StdoutEof
                    } else {
                        DrainEvent::StderrEof
                    })
                    .await;
                return;
            }
            Ok(n) => {
                if sent_total >= limits.max_stream_bytes {
                    // Already over cap: keep draining (so the child never
                    // blocks on a full pipe) but discard the bytes.
                    continue;
                }
                let remaining = limits.max_stream_bytes - sent_total;
                let take = remaining.min(n);
                let truncated = take < n || sent_total + take >= limits.max_stream_bytes;
                sent_total += take;
                let event = if is_stdout {
                    DrainEvent::Stdout {
                        data: buf[..take].to_vec(),
                        truncated,
                    }
                } else {
                    DrainEvent::Stderr {
                        data: buf[..take].to_vec(),
                        truncated,
                    }
                };
                // If the receiver is gone, keep looping (still draining
                // silently) until EOF; never blocks the child either way.
                let _ = tx.send(event).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn test_command(program: &str, args: &[&str]) -> Command {
        let mut command = Command::new(program);
        command.args(args);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.process_group(0);
        command
    }

    #[tokio::test]
    async fn simple_command_exits_with_captured_stdout() {
        let command = test_command("/bin/echo", &["hello"]);
        let (tx, mut rx) = mpsc::channel(32);
        let (_cancel_tx, cancel_rx) = oneshot::channel();

        let outcome = run_to_completion(
            command,
            "corr-1".into(),
            Vec::new(),
            Duration::from_secs(5),
            ProcessLimits::default(),
            tx,
            cancel_rx,
            None,
        )
        .await
        .expect("run_to_completion");

        assert_eq!(
            outcome,
            Outcome::Exited {
                exit_code: Some(0),
                signal: None
            }
        );

        let mut saw_started = false;
        let mut stdout_data = Vec::new();
        while let Some(event) = rx.recv().await {
            match event {
                ServerEvent::Started { .. } => saw_started = true,
                ServerEvent::Stdout { data, .. } => {
                    stdout_data.extend(
                        base64::engine::general_purpose::STANDARD
                            .decode(data)
                            .unwrap(),
                    );
                }
                ServerEvent::Completed { .. } => break,
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert!(saw_started);
        assert_eq!(stdout_data, b"hello\n");
    }

    #[tokio::test]
    async fn timeout_kills_process_group() {
        let command = test_command("/bin/sleep", &["30"]);
        let (tx, mut rx) = mpsc::channel(32);
        let (_cancel_tx, cancel_rx) = oneshot::channel();

        let outcome = run_to_completion(
            command,
            "corr-1".into(),
            Vec::new(),
            Duration::from_millis(200),
            ProcessLimits::default(),
            tx,
            cancel_rx,
            None,
        )
        .await
        .expect("run_to_completion");

        assert_eq!(outcome, Outcome::TimedOut);
        while let Some(event) = rx.recv().await {
            if let ServerEvent::Completed { outcome, .. } = event {
                assert_eq!(outcome, Outcome::TimedOut);
                break;
            }
        }
    }

    #[tokio::test]
    async fn cancel_stops_a_long_running_command() {
        let command = test_command("/bin/sleep", &["30"]);
        let (tx, mut rx) = mpsc::channel(32);
        let (cancel_tx, cancel_rx) = oneshot::channel();

        let handle = tokio::spawn(run_to_completion(
            command,
            "corr-1".into(),
            Vec::new(),
            Duration::from_secs(30),
            ProcessLimits::default(),
            tx,
            cancel_rx,
            None,
        ));

        // Give the process a moment to actually start before cancelling.
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel_tx
            .send(CancelReason::Cancelled)
            .expect("send cancel");

        let outcome = handle.await.expect("join").expect("run_to_completion");
        assert_eq!(outcome, Outcome::Cancelled);
        while let Some(event) = rx.recv().await {
            if let ServerEvent::Completed { outcome, .. } = event {
                assert_eq!(outcome, Outcome::Cancelled);
                break;
            }
        }
    }

    #[tokio::test]
    async fn stream_output_beyond_cap_is_truncated_but_never_blocks() {
        // `yes` writes forever, fast; a small cap plus overall timeout
        // proves the reader keeps draining (never blocking the child)
        // even once the cap has been reached, and that the process group
        // is still torn down cleanly afterward.
        let command = test_command("/usr/bin/yes", &[]);
        let (tx, mut rx) = mpsc::channel(32);
        let (_cancel_tx, cancel_rx) = oneshot::channel();
        let limits = ProcessLimits {
            max_stream_bytes: 64,
            read_chunk_bytes: 4096,
            post_exit_drain_grace: Duration::from_millis(200),
            ..ProcessLimits::default()
        };

        let outcome = run_to_completion(
            command,
            "corr-1".into(),
            Vec::new(),
            Duration::from_millis(300),
            limits,
            tx,
            cancel_rx,
            None,
        )
        .await
        .expect("run_to_completion");

        assert_eq!(outcome, Outcome::TimedOut);
        let mut saw_truncated = false;
        while let Some(event) = rx.recv().await {
            if let ServerEvent::Stdout {
                truncated: true, ..
            } = event
            {
                saw_truncated = true;
            }
            if matches!(event, ServerEvent::Completed { .. }) {
                break;
            }
        }
        assert!(
            saw_truncated,
            "expected at least one truncated stdout chunk"
        );
    }
}
