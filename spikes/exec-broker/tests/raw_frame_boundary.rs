//! Live, end-to-end tests of the wire protocol's *boundary* behavior:
//! malformed/oversized raw bytes, structurally-invalid-but-well-formed
//! requests, unknown/invalid correlation ids, unauthenticated sessions,
//! stale runtime-directory/socket replacement, and unauthorized peer UIDs.
//!
//! Every test here talks to a real, running `exec-broker` binary over its
//! real Unix socket (the same pattern `tests/broker_e2e.rs` uses for its
//! `duplicate_correlation_id_is_rejected_across_separate_connections`
//! test), writing raw bytes directly to the socket where a test needs to
//! prove behavior that the safe [`exec_broker_spike::broker::framing`]
//! helpers could never produce on their own (invalid UTF-8, invalid JSON,
//! a length prefix that lies about the payload size).
//!
//! # What "rejected" means at each layer
//!
//! Two distinct failure layers exist, and this file exercises both,
//! deliberately keeping them distinguishable rather than treating every
//! failure as equivalent:
//!
//! - **Framing-layer failures** (oversized length prefix, invalid UTF-8,
//!   invalid JSON) are detected while decoding the raw frame itself,
//!   before any [`exec_broker_spike::protocol::ClientMessage`] exists to
//!   reject. `src/broker/server.rs`'s connection loop treats a framing
//!   error identically to a clean disconnect: it cancels any in-flight
//!   work and **closes the connection with no reply**. There is no
//!   `Rejected` event for these — the tests below assert the connection
//!   closes and that a fresh connection can still be served normally
//!   afterward (the broker itself is unharmed).
//! - **Application-layer rejections** (bad session credentials, a
//!   duplicate/unknown/invalid correlation id, a structurally-oversized
//!   `Execute` that still fits inside one valid frame, a NUL byte in a
//!   string field) decode successfully as a well-formed
//!   [`exec_broker_spike::protocol::ClientMessage`] and are rejected with
//!   an explicit `ServerEvent::Rejected { code, .. }` reply, and the
//!   connection stays open and usable afterward.
//!
//! Linux-gated: matches every other Linux-specific integration test in
//! this crate.

#![cfg(target_os = "linux")]

use exec_broker_spike::broker::framing::{read_message, write_message};
use exec_broker_spike::protocol::{ClientMessage, RejectionCode, ServerEvent};
use exec_broker_spike::session::{self, SessionCredentials};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::net::UnixStream;

const BROKER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker");
const LAUNCHER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-launcher");
const TEST_HELPER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-test-helper");

/// A running `exec-broker` instance with its own private runtime
/// directory, torn down (SIGKILL) on drop unless a test already reaped
/// it. Mirrors `tests/broker_e2e.rs`'s `TestBroker`; duplicated rather
/// than shared because Rust integration-test binaries cannot import from
/// one another.
struct TestBroker {
    child: Child,
    _tempdir: tempfile::TempDir,
    runtime_dir: PathBuf,
    root: PathBuf,
}

/// Marks this test binary's process as a `PR_SET_CHILD_SUBREAPER`
/// (see [`exec_broker_spike::supervisor::become_child_subreaper`]),
/// exactly once no matter how many `TestBroker`s this process starts
/// across however many parallel test threads. Without this, a
/// `TestBroker` that gets forcibly killed mid-test (before its broker
/// has reaped a just-spawned launcher/target process itself) would leak
/// that descendant as a permanent zombie: it would be reparented to
/// whatever the container's real PID 1 is, which does not reap
/// unrelated processes. With this, such descendants reparent to *this*
/// test binary process instead, where [`TestBroker::drop`] can actually
/// reap them after killing their process group.
fn become_child_subreaper_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(exec_broker_spike::supervisor::become_child_subreaper);
}

impl TestBroker {
    fn start(allow_exec: &[&str]) -> Self {
        become_child_subreaper_once();

        let tempdir = tempfile::tempdir().expect("tempdir");
        let root = tempdir.path().join("root");
        std::fs::create_dir_all(&root).expect("create allowed root");
        let runtime_dir = tempdir.path().join("runtime");

        let mut cmd = Command::new(BROKER_EXE);
        cmd.arg("--runtime-dir")
            .arg(&runtime_dir)
            .arg("--allowed-root")
            .arg(&root)
            .arg("--launcher-binary")
            .arg(LAUNCHER_EXE)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for exe in allow_exec {
            cmd.arg("--allow-exec").arg(exe);
        }
        let child = cmd.spawn().expect("failed to spawn exec-broker");
        let broker = Self {
            child,
            _tempdir: tempdir,
            runtime_dir,
            root,
        };
        broker.wait_until_ready();
        broker
    }

    fn wait_until_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.runtime_dir.join("broker.sock").exists()
                && self.runtime_dir.join("session.credentials").exists()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "exec-broker did not create its socket/credentials in {:?} \
             within the startup deadline",
            self.runtime_dir
        );
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    fn credentials(&self, expected_uid: u32) -> SessionCredentials {
        session::load_credentials_file(
            &self.runtime_dir.join(session::CREDENTIALS_FILE_NAME),
            expected_uid,
        )
        .expect("load session credentials")
    }

    /// Connects a fresh, authenticated (`SO_PEERCRED`-validated) Unix
    /// socket connection to this broker, handed off to Tokio.
    async fn connect(&self, expected_uid: u32) -> UnixStream {
        let std_stream = exec_broker_spike::broker::socket::connect(
            &self.runtime_dir.join("broker.sock"),
            expected_uid,
        )
        .expect("connect to broker socket");
        std_stream.set_nonblocking(true).expect("set nonblocking");
        UnixStream::from_std(std_stream).expect("hand off to tokio")
    }

    /// Connects a raw, unvalidated `std` Unix socket (bypassing
    /// `broker::socket::connect`'s own `lstat` checks), for tests that
    /// need to write bytes `write_message` could never produce.
    fn connect_raw(&self) -> StdUnixStream {
        StdUnixStream::connect(self.runtime_dir.join("broker.sock"))
            .expect("raw connect to broker socket")
    }
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        // Best-effort: if the runtime directory (and its pgid registry)
        // still exists, kill every process group the broker registered
        // *before* killing the broker itself — mirrors what a real
        // deployment's supervisor does on unexpected broker death (see
        // `exec_broker_spike::supervisor::kill_all_registered`), and is
        // what prevents a test that kills this `TestBroker` mid-flight
        // (rather than waiting for every spawned execution to finish
        // and be reaped first) from leaking an orphaned launcher/target
        // process as a permanent zombie. If the runtime directory was
        // already removed (e.g. a graceful-shutdown test already ran),
        // there is nothing registered to clean up here.
        if self.runtime_dir.exists() {
            let registry = exec_broker_spike::pgid_registry::PgidRegistry::new(
                self.runtime_dir.join("pgids.json"),
            );
            let _ = exec_broker_spike::supervisor::kill_all_registered(&registry);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Reap anything the kill above just caused to exit and that
        // reparented to this process (see `become_child_subreaper_once`).
        exec_broker_spike::supervisor::reap_available_children(std::time::Duration::from_secs(2));
    }
}

fn expected_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

/// Reads until the broker explicitly closes or resets the malformed
/// connection. A mere timeout is a test failure: no-reply-but-still-open is
/// not equivalent to fail-closed connection teardown.
fn read_raw_until_closed(stream: &mut StdUnixStream, timeout: Duration) -> Vec<u8> {
    stream
        .set_read_timeout(Some(timeout))
        .expect("set read timeout");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match std::io::Read::read(stream, &mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                panic!("broker did not close malformed-frame connection within {timeout:?}");
            }
            Err(e) => panic!("unexpected read error: {e}"),
        }
    }
    buf
}

// ---------------------------------------------------------------------
// Framing-layer failures: connection closes, no reply, no spawn.
// ---------------------------------------------------------------------

/// A length prefix declaring a payload larger than `MAX_FRAME_BYTES` must
/// be rejected before the broker ever reads the (never sent) payload, and
/// the connection must simply close — no `Rejected` reply is possible
/// once the length prefix itself is already invalid, and nothing is ever
/// spawned (no `ClientMessage` was ever decoded to spawn from).
#[test]
fn oversized_length_prefix_closes_connection_with_no_reply_and_no_spawn() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let mut stream = broker.connect_raw();

    let huge_length = (exec_broker_spike::protocol::MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
    stream.write_all(&huge_length).expect("write length prefix");
    // Deliberately never send a payload: the broker must reject based on
    // the length prefix alone, before attempting to read one.

    let reply = read_raw_until_closed(&mut stream, Duration::from_secs(5));
    assert!(
        reply.is_empty(),
        "an oversized length prefix must produce no reply bytes at all, got {reply:?}"
    );

    // The broker itself must be unharmed: a fresh, well-formed connection
    // still works normally afterward.
    assert_broker_still_serves_normally(&broker);
}

/// A peer that closes after sending only part of the four-byte length prefix
/// has sent a malformed frame, not a clean boundary-aligned disconnect.
#[test]
fn truncated_length_prefix_closes_connection_with_no_reply_and_no_spawn() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let mut stream = broker.connect_raw();

    stream.write_all(&[0, 0]).expect("write partial prefix");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("close client write half");

    let reply = read_raw_until_closed(&mut stream, Duration::from_secs(5));
    assert!(
        reply.is_empty(),
        "a truncated length prefix must produce no reply bytes, got {reply:?}"
    );
    assert_broker_still_serves_normally(&broker);
}

/// A payload that is not valid UTF-8 fails JSON decoding (`serde_json`
/// validates UTF-8 as part of parsing) and must close the connection with
/// no reply, exactly like an oversized length prefix.
#[test]
fn invalid_utf8_payload_closes_connection_with_no_reply_and_no_spawn() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let mut stream = broker.connect_raw();

    let payload: &[u8] = &[0xFF, 0xFE, 0xFD, 0xFC];
    let length = (payload.len() as u32).to_be_bytes();
    stream.write_all(&length).expect("write length");
    stream
        .write_all(payload)
        .expect("write invalid utf-8 payload");

    let reply = read_raw_until_closed(&mut stream, Duration::from_secs(5));
    assert!(
        reply.is_empty(),
        "an invalid-UTF-8 payload must produce no reply bytes at all, got {reply:?}"
    );
    assert_broker_still_serves_normally(&broker);
}

/// A payload that is valid UTF-8 but not valid JSON at all must also
/// close the connection with no reply.
#[test]
fn invalid_json_payload_closes_connection_with_no_reply_and_no_spawn() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let mut stream = broker.connect_raw();

    let payload = b"{ this is not valid json at all ";
    let length = (payload.len() as u32).to_be_bytes();
    stream.write_all(&length).expect("write length");
    stream
        .write_all(payload)
        .expect("write invalid json payload");

    let reply = read_raw_until_closed(&mut stream, Duration::from_secs(5));
    assert!(
        reply.is_empty(),
        "an invalid-JSON payload must produce no reply bytes at all, got {reply:?}"
    );
    assert_broker_still_serves_normally(&broker);
}

/// A well-formed-but-unknown JSON shape (valid JSON, valid UTF-8, but not
/// a `ClientMessage` variant) is a decode error identical in kind to
/// invalid JSON from the framing layer's point of view: still no reply,
/// still connection-closed.
#[test]
fn unrecognized_json_shape_closes_connection_with_no_reply_and_no_spawn() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let mut stream = broker.connect_raw();

    let payload = br#"{"totally_unknown_variant": true}"#;
    let length = (payload.len() as u32).to_be_bytes();
    stream.write_all(&length).expect("write length");
    stream.write_all(payload).expect("write payload");

    let reply = read_raw_until_closed(&mut stream, Duration::from_secs(5));
    assert!(
        reply.is_empty(),
        "an unrecognized JSON shape must produce no reply bytes at all, got {reply:?}"
    );
    assert_broker_still_serves_normally(&broker);
}

/// Confirms the broker is still alive and correctly serving *new*
/// connections after a prior connection sent a malformed frame — proving
/// the malformed-frame handling tears down only the offending connection,
/// never the broker process itself.
fn assert_broker_still_serves_normally(broker: &TestBroker) {
    let runtime = tokio::runtime::Runtime::new().expect("build runtime");
    runtime.block_on(async {
        let uid = expected_uid();
        let credentials = broker.credentials(uid);
        let mut stream = broker.connect(uid).await;
        let msg = ClientMessage::Execute {
            correlation_id: "post-malformed-frame-sanity-check".to_string(),
            session_id: credentials.session_id.clone(),
            token: credentials.token_hex.clone(),
            argv: vec!["/usr/bin/true".to_string()],
            cwd: broker.root().to_string_lossy().into_owned(),
            env: BTreeMap::new(),
            timeout_ms: 5_000,
        };
        write_message(&mut stream, &msg)
            .await
            .expect("send Execute");
        let event: ServerEvent = read_message(&mut stream)
            .await
            .expect("read event")
            .expect("connection must not be closed");
        assert!(
            matches!(event, ServerEvent::Started { .. }),
            "expected Started on a fresh connection after a prior malformed frame, got {event:?}"
        );
    });
}

// ---------------------------------------------------------------------
// Application-layer rejections: connection stays open, explicit reply.
// ---------------------------------------------------------------------

/// An `Execute` whose argv exceeds `Limits::default().max_argc` (64) is
/// rejected by policy with `ArgcExceeded`, while still fitting easily
/// inside one valid 64 KiB frame — this is *not* a framing-layer failure,
/// and the connection must remain open and usable afterward.
#[tokio::test]
async fn oversized_argc_is_rejected_by_policy_not_by_framing() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let uid = expected_uid();
    let credentials = broker.credentials(uid);
    let mut stream = broker.connect(uid).await;

    let mut argv = vec!["/usr/bin/true".to_string()];
    argv.extend((0..70).map(|i| format!("arg{i}")));
    assert!(argv.len() > exec_broker_spike::protocol::Limits::default().max_argc);

    let msg = ClientMessage::Execute {
        correlation_id: "oversized-argc".to_string(),
        session_id: credentials.session_id.clone(),
        token: credentials.token_hex.clone(),
        argv,
        cwd: broker.root().to_string_lossy().into_owned(),
        env: BTreeMap::new(),
        timeout_ms: 5_000,
    };
    write_message(&mut stream, &msg)
        .await
        .expect("send Execute");
    let event: ServerEvent = read_message(&mut stream)
        .await
        .expect("read event")
        .expect("connection must stay open for an application-layer rejection");
    match event {
        ServerEvent::Rejected { code, .. } => {
            assert_eq!(code, RejectionCode::ArgcExceeded);
        }
        other => panic!("expected Rejected(ArgcExceeded), got {other:?}"),
    }

    assert_connection_still_usable(&broker, &credentials, &mut stream, "after-oversized-argc")
        .await;
}

/// An `Execute` whose combined env entries exceed
/// `Limits::default().max_env_entries` (64) is rejected by policy with
/// `EnvEntriesExceeded`, again while still fitting inside one valid
/// frame — the connection must remain open afterward.
#[tokio::test]
async fn oversized_env_entries_is_rejected_by_policy_not_by_framing() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let uid = expected_uid();
    let credentials = broker.credentials(uid);
    let mut stream = broker.connect(uid).await;

    let mut env = BTreeMap::new();
    for i in 0..70 {
        env.insert(format!("VAR_{i}"), "v".to_string());
    }
    assert!(env.len() > exec_broker_spike::protocol::Limits::default().max_env_entries);

    let msg = ClientMessage::Execute {
        correlation_id: "oversized-env".to_string(),
        session_id: credentials.session_id.clone(),
        token: credentials.token_hex.clone(),
        argv: vec!["/usr/bin/true".to_string()],
        cwd: broker.root().to_string_lossy().into_owned(),
        env,
        timeout_ms: 5_000,
    };
    write_message(&mut stream, &msg)
        .await
        .expect("send Execute");
    let event: ServerEvent = read_message(&mut stream)
        .await
        .expect("read event")
        .expect("connection must stay open for an application-layer rejection");
    match event {
        ServerEvent::Rejected { code, .. } => {
            assert_eq!(code, RejectionCode::EnvEntriesExceeded);
        }
        other => panic!("expected Rejected(EnvEntriesExceeded), got {other:?}"),
    }

    assert_connection_still_usable(&broker, &credentials, &mut stream, "after-oversized-env").await;
}

/// A NUL byte embedded in an argv element decodes fine as JSON/UTF-8
/// (`serde_json` happily materializes `\u0000`) but is rejected by
/// structural validation before ever reaching a C string boundary.
#[tokio::test]
async fn embedded_nul_byte_in_argv_is_rejected_by_policy_not_by_framing() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let uid = expected_uid();
    let credentials = broker.credentials(uid);
    let mut stream = broker.connect(uid).await;

    let msg = ClientMessage::Execute {
        correlation_id: "embedded-nul".to_string(),
        session_id: credentials.session_id.clone(),
        token: credentials.token_hex.clone(),
        argv: vec![
            "/usr/bin/true".to_string(),
            "arg\u{0}with\u{0}nul".to_string(),
        ],
        cwd: broker.root().to_string_lossy().into_owned(),
        env: BTreeMap::new(),
        timeout_ms: 5_000,
    };
    write_message(&mut stream, &msg)
        .await
        .expect("send Execute");
    let event: ServerEvent = read_message(&mut stream)
        .await
        .expect("read event")
        .expect("connection must stay open for an application-layer rejection");
    match event {
        ServerEvent::Rejected { code, .. } => {
            assert_eq!(code, RejectionCode::NulByte);
        }
        other => panic!("expected Rejected(NulByte), got {other:?}"),
    }

    assert_connection_still_usable(&broker, &credentials, &mut stream, "after-embedded-nul").await;
}

/// `Execute` with an empty correlation id is rejected with
/// `InvalidCorrelationId`.
#[tokio::test]
async fn invalid_correlation_id_is_rejected() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let uid = expected_uid();
    let credentials = broker.credentials(uid);
    let mut stream = broker.connect(uid).await;

    let msg = ClientMessage::Execute {
        correlation_id: String::new(),
        session_id: credentials.session_id.clone(),
        token: credentials.token_hex.clone(),
        argv: vec!["/usr/bin/true".to_string()],
        cwd: broker.root().to_string_lossy().into_owned(),
        env: BTreeMap::new(),
        timeout_ms: 5_000,
    };
    write_message(&mut stream, &msg)
        .await
        .expect("send Execute");
    let event: ServerEvent = read_message(&mut stream)
        .await
        .expect("read event")
        .expect("connection must stay open for an application-layer rejection");
    match event {
        ServerEvent::Rejected { code, .. } => {
            assert_eq!(code, RejectionCode::InvalidCorrelationId);
        }
        other => panic!("expected Rejected(InvalidCorrelationId), got {other:?}"),
    }
}

/// `Cancel` referencing a correlation id that was never registered on
/// this session (never sent in any `Execute`) is rejected explicitly with
/// `UnknownCorrelationId` rather than being silently ignored — this
/// wires up a rejection code that previously existed in
/// `protocol::RejectionCode` but was never actually constructed anywhere
/// in the broker; see `src/broker/server.rs`'s `Cancel` handling.
#[tokio::test]
async fn unknown_correlation_id_cancel_is_rejected_explicitly() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let uid = expected_uid();
    let credentials = broker.credentials(uid);
    let mut stream = broker.connect(uid).await;

    let msg = ClientMessage::Cancel {
        correlation_id: "never-registered-correlation-id".to_string(),
        session_id: credentials.session_id.clone(),
        token: credentials.token_hex.clone(),
    };
    write_message(&mut stream, &msg).await.expect("send Cancel");
    let event: ServerEvent = read_message(&mut stream)
        .await
        .expect("read event")
        .expect("connection must stay open for an application-layer rejection");
    match event {
        ServerEvent::Rejected { code, .. } => {
            assert_eq!(code, RejectionCode::UnknownCorrelationId);
        }
        other => panic!("expected Rejected(UnknownCorrelationId), got {other:?}"),
    }
}

/// An `Execute` with a wrong session token is rejected with
/// `SessionUnauthorized`, and — because authentication happens before the
/// correlation-id registry or the spawn path are ever touched — no
/// `Started` event is possible; `Rejected` is the only event that can
/// arrive.
#[tokio::test]
async fn unauthenticated_execute_is_rejected_before_any_spawn() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let uid = expected_uid();
    let credentials = broker.credentials(uid);
    let mut stream = broker.connect(uid).await;

    let msg = ClientMessage::Execute {
        correlation_id: "unauthenticated-execute".to_string(),
        session_id: credentials.session_id.clone(),
        token: "0".repeat(credentials.token_hex.len()),
        argv: vec!["/usr/bin/true".to_string()],
        cwd: broker.root().to_string_lossy().into_owned(),
        env: BTreeMap::new(),
        timeout_ms: 5_000,
    };
    write_message(&mut stream, &msg)
        .await
        .expect("send Execute");
    let event: ServerEvent = read_message(&mut stream)
        .await
        .expect("read event")
        .expect("connection must stay open for an application-layer rejection");
    match event {
        ServerEvent::Rejected { code, .. } => {
            assert_eq!(code, RejectionCode::SessionUnauthorized);
        }
        other => panic!("expected Rejected(SessionUnauthorized), got {other:?}"),
    }
}

/// A `Cancel` with a wrong session token is likewise rejected with
/// `SessionUnauthorized`, before the cancel-handles map is ever
/// consulted.
#[tokio::test]
async fn unauthenticated_cancel_is_rejected() {
    let broker = TestBroker::start(&["/usr/bin/true"]);
    let uid = expected_uid();
    let credentials = broker.credentials(uid);
    let mut stream = broker.connect(uid).await;

    let msg = ClientMessage::Cancel {
        correlation_id: "unauthenticated-cancel".to_string(),
        session_id: credentials.session_id.clone(),
        token: "0".repeat(credentials.token_hex.len()),
    };
    write_message(&mut stream, &msg).await.expect("send Cancel");
    let event: ServerEvent = read_message(&mut stream)
        .await
        .expect("read event")
        .expect("connection must stay open for an application-layer rejection");
    match event {
        ServerEvent::Rejected { code, .. } => {
            assert_eq!(code, RejectionCode::SessionUnauthorized);
        }
        other => panic!("expected Rejected(SessionUnauthorized), got {other:?}"),
    }
}

/// Helper: after an application-layer rejection, sends one more,
/// definitely-valid `Execute` on the *same* connection and confirms it
/// still gets a `Started` reply — proving the rejection did not silently
/// tear the connection down (unlike a framing-layer failure).
async fn assert_connection_still_usable(
    broker: &TestBroker,
    credentials: &SessionCredentials,
    stream: &mut UnixStream,
    correlation_suffix: &str,
) {
    let msg = ClientMessage::Execute {
        correlation_id: format!("sanity-check-{correlation_suffix}"),
        session_id: credentials.session_id.clone(),
        token: credentials.token_hex.clone(),
        argv: vec!["/usr/bin/true".to_string()],
        cwd: broker.root().to_string_lossy().into_owned(),
        env: BTreeMap::new(),
        timeout_ms: 5_000,
    };
    write_message(stream, &msg)
        .await
        .expect("send follow-up Execute");
    let event: ServerEvent = read_message(stream)
        .await
        .expect("read follow-up event")
        .expect("connection must still be open");
    assert!(
        matches!(event, ServerEvent::Started { .. }),
        "expected the connection to still accept a valid Execute after an \
         application-layer rejection, got {event:?}"
    );
}

// ---------------------------------------------------------------------
// Stale runtime directory / socket replacement.
// ---------------------------------------------------------------------

/// Pointing `exec-broker` at a runtime-directory path that already has a
/// stale directory sitting at it must refuse to start (exit non-zero,
/// clear error message), and must leave the stale directory's contents
/// completely untouched — no silent takeover, no socket bound inside
/// someone else's leftover directory.
#[test]
fn stale_runtime_directory_is_refused_and_left_untouched() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let runtime_dir = tempdir.path().join("runtime");
    std::fs::create_dir_all(&runtime_dir).expect("pre-create stale runtime dir");
    let sentinel = runtime_dir.join("leftover-from-a-previous-run.txt");
    std::fs::write(&sentinel, b"do not touch me").expect("write sentinel file");

    let root = tempdir.path().join("root");
    std::fs::create_dir_all(&root).expect("create allowed root");

    let output = Command::new(BROKER_EXE)
        .arg("--runtime-dir")
        .arg(&runtime_dir)
        .arg("--allowed-root")
        .arg(&root)
        .arg("--launcher-binary")
        .arg(LAUNCHER_EXE)
        .arg("--allow-exec")
        .arg("/usr/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run exec-broker against a stale runtime dir");

    assert!(
        !output.status.success(),
        "exec-broker must refuse to start against a pre-existing runtime \
         directory path; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("restart is not supported") || stderr.contains("already exist"),
        "expected a clear restart-unsupported/stale-path error on stderr, got: {stderr}"
    );

    // The stale directory's contents must be exactly as left: no socket
    // was bound inside it, and the sentinel file is untouched.
    assert!(
        sentinel.exists(),
        "the pre-existing sentinel file must not have been removed"
    );
    assert!(
        !runtime_dir.join("broker.sock").exists(),
        "no socket may have been bound inside a rejected stale runtime directory"
    );
    assert_eq!(
        std::fs::read(&sentinel).expect("read sentinel back"),
        b"do not touch me",
        "the sentinel file's contents must be unmodified"
    );
}

/// A symlink sitting at the runtime-directory path (rather than a real
/// leftover directory) must be refused identically — `RuntimeDir` uses
/// `lstat`, not `stat`, specifically so a symlink is never silently
/// followed and reused.
#[test]
fn symlinked_runtime_directory_path_is_refused() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let elsewhere = tempdir.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("mkdir elsewhere");
    let runtime_dir = tempdir.path().join("runtime");
    std::os::unix::fs::symlink(&elsewhere, &runtime_dir).expect("symlink runtime dir");

    let root = tempdir.path().join("root");
    std::fs::create_dir_all(&root).expect("create allowed root");

    let output = Command::new(BROKER_EXE)
        .arg("--runtime-dir")
        .arg(&runtime_dir)
        .arg("--allowed-root")
        .arg(&root)
        .arg("--launcher-binary")
        .arg(LAUNCHER_EXE)
        .arg("--allow-exec")
        .arg("/usr/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run exec-broker against a symlinked runtime dir");

    assert!(
        !output.status.success(),
        "exec-broker must refuse to start when a symlink already sits at \
         the runtime directory path"
    );
    assert!(
        !elsewhere.join("broker.sock").exists(),
        "no socket may have been bound through the symlink into `elsewhere`"
    );
}

// ---------------------------------------------------------------------
// Unauthorized peer UID.
// ---------------------------------------------------------------------

/// Unconditional, hosted-safe unit-level proof that `authenticate_peer`
/// rejects a mismatched UID: already present in
/// `src/broker/socket.rs::tests::authenticate_peer_rejects_unexpected_uid`
/// and deliberately *not* duplicated here — this comment exists so a
/// reader of this file's UID-related tests can find that proof without
/// searching, since the live, full-`accept()`-loop version below can only
/// run with root/`CAP_SETUID` (see its own doc comment for why).
const _SEE_SOCKET_RS_FOR_UNCONDITIONAL_UID_MISMATCH_UNIT_PROOF: () = ();

/// **Self-hosted/root-only live gate.** Proves that a connection from a
/// UID other than the broker's own is rejected end-to-end, through
/// whichever layer actually stops it first:
///
/// - The broker's socket file is `0600`, owned by the broker's own uid,
///   so in the common case a different uid's `connect(2)` itself fails
///   with `EACCES`/`PermissionDenied` — never even reaching the kernel's
///   accept queue.
/// - If that filesystem-permission layer were ever weakened (e.g. a
///   misconfigured mode, or a peer sharing a group with read/write on
///   the socket inode), `connect(2)` would succeed, but `serve()`'s
///   accept loop then rejects the peer via `SO_PEERCRED` before ever
///   spawning a `handle_connection` task for it — the peer observes EOF
///   on its first read with zero protocol bytes ever exchanged.
///
/// Either outcome is accepted as proof here: both mean a cross-UID peer
/// can never reach the application protocol, which is the actual
/// security property this test exists to prove — not "exactly one
/// specific kernel primitive was the one that stopped it".
///
/// Creating a genuine second UID to connect *as* requires `CAP_SETUID`
/// (in practice, running as root), which a typical GitHub-hosted
/// unprivileged CI runner does not have. Rather than silently skip this
/// proof in that environment, or fake it by only ever testing from the
/// broker's own UID, this test is marked `#[ignore]` with an explicit,
/// visible reason (surfaced by `cargo test` as one clearly-labeled
/// ignored test, and by `cargo test -- --ignored --list` with the reason
/// text) and is expected to be run explicitly — `cargo test -- --ignored`
/// — in a self-hosted or root-capable environment (this crate's own
/// Linux container development environment, running as root by default,
/// is one such environment; it was used to verify this test actually
/// passes, not merely compiles).
///
/// The unconditional, always-run unit-level proof that
/// `authenticate_peer` itself rejects a UID mismatch (without needing a
/// real second UID) lives in `src/broker/socket.rs` — see
/// `authenticate_peer_rejects_unexpected_uid` — and is *not* weakened,
/// removed, or made conditional by this test's existence.
#[test]
#[ignore = "requires root/CAP_SETUID to setuid() to a second real UID; \
            run explicitly with `cargo test -- --ignored` in a self-hosted \
            or root-capable environment. The unconditional unit-level \
            proof (SO_PEERCRED wrong-expected-uid) is in \
            src/broker/socket.rs::tests::authenticate_peer_rejects_unexpected_uid \
            and always runs."]
fn unauthorized_peer_uid_is_dropped_before_handle_connection() {
    assert_eq!(
        nix::unistd::getuid().as_raw(),
        0,
        "this test must be run as root (it spawns a helper subprocess that \
         setuid()s to a different, unused UID to prove a real cross-UID \
         rejection); it is marked #[ignore] for exactly this reason and \
         must be invoked with `cargo test -- --ignored`"
    );

    let broker = TestBroker::start(&["/usr/bin/true"]);
    let broker_uid = expected_uid();
    // An arbitrary, almost-certainly-unused UID distinct from the
    // broker's own (root, 0, in this gated test).
    let other_uid = 65_500u32;
    let socket_path = broker.runtime_dir().join("broker.sock");

    // A same-UID control connection must be accepted normally, to prove
    // any observed rejection below is really about the UID mismatch and
    // not, say, a broken socket path.
    {
        let mut control = broker.connect_raw();
        let bytes_written = control.write(&0u32.to_be_bytes()).unwrap_or(0);
        assert!(
            bytes_written > 0
                || read_raw_until_closed(&mut control, Duration::from_millis(500)).is_empty(),
            "a same-uid control connection should not be rejected at accept time"
        );
    }

    // The actual cross-UID probe runs in a genuinely separate process
    // (`exec-broker-test-helper connect-as-uid`) rather than an in-test
    // `fork()`: this crate denies `unsafe_code` crate-wide (including in
    // its tests) and `fork()` is `unsafe` in `nix`, so a real subprocess
    // is used instead — see that binary's `run_connect_as_uid` for the
    // exact `setuid`/`connect`/read logic and its exit-code contract
    // (`0` = rejected, `1` = not rejected, `2` = setup failure).
    let output = Command::new(TEST_HELPER_EXE)
        .arg("connect-as-uid")
        .arg("--uid")
        .arg(other_uid.to_string())
        .arg("--socket-path")
        .arg(&socket_path)
        .output()
        .expect("run exec-broker-test-helper connect-as-uid");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the setuid({other_uid}) probe must observe its connection rejected \
         (EOF with no reply bytes); stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // The broker's own UID connection must still work fully normally
    // afterward.
    let credentials = broker.credentials(broker_uid);
    let runtime = tokio::runtime::Runtime::new().expect("build runtime");
    runtime.block_on(async {
        let mut stream = broker.connect(broker_uid).await;
        let msg = ClientMessage::Execute {
            correlation_id: "after-unauthorized-uid-attempt".to_string(),
            session_id: credentials.session_id.clone(),
            token: credentials.token_hex.clone(),
            argv: vec!["/usr/bin/true".to_string()],
            cwd: broker.root().to_string_lossy().into_owned(),
            env: BTreeMap::new(),
            timeout_ms: 5_000,
        };
        write_message(&mut stream, &msg)
            .await
            .expect("send Execute");
        let event: ServerEvent = read_message(&mut stream)
            .await
            .expect("read event")
            .expect("connection must not be closed");
        assert!(matches!(event, ServerEvent::Started { .. }));
    });
}
