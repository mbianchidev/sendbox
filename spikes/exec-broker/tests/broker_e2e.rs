//! Credible end-to-end integration tests for the full
//! broker/launcher/policy/session pipeline: every test here spawns the
//! actual compiled `exec-broker` and `exec-broker-agent` binaries (via
//! `CARGO_BIN_EXE_...`, the same pattern used by
//! `tests/agent_probe_seccomp.rs`) as real subprocesses talking over a
//! real Unix socket, rather than calling library functions directly —
//! proving the wiring between binaries (CLI parsing, session credential
//! file handoff, `LauncherEnvelope` handoff to `exec-broker-launcher`,
//! and the wire protocol itself) actually works, not just each piece in
//! isolation.
//!
//! Linux-gated: every hardening primitive this crate provides
//! (`PR_SET_NO_NEW_PRIVS`, seccomp, process groups) only exists on Linux,
//! matching every other Linux-specific module and test in this crate.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BROKER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker");
const AGENT_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-agent");
const LAUNCHER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-launcher");

/// A running `exec-broker` instance, spawned fresh for one test, with its
/// own private runtime directory. Dropping this always tears the broker
/// down (SIGKILL, to guarantee no orphaned process lingers regardless of
/// what a given test already did to it) unless a test has already reaped
/// it itself.
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
    /// Starts a broker whose allowlist contains exactly `allow_exec`,
    /// with its `allowed_root` set to a fresh, private temp directory.
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
            "exec-broker did not create its socket/credentials in \
             {:?} within the startup deadline",
            self.runtime_dir
        );
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// Runs `exec-broker-agent broker-client` against this broker to
    /// completion and returns its captured output. `extra_args` are
    /// inserted before the `--` separator (e.g. `--timeout-ms`,
    /// `--cancel-after-ms`, `--env`); `argv` is the command to execute.
    fn run_agent(&self, extra_args: &[&str], argv: &[&str]) -> Output {
        Command::new(AGENT_EXE)
            .arg("broker-client")
            .arg("--runtime-dir")
            .arg(&self.runtime_dir)
            .arg("--cwd")
            .arg(&self.root)
            .args(extra_args)
            .arg("--")
            .args(argv)
            .output()
            .expect("failed to run exec-broker-agent broker-client")
    }

    /// Sends `SIGTERM` (graceful shutdown) and waits for the broker to
    /// exit and remove its own runtime directory, up to `timeout`.
    /// Returns `true` if the runtime directory is gone by then.
    fn graceful_shutdown_removes_runtime_dir(&mut self, timeout: Duration) -> bool {
        let pid = self.child.id() as i32;
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGTERM,
        );
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !self.runtime_dir.exists() {
                let _ = self.child.wait();
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
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
        // already removed (e.g. `graceful_shutdown_removes_runtime_dir`
        // already ran), there is nothing registered to clean up here.
        if self.runtime_dir.exists() {
            let registry = exec_broker_spike::pgid_registry::PgidRegistry::new(
                self.runtime_dir.join("pgids.json"),
            );
            let _ = exec_broker_spike::supervisor::kill_all_registered(&registry);
        }
        // Best-effort: if a test already reaped the child (e.g. via
        // `graceful_shutdown_removes_runtime_dir`), `try_wait` already
        // returns `Some`, and `kill`/`wait` below are harmless no-ops
        // beyond an ignored `ESRCH`.
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Reap anything the kill above just caused to exit and that
        // reparented to this process (see `become_child_subreaper_once`).
        exec_broker_spike::supervisor::reap_available_children(Duration::from_secs(2));
    }
}

/// Blocks (bounded by `timeout`) until `pid` no longer exists as a
/// process, by polling `/proc/<pid>`. Used to prove that cancellation /
/// disconnect actually reaches and kills the spawned process, without
/// depending on this test process being the child's parent (it is not:
/// the broker is).
fn wait_until_pid_gone(pid: i32, timeout: Duration) -> bool {
    let proc_path = format!("/proc/{pid}");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !Path::new(&proc_path).exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Extracts the pid from the `started: pid=<N> pgid=<N>` line
/// `exec-broker-agent broker-client` prints to stderr on `Started`
/// (see `src/bin/agent.rs`). Lets tests that drive the broker through
/// `TestBroker::run_agent` (which only returns once the whole execution
/// has completed) still explicitly assert the spawned process is
/// actually gone by then, rather than only trusting that the reported
/// exit code/outcome implies it.
fn started_pid_from_agent_output(output: &Output) -> i32 {
    let stderr = stderr_str(output);
    stderr
        .lines()
        .find_map(|line| line.strip_prefix("started: pid="))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|pid_str| pid_str.parse::<i32>().ok())
        .unwrap_or_else(|| panic!("could not find 'started: pid=<N>' in agent stderr: {stderr}"))
}

/// An approved command, containing argv bytes that would be dangerous if
/// ever passed through a shell (command separators, subshells, variable
/// expansion, pipes, backticks), must be executed literally: `exec-broker`
/// (via `contained-launcher`) always calls `execve` directly on the
/// validated argv and never invokes `/bin/sh` or any other interpreter,
/// so these characters can only ever be *data*, never *syntax*.
#[test]
fn allowed_printf_with_shell_metacharacters_executes_literally() {
    let broker = TestBroker::start(&["/usr/bin/printf"]);
    let payload = "hello; rm -rf /nonexistent && echo $(whoami) | cat `id` > /tmp/pwned";

    let output = broker.run_agent(&[], &["/usr/bin/printf", "%s\n", payload]);

    assert!(
        output.status.success(),
        "expected success, got status={:?} stderr={}",
        output.status,
        stderr_str(&output)
    );
    assert_eq!(
        stdout_str(&output),
        format!("{payload}\n"),
        "the shell metacharacters must be reproduced exactly, byte for byte, \
         proving they were never interpreted by a shell"
    );
}

/// A request for an executable that is not in the broker's allowlist must
/// be rejected before anything is spawned: the client must never observe
/// a `Started` event, and the broker's `Rejected` event must carry
/// `ExecutableNotAllowlisted`.
#[test]
fn denied_request_never_reaches_started() {
    // Deliberately allowlist only `/usr/bin/printf`, then request
    // `/usr/bin/true` instead.
    let broker = TestBroker::start(&["/usr/bin/printf"]);

    let output = broker.run_agent(&[], &["/usr/bin/true"]);

    assert!(
        !output.status.success(),
        "a denied request must not exit successfully"
    );
    // The agent prints "started: pid=<N> pgid=<N>" to *stderr* on a real
    // `Started` event (see `src/bin/agent.rs`); checking stdout here
    // would be a no-op (the target's own stdout is echoed there, but
    // never contains this literal marker), so this must check stderr to
    // actually prove no process was ever spawned.
    let stderr = stderr_str(&output);
    assert!(
        !stderr.contains("started:"),
        "a denied request must never reach Started; stderr={stderr}"
    );
    assert!(
        stderr.contains("ExecutableNotAllowlisted"),
        "expected the ExecutableNotAllowlisted rejection code on stderr, got: {stderr}"
    );
}

/// Injecting a well-known dangerous environment variable (`LD_PRELOAD`,
/// here) must reject the whole request before spawning anything,
/// regardless of the target executable's own allowlist status.
#[test]
fn dangerous_env_var_injection_is_rejected() {
    let broker = TestBroker::start(&["/usr/bin/printf"]);

    let output = broker.run_agent(
        &["--env", "LD_PRELOAD=/definitely/not/a/real/lib.so"],
        &["/usr/bin/printf", "unreachable"],
    );

    assert!(!output.status.success());
    // See `denied_request_never_reaches_started`'s comment: "started:"
    // is only ever printed to stderr, never stdout, so stderr is the
    // stream that must be checked for it to be a meaningful proof.
    let stderr = stderr_str(&output);
    assert!(
        !stderr.contains("started:"),
        "a request with a dangerous env var must never reach Started; stderr={stderr}"
    );
    assert!(
        stderr.contains("DangerousEnvVar"),
        "expected the DangerousEnvVar rejection code on stderr, got: {stderr}"
    );
}

/// The spawned process's environment is always `env_clear()`ed before the
/// broker's fixed `PATH`/`LANG` and the caller's (sanitized) entries are
/// applied: none of this *test* process's own ambient environment
/// variables (which the broker/launcher inherited at their own spawn
/// time) may leak through to the target.
#[test]
fn target_environment_is_cleared_not_inherited() {
    let broker = TestBroker::start(&["/usr/bin/printenv"]);

    // Poison the *test's own* environment with a variable that must not
    // appear in the target's environment if `env_clear()` ran correctly.
    let output = Command::new(AGENT_EXE)
        .arg("broker-client")
        .arg("--runtime-dir")
        .arg(broker.runtime_dir())
        .arg("--cwd")
        .arg(broker.root())
        .arg("--env")
        .arg("ALLOWED_TEST_VAR=present")
        .arg("--")
        .arg("/usr/bin/printenv")
        .env("EXEC_BROKER_E2E_CANARY", "should-not-leak-into-target")
        .output()
        .expect("failed to run exec-broker-agent broker-client");

    assert!(
        output.status.success(),
        "printenv must run to completion: stderr={}",
        stderr_str(&output)
    );
    let stdout = stdout_str(&output);
    assert!(
        !stdout.contains("EXEC_BROKER_E2E_CANARY"),
        "ambient environment leaked into the target's environment: {stdout}"
    );
    assert!(
        stdout.contains("ALLOWED_TEST_VAR=present"),
        "explicitly requested, sanitized env entries must still reach the target: {stdout}"
    );
}

/// A command that outruns its requested timeout has its process group
/// killed and the client observes `Outcome::TimedOut`.
#[test]
fn timeout_kills_the_process_and_is_reported() {
    let broker = TestBroker::start(&["/usr/bin/sleep"]);

    let started = Instant::now();
    let output = broker.run_agent(&["--timeout-ms", "300"], &["/usr/bin/sleep", "30"]);
    let elapsed = started.elapsed();

    assert_eq!(
        output.status.code(),
        Some(124),
        "expected the TimedOut exit code"
    );
    assert!(
        stderr_str(&output).contains("TimedOut"),
        "expected TimedOut in stderr: {}",
        stderr_str(&output)
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the 30s sleep must have been killed well before completing on its own; took {elapsed:?}"
    );

    // Explicit process-cleanup proof, not just an implied one: the
    // reported `TimedOut` outcome must mean the spawned process is
    // already dead, not merely that the agent stopped waiting on it.
    let pid = started_pid_from_agent_output(&output);
    assert!(
        wait_until_pid_gone(pid, Duration::from_secs(2)),
        "pid {pid} (the timed-out 30s sleep) was still alive after \
         `TimedOut` was reported"
    );
}

/// A client-issued `Cancel` for a still-running execution stops it well
/// before its own timeout or natural completion, and is reported as
/// `Outcome::Cancelled`.
#[test]
fn cancel_stops_a_running_command_before_its_timeout() {
    let broker = TestBroker::start(&["/usr/bin/sleep"]);

    let started = Instant::now();
    let output = broker.run_agent(
        &["--timeout-ms", "30000", "--cancel-after-ms", "300"],
        &["/usr/bin/sleep", "30"],
    );
    let elapsed = started.elapsed();

    assert_eq!(
        output.status.code(),
        Some(130),
        "expected the Cancelled exit code"
    );
    assert!(
        stderr_str(&output).contains("Cancelled"),
        "expected Cancelled in stderr: {}",
        stderr_str(&output)
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "cancellation must stop the 30s sleep almost immediately; took {elapsed:?}"
    );

    // Explicit process-cleanup proof: the reported `Cancelled` outcome
    // must mean the spawned process is already dead, not merely that
    // the agent stopped waiting on it.
    let pid = started_pid_from_agent_output(&output);
    assert!(
        wait_until_pid_gone(pid, Duration::from_secs(2)),
        "pid {pid} (the cancelled 30s sleep) was still alive after \
         `Cancelled` was reported"
    );
}

/// A client that disconnects mid-execution (without ever sending
/// `Cancel`) must not leave the spawned process running: the broker
/// treats a read-side EOF/error as `CancelReason::ClientDisconnected` and
/// kills the process group.
#[tokio::test]
async fn disconnect_without_cancel_still_kills_the_spawned_process() {
    let broker = TestBroker::start(&["/usr/bin/sleep"]);

    let expected_uid = nix::unistd::getuid().as_raw();
    let credentials = exec_broker_spike::session::load_credentials_file(
        &broker
            .runtime_dir()
            .join(exec_broker_spike::session::CREDENTIALS_FILE_NAME),
        expected_uid,
    )
    .expect("load session credentials");
    let std_stream = exec_broker_spike::broker::socket::connect(
        &broker.runtime_dir().join("broker.sock"),
        expected_uid,
    )
    .expect("connect to broker socket");
    std_stream.set_nonblocking(true).expect("set nonblocking");
    let mut stream = tokio::net::UnixStream::from_std(std_stream).expect("hand off to tokio");

    let execute = exec_broker_spike::protocol::ClientMessage::Execute {
        correlation_id: "disconnect-test".to_string(),
        session_id: credentials.session_id.clone(),
        token: credentials.token_hex.clone(),
        argv: vec!["/usr/bin/sleep".to_string(), "30".to_string()],
        cwd: broker.root().to_string_lossy().into_owned(),
        env: std::collections::BTreeMap::new(),
        timeout_ms: 30_000,
    };
    exec_broker_spike::broker::framing::write_message(&mut stream, &execute)
        .await
        .expect("send Execute");

    let started: exec_broker_spike::protocol::ServerEvent =
        exec_broker_spike::broker::framing::read_message(&mut stream)
            .await
            .expect("read Started event")
            .expect("connection must not be closed yet");
    let pid = match started {
        exec_broker_spike::protocol::ServerEvent::Started { pid, .. } => pid,
        other => panic!("expected Started, got {other:?}"),
    };

    // Disconnect immediately, without reading `Completed` or sending
    // `Cancel`.
    drop(stream);

    assert!(
        wait_until_pid_gone(pid, Duration::from_secs(5)),
        "pid {pid} was still alive 5s after the client disconnected from a 30s sleep"
    );
}

/// A target that produces far more stdout than the broker's per-stream
/// byte cap must still run to completion (never blocked on a full pipe
/// buffer) with the excess silently dropped rather than buffered
/// unboundedly; the client observes the `truncated` flag.
#[test]
fn stdout_saturation_is_truncated_not_blocked() {
    let broker = TestBroker::start(&["/usr/bin/yes"]);

    // `yes` never exits on its own; bound it with a short timeout. If
    // draining ever blocked on the client, this would hang for the full
    // timeout (or longer); instead it should hit the byte cap almost
    // immediately and still be killed cleanly at the timeout.
    let output = broker.run_agent(&["--timeout-ms", "500"], &["/usr/bin/yes"]);

    assert_eq!(
        output.status.code(),
        Some(124),
        "expected the TimedOut exit code for `yes` under a short timeout"
    );
    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("stream truncated by broker-side cap"),
        "expected at least one truncated stdout chunk to be reported: {stderr}"
    );

    // Explicit process-cleanup proof: the timed-out `yes` (which would
    // otherwise run forever) must actually be dead, not merely reported
    // as timed out.
    let pid = started_pid_from_agent_output(&output);
    assert!(
        wait_until_pid_gone(pid, Duration::from_secs(2)),
        "pid {pid} (the timed-out infinite `yes`) was still alive after \
         `TimedOut` was reported"
    );
}

/// On graceful shutdown (`SIGTERM`) the broker removes its own runtime
/// directory (socket + session credential file) rather than leaking it.
#[test]
fn broker_removes_runtime_dir_on_graceful_shutdown() {
    let mut broker = TestBroker::start(&["/usr/bin/printf"]);
    assert!(
        broker.graceful_shutdown_removes_runtime_dir(Duration::from_secs(5)),
        "runtime directory {:?} still existed after graceful shutdown",
        broker.runtime_dir()
    );
}

/// A client that authenticates, starts a long-running command, and then
/// never reads another byte from the socket (without disconnecting) must
/// not be able to wedge the broker forever: once the writer task's
/// per-write timeout elapses with no progress, the connection is treated
/// as stalled (`CancelReason::StreamStalled`, distinct from a clean
/// disconnect), the process group is killed, and the receiver is dropped
/// so producer tasks cannot block on a full event channel indefinitely.
#[tokio::test]
async fn slow_non_reading_client_is_treated_as_stalled_and_cleaned_up() {
    let broker = TestBroker::start(&["/usr/bin/yes"]);

    let expected_uid = nix::unistd::getuid().as_raw();
    let credentials = exec_broker_spike::session::load_credentials_file(
        &broker
            .runtime_dir()
            .join(exec_broker_spike::session::CREDENTIALS_FILE_NAME),
        expected_uid,
    )
    .expect("load session credentials");
    let std_stream = exec_broker_spike::broker::socket::connect(
        &broker.runtime_dir().join("broker.sock"),
        expected_uid,
    )
    .expect("connect to broker socket");
    std_stream.set_nonblocking(true).expect("set nonblocking");
    let mut stream = tokio::net::UnixStream::from_std(std_stream).expect("hand off to tokio");

    // A generous request-level timeout: this test must prove the
    // *writer-stall* path kills the process, not the ordinary per-request
    // timeout racing it.
    let execute = exec_broker_spike::protocol::ClientMessage::Execute {
        correlation_id: "stall-test".to_string(),
        session_id: credentials.session_id.clone(),
        token: credentials.token_hex.clone(),
        argv: vec!["/usr/bin/yes".to_string()],
        cwd: broker.root().to_string_lossy().into_owned(),
        env: std::collections::BTreeMap::new(),
        timeout_ms: 60_000,
    };
    exec_broker_spike::broker::framing::write_message(&mut stream, &execute)
        .await
        .expect("send Execute");

    let started: exec_broker_spike::protocol::ServerEvent =
        exec_broker_spike::broker::framing::read_message(&mut stream)
            .await
            .expect("read Started event")
            .expect("connection must not be closed yet");
    let pid = match started {
        exec_broker_spike::protocol::ServerEvent::Started { pid, .. } => pid,
        other => panic!("expected Started, got {other:?}"),
    };

    // Deliberately stop reading (but keep the socket open, unlike the
    // disconnect test) while `yes` floods stdout. The broker's writer
    // task will eventually block on a single write once kernel socket
    // buffers fill, hit its write timeout, and tear the execution down.
    // `WRITE_TIMEOUT` is 10s; allow generous margin for the buffer to
    // fill and the cleanup to complete.
    assert!(
        wait_until_pid_gone(pid, Duration::from_secs(30)),
        "pid {pid} (an infinite `yes`) was still alive 30s after its client \
         stopped reading without disconnecting; the writer-stall detection \
         did not clean it up"
    );

    // The connection itself must still have been usable up to the point
    // of the stall (i.e. this really was a stall, not an early protocol
    // error) — best-effort: reading further either yields the
    // broker-initiated close or an I/O error, both acceptable, but must
    // not hang the test.
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        exec_broker_spike::broker::framing::read_message::<
            exec_broker_spike::protocol::ServerEvent,
            _,
        >(&mut stream),
    )
    .await;
}

/// Correlation IDs are unique per *session*, not per connection: two
/// separate socket connections authenticated against the same (shared,
/// broker-instance-wide) session must not be able to reuse a correlation
/// ID that is still in flight on the other connection.
#[tokio::test]
async fn duplicate_correlation_id_is_rejected_across_separate_connections() {
    let broker = TestBroker::start(&["/usr/bin/sleep"]);

    let expected_uid = nix::unistd::getuid().as_raw();
    let credentials = exec_broker_spike::session::load_credentials_file(
        &broker
            .runtime_dir()
            .join(exec_broker_spike::session::CREDENTIALS_FILE_NAME),
        expected_uid,
    )
    .expect("load session credentials");

    let connect = || {
        let std_stream = exec_broker_spike::broker::socket::connect(
            &broker.runtime_dir().join("broker.sock"),
            expected_uid,
        )
        .expect("connect to broker socket");
        std_stream.set_nonblocking(true).expect("set nonblocking");
        tokio::net::UnixStream::from_std(std_stream).expect("hand off to tokio")
    };

    let mut first = connect();
    let mut second = connect();

    let shared_correlation_id = "shared-correlation-id".to_string();
    let make_execute =
        |argv: Vec<String>, timeout_ms: u64| exec_broker_spike::protocol::ClientMessage::Execute {
            correlation_id: shared_correlation_id.clone(),
            session_id: credentials.session_id.clone(),
            token: credentials.token_hex.clone(),
            argv,
            cwd: broker.root().to_string_lossy().into_owned(),
            env: std::collections::BTreeMap::new(),
            timeout_ms,
        };

    // First connection starts a long-running execution under the shared
    // correlation id and keeps it in flight.
    exec_broker_spike::broker::framing::write_message(
        &mut first,
        &make_execute(vec!["/usr/bin/sleep".to_string(), "5".to_string()], 30_000),
    )
    .await
    .expect("send first Execute");
    let first_started: exec_broker_spike::protocol::ServerEvent =
        exec_broker_spike::broker::framing::read_message(&mut first)
            .await
            .expect("read Started event")
            .expect("connection must not be closed yet");
    let first_pid = match first_started {
        exec_broker_spike::protocol::ServerEvent::Started { pid, .. } => pid,
        other => panic!("expected Started, got {other:?}"),
    };

    // Second, entirely separate connection reuses the same correlation
    // id while the first is still in flight; it must be rejected as a
    // session-wide duplicate, not merely a per-connection one.
    exec_broker_spike::broker::framing::write_message(
        &mut second,
        &make_execute(vec!["/usr/bin/sleep".to_string(), "1".to_string()], 30_000),
    )
    .await
    .expect("send second Execute");
    let second_response: exec_broker_spike::protocol::ServerEvent =
        exec_broker_spike::broker::framing::read_message(&mut second)
            .await
            .expect("read response on second connection")
            .expect("connection must not be closed yet");
    match second_response {
        exec_broker_spike::protocol::ServerEvent::Rejected { code, .. } => {
            assert_eq!(
                code,
                exec_broker_spike::protocol::RejectionCode::DuplicateCorrelationId,
                "expected DuplicateCorrelationId, got {code:?}"
            );
        }
        other => panic!("expected Rejected(DuplicateCorrelationId), got {other:?}"),
    }

    // Clean up: let the first execution finish and confirm its process
    // exits naturally (it was never disturbed by the rejected duplicate).
    assert!(
        wait_until_pid_gone(first_pid, Duration::from_secs(10)),
        "the original in-flight execution (pid {first_pid}) should still \
         complete normally; a rejected duplicate must not affect it"
    );
}
