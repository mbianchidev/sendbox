//! Proves the "fail-closed after broker death" claim end to end: an
//! agent process that has already installed its seccomp filter, and has
//! authenticated a real session against a real, running broker, still
//! has every direct exec-family syscall denied *after* that broker is
//! killed and cleaned up by the supervisor — because the filter is a
//! kernel-held property of the agent process itself, never something
//! that depends on any particular broker instance staying alive.
//!
//! This is the integration harness the `fail-closed-probe` agent mode's
//! own documentation refers to: it starts the real
//! `exec-broker-supervisor` (which starts the real `exec-broker`), starts
//! the real `exec-broker-agent fail-closed-probe` as a genuine
//! subprocess, waits for it to report a real authenticated session, kills
//! only the broker (identified precisely via `/proc`, exactly as
//! `tests/supervisor_crash.rs` does), and then asserts on the typed JSON
//! the agent process itself prints once it observes the broker is gone.
//!
//! Linux-gated: every hardening primitive under test here (seccomp,
//! process groups, `/proc`) only exists on Linux, matching every other
//! Linux-specific integration test in this crate.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SUPERVISOR_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-supervisor");
const BROKER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker");
const AGENT_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-agent");
const LAUNCHER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-launcher");

/// The exact set of probe names the post-broker-death battery must emit,
/// every one of which must be `Denied`. Kept as an explicit exhaustive
/// set (not just "at least N lines") so a probe silently missing from the
/// output — not merely one silently passing — is also caught.
const EXPECTED_PROBE_NAMES: &[&str] = &[
    "libc_execve_bin_true",
    "raw_syscall_execve_bin_true",
    "libc_execveat_memfd",
    "raw_syscall_execveat_memfd",
    "libc_execveat_bin_true_fd",
    "raw_syscall_execveat_bin_true_fd",
];

/// EPERM, the errno every one of these attempts must fail with: seccomp
/// denials configured with `SECCOMP_RET_ERRNO` return this specific
/// errno, and accepting any other errno here would risk masking a
/// different, non-seccomp failure mode as if it were a real denial.
const EPERM: i32 = 1;

fn parent_pid_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<i32>().ok())
}

fn find_child_pid(parent_pid: i32, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                    continue;
                };
                if parent_pid_of(pid) == Some(parent_pid) {
                    return Some(pid);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[derive(serde::Deserialize, Debug)]
struct ProbeResultJson {
    name: String,
    outcome: OutcomeJson,
}

#[derive(serde::Deserialize, Debug)]
#[serde(tag = "kind")]
enum OutcomeJson {
    Denied { errno: i32 },
    UnexpectedSuccess,
    SetupFailed { message: String },
}

#[test]
fn agent_exec_attempts_remain_denied_after_the_broker_is_killed_and_cleaned_up() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path().join("root");
    std::fs::create_dir_all(&root).expect("create allowed root");
    let runtime_dir: PathBuf = tempdir.path().join("runtime");

    let mut supervisor = Command::new(SUPERVISOR_EXE)
        .arg("--broker-binary")
        .arg(BROKER_EXE)
        .arg("--runtime-dir")
        .arg(&runtime_dir)
        .arg("--")
        .arg("--allowed-root")
        .arg(&root)
        .arg("--launcher-binary")
        .arg(LAUNCHER_EXE)
        .arg("--allow-exec")
        .arg("/usr/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn exec-broker-supervisor");
    let supervisor_pid = supervisor.id() as i32;

    let socket_path = runtime_dir.join("broker.sock");
    let credentials_path = runtime_dir.join("session.credentials");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !(socket_path.exists() && credentials_path.exists()) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        socket_path.exists() && credentials_path.exists(),
        "broker (under supervisor) did not become ready in time"
    );

    let broker_pid = find_child_pid(supervisor_pid, Duration::from_secs(5))
        .expect("could not identify the broker's PID as a child of the supervisor");
    assert_ne!(
        broker_pid, supervisor_pid,
        "must never target the supervisor itself"
    );

    let mut agent = Command::new(AGENT_EXE)
        .arg("fail-closed-probe")
        .arg("--runtime-dir")
        .arg(&runtime_dir)
        .arg("--cwd")
        .arg(&root)
        .arg("--death-timeout-secs")
        .arg("15")
        .arg("--")
        .arg("/usr/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn exec-broker-agent fail-closed-probe");

    let mut stdout_reader =
        BufReader::new(agent.stdout.take().expect("agent stdout must be piped"));

    // Read lines until the agent reports it authenticated a real session
    // and is now waiting for the broker to die — proving steps 1-3 of the
    // scenario (filter installed, session authenticated/observed) before
    // we go on to kill the broker.
    let mut saw_authenticated = false;
    let mut saw_ready = false;
    let read_deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while !saw_ready {
        line.clear();
        let n = stdout_reader
            .read_line(&mut line)
            .expect("read line from agent stdout");
        assert!(
            n > 0,
            "agent stdout closed before reporting readiness (saw_authenticated={saw_authenticated})"
        );
        if line.contains("authenticated and observed a real broker session") {
            saw_authenticated = true;
        }
        if line.contains("ready, waiting for the broker to be killed") {
            saw_ready = true;
        }
        assert!(
            Instant::now() < read_deadline,
            "did not see the agent's readiness line in time"
        );
    }
    assert!(
        saw_authenticated,
        "agent must report authenticating a real session before reporting readiness"
    );

    // Kill *only* the broker, precisely, from outside.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(broker_pid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect("failed to SIGKILL the broker");

    let agent_status = wait_for_exit(&mut agent, Duration::from_secs(20)).unwrap_or_else(|| {
        panic!("exec-broker-agent fail-closed-probe did not exit within the deadline")
    });

    let mut remaining_stdout = String::new();
    stdout_reader
        .read_to_string(&mut remaining_stdout)
        .expect("read remaining agent stdout");
    let mut stderr_buf = String::new();
    let _ = agent
        .stderr
        .take()
        .expect("agent stderr must be piped")
        .read_to_string(&mut stderr_buf);

    assert!(
        agent_status.success(),
        "fail-closed-probe must exit 0 (every post-death exec attempt denied), got \
         {agent_status:?}; stderr={stderr_buf}"
    );

    let mut seen_names: BTreeSet<String> = BTreeSet::new();
    for json_line in remaining_stdout
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
    {
        let parsed: ProbeResultJson = serde_json::from_str(json_line)
            .unwrap_or_else(|e| panic!("failed to parse probe JSON line {json_line:?}: {e}"));
        match parsed.outcome {
            OutcomeJson::Denied { errno } => {
                assert_eq!(
                    errno, EPERM,
                    "probe {} must be denied with EPERM specifically, got errno {errno}",
                    parsed.name
                );
            }
            OutcomeJson::UnexpectedSuccess => {
                panic!(
                    "probe {} unexpectedly SUCCEEDED after the broker died — the agent's own \
                     seccomp filter must remain enforced regardless of broker liveness",
                    parsed.name
                );
            }
            OutcomeJson::SetupFailed { message } => {
                panic!(
                    "probe {} could not even be attempted (setup failed: {message}); this must \
                     be a genuine kernel denial, not an inconclusive setup failure",
                    parsed.name
                );
            }
        }
        seen_names.insert(parsed.name);
    }

    let expected: BTreeSet<String> = EXPECTED_PROBE_NAMES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        seen_names, expected,
        "every expected post-broker-death probe must appear exactly once, denied"
    );

    // No orphan agent process: it already exited above. Reap the
    // supervisor too, tolerating it taking a little longer to finish its
    // own cleanup (already proven thoroughly by
    // `tests/supervisor_crash.rs`; here we only need to not leak it).
    let _ = wait_for_exit(&mut supervisor, Duration::from_secs(15));
    let _ = supervisor.kill();
    let _ = supervisor.wait();
}
