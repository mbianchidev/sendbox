//! Proves the supervisor's core reason for existing: if the broker
//! process dies for any reason (here, `SIGKILL` from outside — modeling
//! an OOM kill, a crash, or operator error) while it has a long-running
//! brokered child registered, the supervisor still (a) kills that
//! child's whole process group, (b) removes every runtime-directory
//! artifact (socket, session credentials, PGID registry), and (c) itself
//! exits — leaving no orphaned process and no stale runtime state behind.
//!
//! This is an actual end-to-end test: it spawns the real
//! `exec-broker-supervisor` binary, which spawns the real `exec-broker`
//! binary as its child, which spawns the real `exec-broker-launcher` and
//! `exec-broker-test-helper longlived` binaries as *its* descendants —
//! then kills only the broker (identified as the supervisor's actual
//! child PID via `/proc`, never the supervisor itself) and observes the
//! supervisor's reaction from outside, exactly as an operator or a real
//! OOM killer would.
//!
//! Linux-gated: every hardening primitive under test here (seccomp,
//! process groups, `/proc`) only exists on Linux, matching every other
//! Linux-specific integration test in this crate.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SUPERVISOR_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-supervisor");
const BROKER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker");
const AGENT_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-agent");
const LAUNCHER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-launcher");
const TEST_HELPER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-test-helper");

/// Reads `/proc/<pid>/stat` and returns its `ppid` field, or `None` if
/// the process does not exist. Parsed defensively: the second field
/// (`comm`) is parenthesized and may itself contain spaces or parens, so
/// this splits on the *last* `)` rather than naively splitting on
/// whitespace.
fn parent_pid_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    // ` state ppid ...` — ppid is the second whitespace-separated field.
    after_comm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<i32>().ok())
}

/// Finds a direct child of `parent_pid` by scanning `/proc/*/stat`, bounded
/// by `timeout`. Used to identify the broker's real OS PID (the
/// supervisor's own direct child) without depending on any output the
/// broker itself prints, so the SIGKILL below can be targeted precisely
/// at the broker and never at the supervisor.
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

fn pid_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn wait_until_pid_gone(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_exists(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Blocks up to `timeout` waiting for `child` to exit (via repeated
/// non-blocking `try_wait`), returning its `ExitStatus` if it did.
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

/// Kills and reaps `child`, tolerating it already being gone.
fn force_kill(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn supervisor_kills_orphaned_child_and_removes_runtime_state_after_broker_is_killed() {
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
        .arg(TEST_HELPER_EXE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn exec-broker-supervisor");
    let supervisor_pid = supervisor.id() as i32;

    // Wait for the broker (the supervisor's direct child) to create its
    // socket and session credentials, proving it is up and ready.
    let socket_path = runtime_dir.join("broker.sock");
    let credentials_path = runtime_dir.join("session.credentials");
    let registry_path = runtime_dir.join("pgids.json");
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

    // Launch a long-running brokered child (`test_helper longlived`) via
    // the real agent CLI, exactly as a real caller would. This process is
    // kept running in the background (not `.output()`'d, which would
    // block until it exits) because it never exits on its own.
    let mut agent_client = Command::new(AGENT_EXE)
        .arg("broker-client")
        .arg("--runtime-dir")
        .arg(&runtime_dir)
        .arg("--cwd")
        .arg(&root)
        .arg("--")
        .arg(TEST_HELPER_EXE)
        .arg("longlived")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn exec-broker-agent broker-client");

    // Read the readiness line the long-lived descendant prints to its own
    // stdout (relayed verbatim through the broker and the agent CLI) to
    // learn its real OS PID, which is also its PGID (the launcher was
    // spawned with `.process_group(0)` and later `execve`'d into
    // `test_helper`, preserving the PID).
    let mut stdout_reader = BufReader::new(
        agent_client
            .stdout
            .take()
            .expect("agent-client stdout must be piped"),
    );
    let mut ready_line = String::new();
    let read_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        ready_line.clear();
        let n = stdout_reader
            .read_line(&mut ready_line)
            .expect("read readiness line from agent-client stdout");
        if n == 0 {
            panic!("agent-client stdout closed before the readiness line was seen");
        }
        if ready_line.contains("longlived ready pid=") {
            break;
        }
        assert!(
            Instant::now() < read_deadline,
            "did not see the long-lived descendant's readiness line in time"
        );
    }
    let descendant_pid: i32 = ready_line
        .trim()
        .rsplit("pid=")
        .next()
        .expect("readiness line must contain pid=")
        .parse()
        .expect("pid must be a valid integer");
    assert!(
        pid_exists(descendant_pid),
        "the long-lived descendant must actually be running before we proceed"
    );

    // The registered PGID must equal the descendant's own PID, and it
    // must actually be present in the on-disk registry before we kill
    // the broker — otherwise this test would not be exercising the
    // "registered, then broker dies" scenario at all.
    let registry_contents = std::fs::read_to_string(&registry_path)
        .expect("pgid registry file must exist once the descendant is registered");
    assert!(
        registry_contents.contains(&descendant_pid.to_string()),
        "expected pgid {descendant_pid} to be registered in {registry_contents}"
    );

    // Kill *only* the broker, precisely, from outside — modeling an OOM
    // kill, crash, or operator error. The supervisor must notice (via
    // `wait()` on its child) and clean up.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(broker_pid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect("failed to SIGKILL the broker");

    let supervisor_status = wait_for_exit(&mut supervisor, Duration::from_secs(15))
        .unwrap_or_else(|| panic!("exec-broker-supervisor did not exit within the deadline after its broker was killed"));
    // The broker died by signal, not cleanly, so `ExitStatus::code()` is
    // `None` on Unix; the supervisor propagates that as a non-zero exit
    // (see `src/bin/supervisor.rs`), which is itself proof the death was
    // observed and handled rather than silently ignored.
    assert!(
        !supervisor_status.success(),
        "supervisor should exit non-zero after its broker was killed by SIGKILL, got {supervisor_status:?}"
    );

    // The core claim under test: the previously-registered descendant
    // (and its whole process group) must be gone — not left as an
    // orphan — once the supervisor has finished its cleanup and exited.
    assert!(
        wait_until_pid_gone(descendant_pid, Duration::from_secs(5)),
        "the long-lived descendant (pid={descendant_pid}) must be killed by the supervisor \
         after its broker died; it must not survive as an orphan"
    );

    // Every runtime-directory artifact must be gone: socket, session
    // credentials, PGID registry, and the directory itself.
    assert!(
        !socket_path.exists(),
        "broker socket must be removed by the supervisor's cleanup"
    );
    assert!(
        !credentials_path.exists(),
        "session credentials file must be removed by the supervisor's cleanup"
    );
    assert!(
        !registry_path.exists(),
        "pgid registry file must be removed by the supervisor's cleanup"
    );
    assert!(
        !runtime_dir.exists(),
        "the whole runtime directory must be removed by the supervisor's cleanup"
    );

    // No orphan process remains: neither the broker (already killed and
    // reaped by the supervisor's own `wait()`), the launcher, nor the
    // descendant should still exist.
    assert!(
        !pid_exists(broker_pid),
        "the broker pid must not still exist (it must have been reaped)"
    );

    // Clean up the agent-client process (its connection will have been
    // severed once the broker died; it should already be exiting or
    // exited with an error on its own, but this test must never itself
    // leak it regardless).
    let mut stderr_buf = String::new();
    let _ = agent_client
        .stderr
        .take()
        .expect("agent-client stderr must be piped")
        .read_to_string(&mut stderr_buf);
    force_kill(agent_client);
    let _ = stderr_buf; // kept for local debugging only; not asserted on.
}

#[test]
fn supervisor_exits_successfully_after_graceful_broker_shutdown() {
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
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !socket_path.exists() {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket_path.exists(), "broker did not become ready");

    let broker_pid = find_child_pid(supervisor_pid, Duration::from_secs(5))
        .expect("could not identify the supervised broker");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(broker_pid),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("failed to SIGTERM broker");

    let status = wait_for_exit(&mut supervisor, Duration::from_secs(15))
        .expect("supervisor did not exit after graceful broker shutdown");
    assert!(
        status.success(),
        "supervisor must preserve successful graceful broker exit: {status:?}"
    );
    assert!(
        !runtime_dir.exists(),
        "clean broker shutdown must remove the runtime directory"
    );
}
