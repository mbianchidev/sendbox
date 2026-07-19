//! Descendant-containment integration tests: proves properties about what
//! a *launched* process (and anything it might itself spawn) can and
//! cannot do, using the `exec-broker-test-helper` fixture binary
//! (`src/bin/test_helper.rs`) as the target. The broker only ever
//! allowlists `exec-broker-test-helper` here, in this test suite — never
//! in a production configuration (see `bin/broker.rs`'s CLI: the
//! allowlist is operator-supplied via repeated `--allow-exec` flags, and
//! these tests are the only place that ever passes this binary's own
//! compiled path).
//!
//! # Semantic boundary this file does NOT cross
//!
//! Every test here proves a property about *this one top-level request*:
//! the broker only ever policy-admits (allowlist/env/cwd checks) the
//! top-level `argv[0]` it is asked to run. Anything that top-level process
//! goes on to do (including spawning its own children, as
//! `exec-broker-test-helper recurse`/`highrisk` do) is never itself
//! re-parsed or re-evaluated against the policy engine — it is *only*
//! kernel-contained, by the process group placement (killable as a unit)
//! and the seccomp filter the launcher installed before `exec`ing the
//! top-level target (inherited, unmodifiable, by every descendant). These
//! tests demonstrate that kernel containment holds; they do not claim (and
//! this crate does not implement) recursive semantic/policy enforcement
//! over descendant processes' own behavior.
//!
//! Linux-gated, matching every other Linux-specific integration test in
//! this crate.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BROKER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker");
const LAUNCHER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-launcher");
const TEST_HELPER_EXE: &str = env!("CARGO_BIN_EXE_exec-broker-test-helper");

/// Mirrors `tests/broker_e2e.rs`'s `TestBroker` helper (kept as an
/// independent copy rather than a shared module: integration test files
/// in this crate are each compiled as their own separate test binary, so
/// there is no straightforward way to share code between them without
/// introducing a `tests/support/` library crate, which is out of scope
/// for this change).
struct TestBroker {
    child: Child,
    _tempdir: tempfile::TempDir,
    runtime_dir: PathBuf,
    root: PathBuf,
}

/// Marks this test binary's process as a `PR_SET_CHILD_SUBREAPER`
/// (see [`exec_broker_spike::supervisor::become_child_subreaper`]),
/// exactly once no matter how many `TestBroker`s this process starts
/// across however many parallel test threads. This file in particular
/// spawns `exec-broker-test-helper recurse`/`highrisk`/`longlived`
/// descendants specifically to prove containment properties about
/// them — the same descendants that would otherwise leak as permanent
/// zombies if this `TestBroker` is killed mid-test (before the broker
/// itself has reaped them), since a real container's PID 1 does not
/// reap unrelated processes reparented to it. With this, such
/// descendants reparent to *this* test binary process instead, where
/// [`TestBroker::drop`] can actually reap them after killing their
/// process group.
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

    fn run_agent(&self, extra_args: &[&str], argv: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_exec-broker-agent"))
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
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        // Best-effort: if the runtime directory (and its pgid registry)
        // still exists, kill every process group the broker registered
        // *before* killing the broker itself — mirrors what a real
        // deployment's supervisor does on unexpected broker death (see
        // `exec_broker_spike::supervisor::kill_all_registered`). This is
        // what prevents this file's `recurse`/`highrisk`/`longlived`
        // descendant tests from leaking an orphaned process tree as
        // permanent zombies when the `TestBroker` is torn down at the
        // end of the test, before the broker itself would otherwise
        // have reaped those descendants on its own.
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
        exec_broker_spike::supervisor::reap_available_children(Duration::from_secs(2));
    }
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A launched target that concurrently floods both stdout and stderr well
/// past the broker's per-stream byte cap must still run to completion
/// (proving the broker's concurrent stdout+stderr draining cannot
/// deadlock against each other or against the client) with both streams
/// independently truncated, not merely one of them.
#[test]
fn flood_stdout_and_stderr_concurrently_does_not_deadlock_and_both_are_bounded() {
    let broker = TestBroker::start(&[TEST_HELPER_EXE]);

    // 4 MiB per stream is well above the crate's default 1 MiB per-stream
    // cap (`ProcessLimits::max_stream_bytes`), so truncation on *both*
    // streams is actually exercised, not merely plausible. A generous but
    // bounded `--timeout-ms` is a safety net, not the expected path: a
    // correctly-draining broker completes this in well under a second, so
    // hitting the timeout at all (`exit code 124`) is itself treated as a
    // failure below, distinguishing "finished normally" from "eventually
    // killed by the safety net after stalling."
    let started = Instant::now();
    let output = broker.run_agent(
        &["--timeout-ms", "20000"],
        &[TEST_HELPER_EXE, "flood", "--bytes=4194304"],
    );
    let elapsed = started.elapsed();

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected the flood target to exit(0) normally (not be killed by the \
         --timeout-ms safety net, which would indicate a stall/deadlock); \
         stderr={}",
        stderr_str(&output)
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "concurrent stdout+stderr flood took {elapsed:?}, suspiciously close \
         to the safety-net timeout; expected well under a second if draining \
         genuinely never blocks"
    );

    let stderr = stderr_str(&output);
    let stdout = output.stdout;

    assert!(
        !stdout.is_empty(),
        "expected at least some flooded stdout bytes to have reached the client"
    );
    assert!(
        stdout.len() <= 1024 * 1024,
        "stdout must be bounded at the broker's per-stream cap (1 MiB); got {} bytes",
        stdout.len()
    );
    assert!(
        stdout.iter().all(|&b| b == b'O'),
        "every decoded stdout byte must be part of the flood's own 'O' \
         pattern; the truncation-cap bookkeeping must not corrupt content"
    );

    assert!(
        stderr.contains("(stream truncated by broker-side cap)"),
        "expected at least one truncated chunk reported for the client's \
         own stderr diagnostic stream; stderr={stderr}"
    );
    let flooded_stderr_bytes = stderr.bytes().filter(|&b| b == b'E').count();
    assert!(
        flooded_stderr_bytes > 0 && flooded_stderr_bytes <= 1024 * 1024,
        "expected a nonzero, capped number of flooded 'E' stderr bytes to \
         have reached the client (bounded at the broker's 1 MiB per-stream \
         cap); got {flooded_stderr_bytes}"
    );
}

/// A launched target's descendant-containment properties: a process
/// placed into a broker-registered process group by the launcher (and
/// anything it might spawn) must never be able to `setsid`/`setpgid`
/// itself out of that group, nor perform any of a representative sample
/// of other high-risk syscalls this crate's seccomp profiles
/// unconditionally deny (`memfd_create`, `ptrace`, the raw
/// `io_uring_setup` syscall). This is a *kernel-level* containment
/// property, proven directly against the real, running seccomp filter —
/// not a claim that the broker recursively semantically parses or
/// re-evaluates anything this descendant subsequently attempts.
#[test]
fn launcher_descendant_cannot_leave_process_group_or_perform_highrisk_syscalls() {
    let broker = TestBroker::start(&[TEST_HELPER_EXE]);

    let output = broker.run_agent(&["--timeout-ms", "10000"], &[TEST_HELPER_EXE, "highrisk"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "the highrisk probe target itself must exit(0) (it never actually \
         executes anything dangerous, only attempts and reports); stderr={}",
        stderr_str(&output)
    );

    let stdout = stdout_str(&output);
    let mut seen = std::collections::HashSet::new();
    let mut checked = 0usize;
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let value: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line was not JSON: {line}: {e}"));
        let name = value["name"]
            .as_str()
            .unwrap_or_else(|| panic!("line missing 'name': {line}"))
            .to_string();
        let kind = value["outcome"]["kind"]
            .as_str()
            .unwrap_or_else(|| panic!("line missing outcome.kind: {line}"));
        assert_eq!(
            kind, "Denied",
            "expected {name:?} to be denied for a launched descendant; got \
             {kind:?} (line: {line})"
        );
        seen.insert(name);
        checked += 1;
    }

    assert!(
        checked > 0,
        "the highrisk probe printed no JSON lines at all"
    );
    for expected in [
        "setsid",
        "setpgid",
        "memfd_create",
        "ptrace_traceme",
        "raw_io_uring_setup",
    ] {
        assert!(
            seen.contains(expected),
            "expected a {expected:?} attempt to have been reported; saw: {seen:?}"
        );
    }
}

/// Process creation for a launched descendant subtree is bounded: this
/// crate's `contained-launcher` applies `RLIMIT_NPROC = 256` (both soft and
/// hard) to itself immediately before `exec`ing the target, and that limit
/// is inherited by everything the target subsequently forks. For a
/// genuinely unprivileged caller this must actually be observed to fail
/// process creation somewhere within generous depth/time bounds — for
/// `uid 0`, the Linux kernel exempts processes holding `CAP_SYS_RESOURCE`
/// (which `root` retains by default) from `RLIMIT_NPROC` enforcement
/// entirely, so this test explicitly does *not* treat root exhausting the
/// depth/time bound as proof of anything: it reports a typed environment
/// limitation instead of a false pass. See `tests/live_environment.rs` for
/// the corresponding hosted-unprivileged-required capability probe.
#[test]
fn process_creation_is_bounded_for_a_launched_descendant_subtree() {
    let euid = nix::unistd::geteuid().as_raw();
    let broker = TestBroker::start(&[TEST_HELPER_EXE]);

    let output = broker.run_agent(
        &["--timeout-ms", "15000"],
        &[
            TEST_HELPER_EXE,
            "recurse",
            "--max-depth=100000",
            "--time-budget-secs=8",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "the recurse target always exits(0) itself regardless of how the \
         recursion stopped; stderr={}",
        stderr_str(&output)
    );

    let stdout = stdout_str(&output);
    let last_line = stdout
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or_else(|| panic!("recurse target printed no JSON at all; stdout={stdout}"));
    let value: serde_json::Value = serde_json::from_str(last_line)
        .unwrap_or_else(|e| panic!("last line was not JSON: {last_line}: {e}"));
    let stopped_reason = value["stopped_reason"]
        .as_str()
        .unwrap_or_else(|| panic!("missing stopped_reason: {value}"));

    if euid == 0 {
        eprintln!(
            "ENVIRONMENT LIMITATION: running as uid 0 (euid={euid}); the \
             Linux kernel exempts CAP_SYS_RESOURCE-holding processes (root, \
             by default) from RLIMIT_NPROC enforcement, so this run cannot \
             prove process-creation is actually bounded for this uid \
             (stopped_reason={stopped_reason:?}). This is a typed \
             environment limitation, not a false pass: this test does not \
             assert strict enforcement for uid 0. See \
             tests/live_environment.rs, which reports this same limitation \
             explicitly and requires a genuinely unprivileged run for the \
             strict hosted proof."
        );
    } else {
        assert_eq!(
            stopped_reason, "ForkFailed",
            "expected process creation to actually fail (RLIMIT_NPROC=256 \
             exhausted) for a genuinely unprivileged caller (euid={euid}) \
             well within the depth/time bounds given; got {stopped_reason:?} \
             instead, meaning the limit was never actually exercised: {value}"
        );
    }
}
