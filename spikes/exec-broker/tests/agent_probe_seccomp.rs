//! Integration test proving the `exec-broker-agent probe` binary's core
//! security claim end-to-end: after the trusted-bootstrap sequence
//! (`PR_SET_NO_NEW_PRIVS` + the `AgentBootstrap` seccomp filter with
//! `TSYNC`) runs, every attempted exec-family primitive — including one
//! issued from a second thread that never itself called `seccomp()`,
//! proving `TSYNC` propagation — is denied by the kernel rather than
//! succeeding.
//!
//! This spawns the actual compiled binary (via `CARGO_BIN_EXE_...`) rather
//! than calling probe logic in-process, because installing a real seccomp
//! filter that denies `execve`/`memfd_create`/etc. is one-way and would
//! otherwise contaminate the shared `cargo test` process for every other
//! test running alongside it.
//!
//! Per the task's scope, this is intentionally the one targeted
//! integration test proving the TSYNC/EPERM bootstrap guarantee; the
//! broader adversarial/integration suite (full broker/launcher/supervisor
//! end-to-end exercises) is deferred to a later task.

#[cfg(target_os = "linux")]
#[test]
fn probe_reports_every_exec_attempt_denied() {
    use std::process::Command;

    let exe = env!("CARGO_BIN_EXE_exec-broker-agent");
    let output = Command::new(exe)
        .arg("probe")
        .output()
        .expect("failed to run exec-broker-agent probe");

    assert!(
        output.status.success(),
        "probe subcommand exited non-zero: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("probe stdout must be valid UTF-8");
    let mut seen_names = std::collections::HashSet::new();
    let mut line_count = 0;
    let mut outcomes: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();

    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        line_count += 1;
        let value: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line was not JSON: {line}: {e}"));

        let name = value["name"]
            .as_str()
            .unwrap_or_else(|| panic!("line missing string 'name' field: {line}"))
            .to_string();
        seen_names.insert(name.clone());

        let kind = value["outcome"]["kind"]
            .as_str()
            .unwrap_or_else(|| panic!("line missing outcome.kind: {line}"));

        // The only two acceptable outcomes are:
        //  - "Denied": the kernel returned EPERM (or another errno) for
        //    the attempted syscall, proving the filter is in effect.
        //  - "SetupFailed": the *setup* for the attempt itself was denied
        //    first — an even stronger defense-in-depth signal, not a test
        //    failure, but (see below) not acceptable for the fd-based
        //    attempts, whose fds are guaranteed to already exist by the
        //    time the probe runs.
        // "UnexpectedSuccess" must never appear: it would mean this
        // process's image was actually replaced, i.e. the sandbox failed.
        assert_ne!(
            kind, "UnexpectedSuccess",
            "attempt {name:?} unexpectedly succeeded at replacing the process image: {line}"
        );
        assert!(
            kind == "Denied" || kind == "SetupFailed",
            "unexpected outcome kind {kind:?} for attempt {name:?}: {line}"
        );
        outcomes.insert(name, value["outcome"].clone());
    }

    assert!(line_count > 0, "probe printed no JSON lines at all");

    // These attempts target something that is guaranteed to already exist
    // by the time the probe runs (`/bin/true` itself, or a memfd/fd that
    // the agent's trusted-bootstrap sequence created and populated
    // *before* installing the filter — see `bin/agent.rs`'s `run`): a
    // `SetupFailed` outcome for any of these would mean the fd-based
    // `execveat` denial was never actually exercised at all, which must
    // be treated as a hard test failure, not tolerated as
    // defense-in-depth. Each of these must report `Denied` with the
    // actual `EPERM` errno the kernel returned for the syscall itself.
    const EPERM: i64 = 1;
    let must_be_denied_with_eperm = [
        "libc_execve_bin_true",
        "raw_syscall_execve_bin_true",
        "libc_execveat_memfd",
        "raw_syscall_execveat_memfd",
        "libc_execveat_bin_true_fd",
        "raw_syscall_execveat_bin_true_fd",
        "libc_execve_proc_self_exe",
        "second_thread_tsync_execve_bin_true",
    ];
    for name in must_be_denied_with_eperm {
        let outcome = outcomes
            .get(name)
            .unwrap_or_else(|| panic!("expected attempt {name:?} to have been reported"));
        let kind = outcome["kind"].as_str().unwrap_or_default();
        assert_eq!(
            kind, "Denied",
            "attempt {name:?} must report an actual kernel denial (not SetupFailed/other), \
             proving the seccomp filter denies the syscall itself against an fd/path that \
             genuinely already exists; got: {outcome:?}"
        );
        let errno = outcome["errno"].as_i64();
        assert_eq!(
            errno,
            Some(EPERM),
            "attempt {name:?} must be denied with EPERM specifically (the errno this crate's \
             seccomp filters use for every deny rule); got: {outcome:?}"
        );
    }

    // Specifically confirm the second-thread TSYNC proof attempt ran and
    // was included, not merely that *some* lines were emitted.
    assert!(
        seen_names.contains("second_thread_tsync_execve_bin_true"),
        "expected the second-thread TSYNC proof attempt to be reported; saw: {seen_names:?}"
    );
}

/// On non-Linux targets the binary must not attempt any of the
/// Linux-specific bootstrap/probe logic at all; it should fail fast with
/// an explicit "unsupported platform" message and a non-zero exit code.
#[cfg(not(target_os = "linux"))]
#[test]
fn probe_reports_unsupported_platform_on_non_linux() {
    use std::process::Command;

    let exe = env!("CARGO_BIN_EXE_exec-broker-agent");
    let output = Command::new(exe)
        .arg("probe")
        .output()
        .expect("failed to run exec-broker-agent probe");

    assert!(
        !output.status.success(),
        "expected non-zero exit on non-Linux platforms"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("requires linux"),
        "expected a platform-mismatch message on stderr, got: {stderr}"
    );
}
