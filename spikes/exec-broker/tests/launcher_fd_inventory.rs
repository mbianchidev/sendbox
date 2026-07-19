//! Proves `exec-broker-launcher` inherits a minimal, CLOEXEC-hygienic set
//! of open file descriptors: this test spawns the launcher binary
//! *directly* (no broker in the loop, but using the exact same
//! `tokio::process::Command` spawn path `src/broker/server.rs` uses) with
//! a hand-crafted [`exec_broker_spike::launcher::LauncherEnvelope`] whose
//! target is `/usr/bin/ls -1 /proc/self/fd`, so the target process itself
//! reports exactly which file descriptors it inherited across the
//! launcher's own `exec`.
//!
//! This is a meaningful CLOEXEC check, not a tautology: the test process
//! deliberately keeps open, across the spawn, examples of every kind of
//! resource the real broker holds open while it spawns a launcher — an
//! ordinary [`std::fs::File`] (standing in for the PGID registry /
//! session credential file) and a bound [`tokio::net::UnixListener`]
//! (standing in for the broker's own accept socket) — neither of which
//! may appear in the child's `/proc/self/fd` listing. Rust's standard
//! `File`/`tokio::net` types already set `FD_CLOEXEC` by default, so a
//! clean result here also guards against a future change accidentally
//! opening a resource in a way that disables that (e.g. a raw `libc::open`
//! call, or an explicit `pre_exec` hook).
//!
//! Linux-gated, matching every other integration test in this crate.

#![cfg(target_os = "linux")]

use exec_broker_spike::launcher::{LauncherEnvelope, encode_envelope_for_launcher};
use exec_broker_spike::policy::{PolicySnapshot, ValidatedExecute};
use exec_broker_spike::protocol::Limits;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn launcher_target_inherits_only_stdio_file_descriptors() {
    let launcher_exe = env!("CARGO_BIN_EXE_exec-broker-launcher");
    let tempdir = tempfile::tempdir().expect("tempdir");
    let cwd = tempdir.path().to_path_buf();

    // Stand-ins for the two kinds of long-lived resources the real
    // broker holds open while it spawns a launcher: a plain file (like
    // the PGID registry / session credential file) and a bound Unix
    // socket listener (the broker's own accept socket). Both are opened
    // through the same standard-library / tokio APIs the real broker
    // uses, and both are kept alive across the spawn below.
    let extra_file_path = tempdir.path().join("extra-open-file");
    let _extra_file = std::fs::File::create(&extra_file_path).expect("create extra file");
    let extra_socket_path = tempdir.path().join("extra.sock");
    let _extra_listener =
        tokio::net::UnixListener::bind(&extra_socket_path).expect("bind extra listener");

    let ls_path = PathBuf::from("/usr/bin/ls");
    let validated = ValidatedExecute {
        correlation_id: "fd-inventory-test".to_string(),
        argv: vec![
            "/usr/bin/ls".to_string(),
            "-1".to_string(),
            "/proc/self/fd".to_string(),
        ],
        canonical_executable: ls_path.clone(),
        canonical_cwd: cwd.clone(),
        env: {
            let mut env = BTreeMap::new();
            env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
            env.insert("LANG".to_string(), "C.UTF-8".to_string());
            env
        },
        timeout: Duration::from_secs(5),
    };
    let policy_snapshot = PolicySnapshot {
        allowed_root: cwd,
        allowlisted_executables: BTreeSet::from([ls_path]),
        fixed_path: "/usr/bin:/bin".to_string(),
        fixed_lang: "C.UTF-8".to_string(),
        limits: Limits::default(),
    };
    let envelope = LauncherEnvelope {
        validated,
        policy_snapshot,
    };
    let stdin_payload =
        encode_envelope_for_launcher(&envelope).expect("encode envelope for launcher");

    // The exact spawn pattern `handle_execute` in `src/broker/server.rs`
    // uses: `tokio::process::Command`, piped stdin/stdout/stderr, write
    // the envelope, then read the output back.
    let mut child = tokio::process::Command::new(launcher_exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn exec-broker-launcher");

    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(&stdin_payload)
        .await
        .expect("write envelope to launcher stdin");

    let output = child
        .wait_with_output()
        .await
        .expect("wait for launcher/target");

    assert!(
        output.status.success(),
        "expected `ls /proc/self/fd` (via the launcher/target) to succeed: \
         status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("ls output must be valid UTF-8");
    let mut fds: Vec<i32> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.trim()
                .parse::<i32>()
                .unwrap_or_else(|e| panic!("unexpected non-numeric fd entry {line:?}: {e}"))
        })
        .collect();
    fds.sort_unstable();

    // Expected: 0 (stdin), 1 (stdout), 2 (stderr), and exactly one
    // additional fd that `ls` itself opens to read the `/proc/self/fd`
    // directory entries it is listing. Neither the extra file nor the
    // extra Unix listener kept open in this test process may appear.
    assert!(
        fds.contains(&0) && fds.contains(&1) && fds.contains(&2),
        "expected stdio fds 0,1,2 present in launcher target's fd list: {fds:?}"
    );
    assert!(
        fds.len() <= 4,
        "launcher target inherited more file descriptors than expected \
         (stdio + at most one fd `ls` itself opens to read the directory); \
         this likely means a resource the broker holds open (file, socket) \
         is missing FD_CLOEXEC: {fds:?}"
    );
}
