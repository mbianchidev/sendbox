//! Library logic for the `exec-broker-supervisor` binary: starts the
//! broker as a child process, and — should the broker die for any reason
//! — kills every process group it had registered in the shared
//! [`PgidRegistry`], then removes the runtime directory's artifacts
//! (socket, registry file, directory itself).
//!
//! # Why a separate process at all
//!
//! The broker's own seccomp filter ([`crate::platform::SeccompProfile::Broker`])
//! and the fact that it may itself be killed (OOM, operator error, a bug)
//! mean it cannot be relied upon to clean up after itself. The supervisor
//! is the trusted parent that outlives it and is the single place
//! responsible for guaranteeing "no orphaned sandboxed process group
//! survives broker death."
//!
//! The supervisor must not itself be a descendant of the (conceptually)
//! seccomp-filtered agent process — it is started directly, alongside (not
//! underneath) the agent, precisely so that nothing the agent's filter
//! denies can ever affect the supervisor's own ability to manage the
//! broker.
//!
//! # The narrow spawn-before-registration race
//!
//! See [`crate::pgid_registry`] for the detailed explanation: a process
//! group spawned by the broker microseconds before the broker itself is
//! killed, and not yet written into the registry file, will not be found
//! by [`kill_all_registered`] and will be leaked. This is an accepted,
//! documented Phase 1 limitation; production hardening requires an
//! atomic cgroup/`clone3`-based containment scheme that does not depend on
//! a registry write happening at all.
//!
//! # Zombie reaping via `PR_SET_CHILD_SUBREAPER`
//!
//! Killing a registered process group with `SIGKILL` guarantees it stops
//! running, but does not by itself guarantee something calls `wait()` on
//! it afterward — without that, a killed process lingers as a zombie
//! (consuming a process-table slot, though nothing else) under whatever
//! process it gets reparented to once its original parent (the broker)
//! is gone. This module marks the supervisor itself as a "child
//! subreaper" ([`become_child_subreaper`]) specifically so that such
//! reparenting lands on *this* process rather than falling through to the
//! system's real init (which, especially in a minimal container without
//! its own reaping loop, may never reap unrelated zombies at all), and
//! then reaps everything it can ([`reap_available_children`]) right after
//! killing. This is best-effort, not a total guarantee: a killed
//! descendant that had itself forked further descendants before dying can
//! still leave those specifically as zombies if they get reparented
//! elsewhere first.

#![forbid(unsafe_code)]

use crate::broker::runtime_dir::RuntimeDir;
use crate::error::BrokerError;
use crate::pgid_registry::PgidRegistry;
use nix::errno::Errno;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tokio::process::Command;

/// One registered PGID that could not be confirmed killed with `SIGKILL`
/// for a reason other than `ESRCH` (which is expected/tolerated: the
/// group had already exited on its own before the supervisor got to it).
/// Surfaced explicitly by [`kill_all_registered`] rather than silently
/// discarded, so a caller can log and/or fail loudly instead of
/// pretending cleanup fully succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillFailure {
    pub pgid: i32,
    pub errno: i32,
}

/// The result of checking whether a registered `pgid` still plausibly
/// refers to the same process group this crate spawned and registered,
/// immediately before attempting to kill it. See [`pgid_liveness`] for
/// the full rationale and its documented residual limitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PgidLiveness {
    /// A process with pid == `pgid` still exists and is still its own
    /// process group's leader: the strongest ownership signal available
    /// without kernel-level pidfd/cgroup tracking.
    LiveAndOwned,
    /// No process with pid == `pgid` exists anymore (the original leader
    /// has exited), but a `killpg(pgid, 0)` existence probe shows the
    /// process group itself still has at least one live member (e.g. a
    /// descendant that inherited the pgid after the leader execed and
    /// later exited). Still killed: failing to do so would leak exactly
    /// the orphaned descendant this function exists to prevent.
    LiveButLeaderGone,
    /// A process with pid == `pgid` exists, but it is no longer the
    /// leader of a process group equal to `pgid` — i.e. this pid has
    /// almost certainly been reused by an unrelated process since this
    /// entry was registered. Not killed, to avoid signaling an unrelated
    /// process; logged instead of silently skipped.
    LikelyStalePidReuse,
    /// Nothing found alive at all: the group has already fully exited.
    /// Not an error — this is the common, expected case for a
    /// short-lived brokered command that already completed.
    Gone,
}

/// Checks [`PgidLiveness`] for `pgid` before [`kill_all_registered`]
/// attempts to kill it.
///
/// This crate always spawns a registered process group with
/// `.process_group(0)` (see `broker::process`), which sets the new pgid
/// equal to the *leader* process's own pid at spawn time. So if a process
/// with that same pid still exists and its own current process group is
/// still that exact value, this is a meaningful ownership signal — not a
/// perfect one, since a pid can in principle be reused by an unrelated
/// process that also happens to be its own group leader, but a real
/// improvement over killing blind.
///
/// If the leader pid no longer exists (e.g. it execed the target, which
/// later exited itself, but left further descendants running under the
/// same inherited pgid — an entirely ordinary case this crate must still
/// catch to avoid leaking those descendants as orphans), this function
/// cannot re-verify ownership through the (now-gone) leader, and instead
/// falls back to a plain `killpg(pgid, 0)` existence probe. That probe
/// cannot distinguish a genuinely-still-alive group this crate owns from
/// an unrelated process that happens to have been assigned the exact same
/// pgid number after full reuse of both the leader's pid and every
/// original member's pid. This residual gap is the same class of
/// limitation already documented for the narrow spawn-before-registration
/// race in [`crate::pgid_registry`]; closing it fully requires the same
/// cgroup/`clone3`-based containment scheme described there.
fn pgid_liveness(pgid: i32) -> PgidLiveness {
    match nix::unistd::getpgid(Some(Pid::from_raw(pgid))) {
        Ok(pgrp) if pgrp.as_raw() == pgid => PgidLiveness::LiveAndOwned,
        Ok(_different_pgrp) => PgidLiveness::LikelyStalePidReuse,
        Err(Errno::ESRCH) => match signal::killpg(Pid::from_raw(pgid), None) {
            Ok(()) => PgidLiveness::LiveButLeaderGone,
            Err(_) => PgidLiveness::Gone,
        },
        Err(_) => PgidLiveness::Gone,
    }
}

/// Kills every process group currently listed in `registry` with
/// `SIGKILL`, after a best-effort [`pgid_liveness`] check for each entry.
/// Returns every kill attempt that failed for a reason other than
/// `ESRCH` (already-exited groups are expected and not reported as
/// failures) so a caller can surface them explicitly rather than
/// silently discarding them, as this function itself never does.
pub fn kill_all_registered(registry: &PgidRegistry) -> std::io::Result<Vec<KillFailure>> {
    let mut failures = Vec::new();
    for pgid in registry.read_all()? {
        if pgid <= 0 {
            continue;
        }
        match pgid_liveness(pgid) {
            PgidLiveness::Gone => {}
            PgidLiveness::LikelyStalePidReuse => {
                eprintln!(
                    "exec-broker-supervisor: warning: registered pgid {pgid} no longer looks \
                     owned (its pid is alive but is no longer that same process group's \
                     leader); skipping SIGKILL to avoid signaling an unrelated process. This is \
                     a documented PID/PGID-reuse limitation (see `pgid_liveness`), not a \
                     cleanup failure."
                );
            }
            PgidLiveness::LiveAndOwned | PgidLiveness::LiveButLeaderGone => {
                if let Err(errno) = signal::killpg(Pid::from_raw(pgid), Signal::SIGKILL)
                    && errno != Errno::ESRCH
                {
                    failures.push(KillFailure {
                        pgid,
                        errno: errno as i32,
                    });
                }
            }
        }
    }
    registry.clear()?;
    Ok(failures)
}

/// Marks this process as a "child subreaper"
/// ([`prctl(2)`](https://man7.org/linux/man-pages/man2/prctl.2.html)'s
/// `PR_SET_CHILD_SUBREAPER`), so that any descendant reparented away from
/// its original (now-dead) parent — e.g. a brokered process group whose
/// broker was just killed — is re-parented to *this* process instead of
/// falling through to the system's real init/PID 1. Without this, such a
/// descendant would still be genuinely killed by [`kill_all_registered`],
/// but this process would have no way to reap it, and it would linger as
/// a zombie under whatever process (often an init that never reaps
/// unrelated zombies) it fell through to instead. Best-effort: if the
/// kernel does not support this (`prctl` failure), cleanup still SIGKILLs
/// every registered group, it just cannot also guarantee those zombies
/// get reaped by *this* process specifically.
///
/// `pub`, not merely an internal detail of `supervise_once`: this
/// crate's own integration test harnesses (`tests/broker_e2e.rs`,
/// `tests/raw_frame_boundary.rs`) run an `exec-broker` directly, without
/// a real supervisor wrapping it, and need this exact same mechanism so
/// that abruptly killing a `TestBroker` mid-test (before it has finished
/// reaping its own just-spawned launcher/target processes) does not leak
/// an orphaned zombie under the test binary's own process the same way
/// it would under a real, un-subreaped container init.
pub fn become_child_subreaper() {
    if let Err(err) = nix::sys::prctl::set_child_subreaper(true) {
        eprintln!(
            "exec-broker-supervisor: warning: failed to become a child subreaper ({err}); \
             killed descendants reparented away from the broker may linger as zombies under \
             whatever process they fall through to instead, until that process reaps them"
        );
    }
}

/// Reaps every already-exited (or now-exiting, e.g. because
/// [`kill_all_registered`] just `SIGKILL`ed it) child of this process,
/// bounded by `timeout`. This only has an effect on descendants that were
/// actually reparented to this process by [`become_child_subreaper`]; it
/// is a best-effort pass, not a guarantee, since a descendant that
/// forked further descendants of its own before being killed may still
/// leave *those* as zombies if they in turn get reparented to some other
/// subreaper first (e.g. the system's real init).
///
/// `pub` for the same reason [`become_child_subreaper`] is: this crate's
/// own `TestBroker` integration-test harnesses call it after killing a
/// standalone (supervisor-less) broker, to actually reap whatever
/// [`kill_all_registered`] just killed.
pub fn reap_available_children(timeout: std::time::Duration) {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(_) => {
                // Reaped one; a killed process group can have more than
                // one member, so keep going until nothing is left.
            }
            Err(Errno::ECHILD) => break, // no children at all: done.
            Err(_) => break,
        }
    }
}

/// for it to exit (for any reason: normal exit, crash, being killed), then
/// performs the death-triggered cleanup: kill every registered process
/// group and remove the runtime directory.
///
/// `runtime_dir_path` and `registry` are **not** created by this
/// function — the broker itself is responsible for creating (and, on
/// clean shutdown, already having removed) its own runtime directory,
/// matching the "broker startup rejects unsafe stale path/replacement"
/// requirement. The supervisor only *attaches* to whatever the broker
/// left behind after it exits, via [`RuntimeDir::open_existing`], and
/// tolerates the directory already being gone (the broker's own clean
/// shutdown path already removed it) as a no-op rather than an error.
///
/// # Restart is not supported
///
/// This function does not loop or restart the broker after it exits; it
/// performs exactly one supervise-then-cleanup cycle and returns. Restart
/// is unsupported by design, in the same sense
/// [`RuntimeDir::create_fresh`] documents: the runtime directory (and
/// therefore the socket path, and the meaning of "the current broker
/// instance") is single-use per process lifetime. A caller that wants a
/// new broker instance must provision a fresh runtime directory rather
/// than reusing this one.
pub async fn supervise_once(
    broker_binary: &std::path::Path,
    broker_args: &[String],
    runtime_dir_path: &std::path::Path,
    registry: PgidRegistry,
) -> Result<std::process::ExitStatus, BrokerError> {
    let mut command = Command::new(broker_binary);
    command.args(broker_args);

    become_child_subreaper();

    let mut broker = command.spawn().map_err(BrokerError::Io)?;
    let status = broker.wait().await.map_err(BrokerError::Io)?;

    // A clean broker shutdown removes the complete runtime directory only
    // after every connection task and registered process group has finished.
    // The registry disappeared with that directory, so there is nothing left
    // for the supervisor to sweep.
    match std::fs::symlink_metadata(runtime_dir_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            reap_available_children(std::time::Duration::from_secs(2));
            return Ok(status);
        }
        Err(error) => return Err(BrokerError::Io(error)),
        Ok(_) => {}
    }

    // The broker is gone (however that happened): sweep every process
    // group it had registered, then remove every artifact of this runtime
    // instance, if it is still there. Cleanup errors are surfaced, not
    // discarded: a caller (the `exec-broker-supervisor` binary) must exit
    // non-zero if an orphan may remain, rather than silently reporting
    // success.
    let kill_failures = kill_all_registered(&registry).map_err(BrokerError::Io)?;
    for failure in &kill_failures {
        eprintln!(
            "exec-broker-supervisor: error: failed to SIGKILL registered pgid {} (errno {})",
            failure.pgid, failure.errno
        );
    }
    // Give any process just SIGKILLed above (now reparented to this
    // subreaper) a bounded chance to actually be reaped, so it does not
    // linger as a zombie under this process.
    reap_available_children(std::time::Duration::from_secs(2));

    let runtime_dir_result: Result<(), BrokerError> =
        match RuntimeDir::open_existing(runtime_dir_path) {
            Ok(runtime_dir) => runtime_dir.remove().map_err(BrokerError::Io),
            Err(BrokerError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                // The broker's own clean-shutdown path already removed it.
                Ok(())
            }
            Err(err) => Err(err),
        };

    if !kill_failures.is_empty() {
        // Surface the kill failures even if runtime-dir removal itself
        // succeeded: a live orphaned process group is the more serious
        // problem, and must not be masked by an otherwise-clean-looking
        // `Ok` return.
        runtime_dir_result?;
        return Err(BrokerError::CleanupFailed(format!(
            "{} pgid(s): {}",
            kill_failures.len(),
            kill_failures
                .iter()
                .map(|f| format!("{}(errno {})", f.pgid, f.errno))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    runtime_dir_result?;

    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_all_registered_ignores_nonexistent_pgids_and_clears_registry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = PgidRegistry::new(dir.path().join("pgids.json"));
        // Extremely unlikely to be a live PGID in any test environment.
        registry.register(999_999).expect("register");

        let failures =
            kill_all_registered(&registry).expect("kill_all_registered must tolerate ESRCH");
        assert!(
            failures.is_empty(),
            "a nonexistent pgid must not be reported as a kill failure: {failures:?}"
        );
        assert!(registry.read_all().expect("read_all").is_empty());
    }

    #[tokio::test]
    async fn supervise_once_cleans_up_runtime_dir_after_broker_exits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime_path = dir.path().join("runtime");
        let runtime = RuntimeDir::create_fresh(&runtime_path).expect("create_fresh");
        let registry_path = runtime.path().join("pgids.json");
        let registry = PgidRegistry::new(&registry_path);
        drop(runtime);

        // Use `/bin/true` as a stand-in "broker" that exits immediately,
        // to exercise the supervise-then-cleanup cycle without needing a
        // real broker binary in this unit test.
        let status = supervise_once(
            std::path::Path::new("/bin/true"),
            &[],
            &runtime_path,
            registry,
        )
        .await
        .expect("supervise_once");

        assert!(status.success());
        assert!(!runtime_path.exists());
    }

    #[tokio::test]
    async fn supervise_once_tolerates_broker_already_having_removed_the_runtime_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime_path = dir.path().join("runtime");
        let registry = PgidRegistry::new(runtime_path.join("pgids.json"));

        // The runtime directory never existed here, simulating a broker
        // that already cleanly shut down and removed it itself.
        let status = supervise_once(
            std::path::Path::new("/bin/true"),
            &[],
            &runtime_path,
            registry,
        )
        .await
        .expect("supervise_once must tolerate an already-removed runtime dir");

        assert!(status.success());
    }
}
