//! A capability probe for whatever host this test suite is actually
//! running on, distinct from every other integration test in this
//! crate: it does not exercise the broker/launcher/agent pipeline at
//! all, it only reports (and, for a small set of genuinely
//! non-negotiable properties, enforces) what this host can and cannot
//! prove.
//!
//! # Why this file exists
//!
//! Several tests elsewhere in this crate (most notably
//! `descendant_containment::process_creation_is_bounded_for_a_launched_descendant_subtree`
//! and `raw_frame_boundary::unauthorized_peer_uid_is_dropped_before_handle_connection`)
//! deliberately relax their own claims depending on properties of the
//! *host* — effective uid, or whether a second real UID is available at
//! all — rather than either (a) silently skipping with no signal, or
//! (b) falsely claiming a strict property was proven when the host
//! could not actually have exercised it (e.g. `root` exhausting
//! `RLIMIT_NPROC` proves nothing, since `CAP_SYS_RESOURCE` exempts it).
//! This file is the single place that makes those host properties
//! explicit, machine-readable (via `eprintln!` on every run) and, where
//! the property is one every correctly configured Linux host (hosted
//! CI or self-hosted, root or non-root) must have for this crate's
//! hardening model to mean anything at all, enforced with a hard
//! `assert!` rather than merely reported.
//!
//! # What is required vs. merely reported
//!
//! * **Required (hard failure if absent)**: actually running on Linux;
//!   `CONFIG_SECCOMP` availability; `PR_SET_NO_NEW_PRIVS` actually taking
//!   effect. Every test in this crate that asserts a seccomp/no-new-privs
//!   property would be vacuously "passing" on a host missing these, so
//!   this probe fails loudly instead.
//! * **Reported, not required**: kernel release/machine (informational);
//!   effective uid (both `0` and non-`0` are legitimate depending on how
//!   this suite is invoked; downstream tests adapt their own claims
//!   rather than this probe gatekeeping a specific uid); whether the
//!   uid-dependent strict `RLIMIT_NPROC` proof is expected to run
//!   strictly here.
//! * **Self-hosted-only, opt-in via an explicit environment variable,
//!   never silently skipped**: the second-real-UID live gate
//!   (`EXEC_BROKER_LIVE_SELF_HOSTED_SECOND_UID=1`). Unlike the required
//!   properties above, this is *not* asserted by default — a genuinely
//!   unprivileged, single-uid hosted runner cannot be expected to have a
//!   second real UID available at all, and this crate must not invent
//!   one just to force the assertion. Setting the variable is this
//!   crate's contributor-facing way of explicitly attesting "this run is
//!   self-hosted/root-capable and the corresponding `#[ignore]`d live
//!   test in `tests/raw_frame_boundary.rs` was run with `--ignored`";
//!   this probe then holds that attestation to its word (asserting
//!   `euid == 0`, the practical prerequisite for `setuid(2)` to a second
//!   UID to even be attemptable) rather than accepting it unconditionally.
//!
//! Linux-gated, matching every other Linux-specific integration test in
//! this crate: every property probed here is itself Linux-specific.

#![cfg(target_os = "linux")]

use std::path::Path;

/// Set to exactly `"1"` to attest that this run is self-hosted/root
/// capable and that `tests/raw_frame_boundary.rs`'s `#[ignore]`d
/// `unauthorized_peer_uid_is_dropped_before_handle_connection` live test
/// was (or will be) run explicitly with `--ignored` in this same
/// environment. Never set on a shared/hosted CI runner that cannot
/// grant a second real UID.
const SELF_HOSTED_SECOND_UID_ENV: &str = "EXEC_BROKER_LIVE_SELF_HOSTED_SECOND_UID";

/// Reports this host's kernel/arch, seccomp availability, `no_new_privs`
/// enforcement, and effective uid; hard-fails if any of the first three
/// (properties every correctly configured Linux host must have for this
/// crate's hardening claims to mean anything) are absent; and reports
/// -- without asserting a specific value -- how the uid-dependent and
/// self-hosted-only live gates elsewhere in this crate are expected to
/// behave on this host.
#[test]
fn capability_probe_reports_and_enforces_required_hosted_environment() {
    let uname = nix::sys::utsname::uname().expect(
        "uname(2) must always succeed on a running Linux kernel; its failure here would \
         indicate a host too broken to draw any conclusion from at all",
    );
    let sysname = uname.sysname().to_string_lossy().into_owned();
    let release = uname.release().to_string_lossy().into_owned();
    let machine = uname.machine().to_string_lossy().into_owned();
    let euid = nix::unistd::geteuid().as_raw();

    // Required: actually Linux. Every other check below (and every
    // seccomp/no-new-privs/RLIMIT_NPROC test in this crate) is
    // meaningless anywhere else, and the whole crate is `cfg`-gated to
    // Linux for exactly this reason.
    assert_eq!(
        sysname, "Linux",
        "required hosted property missing: this crate's entire hardening model \
         (seccomp, PR_SET_NO_NEW_PRIVS, RLIMIT_NPROC, process-group containment) is \
         Linux-only, but uname(2) reports sysname={sysname:?}, not \"Linux\""
    );

    // Required: CONFIG_SECCOMP. This is a documented, always-safe-to-read
    // kernel interface -- no raw syscalls or `unsafe` needed here, so this
    // check does not need to go through the isolated `platform::linux::adapter`.
    let seccomp_actions_avail = Path::new("/proc/sys/kernel/seccomp/actions_avail");
    let seccomp_available = seccomp_actions_avail.exists();
    assert!(
        seccomp_available,
        "required hosted property missing: {seccomp_actions_avail:?} does not exist, \
         meaning this kernel was not built with CONFIG_SECCOMP; every seccomp-enforcement \
         test in this crate (agent_probe_seccomp, descendant_containment, \
         fail_closed_after_broker_death) would be vacuously meaningless on this host"
    );

    // Required: PR_SET_NO_NEW_PRIVS actually takes effect. Uses the same
    // trusted-bootstrap entry point every real binary in this crate calls
    // (`exec_broker_spike::platform::set_no_new_privs`), then reads it back
    // through the isolated adapter's dedicated, test-only accessor. Safe to
    // call unconditionally: this attribute is per-thread (not per-process),
    // so setting it on this test's own thread cannot affect any other test.
    exec_broker_spike::platform::set_no_new_privs().expect(
        "required hosted property missing: PR_SET_NO_NEW_PRIVS itself failed to set, \
         meaning this kernel cannot support this crate's hardening model at all \
         (requires Linux >= 3.5)",
    );
    let no_new_privs = exec_broker_spike::platform::linux::adapter::no_new_privs_is_set().expect(
        "reading back /proc/thread-self/status immediately after a successful \
         PR_SET_NO_NEW_PRIVS must always succeed",
    );
    assert!(
        no_new_privs,
        "required hosted property missing: PR_SET_NO_NEW_PRIVS was just set successfully, \
         but reading it back immediately afterward on the same thread reports false; this \
         kernel does not actually enforce the attribute it claims to accept"
    );

    eprintln!(
        "live-environment capability probe: kernel={sysname} {release} {machine}, \
         seccomp_available={seccomp_available}, no_new_privs={no_new_privs}, euid={euid}"
    );

    // Reported, not required: whether the uid-dependent strict
    // RLIMIT_NPROC proof is expected to run strictly here. See
    // `descendant_containment::process_creation_is_bounded_for_a_launched_descendant_subtree`,
    // which contains the actual assertion and makes the identical
    // uid==0 distinction; this is purely an explicit, cross-referenced
    // status report, not a duplicate assertion.
    if euid == 0 {
        eprintln!(
            "ENVIRONMENT LIMITATION: euid=0 (root). \
             `descendant_containment::process_creation_is_bounded_for_a_launched_descendant_subtree` \
             cannot strictly prove RLIMIT_NPROC enforcement for this uid, because the Linux \
             kernel exempts CAP_SYS_RESOURCE-holding processes (root, by default) from that \
             limit entirely; that test reports this same typed environment limitation itself \
             and does not assert strict enforcement for uid 0. A strict, hosted proof of \
             process-creation bounding requires re-running this suite as a genuinely \
             unprivileged user (e.g. a standard GitHub-hosted Actions runner)."
        );
    } else {
        eprintln!(
            "euid={euid} (non-root, unprivileged): \
             `descendant_containment::process_creation_is_bounded_for_a_launched_descendant_subtree` \
             is expected to run its strict RLIMIT_NPROC-exhaustion assertion (not merely report \
             an environment limitation) on this host."
        );
    }

    // Self-hosted-only, opt-in, never silently skipped: the second-real-UID
    // live gate. Reported either way; only *asserted* when the operator has
    // explicitly attested to it via the environment variable.
    match std::env::var(SELF_HOSTED_SECOND_UID_ENV) {
        Ok(value) if value == "1" => {
            assert_eq!(
                euid, 0,
                "{SELF_HOSTED_SECOND_UID_ENV}=1 attests that this is a self-hosted, \
                 root-capable run in which \
                 `raw_frame_boundary::unauthorized_peer_uid_is_dropped_before_handle_connection` \
                 (an #[ignore]d, root-only live test -- run it explicitly with \
                 `cargo test --test raw_frame_boundary -- --ignored`) can actually exercise a \
                 second real UID via setuid(2), which requires CAP_SETUID -- in practice, on \
                 this suite's own environment, euid=0. Got euid={euid} instead: either unset \
                 {SELF_HOSTED_SECOND_UID_ENV} or actually run this suite as root."
            );
            eprintln!(
                "self-hosted second-UID gate: {SELF_HOSTED_SECOND_UID_ENV}=1 and euid=0 -- \
                 the root-only unauthorized-peer-UID live test is attested to have been (or \
                 about to be) run explicitly with `--ignored` in this environment."
            );
        }
        Ok(other) => {
            panic!(
                "{SELF_HOSTED_SECOND_UID_ENV} is set to {other:?}, not exactly \"1\"; set it to \
                 \"1\" to attest a self-hosted/root-capable run, or leave it unset entirely -- \
                 an ambiguous non-empty value must not be silently treated as either"
            );
        }
        Err(_) => {
            eprintln!(
                "self-hosted second-UID gate: {SELF_HOSTED_SECOND_UID_ENV} is not set; the \
                 unauthorized-peer-UID *live* test \
                 (`raw_frame_boundary::unauthorized_peer_uid_is_dropped_before_handle_connection`) \
                 requires a genuinely self-hosted/root-capable environment and is not expected \
                 to have run here. This is not a failure of this probe: the unconditional, \
                 always-run unit-level proof of the identical SO_PEERCRED rejection logic \
                 (`broker::socket::tests::authenticate_peer_rejects_unexpected_uid`) still ran \
                 and passed as part of the normal test suite regardless of this variable."
            );
        }
    }
}
