//! Library logic for the `contained-launcher` binary: the small trusted
//! helper that the broker forks for every accepted `Execute` request.
//!
//! `contained-launcher` runs the following sequence, strictly in order,
//! before ever executing caller-controlled input:
//!
//! 1. `PR_SET_NO_NEW_PRIVS` + the [`SeccompProfile::Launcher`] filter
//!    (still permits `execve`/`execveat` for the target and its
//!    descendants, but denies `setsid`/`setpgid` so that the process group
//!    the broker placed this process into at spawn time cannot be
//!    escaped, and denies the same high-risk primitives every profile
//!    denies).
//! 2. Drop all capabilities.
//! 3. Apply default rlimits (`NOFILE`, `NPROC`, `CORE`, `FSIZE`, `AS`).
//! 4. Read a [`LauncherEnvelope`] as JSON from stdin (written by the
//!    broker immediately after fork, over a pipe — never via argv, so
//!    that potentially sensitive environment values never appear in
//!    `/proc/<pid>/cmdline`, and never via CLI flags, so this binary
//!    requires no policy configuration of its own). The envelope bundles
//!    the already-[`Policy::evaluate`]d [`ValidatedExecute`] together
//!    with an immutable [`PolicySnapshot`] of the exact policy the broker
//!    validated it against — derived solely from the broker's own trusted
//!    configuration, never from client-supplied data — so this process
//!    can reconstruct that same policy purely in-memory
//!    ([`Policy::from_snapshot`], no filesystem re-derivation, no CLI
//!    parsing of policy arguments) and re-validate independently.
//! 5. Re-validate the executable/cwd immediately before spawn via
//!    [`Policy::revalidate_before_spawn`], to narrow (though not fully
//!    eliminate — see [`BrokerError::ResidualToctou`]) the TOCTOU window
//!    between the broker's original validation and this moment.
//! 6. `env_clear()`, set exactly the validated env and cwd, then
//!    [`std::os::unix::process::CommandExt::exec`] the target directly.
//!    `exec` is a safe standard-library function (it does not require an
//!    `unsafe` block); this module forbids `unsafe` throughout.
//!
//! `contained-launcher` never invokes a shell and never calls
//! `/usr/bin/env`: `argv[0]` (already validated to be the canonical
//! executable path) is exec'd directly.

#![forbid(unsafe_code)]

use crate::error::{BrokerError, ProtocolError};
use crate::platform::{self, SeccompProfile};
use crate::policy::{Policy, PolicySnapshot, ValidatedExecute};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// What the broker sends `contained-launcher` over stdin for a single
/// execution: the already-validated request plus the exact policy
/// snapshot it was validated against, so the launcher never needs (and
/// never accepts) policy configuration via its own CLI arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherEnvelope {
    pub validated: ValidatedExecute,
    pub policy_snapshot: PolicySnapshot,
}

/// Applies every hardening primitive in order, reads the envelope from
/// stdin, reconstructs and re-validates against the embedded policy
/// snapshot, and `exec`s the target.
///
/// On success this function never returns (the process image has been
/// replaced). On failure it returns the error describing which step
/// failed; the caller (the `exec-broker-launcher` binary) is expected to
/// print it to stderr and exit non-zero, which the broker observes as the
/// launcher exiting rather than the target process ever starting.
pub fn run() -> Result<Infallible, BrokerError> {
    platform::set_no_new_privs()?;
    platform::install_seccomp_filter(SeccompProfile::Launcher)?;
    platform::drop_all_capabilities()?;
    platform::apply_default_rlimits()?;

    let envelope = read_envelope_from_stdin()?;
    let policy = Policy::from_snapshot(envelope.policy_snapshot);
    policy
        .revalidate_before_spawn(&envelope.validated)
        .map_err(|_| BrokerError::ResidualToctou)?;

    exec_target(&envelope.validated)
}

fn read_envelope_from_stdin() -> Result<LauncherEnvelope, BrokerError> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(BrokerError::Io)?;
    serde_json::from_str(&input).map_err(|e| BrokerError::Protocol(ProtocolError::Decode(e)))
}

/// `env_clear`s, applies exactly the validated argv/env/cwd, and execs.
/// Never invokes a shell or `/usr/bin/env`.
fn exec_target(validated: &ValidatedExecute) -> Result<Infallible, BrokerError> {
    let mut command = Command::new(&validated.argv[0]);
    command.args(&validated.argv[1..]);
    command.current_dir(&validated.canonical_cwd);
    command.env_clear();
    command.envs(&validated.env);

    // `exec` replaces this process image on success and therefore never
    // returns in that case; on failure it returns the `io::Error`.
    Err(BrokerError::Io(command.exec()))
}

/// Serializes a [`LauncherEnvelope`] for handoff to `contained-launcher`
/// over its stdin pipe. `policy_snapshot` must be derived from the
/// broker's own trusted [`Policy`] (via [`Policy::snapshot`]), never from
/// client-supplied data.
pub fn encode_envelope_for_launcher(envelope: &LauncherEnvelope) -> Result<Vec<u8>, BrokerError> {
    serde_json::to_vec(envelope).map_err(|e| BrokerError::Protocol(ProtocolError::Encode(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    fn sample_snapshot() -> PolicySnapshot {
        PolicySnapshot {
            allowed_root: PathBuf::from("/tmp"),
            allowlisted_executables: std::iter::once(PathBuf::from("/bin/true")).collect(),
            fixed_path: "/usr/bin:/bin".to_string(),
            fixed_lang: "C.UTF-8".to_string(),
            limits: crate::protocol::Limits::default(),
        }
    }

    #[test]
    fn encode_envelope_round_trips_through_json() {
        let envelope = LauncherEnvelope {
            validated: ValidatedExecute {
                correlation_id: "corr-1".into(),
                argv: vec!["/bin/true".into()],
                canonical_executable: "/bin/true".into(),
                canonical_cwd: "/tmp".into(),
                env: BTreeMap::new(),
                timeout: Duration::from_secs(1),
            },
            policy_snapshot: sample_snapshot(),
        };
        let bytes = encode_envelope_for_launcher(&envelope).expect("encode");
        let decoded: LauncherEnvelope = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(decoded.validated.correlation_id, "corr-1");
        assert_eq!(decoded.validated.argv, vec!["/bin/true".to_string()]);
        assert_eq!(
            decoded.policy_snapshot.allowlisted_executables,
            sample_snapshot().allowlisted_executables
        );
    }

    // Applying seccomp/rlimits/exec is exercised in isolated subprocess
    // (integration) tests rather than here, for the same reason described
    // in `platform::linux::seccomp` and `platform::linux::rlimits`: doing
    // so in-process would corrupt the shared `cargo test` binary for every
    // other concurrently running test.
}
