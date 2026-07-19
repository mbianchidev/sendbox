//! Opt-in Linux network namespace harness.
//!
//! This module never touches the host's normal firewall: every `nft` and
//! address/link mutation is executed with `ip netns exec <unique-ns>` so all
//! state lives inside a throwaway, uniquely named namespace, using a
//! uniquely named `inet` table. Nothing here runs unless the caller has
//! already verified [`CapabilityReport::all_ready`], is on Linux, is root,
//! and has opted in (the binary and integration test both require an
//! explicit environment variable in addition to root, so a plain `cargo
//! test` never mutates host networking state by accident).
//!
//! All process invocations use `std::process::Command` argv arrays; nothing
//! here is ever passed through a shell.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Output};

use serde::Serialize;
use thiserror::Error;

use crate::nft::{NftConfig, NftError, NftRunner};

#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("command '{program}' failed to execute: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("command '{program} {args}' exited with {status}: {stderr}")]
    NonZeroExit {
        program: String,
        args: String,
        status: String,
        stderr: String,
    },
    #[error(transparent)]
    Nft(#[from] NftError),
}

/// Runs `program` with an explicit argv array (never a shell) and returns an
/// error including captured stderr on non-zero exit. Forces the `C` locale
/// so any stderr text this harness pattern-matches on (e.g. to distinguish
/// "resource confirmed absent" from a genuine error) has stable,
/// locale-independent wording.
pub fn run(program: &str, args: &[&str]) -> Result<Output, HarnessError> {
    Command::new(program)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .args(args)
        .output()
        .map_err(|source| HarnessError::Spawn {
            program: program.to_owned(),
            source,
        })
}

pub fn run_checked(program: &str, args: &[&str]) -> Result<(), HarnessError> {
    let output = run(program, args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(HarnessError::NonZeroExit {
            program: program.to_owned(),
            args: args.join(" "),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Best-effort variant: logs but never propagates failure. Used during
/// teardown so cleanup always runs to completion even if an earlier step in
/// the sequence already failed (idempotent, absent-safe cleanup).
pub fn run_best_effort(program: &str, args: &[&str]) -> Option<HarnessError> {
    run_checked(program, args).err()
}

/// True only when running on Linux with effective UID 0. Implemented via
/// `/proc/self/status` (no unsafe FFI) so it stays honest about the one
/// platform this harness ever touches.
pub fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|contents| {
            contents
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(1).map(|uid| uid == "0"))
        })
        .unwrap_or(false)
}

pub fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolProbe {
    pub name: String,
    pub available: bool,
    pub detail: String,
}

fn probe_tool(name: &str, version_args: &[&str]) -> ToolProbe {
    match Command::new(name).args(version_args).output() {
        Ok(output) if output.status.success() => ToolProbe {
            name: name.to_owned(),
            available: true,
            detail: String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned(),
        },
        Ok(output) => ToolProbe {
            name: name.to_owned(),
            available: false,
            detail: format!(
                "exit {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        },
        Err(err) => ToolProbe {
            name: name.to_owned(),
            available: false,
            detail: err.to_string(),
        },
    }
}

/// Precise, machine-readable verdict on whether this environment can run
/// the live namespace suite. Meant to be printed as a CI step artifact so a
/// hosted runner without the right capabilities produces an explicit
/// failure/limitation instead of a silently skipped test.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReport {
    pub is_linux: bool,
    pub is_root: bool,
    pub ip: ToolProbe,
    pub nft: ToolProbe,
    pub setpriv: ToolProbe,
}

impl CapabilityReport {
    pub fn probe() -> Self {
        Self {
            is_linux: is_linux(),
            is_root: is_root(),
            ip: probe_tool("ip", &["-Version"]),
            nft: probe_tool("nft", &["-v"]),
            setpriv: probe_tool("setpriv", &["--version"]),
        }
    }

    pub fn all_ready(&self) -> bool {
        self.is_linux
            && self.is_root
            && self.ip.available
            && self.nft.available
            && self.setpriv.available
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }
}

/// Generates a short (6 hex character), unique, lowercase-alphanumeric
/// suffix suitable for namespace/interface/table names (which the kernel
/// caps at 15 characters for interfaces). A process-local counter
/// guarantees uniqueness across repeated in-process calls, and the low byte
/// of the process id adds cross-process variation for concurrent CI jobs.
pub fn unique_suffix() -> String {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    format!("{:02x}{:04x}", pid & 0xff, count & 0xffff)
}

/// Full addressing/naming plan for one harness run. Every name is derived
/// from a single unique suffix so a run never collides with another
/// concurrent run or leaves an ambiguous trace.
#[derive(Debug, Clone)]
pub struct NetnsTopology {
    pub ns_name: String,
    pub veth_host: String,
    pub veth_guest: String,
    pub table_name: String,
    pub host_v4: Ipv4Addr,
    pub guest_v4: Ipv4Addr,
    pub v4_prefix: u8,
    pub host_v6: Ipv6Addr,
    pub guest_v6: Ipv6Addr,
    pub v6_prefix: u8,
    pub agent_uid: u32,
    pub broker_uid: u32,
}

impl NetnsTopology {
    pub fn generate(agent_uid: u32, broker_uid: u32) -> Self {
        let suffix = unique_suffix();
        // Interface names are capped at 15 characters by the kernel; the
        // suffix is fixed at 6 characters, so every derived name below
        // fits comfortably.
        Self {
            ns_name: format!("sbxspk{suffix}"),
            veth_host: format!("sbxh{suffix}"),
            veth_guest: format!("sbxg{suffix}"),
            table_name: format!("sendbox_spike_{suffix}"),
            host_v4: Ipv4Addr::new(10, 200, 0, 1),
            guest_v4: Ipv4Addr::new(10, 200, 0, 2),
            v4_prefix: 30,
            host_v6: Ipv6Addr::new(0xfd00, 0xdead, 0xbeef, 0, 0, 0, 0, 1),
            guest_v6: Ipv6Addr::new(0xfd00, 0xdead, 0xbeef, 0, 0, 0, 0, 2),
            v6_prefix: 126,
            agent_uid,
            broker_uid,
        }
    }
}

/// Executes `nft` inside the harness's namespace via `ip netns exec <ns>
/// nft ...`, so [`crate::nft::apply`]/[`crate::nft::cleanup`] can be reused
/// unmodified against a namespace-scoped ruleset.
pub struct NetnsNftRunner {
    pub ns_name: String,
}

impl NftRunner for NetnsNftRunner {
    fn run(&self, args: &[&str]) -> std::io::Result<Output> {
        let mut full_args: Vec<&str> = vec!["netns", "exec", &self.ns_name, "nft"];
        full_args.extend_from_slice(args);
        Command::new("ip").args(full_args).output()
    }
}

/// Creates the namespace, veth pair, and assigns fixture (non-loopback)
/// addresses on both ends. Fixture services bind to the host side of the
/// veth so only the brokers are ever reachable on loopback from inside the
/// namespace.
///
/// IPv6 addresses are assigned with `nodad`: this is a throwaway,
/// point-to-point veth link with exactly one peer, so duplicate address
/// detection can never usefully detect a conflict, and without `nodad` an
/// address stays in the kernel's "tentative" state (unusable for
/// bind/connect) for the DAD window, which would otherwise make an
/// immediately-following fixture bind flaky.
pub fn setup_namespace_and_veth(topo: &NetnsTopology) -> Result<(), HarnessError> {
    run_checked("ip", &["netns", "add", &topo.ns_name])?;
    run_checked(
        "ip",
        &[
            "link",
            "add",
            &topo.veth_host,
            "type",
            "veth",
            "peer",
            "name",
            &topo.veth_guest,
        ],
    )?;
    run_checked(
        "ip",
        &["link", "set", &topo.veth_guest, "netns", &topo.ns_name],
    )?;

    let host_v4_cidr = format!("{}/{}", topo.host_v4, topo.v4_prefix);
    run_checked(
        "ip",
        &["addr", "add", &host_v4_cidr, "dev", &topo.veth_host],
    )?;
    let host_v6_cidr = format!("{}/{}", topo.host_v6, topo.v6_prefix);
    run_checked(
        "ip",
        &[
            "-6",
            "addr",
            "add",
            &host_v6_cidr,
            "dev",
            &topo.veth_host,
            "nodad",
        ],
    )?;
    run_checked("ip", &["link", "set", &topo.veth_host, "up"])?;

    let ns = topo.ns_name.as_str();
    let guest_v4_cidr = format!("{}/{}", topo.guest_v4, topo.v4_prefix);
    run_checked(
        "ip",
        &[
            "netns",
            "exec",
            ns,
            "ip",
            "addr",
            "add",
            &guest_v4_cidr,
            "dev",
            &topo.veth_guest,
        ],
    )?;
    let guest_v6_cidr = format!("{}/{}", topo.guest_v6, topo.v6_prefix);
    run_checked(
        "ip",
        &[
            "netns",
            "exec",
            ns,
            "ip",
            "-6",
            "addr",
            "add",
            &guest_v6_cidr,
            "dev",
            &topo.veth_guest,
            "nodad",
        ],
    )?;
    run_checked(
        "ip",
        &[
            "netns",
            "exec",
            ns,
            "ip",
            "link",
            "set",
            &topo.veth_guest,
            "up",
        ],
    )?;
    run_checked(
        "ip",
        &["netns", "exec", ns, "ip", "link", "set", "lo", "up"],
    )?;
    Ok(())
}

/// Builds the [`NftConfig`] for a topology and a set of broker ports, and
/// applies it as one atomic transaction inside the namespace. Uses the
/// deterministic, documented cloud-metadata address lists from
/// [`crate::address`] and scopes ICMPv6 neighbor discovery to the guest
/// veth interface only.
pub fn apply_firewall(
    topo: &NetnsTopology,
    dns_udp_port: u16,
    dns_tcp_port: u16,
    connect_tcp_port: u16,
) -> Result<(), HarnessError> {
    let config = NftConfig {
        table_name: topo.table_name.clone(),
        agent_uid: topo.agent_uid,
        broker_uid: topo.broker_uid,
        dns_broker_udp_port: dns_udp_port,
        dns_broker_tcp_port: dns_tcp_port,
        connect_broker_tcp_port: connect_tcp_port,
        metadata_v4_addresses: crate::address::METADATA_V4_ADDRESSES.to_vec(),
        metadata_v6_addresses: crate::address::METADATA_V6_ADDRESSES.to_vec(),
        fixture_iface: Some(topo.veth_guest.clone()),
    };
    let runner = NetnsNftRunner {
        ns_name: topo.ns_name.clone(),
    };
    crate::nft::apply(&config, &runner)?;
    Ok(())
}

/// Classifies a completed command's output as confirmed-present
/// (`Ok(true)`, exit success), confirmed-*absent* (`Ok(false)`, an exit
/// failure whose stderr matches one of `absence_markers`), or a genuine,
/// unexplained failure (`Err`). Only a confirmed absence is ever treated as
/// "safe to skip a destructive command" — every other failure, including
/// ones this function cannot explain, propagates as an error rather than
/// being silently folded into "not present".
///
/// This is a pure function over an already-completed [`Output`] (not a
/// function that itself runs a command), specifically so the
/// present/absent/error classification can be unit tested with synthetic
/// outputs, independent of whether `ip`/`nft` are actually installed.
fn classify_presence_output(
    program: &str,
    args: &[&str],
    output: &Output,
    absence_markers: &[&str],
) -> Result<bool, HarnessError> {
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if absence_markers.iter().any(|marker| stderr.contains(marker)) {
        Ok(false)
    } else {
        Err(HarnessError::NonZeroExit {
            program: program.to_owned(),
            args: args.join(" "),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Reports whether a network namespace named `ns_name` currently exists,
/// per `ip netns list`. `ip netns list` is a listing (not a per-name
/// query), so a genuine command failure here (bad binary, permission
/// error) always propagates as `Err` — there is no "not found" exit code to
/// distinguish, absence is determined purely by scanning a successful
/// listing's output.
pub fn namespace_exists(ns_name: &str) -> Result<bool, HarnessError> {
    let args = ["netns", "list"];
    let output = run("ip", &args)?;
    if !output.status.success() {
        return Err(HarnessError::NonZeroExit {
            program: "ip".to_owned(),
            args: args.join(" "),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.split_whitespace().next() == Some(ns_name)))
}

/// Reports whether a network interface named `link_name` currently exists
/// in the *current* network namespace (the root namespace, for the
/// host-side veth end this harness creates), per `ip link show`. Iproute2
/// reports a missing device via a non-zero exit with a stable "does not
/// exist"/"Cannot find device" stderr message (forced to the `C` locale by
/// [`run`]); any other failure is a genuine error, not a confirmed absence.
pub fn link_exists(link_name: &str) -> Result<bool, HarnessError> {
    let args = ["link", "show", link_name];
    let output = run("ip", &args)?;
    classify_presence_output(
        "ip",
        &args,
        &output,
        &["does not exist", "cannot find device"],
    )
}

/// Reports whether an `inet` table named `table_name` currently exists
/// inside the namespace `ns_name`, per `nft list table`. Only meaningful
/// when the namespace itself exists; callers should check
/// [`namespace_exists`] first to avoid attributing an "entering a
/// nonexistent namespace" failure to "the table doesn't exist". A missing
/// table surfaces as a non-zero exit with a stable "No such file or
/// directory"/"does not exist" stderr message; any other failure is a
/// genuine error.
pub fn nft_table_exists(ns_name: &str, table_name: &str) -> Result<bool, HarnessError> {
    let args = [
        "netns", "exec", ns_name, "nft", "list", "table", "inet", table_name,
    ];
    let output = run("ip", &args)?;
    classify_presence_output(
        "ip",
        &args,
        &output,
        &["no such file or directory", "does not exist"],
    )
}

/// Idempotent, absent-safe teardown. Each of the three resources this
/// harness can create (the nft table, the host-side veth link, the
/// namespace itself) is independently existence-checked *before* attempting
/// its destructive command, and only a **confirmed absence**
/// (`Ok(false)`) is ever treated as "nothing to do here, not an error":
///
/// - If the namespace is confirmed already gone, the nft table cleanup
///   step is skipped entirely rather than attempted, because `ip netns
///   exec <absent-ns> nft destroy table ...` fails for a reason unrelated
///   to whether the table exists (entering an absent namespace is itself
///   an error) — treating that failure as "table cleanup failed" would
///   give a false negative on a second, otherwise-successful teardown call
///   and break idempotency.
/// - If the veth link or the namespace are confirmed already absent, their
///   respective delete commands are skipped the same way.
/// - If an existence probe itself fails (`Err` — a genuine inspection
///   failure such as a permission error, not a recognized "not found"
///   response), that error is recorded and the corresponding destructive
///   step is *not* attempted speculatively; guessing at the resource's
///   state would risk misattributing a follow-on failure.
///
/// A genuine destructive-command failure (the resource demonstrably
/// exists but its delete/destroy command still fails) is likewise
/// collected and returned, so none of this papers over real errors — only
/// ones caused by the resource being confirmed absent.
pub fn teardown(topo: &NetnsTopology) -> Vec<HarnessError> {
    let mut errors = Vec::new();

    match namespace_exists(&topo.ns_name) {
        Ok(true) => {
            // `nft destroy` is idempotent regardless of whether the table
            // itself is present, so once the namespace is confirmed to
            // exist (the one precondition `ip netns exec` requires), the
            // destroy is attempted directly; `nft_table_exists` remains a
            // separately usable, separately tested probe, but teardown's
            // correctness never depends on calling it.
            let runner = NetnsNftRunner {
                ns_name: topo.ns_name.clone(),
            };
            let config = NftConfig {
                table_name: topo.table_name.clone(),
                agent_uid: topo.agent_uid,
                broker_uid: topo.broker_uid,
                dns_broker_udp_port: 0,
                dns_broker_tcp_port: 0,
                connect_broker_tcp_port: 0,
                metadata_v4_addresses: Vec::new(),
                metadata_v6_addresses: Vec::new(),
                fixture_iface: None,
            };
            if let Err(err) = crate::nft::cleanup(&config, &runner) {
                errors.push(HarnessError::Nft(err));
            }
        }
        Ok(false) => {}
        Err(err) => errors.push(err),
    }

    match link_exists(&topo.veth_host) {
        Ok(true) => {
            if let Some(err) = run_best_effort("ip", &["link", "delete", &topo.veth_host]) {
                errors.push(err);
            }
        }
        Ok(false) => {}
        Err(err) => errors.push(err),
    }

    match namespace_exists(&topo.ns_name) {
        Ok(true) => {
            if let Some(err) = run_best_effort("ip", &["netns", "delete", &topo.ns_name]) {
                errors.push(err);
            }
        }
        Ok(false) => {}
        Err(err) => errors.push(err),
    }

    errors
}

/// Builds the `setpriv` argv (as owned `String`s, so callers can build a
/// `Vec<&str>` from references into it) used to run a process as `uid`
/// with every ambient/inheritable/bounding capability actually cleared —
/// not just a UID change — and `no_new_privs` set so the process can never
/// regain privileges via a setuid/setgid/file-capability binary. Used for
/// both the agent and broker UIDs: neither needs any Linux capability to
/// do its job (both only ever use plain TCP/UDP sockets on unprivileged
/// ports), so clearing every set for both is strictly least-privilege.
pub fn setpriv_argv(uid: u32) -> Vec<String> {
    vec![
        "setpriv".to_owned(),
        "--reuid".to_owned(),
        uid.to_string(),
        "--regid".to_owned(),
        uid.to_string(),
        "--clear-groups".to_owned(),
        "--inh-caps=-all".to_owned(),
        "--ambient-caps=-all".to_owned(),
        "--bounding-set=-all".to_owned(),
        "--no-new-privs".to_owned(),
        "--".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn topology_names_are_unique_across_generations() {
        let a = NetnsTopology::generate(5001, 5002);
        let b = NetnsTopology::generate(5001, 5002);
        assert_ne!(a.ns_name, b.ns_name);
        assert!(a.ns_name.len() <= 15);
        assert!(a.veth_host.len() <= 15);
        assert!(a.veth_guest.len() <= 15);
    }

    #[test]
    fn topology_uses_non_loopback_fixture_addresses() {
        let topo = NetnsTopology::generate(5001, 5002);
        assert!(!topo.host_v4.is_loopback());
        assert!(!topo.guest_v4.is_loopback());
    }

    #[test]
    fn capability_report_serializes_deterministically_shaped_json() {
        let report = CapabilityReport {
            is_linux: false,
            is_root: false,
            ip: ToolProbe {
                name: "ip".to_owned(),
                available: false,
                detail: "not found".to_owned(),
            },
            nft: ToolProbe {
                name: "nft".to_owned(),
                available: false,
                detail: "not found".to_owned(),
            },
            setpriv: ToolProbe {
                name: "setpriv".to_owned(),
                available: false,
                detail: "not found".to_owned(),
            },
        };
        assert!(!report.all_ready());
        let json = report.to_json();
        assert!(json.contains("\"is_linux\":false"));
    }

    #[test]
    fn run_reports_spawn_failure_without_panicking() {
        let result = run_checked("definitely-not-a-real-binary-xyz", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn setpriv_argv_clears_every_capability_set_for_any_uid() {
        let argv = setpriv_argv(65177);
        assert!(argv.contains(&"--inh-caps=-all".to_owned()));
        assert!(argv.contains(&"--ambient-caps=-all".to_owned()));
        assert!(argv.contains(&"--bounding-set=-all".to_owned()));
        assert!(argv.contains(&"--no-new-privs".to_owned()));
        assert!(argv.contains(&"65177".to_owned()));
    }

    // These exercise the existence-check helpers themselves. They are safe
    // to run anywhere `ip` may or may not be installed (unlike the rest of
    // this harness, they never mutate state — `ip netns list`/`ip link
    // show` are read-only), so they are *not* gated behind the live-suite
    // opt-in and run as part of the ordinary unit-test suite in CI. On a
    // host without `ip` installed (e.g. this spike's macOS development
    // host), a genuine inspection failure (`Err`) is the *honest* outcome
    // — not a silently substituted `Ok(false)` — so these only assert that
    // presence is never falsely reported, not that a specific variant is
    // returned.
    #[test]
    fn namespace_exists_never_falsely_reports_presence_for_a_never_created_name() {
        if let Ok(exists) = namespace_exists("sbxspk_definitely_never_created") {
            assert!(
                !exists,
                "a never-created namespace must not read as existing"
            );
        }
    }

    #[test]
    fn link_exists_never_falsely_reports_presence_for_a_never_created_interface() {
        if let Ok(exists) = link_exists("sbx_never_created_iface") {
            assert!(
                !exists,
                "a never-created interface must not read as existing"
            );
        }
    }

    #[test]
    fn nft_table_exists_never_falsely_reports_presence_for_a_never_created_namespace() {
        if let Ok(exists) =
            nft_table_exists("sbxspk_definitely_never_created", "sendbox_spike_test")
        {
            assert!(
                !exists,
                "a table in a never-created namespace must not read as existing"
            );
        }
    }

    // `classify_presence_output` is the pure classification logic behind
    // all three probes above. Testing it directly with synthetic outputs
    // lets "confirmed absent" vs "genuine command failure" be verified
    // deterministically on any platform, independent of whether `ip`/`nft`
    // are actually installed.
    fn synthetic_output(success: bool, stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 }),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn classify_presence_output_success_is_present() {
        let output = synthetic_output(true, "");
        let result =
            classify_presence_output("ip", &["link", "show", "x"], &output, &["does not exist"]);
        assert!(matches!(result, Ok(true)));
    }

    #[test]
    fn classify_presence_output_matching_stderr_is_confirmed_absent() {
        let output = synthetic_output(false, "Device \"x\" does not exist.");
        let result =
            classify_presence_output("ip", &["link", "show", "x"], &output, &["does not exist"]);
        assert!(matches!(result, Ok(false)));
    }

    #[test]
    fn classify_presence_output_non_matching_stderr_is_a_genuine_error() {
        let output = synthetic_output(false, "Operation not permitted");
        assert!(matches!(
            classify_presence_output("ip", &["link", "show", "x"], &output, &["does not exist"]),
            Err(HarnessError::NonZeroExit { .. })
        ));
    }

    #[test]
    fn classify_presence_output_matching_is_case_insensitive() {
        let output = synthetic_output(false, "DOES NOT EXIST");
        let result =
            classify_presence_output("ip", &["link", "show", "x"], &output, &["does not exist"]);
        assert!(matches!(result, Ok(false)));
    }
}
