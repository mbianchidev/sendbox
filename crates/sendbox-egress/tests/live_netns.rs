//! Opt-in Linux network-namespace live enforcement proof for the production
//! cgroup-v2 + `SO_MARK` + nftables model.
//!
//! Inert everywhere except a Linux host running as root with
//! `SENDBOX_EGRESS_LIVE=1`, because it mutates real kernel state (a network
//! namespace, a veth pair, cgroups, and an nftables table). Gating order:
//! 1. `target_os == "linux"` (this file is `cfg`-gated to Linux entirely);
//! 2. `SENDBOX_EGRESS_LIVE=1` explicit opt-in, so a plain `cargo test` — even
//!    on Linux as root — never mutates host state;
//! 3. a full [`Preflight`] readiness check (cgroup v2, `nft socket cgroupv2`,
//!    `CAP_NET_ADMIN`, `SO_MARK`) plus `setpriv`. If it fails, the test prints
//!    the JSON verdict and returns, unless `SENDBOX_EGRESS_LIVE_REQUIRE=1` is set
//!    (the CI job that claims to run the suite), in which case a missing
//!    capability fails loudly.
//!
//! Cleanup is RAII: [`LiveEnvironment`] tears down the supervisor (cgroups then
//! nftables, fail-closed order), the veth, the namespace, and every child
//! process on drop, whether the test completes, an assertion fails, or a panic
//! unwinds. Teardown surfaces errors, which the normal-path test asserts are
//! empty, then verifies every resource is absent.
//!
//! The kernel-enforcement scenarios proven here — cgroup identity isolation, the
//! mark requirement, sibling/identity-spoof denial, direct-egress bypass,
//! non-vacuous IPv6/UDP denial with reachable positive controls, an unprivileged
//! agent with all capabilities cleared and raw sockets denied, marked upstream
//! DNS with UDP-truncation → TCP fallback, apply-time-failure rollback, and
//! broker restart — are the ones that cannot be shown in the portable
//! `gateway_integration` suite.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use sendbox_egress::linux::cgroup;
use sendbox_egress::linux::nft::{self, CgroupIdentity, NftConfig, NftRunner, SystemNftRunner};
use sendbox_egress::linux::preflight::Preflight;
use sendbox_egress::linux::supervisor::{ArmedEgress, SupervisorConfig};
use serde_json::Value;

const OPT_IN_ENV: &str = "SENDBOX_EGRESS_LIVE";
const REQUIRE_ENV: &str = "SENDBOX_EGRESS_LIVE_REQUIRE";
const BROKER_MARK: u32 = 0x5b0e;
/// Unprivileged identity the agent probes drop to (nobody/nogroup on Ubuntu).
const AGENT_UID: u32 = 65534;
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const DNS_PORT: u16 = 15053;
const CONNECT_PORT: u16 = 15080;

fn run(program: &str, args: &[&str]) -> std::io::Result<Output> {
    Command::new(program)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .args(args)
        .output()
}

fn run_checked(program: &str, args: &[&str]) {
    let output = run(program, args).unwrap_or_else(|e| panic!("spawn {program} {args:?}: {e}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(|u| u == "0"))
        })
        .unwrap_or(false)
}

fn has_setpriv() -> bool {
    run("setpriv", &["--version"])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Applies nftables inside the harness's network namespace via
/// `ip netns exec <ns> nft ...`, passing the ruleset on stdin.
struct NetnsNftRunner {
    ns_name: String,
}

impl NftRunner for NetnsNftRunner {
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> std::io::Result<Output> {
        let mut full: Vec<&str> = vec!["netns", "exec", &self.ns_name, "nft"];
        full.extend_from_slice(args);
        let mut command = Command::new("ip");
        command
            .args(&full)
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn()?;
        if let Some(bytes) = stdin {
            child.stdin.take().expect("stdin").write_all(bytes)?;
        }
        child.wait_with_output()
    }
}

/// Wraps the netns runner and, when armed, removes a *candidate* cgroup
/// directory immediately before forwarding the real commit (`nft -f -`). An
/// update ruleset references that candidate cgroup and has already passed
/// `--check` (which resolved the path while it still existed); deleting it just
/// before the genuine commit makes the real `nft` transaction fail to resolve
/// the now-missing `socket cgroupv2` path — a true kernel/tool apply-time
/// failure *after* successful validation, which proves the previous table
/// survives without any synthetic exit code.
struct CandidateRemovingRunner {
    inner: NetnsNftRunner,
    candidate_dir: PathBuf,
    remove_on_commit: Arc<AtomicBool>,
}

impl NftRunner for CandidateRemovingRunner {
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> std::io::Result<Output> {
        // Only the commit (`-f -`, not `--check -f -`) triggers the removal.
        if args.first() == Some(&"-f") && self.remove_on_commit.swap(false, Ordering::SeqCst) {
            let _ = std::fs::remove_dir(&self.candidate_dir);
        }
        self.inner.run(args, stdin)
    }
}

struct Topology {
    ns_name: String,
    veth_host: String,
    veth_guest: String,
    instance_id: String,
    host_v4: Ipv4Addr,
    host_v6: Ipv6Addr,
}

impl Topology {
    fn generate() -> Self {
        let suffix = format!("{:x}", std::process::id() & 0xffff);
        Self {
            ns_name: format!("sbxeg{suffix}"),
            veth_host: format!("sbxh{suffix}"),
            veth_guest: format!("sbxg{suffix}"),
            instance_id: format!("live{suffix}"),
            host_v4: Ipv4Addr::new(10, 210, 0, 1),
            host_v6: Ipv6Addr::new(0xfd00, 0xbeef, 0, 0, 0, 0, 0, 1),
        }
    }
}

/// RAII guard: tears down the supervisor, namespace, veth, and children.
struct LiveEnvironment {
    topo: Topology,
    cgroup_root: PathBuf,
    armed: Option<ArmedEgress>,
    /// Armed to make the next real `nft` commit fail by removing a candidate
    /// cgroup the update ruleset references (fix G: a real kernel apply-time
    /// failure after `--check` has already passed).
    remove_candidate: Arc<AtomicBool>,
    /// Absolute path of the candidate cgroup the update ruleset references.
    candidate_dir: PathBuf,
    /// Retained exclusive, mode-0600 temp config files. Held for the whole run
    /// so they cannot be swapped, and explicitly closed (with absence
    /// assertions) in teardown.
    temp_files: Vec<tempfile::NamedTempFile>,
    children: Vec<Child>,
}

impl LiveEnvironment {
    fn new(topo: Topology, cgroup_root: PathBuf) -> Self {
        let candidate_dir = cgroup_root.join(format!("sendbox/{}/candidate", topo.instance_id));
        Self {
            topo,
            cgroup_root,
            armed: None,
            remove_candidate: Arc::new(AtomicBool::new(false)),
            candidate_dir,
            temp_files: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Writes `contents` to a fresh exclusive, unpredictable, mode-0600 temp
    /// file (via `tempfile`, which uses `O_EXCL` + `0600`) and retains the
    /// handle for the whole run, returning its path. The harness opens this
    /// path with `O_NOFOLLOW` *before* any namespace/cgroup transition, so a
    /// predictable-path reopen or symlink swap after a transition cannot
    /// influence it. (Stable Rust's `std::process::Command` cannot pass an
    /// inherited fd across the `ip netns exec` / `setpriv` re-exec, which is why
    /// a random exclusive file read with `O_NOFOLLOW` is used here rather than
    /// the harness's `--policy-fd`/`--fixtures-fd` inherited-descriptor mode.)
    fn temp_config(&mut self, contents: &str) -> PathBuf {
        let mut file = tempfile::Builder::new()
            .prefix("sbxeg-")
            .suffix(".json")
            .tempfile()
            .expect("create exclusive temp config");
        file.write_all(contents.as_bytes())
            .expect("write temp config");
        file.flush().expect("flush temp config");
        let path = file.path().to_path_buf();
        self.temp_files.push(file);
        path
    }

    fn track(&mut self, child: Child) {
        self.children.push(child);
    }

    fn kill_children(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.children.clear();
    }

    fn namespace_exists(&self) -> bool {
        run("ip", &["netns", "list"])
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.split_whitespace().next() == Some(self.topo.ns_name.as_str()))
            })
            .unwrap_or(false)
    }

    fn veth_exists(&self) -> bool {
        run("ip", &["link", "show", &self.topo.veth_host])
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn cgroups_exist(&self) -> bool {
        self.cgroup_root
            .join(format!("sendbox/{}", self.topo.instance_id))
            .exists()
    }

    /// Fail-closed teardown that surfaces (does not discard) errors. Kills
    /// children first (so cgroups can empty), removes any lingering candidate
    /// cgroup (so the owned base can be removed), then the supervisor (cgroups
    /// before nftables), then the veth, namespace, and temp config files.
    fn teardown(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        self.kill_children();
        thread::sleep(Duration::from_millis(250));
        // Remove the fix-G candidate cgroup first if it lingers (e.g. a panic
        // before the runner deleted it), so it does not keep the owned base
        // cgroup non-empty and block the supervisor's teardown. Absent-safe; a
        // real failure is surfaced.
        match std::fs::remove_dir(&self.candidate_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("candidate cgroup remove: {e}")),
        }
        if let Some(mut armed) = self.armed.take() {
            for err in armed.teardown() {
                errors.push(format!("supervisor: {err}"));
            }
        }
        if self.veth_exists() {
            let ok = run("ip", &["link", "delete", &self.topo.veth_host])
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !ok {
                errors.push("veth delete failed".to_owned());
            }
        }
        if self.namespace_exists() {
            let ok = run("ip", &["netns", "delete", &self.topo.ns_name])
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !ok {
                errors.push("netns delete failed".to_owned());
            }
        }
        // Close (delete) the retained exclusive temp config files and assert
        // each is gone afterward, surfacing any failure.
        for file in self.temp_files.drain(..) {
            let path = file.path().to_path_buf();
            if let Err(e) = file.close() {
                errors.push(format!("temp config close {}: {e}", path.display()));
            }
            if path.exists() {
                errors.push(format!("temp config not removed: {}", path.display()));
            }
        }
        errors
    }
}

impl Drop for LiveEnvironment {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

fn gate_or_skip() -> Option<PathBuf> {
    if std::env::var(OPT_IN_ENV).ok().as_deref() != Some("1") {
        eprintln!("skipping live suite: set {OPT_IN_ENV}=1 to run");
        return None;
    }
    let require = std::env::var(REQUIRE_ENV).ok().as_deref() == Some("1");
    let preflight = Preflight::probe(&SystemNftRunner::default());
    let root = match cgroup::detect_cgroup2_root() {
        Ok(root) => root,
        Err(err) => {
            let message = format!("cgroup2 root unavailable: {err}");
            assert!(!require, "{message}");
            eprintln!("skipping live suite: {message}");
            return None;
        }
    };
    if !is_root() || !preflight.all_ready() || !has_setpriv() {
        let verdict = format!("{} setpriv={}", preflight.to_json(), has_setpriv());
        assert!(
            !require,
            "live suite required but environment not ready: {verdict}"
        );
        eprintln!("skipping live suite; capability verdict: {verdict}");
        return None;
    }
    Some(root)
}

#[test]
fn live_netns_enforcement_proof() {
    let Some(cgroup_root) = gate_or_skip() else {
        return;
    };
    let topo = Topology::generate();
    let mut env = LiveEnvironment::new(topo, cgroup_root);
    run_live_suite(&mut env);

    // Fix I: teardown must surface no errors on the normal path, and every
    // resource must be absent afterward; a repeated teardown is idempotent.
    let errors = env.teardown();
    assert!(
        errors.is_empty(),
        "clean teardown reported errors: {errors:?}"
    );
    assert!(
        !env.namespace_exists(),
        "namespace must be gone after teardown"
    );
    assert!(!env.veth_exists(), "veth must be gone after teardown");
    assert!(!env.cgroups_exist(), "cgroups must be gone after teardown");
    let again = env.teardown();
    assert!(
        again.is_empty(),
        "repeated teardown must be a no-op: {again:?}"
    );
}

/// Fix I: a panic mid-setup must still leave no leaked namespace/veth/cgroups.
#[test]
fn live_netns_injected_failure_cleanup() {
    let Some(cgroup_root) = gate_or_skip() else {
        return;
    };
    let topo = Topology::generate();
    let ns_name = topo.ns_name.clone();
    let veth = topo.veth_host.clone();
    let instance = topo.instance_id.clone();
    let root = cgroup_root.clone();

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = LiveEnvironment::new(topo, cgroup_root);
        setup_namespace_and_veth(&env.topo);
        let config = SupervisorConfig::new(&env.topo.instance_id, BROKER_MARK, CONNECT_PORT)
            .with_dns_port(DNS_PORT)
            .with_fixture_iface(&env.topo.veth_guest);
        let runner: Box<dyn NftRunner> = Box::new(NetnsNftRunner {
            ns_name: env.topo.ns_name.clone(),
        });
        env.armed = Some(
            ArmedEgress::arm_under(&env.cgroup_root, runner, config).expect("arm must succeed"),
        );
        // Force an unwind after real state has been created.
        panic!("injected mid-setup failure");
    }));
    assert!(outcome.is_err(), "the injected panic must propagate");

    // The RAII Drop must have cleaned everything up.
    let ns_gone = run("ip", &["netns", "list"])
        .map(|o| {
            !String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.split_whitespace().next() == Some(ns_name.as_str()))
        })
        .unwrap_or(false);
    assert!(ns_gone, "namespace leaked after panic");
    let veth_gone = !run("ip", &["link", "show", &veth])
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(veth_gone, "veth leaked after panic");
    assert!(
        !root.join(format!("sendbox/{instance}")).exists(),
        "cgroups leaked after panic"
    );
}

fn run_live_suite(env: &mut LiveEnvironment) {
    let allowed_v4_port: u16 = 19001;
    let denied_v4_port: u16 = 19002;
    let alt_dns_port: u16 = 53;
    let metadata_port: u16 = 80;
    let udp_echo_port: u16 = 19005;
    let allowed_v6_port: u16 = 19006;
    let denied_v6_port: u16 = 19007;
    let dns_fixture_port: u16 = 15353;
    let forward_connect_port: u16 = 19008;

    setup_namespace_and_veth(&env.topo);
    // Route + secondary address for the metadata literal so an attempt has a
    // real listener to be blocked from.
    run_checked(
        "ip",
        &[
            "addr",
            "add",
            &format!("{METADATA_V4}/32"),
            "dev",
            &env.topo.veth_host,
        ],
    );
    run_checked(
        "ip",
        &[
            "netns",
            "exec",
            &env.topo.ns_name,
            "ip",
            "route",
            "add",
            &format!("{METADATA_V4}/32"),
            "dev",
            &env.topo.veth_guest,
        ],
    );

    // Arm the supervisor with a runner that can inject a *real* apply-time
    // failure (fix G) by removing a candidate cgroup before the commit;
    // `remove_candidate` stays false during the ordinary scenarios.
    let config = SupervisorConfig::new(&env.topo.instance_id, BROKER_MARK, CONNECT_PORT)
        .with_dns_port(DNS_PORT)
        .with_fixture_iface(&env.topo.veth_guest);
    let runner: Box<dyn NftRunner> = Box::new(CandidateRemovingRunner {
        inner: NetnsNftRunner {
            ns_name: env.topo.ns_name.clone(),
        },
        candidate_dir: env.candidate_dir.clone(),
        remove_on_commit: Arc::clone(&env.remove_candidate),
    });
    let armed = ArmedEgress::arm_under(&env.cgroup_root, runner, config)
        .expect("arming egress must succeed with a ready environment");
    // Use the supervisor's mount-relative `cgroup.procs` accessors, never the
    // global nft identity path (which carries the process's own cgroup prefix
    // and would not resolve when joined onto the mounted root).
    let agent_procs = armed.agent_procs_path();
    let broker_procs = armed.broker_procs_path();
    env.armed = Some(armed);

    let allowed_v4 = SocketAddr::new(IpAddr::V4(env.topo.host_v4), allowed_v4_port);
    let denied_v4 = SocketAddr::new(IpAddr::V4(env.topo.host_v4), denied_v4_port);
    let alt_dns = SocketAddr::new(IpAddr::V4(env.topo.host_v4), alt_dns_port);
    let metadata = SocketAddr::new(IpAddr::V4(METADATA_V4), metadata_port);
    let udp_echo = SocketAddr::new(IpAddr::V4(env.topo.host_v4), udp_echo_port);
    let allowed_v6 = SocketAddr::new(IpAddr::V6(env.topo.host_v6), allowed_v6_port);
    let denied_v6 = SocketAddr::new(IpAddr::V6(env.topo.host_v6), denied_v6_port);
    let dns_fixture = SocketAddr::new(IpAddr::V4(env.topo.host_v4), dns_fixture_port);
    let forward_v4 = SocketAddr::new(IpAddr::V4(env.topo.host_v4), forward_connect_port);

    let _f_allowed_tcp = spawn_echo(allowed_v4);
    let _f_allowed_udp = spawn_udp_echo(allowed_v4);
    let _f_denied_tcp = spawn_echo(denied_v4);
    let _f_alt_tcp = spawn_echo(alt_dns);
    let _f_alt_udp = spawn_udp_echo(alt_dns);
    let _f_meta = spawn_echo(metadata);
    let _f_udp = spawn_udp_echo(udp_echo);
    let _f_allowed_v6 = spawn_echo(allowed_v6);
    let _f_denied_v6 = spawn_echo(denied_v6); // reachable IPv6 denied fixture (fix H)
    let _f_forward = spawn_echo(forward_v4);
    let _dns = spawn_dns_fixture(dns_fixture, env.topo.host_v4); // marked upstream DNS (fix F)

    let policy = policy_json(&env.topo);
    let policy_path = env.temp_config(&policy);
    let fixtures = fixtures_json(allowed_v4, allowed_v6);
    let fixtures_path = env.temp_config(&fixtures);

    let gateway = spawn_gateway(&env.topo, &policy_path, &fixtures_path, &broker_procs);
    env.track(gateway);
    wait_for_gateway_ready(&env.topo, &agent_procs, true);

    // ── Scenario 1: brokered allow round-trips (v4 + v6), agent unprivileged.
    let v4 = connect_attempt(&env.topo, &agent_procs, "allowed.fixture", allowed_v4_port);
    assert_eq!(v4["outcome"], "ok", "brokered v4: {v4}");
    assert_eq!(v4["echo_verified"], true, "brokered v4 echo: {v4}");
    let v6 = connect_attempt(
        &env.topo,
        &agent_procs,
        "allowed-v6.fixture",
        allowed_v6_port,
    );
    assert_eq!(v6["outcome"], "ok", "brokered v6: {v6}");

    // ── Scenario 2: agent direct bypass of the allowed address is blocked.
    let bypass = agent_raw(&env.topo, &agent_procs, "tcp", allowed_v4);
    assert_eq!(
        bypass["outcome"], "blocked_or_unreachable",
        "direct bypass: {bypass}"
    );

    // ── Scenario 3: arbitrary direct v4/v6 blocked for the agent.
    let arb4 = agent_raw(&env.topo, &agent_procs, "tcp", denied_v4);
    assert_eq!(
        arb4["outcome"], "blocked_or_unreachable",
        "arbitrary v4: {arb4}"
    );

    // ── Scenario 3b (fix H): non-vacuous IPv6 denial. Prove the exact denied
    // IPv6 fixture is reachable by the broker (cgroup + mark) first, then that
    // the agent is blocked from that same reachable target.
    let v6_pos = broker_raw(&env.topo, &broker_procs, "tcp", denied_v6);
    assert_eq!(
        v6_pos["outcome"], "connected",
        "positive control: broker+mark must reach the IPv6 fixture: {v6_pos}"
    );
    let v6_deny = agent_raw(&env.topo, &agent_procs, "tcp", denied_v6);
    assert_eq!(
        v6_deny["outcome"], "blocked_or_unreachable",
        "agent must be blocked from a reachable IPv6 target: {v6_deny}"
    );

    // ── Scenario 4 (fix H): alternate DNS. TCP blocked for the agent; UDP with
    // a reachable positive control (broker+mark) then agent denial.
    let alt_tcp = agent_raw(&env.topo, &agent_procs, "tcp", alt_dns);
    assert_eq!(
        alt_tcp["outcome"], "blocked_or_unreachable",
        "alt dns tcp: {alt_tcp}"
    );
    let alt_udp_pos = broker_raw(&env.topo, &broker_procs, "udp", alt_dns);
    assert_eq!(
        alt_udp_pos["outcome"], "connected",
        "positive control: broker+mark must reach alt-DNS UDP: {alt_udp_pos}"
    );
    let alt_udp = agent_raw(&env.topo, &agent_procs, "udp", alt_dns);
    assert_eq!(
        alt_udp["outcome"], "blocked_or_unreachable",
        "agent must be blocked from a reachable alt-DNS UDP: {alt_udp}"
    );

    // ── Scenario 5 (fix H): arbitrary UDP/QUIC denial with a positive control.
    let udp_pos = broker_raw(&env.topo, &broker_procs, "udp", udp_echo);
    assert_eq!(
        udp_pos["outcome"], "connected",
        "positive control: broker+mark must reach the UDP echo: {udp_pos}"
    );
    let udp_deny = agent_raw(&env.topo, &agent_procs, "udp", udp_echo);
    assert_eq!(
        udp_deny["outcome"], "blocked_or_unreachable",
        "agent must be blocked from a reachable UDP target: {udp_deny}"
    );

    // ── Scenario 6: metadata blocked for the agent.
    let meta = agent_raw(&env.topo, &agent_procs, "tcp", metadata);
    assert_eq!(
        meta["outcome"], "blocked_or_unreachable",
        "agent metadata: {meta}"
    );

    // ── Scenario 7 (fix E): the agent runs unprivileged with every capability
    // cleared and cannot create a raw socket (so it cannot bypass the IP-layer
    // filter below the inet hooks).
    let caps = caps_probe(&env.topo, &agent_procs);
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert_eq!(
            caps[field], "0000000000000000",
            "agent capability set {field} must be cleared: {caps}"
        );
    }
    let raw_sock = raw_socket_probe(&env.topo, &agent_procs);
    assert_eq!(
        raw_sock["raw_socket"], "denied",
        "unprivileged agent must be denied a raw socket: {raw_sock}"
    );

    // ── Scenario 8: sibling / identity spoof. A process in neither cgroup can
    // reach neither the broker port nor any external destination.
    let sib_broker = sibling_raw(
        &env.topo,
        "tcp",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), CONNECT_PORT),
    );
    assert_eq!(
        sib_broker["outcome"], "blocked_or_unreachable",
        "sibling reaching broker port: {sib_broker}"
    );
    let sib_ext = sibling_raw(&env.topo, "tcp", allowed_v4);
    assert_eq!(
        sib_ext["outcome"], "blocked_or_unreachable",
        "sibling reaching external: {sib_ext}"
    );

    // ── Scenario 9: socket-mark necessity. A process in the broker cgroup but
    // without the mark is still blocked from external egress.
    let broker_no_mark = broker_raw_no_mark(&env.topo, &broker_procs, "tcp", allowed_v4);
    assert_eq!(
        broker_no_mark["outcome"], "blocked_or_unreachable",
        "broker cgroup without the mark must be blocked: {broker_no_mark}"
    );

    // ── Scenario 10: broker restart — the ruleset persists (default-deny holds
    // with the broker dead) and brokered allow works again after restart.
    env.kill_children();
    thread::sleep(Duration::from_millis(200));
    let table = env.armed.as_ref().unwrap().current_config().clone();
    assert!(
        table_present(&env.topo, &table),
        "table must persist after broker death"
    );
    let still = agent_raw(&env.topo, &agent_procs, "tcp", denied_v4);
    assert_eq!(
        still["outcome"], "blocked_or_unreachable",
        "default-deny must hold with the broker dead: {still}"
    );
    let gateway2 = spawn_gateway(&env.topo, &policy_path, &fixtures_path, &broker_procs);
    env.track(gateway2);
    wait_for_gateway_ready(&env.topo, &agent_procs, true);
    let restarted = connect_attempt(&env.topo, &agent_procs, "allowed.fixture", allowed_v4_port);
    assert_eq!(
        restarted["outcome"], "ok",
        "brokered allow after restart: {restarted}"
    );

    // ── Scenario 11 (fix G): a REAL kernel apply-time failure after `--check`
    // passes. Create an empty candidate cgroup referenced only by the update
    // ruleset so validation resolves it; the runner deletes it immediately
    // before the genuine commit, so the real `nft -f -` transaction fails to
    // resolve the now-missing `socket cgroupv2` path and the previous table
    // survives intact. Explicit disruption then rollback restores enforcement.
    // (`table`, captured in scenario 10, is the last-known-good ruleset.)
    std::fs::create_dir_all(&env.candidate_dir).expect("create candidate cgroup");
    env.remove_candidate.store(true, Ordering::SeqCst);
    let mut bad = env.armed.as_ref().unwrap().current_config().clone();
    // The candidate's nft identity must carry the same global cgroup prefix as
    // the agent (a sibling leaf under the instance base), so `--check` resolves
    // it before the runner deletes it ahead of the real commit.
    let agent_global = bad.agent.relative_path().to_owned();
    let candidate_global = agent_global
        .rsplit_once('/')
        .map(|(base, _)| format!("{base}/candidate"))
        .expect("agent identity has a parent");
    bad.agent = CgroupIdentity::new(candidate_global).expect("candidate identity");
    let update_res = env.armed.as_mut().unwrap().update(bad);
    assert!(
        update_res.is_err(),
        "a real apply-time failure must be surfaced: {update_res:?}"
    );
    assert!(
        !env.candidate_dir.exists(),
        "the candidate cgroup must have been removed before the commit"
    );
    // Previous table survived: the agent is still enforced.
    let after_fail = agent_raw(&env.topo, &agent_procs, "tcp", denied_v4);
    assert_eq!(
        after_fail["outcome"], "blocked_or_unreachable",
        "previous table must survive a failed apply: {after_fail}"
    );
    // Disrupt: destroy the table so enforcement is gone.
    let netns_runner = NetnsNftRunner {
        ns_name: env.topo.ns_name.clone(),
    };
    nft::cleanup(&table, &netns_runner).expect("disrupting destroy must succeed");
    let disrupted = agent_raw(&env.topo, &agent_procs, "tcp", denied_v4);
    assert_eq!(
        disrupted["outcome"], "connected",
        "with the table destroyed the agent must reach the target: {disrupted}"
    );
    // Rollback re-applies the last-known-good ruleset.
    env.armed
        .as_ref()
        .unwrap()
        .rollback()
        .expect("rollback must succeed");
    let restored = agent_raw(&env.topo, &agent_procs, "tcp", denied_v4);
    assert_eq!(
        restored["outcome"], "blocked_or_unreachable",
        "rollback must restore enforcement: {restored}"
    );

    // ── Scenario 12 (fix F): marked upstream DNS with UDP-truncation → TCP
    // fallback. Restart the gateway using a real ForwardingResolver pointed at
    // the local DNS fixture (which always truncates over UDP), require both DNS
    // listeners ready, and prove a brokered CONNECT to a forward-resolved name
    // succeeds end to end.
    env.kill_children();
    thread::sleep(Duration::from_millis(200));
    let forward = forward_policy_json(&env.topo);
    let forward_policy = env.temp_config(&forward);
    let fwd = spawn_forwarding_gateway(&env.topo, &forward_policy, dns_fixture, &broker_procs);
    env.track(fwd);
    wait_for_gateway_ready(&env.topo, &agent_procs, true);
    let forwarded = connect_attempt(
        &env.topo,
        &agent_procs,
        "forward.fixture",
        forward_connect_port,
    );
    assert_eq!(
        forwarded["outcome"], "ok",
        "brokered CONNECT via marked forwarding DNS (UDP->TCP) must succeed: {forwarded}"
    );
    assert_eq!(
        forwarded["echo_verified"], true,
        "forwarded echo: {forwarded}"
    );
}

fn setup_namespace_and_veth(topo: &Topology) {
    run_checked("ip", &["netns", "add", &topo.ns_name]);
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
    );
    run_checked(
        "ip",
        &["link", "set", &topo.veth_guest, "netns", &topo.ns_name],
    );
    run_checked(
        "ip",
        &[
            "addr",
            "add",
            &format!("{}/30", topo.host_v4),
            "dev",
            &topo.veth_host,
        ],
    );
    run_checked(
        "ip",
        &[
            "-6",
            "addr",
            "add",
            &format!("{}/126", topo.host_v6),
            "dev",
            &topo.veth_host,
            "nodad",
        ],
    );
    run_checked("ip", &["link", "set", &topo.veth_host, "up"]);
    let ns = topo.ns_name.as_str();
    run_checked(
        "ip",
        &[
            "netns",
            "exec",
            ns,
            "ip",
            "addr",
            "add",
            "10.210.0.2/30",
            "dev",
            &topo.veth_guest,
        ],
    );
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
            "fd00:beef::2/126",
            "dev",
            &topo.veth_guest,
            "nodad",
        ],
    );
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
    );
    run_checked(
        "ip",
        &["netns", "exec", ns, "ip", "link", "set", "lo", "up"],
    );
}

fn table_present(topo: &Topology, config: &NftConfig) -> bool {
    run(
        "ip",
        &[
            "netns",
            "exec",
            &topo.ns_name,
            "nft",
            "list",
            "table",
            "inet",
            &config.table_name,
        ],
    )
    .map(|o| o.status.success())
    .unwrap_or(false)
}

fn spawn_echo(addr: SocketAddr) -> thread::JoinHandle<()> {
    use std::io::Read;
    let listener = std::net::TcpListener::bind(addr).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            thread::spawn(move || {
                let mut buf = [0u8; 512];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    })
}

fn spawn_udp_echo(addr: SocketAddr) -> thread::JoinHandle<()> {
    let socket = std::net::UdpSocket::bind(addr).unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], peer);
        }
    })
}

/// A DNS fixture that always truncates over UDP (forcing a TCP retry) and
/// answers `forward.fixture. A -> answer_ip` over TCP. Used to exercise the
/// broker's marked ForwardingResolver and its UDP→TCP fallback.
fn spawn_dns_fixture(addr: SocketAddr, answer_ip: Ipv4Addr) -> Vec<thread::JoinHandle<()>> {
    use hickory_proto::op::{Message, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::io::Read;

    fn build_answer(query: &Message, answer_ip: Ipv4Addr, truncated: bool) -> Message {
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.metadata.truncation = truncated;
        response.metadata.response_code = ResponseCode::NoError;
        for q in &query.queries {
            response.add_query(q.clone());
        }
        if !truncated
            && let Some(q) = query.queries.first()
            && q.query_type() == RecordType::A
        {
            response.add_answer(Record::from_rdata(
                Name::from_str("forward.fixture.").unwrap(),
                30,
                RData::A(A(answer_ip)),
            ));
        }
        response
    }

    let udp = std::net::UdpSocket::bind(addr).unwrap();
    let udp_handle = thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf) else {
                break;
            };
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            // Always truncate over UDP to force the TCP fallback.
            let response = build_answer(&query, answer_ip, true);
            if let Ok(bytes) = response.to_vec() {
                let _ = udp.send_to(&bytes, peer);
            }
        }
    });

    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let tcp_handle = thread::spawn(move || {
        for stream in tcp.incoming() {
            let Ok(mut stream) = stream else { break };
            thread::spawn(move || {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).is_err() {
                    return;
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; n];
                if stream.read_exact(&mut msg).is_err() {
                    return;
                }
                let Ok(query) = Message::from_vec(&msg) else {
                    return;
                };
                let response = build_answer(&query, answer_ip, false);
                let Ok(bytes) = response.to_vec() else {
                    return;
                };
                let prefix = (bytes.len() as u16).to_be_bytes();
                let _ = stream.write_all(&prefix);
                let _ = stream.write_all(&bytes);
            });
        }
    });
    vec![udp_handle, tcp_handle]
}

fn harness_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    path.pop(); // profile
    path.push("sendbox-egress-harness");
    path
}

fn policy_json(topo: &Topology) -> String {
    serde_json::json!({
        "default_action": "deny",
        "allowed_domains": ["allowed.fixture", "allowed-v6.fixture"],
        "blocked_domains": [],
        "allow_dns": true,
        "max_connections": 8,
        "allowed_networks": [format!("{}/32", topo.host_v4), format!("{}/128", topo.host_v6)],
        "blocked_networks": [],
        "allowed_ports": [],
        "dns": { "max_ttl_secs": 30 }
    })
    .to_string()
}

fn forward_policy_json(topo: &Topology) -> String {
    serde_json::json!({
        "default_action": "deny",
        "allowed_domains": ["forward.fixture"],
        "blocked_domains": [],
        "allow_dns": true,
        "max_connections": 8,
        "allowed_networks": [format!("{}/32", topo.host_v4)],
        "blocked_networks": [],
        "allowed_ports": [],
        "dns": { "max_ttl_secs": 30 }
    })
    .to_string()
}

fn fixtures_json(v4: SocketAddr, v6: SocketAddr) -> String {
    serde_json::json!({
        "allowed.fixture.": {
            "cname_chain": [],
            "final_name": "allowed.fixture.",
            "addresses": [{ "ip": v4.ip().to_string(), "ttl_secs": 30 }]
        },
        "allowed-v6.fixture.": {
            "cname_chain": [],
            "final_name": "allowed-v6.fixture.",
            "addresses": [{ "ip": v6.ip().to_string(), "ttl_secs": 30 }]
        }
    })
    .to_string()
}

fn spawn_gateway(topo: &Topology, policy: &Path, fixtures: &Path, broker_procs: &Path) -> Child {
    Command::new("ip")
        .args([
            "netns",
            "exec",
            &topo.ns_name,
            harness_binary().to_str().unwrap(),
            "gateway",
            "--policy",
            policy.to_str().unwrap(),
            "--fixtures",
            fixtures.to_str().unwrap(),
            "--dns-listen",
            &format!("127.0.0.1:{DNS_PORT}"),
            "--connect-listen",
            &format!("127.0.0.1:{CONNECT_PORT}"),
            "--cgroup-procs",
            broker_procs.to_str().unwrap(),
            "--broker-mark",
            &BROKER_MARK.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gateway")
}

fn spawn_forwarding_gateway(
    topo: &Topology,
    policy: &Path,
    dns_upstream: SocketAddr,
    broker_procs: &Path,
) -> Child {
    Command::new("ip")
        .args([
            "netns",
            "exec",
            &topo.ns_name,
            harness_binary().to_str().unwrap(),
            "gateway",
            "--policy",
            policy.to_str().unwrap(),
            "--dns-upstream",
            &dns_upstream.to_string(),
            "--dns-listen",
            &format!("127.0.0.1:{DNS_PORT}"),
            "--connect-listen",
            &format!("127.0.0.1:{CONNECT_PORT}"),
            "--cgroup-procs",
            broker_procs.to_str().unwrap(),
            "--broker-mark",
            &BROKER_MARK.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn forwarding gateway")
}

fn wait_for_gateway_ready(topo: &Topology, agent_procs: &Path, require_dns: bool) {
    for _ in 0..80 {
        let probe = run(
            "ip",
            &[
                "netns",
                "exec",
                &topo.ns_name,
                harness_binary().to_str().unwrap(),
                "gateway-probe",
                "--dns",
                &format!("127.0.0.1:{DNS_PORT}"),
                "--connect",
                &format!("127.0.0.1:{CONNECT_PORT}"),
                "--cgroup-procs",
                agent_procs.to_str().unwrap(),
            ],
        )
        .expect("gateway-probe");
        if let Ok(value) = parse_last_json(&probe.stdout) {
            let connect = value["connect_ready"] == true;
            let dns = value["dns_udp_ready"] == true && value["dns_tcp_ready"] == true;
            if connect && (!require_dns || dns) {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("gateway did not become ready in time");
}

fn connect_attempt(topo: &Topology, agent_procs: &Path, target: &str, port: u16) -> Value {
    // The agent connects unprivileged (all caps cleared, no_new_privs).
    let output = run(
        "ip",
        &[
            "netns",
            "exec",
            &topo.ns_name,
            harness_binary().to_str().unwrap(),
            "connect-attempt",
            "--broker",
            &format!("127.0.0.1:{CONNECT_PORT}"),
            "--target",
            target,
            "--port",
            &port.to_string(),
            "--cgroup-procs",
            agent_procs.to_str().unwrap(),
            "--drop-to-uid",
            &AGENT_UID.to_string(),
        ],
    )
    .expect("connect-attempt");
    parse_last_json(&output.stdout).expect("connect-attempt json")
}

/// An agent raw attempt: placed in the agent cgroup, then dropped to an
/// unprivileged identity with all capabilities cleared.
fn agent_raw(topo: &Topology, agent_procs: &Path, protocol: &str, target: SocketAddr) -> Value {
    raw_invoke(
        topo,
        &[
            "--cgroup-procs",
            agent_procs.to_str().unwrap(),
            "--drop-to-uid",
            &AGENT_UID.to_string(),
        ],
        protocol,
        target,
    )
}

/// A broker positive-control raw attempt: placed in the broker cgroup and
/// carrying the fixed SO_MARK, so it may reach external destinations.
fn broker_raw(topo: &Topology, broker_procs: &Path, protocol: &str, target: SocketAddr) -> Value {
    raw_invoke(
        topo,
        &[
            "--cgroup-procs",
            broker_procs.to_str().unwrap(),
            "--socket-mark",
            &BROKER_MARK.to_string(),
        ],
        protocol,
        target,
    )
}

/// A broker raw attempt WITHOUT the mark: proves cgroup identity alone is not
/// sufficient for external egress.
fn broker_raw_no_mark(
    topo: &Topology,
    broker_procs: &Path,
    protocol: &str,
    target: SocketAddr,
) -> Value {
    raw_invoke(
        topo,
        &["--cgroup-procs", broker_procs.to_str().unwrap()],
        protocol,
        target,
    )
}

/// A sibling raw attempt: in neither cgroup and unmarked.
fn sibling_raw(topo: &Topology, protocol: &str, target: SocketAddr) -> Value {
    raw_invoke(topo, &[], protocol, target)
}

fn raw_invoke(topo: &Topology, extra: &[&str], protocol: &str, target: SocketAddr) -> Value {
    let harness = harness_binary();
    let target = target.to_string();
    let mut args: Vec<&str> = vec![
        "netns",
        "exec",
        &topo.ns_name,
        harness.to_str().unwrap(),
        "raw-attempt",
        "--protocol",
        protocol,
        "--target",
        &target,
    ];
    args.extend_from_slice(extra);
    let output = run("ip", &args).expect("raw-attempt");
    parse_last_json(&output.stdout).expect("raw-attempt json")
}

fn caps_probe(topo: &Topology, agent_procs: &Path) -> Value {
    let output = run(
        "ip",
        &[
            "netns",
            "exec",
            &topo.ns_name,
            harness_binary().to_str().unwrap(),
            "caps-probe",
            "--cgroup-procs",
            agent_procs.to_str().unwrap(),
            "--drop-to-uid",
            &AGENT_UID.to_string(),
        ],
    )
    .expect("caps-probe");
    parse_last_json(&output.stdout).expect("caps-probe json")
}

fn raw_socket_probe(topo: &Topology, agent_procs: &Path) -> Value {
    let output = run(
        "ip",
        &[
            "netns",
            "exec",
            &topo.ns_name,
            harness_binary().to_str().unwrap(),
            "raw-socket-probe",
            "--cgroup-procs",
            agent_procs.to_str().unwrap(),
            "--drop-to-uid",
            &AGENT_UID.to_string(),
        ],
    )
    .expect("raw-socket-probe");
    parse_last_json(&output.stdout).expect("raw-socket-probe json")
}

fn parse_last_json(stdout: &[u8]) -> Result<Value, serde_json::Error> {
    let text = String::from_utf8_lossy(stdout);
    let line = text
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or("{}");
    serde_json::from_str(line)
}
