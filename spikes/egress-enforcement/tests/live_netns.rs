//! Opt-in Linux network namespace live enforcement proof.
//!
//! This test is intentionally inert everywhere except a Linux host running
//! as root with `SENDBOX_EGRESS_LIVE=1` set, because it mutates real kernel
//! state (creates a network namespace, a veth pair, and an `nft` table).
//! Gating order:
//! 1. `target_os == "linux"` — this mechanism is Linux-only by design.
//! 2. `SENDBOX_EGRESS_LIVE=1` — explicit opt-in, so a plain `cargo test`
//!    (including on Linux, including as root) never mutates host state.
//! 3. [`CapabilityReport::all_ready`] — `ip`/`nft`/`setpriv` must be present
//!    and the process must be root.
//!
//! When gate 3 fails, the test prints the exact JSON capability verdict and
//! returns rather than silently reporting success. If `SENDBOX_EGRESS_LIVE_REQUIRE=1`
//! is also set (used by the CI job that specifically claims to run the live
//! suite), a missing capability instead fails the test loudly, so that job
//! can never silently downgrade to a no-op.
//!
//! Cleanup is RAII-based: [`LiveEnvironment`] is constructed *before* any
//! namespace/veth/firewall mutation begins, and its `Drop` implementation
//! always runs `netns_harness::teardown` (idempotent/absent-safe) and kills
//! every tracked child process, whether the test completes normally, an
//! assertion fails, or a panic unwinds through it. `live_netns_injected_failure_cleanup`
//! specifically proves this by triggering a panic mid-setup and then
//! asserting the namespace and any spawned process are gone.
//!
//! macOS note: this test always takes the gate-1 exit on the local
//! development host used for this spike; the live enforcement claims below
//! are proven only when this file actually runs to completion on Linux with
//! root (see `docs/egress-enforcement-spike.md` for the current recorded
//! result).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use egress_enforcement_spike::netns_harness::{self, CapabilityReport, NetnsTopology};
use serde_json::Value;

const OPT_IN_ENV: &str = "SENDBOX_EGRESS_LIVE";
const REQUIRE_ENV: &str = "SENDBOX_EGRESS_LIVE_REQUIRE";
const AGENT_UID: u32 = 65177;
const BROKER_UID: u32 = 65178;
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const DNS_PORT: u16 = 15053;
const CONNECT_PORT: u16 = 15080;

/// RAII guard for one live namespace environment. Constructed before any
/// mutation begins; its `Drop` impl always tears down whatever was created
/// (namespace, veth, nft table) and kills every tracked child process, so a
/// panic anywhere in setup or in a scenario assertion still leaves no
/// leaked kernel state or orphaned processes.
struct LiveEnvironment {
    topo: NetnsTopology,
    children: Vec<Child>,
}

impl LiveEnvironment {
    fn new(topo: NetnsTopology) -> Self {
        Self {
            topo,
            children: Vec::new(),
        }
    }

    fn track(&mut self, child: Child) {
        self.children.push(child);
    }

    /// Returns the most recently tracked child. Used to run the readiness
    /// probe *after* the child is already tracked (so a panic during
    /// readiness-waiting still results in the process being killed by
    /// `Drop`, instead of leaking an untracked `Child`).
    fn last_child_mut(&mut self) -> &mut Child {
        self.children
            .last_mut()
            .expect("last_child_mut called with no tracked child")
    }

    fn kill_all_children(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.children.clear();
    }

    /// Kills every tracked child and removes the namespace/nft table.
    /// Idempotent and absent-safe: calling this more than once (or letting
    /// `Drop` call it again after an explicit call) must never error and
    /// must never leave anything behind that a prior call did not already
    /// remove.
    fn teardown(&mut self) -> Vec<netns_harness::HarnessError> {
        self.kill_all_children();
        netns_harness::teardown(&self.topo)
    }
}

impl Drop for LiveEnvironment {
    fn drop(&mut self) {
        // Best-effort: this is the safety net that fires even if the test
        // panicked before an explicit `teardown()` call, or if `teardown()`
        // was already called (in which case this is just an extra
        // idempotent pass).
        let _ = self.teardown();
    }
}

#[test]
fn live_netns_enforcement_proof() {
    let Some(()) = gate_or_skip() else {
        return;
    };

    let topo = NetnsTopology::generate(AGENT_UID, BROKER_UID);
    let mut env = LiveEnvironment::new(topo);
    run_live_suite(&mut env);

    // Explicit teardown, called twice, to assert idempotency directly
    // (beyond the implicit third pass `Drop` performs at function end).
    let errors_first = env.teardown();
    assert!(
        errors_first.is_empty(),
        "first explicit teardown must not report errors: {errors_first:?}"
    );
    let errors_second = env.teardown();
    assert!(
        errors_second.is_empty(),
        "second (idempotent) teardown must not report errors: {errors_second:?}"
    );

    let namespaces_after = netns_harness::run("ip", &["netns", "list"])
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    assert!(
        !namespaces_after.contains(&env.topo.ns_name),
        "namespace must not exist after teardown: {namespaces_after}"
    );
}

/// Deliberately panics partway through setup and asserts that the RAII
/// guard's `Drop` impl still removed the namespace and killed the spawned
/// process, proving cleanup after an injected failure — not just after a
/// clean run.
#[test]
fn live_netns_injected_failure_cleanup() {
    let Some(()) = gate_or_skip() else {
        return;
    };

    let topo = NetnsTopology::generate(AGENT_UID + 1000, BROKER_UID + 1000);
    let ns_name = topo.ns_name.clone();
    let leaked_child_pid: std::cell::Cell<Option<u32>> = std::cell::Cell::new(None);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut env = LiveEnvironment::new(topo);
        netns_harness::setup_namespace_and_veth(&env.topo)
            .expect("namespace/veth setup must succeed with root+ip present");
        netns_harness::apply_firewall(&env.topo, DNS_PORT, DNS_PORT, CONNECT_PORT)
            .expect("nft apply must succeed with root+nft present");

        let fixture_addr = SocketAddr::new(IpAddr::V4(env.topo.host_v4), 19099);
        let _fixture = spawn_echo_fixture(fixture_addr);
        let policy_path = write_policy_file(&env.topo);
        let fixtures_path = write_fixtures_file(fixture_addr, None);
        let child = spawn_gateway(
            &env.topo,
            &policy_path,
            &fixtures_path,
            DNS_PORT,
            CONNECT_PORT,
        );
        leaked_child_pid.set(Some(child.id()));
        env.track(child);
        wait_for_gateway_ready(&mut env, DNS_PORT, CONNECT_PORT);

        panic!("injected failure: simulating a mid-run failure to prove Drop-based cleanup");
    }));

    assert!(
        result.is_err(),
        "the injected panic must actually have occurred"
    );

    let namespaces_after = netns_harness::run("ip", &["netns", "list"])
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    assert!(
        !namespaces_after.contains(&ns_name),
        "namespace must be cleaned up after an injected failure, found: {namespaces_after}"
    );

    if let Some(pid) = leaked_child_pid.get() {
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "spawned gateway process {pid} must not survive an injected failure (no leaked processes)"
        );
    }
}

/// Applies the gating order (Linux, opt-in env var, capability probe) once
/// for both live tests. Returns `Some(())` when the caller should proceed,
/// or `None` after already printing/asserting the appropriate skip/failure.
fn gate_or_skip() -> Option<()> {
    if !netns_harness::is_linux() {
        eprintln!(
            "SKIP (documented limitation): the network-namespace enforcement proof only runs on \
             Linux; current host OS is '{}'. See docs/egress-enforcement-spike.md for the Linux/CI \
             evidence this spike relies on instead.",
            std::env::consts::OS
        );
        return None;
    }

    if std::env::var(OPT_IN_ENV).as_deref() != Ok("1") {
        eprintln!(
            "SKIP (opt-in required): set {OPT_IN_ENV}=1 to run the live network-namespace suite. \
             This mutates kernel state (namespace, veth, nftables) and requires root."
        );
        return None;
    }

    let report = CapabilityReport::probe();
    if !report.all_ready() {
        eprintln!("CAPABILITY VERDICT: {}", report.to_json());
        if std::env::var(REQUIRE_ENV).as_deref() == Ok("1") {
            panic!(
                "required live capabilities are not available: {}",
                report.to_json()
            );
        }
        eprintln!(
            "SKIP: required capabilities (root, ip, nft, setpriv) are not fully available in this \
             environment; see the verdict above for exactly which one is missing."
        );
        return None;
    }

    Some(())
}

fn run_live_suite(env: &mut LiveEnvironment) {
    let allowed_v4_port: u16 = 19001;
    let denied_v4_port: u16 = 19002;
    let alt_dns_fixture_port: u16 = 53;
    let metadata_fixture_port: u16 = 80;
    let udp_echo_port: u16 = 19005;
    let allowed_v6_port: u16 = 19006;
    let denied_v6_port: u16 = 19007;

    netns_harness::setup_namespace_and_veth(&env.topo)
        .expect("namespace/veth setup must succeed with root+ip present");

    // Give the guest namespace a route to the metadata literal, which is
    // outside the /30 veth subnet, and add it as a secondary address on the
    // host side so a broker-UID connection attempt has a real listener to
    // either reach (bug) or be blocked from reaching (expected).
    netns_harness::run_checked(
        "ip",
        &[
            "addr",
            "add",
            &format!("{METADATA_V4}/32"),
            "dev",
            &env.topo.veth_host,
        ],
    )
    .expect("adding secondary metadata address to host veth must succeed");
    netns_harness::run_checked(
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
    )
    .expect("adding guest route to metadata literal must succeed");

    netns_harness::apply_firewall(&env.topo, DNS_PORT, DNS_PORT, CONNECT_PORT)
        .expect("nft apply must succeed with root+nft present");

    let allowed_v4_addr = SocketAddr::new(IpAddr::V4(env.topo.host_v4), allowed_v4_port);
    let denied_v4_addr = SocketAddr::new(IpAddr::V4(env.topo.host_v4), denied_v4_port);
    let alt_dns_addr = SocketAddr::new(IpAddr::V4(env.topo.host_v4), alt_dns_fixture_port);
    let metadata_addr = SocketAddr::new(IpAddr::V4(METADATA_V4), metadata_fixture_port);
    let udp_echo_addr = SocketAddr::new(IpAddr::V4(env.topo.host_v4), udp_echo_port);
    let allowed_v6_addr = SocketAddr::new(IpAddr::V6(env.topo.host_v6), allowed_v6_port);
    let denied_v6_addr = SocketAddr::new(IpAddr::V6(env.topo.host_v6), denied_v6_port);

    let _allowed_v4_fixture = spawn_echo_fixture(allowed_v4_addr);
    let _allowed_v4_udp_fixture = spawn_udp_echo_fixture(allowed_v4_addr);
    let _denied_v4_fixture = spawn_echo_fixture(denied_v4_addr);
    let _alt_dns_fixture = spawn_echo_fixture(alt_dns_addr);
    let _alt_dns_udp_fixture = spawn_udp_echo_fixture(alt_dns_addr);
    let _metadata_fixture = spawn_echo_fixture(metadata_addr);
    let _udp_echo_fixture = spawn_udp_echo_fixture(udp_echo_addr);
    let _allowed_v6_fixture = spawn_echo_fixture(allowed_v6_addr);
    let _denied_v6_fixture = spawn_echo_fixture(denied_v6_addr);

    let policy_path = write_policy_file(&env.topo);
    let fixtures_path = write_fixtures_file(allowed_v4_addr, Some(allowed_v6_addr));

    let gateway = spawn_gateway(
        &env.topo,
        &policy_path,
        &fixtures_path,
        DNS_PORT,
        CONNECT_PORT,
    );
    env.track(gateway);
    wait_for_gateway_ready(env, DNS_PORT, CONNECT_PORT);

    // Scenario 1: brokered allow succeeds end to end (IPv4).
    let brokered = connect_attempt(&env.topo, "allowed.fixture", allowed_v4_port, None);
    assert_eq!(
        brokered["outcome"], "ok",
        "brokered allow (v4) must succeed: {brokered}"
    );
    assert_eq!(
        brokered["echo_verified"], true,
        "brokered echo (v4) must round-trip: {brokered}"
    );

    // Scenario 1b: brokered allow succeeds end to end (IPv6) — a genuine
    // positive control proving IPv6 connectivity works through the
    // gateway, not merely that IPv6 traffic is silently ignored.
    let brokered_v6 = connect_attempt(&env.topo, "allowed-v6.fixture", allowed_v6_port, None);
    assert_eq!(
        brokered_v6["outcome"], "ok",
        "brokered allow (v6) must succeed: {brokered_v6}"
    );
    assert_eq!(
        brokered_v6["echo_verified"], true,
        "brokered echo (v6) must round-trip: {brokered_v6}"
    );

    // Scenario 2: direct allowed-domain IP bypass is blocked for the
    // agent UID even though the same address is reachable via the broker
    // (IPv4 and IPv6).
    let bypass_v4 = raw_attempt(&env.topo, AGENT_UID, "tcp", allowed_v4_addr);
    assert_eq!(
        bypass_v4["outcome"], "blocked_or_unreachable",
        "direct bypass of the allowed IPv4 must be blocked: {bypass_v4}"
    );
    let bypass_v6 = raw_attempt(&env.topo, AGENT_UID, "tcp", allowed_v6_addr);
    assert_eq!(
        bypass_v6["outcome"], "blocked_or_unreachable",
        "direct bypass of the allowed IPv6 must be blocked: {bypass_v6}"
    );

    // Scenario 3: arbitrary direct v4/v6 destination blocked.
    let arbitrary_v4 = raw_attempt(&env.topo, AGENT_UID, "tcp", denied_v4_addr);
    assert_eq!(
        arbitrary_v4["outcome"], "blocked_or_unreachable",
        "arbitrary direct IPv4 must be blocked: {arbitrary_v4}"
    );
    let arbitrary_v6 = raw_attempt(&env.topo, AGENT_UID, "tcp", denied_v6_addr);
    assert_eq!(
        arbitrary_v6["outcome"], "blocked_or_unreachable",
        "arbitrary direct IPv6 must be blocked: {arbitrary_v6}"
    );

    // Scenario 4: alternate DNS (TCP and UDP, non-broker port) blocked. The
    // UDP half uses the same not-vacuous positive-control pattern as
    // scenario 5 below: a genuine UDP echo fixture on the *exact* address
    // and port used for the agent-deny assertion, proven reachable by the
    // broker UID first.
    let alt_dns_tcp = raw_attempt(&env.topo, AGENT_UID, "tcp", alt_dns_addr);
    assert_eq!(
        alt_dns_tcp["outcome"], "blocked_or_unreachable",
        "alternate TCP DNS must be blocked: {alt_dns_tcp}"
    );
    let alt_dns_udp_positive_control = raw_attempt(&env.topo, BROKER_UID, "udp", alt_dns_addr);
    assert_eq!(
        alt_dns_udp_positive_control["outcome"], "connected",
        "positive control: broker UID must reach the alternate-DNS UDP fixture when not blocked: {alt_dns_udp_positive_control}"
    );
    let alt_dns_udp = raw_attempt(&env.topo, AGENT_UID, "udp", alt_dns_addr);
    assert_eq!(
        alt_dns_udp["outcome"], "blocked_or_unreachable",
        "alternate UDP DNS must be blocked from a destination proven reachable above: {alt_dns_udp}"
    );

    // Scenario 5 (UDP positive control + negative, not vacuous): UDP is
    // connectionless, so "blocked" and "unreachable-but-not-blocked" look
    // identical from a client that never gets a reply. This differential
    // makes the negative meaningful: the broker UID (which nftables allows
    // to originate arbitrary egress) is first proven able to reach and
    // round-trip with a genuine UDP echo fixture; only then is the agent
    // UID's denial against that *same, demonstrably reachable* target
    // asserted.
    let broker_udp_positive_control = raw_attempt(&env.topo, BROKER_UID, "udp", udp_echo_addr);
    assert_eq!(
        broker_udp_positive_control["outcome"], "connected",
        "positive control: broker UID must reach the UDP echo fixture when not blocked: {broker_udp_positive_control}"
    );
    let agent_udp_denied = raw_attempt(&env.topo, AGENT_UID, "udp", udp_echo_addr);
    assert_eq!(
        agent_udp_denied["outcome"], "blocked_or_unreachable",
        "agent must be blocked from a UDP destination proven reachable above: {agent_udp_denied}"
    );

    // Scenario 6: metadata is blocked for the agent UID (trivially, via
    // default-drop) and, more importantly, for the broker UID too, as a
    // kernel-level defense-in-depth independent of the broker's own
    // userspace SSRF guard.
    let agent_metadata = raw_attempt(&env.topo, AGENT_UID, "tcp", metadata_addr);
    assert_eq!(
        agent_metadata["outcome"], "blocked_or_unreachable",
        "agent must never reach metadata: {agent_metadata}"
    );
    let broker_metadata = raw_attempt(&env.topo, BROKER_UID, "tcp", metadata_addr);
    assert_eq!(
        broker_metadata["outcome"], "blocked_or_unreachable",
        "broker UID must be kernel-blocked from metadata even bypassing its own policy engine: {broker_metadata}"
    );

    // Scenario 7: UDP is unconditionally denied for the agent even toward
    // the allowed fixture address — again with a positive control on the
    // exact same address+port tuple first, since a TCP-reachable fixture
    // address says nothing about UDP reachability.
    let allowed_v4_udp_positive_control =
        raw_attempt(&env.topo, BROKER_UID, "udp", allowed_v4_addr);
    assert_eq!(
        allowed_v4_udp_positive_control["outcome"], "connected",
        "positive control: broker UID must reach the allowed fixture's UDP echo when not blocked: {allowed_v4_udp_positive_control}"
    );
    let udp_denied = raw_attempt(&env.topo, AGENT_UID, "udp", allowed_v4_addr);
    assert_eq!(
        udp_denied["outcome"], "blocked_or_unreachable",
        "all UDP must be blocked for the agent, from a destination proven reachable above: {udp_denied}"
    );

    // Scenario 7b: the agent process actually has every capability set
    // cleared (not just a UID change). `Cap*` fields in `/proc/self/status`
    // are 16-hex-digit bitmasks; all-zero means that set is empty.
    let agent_caps = caps_probe(&env.topo, AGENT_UID);
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert_eq!(
            agent_caps[field], "0000000000000000",
            "agent capability set {field} must be fully cleared: {agent_caps}"
        );
    }

    // Scenario 8: kill the gateway; rules must remain default-deny.
    env.kill_all_children();
    thread::sleep(Duration::from_millis(200));

    let table_listing = netns_harness::run(
        "ip",
        &[
            "netns",
            "exec",
            &env.topo.ns_name,
            "nft",
            "list",
            "table",
            "inet",
            &env.topo.table_name,
        ],
    )
    .expect("listing the table after gateway death must still succeed as a command");
    assert!(
        table_listing.status.success(),
        "nft table must persist after the gateway dies"
    );

    let still_blocked = raw_attempt(&env.topo, AGENT_UID, "tcp", denied_v4_addr);
    assert_eq!(
        still_blocked["outcome"], "blocked_or_unreachable",
        "default-deny must hold with the gateway dead: {still_blocked}"
    );

    // Scenario 9: restart the gateway; brokered allow works again.
    let gateway2 = spawn_gateway(
        &env.topo,
        &policy_path,
        &fixtures_path,
        DNS_PORT,
        CONNECT_PORT,
    );
    env.track(gateway2);
    wait_for_gateway_ready(env, DNS_PORT, CONNECT_PORT);
    let restarted = connect_attempt(&env.topo, "allowed.fixture", allowed_v4_port, None);
    assert_eq!(
        restarted["outcome"], "ok",
        "brokered allow must work again after restart: {restarted}"
    );
}

fn spawn_echo_fixture(addr: SocketAddr) -> thread::JoinHandle<()> {
    let listener = TcpListener::bind(addr)
        .unwrap_or_else(|err| panic!("binding fixture {addr} must succeed: {err}"));
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    })
}

/// A real UDP echo fixture (not merely a target that happens to have no
/// listener). Needed to make a UDP "blocked" assertion meaningful: without
/// a fixture that demonstrably responds when reachable, a blocked
/// connectionless probe and an unreachable-but-unblocked one are
/// indistinguishable.
fn spawn_udp_echo_fixture(addr: SocketAddr) -> thread::JoinHandle<()> {
    let socket = UdpSocket::bind(addr)
        .unwrap_or_else(|err| panic!("binding udp fixture {addr} must succeed: {err}"));
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], peer);
        }
    })
}

fn write_policy_file(topo: &NetnsTopology) -> PathBuf {
    let policy = serde_json::json!({
        "default_action": "deny",
        "allowed_domains": ["allowed.fixture", "allowed-v6.fixture"],
        "blocked_domains": [],
        "allowed_networks": [format!("{}/32", topo.host_v4), format!("{}/128", topo.host_v6)],
        "blocked_networks": [],
        "allowed_ports": [],
        "max_concurrent_connections": 8,
        "max_dns_ttl_secs": 30
    });
    write_temp_json("egress-spike-policy", &policy)
}

fn write_fixtures_file(
    allowed_v4_addr: SocketAddr,
    allowed_v6_addr: Option<SocketAddr>,
) -> PathBuf {
    let mut fixtures = serde_json::json!({
        "allowed.fixture.": {
            "cname_chain": [],
            "final_name": "allowed.fixture.",
            "addresses": [{ "ip": allowed_v4_addr.ip().to_string(), "ttl_secs": 30 }]
        }
    });
    if let Some(v6_addr) = allowed_v6_addr {
        fixtures["allowed-v6.fixture."] = serde_json::json!({
            "cname_chain": [],
            "final_name": "allowed-v6.fixture.",
            "addresses": [{ "ip": v6_addr.ip().to_string(), "ttl_secs": 30 }]
        });
    }
    write_temp_json("egress-spike-fixtures", &fixtures)
}

fn write_temp_json(prefix: &str, value: &Value) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("{prefix}-{}.json", netns_harness::unique_suffix()));
    std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap())
        .expect("writing temp fixture/policy file must succeed");
    // World-readable so a gateway process running under a distinct,
    // unprivileged UID can read it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
    }
    path
}

fn gateway_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_egress-gateway"))
}

fn harness_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_netns-harness"))
}

/// Spawns the single `egress-gateway` process (DNS broker + CONNECT broker,
/// sharing one authorization cache) as the broker UID inside the namespace.
fn spawn_gateway(
    topo: &NetnsTopology,
    policy_path: &Path,
    fixtures_path: &Path,
    dns_port: u16,
    connect_port: u16,
) -> Child {
    Command::new("ip")
        .args(["netns", "exec", &topo.ns_name])
        .args(netns_harness::setpriv_argv(topo.broker_uid))
        .arg(gateway_binary())
        .args(["--policy", &policy_path.to_string_lossy()])
        .args(["--fixtures", &fixtures_path.to_string_lossy()])
        .args(["--dns-listen", &format!("127.0.0.1:{dns_port}")])
        .args(["--connect-listen", &format!("127.0.0.1:{connect_port}")])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("spawning egress-gateway must succeed: {err}"))
}

/// Polls the *actual* running gateway from inside the target namespace (as
/// the agent UID, mirroring the real consumer of these ports) using the
/// `netns-harness gateway-probe` subcommand, which performs genuine DNS
/// (UDP + TCP) and CONNECT protocol round-trips rather than a bare
/// port-open check. Fails loudly — panicking rather than silently
/// continuing — in two cases: the gateway child has already exited before
/// becoming ready, or the probe command itself exits non-zero (a tooling
/// failure distinct from "not ready yet", since `gateway-probe` always
/// exits successfully and reports readiness via its JSON body). Panics on
/// overall timeout instead of proceeding blindly.
fn wait_for_gateway_ready(env: &mut LiveEnvironment, dns_port: u16, connect_port: u16) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let dns_target = format!("127.0.0.1:{dns_port}");
    let connect_target = format!("127.0.0.1:{connect_port}");
    let ns_name = env.topo.ns_name.clone();
    let agent_uid = env.topo.agent_uid;
    let mut last_report: Option<Value> = None;

    loop {
        let gateway = env.last_child_mut();
        if let Ok(Some(status)) = gateway.try_wait() {
            let mut stderr_tail = String::new();
            if let Some(stderr) = gateway.stderr.as_mut() {
                let _ = stderr.read_to_string(&mut stderr_tail);
            }
            panic!(
                "egress-gateway exited early with {status} before becoming ready; stderr: \
                 {stderr_tail}"
            );
        }

        if std::time::Instant::now() >= deadline {
            panic!(
                "egress-gateway did not become ready within the deadline; last probe result: \
                 {last_report:?}"
            );
        }

        let mut args = vec!["netns".to_owned(), "exec".to_owned(), ns_name.clone()];
        args.extend(netns_harness::setpriv_argv(agent_uid));
        args.push(harness_binary().to_string_lossy().into_owned());
        args.push("gateway-probe".to_owned());
        args.push("--dns".to_owned());
        args.push(dns_target.clone());
        args.push("--connect".to_owned());
        args.push(connect_target.clone());
        args.push("--timeout-ms".to_owned());
        args.push("300".to_owned());
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

        let output = netns_harness::run("ip", &arg_refs).unwrap_or_else(|err| {
            panic!("running gateway-probe via ip netns exec must succeed as a command: {err}")
        });
        if !output.status.success() {
            panic!(
                "gateway-probe exited with {}, which is a tooling failure distinct from \
                 'not ready yet': stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let report = parse_last_json_line(&output.stdout, &output.stderr);
        let ready = report["connect_ready"] == true
            && report["dns_udp_ready"] == true
            && report["dns_tcp_ready"] == true;
        last_report = Some(report);
        if ready {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn raw_attempt(topo: &NetnsTopology, uid: u32, protocol: &str, target: SocketAddr) -> Value {
    let output = Command::new("ip")
        .args(["netns", "exec", &topo.ns_name])
        .args(netns_harness::setpriv_argv(uid))
        .arg(harness_binary())
        .args([
            "raw-attempt",
            "--protocol",
            protocol,
            "--target",
            &target.to_string(),
            "--timeout-ms",
            "800",
        ])
        .output()
        .expect("running raw-attempt via ip netns exec + setpriv must succeed as a command");
    parse_last_json_line(&output.stdout, &output.stderr)
}

fn connect_attempt(
    topo: &NetnsTopology,
    target: &str,
    port: u16,
    expected_ip: Option<IpAddr>,
) -> Value {
    let mut args = vec![
        "connect-attempt".to_owned(),
        "--broker".to_owned(),
        format!("127.0.0.1:{CONNECT_PORT}"),
        "--target".to_owned(),
        target.to_owned(),
        "--port".to_owned(),
        port.to_string(),
        "--timeout-ms".to_owned(),
        "2000".to_owned(),
    ];
    if let Some(ip) = expected_ip {
        args.push("--expected-ip".to_owned());
        args.push(ip.to_string());
    }
    let output = Command::new("ip")
        .args(["netns", "exec", &topo.ns_name])
        .args(netns_harness::setpriv_argv(topo.agent_uid))
        .arg(harness_binary())
        .args(args)
        .output()
        .expect("running connect-attempt via ip netns exec + setpriv must succeed as a command");
    parse_last_json_line(&output.stdout, &output.stderr)
}

/// Runs the `caps-probe` subcommand as `uid` (via the same capability-
/// clearing `setpriv` invocation used everywhere else) and returns the
/// parsed `/proc/self/status` capability-set JSON, so the live suite can
/// assert every set is actually zeroed rather than merely asserting a UID
/// change happened.
fn caps_probe(topo: &NetnsTopology, uid: u32) -> Value {
    let output = Command::new("ip")
        .args(["netns", "exec", &topo.ns_name])
        .args(netns_harness::setpriv_argv(uid))
        .arg(harness_binary())
        .arg("caps-probe")
        .output()
        .expect("running caps-probe via ip netns exec + setpriv must succeed as a command");
    parse_last_json_line(&output.stdout, &output.stderr)
}

fn parse_last_json_line(stdout: &[u8], stderr: &[u8]) -> Value {
    let text = String::from_utf8_lossy(stdout);
    let last_line = text.lines().next_back().unwrap_or_default();
    serde_json::from_str(last_line).unwrap_or_else(|_| {
        serde_json::json!({
            "outcome": "harness_command_error",
            "stdout": text.into_owned(),
            "stderr": String::from_utf8_lossy(stderr).into_owned(),
        })
    })
}
