//! Deterministic nftables ruleset generation and atomic application for the
//! Linux egress enforcement layer.
//!
//! The ruleset lives in one crate-owned, versioned `inet` table (covering IPv4
//! and IPv6 in a single family) applied through `nft -f -` — the ruleset is
//! written to `nft`'s **stdin**, never a temp file, and `nft` is always invoked
//! with an explicit argv, never a shell.
//!
//! Identity is expressed with `socket cgroupv2 level N "path"`, *not*
//! `meta cgroup` (which is cgroup v1 `net_cls` and is deliberately never
//! emitted). The agent cgroup may only reach the loopback broker ports; the
//! broker cgroup may originate external traffic **only** when it also carries
//! the fixed `SO_MARK` (`meta mark`), and never to cloud-metadata addresses.
//!
//! Atomicity: [`NftConfig::render_transaction`] emits a `destroy table` before
//! a fresh table definition, all in one `nft -f -` transaction. `nft` applies a
//! file atomically, so a syntax/reference error anywhere aborts the whole
//! update and leaves the *previous* table intact — never a partial ruleset.

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Output, Stdio};

use thiserror::Error;

/// Version of the owned table's rule layout. Emitted as a comment so rule
/// ownership/version is deterministic and auditable.
pub const SENDBOX_EGRESS_TABLE_VERSION: u32 = 1;

/// A cgroup v2 identity for an `nft socket cgroupv2` match: the cgroup path
/// **relative to the cgroup v2 mount root** (no leading slash) and its depth
/// (`level`), which nftables requires to equal the number of path components.
///
/// The path is exactly what nftables userspace stats under `/sys/fs/cgroup`;
/// the kernel adds the current cgroup-namespace subtree level internally, so the
/// crate's supervisor-owned `sendbox/<instance>/…` hierarchy (created directly
/// under the mount root) is referenced by that mount-relative path, never a
/// process-cgroup-prefixed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupIdentity {
    relative_path: String,
    level: u32,
}

impl CgroupIdentity {
    /// Builds an identity from a cgroup path relative to the cgroup v2 root,
    /// computing and validating the level.
    pub fn new(relative_path: impl Into<String>) -> Result<Self, NftError> {
        let relative_path = relative_path.into();
        let trimmed = relative_path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(NftError::InvalidCgroupPath(relative_path));
        }
        // Reject anything that could break out of the quoted nft string or
        // reference a parent; each component must be a plain path segment.
        let components: Vec<&str> = trimmed.split('/').collect();
        for component in &components {
            let ok = !component.is_empty()
                && *component != "."
                && *component != ".."
                && component
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'));
            if !ok {
                return Err(NftError::InvalidCgroupPath(relative_path));
            }
        }
        let level = u32::try_from(components.len())
            .map_err(|_| NftError::InvalidCgroupPath(relative_path.clone()))?;
        Ok(Self {
            relative_path: trimmed.to_owned(),
            level,
        })
    }

    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    #[must_use]
    pub fn level(&self) -> u32 {
        self.level
    }
}

/// Deterministic nftables configuration for one sandbox.
#[derive(Debug, Clone)]
pub struct NftConfig {
    /// Sanitized table name: must match `^[a-z][a-z0-9_]{0,30}$`.
    pub table_name: String,
    /// The agent cgroup identity (may reach only loopback broker ports).
    pub agent: CgroupIdentity,
    /// The broker cgroup identity (may reach external only when marked).
    pub broker: CgroupIdentity,
    /// The fixed `SO_MARK` the broker sets on its external sockets. Must be
    /// non-zero so the `meta mark` match is meaningful.
    pub broker_mark: u32,
    /// The loopback TCP port the CONNECT broker listens on.
    pub connect_broker_tcp_port: u16,
    /// The loopback port the DNS broker listens on (UDP+TCP), or `None` when
    /// the policy disables DNS (`allow_dns = false`), in which case no DNS
    /// accept rule is emitted at all.
    pub dns_broker_port: Option<u16>,
    /// Cloud metadata IPv4 addresses always dropped for the broker.
    pub metadata_v4_addresses: Vec<Ipv4Addr>,
    /// Cloud metadata IPv6 addresses always dropped for the broker.
    pub metadata_v6_addresses: Vec<Ipv6Addr>,
    /// Optional fixture veth interface for which ICMPv6 neighbor discovery
    /// (types 135/136 only) is permitted, so IPv6 works over a test link.
    pub fixture_iface: Option<String>,
}

#[derive(Debug, Error)]
pub enum NftError {
    #[error("invalid table name '{0}': must match ^[a-z][a-z0-9_]{{0,30}}$")]
    InvalidTableName(String),
    #[error("invalid cgroup path '{0}'")]
    InvalidCgroupPath(String),
    #[error("agent and broker cgroup identities must differ")]
    IdentitiesMustDiffer,
    #[error("broker_mark must be non-zero")]
    ZeroMark,
    #[error("invalid fixture interface name '{0}'")]
    InvalidInterface(String),
    #[error("nft command failed to execute: {0}")]
    CommandFailed(#[source] io::Error),
    #[error("nft exited with status {status}: {stderr}")]
    NonZeroExit { status: String, stderr: String },
}

impl NftConfig {
    /// Validates the configuration, failing closed on any structural problem.
    pub fn validate(&self) -> Result<(), NftError> {
        let bytes = self.table_name.as_bytes();
        let valid_name = !bytes.is_empty()
            && bytes.len() <= 31
            && bytes[0].is_ascii_lowercase()
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_');
        if !valid_name {
            return Err(NftError::InvalidTableName(self.table_name.clone()));
        }
        if self.agent == self.broker {
            return Err(NftError::IdentitiesMustDiffer);
        }
        if self.broker_mark == 0 {
            return Err(NftError::ZeroMark);
        }
        if let Some(iface) = &self.fixture_iface
            && !is_valid_iface(iface)
        {
            return Err(NftError::InvalidInterface(iface.clone()));
        }
        Ok(())
    }

    /// Deterministically renders the table body (no `destroy` prefix). Identical
    /// configuration always renders identical text.
    #[must_use]
    pub fn render(&self) -> String {
        let t = &self.table_name;
        let mut out = String::new();
        let _ = writeln!(out, "table inet {t} {{");
        let _ = writeln!(
            out,
            "  # sendbox-egress owned table (version {SENDBOX_EGRESS_TABLE_VERSION})"
        );

        // ── input chain ──────────────────────────────────────────────────
        out.push_str("  chain input {\n");
        out.push_str("    type filter hook input priority filter; policy drop;\n");
        out.push_str("    ct state established,related accept\n");
        if let Some(iface) = &self.fixture_iface {
            let _ = writeln!(out, "    iifname \"{iface}\" icmpv6 type 135 accept");
            let _ = writeln!(out, "    iifname \"{iface}\" icmpv6 type 136 accept");
        }
        // New inbound to the brokers' loopback ports. The originating socket's
        // identity is not visible at the input hook (it is only attached to
        // locally-originated/output packets), so these scope by iif lo + exact
        // destination + port; the *output* chain is what restricts who may
        // originate this traffic.
        self.push_loopback_accept(&mut out, "    iif lo", "tcp", self.connect_broker_tcp_port);
        if let Some(dns_port) = self.dns_broker_port {
            self.push_loopback_accept(&mut out, "    iif lo", "udp", dns_port);
            self.push_loopback_accept(&mut out, "    iif lo", "tcp", dns_port);
        }
        out.push_str("  }\n\n");

        // ── output chain ─────────────────────────────────────────────────
        out.push_str("  chain output {\n");
        out.push_str("    type filter hook output priority filter; policy drop;\n");
        out.push_str("    ct state established,related accept\n");
        if let Some(iface) = &self.fixture_iface {
            let _ = writeln!(out, "    oifname \"{iface}\" icmpv6 type 135 accept");
            let _ = writeln!(out, "    oifname \"{iface}\" icmpv6 type 136 accept");
        }

        let agent = self.agent_match();
        let _ = writeln!(
            out,
            "    # agent cgroup -> loopback brokers only, exact ports"
        );
        self.push_cgroup_loopback_accept(&mut out, &agent, "tcp", self.connect_broker_tcp_port);
        if let Some(dns_port) = self.dns_broker_port {
            self.push_cgroup_loopback_accept(&mut out, &agent, "udp", dns_port);
            self.push_cgroup_loopback_accept(&mut out, &agent, "tcp", dns_port);
        }

        let broker = self.broker_match();
        let mark = self.broker_mark;
        let _ = writeln!(
            out,
            "    # broker cgroup + mark may originate external traffic, but metadata stays blocked"
        );
        for v4 in &self.metadata_v4_addresses {
            let _ = writeln!(out, "    {broker} meta mark {mark} ip daddr {v4} drop");
        }
        for v6 in &self.metadata_v6_addresses {
            let _ = writeln!(out, "    {broker} meta mark {mark} ip6 daddr {v6} drop");
        }
        let _ = writeln!(out, "    {broker} meta mark {mark} accept");

        out.push_str("  }\n");
        out.push_str("}\n");
        out
    }

    /// The exact text passed to `nft -f -`: a `destroy table` followed by the
    /// fresh table definition, applied atomically as one transaction.
    #[must_use]
    pub fn render_transaction(&self) -> String {
        format!("destroy table inet {}\n{}", self.table_name, self.render())
    }

    fn agent_match(&self) -> String {
        format!(
            "socket cgroupv2 level {} \"{}\"",
            self.agent.level(),
            self.agent.relative_path()
        )
    }

    fn broker_match(&self) -> String {
        format!(
            "socket cgroupv2 level {} \"{}\"",
            self.broker.level(),
            self.broker.relative_path()
        )
    }

    fn push_loopback_accept(&self, out: &mut String, prefix: &str, proto: &str, port: u16) {
        let _ = writeln!(
            out,
            "{prefix} ip daddr 127.0.0.1 {proto} dport {port} accept"
        );
        let _ = writeln!(out, "{prefix} ip6 daddr ::1 {proto} dport {port} accept");
    }

    fn push_cgroup_loopback_accept(
        &self,
        out: &mut String,
        cgroup_match: &str,
        proto: &str,
        port: u16,
    ) {
        let _ = writeln!(
            out,
            "    {cgroup_match} ip daddr 127.0.0.1 {proto} dport {port} accept"
        );
        let _ = writeln!(
            out,
            "    {cgroup_match} ip6 daddr ::1 {proto} dport {port} accept"
        );
    }
}

fn is_valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Abstraction over `nft` execution so apply/cleanup/verify can be tested
/// without a real `nft` binary or root. The production implementation runs
/// `nft` with an explicit argv (never a shell) and passes the ruleset on
/// stdin.
pub trait NftRunner: Send + Sync {
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> io::Result<Output>;
}

/// Runs the real `nft` binary.
pub struct SystemNftRunner {
    pub binary: String,
}

impl SystemNftRunner {
    #[must_use]
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
        }
    }
}

impl Default for SystemNftRunner {
    fn default() -> Self {
        Self::new("nft")
    }
}

impl NftRunner for SystemNftRunner {
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> io::Result<Output> {
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn()?;
        if let Some(bytes) = stdin {
            let mut handle = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("nft stdin unavailable"))?;
            handle.write_all(bytes)?;
            // Drop closes stdin (EOF) before we wait for output.
        }
        child.wait_with_output()
    }
}

/// Validates the ruleset without committing it (`nft --check -f -`). This is
/// the explicit `socket cgroupv2` support probe against the real, already
/// created cgroup paths; failure fails closed.
pub fn validate_ruleset(config: &NftConfig, runner: &dyn NftRunner) -> Result<(), NftError> {
    config.validate()?;
    let transaction = config.render_transaction();
    run_checked(
        runner,
        &["--check", "-f", "-"],
        Some(transaction.as_bytes()),
    )
}

/// Applies the ruleset atomically (`nft -f -`). A leading `destroy table`
/// makes reapply an atomic replace; a failure anywhere aborts the whole
/// transaction and leaves the previous table intact.
pub fn apply(config: &NftConfig, runner: &dyn NftRunner) -> Result<(), NftError> {
    config.validate()?;
    let transaction = config.render_transaction();
    run_checked(runner, &["-f", "-"], Some(transaction.as_bytes()))
}

/// Removes only this crate's table. Uses `destroy` (nft's idempotent delete),
/// so cleanup is absent-safe; a non-absence failure (e.g. permission) still
/// surfaces as an error.
pub fn cleanup(config: &NftConfig, runner: &dyn NftRunner) -> Result<(), NftError> {
    // No full validate(): during teardown only the table name matters, and it
    // is still checked for injection-safety below.
    if !table_name_valid(&config.table_name) {
        return Err(NftError::InvalidTableName(config.table_name.clone()));
    }
    run_checked(
        runner,
        &["destroy", "table", "inet", &config.table_name],
        None,
    )
}

/// Reports whether the owned table is currently installed
/// (`nft list table inet <name>` succeeds). Used to verify the ruleset after
/// applying it, before the caller is permitted to start the agent.
pub fn table_installed(config: &NftConfig, runner: &dyn NftRunner) -> Result<bool, NftError> {
    if !table_name_valid(&config.table_name) {
        return Err(NftError::InvalidTableName(config.table_name.clone()));
    }
    let output = runner
        .run(&["list", "table", "inet", &config.table_name], None)
        .map_err(NftError::CommandFailed)?;
    Ok(output.status.success())
}

fn table_name_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 31
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

fn run_checked(
    runner: &dyn NftRunner,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<(), NftError> {
    let output = runner.run(args, stdin).map_err(NftError::CommandFailed)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(NftError::NonZeroExit {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::Mutex;

    fn identity(path: &str) -> CgroupIdentity {
        CgroupIdentity::new(path).unwrap()
    }

    fn config() -> NftConfig {
        NftConfig {
            table_name: "sendbox_egress_test".to_owned(),
            agent: identity("sendbox/inst01/agent"),
            broker: identity("sendbox/inst01/broker"),
            broker_mark: 0x5b0e,
            connect_broker_tcp_port: 15080,
            dns_broker_port: Some(15053),
            metadata_v4_addresses: crate::address::METADATA_V4_ADDRESSES.to_vec(),
            metadata_v6_addresses: crate::address::METADATA_V6_ADDRESSES.to_vec(),
            fixture_iface: Some("sbxg01".to_owned()),
        }
    }

    #[test]
    fn cgroup_identity_level_is_component_count() {
        let id = identity("sendbox/inst01/agent");
        assert_eq!(id.level(), 3);
        assert_eq!(id.relative_path(), "sendbox/inst01/agent");
        // Leading/trailing slashes are trimmed and do not change the level.
        let trimmed = identity("/sendbox/inst01/agent/");
        assert_eq!(trimmed.level(), 3);
        assert_eq!(trimmed.relative_path(), "sendbox/inst01/agent");
    }

    #[test]
    fn cgroup_identity_rejects_traversal_and_injection() {
        assert!(CgroupIdentity::new("sendbox/../etc").is_err());
        assert!(CgroupIdentity::new("sendbox/\"quote").is_err());
        assert!(CgroupIdentity::new("sendbox/ space").is_err());
        assert!(CgroupIdentity::new("").is_err());
    }

    #[test]
    fn render_uses_socket_cgroupv2_never_meta_cgroup() {
        let text = config().render();
        assert!(text.contains("socket cgroupv2 level 3 \"sendbox/inst01/agent\""));
        assert!(text.contains("socket cgroupv2 level 3 \"sendbox/inst01/broker\""));
        // cgroup v1 net_cls syntax must never appear.
        assert!(!text.contains("meta cgroup"));
    }

    #[test]
    fn render_scopes_agent_to_loopback_broker_ports_only() {
        let text = config().render();
        assert!(text.contains(
            "socket cgroupv2 level 3 \"sendbox/inst01/agent\" ip daddr 127.0.0.1 tcp dport 15080 accept"
        ));
        assert!(text.contains(
            "socket cgroupv2 level 3 \"sendbox/inst01/agent\" ip daddr 127.0.0.1 udp dport 15053 accept"
        ));
        // The agent identity never gets a blanket accept.
        assert!(!text.contains("\"sendbox/inst01/agent\" meta mark"));
        assert!(!text.contains("\"sendbox/inst01/agent\" accept"));
    }

    #[test]
    fn render_requires_both_cgroup_and_mark_for_broker_external() {
        let text = config().render();
        let mark = config().broker_mark;
        assert!(text.contains(&format!(
            "socket cgroupv2 level 3 \"sendbox/inst01/broker\" meta mark {mark} accept"
        )));
        // There must be no broker external accept that omits the mark.
        assert!(!text.contains("\"sendbox/inst01/broker\" accept"));
    }

    #[test]
    fn render_blocks_metadata_for_broker_even_when_marked() {
        let text = config().render();
        let mark = config().broker_mark;
        assert!(text.contains(&format!(
            "socket cgroupv2 level 3 \"sendbox/inst01/broker\" meta mark {mark} ip daddr 169.254.169.254 drop"
        )));
        assert!(text.contains(&format!(
            "socket cgroupv2 level 3 \"sendbox/inst01/broker\" meta mark {mark} ip6 daddr fd00:ec2::254 drop"
        )));
        assert!(text.contains("ip daddr 100.100.100.200 drop"));
    }

    #[test]
    fn render_omits_dns_rules_when_dns_disabled() {
        let mut cfg = config();
        cfg.dns_broker_port = None;
        let text = cfg.render();
        assert!(!text.contains("dport 15053"));
        // The CONNECT port is still present.
        assert!(text.contains("dport 15080"));
    }

    #[test]
    fn render_has_default_drop_and_established_accept() {
        let text = config().render();
        assert_eq!(text.matches("policy drop;").count(), 2);
        assert_eq!(
            text.matches("ct state established,related accept").count(),
            2
        );
    }

    #[test]
    fn render_is_deterministic() {
        assert_eq!(config().render(), config().render());
        assert_eq!(config().render_transaction(), config().render_transaction());
    }

    #[test]
    fn render_transaction_prefixes_a_destroy() {
        let text = config().render_transaction();
        assert!(text.starts_with("destroy table inet sendbox_egress_test\n"));
        assert!(text.contains("table inet sendbox_egress_test {"));
    }

    #[test]
    fn render_transaction_never_accumulates_stale_rules_across_a_reapply() {
        let mut second = config();
        second.connect_broker_tcp_port = 25080;
        let first = config().render_transaction();
        let second_text = second.render_transaction();
        assert!(first.contains("dport 15080 accept"));
        assert!(!second_text.contains("dport 15080 accept"));
        assert!(second_text.contains("dport 25080 accept"));
    }

    #[test]
    fn render_permits_only_ndp_types_on_the_fixture_interface() {
        let text = config().render();
        assert!(text.contains("iifname \"sbxg01\" icmpv6 type 135 accept"));
        assert!(text.contains("oifname \"sbxg01\" icmpv6 type 136 accept"));
        assert!(!text.contains("icmpv6 type 128"));
        assert!(!text.contains("meta l4proto ipv6-icmp accept"));
    }

    #[test]
    fn validate_rejects_bad_inputs() {
        let mut bad = config();
        bad.table_name = "Sendbox".to_owned();
        assert!(matches!(bad.validate(), Err(NftError::InvalidTableName(_))));

        let mut equal = config();
        equal.broker = equal.agent.clone();
        assert!(matches!(
            equal.validate(),
            Err(NftError::IdentitiesMustDiffer)
        ));

        let mut zero = config();
        zero.broker_mark = 0;
        assert!(matches!(zero.validate(), Err(NftError::ZeroMark)));

        let mut iface = config();
        iface.fixture_iface = Some("bad iface".to_owned());
        assert!(matches!(
            iface.validate(),
            Err(NftError::InvalidInterface(_))
        ));
    }

    struct RecordingRunner {
        calls: Mutex<Vec<(Vec<String>, Option<String>)>>,
        exit_code: i32,
        stderr: String,
    }

    impl RecordingRunner {
        fn success() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                exit_code: 0,
                stderr: String::new(),
            }
        }

        fn failing(code: i32, stderr: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                exit_code: code,
                stderr: stderr.to_owned(),
            }
        }
    }

    impl NftRunner for RecordingRunner {
        fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> io::Result<Output> {
            self.calls.lock().unwrap().push((
                args.iter().map(|s| (*s).to_owned()).collect(),
                stdin.map(|b| String::from_utf8_lossy(b).into_owned()),
            ));
            Ok(Output {
                status: std::process::ExitStatus::from_raw(self.exit_code),
                stdout: Vec::new(),
                stderr: self.stderr.clone().into_bytes(),
            })
        }
    }

    #[test]
    fn apply_passes_transaction_on_stdin_with_dash_f_dash() {
        let runner = RecordingRunner::success();
        apply(&config(), &runner).unwrap();
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, vec!["-f", "-"]);
        let stdin = calls[0].1.as_ref().expect("ruleset must be on stdin");
        assert!(stdin.starts_with("destroy table inet sendbox_egress_test\n"));
    }

    #[test]
    fn validate_ruleset_uses_check_flag() {
        let runner = RecordingRunner::success();
        validate_ruleset(&config(), &runner).unwrap();
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls[0].0, vec!["--check", "-f", "-"]);
    }

    #[test]
    fn apply_propagates_nft_failure() {
        let runner = RecordingRunner::failing(1, "Error: syntax error");
        assert!(matches!(
            apply(&config(), &runner),
            Err(NftError::NonZeroExit { .. })
        ));
    }

    #[test]
    fn cleanup_uses_destroy_argv_and_is_idempotent() {
        let runner = RecordingRunner::success();
        cleanup(&config(), &runner).unwrap();
        cleanup(&config(), &runner).unwrap();
        let calls = runner.calls.lock().unwrap();
        assert_eq!(
            calls[0].0,
            vec!["destroy", "table", "inet", "sendbox_egress_test"]
        );
        assert!(calls[0].1.is_none());
    }

    #[test]
    fn cleanup_reports_genuine_failure() {
        let runner = RecordingRunner::failing(1, "Error: permission denied");
        assert!(cleanup(&config(), &runner).is_err());
    }

    #[test]
    fn table_installed_reflects_exit_status() {
        let ok = RecordingRunner::success();
        assert!(table_installed(&config(), &ok).unwrap());
        let missing = RecordingRunner::failing(1, "No such file or directory");
        assert!(!table_installed(&config(), &missing).unwrap());
    }
}
