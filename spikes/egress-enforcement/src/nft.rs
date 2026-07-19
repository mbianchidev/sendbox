//! Deterministic nftables ruleset generation and atomic application via a
//! single `nft -f <path>` transaction, invoked strictly through
//! `std::process::Command` argv (never a shell).
//!
//! The generated ruleset lives in one spike-owned `inet` table (covering
//! both IPv4 and IPv6 in a single family) so it can be applied and removed
//! as one atomic unit and never touches any other table on the host.
//!
//! Enforcement shape:
//! - `ct state established,related accept` in both `input` and `output` so
//!   reply traffic for permitted connections always works.
//! - The agent UID may only *originate* (output) traffic to the loopback
//!   DNS broker (UDP+TCP) and the loopback CONNECT broker (TCP), each on an
//!   exact port. There is no blanket loopback allow.
//! - The broker's listening sockets additionally need a narrow *input*
//!   accept for the brand-new (not-yet-established) inbound SYN/datagram
//!   that reaches them: `meta skuid` is only ever populated for locally
//!   *originated* packets (output/postrouting), so it is not meaningful at
//!   the input hook for a packet destined to a listening socket — a
//!   detail nft's ct-state bookkeeping does not paper over, since the very
//!   first inbound packet of a new flow is `ct state new`, not
//!   `established`. Without an explicit input accept for it, that first
//!   packet is dropped by the default-drop input policy before the
//!   broker's socket ever sees it, and the whole mechanism never works.
//!   This narrows on `iif lo` plus the exact destination address/port
//!   instead, which is the strongest identity nftables can express for a
//!   locally-destined packet; it does *not* restrict who may originate
//!   that inbound traffic (see "Known limitation" in
//!   `docs/egress-enforcement-spike.md` for the UID-based-isolation
//!   consequence of this).
//! - The broker UID is free to originate fixture/external traffic (the
//!   broker enforces `PolicyEngine` itself in user space) except that cloud
//!   metadata destinations (a deterministic, documented list — see
//!   [`crate::address::METADATA_V4_ADDRESSES`]/[`crate::address::METADATA_V6_ADDRESSES`])
//!   are always dropped for the broker too, as a defense-in-depth SSRF
//!   guard independent of the broker's own logic.
//! - When a fixture veth interface is configured, ICMPv6 neighbor discovery
//!   (types 135/136 only) is permitted on that interface alone, so IPv6
//!   connectivity over the link works without broadening ICMPv6 to any
//!   other type or any other interface.
//! - Everything else (default policy `drop`) blocks direct IPv4/IPv6 TCP
//!   from the agent, all other UDP/QUIC, and any DNS attempted on a port
//!   other than the broker's.
//!
//! Known limitation: nftables' `inet` family filter hooks operate at the IP
//! layer. They cannot see or block `AF_PACKET` raw sockets, which operate
//! below IP. Raw-socket denial in this spike therefore relies on the netns
//! harness clearing `CAP_NET_RAW` (and other capabilities) from the agent
//! process via `setpriv`, not on nftables rules. This is documented rather
//! than silently assumed; see `docs/egress-enforcement-spike.md`.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::{Command, Output};

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct NftConfig {
    /// Sanitized table name: must match `^[a-z][a-z0-9_]{0,30}$`.
    pub table_name: String,
    pub agent_uid: u32,
    pub broker_uid: u32,
    pub dns_broker_udp_port: u16,
    pub dns_broker_tcp_port: u16,
    pub connect_broker_tcp_port: u16,
    /// Deterministic list of cloud-provider metadata IPv4 addresses to
    /// block for the broker UID. Defaults to
    /// [`crate::address::METADATA_V4_ADDRESSES`]; see that constant's
    /// documentation for exactly which providers/addresses are covered and
    /// which are not.
    pub metadata_v4_addresses: Vec<Ipv4Addr>,
    /// Deterministic list of cloud-provider metadata IPv6 addresses to
    /// block for the broker UID. See [`crate::address::METADATA_V6_ADDRESSES`].
    pub metadata_v6_addresses: Vec<Ipv6Addr>,
    /// The unique fixture veth interface name (as seen from inside the
    /// namespace) on which ICMPv6 neighbor discovery (types 135/136 only —
    /// neighbor solicitation/advertisement) is permitted, so IPv6
    /// connectivity over that specific link actually works without
    /// broadening ICMPv6 to any other type or interface. `None` omits the
    /// NDP rules entirely (e.g. for configurations that don't need IPv6
    /// connectivity over a veth at all).
    pub fixture_iface: Option<String>,
}

#[derive(Debug, Error)]
pub enum NftError {
    #[error("invalid table name '{0}': must match ^[a-z][a-z0-9_]{{0,30}}$")]
    InvalidTableName(String),
    #[error("agent_uid and broker_uid must differ, both were {0}")]
    UidsMustDiffer(u32),
    #[error("failed to write ruleset to temp file: {0}")]
    TempFile(#[source] std::io::Error),
    #[error("nft command failed to execute: {0}")]
    CommandFailed(#[source] std::io::Error),
    #[error("nft exited with status {status}: {stderr}")]
    NonZeroExit { status: String, stderr: String },
}

impl NftConfig {
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
        if self.agent_uid == self.broker_uid {
            return Err(NftError::UidsMustDiffer(self.agent_uid));
        }
        Ok(())
    }

    /// Deterministically renders the full ruleset (table body only, no
    /// `destroy`/replace prefix) as nft native syntax. Identical
    /// configuration always renders identical text. See [`Self::render_transaction`]
    /// for the actual text applied to `nft`.
    pub fn render(&self) -> String {
        let t = &self.table_name;
        let mut out = String::new();
        out.push_str(&format!("table inet {t} {{\n"));

        out.push_str("  chain input {\n");
        out.push_str("    type filter hook input priority filter; policy drop;\n");
        out.push_str("    ct state established,related accept\n\n");
        if let Some(iface) = &self.fixture_iface {
            out.push_str(concat!(
                "    # IPv6 neighbor discovery on the fixture veth link only:\n",
                "    # types 135 (neighbor solicitation) and 136 (neighbor\n",
                "    # advertisement) are the minimum needed for IPv6 to work at\n",
                "    # all over this link; no other ICMPv6 type is permitted.\n"
            ));
            out.push_str(&format!("    iifname \"{iface}\" icmpv6 type 135 accept\n"));
            out.push_str(&format!(
                "    iifname \"{iface}\" icmpv6 type 136 accept\n\n"
            ));
        }
        out.push_str(concat!(
            "    # brand-new inbound traffic to the brokers' loopback ports:\n",
            "    # the sending socket's uid is not visible on this side (that\n",
            "    # identity is only ever attached to locally-originated packets),\n",
            "    # so this is scoped by iif lo + exact destination/port instead.\n"
        ));
        {
            let (proto, port) = ("tcp", self.connect_broker_tcp_port);
            out.push_str(&format!(
                "    iif lo ip daddr 127.0.0.1 {proto} dport {port} accept\n"
            ));
            out.push_str(&format!(
                "    iif lo ip6 daddr ::1 {proto} dport {port} accept\n"
            ));
        }
        for (proto, port) in [
            ("udp", self.dns_broker_udp_port),
            ("tcp", self.dns_broker_tcp_port),
        ] {
            out.push_str(&format!(
                "    iif lo ip daddr 127.0.0.1 {proto} dport {port} accept\n"
            ));
            out.push_str(&format!(
                "    iif lo ip6 daddr ::1 {proto} dport {port} accept\n"
            ));
        }
        out.push_str("  }\n\n");

        out.push_str("  chain output {\n");
        out.push_str("    type filter hook output priority filter; policy drop;\n");
        out.push_str("    ct state established,related accept\n\n");
        if let Some(iface) = &self.fixture_iface {
            out.push_str(&format!("    oifname \"{iface}\" icmpv6 type 135 accept\n"));
            out.push_str(&format!(
                "    oifname \"{iface}\" icmpv6 type 136 accept\n\n"
            ));
        }

        out.push_str(&format!(
            "    # agent ({}) -> loopback brokers only, exact ports\n",
            self.agent_uid
        ));
        {
            let (proto, port) = ("tcp", self.connect_broker_tcp_port);
            out.push_str(&format!(
                "    meta skuid {} ip daddr 127.0.0.1 {} dport {} accept\n",
                self.agent_uid, proto, port
            ));
            out.push_str(&format!(
                "    meta skuid {} ip6 daddr ::1 {} dport {} accept\n",
                self.agent_uid, proto, port
            ));
        }
        for (proto, port) in [
            ("udp", self.dns_broker_udp_port),
            ("tcp", self.dns_broker_tcp_port),
        ] {
            out.push_str(&format!(
                "    meta skuid {} ip daddr 127.0.0.1 {} dport {} accept\n",
                self.agent_uid, proto, port
            ));
            out.push_str(&format!(
                "    meta skuid {} ip6 daddr ::1 {} dport {} accept\n",
                self.agent_uid, proto, port
            ));
        }

        out.push_str(&format!(
            "\n    # broker ({}) may originate fixture/external traffic, but metadata stays blocked\n",
            self.broker_uid
        ));
        for metadata_v4 in &self.metadata_v4_addresses {
            out.push_str(&format!(
                "    meta skuid {} ip daddr {} drop\n",
                self.broker_uid, metadata_v4
            ));
        }
        for metadata_v6 in &self.metadata_v6_addresses {
            out.push_str(&format!(
                "    meta skuid {} ip6 daddr {} drop\n",
                self.broker_uid, metadata_v6
            ));
        }
        out.push_str(&format!("    meta skuid {} accept\n", self.broker_uid));

        out.push_str("  }\n");
        out.push_str("}\n");
        out
    }

    /// The exact text passed to `nft -f`: a `destroy table inet <name>`
    /// statement followed by a full, fresh table definition, all in one
    /// atomic transaction. `destroy` (unlike `delete`) does not fail if the
    /// table does not already exist, so this same text is correct for both
    /// the first-ever apply (destroy is a no-op) and a reapply (destroy
    /// removes every chain/rule the previous apply created before the new
    /// table is added) — no stale rule from a prior configuration can
    /// survive a reapply, and because `nft -f` applies the whole file as
    /// one transaction, a syntax/reference error anywhere aborts the
    /// entire update, leaving the *previous* table completely intact
    /// rather than partially destroyed.
    pub fn render_transaction(&self) -> String {
        format!("destroy table inet {}\n{}", self.table_name, self.render())
    }
}

/// Abstraction over process execution so the atomic-apply/cleanup logic can
/// be tested without a real `nft` binary or root privileges. The production
/// implementation runs `Command::new(binary).args(args)` directly; argv is
/// always constructed explicitly and never passed through a shell.
pub trait NftRunner {
    fn run(&self, args: &[&str]) -> std::io::Result<Output>;
}

pub struct SystemNftRunner {
    pub binary: String,
}

impl SystemNftRunner {
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
        }
    }
}

impl NftRunner for SystemNftRunner {
    fn run(&self, args: &[&str]) -> std::io::Result<Output> {
        Command::new(&self.binary).args(args).output()
    }
}

/// Applies the ruleset as a single atomic transaction: [`NftConfig::render_transaction`]
/// (a `destroy table` followed by a fresh table definition) is written to
/// one temp file, then passed to `nft -f <path>`. `nft -f` applies a file as
/// one transaction, so a syntax or reference error anywhere in the file
/// aborts the whole update instead of leaving a partially-applied ruleset —
/// this is the "one generated ruleset transaction" atomicity guarantee. The
/// leading `destroy table` makes reapply an atomic *replace*: no rule from
/// a previous apply can survive into the new ruleset, because the entire
/// table is torn down and rebuilt within the same transaction rather than
/// having new rules appended to whatever chains already existed.
pub fn apply(config: &NftConfig, runner: &dyn NftRunner) -> Result<(), NftError> {
    config.validate()?;
    let transaction = config.render_transaction();
    let mut file = tempfile::NamedTempFile::new().map_err(NftError::TempFile)?;
    file.write_all(transaction.as_bytes())
        .map_err(NftError::TempFile)?;
    file.flush().map_err(NftError::TempFile)?;
    let path = file.path();
    run_checked(runner, &["-f", &path_str(path)])
}

/// Removes only this spike's table. Uses `destroy` rather than `delete`:
/// `destroy` is nft's idempotent-delete variant and succeeds whether or not
/// the table currently exists, so cleanup is unconditionally absent-safe
/// without needing to pattern-match `nft`'s stderr for "not found"-style
/// messages (which varies across nft versions/locales).
pub fn cleanup(config: &NftConfig, runner: &dyn NftRunner) -> Result<(), NftError> {
    config.validate()?;
    run_checked(runner, &["destroy", "table", "inet", &config.table_name])
}

fn run_checked(runner: &dyn NftRunner, args: &[&str]) -> Result<(), NftError> {
    let output = runner.run(args).map_err(NftError::CommandFailed)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(NftError::NonZeroExit {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn path_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::Mutex;

    fn config() -> NftConfig {
        NftConfig {
            table_name: "sendbox_spike_test".to_owned(),
            agent_uid: 5001,
            broker_uid: 5002,
            dns_broker_udp_port: 15053,
            dns_broker_tcp_port: 15053,
            connect_broker_tcp_port: 15080,
            metadata_v4_addresses: crate::address::METADATA_V4_ADDRESSES.to_vec(),
            metadata_v6_addresses: crate::address::METADATA_V6_ADDRESSES.to_vec(),
            fixture_iface: Some("sbxgabc123".to_owned()),
        }
    }

    struct RecordingRunner {
        calls: Mutex<Vec<Vec<String>>>,
        /// Contents of any `-f <path>` ruleset file, captured at call time
        /// (before `apply()` drops its `NamedTempFile` and deletes it).
        file_contents: Mutex<Vec<String>>,
        exit_code: i32,
        stderr: String,
    }

    impl RecordingRunner {
        fn success() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                file_contents: Mutex::new(Vec::new()),
                exit_code: 0,
                stderr: String::new(),
            }
        }

        fn failing(exit_code: i32, stderr: impl Into<String>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                file_contents: Mutex::new(Vec::new()),
                exit_code,
                stderr: stderr.into(),
            }
        }
    }

    impl NftRunner for RecordingRunner {
        fn run(&self, args: &[&str]) -> std::io::Result<Output> {
            if let [flag, path] = args
                && *flag == "-f"
            {
                let contents = std::fs::read_to_string(path).unwrap_or_default();
                self.file_contents.lock().unwrap().push(contents);
            }
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|s| s.to_string()).collect());
            Ok(Output {
                status: std::process::ExitStatus::from_raw(self.exit_code),
                stdout: Vec::new(),
                stderr: self.stderr.clone().into_bytes(),
            })
        }
    }

    #[test]
    fn render_is_deterministic() {
        let a = config().render();
        let b = config().render();
        assert_eq!(a, b);
    }

    #[test]
    fn render_scopes_agent_to_loopback_broker_ports_only() {
        let text = config().render();
        assert!(text.contains("meta skuid 5001 ip daddr 127.0.0.1 tcp dport 15080 accept"));
        assert!(text.contains("meta skuid 5001 ip daddr 127.0.0.1 udp dport 15053 accept"));
        assert!(!text.contains("meta skuid 5001 accept"));
    }

    #[test]
    fn render_blocks_metadata_for_broker_uid() {
        let text = config().render();
        assert!(text.contains("meta skuid 5002 ip daddr 169.254.169.254 drop"));
        assert!(text.contains("meta skuid 5002 ip6 daddr fd00:ec2::254 drop"));
    }

    #[test]
    fn render_blocks_alibaba_metadata_for_broker_uid_too() {
        let text = config().render();
        assert!(text.contains("meta skuid 5002 ip daddr 100.100.100.200 drop"));
    }

    #[test]
    fn render_permits_only_ndp_types_on_the_fixture_interface() {
        let text = config().render();
        assert!(text.contains("iifname \"sbxgabc123\" icmpv6 type 135 accept"));
        assert!(text.contains("iifname \"sbxgabc123\" icmpv6 type 136 accept"));
        assert!(text.contains("oifname \"sbxgabc123\" icmpv6 type 135 accept"));
        assert!(text.contains("oifname \"sbxgabc123\" icmpv6 type 136 accept"));
        // No other ICMPv6 type or a blanket ICMPv6 allow must appear.
        assert!(!text.contains("icmpv6 type 128")); // echo-request
        assert!(!text.contains("icmpv6 type 129")); // echo-reply
        assert!(!text.contains("icmpv6 type 133")); // router solicitation
        assert!(!text.contains("icmpv6 type 134")); // router advertisement
        assert!(!text.to_lowercase().contains("ip6 nexthdr icmpv6 accept"));
        assert!(!text.contains("meta l4proto ipv6-icmp accept"));
    }

    #[test]
    fn render_omits_ndp_rules_when_no_fixture_interface_configured() {
        let mut cfg = config();
        cfg.fixture_iface = None;
        let text = cfg.render();
        assert!(!text.contains("icmpv6"));
    }

    #[test]
    fn render_has_default_drop_policy_and_established_accept() {
        let text = config().render();
        assert!(text.contains("policy drop;"));
        assert!(text.contains("ct state established,related accept"));
    }

    #[test]
    fn render_input_chain_accepts_new_inbound_traffic_to_broker_ports_without_skuid() {
        let text = config().render();
        let input_chain = text
            .split("chain output")
            .next()
            .expect("input chain must precede output chain");
        // The input side cannot filter on the sender's skuid (that meta key
        // is only populated for locally-originated/output packets), so it
        // must not appear in the input chain's accept rules; instead it
        // must scope by iif lo + exact destination + port.
        assert!(!input_chain.contains("meta skuid"));
        assert!(input_chain.contains("iif lo ip daddr 127.0.0.1 tcp dport 15080 accept"));
        assert!(input_chain.contains("iif lo ip6 daddr ::1 tcp dport 15080 accept"));
        assert!(input_chain.contains("iif lo ip daddr 127.0.0.1 udp dport 15053 accept"));
        assert!(input_chain.contains("iif lo ip daddr 127.0.0.1 tcp dport 15053 accept"));
    }

    #[test]
    fn render_transaction_prefixes_a_destroy_before_the_fresh_table() {
        let text = config().render_transaction();
        let destroy_pos = text
            .find("destroy table inet sendbox_spike_test")
            .expect("transaction must destroy the old table first");
        let table_pos = text
            .find("table inet sendbox_spike_test {")
            .expect("transaction must define a fresh table");
        assert!(
            destroy_pos < table_pos,
            "destroy must precede the fresh table definition in the same transaction"
        );
    }

    #[test]
    fn render_transaction_reflects_only_the_current_config_no_accumulation() {
        // Simulates a config change across two applies (e.g. a different
        // connect broker port). The second transaction's destroy+redefine
        // strategy means it never contains the *old* port's specific
        // accept rule text, proving there is nothing in the generated text
        // itself that could accumulate stale rules across a reapply.
        let mut second = config();
        second.connect_broker_tcp_port = 25080;
        let first_transaction = config().render_transaction();
        let second_transaction = second.render_transaction();
        assert!(first_transaction.contains("dport 15080 accept"));
        assert!(!second_transaction.contains("dport 15080 accept"));
        assert!(second_transaction.contains("dport 25080 accept"));
        assert!(second_transaction.starts_with("destroy table inet sendbox_spike_test\n"));
    }

    #[test]
    fn validate_rejects_uppercase_or_bad_table_name() {
        let mut bad = config();
        bad.table_name = "Sendbox".to_owned();
        assert!(matches!(bad.validate(), Err(NftError::InvalidTableName(_))));
    }

    #[test]
    fn validate_rejects_equal_uids() {
        let mut bad = config();
        bad.broker_uid = bad.agent_uid;
        assert!(matches!(bad.validate(), Err(NftError::UidsMustDiffer(_))));
    }

    #[test]
    fn apply_invokes_nft_with_dash_f_and_a_path_argv_only() {
        let runner = RecordingRunner::success();
        apply(&config(), &runner).unwrap();
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0], "-f");
        assert!(
            !calls[0][1].is_empty(),
            "the temp ruleset path argument must be non-empty"
        );
    }

    #[test]
    fn apply_writes_the_destroy_prefixed_transaction_to_the_temp_file() {
        let runner = RecordingRunner::success();
        apply(&config(), &runner).unwrap();
        let file_contents = runner.file_contents.lock().unwrap();
        let contents = &file_contents[0];
        assert!(contents.starts_with("destroy table inet sendbox_spike_test\n"));
        assert!(contents.contains("table inet sendbox_spike_test {"));
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
    fn cleanup_uses_destroy_which_is_idempotent_by_construction() {
        // Real `nft destroy table` succeeds whether or not the table
        // exists; cleanup() no longer needs to pattern-match stderr to
        // decide idempotency, so a runner simulating nft's success exit
        // status is sufficient for both a first cleanup and a repeat.
        let runner = RecordingRunner::success();
        assert!(cleanup(&config(), &runner).is_ok());
        assert!(cleanup(&config(), &runner).is_ok());
    }

    #[test]
    fn cleanup_reports_genuine_failures() {
        let runner = RecordingRunner::failing(1, "Error: permission denied");
        assert!(cleanup(&config(), &runner).is_err());
    }

    #[test]
    fn cleanup_uses_destroy_not_delete() {
        let runner = RecordingRunner::success();
        cleanup(&config(), &runner).unwrap();
        let calls = runner.calls.lock().unwrap();
        assert_eq!(
            calls[0],
            vec!["destroy", "table", "inet", "sendbox_spike_test"]
        );
    }
}
