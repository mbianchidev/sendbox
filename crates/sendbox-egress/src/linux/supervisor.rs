//! Supervisor: the armed guard that enforces the safe egress setup ordering
//! and owns teardown.
//!
//! [`ArmedEgress::arm`] never fails open. Its ordering is strict:
//! 1. preflight (cgroup v2, `nft socket cgroupv2`, `CAP_NET_ADMIN`, `SO_MARK`);
//! 2. create the stable cgroup hierarchy;
//! 3. validate the ruleset (`nft --check`) against the real cgroup paths;
//! 4. apply the ruleset atomically;
//! 5. verify the owned table is installed;
//! 6. only then return an [`ArmedEgress`] guard, which is the token the caller
//!    must hold before it is permitted to place and start the agent.
//!
//! Any failure at or after step 2 best-effort unwinds whatever *this call*
//! created, so an agent is never started behind a half-installed ruleset. A
//! failed apply is atomic: the whole `nft` transaction rolls back, so on a
//! re-arm of an already-live instance the previous owned table is preserved
//! (never cleaned up) and its cgroups are left untouched. The guard keeps the
//! last-known-good [`NftConfig`] in memory for explicit
//! [`ArmedEgress::rollback`]/[`ArmedEgress::update`], and its `Drop` tears
//! everything down.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use thiserror::Error;

use crate::linux::cgroup::{CgroupError, CgroupHierarchy};
use crate::linux::nft::{self, CgroupIdentity, NftConfig, NftError, NftRunner, SystemNftRunner};
use crate::linux::preflight::Preflight;

/// Inputs the supervisor needs to arm one sandbox's egress enforcement.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Stable instance id (1-24 chars of `[a-z0-9_]`); names the cgroup
    /// hierarchy and derives the nftables table name.
    pub instance_id: String,
    /// Owned nftables table name (`^[a-z][a-z0-9_]{0,30}$`).
    pub table_name: String,
    /// Fixed non-zero `SO_MARK` the broker sets on external sockets.
    pub broker_mark: u32,
    /// Loopback CONNECT broker port.
    pub connect_port: u16,
    /// Loopback DNS broker port, or `None` when the policy disables DNS.
    pub dns_port: Option<u16>,
    /// Cloud metadata addresses dropped for the broker (defaults to the
    /// documented lists).
    pub metadata_v4: Vec<Ipv4Addr>,
    pub metadata_v6: Vec<Ipv6Addr>,
    /// Optional fixture veth interface for ICMPv6 neighbor discovery.
    pub fixture_iface: Option<String>,
}

impl SupervisorConfig {
    /// Builds a config with a derived table name and the documented metadata
    /// address lists. `instance_id` should be short (≤ 24 chars) so the derived
    /// table name stays within the 31-char nftables limit.
    #[must_use]
    pub fn new(instance_id: impl Into<String>, broker_mark: u32, connect_port: u16) -> Self {
        let instance_id = instance_id.into();
        let table_name = format!("sbxeg_{instance_id}");
        Self {
            instance_id,
            table_name,
            broker_mark,
            connect_port,
            dns_port: None,
            metadata_v4: crate::address::METADATA_V4_ADDRESSES.to_vec(),
            metadata_v6: crate::address::METADATA_V6_ADDRESSES.to_vec(),
            fixture_iface: None,
        }
    }

    /// Sets the loopback DNS broker port (enables DNS accept rules).
    #[must_use]
    pub fn with_dns_port(mut self, port: u16) -> Self {
        self.dns_port = Some(port);
        self
    }

    /// Sets the fixture veth interface for ICMPv6 neighbor discovery.
    #[must_use]
    pub fn with_fixture_iface(mut self, iface: impl Into<String>) -> Self {
        self.fixture_iface = Some(iface.into());
        self
    }

    fn nft_config(&self, agent: CgroupIdentity, broker: CgroupIdentity) -> NftConfig {
        NftConfig {
            table_name: self.table_name.clone(),
            agent,
            broker,
            broker_mark: self.broker_mark,
            connect_broker_tcp_port: self.connect_port,
            dns_broker_port: self.dns_port,
            metadata_v4_addresses: self.metadata_v4.clone(),
            metadata_v6_addresses: self.metadata_v6.clone(),
            fixture_iface: self.fixture_iface.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("preflight failed; environment cannot enforce egress: {0}")]
    Preflight(String),
    #[error(transparent)]
    Cgroup(#[from] CgroupError),
    #[error(transparent)]
    Nft(#[from] NftError),
    #[error("owned nftables table was not installed after apply; refusing to arm")]
    TableNotInstalled,
    #[error("cannot update: table name must not change")]
    TableNameChanged,
    #[error("egress guard already torn down")]
    AlreadyTornDown,
}

/// The armed egress guard. Holding it is the precondition for starting the
/// agent. Dropping it tears down the nftables table and cgroup hierarchy.
pub struct ArmedEgress {
    hierarchy: CgroupHierarchy,
    runner: Box<dyn NftRunner>,
    config: NftConfig,
    /// Set once the owned cgroups have been removed/verified-empty.
    cgroups_torn_down: bool,
    /// Set once the owned nftables table has been destroyed. Tracked separately
    /// from `cgroups_torn_down` so a teardown whose nft cleanup fails can be
    /// retried by a later call without re-running (or skipping) the cgroup step.
    nft_torn_down: bool,
}

impl ArmedEgress {
    /// Production entry point: full preflight, then arm under the detected
    /// cgroup v2 root using the real `nft` binary.
    pub fn arm(config: SupervisorConfig) -> Result<Self, SupervisorError> {
        let runner: Box<dyn NftRunner> = Box::new(SystemNftRunner::default());
        let preflight = Preflight::probe(runner.as_ref());
        if !preflight.all_ready() {
            return Err(SupervisorError::Preflight(preflight.to_json()));
        }
        let root = crate::linux::cgroup::detect_cgroup2_root()?;
        Self::arm_under(&root, runner, config)
    }

    /// Lower-level arm used by tests (tempdir root + injected runner) and by
    /// [`Self::arm`] after preflight. Performs steps 2-6 of the ordering. Host
    /// capability checks are the caller's responsibility here.
    pub fn arm_under(
        root: &Path,
        runner: Box<dyn NftRunner>,
        config: SupervisorConfig,
    ) -> Result<Self, SupervisorError> {
        // 2. Create the stable cgroup hierarchy. `preexisting` tells us whether
        //    this is a re-arm of a possibly-live instance, in which case a
        //    failure must not tear its cgroups (or table) down.
        let hierarchy = CgroupHierarchy::create_under(root, &config.instance_id)?;
        let preexisting = hierarchy.preexisting();
        let nft_config = config.nft_config(
            hierarchy.agent_identity().clone(),
            hierarchy.broker_identity().clone(),
        );

        // 3. Validate the ruleset against the real cgroup paths (fail closed).
        //    `--check` never commits, so any pre-existing owned table is
        //    untouched; only tear down cgroups this call freshly created.
        if let Err(err) = nft::validate_ruleset(&nft_config, runner.as_ref()) {
            if !preexisting {
                let _ = hierarchy.teardown();
            }
            return Err(SupervisorError::Nft(err));
        }

        // 4. Apply atomically. A failed apply rolls the *entire* transaction
        //    back, so any pre-existing owned table for this stable instance
        //    survives intact. We must therefore NOT run `nft::cleanup` here —
        //    destroying that table would strip live enforcement from an already
        //    running instance. Only tear down cgroups this call freshly created.
        if let Err(err) = nft::apply(&nft_config, runner.as_ref()) {
            if !preexisting {
                let _ = hierarchy.teardown();
            }
            return Err(SupervisorError::Nft(err));
        }

        // 5. Verify the owned table is installed before permitting startup. Here
        //    apply already committed (atomically replacing any prior table), so
        //    removing the just-applied table on failure is correct — it prevents
        //    leaking an unowned table — while cgroups of a pre-existing instance
        //    are still left in place.
        match nft::table_installed(&nft_config, runner.as_ref()) {
            Ok(true) => {}
            Ok(false) => {
                let _ = nft::cleanup(&nft_config, runner.as_ref());
                if !preexisting {
                    let _ = hierarchy.teardown();
                }
                return Err(SupervisorError::TableNotInstalled);
            }
            Err(err) => {
                let _ = nft::cleanup(&nft_config, runner.as_ref());
                if !preexisting {
                    let _ = hierarchy.teardown();
                }
                return Err(SupervisorError::Nft(err));
            }
        }

        Ok(Self {
            hierarchy,
            runner,
            config: nft_config,
            cgroups_torn_down: false,
            nft_torn_down: false,
        })
    }

    #[must_use]
    pub fn agent_identity(&self) -> &CgroupIdentity {
        self.hierarchy.agent_identity()
    }

    #[must_use]
    pub fn broker_identity(&self) -> &CgroupIdentity {
        self.hierarchy.broker_identity()
    }

    /// Local filesystem path of the agent cgroup's `cgroup.procs` (mount-relative,
    /// never the global nft identity), for a helper that self-places into it.
    #[must_use]
    pub fn agent_procs_path(&self) -> std::path::PathBuf {
        self.hierarchy.agent_procs_path()
    }

    /// Local filesystem path of the broker cgroup's `cgroup.procs`.
    #[must_use]
    pub fn broker_procs_path(&self) -> std::path::PathBuf {
        self.hierarchy.broker_procs_path()
    }

    #[must_use]
    pub fn broker_mark(&self) -> u32 {
        self.config.broker_mark
    }

    /// The last-known-good ruleset currently installed.
    #[must_use]
    pub fn current_config(&self) -> &NftConfig {
        &self.config
    }

    /// Places the broker process into the broker cgroup. Safe to call again
    /// after a broker restart; the cgroup is never recreated.
    pub fn place_broker(&self, pid: u32) -> Result<(), SupervisorError> {
        if self.teardown_started() {
            return Err(SupervisorError::AlreadyTornDown);
        }
        self.hierarchy.place_broker(pid)?;
        Ok(())
    }

    /// Places the agent process into the agent cgroup. Only meaningful once
    /// the guard is armed (which is the whole point of the ordering).
    pub fn place_agent(&self, pid: u32) -> Result<(), SupervisorError> {
        if self.teardown_started() {
            return Err(SupervisorError::AlreadyTornDown);
        }
        self.hierarchy.place_agent(pid)?;
        Ok(())
    }

    /// Atomically replaces the installed ruleset with `new_config` (same table
    /// name required). On success it becomes the new last-known-good; on
    /// failure the previous table remains installed (atomic transaction) and
    /// the last-known-good is unchanged.
    pub fn update(&mut self, new_config: NftConfig) -> Result<(), SupervisorError> {
        if self.teardown_started() {
            return Err(SupervisorError::AlreadyTornDown);
        }
        if new_config.table_name != self.config.table_name {
            return Err(SupervisorError::TableNameChanged);
        }
        nft::validate_ruleset(&new_config, self.runner.as_ref())?;
        nft::apply(&new_config, self.runner.as_ref())?;
        self.config = new_config;
        Ok(())
    }

    /// Re-applies the last-known-good ruleset, e.g. after an external
    /// disruption or a failed update.
    pub fn rollback(&self) -> Result<(), SupervisorError> {
        if self.teardown_started() {
            return Err(SupervisorError::AlreadyTornDown);
        }
        nft::apply(&self.config, self.runner.as_ref())?;
        Ok(())
    }

    /// Whether teardown has begun (cgroups and/or the nft table already
    /// removed). Once it has, placing processes or mutating the ruleset is
    /// refused.
    fn teardown_started(&self) -> bool {
        self.cgroups_torn_down || self.nft_torn_down
    }

    /// Tears down enforcement in a **fail-closed order**: the owned cgroups are
    /// removed/verified-empty *first*; only once they are gone is the nftables
    /// table removed. If cgroup cleanup reports any real error (e.g. a process
    /// still occupies a cgroup), the nftables table is **retained** so that
    /// process cannot regain unrestricted egress, the error is returned, and the
    /// guard is left un-torn-down so a later call can complete the teardown.
    ///
    /// Each stage is tracked independently, so teardown is fully **retryable**:
    /// if the cgroups are removed but the nftables `destroy` fails, a later
    /// `teardown()` skips the already-done cgroup step and retries only the
    /// table removal. The top-level owned `sendbox` cgroup directory is removed
    /// when empty and tolerated when a sibling instance still owns it.
    /// Idempotent once both stages have succeeded.
    pub fn teardown(&mut self) -> Vec<SupervisorError> {
        // 1. Remove/verify the owned cgroups first. Retryable: on failure the
        //    flag stays unset and the nft table is retained.
        if !self.cgroups_torn_down {
            let cgroup_errors = self.hierarchy.teardown();
            if cgroup_errors.is_empty() {
                self.cgroups_torn_down = true;
            } else {
                // Retain the nftables table: a process may still be confined by
                // it. A later call (or `Drop`) can try again.
                return cgroup_errors
                    .into_iter()
                    .map(SupervisorError::Cgroup)
                    .collect();
            }
        }
        // 2. Cgroups are gone; only now remove the nftables table. Retryable:
        //    if `destroy` fails, `nft_torn_down` stays false so a later call
        //    retries just this step.
        let mut errors = Vec::new();
        if !self.nft_torn_down {
            match nft::cleanup(&self.config, self.runner.as_ref()) {
                Ok(()) => self.nft_torn_down = true,
                Err(err) => errors.push(SupervisorError::Nft(err)),
            }
        }
        errors
    }
}

impl Drop for ArmedEgress {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::nft::NftRunner;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Output;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Shared record of the verbs an `nft` runner was asked to run, so a test
    /// can assert (for example) that `destroy` was never called.
    type CallLog = Arc<Mutex<Vec<String>>>;

    /// Scriptable fake `nft` runner: records verbs into a shared log and can be
    /// told to fail a specific verb, so the arm ordering, teardown ordering, and
    /// rollback semantics are testable without a real `nft`.
    struct ScriptRunner {
        fail_verb: Option<String>,
        list_installed: bool,
        log: CallLog,
    }

    impl ScriptRunner {
        fn ok() -> Self {
            Self::with_log(None, true, Arc::new(Mutex::new(Vec::new())))
        }

        fn failing(verb: &str) -> Self {
            Self::with_log(
                Some(verb.to_owned()),
                true,
                Arc::new(Mutex::new(Vec::new())),
            )
        }

        fn table_absent() -> Self {
            Self::with_log(None, false, Arc::new(Mutex::new(Vec::new())))
        }

        fn with_log(fail_verb: Option<String>, list_installed: bool, log: CallLog) -> Self {
            Self {
                fail_verb,
                list_installed,
                log,
            }
        }

        fn verb(args: &[&str]) -> &'static str {
            if args.first() == Some(&"--check") {
                "check"
            } else if args.first() == Some(&"-f") {
                "apply"
            } else if args.first() == Some(&"list") {
                "list"
            } else if args.first() == Some(&"destroy") {
                "destroy"
            } else {
                "other"
            }
        }
    }

    impl NftRunner for ScriptRunner {
        fn run(&self, args: &[&str], _stdin: Option<&[u8]>) -> std::io::Result<Output> {
            let verb = Self::verb(args);
            self.log.lock().unwrap().push(verb.to_owned());
            let success = if self.fail_verb.as_deref() == Some(verb) {
                false
            } else if verb == "list" {
                self.list_installed
            } else {
                true
            };
            Ok(Output {
                status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 }),
                stdout: Vec::new(),
                stderr: b"scripted".to_vec(),
            })
        }
    }

    fn config() -> SupervisorConfig {
        SupervisorConfig::new("inst01", 0x5b0e, 15080).with_dns_port(15053)
    }

    #[test]
    fn arm_creates_cgroups_and_installs_table_in_order() {
        let root = tempfile::tempdir().unwrap();
        let runner = Box::new(ScriptRunner::ok());
        let armed = ArmedEgress::arm_under(root.path(), runner, config()).unwrap();
        // The nft identity is the mount-relative cgroup path.
        assert_eq!(
            armed.agent_identity().relative_path(),
            "sendbox/inst01/agent"
        );
        assert!(
            armed
                .agent_procs_path()
                .ends_with("sendbox/inst01/agent/cgroup.procs")
        );
        assert_eq!(armed.broker_mark(), 0x5b0e);
        // cgroups were created at the mount-relative path.
        assert!(root.path().join("sendbox/inst01/agent").is_dir());
        drop(armed);
    }

    #[test]
    fn arm_fails_closed_and_unwinds_when_validation_fails() {
        let root = tempfile::tempdir().unwrap();
        let runner = Box::new(ScriptRunner::failing("check"));
        let result = ArmedEgress::arm_under(root.path(), runner, config());
        assert!(matches!(result, Err(SupervisorError::Nft(_))));
        // The hierarchy was torn down on failure (fail closed).
        assert!(!root.path().join("sendbox/inst01/agent").exists());
    }

    #[test]
    fn arm_fails_closed_when_apply_fails() {
        let root = tempfile::tempdir().unwrap();
        let runner = Box::new(ScriptRunner::failing("apply"));
        let result = ArmedEgress::arm_under(root.path(), runner, config());
        assert!(matches!(result, Err(SupervisorError::Nft(_))));
        assert!(!root.path().join("sendbox/inst01").exists());
    }

    #[test]
    fn arm_refuses_when_table_not_installed_after_apply() {
        let root = tempfile::tempdir().unwrap();
        let runner = Box::new(ScriptRunner::table_absent());
        let result = ArmedEgress::arm_under(root.path(), runner, config());
        assert!(matches!(result, Err(SupervisorError::TableNotInstalled)));
        assert!(!root.path().join("sendbox/inst01").exists());
    }

    #[test]
    fn update_rejects_a_different_table_name() {
        let root = tempfile::tempdir().unwrap();
        let mut armed =
            ArmedEgress::arm_under(root.path(), Box::new(ScriptRunner::ok()), config()).unwrap();
        let mut other = armed.current_config().clone();
        other.table_name = "sbxeg_other".to_owned();
        assert!(matches!(
            armed.update(other),
            Err(SupervisorError::TableNameChanged)
        ));
    }

    #[test]
    fn update_becomes_new_last_known_good_on_success() {
        let root = tempfile::tempdir().unwrap();
        let mut armed =
            ArmedEgress::arm_under(root.path(), Box::new(ScriptRunner::ok()), config()).unwrap();
        let mut next = armed.current_config().clone();
        next.connect_broker_tcp_port = 25080;
        armed.update(next).unwrap();
        assert_eq!(armed.current_config().connect_broker_tcp_port, 25080);
    }

    #[test]
    fn teardown_is_idempotent_and_absent_safe() {
        let root = tempfile::tempdir().unwrap();
        let mut armed =
            ArmedEgress::arm_under(root.path(), Box::new(ScriptRunner::ok()), config()).unwrap();
        let first = armed.teardown();
        assert!(first.is_empty(), "teardown errors: {first:?}");
        let second = armed.teardown();
        assert!(second.is_empty());
        assert!(!root.path().join("sendbox/inst01").exists());
    }

    #[test]
    fn teardown_removes_cgroups_before_the_nft_table() {
        let root = tempfile::tempdir().unwrap();
        let log: CallLog = Arc::new(Mutex::new(Vec::new()));
        let runner = Box::new(ScriptRunner::with_log(None, true, Arc::clone(&log)));
        let mut armed = ArmedEgress::arm_under(root.path(), runner, config()).unwrap();
        log.lock().unwrap().clear();
        let errors = armed.teardown();
        assert!(errors.is_empty(), "teardown errors: {errors:?}");
        // On a clean teardown, the nft table is destroyed only after cgroups.
        assert_eq!(log.lock().unwrap().as_slice(), ["destroy"]);
    }

    #[test]
    fn teardown_retains_nft_when_cgroup_cleanup_fails() {
        let root = tempfile::tempdir().unwrap();
        let log: CallLog = Arc::new(Mutex::new(Vec::new()));
        let runner = Box::new(ScriptRunner::with_log(None, true, Arc::clone(&log)));
        let mut armed = ArmedEgress::arm_under(root.path(), runner, config()).unwrap();
        // Simulate a lingering process so the leaf cgroup cannot be removed.
        armed.place_agent(4242).unwrap();
        log.lock().unwrap().clear();
        let errors = armed.teardown();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, SupervisorError::Cgroup(_))),
            "expected a surfaced cgroup error, got {errors:?}"
        );
        // Fail-closed: the nft table must NOT be destroyed while a process may
        // still be confined by it.
        assert!(
            !log.lock().unwrap().iter().any(|v| v == "destroy"),
            "nft cleanup must not run when cgroup cleanup fails: {:?}",
            log.lock().unwrap()
        );
    }

    /// Fix 1: a re-arm of an already-armed (live) instance whose apply fails
    /// must NOT destroy the pre-existing owned table, and must leave the live
    /// cgroups in place. The atomic transaction rolled back, so the previous
    /// table is still enforcing.
    #[test]
    fn failed_rearm_preserves_preexisting_table_and_cgroups() {
        let root = tempfile::tempdir().unwrap();
        // First arm installs the table + cgroups for this stable instance.
        let armed =
            ArmedEgress::arm_under(root.path(), Box::new(ScriptRunner::ok()), config()).unwrap();
        // A broker is confined, so the instance is live and its cgroup is
        // non-empty (cannot be removed by a re-arm anyway).
        armed.place_broker(4242).unwrap();

        // A re-arm whose apply fails must not destroy the pre-existing table.
        let log: CallLog = Arc::new(Mutex::new(Vec::new()));
        let runner = Box::new(ScriptRunner::with_log(
            Some("apply".to_owned()),
            true,
            Arc::clone(&log),
        ));
        let result = ArmedEgress::arm_under(root.path(), runner, config());
        assert!(matches!(result, Err(SupervisorError::Nft(_))));
        assert!(
            !log.lock().unwrap().iter().any(|v| v == "destroy"),
            "failed re-arm must not destroy the pre-existing table: {:?}",
            log.lock().unwrap()
        );
        // The live instance's cgroups survive the failed re-arm.
        assert!(root.path().join("sendbox/inst01/broker").is_dir());
        assert!(root.path().join("sendbox/inst01/agent").is_dir());
        drop(armed);
    }

    /// A fake runner that fails the *first* `destroy` and succeeds afterward, so
    /// a teardown whose nft cleanup transiently fails can be shown to retry.
    struct DestroyFailsOnceRunner {
        destroy_calls: Arc<AtomicUsize>,
        log: CallLog,
    }

    impl NftRunner for DestroyFailsOnceRunner {
        fn run(&self, args: &[&str], _stdin: Option<&[u8]>) -> std::io::Result<Output> {
            let verb = ScriptRunner::verb(args);
            self.log.lock().unwrap().push(verb.to_owned());
            let success = if verb == "destroy" {
                // Fail only the first destroy attempt.
                self.destroy_calls.fetch_add(1, Ordering::SeqCst) != 0
            } else {
                true
            };
            Ok(Output {
                status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 }),
                stdout: Vec::new(),
                stderr: b"scripted".to_vec(),
            })
        }
    }

    /// Fix 2: teardown is retryable. When cgroup removal succeeds but the nft
    /// `destroy` fails, the error is surfaced and a *later* teardown retries the
    /// table removal (rather than being silently marked complete).
    #[test]
    fn teardown_retries_nft_cleanup_after_a_transient_failure() {
        let root = tempfile::tempdir().unwrap();
        let log: CallLog = Arc::new(Mutex::new(Vec::new()));
        let runner = Box::new(DestroyFailsOnceRunner {
            destroy_calls: Arc::new(AtomicUsize::new(0)),
            log: Arc::clone(&log),
        });
        let mut armed = ArmedEgress::arm_under(root.path(), runner, config()).unwrap();

        // First teardown: cgroups are removed, but the nft destroy fails.
        let first = armed.teardown();
        assert!(
            first.iter().any(|e| matches!(e, SupervisorError::Nft(_))),
            "first teardown must surface the nft failure: {first:?}"
        );
        // Cgroups are already gone (they were removed before the nft step).
        assert!(!root.path().join("sendbox/inst01").exists());

        // Second teardown: the cgroup step is skipped and the destroy is retried
        // and now succeeds.
        let second = armed.teardown();
        assert!(
            second.is_empty(),
            "retry must complete the nft cleanup: {second:?}"
        );
        let destroys = log
            .lock()
            .unwrap()
            .iter()
            .filter(|v| *v == "destroy")
            .count();
        assert_eq!(destroys, 2, "destroy should have been attempted twice");
    }
}
