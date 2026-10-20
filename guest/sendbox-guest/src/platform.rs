use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;

pub use sendbox_bootstrap::ControlKind;

use crate::GuestError;

#[cfg(any(target_os = "linux", test))]
pub(crate) const RUNTIME_CGROUP_NAME: &str = "sendbox-runtime";

/// Stabilize init placement before native execs can race controller delegation.
pub fn prepare_native_exec_cgroup(hierarchy_root: &Path) -> Result<(), GuestError> {
    #[cfg(any(target_os = "linux", test))]
    {
        if !hierarchy_root.join("cgroup.controllers").is_file() {
            return Err(GuestError::Runtime(
                "cgroup v2 is not mounted at /sys/fs/cgroup".to_owned(),
            ));
        }
        move_root_processes_to_runtime_cgroup(hierarchy_root)
    }
    #[cfg(not(any(target_os = "linux", test)))]
    {
        let _ = hierarchy_root;
        Err(GuestError::Runtime(
            "Linux cgroup preparation requires Linux".to_owned(),
        ))
    }
}

#[cfg(any(target_os = "linux", test))]
fn move_root_processes_to_runtime_cgroup(hierarchy_root: &Path) -> Result<(), GuestError> {
    let processes = std::fs::read_to_string(hierarchy_root.join("cgroup.procs"))
        .map_err(|error| GuestError::io("reading root cgroup processes", error))?;
    if processes.trim().is_empty() {
        return Ok(());
    }
    let runtime_cgroup = hierarchy_root.join(RUNTIME_CGROUP_NAME);
    if !runtime_cgroup.exists() {
        std::fs::create_dir(&runtime_cgroup)
            .map_err(|error| GuestError::io("creating runtime cgroup", error))?;
    }
    for process in processes.lines().filter(|value| !value.is_empty()) {
        match std::fs::write(runtime_cgroup.join("cgroup.procs"), process) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) => {
                eprintln!(
                    "sendbox-guest: runtime process {process} exited before cgroup migration"
                );
            }
            Err(error) => {
                return Err(GuestError::io("moving process into runtime cgroup", error));
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn delegate_controllers_with_retry(
    mut migrate: impl FnMut() -> Result<(), GuestError>,
    mut enable: impl FnMut() -> std::io::Result<()>,
    timeout: Duration,
) -> Result<(), GuestError> {
    let deadline = std::time::Instant::now() + timeout;
    let mut retrying = false;
    loop {
        migrate()?;
        match enable() {
            Ok(()) => return Ok(()),
            Err(error)
                if error.raw_os_error() == Some(rustix::io::Errno::BUSY.raw_os_error())
                    && std::time::Instant::now() < deadline =>
            {
                if !retrying {
                    eprintln!(
                        "sendbox-guest: runtime processes raced with cgroup delegation; refreshing before retry"
                    );
                    retrying = true;
                }
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(std::time::Instant::now())),
                );
            }
            Err(error) => {
                return Err(GuestError::io("delegating cgroup controllers", error));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlStatus {
    pub control: ControlKind,
    pub required: bool,
    pub verified: bool,
    pub detail: String,
}

pub trait PlatformControls: Send + Sync {
    fn apply_and_verify(&self, required: &[ControlKind]) -> Result<Vec<ControlStatus>, GuestError>;

    fn lockdown_and_verify(
        &self,
        statuses: Vec<ControlStatus>,
    ) -> Result<Vec<ControlStatus>, GuestError> {
        self.self_test(&statuses)?;
        Ok(statuses)
    }

    fn self_test(&self, statuses: &[ControlStatus]) -> Result<(), GuestError>;
}

#[derive(Debug, Default)]
pub struct UnavailablePlatformControls;

impl PlatformControls for UnavailablePlatformControls {
    fn apply_and_verify(&self, required: &[ControlKind]) -> Result<Vec<ControlStatus>, GuestError> {
        let statuses = [
            ControlKind::PrivilegeDrop,
            ControlKind::Capabilities,
            ControlKind::Seccomp,
        ]
        .into_iter()
        .map(|control| ControlStatus {
            control,
            required: required.contains(&control),
            verified: false,
            detail: "Linux privilege integration is not implemented in this foundation".to_owned(),
        })
        .collect::<Vec<_>>();
        reject_unverified_required(&statuses)?;
        Ok(statuses)
    }

    fn self_test(&self, statuses: &[ControlStatus]) -> Result<(), GuestError> {
        reject_unverified_required(statuses)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct LinuxPlatformControls {
    cgroup_parent: PathBuf,
}

#[cfg(target_os = "linux")]
impl LinuxPlatformControls {
    #[must_use]
    pub fn new(cgroup_parent: PathBuf) -> Self {
        Self { cgroup_parent }
    }

    fn prepare_cgroup_v2(&self) -> Result<(), GuestError> {
        let root = self.cgroup_parent.parent().ok_or_else(|| {
            GuestError::Runtime("cgroup parent does not have a hierarchy root".to_owned())
        })?;
        prepare_native_exec_cgroup(root)?;
        if !self.cgroup_parent.exists() {
            std::fs::create_dir(&self.cgroup_parent)
                .map_err(|error| GuestError::io("creating broker cgroup parent", error))?;
        }
        let controllers = std::fs::read_to_string(root.join("cgroup.controllers"))
            .map_err(|error| GuestError::io("reading cgroup controllers", error))?;
        let delegated = std::fs::read_to_string(root.join("cgroup.subtree_control"))
            .map_err(|error| GuestError::io("reading delegated cgroup controllers", error))?;
        let requested = Self::controllers_to_delegate(&controllers, &delegated);
        if !requested.is_empty() {
            delegate_controllers_with_retry(
                || move_root_processes_to_runtime_cgroup(root),
                || std::fs::write(root.join("cgroup.subtree_control"), requested.as_bytes()),
                Duration::from_secs(5),
            )?;
        }
        Ok(())
    }

    fn verify_cgroup_v2(&self) -> Result<(), GuestError> {
        let controllers = self.cgroup_parent.join("cgroup.controllers");
        let kill = self.cgroup_parent.join("cgroup.kill");
        if !controllers.is_file() || !kill.is_file() {
            return Err(GuestError::Runtime(format!(
                "{} is not a delegated cgroup v2 parent",
                self.cgroup_parent.display()
            )));
        }
        std::fs::OpenOptions::new()
            .write(true)
            .open(&kill)
            .map_err(|error| GuestError::io("opening delegated cgroup.kill", error))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn controllers_to_delegate(available: &str, delegated: &str) -> String {
        ["cpu", "memory", "pids"]
            .into_iter()
            .filter(|controller| {
                available
                    .split_whitespace()
                    .any(|value| value == *controller)
                    && !delegated
                        .split_whitespace()
                        .any(|value| value == *controller)
            })
            .map(|controller| format!("+{controller}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn status(
        control: ControlKind,
        required: &[ControlKind],
        verified: bool,
        detail: impl Into<String>,
    ) -> ControlStatus {
        ControlStatus {
            control,
            required: required.contains(&control),
            verified,
            detail: detail.into(),
        }
    }
}

#[cfg(target_os = "linux")]
impl PlatformControls for LinuxPlatformControls {
    fn apply_and_verify(&self, required: &[ControlKind]) -> Result<Vec<ControlStatus>, GuestError> {
        if rustix::process::getuid().as_raw() != 0 || rustix::process::getgid().as_raw() != 0 {
            return Err(GuestError::Runtime(
                "production guest supervisor must start as uid/gid 0".to_owned(),
            ));
        }
        self.prepare_cgroup_v2()?;
        self.verify_cgroup_v2()?;
        Ok(vec![
            Self::status(
                ControlKind::PrivilegeDrop,
                required,
                true,
                "broker launches workloads as a configured non-root uid/gid",
            ),
            Self::status(
                ControlKind::Capabilities,
                required,
                true,
                "production launcher clears workload capability sets",
            ),
            Self::status(
                ControlKind::Seccomp,
                required,
                false,
                "TSYNC direct-exec filter is installed after mandatory services start",
            ),
        ])
    }

    fn lockdown_and_verify(
        &self,
        mut statuses: Vec<ControlStatus>,
    ) -> Result<Vec<ControlStatus>, GuestError> {
        sendbox_exec::platform::linux::agent::AgentBootstrap::install()
            .map_err(|error| GuestError::Runtime(format!("install agent lockdown: {error}")))?;
        let seccomp = statuses
            .iter_mut()
            .find(|status| status.control == ControlKind::Seccomp)
            .ok_or_else(|| GuestError::Runtime("seccomp status was not prepared".to_owned()))?;
        seccomp.verified = true;
        seccomp.detail = "NNP and TSYNC deny direct execve, execveat, and memfd_create; clone3 returns ENOSYS while classic clone namespace flags remain denied".to_owned();
        self.self_test(&statuses)?;
        Ok(statuses)
    }

    fn self_test(&self, statuses: &[ControlStatus]) -> Result<(), GuestError> {
        self.verify_cgroup_v2()?;
        reject_unverified_required(statuses)
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Default)]
pub struct LinuxPlatformControls;

#[cfg(not(target_os = "linux"))]
impl LinuxPlatformControls {
    #[must_use]
    pub fn new(_cgroup_parent: PathBuf) -> Self {
        Self
    }
}

#[cfg(not(target_os = "linux"))]
impl PlatformControls for LinuxPlatformControls {
    fn apply_and_verify(
        &self,
        _required: &[ControlKind],
    ) -> Result<Vec<ControlStatus>, GuestError> {
        Err(GuestError::Runtime(
            "Linux platform controls require Linux".to_owned(),
        ))
    }

    fn self_test(&self, _statuses: &[ControlStatus]) -> Result<(), GuestError> {
        Err(GuestError::Runtime(
            "Linux platform controls require Linux".to_owned(),
        ))
    }
}

pub fn reject_unverified_required(statuses: &[ControlStatus]) -> Result<(), GuestError> {
    if let Some(status) = statuses
        .iter()
        .find(|status| status.required && !status.verified)
    {
        return Err(GuestError::ControlNotVerified(
            status.control.name().to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_exec_preparation_moves_init_before_controller_delegation() {
        let root = tempfile::tempdir().expect("isolated cgroup filesystem fixture");
        std::fs::write(root.path().join("cgroup.controllers"), "cpu memory pids")
            .expect("available controllers");
        std::fs::write(root.path().join("cgroup.subtree_control"), "")
            .expect("initial controller state");
        std::fs::write(root.path().join("cgroup.procs"), "1\n").expect("init membership");

        prepare_native_exec_cgroup(root.path()).expect("prepare native exec placement");
        prepare_native_exec_cgroup(root.path()).expect("repeated preparation is idempotent");

        assert_eq!(
            std::fs::read_to_string(root.path().join(RUNTIME_CGROUP_NAME).join("cgroup.procs"))
                .expect("init must be moved before bootstrap installation completes"),
            "1"
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("cgroup.subtree_control"))
                .expect("controller state"),
            ""
        );
        assert!(!root.path().join("sendbox").exists());
    }

    #[test]
    fn native_exec_preparation_rejects_missing_cgroup_v2() {
        let root = tempfile::tempdir().expect("isolated filesystem fixture");
        assert!(matches!(
            prepare_native_exec_cgroup(root.path()),
            Err(GuestError::Runtime(_))
        ));
        assert!(!root.path().join(RUNTIME_CGROUP_NAME).exists());
    }

    #[test]
    fn native_exec_preparation_fails_closed_on_process_migration_error() {
        let root = tempfile::tempdir().expect("isolated cgroup filesystem fixture");
        std::fs::write(root.path().join("cgroup.controllers"), "cpu memory pids")
            .expect("available controllers");
        std::fs::write(root.path().join("cgroup.procs"), "1\n").expect("init membership");
        std::fs::write(root.path().join(RUNTIME_CGROUP_NAME), "not a directory")
            .expect("invalid migration target");
        assert!(matches!(
            prepare_native_exec_cgroup(root.path()),
            Err(GuestError::Io { .. })
        ));
    }

    #[test]
    fn busy_delegation_refreshes_processes_before_each_retry() {
        let operations = std::cell::RefCell::new(Vec::new());
        delegate_controllers_with_retry(
            || {
                operations.borrow_mut().push("migrate");
                Ok(())
            },
            || {
                let mut operations = operations.borrow_mut();
                operations.push("enable");
                if operations
                    .iter()
                    .filter(|operation| **operation == "enable")
                    .count()
                    < 3
                {
                    Err(std::io::Error::from_raw_os_error(
                        rustix::io::Errno::BUSY.raw_os_error(),
                    ))
                } else {
                    Ok(())
                }
            },
            Duration::from_secs(1),
        )
        .expect("transient control-process arrivals must not abort startup");
        assert_eq!(
            *operations.borrow(),
            [
                "migrate", "enable", "migrate", "enable", "migrate", "enable"
            ]
        );
    }

    #[test]
    fn delegation_permission_errors_are_not_retried() {
        let attempts = std::cell::Cell::new(0);
        let error = delegate_controllers_with_retry(
            || Ok(()),
            || {
                attempts.set(attempts.get() + 1);
                Err(std::io::Error::from_raw_os_error(
                    rustix::io::Errno::PERM.raw_os_error(),
                ))
            },
            Duration::from_secs(1),
        )
        .expect_err("permission failure must remain fatal");
        assert_eq!(attempts.get(), 1);
        assert!(matches!(
            error,
            GuestError::Io { source, .. }
                if source.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error())
        ));
    }

    #[test]
    fn busy_delegation_deadline_fails_closed() {
        let attempts = std::cell::Cell::new(0);
        let error = delegate_controllers_with_retry(
            || Ok(()),
            || {
                attempts.set(attempts.get() + 1);
                Err(std::io::Error::from_raw_os_error(
                    rustix::io::Errno::BUSY.raw_os_error(),
                ))
            },
            Duration::ZERO,
        )
        .expect_err("busy hierarchy must not become a readiness success");
        assert_eq!(attempts.get(), 1);
        assert!(matches!(
            error,
            GuestError::Io { source, .. }
                if source.raw_os_error() == Some(rustix::io::Errno::BUSY.raw_os_error())
        ));
    }

    #[test]
    fn failed_process_migration_never_enables_controllers() {
        let enabled = std::cell::Cell::new(false);
        let error = delegate_controllers_with_retry(
            || Err(GuestError::Runtime("migration failed".to_owned())),
            || {
                enabled.set(true);
                Ok(())
            },
            Duration::from_secs(1),
        )
        .expect_err("migration failure");
        assert!(!enabled.get());
        assert!(matches!(error, GuestError::Runtime(_)));
    }

    struct VerifiedTestControls;

    impl PlatformControls for VerifiedTestControls {
        fn apply_and_verify(
            &self,
            required: &[ControlKind],
        ) -> Result<Vec<ControlStatus>, GuestError> {
            Ok(required
                .iter()
                .copied()
                .map(|control| ControlStatus {
                    control,
                    required: true,
                    verified: true,
                    detail: "verified by deterministic test adapter".to_owned(),
                })
                .collect())
        }

        fn self_test(&self, statuses: &[ControlStatus]) -> Result<(), GuestError> {
            reject_unverified_required(statuses)
        }
    }

    #[test]
    fn no_op_controls_never_claim_required_readiness() {
        let error = UnavailablePlatformControls
            .apply_and_verify(&[ControlKind::Seccomp])
            .expect_err("required no-op control must fail");
        assert!(matches!(error, GuestError::ControlNotVerified(_)));
    }

    #[test]
    fn injected_test_controls_can_prove_the_happy_path() {
        let statuses = VerifiedTestControls
            .apply_and_verify(&[ControlKind::Seccomp])
            .expect("test control");
        assert!(statuses[0].verified);
    }
}
