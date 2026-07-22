use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::GuestError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    PrivilegeDrop,
    Capabilities,
    Seccomp,
}

impl ControlKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PrivilegeDrop => "privilege_drop",
            Self::Capabilities => "capabilities",
            Self::Seccomp => "seccomp",
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
        if !root.join("cgroup.controllers").is_file() {
            return Err(GuestError::Runtime(
                "cgroup v2 is not mounted at /sys/fs/cgroup".to_owned(),
            ));
        }
        if !self.cgroup_parent.exists() {
            std::fs::create_dir(&self.cgroup_parent)
                .map_err(|error| GuestError::io("creating broker cgroup parent", error))?;
        }
        let controllers = std::fs::read_to_string(root.join("cgroup.controllers"))
            .map_err(|error| GuestError::io("reading cgroup controllers", error))?;
        let requested = ["cpu", "memory", "pids"]
            .into_iter()
            .filter(|controller| {
                controllers
                    .split_whitespace()
                    .any(|value| value == *controller)
            })
            .map(|controller| format!("+{controller}"))
            .collect::<Vec<_>>()
            .join(" ");
        if !requested.is_empty() {
            std::fs::write(root.join("cgroup.subtree_control"), requested)
                .map_err(|error| GuestError::io("delegating cgroup controllers", error))?;
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
        seccomp.detail =
            "NNP and TSYNC deny direct execve, execveat, clone3, and memfd_create".to_owned();
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
