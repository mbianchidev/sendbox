use serde::{Deserialize, Serialize};

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
