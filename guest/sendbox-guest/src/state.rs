use serde::{Deserialize, Serialize};

use crate::GuestError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupState {
    AwaitingBootstrap,
    BootstrapConsumed,
    ManifestVerified,
    RuntimePrepared,
    ControlsVerified,
    ServicesStarting,
    SelfTesting,
    Ready,
    AgentLaunchPermitted,
    ShuttingDown,
    Terminated,
    Failed,
}

impl StartupState {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AwaitingBootstrap => "awaiting_bootstrap",
            Self::BootstrapConsumed => "bootstrap_consumed",
            Self::ManifestVerified => "manifest_verified",
            Self::RuntimePrepared => "runtime_prepared",
            Self::ControlsVerified => "controls_verified",
            Self::ServicesStarting => "services_starting",
            Self::SelfTesting => "self_testing",
            Self::Ready => "ready",
            Self::AgentLaunchPermitted => "agent_launch_permitted",
            Self::ShuttingDown => "shutting_down",
            Self::Terminated => "terminated",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug)]
pub struct StartupStateMachine {
    state: StartupState,
}

impl Default for StartupStateMachine {
    fn default() -> Self {
        Self {
            state: StartupState::AwaitingBootstrap,
        }
    }
}

impl StartupStateMachine {
    #[must_use]
    pub const fn state(&self) -> StartupState {
        self.state
    }

    pub fn transition(&mut self, next: StartupState) -> Result<(), GuestError> {
        if !is_allowed(self.state, next) {
            return Err(GuestError::InvalidTransition {
                from: self.state.name(),
                to: next.name(),
            });
        }
        self.state = next;
        Ok(())
    }

    pub fn permit_agent_launch(&mut self) -> Result<(), GuestError> {
        self.transition(StartupState::AgentLaunchPermitted)
    }

    pub fn fail(&mut self) {
        if !matches!(
            self.state,
            StartupState::ShuttingDown | StartupState::Terminated
        ) {
            self.state = StartupState::Failed;
        }
    }
}

const fn is_allowed(from: StartupState, to: StartupState) -> bool {
    matches!(
        (from, to),
        (
            StartupState::AwaitingBootstrap,
            StartupState::BootstrapConsumed
        ) | (
            StartupState::BootstrapConsumed,
            StartupState::ManifestVerified
        ) | (
            StartupState::ManifestVerified,
            StartupState::RuntimePrepared
        ) | (
            StartupState::RuntimePrepared,
            StartupState::ServicesStarting
        ) | (
            StartupState::ServicesStarting,
            StartupState::ControlsVerified
        ) | (StartupState::ControlsVerified, StartupState::SelfTesting)
            | (StartupState::SelfTesting, StartupState::Ready)
            | (StartupState::Ready, StartupState::AgentLaunchPermitted)
            | (StartupState::Ready, StartupState::ShuttingDown)
            | (
                StartupState::AgentLaunchPermitted,
                StartupState::ShuttingDown
            )
            | (StartupState::Failed, StartupState::ShuttingDown)
            | (StartupState::ShuttingDown, StartupState::Terminated)
    )
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn strict_happy_path_reaches_launch_permission() {
        let mut machine = StartupStateMachine::default();
        for state in [
            StartupState::BootstrapConsumed,
            StartupState::ManifestVerified,
            StartupState::RuntimePrepared,
            StartupState::ServicesStarting,
            StartupState::ControlsVerified,
            StartupState::SelfTesting,
            StartupState::Ready,
            StartupState::AgentLaunchPermitted,
        ] {
            machine.transition(state).expect("valid transition");
        }
    }

    proptest! {
        #[test]
        fn readiness_cannot_be_skipped(index in 0_usize..6) {
            let states = [
                StartupState::AwaitingBootstrap,
                StartupState::BootstrapConsumed,
                StartupState::ManifestVerified,
                StartupState::RuntimePrepared,
                StartupState::ControlsVerified,
                StartupState::ServicesStarting,
            ];
            let mut machine = StartupStateMachine { state: states[index] };
            prop_assert!(machine.transition(StartupState::Ready).is_err());
        }
    }
}
