use std::sync::Mutex;

use thiserror::Error;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifecycleState {
    #[default]
    New,
    Initialized,
    Created,
    Running,
    Stopping,
    Stopped,
    Cleaning,
    Cleaned,
    Failed,
}

impl LifecycleState {
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::New, Self::Initialized | Self::Cleaning | Self::Failed)
                | (
                    Self::Initialized,
                    Self::Created | Self::Cleaning | Self::Failed
                )
                | (
                    Self::Created,
                    Self::Running | Self::Stopped | Self::Cleaning | Self::Failed
                )
                | (Self::Running, Self::Stopping | Self::Stopped | Self::Failed)
                | (Self::Stopping, Self::Stopped | Self::Failed)
                | (Self::Stopped, Self::Cleaning | Self::Cleaned | Self::Failed)
                | (Self::Cleaning, Self::Cleaned | Self::Failed)
                | (Self::Failed, Self::Cleaning | Self::Cleaned)
        )
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum LifecycleTransitionError {
    #[error("duplicate lifecycle transition to {state:?}")]
    Duplicate { state: LifecycleState },
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    Invalid {
        from: LifecycleState,
        to: LifecycleState,
    },
}

/// A lifecycle state machine whose validation and update share one critical section.
///
/// Concurrent callers cannot both observe the same source state and commit
/// conflicting updates. A duplicate request is an error rather than an idempotent
/// success so adapter orchestration bugs remain visible.
#[derive(Debug, Default)]
pub struct LifecycleStateMachine {
    state: Mutex<LifecycleState>,
}

impl LifecycleStateMachine {
    #[must_use]
    pub fn new(initial: LifecycleState) -> Self {
        Self {
            state: Mutex::new(initial),
        }
    }

    #[must_use]
    pub fn current(&self) -> LifecycleState {
        *self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn transition(
        &self,
        next: LifecycleState,
    ) -> Result<LifecycleState, LifecycleTransitionError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous = *state;
        if previous == next {
            return Err(LifecycleTransitionError::Duplicate { state: next });
        }
        if !previous.can_transition_to(next) {
            return Err(LifecycleTransitionError::Invalid {
                from: previous,
                to: next,
            });
        }
        *state = next;
        Ok(previous)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use proptest::prelude::*;

    use super::{LifecycleState, LifecycleStateMachine, LifecycleTransitionError};

    const STATES: [LifecycleState; 9] = [
        LifecycleState::New,
        LifecycleState::Initialized,
        LifecycleState::Created,
        LifecycleState::Running,
        LifecycleState::Stopping,
        LifecycleState::Stopped,
        LifecycleState::Cleaning,
        LifecycleState::Cleaned,
        LifecycleState::Failed,
    ];

    #[test]
    fn every_state_pair_matches_the_transition_table() {
        for from in STATES {
            for to in STATES {
                let machine = LifecycleStateMachine::new(from);
                let result = machine.transition(to);
                if from == to {
                    assert_eq!(
                        result,
                        Err(LifecycleTransitionError::Duplicate { state: to })
                    );
                    assert_eq!(machine.current(), from);
                } else if from.can_transition_to(to) {
                    assert_eq!(result, Ok(from));
                    assert_eq!(machine.current(), to);
                } else {
                    assert_eq!(result, Err(LifecycleTransitionError::Invalid { from, to }));
                    assert_eq!(machine.current(), from);
                }
            }
        }
    }

    proptest! {
        #[test]
        fn arbitrary_sequences_never_apply_invalid_or_duplicate_transitions(
            initial in 0_usize..STATES.len(),
            sequence in proptest::collection::vec(0_usize..STATES.len(), 0..128),
        ) {
            let initial = STATES[initial];
            let machine = LifecycleStateMachine::new(initial);
            let mut expected = initial;

            for index in sequence {
                let next = STATES[index];
                let result = machine.transition(next);
                if expected != next && expected.can_transition_to(next) {
                    prop_assert_eq!(result, Ok(expected));
                    expected = next;
                } else {
                    prop_assert!(result.is_err());
                }
                prop_assert_eq!(machine.current(), expected);
            }
        }
    }

    #[test]
    fn concurrent_duplicate_transition_has_exactly_one_winner() {
        let machine = Arc::new(LifecycleStateMachine::default());
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();

        for _ in 0..2 {
            let machine = Arc::clone(&machine);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                machine.transition(LifecycleState::Initialized)
            }));
        }

        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().expect("transition thread"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(LifecycleTransitionError::Duplicate { .. })))
                .count(),
            1
        );
        assert_eq!(machine.current(), LifecycleState::Initialized);
    }
}
