use std::{error::Error, fmt, sync::Arc};

use tokio::sync::Mutex;

use crate::{BoxFuture, CancellationToken, RuntimeError};

pub trait CleanupStep: Send + Sync {
    fn name(&self) -> &str;

    fn cleanup<'a>(
        &'a self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>>;
}

struct StepState {
    step: Arc<dyn CleanupStep>,
    completed: bool,
}

/// An idempotent compensation stack for partially completed lifecycle work.
///
/// Steps run in reverse registration order. Every incomplete step is attempted
/// in each pass even after another step fails. Successful steps are permanently
/// marked complete; failed steps remain eligible for a later retry. Implementors
/// must treat an already-absent resource as success.
pub struct CleanupTransaction {
    steps: Mutex<Vec<StepState>>,
}

impl fmt::Debug for CleanupTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanupTransaction")
            .finish_non_exhaustive()
    }
}

impl Default for CleanupTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl CleanupTransaction {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            steps: Mutex::const_new(Vec::new()),
        }
    }

    pub async fn push(&self, step: Arc<dyn CleanupStep>) {
        self.steps.lock().await.push(StepState {
            step,
            completed: false,
        });
    }

    pub async fn cleanup(&self, cancellation: &CancellationToken) -> CleanupReport {
        let mut steps = self.steps.lock().await;
        let mut attempted = 0;
        let mut succeeded = 0;
        let mut failures = Vec::new();

        for index in (0..steps.len()).rev() {
            if steps[index].completed {
                continue;
            }
            attempted += 1;
            let step = Arc::clone(&steps[index].step);
            match step.cleanup(cancellation).await {
                Ok(()) => {
                    steps[index].completed = true;
                    succeeded += 1;
                }
                Err(error) => failures.push(CleanupFailure {
                    step: step.name().to_owned(),
                    error,
                }),
            }
        }

        let remaining = steps.iter().filter(|state| !state.completed).count();
        CleanupReport {
            attempted,
            succeeded,
            remaining,
            failures,
        }
    }
}

#[derive(Debug)]
pub struct CleanupFailure {
    pub step: String,
    pub error: RuntimeError,
}

#[derive(Debug, Default)]
pub struct CleanupReport {
    pub attempted: usize,
    pub succeeded: usize,
    pub remaining: usize,
    pub failures: Vec<CleanupFailure>,
}

impl CleanupReport {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.remaining == 0 && self.failures.is_empty()
    }
}

#[derive(Debug)]
pub struct OperationFailure {
    pub primary: RuntimeError,
    pub cleanup: CleanupReport,
}

impl OperationFailure {
    #[must_use]
    pub const fn new(primary: RuntimeError, cleanup: CleanupReport) -> Self {
        Self { primary, cleanup }
    }
}

impl fmt::Display for OperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.primary)?;
        if !self.cleanup.failures.is_empty() {
            write!(
                formatter,
                " ({} cleanup step(s) failed)",
                self.cleanup.failures.len()
            )?;
        }
        Ok(())
    }
}

impl Error for OperationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}
