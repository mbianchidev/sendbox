#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use sendbox_runtime::{
    BoxFuture, CancellationToken, CleanupStep, CleanupTransaction, OperationFailure, RuntimeError,
};

#[derive(Debug)]
struct InjectedStep {
    name: String,
    order: Arc<Mutex<Vec<String>>>,
    failures_remaining: Mutex<usize>,
}

impl CleanupStep for InjectedStep {
    fn name(&self) -> &str {
        &self.name
    }

    fn cleanup<'a>(
        &'a self,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            self.order
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(self.name.clone());
            let mut failures = self
                .failures_remaining
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if *failures > 0 {
                *failures -= 1;
                Err(RuntimeError::Injected {
                    operation: self.name.clone(),
                    message: "cleanup failure".to_owned(),
                })
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test]
async fn every_step_failure_continues_in_reverse_order_and_retries_only_failures() {
    let names = ["mount", "network", "container", "temporary-files"];

    for failing_index in 0..names.len() {
        let transaction = CleanupTransaction::new();
        let order = Arc::new(Mutex::new(Vec::new()));
        for (index, name) in names.iter().enumerate() {
            transaction
                .push(Arc::new(InjectedStep {
                    name: (*name).to_owned(),
                    order: Arc::clone(&order),
                    failures_remaining: Mutex::new(usize::from(index == failing_index)),
                }))
                .await;
        }

        let first = transaction.cleanup(&CancellationToken::new()).await;
        assert_eq!(first.attempted, names.len());
        assert_eq!(first.succeeded, names.len() - 1);
        assert_eq!(first.remaining, 1);
        assert_eq!(first.failures.len(), 1);
        assert_eq!(
            order
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .as_slice(),
            ["temporary-files", "container", "network", "mount"]
        );

        order
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
        let second = transaction.cleanup(&CancellationToken::new()).await;
        assert!(second.is_complete());
        assert_eq!(second.attempted, 1);
        assert_eq!(
            order
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .as_slice(),
            [names[failing_index]]
        );

        order
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
        let third = transaction.cleanup(&CancellationToken::new()).await;
        assert!(third.is_complete());
        assert_eq!(third.attempted, 0);
        assert!(
            order
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .is_empty()
        );
    }
}

#[tokio::test]
async fn primary_error_is_preserved_with_structured_cleanup_failures() {
    let transaction = CleanupTransaction::new();
    transaction
        .push(Arc::new(InjectedStep {
            name: "container".to_owned(),
            order: Arc::new(Mutex::new(Vec::new())),
            failures_remaining: Mutex::new(1),
        }))
        .await;
    let cleanup = transaction.cleanup(&CancellationToken::new()).await;
    let failure = OperationFailure::new(
        RuntimeError::Provider("primary create failure".to_owned()),
        cleanup,
    );

    assert!(matches!(failure.primary, RuntimeError::Provider(_)));
    assert_eq!(failure.cleanup.failures.len(), 1);
    assert_eq!(failure.cleanup.failures[0].step, "container");
    assert!(failure.to_string().contains("primary create failure"));
}
