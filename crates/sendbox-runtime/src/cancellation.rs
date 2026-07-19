use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::Notify;

#[derive(Debug, Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

/// Explicit cooperative cancellation.
///
/// This token is not channel-backed. Dropping the last token, or any subset of
/// cloned tokens, never means cancellation. Only [`CancellationToken::cancel`]
/// changes the state and wakes waiters.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    state: Arc<CancellationState>,
}

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        if !self.state.cancelled.swap(true, Ordering::AcqRel) {
            self.state.notify.notify_waiters();
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        loop {
            let notified = self.state.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::CancellationToken;

    #[tokio::test]
    async fn dropping_handles_is_not_cancellation() {
        let token = CancellationToken::new();
        let dropped = token.clone();
        drop(dropped);

        assert!(
            tokio::time::timeout(Duration::from_millis(10), token.cancelled())
                .await
                .is_err()
        );

        token.cancel();
        token.cancelled().await;
    }
}
