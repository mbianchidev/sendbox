use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use tokio::sync::mpsc;

use crate::{BoxFuture, CancellationToken, RuntimeError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutputLoss {
    pub dropped_events: u64,
    pub dropped_bytes: u64,
    pub first_global_sequence: u64,
    pub last_global_sequence: u64,
    pub stdout_events: u64,
    pub stderr_events: u64,
}

impl OutputLoss {
    fn record(&mut self, stream: OutputStream, sequence: u64, bytes: usize) {
        if self.dropped_events == 0 {
            self.first_global_sequence = sequence;
        }
        self.dropped_events = self.dropped_events.saturating_add(1);
        self.dropped_bytes = self.dropped_bytes.saturating_add(bytes as u64);
        self.last_global_sequence = sequence;
        match stream {
            OutputStream::Stdout => {
                self.stdout_events = self.stdout_events.saturating_add(1);
            }
            OutputStream::Stderr => {
                self.stderr_events = self.stderr_events.saturating_add(1);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputEvent {
    Data {
        stream: OutputStream,
        global_sequence: u64,
        stream_sequence: u64,
        bytes: Vec<u8>,
        dropped_before: Option<OutputLoss>,
    },
    Loss {
        global_sequence: u64,
        dropped: OutputLoss,
    },
}

impl OutputEvent {
    #[must_use]
    pub const fn global_sequence(&self) -> u64 {
        match self {
            Self::Data {
                global_sequence, ..
            }
            | Self::Loss {
                global_sequence, ..
            } => *global_sequence,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutputStats {
    pub delivered_events: u64,
    pub dropped: OutputLoss,
}

pub trait OutputSubscription: Send {
    fn next<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Option<OutputEvent>, RuntimeError>>;
}

#[derive(Debug, Default)]
pub struct VecOutputSubscription {
    events: VecDeque<OutputEvent>,
}

impl VecOutputSubscription {
    #[must_use]
    pub fn new(events: impl IntoIterator<Item = OutputEvent>) -> Self {
        Self {
            events: events.into_iter().collect(),
        }
    }
}

impl OutputSubscription for VecOutputSubscription {
    fn next<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Option<OutputEvent>, RuntimeError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            Ok(self.events.pop_front())
        })
    }
}

struct PublisherState {
    next_global_sequence: u64,
    next_stdout_sequence: u64,
    next_stderr_sequence: u64,
    pending_loss: Option<OutputLoss>,
    stats: OutputStats,
}

impl Default for PublisherState {
    fn default() -> Self {
        Self {
            next_global_sequence: 1,
            next_stdout_sequence: 1,
            next_stderr_sequence: 1,
            pending_loss: None,
            stats: OutputStats::default(),
        }
    }
}

pub(crate) struct OutputPublisher {
    sender: mpsc::Sender<OutputEvent>,
    state: Arc<Mutex<PublisherState>>,
}

impl Clone for OutputPublisher {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

impl OutputPublisher {
    pub(crate) fn publish(&self, stream: OutputStream, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let global_sequence = state.next_global_sequence;
        state.next_global_sequence = state
            .next_global_sequence
            .checked_add(1)
            .ok_or(RuntimeError::OutputSequenceExhausted)?;
        let stream_sequence = match stream {
            OutputStream::Stdout => {
                let sequence = state.next_stdout_sequence;
                state.next_stdout_sequence = state
                    .next_stdout_sequence
                    .checked_add(1)
                    .ok_or(RuntimeError::OutputSequenceExhausted)?;
                sequence
            }
            OutputStream::Stderr => {
                let sequence = state.next_stderr_sequence;
                state.next_stderr_sequence = state
                    .next_stderr_sequence
                    .checked_add(1)
                    .ok_or(RuntimeError::OutputSequenceExhausted)?;
                sequence
            }
        };
        let event = OutputEvent::Data {
            stream,
            global_sequence,
            stream_sequence,
            bytes,
            dropped_before: state.pending_loss.clone(),
        };

        match self.sender.try_send(event) {
            Ok(()) => {
                state.pending_loss = None;
                state.stats.delivered_events = state.stats.delivered_events.saturating_add(1);
            }
            Err(mpsc::error::TrySendError::Full(event))
            | Err(mpsc::error::TrySendError::Closed(event)) => {
                let OutputEvent::Data { bytes, .. } = event else {
                    unreachable!("publisher creates data events");
                };
                let mut loss = state.pending_loss.take().unwrap_or_default();
                loss.record(stream, global_sequence, bytes.len());
                state
                    .stats
                    .dropped
                    .record(stream, global_sequence, bytes.len());
                state.pending_loss = Some(loss);
            }
        }
        Ok(())
    }

    pub(crate) fn stats(&self) -> OutputStats {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .stats
            .clone()
    }
}

pub(crate) struct ChannelOutputSubscription {
    receiver: mpsc::Receiver<OutputEvent>,
    state: Arc<Mutex<PublisherState>>,
    final_loss_emitted: bool,
}

impl OutputSubscription for ChannelOutputSubscription {
    fn next<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Option<OutputEvent>, RuntimeError>> {
        Box::pin(async move {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => Err(RuntimeError::Cancelled),
                event = self.receiver.recv() => {
                    if let Some(event) = event {
                        return Ok(Some(event));
                    }
                    if self.final_loss_emitted {
                        return Ok(None);
                    }
                    self.final_loss_emitted = true;
                    let pending = self
                        .state
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .pending_loss
                        .take();
                    Ok(pending.map(|dropped| OutputEvent::Loss {
                        global_sequence: dropped.last_global_sequence,
                        dropped,
                    }))
                }
            }
        })
    }
}

pub(crate) fn output_channel(capacity: usize) -> (OutputPublisher, ChannelOutputSubscription) {
    let (sender, receiver) = mpsc::channel(capacity.max(1));
    let state = Arc::new(Mutex::new(PublisherState::default()));
    (
        OutputPublisher {
            sender,
            state: Arc::clone(&state),
        },
        ChannelOutputSubscription {
            receiver,
            state,
            final_loss_emitted: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use crate::{CancellationToken, OutputSubscription};

    use super::{OutputEvent, OutputStream, output_channel};

    #[tokio::test]
    async fn full_client_channel_reports_loss_without_blocking_publisher() {
        let (publisher, mut subscription) = output_channel(1);
        publisher
            .publish(OutputStream::Stdout, vec![1])
            .expect("first publish");
        publisher
            .publish(OutputStream::Stderr, vec![2])
            .expect("nonblocking drop");
        publisher
            .publish(OutputStream::Stdout, vec![3])
            .expect("nonblocking drop");
        drop(publisher);

        let cancellation = CancellationToken::new();
        assert!(matches!(
            subscription.next(&cancellation).await.expect("event"),
            Some(OutputEvent::Data {
                global_sequence: 1,
                ..
            })
        ));
        let Some(OutputEvent::Loss {
            global_sequence,
            dropped,
        }) = subscription.next(&cancellation).await.expect("loss")
        else {
            panic!("expected final loss event");
        };
        assert_eq!(global_sequence, 3);
        assert_eq!(dropped.dropped_events, 2);
        assert_eq!(dropped.stdout_events, 1);
        assert_eq!(dropped.stderr_events, 1);
        assert!(
            subscription
                .next(&cancellation)
                .await
                .expect("end")
                .is_none()
        );
    }
}
