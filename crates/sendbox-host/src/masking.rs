use std::sync::Arc;

use sendbox_agent::{AgentError, BoxFuture, OutputSink};
use sendbox_runtime::{CancellationToken, OutputStream};
use sendbox_secrets::{CredentialMasker, CredentialMaskingStream};
use tokio::sync::Mutex;

pub(crate) fn mask_error(masker: &CredentialMasker, error: crate::HostError) -> crate::HostError {
    let cancelled = error.is_cancelled();
    let kind = error.kind();
    let original = error.to_string();
    let debug = format!("{error:?}");
    let debug_masked = masker.mask(debug.as_bytes());
    match masker.mask(original.as_bytes()) {
        Ok(bytes)
            if bytes == original.as_bytes()
                && debug_masked
                    .as_ref()
                    .is_ok_and(|masked| masked == debug.as_bytes()) =>
        {
            error
        }
        Ok(bytes) => crate::HostError::CredentialMasked {
            message: String::from_utf8_lossy(&bytes).into_owned(),
            kind,
            cancelled,
        },
        Err(masking_error) => crate::HostError::CredentialMasked {
            message: format!("{masking_error}; original diagnostic withheld"),
            kind,
            cancelled,
        },
    }
}

pub(crate) fn mask_report(
    masker: &CredentialMasker,
    mut report: crate::HostRunReport,
) -> Result<crate::HostRunReport, crate::HostError> {
    match &mut report {
        crate::HostRunReport::Persistent(report) => {
            if let sendbox_agent::GuestTerminal::Failed { message } = &mut report.agent.terminal {
                let masked = masker.mask(message.as_bytes())?;
                *message = String::from_utf8_lossy(&masked).into_owned();
            }
        }
        crate::HostRunReport::OneShot(outcome) => {
            for capture in [&mut outcome.stdout, &mut outcome.stderr] {
                let original = zeroize::Zeroizing::new(std::mem::take(&mut capture.bytes));
                capture.bytes = masker.mask(&original)?;
            }
        }
    }
    Ok(report)
}

struct Streams {
    stdout: CredentialMaskingStream,
    stderr: CredentialMaskingStream,
}

pub(crate) struct MaskingOutputSink {
    destination: Arc<dyn OutputSink>,
    streams: Mutex<Streams>,
}

impl MaskingOutputSink {
    pub(crate) fn new(masker: CredentialMasker, destination: Arc<dyn OutputSink>) -> Self {
        Self {
            destination,
            streams: Mutex::new(Streams {
                stdout: masker.stream(),
                stderr: masker.stream(),
            }),
        }
    }

    pub(crate) async fn finish(&self, cancellation: &CancellationToken) -> Result<(), AgentError> {
        let mut streams = self.streams.lock().await;
        for stream in [OutputStream::Stdout, OutputStream::Stderr] {
            let source = match stream {
                OutputStream::Stdout => &mut streams.stdout,
                OutputStream::Stderr => &mut streams.stderr,
            };
            let bytes = source
                .finish()
                .map_err(|error| AgentError::Output(error.to_string()))?;
            if !bytes.is_empty() {
                self.destination.write(stream, &bytes, cancellation).await?;
            }
        }
        Ok(())
    }
}

impl OutputSink for MaskingOutputSink {
    fn write<'a>(
        &'a self,
        stream: OutputStream,
        bytes: &'a [u8],
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async move {
            let mut streams = self.streams.lock().await;
            let source = match stream {
                OutputStream::Stdout => &mut streams.stdout,
                OutputStream::Stderr => &mut streams.stderr,
            };
            let masked = source
                .push(bytes)
                .map_err(|error| AgentError::Output(error.to_string()))?;
            if !masked.is_empty() {
                self.destination
                    .write(stream, &masked, cancellation)
                    .await?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostError, HostRunReport};
    use sendbox_agent::{CleanupFailure, RunFailure};

    #[test]
    fn persistent_terminal_failures_expose_only_the_masked_diagnostic() {
        let masker = CredentialMasker::default();
        masker.register(b"synthetic-terminal-credential").unwrap();
        let report = HostRunReport::Persistent(crate::PersistentHostRunReport {
            session_id: sendbox_core::SessionId::from_bytes([0x45; 16]),
            agent: sendbox_agent::AgentReport {
                terminal: sendbox_agent::GuestTerminal::Failed {
                    message: "synthetic launch failure: synthetic-terminal-credential".to_owned(),
                },
                states: Vec::new(),
                safe_outputs: None,
                package_report: None,
                syscall_report: None,
                network_report: None,
            },
            package_report: None,
            syscall_report: None,
            network_report: None,
        });
        let masked = mask_report(&masker, report).unwrap();
        assert_eq!(
            masked.failure_message(),
            Some("synthetic launch failure: [REDACTED]")
        );
        assert!(!format!("{masked:?}").contains("synthetic-terminal-credential"));
    }

    #[test]
    fn successful_reports_do_not_invent_a_failure_diagnostic() {
        let report = HostRunReport::OneShot(sendbox_runtime::ProcessOutcome::successful(
            Vec::new(),
            Vec::new(),
        ));
        assert_eq!(report.failure_message(), None);
    }

    #[test]
    fn diagnostics_preserve_kind_and_cancellation_without_debug_leaks() {
        let masker = CredentialMasker::default();
        masker.register(b"synthetic-opaque-value").unwrap();
        let original = HostError::OutputFinalization {
            runtime: Box::new(HostError::AgentRun(RunFailure {
                primary: AgentError::Cancelled,
                cleanup: vec![CleanupFailure {
                    step: "synthetic cleanup",
                    error: AgentError::Output("synthetic-opaque-value".to_owned()),
                }],
            })),
            output: AgentError::Output("synthetic-opaque-value".to_owned()),
        };
        let masked = mask_error(&masker, original);
        assert!(masked.is_cancelled());
        assert_eq!(masked.kind(), "agent_run");
        assert!(!masked.to_string().contains("synthetic-opaque-value"));
        assert!(!format!("{masked:?}").contains("synthetic-opaque-value"));
    }

    #[test]
    fn captured_results_mask_bytes_but_preserve_original_output_accounting() {
        let masker = CredentialMasker::default();
        masker.register(b"synthetic-opaque-value").unwrap();
        let report = HostRunReport::OneShot(sendbox_runtime::ProcessOutcome::successful(
            b"before synthetic-opaque-value after".to_vec(),
            b"synthetic-opaque-value".to_vec(),
        ));
        let HostRunReport::OneShot(masked) = mask_report(&masker, report).unwrap() else {
            panic!("wrong report kind");
        };
        assert_eq!(masked.stdout.bytes, b"before [REDACTED] after");
        assert_eq!(masked.stderr.bytes, b"[REDACTED]");
        assert_eq!(masked.stdout.total_bytes, 35);
        assert_eq!(masked.stderr.total_bytes, 22);
    }
}
