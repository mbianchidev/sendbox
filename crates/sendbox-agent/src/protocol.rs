use sendbox_protocol::{
    AGENT_LAUNCH_OPERATION, BootstrapSecret, CapabilitySet, CloseCode, EnvironmentEntryV2,
    EventKind, FrameLimits, GracefulClose, HandshakeConfig, HostHandshake, LaunchRequestV2,
    Message, OPERATION_SCHEMA_VERSION, Request, ResponseStatus, SecretEnvelopeV2, TerminalResultV2,
    TerminalStateV1, VersionRange,
};
use sendbox_runtime::{CancellationToken, ControlStream, OutputStream};
use sendbox_secrets::{
    EnvelopeBinding, EnvelopeCipher, RecipientRole, SecretName, SecretValue, SessionKeyMaterial,
};

use std::{
    collections::BTreeSet,
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    AgentError, BoxFuture, GuestConnectionConfiguration, GuestConnector, GuestEvent,
    GuestExecution, GuestLaunchRequest, GuestSession, GuestTerminal,
};

const REQUEST_ID: u64 = 1;
const PROTOCOL_IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct ProtocolGuestConnector;

impl GuestConnector for ProtocolGuestConnector {
    fn connect<'a>(
        &'a self,
        stream: Box<dyn ControlStream>,
        configuration: GuestConnectionConfiguration,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestSession>, AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(AgentError::Cancelled);
            }
            let material = SessionKeyMaterial::new(configuration.bootstrap_secret.clone())
                .map_err(|error| AgentError::Guest(format!("prepare secret key: {error}")))?;
            let secret_cipher =
                EnvelopeCipher::new(&material, configuration.session_id).map_err(|error| {
                    AgentError::Guest(format!("derive secret envelope key: {error}"))
                })?;
            let handshake = HandshakeConfig::new(
                configuration.session_id,
                VersionRange::default(),
                configuration.capabilities,
                configuration.required_capabilities,
                FrameLimits::default(),
                BootstrapSecret::new(configuration.bootstrap_secret)?,
                configuration.boundary_plan_digest,
            )?;
            let mut host = HostHandshake::new(handshake);
            let connection = host.establish(stream).await?;
            let negotiated = connection.negotiated().capabilities.clone();
            let (mut reader, writer) = connection.into_parts();
            let readiness =
                protocol_io("receive guest readiness", cancellation, reader.receive()).await?;
            let Message::Event(readiness) = readiness else {
                return Err(AgentError::Guest(
                    "guest omitted authenticated operational readiness".to_owned(),
                ));
            };
            if readiness.kind != EventKind::Lifecycle {
                return Err(AgentError::Guest(
                    "guest readiness used an unexpected event kind".to_owned(),
                ));
            }
            validate_operational_readiness(&readiness.payload)?;
            Ok(Box::new(ProtocolGuestSession {
                negotiated,
                reader: Some(reader),
                writer: Some(writer),
                session_id: configuration.session_id,
                policy_digest: configuration.policy_digest,
                boundary_plan_digest: configuration.boundary_plan_digest,
                secret_cipher,
                next_secret_sequence: 1,
            }) as Box<dyn GuestSession>)
        })
    }
}

pub struct ProtocolGuestSession {
    negotiated: CapabilitySet,
    reader: Option<sendbox_protocol::FramedReader<tokio::io::ReadHalf<Box<dyn ControlStream>>>>,
    writer: Option<sendbox_protocol::FramedWriter<tokio::io::WriteHalf<Box<dyn ControlStream>>>>,
    session_id: sendbox_core::SessionId,
    policy_digest: [u8; 32],
    boundary_plan_digest: sendbox_core::BoundaryPlanDigest,
    secret_cipher: EnvelopeCipher,
    next_secret_sequence: u64,
}

impl GuestSession for ProtocolGuestSession {
    fn negotiated_capabilities(&self) -> &CapabilitySet {
        &self.negotiated
    }

    fn start<'a>(
        &'a mut self,
        request: GuestLaunchRequest<'a>,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestExecution>, AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(AgentError::Cancelled);
            }
            let secrets = seal_secrets(
                request.environment,
                request.secrets,
                self.session_id,
                self.policy_digest,
                self.boundary_plan_digest,
                &mut self.secret_cipher,
                &mut self.next_secret_sequence,
            )?;
            let payload = serde_json::to_vec(&LaunchRequestV2 {
                schema_version: OPERATION_SCHEMA_VERSION,
                boundary_plan_digest: self.boundary_plan_digest,
                program: request.command.program.clone(),
                arguments: request.command.arguments.clone(),
                working_directory: request.command.working_directory.clone(),
                environment: request
                    .environment
                    .iter()
                    .map(|entry| EnvironmentEntryV2 {
                        name: entry.name.clone(),
                        value: entry.value.clone(),
                    })
                    .collect(),
                secrets,
                timeout_ms: 300_000,
            })
            .map_err(|error| AgentError::Guest(format!("encode launch request: {error}")))?;
            let mut writer = self
                .writer
                .take()
                .ok_or_else(|| AgentError::Guest("guest session already started".to_owned()))?;
            protocol_io(
                "send guest launch request",
                cancellation,
                writer.send(&Message::Request(Request {
                    request_id: REQUEST_ID,
                    operation: AGENT_LAUNCH_OPERATION.to_owned(),
                    payload,
                })),
            )
            .await?;
            let reader = self
                .reader
                .take()
                .ok_or_else(|| AgentError::Guest("guest session reader unavailable".to_owned()))?;
            Ok(Box::new(ProtocolGuestExecution {
                reader,
                writer,
                terminal: false,
                cancelled: false,
            }) as Box<dyn GuestExecution>)
        })
    }

    fn cleanup<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            if let Some(writer) = self.writer.as_mut() {
                protocol_io(
                    "send guest graceful close",
                    cancellation,
                    writer.send(&Message::GracefulClose(GracefulClose {
                        code: CloseCode::Shutdown,
                        reason: "agent cleanup".to_owned(),
                    })),
                )
                .await?;
            }
            Ok(())
        })
    }
}

fn seal_secrets(
    environment: &[crate::EnvironmentIntent],
    secrets: Vec<crate::GuestSecretEnvelope<'_>>,
    session_id: sendbox_core::SessionId,
    policy_digest: [u8; 32],
    boundary_plan_digest: sendbox_core::BoundaryPlanDigest,
    cipher: &mut EnvelopeCipher,
    next_sequence: &mut u64,
) -> Result<Vec<SecretEnvelopeV2>, AgentError> {
    let mut names = environment
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<BTreeSet<_>>();
    let now = unix_time_ms()?;
    let expires_at_unix_ms = now
        .checked_add(5 * 60 * 1_000)
        .ok_or_else(|| AgentError::Guest("secret envelope expiry overflowed".to_owned()))?;
    secrets
        .into_iter()
        .map(|secret| {
            if !names.insert(secret.reference.to_owned()) {
                return Err(AgentError::Guest(format!(
                    "duplicate environment or secret name {}",
                    secret.reference
                )));
            }
            let name = SecretName::new(secret.reference.to_owned())
                .map_err(|error| AgentError::Guest(format!("invalid secret name: {error}")))?;
            let value = SecretValue::new(secret.envelope.to_vec())
                .map_err(|error| AgentError::Guest(format!("invalid secret value: {error}")))?;
            let sequence = *next_sequence;
            *next_sequence = (*next_sequence).checked_add(1).ok_or_else(|| {
                AgentError::Guest("secret envelope sequence overflowed".to_owned())
            })?;
            let binding = EnvelopeBinding {
                session_id,
                recipient: RecipientRole::Guest,
                secret_name: name,
                sequence,
                expires_at_unix_ms,
                policy_digest,
                boundary_plan_digest,
            };
            let envelope = cipher
                .seal(&binding, &value)
                .map_err(|error| AgentError::Guest(format!("seal secret envelope: {error}")))?;
            Ok(SecretEnvelopeV2 {
                reference: secret.reference.to_owned(),
                sequence,
                expires_at_unix_ms,
                policy_digest,
                boundary_plan_digest,
                envelope,
            })
        })
        .collect()
}

fn unix_time_ms() -> Result<u64, AgentError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AgentError::Guest(format!("read system time: {error}")))?
        .as_millis()
        .try_into()
        .map_err(|_| AgentError::Guest("system time is out of range".to_owned()))
}

pub struct ProtocolGuestExecution {
    reader: sendbox_protocol::FramedReader<tokio::io::ReadHalf<Box<dyn ControlStream>>>,
    writer: sendbox_protocol::FramedWriter<tokio::io::WriteHalf<Box<dyn ControlStream>>>,
    terminal: bool,
    cancelled: bool,
}

impl GuestExecution for ProtocolGuestExecution {
    fn next_event<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<GuestEvent, AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(AgentError::Cancelled);
            }
            if self.terminal {
                return Err(AgentError::Guest(
                    "event requested after terminal response".to_owned(),
                ));
            }
            let message = self.reader.receive().await?;
            match message {
                Message::Event(event) => match event.kind {
                    sendbox_protocol::EventKind::StandardOutput => Ok(GuestEvent::Output {
                        stream: OutputStream::Stdout,
                        bytes: event.payload,
                    }),
                    sendbox_protocol::EventKind::StandardError => Ok(GuestEvent::Output {
                        stream: OutputStream::Stderr,
                        bytes: event.payload,
                    }),
                    kind => Err(AgentError::Guest(format!(
                        "unexpected guest event kind {kind:?}"
                    ))),
                },
                Message::Response(response) if response.request_id == REQUEST_ID => {
                    self.terminal = true;
                    if response.status == ResponseStatus::Ok {
                        let terminal: TerminalResultV2 = serde_json::from_slice(&response.payload)
                            .map_err(|error| {
                                AgentError::Guest(format!("decode terminal response: {error}"))
                            })?;
                        Ok(GuestEvent::Terminal(map_terminal(terminal)))
                    } else {
                        Err(AgentError::Guest(format!(
                            "guest rejected launch with status {:?}",
                            response.status
                        )))
                    }
                }

                Message::ProtocolError(error) => Err(AgentError::Guest(format!(
                    "guest protocol error {:?}: {}",
                    error.code, error.detail
                ))),
                other => Err(AgentError::Guest(format!(
                    "unexpected guest message {:?}",
                    other.kind()
                ))),
            }
        })
    }

    fn cancel<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        Box::pin(async move {
            if self.cancelled {
                return Ok(());
            }
            if self.terminal {
                let _ = protocol_io(
                    "close completed guest execution",
                    cancellation,
                    self.writer.send(&Message::GracefulClose(GracefulClose {
                        code: CloseCode::Normal,
                        reason: "execution complete".to_owned(),
                    })),
                )
                .await;
                self.cancelled = true;
                return Ok(());
            }
            protocol_io(
                "send guest cancellation",
                cancellation,
                self.writer
                    .send(&Message::Cancellation(sendbox_protocol::Cancellation {
                        request_id: REQUEST_ID,
                        reason: Some("agent cancellation".to_owned()),
                    })),
            )
            .await?;
            self.cancelled = true;
            Ok(())
        })
    }
}

fn validate_operational_readiness(payload: &[u8]) -> Result<(), AgentError> {
    let readiness: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|error| AgentError::Guest(format!("decode guest readiness: {error}")))?;
    let state_ready = readiness
        .get("state")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|state| state.eq_ignore_ascii_case("ready"));
    let broker_live = readiness
        .get("services")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| {
                service.get("id").and_then(serde_json::Value::as_str) == Some("exec")
                    && service
                        .get("mandatory")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                    && service.get("healthy").and_then(serde_json::Value::as_bool) == Some(true)
            })
        });
    if state_ready && broker_live {
        Ok(())
    } else {
        Err(AgentError::Guest(
            "guest readiness did not prove a live mandatory execution broker".to_owned(),
        ))
    }
}

fn map_terminal(result: TerminalResultV2) -> GuestTerminal {
    match result.terminal {
        TerminalStateV1::Exited {
            exit_code: Some(code),
            signal: None,
        } if result.cleanup_complete => GuestTerminal::Exited { code },
        TerminalStateV1::Exited {
            exit_code: _,
            signal: Some(signal),
        } if result.cleanup_complete => GuestTerminal::Signaled { signal },
        TerminalStateV1::Cancelled => GuestTerminal::Cancelled,
        terminal => GuestTerminal::Failed {
            message: format!(
                "broker terminal {terminal:?} (cleanup_complete={})",
                result.cleanup_complete
            ),
        },
    }
}

async fn protocol_io<T>(
    operation: &'static str,
    cancellation: &CancellationToken,
    future: impl Future<Output = Result<T, sendbox_protocol::ProtocolError>>,
) -> Result<T, AgentError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(AgentError::Cancelled),
        result = tokio::time::timeout(PROTOCOL_IO_TIMEOUT, future) => {
            result
                .map_err(|_| AgentError::Guest(format!("{operation} timed out")))?
                .map_err(AgentError::Protocol)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_signal_terminal_is_preserved() {
        assert_eq!(
            map_terminal(TerminalResultV2 {
                schema_version: OPERATION_SCHEMA_VERSION,
                terminal: TerminalStateV1::Exited {
                    exit_code: None,
                    signal: Some(15),
                },
                cleanup_complete: true,
            }),
            GuestTerminal::Signaled { signal: 15 }
        );
    }
}
