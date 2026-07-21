use sendbox_protocol::{
    BootstrapSecret, CapabilitySet, CloseCode, FrameLimits, GracefulClose, HandshakeConfig,
    HostHandshake, Message, Request, ResponseStatus, VersionRange,
};
use sendbox_runtime::{CancellationToken, ControlStream, OutputStream};

use std::{future::Future, time::Duration};

use crate::{
    AgentError, BoxFuture, GuestConnectionConfiguration, GuestConnector, GuestEvent,
    GuestExecution, GuestLaunchRequest, GuestSession,
};

const LAUNCH_OPERATION: &str = "agent.launch";
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
            let handshake = HandshakeConfig::new(
                configuration.session_id,
                VersionRange::default(),
                configuration.capabilities,
                configuration.required_capabilities,
                FrameLimits::default(),
                BootstrapSecret::new(configuration.bootstrap_secret)?,
            )?;
            let mut host = HostHandshake::new(handshake);
            let connection = host.establish(stream).await?;
            let negotiated = connection.negotiated().capabilities.clone();
            let (reader, writer) = connection.into_parts();
            Ok(Box::new(ProtocolGuestSession {
                negotiated,
                reader: Some(reader),
                writer: Some(writer),
            }) as Box<dyn GuestSession>)
        })
    }
}

pub struct ProtocolGuestSession {
    negotiated: CapabilitySet,
    reader: Option<sendbox_protocol::FramedReader<tokio::io::ReadHalf<Box<dyn ControlStream>>>>,
    writer: Option<sendbox_protocol::FramedWriter<tokio::io::WriteHalf<Box<dyn ControlStream>>>>,
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
            let payload = serde_json::to_vec(&request)
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
                    operation: LAUNCH_OPERATION.to_owned(),
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
                        serde_json::from_slice(&response.payload)
                            .map(GuestEvent::Terminal)
                            .map_err(|error| {
                                AgentError::Guest(format!("decode terminal response: {error}"))
                            })
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
            if self.cancelled || self.terminal {
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
