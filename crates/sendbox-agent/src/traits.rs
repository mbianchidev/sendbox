use std::{fmt, future::Future, pin::Pin};

use sendbox_protocol::CapabilitySet;
use sendbox_runtime::{CancellationToken, ControlStream, OutputStream};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{AgentError, EnvironmentIntent, GuestCommand, SecretReference};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub struct SecretEnvelope {
    reference: SecretReference,
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretEnvelope {
    #[must_use]
    pub fn new(reference: SecretReference, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            reference,
            bytes: Zeroizing::new(bytes.into()),
        }
    }

    #[must_use]
    pub const fn reference(&self) -> &SecretReference {
        &self.reference
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl fmt::Debug for SecretEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEnvelope")
            .field("reference", &self.reference)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

pub trait SecretResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        reference: &'a SecretReference,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<SecretEnvelope, AgentError>>;
}

#[derive(Debug, Serialize)]
pub struct GuestSecretEnvelope<'a> {
    pub reference: &'a str,
    pub envelope: &'a [u8],
}

#[derive(Debug, Serialize)]
pub struct GuestLaunchRequest<'a> {
    pub command: &'a GuestCommand,
    pub environment: &'a [EnvironmentIntent],
    pub secrets: Vec<GuestSecretEnvelope<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestTerminal {
    Exited { code: i32 },
    Cancelled,
    Failed { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestEvent {
    Output {
        stream: OutputStream,
        bytes: Vec<u8>,
    },
    Terminal(GuestTerminal),
}

pub trait GuestConnector: Send + Sync {
    fn connect<'a>(
        &'a self,
        stream: Box<dyn ControlStream>,
        configuration: GuestConnectionConfiguration,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestSession>, AgentError>>;
}

pub struct GuestConnectionConfiguration {
    pub session_id: sendbox_core::SessionId,
    pub capabilities: CapabilitySet,
    pub required_capabilities: CapabilitySet,
    pub bootstrap_secret: Vec<u8>,
}

impl fmt::Debug for GuestConnectionConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestConnectionConfiguration")
            .field("session_id", &self.session_id)
            .field("capabilities", &self.capabilities)
            .field("required_capabilities", &self.required_capabilities)
            .field("bootstrap_secret", &"[REDACTED]")
            .finish()
    }
}

pub trait GuestSession: Send {
    fn negotiated_capabilities(&self) -> &CapabilitySet;

    fn start<'a>(
        &'a mut self,
        request: GuestLaunchRequest<'a>,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn GuestExecution>, AgentError>>;

    fn cleanup<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>>;
}

pub trait GuestExecution: Send {
    fn next_event<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<GuestEvent, AgentError>>;

    fn cancel<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>>;
}

pub trait OutputSink: Send + Sync {
    fn write<'a>(
        &'a self,
        stream: OutputStream,
        bytes: &'a [u8],
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSignal {
    Interrupt,
    Terminate,
}

pub trait SignalSource: Send + Sync {
    fn next_signal<'a>(&'a self) -> BoxFuture<'a, Option<AgentSignal>>;
}

#[derive(Debug, Default)]
pub struct NoSignals;

impl SignalSource for NoSignals {
    fn next_signal<'a>(&'a self) -> BoxFuture<'a, Option<AgentSignal>> {
        Box::pin(std::future::pending())
    }
}
