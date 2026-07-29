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

#[derive(Serialize)]
pub struct GuestSecretEnvelope<'a> {
    pub reference: &'a str,
    pub envelope: &'a [u8],
}

impl fmt::Debug for GuestSecretEnvelope<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestSecretEnvelope")
            .field("reference", &self.reference)
            .field("envelope", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize)]
pub struct GuestLaunchRequest<'a> {
    pub command: &'a GuestCommand,
    pub environment: &'a [EnvironmentIntent],
    pub secrets: Vec<GuestSecretEnvelope<'a>>,
    /// Present only for interactive runs; selects the interactive launch
    /// operation and the workload's initial terminal size.
    pub terminal: Option<GuestTerminalSize>,
}

/// Initial terminal geometry and type for an interactive launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestTerminalSize {
    pub columns: u16,
    pub rows: u16,
    pub term: String,
    pub separate_stderr: bool,
}

impl fmt::Debug for GuestLaunchRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestLaunchRequest")
            .field("command", &self.command.program)
            .field("environment_entries", &self.environment.len())
            .field("secret_envelopes", &self.secrets.len())
            .field("terminal", &self.terminal)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestTerminal {
    Exited { code: i32 },
    Signaled { signal: i32 },
    Cancelled,
    Failed { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestEvent {
    Output {
        stream: OutputStream,
        bytes: Vec<u8>,
    },
    TerminalInputCredit {
        credits: u16,
    },
    Terminal(GuestTerminal),
}

#[derive(Clone, PartialEq, Eq)]
pub struct GuestPackageReport {
    pub json: Vec<u8>,
    pub sha256: String,
}

impl fmt::Debug for GuestPackageReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestPackageReport")
            .field("json_bytes", &self.json.len())
            .field("sha256", &self.sha256)
            .finish()
    }
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
    pub boundary_plan_digest: sendbox_core::BoundaryPlanDigest,
    pub capabilities: CapabilitySet,
    pub required_capabilities: CapabilitySet,
    pub bootstrap_secret: Vec<u8>,
    pub policy_digest: [u8; 32],
}

impl fmt::Debug for GuestConnectionConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestConnectionConfiguration")
            .field("session_id", &self.session_id)
            .field("boundary_plan_digest", &self.boundary_plan_digest)
            .field("capabilities", &self.capabilities)
            .field("required_capabilities", &self.required_capabilities)
            .field("bootstrap_secret", &"[REDACTED]")
            .field("policy_digest", &self.policy_digest)
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

    fn fetch_package_report<'a>(
        &'a mut self,
        maximum_bytes: usize,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<GuestPackageReport, AgentError>> {
        let _ = (maximum_bytes, cancellation);
        Box::pin(async {
            Err(AgentError::Guest(
                "this execution does not support package report retrieval".to_owned(),
            ))
        })
    }

    /// Forwards one host terminal command to the guest.
    ///
    /// The default rejects the command, so a transport that never negotiated
    /// an interactive launch fails loudly instead of silently discarding
    /// keystrokes.
    fn send_terminal<'a>(
        &'a mut self,
        command: HostTerminalCommand,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), AgentError>> {
        let _ = (command, cancellation);
        Box::pin(async {
            Err(AgentError::Guest(
                "this execution does not accept terminal input".to_owned(),
            ))
        })
    }
}

/// One host-originated terminal command.
///
/// Input bytes may contain pasted credentials, so [`fmt::Debug`] reports only
/// a length.
#[derive(Clone, PartialEq, Eq)]
pub enum HostTerminalCommand {
    Input(Vec<u8>),
    InputEof,
    Resize { columns: u16, rows: u16 },
}

impl fmt::Debug for HostTerminalCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(bytes) => formatter
                .debug_tuple("Input")
                .field(&format_args!("<{} bytes>", bytes.len()))
                .finish(),
            Self::InputEof => formatter.write_str("InputEof"),
            Self::Resize { columns, rows } => formatter
                .debug_struct("Resize")
                .field("columns", columns)
                .field("rows", rows)
                .finish(),
        }
    }
}

/// Source of host terminal commands for an interactive run.
pub trait TerminalSource: Send + Sync {
    fn next_command<'a>(&'a self) -> BoxFuture<'a, Option<HostTerminalCommand>>;

    fn grant_input_credit(&self, _credits: u16) -> Result<(), AgentError> {
        Ok(())
    }
}

/// Terminal source for headless runs, which never produce commands.
#[derive(Debug, Default)]
pub struct NoTerminal;

impl TerminalSource for NoTerminal {
    fn next_command<'a>(&'a self) -> BoxFuture<'a, Option<HostTerminalCommand>> {
        Box::pin(std::future::pending())
    }
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
