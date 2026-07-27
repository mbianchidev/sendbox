use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};

use sendbox_config::SandboxConfiguration;
use sendbox_core::SessionId;
use sendbox_protocol::{Capability, CapabilitySet};
use sendbox_runtime::{
    ContainerId, ControlEndpointKind, RuntimeCapabilities, RuntimeCapability, RuntimeResources,
};
use serde::{Deserialize, Serialize};

use crate::AgentError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretReference(String);

impl SecretReference {
    pub fn new(value: impl Into<String>) -> Result<Self, AgentError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || value.as_bytes().contains(&0) {
            return Err(AgentError::InvalidPlan(
                "secret references must contain 1..=128 non-NUL bytes".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIntent {
    pub host_path: PathBuf,
    pub guest_path: PathBuf,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountIntent {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentIntent {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestCommand {
    pub program: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
}

#[derive(Debug, Clone)]
pub struct AgentRequest {
    pub session_id: SessionId,
    pub state_directory: PathBuf,
    pub image: String,
    pub guest_workspace: PathBuf,
    pub command: GuestCommand,
    pub environment: Vec<EnvironmentIntent>,
    pub mounts: Vec<MountIntent>,
    pub bootstrap_reference: SecretReference,
    pub readiness_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct RunPlan {
    session_id: SessionId,
    container_id: ContainerId,
    state_directory: PathBuf,
    image: String,
    workspace: WorkspaceIntent,
    mounts: Vec<MountIntent>,
    environment: Vec<EnvironmentIntent>,
    command: GuestCommand,
    secret_references: Vec<SecretReference>,
    bootstrap_reference: SecretReference,
    endpoint_kind: ControlEndpointKind,
    readiness_timeout: Duration,
    resources: RuntimeResources,
    required_runtime_capabilities: RuntimeCapabilities,
    required_guest_capabilities: CapabilitySet,
}

impl RunPlan {
    pub fn compile(
        configuration: &SandboxConfiguration,
        request: AgentRequest,
        available: &RuntimeCapabilities,
    ) -> Result<Self, AgentError> {
        configuration
            .validate()
            .map_err(|error| AgentError::Configuration(error.to_string()))?;
        validate_request(configuration, &request)?;
        let endpoint_kind = select_endpoint(available)?;
        let transport_capability = endpoint_capability(endpoint_kind);
        let required_runtime_capabilities = RuntimeCapabilities::new([
            RuntimeCapability::Lifecycle,
            RuntimeCapability::TransportProvisioning,
            RuntimeCapability::BrokeredExec,
            transport_capability,
        ]);
        let missing = required_runtime_capabilities.missing_from(available);
        if !missing.is_empty() {
            return Err(AgentError::RuntimeCapabilities(format_capabilities(
                &missing,
            )));
        }
        let secret_references = configuration
            .secrets
            .iter()
            .map(|reference| SecretReference::new(reference.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let container_id = ContainerId::new(format!(
            "{}-{}",
            sanitize_identifier(&configuration.name),
            request.session_id
        ))
        .or_else(|_| ContainerId::new(format!("sendbox-{}", request.session_id)))
        .map_err(AgentError::Runtime)?;
        Ok(Self {
            session_id: request.session_id,
            container_id,
            state_directory: request.state_directory,
            image: request.image,
            workspace: WorkspaceIntent {
                host_path: configuration.project_path.clone(),
                guest_path: request.guest_workspace,
                writable: true,
            },
            mounts: request.mounts,
            environment: request.environment,
            command: request.command,
            secret_references,
            bootstrap_reference: request.bootstrap_reference,
            endpoint_kind,
            readiness_timeout: request.readiness_timeout,
            resources: RuntimeResources {
                cpus: u32::try_from(configuration.resources.cpus).map_err(|_| {
                    AgentError::InvalidPlan("resource CPU count is out of range".to_owned())
                })?,
                memory_bytes: u64::try_from(configuration.resources.memory_mb)
                    .map_err(|_| {
                        AgentError::InvalidPlan("resource memory is out of range".to_owned())
                    })?
                    .checked_mul(1024 * 1024)
                    .ok_or_else(|| {
                        AgentError::InvalidPlan("resource memory is out of range".to_owned())
                    })?,
            },
            required_runtime_capabilities,
            required_guest_capabilities: CapabilitySet::from([
                Capability::Exec,
                Capability::StreamedIo,
                Capability::Health,
            ]),
        })
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub fn container_id(&self) -> &ContainerId {
        &self.container_id
    }

    #[must_use]
    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }

    #[must_use]
    pub const fn workspace(&self) -> &WorkspaceIntent {
        &self.workspace
    }

    #[must_use]
    pub fn mounts(&self) -> &[MountIntent] {
        &self.mounts
    }

    #[must_use]
    pub fn environment(&self) -> &[EnvironmentIntent] {
        &self.environment
    }

    #[must_use]
    pub const fn command(&self) -> &GuestCommand {
        &self.command
    }

    #[must_use]
    pub fn secret_references(&self) -> &[SecretReference] {
        &self.secret_references
    }

    #[must_use]
    pub const fn bootstrap_reference(&self) -> &SecretReference {
        &self.bootstrap_reference
    }

    #[must_use]
    pub const fn endpoint_kind(&self) -> ControlEndpointKind {
        self.endpoint_kind
    }

    #[must_use]
    pub const fn readiness_timeout(&self) -> Duration {
        self.readiness_timeout
    }

    #[must_use]
    pub const fn resources(&self) -> RuntimeResources {
        self.resources
    }

    #[must_use]
    pub const fn required_runtime_capabilities(&self) -> &RuntimeCapabilities {
        &self.required_runtime_capabilities
    }

    #[must_use]
    pub const fn required_guest_capabilities(&self) -> &CapabilitySet {
        &self.required_guest_capabilities
    }
}

fn validate_request(
    configuration: &SandboxConfiguration,
    request: &AgentRequest,
) -> Result<(), AgentError> {
    if request.image.trim().is_empty() {
        return Err(AgentError::InvalidPlan("image cannot be empty".to_owned()));
    }
    if !request.state_directory.is_absolute()
        || !request.guest_workspace.is_absolute()
        || !Path::new(&request.command.program).is_absolute()
        || !Path::new(&request.command.working_directory).is_absolute()
    {
        return Err(AgentError::InvalidPlan(
            "state, workspace, program, and working-directory paths must be absolute".to_owned(),
        ));
    }
    let mut names = BTreeSet::new();
    for entry in &request.environment {
        if entry.name.is_empty()
            || entry.name.contains('=')
            || entry.name.as_bytes().contains(&0)
            || entry.value.as_bytes().contains(&0)
            || !names.insert(entry.name.as_str())
        {
            return Err(AgentError::InvalidPlan(format!(
                "invalid or duplicate environment entry `{}`",
                entry.name
            )));
        }
    }
    if request
        .mounts
        .iter()
        .any(|mount| !mount.source.is_absolute() || !mount.destination.is_absolute())
    {
        return Err(AgentError::InvalidPlan(
            "mount paths must be absolute".to_owned(),
        ));
    }
    if configuration.project_path == request.guest_workspace {
        return Err(AgentError::InvalidPlan(
            "host and guest workspace paths must be distinct".to_owned(),
        ));
    }
    Ok(())
}

fn select_endpoint(available: &RuntimeCapabilities) -> Result<ControlEndpointKind, AgentError> {
    [
        (
            RuntimeCapability::RuntimeExecStdioControlChannel,
            ControlEndpointKind::RuntimeExecStdio,
        ),
        (
            RuntimeCapability::VsockControlChannel,
            ControlEndpointKind::Vsock,
        ),
        (
            RuntimeCapability::PublishedUnixControlChannel,
            ControlEndpointKind::PublishedUnixSocket,
        ),
        (
            RuntimeCapability::InheritedFileDescriptorControlChannel,
            ControlEndpointKind::InheritedFileDescriptor,
        ),
        (
            RuntimeCapability::InheritedStdioControlChannel,
            ControlEndpointKind::InheritedStdio,
        ),
    ]
    .into_iter()
    .find_map(|(capability, endpoint)| available.contains(capability).then_some(endpoint))
    .ok_or_else(|| {
        AgentError::RuntimeCapabilities("no supported host/guest control transport".to_owned())
    })
}

const fn endpoint_capability(endpoint: ControlEndpointKind) -> RuntimeCapability {
    match endpoint {
        ControlEndpointKind::Vsock => RuntimeCapability::VsockControlChannel,
        ControlEndpointKind::PublishedUnixSocket => RuntimeCapability::PublishedUnixControlChannel,
        ControlEndpointKind::InheritedStdio => RuntimeCapability::InheritedStdioControlChannel,
        ControlEndpointKind::InheritedFileDescriptor => {
            RuntimeCapability::InheritedFileDescriptorControlChannel
        }
        ControlEndpointKind::RuntimeExecStdio => RuntimeCapability::RuntimeExecStdioControlChannel,
        ControlEndpointKind::Unavailable => RuntimeCapability::TransportProvisioning,
    }
}

fn format_capabilities(capabilities: &RuntimeCapabilities) -> String {
    capabilities
        .iter()
        .map(|capability| format!("{capability:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sanitize_identifier(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect()
}
