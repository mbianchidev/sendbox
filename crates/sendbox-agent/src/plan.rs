use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};

use sendbox_boundary::{
    MountDeclaration, ResolvedRuntime, VerifiedBoundaryPlan, WorkloadIdentity, sha256_hex,
};
use sendbox_config::SandboxConfiguration;
use sendbox_core::{BoundaryPlanDigest, SessionId};
use sendbox_protocol::{Capability, CapabilitySet, agent_host_required_capabilities};
use sendbox_runtime::{
    ContainerId, ControlEndpointKind, RuntimeCapabilities, RuntimeCapability, RuntimeResources,
};
use sendbox_secrets::SecretName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AgentError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretReference(String);

impl SecretReference {
    pub fn new(value: impl Into<String>) -> Result<Self, AgentError> {
        let value = value.into();
        SecretName::new(value.clone()).map_err(|error| {
            AgentError::InvalidPlan(format!("invalid secret reference: {error}"))
        })?;
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
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestCommand {
    pub program: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
}

#[derive(Debug, Clone)]
pub struct AgentRequest {
    pub boundary_plan: VerifiedBoundaryPlan,
    pub session_id: SessionId,
    pub state_directory: PathBuf,
    pub image: String,
    pub guest_workspace: PathBuf,
    pub command: GuestCommand,
    pub environment: Vec<EnvironmentIntent>,
    pub mounts: Vec<MountIntent>,
    pub bootstrap_reference: SecretReference,
    pub readiness_timeout: Duration,
    /// Requests a pseudoterminal for the workload and host keystroke
    /// forwarding. Runtimes that cannot provide one are rejected during
    /// compilation, before anything is created or started.
    pub interactive: bool,
}

#[derive(Debug, Clone)]
pub struct RunPlan {
    verified_boundary_plan: VerifiedBoundaryPlan,
    resolved_runtime: ResolvedRuntime,
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
    package_report_maximum_bytes: Option<usize>,
    policy_digest: [u8; 32],
    interactive: bool,
    safe_outputs: bool,
}

impl RunPlan {
    pub fn compile(
        configuration: &SandboxConfiguration,
        request: AgentRequest,
        available: &RuntimeCapabilities,
        now_unix: u64,
    ) -> Result<Self, AgentError> {
        configuration
            .validate()
            .map_err(|error| AgentError::Configuration(error.to_string()))?;
        request
            .boundary_plan
            .reverify(now_unix)
            .map_err(|error| AgentError::InvalidPlan(error.to_string()))?;
        validate_request(configuration, &request)?;
        validate_boundary_equivalence(configuration, &request)?;
        let boundary = request.boundary_plan.plan().clone();
        let image = match &boundary.workload {
            WorkloadIdentity::OciImage { reference, .. } => reference.clone(),
            WorkloadIdentity::GuestBundle { .. } => {
                return Err(AgentError::InvalidPlan(
                    "persistent guest sessions require an OCI image workload".to_owned(),
                ));
            }
        };
        let endpoint_kind = select_endpoint(available)?;
        let transport_capability = endpoint_capability(endpoint_kind);
        let mut required_capabilities = vec![
            RuntimeCapability::Lifecycle,
            RuntimeCapability::TransportProvisioning,
            RuntimeCapability::BrokeredExec,
            transport_capability,
        ];
        if request.interactive {
            required_capabilities.push(RuntimeCapability::InteractiveTerminal);
        }
        let required_runtime_capabilities = RuntimeCapabilities::new(required_capabilities);
        let missing = required_runtime_capabilities.missing_from(available);
        if !missing.is_empty() {
            return Err(AgentError::RuntimeCapabilities(format_capabilities(
                &missing,
            )));
        }
        let secret_references = boundary
            .secrets
            .iter()
            .map(|reference| SecretReference::new(reference.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let policy_digest = Sha256::digest(
            serde_json::to_vec(&configuration.policy)
                .map_err(|error| AgentError::InvalidPlan(error.to_string()))?,
        )
        .into();
        let package_report_maximum_bytes = configuration
            .policy
            .packages
            .enabled
            .then(|| {
                usize::try_from(configuration.policy.packages.limits.max_report_bytes).map_err(
                    |_| {
                        AgentError::InvalidPlan(
                            "package report byte limit is out of range".to_owned(),
                        )
                    },
                )
            })
            .transpose()?;
        let mut required_guest_capabilities = agent_host_required_capabilities()
            .iter()
            .collect::<Vec<_>>();
        if package_report_maximum_bytes.is_some() {
            required_guest_capabilities.push(Capability::Audit);
        }
        let container_id = ContainerId::new(format!(
            "{}-{}",
            sanitize_identifier(&configuration.name),
            boundary.session_id
        ))
        .or_else(|_| ContainerId::new(format!("sendbox-{}", boundary.session_id)))
        .map_err(AgentError::Runtime)?;
        let safe_outputs = configuration.github.safe_outputs.enabled;
        Ok(Self {
            verified_boundary_plan: request.boundary_plan,
            resolved_runtime: boundary.selection.selected,
            session_id: boundary.session_id,
            container_id,
            state_directory: request.state_directory,
            image,
            workspace: WorkspaceIntent {
                host_path: boundary.workspace.source,
                guest_path: boundary.workspace.destination,
                writable: boundary.workspace.writable,
            },
            mounts: boundary
                .mounts
                .into_iter()
                .map(|mount| MountIntent {
                    source: mount.source,
                    destination: mount.destination,
                    writable: mount.writable,
                })
                .collect(),
            environment: request.environment,
            command: GuestCommand {
                program: boundary.command.program,
                arguments: boundary.command.arguments,
                working_directory: boundary.command.working_directory,
            },
            secret_references,
            bootstrap_reference: request.bootstrap_reference,
            endpoint_kind,
            readiness_timeout: request.readiness_timeout,
            resources: RuntimeResources {
                cpus: boundary.resources.cpus,
                memory_bytes: boundary.resources.memory_bytes,
            },
            required_runtime_capabilities,
            required_guest_capabilities: CapabilitySet::new(required_guest_capabilities),
            package_report_maximum_bytes,
            policy_digest,
            interactive: request.interactive,
            safe_outputs,
        })
    }

    /// Whether this plan requests a pseudoterminal for the workload.
    #[must_use]
    pub const fn interactive(&self) -> bool {
        self.interactive
    }

    #[must_use]
    pub const fn safe_outputs(&self) -> bool {
        self.safe_outputs
    }

    #[must_use]
    pub const fn boundary_plan_digest(&self) -> BoundaryPlanDigest {
        self.verified_boundary_plan.digest()
    }

    pub fn reverify_boundary(&self, now_unix: u64) -> Result<(), AgentError> {
        self.verified_boundary_plan
            .reverify(now_unix)
            .map_err(|error| AgentError::InvalidPlan(error.to_string()))
    }

    #[must_use]
    pub const fn resolved_runtime(&self) -> ResolvedRuntime {
        self.resolved_runtime
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
    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    #[must_use]
    pub const fn required_guest_capabilities(&self) -> &CapabilitySet {
        &self.required_guest_capabilities
    }

    #[must_use]
    pub const fn package_report_maximum_bytes(&self) -> Option<usize> {
        self.package_report_maximum_bytes
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
        if entry.sensitive {
            return Err(AgentError::InvalidPlan(format!(
                "sensitive environment entry `{}` must use a secret reference",
                entry.name
            )));
        }
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

fn validate_boundary_equivalence(
    configuration: &SandboxConfiguration,
    request: &AgentRequest,
) -> Result<(), AgentError> {
    let boundary = request.boundary_plan.plan();
    require_equal("session ID", &boundary.session_id, &request.session_id)?;
    require_equal(
        "configuration digest",
        &boundary.configuration_sha256,
        &sha256_hex(
            &serde_json::to_vec(configuration)
                .map_err(|error| AgentError::InvalidPlan(error.to_string()))?,
        ),
    )?;
    require_equal(
        "policy digest",
        &boundary.policy_sha256,
        &sha256_hex(
            &serde_json::to_vec(&configuration.policy)
                .map_err(|error| AgentError::InvalidPlan(error.to_string()))?,
        ),
    )?;
    let WorkloadIdentity::OciImage { reference, .. } = &boundary.workload else {
        return boundary_mismatch("persistent OCI workload");
    };
    require_equal("image reference", reference, &request.image)?;
    require_equal(
        "workspace source",
        &boundary.workspace.source,
        &configuration.project_path,
    )?;
    require_equal(
        "workspace destination",
        &boundary.workspace.destination,
        &request.guest_workspace,
    )?;
    require_equal(
        "workspace writable flag",
        &boundary.workspace.writable,
        &true,
    )?;
    require_equal(
        "command program",
        &boundary.command.program,
        &request.command.program,
    )?;
    require_equal(
        "command arguments",
        &boundary.command.arguments,
        &request.command.arguments,
    )?;
    require_equal(
        "command working directory",
        &boundary.command.working_directory,
        &request.command.working_directory,
    )?;

    let supplied_mounts = request
        .mounts
        .iter()
        .map(|mount| MountDeclaration {
            source: mount.source.clone(),
            destination: mount.destination.clone(),
            writable: mount.writable,
        })
        .collect::<Vec<_>>();
    require_equal("mounts", &boundary.mounts, &supplied_mounts)?;

    if boundary.environment.len() != request.environment.len() {
        return boundary_mismatch("environment");
    }
    for (declared, supplied) in boundary.environment.iter().zip(&request.environment) {
        require_equal("environment name", &declared.name, &supplied.name)?;
        require_equal(
            "environment value digest",
            &declared.value_sha256,
            &sha256_hex(supplied.value.as_bytes()),
        )?;
        require_equal(
            "environment sensitivity",
            &declared.sensitive,
            &supplied.sensitive,
        )?;
    }

    require_equal("secret names", &boundary.secrets, &configuration.secrets)?;
    let gateway_secrets = configuration
        .policy
        .boundaries
        .tool_calls
        .gateway_secret_names()
        .into_iter()
        .collect::<Vec<_>>();
    require_equal(
        "gateway secret names",
        &boundary.gateway_secrets,
        &gateway_secrets,
    )?;
    let cpus = u32::try_from(configuration.resources.cpus)
        .map_err(|_| AgentError::InvalidPlan("resource CPU count is out of range".to_owned()))?;
    let memory_bytes = u64::try_from(configuration.resources.memory_mb)
        .map_err(|_| AgentError::InvalidPlan("resource memory is out of range".to_owned()))?
        .checked_mul(1024 * 1024)
        .ok_or_else(|| AgentError::InvalidPlan("resource memory is out of range".to_owned()))?;
    require_equal("resource CPUs", &boundary.resources.cpus, &cpus)?;
    require_equal(
        "resource memory",
        &boundary.resources.memory_bytes,
        &memory_bytes,
    )?;
    Ok(())
}

fn require_equal<T>(field: &str, declared: &T, supplied: &T) -> Result<(), AgentError>
where
    T: PartialEq + ?Sized,
{
    if declared == supplied {
        Ok(())
    } else {
        boundary_mismatch(field)
    }
}

fn boundary_mismatch<T>(field: &str) -> Result<T, AgentError> {
    Err(AgentError::InvalidPlan(format!(
        "signed boundary plan does not match supplied {field}"
    )))
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
