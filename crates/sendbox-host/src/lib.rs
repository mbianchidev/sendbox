#![forbid(unsafe_code)]

mod security;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sendbox_agent::{
    AgentOrchestrator, AgentReport, AgentRequest, BoxFuture, EnvironmentIntent, GuestCommand,
    GuestTerminal, GuestTerminalSize, OutputSink, ProtocolGuestConnector, RunFailure, RunPlan,
    SecretEnvelope, SecretReference, SecretResolver, SignalSource, TerminalSource,
};
use sendbox_bootstrap::{
    DEFAULT_REGISTRY_CACHE_ROOT, DEFAULT_REGISTRY_GID, DEFAULT_REGISTRY_UID, RegistryCredential,
    RegistryProxyConfiguration,
};
use sendbox_boundary::{
    Architecture, ArtifactIdentity, ArtifactKind, BOUNDARY_PLAN_FORMAT, BOUNDARY_PLAN_VERSION,
    BoundaryError, BoundaryPlan, CommandDeclaration, ControlTransport, EnvironmentDeclaration,
    FeatureAdmission, FeatureDecision, HostPlatform, MountDeclaration, OperatingSystem,
    ProviderDeclaration, ResolvedRuntime, ResourceDeclaration, SignedBoundaryPlan,
    TrustDeclaration, VerifiedBoundaryPlan, WorkloadIdentity, select_runtime, sha256_hex,
};
use sendbox_bundle::{Architecture as BundleArchitecture, VerifyOptions, verify_bundle};
use sendbox_config::{
    InspectionTransport, RuntimeProvider as ConfiguredRuntime, SandboxConfiguration,
};
use sendbox_core::{SessionId, VERSION};
use sendbox_credentials::{
    CredentialBrokerError, GhMetadataClient, GhProcessConfiguration, GitHubSessionCredentials,
    RepositoryIdentity as CredentialRepositoryIdentity, authorize_github,
};
use sendbox_egress::runtime::{
    DEFAULT_REGISTRY_PROXY_PORT, DEFAULT_TRUSTED_REGISTRY_PORT,
    RuntimePolicyDocument as EgressRuntimePolicyDocument, requires_enforcement,
};
use sendbox_exec::{AdmissionDisposition, CompiledCommandPolicy};
use sendbox_git::{
    BranchPolicyConfiguration, EnvironmentPolicy, GITHUB_TOKEN_ENVIRONMENT, GitProcessRunner,
    GuardError, GuardLimits, GuardPolicyDocument, PolicySchemaVersion, ProcessRequest,
    RepositoryIdentity, SSH_KEY_ENVIRONMENT, SystemGitProcessRunner, TrustedGitBinary,
    discover_repository_identity,
};
use sendbox_mcp::config::{NATIVE_BROKER_PATH, PROJECT_CONFIG_PATHS};
use sendbox_mcp::runtime::{
    RUNTIME_POLICY_SCHEMA_VERSION, RuntimeObservationConfiguration, RuntimePolicyDocument,
};
use sendbox_runtime::{
    BootstrapMaterial, CancellationToken, CommandArgument, CommandSpec, ContainerId, CreateRequest,
    InitializeRequest, OutputStream, ProcessOptions, ProcessOutcome, Program, RuntimeError,
    RuntimeProvider, RuntimeResources, RuntimeSignal, StartRequest, StopRequest,
};
use sendbox_runtime_apple::{
    APPLE_RUNTIME_ID, AppleRuntime, AppleRuntimeConfiguration, resolve_container_executable,
};
use sendbox_runtime_hyperlight::{
    AuthenticatedLaunchRequest, HyperlightConfiguration, HyperlightMount,
    HyperlightNetworkConfiguration, HyperlightRuntime,
};
use sendbox_runtime_kata::{KataProviderConfiguration, KataRuntimeProvider};
use sendbox_secrets::{SecretName, SecretStore, SecretValue, requires_guarded_github_forwarding};
use sendbox_security::{SecurityError, provenance::SigningKeyMaterial};
use sendbox_session_security::SessionSecurityError;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const PLAN_VALIDITY: Duration = Duration::from_secs(60 * 60);
/// Name injected into the guest environment. Current GitHub Copilot CLI
/// releases read `COPILOT_GITHUB_TOKEN`; the legacy `GITHUB_COPILOT_TOKEN`
/// name is never exposed inside the guest.
const COPILOT_GUEST_TOKEN_ENVIRONMENT: &str = "COPILOT_GITHUB_TOKEN";
/// Host variables consulted for independent Copilot forwarding, in precedence
/// order. Only a missing variable falls through to the next candidate; a
/// present-but-empty variable is a hard error. Repository-scoped GitHub
/// credentials (`GH_TOKEN`/`GITHUB_TOKEN`) are deliberately excluded so that
/// Copilot authentication stays independent of `github.forward_auth`.
const COPILOT_HOST_TOKEN_ENVIRONMENTS: &[&str] =
    &[COPILOT_GUEST_TOKEN_ENVIRONMENT, "GITHUB_COPILOT_TOKEN"];
const MCP_PROXY_ENVIRONMENT: &str = "SENDBOX_MCP_PROXY";
const MAX_EXECUTION_ENVIRONMENT_ENTRY_BYTES: usize = 4 * 1024;
const MAX_EXECUTION_ENVIRONMENT_BYTES: usize = 16 * 1024;
const PACKAGE_REPORT_FILE: &str = "package-security-report.json";
#[cfg(target_os = "linux")]
const SECRET_SERVICE: &str = "sendbox";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedRuntime {
    Auto,
    Apple,
    Kata,
    Hyperlight,
}

#[derive(Debug)]
pub struct HostRunRequest {
    pub requested_runtime: RequestedRuntime,
    pub configuration: SandboxConfiguration,
    pub image: Option<String>,
    pub bundle_root: PathBuf,
    pub trust_root: PathBuf,
    pub trust_root_id: String,
    pub minimum_release_sequence: u64,
    pub command: Vec<String>,
    pub state_root: PathBuf,
    pub readiness_timeout: Duration,
    /// Requests a pseudoterminal for the workload with this initial geometry.
    pub terminal: Option<GuestTerminalSize>,
}

#[derive(Debug)]
pub enum HostRunReport {
    Persistent(AgentReport),
    OneShot(ProcessOutcome),
}

impl HostRunReport {
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Persistent(report) => match &report.terminal {
                GuestTerminal::Exited { code } => *code,
                GuestTerminal::Signaled { signal } => 128_i32.saturating_add(*signal),
                GuestTerminal::Cancelled => 130,
                GuestTerminal::Failed { .. } => 5,
            },
            Self::OneShot(outcome) => outcome
                .status
                .code
                .unwrap_or_else(|| outcome.status.signal.map_or(5, |signal| 128 + signal)),
        }
    }

    fn successful(&self) -> bool {
        match self {
            Self::Persistent(report) => {
                matches!(report.terminal, GuestTerminal::Exited { code: 0 })
            }
            Self::OneShot(outcome) => outcome.status.success,
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Persistent(_) => "persistent",
            Self::OneShot(_) => "one_shot",
        }
    }
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("{0}")]
    Invalid(String),
    #[error("boundary plan: {0}")]
    Boundary(#[from] BoundaryError),
    #[error("runtime: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("security: {0}")]
    Security(#[from] SecurityError),
    #[error("session security: {0}")]
    SessionSecurity(#[from] SessionSecurityError),
    #[error("runtime failed: {runtime}; session security also failed: {security}")]
    RuntimeSecurity {
        runtime: Box<HostError>,
        security: SessionSecurityError,
    },
    #[error("agent plan: {0}")]
    AgentPlan(#[from] sendbox_agent::AgentError),
    #[error("agent execution: {0}")]
    AgentRun(#[from] RunFailure),
    #[error("Git guard: {0}")]
    GitGuard(#[from] GuardError),
    #[error("credentials: {0}")]
    Credentials(#[from] CredentialBrokerError),
    #[error("secret store: {0}")]
    SecretStore(#[from] sendbox_secrets::SecretStoreError),
    #[error("{context} `{path}`: {source}")]
    Io {
        context: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("bundle verification: {0}")]
    Bundle(String),
}

pub struct PreparedHostRun {
    execution: HostExecution,
    secrets: Arc<HostSecretResolver>,
    security: security::HostSecurityContext,
    signed_plan_path: PathBuf,
    terminal_source: Option<Arc<dyn TerminalSource>>,
}

struct EffectiveCredentialSet {
    values: BTreeMap<String, SecretValue>,
    github_https_auth: bool,
    copilot_auth: bool,
    git_ssh_auth: bool,
}

impl EffectiveCredentialSet {
    fn apply_to(&self, configuration: &mut SandboxConfiguration) {
        configuration.secrets.extend(self.values.keys().cloned());
    }

    fn into_values(self) -> BTreeMap<String, SecretValue> {
        self.values
    }
}

enum HostExecution {
    Persistent {
        provider: Arc<dyn RuntimeProvider>,
        plan: RunPlan,
        terminal: Option<GuestTerminalSize>,
    },
    Hyperlight(HyperlightExecution),
}

struct HyperlightExecution {
    provider: Arc<HyperlightRuntime>,
    verified_plan: VerifiedBoundaryPlan,
    create_request: CreateRequest,
    state_directory: PathBuf,
    command: CommandSpec,
    listen_ports: Vec<u16>,
}

impl PreparedHostRun {
    #[must_use]
    pub fn signed_plan_path(&self) -> &Path {
        &self.signed_plan_path
    }

    /// Supplies the host keystroke/resize source for an interactive run.
    ///
    /// Ignored unless the request asked for a terminal; an interactive request
    /// without a source fails at execution time rather than leaving the
    /// workload unable to be typed into.
    #[must_use]
    pub fn with_terminal_source(mut self, source: Arc<dyn TerminalSource>) -> Self {
        self.terminal_source = Some(source);
        self
    }

    pub async fn execute(
        self,
        output: Arc<dyn OutputSink>,
        signals: Arc<dyn SignalSource>,
        cancellation: &CancellationToken,
    ) -> Result<HostRunReport, HostError> {
        let runtime = execute_runtime(
            self.execution,
            self.secrets,
            output,
            signals,
            self.terminal_source,
            cancellation,
        );
        security::execute(self.security, runtime, cancellation).await
    }
}

pub async fn prepare(mut request: HostRunRequest) -> Result<PreparedHostRun, HostError> {
    request
        .configuration
        .validate()
        .map_err(|error| HostError::Invalid(error.to_string()))?;
    validate_reserved_secret_names(&request.configuration)?;
    let command = validate_command(&request.command)?;
    validate_command_policy(&request.configuration.policy.commands, &request.command)?;
    let host = current_host()?;
    let runtime_request = effective_runtime_request(
        request.requested_runtime,
        request
            .configuration
            .runtime
            .as_ref()
            .map_or(ConfiguredRuntime::Auto, |runtime| runtime.provider),
    );
    let selection = select_runtime(runtime_request, host)?;
    let selected_runtime = selection.selected;
    validate_runtime_features(selected_runtime, &request.configuration)?;
    let workspace_source =
        canonical_file_or_directory(&request.configuration.project_path, "project root")?;
    let bundle_root = canonical_file_or_directory(&request.bundle_root, "bundle root")?;
    let trust_root = canonical_file_or_directory(&request.trust_root, "bundle trust root")?;
    let bundle = verify_bundle(&VerifyOptions {
        root: &bundle_root,
        public_key: &trust_root,
        trust_root_id: &request.trust_root_id,
        minimum_release_sequence: request.minimum_release_sequence,
        host_version: VERSION,
        guest_version: VERSION,
        architecture: bundle_architecture(host.architecture),
    })
    .map_err(|error| HostError::Bundle(error.to_string()))?;
    let manifest_sha256 = hash_file(&bundle_root.join("manifest.json"))?;
    let bundle_id = format!("{}:{}", request.trust_root_id, bundle.release_sequence);
    let selected_repository =
        discover_selected_repository(&request.configuration, &workspace_source)?;
    let credentials =
        prepare_effective_credentials(&request.configuration, selected_repository.as_ref()).await?;
    credentials.apply_to(&mut request.configuration);
    request
        .configuration
        .validate()
        .map_err(|error| HostError::Invalid(error.to_string()))?;
    let workspace_destination = PathBuf::from("/workspace");
    let workload_identity = match selected_runtime {
        ResolvedRuntime::Apple | ResolvedRuntime::Kata => {
            Some(project_identity(&workspace_source)?)
        }
        ResolvedRuntime::Hyperlight => None,
    };
    let session_id = random_session_id()?;
    ensure_private_directory(&request.state_root)?;
    let state_root = canonical_file_or_directory(&request.state_root, "runtime state root")?;
    let registry_proxy = prepare_registry_proxy(
        selected_runtime,
        &request.configuration,
        session_id,
        &state_root,
        workload_identity,
    )?;
    let egress_policy = make_egress_policy(selected_runtime, &request.configuration, session_id)?;
    let git_guard_policy = make_git_guard_policy(
        selected_runtime,
        &request.configuration,
        selected_repository.as_ref(),
        &workspace_source,
        &workspace_destination,
        &credentials,
    )?;
    let mcp_policy = make_mcp_policy(
        selected_runtime,
        &request.configuration,
        &workspace_source,
        &workspace_destination,
        workload_identity,
        egress_policy.as_ref(),
    )?;
    let environment = runtime_environment(mcp_policy.as_ref(), egress_policy.as_ref());
    let features = boundary_features(
        &request.configuration,
        git_guard_policy.as_ref(),
        mcp_policy.as_ref(),
        egress_policy.as_ref(),
        &credentials,
    )?;
    validate_security_composition(SecurityComposition {
        selected_runtime,
        configuration: &request.configuration,
        selected_repository: selected_repository.as_ref(),
        host_workspace: &workspace_source,
        guest_workspace: &workspace_destination,
        workload_identity,
        session_id,
        git_guard_policy: git_guard_policy.as_ref(),
        mcp_policy: mcp_policy.as_ref(),
        egress_policy: egress_policy.as_ref(),
        credentials: &credentials,
        features: &features,
    })?;

    let prospective_state_directory = state_root.join("sessions").join(session_id.to_string());
    security::validate_state_workspace_disjoint(&workspace_source, &prospective_state_directory)?;
    let state_directory = create_session_directory(&state_root, session_id)?;
    let key = load_or_create_signing_key(&state_root)?;
    let signer_fingerprint = key
        .identity("SendBox local runtime", None, 0, None)
        .fingerprint;
    let now_unix = unix_time()?;
    let configuration_bytes = serde_json::to_vec(&request.configuration)
        .map_err(|error| HostError::Invalid(error.to_string()))?;
    let policy_bytes = serde_json::to_vec(&request.configuration.policy)
        .map_err(|error| HostError::Invalid(error.to_string()))?;
    let configuration_sha256 = sha256_hex(&configuration_bytes);
    let policy_sha256 = sha256_hex(&policy_bytes);
    let resources = runtime_resources(&request.configuration)?;
    let bootstrap_reference =
        SecretReference::new(format!("bootstrap-{session_id}")).map_err(HostError::AgentPlan)?;
    let secrets = Arc::new(HostSecretResolver::open(
        bootstrap_reference.clone(),
        random_bootstrap_secret()?,
        credentials.into_values(),
    )?);

    let runtime = build_runtime(
        selected_runtime,
        &request,
        &bundle_root,
        &trust_root,
        host,
        resources,
        &workspace_source,
        workload_identity,
        git_guard_policy.as_ref(),
        mcp_policy.as_ref(),
        egress_policy.as_ref(),
        registry_proxy.as_ref(),
    )?;
    let registry_mounts = registry_proxy
        .as_ref()
        .map(|prepared| {
            vec![MountDeclaration {
                source: prepared.host_cache_root.clone(),
                destination: prepared.bootstrap.cache_root.clone(),
                writable: true,
            }]
        })
        .unwrap_or_default();
    let workload = match selected_runtime {
        ResolvedRuntime::Hyperlight => WorkloadIdentity::GuestBundle {
            root: bundle_root.clone(),
            manifest_sha256: manifest_sha256.clone(),
        },
        ResolvedRuntime::Apple | ResolvedRuntime::Kata => {
            let image = request.image.as_deref().ok_or_else(|| {
                HostError::Invalid("persistent runtimes require --image".to_owned())
            })?;
            WorkloadIdentity::OciImage {
                reference: image.to_owned(),
                digest: parse_oci_digest(image)?,
            }
        }
    };
    let plan = BoundaryPlan {
        format: BOUNDARY_PLAN_FORMAT.to_owned(),
        version: BOUNDARY_PLAN_VERSION,
        session_id,
        created_at_unix: now_unix,
        expires_at_unix: now_unix.saturating_add(PLAN_VALIDITY.as_secs()),
        selection,
        configuration_sha256,
        policy_sha256,
        workload,
        workspace: MountDeclaration {
            source: workspace_source.clone(),
            destination: workspace_destination.clone(),
            writable: true,
        },
        command: CommandDeclaration {
            program: command.0.clone(),
            arguments: command.1.clone(),
            working_directory: workspace_destination.display().to_string(),
        },
        mounts: registry_mounts.clone(),
        environment: environment
            .iter()
            .map(|entry| EnvironmentDeclaration {
                name: entry.name.clone(),
                value_sha256: sha256_hex(entry.value.as_bytes()),
                sensitive: entry.sensitive,
            })
            .collect(),
        secrets: request.configuration.secrets.clone(),
        resources: ResourceDeclaration {
            cpus: resources.cpus,
            memory_bytes: resources.memory_bytes,
        },
        trust: TrustDeclaration {
            trust_root_id: request.trust_root_id.clone(),
            minimum_release_sequence: request.minimum_release_sequence,
            host_version: VERSION.to_owned(),
            guest_version: VERSION.to_owned(),
        },
        provider: runtime.declaration,
        artifacts: runtime.artifacts,
        features,
    };
    let signed_plan = SignedBoundaryPlan::sign(plan, &key, now_unix)?;
    let verified_plan = signed_plan.verify(&signer_fingerprint, now_unix)?;
    let security_plan = verified_plan.clone();
    let signed_plan_path = state_directory.join("boundary-plan.json");
    atomic_write(
        &signed_plan_path,
        &serde_json::to_vec_pretty(&signed_plan)
            .map_err(|error| HostError::Invalid(error.to_string()))?,
        0o600,
    )?;

    let execution = match runtime.provider {
        RuntimeInstance::Persistent(provider) => {
            assert_provider_identity(provider.as_ref(), selected_runtime)?;
            let agent_request = AgentRequest {
                boundary_plan: verified_plan,
                session_id,
                state_directory: state_directory.clone(),
                image: request.image.ok_or_else(|| {
                    HostError::Invalid("persistent runtimes require --image".to_owned())
                })?,
                guest_workspace: workspace_destination,
                command: GuestCommand {
                    program: command.0,
                    arguments: command.1,
                    working_directory: "/workspace".to_owned(),
                },
                environment,
                mounts: registry_mounts
                    .into_iter()
                    .map(|mount| sendbox_agent::MountIntent {
                        source: mount.source,
                        destination: mount.destination,
                        writable: mount.writable,
                    })
                    .collect(),
                bootstrap_reference,
                readiness_timeout: request.readiness_timeout,
                interactive: request.terminal.is_some(),
            };
            let plan = RunPlan::compile(
                &request.configuration,
                agent_request,
                &provider.capabilities(),
                now_unix,
            )?;
            HostExecution::Persistent {
                provider,
                plan,
                terminal: request.terminal.clone(),
            }
        }
        RuntimeInstance::Hyperlight(provider) => {
            assert_provider_identity(provider.as_ref(), selected_runtime)?;
            if request.terminal.is_some() {
                return Err(HostError::Invalid(
                    "the hyperlight runtime cannot provide an interactive terminal; \
                     use a persistent runtime such as apple or kata"
                        .to_owned(),
                ));
            }
            let create_request = CreateRequest {
                session_id,
                container_id: container_id(&request.configuration.name, session_id)?,
                boundary_plan_digest: verified_plan.digest(),
                image: bundle_id,
                hostname: format!("sendbox-{session_id}"),
                resources,
                mounts: vec![sendbox_runtime::RuntimeMount {
                    source: workspace_source.clone(),
                    destination: workspace_destination,
                    writable: true,
                }],
                environment: Vec::new(),
                working_directory: PathBuf::from("/workspace"),
                dns_servers: Vec::new(),
                labels: Vec::new(),
            };
            let command = CommandSpec {
                arguments: command.1.into_iter().map(CommandArgument::plain).collect(),
                current_directory: Some(PathBuf::from("/workspace")),
                environment: Vec::new(),
                clear_environment: true,
                ..CommandSpec::new(Program::Absolute(PathBuf::from(command.0)))
            };
            HostExecution::Hyperlight(HyperlightExecution {
                provider,
                verified_plan,
                create_request,
                state_directory: state_directory.clone(),
                command,
                listen_ports: Vec::new(),
            })
        }
    };
    let security = security::HostSecurityContext::new(
        security_plan,
        configuration_bytes,
        policy_bytes,
        workspace_source,
        state_directory,
        key,
    );

    Ok(PreparedHostRun {
        execution,
        secrets,
        security,
        signed_plan_path,
        terminal_source: None,
    })
}

async fn execute_runtime(
    execution: HostExecution,
    secrets: Arc<HostSecretResolver>,
    output: Arc<dyn OutputSink>,
    signals: Arc<dyn SignalSource>,
    terminal_source: Option<Arc<dyn TerminalSource>>,
    cancellation: &CancellationToken,
) -> Result<HostRunReport, HostError> {
    match execution {
        HostExecution::Persistent {
            provider,
            plan,
            terminal,
        } => {
            let mut orchestrator = AgentOrchestrator::new(
                provider,
                secrets,
                Arc::new(ProtocolGuestConnector),
                output,
                signals,
            );
            if let Some(size) = terminal {
                let source = terminal_source.ok_or_else(|| {
                    HostError::Invalid(
                        "interactive runs require a terminal input source".to_owned(),
                    )
                })?;
                orchestrator = orchestrator.with_terminal(size, source);
            }
            orchestrator
                .run(&plan, cancellation)
                .await
                .map(HostRunReport::Persistent)
                .map_err(HostError::AgentRun)
        }
        HostExecution::Hyperlight(execution) => {
            execute_hyperlight(execution, secrets, output, cancellation)
                .await
                .map(HostRunReport::OneShot)
        }
    }
}

struct RuntimeBuild {
    provider: RuntimeInstance,
    declaration: ProviderDeclaration,
    artifacts: Vec<ArtifactIdentity>,
}

enum RuntimeInstance {
    Persistent(Arc<dyn RuntimeProvider>),
    Hyperlight(Arc<HyperlightRuntime>),
}

#[allow(clippy::too_many_arguments)]
fn build_runtime(
    selected_runtime: ResolvedRuntime,
    request: &HostRunRequest,
    bundle_root: &Path,
    trust_root: &Path,
    host: HostPlatform,
    resources: RuntimeResources,
    workspace_source: &Path,
    workload_identity: Option<(u32, u32)>,
    git_guard_policy: Option<&GuardPolicyDocument>,
    mcp_policy: Option<&RuntimePolicyDocument>,
    egress_policy: Option<&EgressRuntimePolicyDocument>,
    registry_proxy: Option<&PreparedRegistryProxy>,
) -> Result<RuntimeBuild, HostError> {
    let manifest_path = bundle_root.join("manifest.json");
    let mut artifacts = vec![
        artifact_identity(ArtifactKind::GuestBundleManifest, &manifest_path)?,
        artifact_identity(ArtifactKind::TrustRoot, trust_root)?,
    ];
    match selected_runtime {
        ResolvedRuntime::Apple => {
            let executable = resolve_container_executable(None);
            let executable =
                executable.resolved_path.ok_or_else(|| {
                    HostError::Invalid(
                        executable.reasons.first().cloned().unwrap_or_else(|| {
                            "Apple container executable was not found".to_owned()
                        }),
                    )
                })?;
            artifacts.push(artifact_identity(
                ArtifactKind::RuntimeExecutable,
                &executable,
            )?);
            let (workload_uid, workload_gid) = workload_identity.ok_or_else(|| {
                HostError::Invalid("Apple workload identity was not prepared".to_owned())
            })?;
            let mut configuration = AppleRuntimeConfiguration::new(
                bundle_root,
                trust_root,
                &request.trust_root_id,
                VERSION,
                VERSION,
                request.minimum_release_sequence,
            );
            configuration.executable = Some(executable.clone());
            configuration.command_policy = request.configuration.policy.commands.clone();
            configuration.git_guard_policy = git_guard_policy.cloned();
            configuration.mcp_policy = mcp_policy.cloned();
            configuration.egress_policy = egress_policy.cloned();
            configuration.registry_proxy =
                registry_proxy.map(|prepared| prepared.bootstrap.clone());
            configuration.workload_uid = workload_uid;
            configuration.workload_gid = workload_gid;
            configuration.launch.resources.cpus =
                Some(u16::try_from(resources.cpus).map_err(|_| {
                    HostError::Invalid("Apple CPU count is out of range".to_owned())
                })?);
            configuration.launch.resources.memory_mib =
                Some(resources.memory_bytes / (1024 * 1024));
            let declaration = ProviderDeclaration::Apple {
                executable,
                command_timeout_ms: u64::try_from(configuration.command_timeout.as_millis())
                    .map_err(|_| HostError::Invalid("Apple timeout is out of range".to_owned()))?,
                output_limit_bytes: u64::try_from(configuration.output_limit_bytes).map_err(
                    |_| HostError::Invalid("Apple output limit is out of range".to_owned()),
                )?,
                transport: ControlTransport::InheritedStdio,
            };
            Ok(RuntimeBuild {
                provider: RuntimeInstance::Persistent(Arc::new(AppleRuntime::new(configuration)?)),
                declaration,
                artifacts,
            })
        }
        ResolvedRuntime::Kata => {
            let kata = request
                .configuration
                .runtime
                .as_ref()
                .map(|runtime| runtime.kata.clone())
                .unwrap_or_default();
            let executable = resolve_executable(&kata.executable)?;
            artifacts.push(artifact_identity(
                ArtifactKind::RuntimeExecutable,
                &executable,
            )?);
            let configuration_path = kata
                .configuration_path
                .as_deref()
                .map(|path| canonical_file_or_directory(path, "Kata configuration"))
                .transpose()?;
            if let Some(path) = &configuration_path {
                artifacts.push(artifact_identity(
                    ArtifactKind::ProviderConfiguration,
                    path,
                )?);
            }
            let (workload_uid, workload_gid) = workload_identity.ok_or_else(|| {
                HostError::Invalid("Kata workload identity was not prepared".to_owned())
            })?;
            let configuration = KataProviderConfiguration {
                executable: executable.display().to_string(),
                runtime_handler: kata.runtime_handler.clone(),
                namespace: kata.namespace.clone(),
                address: kata.address.clone(),
                snapshotter: kata.snapshotter.clone(),
                configuration_path: configuration_path.clone(),
                bundle_root: bundle_root.to_path_buf(),
                trust_root_file: trust_root.to_path_buf(),
                trust_root_id: request.trust_root_id.clone(),
                minimum_release_sequence: request.minimum_release_sequence,
                command_policy: request.configuration.policy.commands.clone(),
                git_guard_policy: git_guard_policy.cloned(),
                mcp_policy: mcp_policy.cloned(),
                egress_policy: egress_policy.cloned(),
                registry_proxy: registry_proxy.map(|prepared| prepared.bootstrap.clone()),
                workload_uid,
                workload_gid,
            };
            let declaration = ProviderDeclaration::Kata {
                executable,
                runtime_handler: kata.runtime_handler,
                namespace: kata.namespace,
                address: kata.address,
                snapshotter: kata.snapshotter,
                configuration_path,
                transport: ControlTransport::RuntimeExecStdio,
            };
            Ok(RuntimeBuild {
                provider: RuntimeInstance::Persistent(Arc::new(KataRuntimeProvider::new(
                    configuration,
                )?)),
                declaration,
                artifacts,
            })
        }
        ResolvedRuntime::Hyperlight => {
            let hyperlight = request
                .configuration
                .runtime
                .as_ref()
                .map(|runtime| runtime.hyperlight.clone())
                .unwrap_or_default();
            let executable =
                canonical_file_or_directory(&hyperlight.executable, "Hyperlight executable")?;
            let kernel_path =
                canonical_file_or_directory(&hyperlight.kernel_path, "Hyperlight kernel")?;
            let initrd_path = hyperlight
                .initrd_path
                .as_deref()
                .map(|path| canonical_file_or_directory(path, "Hyperlight initrd"))
                .transpose()?;
            artifacts.push(artifact_identity(
                ArtifactKind::RuntimeExecutable,
                &executable,
            )?);
            artifacts.push(artifact_identity(ArtifactKind::Kernel, &kernel_path)?);
            if let Some(path) = &initrd_path {
                artifacts.push(artifact_identity(ArtifactKind::Initrd, path)?);
            }
            let memory_mib = resources.memory_bytes / (1024 * 1024);
            let stack_mib = u64::try_from(hyperlight.stack_mb)
                .map_err(|_| HostError::Invalid("Hyperlight stack size is invalid".to_owned()))?;
            let mounts = vec![HyperlightMount {
                source: workspace_source.to_path_buf(),
                destination: PathBuf::from("/workspace"),
                read_only: false,
            }];
            let configuration = HyperlightConfiguration {
                executable: executable.clone(),
                expected_cli_version: VERSION.to_owned(),
                bundle_root: bundle_root.to_path_buf(),
                public_key: trust_root.to_path_buf(),
                trust_root_id: request.trust_root_id.clone(),
                expected_host_version: VERSION.to_owned(),
                expected_guest_version: VERSION.to_owned(),
                minimum_release_sequence: request.minimum_release_sequence,
                kernel_path: kernel_path.clone(),
                initrd_path: initrd_path.clone(),
                memory_mib,
                stack_mib,
                working_directory: request.state_root.clone(),
                start_command: None,
                mounts,
                network: HyperlightNetworkConfiguration::default(),
                listen_ports: Vec::new(),
                process_options: ProcessOptions::default(),
            };
            let declaration = ProviderDeclaration::Hyperlight {
                executable,
                kernel: kernel_path,
                initrd: initrd_path,
                stack_mib,
                network_enabled: false,
                listen_ports: Vec::new(),
                transport: ControlTransport::AuthenticatedOneShot,
            };
            let provider = HyperlightRuntime::new(configuration)?;
            if host.operating_system != OperatingSystem::Linux
                || host.architecture != Architecture::X86_64
            {
                return Err(HostError::Invalid(
                    "Hyperlight requires Linux x86_64".to_owned(),
                ));
            }
            Ok(RuntimeBuild {
                provider: RuntimeInstance::Hyperlight(Arc::new(provider)),
                declaration,
                artifacts,
            })
        }
    }
}

async fn execute_hyperlight(
    execution: HyperlightExecution,
    secrets: Arc<HostSecretResolver>,
    output: Arc<dyn OutputSink>,
    cancellation: &CancellationToken,
) -> Result<ProcessOutcome, HostError> {
    let HyperlightExecution {
        provider,
        verified_plan,
        create_request,
        state_directory,
        command,
        listen_ports,
    } = execution;
    verified_plan.reverify(unix_time()?)?;
    provider
        .preflight(
            sendbox_runtime::PreflightRequest {
                required_capabilities: provider.capabilities(),
            },
            cancellation,
        )
        .await?;
    let container_id = create_request.container_id.clone();
    provider
        .initialize(InitializeRequest { state_directory }, cancellation)
        .await?;
    provider
        .create(create_request.clone(), cancellation)
        .await?;
    let result = async {
        provider
            .start(&container_id, StartRequest::default(), cancellation)
            .await?;
        if cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        let bootstrap = secrets
            .bootstrap_material()
            .map_err(|error| RuntimeError::Provider(error.to_string()))?;
        let outcome = provider
            .execute_authenticated_once(
                &container_id,
                AuthenticatedLaunchRequest {
                    session_id: create_request.session_id,
                    boundary_plan_digest: verified_plan.digest(),
                    command,
                    bootstrap_material: bootstrap,
                    listen_ports,
                },
                cancellation,
            )
            .await?;
        if !outcome.stdout.bytes.is_empty() {
            output
                .write(OutputStream::Stdout, &outcome.stdout.bytes, cancellation)
                .await
                .map_err(|error| RuntimeError::Provider(error.to_string()))?;
        }
        if !outcome.stderr.bytes.is_empty() {
            output
                .write(OutputStream::Stderr, &outcome.stderr.bytes, cancellation)
                .await
                .map_err(|error| RuntimeError::Provider(error.to_string()))?;
        }
        Ok(outcome)
    }
    .await;
    let cleanup = cleanup_hyperlight(provider.as_ref(), &container_id).await;
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(primary), Ok(())) => Err(HostError::Runtime(primary)),
        (Ok(_), Err(cleanup)) => Err(HostError::Runtime(cleanup)),
        (Err(primary), Err(cleanup)) => Err(HostError::Invalid(format!(
            "{primary}; cleanup also failed: {cleanup}"
        ))),
    }
}

async fn cleanup_hyperlight(
    provider: &HyperlightRuntime,
    container_id: &ContainerId,
) -> Result<(), RuntimeError> {
    let mut failures = Vec::new();
    let cleanup_cancellation = CancellationToken::new();
    if let Err(error) = provider
        .signal(
            container_id,
            RuntimeSignal::Terminate,
            &cleanup_cancellation,
        )
        .await
    {
        failures.push(error.to_string());
    }
    if let Err(error) = provider
        .stop(container_id, StopRequest::default(), &cleanup_cancellation)
        .await
    {
        failures.push(error.to_string());
    }
    match provider.cleanup(container_id, &cleanup_cancellation).await {
        Ok(report) if report.is_complete() => {}
        Ok(report) => failures.extend(
            report
                .failures
                .into_iter()
                .map(|failure| failure.error.to_string()),
        ),
        Err(error) => failures.push(error.to_string()),
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::Provider(failures.join("; ")))
    }
}

struct HostSecretResolver {
    bootstrap_reference: SecretReference,
    bootstrap: Zeroizing<[u8; 32]>,
    ephemeral: BTreeMap<String, SecretValue>,
    native: Arc<dyn SecretStore>,
}

impl HostSecretResolver {
    fn open(
        bootstrap_reference: SecretReference,
        bootstrap: [u8; 32],
        ephemeral: BTreeMap<String, SecretValue>,
    ) -> Result<Self, HostError> {
        Ok(Self {
            bootstrap_reference,
            bootstrap: Zeroizing::new(bootstrap),
            ephemeral,
            native: native_secret_store()?,
        })
    }

    fn bootstrap_material(&self) -> Result<BootstrapMaterial, HostError> {
        BootstrapMaterial::new(self.bootstrap.to_vec()).map_err(HostError::Runtime)
    }
}

impl SecretResolver for HostSecretResolver {
    fn resolve<'a>(
        &'a self,
        reference: &'a SecretReference,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<SecretEnvelope, sendbox_agent::AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(sendbox_agent::AgentError::Cancelled);
            }
            if reference == &self.bootstrap_reference {
                return Ok(SecretEnvelope::new(
                    reference.clone(),
                    self.bootstrap.to_vec(),
                ));
            }
            if let Some(secret) = self.ephemeral.get(reference.as_str()) {
                return Ok(SecretEnvelope::new(
                    reference.clone(),
                    secret.expose_secret().to_vec(),
                ));
            }
            let name = SecretName::new(reference.as_str()).map_err(|error| {
                sendbox_agent::AgentError::Secret {
                    reference: reference.as_str().to_owned(),
                    message: error.to_string(),
                }
            })?;
            let secret =
                self.native
                    .retrieve(&name)
                    .map_err(|error| sendbox_agent::AgentError::Secret {
                        reference: reference.as_str().to_owned(),
                        message: error.to_string(),
                    })?;
            Ok(SecretEnvelope::new(
                reference.clone(),
                secret.value.expose_secret().to_vec(),
            ))
        })
    }
}

#[cfg(target_os = "macos")]
fn native_secret_store() -> Result<Arc<dyn SecretStore>, HostError> {
    Ok(Arc::new(sendbox_secrets::KeychainStore::default_service()))
}

#[cfg(target_os = "linux")]
fn native_secret_store() -> Result<Arc<dyn SecretStore>, HostError> {
    Ok(Arc::new(sendbox_secrets::LinuxFileStore::open_default(
        SECRET_SERVICE,
    )?))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn native_secret_store() -> Result<Arc<dyn SecretStore>, HostError> {
    Err(HostError::Invalid(
        "native secret storage is unsupported on this host".to_owned(),
    ))
}

fn effective_runtime_request(
    requested: RequestedRuntime,
    configured: ConfiguredRuntime,
) -> ConfiguredRuntime {
    match requested {
        RequestedRuntime::Auto => configured,
        RequestedRuntime::Apple => ConfiguredRuntime::Apple,
        RequestedRuntime::Kata => ConfiguredRuntime::Kata,
        RequestedRuntime::Hyperlight => ConfiguredRuntime::Hyperlight,
    }
}

fn current_host() -> Result<HostPlatform, HostError> {
    let operating_system = if cfg!(target_os = "macos") {
        OperatingSystem::Macos
    } else if cfg!(target_os = "linux") {
        OperatingSystem::Linux
    } else {
        return Err(HostError::Invalid(
            "sendbox runtime is supported only on macOS and Linux".to_owned(),
        ));
    };
    let architecture = if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64
    } else if cfg!(target_arch = "x86_64") {
        Architecture::X86_64
    } else {
        return Err(HostError::Invalid(
            "sendbox runtime requires arm64 or x86_64".to_owned(),
        ));
    };
    Ok(HostPlatform {
        operating_system,
        architecture,
    })
}

fn bundle_architecture(architecture: Architecture) -> BundleArchitecture {
    match architecture {
        Architecture::Aarch64 => BundleArchitecture::Aarch64,
        Architecture::X86_64 => BundleArchitecture::X86_64,
    }
}

fn validate_runtime_features(
    selected_runtime: ResolvedRuntime,
    configuration: &SandboxConfiguration,
) -> Result<(), HostError> {
    if selected_runtime == ResolvedRuntime::Hyperlight && !configuration.secrets.is_empty() {
        return Err(HostError::Invalid(
            "Hyperlight does not support authenticated configured-secret delivery".to_owned(),
        ));
    }
    if selected_runtime == ResolvedRuntime::Hyperlight
        && (configuration.github.branch_protection.enabled
            || configuration.github.forward_auth
            || configuration.github.forward_copilot_auth
            || configuration.github.ssh_key_path.is_some())
    {
        return Err(HostError::Invalid(
            "Hyperlight does not support authenticated Git or credential delivery".to_owned(),
        ));
    }
    if selected_runtime == ResolvedRuntime::Hyperlight
        && (requires_enforcement(&configuration.policy.network)
            || configuration.policy.packages.enabled)
    {
        return Err(HostError::Invalid(
            "Hyperlight does not support authenticated production egress enforcement".to_owned(),
        ));
    }
    Ok(())
}

fn make_egress_policy(
    selected_runtime: ResolvedRuntime,
    configuration: &SandboxConfiguration,
    session_id: SessionId,
) -> Result<Option<EgressRuntimePolicyDocument>, HostError> {
    if !requires_enforcement(&configuration.policy.network)
        && !configuration.policy.packages.enabled
    {
        return Ok(None);
    }
    if selected_runtime == ResolvedRuntime::Hyperlight {
        return Err(HostError::Invalid(
            "Hyperlight does not support authenticated production egress enforcement".to_owned(),
        ));
    }
    let original = configuration.policy.network.clone();
    let mut workload = original.clone();
    if configuration.policy.packages.enabled {
        for registry in &configuration.policy.packages.registries {
            let url = Url::parse(&registry.url).map_err(|error| {
                HostError::Invalid(format!("invalid package registry URL: {error}"))
            })?;
            let host = url
                .host_str()
                .ok_or_else(|| HostError::Invalid("package registry URL has no host".to_owned()))?;
            workload.blocked_domains.push(host.to_owned());
        }
        workload.blocked_domains.sort();
        workload.blocked_domains.dedup();
    }
    let mut policy = EgressRuntimePolicyDocument::for_session(session_id, workload);
    if configuration.policy.packages.enabled {
        policy = policy.with_registry(
            DEFAULT_REGISTRY_PROXY_PORT,
            DEFAULT_TRUSTED_REGISTRY_PORT,
            original,
        );
    }
    policy
        .validate()
        .map_err(|error| HostError::Invalid(format!("invalid egress runtime policy: {error}")))?;
    Ok(Some(policy))
}

#[derive(Debug, Clone)]
struct PreparedRegistryProxy {
    bootstrap: RegistryProxyConfiguration,
    host_cache_root: PathBuf,
}

fn prepare_registry_proxy(
    selected_runtime: ResolvedRuntime,
    configuration: &SandboxConfiguration,
    session_id: SessionId,
    state_root: &Path,
    workload_identity: Option<(u32, u32)>,
) -> Result<Option<PreparedRegistryProxy>, HostError> {
    let policy = &configuration.policy.packages;
    if !policy.enabled {
        return Ok(None);
    }
    if selected_runtime == ResolvedRuntime::Hyperlight {
        return Err(HostError::Invalid(
            "Hyperlight does not support the authenticated package registry proxy".to_owned(),
        ));
    }
    let npm_registries = policy
        .registries
        .iter()
        .filter(|registry| registry.ecosystem == sendbox_policy::PackageEcosystem::Npm)
        .collect::<Vec<_>>();
    if npm_registries.len() != 1 || policy.registries.len() != 1 {
        return Err(HostError::Invalid(
            "the npm-first registry proxy currently requires exactly one npm registry".to_owned(),
        ));
    }
    if workload_identity == Some((DEFAULT_REGISTRY_UID, DEFAULT_REGISTRY_GID)) {
        return Err(HostError::Invalid(
            "workload and registry proxy identities must differ".to_owned(),
        ));
    }
    let configured_secrets = configuration.secrets.iter().collect::<BTreeSet<_>>();
    let references = policy
        .registries
        .iter()
        .filter_map(|registry| registry.credential_secret.as_ref())
        .collect::<Vec<_>>();
    if references
        .iter()
        .any(|reference| configured_secrets.contains(reference))
    {
        return Err(HostError::Invalid(
            "registry credentials must not also be delivered to the workload".to_owned(),
        ));
    }
    let credentials = if references.is_empty() {
        Vec::new()
    } else {
        let store = native_secret_store()?;
        references
            .into_iter()
            .map(|reference| {
                let name = SecretName::new(reference.clone())?;
                let secret = store.retrieve(&name)?;
                RegistryCredential::new(reference.clone(), secret.value.expose_secret().to_vec())
                    .map_err(|error| HostError::Invalid(error.to_string()))
            })
            .collect::<Result<Vec<_>, HostError>>()?
    };
    let host_cache_root = state_root.join("package-cache");
    ensure_private_directory(&host_cache_root)?;
    let host_cache_root = canonical_file_or_directory(&host_cache_root, "package cache root")?;
    Ok(Some(PreparedRegistryProxy {
        host_cache_root,
        bootstrap: RegistryProxyConfiguration {
            policy: policy.clone(),
            proxy_port: DEFAULT_REGISTRY_PROXY_PORT,
            trusted_upstream_port: DEFAULT_TRUSTED_REGISTRY_PORT,
            cache_root: PathBuf::from(DEFAULT_REGISTRY_CACHE_ROOT),
            report_path: PathBuf::from("/run/sendbox")
                .join(session_id.to_string())
                .join("registry")
                .join(PACKAGE_REPORT_FILE),
            proxy_uid: DEFAULT_REGISTRY_UID,
            proxy_gid: DEFAULT_REGISTRY_GID,
            credentials,
        },
    }))
}

fn make_git_guard_policy(
    selected_runtime: ResolvedRuntime,
    configuration: &SandboxConfiguration,
    selected_repository: Option<&RepositoryIdentity>,
    workspace_source: &Path,
    workspace_destination: &Path,
    credentials: &EffectiveCredentialSet,
) -> Result<Option<GuardPolicyDocument>, HostError> {
    if !configuration.github.branch_protection.enabled
        && !credentials.github_https_auth
        && !credentials.git_ssh_auth
    {
        return Ok(None);
    }
    if selected_runtime == ResolvedRuntime::Hyperlight {
        return Err(HostError::Invalid(
            "Hyperlight does not support the authenticated guest Git guard".to_owned(),
        ));
    }
    let repository = selected_repository
        .ok_or_else(|| HostError::Invalid("selected Git repository is unavailable".to_owned()))?;
    let configured = &configuration.github.branch_protection;
    let username = configured
        .enabled
        .then(|| {
            configured
                .username
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .or_else(|| resolve_github_username(repository.host(), workspace_source))
        })
        .flatten();
    let mut environment = EnvironmentPolicy::default();
    if credentials.github_https_auth {
        environment
            .inherited_keys
            .insert(GITHUB_TOKEN_ENVIRONMENT.to_owned());
    }
    if credentials.git_ssh_auth {
        environment
            .inherited_keys
            .insert(SSH_KEY_ENVIRONMENT.to_owned());
    }
    let policy = GuardPolicyDocument {
        schema_version: PolicySchemaVersion::V1,
        selected_repository: repository.clone(),
        selected_workspace: workspace_destination.to_path_buf(),
        branch_protection: BranchPolicyConfiguration {
            enabled: configured.enabled,
            username,
            protected_branches: configured.protected_branches.clone(),
            allowed_branch_patterns: configured.allowed_branch_patterns.clone(),
        },
        environment,
        github_https_auth: credentials.github_https_auth,
        git_ssh_auth: credentials.git_ssh_auth,
        limits: GuardLimits::default(),
    };
    policy.validate()?;
    Ok(Some(policy))
}

fn make_mcp_policy(
    selected_runtime: ResolvedRuntime,
    configuration: &SandboxConfiguration,
    host_workspace: &Path,
    guest_workspace: &Path,
    workload_identity: Option<(u32, u32)>,
    egress_policy: Option<&EgressRuntimePolicyDocument>,
) -> Result<Option<RuntimePolicyDocument>, HostError> {
    let has_project_configuration = PROJECT_CONFIG_PATHS
        .iter()
        .any(|relative| host_workspace.join(relative).symlink_metadata().is_ok());
    let inspection = configuration
        .observability
        .as_ref()
        .map(|observability| &observability.mcp_inspection)
        .filter(|inspection| inspection.enabled);
    if !has_project_configuration
        && configuration
            .policy
            .boundaries
            .tool_calls
            .allowed_server_commands
            .is_empty()
        && inspection.is_none()
    {
        return Ok(None);
    }
    if selected_runtime == ResolvedRuntime::Hyperlight {
        return Err(HostError::Invalid(
            "Hyperlight does not support the authenticated MCP broker".to_owned(),
        ));
    }
    if !configuration.policy.boundaries.enabled {
        return Err(HostError::Invalid(
            "MCP composition requires policy.boundaries.enabled".to_owned(),
        ));
    }
    if configuration
        .policy
        .boundaries
        .tool_calls
        .allowed_server_commands
        .is_empty()
    {
        return Err(HostError::Invalid(
            "MCP composition requires at least one exactly approved server command".to_owned(),
        ));
    }
    let (workload_uid, workload_gid) = workload_identity
        .ok_or_else(|| HostError::Invalid("MCP workload identity was not prepared".to_owned()))?;
    let observation = inspection
        .map(|inspection| {
            if inspection
                .transports
                .contains(&InspectionTransport::Http)
            {
                return Err(HostError::Invalid(
                    "HTTP/SSE MCP inspection is not available in the authenticated native runtime; configure stdio inspection only"
                        .to_owned(),
                ));
            }
            if !inspection
                .transports
                .contains(&InspectionTransport::Stdio)
            {
                return Err(HostError::Invalid(
                    "native MCP inspection requires the stdio transport".to_owned(),
                ));
            }
            Ok(RuntimeObservationConfiguration {
                capture_payloads: inspection.capture_payloads,
                max_payload_bytes: usize::try_from(inspection.max_payload_bytes).map_err(|_| {
                    HostError::Invalid("MCP observation payload limit is invalid".to_owned())
                })?,
                log_path: inspection.log_path.clone(),
            })
        })
        .transpose()?;
    let mut fixed_environment = BTreeMap::from([
        ("HOME".to_owned(), guest_workspace.display().to_string()),
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ("LOGNAME".to_owned(), "sendbox".to_owned()),
        (
            MCP_PROXY_ENVIRONMENT.to_owned(),
            NATIVE_BROKER_PATH.to_owned(),
        ),
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("TMPDIR".to_owned(), "/tmp".to_owned()),
        ("USER".to_owned(), "sendbox".to_owned()),
    ]);
    if let Some(egress_policy) = egress_policy {
        fixed_environment.extend(egress_policy.proxy_environment.clone());
    }
    let inherited_environment_keys = configuration
        .secrets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let policy = RuntimePolicyDocument {
        schema_version: RUNTIME_POLICY_SCHEMA_VERSION,
        workspace_root: guest_workspace.to_path_buf(),
        workload_uid,
        workload_gid,
        tool_policy: configuration.policy.boundaries.tool_calls.clone(),
        fixed_environment,
        inherited_environment_keys,
        observation,
    };
    policy
        .validate()
        .map_err(|error| HostError::Invalid(format!("invalid MCP runtime policy: {error}")))?;
    policy
        .project_validator()
        .map_err(|error| HostError::Invalid(format!("invalid MCP project policy: {error}")))?
        .validate_project(host_workspace)
        .map_err(|error| {
            HostError::Invalid(format!("unsafe MCP project configuration: {error}"))
        })?;
    Ok(Some(policy))
}

fn runtime_environment(
    mcp_policy: Option<&RuntimePolicyDocument>,
    egress_policy: Option<&EgressRuntimePolicyDocument>,
) -> Vec<EnvironmentIntent> {
    let mut environment = egress_policy.map_or_else(Vec::new, |policy| {
        policy
            .proxy_environment
            .iter()
            .map(|(name, value)| EnvironmentIntent {
                name: name.clone(),
                value: value.clone(),
                sensitive: false,
            })
            .collect()
    });
    if mcp_policy.is_some() {
        environment.push(EnvironmentIntent {
            name: MCP_PROXY_ENVIRONMENT.to_owned(),
            value: NATIVE_BROKER_PATH.to_owned(),
            sensitive: false,
        });
    }
    environment
}

fn boundary_features(
    configuration: &SandboxConfiguration,
    git_guard_policy: Option<&GuardPolicyDocument>,
    mcp_policy: Option<&RuntimePolicyDocument>,
    egress_policy: Option<&EgressRuntimePolicyDocument>,
    credentials: &EffectiveCredentialSet,
) -> Result<BTreeMap<String, FeatureAdmission>, HostError> {
    let mut features = BTreeMap::new();
    if let Some(policy) = git_guard_policy {
        let encoded =
            serde_json::to_vec(policy).map_err(|error| HostError::Invalid(error.to_string()))?;
        let mechanism = format!(
            "authenticated_guest_git_guard_v1:sha256={}",
            sha256_hex(&encoded)
        );
        features.insert(
            "git_runtime_guard".to_owned(),
            FeatureAdmission {
                decision: FeatureDecision::Enforced,
                mechanism: mechanism.clone(),
            },
        );
        if configuration.github.branch_protection.enabled {
            features.insert(
                "git_branch_protection".to_owned(),
                FeatureAdmission {
                    decision: FeatureDecision::Enforced,
                    mechanism,
                },
            );
        }
    }
    if let Some(policy) = mcp_policy {
        let encoded =
            serde_json::to_vec(policy).map_err(|error| HostError::Invalid(error.to_string()))?;
        let mechanism = format!(
            "authenticated_guest_mcp_broker_v1:sha256={}",
            sha256_hex(&encoded)
        );
        features.insert(
            "mcp_stdio_broker".to_owned(),
            FeatureAdmission {
                decision: FeatureDecision::Enforced,
                mechanism: mechanism.clone(),
            },
        );
        if policy.observation.is_some() {
            features.insert(
                "mcp_stdio_observation".to_owned(),
                FeatureAdmission {
                    decision: FeatureDecision::Enforced,
                    mechanism,
                },
            );
        }
    }
    if let Some(policy) = egress_policy {
        let encoded =
            serde_json::to_vec(policy).map_err(|error| HostError::Invalid(error.to_string()))?;
        let mechanism = format!(
            "authenticated_guest_egress_v1:sha256={}",
            sha256_hex(&encoded)
        );
        features.insert(
            "network_egress_enforcement".to_owned(),
            FeatureAdmission {
                decision: FeatureDecision::Enforced,
                mechanism: mechanism.clone(),
            },
        );
        if policy.dns_port.is_some() {
            features.insert(
                "network_dns_broker".to_owned(),
                FeatureAdmission {
                    decision: FeatureDecision::Enforced,
                    mechanism,
                },
            );
        }
    }
    if credentials.github_https_auth {
        features.insert(
            "github_repository_credentials".to_owned(),
            FeatureAdmission {
                decision: FeatureDecision::Enforced,
                mechanism: "repository_scoped_gh_authorization+secret_envelope_v2".to_owned(),
            },
        );
    }
    if credentials.copilot_auth {
        features.insert(
            "github_copilot_credentials".to_owned(),
            FeatureAdmission {
                decision: FeatureDecision::Enforced,
                mechanism: "independent_copilot_token+copilot_github_token+secret_envelope_v2"
                    .to_owned(),
            },
        );
    }
    if credentials.git_ssh_auth {
        features.insert(
            "git_ssh_credentials".to_owned(),
            FeatureAdmission {
                decision: FeatureDecision::Enforced,
                mechanism: "validated_private_key+secret_envelope_v2+trusted_ssh_wrapper"
                    .to_owned(),
            },
        );
    }
    Ok(features)
}

fn discover_selected_repository(
    configuration: &SandboxConfiguration,
    workspace_source: &Path,
) -> Result<Option<RepositoryIdentity>, HostError> {
    if !configuration.github.branch_protection.enabled
        && !configuration.github.forward_auth
        && configuration.github.ssh_key_path.is_none()
    {
        return Ok(None);
    }
    let git = trusted_host_git()?;
    discover_repository_identity(
        &git,
        &SystemGitProcessRunner,
        workspace_source,
        host_git_environment(),
    )
    .map(Some)
    .map_err(HostError::GitGuard)
}

async fn prepare_effective_credentials(
    configuration: &SandboxConfiguration,
    selected_repository: Option<&RepositoryIdentity>,
) -> Result<EffectiveCredentialSet, HostError> {
    let copilot_token = if configuration.github.forward_copilot_auth {
        Some(discover_copilot_token()?)
    } else {
        None
    };

    let github = if configuration.github.forward_auth {
        let repository = selected_repository.ok_or_else(|| {
            HostError::Invalid(
                "selected Git repository is required for GitHub credential authorization"
                    .to_owned(),
            )
        })?;
        if repository.host() != "github.com" {
            return Err(HostError::Invalid(format!(
                "guarded GitHub credential forwarding currently supports github.com, not {}",
                repository.host()
            )));
        }
        let identity = CredentialRepositoryIdentity::parse(&format!(
            "{}/{}",
            repository.owner(),
            repository.name()
        ))?;
        let client = GhMetadataClient::new(gh_process_configuration()?)?;
        authorize_github(
            &client,
            &identity,
            &configuration.github,
            copilot_token,
            &CancellationToken::new(),
        )
        .await?
        .credentials
    } else {
        GitHubSessionCredentials {
            github_token: None,
            copilot_token,
        }
    };

    collect_credential_values(configuration, github)
}

fn collect_credential_values(
    configuration: &SandboxConfiguration,
    github: GitHubSessionCredentials,
) -> Result<EffectiveCredentialSet, HostError> {
    let mut values = BTreeMap::new();
    if let Some(value) = github.github_token {
        values.insert(
            GITHUB_TOKEN_ENVIRONMENT.to_owned(),
            checked_environment_secret(GITHUB_TOKEN_ENVIRONMENT, value.expose_secret().to_vec())?,
        );
    }
    if let Some(value) = github.copilot_token {
        values.insert(
            COPILOT_GUEST_TOKEN_ENVIRONMENT.to_owned(),
            checked_environment_secret(
                COPILOT_GUEST_TOKEN_ENVIRONMENT,
                value.expose_secret().to_vec(),
            )?,
        );
    }
    if let Some(path) = configuration.github.ssh_key_path.as_deref() {
        values.insert(SSH_KEY_ENVIRONMENT.to_owned(), read_ssh_private_key(path)?);
    }
    let environment_bytes = values.iter().fold(0_usize, |total, (name, value)| {
        total
            .saturating_add(name.len())
            .saturating_add(value.expose_secret().len())
            .saturating_add(1)
    });
    if environment_bytes > MAX_EXECUTION_ENVIRONMENT_BYTES {
        return Err(HostError::Invalid(
            "prepared credentials exceed the guest environment limit".to_owned(),
        ));
    }
    Ok(EffectiveCredentialSet {
        github_https_auth: values.contains_key(GITHUB_TOKEN_ENVIRONMENT),
        copilot_auth: values.contains_key(COPILOT_GUEST_TOKEN_ENVIRONMENT),
        git_ssh_auth: values.contains_key(SSH_KEY_ENVIRONMENT),
        values,
    })
}

fn validate_reserved_secret_names(configuration: &SandboxConfiguration) -> Result<(), HostError> {
    for value in &configuration.secrets {
        let name = SecretName::new(value.clone())?;
        if requires_guarded_github_forwarding(&name) {
            return Err(HostError::Invalid(format!(
                "configured secret `{value}` requires guarded credential forwarding"
            )));
        }
    }
    Ok(())
}

struct SecurityComposition<'a> {
    selected_runtime: ResolvedRuntime,
    configuration: &'a SandboxConfiguration,
    selected_repository: Option<&'a RepositoryIdentity>,
    host_workspace: &'a Path,
    guest_workspace: &'a Path,
    workload_identity: Option<(u32, u32)>,
    session_id: SessionId,
    git_guard_policy: Option<&'a GuardPolicyDocument>,
    mcp_policy: Option<&'a RuntimePolicyDocument>,
    egress_policy: Option<&'a EgressRuntimePolicyDocument>,
    credentials: &'a EffectiveCredentialSet,
    features: &'a BTreeMap<String, FeatureAdmission>,
}

fn validate_security_composition(composition: SecurityComposition<'_>) -> Result<(), HostError> {
    let SecurityComposition {
        selected_runtime,
        configuration,
        selected_repository,
        host_workspace,
        guest_workspace,
        workload_identity,
        session_id,
        git_guard_policy,
        mcp_policy,
        egress_policy,
        credentials,
        features,
    } = composition;
    if credentials.github_https_auth != configuration.github.forward_auth
        || credentials.copilot_auth != configuration.github.forward_copilot_auth
        || credentials.git_ssh_auth != configuration.github.ssh_key_path.is_some()
    {
        return Err(HostError::Invalid(
            "credential preparation does not match the requested configuration".to_owned(),
        ));
    }
    let expected_guard = configuration.github.branch_protection.enabled
        || credentials.github_https_auth
        || credentials.git_ssh_auth;
    if git_guard_policy.is_some() != expected_guard {
        return Err(HostError::Invalid(
            "authenticated Git guard composition is inconsistent".to_owned(),
        ));
    }
    if let Some(policy) = git_guard_policy
        && (selected_runtime == ResolvedRuntime::Hyperlight
            || Some(&policy.selected_repository) != selected_repository
            || policy.branch_protection.enabled != configuration.github.branch_protection.enabled
            || policy.github_https_auth != credentials.github_https_auth
            || policy.git_ssh_auth != credentials.git_ssh_auth)
    {
        return Err(HostError::Invalid(
            "authenticated Git policy does not match the signed run configuration".to_owned(),
        ));
    }
    if let Some(policy) = mcp_policy {
        if selected_runtime == ResolvedRuntime::Hyperlight {
            return Err(HostError::Invalid(
                "Hyperlight does not support the authenticated MCP broker".to_owned(),
            ));
        }
        policy
            .validate()
            .map_err(|error| HostError::Invalid(format!("invalid MCP composition: {error}")))?;
    }
    let expected_egress_policy = make_egress_policy(selected_runtime, configuration, session_id)?;
    if expected_egress_policy.as_ref() != egress_policy {
        return Err(HostError::Invalid(
            "authenticated egress policy does not match the signed run configuration".to_owned(),
        ));
    }
    let expected_mcp_policy = make_mcp_policy(
        selected_runtime,
        configuration,
        host_workspace,
        guest_workspace,
        workload_identity,
        egress_policy,
    )?;
    if expected_mcp_policy.as_ref() != mcp_policy {
        return Err(HostError::Invalid(
            "authenticated MCP policy does not match the signed run configuration".to_owned(),
        ));
    }
    let expected_names = credentials.values.keys().cloned().collect::<Vec<_>>();
    let actual_names = configuration
        .secrets
        .iter()
        .filter_map(|value| {
            SecretName::new(value.clone())
                .ok()
                .filter(requires_guarded_github_forwarding)
                .map(|_| value.clone())
        })
        .collect::<Vec<_>>();
    if actual_names != expected_names {
        return Err(HostError::Invalid(
            "signed secret names do not match prepared credentials".to_owned(),
        ));
    }
    let expected_features = boundary_features(
        configuration,
        git_guard_policy,
        mcp_policy,
        egress_policy,
        credentials,
    )?;
    if &expected_features != features {
        return Err(HostError::Invalid(
            "signed feature admissions do not match prepared credentials".to_owned(),
        ));
    }
    Ok(())
}

/// Resolves the independent Copilot credential from the host environment.
///
/// Candidates are consulted in [`COPILOT_HOST_TOKEN_ENVIRONMENTS`] order. Only
/// an absent variable falls through to the next candidate: a variable that is
/// present but empty is a hard error, so a blanked-out primary never silently
/// resolves to a stale legacy value. Errors name the supported variables and
/// never include a credential value.
fn discover_copilot_token() -> Result<SecretValue, HostError> {
    discover_copilot_token_from(|name| std::env::var(name).ok())
}

fn discover_copilot_token_from(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<SecretValue, HostError> {
    for name in COPILOT_HOST_TOKEN_ENVIRONMENTS {
        let Some(value) = lookup(name) else {
            continue;
        };
        if value.is_empty() {
            return Err(HostError::Invalid(format!(
                "{name} is set but empty for requested Copilot forwarding"
            )));
        }
        return checked_environment_secret(COPILOT_GUEST_TOKEN_ENVIRONMENT, value.into_bytes());
    }
    Err(HostError::Invalid(format!(
        "no Copilot credential is available for requested Copilot forwarding; set one of {}",
        COPILOT_HOST_TOKEN_ENVIRONMENTS.join(", ")
    )))
}

fn checked_environment_secret(name: &str, bytes: Vec<u8>) -> Result<SecretValue, HostError> {
    if name.len().saturating_add(bytes.len()).saturating_add(1)
        > MAX_EXECUTION_ENVIRONMENT_ENTRY_BYTES
    {
        return Err(HostError::Invalid(format!(
            "credential `{name}` exceeds the guest environment entry limit"
        )));
    }
    SecretValue::new(bytes).map_err(HostError::SecretStore)
}

fn read_ssh_private_key(path: &Path) -> Result<SecretValue, HostError> {
    let path = canonical_file_or_directory(path, "Git SSH private key")?;
    let metadata = path.symlink_metadata().map_err(|source| HostError::Io {
        context: "inspect Git SSH private key",
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(HostError::Invalid(format!(
            "Git SSH private key `{}` must be an owner-only regular file",
            path.display()
        )));
    }
    let bytes = fs::read(&path).map_err(|source| HostError::Io {
        context: "read Git SSH private key",
        path: path.clone(),
        source,
    })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| HostError::Invalid("Git SSH private key must be UTF-8".to_owned()))?;
    if !text.contains("PRIVATE KEY") {
        return Err(HostError::Invalid(
            "Git SSH private key has an unsupported format".to_owned(),
        ));
    }
    checked_environment_secret(SSH_KEY_ENVIRONMENT, bytes)
}

fn gh_process_configuration() -> Result<GhProcessConfiguration, HostError> {
    let executable = trusted_gh_path()?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| HostError::Invalid("HOME is unavailable for gh".to_owned()))?;
    let home = canonical_file_or_directory(&home, "gh home directory")?;
    let config_dir = std::env::var_os("GH_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(|root| PathBuf::from(root).join("gh")))
        .unwrap_or_else(|| home.join(".config/gh"));
    GhProcessConfiguration::new(executable, config_dir, home).map_err(HostError::Credentials)
}

fn trusted_gh_path() -> Result<PathBuf, HostError> {
    [
        "/usr/local/bin/gh",
        "/opt/homebrew/bin/gh",
        "/usr/bin/gh",
        "/bin/gh",
    ]
    .into_iter()
    .filter_map(|candidate| Path::new(candidate).canonicalize().ok())
    .find_map(|candidate| TrustedGitBinary::verify(&candidate).ok().map(|_| candidate))
    .ok_or_else(|| HostError::Invalid("a trusted gh executable was not found".to_owned()))
}

fn trusted_host_git() -> Result<TrustedGitBinary, HostError> {
    [
        "/usr/bin/git",
        "/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
    ]
    .into_iter()
    .filter_map(|candidate| Path::new(candidate).canonicalize().ok())
    .find_map(|candidate| TrustedGitBinary::verify(candidate).ok())
    .ok_or_else(|| HostError::Invalid("a trusted host Git executable was not found".to_owned()))
}

fn resolve_github_username(host: &str, current_directory: &Path) -> Option<String> {
    let executable = [
        "/usr/local/bin/gh",
        "/opt/homebrew/bin/gh",
        "/usr/bin/gh",
        "/bin/gh",
    ]
    .into_iter()
    .filter_map(|candidate| Path::new(candidate).canonicalize().ok())
    .find_map(|candidate| TrustedGitBinary::verify(candidate).ok())?;
    let arguments = vec![
        "api".to_owned(),
        "--hostname".to_owned(),
        host.to_owned(),
        "user".to_owned(),
        "--jq".to_owned(),
        ".login".to_owned(),
    ];
    let environment = github_cli_environment();
    let output = SystemGitProcessRunner
        .query(&ProcessRequest {
            executable: &executable,
            arguments: &arguments,
            environment: &environment,
            current_directory,
            timeout: Duration::from_secs(5),
            output_limit: 4 * 1024,
        })
        .ok()?;
    if output.exit_code != Some(0) {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let mut lines = value.lines().map(str::trim).filter(|line| !line.is_empty());
    let username = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    Some(username.to_owned())
}

fn host_git_environment() -> BTreeMap<String, String> {
    [
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "LANG",
        "LOGNAME",
        "SSH_AUTH_SOCK",
        "TERM",
        "TMPDIR",
        "USER",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect()
}

fn github_cli_environment() -> BTreeMap<String, String> {
    let mut environment = [
        "GH_CONFIG_DIR",
        "GH_ENTERPRISE_TOKEN",
        "GH_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITHUB_TOKEN",
        "HOME",
        "LANG",
        "LC_ALL",
        "XDG_CONFIG_HOME",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect::<BTreeMap<_, _>>();
    environment.insert(
        "PATH".to_owned(),
        "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin".to_owned(),
    );
    environment.insert("GH_PROMPT_DISABLED".to_owned(), "1".to_owned());
    environment.insert("GH_NO_UPDATE_NOTIFIER".to_owned(), "1".to_owned());
    environment.insert("GH_PAGER".to_owned(), "cat".to_owned());
    environment.insert("NO_COLOR".to_owned(), "1".to_owned());
    environment
}

fn validate_command(command: &[String]) -> Result<(String, Vec<String>), HostError> {
    let Some(program) = command.first() else {
        return Err(HostError::Invalid("command is empty".to_owned()));
    };
    if !Path::new(program).is_absolute() {
        return Err(HostError::Invalid(
            "guest command must use an absolute executable path".to_owned(),
        ));
    }
    Ok((program.clone(), command[1..].to_vec()))
}

fn validate_command_policy(
    policy: &sendbox_policy::CommandPolicy,
    command: &[String],
) -> Result<(), HostError> {
    let compiled = CompiledCommandPolicy::compile(policy)
        .map_err(|error| HostError::Invalid(format!("invalid command policy: {error}")))?;
    let admission = compiled.evaluate(command);
    if admission.disposition == AdmissionDisposition::Deny {
        let source = admission.matched.source.map_or_else(
            || "default action".to_owned(),
            |rule| format!("rule `{rule}`"),
        );
        return Err(HostError::Invalid(format!(
            "guest command is denied by command policy {source}"
        )));
    }
    Ok(())
}

fn parse_oci_digest(image: &str) -> Result<String, HostError> {
    let digest = image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            HostError::Invalid(
                "persistent runtimes require IMAGE@sha256:<64 hex characters>".to_owned(),
            )
        })?;
    Ok(format!("sha256:{}", digest.to_ascii_lowercase()))
}

fn runtime_resources(configuration: &SandboxConfiguration) -> Result<RuntimeResources, HostError> {
    let cpus = u32::try_from(configuration.resources.cpus)
        .map_err(|_| HostError::Invalid("resource CPU count is out of range".to_owned()))?;
    let memory_bytes = megabytes(configuration.resources.memory_mb, "memory")?;
    if cpus == 0 || memory_bytes == 0 {
        return Err(HostError::Invalid(
            "runtime resources must be non-zero".to_owned(),
        ));
    }
    Ok(RuntimeResources { cpus, memory_bytes })
}

fn megabytes(value: i64, description: &str) -> Result<u64, HostError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| value.checked_mul(1024 * 1024))
        .ok_or_else(|| HostError::Invalid(format!("{description} is out of range")))
}

fn project_identity(path: &Path) -> Result<(u32, u32), HostError> {
    let metadata = fs::metadata(path).map_err(|source| HostError::Io {
        context: "inspect project root",
        path: path.to_path_buf(),
        source,
    })?;
    Ok((metadata.uid(), metadata.gid()))
}

fn resolve_executable(value: &str) -> Result<PathBuf, HostError> {
    let path = Path::new(value);
    if path.is_absolute() {
        return canonical_file_or_directory(path, "runtime executable");
    }
    ["/usr/local/bin", "/usr/bin", "/bin"]
        .into_iter()
        .map(|directory| Path::new(directory).join(value))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| HostError::Invalid(format!("runtime executable `{value}` was not found")))
}

fn artifact_identity(kind: ArtifactKind, path: &Path) -> Result<ArtifactIdentity, HostError> {
    let path = canonical_file_or_directory(path, "runtime artifact")?;
    Ok(ArtifactIdentity {
        kind,
        sha256: hash_file(&path)?,
        path,
    })
}

fn hash_file(path: &Path) -> Result<String, HostError> {
    let bytes = fs::read(path).map_err(|source| HostError::Io {
        context: "read file",
        path: path.to_path_buf(),
        source,
    })?;
    Ok(sha256_hex(&bytes))
}

fn assert_provider_identity(
    provider: &dyn RuntimeProvider,
    selected: ResolvedRuntime,
) -> Result<(), HostError> {
    let expected = match selected {
        ResolvedRuntime::Apple => APPLE_RUNTIME_ID,
        ResolvedRuntime::Kata => "kata",
        ResolvedRuntime::Hyperlight => "hyperlight",
    };
    if provider.runtime_id().as_str() == expected {
        Ok(())
    } else {
        Err(HostError::Invalid(format!(
            "signed runtime `{expected}` does not match provider `{}`",
            provider.runtime_id()
        )))
    }
}

fn container_id(name: &str, session_id: SessionId) -> Result<ContainerId, HostError> {
    let sanitized = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    ContainerId::new(format!("{sanitized}-{session_id}"))
        .or_else(|_| ContainerId::new(format!("sendbox-{session_id}")))
        .map_err(HostError::Runtime)
}

fn canonical_file_or_directory(path: &Path, context: &'static str) -> Result<PathBuf, HostError> {
    if !path.is_absolute() {
        return Err(HostError::Invalid(format!(
            "{context} must be an absolute path"
        )));
    }
    reject_symlink_components(path, context)?;
    fs::canonicalize(path).map_err(|source| HostError::Io {
        context,
        path: path.to_path_buf(),
        source,
    })
}

fn reject_symlink_components(path: &Path, context: &'static str) -> Result<(), HostError> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => current.push(value),
            _ => {
                return Err(HostError::Invalid(format!(
                    "{context} contains an invalid path component"
                )));
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(|source| HostError::Io {
            context,
            path: current.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(HostError::Invalid(format!(
                "{context} must not contain symbolic links"
            )));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(HostError::Invalid(format!(
                "{context} path component `{}` is group/world writable",
                current.display()
            )));
        }
    }
    Ok(())
}

fn create_session_directory(root: &Path, session_id: SessionId) -> Result<PathBuf, HostError> {
    ensure_private_directory(root)?;
    let sessions = root.join("sessions");
    ensure_private_directory(&sessions)?;
    let session = sessions.join(session_id.to_string());
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&session).map_err(|source| HostError::Io {
        context: "create session state directory",
        path: session.clone(),
        source,
    })?;
    Ok(session)
}

fn ensure_private_directory(path: &Path) -> Result<(), HostError> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|source| HostError::Io {
            context: "inspect private directory",
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != current_uid()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(HostError::Invalid(format!(
                "private directory `{}` must be user-owned, mode 0700, and not a symlink",
                path.display()
            )));
        }
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        HostError::Invalid(format!(
            "private directory `{}` has no parent",
            path.display()
        ))
    })?;
    if !parent.exists() {
        ensure_private_directory(parent)?;
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|source| HostError::Io {
        context: "create private directory",
        path: path.to_path_buf(),
        source,
    })
}

fn load_or_create_signing_key(root: &Path) -> Result<SigningKeyMaterial, HostError> {
    let identity = root.join("identity");
    ensure_private_directory(&identity)?;
    let path = identity.join("boundary-signing.key");
    if path.exists() {
        return read_signing_key(&path);
    }
    let key = SigningKeyMaterial::generate()?;
    let exported = key.export();
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(exported.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|source| HostError::Io {
                    context: "write boundary signing key",
                    path,
                    source,
                })?;
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_signing_key(&path),
        Err(source) => Err(HostError::Io {
            context: "create boundary signing key",
            path,
            source,
        }),
    }
}

fn read_signing_key(path: &Path) -> Result<SigningKeyMaterial, HostError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| HostError::Io {
        context: "inspect boundary signing key",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(HostError::Invalid(
            "boundary signing key must be user-owned, mode 0600, single-link, and not a symlink"
                .to_owned(),
        ));
    }
    let mut representation = Zeroizing::new(String::new());
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut representation))
        .map_err(|source| HostError::Io {
            context: "read boundary signing key",
            path: path.to_path_buf(),
            source,
        })?;
    SigningKeyMaterial::import(representation.trim()).map_err(HostError::Security)
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), HostError> {
    let parent = path.parent().ok_or_else(|| {
        HostError::Invalid(format!("output path `{}` has no parent", path.display()))
    })?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("sendbox"),
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
            .map_err(|source| HostError::Io {
                context: "create temporary file",
                path: temporary.clone(),
                source,
            })?;
        file.write_all(bytes).map_err(|source| HostError::Io {
            context: "write temporary file",
            path: temporary.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| HostError::Io {
            context: "sync temporary file",
            path: temporary.clone(),
            source,
        })?;
        fs::rename(&temporary, path).map_err(|source| HostError::Io {
            context: "install file",
            path: path.to_path_buf(),
            source,
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| HostError::Io {
                context: "sync parent directory",
                path: parent.to_path_buf(),
                source,
            })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn random_session_id() -> Result<SessionId, HostError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| HostError::Invalid(format!("generate session ID: {error}")))?;
    Ok(SessionId::from_bytes(bytes))
}

fn random_bootstrap_secret() -> Result<[u8; 32], HostError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| HostError::Invalid(format!("generate bootstrap secret: {error}")))?;
    Ok(bytes)
}

fn unix_time() -> Result<u64, HostError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| HostError::Invalid(format!("system clock is before Unix epoch: {error}")))
}

fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

#[cfg(test)]
mod tests {
    use sendbox_config::{PolicyPreset, RuntimeProvider as ConfigRuntimeProvider};
    use sendbox_policy::Action;
    use tempfile::TempDir;

    use super::*;

    fn supported_configuration(project_path: PathBuf) -> SandboxConfiguration {
        let mut configuration = SandboxConfiguration::for_project(
            project_path,
            PolicyPreset::Permissive,
            ConfigRuntimeProvider::Auto,
        );
        configuration.github.forward_auth = false;
        configuration.github.forward_copilot_auth = false;
        configuration.github.allow_private_repository_access = false;
        configuration.github.branch_protection.enabled = false;
        configuration.github.ssh_key_path = None;
        if let Some(observability) = &mut configuration.observability {
            observability.mcp_inspection.enabled = false;
        }
        configuration
    }

    fn test_session() -> SessionId {
        SessionId::from_bytes([0x42; 16])
    }

    fn secure_tempdir() -> TempDir {
        let base = std::env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("canonical test base");
        tempfile::tempdir_in(base).expect("secure temporary directory")
    }

    #[test]
    fn host_security_policies_fail_closed_or_compose() {
        let temp = TempDir::new().expect("temp dir");

        let mut mcp = supported_configuration(temp.path().to_path_buf());
        mcp.policy.boundaries.tool_calls.allowed_server_commands =
            vec![vec!["/usr/bin/mcp-server".to_owned()]];
        let inspection = &mut mcp
            .observability
            .as_mut()
            .expect("observability")
            .mcp_inspection;
        inspection.enabled = true;
        inspection.transports = vec![InspectionTransport::Stdio, InspectionTransport::Http];
        let error = make_mcp_policy(
            ResolvedRuntime::Kata,
            &mcp,
            temp.path(),
            Path::new("/workspace"),
            Some((1000, 1000)),
            None,
        )
        .expect_err("HTTP inspection must be rejected");
        assert!(matches!(
            error,
            HostError::Invalid(message)
                if message
                    == "HTTP/SSE MCP inspection is not available in the authenticated native runtime; configure stdio inspection only"
        ));

        let mut egress = supported_configuration(temp.path().to_path_buf());
        egress.policy.network.default_action = Action::Deny;
        let policy = make_egress_policy(ResolvedRuntime::Kata, &egress, test_session())
            .expect("egress policy")
            .expect("restrictive network");
        assert_eq!(policy.network_policy, egress.policy.network);
        assert!(make_egress_policy(ResolvedRuntime::Hyperlight, &egress, test_session()).is_err());
    }

    #[test]
    fn native_mcp_policy_validates_project_configuration_and_binds_features() {
        let temp = TempDir::new().expect("temp dir");
        fs::write(
            temp.path().join(".mcp.json"),
            r#"{
                "mcpServers": {
                    "fixture": {
                        "type": "stdio",
                        "command": "/run/sendbox-boundary/mcp-broker",
                        "args": ["--", "/usr/bin/mcp-server", "--stdio"]
                    }
                }
            }"#,
        )
        .expect("MCP configuration");
        let mut configuration = supported_configuration(temp.path().to_path_buf());
        configuration
            .policy
            .boundaries
            .tool_calls
            .allowed_server_commands =
            vec![vec!["/usr/bin/mcp-server".to_owned(), "--stdio".to_owned()]];
        let inspection = &mut configuration
            .observability
            .as_mut()
            .expect("observability")
            .mcp_inspection;
        inspection.enabled = true;
        inspection.transports = vec![InspectionTransport::Stdio];

        let policy = make_mcp_policy(
            ResolvedRuntime::Kata,
            &configuration,
            temp.path(),
            Path::new("/workspace"),
            Some((1000, 1000)),
            None,
        )
        .expect("MCP policy")
        .expect("MCP composition");
        assert_eq!(policy.workspace_root, Path::new("/workspace"));
        assert_eq!(
            runtime_environment(Some(&policy), None)[0].value,
            NATIVE_BROKER_PATH
        );
        let credentials = EffectiveCredentialSet {
            values: BTreeMap::new(),
            github_https_auth: false,
            copilot_auth: false,
            git_ssh_auth: false,
        };
        let features = boundary_features(&configuration, None, Some(&policy), None, &credentials)
            .expect("MCP features");
        assert!(features.contains_key("mcp_stdio_broker"));
        assert!(features.contains_key("mcp_stdio_observation"));
        validate_security_composition(SecurityComposition {
            selected_runtime: ResolvedRuntime::Kata,
            configuration: &configuration,
            selected_repository: None,
            host_workspace: temp.path(),
            guest_workspace: Path::new("/workspace"),
            workload_identity: Some((1000, 1000)),
            session_id: test_session(),
            git_guard_policy: None,
            mcp_policy: Some(&policy),
            egress_policy: None,
            credentials: &credentials,
            features: &features,
        })
        .expect("consistent MCP composition");

        let mut drifted = policy.clone();
        drifted
            .fixed_environment
            .insert("PATH".to_owned(), "/tmp/bin".to_owned());
        let drifted_features =
            boundary_features(&configuration, None, Some(&drifted), None, &credentials)
                .expect("drifted features");
        assert!(
            validate_security_composition(SecurityComposition {
                selected_runtime: ResolvedRuntime::Kata,
                configuration: &configuration,
                selected_repository: None,
                host_workspace: temp.path(),
                guest_workspace: Path::new("/workspace"),
                workload_identity: Some((1000, 1000)),
                session_id: test_session(),
                git_guard_policy: None,
                mcp_policy: Some(&drifted),
                egress_policy: None,
                credentials: &credentials,
                features: &drifted_features,
            })
            .is_err()
        );
    }

    #[test]
    fn native_mcp_policy_rejects_unbrokered_project_server() {
        let temp = TempDir::new().expect("temp dir");
        fs::write(
            temp.path().join(".mcp.json"),
            r#"{
                "mcpServers": {
                    "fixture": {
                        "type": "stdio",
                        "command": "/usr/bin/mcp-server",
                        "args": ["--stdio"]
                    }
                }
            }"#,
        )
        .expect("MCP configuration");
        let mut configuration = supported_configuration(temp.path().to_path_buf());
        configuration
            .policy
            .boundaries
            .tool_calls
            .allowed_server_commands =
            vec![vec!["/usr/bin/mcp-server".to_owned(), "--stdio".to_owned()]];
        let error = make_mcp_policy(
            ResolvedRuntime::Kata,
            &configuration,
            temp.path(),
            Path::new("/workspace"),
            Some((1000, 1000)),
            None,
        )
        .expect_err("unbrokered MCP must fail");
        assert!(matches!(
            error,
            HostError::Invalid(message) if message.contains("approved broker prefix")
        ));
    }

    #[test]
    fn authenticated_egress_binds_runtime_mcp_features_and_drift() {
        let temp = TempDir::new().expect("temp dir");
        let mut configuration = supported_configuration(temp.path().to_path_buf());
        configuration.policy.network.default_action = Action::Deny;
        configuration
            .policy
            .boundaries
            .tool_calls
            .allowed_server_commands = vec![vec!["/usr/bin/mcp-server".to_owned()]];
        let egress = make_egress_policy(ResolvedRuntime::Kata, &configuration, test_session())
            .expect("egress policy")
            .expect("restrictive network");
        let credentials = EffectiveCredentialSet {
            values: BTreeMap::new(),
            github_https_auth: false,
            copilot_auth: false,
            git_ssh_auth: false,
        };

        let egress_only =
            boundary_features(&configuration, None, None, Some(&egress), &credentials)
                .expect("egress features");
        assert!(egress_only.contains_key("network_egress_enforcement"));
        assert!(egress_only.contains_key("network_dns_broker"));

        let mcp = make_mcp_policy(
            ResolvedRuntime::Kata,
            &configuration,
            temp.path(),
            Path::new("/workspace"),
            Some((1000, 1000)),
            Some(&egress),
        )
        .expect("MCP policy")
        .expect("MCP composition");
        for (name, value) in &egress.proxy_environment {
            assert_eq!(mcp.fixed_environment.get(name), Some(value));
        }
        let environment = runtime_environment(Some(&mcp), Some(&egress))
            .into_iter()
            .map(|entry| (entry.name, entry.value))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment.get(MCP_PROXY_ENVIRONMENT).map(String::as_str),
            Some(NATIVE_BROKER_PATH)
        );
        for (name, value) in &egress.proxy_environment {
            assert_eq!(environment.get(name), Some(value));
        }

        let features = boundary_features(
            &configuration,
            None,
            Some(&mcp),
            Some(&egress),
            &credentials,
        )
        .expect("composed features");
        let admission = features
            .get("network_egress_enforcement")
            .expect("egress feature");
        assert_eq!(
            admission.mechanism,
            format!(
                "authenticated_guest_egress_v1:sha256={}",
                sha256_hex(&serde_json::to_vec(&egress).expect("egress JSON"))
            )
        );
        validate_security_composition(SecurityComposition {
            selected_runtime: ResolvedRuntime::Kata,
            configuration: &configuration,
            selected_repository: None,
            host_workspace: temp.path(),
            guest_workspace: Path::new("/workspace"),
            workload_identity: Some((1000, 1000)),
            session_id: test_session(),
            git_guard_policy: None,
            mcp_policy: Some(&mcp),
            egress_policy: Some(&egress),
            credentials: &credentials,
            features: &features,
        })
        .expect("consistent egress composition");

        let mut drifted = egress.clone();
        drifted.broker_mark ^= 2;
        let drifted_features = boundary_features(
            &configuration,
            None,
            Some(&mcp),
            Some(&drifted),
            &credentials,
        )
        .expect("drifted features");
        assert!(
            validate_security_composition(SecurityComposition {
                selected_runtime: ResolvedRuntime::Kata,
                configuration: &configuration,
                selected_repository: None,
                host_workspace: temp.path(),
                guest_workspace: Path::new("/workspace"),
                workload_identity: Some((1000, 1000)),
                session_id: test_session(),
                git_guard_policy: None,
                mcp_policy: Some(&mcp),
                egress_policy: Some(&drifted),
                credentials: &credentials,
                features: &drifted_features,
            })
            .is_err()
        );
    }

    #[test]
    fn hyperlight_rejects_configured_secrets() {
        let temp = TempDir::new().expect("temp dir");
        let mut configuration = supported_configuration(temp.path().to_path_buf());
        configuration.secrets.push("TOKEN".to_owned());
        let error = validate_runtime_features(ResolvedRuntime::Hyperlight, &configuration)
            .expect_err("Hyperlight secrets must fail closed");
        assert!(matches!(
            error,
            HostError::Invalid(message)
                if message
                    == "Hyperlight does not support authenticated configured-secret delivery"
        ));
        validate_runtime_features(ResolvedRuntime::Kata, &configuration)
            .expect("persistent runtime supports configured secrets");

        configuration.secrets.clear();
        configuration.github.branch_protection.enabled = true;
        let error = validate_runtime_features(ResolvedRuntime::Hyperlight, &configuration)
            .expect_err("Hyperlight Git guard must fail closed");
        assert!(matches!(
            error,
            HostError::Invalid(message)
                if message == "Hyperlight does not support authenticated Git or credential delivery"
        ));
        validate_runtime_features(ResolvedRuntime::Kata, &configuration)
            .expect("persistent runtime supports the Git guard");
    }

    #[test]
    fn git_guard_is_admitted_and_bound_into_boundary_features() {
        let temp = TempDir::new().expect("temp dir");
        let mut configuration = supported_configuration(temp.path().to_path_buf());
        configuration.github.branch_protection.enabled = true;

        let policy = GuardPolicyDocument {
            schema_version: PolicySchemaVersion::V1,
            selected_repository: sendbox_git::RepositoryIdentity::new(
                "github.com",
                "owner",
                "repository",
            )
            .expect("repository"),
            selected_workspace: PathBuf::from("/workspace"),
            branch_protection: BranchPolicyConfiguration::default(),
            environment: EnvironmentPolicy::default(),
            github_https_auth: false,
            git_ssh_auth: false,
            limits: GuardLimits::default(),
        };
        let credentials = EffectiveCredentialSet {
            values: BTreeMap::new(),
            github_https_auth: false,
            copilot_auth: false,
            git_ssh_auth: false,
        };
        let first = boundary_features(&configuration, Some(&policy), None, None, &credentials)
            .expect("features");
        let second = boundary_features(&configuration, Some(&policy), None, None, &credentials)
            .expect("features");
        assert_eq!(first, second);
        let admission = first
            .get("git_branch_protection")
            .expect("Git feature admission");
        assert_eq!(admission.decision, FeatureDecision::Enforced);
        assert!(
            admission
                .mechanism
                .starts_with("authenticated_guest_git_guard_v1:sha256=")
        );
    }
    #[test]
    fn auth_only_and_ssh_only_runs_install_the_transport_guard() {
        let temp = TempDir::new().expect("temp dir");
        let repository =
            RepositoryIdentity::new("github.com", "owner", "repository").expect("repository");
        let workspace = temp.path().to_path_buf();

        let mut auth_configuration = supported_configuration(workspace.clone());
        auth_configuration.github.forward_auth = true;
        let auth_credentials = EffectiveCredentialSet {
            values: BTreeMap::from([(
                GITHUB_TOKEN_ENVIRONMENT.to_owned(),
                SecretValue::try_from("token").expect("token"),
            )]),
            github_https_auth: true,
            copilot_auth: false,
            git_ssh_auth: false,
        };
        let auth_policy = make_git_guard_policy(
            ResolvedRuntime::Kata,
            &auth_configuration,
            Some(&repository),
            &workspace,
            Path::new("/workspace"),
            &auth_credentials,
        )
        .expect("auth policy")
        .expect("transport guard");
        assert!(!auth_policy.branch_protection.enabled);
        assert!(auth_policy.github_https_auth);

        let mut ssh_configuration = supported_configuration(workspace.clone());
        ssh_configuration.github.ssh_key_path = Some(workspace.join("id"));
        let ssh_credentials = EffectiveCredentialSet {
            values: BTreeMap::from([(
                SSH_KEY_ENVIRONMENT.to_owned(),
                SecretValue::try_from("-----BEGIN PRIVATE KEY-----").expect("private key"),
            )]),
            github_https_auth: false,
            copilot_auth: false,
            git_ssh_auth: true,
        };
        let ssh_policy = make_git_guard_policy(
            ResolvedRuntime::Apple,
            &ssh_configuration,
            Some(&repository),
            &workspace,
            Path::new("/workspace"),
            &ssh_credentials,
        )
        .expect("SSH policy")
        .expect("transport guard");
        assert!(ssh_policy.git_ssh_auth);
    }

    #[test]
    fn reserved_credentials_cannot_come_from_the_general_secret_store() {
        let temp = TempDir::new().expect("temp dir");
        let mut configuration = supported_configuration(temp.path().to_path_buf());
        configuration.secrets.push("github_token".to_owned());
        let error = validate_reserved_secret_names(&configuration)
            .expect_err("reserved credential must fail");
        assert!(matches!(
            error,
            HostError::Invalid(message)
                if message
                    == "configured secret `github_token` requires guarded credential forwarding"
        ));
    }

    #[test]
    fn security_composition_rejects_feature_and_secret_drift() {
        let temp = TempDir::new().expect("temp dir");
        let workspace = temp.path().to_path_buf();
        let repository =
            RepositoryIdentity::new("github.com", "owner", "repository").expect("repository");
        let mut configuration = supported_configuration(workspace.clone());
        configuration.github.forward_auth = true;
        let credentials = EffectiveCredentialSet {
            values: BTreeMap::from([(
                GITHUB_TOKEN_ENVIRONMENT.to_owned(),
                SecretValue::try_from("token").expect("token"),
            )]),
            github_https_auth: true,
            copilot_auth: false,
            git_ssh_auth: false,
        };
        credentials.apply_to(&mut configuration);
        let policy = make_git_guard_policy(
            ResolvedRuntime::Kata,
            &configuration,
            Some(&repository),
            &workspace,
            Path::new("/workspace"),
            &credentials,
        )
        .expect("policy");
        let mut features =
            boundary_features(&configuration, policy.as_ref(), None, None, &credentials)
                .expect("features");
        validate_security_composition(SecurityComposition {
            selected_runtime: ResolvedRuntime::Kata,
            configuration: &configuration,
            selected_repository: Some(&repository),
            host_workspace: &workspace,
            guest_workspace: Path::new("/workspace"),
            workload_identity: None,
            session_id: test_session(),
            git_guard_policy: policy.as_ref(),
            mcp_policy: None,
            egress_policy: None,
            credentials: &credentials,
            features: &features,
        })
        .expect("consistent composition");

        features.remove("github_repository_credentials");
        assert!(
            validate_security_composition(SecurityComposition {
                selected_runtime: ResolvedRuntime::Kata,
                configuration: &configuration,
                selected_repository: Some(&repository),
                host_workspace: &workspace,
                guest_workspace: Path::new("/workspace"),
                workload_identity: None,
                session_id: test_session(),
                git_guard_policy: policy.as_ref(),
                mcp_policy: None,
                egress_policy: None,
                credentials: &credentials,
                features: &features,
            })
            .is_err()
        );
        configuration.secrets.clear();
        assert!(
            validate_security_composition(SecurityComposition {
                selected_runtime: ResolvedRuntime::Kata,
                configuration: &configuration,
                selected_repository: Some(&repository),
                host_workspace: &workspace,
                guest_workspace: Path::new("/workspace"),
                workload_identity: None,
                session_id: test_session(),
                git_guard_policy: policy.as_ref(),
                mcp_policy: None,
                egress_policy: None,
                credentials: &credentials,
                features: &boundary_features(
                    &configuration,
                    policy.as_ref(),
                    None,
                    None,
                    &credentials,
                )
                .expect("features"),
            })
            .is_err()
        );
    }

    #[test]
    fn ssh_private_keys_require_owner_only_files_and_execution_size() {
        let temp = secure_tempdir();
        let root = temp.path();
        let key = root.join("id");
        fs::write(
            &key,
            "-----BEGIN PRIVATE KEY-----\nvalue\n-----END PRIVATE KEY-----\n",
        )
        .expect("write key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(read_ssh_private_key(&key).is_err());

        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("mode");
        read_ssh_private_key(&key).expect("valid key");
        fs::write(
            &key,
            format!("-----BEGIN PRIVATE KEY-----\n{}\n", "x".repeat(4096)),
        )
        .expect("large key");
        assert!(read_ssh_private_key(&key).is_err());
    }

    #[test]
    fn host_admits_entry_commands_through_shared_policy() {
        let temp = TempDir::new().expect("temp dir");
        let mut configuration = supported_configuration(temp.path().to_path_buf());
        configuration.policy.commands.default_action = Action::Allow;
        configuration.policy.commands.denylist = vec!["true".to_owned()];

        let error =
            validate_command_policy(&configuration.policy.commands, &["/bin/true".to_owned()])
                .expect_err("basename deny rule must reject absolute entry command");
        assert!(matches!(
            error,
            HostError::Invalid(message)
                if message == "guest command is denied by command policy rule `true`"
        ));
    }

    #[test]
    fn copilot_discovery_prefers_the_supported_variable_over_the_legacy_one() {
        let token = discover_copilot_token_from(|name| match name {
            "COPILOT_GITHUB_TOKEN" => Some("supported-token".to_owned()),
            "GITHUB_COPILOT_TOKEN" => Some("legacy-token".to_owned()),
            _ => None,
        })
        .expect("supported variable must resolve");

        assert_eq!(token.expose_secret(), b"supported-token");
    }

    #[test]
    fn copilot_discovery_falls_back_to_the_legacy_variable() {
        let token = discover_copilot_token_from(|name| {
            (name == "GITHUB_COPILOT_TOKEN").then(|| "legacy-token".to_owned())
        })
        .expect("legacy variable must remain supported");

        assert_eq!(token.expose_secret(), b"legacy-token");
    }

    #[test]
    fn copilot_discovery_rejects_an_empty_supported_variable_without_legacy_fallback() {
        let error = discover_copilot_token_from(|name| match name {
            "COPILOT_GITHUB_TOKEN" => Some(String::new()),
            "GITHUB_COPILOT_TOKEN" => Some("legacy-token".to_owned()),
            _ => None,
        })
        .expect_err("a blanked-out supported variable must fail closed");

        assert!(matches!(
            error,
            HostError::Invalid(message)
                if message == "COPILOT_GITHUB_TOKEN is set but empty for requested Copilot forwarding"
        ));
    }

    #[test]
    fn copilot_discovery_names_every_supported_variable_when_absent() {
        let error = discover_copilot_token_from(|_| None)
            .expect_err("missing Copilot credentials must fail closed");

        let HostError::Invalid(message) = error else {
            panic!("expected an invalid-configuration error");
        };
        assert!(message.contains("COPILOT_GITHUB_TOKEN"));
        assert!(message.contains("GITHUB_COPILOT_TOKEN"));
    }

    #[test]
    fn copilot_discovery_ignores_repository_scoped_github_credentials() {
        let error = discover_copilot_token_from(|name| {
            matches!(name, "GH_TOKEN" | "GITHUB_TOKEN").then(|| "repository-token".to_owned())
        })
        .expect_err("Copilot forwarding must stay independent of repository credentials");

        assert!(matches!(error, HostError::Invalid(_)));
    }

    #[test]
    fn copilot_errors_never_disclose_credential_values() {
        const SENTINEL: &str = "ghu_supersecretcopilotcredential";
        let oversized = SENTINEL.repeat(MAX_EXECUTION_ENVIRONMENT_ENTRY_BYTES);
        let error = discover_copilot_token_from(|name| {
            (name == "COPILOT_GITHUB_TOKEN").then(|| oversized.clone())
        })
        .expect_err("oversized credentials must fail closed");

        let HostError::Invalid(message) = error else {
            panic!("expected an invalid-configuration error");
        };
        assert!(
            !message.contains(SENTINEL),
            "error disclosed the credential: {message}"
        );
    }

    #[test]
    fn prepared_copilot_credentials_only_expose_the_supported_guest_variable() {
        let temp = TempDir::new().expect("temp dir");
        let mut configuration = supported_configuration(temp.path().to_path_buf());
        configuration.github.forward_auth = false;
        configuration.github.forward_copilot_auth = true;

        let credentials = collect_credential_values(
            &configuration,
            GitHubSessionCredentials {
                github_token: None,
                copilot_token: Some(SecretValue::new(b"guest-token".to_vec()).expect("secret")),
            },
        )
        .expect("Copilot-only forwarding must prepare credentials");

        assert!(credentials.copilot_auth);
        assert!(!credentials.github_https_auth);
        assert_eq!(
            credentials.values.keys().collect::<Vec<_>>(),
            vec!["COPILOT_GITHUB_TOKEN"],
            "the legacy variable must never reach the guest"
        );
    }

    #[test]
    fn host_rejects_command_policy_grammar_errors() {
        let temp = TempDir::new().expect("temp dir");
        let mut configuration = supported_configuration(temp.path().to_path_buf());
        configuration.policy.commands.allowlist = vec!["tool\\".to_owned()];

        let error =
            validate_command_policy(&configuration.policy.commands, &["/bin/true".to_owned()])
                .expect_err("malformed command policy must fail closed");
        assert!(matches!(
            error,
            HostError::Invalid(message)
                if message == "invalid command policy: allowlist[0] ends with an incomplete backslash escape"
        ));
    }
}
