#![forbid(unsafe_code)]

mod security;

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sendbox_agent::{
    AgentOrchestrator, AgentReport, AgentRequest, BoxFuture, EnvironmentIntent, GuestCommand,
    GuestTerminal, OutputSink, ProtocolGuestConnector, RunFailure, RunPlan, SecretEnvelope,
    SecretReference, SecretResolver, SignalSource,
};
use sendbox_boundary::{
    Architecture, ArtifactIdentity, ArtifactKind, BOUNDARY_PLAN_FORMAT, BOUNDARY_PLAN_VERSION,
    BoundaryError, BoundaryPlan, CommandDeclaration, ControlTransport, EnvironmentDeclaration,
    FeatureAdmission, FeatureDecision, HostPlatform, MountDeclaration, OperatingSystem,
    ProviderDeclaration, ResolvedRuntime, ResourceDeclaration, SignedBoundaryPlan,
    TrustDeclaration, VerifiedBoundaryPlan, WorkloadIdentity, select_runtime, sha256_hex,
};
use sendbox_bundle::{Architecture as BundleArchitecture, VerifyOptions, verify_bundle};
use sendbox_config::{RuntimeProvider as ConfiguredRuntime, SandboxConfiguration};
use sendbox_core::{SessionId, VERSION};
use sendbox_credentials::{
    CredentialBrokerError, GhMetadataClient, GhProcessConfiguration, GitHubSessionCredentials,
    RepositoryIdentity as CredentialRepositoryIdentity, authorize_github,
};
use sendbox_exec::{AdmissionDisposition, CompiledCommandPolicy};
use sendbox_git::{
    BranchPolicyConfiguration, EnvironmentPolicy, GITHUB_TOKEN_ENVIRONMENT, GitProcessRunner,
    GuardError, GuardLimits, GuardPolicyDocument, PolicySchemaVersion, ProcessRequest,
    RepositoryIdentity, SSH_KEY_ENVIRONMENT, SystemGitProcessRunner, TrustedGitBinary,
    discover_repository_identity,
};
use sendbox_policy::{Action, DnsPolicy};
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
use zeroize::Zeroizing;

const PLAN_VALIDITY: Duration = Duration::from_secs(60 * 60);
const COPILOT_TOKEN_ENVIRONMENT: &str = "GITHUB_COPILOT_TOKEN";
const MAX_EXECUTION_ENVIRONMENT_ENTRY_BYTES: usize = 4 * 1024;
const MAX_EXECUTION_ENVIRONMENT_BYTES: usize = 16 * 1024;
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

    pub async fn execute(
        self,
        output: Arc<dyn OutputSink>,
        signals: Arc<dyn SignalSource>,
        cancellation: &CancellationToken,
    ) -> Result<HostRunReport, HostError> {
        let runtime = execute_runtime(self.execution, self.secrets, output, signals, cancellation);
        security::execute(self.security, runtime, cancellation).await
    }
}

pub async fn prepare(mut request: HostRunRequest) -> Result<PreparedHostRun, HostError> {
    request
        .configuration
        .validate()
        .map_err(|error| HostError::Invalid(error.to_string()))?;
    validate_reserved_secret_names(&request.configuration)?;
    if let Some(error) = unavailable_run_feature(&request.configuration) {
        return Err(HostError::Invalid(error.to_owned()));
    }
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
    let git_guard_policy = make_git_guard_policy(
        selected_runtime,
        &request.configuration,
        selected_repository.as_ref(),
        &workspace_source,
        &workspace_destination,
        &credentials,
    )?;
    let features = boundary_features(
        &request.configuration,
        git_guard_policy.as_ref(),
        &credentials,
    )?;
    validate_security_composition(
        selected_runtime,
        &request.configuration,
        selected_repository.as_ref(),
        git_guard_policy.as_ref(),
        &credentials,
        &features,
    )?;

    ensure_private_directory(&request.state_root)?;
    let state_root = canonical_file_or_directory(&request.state_root, "runtime state root")?;
    let session_id = random_session_id()?;
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
        git_guard_policy.as_ref(),
    )?;
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
        mounts: Vec::new(),
        environment: Vec::<EnvironmentDeclaration>::new(),
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
                environment: Vec::<EnvironmentIntent>::new(),
                mounts: Vec::new(),
                bootstrap_reference,
                readiness_timeout: request.readiness_timeout,
            };
            let plan = RunPlan::compile(
                &request.configuration,
                agent_request,
                &provider.capabilities(),
                now_unix,
            )?;
            HostExecution::Persistent { provider, plan }
        }
        RuntimeInstance::Hyperlight(provider) => {
            assert_provider_identity(provider.as_ref(), selected_runtime)?;
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
    })
}

async fn execute_runtime(
    execution: HostExecution,
    secrets: Arc<HostSecretResolver>,
    output: Arc<dyn OutputSink>,
    signals: Arc<dyn SignalSource>,
    cancellation: &CancellationToken,
) -> Result<HostRunReport, HostError> {
    match execution {
        HostExecution::Persistent { provider, plan } => {
            let orchestrator = AgentOrchestrator::new(
                provider,
                secrets,
                Arc::new(ProtocolGuestConnector),
                output,
                signals,
            );
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
    git_guard_policy: Option<&GuardPolicyDocument>,
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
            let (workload_uid, workload_gid) = project_identity(workspace_source)?;
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
            let (workload_uid, workload_gid) = project_identity(workspace_source)?;
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

fn unavailable_run_feature(configuration: &SandboxConfiguration) -> Option<&'static str> {
    if configuration
        .observability
        .as_ref()
        .is_some_and(|value| value.mcp_inspection.enabled)
    {
        return Some("production run does not yet wire the native MCP subsystem");
    }
    let network = &configuration.policy.network;
    if network.default_action != Action::Allow
        || !network.allowed_domains.is_empty()
        || !network.blocked_domains.is_empty()
        || !network.allowed_networks.is_empty()
        || !network.blocked_networks.is_empty()
        || !network.allowed_ports.is_empty()
        || !network.allow_dns
        || network.max_connections.is_some()
        || network.dns != DnsPolicy::default()
    {
        return Some("production run does not yet wire production egress enforcement");
    }
    None
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
    Ok(())
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

fn boundary_features(
    configuration: &SandboxConfiguration,
    git_guard_policy: Option<&GuardPolicyDocument>,
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
                mechanism: "independent_copilot_token+secret_envelope_v2".to_owned(),
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
        let value = std::env::var(COPILOT_TOKEN_ENVIRONMENT).map_err(|_| {
            HostError::Invalid(format!(
                "{COPILOT_TOKEN_ENVIRONMENT} is unavailable for requested Copilot forwarding"
            ))
        })?;
        Some(checked_environment_secret(
            COPILOT_TOKEN_ENVIRONMENT,
            value.into_bytes(),
        )?)
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

    let mut values = BTreeMap::new();
    if let Some(value) = github.github_token {
        values.insert(
            GITHUB_TOKEN_ENVIRONMENT.to_owned(),
            checked_environment_secret(GITHUB_TOKEN_ENVIRONMENT, value.expose_secret().to_vec())?,
        );
    }
    if let Some(value) = github.copilot_token {
        values.insert(
            COPILOT_TOKEN_ENVIRONMENT.to_owned(),
            checked_environment_secret(COPILOT_TOKEN_ENVIRONMENT, value.expose_secret().to_vec())?,
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
        copilot_auth: values.contains_key(COPILOT_TOKEN_ENVIRONMENT),
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

fn validate_security_composition(
    selected_runtime: ResolvedRuntime,
    configuration: &SandboxConfiguration,
    selected_repository: Option<&RepositoryIdentity>,
    git_guard_policy: Option<&GuardPolicyDocument>,
    credentials: &EffectiveCredentialSet,
    features: &BTreeMap<String, FeatureAdmission>,
) -> Result<(), HostError> {
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
    let expected_features = boundary_features(configuration, git_guard_policy, credentials)?;
    if &expected_features != features {
        return Err(HostError::Invalid(
            "signed feature admissions do not match prepared credentials".to_owned(),
        ));
    }
    Ok(())
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
        assert_eq!(unavailable_run_feature(&configuration), None);
        configuration
    }

    fn request(temp: &TempDir, configuration: SandboxConfiguration) -> HostRunRequest {
        HostRunRequest {
            requested_runtime: RequestedRuntime::Auto,
            configuration,
            image: None,
            bundle_root: temp.path().join("missing-bundle"),
            trust_root: temp.path().join("missing-trust-root"),
            trust_root_id: "test-root".to_owned(),
            minimum_release_sequence: 1,
            command: vec!["/bin/true".to_owned()],
            state_root: temp.path().join("state"),
            readiness_timeout: Duration::from_secs(1),
        }
    }

    async fn assert_prepare_rejects(request: HostRunRequest, expected: &str) {
        let error = match prepare(request).await {
            Ok(_) => panic!("unsupported feature must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, HostError::Invalid(message) if message == expected));
    }

    #[tokio::test]
    async fn direct_host_api_rejects_uncomposed_security_features() {
        let temp = TempDir::new().expect("temp dir");

        let mut mcp = supported_configuration(temp.path().to_path_buf());
        mcp.observability
            .as_mut()
            .expect("observability")
            .mcp_inspection
            .enabled = true;
        assert_prepare_rejects(
            request(&temp, mcp),
            "production run does not yet wire the native MCP subsystem",
        )
        .await;

        let mut credentials = supported_configuration(temp.path().to_path_buf());
        credentials.github.forward_auth = true;
        assert_eq!(unavailable_run_feature(&credentials), None);

        let mut egress = supported_configuration(temp.path().to_path_buf());
        egress.policy.network.default_action = Action::Deny;
        assert_prepare_rejects(
            request(&temp, egress),
            "production run does not yet wire production egress enforcement",
        )
        .await;
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
        assert_eq!(unavailable_run_feature(&configuration), None);

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
        let first =
            boundary_features(&configuration, Some(&policy), &credentials).expect("features");
        let second =
            boundary_features(&configuration, Some(&policy), &credentials).expect("features");
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
            boundary_features(&configuration, policy.as_ref(), &credentials).expect("features");
        validate_security_composition(
            ResolvedRuntime::Kata,
            &configuration,
            Some(&repository),
            policy.as_ref(),
            &credentials,
            &features,
        )
        .expect("consistent composition");

        features.remove("github_repository_credentials");
        assert!(
            validate_security_composition(
                ResolvedRuntime::Kata,
                &configuration,
                Some(&repository),
                policy.as_ref(),
                &credentials,
                &features,
            )
            .is_err()
        );
        configuration.secrets.clear();
        assert!(
            validate_security_composition(
                ResolvedRuntime::Kata,
                &configuration,
                Some(&repository),
                policy.as_ref(),
                &credentials,
                &boundary_features(&configuration, policy.as_ref(), &credentials)
                    .expect("features"),
            )
            .is_err()
        );
    }

    #[test]
    fn ssh_private_keys_require_owner_only_files_and_execution_size() {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temporary");
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
