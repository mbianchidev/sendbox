#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::IpAddr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt as CapDirBuilderExt, MetadataExt as CapMetadataExt,
};
use ipnet::IpNet;
use sendbox_bundle::{Architecture, VerifiedBundle, VerifyOptions, verify_bundle_artifacts};
use sendbox_egress::{address, domain};
use sendbox_guest::{
    manifest::{ArtifactKind, encode_hex},
    secure_fs::open_directory_no_symlinks,
};
use sendbox_runtime::{
    BootstrapMaterial, BoxFuture, CancellationToken, CleanupFailure, CleanupReport,
    CommandArgument, CommandSpec, ContainerId, ControlChannelRequest, ExecPurpose, ExecRequest,
    InitializeRequest, LifecycleState, LifecycleStateMachine, LifecycleTransitionError,
    OutputSubscription, PreflightReport, PreflightRequest, ProcessOptions, ProcessOutcome,
    ProcessRunner, Program, RuntimeCapabilities, RuntimeCapability, RuntimeError, RuntimeHealth,
    RuntimeId, RuntimeProvider, RuntimeSignal, RuntimeStatus, SearchPathResolver, StartRequest,
    StopRequest, VecOutputSubscription,
};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Mutex, Notify},
    task::JoinHandle,
};

pub const AUTHENTICATED_BOOTSTRAP_GUEST_DIRECTORY: &str = "/run/sendbox-control";
pub const AUTHENTICATED_BOOTSTRAP_GUEST_PATH: &str = "/run/sendbox-control/bootstrap-material";

const HOST_PATH: &str = "/usr/bin:/bin";
const HOST_LANG: &str = "C";
const MAX_MEMORY_MIB: u64 = 1024 * 1024;
const MAX_STACK_MIB: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HyperlightMount {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HyperlightNetworkMode {
    Disabled,
    AllowAll,
    AllowList,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HyperlightNetworkConfiguration {
    pub mode: HyperlightNetworkMode,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    pub allowed_addresses: Vec<String>,
    pub blocked_addresses: Vec<String>,
    pub allow_dns: bool,
    pub max_connections: Option<u32>,
    pub custom_dns_controls: bool,
    pub destination_port_rules: bool,
}

impl Default for HyperlightNetworkConfiguration {
    fn default() -> Self {
        Self {
            mode: HyperlightNetworkMode::Disabled,
            allowed_hosts: Vec::new(),
            blocked_hosts: Vec::new(),
            allowed_addresses: Vec::new(),
            blocked_addresses: Vec::new(),
            allow_dns: true,
            max_connections: None,
            custom_dns_controls: false,
            destination_port_rules: false,
        }
    }
}

#[derive(Clone)]
pub struct HyperlightConfiguration {
    pub executable: PathBuf,
    pub expected_cli_version: String,
    pub bundle_root: PathBuf,
    pub public_key: PathBuf,
    pub trust_root_id: String,
    pub expected_host_version: String,
    pub expected_guest_version: String,
    pub minimum_release_sequence: u64,
    pub kernel_path: PathBuf,
    pub initrd_path: Option<PathBuf>,
    pub memory_mib: u64,
    pub stack_mib: u64,
    pub working_directory: PathBuf,
    pub start_command: Option<CommandSpec>,
    pub mounts: Vec<HyperlightMount>,
    pub network: HyperlightNetworkConfiguration,
    pub listen_ports: Vec<u16>,
    pub process_options: ProcessOptions,
}

pub struct AuthenticatedLaunchRequest {
    pub command: CommandSpec,
    pub bootstrap_material: BootstrapMaterial,
    pub listen_ports: Vec<u16>,
}

impl std::fmt::Debug for HyperlightConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HyperlightConfiguration")
            .field("executable", &self.executable)
            .field("expected_cli_version", &self.expected_cli_version)
            .field("bundle_root", &self.bundle_root)
            .field("public_key", &self.public_key)
            .field("trust_root_id", &self.trust_root_id)
            .field("expected_host_version", &self.expected_host_version)
            .field("expected_guest_version", &self.expected_guest_version)
            .field("minimum_release_sequence", &self.minimum_release_sequence)
            .field("kernel_path", &self.kernel_path)
            .field("initrd_path", &self.initrd_path)
            .field("memory_mib", &self.memory_mib)
            .field("stack_mib", &self.stack_mib)
            .field("working_directory", &self.working_directory)
            .field("start_command_configured", &self.start_command.is_some())
            .field("mounts", &self.mounts)
            .field("network", &self.network)
            .field("listen_ports", &self.listen_ports)
            .field("process_options", &self.process_options)
            .finish()
    }
}

impl std::fmt::Debug for AuthenticatedLaunchRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedLaunchRequest")
            .field("command", &"[REDACTED]")
            .field("bootstrap_material", &self.bootstrap_material)
            .field("listen_ports", &self.listen_ports)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

struct StateRoot {
    path: PathBuf,
    directory: Arc<Dir>,
}

#[derive(Debug)]
struct ArtifactSource {
    file: File,
    sha256: String,
}

impl ArtifactSource {
    fn copy_to(&self, path: &Path, mode: u32) -> Result<(), RuntimeError> {
        let mut source = self
            .file
            .try_clone()
            .map_err(|error| provider_io("duplicating verified artifact descriptor", error))?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|error| provider_io("rewinding verified artifact", error))?;
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .map_err(|error| provider_io("creating staged artifact", error))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = source
                .read(&mut buffer)
                .map_err(|error| provider_io("reading verified artifact", error))?;
            if read == 0 {
                break;
            }
            destination
                .write_all(&buffer[..read])
                .map_err(|error| provider_io("copying verified artifact", error))?;
            hasher.update(&buffer[..read]);
        }
        if encode_hex(&hasher.finalize()) != self.sha256 {
            return Err(RuntimeError::Provider(
                "verified artifact changed after signature verification".to_owned(),
            ));
        }
        destination
            .sync_all()
            .map_err(|error| provider_io("syncing staged artifact", error))
    }
}

#[derive(Debug)]
struct VerifiedArtifacts {
    kernel: ArtifactSource,
    initrd: Option<ArtifactSource>,
}

struct StartInvocation {
    cancellation: CancellationToken,
    task: JoinHandle<Result<ProcessOutcome, RuntimeError>>,
}

struct ActiveInvocationGuard {
    id: u64,
    container: Arc<Container>,
    cancellation: CancellationToken,
}

impl ActiveInvocationGuard {
    fn new(id: u64, container: Arc<Container>) -> Self {
        let cancellation = CancellationToken::new();
        container
            .active_invocations
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(id, cancellation.clone());
        Self {
            id,
            container,
            cancellation,
        }
    }

    fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
}

impl Drop for ActiveInvocationGuard {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.container
            .active_invocations
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.id);
        self.container.active_notify.notify_one();
    }
}

struct Container {
    lifecycle: LifecycleStateMachine,
    operation: Mutex<()>,
    artifacts: VerifiedArtifacts,
    directory: PathBuf,
    directory_handle: Arc<Dir>,
    start: Mutex<Option<StartInvocation>>,
    output: Mutex<Option<Box<dyn OutputSubscription>>>,
    last_result: Mutex<Option<ProcessOutcome>>,
    pending_cleanup: Arc<StdMutex<Vec<PathBuf>>>,
    active_invocations: StdMutex<BTreeMap<u64, CancellationToken>>,
    active_notify: Notify,
}

impl std::fmt::Debug for Container {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Container")
            .field("lifecycle", &self.lifecycle.current())
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

pub struct HyperlightRuntime {
    runtime_id: RuntimeId,
    configuration: Arc<HyperlightConfiguration>,
    process_runner: Arc<ProcessRunner>,
    initialized: AtomicBool,
    state_root: StdMutex<Option<StateRoot>>,
    executable_identity: StdMutex<Option<ExecutableIdentity>>,
    containers: Mutex<BTreeMap<ContainerId, Arc<Container>>>,
    active_start_cancellations: Arc<StdMutex<BTreeMap<u64, CancellationToken>>>,
    invocation_sequence: AtomicU64,
    skip_host_checks: bool,
}

impl std::fmt::Debug for HyperlightRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HyperlightRuntime")
            .field("runtime_id", &self.runtime_id)
            .field("configuration", &self.configuration)
            .finish_non_exhaustive()
    }
}

impl HyperlightRuntime {
    pub fn new(configuration: HyperlightConfiguration) -> Result<Self, RuntimeError> {
        Self::new_inner(configuration, false)
    }

    fn new_inner(
        configuration: HyperlightConfiguration,
        skip_host_checks: bool,
    ) -> Result<Self, RuntimeError> {
        validate_configuration(&configuration)?;
        let resolver = SearchPathResolver::new(Vec::<PathBuf>::new())?;
        Ok(Self {
            runtime_id: RuntimeId::new("hyperlight")?,
            configuration: Arc::new(configuration),
            process_runner: Arc::new(ProcessRunner::new(Arc::new(resolver))),
            initialized: AtomicBool::new(false),
            state_root: StdMutex::new(None),
            executable_identity: StdMutex::new(None),
            containers: Mutex::new(BTreeMap::new()),
            active_start_cancellations: Arc::new(StdMutex::new(BTreeMap::new())),
            invocation_sequence: AtomicU64::new(1),
            skip_host_checks,
        })
    }

    pub async fn execute_authenticated_once(
        &self,
        container: &ContainerId,
        request: AuthenticatedLaunchRequest,
        cancellation: &CancellationToken,
    ) -> Result<ProcessOutcome, RuntimeError> {
        let container = self.container(container).await?;
        let guard = {
            let _operation = container.operation.lock().await;
            require_running(&container)?;
            validate_ports(&request.listen_ports)?;
            self.register_invocation(Arc::clone(&container))?
        };
        let mut staging =
            self.prepare_invocation(&container, Some(request.bootstrap_material.as_bytes()))?;
        let command = self.launch_command(&staging, &request.command, &request.listen_ports)?;
        let result = self.run_invocation(command, &guard, cancellation).await;
        finish_invocation(result, &mut staging)
    }

    async fn container(&self, id: &ContainerId) -> Result<Arc<Container>, RuntimeError> {
        self.containers
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| {
                RuntimeError::Provider(format!("Hyperlight container `{id}` was not found",))
            })
    }

    fn verify_host(&self) -> Result<(), RuntimeError> {
        if self.skip_host_checks {
            return Ok(());
        }
        verify_kvm(&self.runtime_id)?;
        validate_trusted_file(&self.configuration.public_key, false)?;
        let identity = validate_trusted_file(&self.configuration.executable, true)?;
        let mut expected = self
            .executable_identity
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match *expected {
            Some(previous) if previous != identity => {
                return Err(RuntimeError::Unavailable {
                    runtime: self.runtime_id.clone(),
                    reason: "trusted hyperlight executable identity changed".to_owned(),
                });
            }
            Some(_) => {}
            None => *expected = Some(identity),
        }
        Ok(())
    }

    async fn probe_version(&self, cancellation: &CancellationToken) -> Result<(), RuntimeError> {
        let outcome = self
            .process_runner
            .run(
                host_command(
                    &self.configuration.executable,
                    [CommandArgument::plain("--version")],
                ),
                ProcessOptions {
                    stdout_capture_bytes: 64 * 1024,
                    stderr_capture_bytes: 64 * 1024,
                    timeout: Some(Duration::from_secs(10)),
                    ..ProcessOptions::default()
                },
                cancellation,
            )
            .await?;
        if !outcome.status.success {
            return Err(RuntimeError::Unavailable {
                runtime: self.runtime_id.clone(),
                reason: format!(
                    "`{} --version` failed with {:?}: {}",
                    self.configuration.executable.display(),
                    outcome.status.code,
                    String::from_utf8_lossy(&outcome.stderr.bytes)
                ),
            });
        }
        let mut version = outcome.stdout.bytes;
        version.extend_from_slice(&outcome.stderr.bytes);
        let expected = format!(
            "hyperlight-unikraft {}",
            self.configuration.expected_cli_version
        );
        if !String::from_utf8_lossy(&version)
            .lines()
            .any(|line| line.trim() == expected)
        {
            return Err(RuntimeError::Unavailable {
                runtime: self.runtime_id.clone(),
                reason: format!("configured executable version did not match pinned `{expected}`"),
            });
        }
        Ok(())
    }

    fn verify_bundle(&self) -> Result<VerifiedBundle, RuntimeError> {
        verify_bundle_artifacts(&VerifyOptions {
            root: &self.configuration.bundle_root,
            public_key: &self.configuration.public_key,
            architecture: host_architecture()?,
            trust_root_id: &self.configuration.trust_root_id,
            host_version: &self.configuration.expected_host_version,
            guest_version: &self.configuration.expected_guest_version,
            minimum_release_sequence: self.configuration.minimum_release_sequence,
        })
        .map_err(|error| {
            RuntimeError::Provider(format!(
                "Hyperlight signed bundle verification failed: {error}",
            ))
        })
    }

    fn load_artifacts(&self) -> Result<VerifiedArtifacts, RuntimeError> {
        let verified = self.verify_bundle()?;
        let kernel_relative = artifact_relative_path(
            &self.configuration.bundle_root,
            &self.configuration.kernel_path,
        )?;
        let kernel = verified
            .manifest
            .artifact_descriptor(&kernel_relative, ArtifactKind::UnikraftShellKernel)
            .map_err(|error| RuntimeError::Provider(error.to_string()))?;
        let kernel_sha256 = artifact_digest(
            &verified,
            &kernel_relative,
            ArtifactKind::UnikraftShellKernel,
        )?;
        let initrd = self
            .configuration
            .initrd_path
            .as_ref()
            .map(|path| {
                let relative = artifact_relative_path(&self.configuration.bundle_root, path)?;
                verified
                    .manifest
                    .artifact_descriptor(&relative, ArtifactKind::Initrd)
                    .map_err(|error| RuntimeError::Provider(error.to_string()))
                    .and_then(|descriptor| {
                        Ok(ArtifactSource {
                            file: File::from(descriptor),
                            sha256: artifact_digest(&verified, &relative, ArtifactKind::Initrd)?,
                        })
                    })
            })
            .transpose()?;
        Ok(VerifiedArtifacts {
            kernel: ArtifactSource {
                file: File::from(kernel),
                sha256: kernel_sha256,
            },
            initrd,
        })
    }

    fn state_root(&self) -> Result<(PathBuf, Arc<Dir>), RuntimeError> {
        let state = self
            .state_root
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .as_ref()
            .map(|state| (state.path.clone(), Arc::clone(&state.directory)))
            .ok_or_else(|| {
                RuntimeError::Provider("Hyperlight runtime has not been initialized".to_owned())
            })?;
        validate_private_directory_handle(&state.1)?;
        Ok(state)
    }

    fn prepare_invocation(
        &self,
        container: &Arc<Container>,
        bootstrap: Option<&[u8]>,
    ) -> Result<InvocationStaging, RuntimeError> {
        self.verify_host()?;
        let sequence = self.invocation_sequence.fetch_add(1, Ordering::Relaxed);
        validate_private_directory_handle(&container.directory_handle)?;
        let name = format!("invocation-{sequence}");
        let root = container.directory.join(&name);
        validate_mount_staging_separation(&self.configuration.mounts, &root)?;
        let root_handle = create_private_child(&container.directory_handle, &name)?;
        let mut staging =
            InvocationStaging::new(root, root_handle, Arc::clone(&container.pending_cleanup));
        staging.stage_artifacts(&container.artifacts)?;
        staging.stage_mounts(&self.configuration.mounts)?;
        if let Some(material) = bootstrap {
            staging.stage_bootstrap(material)?;
        }
        Ok(staging)
    }

    fn launch_command(
        &self,
        staging: &InvocationStaging,
        guest_command: &CommandSpec,
        ports: &[u16],
    ) -> Result<CommandSpec, RuntimeError> {
        staging.verify_artifacts()?;
        validate_guest_command(guest_command)?;
        validate_ports(ports)?;
        let mut arguments = vec![CommandArgument::plain(
            staging.kernel_path().display().to_string(),
        )];
        if let Some(initrd) = staging.initrd_path() {
            arguments.extend([
                CommandArgument::plain("--initrd"),
                CommandArgument::plain(initrd.display().to_string()),
            ]);
        }
        arguments.extend([
            CommandArgument::plain("--memory"),
            CommandArgument::plain(format!("{}Mi", self.configuration.memory_mib)),
            CommandArgument::plain("--stack"),
            CommandArgument::plain(format!("{}Mi", self.configuration.stack_mib)),
            CommandArgument::plain("--quiet"),
        ]);
        for mount in staging.mounts() {
            arguments.extend([
                CommandArgument::plain("--mount"),
                CommandArgument::plain(format!(
                    "{}:{}",
                    mount.source.display(),
                    mount.destination.display()
                )),
            ]);
        }
        let network = network_arguments(&self.configuration.network)?;
        if !ports.is_empty() && network.is_empty() {
            return Err(invalid(
                "listen ports require an explicit Hyperlight network policy",
            ));
        }
        arguments.extend(network);
        for port in ports {
            arguments.extend([
                CommandArgument::plain("--port"),
                CommandArgument::plain(port.to_string()),
            ]);
        }
        let working_directory = guest_command
            .current_directory
            .as_deref()
            .unwrap_or(&self.configuration.working_directory);
        validate_guest_path(working_directory, "working directory")?;
        arguments.push(CommandArgument::plain("--exec"));
        let expression = format!(
            "cd {} && exec {}",
            shell_quote(&working_directory.display().to_string()),
            shell_command(guest_command)?
        );
        arguments.push(
            if guest_command
                .arguments
                .iter()
                .any(|argument| argument.sensitive)
            {
                CommandArgument::sensitive(expression)
            } else {
                CommandArgument::plain(expression)
            },
        );
        Ok(host_command(&self.configuration.executable, arguments))
    }

    fn register_invocation(
        &self,
        container: Arc<Container>,
    ) -> Result<ActiveInvocationGuard, RuntimeError> {
        if !container
            .active_invocations
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .is_empty()
        {
            return Err(RuntimeError::Provider(
                "a one-shot Hyperlight invocation is already active".to_owned(),
            ));
        }
        let id = self.invocation_sequence.fetch_add(1, Ordering::Relaxed);
        Ok(ActiveInvocationGuard::new(id, container))
    }

    async fn run_invocation(
        &self,
        command: CommandSpec,
        guard: &ActiveInvocationGuard,
        caller_cancellation: &CancellationToken,
    ) -> Result<ProcessOutcome, RuntimeError> {
        if caller_cancellation.is_cancelled() {
            guard.cancellation().cancel();
        }
        let caller = caller_cancellation.clone();
        let invocation = guard.cancellation().clone();
        let relay = tokio::spawn(async move {
            caller.cancelled().await;
            invocation.cancel();
        });
        let result = self
            .process_runner
            .run(
                command,
                self.configuration.process_options.clone(),
                guard.cancellation(),
            )
            .await;
        relay.abort();
        result
    }

    async fn cancel_active_invocations(&self, container: &Container) {
        loop {
            let notified = container.active_notify.notified();
            let active = container
                .active_invocations
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .values()
                .cloned()
                .collect::<Vec<_>>();
            if active.is_empty() {
                return;
            }
            for cancellation in active {
                cancellation.cancel();
            }
            notified.await;
        }
    }

    async fn stop_container(
        &self,
        container: &Arc<Container>,
        cancellation: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        if cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        match container.lifecycle.current() {
            LifecycleState::Running => {
                transition(&container.lifecycle, LifecycleState::Stopping)?;
            }
            LifecycleState::Created => {
                transition(&container.lifecycle, LifecycleState::Stopped)?;
                return Ok(());
            }
            LifecycleState::Stopping | LifecycleState::Stopped | LifecycleState::Failed => {}
            state => {
                return Err(RuntimeError::InvalidTransition {
                    from: state,
                    to: LifecycleState::Stopped,
                });
            }
        }
        let invocation = container.start.lock().await.take();
        if let Some(invocation) = invocation {
            invocation.cancellation.cancel();
            let outcome = invocation
                .task
                .await
                .map_err(|error| RuntimeError::ProcessTask(error.to_string()))??;
            *container.last_result.lock().await = Some(outcome);
        }
        self.cancel_active_invocations(container).await;
        if matches!(
            container.lifecycle.current(),
            LifecycleState::Running | LifecycleState::Stopping
        ) {
            transition(&container.lifecycle, LifecycleState::Stopped)?;
        }
        Ok(())
    }
}

impl Drop for HyperlightRuntime {
    fn drop(&mut self) {
        for cancellation in self
            .active_start_cancellations
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .values()
        {
            cancellation.cancel();
        }
        if let Ok(containers) = self.containers.try_lock() {
            for container in containers.values() {
                for cancellation in container
                    .active_invocations
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .values()
                {
                    cancellation.cancel();
                }
                if let Ok(start) = container.start.try_lock()
                    && let Some(invocation) = start.as_ref()
                {
                    invocation.cancellation.cancel();
                }
            }
        }
    }
}

impl RuntimeProvider for HyperlightRuntime {
    fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::from([
            RuntimeCapability::Lifecycle,
            RuntimeCapability::Exec,
            RuntimeCapability::Mounts,
            RuntimeCapability::Network,
            RuntimeCapability::Health,
        ])
    }

    fn initialize<'a>(
        &'a self,
        request: InitializeRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            validate_absolute_clean_path(&request.state_directory, "state directory")?;
            validate_state_directory_ancestry(&request.state_directory)?;
            let state_descriptor =
                open_directory_no_symlinks(&request.state_directory).map_err(|error| {
                    RuntimeError::Provider(format!("opening runtime state directory: {error}"))
                })?;
            let state_directory = Dir::from_std_file(File::from(state_descriptor));
            let root = request.state_directory.join("hyperlight");
            let root_directory = match state_directory.open_dir("hyperlight") {
                Ok(directory) => directory,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    create_private_child(&state_directory, "hyperlight")?
                }
                Err(error) => {
                    return Err(provider_io("opening Hyperlight state root", error));
                }
            };
            validate_private_directory_handle(&root_directory)?;
            let mut state = self
                .state_root
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if let Some(existing) = state.as_ref()
                && existing.path != root
            {
                return Err(RuntimeError::Provider(format!(
                    "Hyperlight runtime is already initialized at {}",
                    existing.path.display()
                )));
            }
            *state = Some(StateRoot {
                path: root,
                directory: Arc::new(root_directory),
            });
            self.initialized.store(true, Ordering::Release);
            Ok(())
        })
    }

    fn preflight<'a>(
        &'a self,
        request: PreflightRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<PreflightReport, RuntimeError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            self.verify_host()?;
            self.load_artifacts()?;
            self.probe_version(cancellation).await?;
            let available = self.capabilities();
            Ok(PreflightReport {
                missing_capabilities: request.required_capabilities.missing_from(&available),
                available_capabilities: available,
            })
        })
    }

    fn create<'a>(
        &'a self,
        request: sendbox_runtime::CreateRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ContainerId, RuntimeError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            if !self.initialized.load(Ordering::Acquire) {
                return Err(RuntimeError::Provider(
                    "Hyperlight runtime has not been initialized".to_owned(),
                ));
            }
            let image = Path::new(&request.image);
            validate_absolute_clean_path(image, "signed bundle image")?;
            if image != self.configuration.bundle_root {
                return Err(RuntimeError::Provider(format!(
                    "Hyperlight does not accept OCI images; expected signed bundle directory `{}`",
                    self.configuration.bundle_root.display()
                )));
            }
            let artifacts = self.load_artifacts()?;
            let mut containers = self.containers.lock().await;
            if containers.contains_key(&request.container_id) {
                return Err(RuntimeError::Provider(format!(
                    "Hyperlight container `{}` already exists",
                    request.container_id
                )));
            }
            let (state_root, state_directory) = self.state_root()?;
            let directory_handle =
                create_private_child(&state_directory, request.container_id.as_str())?;
            let directory = state_root.join(request.container_id.as_str());
            let container = Arc::new(Container {
                lifecycle: LifecycleStateMachine::new(LifecycleState::Created),
                operation: Mutex::new(()),
                artifacts,
                directory,
                directory_handle: Arc::new(directory_handle),
                start: Mutex::new(None),
                output: Mutex::new(None),
                last_result: Mutex::new(None),
                pending_cleanup: Arc::new(StdMutex::new(Vec::new())),
                active_invocations: StdMutex::new(BTreeMap::new()),
                active_notify: Notify::new(),
            });
            containers.insert(request.container_id.clone(), container);
            Ok(request.container_id)
        })
    }

    fn start<'a>(
        &'a self,
        id: &'a ContainerId,
        request: StartRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            if request.attach_standard_streams {
                return Err(RuntimeError::MissingCapabilities {
                    missing: "Hyperlight has captured stdout/stderr only and no forwarded stdin"
                        .to_owned(),
                });
            }
            let container = self.container(id).await?;
            let _operation = container.operation.lock().await;
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            if container.lifecycle.current() != LifecycleState::Created {
                return Err(RuntimeError::InvalidTransition {
                    from: container.lifecycle.current(),
                    to: LifecycleState::Running,
                });
            }
            let Some(start_command) = self.configuration.start_command.clone() else {
                transition(&container.lifecycle, LifecycleState::Running)?;
                return Ok(());
            };
            let mut staging = self.prepare_invocation(&container, None)?;
            let command =
                self.launch_command(&staging, &start_command, &self.configuration.listen_ports)?;
            let start_cancellation = CancellationToken::new();
            let mut output_slot = container.output.lock().await;
            let mut start_slot = container.start.lock().await;
            let mut running = self
                .process_runner
                .spawn(
                    command,
                    self.configuration.process_options.clone(),
                    &start_cancellation,
                )
                .await?;
            let start_id = self.invocation_sequence.fetch_add(1, Ordering::Relaxed);
            *output_slot = running.take_output_subscription();
            transition(&container.lifecycle, LifecycleState::Running)?;
            self.active_start_cancellations
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .insert(start_id, start_cancellation.clone());
            let task_container = Arc::clone(&container);
            let task_cancellation = start_cancellation.clone();
            let active_starts = Arc::clone(&self.active_start_cancellations);
            let task = tokio::spawn(async move {
                let result = running.wait(&task_cancellation).await;
                let result = finish_invocation(result, &mut staging);
                match &result {
                    Ok(outcome) => {
                        *task_container.last_result.lock().await = Some(outcome.clone());
                        let current = task_container.lifecycle.current();
                        if matches!(current, LifecycleState::Running | LifecycleState::Stopping) {
                            let _ = transition(&task_container.lifecycle, LifecycleState::Stopped);
                        }
                    }
                    Err(_) => {
                        let current = task_container.lifecycle.current();
                        if matches!(
                            current,
                            LifecycleState::Running
                                | LifecycleState::Stopping
                                | LifecycleState::Created
                        ) {
                            let _ = transition(&task_container.lifecycle, LifecycleState::Failed);
                        }
                    }
                }
                active_starts
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .remove(&start_id);
                result
            });
            *start_slot = Some(StartInvocation {
                cancellation: start_cancellation,
                task,
            });
            Ok(())
        })
    }

    fn provision_control_channel<'a>(
        &'a self,
        request: ControlChannelRequest,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn sendbox_runtime::ProvisionedControlChannel>, RuntimeError>>
    {
        Box::pin(async move {
            Err(RuntimeError::TransportUnavailable {
                endpoint: request.endpoint_kind,
                reason: concat!(
                    "hyperlight-unikraft is one-shot and cannot host the persistent guest ",
                    "supervisor/control stream; use execute_authenticated_once for an ",
                    "ephemeral bootstrap-file launch"
                )
                .to_owned(),
            })
        })
    }

    fn status<'a>(
        &'a self,
        id: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<RuntimeStatus, RuntimeError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            let lifecycle = self.container(id).await?.lifecycle.current();
            let health = match lifecycle {
                LifecycleState::Running | LifecycleState::Stopped => RuntimeHealth::Healthy,
                LifecycleState::Failed => RuntimeHealth::Unhealthy,
                LifecycleState::Stopping => RuntimeHealth::Degraded,
                _ => RuntimeHealth::Unknown,
            };
            Ok(RuntimeStatus { lifecycle, health })
        })
    }

    fn exec<'a>(
        &'a self,
        id: &'a ContainerId,
        request: ExecRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ProcessOutcome, RuntimeError>> {
        Box::pin(async move {
            if request.purpose == ExecPurpose::Workload {
                return Err(RuntimeError::WorkloadExecRequiresGuestBroker);
            }
            let container = self.container(id).await?;
            let guard = {
                let _operation = container.operation.lock().await;
                require_running(&container)?;
                self.register_invocation(Arc::clone(&container))?
            };
            let mut staging = self.prepare_invocation(&container, None)?;
            let command = self.launch_command(&staging, &request.command, &[])?;
            let result = self.run_invocation(command, &guard, cancellation).await;
            finish_invocation(result, &mut staging)
        })
    }

    fn attach<'a>(
        &'a self,
        id: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn OutputSubscription>, RuntimeError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            let container = self.container(id).await?;
            Ok(container
                .output
                .lock()
                .await
                .take()
                .unwrap_or_else(|| Box::new(VecOutputSubscription::default())))
        })
    }

    fn signal<'a>(
        &'a self,
        _container: &'a ContainerId,
        signal: RuntimeSignal,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            Err(RuntimeError::UnsupportedSignal {
                signal: format!("{signal:?}"),
            })
        })
    }

    fn stop<'a>(
        &'a self,
        id: &'a ContainerId,
        request: StopRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            if request.grace != self.configuration.process_options.termination_grace {
                return Err(invalid(format!(
                    "Hyperlight stop grace {:?} must match the launch-time termination grace {:?}",
                    request.grace, self.configuration.process_options.termination_grace
                )));
            }
            let container = self.container(id).await?;
            let _operation = container.operation.lock().await;
            self.stop_container(&container, cancellation).await
        })
    }

    fn cleanup<'a>(
        &'a self,
        id: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<CleanupReport, RuntimeError>> {
        Box::pin(async move {
            let container = self.container(id).await?;
            let _operation = container.operation.lock().await;
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            if matches!(
                container.lifecycle.current(),
                LifecycleState::Running | LifecycleState::Stopping
            ) {
                self.stop_container(&container, cancellation).await?;
            } else {
                self.cancel_active_invocations(&container).await;
            }
            if matches!(
                container.lifecycle.current(),
                LifecycleState::Created | LifecycleState::Stopped | LifecycleState::Failed
            ) {
                transition(&container.lifecycle, LifecycleState::Cleaning)?;
            }
            let mut paths = {
                let mut pending = container
                    .pending_cleanup
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                std::mem::take(&mut *pending)
            };
            paths.push(container.directory.clone());
            paths.sort();
            paths.dedup();
            let mut report = CleanupReport::default();
            for path in paths.into_iter().rev() {
                report.attempted += 1;
                match remove_path(&path) {
                    Ok(()) => {
                        report.succeeded += 1;
                    }
                    Err(error) => {
                        report.remaining += 1;
                        report.failures.push(CleanupFailure {
                            step: format!("remove {}", path.display()),
                            error,
                        });
                        container
                            .pending_cleanup
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .push(path);
                    }
                }
            }
            if report.is_complete() {
                transition(&container.lifecycle, LifecycleState::Cleaned)?;
                self.containers.lock().await.remove(id);
            }
            Ok(report)
        })
    }
}

#[derive(Debug)]
struct PreparedMount {
    source: PathBuf,
    destination: PathBuf,
}

#[derive(Debug)]
struct InvocationStaging {
    root: Option<PathBuf>,
    root_handle: Option<Dir>,
    pending_cleanup: Arc<StdMutex<Vec<PathBuf>>>,
    kernel: PathBuf,
    kernel_sha256: Option<String>,
    initrd: Option<PathBuf>,
    initrd_sha256: Option<String>,
    mounts: Vec<PreparedMount>,
}

impl InvocationStaging {
    fn new(root: PathBuf, root_handle: Dir, pending_cleanup: Arc<StdMutex<Vec<PathBuf>>>) -> Self {
        Self {
            kernel: root.join("kernel"),
            kernel_sha256: None,
            initrd: None,
            initrd_sha256: None,
            root: Some(root),
            root_handle: Some(root_handle),
            pending_cleanup,
            mounts: Vec::new(),
        }
    }

    fn root(&self) -> Result<&Path, RuntimeError> {
        self.root.as_deref().ok_or_else(|| {
            RuntimeError::Provider("invocation staging was already cleaned".to_owned())
        })
    }

    fn kernel_path(&self) -> &Path {
        &self.kernel
    }

    fn initrd_path(&self) -> Option<&Path> {
        self.initrd.as_deref()
    }

    fn mounts(&self) -> &[PreparedMount] {
        &self.mounts
    }

    fn stage_artifacts(&mut self, artifacts: &VerifiedArtifacts) -> Result<(), RuntimeError> {
        artifacts.kernel.copy_to(&self.kernel, 0o500)?;
        self.kernel_sha256 = Some(artifacts.kernel.sha256.clone());
        if let Some(initrd) = &artifacts.initrd {
            let path = self.root()?.join("rootfs.cpio");
            initrd.copy_to(&path, 0o400)?;
            self.initrd = Some(path);
            self.initrd_sha256 = Some(initrd.sha256.clone());
        }
        Ok(())
    }

    fn verify_artifacts(&self) -> Result<(), RuntimeError> {
        let kernel_sha256 = self.kernel_sha256.as_deref().ok_or_else(|| {
            RuntimeError::Provider("staged kernel digest is unavailable".to_owned())
        })?;
        verify_file_digest(&self.kernel, kernel_sha256)?;
        match (&self.initrd, &self.initrd_sha256) {
            (Some(path), Some(sha256)) => verify_file_digest(path, sha256),
            (None, None) => Ok(()),
            _ => Err(RuntimeError::Provider(
                "staged initrd digest state is inconsistent".to_owned(),
            )),
        }
    }

    fn stage_mounts(&mut self, mounts: &[HyperlightMount]) -> Result<(), RuntimeError> {
        for (index, mount) in mounts.iter().enumerate() {
            if mount.read_only {
                let destination = self.root()?.join(format!("mount-{index}"));
                copy_directory_read_only(&mount.source, &destination)?;
                self.mounts.push(PreparedMount {
                    source: destination,
                    destination: mount.destination.clone(),
                });
            } else {
                self.mounts.push(PreparedMount {
                    source: mount.source.clone(),
                    destination: mount.destination.clone(),
                });
            }
        }
        Ok(())
    }

    fn stage_bootstrap(&mut self, material: &[u8]) -> Result<(), RuntimeError> {
        let directory = self.root()?.join("authenticated-control");
        create_private_directory(&directory)?;
        let path = directory.join("bootstrap-material");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)
            .map_err(|error| provider_io("creating authenticated bootstrap material", error))?;
        file.write_all(material)
            .map_err(|error| provider_io("writing authenticated bootstrap material", error))?;
        file.sync_all()
            .map_err(|error| provider_io("syncing authenticated bootstrap material", error))?;
        self.mounts.push(PreparedMount {
            source: directory,
            destination: PathBuf::from(AUTHENTICATED_BOOTSTRAP_GUEST_DIRECTORY),
        });
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), RuntimeError> {
        let Some(root) = self.root.take() else {
            return Ok(());
        };
        self.root_handle = None;
        if let Err(error) = remove_path(&root) {
            self.pending_cleanup
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(root);
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for InvocationStaging {
    fn drop(&mut self) {
        let Some(root) = self.root.take() else {
            return;
        };
        self.root_handle = None;
        if remove_path(&root).is_err() {
            self.pending_cleanup
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(root);
        }
    }
}

fn finish_invocation(
    result: Result<ProcessOutcome, RuntimeError>,
    staging: &mut InvocationStaging,
) -> Result<ProcessOutcome, RuntimeError> {
    let cleanup = staging.cleanup();
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(RuntimeError::Provider(format!(
            "{primary}; staging cleanup also failed: {cleanup}"
        ))),
    }
}

fn validate_configuration(configuration: &HyperlightConfiguration) -> Result<(), RuntimeError> {
    validate_absolute_clean_path(&configuration.executable, "executable")?;
    validate_absolute_clean_path(&configuration.bundle_root, "signed bundle root")?;
    validate_absolute_clean_path(&configuration.public_key, "public key")?;
    validate_absolute_clean_path(&configuration.kernel_path, "kernel path")?;
    if let Some(initrd) = &configuration.initrd_path {
        validate_absolute_clean_path(initrd, "initrd path")?;
    }
    artifact_relative_path(&configuration.bundle_root, &configuration.kernel_path)?;
    if let Some(initrd) = &configuration.initrd_path {
        artifact_relative_path(&configuration.bundle_root, initrd)?;
    }
    for (field, value) in [
        (
            "expected_cli_version",
            configuration.expected_cli_version.as_str(),
        ),
        ("trust_root_id", configuration.trust_root_id.as_str()),
        (
            "expected_host_version",
            configuration.expected_host_version.as_str(),
        ),
        (
            "expected_guest_version",
            configuration.expected_guest_version.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(invalid(format!("{field} must not be empty")));
        }
    }
    if configuration.memory_mib == 0 || configuration.memory_mib > MAX_MEMORY_MIB {
        return Err(invalid(format!(
            "memory_mib must be between 1 and {MAX_MEMORY_MIB}"
        )));
    }
    if configuration.stack_mib == 0 || configuration.stack_mib > MAX_STACK_MIB {
        return Err(invalid(format!(
            "stack_mib must be between 1 and {MAX_STACK_MIB}"
        )));
    }
    validate_guest_path(&configuration.working_directory, "working directory")?;
    if let Some(command) = &configuration.start_command {
        validate_guest_command(command)?;
    }
    validate_mounts(&configuration.mounts)?;
    let network = network_arguments(&configuration.network)?;
    validate_ports(&configuration.listen_ports)?;
    if !configuration.listen_ports.is_empty() && network.is_empty() {
        return Err(invalid(
            "listen ports require an explicit Hyperlight network policy",
        ));
    }
    Ok(())
}

fn validate_mounts(mounts: &[HyperlightMount]) -> Result<(), RuntimeError> {
    let mut destinations = BTreeSet::new();
    for mount in mounts {
        if !mount.read_only {
            return Err(invalid(
                "writable Hyperlight mounts cannot be securely anchored and are unsupported",
            ));
        }
        validate_absolute_clean_path(&mount.source, "mount source")?;
        validate_guest_path(&mount.destination, "mount destination")?;
        validate_mount_destination(&mount.destination)?;
        validate_no_colon(&mount.source, "mount source")?;
        validate_no_colon(&mount.destination, "mount destination")?;
        validate_directory_no_symlinks(&mount.source)?;
        if !destinations.insert(mount.destination.clone()) {
            return Err(invalid(format!(
                "duplicate Hyperlight mount destination `{}`",
                mount.destination.display()
            )));
        }
    }
    Ok(())
}

fn validate_mount_staging_separation(
    mounts: &[HyperlightMount],
    staging_root: &Path,
) -> Result<(), RuntimeError> {
    if let Some(mount) = mounts
        .iter()
        .find(|mount| staging_root.starts_with(&mount.source))
    {
        return Err(invalid(format!(
            "mount source `{}` contains the Hyperlight staging root `{}`",
            mount.source.display(),
            staging_root.display()
        )));
    }
    Ok(())
}

fn validate_mount_destination(path: &Path) -> Result<(), RuntimeError> {
    for reserved in ["/", "/bin", "/dev", "/proc", "/sys", "/usr"] {
        let reserved = Path::new(reserved);
        if path == reserved || (reserved != Path::new("/") && path.starts_with(reserved)) {
            return Err(invalid(format!(
                "mount destination `{}` shadows reserved guest path `{}`",
                path.display(),
                reserved.display()
            )));
        }
    }
    Ok(())
}

fn validate_ports(ports: &[u16]) -> Result<(), RuntimeError> {
    let mut unique = BTreeSet::new();
    for port in ports {
        if *port == 0 {
            return Err(invalid("listen ports must be between 1 and 65535"));
        }
        if !unique.insert(*port) {
            return Err(invalid(format!("duplicate listen port {port}")));
        }
    }
    Ok(())
}

fn network_arguments(
    policy: &HyperlightNetworkConfiguration,
) -> Result<Vec<CommandArgument>, RuntimeError> {
    let enabled = policy.mode != HyperlightNetworkMode::Disabled;
    if enabled && policy.custom_dns_controls {
        return Err(invalid(
            "Hyperlight cannot enforce DNS TTL, record, or query-budget controls",
        ));
    }
    if enabled && policy.destination_port_rules {
        return Err(invalid(
            "Hyperlight cannot enforce destination port/protocol rules",
        ));
    }
    if enabled && !policy.allow_dns {
        return Err(invalid(
            "Hyperlight networking cannot guarantee DNS is disabled",
        ));
    }
    if enabled && policy.max_connections.is_some() {
        return Err(invalid("Hyperlight cannot enforce max_connections"));
    }
    let allowed_hosts = normalized_host_entries(&policy.allowed_hosts, "allowed")?;
    let blocked_hosts = normalized_host_entries(&policy.blocked_hosts, "blocked")?;
    let allowed_addresses = normalized_address_entries(&policy.allowed_addresses, "allowed")?;
    let blocked_addresses = normalized_address_entries(&policy.blocked_addresses, "blocked")?;
    if policy.mode == HyperlightNetworkMode::Disabled
        && (!allowed_hosts.is_empty()
            || !blocked_hosts.is_empty()
            || !allowed_addresses.is_empty()
            || !blocked_addresses.is_empty())
    {
        return Err(invalid(
            "disabled Hyperlight networking cannot contain allow or block entries",
        ));
    }
    if policy.mode == HyperlightNetworkMode::AllowAll
        && (!allowed_hosts.is_empty() || !allowed_addresses.is_empty())
    {
        return Err(invalid(
            "allow-all Hyperlight networking cannot contain allow-list entries",
        ));
    }
    if policy.mode == HyperlightNetworkMode::AllowList
        && ((!allowed_hosts.is_empty() && !blocked_addresses.is_empty())
            || (!allowed_addresses.is_empty() && !blocked_hosts.is_empty()))
    {
        return Err(invalid(
            "Hyperlight cannot preserve hostname/IP block precedence across an allow-list",
        ));
    }

    let mut allowed = allowed_hosts;
    allowed.extend(allowed_addresses);
    let mut blocked = blocked_hosts;
    blocked.extend(blocked_addresses);

    let mut arguments = Vec::new();
    match policy.mode {
        HyperlightNetworkMode::Disabled => {}
        HyperlightNetworkMode::AllowAll => {
            if blocked.is_empty() {
                arguments.push(CommandArgument::plain("--net"));
            } else {
                for entry in blocked {
                    arguments.extend([
                        CommandArgument::plain("--net-block"),
                        CommandArgument::plain(entry),
                    ]);
                }
            }
        }
        HyperlightNetworkMode::AllowList => {
            let blocked = blocked.into_iter().collect::<BTreeSet<_>>();
            for entry in allowed.into_iter().filter(|entry| !blocked.contains(entry)) {
                arguments.extend([
                    CommandArgument::plain("--net-allow"),
                    CommandArgument::plain(entry),
                ]);
            }
        }
    }
    Ok(arguments)
}

fn normalized_host_entries(hosts: &[String], field: &str) -> Result<Vec<String>, RuntimeError> {
    let mut entries = BTreeSet::new();
    for value in hosts {
        if value.contains(['*', '?']) {
            return Err(invalid(format!(
                "Hyperlight {field} network entries must be concrete hostnames or IP addresses"
            )));
        }
        let trimmed = value.trim().trim_end_matches('.');
        let normalized = match trimmed.parse::<IpAddr>() {
            Ok(ip) => address::canonicalize(ip).to_string(),
            Err(_) => domain::normalize_domain(trimmed)
                .map_err(|error| invalid(format!("invalid {field} hostname `{value}`: {error}")))?,
        };
        entries.insert(normalized);
    }
    Ok(entries.into_iter().collect())
}

fn normalized_address_entries(
    addresses: &[String],
    field: &str,
) -> Result<Vec<String>, RuntimeError> {
    let mut entries = BTreeSet::new();
    for value in addresses {
        let network = value.parse::<IpNet>().map_err(|error| {
            invalid(format!(
                "invalid {field} network literal `{value}`: {error}"
            ))
        })?;
        let exact = match network {
            IpNet::V4(network) if network.prefix_len() == 32 => IpAddr::V4(network.addr()),
            IpNet::V6(network) if network.prefix_len() == 128 => IpAddr::V6(network.addr()),
            _ => {
                return Err(invalid(format!(
                    "Hyperlight does not support CIDR {field} entry `{value}`; use exact /32 or /128 addresses"
                )));
            }
        };
        entries.insert(address::canonicalize(exact).to_string());
    }
    Ok(entries.into_iter().collect())
}

fn validate_guest_command(command: &CommandSpec) -> Result<(), RuntimeError> {
    if !command.clear_environment || !command.environment.is_empty() {
        return Err(invalid(
            "hyperlight-unikraft does not support guest environment injection",
        ));
    }
    let program = match &command.program {
        Program::Absolute(path) => {
            validate_guest_path(path, "guest program")?;
            path.display().to_string()
        }
        Program::Named(name) => {
            if name.is_empty()
                || name.contains('/')
                || name.contains('\0')
                || name.chars().any(char::is_whitespace)
            {
                return Err(invalid("guest program name is invalid"));
            }
            name.clone()
        }
    };
    validate_shell_value(&program, "guest program")?;
    for argument in &command.arguments {
        validate_shell_value(&argument.value, "guest argument")?;
    }
    if let Some(directory) = &command.current_directory {
        validate_guest_path(directory, "guest working directory")?;
    }
    Ok(())
}

fn shell_command(command: &CommandSpec) -> Result<String, RuntimeError> {
    let program = match &command.program {
        Program::Absolute(path) => path.display().to_string(),
        Program::Named(name) => name.clone(),
    };
    let mut values = Vec::with_capacity(command.arguments.len() + 1);
    values.push(program);
    values.extend(
        command
            .arguments
            .iter()
            .map(|argument| argument.value.clone()),
    );
    for value in &values {
        validate_shell_value(value, "command value")?;
    }
    Ok(values
        .iter()
        .map(|value| shell_quote(value))
        .collect::<Vec<_>>()
        .join(" "))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn validate_shell_value(value: &str, field: &str) -> Result<(), RuntimeError> {
    if value.contains('\0') {
        return Err(invalid(format!("{field} contains a NUL byte")));
    }
    Ok(())
}

fn host_command(
    executable: &Path,
    arguments: impl IntoIterator<Item = CommandArgument>,
) -> CommandSpec {
    CommandSpec {
        arguments: arguments.into_iter().collect(),
        environment: vec![
            sendbox_runtime::EnvironmentVariable::plain("LANG", HOST_LANG),
            sendbox_runtime::EnvironmentVariable::plain("PATH", HOST_PATH),
        ],
        clear_environment: true,
        ..CommandSpec::new(Program::Absolute(executable.to_path_buf()))
    }
}

fn validate_trusted_file(
    path: &Path,
    executable: bool,
) -> Result<ExecutableIdentity, RuntimeError> {
    validate_absolute_clean_path(path, "trusted file")?;
    let mut current = PathBuf::from("/");
    let components = path.components().filter_map(|component| match component {
        Component::Normal(value) => Some(value),
        _ => None,
    });
    for component in components {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| provider_io("inspecting trusted path component", error))?;
        if metadata.file_type().is_symlink() {
            return Err(invalid(format!(
                "trusted path `{}` must not contain symbolic links",
                path.display()
            )));
        }
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(invalid(format!(
                "trusted path component `{}` must be root-owned and not group- or world-writable",
                current.display()
            )));
        }
    }
    let metadata =
        fs::metadata(path).map_err(|error| provider_io("inspecting trusted file", error))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(invalid(format!(
            "trusted file `{}` must be a single-link regular file",
            path.display()
        )));
    }
    if executable && metadata.mode() & 0o111 == 0 {
        return Err(invalid(format!(
            "trusted executable `{}` is not executable",
            path.display()
        )));
    }
    Ok(ExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

fn validate_absolute_clean_path(path: &Path, field: &str) -> Result<(), RuntimeError> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(invalid(format!(
            "{field} must be a non-empty absolute path"
        )));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(invalid(format!(
            "{field} contains a forbidden path component"
        )));
    }
    Ok(())
}

fn validate_guest_path(path: &Path, field: &str) -> Result<(), RuntimeError> {
    validate_absolute_clean_path(path, field)?;
    validate_shell_value(&path.display().to_string(), field)
}

fn validate_no_colon(path: &Path, field: &str) -> Result<(), RuntimeError> {
    if path.as_os_str().to_string_lossy().contains(':') {
        return Err(invalid(format!(
            "{field} cannot contain `:` in Hyperlight mount syntax"
        )));
    }
    Ok(())
}

fn validate_directory_no_symlinks(path: &Path) -> Result<(), RuntimeError> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(value) = component else {
            continue;
        };
        current.push(value);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| provider_io("inspecting mount path", error))?;
        if metadata.file_type().is_symlink() {
            return Err(invalid(format!(
                "mount path `{}` must not contain symbolic links",
                path.display()
            )));
        }
    }
    if !fs::metadata(path)
        .map_err(|error| provider_io("inspecting mount source", error))?
        .is_dir()
    {
        return Err(invalid(format!(
            "Hyperlight mount source `{}` must be a directory",
            path.display()
        )));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), RuntimeError> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|error| provider_io("creating private Hyperlight directory", error))?;
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| provider_io("inspecting private Hyperlight directory", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid(format!(
            "Hyperlight state directory `{}` must be a non-symlink directory with mode 0700",
            path.display()
        )));
    }
    Ok(())
}

fn create_private_child(parent: &Dir, name: &str) -> Result<Dir, RuntimeError> {
    parent
        .create_dir_with(name, DirBuilder::new().mode(0o700))
        .map_err(|error| provider_io("creating anchored Hyperlight directory", error))?;
    let child = parent
        .open_dir(name)
        .map_err(|error| provider_io("opening anchored Hyperlight directory", error))?;
    validate_private_directory_handle(&child)?;
    Ok(child)
}

fn validate_private_directory_handle(directory: &Dir) -> Result<(), RuntimeError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| provider_io("inspecting anchored Hyperlight directory", error))?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "anchored Hyperlight directory must be owned by the runtime user with mode 0700",
        ));
    }
    Ok(())
}

fn validate_state_directory_ancestry(path: &Path) -> Result<(), RuntimeError> {
    validate_absolute_clean_path(path, "state directory")?;
    let runtime_uid = rustix::process::getuid().as_raw();
    let mut current = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(value) = component else {
            continue;
        };
        current.push(value);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| provider_io("inspecting state directory ancestry", error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != runtime_uid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid(format!(
                "state path component `{}` must be a non-symlink directory owned by root or the runtime user and not group- or world-writable",
                current.display()
            )));
        }
    }
    Ok(())
}

fn copy_directory_read_only(source: &Path, destination: &Path) -> Result<(), RuntimeError> {
    let descriptor = open_directory_no_symlinks(source)
        .map_err(|error| RuntimeError::Provider(format!("opening read-only mount: {error}")))?;
    let source = Dir::from_std_file(File::from(descriptor));
    create_private_directory(destination)?;
    copy_directory_contents(&source, destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o500))
        .map_err(|error| provider_io("locking staged mount directory", error))
}

fn copy_directory_contents(source: &Dir, destination: &Path) -> Result<(), RuntimeError> {
    for entry in source
        .entries()
        .map_err(|error| provider_io("reading read-only mount source", error))?
    {
        let entry = entry.map_err(|error| provider_io("reading mount entry", error))?;
        let name = entry.file_name();
        let destination_path = destination.join(&name);
        let metadata = source
            .symlink_metadata(&name)
            .map_err(|error| provider_io("inspecting mount entry", error))?;
        if metadata.file_type().is_symlink() {
            return Err(invalid(format!(
                "read-only mount contains symbolic link `{}`",
                name.to_string_lossy()
            )));
        }
        if metadata.is_dir() {
            let child = source
                .open_dir(&name)
                .map_err(|error| provider_io("opening staged mount directory", error))?;
            if !child
                .dir_metadata()
                .map_err(|error| provider_io("inspecting opened mount directory", error))?
                .is_dir()
            {
                return Err(invalid("read-only mount directory changed while staging"));
            }
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&destination_path)
                .map_err(|error| provider_io("creating staged mount directory", error))?;
            copy_directory_contents(&child, &destination_path)?;
            fs::set_permissions(&destination_path, fs::Permissions::from_mode(0o500))
                .map_err(|error| provider_io("locking staged mount directory", error))?;
        } else if metadata.is_file() {
            let mut source_file = source
                .open(&name)
                .map_err(|error| provider_io("opening staged mount source file", error))?
                .into_std();
            let opened_metadata = source_file
                .metadata()
                .map_err(|error| provider_io("inspecting opened mount source file", error))?;
            if !opened_metadata.is_file() {
                return Err(invalid("read-only mount file changed while staging"));
            }
            if opened_metadata.nlink() != 1 {
                return Err(invalid(format!(
                    "read-only mount file `{}` has multiple hard links",
                    name.to_string_lossy()
                )));
            }
            let mut destination_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&destination_path)
                .map_err(|error| provider_io("creating staged mount file", error))?;
            std::io::copy(&mut source_file, &mut destination_file)
                .map_err(|error| provider_io("copying staged mount file", error))?;
        } else {
            return Err(invalid(format!(
                "read-only mount contains non-regular entry `{}`",
                name.to_string_lossy()
            )));
        }
    }
    Ok(())
}

fn artifact_relative_path(root: &Path, artifact: &Path) -> Result<PathBuf, RuntimeError> {
    artifact
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|_| {
            invalid(format!(
                "artifact `{}` must be inside signed bundle root `{}`",
                artifact.display(),
                root.display()
            ))
        })
        .and_then(|relative| {
            if relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                Err(invalid("artifact path must identify a bundle file"))
            } else {
                Ok(relative)
            }
        })
}

fn artifact_digest(
    verified: &VerifiedBundle,
    path: &Path,
    kind: ArtifactKind,
) -> Result<String, RuntimeError> {
    verified
        .manifest
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.path == path && artifact.kind == kind)
        .map(|artifact| artifact.sha256.to_ascii_lowercase())
        .ok_or_else(|| {
            RuntimeError::Provider(format!(
                "signed bundle is missing expected {kind:?} artifact `{}`",
                path.display()
            ))
        })
}

fn verify_file_digest(path: &Path, expected: &str) -> Result<(), RuntimeError> {
    let mut file =
        File::open(path).map_err(|error| provider_io("opening staged artifact", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| provider_io("hashing staged artifact", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if encode_hex(&hasher.finalize()) != expected {
        return Err(RuntimeError::Provider(format!(
            "staged artifact `{}` failed signed digest verification",
            path.display()
        )));
    }
    Ok(())
}

fn host_architecture() -> Result<Architecture, RuntimeError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::Aarch64),
        architecture => Err(RuntimeError::Unavailable {
            runtime: RuntimeId::new("hyperlight")?,
            reason: format!("unsupported Hyperlight architecture `{architecture}`"),
        }),
    }
}

#[cfg(target_os = "linux")]
fn verify_kvm(runtime_id: &RuntimeId) -> Result<(), RuntimeError> {
    verify_kvm_device(Path::new("/dev/kvm"), runtime_id)
}

#[cfg(any(target_os = "linux", test))]
fn verify_kvm_device(path: &Path, runtime_id: &RuntimeId) -> Result<(), RuntimeError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map(|_| ())
        .map_err(|error| RuntimeError::Unavailable {
            runtime: runtime_id.clone(),
            reason: format!("{} must be readable and writable: {error}", path.display()),
        })
}

#[cfg(not(target_os = "linux"))]
fn verify_kvm(runtime_id: &RuntimeId) -> Result<(), RuntimeError> {
    Err(RuntimeError::Unavailable {
        runtime: runtime_id.clone(),
        reason: "hyperlight-unikraft requires Linux KVM".to_owned(),
    })
}

fn transition(lifecycle: &LifecycleStateMachine, next: LifecycleState) -> Result<(), RuntimeError> {
    lifecycle
        .transition(next)
        .map(|_| ())
        .map_err(|error| match error {
            LifecycleTransitionError::Duplicate { state } => {
                RuntimeError::DuplicateTransition { state }
            }
            LifecycleTransitionError::Invalid { from, to } => {
                RuntimeError::InvalidTransition { from, to }
            }
        })
}

fn require_running(container: &Container) -> Result<(), RuntimeError> {
    let state = container.lifecycle.current();
    if state == LifecycleState::Running {
        Ok(())
    } else {
        Err(RuntimeError::InvalidTransition {
            from: state,
            to: LifecycleState::Running,
        })
    }
}

fn remove_path(path: &Path) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            make_tree_owner_writable(path)?;
            fs::remove_dir_all(path)
                .map_err(|error| provider_io("removing Hyperlight directory", error))
        }
        Ok(_) => {
            fs::remove_file(path).map_err(|error| provider_io("removing Hyperlight file", error))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(provider_io("inspecting Hyperlight cleanup path", error)),
    }
}

fn make_tree_owner_writable(path: &Path) -> Result<(), RuntimeError> {
    for entry in fs::read_dir(path)
        .map_err(|error| provider_io("reading Hyperlight cleanup directory", error))?
    {
        let entry =
            entry.map_err(|error| provider_io("reading Hyperlight cleanup entry", error))?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)
            .map_err(|error| provider_io("inspecting Hyperlight cleanup entry", error))?;
        if metadata.is_dir() {
            make_tree_owner_writable(&entry_path)?;
            fs::set_permissions(&entry_path, fs::Permissions::from_mode(0o700))
                .map_err(|error| provider_io("unlocking Hyperlight cleanup directory", error))?;
        } else if metadata.is_file() {
            fs::set_permissions(&entry_path, fs::Permissions::from_mode(0o600))
                .map_err(|error| provider_io("unlocking Hyperlight cleanup file", error))?;
        } else {
            return Err(invalid(format!(
                "cleanup path `{}` contains an unexpected file type",
                path.display()
            )));
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| provider_io("unlocking Hyperlight cleanup root", error))
}

fn invalid(reason: impl Into<String>) -> RuntimeError {
    RuntimeError::InvalidCommand {
        reason: reason.into(),
    }
}

fn provider_io(context: &str, error: std::io::Error) -> RuntimeError {
    RuntimeError::Provider(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests;
