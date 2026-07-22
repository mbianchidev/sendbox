use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, RwLock},
    time::Duration,
};

use sendbox_bundle::{Architecture, VerifyOptions, verify_bundle};
use sendbox_runtime::{
    BootstrapDelivery, BoxFuture, CancellationToken, CleanupFailure, CleanupReport, ContainerId,
    ControlChannelRequest, ControlEndpointKind, CreateRequest, ExecPurpose, ExecRequest,
    InitializeRequest, LifecycleState, OutputSubscription, PreflightReport, PreflightRequest,
    ProcessOptions, ProcessOutcome, ProcessRunner, ProgramResolver, ProvisionedControlChannel,
    RunningProcess, RuntimeCapabilities, RuntimeCapability, RuntimeError, RuntimeHealth, RuntimeId,
    RuntimeProvider, RuntimeSignal, RuntimeStatus, StartRequest, StopRequest, TerminationReason,
};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

use crate::{
    channel::AppleStdioChannel,
    command::{
        AppleContainerCommands, AppleLaunchConfiguration, ImagePullPolicy, minimal_environment,
    },
    executable::{ExecutableReport, resolve_container_executable},
};

pub const APPLE_RUNTIME_ID: &str = "apple-container";
const SUPPORTED_VERSION: &str = "0.10.0";
const BOOTSTRAP_TARGET: &str = "/run/sendbox-bootstrap/bootstrap.json";
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_OUTPUT_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AppleRuntimeConfiguration {
    pub executable: Option<PathBuf>,
    pub bundle_root: PathBuf,
    pub public_key: PathBuf,
    pub trust_root_id: String,
    pub host_version: String,
    pub guest_version: String,
    pub minimum_release_sequence: u64,
    pub launch: AppleLaunchConfiguration,
    pub command_timeout: Duration,
    pub output_limit_bytes: usize,
    allow_untrusted_executable: bool,
    allow_untrusted_public_key: bool,
    allow_untrusted_bundle: bool,
    allow_non_apple_host: bool,
}

impl AppleRuntimeConfiguration {
    #[must_use]
    pub fn new(
        bundle_root: impl Into<PathBuf>,
        public_key: impl Into<PathBuf>,
        trust_root_id: impl Into<String>,
        host_version: impl Into<String>,
        guest_version: impl Into<String>,
    ) -> Self {
        Self {
            executable: None,
            bundle_root: bundle_root.into(),
            public_key: public_key.into(),
            trust_root_id: trust_root_id.into(),
            host_version: host_version.into(),
            guest_version: guest_version.into(),
            minimum_release_sequence: 0,
            launch: AppleLaunchConfiguration::default(),
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
            output_limit_bytes: DEFAULT_OUTPUT_LIMIT,
            allow_untrusted_executable: false,
            allow_untrusted_public_key: false,
            allow_untrusted_bundle: false,
            allow_non_apple_host: false,
        }
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        if !self.bundle_root.is_absolute() || !self.public_key.is_absolute() {
            return Err(provider_error(
                "Apple guest bundle and public-key paths must be absolute",
            ));
        }
        if self.trust_root_id.is_empty()
            || self.host_version.is_empty()
            || self.guest_version.is_empty()
        {
            return Err(provider_error(
                "Apple trust-root ID and host/guest versions must be non-empty",
            ));
        }
        if self.command_timeout.is_zero() || self.output_limit_bytes == 0 {
            return Err(provider_error(
                "Apple command timeout and output limit must be greater than zero",
            ));
        }
        self.launch.validate()
    }
}

struct AbsoluteOnlyResolver;

impl ProgramResolver for AbsoluteOnlyResolver {
    fn resolve(&self, name: &str) -> Result<PathBuf, RuntimeError> {
        Err(RuntimeError::ProgramNotFound {
            name: name.to_owned(),
        })
    }
}

struct ContainerRecord {
    lifecycle: LifecycleState,
    host_state_directory: PathBuf,
    log_process: Option<RunningProcess>,
    channel_provisioned: bool,
}

pub struct AppleRuntime {
    runtime_id: RuntimeId,
    configuration: AppleRuntimeConfiguration,
    executable_report: ExecutableReport,
    commands: AppleContainerCommands,
    runner: ProcessRunner,
    state_directory: RwLock<Option<PathBuf>>,
    containers: RwLock<BTreeMap<ContainerId, Arc<tokio::sync::Mutex<ContainerRecord>>>>,
}

impl std::fmt::Debug for AppleRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppleRuntime")
            .field("runtime_id", &self.runtime_id)
            .field("configuration", &self.configuration)
            .field("executable_report", &self.executable_report)
            .finish_non_exhaustive()
    }
}

impl AppleRuntime {
    pub fn new(configuration: AppleRuntimeConfiguration) -> Result<Self, RuntimeError> {
        configuration.validate()?;
        let executable_report = resolve_container_executable(configuration.executable.as_deref());
        let executable = executable_report
            .resolved_path
            .clone()
            .or_else(|| configuration.executable.clone())
            .unwrap_or_else(|| PathBuf::from("/usr/local/bin/container"));
        Ok(Self {
            runtime_id: RuntimeId::new(APPLE_RUNTIME_ID)?,
            configuration,
            executable_report,
            commands: AppleContainerCommands::new(executable),
            runner: ProcessRunner::new(Arc::new(AbsoluteOnlyResolver)),
            state_directory: RwLock::new(None),
            containers: RwLock::new(BTreeMap::new()),
        })
    }

    fn advertised_capabilities() -> RuntimeCapabilities {
        RuntimeCapabilities::from([
            RuntimeCapability::Lifecycle,
            RuntimeCapability::Exec,
            RuntimeCapability::StreamedIo,
            RuntimeCapability::Signals,
            RuntimeCapability::Mounts,
            RuntimeCapability::Network,
            RuntimeCapability::Health,
            RuntimeCapability::TransportProvisioning,
            RuntimeCapability::BrokeredExec,
            RuntimeCapability::InheritedStdioControlChannel,
        ])
    }

    async fn check_preflight(&self, cancellation: &CancellationToken) -> Result<(), RuntimeError> {
        self.configuration.validate()?;
        if !self.configuration.allow_non_apple_host
            && (std::env::consts::OS != "macos" || std::env::consts::ARCH != "aarch64")
        {
            return Err(RuntimeError::Unavailable {
                runtime: self.runtime_id.clone(),
                reason: format!(
                    "requires macOS arm64, found {} {}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ),
            });
        }
        if !self.executable_report.trusted && !self.configuration.allow_untrusted_executable {
            return Err(RuntimeError::Unavailable {
                runtime: self.runtime_id.clone(),
                reason: self.executable_report.reasons.join("; "),
            });
        }
        self.verify_launch_artifacts()?;

        let version = self
            .run_checked(self.commands.version(), cancellation)
            .await?;
        ensure_complete_output(&version, "Apple container version")?;
        let version = String::from_utf8_lossy(&version.stdout.bytes);
        if !version.contains(&format!("container CLI version {SUPPORTED_VERSION}")) {
            return Err(RuntimeError::Unavailable {
                runtime: self.runtime_id.clone(),
                reason: format!(
                    "requires official Apple container CLI {SUPPORTED_VERSION}; observed `{}`",
                    version.trim()
                ),
            });
        }

        for (command, tokens) in required_help_tokens() {
            let output = self
                .run_checked(self.commands.help(command), cancellation)
                .await?;
            ensure_complete_output(&output, &format!("Apple container {command} help"))?;
            let help = String::from_utf8_lossy(&output.stdout.bytes);
            let missing = tokens
                .iter()
                .filter(|token| !help.contains(**token))
                .copied()
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                return Err(RuntimeError::Unavailable {
                    runtime: self.runtime_id.clone(),
                    reason: format!(
                        "`container {command} --help` is missing required capability tokens: {}",
                        missing.join(", ")
                    ),
                });
            }
        }

        let service = self
            .run_raw(self.commands.service_status(), cancellation)
            .await?;
        ensure_complete_output(&service, "Apple container service status")?;
        let service_status: ServiceStatus =
            serde_json::from_slice(&service.stdout.bytes).map_err(|error| {
                RuntimeError::Unavailable {
                    runtime: self.runtime_id.clone(),
                    reason: format!("service status was not complete valid JSON: {error}"),
                }
            })?;
        if service_status.status != "running" {
            return Err(RuntimeError::Unavailable {
                runtime: self.runtime_id.clone(),
                reason: format!(
                    "Apple container service is `{}`; SendBox never starts, registers, or stops it",
                    service_status.status
                ),
            });
        }
        Ok(())
    }

    fn verify_bundle(&self) -> Result<(), RuntimeError> {
        verify_bundle(&VerifyOptions {
            root: &self.configuration.bundle_root,
            public_key: &self.configuration.public_key,
            architecture: Architecture::Aarch64,
            trust_root_id: &self.configuration.trust_root_id,
            host_version: &self.configuration.host_version,
            guest_version: &self.configuration.guest_version,
            minimum_release_sequence: self.configuration.minimum_release_sequence,
        })
        .map_err(|error| provider_error(format!("Apple guest bundle rejected: {error}")))?;
        Ok(())
    }

    fn verify_launch_artifacts(&self) -> Result<(), RuntimeError> {
        validate_public_key(
            &self.configuration.public_key,
            self.configuration.allow_untrusted_public_key,
        )?;
        validate_trusted_directory(
            &self.configuration.bundle_root,
            "Apple guest bundle",
            self.configuration.allow_untrusted_bundle,
        )?;
        if let Some(kernel) = &self.configuration.launch.kernel {
            validate_trusted_file(kernel, "Apple guest kernel", false)?;
        }
        self.verify_bundle()
    }

    fn process_options(&self) -> ProcessOptions {
        ProcessOptions {
            stdout_capture_bytes: self.configuration.output_limit_bytes,
            stderr_capture_bytes: self.configuration.output_limit_bytes,
            timeout: Some(self.configuration.command_timeout),
            ..ProcessOptions::default()
        }
    }

    async fn run_raw(
        &self,
        command: sendbox_runtime::CommandSpec,
        cancellation: &CancellationToken,
    ) -> Result<ProcessOutcome, RuntimeError> {
        let secrets = command
            .arguments
            .iter()
            .filter(|argument| argument.sensitive)
            .map(|argument| argument.value.as_bytes().to_vec())
            .chain(
                command
                    .environment
                    .iter()
                    .filter(|variable| variable.sensitive)
                    .map(|variable| variable.value.as_bytes().to_vec()),
            )
            .filter(|secret| !secret.is_empty())
            .collect::<Vec<_>>();
        let mut outcome = self
            .runner
            .run(command, self.process_options(), cancellation)
            .await?;
        redact_capture(&mut outcome.stdout.bytes, &secrets);
        redact_capture(&mut outcome.stderr.bytes, &secrets);
        Ok(outcome)
    }

    async fn run_checked(
        &self,
        command: sendbox_runtime::CommandSpec,
        cancellation: &CancellationToken,
    ) -> Result<ProcessOutcome, RuntimeError> {
        let outcome = self.run_raw(command, cancellation).await?;
        checked_outcome(outcome)
    }

    fn container(
        &self,
        id: &ContainerId,
    ) -> Result<Arc<tokio::sync::Mutex<ContainerRecord>>, RuntimeError> {
        self.containers
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| provider_error(format!("unknown Apple container `{id}`")))
    }

    async fn ensure_image(
        &self,
        image: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        match self.configuration.launch.pull_policy {
            ImagePullPolicy::Always => {
                self.run_checked(self.commands.image_pull(image), cancellation)
                    .await?;
            }
            ImagePullPolicy::Missing => {
                let inspection = self
                    .run_raw(self.commands.image_inspect(image), cancellation)
                    .await?;
                if !inspection.status.success {
                    self.run_checked(self.commands.image_pull(image), cancellation)
                        .await?;
                }
            }
            ImagePullPolicy::Never => {
                self.run_checked(self.commands.image_inspect(image), cancellation)
                    .await?;
            }
        }
        Ok(())
    }

    async fn inject_bootstrap(
        &self,
        id: &ContainerId,
        material: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        if cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        let argv = self.commands.bootstrap_install_argv(id);
        let mut command = Command::new(self.commands.executable());
        command
            .args(&argv)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for variable in minimal_environment() {
            command.env(variable.key, variable.value);
        }
        let mut child = command.spawn().map_err(|source| RuntimeError::Spawn {
            diagnostic: format!(
                "{} {}",
                self.commands.executable().display(),
                argv.join(" ")
            ),
            source,
        })?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| provider_error("Apple bootstrap installer stdin was not created"))?;
        stdin
            .write_all(material)
            .await
            .map_err(|source| RuntimeError::ProcessIo {
                stream: "Apple bootstrap installer stdin",
                source,
            })?;
        stdin
            .shutdown()
            .await
            .map_err(|source| RuntimeError::ProcessIo {
                stream: "Apple bootstrap installer stdin",
                source,
            })?;
        drop(stdin);
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| provider_error("Apple bootstrap installer stderr was not created"))?;
        let output_limit = self.configuration.output_limit_bytes;
        let stderr_task = tokio::spawn(async move {
            let mut bytes = Vec::new();
            stderr
                .take(u64::try_from(output_limit).unwrap_or(u64::MAX))
                .read_to_end(&mut bytes)
                .await
                .map(|_| bytes)
        });
        let status = tokio::select! {
            result = child.wait() => result.map_err(RuntimeError::Wait)?,
            () = cancellation.cancelled() => {
                child.start_kill().map_err(RuntimeError::Wait)?;
                child.wait().await.map_err(RuntimeError::Wait)?;
                return Err(RuntimeError::Cancelled);
            }
            () = tokio::time::sleep(self.configuration.command_timeout) => {
                child.start_kill().map_err(RuntimeError::Wait)?;
                child.wait().await.map_err(RuntimeError::Wait)?;
                return Err(RuntimeError::TimedOut);
            }
        };
        let stderr = stderr_task
            .await
            .map_err(|error| RuntimeError::ProcessTask(error.to_string()))?
            .map_err(|source| RuntimeError::ProcessIo {
                stream: "Apple bootstrap installer stderr",
                source,
            })?;
        if !status.success() {
            return Err(provider_error(format!(
                "Apple bootstrap installer failed: {}",
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        Ok(())
    }
}

impl RuntimeProvider for AppleRuntime {
    fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        Self::advertised_capabilities()
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
            prepare_state_directory(&request.state_directory)?;
            let mut state = self
                .state_directory
                .write()
                .unwrap_or_else(|poison| poison.into_inner());
            match state.as_ref() {
                Some(existing) if existing != &request.state_directory => Err(provider_error(
                    "Apple runtime was already initialized with a different state directory",
                )),
                Some(_) => Ok(()),
                None => {
                    *state = Some(request.state_directory);
                    Ok(())
                }
            }
        })
    }

    fn preflight<'a>(
        &'a self,
        request: PreflightRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<PreflightReport, RuntimeError>> {
        Box::pin(async move {
            self.check_preflight(cancellation).await?;
            let available = Self::advertised_capabilities();
            Ok(PreflightReport {
                missing_capabilities: request.required_capabilities.missing_from(&available),
                available_capabilities: available,
            })
        })
    }

    fn create<'a>(
        &'a self,
        request: CreateRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ContainerId, RuntimeError>> {
        Box::pin(async move {
            let state_root = self
                .state_directory
                .read()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone()
                .ok_or_else(|| provider_error("Apple runtime is not initialized"))?;
            self.verify_launch_artifacts()?;
            self.ensure_image(&request.image, cancellation).await?;
            let container_state = state_root.join("apple").join(request.container_id.as_str());
            prepare_state_directory(&container_state)?;
            let record = Arc::new(tokio::sync::Mutex::new(ContainerRecord {
                lifecycle: LifecycleState::Initialized,
                host_state_directory: container_state.clone(),
                log_process: None,
                channel_provisioned: false,
            }));
            {
                let mut containers = self
                    .containers
                    .write()
                    .unwrap_or_else(|poison| poison.into_inner());
                if containers.contains_key(&request.container_id) {
                    return Err(provider_error(format!(
                        "Apple container `{}` already exists",
                        request.container_id
                    )));
                }
                containers.insert(request.container_id.clone(), Arc::clone(&record));
            }
            let command = self.commands.create(
                &request.container_id,
                &request.image,
                &self.configuration.launch,
                &self.configuration.bundle_root,
                &self.configuration.public_key,
            )?;
            if let Err(error) = self.run_checked(command, cancellation).await {
                if !error
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("already exists")
                {
                    let cleanup_cancellation = CancellationToken::new();
                    let _ = self
                        .run_raw(
                            self.commands.delete(&request.container_id),
                            &cleanup_cancellation,
                        )
                        .await;
                }
                self.containers
                    .write()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .remove(&request.container_id);
                let _ = fs::remove_dir_all(&container_state);
                return Err(error);
            }
            record.lock().await.lifecycle = LifecycleState::Created;
            Ok(request.container_id)
        })
    }

    fn start<'a>(
        &'a self,
        container: &'a ContainerId,
        _request: StartRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            let record = self.container(container)?;
            let mut record = record.lock().await;
            if record.lifecycle == LifecycleState::Running {
                return Ok(());
            }
            if record.lifecycle != LifecycleState::Created {
                return Err(RuntimeError::InvalidTransition {
                    from: record.lifecycle,
                    to: LifecycleState::Running,
                });
            }
            self.run_checked(self.commands.start(container), cancellation)
                .await?;
            record.lifecycle = LifecycleState::Running;
            Ok(())
        })
    }

    fn provision_control_channel<'a>(
        &'a self,
        request: ControlChannelRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ProvisionedControlChannel>, RuntimeError>> {
        Box::pin(async move {
            request.validate()?;
            if request.endpoint_kind != ControlEndpointKind::InheritedStdio {
                return Err(RuntimeError::TransportUnavailable {
                    endpoint: request.endpoint_kind,
                    reason: "`--publish-socket` is intentionally not advertised without live VM evidence; Apple uses an authenticated `container exec --interactive` stdio relay"
                        .to_owned(),
                });
            }
            match &request.bootstrap_delivery {
                BootstrapDelivery::RuntimeInjection { target } if target == BOOTSTRAP_TARGET => {}
                _ => {
                    return Err(RuntimeError::InvalidControlChannel {
                        reason: format!(
                            "Apple inherited-stdio transport requires runtime injection at {BOOTSTRAP_TARGET}"
                        ),
                    });
                }
            }
            let record = self.container(&request.container_id)?;
            let mut record = record.lock().await;
            if record.lifecycle != LifecycleState::Running {
                return Err(RuntimeError::InvalidTransition {
                    from: record.lifecycle,
                    to: LifecycleState::Running,
                });
            }
            if record.channel_provisioned {
                return Err(RuntimeError::InvalidControlChannel {
                    reason: "Apple control channel was already provisioned".to_owned(),
                });
            }
            self.inject_bootstrap(
                &request.container_id,
                request.bootstrap_material.as_bytes(),
                cancellation,
            )
            .await?;
            self.run_checked(
                self.commands.supervisor(&request.container_id),
                cancellation,
            )
            .await?;
            let guest_socket =
                PathBuf::from(format!("/run/sendbox/{}/control.sock", request.session_id));
            let timeout_seconds = request.readiness_timeout.as_secs().clamp(1, 300);
            let bridge_argv =
                self.commands
                    .bridge_argv(&request.container_id, &guest_socket, timeout_seconds)?;
            record.channel_provisioned = true;
            Ok(
                Box::new(AppleStdioChannel::new(self.commands.clone(), bridge_argv))
                    as Box<dyn ProvisionedControlChannel>,
            )
        })
    }

    fn status<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<RuntimeStatus, RuntimeError>> {
        Box::pin(async move {
            let record = self.container(container)?;
            let lifecycle = record.lock().await.lifecycle;
            if matches!(
                lifecycle,
                LifecycleState::Cleaned | LifecycleState::Cleaning
            ) {
                return Ok(RuntimeStatus {
                    lifecycle,
                    health: RuntimeHealth::Unknown,
                });
            }
            let outcome = self
                .run_checked(self.commands.inspect(container), cancellation)
                .await?;
            ensure_complete_output(&outcome, "Apple container inspect")?;
            let observed = parse_lifecycle(&outcome.stdout.bytes).unwrap_or(lifecycle);
            Ok(RuntimeStatus {
                lifecycle: observed,
                health: if observed == LifecycleState::Running {
                    RuntimeHealth::Healthy
                } else {
                    RuntimeHealth::Unknown
                },
            })
        })
    }

    fn exec<'a>(
        &'a self,
        container: &'a ContainerId,
        request: ExecRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ProcessOutcome, RuntimeError>> {
        Box::pin(async move {
            if request.purpose == ExecPurpose::Workload {
                return Err(RuntimeError::WorkloadExecRequiresGuestBroker);
            }
            let record = self.container(container)?;
            if record.lock().await.lifecycle != LifecycleState::Running {
                return Err(provider_error("Apple exec requires a running container"));
            }
            let command = self.commands.exec(container, &request)?;
            self.run_raw(command, cancellation).await
        })
    }

    fn attach<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn OutputSubscription>, RuntimeError>> {
        Box::pin(async move {
            let record = self.container(container)?;
            let mut record = record.lock().await;
            if record.log_process.is_some() {
                return Err(provider_error("Apple logs are already attached"));
            }
            let mut process = self
                .runner
                .spawn(
                    self.commands.logs(container),
                    self.process_options(),
                    cancellation,
                )
                .await?;
            let subscription = process.take_output_subscription().ok_or_else(|| {
                provider_error("Apple logs process did not create an output subscription")
            })?;
            record.log_process = Some(process);
            Ok(subscription)
        })
    }

    fn signal<'a>(
        &'a self,
        container: &'a ContainerId,
        signal: RuntimeSignal,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            let record = self.container(container)?;
            if record.lock().await.lifecycle != LifecycleState::Running {
                return Ok(());
            }
            self.run_checked(self.commands.signal(container, signal), cancellation)
                .await?;
            Ok(())
        })
    }

    fn stop<'a>(
        &'a self,
        container: &'a ContainerId,
        request: StopRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            let record = self.container(container)?;
            let mut record = record.lock().await;
            if matches!(
                record.lifecycle,
                LifecycleState::Stopped | LifecycleState::Cleaned | LifecycleState::Cleaning
            ) {
                return Ok(());
            }
            if record.lifecycle != LifecycleState::Running {
                return Err(RuntimeError::InvalidTransition {
                    from: record.lifecycle,
                    to: LifecycleState::Stopped,
                });
            }
            record.lifecycle = LifecycleState::Stopping;
            let seconds = request.grace.as_secs().max(1);
            match self
                .run_checked(self.commands.stop(container, seconds), cancellation)
                .await
            {
                Ok(_) => {
                    record.lifecycle = LifecycleState::Stopped;
                    Ok(())
                }
                Err(error) => {
                    record.lifecycle = LifecycleState::Failed;
                    Err(error)
                }
            }
        })
    }

    fn cleanup<'a>(
        &'a self,
        container: &'a ContainerId,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<CleanupReport, RuntimeError>> {
        Box::pin(async move {
            let Some(record) = self
                .containers
                .read()
                .unwrap_or_else(|poison| poison.into_inner())
                .get(container)
                .cloned()
            else {
                return Ok(CleanupReport::default());
            };
            let mut record = record.lock().await;
            if record.lifecycle == LifecycleState::Cleaned {
                return Ok(CleanupReport::default());
            }
            let mut report = CleanupReport::default();
            let cleanup_cancellation = CancellationToken::new();
            if let Some(process) = record.log_process.take() {
                report.attempted += 1;
                drop(process);
                report.succeeded += 1;
            }
            if matches!(
                record.lifecycle,
                LifecycleState::Running | LifecycleState::Stopping
            ) {
                report.attempted += 1;
                match self
                    .run_checked(self.commands.stop(container, 1), &cleanup_cancellation)
                    .await
                {
                    Ok(_) => report.succeeded += 1,
                    Err(error) => report.failures.push(CleanupFailure {
                        step: "stop Apple container".to_owned(),
                        error,
                    }),
                }
            }
            report.attempted += 1;
            match self
                .run_raw(self.commands.delete(container), &cleanup_cancellation)
                .await
            {
                Ok(outcome) if outcome.status.success => report.succeeded += 1,
                Ok(outcome)
                    if String::from_utf8_lossy(&outcome.stderr.bytes)
                        .to_ascii_lowercase()
                        .contains("not found") =>
                {
                    report.succeeded += 1;
                }
                Ok(outcome) => report.failures.push(CleanupFailure {
                    step: "delete Apple container".to_owned(),
                    error: outcome_error(&outcome),
                }),
                Err(error) => report.failures.push(CleanupFailure {
                    step: "delete Apple container".to_owned(),
                    error,
                }),
            }
            report.attempted += 1;
            match fs::remove_dir_all(&record.host_state_directory) {
                Ok(()) => report.succeeded += 1,
                Err(error) if error.kind() == io::ErrorKind::NotFound => report.succeeded += 1,
                Err(error) => report.failures.push(CleanupFailure {
                    step: "remove Apple runtime state".to_owned(),
                    error: provider_error(format!(
                        "removing {}: {error}",
                        record.host_state_directory.display()
                    )),
                }),
            }
            report.remaining = report.failures.len();
            if report.is_complete() {
                record.lifecycle = LifecycleState::Cleaned;
                drop(record);
                self.containers
                    .write()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .remove(container);
            } else {
                record.lifecycle = LifecycleState::Failed;
            }
            Ok(report)
        })
    }
}

#[derive(Deserialize)]
struct ServiceStatus {
    status: String,
}

fn required_help_tokens() -> [(&'static str, &'static [&'static str]); 8] {
    [
        (
            "create",
            &[
                "--mount",
                "--env",
                "--network",
                "--dns",
                "--cpus",
                "--memory",
                "--kernel",
            ],
        ),
        ("start", &["container start"]),
        ("exec", &["--interactive", "--detach", "--workdir"]),
        ("logs", &["--follow"]),
        ("kill", &["--signal"]),
        ("stop", &["--time"]),
        ("delete", &["container delete"]),
        ("inspect", &["container inspect"]),
    ]
}

fn validate_public_key(path: &Path, allow_untrusted: bool) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        provider_error(format!(
            "cannot inspect Apple trust root {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(provider_error(
            "Apple trust root must be a single-link regular file, not a symlink",
        ));
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(provider_error(
            "Apple trust root must not be writable by group or other users",
        ));
    }
    if !allow_untrusted {
        if metadata.uid() != 0 {
            return Err(provider_error(format!(
                "Apple trust root must be root-owned, found uid {}",
                metadata.uid()
            )));
        }
        if mode != 0o444 {
            return Err(provider_error(format!(
                "Apple trust root must have mode 0444 for guest verification, found {mode:04o}"
            )));
        }
        validate_trusted_ancestors(path, "Apple trust root")?;
    }
    Ok(())
}

fn validate_trusted_directory(
    path: &Path,
    subject: &str,
    allow_untrusted: bool,
) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| provider_error(format!("cannot inspect {subject}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(provider_error(format!(
            "{subject} must be a real directory, not a symlink"
        )));
    }
    if !allow_untrusted {
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(provider_error(format!(
                "{subject} must be root-owned and not writable by group or other users"
            )));
        }
        validate_trusted_ancestors(path, subject)?;
    }
    Ok(())
}

fn validate_trusted_file(
    path: &Path,
    subject: &str,
    allow_untrusted: bool,
) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| provider_error(format!("cannot inspect {subject}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(provider_error(format!(
            "{subject} must be a single-link regular file, not a symlink"
        )));
    }
    if !allow_untrusted {
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(provider_error(format!(
                "{subject} must be root-owned and not writable by group or other users"
            )));
        }
        validate_trusted_ancestors(path, subject)?;
    }
    Ok(())
}

fn validate_trusted_ancestors(path: &Path, subject: &str) -> Result<(), RuntimeError> {
    for ancestor in path.ancestors().skip(1) {
        let metadata = fs::metadata(ancestor).map_err(|error| {
            provider_error(format!(
                "cannot inspect {subject} ancestor {}: {error}",
                ancestor.display()
            ))
        })?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(provider_error(format!(
                "{subject} ancestor {} is not root-owned and non-writable",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

fn prepare_state_directory(path: &Path) -> Result<(), RuntimeError> {
    if !path.is_absolute() {
        return Err(provider_error(
            "Apple runtime state directory must be absolute",
        ));
    }
    fs::create_dir_all(path).map_err(|error| {
        provider_error(format!(
            "creating Apple runtime state directory {}: {error}",
            path.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        provider_error(format!(
            "inspecting Apple runtime state directory {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(provider_error(
            "Apple runtime state path must be a real directory",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        provider_error(format!(
            "securing Apple runtime state directory {}: {error}",
            path.display()
        ))
    })
}

fn checked_outcome(outcome: ProcessOutcome) -> Result<ProcessOutcome, RuntimeError> {
    match outcome.termination {
        TerminationReason::Cancelled => Err(RuntimeError::Cancelled),
        TerminationReason::TimedOut => Err(RuntimeError::TimedOut),
        TerminationReason::Exited if outcome.status.success => Ok(outcome),
        TerminationReason::Exited => Err(outcome_error(&outcome)),
    }
}

fn ensure_complete_output(outcome: &ProcessOutcome, subject: &str) -> Result<(), RuntimeError> {
    if outcome.stdout.truncated_bytes != 0 || outcome.stderr.truncated_bytes != 0 {
        return Err(provider_error(format!(
            "{subject} exceeded the configured output cap"
        )));
    }
    Ok(())
}

fn redact_capture(bytes: &mut Vec<u8>, secrets: &[Vec<u8>]) {
    for secret in secrets {
        let mut offset = 0;
        while let Some(relative) = bytes[offset..]
            .windows(secret.len())
            .position(|window| window == secret)
        {
            let start = offset + relative;
            bytes.splice(start..start + secret.len(), b"<redacted>".iter().copied());
            offset = start + b"<redacted>".len();
        }
    }
}

fn outcome_error(outcome: &ProcessOutcome) -> RuntimeError {
    provider_error(format!(
        "Apple container command failed with code {:?}, signal {:?}: {}",
        outcome.status.code,
        outcome.status.signal,
        String::from_utf8_lossy(&outcome.stderr.bytes).trim()
    ))
}

fn parse_lifecycle(bytes: &[u8]) -> Option<LifecycleState> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    find_status(&value).and_then(|status| match status.to_ascii_lowercase().as_str() {
        "running" => Some(LifecycleState::Running),
        "stopped" | "exited" => Some(LifecycleState::Stopped),
        "created" => Some(LifecycleState::Created),
        _ => None,
    })
}

fn find_status(value: &serde_json::Value) -> Option<&str> {
    match value {
        serde_json::Value::Object(object) => object
            .iter()
            .find_map(|(key, value)| {
                key.eq_ignore_ascii_case("status")
                    .then(|| value.as_str())
                    .flatten()
            })
            .or_else(|| object.values().find_map(find_status)),
        serde_json::Value::Array(values) => values.iter().find_map(find_status),
        _ => None,
    }
}

fn provider_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::Provider(message.into())
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        sync::Arc,
    };

    use super::*;
    use sendbox_bundle::{Architecture, StageOptions, stage_bundle, write_public_key};
    use sendbox_runtime::{
        CommandArgument, CommandSpec, CreateRequest, ExecPurpose, ExecRequest, InitializeRequest,
        Program, StartRequest,
    };
    use sendbox_testkit::{RuntimeConformanceScenario, run_runtime_conformance};

    fn fixture_runtime() -> (tempfile::TempDir, AppleRuntime) {
        let temporary = tempfile::tempdir_in(std::env::current_dir().expect("current directory"))
            .expect("temporary");
        let fake_state = temporary.path().join("fake-state");
        fs::create_dir(&fake_state).expect("fake state");
        let executable = temporary.path().join("container");
        let script = format!(
            r#"#!/bin/sh
set -eu
state='{}'
last=''
for arg in "$@"; do last="$arg"; done
case "$1" in
  --version) echo 'container CLI version 0.10.0 (build: release, commit: fixture)' ;;
  system) echo '{{"status":"running"}}' ;;
  create|start|exec|logs|kill|stop|delete|inspect)
    if [ "${{2:-}}" = "--help" ]; then
      case "$1" in
        create) echo 'container create --mount --env --network --dns --cpus --memory --kernel' ;;
        start) echo 'container start' ;;
        exec) echo 'container exec --interactive --detach --workdir' ;;
        logs) echo 'container logs --follow' ;;
        kill) echo 'container kill --signal' ;;
        stop) echo 'container stop --time' ;;
        delete) echo 'container delete' ;;
        inspect) echo 'container inspect' ;;
      esac
      exit 0
    fi
    case "$1" in
      create) touch "$state/created" ;;
      start) touch "$state/running" ;;
      inspect) if [ -f "$state/running" ]; then echo '{{"status":"running"}}'; else echo '{{"status":"stopped"}}'; fi ;;
      exec) if [ "$last" = "noisy" ]; then printf '0123456789abcdef'; else echo 'exec-ok'; fi ;;
      logs) echo 'log-line' ;;
      stop) rm -f "$state/running" ;;
      delete) rm -f "$state/created" "$state/running" ;;
    esac
    ;;
  image)
    if [ "$last" = "slow:image" ]; then sleep 5; fi
    if [ "$last" = "fail:image" ]; then echo 'intentional image failure' >&2; exit 23; fi
    if [ "$2" = "inspect" ] || [ "$2" = "pull" ]; then exit 0; fi
    ;;
  *) echo "unexpected: $*" >&2; exit 64 ;;
esac
"#,
            fake_state.display()
        );
        fs::write(&executable, script).expect("script");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("mode");

        let inputs = temporary.path().join("inputs");
        fs::create_dir(&inputs).expect("inputs");
        let guest = inputs.join("guest");
        let launcher = inputs.join("launcher");
        let bpf = inputs.join("observe.bpf.o");
        fs::write(&guest, b"guest").expect("guest");
        fs::write(&launcher, b"launcher").expect("launcher");
        fs::write(&bpf, b"bpf").expect("bpf");
        let signing_key = inputs.join("signing.key");
        fs::write(&signing_key, [7_u8; 32]).expect("key");
        let public_key = inputs.join("root.pub");
        write_public_key(&signing_key, &public_key).expect("public key");
        let bundle = temporary.path().join("bundle");
        let input_metadata = fs::metadata(&guest).expect("guest metadata");
        let uid = input_metadata.uid();
        let gid = input_metadata.gid();
        stage_bundle(&StageOptions {
            output: &bundle,
            guest_binary: &guest,
            exec_launcher: &launcher,
            bpf_object: &bpf,
            signing_key: &signing_key,
            architecture: Architecture::Aarch64,
            trust_root_id: "fixture-root",
            release_sequence: 7,
            minimum_accepted_sequence: 1,
            host_version: "0.1.0",
            guest_version: "0.1.0",
            minimum_kernel: "6.6",
            btf_archive_sha256: &"a".repeat(64),
            vmlinux_header_sha256: &"b".repeat(64),
            uid,
            gid,
        })
        .expect("bundle");

        let mut configuration =
            AppleRuntimeConfiguration::new(bundle, public_key, "fixture-root", "0.1.0", "0.1.0");
        configuration.executable = Some(executable);
        configuration.minimum_release_sequence = 7;
        configuration.allow_non_apple_host = true;
        configuration.allow_untrusted_executable = true;
        configuration.allow_untrusted_public_key = true;
        configuration.allow_untrusted_bundle = true;
        (
            temporary,
            AppleRuntime::new(configuration).expect("runtime"),
        )
    }

    #[tokio::test]
    async fn fake_cli_passes_shared_runtime_conformance() {
        let (temporary, runtime) = fixture_runtime();
        let state = temporary.path().join("runtime-state");
        let scenario = RuntimeConformanceScenario {
            initialize: InitializeRequest {
                state_directory: state,
            },
            create: CreateRequest {
                container_id: ContainerId::new("apple-conformance").expect("id"),
                image: "fixture:image".to_owned(),
            },
            start: StartRequest::default(),
            exec: ExecRequest {
                command: CommandSpec {
                    arguments: vec![CommandArgument::plain("ok")],
                    ..CommandSpec::new(Program::Absolute(PathBuf::from("/bin/echo")))
                },
                purpose: ExecPurpose::BootstrapControl,
            },
            signal: Some(RuntimeSignal::Interrupt),
        };
        run_runtime_conformance(&runtime, scenario)
            .await
            .expect("conformance");
    }

    #[tokio::test]
    async fn workload_exec_is_rejected_without_invoking_cli() {
        let (temporary, runtime) = fixture_runtime();
        let cancellation = CancellationToken::new();
        runtime
            .initialize(
                InitializeRequest {
                    state_directory: temporary.path().join("state"),
                },
                &cancellation,
            )
            .await
            .expect("initialize");
        let id = runtime
            .create(
                CreateRequest {
                    container_id: ContainerId::new("apple-workload").expect("id"),
                    image: "fixture:image".to_owned(),
                },
                &cancellation,
            )
            .await
            .expect("create");
        runtime
            .start(&id, StartRequest::default(), &cancellation)
            .await
            .expect("start");
        let error = runtime
            .exec(
                &id,
                ExecRequest {
                    command: CommandSpec::new(Program::Absolute("/bin/true".into())),
                    purpose: ExecPurpose::Workload,
                },
                &cancellation,
            )
            .await
            .expect_err("workload exec must use broker");
        assert!(matches!(
            error,
            RuntimeError::WorkloadExecRequiresGuestBroker
        ));
    }

    #[tokio::test]
    async fn fake_cli_cancellation_terminates_the_inflight_operation() {
        let (temporary, runtime) = fixture_runtime();
        let runtime = Arc::new(runtime);
        let cancellation = CancellationToken::new();
        runtime
            .initialize(
                InitializeRequest {
                    state_directory: temporary.path().join("state"),
                },
                &cancellation,
            )
            .await
            .expect("initialize");
        let task_runtime = Arc::clone(&runtime);
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            task_runtime
                .create(
                    CreateRequest {
                        container_id: ContainerId::new("apple-cancel").expect("id"),
                        image: "slow:image".to_owned(),
                    },
                    &task_cancellation,
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancellation.cancel();
        assert!(matches!(
            task.await.expect("task"),
            Err(RuntimeError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn fake_cli_failures_are_reported_and_output_is_capped() {
        let (temporary, mut runtime) = fixture_runtime();
        runtime.configuration.output_limit_bytes = 8;
        let cancellation = CancellationToken::new();
        runtime
            .initialize(
                InitializeRequest {
                    state_directory: temporary.path().join("state"),
                },
                &cancellation,
            )
            .await
            .expect("initialize");
        assert!(
            runtime
                .create(
                    CreateRequest {
                        container_id: ContainerId::new("apple-failure").expect("id"),
                        image: "fail:image".to_owned(),
                    },
                    &cancellation,
                )
                .await
                .is_err()
        );
        let id = runtime
            .create(
                CreateRequest {
                    container_id: ContainerId::new("apple-output").expect("id"),
                    image: "fixture:image".to_owned(),
                },
                &cancellation,
            )
            .await
            .expect("create");
        runtime
            .start(&id, StartRequest::default(), &cancellation)
            .await
            .expect("start");
        let outcome = runtime
            .exec(
                &id,
                ExecRequest {
                    command: CommandSpec {
                        arguments: vec![CommandArgument::plain("noisy")],
                        ..CommandSpec::new(Program::Absolute("/bin/echo".into()))
                    },
                    purpose: ExecPurpose::BootstrapControl,
                },
                &cancellation,
            )
            .await
            .expect("exec");
        assert_eq!(outcome.stdout.bytes, b"01234567");
        assert_eq!(outcome.stdout.total_bytes, 16);
        assert_eq!(outcome.stdout.truncated_bytes, 8);
    }

    #[tokio::test]
    async fn adapter_rejects_bundle_rollback_before_image_or_container_launch() {
        let (temporary, mut runtime) = fixture_runtime();
        runtime.configuration.minimum_release_sequence = 8;
        let cancellation = CancellationToken::new();
        runtime
            .initialize(
                InitializeRequest {
                    state_directory: temporary.path().join("state"),
                },
                &cancellation,
            )
            .await
            .expect("initialize");
        let error = runtime
            .create(
                CreateRequest {
                    container_id: ContainerId::new("apple-rollback").expect("id"),
                    image: "fixture:image".to_owned(),
                },
                &cancellation,
            )
            .await
            .expect_err("rollback must fail closed");
        assert!(error.to_string().contains("bundle"));
    }
}
