#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use sendbox_bundle::{Architecture, VerifyOptions, verify_bundle};
use sendbox_policy::CommandPolicy;
use sendbox_runtime::{
    BootstrapDelivery, BoxFuture, CancellationToken, CleanupReport, CommandArgument, CommandSpec,
    ContainerId, ControlChannelRequest, ControlEndpointKind, ExecPurpose, ExecRequest,
    GuestAddress, HostAddress, InitializeRequest, LifecycleState, OutputSubscription,
    PreflightReport, PreflightRequest, ProcessOptions, ProcessOutcome, ProcessRunner, Program,
    ProvisionedControlChannel, ProvisionedControlChannelDescriptor, RuntimeCapabilities,
    RuntimeCapability, RuntimeError, RuntimeHealth, RuntimeId, RuntimeProvider, RuntimeSignal,
    RuntimeStatus, SearchPathResolver, StartRequest, StopRequest,
};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

const BUNDLE_GUEST: &str = "bin/sendbox-guest";
const BUNDLE_LAUNCHER: &str = "bin/sendbox-exec-launcher";
const GUEST_BUNDLE_ROOT: &str = "/opt/sendbox";
const GUEST_BOOTSTRAP: &str = "/run/sendbox-injected/bootstrap.json";
const GUEST_TRUST_ROOT: &str = "/run/sendbox-injected/trust.key";
const GUEST_RUNTIME_ROOT: &str = "/run/sendbox";
const GUEST_REPLAY_ROOT: &str = "/var/lib/sendbox/replay";
const GUEST_BROKER_RUNTIME: &str = "/run/sendbox-broker";
const GUEST_CGROUP_PARENT: &str = "/sys/fs/cgroup/sendbox";
const MAX_DIAGNOSTIC_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct KataProviderConfiguration {
    pub executable: String,
    pub runtime_handler: String,
    pub namespace: String,
    pub address: Option<String>,
    pub snapshotter: Option<String>,
    pub configuration_path: Option<PathBuf>,
    pub bundle_root: PathBuf,
    pub trust_root_file: PathBuf,
    pub trust_root_id: String,
    pub minimum_release_sequence: u64,
    pub command_policy: CommandPolicy,
    pub workload_uid: u32,
    pub workload_gid: u32,
}

#[derive(Debug, Clone)]
struct ContainerState {
    request: sendbox_runtime::CreateRequest,
    lifecycle: LifecycleState,
}

pub struct KataRuntimeProvider {
    runtime_id: RuntimeId,
    configuration: KataProviderConfiguration,
    executable: PathBuf,
    runner: ProcessRunner,
    state_directory: Mutex<Option<PathBuf>>,
    containers: Mutex<BTreeMap<ContainerId, ContainerState>>,
}

impl std::fmt::Debug for KataRuntimeProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KataRuntimeProvider")
            .field("runtime_id", &self.runtime_id)
            .field("executable", &self.executable)
            .field("namespace", &self.configuration.namespace)
            .finish_non_exhaustive()
    }
}

impl KataRuntimeProvider {
    pub fn new(configuration: KataProviderConfiguration) -> Result<Self, RuntimeError> {
        let executable = resolve_nerdctl(&configuration.executable)?;
        let resolver = SearchPathResolver::new([executable
            .parent()
            .ok_or_else(|| RuntimeError::Provider("nerdctl path has no parent".to_owned()))?
            .to_path_buf()])?;
        Ok(Self {
            runtime_id: RuntimeId::new("kata")?,
            configuration,
            executable,
            runner: ProcessRunner::new(Arc::new(resolver)),
            state_directory: Mutex::new(None),
            containers: Mutex::new(BTreeMap::new()),
        })
    }

    fn command(&self, operation: &str) -> CommandSpec {
        let mut command = CommandSpec::new(Program::Absolute(self.executable.clone()));
        command.arguments = self
            .global_arguments()
            .into_iter()
            .chain(std::iter::once(operation.to_owned()))
            .map(CommandArgument::plain)
            .collect();
        command.environment = minimal_client_environment();
        command
    }

    fn tokio_command(&self, operation: &str) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .args(self.global_arguments())
            .arg(operation)
            .env_clear();
        for variable in minimal_client_environment() {
            command.env(variable.key, variable.value);
        }
        command
    }

    fn global_arguments(&self) -> Vec<String> {
        let mut arguments = vec![
            "--namespace".to_owned(),
            self.configuration.namespace.clone(),
        ];
        if let Some(address) = &self.configuration.address {
            arguments.extend(["--address".to_owned(), address.clone()]);
        }
        if let Some(snapshotter) = &self.configuration.snapshotter {
            arguments.extend(["--snapshotter".to_owned(), snapshotter.clone()]);
        }
        arguments
    }

    async fn run_command(
        &self,
        command: CommandSpec,
        cancellation: &CancellationToken,
    ) -> Result<ProcessOutcome, RuntimeError> {
        self.runner
            .run(
                command,
                ProcessOptions {
                    stdout_capture_bytes: MAX_DIAGNOSTIC_BYTES,
                    stderr_capture_bytes: MAX_DIAGNOSTIC_BYTES,
                    timeout: Some(Duration::from_secs(120)),
                    ..ProcessOptions::default()
                },
                cancellation,
            )
            .await
    }

    fn require_success(operation: &str, outcome: ProcessOutcome) -> Result<(), RuntimeError> {
        if outcome.status.success {
            Ok(())
        } else {
            Err(RuntimeError::Provider(format!(
                "kata {operation} failed (exit={:?}, signal={:?}): {}",
                outcome.status.code,
                outcome.status.signal,
                String::from_utf8_lossy(&outcome.stderr.bytes)
            )))
        }
    }

    fn state_root(&self) -> Result<PathBuf, RuntimeError> {
        self.state_directory
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
            .ok_or_else(|| RuntimeError::Provider("kata runtime is not initialized".to_owned()))
    }

    fn update_lifecycle(
        &self,
        container: &ContainerId,
        expected: &[LifecycleState],
        next: LifecycleState,
    ) -> Result<(), RuntimeError> {
        let mut containers = self
            .containers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let state = containers
            .get_mut(container)
            .ok_or_else(|| RuntimeError::Provider(format!("unknown container `{container}`")))?;
        if !expected.contains(&state.lifecycle) {
            return Err(RuntimeError::InvalidTransition {
                from: state.lifecycle,
                to: next,
            });
        }
        state.lifecycle = next;
        Ok(())
    }

    async fn ensure_image(
        &self,
        image: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        if !image.contains("@sha256:") {
            return Err(RuntimeError::Provider(
                "Kata workload image must be pinned by sha256 digest".to_owned(),
            ));
        }
        let mut inspect = self.command("image");
        inspect
            .arguments
            .extend(["inspect", image].into_iter().map(CommandArgument::plain));
        if self
            .run_command(inspect, cancellation)
            .await?
            .status
            .success
        {
            return Ok(());
        }
        let mut pull = self.command("pull");
        pull.arguments.push(CommandArgument::plain(image));
        Self::require_success("image pull", self.run_command(pull, cancellation).await?)?;
        let mut inspect = self.command("image");
        inspect
            .arguments
            .extend(["inspect", image].into_iter().map(CommandArgument::plain));
        Self::require_success(
            "image verification",
            self.run_command(inspect, cancellation).await?,
        )
    }

    fn create_arguments(
        &self,
        request: &sendbox_runtime::CreateRequest,
        env_file: &Path,
    ) -> Result<Vec<CommandArgument>, RuntimeError> {
        validate_create_request(request)?;
        let mut arguments = Vec::new();
        push_pair(&mut arguments, "--name", request.container_id.as_str());
        push_pair(
            &mut arguments,
            "--runtime",
            &self.configuration.runtime_handler,
        );
        push_pair(&mut arguments, "--hostname", &request.hostname);
        push_pair(
            &mut arguments,
            "--cpus",
            &request.resources.cpus.to_string(),
        );
        push_pair(
            &mut arguments,
            "--memory",
            &request.resources.memory_bytes.to_string(),
        );
        push_pair(
            &mut arguments,
            "--workdir",
            request
                .working_directory
                .to_str()
                .ok_or_else(|| RuntimeError::InvalidCommand {
                    reason: "working directory is not UTF-8".to_owned(),
                })?,
        );
        push_pair(&mut arguments, "--user", "0:0");
        push_pair(&mut arguments, "--cgroupns", "host");
        push_pair(&mut arguments, "--security-opt", "seccomp=unconfined");
        for capability in ["SYS_ADMIN", "SETUID", "SETGID", "SETPCAP", "KILL"] {
            push_pair(&mut arguments, "--cap-add", capability);
        }
        if !request.environment.is_empty() {
            push_pair(
                &mut arguments,
                "--env-file",
                env_file
                    .to_str()
                    .ok_or_else(|| RuntimeError::InvalidCommand {
                        reason: "environment file path is not UTF-8".to_owned(),
                    })?,
            );
        }
        for dns in &request.dns_servers {
            push_pair(&mut arguments, "--dns", dns);
        }
        for label in &request.labels {
            push_pair(
                &mut arguments,
                "--label",
                &format!("{}={}", label.name, label.value),
            );
        }
        push_mount(
            &mut arguments,
            &self.configuration.bundle_root,
            Path::new(GUEST_BUNDLE_ROOT),
            false,
        )?;
        for mount in &request.mounts {
            push_mount(
                &mut arguments,
                &mount.source,
                &mount.destination,
                mount.writable,
            )?;
        }
        if let Some(path) = &self.configuration.configuration_path {
            push_pair(
                &mut arguments,
                "--annotation",
                &format!("io.katacontainers.config_path={}", path.display()),
            );
        }
        arguments.push(CommandArgument::plain(&request.image));
        arguments.extend(
            [
                format!("{GUEST_BUNDLE_ROOT}/{BUNDLE_GUEST}"),
                "supervisor".to_owned(),
                "--bootstrap-file".to_owned(),
                GUEST_BOOTSTRAP.to_owned(),
                "--trust-root-file".to_owned(),
                GUEST_TRUST_ROOT.to_owned(),
                "--artifact-root".to_owned(),
                GUEST_BUNDLE_ROOT.to_owned(),
                "--runtime-root".to_owned(),
                GUEST_RUNTIME_ROOT.to_owned(),
                "--replay-root".to_owned(),
                GUEST_REPLAY_ROOT.to_owned(),
            ]
            .into_iter()
            .map(CommandArgument::plain),
        );
        Ok(arguments)
    }

    async fn inject_bootstrap(
        &self,
        container: &ContainerId,
        payload: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        if cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        let mut command = self.tokio_command("exec");
        command
            .arg("-i")
            .arg(container.as_str())
            .arg(format!("{GUEST_BUNDLE_ROOT}/{BUNDLE_GUEST}"))
            .arg("inject-bootstrap")
            .arg("--bootstrap-target")
            .arg(GUEST_BOOTSTRAP)
            .arg("--trust-root-target")
            .arg(GUEST_TRUST_ROOT)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|source| RuntimeError::Spawn {
            diagnostic: "nerdctl bootstrap injection".to_owned(),
            source,
        })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            RuntimeError::Provider("bootstrap injection stdin was not created".to_owned())
        })?;
        tokio::select! {
            () = cancellation.cancelled() => {
                let _ = child.kill().await;
                return Err(RuntimeError::Cancelled);
            }
            result = stdin.write_all(payload) => {
                result.map_err(|source| RuntimeError::ProcessIo { stream: "stdin", source })?;
            }
        }
        drop(stdin);
        let output = child.wait_with_output().await.map_err(RuntimeError::Wait)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(RuntimeError::Provider(format!(
                "bootstrap injection failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }
}

impl RuntimeProvider for KataRuntimeProvider {
    fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::new([
            RuntimeCapability::Lifecycle,
            RuntimeCapability::Exec,
            RuntimeCapability::StreamedIo,
            RuntimeCapability::Signals,
            RuntimeCapability::Mounts,
            RuntimeCapability::Health,
            RuntimeCapability::TransportProvisioning,
            RuntimeCapability::BrokeredExec,
            RuntimeCapability::RuntimeExecStdioControlChannel,
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
            if !request.state_directory.is_absolute() {
                return Err(RuntimeError::Provider(
                    "Kata state directory must be absolute".to_owned(),
                ));
            }
            let root = request.state_directory.join("kata");
            fs::create_dir_all(&root).map_err(|source| {
                RuntimeError::Provider(format!(
                    "create Kata state directory {}: {source}",
                    root.display()
                ))
            })?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|source| {
                RuntimeError::Provider(format!(
                    "set Kata state directory permissions {}: {source}",
                    root.display()
                ))
            })?;
            *self
                .state_directory
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(root);
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
            strict_host_preflight(&self.executable, &self.configuration)?;
            verify_trusted_bundle(&self.configuration)?;
            let mut info = self.command("info");
            info.arguments.push(CommandArgument::plain("--format"));
            info.arguments.push(CommandArgument::plain("json"));
            let outcome = self.run_command(info, cancellation).await?;
            Self::require_success("containerd connectivity", outcome.clone())?;
            if !String::from_utf8_lossy(&outcome.stdout.bytes)
                .contains(&self.configuration.runtime_handler)
            {
                return Err(RuntimeError::Unavailable {
                    runtime: self.runtime_id.clone(),
                    reason: format!(
                        "nerdctl info did not report Kata handler `{}`",
                        self.configuration.runtime_handler
                    ),
                });
            }
            let available = self.capabilities();
            let missing = request.required_capabilities.missing_from(&available);
            Ok(PreflightReport {
                available_capabilities: available,
                missing_capabilities: missing,
            })
        })
    }

    fn create<'a>(
        &'a self,
        request: sendbox_runtime::CreateRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ContainerId, RuntimeError>> {
        Box::pin(async move {
            self.ensure_image(&request.image, cancellation).await?;
            let container_root = self.state_root()?.join(request.container_id.as_str());
            fs::create_dir(&container_root).map_err(|source| {
                RuntimeError::Provider(format!(
                    "create container state {}: {source}",
                    container_root.display()
                ))
            })?;
            fs::set_permissions(&container_root, fs::Permissions::from_mode(0o700)).map_err(
                |source| {
                    RuntimeError::Provider(format!(
                        "set container state permissions {}: {source}",
                        container_root.display()
                    ))
                },
            )?;
            let env_file = container_root.join("environment");
            write_environment_file(&env_file, &request.environment)?;
            let mut command = self.command("create");
            command
                .arguments
                .extend(self.create_arguments(&request, &env_file)?);
            let result = self.run_command(command, cancellation).await;
            let _ = fs::remove_file(&env_file);
            if let Err(error) = result.and_then(|outcome| Self::require_success("create", outcome))
            {
                let _ = fs::remove_dir_all(&container_root);
                return Err(error);
            }
            self.containers
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .insert(
                    request.container_id.clone(),
                    ContainerState {
                        request: request.clone(),
                        lifecycle: LifecycleState::Created,
                    },
                );
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
            let mut command = self.command("start");
            command
                .arguments
                .push(CommandArgument::plain(container.as_str()));
            Self::require_success("start", self.run_command(command, cancellation).await?)?;
            self.update_lifecycle(
                container,
                &[LifecycleState::Created],
                LifecycleState::Running,
            )
        })
    }

    fn provision_control_channel<'a>(
        &'a self,
        request: ControlChannelRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ProvisionedControlChannel>, RuntimeError>> {
        Box::pin(async move {
            request.validate()?;
            if request.endpoint_kind != ControlEndpointKind::RuntimeExecStdio {
                return Err(RuntimeError::TransportUnavailable {
                    endpoint: request.endpoint_kind,
                    reason: "Kata supports only the runtime exec stdio bridge".to_owned(),
                });
            }
            let BootstrapDelivery::RuntimeInjection { target } = &request.bootstrap_delivery else {
                return Err(RuntimeError::InvalidControlChannel {
                    reason: "Kata requires runtime-injected bootstrap material".to_owned(),
                });
            };
            if target != GUEST_BOOTSTRAP {
                return Err(RuntimeError::InvalidControlChannel {
                    reason: "unexpected Kata bootstrap target".to_owned(),
                });
            }
            let container = self
                .containers
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .get(&request.container_id)
                .cloned()
                .ok_or_else(|| RuntimeError::Provider("unknown Kata container".to_owned()))?;
            if container.lifecycle != LifecycleState::Running {
                return Err(RuntimeError::InvalidTransition {
                    from: container.lifecycle,
                    to: LifecycleState::Running,
                });
            }
            let trust_root =
                Zeroizing::new(fs::read(&self.configuration.trust_root_file).map_err(
                    |source| RuntimeError::Provider(format!("read trust root: {source}")),
                )?);
            if trust_root.len() != 32 {
                return Err(RuntimeError::Provider(
                    "trust root must contain exactly 32 bytes".to_owned(),
                ));
            }
            let payload = bootstrap_payload(
                &self.configuration,
                &request,
                &container.request,
                request.bootstrap_material.as_bytes(),
                &trust_root,
            )?;
            self.inject_bootstrap(&request.container_id, &payload, cancellation)
                .await?;
            let mut command = self.tokio_command("exec");
            command
                .arg("-i")
                .arg(request.container_id.as_str())
                .arg(format!("{GUEST_BUNDLE_ROOT}/{BUNDLE_GUEST}"))
                .arg("tunnel")
                .arg("--socket")
                .arg(format!(
                    "{GUEST_RUNTIME_ROOT}/{}/control.sock",
                    request.session_id
                ))
                .arg("--connect-timeout-ms")
                .arg(request.readiness_timeout.as_millis().to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().map_err(|source| RuntimeError::Spawn {
                diagnostic: "nerdctl Kata control tunnel".to_owned(),
                source,
            })?;
            let stdin = child.stdin.take().ok_or_else(|| {
                RuntimeError::Provider("control tunnel stdin was not created".to_owned())
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                RuntimeError::Provider("control tunnel stdout was not created".to_owned())
            })?;
            let stderr = child.stderr.take().ok_or_else(|| {
                RuntimeError::Provider("control tunnel stderr was not created".to_owned())
            })?;
            Ok(Box::new(KataControlChannel {
                descriptor: ProvisionedControlChannelDescriptor {
                    endpoint_kind: ControlEndpointKind::RuntimeExecStdio,
                    host_address: HostAddress::Stdio,
                    guest_address: GuestAddress::RuntimeDefined(format!(
                        "containerd-exec:{}/control.sock",
                        request.session_id
                    )),
                    ownership: request.ownership,
                    lifetime: request.lifetime,
                },
                child: Some(child),
                stream: Some(ExecControlStream {
                    reader: stdout,
                    writer: stdin,
                }),
                stderr_task: Some(spawn_stderr_capture(stderr)),
                cleaned: false,
            }) as Box<dyn ProvisionedControlChannel>)
        })
    }

    fn status<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<RuntimeStatus, RuntimeError>> {
        Box::pin(async move {
            let mut command = self.command("inspect");
            command
                .arguments
                .push(CommandArgument::plain(container.as_str()));
            let outcome = self.run_command(command, cancellation).await?;
            let lifecycle = self
                .containers
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .get(container)
                .map(|state| state.lifecycle)
                .unwrap_or(LifecycleState::Cleaned);
            Ok(RuntimeStatus {
                lifecycle,
                health: if outcome.status.success {
                    RuntimeHealth::Healthy
                } else {
                    RuntimeHealth::Unhealthy
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
            let mut command = self.command("exec");
            command
                .arguments
                .push(CommandArgument::plain(container.as_str()));
            append_command_spec(&mut command.arguments, request.command)?;
            self.run_command(command, cancellation).await
        })
    }

    fn attach<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn OutputSubscription>, RuntimeError>> {
        Box::pin(async move {
            let mut command = self.command("logs");
            command.arguments.extend(
                ["--follow", container.as_str()]
                    .into_iter()
                    .map(CommandArgument::plain),
            );
            let mut process = self
                .runner
                .spawn(
                    command,
                    ProcessOptions {
                        stdout_capture_bytes: MAX_DIAGNOSTIC_BYTES,
                        stderr_capture_bytes: MAX_DIAGNOSTIC_BYTES,
                        output_channel_capacity: 64,
                        ..ProcessOptions::default()
                    },
                    cancellation,
                )
                .await?;
            let subscription = process.take_output_subscription().ok_or_else(|| {
                RuntimeError::Provider("log subscription was unavailable".to_owned())
            })?;
            Ok(Box::new(OwnedProcessSubscription {
                process,
                subscription,
            }) as Box<dyn OutputSubscription>)
        })
    }

    fn signal<'a>(
        &'a self,
        container: &'a ContainerId,
        signal: RuntimeSignal,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            let mut command = self.command("kill");
            push_pair(
                &mut command.arguments,
                "--signal",
                match signal {
                    RuntimeSignal::Interrupt => "INT",
                    RuntimeSignal::Terminate => "TERM",
                    RuntimeSignal::Kill => "KILL",
                    RuntimeSignal::Hangup => "HUP",
                    RuntimeSignal::User1 => "USR1",
                    RuntimeSignal::User2 => "USR2",
                },
            );
            command
                .arguments
                .push(CommandArgument::plain(container.as_str()));
            Self::require_success("signal", self.run_command(command, cancellation).await?)
        })
    }

    fn stop<'a>(
        &'a self,
        container: &'a ContainerId,
        request: StopRequest,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            let mut command = self.command("stop");
            push_pair(
                &mut command.arguments,
                "--time",
                &request.grace.as_secs().to_string(),
            );
            command
                .arguments
                .push(CommandArgument::plain(container.as_str()));
            let outcome = self.run_command(command, cancellation).await?;
            if !outcome.status.success
                && !String::from_utf8_lossy(&outcome.stderr.bytes).contains("not found")
            {
                Self::require_success("stop", outcome)?;
            }
            let result = self.update_lifecycle(
                container,
                &[LifecycleState::Running, LifecycleState::Stopping],
                LifecycleState::Stopped,
            );
            match result {
                Err(RuntimeError::InvalidTransition {
                    from: LifecycleState::Stopped,
                    ..
                }) => Ok(()),
                other => other,
            }
        })
    }

    fn cleanup<'a>(
        &'a self,
        container: &'a ContainerId,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<CleanupReport, RuntimeError>> {
        Box::pin(async move {
            let mut command = self.command("rm");
            command.arguments.extend(
                ["--force", container.as_str()]
                    .into_iter()
                    .map(CommandArgument::plain),
            );
            let outcome = self.run_command(command, cancellation).await?;
            let mut failures = Vec::new();
            if !outcome.status.success
                && !String::from_utf8_lossy(&outcome.stderr.bytes).contains("not found")
            {
                failures.push(sendbox_runtime::CleanupFailure {
                    step: "remove container".to_owned(),
                    error: RuntimeError::Provider(format!(
                        "kata remove failed: {}",
                        String::from_utf8_lossy(&outcome.stderr.bytes)
                    )),
                });
            }
            if let Ok(root) = self.state_root() {
                let path = root.join(container.as_str());
                if let Err(source) = fs::remove_dir_all(&path)
                    && source.kind() != io::ErrorKind::NotFound
                {
                    failures.push(sendbox_runtime::CleanupFailure {
                        step: "remove state directory".to_owned(),
                        error: RuntimeError::Provider(format!(
                            "remove Kata state {}: {source}",
                            path.display()
                        )),
                    });
                }
            }
            self.containers
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .remove(container);
            Ok(CleanupReport {
                attempted: 2,
                succeeded: 2usize.saturating_sub(failures.len()),
                remaining: failures.len(),
                failures,
            })
        })
    }
}

struct KataControlChannel {
    descriptor: ProvisionedControlChannelDescriptor,
    child: Option<Child>,
    stream: Option<ExecControlStream>,
    stderr_task: Option<JoinHandle<Vec<u8>>>,
    cleaned: bool,
}

impl ProvisionedControlChannel for KataControlChannel {
    fn descriptor(&self) -> &ProvisionedControlChannelDescriptor {
        &self.descriptor
    }

    fn accept<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn sendbox_runtime::ControlStream>, RuntimeError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            self.stream
                .take()
                .map(|stream| Box::new(stream) as Box<dyn sendbox_runtime::ControlStream>)
                .ok_or(RuntimeError::ControlChannelAlreadyAccepted)
        })
    }

    fn cleanup<'a>(
        &'a mut self,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            if self.cleaned {
                return Ok(());
            }
            self.cleaned = true;
            self.stream.take();
            if let Some(mut child) = self.child.take() {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
            if let Some(task) = self.stderr_task.take() {
                let _ = task.await;
            }
            Ok(())
        })
    }
}

struct ExecControlStream {
    reader: ChildStdout,
    writer: ChildStdin,
}

impl AsyncRead for ExecControlStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(context, buffer)
    }
}

impl AsyncWrite for ExecControlStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.writer).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.writer).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.writer).poll_shutdown(context)
    }
}

struct OwnedProcessSubscription {
    process: sendbox_runtime::RunningProcess,
    subscription: Box<dyn OutputSubscription>,
}

impl OutputSubscription for OwnedProcessSubscription {
    fn next<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Option<sendbox_runtime::OutputEvent>, RuntimeError>> {
        let _ = &self.process;
        self.subscription.next(cancellation)
    }
}

#[derive(Serialize)]
struct BootstrapEnvelope<'a> {
    bootstrap: &'a [u8],
    trust_root: &'a [u8],
}

fn bootstrap_payload(
    configuration: &KataProviderConfiguration,
    channel: &ControlChannelRequest,
    create: &sendbox_runtime::CreateRequest,
    secret: &[u8],
    trust_root: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let mut nonce = [0_u8; 32];
    let mut authentication = [0_u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|error| RuntimeError::Provider(format!("generate bootstrap nonce: {error}")))?;
    getrandom::fill(&mut authentication).map_err(|error| {
        RuntimeError::Provider(format!("generate broker authentication: {error}"))
    })?;
    let workspace = create
        .mounts
        .iter()
        .find(|mount| mount.destination == Path::new("/workspace"))
        .ok_or_else(|| RuntimeError::Provider("Kata run requires a /workspace mount".to_owned()))?;
    let bootstrap = serde_json::json!({
        "schema_version": 1,
        "session_id": channel.session_id,
        "bootstrap_nonce": nonce,
        "bootstrap_secret": secret,
        "host_version": env!("CARGO_PKG_VERSION"),
        "trust_root_id": configuration.trust_root_id,
        "manifest_path": "manifest.json",
        "minimum_release_sequence": configuration.minimum_release_sequence,
        "required_controls": ["privilege_drop", "capabilities", "seccomp"],
        "required_services": [],
        "services": [],
        "execution_broker": {
            "authentication": authentication,
            "runtime_parent": GUEST_BROKER_RUNTIME,
            "socket_path": format!("{GUEST_BROKER_RUNTIME}/{}/s", channel.session_id),
            "launcher_path": format!("{GUEST_BUNDLE_ROOT}/{BUNDLE_LAUNCHER}"),
            "cgroup_parent": GUEST_CGROUP_PARENT,
            "workspace_root": workspace.destination,
            "system_root": "/",
            "workload_uid": configuration.workload_uid,
            "workload_gid": configuration.workload_gid,
            "command_policy": configuration.command_policy,
        }
    });
    let bootstrap = Zeroizing::new(
        serde_json::to_vec(&bootstrap)
            .map_err(|error| RuntimeError::Provider(format!("encode bootstrap: {error}")))?,
    );
    serde_json::to_vec(&BootstrapEnvelope {
        bootstrap: &bootstrap,
        trust_root,
    })
    .map_err(|error| RuntimeError::Provider(format!("encode bootstrap injection: {error}")))
}

fn strict_host_preflight(
    executable: &Path,
    configuration: &KataProviderConfiguration,
) -> Result<(), RuntimeError> {
    if !cfg!(target_os = "linux") {
        return Err(RuntimeError::Unavailable {
            runtime: RuntimeId::new("kata")?,
            reason: "Kata runtime requires Linux".to_owned(),
        });
    }
    let kvm = fs::metadata("/dev/kvm")
        .map_err(|source| RuntimeError::Provider(format!("inspect /dev/kvm: {source}")))?;
    if !kvm.file_type().is_char_device() {
        return Err(RuntimeError::Provider(
            "/dev/kvm is not a character device".to_owned(),
        ));
    }
    validate_trusted_file(executable, "nerdctl executable")?;
    validate_trusted_file(&configuration.trust_root_file, "bundle trust root")?;
    if let Some(path) = &configuration.configuration_path {
        if !path.is_absolute() {
            return Err(RuntimeError::Provider(
                "Kata configuration path must be absolute".to_owned(),
            ));
        }
        validate_trusted_file(path, "Kata configuration")?;
    }
    if configuration.namespace.is_empty()
        || configuration.runtime_handler.is_empty()
        || configuration.trust_root_id.is_empty()
        || configuration.minimum_release_sequence == 0
        || configuration.workload_uid == 0
        || configuration.workload_gid == 0
    {
        return Err(RuntimeError::Provider(
            "Kata provider configuration is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn verify_trusted_bundle(configuration: &KataProviderConfiguration) -> Result<(), RuntimeError> {
    let architecture = match std::env::consts::ARCH {
        "x86_64" => Architecture::X86_64,
        "aarch64" => Architecture::Aarch64,
        architecture => {
            return Err(RuntimeError::Provider(format!(
                "unsupported Kata bundle architecture `{architecture}`"
            )));
        }
    };
    verify_bundle(&VerifyOptions {
        root: &configuration.bundle_root,
        public_key: &configuration.trust_root_file,
        architecture,
        trust_root_id: &configuration.trust_root_id,
        host_version: env!("CARGO_PKG_VERSION"),
        guest_version: env!("CARGO_PKG_VERSION"),
        minimum_release_sequence: configuration.minimum_release_sequence,
    })
    .map_err(|error| RuntimeError::Provider(format!("verify signed guest bundle: {error}")))?;
    for executable in [BUNDLE_GUEST, BUNDLE_LAUNCHER] {
        verify_static_elf(&configuration.bundle_root.join(executable))?;
    }
    Ok(())
}

fn verify_static_elf(path: &Path) -> Result<(), RuntimeError> {
    let bytes = fs::read(path)
        .map_err(|source| RuntimeError::Provider(format!("read {}: {source}", path.display())))?;
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err(RuntimeError::Provider(format!(
            "{} is not a supported 64-bit little-endian ELF",
            path.display()
        )));
    }
    let phoff = usize::try_from(read_u64(&bytes, 32)?)
        .map_err(|_| RuntimeError::Provider("ELF program header offset is too large".to_owned()))?;
    let phentsize = usize::from(read_u16(&bytes, 54)?);
    let phnum = usize::from(read_u16(&bytes, 56)?);
    for index in 0..phnum {
        let offset = phoff
            .checked_add(index.saturating_mul(phentsize))
            .ok_or_else(|| RuntimeError::Provider("ELF program headers overflow".to_owned()))?;
        if read_u32(&bytes, offset)? == 3 {
            return Err(RuntimeError::Provider(format!(
                "{} contains PT_INTERP and is not static",
                path.display()
            )));
        }
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, RuntimeError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| RuntimeError::Provider("truncated ELF metadata".to_owned()))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RuntimeError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| RuntimeError::Provider("truncated ELF metadata".to_owned()))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, RuntimeError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| RuntimeError::Provider("truncated ELF metadata".to_owned()))?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn validate_trusted_file(path: &Path, description: &str) -> Result<(), RuntimeError> {
    let metadata = path.symlink_metadata().map_err(|source| {
        RuntimeError::Provider(format!(
            "inspect {description} {}: {source}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(RuntimeError::Provider(format!(
            "{description} {} must be root-owned, regular, and not group/world writable",
            path.display()
        )));
    }
    Ok(())
}

fn resolve_nerdctl(value: &str) -> Result<PathBuf, RuntimeError> {
    let path = Path::new(value);
    if path.is_absolute() {
        return fs::canonicalize(path).map_err(|source| {
            RuntimeError::Provider(format!("resolve nerdctl {}: {source}", path.display()))
        });
    }
    ["/usr/local/bin", "/usr/bin", "/bin"]
        .into_iter()
        .map(|directory| Path::new(directory).join(value))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| RuntimeError::ProgramNotFound {
            name: value.to_owned(),
        })
}

fn validate_create_request(request: &sendbox_runtime::CreateRequest) -> Result<(), RuntimeError> {
    if request.resources.cpus == 0 || request.resources.memory_bytes == 0 {
        return Err(RuntimeError::InvalidCommand {
            reason: "Kata CPU and memory resources must be non-zero".to_owned(),
        });
    }
    if request.hostname.is_empty()
        || request.hostname.len() > 63
        || !request
            .hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(RuntimeError::InvalidCommand {
            reason: "invalid Kata hostname".to_owned(),
        });
    }
    if !request.working_directory.is_absolute() {
        return Err(RuntimeError::InvalidWorkingDirectory {
            path: request.working_directory.clone(),
            reason: "must be absolute".to_owned(),
        });
    }
    for mount in &request.mounts {
        if !mount.source.is_absolute() || !mount.destination.is_absolute() || !mount.source.exists()
        {
            return Err(RuntimeError::InvalidCommand {
                reason: format!(
                    "invalid Kata mount {} -> {}",
                    mount.source.display(),
                    mount.destination.display()
                ),
            });
        }
    }
    for environment in &request.environment {
        if environment.name.is_empty()
            || environment.name.contains('=')
            || environment.name.as_bytes().contains(&0)
            || environment.value.contains(['\n', '\r', '\0'])
        {
            return Err(RuntimeError::InvalidCommand {
                reason: format!("invalid environment entry `{}`", environment.name),
            });
        }
    }
    for label in &request.labels {
        if label.name.is_empty()
            || label.name.contains('=')
            || label.name.as_bytes().contains(&0)
            || label.value.as_bytes().contains(&0)
        {
            return Err(RuntimeError::InvalidCommand {
                reason: "invalid Kata label".to_owned(),
            });
        }
    }
    Ok(())
}

fn write_environment_file(
    path: &Path,
    environment: &[sendbox_runtime::RuntimeEnvironment],
) -> Result<(), RuntimeError> {
    if environment.is_empty() {
        return Ok(());
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| RuntimeError::Provider(format!("create environment file: {source}")))?;
    for entry in environment {
        writeln!(file, "{}={}", entry.name, entry.value).map_err(|source| {
            RuntimeError::Provider(format!("write environment file: {source}"))
        })?;
    }
    file.sync_all()
        .map_err(|source| RuntimeError::Provider(format!("sync environment file: {source}")))
}

fn push_pair(arguments: &mut Vec<CommandArgument>, name: &str, value: &str) {
    arguments.push(CommandArgument::plain(name));
    arguments.push(CommandArgument::plain(value));
}

fn push_mount(
    arguments: &mut Vec<CommandArgument>,
    source: &Path,
    destination: &Path,
    writable: bool,
) -> Result<(), RuntimeError> {
    let source = source
        .to_str()
        .ok_or_else(|| RuntimeError::InvalidCommand {
            reason: "mount source is not UTF-8".to_owned(),
        })?;
    let destination = destination
        .to_str()
        .ok_or_else(|| RuntimeError::InvalidCommand {
            reason: "mount destination is not UTF-8".to_owned(),
        })?;
    let mode = if writable { "rw" } else { "ro" };
    push_pair(
        arguments,
        "--mount",
        &format!("type=bind,src={source},dst={destination},{mode}"),
    );
    Ok(())
}

fn append_command_spec(
    arguments: &mut Vec<CommandArgument>,
    command: CommandSpec,
) -> Result<(), RuntimeError> {
    let program = match command.program {
        Program::Absolute(path) => path
            .to_str()
            .ok_or_else(|| RuntimeError::InvalidCommand {
                reason: "exec program is not UTF-8".to_owned(),
            })?
            .to_owned(),
        Program::Named(name) => name,
    };
    arguments.push(CommandArgument::plain(program));
    arguments.extend(command.arguments);
    Ok(())
}

fn minimal_client_environment() -> Vec<sendbox_runtime::EnvironmentVariable> {
    let mut environment = vec![sendbox_runtime::EnvironmentVariable::plain(
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
    )];
    for name in ["HOME", "XDG_RUNTIME_DIR"] {
        if let Ok(value) = std::env::var(name) {
            environment.push(sendbox_runtime::EnvironmentVariable::plain(name, value));
        }
    }
    environment
}

fn spawn_stderr_capture(stderr: ChildStderr) -> JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        let _ = stderr
            .take(MAX_DIAGNOSTIC_BYTES as u64)
            .read_to_end(&mut bytes)
            .await;
        bytes
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use sendbox_policy::Action;
    use sendbox_runtime::{
        CreateRequest, InitializeRequest, RuntimeEnvironment, RuntimeLabel, RuntimeMount,
        RuntimeProvider, RuntimeResources, StartRequest, StopRequest,
    };
    use tempfile::tempdir;

    use super::*;

    fn configuration(
        executable: &Path,
        bundle: &Path,
        trust_root: &Path,
    ) -> KataProviderConfiguration {
        KataProviderConfiguration {
            executable: executable.display().to_string(),
            runtime_handler: "io.containerd.kata.v2".to_owned(),
            namespace: "sendbox-test".to_owned(),
            address: Some("/run/containerd-test.sock".to_owned()),
            snapshotter: Some("overlayfs".to_owned()),
            configuration_path: None,
            bundle_root: bundle.to_path_buf(),
            trust_root_file: trust_root.to_path_buf(),
            trust_root_id: "test-root".to_owned(),
            minimum_release_sequence: 1,
            command_policy: CommandPolicy {
                default_action: Action::Allow,
                allowlist: Vec::new(),
                denylist: Vec::new(),
                log_blocked: true,
            },
            workload_uid: 65_534,
            workload_gid: 65_534,
        }
    }

    fn request(workspace: &Path) -> CreateRequest {
        CreateRequest {
            container_id: ContainerId::new("kata-test").expect("container"),
            image: "registry.example/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            hostname: "kata-test".to_owned(),
            resources: RuntimeResources {
                cpus: 2,
                memory_bytes: 512 * 1024 * 1024,
            },
            mounts: vec![RuntimeMount {
                source: workspace.to_path_buf(),
                destination: PathBuf::from("/workspace"),
                writable: true,
            }],
            environment: vec![RuntimeEnvironment {
                name: "TOKEN".to_owned(),
                value: "not-on-argv".to_owned(),
                sensitive: true,
            }],
            working_directory: PathBuf::from("/workspace"),
            dns_servers: vec!["1.1.1.1".to_owned()],
            labels: vec![RuntimeLabel {
                name: "dev.sendbox.test".to_owned(),
                value: "exact value".to_owned(),
            }],
        }
    }

    #[tokio::test]
    async fn fake_nerdctl_preserves_argv_and_cleans_lifecycle() {
        let temporary = tempdir().expect("temporary");
        let log = temporary.path().join("argv.bin");
        let executable = temporary.path().join("nerdctl");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nprintf '%s\\0' \"$@\" >> '{}'\nexit 0\n",
                log.display()
            ),
        )
        .expect("fake nerdctl");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("executable mode");
        let bundle = temporary.path().join("bundle");
        let workspace = temporary.path().join("workspace");
        fs::create_dir(&bundle).expect("bundle");
        fs::create_dir(&workspace).expect("workspace");
        let trust_root = temporary.path().join("trust.key");
        fs::write(&trust_root, [7_u8; 32]).expect("trust root");
        let provider = KataRuntimeProvider::new(configuration(&executable, &bundle, &trust_root))
            .expect("provider");
        let state = temporary.path().join("state");
        provider
            .initialize(
                InitializeRequest {
                    state_directory: state,
                },
                &CancellationToken::new(),
            )
            .await
            .expect("initialize");
        let request = request(&workspace);
        let container = provider
            .create(request.clone(), &CancellationToken::new())
            .await
            .expect("create");
        provider
            .start(
                &container,
                StartRequest::default(),
                &CancellationToken::new(),
            )
            .await
            .expect("start");
        assert_eq!(
            provider
                .status(&container, &CancellationToken::new())
                .await
                .expect("status")
                .lifecycle,
            LifecycleState::Running
        );
        provider
            .stop(
                &container,
                StopRequest::default(),
                &CancellationToken::new(),
            )
            .await
            .expect("stop");
        assert!(
            provider
                .cleanup(&container, &CancellationToken::new())
                .await
                .expect("cleanup")
                .is_complete()
        );
        let argv = fs::read(log).expect("argv log");
        let arguments = argv
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .map(|argument| String::from_utf8(argument.to_vec()).expect("UTF-8 argv"))
            .collect::<Vec<_>>();
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--runtime", "io.containerd.kata.v2"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--label", "dev.sendbox.test=exact value"])
        );
        assert!(arguments.iter().any(|argument| argument == &request.image));
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("not-on-argv"))
        );
    }

    #[test]
    fn invalid_environment_and_mounts_fail_before_argv_generation() {
        let temporary = tempdir().expect("temporary");
        let executable = temporary.path().join("nerdctl");
        fs::write(&executable, b"").expect("executable");
        let bundle = temporary.path().join("bundle");
        fs::create_dir(&bundle).expect("bundle");
        let trust_root = temporary.path().join("trust.key");
        fs::write(&trust_root, [7_u8; 32]).expect("trust");
        let provider = KataRuntimeProvider::new(configuration(&executable, &bundle, &trust_root))
            .expect("provider");
        let mut invalid = request(temporary.path());
        invalid.environment[0].value = "line one\nline two".to_owned();
        assert!(
            provider
                .create_arguments(&invalid, Path::new("/secure/env"))
                .is_err()
        );
        invalid.environment.clear();
        invalid.mounts[0].source = PathBuf::from("relative");
        assert!(
            provider
                .create_arguments(&invalid, Path::new("/secure/env"))
                .is_err()
        );
    }

    #[test]
    fn elf_interpreter_is_rejected() {
        let temporary = tempdir().expect("temporary");
        let path = temporary.path().join("dynamic");
        let mut elf = vec![0_u8; 128];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        elf[64..68].copy_from_slice(&3_u32.to_le_bytes());
        fs::write(&path, elf).expect("ELF fixture");
        assert!(verify_static_elf(&path).is_err());
    }
}
