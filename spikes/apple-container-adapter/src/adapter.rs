use crate::process::{CommandSpec, ProcessControls, ProcessError, ProcessOutput, ProcessRunner};
use crate::transport::SocketPublication;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ContainerId(String);

impl ContainerId {
    pub fn parse(value: impl Into<String>) -> Result<Self, CommandBuildError> {
        let value = value.into();
        let mut characters = value.chars();
        let first = characters
            .next()
            .ok_or_else(|| CommandBuildError::InvalidContainerId(value.clone()))?;
        let valid_first = first.is_ascii_alphanumeric();
        let valid_rest = characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        });
        if !valid_first || !valid_rest || value.len() > 128 {
            return Err(CommandBuildError::InvalidContainerId(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestEnvironmentVariable {
    pub key: String,
    pub value: String,
    pub sensitive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountMapping {
    pub source: PathBuf,
    pub target: PathBuf,
    pub read_only: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkMapping {
    pub network: Option<String>,
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
    pub no_dns: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceMapping {
    pub cpus: Option<u16>,
    pub memory_mib: Option<u64>,
    pub ulimits: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerRequest {
    pub id: ContainerId,
    pub image: String,
    pub arguments: Vec<String>,
    pub detached: bool,
    pub environment: Vec<GuestEnvironmentVariable>,
    pub mounts: Vec<MountMapping>,
    pub network: NetworkMapping,
    pub resources: ResourceMapping,
    pub kernel: Option<PathBuf>,
    pub transport: Option<SocketPublication>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecRequest {
    pub id: ContainerId,
    pub arguments: Vec<String>,
    pub environment: Vec<GuestEnvironmentVariable>,
    pub workdir: Option<PathBuf>,
    pub detached: bool,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CommandBuildError {
    #[error("invalid container ID `{0}`")]
    InvalidContainerId(String),
    #[error(
        "image reference must be non-empty, must not start with `-`, and must not contain whitespace"
    )]
    InvalidImage,
    #[error("exec requires at least one argument")]
    EmptyExec,
    #[error("environment key `{0}` is invalid")]
    InvalidEnvironmentKey(String),
    #[error("{field} path must be absolute and must not contain commas, equals signs, or NUL")]
    InvalidMappingPath { field: &'static str },
    #[error("network name `{0}` is invalid")]
    InvalidNetwork(String),
    #[error("CPU count must be greater than zero")]
    InvalidCpuCount,
    #[error("memory limit must be greater than zero")]
    InvalidMemoryLimit,
    #[error("kernel path must be absolute")]
    InvalidKernel,
    #[error("signal `{0}` is invalid")]
    InvalidSignal(String),
}

#[derive(Clone, Debug)]
pub struct AppleContainerCommands {
    executable: PathBuf,
}

impl AppleContainerCommands {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }

    #[must_use]
    pub fn version(&self) -> CommandSpec {
        self.spec(["--version"])
    }

    #[must_use]
    pub fn service_status(&self) -> CommandSpec {
        self.spec(["system", "status", "--format", "json"])
    }

    pub fn create(&self, request: &ContainerRequest) -> Result<CommandSpec, CommandBuildError> {
        self.container_lifecycle("create", request)
    }

    pub fn run(&self, request: &ContainerRequest) -> Result<CommandSpec, CommandBuildError> {
        self.container_lifecycle("run", request)
    }

    #[must_use]
    pub fn start(&self, id: &ContainerId, attach: bool, interactive: bool) -> CommandSpec {
        let mut arguments = vec!["start".to_owned()];
        if attach {
            arguments.push("--attach".to_owned());
        }
        if interactive {
            arguments.push("--interactive".to_owned());
        }
        arguments.push(id.as_str().to_owned());
        CommandSpec::new(&self.executable, arguments)
    }

    #[must_use]
    pub fn status(&self, id: &ContainerId) -> CommandSpec {
        self.spec(["inspect", id.as_str()])
    }

    pub fn exec(&self, request: &ExecRequest) -> Result<CommandSpec, CommandBuildError> {
        if request.arguments.is_empty() {
            return Err(CommandBuildError::EmptyExec);
        }
        let mut arguments = vec!["exec".to_owned()];
        if request.detached {
            arguments.push("--detach".to_owned());
        }
        if let Some(workdir) = &request.workdir {
            validate_mapping_path(workdir, "workdir")?;
            arguments.extend(["--workdir".to_owned(), display_path(workdir)]);
        }
        let mut secret_environment = BTreeMap::new();
        append_environment(
            &mut arguments,
            &request.environment,
            &mut secret_environment,
        )?;
        arguments.push(request.id.as_str().to_owned());
        arguments.extend(request.arguments.clone());
        let mut specification = CommandSpec::new(&self.executable, arguments);
        for (key, value) in secret_environment {
            specification.add_secret_environment(key, value);
        }
        Ok(specification)
    }

    #[must_use]
    pub fn attach_logs(&self, id: &ContainerId) -> CommandSpec {
        self.spec(["logs", "--follow", id.as_str()])
    }

    pub fn signal(&self, id: &ContainerId, signal: &str) -> Result<CommandSpec, CommandBuildError> {
        if signal.is_empty()
            || signal.len() > 16
            || !signal
                .chars()
                .all(|character| character.is_ascii_alphanumeric())
        {
            return Err(CommandBuildError::InvalidSignal(signal.to_owned()));
        }
        Ok(self.spec(["kill", "--signal", signal, id.as_str()]))
    }

    #[must_use]
    pub fn stop(&self, id: &ContainerId, timeout_seconds: u32) -> CommandSpec {
        self.spec(["stop", "--time", &timeout_seconds.to_string(), id.as_str()])
    }

    #[must_use]
    pub fn delete(&self, id: &ContainerId) -> CommandSpec {
        self.spec(["delete", id.as_str()])
    }

    fn container_lifecycle(
        &self,
        subcommand: &str,
        request: &ContainerRequest,
    ) -> Result<CommandSpec, CommandBuildError> {
        validate_image(&request.image)?;
        let mut arguments = vec![
            subcommand.to_owned(),
            "--name".to_owned(),
            request.id.as_str().to_owned(),
        ];
        if request.detached {
            arguments.push("--detach".to_owned());
        }

        let mut secret_environment = BTreeMap::new();
        append_environment(
            &mut arguments,
            &request.environment,
            &mut secret_environment,
        )?;
        append_mounts(&mut arguments, &request.mounts)?;
        append_network(&mut arguments, &request.network)?;
        append_resources(&mut arguments, &request.resources)?;

        if let Some(kernel) = &request.kernel {
            if !kernel.is_absolute() {
                return Err(CommandBuildError::InvalidKernel);
            }
            arguments.extend(["--kernel".to_owned(), display_path(kernel)]);
        }
        if let Some(transport) = &request.transport {
            arguments.extend(["--publish-socket".to_owned(), transport.specification()]);
        }
        arguments.push(request.image.clone());
        arguments.extend(request.arguments.clone());

        let mut specification = CommandSpec::new(&self.executable, arguments);
        for (key, value) in secret_environment {
            specification.add_secret_environment(key, value);
        }
        Ok(specification)
    }

    fn spec<const N: usize>(&self, arguments: [&str; N]) -> CommandSpec {
        CommandSpec::new(
            &self.executable,
            arguments.into_iter().map(ToString::to_string).collect(),
        )
    }
}

fn append_environment(
    arguments: &mut Vec<String>,
    environment: &[GuestEnvironmentVariable],
    secret_environment: &mut BTreeMap<String, String>,
) -> Result<(), CommandBuildError> {
    let mut sorted = environment.to_vec();
    sorted.sort_by(|left, right| left.key.cmp(&right.key));
    for variable in sorted {
        if !valid_environment_key(&variable.key) {
            return Err(CommandBuildError::InvalidEnvironmentKey(variable.key));
        }
        arguments.push("--env".to_owned());
        if variable.sensitive {
            arguments.push(variable.key.clone());
            secret_environment.insert(variable.key, variable.value);
        } else {
            arguments.push(format!("{}={}", variable.key, variable.value));
        }
    }
    Ok(())
}

fn append_mounts(
    arguments: &mut Vec<String>,
    mounts: &[MountMapping],
) -> Result<(), CommandBuildError> {
    for mount in mounts {
        validate_mapping_path(&mount.source, "mount source")?;
        validate_mapping_path(&mount.target, "mount target")?;
        let mut value = format!(
            "type=bind,source={},target={}",
            mount.source.display(),
            mount.target.display()
        );
        if mount.read_only {
            value.push_str(",readonly");
        }
        arguments.extend(["--mount".to_owned(), value]);
    }
    Ok(())
}

fn append_network(
    arguments: &mut Vec<String>,
    network: &NetworkMapping,
) -> Result<(), CommandBuildError> {
    if let Some(name) = &network.network {
        if name.is_empty()
            || !name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            })
        {
            return Err(CommandBuildError::InvalidNetwork(name.clone()));
        }
        arguments.extend(["--network".to_owned(), name.clone()]);
    }
    for server in &network.dns_servers {
        arguments.extend(["--dns".to_owned(), server.clone()]);
    }
    for search in &network.dns_search {
        arguments.extend(["--dns-search".to_owned(), search.clone()]);
    }
    if network.no_dns {
        arguments.push("--no-dns".to_owned());
    }
    Ok(())
}

fn append_resources(
    arguments: &mut Vec<String>,
    resources: &ResourceMapping,
) -> Result<(), CommandBuildError> {
    if let Some(cpus) = resources.cpus {
        if cpus == 0 {
            return Err(CommandBuildError::InvalidCpuCount);
        }
        arguments.extend(["--cpus".to_owned(), cpus.to_string()]);
    }
    if let Some(memory_mib) = resources.memory_mib {
        if memory_mib == 0 {
            return Err(CommandBuildError::InvalidMemoryLimit);
        }
        arguments.extend(["--memory".to_owned(), format!("{memory_mib}M")]);
    }
    for ulimit in &resources.ulimits {
        arguments.extend(["--ulimit".to_owned(), ulimit.clone()]);
    }
    Ok(())
}

fn validate_image(image: &str) -> Result<(), CommandBuildError> {
    if image.is_empty() || image.starts_with('-') || image.chars().any(char::is_whitespace) {
        return Err(CommandBuildError::InvalidImage);
    }
    Ok(())
}

fn validate_mapping_path(path: &Path, field: &'static str) -> Result<(), CommandBuildError> {
    let path = path.to_string_lossy();
    if !Path::new(path.as_ref()).is_absolute()
        || path.contains(',')
        || path.contains('=')
        || path.contains('\0')
    {
        return Err(CommandBuildError::InvalidMappingPath { field });
    }
    Ok(())
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn valid_environment_key(key: &str) -> bool {
    let mut characters = key.chars();
    matches!(characters.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error(transparent)]
    Build(#[from] CommandBuildError),
    #[error(transparent)]
    Process(#[from] ProcessError),
    #[error("adapter state lock is poisoned")]
    StatePoisoned,
}

#[derive(Clone, Debug)]
pub struct PreflightOutput {
    pub version: ProcessOutput,
    pub service_status: ProcessOutput,
}

#[async_trait]
pub trait RuntimeAdapter {
    async fn initialize(&self) -> Result<PreflightOutput, AdapterError>;
    async fn create(&self, request: &ContainerRequest) -> Result<ProcessOutput, AdapterError>;
    async fn run(&self, request: &ContainerRequest) -> Result<ProcessOutput, AdapterError>;
    async fn start(
        &self,
        id: &ContainerId,
        attach: bool,
        interactive: bool,
    ) -> Result<ProcessOutput, AdapterError>;
    async fn status(&self, id: &ContainerId) -> Result<ProcessOutput, AdapterError>;
    async fn exec(&self, request: &ExecRequest) -> Result<ProcessOutput, AdapterError>;
    async fn attach_output(&self, id: &ContainerId) -> Result<ProcessOutput, AdapterError>;
    async fn signal(&self, id: &ContainerId, signal: &str) -> Result<ProcessOutput, AdapterError>;
    async fn stop(
        &self,
        id: &ContainerId,
        timeout_seconds: u32,
    ) -> Result<ProcessOutput, AdapterError>;
    async fn cleanup(&self) -> Result<Vec<ProcessOutput>, AdapterError>;
}

pub struct AppleContainerAdapter<R> {
    commands: AppleContainerCommands,
    runner: R,
    controls: ProcessControls,
    created: Mutex<BTreeSet<ContainerId>>,
}

impl<R> AppleContainerAdapter<R> {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>, runner: R, controls: ProcessControls) -> Self {
        Self {
            commands: AppleContainerCommands::new(executable),
            runner,
            controls,
            created: Mutex::new(BTreeSet::new()),
        }
    }
}

#[async_trait]
impl<R: ProcessRunner> RuntimeAdapter for AppleContainerAdapter<R> {
    async fn initialize(&self) -> Result<PreflightOutput, AdapterError> {
        let version = self
            .runner
            .run(&self.commands.version(), self.controls.clone())
            .await?;
        let service_status = self
            .runner
            .run(&self.commands.service_status(), self.controls.clone())
            .await?;
        Ok(PreflightOutput {
            version,
            service_status,
        })
    }

    async fn create(&self, request: &ContainerRequest) -> Result<ProcessOutput, AdapterError> {
        let output = self
            .runner
            .run(&self.commands.create(request)?, self.controls.clone())
            .await?;
        if output.status.success {
            self.record_created(request.id.clone())?;
        }
        Ok(output)
    }

    async fn run(&self, request: &ContainerRequest) -> Result<ProcessOutput, AdapterError> {
        let output = self
            .runner
            .run(&self.commands.run(request)?, self.controls.clone())
            .await?;
        if output.status.success {
            self.record_created(request.id.clone())?;
        }
        Ok(output)
    }

    async fn start(
        &self,
        id: &ContainerId,
        attach: bool,
        interactive: bool,
    ) -> Result<ProcessOutput, AdapterError> {
        Ok(self
            .runner
            .run(
                &self.commands.start(id, attach, interactive),
                self.controls.clone(),
            )
            .await?)
    }

    async fn status(&self, id: &ContainerId) -> Result<ProcessOutput, AdapterError> {
        Ok(self
            .runner
            .run(&self.commands.status(id), self.controls.clone())
            .await?)
    }

    async fn exec(&self, request: &ExecRequest) -> Result<ProcessOutput, AdapterError> {
        Ok(self
            .runner
            .run(&self.commands.exec(request)?, self.controls.clone())
            .await?)
    }

    async fn attach_output(&self, id: &ContainerId) -> Result<ProcessOutput, AdapterError> {
        Ok(self
            .runner
            .run(&self.commands.attach_logs(id), self.controls.clone())
            .await?)
    }

    async fn signal(&self, id: &ContainerId, signal: &str) -> Result<ProcessOutput, AdapterError> {
        Ok(self
            .runner
            .run(&self.commands.signal(id, signal)?, self.controls.clone())
            .await?)
    }

    async fn stop(
        &self,
        id: &ContainerId,
        timeout_seconds: u32,
    ) -> Result<ProcessOutput, AdapterError> {
        Ok(self
            .runner
            .run(
                &self.commands.stop(id, timeout_seconds),
                self.controls.clone(),
            )
            .await?)
    }

    async fn cleanup(&self) -> Result<Vec<ProcessOutput>, AdapterError> {
        let identifiers = self
            .created
            .lock()
            .map_err(|_| AdapterError::StatePoisoned)?
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut outputs = Vec::with_capacity(identifiers.len());
        for id in identifiers {
            let output = self
                .runner
                .run(&self.commands.delete(&id), self.controls.clone())
                .await?;
            if output.status.success {
                self.created
                    .lock()
                    .map_err(|_| AdapterError::StatePoisoned)?
                    .remove(&id);
            }
            outputs.push(output);
        }
        Ok(outputs)
    }
}

impl<R> AppleContainerAdapter<R> {
    fn record_created(&self, id: ContainerId) -> Result<(), AdapterError> {
        self.created
            .lock()
            .map_err(|_| AdapterError::StatePoisoned)?
            .insert(id);
        Ok(())
    }
}
