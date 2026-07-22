use std::path::{Component, Path, PathBuf};

use sendbox_runtime::{
    CommandArgument, CommandSpec, ContainerId, EnvironmentVariable, ExecRequest, Program,
    RuntimeError, RuntimeSignal,
};

const GUEST_ARTIFACT_ROOT: &str = "/opt/sendbox";
const GUEST_TRUST_ROOT: &str = "/sendbox-trust-root.pub";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ImagePullPolicy {
    Always,
    #[default]
    Missing,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleEnvironmentVariable {
    pub key: String,
    pub value: String,
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleMount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppleNetworkConfiguration {
    pub network: Option<String>,
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
    pub no_dns: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppleResourceConfiguration {
    pub cpus: Option<u16>,
    pub memory_mib: Option<u64>,
    pub ulimits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleLaunchConfiguration {
    pub environment: Vec<AppleEnvironmentVariable>,
    pub mounts: Vec<AppleMount>,
    pub network: AppleNetworkConfiguration,
    pub resources: AppleResourceConfiguration,
    pub kernel: Option<PathBuf>,
    pub pull_policy: ImagePullPolicy,
    pub read_only_root: bool,
}

impl Default for AppleLaunchConfiguration {
    fn default() -> Self {
        Self {
            environment: Vec::new(),
            mounts: Vec::new(),
            network: AppleNetworkConfiguration::default(),
            resources: AppleResourceConfiguration::default(),
            kernel: None,
            pull_policy: ImagePullPolicy::Missing,
            read_only_root: false,
        }
    }
}

impl AppleLaunchConfiguration {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        for variable in &self.environment {
            validate_environment_key(&variable.key)?;
            if variable.value.as_bytes().contains(&0) {
                return Err(invalid("environment values must not contain NUL"));
            }
        }
        for mount in &self.mounts {
            validate_mapping_path(&mount.source, "mount source")?;
            validate_mapping_path(&mount.target, "mount target")?;
        }
        if let Some(network) = &self.network.network
            && (network.is_empty()
                || !network.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b',')
                }))
        {
            return Err(invalid("network names contain unsupported characters"));
        }
        for value in self
            .network
            .dns_servers
            .iter()
            .chain(self.network.dns_search.iter())
            .chain(self.resources.ulimits.iter())
        {
            validate_cli_value(value, "network and resource values")?;
        }
        if self.resources.cpus == Some(0) {
            return Err(invalid("CPU allocation must be greater than zero"));
        }
        if self.resources.memory_mib == Some(0) {
            return Err(invalid("memory allocation must be greater than zero"));
        }
        if let Some(kernel) = &self.kernel {
            validate_mapping_path(kernel, "kernel")?;
            if !kernel.is_file() {
                return Err(invalid("configured Apple container kernel does not exist"));
            }
        }
        if self.read_only_root {
            return Err(invalid(
                "read-only guest roots are unsupported until writable runtime tmpfs mounts are qualified",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
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

    #[must_use]
    pub fn help(&self, command: &str) -> CommandSpec {
        self.spec([command, "--help"])
    }

    #[must_use]
    pub fn image_inspect(&self, image: &str) -> CommandSpec {
        self.spec(["image", "inspect", image])
    }

    #[must_use]
    pub fn image_pull(&self, image: &str) -> CommandSpec {
        self.spec([
            "image",
            "pull",
            "--progress",
            "none",
            "--platform",
            "linux/arm64",
            image,
        ])
    }

    pub fn create(
        &self,
        id: &ContainerId,
        image: &str,
        launch: &AppleLaunchConfiguration,
        bundle_root: &Path,
        public_key: &Path,
    ) -> Result<CommandSpec, RuntimeError> {
        validate_image(image)?;
        launch.validate()?;
        validate_mapping_path(bundle_root, "bundle root")?;
        validate_mapping_path(public_key, "public key")?;

        let mut arguments = vec![
            plain("create"),
            plain("--name"),
            plain(id.as_str()),
            plain("--platform"),
            plain("linux/arm64"),
            plain("--entrypoint"),
            plain("/opt/sendbox/bin/sendbox-guest"),
            plain("--mount"),
            plain(format!(
                "type=bind,source={},target={GUEST_ARTIFACT_ROOT},readonly",
                display_path(bundle_root)
            )),
            plain("--mount"),
            plain(format!(
                "type=bind,source={},target={GUEST_TRUST_ROOT},readonly",
                display_path(public_key)
            )),
        ];
        append_environment(&mut arguments, &launch.environment);
        append_mounts(&mut arguments, &launch.mounts)?;
        append_network(&mut arguments, &launch.network)?;
        append_resources(&mut arguments, &launch.resources)?;
        if let Some(kernel) = &launch.kernel {
            arguments.extend([plain("--kernel"), plain(display_path(kernel))]);
        }
        arguments.extend([plain(image), plain("container-init")]);

        let mut command = self.command(arguments);
        append_secret_environment(&mut command, &launch.environment);
        Ok(command)
    }

    pub fn run(
        &self,
        id: &ContainerId,
        image: &str,
        launch: &AppleLaunchConfiguration,
        bundle_root: &Path,
        public_key: &Path,
    ) -> Result<CommandSpec, RuntimeError> {
        let mut command = self.create(id, image, launch, bundle_root, public_key)?;
        command.arguments[0] = plain("run");
        command.arguments.insert(3, plain("--detach"));
        Ok(command)
    }

    #[must_use]
    pub fn start(&self, id: &ContainerId) -> CommandSpec {
        self.spec(["start", id.as_str()])
    }

    #[must_use]
    pub fn inspect(&self, id: &ContainerId) -> CommandSpec {
        self.spec(["inspect", id.as_str()])
    }

    pub fn exec(
        &self,
        id: &ContainerId,
        request: &ExecRequest,
    ) -> Result<CommandSpec, RuntimeError> {
        let Program::Absolute(program) = &request.command.program else {
            return Err(invalid(
                "Apple container exec requires an absolute guest program",
            ));
        };
        validate_guest_path(program, "exec program")?;
        let mut arguments = vec![plain("exec")];
        if let Some(directory) = &request.command.current_directory {
            validate_guest_path(directory, "exec working directory")?;
            arguments.extend([plain("--workdir"), plain(display_path(directory))]);
        }
        let mut environment = request.command.environment.clone();
        environment.sort_by(|left, right| left.key.cmp(&right.key));
        for variable in &environment {
            validate_environment_key(&variable.key)?;
            arguments.push(plain("--env"));
            if variable.sensitive {
                arguments.push(plain(&variable.key));
            } else {
                arguments.push(plain(format!("{}={}", variable.key, variable.value)));
            }
        }
        arguments.extend([plain(id.as_str()), plain(display_path(program))]);
        arguments.extend(request.command.arguments.iter().cloned());
        let mut command = self.command(arguments);
        command.environment.extend(environment);
        Ok(command)
    }

    #[must_use]
    pub fn logs(&self, id: &ContainerId) -> CommandSpec {
        self.spec(["logs", "--follow", id.as_str()])
    }

    #[must_use]
    pub fn signal(&self, id: &ContainerId, signal: RuntimeSignal) -> CommandSpec {
        self.spec(["kill", "--signal", signal_name(signal), id.as_str()])
    }

    #[must_use]
    pub fn stop(&self, id: &ContainerId, seconds: u64) -> CommandSpec {
        self.spec(["stop", "--time", &seconds.to_string(), id.as_str()])
    }

    #[must_use]
    pub fn delete(&self, id: &ContainerId) -> CommandSpec {
        self.spec(["delete", id.as_str()])
    }

    #[must_use]
    pub fn supervisor(&self, id: &ContainerId) -> CommandSpec {
        self.spec([
            "exec",
            "--detach",
            "--user",
            "0:0",
            id.as_str(),
            "/opt/sendbox/bin/sendbox-guest",
            "supervisor",
            "--bootstrap-file",
            "/run/sendbox-bootstrap/bootstrap.json",
            "--trust-root-file",
            GUEST_TRUST_ROOT,
            "--artifact-root",
            GUEST_ARTIFACT_ROOT,
            "--runtime-root",
            "/run/sendbox",
            "--replay-root",
            "/var/lib/sendbox/replay",
        ])
    }

    #[must_use]
    pub fn bootstrap_install_argv(&self, id: &ContainerId) -> Vec<String> {
        [
            "exec",
            "--interactive",
            "--user",
            "0:0",
            id.as_str(),
            "/opt/sendbox/bin/sendbox-guest",
            "bootstrap-install",
            "--target",
            "/run/sendbox-bootstrap/bootstrap.json",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    pub fn bridge_argv(
        &self,
        id: &ContainerId,
        socket: &Path,
        timeout_seconds: u64,
    ) -> Result<Vec<String>, RuntimeError> {
        validate_guest_path(socket, "control socket")?;
        Ok([
            "exec",
            "--interactive",
            "--user",
            "0:0",
            id.as_str(),
            "/opt/sendbox/bin/sendbox-guest",
            "stdio-bridge",
            "--socket",
            &display_path(socket),
            "--connect-timeout-seconds",
            &timeout_seconds.to_string(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect())
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    fn spec<const N: usize>(&self, arguments: [&str; N]) -> CommandSpec {
        self.command(arguments.into_iter().map(plain).collect())
    }

    fn command(&self, arguments: Vec<CommandArgument>) -> CommandSpec {
        CommandSpec {
            arguments,
            environment: minimal_environment(),
            ..CommandSpec::new(Program::Absolute(self.executable.clone()))
        }
    }
}

fn append_environment(
    arguments: &mut Vec<CommandArgument>,
    environment: &[AppleEnvironmentVariable],
) {
    let mut sorted = environment.to_vec();
    sorted.sort_by(|left, right| left.key.cmp(&right.key));
    for variable in sorted {
        arguments.push(plain("--env"));
        if variable.sensitive {
            arguments.push(plain(variable.key));
        } else {
            arguments.push(plain(format!("{}={}", variable.key, variable.value)));
        }
    }
}

fn append_secret_environment(command: &mut CommandSpec, environment: &[AppleEnvironmentVariable]) {
    command.environment.extend(
        environment
            .iter()
            .filter(|variable| variable.sensitive)
            .map(|variable| {
                EnvironmentVariable::sensitive(variable.key.clone(), variable.value.clone())
            }),
    );
}

fn append_mounts(
    arguments: &mut Vec<CommandArgument>,
    mounts: &[AppleMount],
) -> Result<(), RuntimeError> {
    for mount in mounts {
        validate_mapping_path(&mount.source, "mount source")?;
        validate_mapping_path(&mount.target, "mount target")?;
        let mut specification = format!(
            "type=bind,source={},target={}",
            display_path(&mount.source),
            display_path(&mount.target)
        );
        if mount.read_only {
            specification.push_str(",readonly");
        }
        arguments.extend([plain("--mount"), plain(specification)]);
    }
    Ok(())
}

fn append_network(
    arguments: &mut Vec<CommandArgument>,
    network: &AppleNetworkConfiguration,
) -> Result<(), RuntimeError> {
    if let Some(name) = &network.network {
        validate_cli_value(name, "network name")?;
        arguments.extend([plain("--network"), plain(name)]);
    }
    for server in &network.dns_servers {
        validate_cli_value(server, "DNS server")?;
        arguments.extend([plain("--dns"), plain(server)]);
    }
    for search in &network.dns_search {
        validate_cli_value(search, "DNS search domain")?;
        arguments.extend([plain("--dns-search"), plain(search)]);
    }
    if network.no_dns {
        arguments.push(plain("--no-dns"));
    }
    Ok(())
}

fn append_resources(
    arguments: &mut Vec<CommandArgument>,
    resources: &AppleResourceConfiguration,
) -> Result<(), RuntimeError> {
    if let Some(cpus) = resources.cpus {
        if cpus == 0 {
            return Err(invalid("CPU allocation must be greater than zero"));
        }
        arguments.extend([plain("--cpus"), plain(cpus.to_string())]);
    }
    if let Some(memory_mib) = resources.memory_mib {
        if memory_mib == 0 {
            return Err(invalid("memory allocation must be greater than zero"));
        }
        arguments.extend([plain("--memory"), plain(format!("{memory_mib}M"))]);
    }
    for ulimit in &resources.ulimits {
        validate_cli_value(ulimit, "ulimit")?;
        arguments.extend([plain("--ulimit"), plain(ulimit)]);
    }
    Ok(())
}

fn validate_image(image: &str) -> Result<(), RuntimeError> {
    if image.is_empty()
        || image.starts_with('-')
        || image
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == 0)
    {
        return Err(invalid("image reference is invalid"));
    }
    Ok(())
}

fn validate_environment_key(key: &str) -> Result<(), RuntimeError> {
    let mut bytes = key.bytes();
    if !matches!(bytes.next(), Some(byte) if byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(invalid("environment key is invalid"));
    }
    Ok(())
}

fn validate_mapping_path(path: &Path, field: &str) -> Result<(), RuntimeError> {
    validate_guest_path(path, field)?;
    let text = path
        .to_str()
        .ok_or_else(|| invalid(format!("{field} must be valid UTF-8")))?;
    if text.contains([',', '=']) {
        return Err(invalid(format!(
            "{field} must not contain commas or equals signs"
        )));
    }
    Ok(())
}

fn validate_guest_path(path: &Path, field: &str) -> Result<(), RuntimeError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
        || path.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(invalid(format!(
            "{field} must be an absolute path without parent traversal or NUL"
        )));
    }
    Ok(())
}

fn validate_cli_value(value: &str, field: &str) -> Result<(), RuntimeError> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        return Err(invalid(format!("{field} must be non-empty and non-NUL")));
    }
    Ok(())
}

fn signal_name(signal: RuntimeSignal) -> &'static str {
    match signal {
        RuntimeSignal::Interrupt => "SIGINT",
        RuntimeSignal::Terminate => "SIGTERM",
        RuntimeSignal::Kill => "SIGKILL",
        RuntimeSignal::Hangup => "SIGHUP",
        RuntimeSignal::User1 => "SIGUSR1",
        RuntimeSignal::User2 => "SIGUSR2",
    }
}

pub(crate) fn minimal_environment() -> Vec<EnvironmentVariable> {
    let mut environment = vec![
        EnvironmentVariable::plain(
            "PATH",
            "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
        ),
        EnvironmentVariable::plain("LANG", "C"),
        EnvironmentVariable::plain("LC_ALL", "C"),
    ];
    for key in ["HOME", "USER", "TMPDIR"] {
        if let Ok(value) = std::env::var(key) {
            environment.push(EnvironmentVariable::plain(key, value));
        }
    }
    environment
}

fn plain(value: impl Into<String>) -> CommandArgument {
    CommandArgument::plain(value)
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn invalid(reason: impl Into<String>) -> RuntimeError {
    RuntimeError::InvalidCommand {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(command: &CommandSpec) -> Vec<&str> {
        command
            .arguments
            .iter()
            .map(|argument| argument.value.as_str())
            .collect()
    }

    #[test]
    fn create_uses_exact_argv_and_keeps_secret_values_out_of_argv() {
        let commands = AppleContainerCommands::new("/usr/local/bin/container");
        let id = ContainerId::new("apple-test").expect("id");
        let launch = AppleLaunchConfiguration {
            environment: vec![
                AppleEnvironmentVariable {
                    key: "PUBLIC".to_owned(),
                    value: "yes".to_owned(),
                    sensitive: false,
                },
                AppleEnvironmentVariable {
                    key: "TOKEN".to_owned(),
                    value: "secret".to_owned(),
                    sensitive: true,
                },
            ],
            mounts: vec![AppleMount {
                source: "/Users/example/project".into(),
                target: "/workspace".into(),
                read_only: true,
            }],
            network: AppleNetworkConfiguration {
                network: Some("sendbox-net".to_owned()),
                dns_servers: vec!["1.1.1.1".to_owned()],
                dns_search: vec!["example.test".to_owned()],
                no_dns: false,
            },
            resources: AppleResourceConfiguration {
                cpus: Some(4),
                memory_mib: Some(2048),
                ulimits: vec!["nofile=1024:2048".to_owned()],
            },
            ..AppleLaunchConfiguration::default()
        };
        let command = commands
            .create(
                &id,
                "ghcr.io/example/sendbox:latest",
                &launch,
                Path::new("/opt/host/sendbox-bundle"),
                Path::new("/opt/host/root.pub"),
            )
            .expect("create");
        assert_eq!(
            values(&command),
            vec![
                "create",
                "--name",
                "apple-test",
                "--platform",
                "linux/arm64",
                "--entrypoint",
                "/opt/sendbox/bin/sendbox-guest",
                "--mount",
                "type=bind,source=/opt/host/sendbox-bundle,target=/opt/sendbox,readonly",
                "--mount",
                "type=bind,source=/opt/host/root.pub,target=/sendbox-trust-root.pub,readonly",
                "--env",
                "PUBLIC=yes",
                "--env",
                "TOKEN",
                "--mount",
                "type=bind,source=/Users/example/project,target=/workspace,readonly",
                "--network",
                "sendbox-net",
                "--dns",
                "1.1.1.1",
                "--dns-search",
                "example.test",
                "--cpus",
                "4",
                "--memory",
                "2048M",
                "--ulimit",
                "nofile=1024:2048",
                "ghcr.io/example/sendbox:latest",
                "container-init",
            ]
        );
        assert!(!values(&command).join(" ").contains("secret"));
        assert!(
            command
                .environment
                .iter()
                .any(|variable| variable.key == "TOKEN"
                    && variable.value == "secret"
                    && variable.sensitive)
        );
    }

    #[test]
    fn bridge_and_lifecycle_argv_are_exact() {
        let commands = AppleContainerCommands::new("/usr/local/bin/container");
        let id = ContainerId::new("apple-test").expect("id");
        assert_eq!(values(&commands.start(&id)), ["start", "apple-test"]);
        assert_eq!(
            values(&commands.signal(&id, RuntimeSignal::User1)),
            ["kill", "--signal", "SIGUSR1", "apple-test"]
        );
        assert_eq!(
            commands
                .bridge_argv(&id, Path::new("/run/sendbox/001122/control.sock"), 30)
                .expect("bridge"),
            [
                "exec",
                "--interactive",
                "--user",
                "0:0",
                "apple-test",
                "/opt/sendbox/bin/sendbox-guest",
                "stdio-bridge",
                "--socket",
                "/run/sendbox/001122/control.sock",
                "--connect-timeout-seconds",
                "30",
            ]
        );
    }
}
