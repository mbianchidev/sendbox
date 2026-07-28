use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use sendbox_policy::{McpServerPolicy, ToolCallPolicy};
use serde_json::{Map, Value};

use crate::error::ConfigError;

pub const PROJECT_CONFIG_PATHS: [&str; 5] = [
    ".mcp.json",
    ".vscode/mcp.json",
    ".github/copilot/mcp.json",
    ".cursor/mcp.json",
    ".claude/mcp.json",
];
pub const NATIVE_BROKER_PATH: &str = "/run/sendbox-boundary/mcp-broker";
pub const LEGACY_PROXY_PATH: &str = "/run/sendbox-boundary/mcp-proxy";

const FORBIDDEN_EXECUTABLES: [&str; 13] = [
    "sh", "bash", "zsh", "fish", "env", "npx", "npm", "pnpm", "yarn", "bunx", "pipx", "uvx",
    "cmd.exe",
];
const MAX_COMMAND_PARTS: usize = 16;
const MAX_COMMAND_PART_BYTES: usize = 4095;
const MAX_PROJECT_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApprovedCommand {
    executable: String,
    arguments: Vec<String>,
}

impl ApprovedCommand {
    pub fn new(
        executable: impl Into<String>,
        arguments: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        let executable = executable.into();
        if !Path::new(&executable).is_absolute() {
            return Err("executable must be an absolute path".into());
        }
        if executable.as_bytes().contains(&0) {
            return Err("executable cannot contain NUL".into());
        }
        let basename = Path::new(&executable)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if FORBIDDEN_EXECUTABLES.contains(&basename.as_str()) {
            return Err("shells and package runners are not approved MCP executables".into());
        }
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        if arguments.len().saturating_add(1) > MAX_COMMAND_PARTS {
            return Err("command may contain at most 16 parts".into());
        }
        if arguments
            .iter()
            .any(|argument| argument.as_bytes().contains(&0))
        {
            return Err("arguments cannot contain NUL".into());
        }
        if executable.len() > MAX_COMMAND_PART_BYTES
            || arguments
                .iter()
                .any(|argument| argument.len() > MAX_COMMAND_PART_BYTES)
        {
            return Err("each command part must be at most 4095 UTF-8 bytes".into());
        }
        Ok(Self {
            executable,
            arguments,
        })
    }

    pub fn from_argv(argv: &[String]) -> Result<Self, String> {
        let Some((executable, arguments)) = argv.split_first() else {
            return Err("command must contain an executable".into());
        };
        Self::new(executable.clone(), arguments.to_vec())
    }

    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        std::iter::once(self.executable.clone())
            .chain(self.arguments.clone())
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ProjectConfigValidator {
    broker_prefixes: BTreeSet<Vec<String>>,
    stdio_servers: BTreeMap<ApprovedCommand, String>,
}

impl ProjectConfigValidator {
    #[must_use]
    pub fn new(
        broker_prefixes: impl IntoIterator<Item = Vec<String>>,
        allowed_server_commands: impl IntoIterator<Item = ApprovedCommand>,
    ) -> Self {
        let stdio_servers = allowed_server_commands
            .into_iter()
            .map(|command| {
                let fingerprint = crate::policy::stdio_fingerprint(&command.argv());
                (command, format!("legacy-{}", &fingerprint[..16]))
            })
            .collect();
        Self {
            broker_prefixes: broker_prefixes.into_iter().collect(),
            stdio_servers,
        }
    }

    pub fn from_policy(policy: &ToolCallPolicy) -> Result<Self, String> {
        let mut stdio_servers = BTreeMap::new();
        if policy.uses_hierarchical_servers() {
            for (id, server) in &policy.servers {
                let McpServerPolicy::Stdio { command, .. } = server else {
                    continue;
                };
                let command = ApprovedCommand::from_argv(command)?;
                if let Some(existing) = stdio_servers.insert(command, id.clone()) {
                    return Err(format!(
                        "MCP stdio command is ambiguously mapped to '{existing}' and '{id}'"
                    ));
                }
            }
        } else {
            for command in &policy.allowed_server_commands {
                let command = ApprovedCommand::from_argv(command)?;
                let fingerprint = crate::policy::stdio_fingerprint(&command.argv());
                stdio_servers.insert(command, format!("legacy-{}", &fingerprint[..16]));
            }
        }
        Ok(Self {
            broker_prefixes: BTreeSet::from([vec![NATIVE_BROKER_PATH.to_owned()]]),
            stdio_servers,
        })
    }

    pub fn validate_project(&self, project: impl AsRef<Path>) -> Result<(), ConfigError> {
        let project = project.as_ref();
        for relative in PROJECT_CONFIG_PATHS {
            let path = project.join(relative);
            if path.symlink_metadata().is_ok() {
                self.validate_file(&path)?;
            }
        }
        Ok(())
    }

    pub fn validate_file(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|source| ConfigError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        let metadata = file.metadata().map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.is_file() || metadata.len() > MAX_PROJECT_CONFIG_BYTES {
            return Err(ConfigError::InvalidJson {
                path: path.to_path_buf(),
                message: format!(
                    "configuration must be a regular file no larger than {MAX_PROJECT_CONFIG_BYTES} bytes"
                ),
            });
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        file.read_to_end(&mut bytes)
            .map_err(|source| ConfigError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        let root: Value =
            serde_json::from_slice(&bytes).map_err(|error| ConfigError::InvalidJson {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
        let root = root.as_object().ok_or_else(|| ConfigError::InvalidJson {
            path: path.to_path_buf(),
            message: "root must be an object".into(),
        })?;
        for servers in server_containers(root) {
            for (name, server) in servers {
                let server = server
                    .as_object()
                    .ok_or_else(|| ConfigError::InvalidServer {
                        path: path.to_path_buf(),
                        server: name.clone(),
                        message: "server definition must be an object".into(),
                    })?;
                self.validate_server(path, name, server)?;
            }
        }
        Ok(())
    }

    fn validate_server(
        &self,
        path: &Path,
        name: &str,
        server: &Map<String, Value>,
    ) -> Result<(), ConfigError> {
        let transport = server
            .get("type")
            .or_else(|| server.get("transport"))
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase);
        let remote = ["http", "https", "sse", "streamable-http"];
        if server.contains_key("url")
            || transport
                .as_deref()
                .is_some_and(|transport| remote.contains(&transport))
        {
            return invalid_server(
                path,
                name,
                "remote HTTP/SSE MCP is observation-only and cannot be authorized",
            );
        }
        if transport
            .as_deref()
            .is_some_and(|transport| transport != "stdio")
        {
            return invalid_server(path, name, "only stdio MCP transport is supported");
        }
        if ["env", "envFile", "cwd", "workingDirectory"]
            .iter()
            .any(|field| server.contains_key(*field))
        {
            return invalid_server(
                path,
                name,
                "server env/cwd overrides are rejected; the broker uses a scrubbed environment and fixed working directory",
            );
        }
        if ["policy", "policyId", "serverId", "sendboxPolicy"]
            .iter()
            .any(|field| server.contains_key(*field))
        {
            return invalid_server(
                path,
                name,
                "project MCP definitions cannot select a SendBox server policy ID",
            );
        }

        let command = parse_command(path, name, server)?;
        let separator = command
            .iter()
            .position(|part| part == "--")
            .ok_or_else(|| ConfigError::InvalidServer {
                path: path.to_path_buf(),
                server: name.to_owned(),
                message: "command must contain an exact approved broker prefix followed by --"
                    .into(),
            })?;
        if separator == 0 || separator + 1 >= command.len() {
            return invalid_server(path, name, "broker prefix and server argv cannot be empty");
        }
        let prefix = command[..separator].to_vec();
        if !self.broker_prefixes.contains(&prefix) {
            return invalid_server(
                path,
                name,
                "command does not use an exact approved MCP broker",
            );
        }
        let server_command =
            ApprovedCommand::from_argv(&command[separator + 1..]).map_err(|message| {
                ConfigError::InvalidServer {
                    path: path.to_path_buf(),
                    server: name.to_owned(),
                    message,
                }
            })?;
        if !self.stdio_servers.contains_key(&server_command) {
            return invalid_server(
                path,
                name,
                "server executable and arguments do not map to an allowed server policy",
            );
        }
        Ok(())
    }
}

fn parse_command(
    path: &Path,
    name: &str,
    server: &Map<String, Value>,
) -> Result<Vec<String>, ConfigError> {
    match server.get("command") {
        Some(Value::String(executable)) => {
            let arguments = match server.get("args") {
                None => Vec::new(),
                Some(Value::Array(arguments)) => arguments
                    .iter()
                    .map(|argument| {
                        argument.as_str().map(str::to_owned).ok_or_else(|| {
                            ConfigError::InvalidServer {
                                path: path.to_path_buf(),
                                server: name.to_owned(),
                                message: "args must contain only strings".into(),
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                Some(_) => {
                    return invalid_server(path, name, "args must be an array of strings");
                }
            };
            Ok(std::iter::once(executable.clone())
                .chain(arguments)
                .collect())
        }
        Some(Value::Array(command)) => {
            if server.contains_key("args") {
                return invalid_server(
                    path,
                    name,
                    "command array cannot be combined with a separate args field",
                );
            }
            command
                .iter()
                .map(|part| {
                    part.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| ConfigError::InvalidServer {
                            path: path.to_path_buf(),
                            server: name.to_owned(),
                            message: "command array must contain only strings".into(),
                        })
                })
                .collect()
        }
        _ => invalid_server(path, name, "missing stdio command"),
    }
}

fn server_containers(root: &Map<String, Value>) -> Vec<&Map<String, Value>> {
    let mut containers = Vec::new();
    for key in ["mcpServers", "servers"] {
        if let Some(servers) = root.get(key).and_then(Value::as_object) {
            containers.push(servers);
        }
    }
    if let Some(mcp) = root.get("mcp").and_then(Value::as_object) {
        for key in ["mcpServers", "servers"] {
            if let Some(servers) = mcp.get(key).and_then(Value::as_object) {
                containers.push(servers);
            }
        }
    }
    containers
}

fn invalid_server<T>(path: &Path, server: &str, message: &str) -> Result<T, ConfigError> {
    Err(ConfigError::InvalidServer {
        path: PathBuf::from(path),
        server: server.to_owned(),
        message: message.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sendbox_policy::{Action, ServerToolPolicy};

    use super::*;
    use tempfile::TempDir;

    fn validator() -> ProjectConfigValidator {
        ProjectConfigValidator::new(
            [vec!["/run/sendbox-boundary/mcp-broker".into()]],
            [
                ApprovedCommand::new("/usr/bin/node", ["/opt/mcp-server-filesystem.js".into()])
                    .unwrap(),
            ],
        )
    }

    fn write_config(temp: &TempDir, path: &str, contents: &str) {
        let path = temp.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn validates_every_supported_path_and_nested_shape() {
        for (index, path) in PROJECT_CONFIG_PATHS.into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let container = if index % 2 == 0 {
                "mcpServers"
            } else {
                "servers"
            };
            write_config(
                &temp,
                path,
                &format!(
                    r#"{{"mcp":{{"{container}":{{"fs":{{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/node","/opt/mcp-server-filesystem.js"]}}}}}}}}"#
                ),
            );
            validator().validate_project(temp.path()).unwrap();
        }
    }

    #[test]
    fn rejects_remote_unproxied_env_and_package_runners() {
        let cases = [
            r#"{"servers":{"x":{"type":"http","url":"https://example.com"}}}"#,
            r#"{"servers":{"x":{"command":"/usr/bin/node","args":["/opt/mcp-server-filesystem.js"]}}}"#,
            r#"{"servers":{"x":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/node","/opt/mcp-server-filesystem.js"],"env":{"NODE_OPTIONS":"--require=/tmp/x"}}}}"#,
            r#"{"servers":{"x":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/node","/opt/mcp-server-filesystem.js"],"envFile":".env"}}}"#,
            r#"{"servers":{"x":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/npx","mcp-server-filesystem"]}}}"#,
            r#"{"servers":{"x":{"type":"websocket","command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/node","/opt/mcp-server-filesystem.js"]}}}"#,
            r#"{"servers":{"x":{"command":["/run/sendbox-boundary/mcp-broker","--","/usr/bin/node","/opt/mcp-server-filesystem.js"],"args":[]}}}"#,
            r#"{"servers":{"x":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/node","/opt/mcp-server-filesystem.js"],"policyId":"more-permissive"}}}"#,
        ];
        for case in cases {
            let temp = TempDir::new().unwrap();
            write_config(&temp, ".mcp.json", case);
            assert!(validator().validate_project(temp.path()).is_err());
        }
    }

    #[test]
    fn rejects_symlinked_project_configuration() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let target = temp.path().join("outside.json");
        fs::write(
            &target,
            r#"{"servers":{"fs":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/node","/opt/mcp-server-filesystem.js"]}}}"#,
        )
        .unwrap();
        symlink(&target, temp.path().join(".mcp.json")).unwrap();
        assert!(validator().validate_project(temp.path()).is_err());
    }

    #[test]
    fn hierarchical_policy_maps_aliases_by_exact_command_not_project_name() {
        let policy = ToolCallPolicy {
            servers: BTreeMap::from([(
                "trusted-github".to_owned(),
                McpServerPolicy::Stdio {
                    command: vec!["/usr/bin/github-mcp".to_owned(), "stdio".to_owned()],
                    tools: ServerToolPolicy {
                        default_action: Action::Deny,
                        allowlist: vec!["search_code".to_owned()],
                        denylist: Vec::new(),
                    },
                },
            )]),
            ..ToolCallPolicy::default()
        };
        let validator = ProjectConfigValidator::from_policy(&policy).unwrap();
        let temp = TempDir::new().unwrap();
        write_config(
            &temp,
            ".mcp.json",
            r#"{"servers":{"untrusted-alias":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/github-mcp","stdio"]},"second-alias":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/github-mcp","stdio"]}}}"#,
        );
        validator.validate_project(temp.path()).unwrap();

        write_config(
            &temp,
            ".vscode/mcp.json",
            r#"{"servers":{"trusted-github":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/github-mcp","changed"]}}}"#,
        );
        assert!(validator.validate_project(temp.path()).is_err());
    }
}
