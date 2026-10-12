use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Mode, OFlags, open, openat};
use sendbox_policy::{McpServerPolicy, ToolCallPolicy, ToolTransport};
use serde_json::{Map, Value};

use crate::error::ConfigError;

pub const PROJECT_CONFIG_PATHS: [&str; 9] = [
    ".mcp.json",
    ".vscode/mcp.json",
    ".github/copilot/mcp.json",
    ".cursor/mcp.json",
    ".claude/mcp.json",
    "opencode.json",
    "opencode.jsonc",
    ".codex/config.toml",
    ".gemini/settings.json",
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
const CLIENT_METADATA_FIELDS: &[&str] = &[
    "enabled",
    "timeout",
    "startup_timeout_sec",
    "startup_timeout_ms",
    "tool_timeout_sec",
    "required",
    "enabled_tools",
    "disabled_tools",
    "includeTools",
    "excludeTools",
    "trust",
    "description",
    "tools",
    "default_tools_approval_mode",
];

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

    pub fn from_broker_argv(argv: &[String]) -> Result<Self, String> {
        let Some((separator, command)) = argv.split_first() else {
            return Err("MCP broker requires -- followed by an exact server command".to_owned());
        };
        if separator != "--" {
            return Err("MCP broker requires -- followed by an exact server command".to_owned());
        }
        Self::from_argv(command)
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
    http_servers: BTreeMap<String, ToolTransport>,
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
            http_servers: BTreeMap::new(),
        }
    }

    pub fn from_policy(policy: &ToolCallPolicy) -> Result<Self, String> {
        let mut stdio_servers = BTreeMap::new();
        let mut http_servers = BTreeMap::new();
        if policy.uses_hierarchical_servers() {
            for (id, server) in &policy.servers {
                match server {
                    McpServerPolicy::Stdio { command, .. } => {
                        let command = ApprovedCommand::from_argv(command)?;
                        if let Some(existing) = stdio_servers.insert(command, id.clone()) {
                            return Err(format!(
                                "MCP stdio command is ambiguously mapped to '{existing}' and '{id}'"
                            ));
                        }
                    }
                    McpServerPolicy::StreamableHttp { .. } => {
                        http_servers.insert(
                            crate::runtime::gateway_url(id),
                            ToolTransport::StreamableHttp,
                        );
                    }
                    McpServerPolicy::StreamableHttp2025 { .. } => {
                        http_servers.insert(
                            crate::runtime::gateway_url(id),
                            ToolTransport::StreamableHttp2025,
                        );
                    }
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
            http_servers,
        })
    }

    pub fn validate_project(&self, project: impl AsRef<Path>) -> Result<(), ConfigError> {
        let project = project.as_ref();
        let root = open_project_root(project)?;
        for relative in PROJECT_CONFIG_PATHS {
            let path = project.join(relative);
            if let Some(file) = open_project_file(&root, Path::new(relative), &path)? {
                self.validate_open_file(&path, file)?;
            }
        }
        Ok(())
    }

    pub fn validate_file(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|source| ConfigError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        self.validate_open_file(path, file)
    }

    fn validate_open_file(&self, path: &Path, mut file: File) -> Result<(), ConfigError> {
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
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_PROJECT_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| ConfigError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes.len() as u64 > MAX_PROJECT_CONFIG_BYTES {
            return Err(ConfigError::InvalidJson {
                path: path.to_path_buf(),
                message: "configuration grew beyond the byte limit while reading".to_owned(),
            });
        }
        let root = parse_configuration(path, &bytes)?;
        let root = root.as_object().ok_or_else(|| ConfigError::InvalidJson {
            path: path.to_path_buf(),
            message: "root must be an object".into(),
        })?;
        for servers in server_containers(path, root)? {
            for (name, server) in servers {
                let server = server
                    .as_object()
                    .ok_or_else(|| ConfigError::InvalidServer {
                        path: path.to_path_buf(),
                        server: name.clone(),
                        message: "server definition must be an object".into(),
                    })?;
                let server = self.normalize_server(path, name, server)?;
                self.validate_server(path, name, &server)?;
            }
        }
        Ok(())
    }

    fn normalize_server(
        &self,
        path: &Path,
        name: &str,
        server: &Map<String, Value>,
    ) -> Result<Map<String, Value>, ConfigError> {
        let mut server = server.clone();
        let opencode_remote =
            is_opencode(path) && server.get("type").and_then(Value::as_str) == Some("remote");
        if opencode_remote {
            if server.get("oauth") != Some(&Value::Bool(false)) {
                return invalid_server(
                    path,
                    name,
                    "OpenCode remote MCP requires oauth: false; authentication belongs to the trusted gateway",
                );
            }
            server.remove("oauth");
        }
        let codex_remote = path.ends_with(".codex/config.toml") && server.contains_key("url");
        let gemini_remote =
            path.ends_with(".gemini/settings.json") && server.contains_key("httpUrl");
        if gemini_remote {
            if server.contains_key("url") {
                return invalid_server(path, name, "HTTP and legacy SSE URLs cannot be combined");
            }
            let url = server.remove("httpUrl").expect("checked HTTP URL");
            server.insert("url".to_owned(), url);
        }
        if opencode_remote || codex_remote || gemini_remote {
            let transport = server
                .get("url")
                .and_then(Value::as_str)
                .and_then(|url| self.http_servers.get(url));
            let transport = match transport {
                Some(ToolTransport::StreamableHttp2025) => "streamable-http-2025",
                _ => "streamable-http",
            };
            server.insert("type".to_owned(), Value::String(transport.to_owned()));
        }
        Ok(server)
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
        let transport = transport.map(|transport| {
            if is_opencode(path) && transport == "local" {
                "stdio".to_owned()
            } else {
                transport
            }
        });
        let remote = [
            "http",
            "https",
            "sse",
            "streamable-http",
            "streamable_http",
            "streamable-http-2025",
            "streamable_http_2025",
        ];
        if server.contains_key("url")
            || transport
                .as_deref()
                .is_some_and(|transport| remote.contains(&transport))
        {
            validate_fields(path, name, server, &["type", "transport", "url"])?;
            return self.validate_http_server(path, name, server, transport.as_deref());
        }
        validate_fields(
            path,
            name,
            server,
            &["type", "transport", "command", "args"],
        )?;
        if transport
            .as_deref()
            .is_some_and(|transport| transport != "stdio")
        {
            return invalid_server(path, name, "only stdio MCP transport is supported");
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

    fn validate_http_server(
        &self,
        path: &Path,
        name: &str,
        server: &Map<String, Value>,
        transport: Option<&str>,
    ) -> Result<(), ConfigError> {
        let url = server.get("url").and_then(Value::as_str).ok_or_else(|| {
            ConfigError::InvalidServer {
                path: path.to_path_buf(),
                server: name.to_owned(),
                message: "HTTP MCP server must contain a string url".to_owned(),
            }
        })?;
        let Some(expected_transport) = self.http_servers.get(url) else {
            return invalid_server(
                path,
                name,
                "HTTP MCP URL does not exactly match a configured trusted gateway route",
            );
        };
        let actual_transport = match transport {
            Some("streamable-http" | "streamable_http" | "http") => ToolTransport::StreamableHttp,
            Some("streamable-http-2025" | "streamable_http_2025") => {
                ToolTransport::StreamableHttp2025
            }
            Some("sse" | "https") => {
                return invalid_server(
                    path,
                    name,
                    "legacy HTTP+SSE and direct HTTPS transports are not supported",
                );
            }
            Some(_) => return invalid_server(path, name, "unsupported HTTP MCP transport"),
            None => {
                return invalid_server(
                    path,
                    name,
                    "HTTP MCP definitions require an explicit transport type",
                );
            }
        };
        if &actual_transport != expected_transport {
            return invalid_server(
                path,
                name,
                "HTTP MCP transport does not match the configured gateway policy",
            );
        }
        Ok(())
    }
}

pub fn has_project_configuration(project: &Path) -> Result<bool, ConfigError> {
    let root = open_project_root(project)?;
    let mut present = false;
    for relative in PROJECT_CONFIG_PATHS {
        present |=
            open_project_file(&root, Path::new(relative), &project.join(relative))?.is_some();
    }
    Ok(present)
}

fn open_project_root(project: &Path) -> Result<OwnedFd, ConfigError> {
    open(
        project,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| ConfigError::Io {
        path: project.to_path_buf(),
        source: source.into(),
    })
}

fn open_project_file(
    root: &OwnedFd,
    relative: &Path,
    path: &Path,
) -> Result<Option<File>, ConfigError> {
    let mut directory = None::<OwnedFd>;
    let mut components = relative.components().peekable();
    while let Some(Component::Normal(name)) = components.next() {
        let parent = directory.as_ref().map_or(root.as_fd(), AsFd::as_fd);
        let leaf = components.peek().is_none();
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if !leaf {
            flags |= OFlags::DIRECTORY;
        }
        match openat(parent, name, flags, Mode::empty()) {
            Ok(file) if leaf => return Ok(Some(File::from(file))),
            Ok(next) => directory = Some(next),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(source) => {
                return Err(ConfigError::Io {
                    path: path.to_path_buf(),
                    source: source.into(),
                });
            }
        }
    }
    Err(ConfigError::InvalidJson {
        path: path.to_path_buf(),
        message: "configuration path must contain only normal relative components".to_owned(),
    })
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

fn is_opencode(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("opencode.json" | "opencode.jsonc")
    )
}

fn parse_configuration(path: &Path, bytes: &[u8]) -> Result<Value, ConfigError> {
    let invalid = |message: String| ConfigError::InvalidJson {
        path: path.to_path_buf(),
        message,
    };
    let source = std::str::from_utf8(bytes).map_err(|error| invalid(error.to_string()))?;
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("toml") => {
            let value: toml::Value =
                toml::from_str(source).map_err(|error| invalid(error.to_string()))?;
            serde_json::to_value(value).map_err(|error| invalid(error.to_string()))
        }
        Some("jsonc") => jsonc_parser::parse_to_serde_value(source, &Default::default())
            .map_err(|error| invalid(error.to_string())),
        _ => serde_json::from_str(source).map_err(|error| invalid(error.to_string())),
    }
}

fn validate_fields(
    path: &Path,
    name: &str,
    server: &Map<String, Value>,
    structural_fields: &[&str],
) -> Result<(), ConfigError> {
    for field in server.keys() {
        if !structural_fields.contains(&field.as_str())
            && !CLIENT_METADATA_FIELDS.contains(&field.as_str())
        {
            return invalid_server(
                path,
                name,
                &format!(
                    "unapproved MCP client field '{field}'; server identity, environment and authentication are controlled by signed policy"
                ),
            );
        }
    }
    Ok(())
}

fn server_containers<'a>(
    path: &Path,
    root: &'a Map<String, Value>,
) -> Result<Vec<&'a Map<String, Value>>, ConfigError> {
    let object = |value: &'a Value, key: &str| {
        value.as_object().ok_or_else(|| ConfigError::InvalidJson {
            path: path.to_path_buf(),
            message: format!("{key} must be an object"),
        })
    };
    let mut containers = Vec::new();
    for key in ["mcpServers", "servers", "mcp_servers"] {
        if let Some(servers) = root.get(key) {
            containers.push(object(servers, key)?);
        }
    }
    if let Some(mcp) = root.get("mcp") {
        let mcp = object(mcp, "mcp")?;
        for key in ["mcpServers", "servers"] {
            if let Some(servers) = mcp.get(key) {
                containers.push(object(servers, key)?);
            }
            if !mcp.contains_key("mcpServers") && !mcp.contains_key("servers") {
                containers.push(mcp);
            }
        }
    }
    Ok(containers)
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
    fn native_broker_invocation_consumes_the_required_argv_separator() {
        let arguments = vec![
            "--".to_owned(),
            "/usr/bin/node".to_owned(),
            "/opt/mcp-server-filesystem.js".to_owned(),
        ];
        let command = ApprovedCommand::from_broker_argv(&arguments).expect("broker argv");
        assert_eq!(command.executable(), "/usr/bin/node");
        assert_eq!(command.arguments(), ["/opt/mcp-server-filesystem.js"]);
        assert!(ApprovedCommand::from_broker_argv(&arguments[1..]).is_err());
        assert!(ApprovedCommand::from_broker_argv(&arguments[..1]).is_err());
    }

    #[test]
    fn validates_every_supported_path_and_nested_shape() {
        for (index, path) in PROJECT_CONFIG_PATHS.into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            if path.ends_with(".toml") {
                write_config(
                    &temp,
                    path,
                    "[mcp_servers.files]\ncommand = '/run/sendbox-boundary/mcp-broker'\nargs = ['--', '/usr/bin/node', '/opt/mcp-server-filesystem.js']\n",
                );
                validator().validate_project(temp.path()).unwrap();
                continue;
            }
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
    fn rejects_unbrokered_opencode_servers() {
        let temp = TempDir::new().unwrap();
        write_config(
            &temp,
            "opencode.json",
            r#"{"mcp":{"files":{"type":"local","command":["/usr/bin/node","/opt/mcp-server-filesystem.js"]}}}"#,
        );
        assert!(validator().validate_project(temp.path()).is_err());
    }

    #[test]
    fn validates_native_cli_agent_formats_through_one_policy() {
        for (path, source) in [
            (
                "opencode.json",
                r#"{"mcp":{"files":{"type":"local","command":["/run/sendbox-boundary/mcp-broker","--","/usr/bin/node","/opt/mcp-server-filesystem.js"]}}}"#,
            ),
            (
                "opencode.jsonc",
                r#"{
                    // OpenCode accepts comments and trailing commas.
                    "mcp": {"files": {
                        "type": "local",
                        "command": ["/run/sendbox-boundary/mcp-broker", "--", "/usr/bin/node", "/opt/mcp-server-filesystem.js"],
                    }},
                }"#,
            ),
            (
                ".codex/config.toml",
                "[mcp_servers.files]\ncommand = '/run/sendbox-boundary/mcp-broker'\nargs = ['--', '/usr/bin/node', '/opt/mcp-server-filesystem.js']\n",
            ),
            (
                ".gemini/settings.json",
                r#"{"mcpServers":{"files":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/node","/opt/mcp-server-filesystem.js"]}}}"#,
            ),
        ] {
            let temp = TempDir::new().unwrap();
            write_config(&temp, path, source);
            validator()
                .validate_file(temp.path().join(path))
                .unwrap_or_else(|error| panic!("{path}: {error}"));
        }
    }

    #[test]
    fn native_remote_definitions_use_the_trusted_gateway() {
        let policy = ToolCallPolicy {
            servers: BTreeMap::from([(
                "docs".to_owned(),
                McpServerPolicy::StreamableHttp {
                    url: "https://mcp.example.com/mcp".to_owned(),
                    tools: ServerToolPolicy::default(),
                    http: Default::default(),
                },
            )]),
            ..ToolCallPolicy::default()
        };
        let validator = ProjectConfigValidator::from_policy(&policy).unwrap();
        for (path, source) in [
            (
                "opencode.json",
                r#"{"mcp":{"docs":{"type":"remote","url":"http://127.0.0.1:15082/mcp/docs","oauth":false}}}"#,
            ),
            (
                ".codex/config.toml",
                "[mcp_servers.docs]\nurl = 'http://127.0.0.1:15082/mcp/docs'\n",
            ),
            (
                ".gemini/settings.json",
                r#"{"mcpServers":{"docs":{"httpUrl":"http://127.0.0.1:15082/mcp/docs"}}}"#,
            ),
        ] {
            let temp = TempDir::new().unwrap();
            write_config(&temp, path, source);
            validator
                .validate_project(temp.path())
                .unwrap_or_else(|error| panic!("{path}: {error}"));
        }
    }

    #[test]
    fn native_client_metadata_cannot_expand_broker_authority() {
        for (path, source) in [
            (
                "opencode.json",
                r#"{"mcp":{"files":{"type":"local","command":["/run/sendbox-boundary/mcp-broker","--","/usr/bin/node","/opt/mcp-server-filesystem.js"],"environment":{"NODE_OPTIONS":"--require=/tmp/untrusted.js"}}}}"#,
            ),
            (
                ".codex/config.toml",
                "[mcp_servers.files]\ncommand = '/run/sendbox-boundary/mcp-broker'\nargs = ['--', '/usr/bin/node', '/opt/mcp-server-filesystem.js']\nenv_vars = ['UNAPPROVED_TOKEN']\n",
            ),
            (
                ".gemini/settings.json",
                r#"{"mcpServers":{"files":{"command":"/run/sendbox-boundary/mcp-broker","args":["--","/usr/bin/node","/opt/mcp-server-filesystem.js"],"unrecognized_launch_override":true}}}"#,
            ),
            (".mcp.json", r#"{"mcpServers":[]}"#),
            (".codex/config.toml", "mcp_servers = 'not-a-table'\n"),
        ] {
            let temp = TempDir::new().unwrap();
            write_config(&temp, path, source);
            assert!(
                validator().validate_project(temp.path()).is_err(),
                "{path}: unsafe metadata was accepted"
            );
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
    fn rejects_symlinked_configuration_parents() {
        use std::os::unix::fs::symlink;

        let project = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(
            outside.path().join("config.toml"),
            "[mcp_servers.files]\ncommand = '/run/sendbox-boundary/mcp-broker'\nargs = ['--', '/usr/bin/node', '/opt/mcp-server-filesystem.js']\n",
        )
        .unwrap();
        symlink(outside.path(), project.path().join(".codex")).unwrap();
        assert!(validator().validate_project(project.path()).is_err());
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

    #[test]
    fn remote_servers_require_exact_gateway_routes_and_transport_modes() {
        let policy = ToolCallPolicy {
            servers: BTreeMap::from([
                (
                    "modern".to_owned(),
                    McpServerPolicy::StreamableHttp {
                        url: "https://mcp.example.com/mcp".to_owned(),
                        tools: ServerToolPolicy::default(),
                        http: Default::default(),
                    },
                ),
                (
                    "compat".to_owned(),
                    McpServerPolicy::StreamableHttp2025 {
                        url: "https://legacy.example.com/mcp".to_owned(),
                        tools: ServerToolPolicy::default(),
                        http: Default::default(),
                    },
                ),
            ]),
            ..ToolCallPolicy::default()
        };
        let validator = ProjectConfigValidator::from_policy(&policy).unwrap();
        let temp = TempDir::new().unwrap();
        write_config(
            &temp,
            ".mcp.json",
            r#"{"servers":{"alias":{"type":"streamable-http","url":"http://127.0.0.1:15082/mcp/modern"},"old":{"type":"streamable-http-2025","url":"http://127.0.0.1:15082/mcp/compat"}}}"#,
        );
        validator.validate_project(temp.path()).unwrap();

        for invalid in [
            r#"{"servers":{"x":{"type":"streamable-http","url":"https://mcp.example.com/mcp"}}}"#,
            r#"{"servers":{"x":{"type":"streamable-http-2025","url":"http://127.0.0.1:15082/mcp/modern"}}}"#,
            r#"{"servers":{"x":{"type":"sse","url":"http://127.0.0.1:15082/mcp/compat"}}}"#,
            r#"{"servers":{"x":{"type":"streamable-http","url":"http://127.0.0.1:15082/mcp/modern","headers":{"Authorization":"secret"}}}}"#,
        ] {
            fs::write(temp.path().join(".mcp.json"), invalid).unwrap();
            assert!(validator.validate_project(temp.path()).is_err());
        }
    }
}
