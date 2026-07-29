use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use sendbox_policy::{
    DEFAULT_MCP_HTTP_GATEWAY_PORT, McpHttpPolicy, McpServerPolicy, ServerToolPolicy,
    ToolCallPolicy, ToolTransport, normalize_mcp_http_endpoint,
};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::config::{ApprovedCommand, ProjectConfigValidator};
use crate::policy::{ResolvedServerPolicy, http_fingerprint, resolve_stdio_server};
use crate::safe_outputs::{
    SAFE_OUTPUTS_MCP_PATH, SAFE_OUTPUTS_SERVER_ID, SafeOutputsRuntimePolicy,
};

pub const RUNTIME_POLICY_SCHEMA_VERSION: u32 = 2;
pub const NATIVE_POLICY_PATH: &str = "/run/sendbox-boundary/mcp-policy.json";
pub const NATIVE_AUDIT_SOCKET_PATH: &str = "/run/sendbox-boundary/audit.sock";
pub const OBSERVATION_ROOT: &str = "/var/log/sendbox";
pub const DEFAULT_AUDIT_LOG_PATH: &str = "/var/log/sendbox/boundary.log";
pub const DEFAULT_HTTP_GATEWAY_PORT: u16 = DEFAULT_MCP_HTTP_GATEWAY_PORT;
pub const HTTP_GATEWAY_ROUTE_PREFIX: &str = "/mcp/";
const MAX_FRAME_BYTES: i64 = 16 * 1024 * 1024;
const MAX_ENVIRONMENT_ENTRY_BYTES: usize = 4 * 1024;
const MAX_ENVIRONMENT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObservationConfiguration {
    pub capture_payloads: bool,
    pub max_payload_bytes: usize,
    pub log_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicyDocument {
    pub schema_version: u32,
    pub workspace_root: PathBuf,
    pub workload_uid: u32,
    pub workload_gid: u32,
    pub tool_policy: ToolCallPolicy,
    pub audit_log_path: PathBuf,
    pub fixed_environment: BTreeMap<String, String>,
    pub inherited_environment_keys: BTreeSet<String>,
    #[serde(default)]
    pub observation: Option<RuntimeObservationConfiguration>,
    #[serde(default)]
    pub safe_outputs: Option<SafeOutputsRuntimePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteServerRuntime {
    pub id: String,
    pub transport: ToolTransport,
    pub fingerprint: String,
    pub endpoint: HttpEndpoint,
    pub gateway_url: String,
    pub tools: ServerToolPolicy,
    pub http: McpHttpPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEndpoint {
    pub normalized: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl HttpEndpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        let normalized = normalize_mcp_http_endpoint(value)?;
        let parsed = Url::parse(&normalized)
            .map_err(|error| format!("invalid MCP endpoint URL: {error}"))?;
        let host = match parsed.host() {
            Some(Host::Domain(domain)) => domain.to_owned(),
            Some(Host::Ipv4(address)) => address.to_string(),
            Some(Host::Ipv6(address)) => address.to_string(),
            None => return Err("MCP endpoint URL must contain a host".to_owned()),
        };
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| "MCP endpoint URL must have a known port".to_owned())?;
        Ok(Self {
            normalized,
            scheme: parsed.scheme().to_owned(),
            host,
            port,
            path: parsed.path().to_owned(),
        })
    }

    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl RuntimePolicyDocument {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != RUNTIME_POLICY_SCHEMA_VERSION {
            return Err(format!(
                "unsupported MCP runtime policy schema version {}",
                self.schema_version
            ));
        }
        if self.workload_uid == 0 || self.workload_gid == 0 {
            return Err("MCP workloads must use a non-root uid and gid".to_owned());
        }
        validate_absolute_normalized(&self.workspace_root, "MCP workspace")?;
        if self.tool_policy.uses_hierarchical_servers() && self.tool_policy.uses_legacy_fields() {
            return Err(
                "hierarchical MCP servers cannot be combined with legacy global policy fields"
                    .to_owned(),
            );
        }
        let _ = self.approved_commands()?;
        if !(1..=MAX_FRAME_BYTES).contains(&self.tool_policy.max_frame_bytes) {
            return Err(format!(
                "MCP maximum frame size must be between 1 and {MAX_FRAME_BYTES} bytes"
            ));
        }
        validate_absolute_normalized(&self.audit_log_path, "MCP audit log")?;
        if self.audit_log_path.parent() != Some(Path::new(OBSERVATION_ROOT)) {
            return Err(format!(
                "MCP audit log must be a direct child of {OBSERVATION_ROOT}"
            ));
        }
        if self
            .fixed_environment
            .len()
            .saturating_add(self.inherited_environment_keys.len())
            > 128
        {
            return Err("MCP environment may contain at most 128 names".to_owned());
        }
        for key in self
            .fixed_environment
            .keys()
            .chain(&self.inherited_environment_keys)
        {
            if !valid_environment_name(key) {
                return Err(format!("invalid MCP environment name `{key}`"));
            }
        }
        if self
            .fixed_environment
            .keys()
            .any(|key| self.inherited_environment_keys.contains(key))
        {
            return Err("MCP fixed and inherited environment names must be disjoint".to_owned());
        }
        let mut environment_bytes = 0_usize;
        for (name, value) in &self.fixed_environment {
            if value.as_bytes().contains(&0) {
                return Err(format!("MCP fixed environment value `{name}` contains NUL"));
            }
            let entry_bytes = name.len().saturating_add(value.len()).saturating_add(1);
            if entry_bytes > MAX_ENVIRONMENT_ENTRY_BYTES {
                return Err(format!(
                    "MCP fixed environment entry `{name}` exceeds {MAX_ENVIRONMENT_ENTRY_BYTES} bytes"
                ));
            }
            environment_bytes = environment_bytes.saturating_add(entry_bytes);
        }
        if environment_bytes > MAX_ENVIRONMENT_BYTES {
            return Err(format!(
                "MCP fixed environment exceeds {MAX_ENVIRONMENT_BYTES} bytes"
            ));
        }
        if let Some(observation) = &self.observation {
            if observation.max_payload_bytes == 0 || observation.max_payload_bytes > 1024 * 1024 {
                return Err(
                    "MCP observation payload limit must be between 1 and 1048576 bytes".to_owned(),
                );
            }
            validate_absolute_normalized(&observation.log_path, "MCP observation log")?;
            if observation.log_path.parent() != Some(Path::new(OBSERVATION_ROOT)) {
                return Err(format!(
                    "MCP observation log must be a direct child of {OBSERVATION_ROOT}"
                ));
            }
            if observation.log_path == self.audit_log_path {
                return Err("MCP audit and observation logs must be different files".to_owned());
            }
        }
        if let Some(safe_outputs) = &self.safe_outputs {
            safe_outputs.validate().map_err(|error| error.to_string())?;
            if self.tool_policy.uses_hierarchical_servers() {
                let expected = safe_outputs.mcp_server_policy();
                match self.tool_policy.servers.get(SAFE_OUTPUTS_SERVER_ID) {
                    Some(actual) if actual == &expected => {}
                    Some(_) => {
                        return Err(
                            "Safe Outputs MCP server policy does not match the authenticated Safe Outputs configuration"
                                .to_owned(),
                        );
                    }
                    None => {
                        return Err(
                            "Safe Outputs MCP server policy is missing from the hierarchical policy"
                                .to_owned(),
                        );
                    }
                }
            } else {
                let command = vec![SAFE_OUTPUTS_MCP_PATH.to_owned()];
                if !self.tool_policy.allowed_server_commands.contains(&command) {
                    return Err(
                        "Safe Outputs MCP command is not in the exact server command allowlist"
                            .to_owned(),
                    );
                }
                for tool in safe_outputs.enabled_tools() {
                    if !self
                        .tool_policy
                        .allowlist
                        .iter()
                        .any(|pattern| sendbox_core::glob_matches(tool.name(), pattern))
                    {
                        return Err(format!(
                            "Safe Outputs tool `{}` is not admitted by the MCP tool policy",
                            tool.name()
                        ));
                    }
                    if self
                        .tool_policy
                        .denylist
                        .iter()
                        .any(|pattern| sendbox_core::glob_matches(tool.name(), pattern))
                    {
                        return Err(format!(
                            "Safe Outputs tool `{}` is denied by the MCP tool policy",
                            tool.name()
                        ));
                    }
                }
            }
        } else if self
            .tool_policy
            .servers
            .contains_key(SAFE_OUTPUTS_SERVER_ID)
        {
            return Err("reserved Safe Outputs MCP server policy is not enabled".to_owned());
        }
        Ok(())
    }

    pub fn approved_commands(&self) -> Result<Vec<ApprovedCommand>, String> {
        if self.tool_policy.uses_hierarchical_servers() {
            self.tool_policy
                .servers
                .values()
                .filter_map(|server| match server {
                    McpServerPolicy::Stdio { command, .. } => Some(command),
                    McpServerPolicy::StreamableHttp { .. }
                    | McpServerPolicy::StreamableHttp2025 { .. } => None,
                })
                .map(|command| ApprovedCommand::from_argv(command))
                .collect()
        } else {
            self.tool_policy
                .allowed_server_commands
                .iter()
                .map(|command| ApprovedCommand::from_argv(command))
                .collect()
        }
    }

    pub fn resolve_stdio(&self, command: &ApprovedCommand) -> Result<ResolvedServerPolicy, String> {
        resolve_stdio_server(&self.tool_policy, &command.argv())
    }

    pub fn project_validator(&self) -> Result<ProjectConfigValidator, String> {
        ProjectConfigValidator::from_policy(&self.tool_policy)
    }

    pub fn remote_servers(&self) -> Result<BTreeMap<String, RemoteServerRuntime>, String> {
        self.tool_policy
            .servers
            .iter()
            .filter_map(|(id, server)| {
                let (transport, url, tools, http) = match server {
                    McpServerPolicy::Stdio { .. } => return None,
                    McpServerPolicy::StreamableHttp { url, tools, http } => {
                        (ToolTransport::StreamableHttp, url, tools, http)
                    }
                    McpServerPolicy::StreamableHttp2025 { url, tools, http } => {
                        (ToolTransport::StreamableHttp2025, url, tools, http)
                    }
                };
                Some((id, transport, url, tools, http))
            })
            .map(|(id, transport, url, tools, http)| {
                let endpoint = HttpEndpoint::parse(url)?;
                Ok((
                    id.clone(),
                    RemoteServerRuntime {
                        id: id.clone(),
                        transport,
                        fingerprint: http_fingerprint(transport, &endpoint.normalized),
                        endpoint,
                        gateway_url: gateway_url(id),
                        tools: tools.clone(),
                        http: http.clone(),
                    },
                ))
            })
            .collect()
    }
}

#[must_use]
pub fn gateway_route(server_id: &str) -> String {
    format!("{HTTP_GATEWAY_ROUTE_PREFIX}{server_id}")
}

#[must_use]
pub fn gateway_url(server_id: &str) -> String {
    format!(
        "http://127.0.0.1:{DEFAULT_HTTP_GATEWAY_PORT}{}",
        gateway_route(server_id)
    )
}

fn validate_absolute_normalized(path: &Path, name: &str) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(format!("{name} path must be absolute and normalized"));
    }
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(first) if first == b'_' || first.is_ascii_alphabetic())
        && name.len() <= 128
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use sendbox_policy::{Action, ToolTransport};

    use super::*;

    fn policy() -> RuntimePolicyDocument {
        RuntimePolicyDocument {
            schema_version: RUNTIME_POLICY_SCHEMA_VERSION,
            workspace_root: PathBuf::from("/workspace"),
            workload_uid: 1000,
            workload_gid: 1000,
            tool_policy: ToolCallPolicy {
                transport: ToolTransport::Stdio,
                default_action: Action::Deny,
                allowlist: vec!["read_*".to_owned()],
                denylist: Vec::new(),
                max_frame_bytes: 4096,
                server_command_patterns: Vec::new(),
                allowed_server_commands: vec![vec![
                    "/usr/bin/server".to_owned(),
                    "--stdio".to_owned(),
                ]],
                servers: BTreeMap::new(),
            },
            audit_log_path: PathBuf::from(DEFAULT_AUDIT_LOG_PATH),
            fixed_environment: BTreeMap::from([
                ("HOME".to_owned(), "/workspace".to_owned()),
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ]),
            inherited_environment_keys: BTreeSet::from(["TOKEN".to_owned()]),
            observation: Some(RuntimeObservationConfiguration {
                capture_payloads: false,
                max_payload_bytes: 4096,
                log_path: PathBuf::from("/var/log/sendbox/mcp.log"),
            }),
            safe_outputs: None,
        }
    }

    #[test]
    fn runtime_policy_validates_exact_commands_and_safe_paths() {
        let policy = policy();
        policy.validate().expect("valid policy");
        assert_eq!(
            policy.approved_commands().expect("commands")[0].argv(),
            ["/usr/bin/server", "--stdio"]
        );
    }

    #[test]
    fn runtime_policy_rejects_unsafe_environment_and_log_paths() {
        {
            let mut policy = policy();
            policy
                .inherited_environment_keys
                .insert("LD_PRELOAD=x".to_owned());
            assert!(policy.validate().is_err());
        }

        let mut policy = policy();
        policy.observation.as_mut().expect("observation").log_path = PathBuf::from("/tmp/mcp.log");
        assert!(policy.validate().is_err());
    }

    #[test]
    fn remote_servers_share_one_normalized_runtime_derivation() {
        let mut policy = policy();
        policy.tool_policy = ToolCallPolicy {
            servers: BTreeMap::from([(
                "remote-github".to_owned(),
                McpServerPolicy::StreamableHttp {
                    url: "https://MCP.Example.com/mcp".to_owned(),
                    tools: ServerToolPolicy::default(),
                    http: McpHttpPolicy::default(),
                },
            )]),
            ..ToolCallPolicy::default()
        };
        let remote = policy.remote_servers().expect("remote runtime");
        let server = remote.get("remote-github").expect("server");
        assert_eq!(
            server.endpoint.normalized,
            "https://mcp.example.com:443/mcp"
        );
        assert_eq!(
            server.gateway_url,
            "http://127.0.0.1:15082/mcp/remote-github"
        );
        assert_eq!(server.endpoint.authority(), "mcp.example.com:443");
        assert_eq!(server.transport, ToolTransport::StreamableHttp);
    }

    #[test]
    fn hierarchical_safe_outputs_policy_must_match_the_runtime_configuration() {
        let configuration = sendbox_config::SafeOutputsConfiguration {
            enabled: true,
            ..sendbox_config::SafeOutputsConfiguration::default()
        };
        let safe_outputs = SafeOutputsRuntimePolicy::from_configuration(
            sendbox_core::SessionId::from_bytes([7; 16]),
            &configuration,
        )
        .expect("Safe Outputs policy");

        let mut policy = policy();
        policy.tool_policy = ToolCallPolicy {
            servers: BTreeMap::from([(
                SAFE_OUTPUTS_SERVER_ID.to_owned(),
                safe_outputs.mcp_server_policy(),
            )]),
            ..ToolCallPolicy::default()
        };
        policy.safe_outputs = Some(safe_outputs);
        policy.validate().expect("matching policy");

        let McpServerPolicy::Stdio { tools, .. } = policy
            .tool_policy
            .servers
            .get_mut(SAFE_OUTPUTS_SERVER_ID)
            .expect("Safe Outputs server")
        else {
            panic!("Safe Outputs must use stdio");
        };
        tools.allowlist.pop();
        assert!(policy.validate().is_err());
    }
}
