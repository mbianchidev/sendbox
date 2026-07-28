use sendbox_config::{InspectionTransport, McpInspectionConfiguration};
use sendbox_policy::{McpServerPolicy, ServerToolPolicy, ToolCallPolicy, ToolTransport};
use serde::Serialize;

use crate::policy::{resolve_http_server, resolve_stdio_server};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpBoundaryInspection {
    pub mode: &'static str,
    pub max_frame_bytes: i64,
    pub servers: Vec<McpServerInspection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpServerInspection {
    pub server_policy_id: String,
    pub transport: ToolTransport,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_endpoint: Option<String>,
    pub tools: ServerToolPolicy,
}

impl McpBoundaryInspection {
    pub fn from_policy(policy: &ToolCallPolicy) -> Result<Self, String> {
        let mode = if policy.uses_hierarchical_servers() {
            "hierarchical"
        } else if policy.allowed_server_commands.is_empty() {
            "disabled"
        } else {
            "legacy"
        };
        let servers = if policy.uses_hierarchical_servers() {
            policy
                .servers
                .iter()
                .map(|(id, server)| match server {
                    McpServerPolicy::Stdio { command, .. } => {
                        let resolved = resolve_stdio_server(policy, command)?;
                        Ok(McpServerInspection {
                            server_policy_id: id.clone(),
                            transport: resolved.identity.transport,
                            fingerprint: resolved.identity.fingerprint,
                            executable: command.first().cloned(),
                            normalized_endpoint: None,
                            tools: resolved.tools,
                        })
                    }
                    McpServerPolicy::StreamableHttp { .. }
                    | McpServerPolicy::StreamableHttp2025 { .. } => {
                        let resolved = resolve_http_server(policy, id)?;
                        Ok(McpServerInspection {
                            server_policy_id: id.clone(),
                            transport: resolved.identity.transport,
                            fingerprint: resolved.identity.fingerprint,
                            executable: None,
                            normalized_endpoint: resolved.identity.endpoint,
                            tools: resolved.tools,
                        })
                    }
                })
                .collect::<Result<Vec<_>, String>>()?
        } else {
            policy
                .allowed_server_commands
                .iter()
                .map(|command| {
                    let resolved = resolve_stdio_server(policy, command)?;
                    Ok(McpServerInspection {
                        server_policy_id: resolved.identity.id,
                        transport: resolved.identity.transport,
                        fingerprint: resolved.identity.fingerprint,
                        executable: command.first().cloned(),
                        normalized_endpoint: None,
                        tools: resolved.tools,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?
        };
        Ok(Self {
            mode,
            max_frame_bytes: policy.max_frame_bytes,
            servers,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeObserverArtifact {
    pub schema_version: u32,
    pub artifact_kind: &'static str,
    pub observer: &'static str,
    pub authorization_boundary: &'static str,
    pub runtime_integration: &'static str,
    pub enabled: bool,
    pub transports: Vec<&'static str>,
    pub capture_payloads: bool,
    pub max_payload_bytes: i64,
    pub log_path: String,
    pub server_command_patterns: Vec<String>,
}

impl NativeObserverArtifact {
    #[must_use]
    pub fn from_config(config: &McpInspectionConfiguration) -> Self {
        Self {
            schema_version: 1,
            artifact_kind: "sendbox.native-mcp-observer-description",
            observer: "future C/libbpf ring-buffer metadata producer",
            authorization_boundary: "local stdio broker only; HTTP/SSE is observation-only",
            runtime_integration: "not included",
            enabled: config.enabled,
            transports: config
                .transports
                .iter()
                .map(|transport| match transport {
                    InspectionTransport::Stdio => "stdio",
                    InspectionTransport::Http => "http",
                })
                .collect(),
            capture_payloads: config.capture_payloads,
            max_payload_bytes: config.max_payload_bytes,
            log_path: config.log_path.display().to_string(),
            server_command_patterns: config.server_command_patterns.clone(),
        }
    }

    pub fn to_pretty_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self).map(|mut json| {
            json.push('\n');
            json
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sendbox_policy::Action;

    use super::*;

    #[test]
    fn artifact_is_deterministic_and_not_an_executable_script() {
        let artifact = NativeObserverArtifact::from_config(&McpInspectionConfiguration::default())
            .to_pretty_json()
            .unwrap();
        assert_eq!(
            artifact,
            NativeObserverArtifact::from_config(&McpInspectionConfiguration::default())
                .to_pretty_json()
                .unwrap()
        );
        assert!(artifact.contains("observation-only"));
        assert!(artifact.contains("\"runtime_integration\": \"not included\""));
        assert!(!artifact.contains("#!/"));
        assert!(!artifact.contains("bpftrace"));
    }

    #[test]
    fn boundary_inspection_exposes_server_ids_fingerprints_and_tools() {
        let policy = ToolCallPolicy {
            servers: BTreeMap::from([(
                "github".to_owned(),
                McpServerPolicy::Stdio {
                    command: vec!["/usr/bin/github-mcp".to_owned(), "stdio".to_owned()],
                    tools: ServerToolPolicy {
                        default_action: Action::Deny,
                        allowlist: vec!["search_code".to_owned()],
                        denylist: vec!["delete_*".to_owned()],
                    },
                },
            )]),
            ..ToolCallPolicy::default()
        };
        let inspection = McpBoundaryInspection::from_policy(&policy).unwrap();
        assert_eq!(inspection.mode, "hierarchical");
        assert_eq!(inspection.servers[0].server_policy_id, "github");
        assert_eq!(inspection.servers[0].fingerprint.len(), 64);
        assert_eq!(
            inspection.servers[0].tools.allowlist,
            ["search_code".to_owned()]
        );
    }
}
