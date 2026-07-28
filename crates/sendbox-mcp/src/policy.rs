use std::collections::BTreeSet;
use std::fmt::Write;

pub use sendbox_core::glob_matches;
use sendbox_policy::{
    Action, McpServerPolicy, ServerToolPolicy, ToolCallPolicy, ToolTransport,
    normalize_mcp_http_endpoint,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::JsonRpcError;
use crate::jsonrpc::{
    IdPresence, MessageKind, ValidatedMessage, denial_response, validate_message,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentity {
    pub id: String,
    pub fingerprint: String,
    pub transport: ToolTransport,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedServerPolicy {
    pub identity: ServerIdentity,
    pub tools: ServerToolPolicy,
}

impl ResolvedServerPolicy {
    #[must_use]
    pub fn compile(&self) -> CompiledToolPolicy {
        CompiledToolPolicy::compile_resolved(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledToolPolicy {
    identity: ServerIdentity,
    default_action: Action,
    allowlist: Vec<String>,
    denylist: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Allowed,
    Denied,
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditDecision {
    pub server_id: String,
    pub server_fingerprint: String,
    pub transport: ToolTransport,
    pub endpoint: Option<String>,
    pub method: String,
    pub tool: Option<String>,
    pub outcome: AuditOutcome,
    pub matched_rule: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    Forward(AuditDecision),
    Respond {
        response: Vec<u8>,
        decision: AuditDecision,
    },
    Drop(AuditDecision),
    Terminate(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredToolList {
    pub payload: Vec<u8>,
    pub decisions: Vec<AuditDecision>,
}

pub fn resolve_stdio_server(
    policy: &ToolCallPolicy,
    command: &[String],
) -> Result<ResolvedServerPolicy, String> {
    if policy.uses_hierarchical_servers() {
        let mut matches = policy
            .servers
            .iter()
            .filter_map(|(id, server)| match server {
                McpServerPolicy::Stdio {
                    command: configured,
                    tools,
                } if configured == command => Some((id, tools)),
                _ => None,
            });
        let Some((id, tools)) = matches.next() else {
            return Err("MCP server command is not mapped to an allowed server policy".to_owned());
        };
        if matches.next().is_some() {
            return Err("MCP server command maps to more than one server policy".to_owned());
        }
        return Ok(ResolvedServerPolicy {
            identity: ServerIdentity {
                id: id.clone(),
                fingerprint: stdio_fingerprint(command),
                transport: ToolTransport::Stdio,
                endpoint: None,
            },
            tools: tools.clone(),
        });
    }

    if !policy
        .allowed_server_commands
        .iter()
        .any(|configured| configured == command)
    {
        return Err("MCP server command is not exactly approved".to_owned());
    }
    let fingerprint = stdio_fingerprint(command);
    Ok(ResolvedServerPolicy {
        identity: ServerIdentity {
            id: format!("legacy-{}", &fingerprint[..16]),
            fingerprint,
            transport: ToolTransport::Stdio,
            endpoint: None,
        },
        tools: ServerToolPolicy {
            default_action: policy.default_action,
            allowlist: policy.allowlist.clone(),
            denylist: policy.denylist.clone(),
        },
    })
}

pub fn resolve_http_server(
    policy: &ToolCallPolicy,
    server_id: &str,
) -> Result<ResolvedServerPolicy, String> {
    let server = policy
        .servers
        .get(server_id)
        .ok_or_else(|| "unknown MCP server policy".to_owned())?;
    let (transport, endpoint, tools) = match server {
        McpServerPolicy::StreamableHttp {
            url,
            tools,
            http: _,
        } => (ToolTransport::StreamableHttp, url, tools),
        McpServerPolicy::StreamableHttp2025 {
            url,
            tools,
            http: _,
        } => (ToolTransport::StreamableHttp2025, url, tools),
        McpServerPolicy::Stdio { .. } => {
            return Err("MCP server policy is not an HTTP transport".to_owned());
        }
    };
    let endpoint = normalize_mcp_http_endpoint(endpoint)?;
    Ok(ResolvedServerPolicy {
        identity: ServerIdentity {
            id: server_id.to_owned(),
            fingerprint: http_fingerprint(transport, &endpoint),
            transport,
            endpoint: Some(endpoint),
        },
        tools: tools.clone(),
    })
}

#[must_use]
pub fn stdio_fingerprint(command: &[String]) -> String {
    let mut bytes = b"sendbox-mcp-stdio-v1\0".to_vec();
    for part in command {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    sha256_hex(&bytes)
}

#[must_use]
pub fn http_fingerprint(transport: ToolTransport, endpoint: &str) -> String {
    let transport = match transport {
        ToolTransport::Stdio => "stdio",
        ToolTransport::StreamableHttp => "streamable_http",
        ToolTransport::StreamableHttp2025 => "streamable_http_2025",
    };
    sha256_hex(format!("sendbox-mcp-http-v1\0{transport}\0{endpoint}").as_bytes())
}

impl CompiledToolPolicy {
    #[must_use]
    pub fn compile_resolved(config: &ResolvedServerPolicy) -> Self {
        Self {
            identity: config.identity.clone(),
            default_action: config.tools.default_action,
            allowlist: config.tools.allowlist.clone(),
            denylist: config.tools.denylist.clone(),
        }
    }

    #[must_use]
    pub fn compile_legacy_unbound(config: &ToolCallPolicy) -> Self {
        Self {
            identity: ServerIdentity {
                id: "legacy-unbound".to_owned(),
                fingerprint: stdio_fingerprint(&[]),
                transport: ToolTransport::Stdio,
                endpoint: None,
            },
            default_action: config.default_action,
            allowlist: config.allowlist.clone(),
            denylist: config.denylist.clone(),
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &ServerIdentity {
        &self.identity
    }

    #[must_use]
    pub fn evaluate_tool(&self, tool: &str) -> AuditDecision {
        self.evaluate_tool_for_method(tool, "tools/call")
    }

    #[must_use]
    pub fn evaluate_message(&self, message: &ValidatedMessage) -> PolicyAction {
        if message.method.as_deref() != Some("tools/call") {
            return PolicyAction::Forward(self.decision(
                message.method.clone().unwrap_or_else(|| "response".into()),
                None,
                AuditOutcome::Allowed,
                None,
                None,
            ));
        }
        let Some(tool) = message.subject.as_deref() else {
            return PolicyAction::Terminate("MCP tools/call request is missing params.name".into());
        };
        let decision = self.evaluate_tool(tool);
        if decision.outcome == AuditOutcome::Allowed {
            return PolicyAction::Forward(decision);
        }
        let reason = decision.reason.clone().unwrap_or_else(|| "denied".into());
        match (&message.kind, &message.id) {
            (MessageKind::Notification, IdPresence::Missing) => {
                let mut dropped = decision;
                dropped.outcome = AuditOutcome::Dropped;
                PolicyAction::Drop(dropped)
            }
            (MessageKind::Request, IdPresence::Present(id)) => PolicyAction::Respond {
                response: denial_response(id, tool.trim(), &reason),
                decision,
            },
            _ => PolicyAction::Terminate("invalid tools/call JSON-RPC shape".into()),
        }
    }

    pub fn filter_tools_list_response(
        &self,
        payload: &[u8],
    ) -> Result<FilteredToolList, JsonRpcError> {
        let message = validate_message(payload)?;
        if message.kind == MessageKind::Error {
            return Ok(FilteredToolList {
                payload: payload.to_vec(),
                decisions: Vec::new(),
            });
        }
        if message.kind != MessageKind::Response {
            return Err(JsonRpcError::InvalidShape(
                "tools/list result must be a JSON-RPC response".to_owned(),
            ));
        }

        let mut root: Value = serde_json::from_slice(payload)
            .map_err(|error| JsonRpcError::InvalidJson(error.to_string()))?;
        let result = root
            .get_mut("result")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                JsonRpcError::InvalidShape("tools/list result must be an object".to_owned())
            })?;
        let tools = result
            .get_mut("tools")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| {
                JsonRpcError::InvalidShape("tools/list result.tools must be an array".to_owned())
            })?;

        let mut names = BTreeSet::new();
        let mut decisions = Vec::with_capacity(tools.len());
        let mut filtered = Vec::with_capacity(tools.len());
        for tool in std::mem::take(tools) {
            let name = tool
                .as_object()
                .and_then(|object| object.get("name"))
                .and_then(Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .ok_or_else(|| {
                    JsonRpcError::InvalidShape(
                        "tools/list entries must contain a non-empty string name".to_owned(),
                    )
                })?;
            if !names.insert(name.to_owned()) {
                return Err(JsonRpcError::InvalidShape(format!(
                    "tools/list contains duplicate tool name '{name}'"
                )));
            }
            let decision = self.evaluate_tool_for_method(name, "tools/list");
            if decision.outcome == AuditOutcome::Allowed {
                filtered.push(tool);
            }
            decisions.push(decision);
        }
        *tools = filtered;
        Ok(FilteredToolList {
            payload: serde_json::to_vec(&root)
                .map_err(|error| JsonRpcError::InvalidJson(error.to_string()))?,
            decisions,
        })
    }

    fn evaluate_tool_for_method(&self, tool: &str, method: &str) -> AuditDecision {
        let tool = tool.trim();
        if tool.is_empty() {
            return self.decision(
                method,
                None,
                AuditOutcome::Denied,
                None,
                Some("MCP tool entry is missing a name".to_owned()),
            );
        }
        if let Some(pattern) = self
            .denylist
            .iter()
            .find(|pattern| glob_matches(tool, pattern))
        {
            return self.decision(
                method,
                Some(tool.to_owned()),
                AuditOutcome::Denied,
                Some(pattern.clone()),
                Some(format!("Tool '{tool}' matches deny pattern '{pattern}'")),
            );
        }
        if let Some(pattern) = self
            .allowlist
            .iter()
            .find(|pattern| glob_matches(tool, pattern))
        {
            return self.decision(
                method,
                Some(tool.to_owned()),
                AuditOutcome::Allowed,
                Some(pattern.clone()),
                None,
            );
        }
        match self.default_action {
            Action::Allow => self.decision(
                method,
                Some(tool.to_owned()),
                AuditOutcome::Allowed,
                None,
                None,
            ),
            Action::Deny => self.decision(
                method,
                Some(tool.to_owned()),
                AuditOutcome::Denied,
                None,
                Some(format!("Tool '{tool}' is not in the allowlist")),
            ),
        }
    }

    fn decision(
        &self,
        method: impl Into<String>,
        tool: Option<String>,
        outcome: AuditOutcome,
        matched_rule: Option<String>,
        reason: Option<String>,
    ) -> AuditDecision {
        AuditDecision {
            server_id: self.identity.id.clone(),
            server_fingerprint: self.identity.fingerprint.clone(),
            transport: self.identity.transport,
            endpoint: self.identity.endpoint.clone(),
            method: method.into(),
            tool,
            outcome,
            matched_rule,
            reason,
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn hierarchical_policy() -> ToolCallPolicy {
        ToolCallPolicy {
            servers: BTreeMap::from([
                (
                    "github".to_owned(),
                    McpServerPolicy::Stdio {
                        command: vec!["/usr/bin/github-mcp".to_owned(), "stdio".to_owned()],
                        tools: ServerToolPolicy {
                            default_action: Action::Deny,
                            allowlist: vec!["read_*".to_owned(), "shared".to_owned()],
                            denylist: vec!["*delete*".to_owned()],
                        },
                    },
                ),
                (
                    "filesystem".to_owned(),
                    McpServerPolicy::Stdio {
                        command: vec!["/usr/bin/fs-mcp".to_owned()],
                        tools: ServerToolPolicy {
                            default_action: Action::Deny,
                            allowlist: vec!["list_*".to_owned()],
                            denylist: vec!["shared".to_owned()],
                        },
                    },
                ),
            ]),
            ..ToolCallPolicy::default()
        }
    }

    fn github_policy() -> CompiledToolPolicy {
        resolve_stdio_server(
            &hierarchical_policy(),
            &["/usr/bin/github-mcp".to_owned(), "stdio".to_owned()],
        )
        .unwrap()
        .compile()
    }

    #[test]
    fn exact_command_resolves_independent_server_policy() {
        let policy = hierarchical_policy();
        let github = resolve_stdio_server(
            &policy,
            &["/usr/bin/github-mcp".to_owned(), "stdio".to_owned()],
        )
        .unwrap()
        .compile();
        let filesystem = resolve_stdio_server(&policy, &["/usr/bin/fs-mcp".to_owned()])
            .unwrap()
            .compile();

        assert_eq!(github.identity().id, "github");
        assert_eq!(filesystem.identity().id, "filesystem");
        assert_eq!(
            github.evaluate_tool("shared").outcome,
            AuditOutcome::Allowed
        );
        assert_eq!(
            filesystem.evaluate_tool("shared").outcome,
            AuditOutcome::Denied
        );
        assert!(
            resolve_stdio_server(
                &policy,
                &["/usr/bin/github-mcp".to_owned(), "changed".to_owned()]
            )
            .is_err()
        );
    }

    #[test]
    fn deny_wins_over_allow() {
        assert_eq!(
            github_policy().evaluate_tool("read_delete").outcome,
            AuditOutcome::Denied
        );
        assert_eq!(
            github_policy().evaluate_tool("read_file").outcome,
            AuditOutcome::Allowed
        );
    }

    #[test]
    fn denied_notification_drops_and_denied_request_responds() {
        let mut notification = validate_message(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_file"}}"#,
        )
        .unwrap();
        assert!(matches!(
            github_policy().evaluate_message(&notification),
            PolicyAction::Drop(_)
        ));
        notification.id = IdPresence::Present("7".into());
        notification.kind = MessageKind::Request;
        assert!(matches!(
            github_policy().evaluate_message(&notification),
            PolicyAction::Respond { .. }
        ));
    }

    #[test]
    fn filters_tools_list_without_weakening_call_time_enforcement() {
        let filtered = github_policy()
            .filter_tools_list_response(
                br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"},{"name":"delete_file"},{"name":"shared"}],"nextCursor":"next"}}"#,
            )
            .unwrap();
        let value: Value = serde_json::from_slice(&filtered.payload).unwrap();
        let names = value["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, ["read_file", "shared"]);
        assert_eq!(
            github_policy().evaluate_tool("delete_file").outcome,
            AuditOutcome::Denied
        );
        assert_eq!(filtered.decisions.len(), 3);
    }

    #[test]
    fn legacy_mode_synthesizes_a_stable_non_sensitive_identity() {
        let policy = ToolCallPolicy {
            allowed_server_commands: vec![vec!["/usr/bin/mcp".to_owned(), "--token=x".to_owned()]],
            allowlist: vec!["read".to_owned()],
            ..ToolCallPolicy::default()
        };
        let resolved = resolve_stdio_server(
            &policy,
            &["/usr/bin/mcp".to_owned(), "--token=x".to_owned()],
        )
        .unwrap();
        assert!(resolved.identity.id.starts_with("legacy-"));
        assert_eq!(resolved.identity.fingerprint.len(), 64);
        assert!(!resolved.identity.id.contains("token"));
    }

    #[test]
    fn glob_matches_swift_semantics() {
        assert!(glob_matches("filesystem.read", "filesystem.*"));
        assert!(glob_matches("abc", "a?c"));
        assert!(!glob_matches("abc", "a?d"));
        assert!(glob_matches("😀x", "?x"));
    }
}
