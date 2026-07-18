#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::Path;

use sendbox_core::{Diagnostic, DiagnosticCode, ValidationFailure};
use serde::{Deserialize, Serialize};

const BPFTRACE_STRING_LENGTH: usize = 4096;
const MAX_SERVER_COMMAND_PARTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicy {
    pub default_action: Action,
    pub allowlist: Vec<String>,
    pub denylist: Vec<String>,
    pub log_blocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub default_action: Action,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub allow_dns: bool,
    pub max_connections: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolTransport {
    Stdio,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolCallPolicy {
    pub transport: ToolTransport,
    pub default_action: Action,
    pub allowlist: Vec<String>,
    pub denylist: Vec<String>,
    pub max_frame_bytes: i64,
    pub server_command_patterns: Vec<String>,
    pub allowed_server_commands: Vec<Vec<String>>,
}

impl Default for ToolCallPolicy {
    fn default() -> Self {
        Self {
            transport: ToolTransport::Stdio,
            default_action: Action::Deny,
            allowlist: Vec::new(),
            denylist: Vec::new(),
            max_frame_bytes: 1_048_576,
            server_command_patterns: default_server_command_patterns(),
            allowed_server_commands: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyscallPolicy {
    pub additional_denylist: Vec<String>,
    pub log_blocked: bool,
}

impl Default for SyscallPolicy {
    fn default() -> Self {
        Self {
            additional_denylist: Vec::new(),
            log_blocked: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BoundaryPolicy {
    pub enabled: bool,
    pub tool_calls: ToolCallPolicy,
    pub syscalls: SyscallPolicy,
    pub log_path: String,
}

impl Default for BoundaryPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            tool_calls: ToolCallPolicy::default(),
            syscalls: SyscallPolicy::default(),
            log_path: "/var/log/sendbox/boundary.log".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfiguration {
    pub commands: CommandPolicy,
    pub network: NetworkPolicy,
    #[serde(default)]
    pub boundaries: BoundaryPolicy,
}

impl PolicyConfiguration {
    pub fn validate(&self) -> Result<(), ValidationFailure> {
        let mut diagnostics = Vec::new();
        validate_nonempty_patterns(
            &self.commands.allowlist,
            "policy.commands.allowlist",
            &mut diagnostics,
        );
        validate_nonempty_patterns(
            &self.commands.denylist,
            "policy.commands.denylist",
            &mut diagnostics,
        );
        validate_nonempty_patterns(
            &self.network.allowed_domains,
            "policy.network.allowed_domains",
            &mut diagnostics,
        );
        validate_nonempty_patterns(
            &self.network.blocked_domains,
            "policy.network.blocked_domains",
            &mut diagnostics,
        );

        if self.network.max_connections.is_some_and(|value| value <= 0) {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                "policy.network.max_connections",
                "must be greater than zero when configured",
            ));
        }

        self.boundaries.validate(&mut diagnostics);

        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(ValidationFailure::new(diagnostics))
        }
    }

    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl BoundaryPolicy {
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        if self.tool_calls.max_frame_bytes <= 0 {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                "policy.boundaries.tool_calls.max_frame_bytes",
                "must be greater than zero",
            ));
        }
        if !Path::new(&self.log_path).is_absolute() {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidPath,
                "policy.boundaries.log_path",
                "must be an absolute path",
            ));
        }

        let required_syscalls = HashSet::from(["execve", "exit", "exit_group", "rt_sigreturn"]);
        for syscall in &self.syscalls.additional_denylist {
            if required_syscalls.contains(syscall.as_str()) {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    "policy.boundaries.syscalls.additional_denylist",
                    format!("cannot deny required syscall '{syscall}'"),
                ));
            }
        }

        let patterns = if self.tool_calls.server_command_patterns.is_empty() {
            default_server_command_patterns()
        } else {
            self.tool_calls.server_command_patterns.clone()
        };
        for pattern in &patterns {
            if pattern.len() >= BPFTRACE_STRING_LENGTH {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    "policy.boundaries.tool_calls.server_command_patterns",
                    format!("pattern exceeds 4095 UTF-8 bytes: {pattern}"),
                ));
            }
        }

        let forbidden = HashSet::from([
            "sh", "bash", "zsh", "fish", "env", "npx", "npm", "pnpm", "yarn", "bunx", "pipx", "uvx",
        ]);
        for (index, command) in self.tool_calls.allowed_server_commands.iter().enumerate() {
            let path = format!("policy.boundaries.tool_calls.allowed_server_commands[{index}]");
            let Some(executable) = command.first() else {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    path,
                    "must contain an executable",
                ));
                continue;
            };
            let basename = Path::new(executable)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if !Path::new(executable).is_absolute() || forbidden.contains(basename) {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidPath,
                    path.clone(),
                    "executable must be an absolute non-shell, non-package-runner path",
                ));
            }
            if command.len() > MAX_SERVER_COMMAND_PARTS {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    path.clone(),
                    "may contain at most 16 command parts",
                ));
            }
            if command
                .iter()
                .any(|part| part.len() >= BPFTRACE_STRING_LENGTH)
            {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    path.clone(),
                    "each command part must be at most 4095 UTF-8 bytes",
                ));
            }
            if !command
                .iter()
                .skip(1)
                .any(|argument| patterns.iter().any(|pattern| argument.contains(pattern)))
            {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    path,
                    "an argument must match a configured server_command_patterns entry",
                ));
            }
        }
    }
}

fn validate_nonempty_patterns(values: &[String], path: &str, diagnostics: &mut Vec<Diagnostic>) {
    if values.iter().any(|value| value.trim().is_empty()) {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            path,
            "entries cannot be empty",
        ));
    }
}

#[must_use]
pub fn default_server_command_patterns() -> Vec<String> {
    [
        "mcp-server",
        "mcp_server",
        "modelcontextprotocol",
        "model-context-protocol",
        "@modelcontextprotocol",
        "mcp-remote",
        "server-mcp",
        "mcp.server",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
