use sendbox_policy::{Action, ToolCallPolicy};

use crate::jsonrpc::{IdPresence, MessageKind, ValidatedMessage, denial_response};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledToolPolicy {
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

impl CompiledToolPolicy {
    #[must_use]
    pub fn compile(config: &ToolCallPolicy) -> Self {
        Self {
            default_action: config.default_action,
            allowlist: config.allowlist.clone(),
            denylist: config.denylist.clone(),
        }
    }

    #[must_use]
    pub fn evaluate_tool(&self, tool: &str) -> AuditDecision {
        let tool = tool.trim();
        if tool.is_empty() {
            return denied(tool, None, "MCP tools/call request is missing params.name");
        }
        if let Some(pattern) = self
            .denylist
            .iter()
            .find(|pattern| glob_matches(tool, pattern))
        {
            return denied(
                tool,
                Some(pattern.clone()),
                format!("Tool '{tool}' matches deny pattern '{pattern}'"),
            );
        }
        if let Some(pattern) = self
            .allowlist
            .iter()
            .find(|pattern| glob_matches(tool, pattern))
        {
            return AuditDecision {
                method: "tools/call".into(),
                tool: Some(tool.to_owned()),
                outcome: AuditOutcome::Allowed,
                matched_rule: Some(pattern.clone()),
                reason: None,
            };
        }
        match self.default_action {
            Action::Allow => AuditDecision {
                method: "tools/call".into(),
                tool: Some(tool.to_owned()),
                outcome: AuditOutcome::Allowed,
                matched_rule: None,
                reason: None,
            },
            Action::Deny => denied(tool, None, format!("Tool '{tool}' is not in the allowlist")),
        }
    }

    #[must_use]
    pub fn evaluate_message(&self, message: &ValidatedMessage) -> PolicyAction {
        if message.method.as_deref() != Some("tools/call") {
            return PolicyAction::Forward(AuditDecision {
                method: message.method.clone().unwrap_or_else(|| "response".into()),
                tool: None,
                outcome: AuditOutcome::Allowed,
                matched_rule: None,
                reason: None,
            });
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
}

fn denied(tool: &str, matched_rule: Option<String>, reason: impl Into<String>) -> AuditDecision {
    AuditDecision {
        method: "tools/call".into(),
        tool: (!tool.is_empty()).then(|| tool.to_owned()),
        outcome: AuditOutcome::Denied,
        matched_rule,
        reason: Some(reason.into()),
    }
}

#[must_use]
pub fn glob_matches(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let value = value.chars().collect::<Vec<_>>();
    let pattern = pattern.chars().collect::<Vec<_>>();
    let (mut value_index, mut pattern_index) = (0usize, 0usize);
    let (mut star_value_index, mut star_pattern_index) = (None, None);

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == '?' || pattern[pattern_index] == value[value_index])
        {
            value_index += 1;
            pattern_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_pattern_index = Some(pattern_index);
            star_value_index = Some(value_index);
            pattern_index += 1;
        } else if let (Some(star_pattern), Some(star_value)) =
            (star_pattern_index, star_value_index)
        {
            pattern_index = star_pattern + 1;
            let next_value = star_value + 1;
            star_value_index = Some(next_value);
            value_index = next_value;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sendbox_policy::ToolTransport;

    fn policy() -> CompiledToolPolicy {
        CompiledToolPolicy::compile(&ToolCallPolicy {
            transport: ToolTransport::Stdio,
            default_action: Action::Deny,
            allowlist: vec!["read_*".into(), "*".into()],
            denylist: vec!["*delete*".into()],
            max_frame_bytes: 4096,
            server_command_patterns: Vec::new(),
            allowed_server_commands: Vec::new(),
        })
    }

    #[test]
    fn deny_wins_over_allow() {
        assert_eq!(
            policy().evaluate_tool("delete_file").outcome,
            AuditOutcome::Denied
        );
        assert_eq!(
            policy().evaluate_tool("read_file").outcome,
            AuditOutcome::Allowed
        );
    }

    #[test]
    fn denied_notification_drops_and_denied_request_responds() {
        let mut notification = crate::jsonrpc::validate_message(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_file"}}"#,
        )
        .unwrap();
        assert!(matches!(
            policy().evaluate_message(&notification),
            PolicyAction::Drop(_)
        ));
        notification.id = IdPresence::Present("7".into());
        notification.kind = MessageKind::Request;
        assert!(matches!(
            policy().evaluate_message(&notification),
            PolicyAction::Respond { .. }
        ));
    }

    #[test]
    fn glob_matches_swift_semantics() {
        assert!(glob_matches("filesystem.read", "filesystem.*"));
        assert!(glob_matches("abc", "a?c"));
        assert!(!glob_matches("abc", "a?d"));
        assert!(glob_matches("😀x", "?x"));
    }
}
