use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use sendbox_policy::ToolCallPolicy;
use serde::{Deserialize, Serialize};

use crate::config::{ApprovedCommand, ProjectConfigValidator};

pub const RUNTIME_POLICY_SCHEMA_VERSION: u32 = 1;
pub const NATIVE_POLICY_PATH: &str = "/run/sendbox-boundary/mcp-policy.json";
pub const OBSERVATION_ROOT: &str = "/var/log/sendbox";
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
    pub fixed_environment: BTreeMap<String, String>,
    pub inherited_environment_keys: BTreeSet<String>,
    #[serde(default)]
    pub observation: Option<RuntimeObservationConfiguration>,
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
        let _ = self.approved_commands()?;
        if !(1..=MAX_FRAME_BYTES).contains(&self.tool_policy.max_frame_bytes) {
            return Err(format!(
                "MCP maximum frame size must be between 1 and {MAX_FRAME_BYTES} bytes"
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
        }
        Ok(())
    }

    pub fn approved_commands(&self) -> Result<Vec<ApprovedCommand>, String> {
        self.tool_policy
            .allowed_server_commands
            .iter()
            .map(|command| ApprovedCommand::from_argv(command))
            .collect()
    }

    pub fn project_validator(&self) -> Result<ProjectConfigValidator, String> {
        Ok(ProjectConfigValidator::new(
            [vec![crate::config::NATIVE_BROKER_PATH.to_owned()]],
            self.approved_commands()?,
        ))
    }
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
            },
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
}
