#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use sendbox_core::{Diagnostic, DiagnosticCode, ValidationFailure};
use sendbox_git::normalize_branch;
use sendbox_policy::PolicyConfiguration;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod persistence;
mod presets;

pub use persistence::{
    AtomicWriteMode, CONFIG_FILE_MODE, LoadedConfiguration, MigrationReport, MigrationResult,
    atomic_write_file, ensure_directory,
};
pub use presets::PolicyPreset;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeProvider {
    Auto,
    Apple,
    Kata,
    Hyperlight,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KataRuntimeConfiguration {
    pub executable: String,
    pub runtime_handler: String,
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshotter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_path: Option<PathBuf>,
}

impl Default for KataRuntimeConfiguration {
    fn default() -> Self {
        Self {
            executable: "nerdctl".to_owned(),
            runtime_handler: "io.containerd.kata.v2".to_owned(),
            namespace: "sendbox".to_owned(),
            address: None,
            snapshotter: None,
            configuration_path: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HyperlightRuntimeConfiguration {
    pub executable: PathBuf,
    pub kernel_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<PathBuf>,
    pub stack_mb: i64,
}

impl Default for HyperlightRuntimeConfiguration {
    fn default() -> Self {
        Self {
            executable: PathBuf::from("/usr/local/bin/hyperlight-unikraft"),
            kernel_path: PathBuf::new(),
            initrd_path: None,
            stack_mb: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfiguration {
    pub provider: RuntimeProvider,
    pub kata: KataRuntimeConfiguration,
    pub hyperlight: HyperlightRuntimeConfiguration,
}

impl Default for RuntimeConfiguration {
    fn default() -> Self {
        Self {
            provider: RuntimeProvider::Auto,
            kata: KataRuntimeConfiguration::default(),
            hyperlight: HyperlightRuntimeConfiguration::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfiguration {
    pub cpus: i64,
    pub memory_mb: i64,
    pub disk_size_mb: i64,
}

impl Default for ResourceConfiguration {
    fn default() -> Self {
        Self {
            cpus: 4,
            memory_mb: 4096,
            disk_size_mb: 10_240,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevContainerConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,
    pub auto_generate: bool,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BranchProtectionConfiguration {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub protected_branches: Vec<String>,
    pub allowed_branch_patterns: Vec<String>,
}

impl Default for BranchProtectionConfiguration {
    fn default() -> Self {
        Self {
            enabled: true,
            username: None,
            protected_branches: vec!["main".to_owned(), "master".to_owned()],
            allowed_branch_patterns: vec![
                "{username}/*".to_owned(),
                "copilot/*".to_owned(),
                "feature/*".to_owned(),
            ],
        }
    }
}

pub const SAFE_OUTPUTS_MAX_ARTIFACT_BYTES: usize = 128 * 1024;
pub const SAFE_OUTPUTS_WRITE_TOKEN_ENVIRONMENT: &str = "SENDBOX_SAFE_OUTPUTS_GITHUB_TOKEN";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeOutputsMode {
    #[default]
    Staged,
    Apply,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CreateIssueSafeOutputConfiguration {
    pub enabled: bool,
    pub max: u32,
    pub title_prefix: String,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
}

impl Default for CreateIssueSafeOutputConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            max: 1,
            title_prefix: "[sendbox] ".to_owned(),
            labels: Vec::new(),
            assignees: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AddCommentSafeOutputConfiguration {
    pub enabled: bool,
    pub max: u32,
}

impl Default for AddCommentSafeOutputConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            max: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CreatePullRequestSafeOutputConfiguration {
    pub enabled: bool,
    pub max: u32,
    pub title_prefix: String,
    pub base_branches: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub protected_paths: Vec<String>,
    pub max_changed_files: u32,
    pub max_patch_bytes: usize,
}

impl Default for CreatePullRequestSafeOutputConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            max: 1,
            title_prefix: "[sendbox] ".to_owned(),
            base_branches: vec!["main".to_owned()],
            allowed_paths: Vec::new(),
            protected_paths: vec![
                ".git/**".to_owned(),
                ".github/workflows/**".to_owned(),
                ".github/actions/**".to_owned(),
            ],
            max_changed_files: 50,
            max_patch_bytes: 512 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LabelSafeOutputConfiguration {
    pub enabled: bool,
    pub max: u32,
    pub max_labels_per_call: u32,
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
}

impl Default for LabelSafeOutputConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            max: 3,
            max_labels_per_call: 3,
            allowed: Vec::new(),
            blocked: vec!["~*".to_owned()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafeOutputsConfiguration {
    pub enabled: bool,
    pub mode: SafeOutputsMode,
    pub write_token_env: String,
    pub allowed_repositories: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub allowed_mentions: Vec<String>,
    pub max_artifact_bytes: usize,
    pub create_issue: CreateIssueSafeOutputConfiguration,
    pub add_comment: AddCommentSafeOutputConfiguration,
    pub create_pull_request: CreatePullRequestSafeOutputConfiguration,
    pub add_labels: LabelSafeOutputConfiguration,
    pub remove_labels: LabelSafeOutputConfiguration,
}

impl Default for SafeOutputsConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: SafeOutputsMode::Staged,
            write_token_env: SAFE_OUTPUTS_WRITE_TOKEN_ENVIRONMENT.to_owned(),
            allowed_repositories: Vec::new(),
            allowed_domains: vec!["github.com".to_owned()],
            allowed_mentions: Vec::new(),
            max_artifact_bytes: SAFE_OUTPUTS_MAX_ARTIFACT_BYTES,
            create_issue: CreateIssueSafeOutputConfiguration::default(),
            add_comment: AddCommentSafeOutputConfiguration::default(),
            create_pull_request: CreatePullRequestSafeOutputConfiguration::default(),
            add_labels: LabelSafeOutputConfiguration::default(),
            remove_labels: LabelSafeOutputConfiguration::default(),
        }
    }
}

impl SafeOutputsConfiguration {
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    #[must_use]
    pub const fn has_write_tools(&self) -> bool {
        self.create_issue.enabled
            || self.add_comment.enabled
            || self.create_pull_request.enabled
            || self.add_labels.enabled
            || self.remove_labels.enabled
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubConfiguration {
    pub forward_auth: bool,
    pub forward_copilot_auth: bool,
    #[serde(default)]
    pub allow_private_repository_access: bool,
    #[serde(default)]
    pub branch_protection: BranchProtectionConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "SafeOutputsConfiguration::is_default")]
    pub safe_outputs: SafeOutputsConfiguration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InspectionTransport {
    Stdio,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpInspectionConfiguration {
    pub enabled: bool,
    pub transports: Vec<InspectionTransport>,
    pub capture_payloads: bool,
    pub max_payload_bytes: i64,
    pub log_path: PathBuf,
    pub server_command_patterns: Vec<String>,
}

impl Default for McpInspectionConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            transports: vec![InspectionTransport::Stdio],
            capture_payloads: true,
            max_payload_bytes: 16_384,
            log_path: PathBuf::from("/var/log/sendbox/mcp-trace.log"),
            server_command_patterns: [
                "mcp-server",
                "mcp_server",
                "modelcontextprotocol",
                "model-context-protocol",
                "@modelcontextprotocol",
                "mcp-remote",
                "server-mcp",
                "--mcp",
                "mcp.server",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObservabilityConfiguration {
    pub mcp_inspection: McpInspectionConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfiguration {
    pub name: String,
    pub project_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeConfiguration>,
    pub resources: ResourceConfiguration,
    pub policy: PolicyConfiguration,
    pub secrets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devcontainer: Option<DevContainerConfiguration>,
    pub github: GitHubConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observability: Option<ObservabilityConfiguration>,
}

impl SandboxConfiguration {
    pub fn parse(yaml: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(yaml)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigurationError> {
        Ok(Self::load_with_migration(path)?.configuration)
    }

    pub fn load_with_migration(
        path: impl AsRef<Path>,
    ) -> Result<LoadedConfiguration, ConfigurationError> {
        let path = path.as_ref();
        let yaml = fs::read_to_string(path).map_err(|source| ConfigurationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        persistence::parse_with_migration(&yaml, path)
    }

    pub fn migrate(yaml: &str) -> Result<MigrationResult, ConfigurationError> {
        persistence::migrate(yaml, Path::new("<memory>"))
    }

    pub fn for_project(
        project_path: PathBuf,
        policy_preset: PolicyPreset,
        runtime_provider: RuntimeProvider,
    ) -> Self {
        let name = project_path
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("sendbox")
            .to_owned();
        let mut policy = policy_preset.configuration();
        let mut runtime = RuntimeConfiguration {
            provider: runtime_provider,
            ..RuntimeConfiguration::default()
        };
        let mut branch_protection = BranchProtectionConfiguration::default();

        if runtime_provider == RuntimeProvider::Hyperlight {
            runtime.hyperlight.kernel_path = PathBuf::from("/opt/hyperlight/shell-kernel");
            policy.boundaries.enabled = false;
            policy
                .network
                .allowed_domains
                .retain(|domain| !domain.contains('*'));
            branch_protection.enabled = false;
        }

        Self {
            name,
            project_path,
            runtime: Some(runtime),
            resources: ResourceConfiguration::default(),
            policy,
            secrets: Vec::new(),
            devcontainer: Some(DevContainerConfiguration {
                config_path: None,
                auto_generate: true,
                extensions: Vec::new(),
            }),
            github: GitHubConfiguration {
                forward_auth: true,
                forward_copilot_auth: true,
                allow_private_repository_access: false,
                branch_protection,
                ssh_key_path: None,
                safe_outputs: SafeOutputsConfiguration::default(),
            },
            observability: Some(ObservabilityConfiguration::default()),
        }
    }

    pub fn validate(&self) -> Result<(), ValidationFailure> {
        let mut diagnostics = Vec::new();
        if self.name.trim().is_empty() {
            invalid_value(&mut diagnostics, "name", "cannot be empty");
        }
        if !self.project_path.is_absolute() {
            invalid_path(&mut diagnostics, "project_path", "must be an absolute path");
        }
        if self.resources.cpus <= 0 {
            invalid_value(
                &mut diagnostics,
                "resources.cpus",
                "must be greater than zero",
            );
        }
        if self.resources.memory_mb <= 0 {
            invalid_value(
                &mut diagnostics,
                "resources.memory_mb",
                "must be greater than zero",
            );
        }
        if self.resources.disk_size_mb <= 0 {
            invalid_value(
                &mut diagnostics,
                "resources.disk_size_mb",
                "must be greater than zero",
            );
        }

        if let Err(error) = self.policy.validate() {
            diagnostics.extend(error.into_diagnostics());
        }
        self.validate_runtime(&mut diagnostics);
        self.validate_github(&mut diagnostics);
        self.validate_observability(&mut diagnostics);

        for (index, secret) in self.secrets.iter().enumerate() {
            if secret.trim().is_empty() {
                invalid_value(
                    &mut diagnostics,
                    format!("secrets[{index}]"),
                    "secret names cannot be empty",
                );
            }
        }

        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(ValidationFailure::new(diagnostics))
        }
    }

    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn to_canonical_yaml(&self) -> Result<String, ConfigurationError> {
        self.validate().map_err(ConfigurationError::Validation)?;
        persistence::serialize(self)
    }

    pub fn write(
        &self,
        path: impl AsRef<Path>,
        mode: AtomicWriteMode,
    ) -> Result<(), ConfigurationError> {
        let path = path.as_ref();
        let yaml = self.to_canonical_yaml()?;
        atomic_write_file(path, yaml.as_bytes(), CONFIG_FILE_MODE, mode).map_err(|source| {
            ConfigurationError::Write {
                path: path.to_path_buf(),
                source,
            }
        })
    }

    fn validate_runtime(&self, diagnostics: &mut Vec<Diagnostic>) {
        let Some(runtime) = &self.runtime else {
            return;
        };
        if let Some(path) = &runtime.kata.configuration_path
            && !path.is_absolute()
        {
            invalid_path(
                diagnostics,
                "runtime.kata.configuration_path",
                "must be an absolute path when configured",
            );
        }
        if runtime.provider != RuntimeProvider::Hyperlight {
            return;
        }

        if runtime.hyperlight.executable.as_os_str().is_empty()
            || !runtime.hyperlight.executable.is_absolute()
        {
            invalid_path(
                diagnostics,
                "runtime.hyperlight.executable",
                "must be a non-empty absolute administrator-controlled path",
            );
        }
        if runtime.hyperlight.kernel_path.as_os_str().is_empty()
            || !runtime.hyperlight.kernel_path.is_absolute()
        {
            invalid_path(
                diagnostics,
                "runtime.hyperlight.kernel_path",
                "must be a non-empty absolute path for the hyperlight provider",
            );
        }
        if let Some(path) = &runtime.hyperlight.initrd_path
            && !path.is_absolute()
        {
            invalid_path(
                diagnostics,
                "runtime.hyperlight.initrd_path",
                "must be an absolute path when configured",
            );
        }
        if runtime.hyperlight.stack_mb <= 0 {
            invalid_value(
                diagnostics,
                "runtime.hyperlight.stack_mb",
                "must be greater than zero",
            );
        }
        if self.policy.boundaries.enabled {
            incompatible(
                diagnostics,
                "runtime.provider",
                "hyperlight requires policy.boundaries.enabled to be false",
            );
        }
        if self
            .policy
            .network
            .allowed_domains
            .iter()
            .any(|domain| domain.contains('*'))
        {
            incompatible(
                diagnostics,
                "policy.network.allowed_domains",
                "hyperlight requires concrete hostnames and does not support wildcards",
            );
        }
    }

    fn validate_github(&self, diagnostics: &mut Vec<Diagnostic>) {
        if self.github.branch_protection.enabled && !self.policy.boundaries.enabled {
            incompatible(
                diagnostics,
                "github.branch_protection.enabled",
                "branch protection requires policy.boundaries.enabled",
            );
        }
        self.validate_safe_outputs(diagnostics);
    }

    fn validate_safe_outputs(&self, diagnostics: &mut Vec<Diagnostic>) {
        let safe = &self.github.safe_outputs;
        if safe.max_artifact_bytes == 0 || safe.max_artifact_bytes > SAFE_OUTPUTS_MAX_ARTIFACT_BYTES
        {
            invalid_value(
                diagnostics,
                "github.safe_outputs.max_artifact_bytes",
                format!("must be between 1 and {SAFE_OUTPUTS_MAX_ARTIFACT_BYTES}"),
            );
        }
        if !valid_environment_name(&safe.write_token_env) {
            invalid_value(
                diagnostics,
                "github.safe_outputs.write_token_env",
                "must be a valid environment variable name",
            );
        }
        validate_count(
            diagnostics,
            "github.safe_outputs.create_issue.max",
            safe.create_issue.max,
        );
        validate_count(
            diagnostics,
            "github.safe_outputs.add_comment.max",
            safe.add_comment.max,
        );
        validate_count(
            diagnostics,
            "github.safe_outputs.create_pull_request.max",
            safe.create_pull_request.max,
        );
        validate_label_configuration(
            diagnostics,
            "github.safe_outputs.add_labels",
            &safe.add_labels,
        );
        validate_label_configuration(
            diagnostics,
            "github.safe_outputs.remove_labels",
            &safe.remove_labels,
        );
        validate_short_prefix(
            diagnostics,
            "github.safe_outputs.create_issue.title_prefix",
            &safe.create_issue.title_prefix,
        );
        validate_short_prefix(
            diagnostics,
            "github.safe_outputs.create_pull_request.title_prefix",
            &safe.create_pull_request.title_prefix,
        );
        validate_unique_nonempty(
            diagnostics,
            "github.safe_outputs.create_issue.labels",
            &safe.create_issue.labels,
        );
        validate_unique_nonempty(
            diagnostics,
            "github.safe_outputs.create_issue.assignees",
            &safe.create_issue.assignees,
        );
        for assignee in &safe.create_issue.assignees {
            if !valid_github_name(assignee) {
                invalid_value(
                    diagnostics,
                    "github.safe_outputs.create_issue.assignees",
                    format!("`{assignee}` is not a valid GitHub login"),
                );
            }
        }
        validate_unique_nonempty(
            diagnostics,
            "github.safe_outputs.allowed_repositories",
            &safe.allowed_repositories,
        );
        for repository in &safe.allowed_repositories {
            if !valid_repository(repository) {
                invalid_value(
                    diagnostics,
                    "github.safe_outputs.allowed_repositories",
                    format!("`{repository}` must use the exact owner/repository form"),
                );
            }
        }
        validate_unique_nonempty(
            diagnostics,
            "github.safe_outputs.allowed_domains",
            &safe.allowed_domains,
        );
        for domain in &safe.allowed_domains {
            if !valid_domain(domain) {
                invalid_value(
                    diagnostics,
                    "github.safe_outputs.allowed_domains",
                    format!("`{domain}` must be a lowercase concrete hostname"),
                );
            }
        }
        validate_unique_nonempty(
            diagnostics,
            "github.safe_outputs.allowed_mentions",
            &safe.allowed_mentions,
        );
        for mention in &safe.allowed_mentions {
            if !valid_github_name(mention) {
                invalid_value(
                    diagnostics,
                    "github.safe_outputs.allowed_mentions",
                    format!("`{mention}` is not a valid GitHub login"),
                );
            }
        }
        validate_unique_nonempty(
            diagnostics,
            "github.safe_outputs.create_pull_request.base_branches",
            &safe.create_pull_request.base_branches,
        );
        for branch in &safe.create_pull_request.base_branches {
            if normalize_branch(branch).as_deref() != Some(branch.as_str()) {
                invalid_value(
                    diagnostics,
                    "github.safe_outputs.create_pull_request.base_branches",
                    format!("`{branch}` is not a normalized Git branch name"),
                );
            }
        }
        validate_unique_nonempty(
            diagnostics,
            "github.safe_outputs.create_pull_request.allowed_paths",
            &safe.create_pull_request.allowed_paths,
        );
        validate_unique_nonempty(
            diagnostics,
            "github.safe_outputs.create_pull_request.protected_paths",
            &safe.create_pull_request.protected_paths,
        );
        if safe.create_pull_request.max_changed_files == 0
            || safe.create_pull_request.max_changed_files > 1_000
        {
            invalid_value(
                diagnostics,
                "github.safe_outputs.create_pull_request.max_changed_files",
                "must be between 1 and 1000",
            );
        }
        if safe.create_pull_request.max_patch_bytes == 0
            || safe.create_pull_request.max_patch_bytes > 10 * 1024 * 1024
        {
            invalid_value(
                diagnostics,
                "github.safe_outputs.create_pull_request.max_patch_bytes",
                "must be between 1 and 10485760",
            );
        }
        if safe.enabled {
            if self
                .secrets
                .iter()
                .any(|name| name == &safe.write_token_env)
            {
                incompatible(
                    diagnostics,
                    "github.safe_outputs.write_token_env",
                    "the Safe Outputs write token must not be forwarded as a sandbox secret",
                );
            }
            if self.github.forward_auth {
                incompatible(
                    diagnostics,
                    "github.forward_auth",
                    "must be false when github.safe_outputs.enabled is true",
                );
            }
            if self.github.ssh_key_path.is_some() {
                incompatible(
                    diagnostics,
                    "github.ssh_key_path",
                    "SSH write authentication is unavailable when Safe Outputs is enabled",
                );
            }
            if self.github.forward_copilot_auth
                && matches!(
                    safe.write_token_env.as_str(),
                    "COPILOT_GITHUB_TOKEN" | "GITHUB_COPILOT_TOKEN"
                )
            {
                incompatible(
                    diagnostics,
                    "github.safe_outputs.write_token_env",
                    "must not reuse a host Copilot token variable while Copilot authentication is forwarded",
                );
            }
            if !self.policy.boundaries.enabled {
                incompatible(
                    diagnostics,
                    "github.safe_outputs.enabled",
                    "Safe Outputs requires policy.boundaries.enabled",
                );
            }
            if safe.has_write_tools() && safe.allowed_repositories.is_empty() {
                invalid_value(
                    diagnostics,
                    "github.safe_outputs.allowed_repositories",
                    "must contain at least one exact repository when a write tool is enabled",
                );
            }
            if safe.create_pull_request.enabled && safe.create_pull_request.allowed_paths.is_empty()
            {
                invalid_value(
                    diagnostics,
                    "github.safe_outputs.create_pull_request.allowed_paths",
                    "must contain at least one path pattern when pull-request creation is enabled",
                );
            }
        }
    }

    fn validate_observability(&self, diagnostics: &mut Vec<Diagnostic>) {
        let Some(observability) = &self.observability else {
            return;
        };
        let inspection = &observability.mcp_inspection;
        if inspection.max_payload_bytes <= 0 {
            invalid_value(
                diagnostics,
                "observability.mcp_inspection.max_payload_bytes",
                "must be greater than zero",
            );
        }
        if !inspection.log_path.is_absolute() {
            invalid_path(
                diagnostics,
                "observability.mcp_inspection.log_path",
                "must be an absolute path",
            );
        }
        if inspection.enabled && inspection.transports.is_empty() {
            invalid_value(
                diagnostics,
                "observability.mcp_inspection.transports",
                "must contain at least one transport when inspection is enabled",
            );
        }
    }
}

fn validate_count(diagnostics: &mut Vec<Diagnostic>, path: &str, count: u32) {
    if count == 0 || count > 100 {
        invalid_value(diagnostics, path, "must be between 1 and 100");
    }
}

fn validate_label_configuration(
    diagnostics: &mut Vec<Diagnostic>,
    path: &str,
    configuration: &LabelSafeOutputConfiguration,
) {
    validate_count(diagnostics, &format!("{path}.max"), configuration.max);
    validate_count(
        diagnostics,
        &format!("{path}.max_labels_per_call"),
        configuration.max_labels_per_call,
    );
    validate_unique_nonempty(
        diagnostics,
        &format!("{path}.allowed"),
        &configuration.allowed,
    );
    validate_unique_nonempty(
        diagnostics,
        &format!("{path}.blocked"),
        &configuration.blocked,
    );
}

fn validate_short_prefix(diagnostics: &mut Vec<Diagnostic>, path: &str, prefix: &str) {
    if prefix.len() > 128 || prefix.as_bytes().contains(&0) {
        invalid_value(
            diagnostics,
            path,
            "must be at most 128 bytes and contain no NUL",
        );
    }
}

fn validate_unique_nonempty(diagnostics: &mut Vec<Diagnostic>, path: &str, values: &[String]) {
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            invalid_value(diagnostics, path, "entries cannot be empty");
        } else if !unique.insert(value) {
            invalid_value(diagnostics, path, format!("duplicate entry `{value}`"));
        }
    }
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(first) if first == b'_' || first.is_ascii_alphabetic())
        && name.len() <= 128
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn valid_repository(repository: &str) -> bool {
    let Some((owner, name)) = repository.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !name.is_empty()
        && !name.contains('/')
        && valid_github_name(owner)
        && name.len() <= 100
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_github_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains('*')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("could not read configuration {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not decode configuration {path}: {source}")]
    Decode {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },
    #[error("could not encode configuration: {source}")]
    Encode {
        #[source]
        source: serde_yaml_ng::Error,
    },
    #[error("unsupported configuration schema version {found}; current version is {current}")]
    UnsupportedVersion { found: u64, current: u32 },
    #[error("configuration validation failed: {0}")]
    Validation(ValidationFailure),
    #[error("could not write configuration {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl ConfigurationError {
    #[must_use]
    pub fn diagnostic(&self) -> Diagnostic {
        match self {
            Self::Io { path, source } => Diagnostic::new(
                DiagnosticCode::Io,
                path.display().to_string(),
                source.to_string(),
            ),
            Self::Decode { path, source } => Diagnostic::new(
                DiagnosticCode::InvalidYaml,
                path.display().to_string(),
                source.to_string(),
            ),
            Self::Encode { source } => Diagnostic::new(
                DiagnosticCode::InvalidYaml,
                "configuration",
                source.to_string(),
            ),
            Self::UnsupportedVersion { found, current } => Diagnostic::new(
                DiagnosticCode::InvalidYaml,
                "schema_version",
                format!("unsupported version {found}; current version is {current}"),
            ),
            Self::Validation(error) => error.diagnostics().first().cloned().unwrap_or_else(|| {
                Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    "configuration",
                    "configuration validation failed",
                )
            }),
            Self::Write { path, source } => Diagnostic::new(
                DiagnosticCode::Io,
                path.display().to_string(),
                source.to_string(),
            ),
        }
    }
}

fn invalid_value(
    diagnostics: &mut Vec<Diagnostic>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    diagnostics.push(Diagnostic::new(DiagnosticCode::InvalidValue, path, message));
}

fn invalid_path(diagnostics: &mut Vec<Diagnostic>, path: impl Into<String>, message: &str) {
    diagnostics.push(Diagnostic::new(DiagnosticCode::InvalidPath, path, message));
}

fn incompatible(diagnostics: &mut Vec<Diagnostic>, path: impl Into<String>, message: &str) {
    diagnostics.push(Diagnostic::new(
        DiagnosticCode::IncompatibleConfiguration,
        path,
        message,
    ));
}
