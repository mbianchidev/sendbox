#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use sendbox_core::{Diagnostic, DiagnosticCode, ValidationFailure};
use sendbox_policy::PolicyConfiguration;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    pub address: Option<String>,
    pub snapshotter: Option<String>,
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
    pub config_path: Option<PathBuf>,
    pub auto_generate: bool,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BranchProtectionConfiguration {
    pub enabled: bool,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubConfiguration {
    pub forward_auth: bool,
    pub forward_copilot_auth: bool,
    #[serde(default)]
    pub allow_private_repository_access: bool,
    #[serde(default)]
    pub branch_protection: BranchProtectionConfiguration,
    pub ssh_key_path: Option<PathBuf>,
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
            transports: vec![InspectionTransport::Stdio, InspectionTransport::Http],
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
    pub runtime: Option<RuntimeConfiguration>,
    pub resources: ResourceConfiguration,
    pub policy: PolicyConfiguration,
    pub secrets: Vec<String>,
    pub devcontainer: Option<DevContainerConfiguration>,
    pub github: GitHubConfiguration,
    pub observability: Option<ObservabilityConfiguration>,
}

impl SandboxConfiguration {
    pub fn parse(yaml: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(yaml)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigurationError> {
        let path = path.as_ref();
        let yaml = fs::read_to_string(path).map_err(|source| ConfigurationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&yaml).map_err(|source| ConfigurationError::Decode {
            path: path.to_path_buf(),
            source,
        })
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
        }
    }
}

fn invalid_value(diagnostics: &mut Vec<Diagnostic>, path: impl Into<String>, message: &str) {
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
