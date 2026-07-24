#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use sendbox_core::{Diagnostic, DiagnosticCode, ValidationFailure};
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
