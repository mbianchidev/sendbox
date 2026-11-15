//! Operator-owned, versioned governance profiles.
//!
//! A profile is the maximum a governed session may be granted. It is parsed
//! from the exact bytes an operator signed; its digest is the SHA-256 of those
//! bytes, so any edit produces a different, separately signed revision.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    GovernanceError, ProfileId, ServiceId,
    digest::Sha256Digest,
    grant::{validate_method, validate_path_prefix},
};

pub const PROFILE_FORMAT: &str = "sendbox.governance-profile";
pub const PROFILE_VERSION: u32 = 1;
pub const MAX_PROFILE_BYTES: usize = 256 * 1024;
/// Upper bound for the validity window of one profile revision.
pub const MAX_PROFILE_VALIDITY_SECONDS: u64 = 400 * 24 * 60 * 60;
/// Placeholder credential value given to agents. It is not a secret: the host
/// broker discards it and injects the operator-managed provider credential.
pub const BROKERED_CREDENTIAL_PLACEHOLDER: &str = "sendbox-brokered-credential";

const MAX_LIST_ENTRIES: usize = 256;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_SECRET_NAME_BYTES: usize = 128;
const MAX_MCP_SERVER_ID_BYTES: usize = 64;
const MAX_CREDENTIAL_SERVICES: usize = 16;
const HARD_MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;
const HARD_MAX_STREAM_SECONDS: u64 = 60 * 60;
const HARD_MAX_IDLE_SECONDS: u64 = 10 * 60;
const MIN_LEASE_SECONDS: u64 = 30;
const MAX_LEASE_SECONDS: u64 = 60 * 60;
const MAX_GRANT_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_REVOCATION_GRACE_SECONDS: u64 = 60;
const MAX_CONCURRENT_STREAMS: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceProfile {
    pub format: String,
    pub version: u32,
    pub id: ProfileId,
    pub revision: u64,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub ceiling: Ceiling,
    #[serde(default)]
    pub denials: Denials,
    #[serde(default)]
    pub credential_services: Vec<CredentialServiceProfile>,
    #[serde(default)]
    pub grants: GrantLimits,
}

/// Identity of one exact profile revision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRef {
    pub id: ProfileId,
    pub revision: u64,
    pub sha256: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CeilingAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeKind {
    Apple,
    Kata,
    Hyperlight,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ceiling {
    pub runtimes: Vec<RuntimeKind>,
    /// Permitted OCI image digests (`sha256:<hex>`). Empty permits any image.
    #[serde(default)]
    pub images: Vec<String>,
    /// Permitted host workspace roots. Empty permits any workspace.
    #[serde(default)]
    pub workspace_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceCeiling>,
    pub commands: CommandCeiling,
    pub network: NetworkCeiling,
    #[serde(default)]
    pub mcp: McpCeiling,
    #[serde(default)]
    pub packages: PackageCeiling,
    #[serde(default)]
    pub secrets: SecretCeiling,
    #[serde(default)]
    pub github: GitHubCeiling,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCeiling {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpus: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_disk_mb: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandCeiling {
    pub default_action: CeilingAction,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortCeiling {
    pub protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCeiling {
    pub default_action: CeilingAction,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_networks: Vec<String>,
    /// Empty permits any destination port.
    #[serde(default)]
    pub allowed_ports: Vec<PortCeiling>,
    #[serde(default)]
    pub allow_dns: bool,
    /// Permits the implicit GitHub Meta CIDR delegation that an exact
    /// `github.com` grant enables.
    #[serde(default)]
    pub github_meta: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<i64>,
    #[serde(default)]
    pub dns: DnsCeiling,
}

/// Loosest DNS broker controls a session may use. Smaller numeric limits and
/// fewer record types are stricter; the budget window must match exactly.
/// Defaults equal the runtime's built-in DNS policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsCeiling {
    pub max_ttl_secs: u32,
    pub max_qname_octets: u32,
    pub max_labels: u32,
    pub max_label_octets: u32,
    pub allowed_record_types: Vec<String>,
    pub max_response_records: u32,
    pub budget_window_secs: u32,
    pub budget_max_queries: u32,
    pub budget_max_query_octets: u64,
    pub budget_max_unique_names: u32,
    pub budget_max_dynamic_labels: u32,
}

impl Default for DnsCeiling {
    fn default() -> Self {
        Self {
            max_ttl_secs: 300,
            max_qname_octets: 253,
            max_labels: 40,
            max_label_octets: 63,
            allowed_record_types: vec!["A".to_owned(), "AAAA".to_owned()],
            max_response_records: 32,
            budget_window_secs: 60,
            budget_max_queries: 600,
            budget_max_query_octets: 32_768,
            budget_max_unique_names: 256,
            budget_max_dynamic_labels: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCeiling {
    /// Sessions must keep the MCP/syscall boundary enabled.
    #[serde(default = "default_true")]
    pub require_boundaries: bool,
    #[serde(default)]
    pub servers: BTreeMap<String, McpServerCeiling>,
}

impl Default for McpCeiling {
    fn default() -> Self {
        Self {
            require_boundaries: true,
            servers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportCeiling {
    Stdio,
    StreamableHttp,
    StreamableHttp2025,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerCeiling {
    pub transport: McpTransportCeiling,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub tools: ToolCeiling,
    #[serde(default)]
    pub allow_plaintext_local: bool,
    #[serde(default)]
    pub allow_private_networks: bool,
    #[serde(default)]
    pub allow_redirects: bool,
    #[serde(default)]
    pub redirect_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_secret: Option<String>,
    #[serde(default)]
    pub stdio_secrets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCeiling {
    pub default_action: CeilingAction,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for ToolCeiling {
    fn default() -> Self {
        Self {
            default_action: CeilingAction::Deny,
            allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PackageCeiling {
    pub allowed_registries: Vec<String>,
    pub allow_insecure_http: bool,
    pub registry_credentials: Vec<String>,
    pub require_supply_chain: bool,
    pub allow_finding_overrides: bool,
    pub allow_exceptions: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretCeiling {
    /// Host secret names that may be delivered into the guest environment.
    pub workload: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GitHubCeiling {
    pub forward_auth: bool,
    pub forward_copilot_auth: bool,
    pub allow_private_repository_access: bool,
    pub ssh_key: bool,
    pub require_branch_protection: bool,
    pub safe_outputs: SafeOutputsCeiling,
}

impl Default for GitHubCeiling {
    fn default() -> Self {
        Self {
            forward_auth: false,
            forward_copilot_auth: false,
            allow_private_repository_access: false,
            ssh_key: false,
            require_branch_protection: true,
            safe_outputs: SafeOutputsCeiling::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafeOutputsCeiling {
    pub enabled: bool,
    pub allow_apply: bool,
    /// Permitted `owner/repository` targets. Empty permits any target.
    pub repositories: Vec<String>,
}

/// Explicit denials appended to every governed session. They always narrow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Denials {
    pub commands: Vec<String>,
    pub domains: Vec<String>,
    pub networks: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialProvider {
    Anthropic,
    Openai,
}

/// How the broker attaches the provider credential to an upstream request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderInjection {
    Bearer,
    Header(&'static str),
}

impl CredentialProvider {
    #[must_use]
    pub const fn target_host(self) -> &'static str {
        match self {
            Self::Anthropic => "api.anthropic.com",
            Self::Openai => "api.openai.com",
        }
    }

    #[must_use]
    pub const fn injection(self) -> ProviderInjection {
        match self {
            Self::Anthropic => ProviderInjection::Header("x-api-key"),
            Self::Openai => ProviderInjection::Bearer,
        }
    }

    #[must_use]
    pub fn default_methods(self) -> Vec<String> {
        vec!["GET".to_owned(), "POST".to_owned()]
    }

    #[must_use]
    pub fn default_path_prefixes(self) -> Vec<String> {
        match self {
            Self::Anthropic => vec!["/v1/messages".to_owned(), "/v1/models".to_owned()],
            Self::Openai => vec![
                "/v1/responses".to_owned(),
                "/v1/chat/completions".to_owned(),
                "/v1/models".to_owned(),
            ],
        }
    }

    /// Path appended to the relay route in the agent's base URL. OpenAI SDKs
    /// expect the version segment in the base URL; Anthropic SDKs append it.
    #[must_use]
    pub const fn base_url_suffix(self) -> &'static str {
        match self {
            Self::Anthropic => "",
            Self::Openai => "/v1",
        }
    }

    /// Provider-standard variables that compatible agents read for an explicit
    /// API base URL and key.
    #[must_use]
    pub const fn base_url_environment(self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC_BASE_URL",
            Self::Openai => "OPENAI_BASE_URL",
        }
    }

    #[must_use]
    pub const fn api_key_environment(self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC_API_KEY",
            Self::Openai => "OPENAI_API_KEY",
        }
    }

    /// Request headers the relay forwards from the agent. Every other header,
    /// including any agent-supplied credential, is dropped.
    #[must_use]
    pub fn forwards_request_header(self, name: &str) -> bool {
        const COMMON: &[&str] = &[
            "accept",
            "accept-encoding",
            "accept-language",
            "content-type",
            "user-agent",
            "idempotency-key",
        ];
        let name = name.to_ascii_lowercase();
        if COMMON.contains(&name.as_str()) || name.starts_with("x-stainless-") {
            return true;
        }
        match self {
            Self::Anthropic => matches!(name.as_str(), "anthropic-version" | "anthropic-beta"),
            Self::Openai => matches!(name.as_str(), "openai-beta" | "originator" | "session_id"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialServiceProfile {
    pub id: ServiceId,
    pub provider: CredentialProvider,
    /// Host secret-store name holding the provider credential.
    pub secret: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: u64,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,
    #[serde(default = "default_max_duration_seconds")]
    pub max_duration_seconds: u64,
    #[serde(default = "default_idle_timeout_seconds")]
    pub idle_timeout_seconds: u64,
    /// Adds the provider host to every governed session's blocked domains so
    /// the workload cannot bypass the broker with its own credential.
    #[serde(default = "default_true")]
    pub deny_direct_egress: bool,
}

impl CredentialServiceProfile {
    #[must_use]
    pub fn effective_methods(&self) -> BTreeSet<String> {
        if self.methods.is_empty() {
            self.provider.default_methods().into_iter().collect()
        } else {
            self.methods.iter().cloned().collect()
        }
    }

    #[must_use]
    pub fn effective_path_prefixes(&self) -> Vec<String> {
        if self.path_prefixes.is_empty() {
            self.provider.default_path_prefixes()
        } else {
            self.path_prefixes.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GrantLimits {
    pub lease_seconds: u64,
    pub max_ttl_seconds: u64,
    pub revocation_grace_seconds: u64,
    pub max_concurrent_streams: u32,
}

impl Default for GrantLimits {
    fn default() -> Self {
        Self {
            lease_seconds: 300,
            max_ttl_seconds: 8 * 60 * 60,
            revocation_grace_seconds: 5,
            max_concurrent_streams: 8,
        }
    }
}

const fn default_true() -> bool {
    true
}

const fn default_max_request_bytes() -> u64 {
    8 * 1024 * 1024
}

const fn default_max_response_bytes() -> u64 {
    64 * 1024 * 1024
}

const fn default_max_duration_seconds() -> u64 {
    15 * 60
}

const fn default_idle_timeout_seconds() -> u64 {
    120
}

impl GovernanceProfile {
    /// Parses and structurally validates the exact signed profile bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, GovernanceError> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(GovernanceError::InvalidProfile(format!(
                "profile exceeds {MAX_PROFILE_BYTES} bytes"
            )));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| GovernanceError::InvalidProfile("profile is not UTF-8".to_owned()))?;
        let profile: Self = serde_yaml_ng::from_str(text)
            .map_err(|error| GovernanceError::InvalidProfile(error.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    #[must_use]
    pub fn reference(&self, signed_bytes: &[u8]) -> ProfileRef {
        ProfileRef {
            id: self.id.clone(),
            revision: self.revision,
            sha256: Sha256Digest::of(signed_bytes),
        }
    }

    /// Rejects a profile outside its validity window.
    pub fn check_validity(&self, now_unix: u64) -> Result<(), GovernanceError> {
        if now_unix < self.not_before_unix {
            return Err(GovernanceError::ProfileNotYetValid {
                id: self.id.to_string(),
                revision: self.revision,
            });
        }
        if now_unix >= self.expires_at_unix {
            return Err(GovernanceError::ProfileExpired {
                id: self.id.to_string(),
                revision: self.revision,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn credential_service(&self, id: &ServiceId) -> Option<&CredentialServiceProfile> {
        self.credential_services
            .iter()
            .find(|service| &service.id == id)
    }

    pub fn validate(&self) -> Result<(), GovernanceError> {
        let mut problems = Vec::new();
        let mut require = |ok: bool, message: String| {
            if !ok {
                problems.push(message);
            }
        };
        require(
            self.format == PROFILE_FORMAT,
            format!("format must be `{PROFILE_FORMAT}`"),
        );
        require(
            self.version == PROFILE_VERSION,
            format!("version must be {PROFILE_VERSION}"),
        );
        require(self.revision >= 1, "revision must be at least 1".to_owned());
        require(
            self.not_before_unix < self.expires_at_unix
                && self.expires_at_unix - self.not_before_unix <= MAX_PROFILE_VALIDITY_SECONDS,
            format!(
                "validity window must be non-empty and at most {MAX_PROFILE_VALIDITY_SECONDS} seconds"
            ),
        );
        if let Some(description) = &self.description {
            require(
                description.len() <= 1024 && !description.chars().any(char::is_control),
                "description must be at most 1024 bytes without control characters".to_owned(),
            );
        }
        self.ceiling.validate(&mut problems);
        validate_patterns(&self.denials.commands, "denials.commands", &mut problems);
        validate_domains(&self.denials.domains, "denials.domains", &mut problems);
        validate_patterns(&self.denials.networks, "denials.networks", &mut problems);
        self.validate_credential_services(&mut problems);
        self.grants.validate(&mut problems);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(GovernanceError::InvalidProfile(problems.join("; ")))
        }
    }

    fn validate_credential_services(&self, problems: &mut Vec<String>) {
        if self.credential_services.len() > MAX_CREDENTIAL_SERVICES {
            problems.push(format!(
                "at most {MAX_CREDENTIAL_SERVICES} credential services are supported"
            ));
        }
        let mut ids = BTreeSet::new();
        for service in &self.credential_services {
            let path = format!("credential_services[{}]", service.id);
            if !ids.insert(&service.id) {
                problems.push(format!("{path}: duplicate service id"));
            }
            if !valid_secret_name(&service.secret) {
                problems.push(format!(
                    "{path}.secret must be 1-{MAX_SECRET_NAME_BYTES} ASCII letters, digits, '_', '-' or '.'"
                ));
            }
            if self
                .ceiling
                .secrets
                .workload
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&service.secret))
            {
                problems.push(format!(
                    "{path}.secret must not also be a workload secret delivered to the guest"
                ));
            }
            let methods = service.effective_methods();
            if methods.len() != service.methods.len() && !service.methods.is_empty() {
                problems.push(format!("{path}.methods contains duplicates"));
            }
            for method in &methods {
                if let Err(error) = validate_method(method) {
                    problems.push(format!("{path}.methods: {error}"));
                }
            }
            let prefixes = service.effective_path_prefixes();
            if prefixes.len() > MAX_LIST_ENTRIES {
                problems.push(format!("{path}.path_prefixes has too many entries"));
            }
            for prefix in &prefixes {
                if let Err(error) = validate_path_prefix(prefix) {
                    problems.push(format!("{path}.path_prefixes: {error}"));
                }
            }
            if !(1..=HARD_MAX_REQUEST_BYTES).contains(&service.max_request_bytes) {
                problems.push(format!(
                    "{path}.max_request_bytes must be 1..={HARD_MAX_REQUEST_BYTES}"
                ));
            }
            if !(1..=HARD_MAX_RESPONSE_BYTES).contains(&service.max_response_bytes) {
                problems.push(format!(
                    "{path}.max_response_bytes must be 1..={HARD_MAX_RESPONSE_BYTES}"
                ));
            }
            if !(1..=HARD_MAX_STREAM_SECONDS).contains(&service.max_duration_seconds) {
                problems.push(format!(
                    "{path}.max_duration_seconds must be 1..={HARD_MAX_STREAM_SECONDS}"
                ));
            }
            if !(1..=HARD_MAX_IDLE_SECONDS).contains(&service.idle_timeout_seconds) {
                problems.push(format!(
                    "{path}.idle_timeout_seconds must be 1..={HARD_MAX_IDLE_SECONDS}"
                ));
            }
        }
    }
}

impl Ceiling {
    fn validate(&self, problems: &mut Vec<String>) {
        let runtimes = self.runtimes.iter().collect::<BTreeSet<_>>();
        if runtimes.is_empty() || runtimes.len() != self.runtimes.len() {
            problems
                .push("ceiling.runtimes must be a non-empty list without duplicates".to_owned());
        }
        bounded(&self.images, "ceiling.images", problems);
        for image in &self.images {
            let valid = image.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
            if !valid {
                problems.push(format!(
                    "ceiling.images entry `{image}` must be sha256:<64 lowercase hex>"
                ));
            }
        }
        bounded(&self.workspace_roots, "ceiling.workspace_roots", problems);
        for root in &self.workspace_roots {
            if !normalized_absolute_path(root) {
                problems.push(format!(
                    "ceiling.workspace_roots entry `{root}` must be an absolute, normalized path below `/`"
                ));
            }
        }
        if let Some(resources) = &self.resources {
            for (name, value) in [
                ("max_cpus", resources.max_cpus),
                ("max_memory_mb", resources.max_memory_mb),
                ("max_disk_mb", resources.max_disk_mb),
            ] {
                if value.is_some_and(|value| value <= 0) {
                    problems.push(format!("ceiling.resources.{name} must be positive"));
                }
            }
        }
        validate_patterns(
            &self.commands.allowlist,
            "ceiling.commands.allowlist",
            problems,
        );
        validate_domains(
            &self.network.allowed_domains,
            "ceiling.network.allowed_domains",
            problems,
        );
        validate_patterns(
            &self.network.allowed_networks,
            "ceiling.network.allowed_networks",
            problems,
        );
        bounded(
            &self.network.allowed_ports,
            "ceiling.network.allowed_ports",
            problems,
        );
        if self.network.allowed_ports.iter().any(|rule| rule.port == 0) {
            problems.push("ceiling.network.allowed_ports cannot contain port 0".to_owned());
        }
        if self.network.max_connections.is_some_and(|value| value <= 0) {
            problems.push("ceiling.network.max_connections must be positive".to_owned());
        }
        let dns = &self.network.dns;
        if dns.allowed_record_types.is_empty()
            || dns
                .allowed_record_types
                .iter()
                .any(|kind| kind != "A" && kind != "AAAA")
        {
            problems.push(
                "ceiling.network.dns.allowed_record_types must contain only A and AAAA".to_owned(),
            );
        }
        if dns.budget_window_secs == 0 {
            problems.push("ceiling.network.dns.budget_window_secs must be positive".to_owned());
        }
        if self.mcp.servers.len() > MAX_LIST_ENTRIES {
            problems.push("ceiling.mcp.servers has too many entries".to_owned());
        }
        for (id, server) in &self.mcp.servers {
            let path = format!("ceiling.mcp.servers.{id}");
            if id.is_empty()
                || id.len() > MAX_MCP_SERVER_ID_BYTES
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                problems.push(format!("{path}: invalid server id"));
            }
            match server.transport {
                McpTransportCeiling::Stdio => {
                    if server.command.is_empty() || server.url.is_some() {
                        problems.push(format!(
                            "{path}: stdio servers require `command` and forbid `url`"
                        ));
                    }
                }
                McpTransportCeiling::StreamableHttp | McpTransportCeiling::StreamableHttp2025 => {
                    if server.url.is_none() || !server.command.is_empty() {
                        problems.push(format!(
                            "{path}: HTTP servers require `url` and forbid `command`"
                        ));
                    }
                }
            }
            validate_patterns(&server.command, &format!("{path}.command"), problems);
            validate_patterns(
                &server.tools.allowlist,
                &format!("{path}.tools.allowlist"),
                problems,
            );
            validate_patterns(
                &server.redirect_allowlist,
                &format!("{path}.redirect_allowlist"),
                problems,
            );
            for secret in server.bearer_secret.iter().chain(&server.stdio_secrets) {
                if !valid_secret_name(secret) {
                    problems.push(format!("{path}: invalid secret name `{secret}`"));
                }
            }
        }
        validate_patterns(
            &self.packages.allowed_registries,
            "ceiling.packages.allowed_registries",
            problems,
        );
        for name in self
            .packages
            .registry_credentials
            .iter()
            .chain(&self.secrets.workload)
        {
            if !valid_secret_name(name) {
                problems.push(format!("ceiling: invalid secret name `{name}`"));
            }
        }
        bounded(
            &self.packages.registry_credentials,
            "ceiling.packages.registry_credentials",
            problems,
        );
        bounded(&self.secrets.workload, "ceiling.secrets.workload", problems);
        validate_patterns(
            &self.github.safe_outputs.repositories,
            "ceiling.github.safe_outputs.repositories",
            problems,
        );
        if self.github.safe_outputs.allow_apply && !self.github.safe_outputs.enabled {
            problems.push(
                "ceiling.github.safe_outputs.allow_apply requires safe_outputs.enabled".to_owned(),
            );
        }
    }
}

impl GrantLimits {
    fn validate(&self, problems: &mut Vec<String>) {
        if !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&self.lease_seconds) {
            problems.push(format!(
                "grants.lease_seconds must be {MIN_LEASE_SECONDS}..={MAX_LEASE_SECONDS}"
            ));
        }
        if self.max_ttl_seconds < self.lease_seconds || self.max_ttl_seconds > MAX_GRANT_TTL_SECONDS
        {
            problems.push(format!(
                "grants.max_ttl_seconds must be between lease_seconds and {MAX_GRANT_TTL_SECONDS}"
            ));
        }
        if self.revocation_grace_seconds > MAX_REVOCATION_GRACE_SECONDS {
            problems.push(format!(
                "grants.revocation_grace_seconds must be at most {MAX_REVOCATION_GRACE_SECONDS}"
            ));
        }
        if !(1..=MAX_CONCURRENT_STREAMS).contains(&self.max_concurrent_streams) {
            problems.push(format!(
                "grants.max_concurrent_streams must be 1..={MAX_CONCURRENT_STREAMS}"
            ));
        }
    }
}

fn bounded<T>(values: &[T], path: &str, problems: &mut Vec<String>) {
    if values.len() > MAX_LIST_ENTRIES {
        problems.push(format!("{path} has more than {MAX_LIST_ENTRIES} entries"));
    }
}

fn validate_patterns(values: &[String], path: &str, problems: &mut Vec<String>) {
    bounded(values, path, problems);
    let mut unique = BTreeSet::new();
    for value in values {
        if value.trim().is_empty()
            || value.len() > MAX_PATTERN_BYTES
            || value.chars().any(char::is_control)
        {
            problems.push(format!(
                "{path} entries must be non-empty, bounded, and free of control characters"
            ));
        } else if !unique.insert(value) {
            problems.push(format!("{path} contains duplicate `{value}`"));
        }
    }
}

fn validate_domains(values: &[String], path: &str, problems: &mut Vec<String>) {
    validate_patterns(values, path, problems);
    for value in values {
        if value.len() > MAX_DOMAIN_BYTES || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            problems.push(format!("{path} entry `{value}` is not a domain pattern"));
        }
    }
}

#[must_use]
pub fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SECRET_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn normalized_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() > 1
        && !value.ends_with('/')
        && !value.chars().any(char::is_control)
        && value[1..]
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const MINIMAL: &str = r#"
format: sendbox.governance-profile
version: 1
id: acme-default
revision: 3
not_before_unix: 1000
expires_at_unix: 2000
ceiling:
  runtimes: [apple, kata]
  commands:
    default_action: deny
    allowlist: ["/usr/bin/git *"]
  network:
    default_action: deny
    allowed_domains: ["*.github.com"]
credential_services:
  - id: anthropic
    provider: anthropic
    secret: SENDBOX_ANTHROPIC_API_KEY
"#;

    #[test]
    fn minimal_profile_parses_with_conservative_defaults() {
        let profile = GovernanceProfile::parse(MINIMAL.as_bytes()).expect("profile");
        assert!(profile.ceiling.mcp.require_boundaries);
        assert!(profile.ceiling.github.require_branch_protection);
        assert!(!profile.ceiling.github.forward_auth);
        assert!(!profile.ceiling.network.github_meta);
        let service = &profile.credential_services[0];
        assert!(service.deny_direct_egress);
        assert_eq!(
            service.effective_path_prefixes(),
            vec!["/v1/messages", "/v1/models"]
        );
        let reference = profile.reference(MINIMAL.as_bytes());
        assert_eq!(reference.revision, 3);
        assert_eq!(reference.sha256, Sha256Digest::of(MINIMAL.as_bytes()));
    }

    #[test]
    fn validity_window_is_enforced() {
        let profile = GovernanceProfile::parse(MINIMAL.as_bytes()).expect("profile");
        assert!(matches!(
            profile.check_validity(999),
            Err(GovernanceError::ProfileNotYetValid { .. })
        ));
        assert!(profile.check_validity(1000).is_ok());
        assert!(matches!(
            profile.check_validity(2000),
            Err(GovernanceError::ProfileExpired { .. })
        ));
    }

    #[test]
    fn invalid_profiles_are_rejected_with_reasons() {
        for (needle, replacement, reason) in [
            ("version: 1", "version: 2", "version"),
            ("revision: 3", "revision: 0", "revision"),
            ("runtimes: [apple, kata]", "runtimes: []", "runtimes"),
            (
                "secret: SENDBOX_ANTHROPIC_API_KEY",
                "secret: \"bad name\"",
                "secret",
            ),
            ("expires_at_unix: 2000", "expires_at_unix: 1000", "validity"),
        ] {
            let text = MINIMAL.replace(needle, replacement);
            let error = GovernanceProfile::parse(text.as_bytes()).expect_err(reason);
            assert!(error.to_string().contains(reason), "{reason}: {error}");
        }
        let unknown = format!("{MINIMAL}unexpected: true\n");
        assert!(GovernanceProfile::parse(unknown.as_bytes()).is_err());
    }

    #[test]
    fn brokered_secret_cannot_also_be_a_workload_secret() {
        let text = MINIMAL.replace(
            "  network:",
            "  secrets:\n    workload: [SENDBOX_ANTHROPIC_API_KEY]\n  network:",
        );
        let error = GovernanceProfile::parse(text.as_bytes()).expect_err("overlap");
        assert!(error.to_string().contains("workload secret"));
    }

    #[test]
    fn provider_header_allowlist_drops_credentials() {
        let provider = CredentialProvider::Anthropic;
        assert!(provider.forwards_request_header("Anthropic-Version"));
        assert!(provider.forwards_request_header("x-stainless-lang"));
        assert!(!provider.forwards_request_header("x-api-key"));
        assert!(!provider.forwards_request_header("authorization"));
        assert!(!CredentialProvider::Openai.forwards_request_header("Authorization"));
        assert!(!CredentialProvider::Openai.forwards_request_header("cookie"));
    }
}
