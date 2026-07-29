#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Component, Path};

use sendbox_core::{Diagnostic, DiagnosticCode, ValidationFailure};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

pub const DEFAULT_MCP_HTTP_GATEWAY_PORT: u16 = 15_082;

const BPFTRACE_STRING_LENGTH: usize = 4096;
const MAX_SERVER_COMMAND_PARTS: usize = 16;
const MAX_MCP_SERVERS: usize = 64;
const MAX_MCP_SERVER_ID_BYTES: usize = 64;
const MAX_HTTP_BODY_BYTES: i64 = 16 * 1024 * 1024;
const MAX_HTTP_TIMEOUT_SECONDS: u64 = 300;
const MAX_HTTP_EVENTS: u32 = 65_536;
const MAX_HTTP_CONCURRENT_REQUESTS: u32 = 1024;
const MAX_HTTP_SESSIONS: u32 = 4096;
const MAX_HTTP_SESSION_SECONDS: u64 = 24 * 60 * 60;
const MAX_TLS_ROOT_BYTES: usize = 1024 * 1024;
const FORBIDDEN_MCP_EXECUTABLES: [&str; 12] = [
    "sh", "bash", "zsh", "fish", "env", "npx", "npm", "pnpm", "yarn", "bunx", "pipx", "uvx",
];
pub const MAX_PACKAGE_REGISTRIES: usize = 16;
pub const MAX_PACKAGE_FINDING_RULES: usize = 64;
pub const MAX_PACKAGE_EXCEPTIONS: usize = 128;
pub const MAX_PACKAGE_REPORT_BYTES: u64 = 96 * 1024;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<i64>,
    /// Exact IP or CIDR literals (v4 or v6) that are always permitted, e.g.
    /// `"93.184.216.34/32"` or `"2001:db8::/32"`. An explicit network grant
    /// is the only mechanism that can authorize a restricted address class
    /// (loopback, link-local, RFC 1918, ULA, cloud metadata). Optional; an
    /// omitted key parses as an empty list so pre-existing policy documents
    /// remain valid.
    #[serde(default)]
    pub allowed_networks: Vec<String>,
    /// Exact IP or CIDR literals (v4 or v6) that are always denied. A blocked
    /// network takes precedence over every allow rule. Optional (see
    /// [`NetworkPolicy::allowed_networks`]).
    #[serde(default)]
    pub blocked_networks: Vec<String>,
    /// Permitted destination `port`/`protocol` pairs. An empty list (the
    /// default) imposes no port constraint; a non-empty list restricts egress
    /// to exactly the listed pairs. Optional.
    #[serde(default)]
    pub allowed_ports: Vec<PortRule>,
    /// DNS broker controls: TTL caps, structural query-name limits, a QTYPE
    /// allowlist, response-size limits, and deterministic query-exfiltration
    /// budgets. Optional; an omitted `dns:` key parses as
    /// [`DnsPolicy::default`].
    #[serde(default)]
    pub dns: DnsPolicy,
}

/// Transport protocol for a [`PortRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A single permitted destination port bound to a transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRule {
    pub protocol: Protocol,
    pub port: u16,
}

/// DNS query record types the broker is permitted to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
}

/// Deterministic, bounded per-window DNS query-exfiltration budgets.
///
/// Every counter resets on a fixed, monotonic window boundary. State is
/// bounded by construction: the unique-name and dynamic-label sets never grow
/// beyond their configured maxima, because reaching a maximum with a new
/// distinct entry is itself a budget denial rather than an unbounded insert.
/// A single budget governs the whole sandbox agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsQueryBudget {
    /// Length of one fixed budget window, in seconds.
    pub window_secs: u32,
    /// Maximum number of queries admitted per window.
    pub max_queries: u32,
    /// Maximum total QNAME octets (summed across admitted queries) per window.
    pub max_query_octets: u64,
    /// Maximum number of distinct normalized QNAMEs per window.
    pub max_unique_names: u32,
    /// Maximum number of distinct leftmost ("dynamic") labels per window.
    /// Data exfiltrated through DNS tunneling is typically encoded in the
    /// leftmost label, so bounding the distinct-label count deterministically
    /// caps exfiltration bandwidth without any entropy heuristic.
    pub max_dynamic_labels: u32,
}

impl Default for DnsQueryBudget {
    fn default() -> Self {
        Self {
            window_secs: 60,
            max_queries: 600,
            max_query_octets: 32_768,
            max_unique_names: 256,
            max_dynamic_labels: 256,
        }
    }
}

/// DNS broker policy: TTL caps, structural query-name limits, a QTYPE
/// allowlist, response-size limits, and the deterministic query budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsPolicy {
    /// Upper bound applied to every DNS TTL before it is used to compute an
    /// authorization expiry.
    pub max_ttl_secs: u32,
    /// Maximum total normalized QNAME length in octets (RFC 1035 caps this at
    /// 253).
    pub max_qname_octets: u32,
    /// Maximum number of labels in a QNAME.
    pub max_labels: u32,
    /// Maximum octets in any single label (RFC 1035 caps this at 63).
    pub max_label_octets: u32,
    /// QTYPEs the broker is permitted to answer. A query for any other type
    /// is refused as unsupported.
    pub allowed_record_types: Vec<DnsRecordType>,
    /// Maximum number of address records returned in a single response.
    pub max_response_records: u32,
    /// Deterministic per-window query-exfiltration budget.
    pub budget: DnsQueryBudget,
}

impl Default for DnsPolicy {
    fn default() -> Self {
        Self {
            max_ttl_secs: 300,
            max_qname_octets: 253,
            max_labels: 40,
            max_label_octets: 63,
            allowed_record_types: vec![DnsRecordType::A, DnsRecordType::Aaaa],
            max_response_records: 32,
            budget: DnsQueryBudget::default(),
        }
    }
}

impl DnsPolicy {
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        let mut require = |ok: bool, field: &str, message: &str| {
            if !ok {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    field,
                    message,
                ));
            }
        };
        require(
            self.max_ttl_secs > 0,
            "policy.network.dns.max_ttl_secs",
            "must be greater than zero",
        );
        require(
            self.max_qname_octets >= 1 && self.max_qname_octets <= 253,
            "policy.network.dns.max_qname_octets",
            "must be between 1 and 253 (RFC 1035)",
        );
        require(
            self.max_labels >= 1,
            "policy.network.dns.max_labels",
            "must be greater than zero",
        );
        require(
            self.max_label_octets >= 1 && self.max_label_octets <= 63,
            "policy.network.dns.max_label_octets",
            "must be between 1 and 63 (RFC 1035)",
        );
        require(
            self.max_response_records >= 1,
            "policy.network.dns.max_response_records",
            "must be greater than zero",
        );
        require(
            !self.allowed_record_types.is_empty(),
            "policy.network.dns.allowed_record_types",
            "must list at least one record type",
        );
        require(
            self.budget.window_secs > 0,
            "policy.network.dns.budget.window_secs",
            "must be greater than zero",
        );
        require(
            self.budget.max_queries >= 1,
            "policy.network.dns.budget.max_queries",
            "must be greater than zero",
        );
        require(
            self.budget.max_query_octets >= 1,
            "policy.network.dns.budget.max_query_octets",
            "must be greater than zero",
        );
        require(
            self.budget.max_unique_names >= 1,
            "policy.network.dns.budget.max_unique_names",
            "must be greater than zero",
        );
        require(
            self.budget.max_dynamic_labels >= 1,
            "policy.network.dns.budget.max_dynamic_labels",
            "must be greater than zero",
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolTransport {
    Stdio,
    StreamableHttp,
    StreamableHttp2025,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerToolPolicy {
    pub default_action: Action,
    pub allowlist: Vec<String>,
    pub denylist: Vec<String>,
}

impl Default for ServerToolPolicy {
    fn default() -> Self {
        Self {
            default_action: Action::Deny,
            allowlist: Vec::new(),
            denylist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct McpTlsPolicy {
    pub trust_roots_pem: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpAuthorizationPolicy {
    pub bearer_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpHttpOrigin {
    pub host: String,
    pub port: u16,
}

impl McpHttpOrigin {
    pub fn from_endpoint(value: &str) -> Result<Self, String> {
        let normalized = normalize_mcp_http_endpoint(value)?;
        let parsed = Url::parse(&normalized)
            .map_err(|error| format!("invalid MCP endpoint URL: {error}"))?;
        let host = match parsed.host() {
            Some(Host::Domain(domain)) => domain.to_ascii_lowercase(),
            Some(Host::Ipv4(address)) => address.to_string(),
            Some(Host::Ipv6(address)) => address.to_string(),
            None => return Err("MCP endpoint URL must contain a host".to_owned()),
        };
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| "MCP endpoint URL must have a known port".to_owned())?;
        Ok(Self { host, port })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpHttpPolicy {
    pub allow_plaintext_local: bool,
    pub allow_private_networks: bool,
    pub allow_redirects: bool,
    pub redirect_allowlist: Vec<String>,
    pub max_redirects: u32,
    pub max_request_bytes: i64,
    pub max_response_bytes: i64,
    pub request_timeout_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_events: u32,
    pub max_concurrent_requests: u32,
    pub max_sessions: u32,
    pub session_ttl_seconds: u64,
    pub tls: McpTlsPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<HttpAuthorizationPolicy>,
}

impl Default for McpHttpPolicy {
    fn default() -> Self {
        Self {
            allow_plaintext_local: false,
            allow_private_networks: false,
            allow_redirects: false,
            redirect_allowlist: Vec::new(),
            max_redirects: 3,
            max_request_bytes: 1_048_576,
            max_response_bytes: 1_048_576,
            request_timeout_seconds: 30,
            connect_timeout_seconds: 10,
            idle_timeout_seconds: 30,
            max_events: 1024,
            max_concurrent_requests: 32,
            max_sessions: 128,
            session_ttl_seconds: 3600,
            tls: McpTlsPolicy::default(),
            authorization: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpServerPolicy {
    Stdio {
        command: Vec<String>,
        #[serde(default)]
        tools: ServerToolPolicy,
    },
    StreamableHttp {
        url: String,
        #[serde(default)]
        tools: ServerToolPolicy,
        #[serde(default)]
        http: McpHttpPolicy,
    },
    StreamableHttp2025 {
        url: String,
        #[serde(default)]
        tools: ServerToolPolicy,
        #[serde(default)]
        http: McpHttpPolicy,
    },
}

impl McpServerPolicy {
    #[must_use]
    pub const fn transport(&self) -> ToolTransport {
        match self {
            Self::Stdio { .. } => ToolTransport::Stdio,
            Self::StreamableHttp { .. } => ToolTransport::StreamableHttp,
            Self::StreamableHttp2025 { .. } => ToolTransport::StreamableHttp2025,
        }
    }

    #[must_use]
    pub const fn tools(&self) -> &ServerToolPolicy {
        match self {
            Self::Stdio { tools, .. }
            | Self::StreamableHttp { tools, .. }
            | Self::StreamableHttp2025 { tools, .. } => tools,
        }
    }

    #[must_use]
    pub fn command(&self) -> Option<&[String]> {
        match self {
            Self::Stdio { command, .. } => Some(command),
            Self::StreamableHttp { .. } | Self::StreamableHttp2025 { .. } => None,
        }
    }

    #[must_use]
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::Stdio { .. } => None,
            Self::StreamableHttp { url, .. } | Self::StreamableHttp2025 { url, .. } => Some(url),
        }
    }

    #[must_use]
    pub const fn http(&self) -> Option<&McpHttpPolicy> {
        match self {
            Self::Stdio { .. } => None,
            Self::StreamableHttp { http, .. } | Self::StreamableHttp2025 { http, .. } => Some(http),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolCallPolicy {
    /// Deprecated flat stdio compatibility mode. New configurations should use
    /// [`ToolCallPolicy::servers`].
    pub transport: ToolTransport,
    pub default_action: Action,
    pub allowlist: Vec<String>,
    pub denylist: Vec<String>,
    pub max_frame_bytes: i64,
    pub server_command_patterns: Vec<String>,
    pub allowed_server_commands: Vec<Vec<String>>,
    #[serde(deserialize_with = "deserialize_unique_servers")]
    pub servers: BTreeMap<String, McpServerPolicy>,
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
            servers: BTreeMap::new(),
        }
    }
}

impl ToolCallPolicy {
    #[must_use]
    pub fn uses_hierarchical_servers(&self) -> bool {
        !self.servers.is_empty()
    }

    #[must_use]
    pub fn uses_legacy_fields(&self) -> bool {
        self.transport != ToolTransport::Stdio
            || self.default_action != Action::Deny
            || !self.allowlist.is_empty()
            || !self.denylist.is_empty()
            || !self.allowed_server_commands.is_empty()
    }

    #[must_use]
    pub fn has_remote_servers(&self) -> bool {
        self.servers
            .values()
            .any(|server| server.transport() != ToolTransport::Stdio)
    }

    #[must_use]
    pub fn gateway_secret_names(&self) -> BTreeSet<String> {
        self.servers
            .values()
            .filter_map(McpServerPolicy::http)
            .filter_map(|http| http.authorization.as_ref())
            .map(|authorization| authorization.bearer_secret.clone())
            .collect()
    }

    pub fn remote_origins(&self) -> Result<BTreeSet<McpHttpOrigin>, String> {
        let mut origins = BTreeSet::new();
        for server in self.servers.values() {
            let Some(url) = server.url() else {
                continue;
            };
            origins.insert(McpHttpOrigin::from_endpoint(url)?);
            if let Some(http) = server.http() {
                for redirect in &http.redirect_allowlist {
                    origins.insert(McpHttpOrigin::from_endpoint(redirect)?);
                }
            }
        }
        Ok(origins)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageEcosystem {
    Npm,
    Pypi,
    Cargo,
    GoModules,
    Maven,
    Oci,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageAction {
    Allow,
    Deny,
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageFindingKind {
    LifecycleScript,
    ArchiveTraversal,
    AbsoluteArchivePath,
    UnsafeSymlink,
    UnsafeHardlink,
    DeviceEntry,
    FifoEntry,
    SparseEntry,
    UnsupportedArchiveEntry,
    DecompressionLimit,
    OversizedEntry,
    UnexpectedExecutable,
    NativeAddon,
    PrebuiltBinary,
    EmbeddedExecutable,
    SubprocessApi,
    ShellApi,
    IntegrityFailure,
    IdentityMismatch,
    SignatureFailure,
    ProvenanceFailure,
    UnsupportedContent,
    ScannerFailure,
    Timeout,
}

impl PackageFindingKind {
    #[must_use]
    pub const fn is_fail_closed(self) -> bool {
        matches!(
            self,
            Self::DecompressionLimit
                | Self::OversizedEntry
                | Self::IntegrityFailure
                | Self::IdentityMismatch
                | Self::SignatureFailure
                | Self::ProvenanceFailure
                | Self::UnsupportedContent
                | Self::ScannerFailure
                | Self::Timeout
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRequirement {
    IfPresent,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PackageRegistryPolicy {
    pub ecosystem: PackageEcosystem,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_secret: Option<String>,
    pub allow_insecure_http: bool,
    pub signature: EvidenceRequirement,
    pub provenance: EvidenceRequirement,
}

impl Default for PackageRegistryPolicy {
    fn default() -> Self {
        Self {
            ecosystem: PackageEcosystem::Npm,
            url: "https://registry.npmjs.org/".to_owned(),
            credential_secret: None,
            allow_insecure_http: false,
            signature: EvidenceRequirement::IfPresent,
            provenance: EvidenceRequirement::IfPresent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFindingPolicy {
    pub finding: PackageFindingKind,
    pub action: PackageAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageExceptionRule {
    pub ecosystem: PackageEcosystem,
    pub package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub artifact_digest: String,
    pub findings: Vec<PackageFindingKind>,
    pub action: PackageAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PackageAnalysisLimits {
    pub max_metadata_bytes: u64,
    pub max_download_bytes: u64,
    pub max_unpacked_bytes: u64,
    pub max_entry_bytes: u64,
    pub max_entries: u32,
    pub max_path_bytes: u32,
    pub max_depth: u32,
    pub max_source_scan_bytes: u64,
    pub request_timeout_secs: u32,
    pub scan_timeout_secs: u32,
    pub max_report_findings: u32,
    pub max_report_bytes: u64,
}

impl Default for PackageAnalysisLimits {
    fn default() -> Self {
        Self {
            max_metadata_bytes: 16 * 1024 * 1024,
            max_download_bytes: 256 * 1024 * 1024,
            max_unpacked_bytes: 1024 * 1024 * 1024,
            max_entry_bytes: 64 * 1024 * 1024,
            max_entries: 100_000,
            max_path_bytes: 4096,
            max_depth: 64,
            max_source_scan_bytes: 8 * 1024 * 1024,
            request_timeout_secs: 120,
            scan_timeout_secs: 30,
            max_report_findings: 4096,
            max_report_bytes: MAX_PACKAGE_REPORT_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PackageCachePolicy {
    pub enabled: bool,
    pub max_bytes: u64,
    pub max_entries: u32,
    pub retain_quarantined: bool,
}

impl Default for PackageCachePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_bytes: 4 * 1024 * 1024 * 1024,
            max_entries: 100_000,
            retain_quarantined: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PackageSupplyChainPolicy {
    pub enabled: bool,
    pub registries: Vec<PackageRegistryPolicy>,
    pub default_finding_action: PackageAction,
    pub finding_actions: Vec<PackageFindingPolicy>,
    pub exceptions: Vec<PackageExceptionRule>,
    pub allow_legacy_sha1: bool,
    pub limits: PackageAnalysisLimits,
    pub cache: PackageCachePolicy,
}

impl Default for PackageSupplyChainPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            registries: Vec::new(),
            default_finding_action: PackageAction::Deny,
            finding_actions: Vec::new(),
            exceptions: Vec::new(),
            allow_legacy_sha1: true,
            limits: PackageAnalysisLimits::default(),
            cache: PackageCachePolicy::default(),
        }
    }
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
    #[serde(default)]
    pub packages: PackageSupplyChainPolicy,
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

        validate_nonempty_patterns(
            &self.network.allowed_networks,
            "policy.network.allowed_networks",
            &mut diagnostics,
        );
        validate_nonempty_patterns(
            &self.network.blocked_networks,
            "policy.network.blocked_networks",
            &mut diagnostics,
        );
        self.network.dns.validate(&mut diagnostics);

        self.boundaries.validate(&mut diagnostics);
        self.packages.validate_into(&mut diagnostics);

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
        self.tool_calls.validate(diagnostics);
        let log_path = Path::new(&self.log_path);
        if !log_path.is_absolute()
            || log_path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || log_path.parent() != Some(Path::new("/var/log/sendbox"))
        {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidPath,
                "policy.boundaries.log_path",
                "must be a normalized direct child of /var/log/sendbox",
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
    }
}

impl ToolCallPolicy {
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        if self.max_frame_bytes <= 0 {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                "policy.boundaries.tool_calls.max_frame_bytes",
                "must be greater than zero",
            ));
        } else if self.max_frame_bytes > MAX_HTTP_BODY_BYTES {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                "policy.boundaries.tool_calls.max_frame_bytes",
                format!("must be at most {MAX_HTTP_BODY_BYTES}"),
            ));
        }
        let patterns = if self.server_command_patterns.is_empty() {
            default_server_command_patterns()
        } else {
            self.server_command_patterns.clone()
        };
        for pattern in &patterns {
            if pattern.trim().is_empty()
                || pattern.len() >= BPFTRACE_STRING_LENGTH
                || pattern.chars().any(char::is_control)
            {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    "policy.boundaries.tool_calls.server_command_patterns",
                    "entries must be printable and between 1 and 4095 UTF-8 bytes",
                ));
            }
        }

        validate_tool_rules(
            self.default_action,
            &self.allowlist,
            &self.denylist,
            "policy.boundaries.tool_calls",
            !self.allowed_server_commands.is_empty(),
            diagnostics,
        );

        if self.uses_hierarchical_servers() && self.uses_legacy_fields() {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                "policy.boundaries.tool_calls",
                "hierarchical servers cannot be combined with legacy transport, allowlist, denylist, default_action, or allowed_server_commands fields",
            ));
        }
        if self.servers.len() > MAX_MCP_SERVERS {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                "policy.boundaries.tool_calls.servers",
                format!("may contain at most {MAX_MCP_SERVERS} servers"),
            ));
        }

        for (index, command) in self.allowed_server_commands.iter().enumerate() {
            let path = format!("policy.boundaries.tool_calls.allowed_server_commands[{index}]");
            validate_mcp_command(command, &path, Some(&patterns), diagnostics);
        }

        let mut commands = BTreeMap::<Vec<String>, String>::new();
        let mut endpoints = BTreeMap::<String, String>::new();
        for (id, server) in &self.servers {
            let base = format!("policy.boundaries.tool_calls.servers.{id}");
            if !valid_server_id(id) {
                diagnostics.push(Diagnostic::new(
                    DiagnosticCode::InvalidValue,
                    base.clone(),
                    "server ID must match [a-z][a-z0-9_-]{0,63}",
                ));
            }
            validate_tool_rules(
                server.tools().default_action,
                &server.tools().allowlist,
                &server.tools().denylist,
                &format!("{base}.tools"),
                true,
                diagnostics,
            );
            match server {
                McpServerPolicy::Stdio { command, .. } => {
                    let path = format!("{base}.command");
                    validate_mcp_command(command, &path, None, diagnostics);
                    if let Some(existing) = commands.insert(command.clone(), id.clone()) {
                        diagnostics.push(Diagnostic::new(
                            DiagnosticCode::InvalidValue,
                            path,
                            format!("command is already mapped to server policy '{existing}'"),
                        ));
                    }
                }
                McpServerPolicy::StreamableHttp { url, http, .. }
                | McpServerPolicy::StreamableHttp2025 { url, http, .. } => {
                    let path = format!("{base}.url");
                    if let Some(normalized) = validate_http_endpoint(url, http, &path, diagnostics)
                        && let Some(existing) = endpoints.insert(normalized, id.clone())
                    {
                        diagnostics.push(Diagnostic::new(
                            DiagnosticCode::InvalidValue,
                            path,
                            format!("endpoint is already mapped to server policy '{existing}'"),
                        ));
                    }
                    validate_http_policy(http, &format!("{base}.http"), diagnostics);
                }
            }
        }
    }
}

fn deserialize_unique_servers<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, McpServerPolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueServersVisitor;

    impl<'de> serde::de::Visitor<'de> for UniqueServersVisitor {
        type Value = BTreeMap<String, McpServerPolicy>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map of uniquely named MCP server policies")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut servers = BTreeMap::new();
            while let Some((id, policy)) = map.next_entry::<String, McpServerPolicy>()? {
                if servers.insert(id.clone(), policy).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate MCP server policy ID '{id}'"
                    )));
                }
            }
            Ok(servers)
        }
    }

    deserializer.deserialize_map(UniqueServersVisitor)
}

fn valid_server_id(value: &str) -> bool {
    value.len() <= MAX_MCP_SERVER_ID_BYTES
        && matches!(value.as_bytes().first(), Some(byte) if byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn validate_mcp_command(
    command: &[String],
    path: &str,
    required_patterns: Option<&[String]>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(executable) = command.first() else {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            path,
            "must contain an executable",
        ));
        return;
    };
    let basename = Path::new(executable)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !Path::new(executable).is_absolute()
        || FORBIDDEN_MCP_EXECUTABLES.contains(&basename.as_str())
    {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidPath,
            path,
            "executable must be an absolute non-shell, non-package-runner path",
        ));
    }
    if command.len() > MAX_SERVER_COMMAND_PARTS {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            path,
            "may contain at most 16 command parts",
        ));
    }
    if command.iter().any(|part| {
        part.is_empty()
            || part.len() >= BPFTRACE_STRING_LENGTH
            || part.as_bytes().contains(&0)
            || part.chars().any(char::is_control)
    }) {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            path,
            "each command part must be printable and between 1 and 4095 UTF-8 bytes",
        ));
    }
    if required_patterns.is_some_and(|patterns| {
        !command
            .iter()
            .skip(1)
            .any(|argument| patterns.iter().any(|pattern| argument.contains(pattern)))
    }) {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            path,
            "an argument must match a configured server_command_patterns entry",
        ));
    }
}

fn validate_tool_rules(
    default_action: Action,
    allowlist: &[String],
    denylist: &[String],
    path: &str,
    active: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_glob_patterns(allowlist, &format!("{path}.allowlist"), diagnostics);
    validate_glob_patterns(denylist, &format!("{path}.denylist"), diagnostics);
    if active && default_action == Action::Allow && allowlist.is_empty() && denylist.is_empty() {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            path,
            "an active allow-by-default tool policy must contain at least one explicit rule",
        ));
    }
}

fn validate_glob_patterns(values: &[String], path: &str, diagnostics: &mut Vec<Diagnostic>) {
    let mut unique = BTreeSet::new();
    for value in values {
        if value.trim().is_empty()
            || value.len() >= BPFTRACE_STRING_LENGTH
            || value.chars().any(char::is_control)
        {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                path,
                "entries must be printable and between 1 and 4095 UTF-8 bytes",
            ));
        }
        if !unique.insert(value) {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                path,
                format!("duplicate pattern '{value}'"),
            ));
        }
    }
}

fn validate_http_policy(policy: &McpHttpPolicy, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    for (field, value) in [
        ("max_request_bytes", policy.max_request_bytes),
        ("max_response_bytes", policy.max_response_bytes),
    ] {
        if !(1..=MAX_HTTP_BODY_BYTES).contains(&value) {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                format!("{path}.{field}"),
                format!("must be between 1 and {MAX_HTTP_BODY_BYTES}"),
            ));
        }
    }
    for (field, value) in [
        ("request_timeout_seconds", policy.request_timeout_seconds),
        ("connect_timeout_seconds", policy.connect_timeout_seconds),
        ("idle_timeout_seconds", policy.idle_timeout_seconds),
    ] {
        if !(1..=MAX_HTTP_TIMEOUT_SECONDS).contains(&value) {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                format!("{path}.{field}"),
                format!("must be between 1 and {MAX_HTTP_TIMEOUT_SECONDS}"),
            ));
        }
    }
    for (field, value, maximum) in [
        ("max_redirects", policy.max_redirects, 10),
        ("max_events", policy.max_events, MAX_HTTP_EVENTS),
        (
            "max_concurrent_requests",
            policy.max_concurrent_requests,
            MAX_HTTP_CONCURRENT_REQUESTS,
        ),
        ("max_sessions", policy.max_sessions, MAX_HTTP_SESSIONS),
    ] {
        if value == 0 || value > maximum {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                format!("{path}.{field}"),
                format!("must be between 1 and {maximum}"),
            ));
        }
    }
    if policy.session_ttl_seconds == 0 || policy.session_ttl_seconds > MAX_HTTP_SESSION_SECONDS {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            format!("{path}.session_ttl_seconds"),
            format!("must be between 1 and {MAX_HTTP_SESSION_SECONDS}"),
        ));
    }
    if !policy.allow_redirects && !policy.redirect_allowlist.is_empty() {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            format!("{path}.redirect_allowlist"),
            "redirect targets require allow_redirects: true",
        ));
    }
    if !policy.allow_redirects && policy.max_redirects != McpHttpPolicy::default().max_redirects {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            format!("{path}.max_redirects"),
            "custom redirect limits require allow_redirects: true",
        ));
    }
    if policy.allow_redirects && policy.redirect_allowlist.is_empty() {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            format!("{path}.redirect_allowlist"),
            "enabled redirects require at least one exact target",
        ));
    }
    let mut redirects = BTreeSet::new();
    for (index, value) in policy.redirect_allowlist.iter().enumerate() {
        let redirect_path = format!("{path}.redirect_allowlist[{index}]");
        if let Some(normalized) = validate_http_endpoint(value, policy, &redirect_path, diagnostics)
            && !redirects.insert(normalized)
        {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                redirect_path,
                "duplicate normalized redirect target",
            ));
        }
    }
    let root_bytes = policy
        .tls
        .trust_roots_pem
        .iter()
        .map(String::len)
        .sum::<usize>();
    if root_bytes > MAX_TLS_ROOT_BYTES
        || policy
            .tls
            .trust_roots_pem
            .iter()
            .any(|root| root.trim().is_empty())
    {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            format!("{path}.tls.trust_roots_pem"),
            format!("roots must be non-empty and total at most {MAX_TLS_ROOT_BYTES} bytes"),
        ));
    }
    if let Some(authorization) = &policy.authorization
        && (authorization.bearer_secret.trim().is_empty()
            || authorization.bearer_secret.len() > 128
            || authorization.bearer_secret.chars().any(char::is_control))
    {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            format!("{path}.authorization.bearer_secret"),
            "secret name must be printable and between 1 and 128 UTF-8 bytes",
        ));
    }
}

fn validate_http_endpoint(
    value: &str,
    policy: &McpHttpPolicy,
    path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<String> {
    let parsed = match Url::parse(value) {
        Ok(parsed) => parsed,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::InvalidValue,
                path,
                format!("invalid MCP endpoint URL: {error}"),
            ));
            return None;
        }
    };
    let normalized = match normalize_parsed_http_endpoint(&parsed) {
        Ok(normalized) => normalized,
        Err(message) => {
            diagnostics.push(Diagnostic::new(DiagnosticCode::InvalidValue, path, message));
            return None;
        }
    };
    let local = endpoint_is_local(&parsed);
    match parsed.scheme() {
        "https" => {}
        "http" if policy.allow_plaintext_local && local => {}
        "http" => diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            path,
            "remote MCP endpoints require HTTPS; plaintext HTTP is limited to explicitly enabled local development endpoints",
        )),
        _ => unreachable!("normalization accepts only HTTP schemes"),
    }
    if endpoint_is_restricted_literal(&parsed) && !policy.allow_private_networks {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::InvalidValue,
            path,
            "restricted literal addresses require allow_private_networks: true",
        ));
    }
    Some(normalized)
}

pub fn normalize_mcp_http_endpoint(value: &str) -> Result<String, String> {
    let parsed = Url::parse(value).map_err(|error| format!("invalid MCP endpoint URL: {error}"))?;
    normalize_parsed_http_endpoint(&parsed)
}

fn normalize_parsed_http_endpoint(url: &Url) -> Result<String, String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("MCP endpoint scheme must be http or https".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("MCP endpoint URL cannot contain user information".to_owned());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("MCP endpoint URL cannot contain a query or fragment".to_owned());
    }
    let host = match url.host() {
        Some(Host::Domain(domain)) => domain.to_ascii_lowercase(),
        Some(Host::Ipv4(address)) => address.to_string(),
        Some(Host::Ipv6(address)) => format!("[{address}]"),
        None => return Err("MCP endpoint URL must contain a host".to_owned()),
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "MCP endpoint URL must have a known port".to_owned())?;
    Ok(format!("{}://{host}:{port}{}", url.scheme(), url.path()))
}

fn endpoint_is_local(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn endpoint_is_restricted_literal(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => {
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
        }
        Some(Host::Ipv6(address)) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || (address.segments()[0] & 0xfe00) == 0xfc00
        }
        Some(Host::Domain(_)) | None => false,
    }
}

impl PackageSupplyChainPolicy {
    pub fn validate(&self) -> Result<(), ValidationFailure> {
        let mut diagnostics = Vec::new();
        self.validate_into(&mut diagnostics);
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(ValidationFailure::new(diagnostics))
        }
    }

    fn validate_into(&self, diagnostics: &mut Vec<Diagnostic>) {
        if !self.enabled {
            return;
        }
        if self.registries.is_empty() {
            invalid_value(
                diagnostics,
                "policy.packages.registries",
                "must list at least one registry when package analysis is enabled",
            );
        }
        if self.registries.len() > MAX_PACKAGE_REGISTRIES {
            invalid_value(
                diagnostics,
                "policy.packages.registries",
                "contains too many registries",
            );
        }
        let mut registries = HashSet::new();
        for (index, registry) in self.registries.iter().enumerate() {
            let path = format!("policy.packages.registries[{index}]");
            match Url::parse(&registry.url) {
                Ok(url) => {
                    let http_allowed = registry.allow_insecure_http
                        && url.scheme() == "http"
                        && url.host_str().is_some_and(|host| {
                            host == "localhost"
                                || host
                                    .parse::<std::net::IpAddr>()
                                    .is_ok_and(|address| address.is_loopback())
                        });
                    if url.scheme() != "https" && !http_allowed {
                        invalid_value(
                            diagnostics,
                            format!("{path}.url"),
                            "must use HTTPS unless insecure HTTP is explicitly limited to loopback",
                        );
                    }
                    if !url.username().is_empty()
                        || url.password().is_some()
                        || url.query().is_some()
                        || url.fragment().is_some()
                    {
                        invalid_value(
                            diagnostics,
                            format!("{path}.url"),
                            "must not contain credentials, a query, or a fragment",
                        );
                    }
                    let mut normalized = url;
                    normalized.set_query(None);
                    normalized.set_fragment(None);
                    let identity = (registry.ecosystem, normalized.to_string());
                    if !registries.insert(identity) {
                        invalid_value(
                            diagnostics,
                            format!("{path}.url"),
                            "duplicates an earlier registry",
                        );
                    }
                }
                Err(_) => invalid_value(
                    diagnostics,
                    format!("{path}.url"),
                    "must be an absolute registry URL",
                ),
            }
            if let Some(secret) = registry.credential_secret.as_deref()
                && !valid_secret_reference(secret)
            {
                invalid_value(
                    diagnostics,
                    format!("{path}.credential_secret"),
                    "must be a valid secret reference",
                );
            }
        }

        if self.finding_actions.len() > MAX_PACKAGE_FINDING_RULES {
            invalid_value(
                diagnostics,
                "policy.packages.finding_actions",
                "contains too many finding rules",
            );
        }
        let mut findings = HashSet::new();
        for (index, rule) in self.finding_actions.iter().enumerate() {
            if !findings.insert(rule.finding) {
                invalid_value(
                    diagnostics,
                    format!("policy.packages.finding_actions[{index}].finding"),
                    "duplicates an earlier finding rule",
                );
            }
            if rule.finding.is_fail_closed() && rule.action != PackageAction::Deny {
                invalid_value(
                    diagnostics,
                    format!("policy.packages.finding_actions[{index}].action"),
                    "fail-closed findings cannot be allowed or quarantined",
                );
            }
        }

        if self.exceptions.len() > MAX_PACKAGE_EXCEPTIONS {
            invalid_value(
                diagnostics,
                "policy.packages.exceptions",
                "contains too many exception rules",
            );
        }
        for (index, exception) in self.exceptions.iter().enumerate() {
            let path = format!("policy.packages.exceptions[{index}]");
            if exception.package.trim().is_empty() || exception.package.len() > 256 {
                invalid_value(
                    diagnostics,
                    format!("{path}.package"),
                    "must contain 1-256 bytes",
                );
            }
            if exception
                .version
                .as_deref()
                .is_some_and(|version| version.trim().is_empty() || version.len() > 128)
            {
                invalid_value(
                    diagnostics,
                    format!("{path}.version"),
                    "must contain 1-128 bytes when configured",
                );
            }
            if !valid_artifact_digest(&exception.artifact_digest) {
                invalid_value(
                    diagnostics,
                    format!("{path}.artifact_digest"),
                    "must be a lowercase sha256 or sha512 digest",
                );
            }
            if exception.findings.is_empty() {
                invalid_value(
                    diagnostics,
                    format!("{path}.findings"),
                    "must list at least one finding",
                );
            }
            let mut exception_findings = HashSet::new();
            if exception
                .findings
                .iter()
                .any(|finding| !exception_findings.insert(*finding))
            {
                invalid_value(
                    diagnostics,
                    format!("{path}.findings"),
                    "must not contain duplicate findings",
                );
            }
            if exception.action != PackageAction::Deny
                && exception
                    .findings
                    .iter()
                    .any(|finding| finding.is_fail_closed())
            {
                invalid_value(
                    diagnostics,
                    format!("{path}.action"),
                    "fail-closed findings cannot be overridden by an exception",
                );
            }
        }

        let limits = &self.limits;
        for (field, value) in [
            ("max_metadata_bytes", limits.max_metadata_bytes),
            ("max_download_bytes", limits.max_download_bytes),
            ("max_unpacked_bytes", limits.max_unpacked_bytes),
            ("max_entry_bytes", limits.max_entry_bytes),
            ("max_source_scan_bytes", limits.max_source_scan_bytes),
            ("max_report_bytes", limits.max_report_bytes),
        ] {
            if value == 0 {
                invalid_value(
                    diagnostics,
                    format!("policy.packages.limits.{field}"),
                    "must be greater than zero",
                );
            }
        }
        for (field, value) in [
            ("max_entries", limits.max_entries),
            ("max_path_bytes", limits.max_path_bytes),
            ("max_depth", limits.max_depth),
            ("request_timeout_secs", limits.request_timeout_secs),
            ("scan_timeout_secs", limits.scan_timeout_secs),
            ("max_report_findings", limits.max_report_findings),
        ] {
            if value == 0 {
                invalid_value(
                    diagnostics,
                    format!("policy.packages.limits.{field}"),
                    "must be greater than zero",
                );
            }
        }
        if limits.max_entry_bytes > limits.max_unpacked_bytes {
            invalid_value(
                diagnostics,
                "policy.packages.limits.max_entry_bytes",
                "must not exceed max_unpacked_bytes",
            );
        }
        if limits.max_report_bytes > MAX_PACKAGE_REPORT_BYTES {
            invalid_value(
                diagnostics,
                "policy.packages.limits.max_report_bytes",
                format!("must not exceed {MAX_PACKAGE_REPORT_BYTES} bytes"),
            );
        }
        if self.cache.enabled && (self.cache.max_bytes == 0 || self.cache.max_entries == 0) {
            invalid_value(
                diagnostics,
                "policy.packages.cache",
                "enabled cache limits must be greater than zero",
            );
        }
    }
}

fn valid_secret_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
        })
}

fn valid_artifact_digest(value: &str) -> bool {
    let (algorithm, digest) = value.split_once(':').unwrap_or(("", ""));
    let expected = match algorithm {
        "sha256" => 64,
        "sha512" => 128,
        _ => return false,
    };
    digest.len() == expected
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_value(
    diagnostics: &mut Vec<Diagnostic>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    diagnostics.push(Diagnostic::new(DiagnosticCode::InvalidValue, path, message));
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
