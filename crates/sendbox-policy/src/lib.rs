#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::Path;

use sendbox_core::{Diagnostic, DiagnosticCode, ValidationFailure};
use serde::{Deserialize, Serialize};
use url::Url;

const BPFTRACE_STRING_LENGTH: usize = 4096;
const MAX_SERVER_COMMAND_PARTS: usize = 16;
pub const MAX_PACKAGE_REGISTRIES: usize = 16;
pub const MAX_PACKAGE_FINDING_RULES: usize = 64;
pub const MAX_PACKAGE_EXCEPTIONS: usize = 128;

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
