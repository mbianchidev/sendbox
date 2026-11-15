//! Checks that a project configuration stays within a governance profile.
//!
//! The check compares the effective, fully expanded session capabilities
//! against the profile ceiling. It never merges allowlists: every capability a
//! session would receive, including implicit grants such as GitHub Meta CIDR
//! delegation, must be individually covered. Dimensions the profile cannot
//! express are rejected rather than ignored.

use std::fmt;
use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use sendbox_config::{KataRuntimeConfiguration, SafeOutputsMode, SandboxConfiguration};
use sendbox_egress::domain::{normalize_pattern, pattern_matches};
use sendbox_governance::ServiceId;
use sendbox_governance::profile::{
    CeilingAction, CredentialServiceProfile, DnsCeiling, GovernanceProfile, McpTransportCeiling,
    RuntimeKind, TransportProtocol,
};
use sendbox_policy::{
    Action, DnsRecordType, McpServerPolicy, NetworkPolicy, PackageAction, PolicyConfiguration,
    Protocol, ToolTransport, normalize_mcp_http_endpoint,
};

/// Session facts that are not part of the project configuration.
#[derive(Debug, Clone)]
pub struct SessionFacts<'a> {
    pub runtime: RuntimeKind,
    pub image: Option<&'a str>,
    pub workspace_root: &'a Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// The session requests more than the profile permits.
    Widening,
    /// The session uses a setting governance cannot reason about safely.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub kind: ViolationKind,
    pub path: String,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            ViolationKind::Widening => "exceeds profile",
            ViolationKind::Unsupported => "unsupported in governed sessions",
        };
        write!(formatter, "{} ({kind}): {}", self.path, self.message)
    }
}

/// Appends the profile's explicit denials. Denials only ever narrow: they add
/// deny rules and blocked destinations and never remove an existing entry.
pub fn apply_denials(profile: &GovernanceProfile, policy: &mut PolicyConfiguration) {
    extend_unique(&mut policy.commands.denylist, &profile.denials.commands);
    extend_unique(
        &mut policy.network.blocked_domains,
        &profile.denials.domains,
    );
    extend_unique(
        &mut policy.network.blocked_networks,
        &profile.denials.networks,
    );
    let provider_hosts = profile
        .credential_services
        .iter()
        .filter(|service| service.deny_direct_egress)
        .map(|service| service.provider.target_host().to_owned())
        .collect::<Vec<_>>();
    extend_unique(&mut policy.network.blocked_domains, &provider_hosts);
}

fn extend_unique(target: &mut Vec<String>, additions: &[String]) {
    for addition in additions {
        if !target.iter().any(|existing| existing == addition) {
            target.push(addition.clone());
        }
    }
}

/// Returns every way `configuration` exceeds `profile`, or nothing when the
/// session is admissible.
#[must_use]
pub fn check(
    profile: &GovernanceProfile,
    configuration: &SandboxConfiguration,
    facts: &SessionFacts<'_>,
) -> Vec<Violation> {
    let mut checker = Checker::default();
    checker.runtime(profile, configuration, facts);
    checker.commands(profile, &configuration.policy);
    checker.network(profile, &configuration.policy.network);
    checker.boundaries(profile, &configuration.policy);
    checker.packages(profile, &configuration.policy);
    checker.secrets(profile, configuration);
    checker.github(profile, configuration);
    checker.credential_services(profile, configuration, facts);
    checker.violations
}

/// The credential services a configuration selects, resolved against the
/// profile in sorted order.
pub fn selected_services<'a>(
    profile: &'a GovernanceProfile,
    configuration: &SandboxConfiguration,
) -> Result<Vec<&'a CredentialServiceProfile>, String> {
    let mut selected = configuration
        .credential_services
        .iter()
        .map(|id| {
            let id = ServiceId::new(id.clone()).map_err(|error| error.to_string())?;
            profile
                .credential_service(&id)
                .ok_or_else(|| format!("credential service `{id}` is not offered by the profile"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(selected)
}

#[derive(Default)]
struct Checker {
    violations: Vec<Violation>,
}

impl Checker {
    fn widening(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.violations.push(Violation {
            kind: ViolationKind::Widening,
            path: path.into(),
            message: message.into(),
        });
    }

    fn unsupported(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.violations.push(Violation {
            kind: ViolationKind::Unsupported,
            path: path.into(),
            message: message.into(),
        });
    }

    fn runtime(
        &mut self,
        profile: &GovernanceProfile,
        configuration: &SandboxConfiguration,
        facts: &SessionFacts<'_>,
    ) {
        let ceiling = &profile.ceiling;
        if facts.runtime == RuntimeKind::Hyperlight {
            self.unsupported(
                "runtime.provider",
                "Hyperlight does not provide the persistent guest boundary that governed sessions require",
            );
        } else if !ceiling.runtimes.contains(&facts.runtime) {
            self.widening(
                "runtime.provider",
                format!("runtime {:?} is not permitted", facts.runtime),
            );
        }
        if let Some(runtime) = &configuration.runtime
            && runtime.kata != KataRuntimeConfiguration::default()
        {
            self.unsupported(
                "runtime.kata",
                "project files cannot select Kata executables, handlers, or configuration in governed sessions",
            );
        }
        if !ceiling.images.is_empty() {
            let digest = facts
                .image
                .and_then(|image| image.rsplit_once('@'))
                .map(|(_, digest)| digest);
            if !digest.is_some_and(|digest| ceiling.images.iter().any(|image| image == digest)) {
                self.widening("--image", "image digest is not in the permitted image set");
            }
        }
        if !ceiling.workspace_roots.is_empty()
            && !ceiling
                .workspace_roots
                .iter()
                .any(|root| facts.workspace_root.starts_with(root))
        {
            self.widening(
                "workspace_path",
                format!(
                    "workspace {} is outside the permitted workspace roots",
                    facts.workspace_root.display()
                ),
            );
        }
        if let Some(resources) = &ceiling.resources {
            for (path, value, maximum) in [
                (
                    "resources.cpus",
                    configuration.resources.cpus,
                    resources.max_cpus,
                ),
                (
                    "resources.memory_mb",
                    configuration.resources.memory_mb,
                    resources.max_memory_mb,
                ),
                (
                    "resources.disk_size_mb",
                    configuration.resources.disk_size_mb,
                    resources.max_disk_mb,
                ),
            ] {
                if let Some(maximum) = maximum
                    && value > maximum
                {
                    self.widening(path, format!("{value} exceeds the maximum {maximum}"));
                }
            }
        }
    }

    fn commands(&mut self, profile: &GovernanceProfile, policy: &PolicyConfiguration) {
        let ceiling = &profile.ceiling.commands;
        if ceiling.default_action == CeilingAction::Allow {
            return;
        }
        if policy.commands.default_action == Action::Allow {
            self.widening(
                "policy.commands.default_action",
                "allow-by-default command execution is not permitted",
            );
            return;
        }
        for rule in &policy.commands.allowlist {
            let mut covered = false;
            for ceiling_rule in &ceiling.allowlist {
                match sendbox_exec::rule_covers(ceiling_rule, rule) {
                    Ok(true) => {
                        covered = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        self.unsupported(
                            "ceiling.commands.allowlist",
                            format!("rule `{ceiling_rule}` cannot be compiled: {error}"),
                        );
                        return;
                    }
                }
            }
            if !covered {
                self.widening(
                    "policy.commands.allowlist",
                    format!("`{rule}` is not covered by a permitted command rule"),
                );
            }
        }
    }

    fn network(&mut self, profile: &GovernanceProfile, network: &NetworkPolicy) {
        let ceiling = &profile.ceiling.network;
        let (blocked, allowed, ceiling_domains) = match (
            normalize_all(&network.blocked_domains),
            normalize_all(&network.allowed_domains),
            normalize_all(&ceiling.allowed_domains),
        ) {
            (Ok(blocked), Ok(allowed), Ok(ceiling)) => (blocked, allowed, ceiling),
            (Err(message), _, _) | (_, Err(message), _) | (_, _, Err(message)) => {
                self.unsupported("policy.network", message);
                return;
            }
        };

        if ceiling.default_action == CeilingAction::Deny {
            if network.default_action == Action::Allow {
                self.widening(
                    "policy.network.default_action",
                    "allow-by-default network egress is not permitted",
                );
            } else {
                for pattern in &allowed {
                    if !pattern_covered(&blocked, pattern)
                        && !pattern_covered(&ceiling_domains, pattern)
                    {
                        self.widening(
                            "policy.network.allowed_domains",
                            format!("`{pattern}` is not covered by a permitted domain"),
                        );
                    }
                }
            }
        }

        let meta_delegated = allowed.iter().any(|name| name == "github.com")
            && !blocked
                .iter()
                .any(|pattern| pattern_matches(pattern, "github.com"));
        if meta_delegated && !ceiling.github_meta {
            self.widening(
                "policy.network.allowed_domains",
                "an exact `github.com` grant implicitly delegates GitHub Meta CIDRs, which the profile does not permit",
            );
        }

        match (
            parse_networks(&network.allowed_networks),
            parse_networks(&ceiling.allowed_networks),
        ) {
            (Ok(networks), Ok(ceiling_networks)) => {
                for net in networks {
                    if !ceiling_networks
                        .iter()
                        .any(|ceiling| ceiling.contains(&net))
                    {
                        self.widening(
                            "policy.network.allowed_networks",
                            format!("`{net}` is not contained in a permitted network"),
                        );
                    }
                }
            }
            (Err(message), _) | (_, Err(message)) => {
                self.unsupported("policy.network.allowed_networks", message);
            }
        }

        if !ceiling.allowed_ports.is_empty() {
            if network.allowed_ports.is_empty() {
                self.widening(
                    "policy.network.allowed_ports",
                    "an empty port list permits every port; list permitted ports explicitly",
                );
            }
            for rule in &network.allowed_ports {
                let protocol = match rule.protocol {
                    Protocol::Tcp => TransportProtocol::Tcp,
                    Protocol::Udp => TransportProtocol::Udp,
                };
                if !ceiling
                    .allowed_ports
                    .iter()
                    .any(|permitted| permitted.protocol == protocol && permitted.port == rule.port)
                {
                    self.widening(
                        "policy.network.allowed_ports",
                        format!("{protocol:?}/{} is not permitted", rule.port),
                    );
                }
            }
        }
        if network.allow_dns && !ceiling.allow_dns {
            self.widening(
                "policy.network.allow_dns",
                "DNS resolution is not permitted",
            );
        }
        if let Some(maximum) = ceiling.max_connections {
            match network.max_connections {
                Some(value) if value <= maximum => {}
                _ => self.widening(
                    "policy.network.max_connections",
                    format!("must be set to at most {maximum}"),
                ),
            }
        }
        self.dns(&ceiling.dns, network);
    }

    fn dns(&mut self, ceiling: &DnsCeiling, network: &NetworkPolicy) {
        let dns = &network.dns;
        let limits: [(&str, u64, u64); 9] = [
            (
                "max_ttl_secs",
                dns.max_ttl_secs.into(),
                ceiling.max_ttl_secs.into(),
            ),
            (
                "max_qname_octets",
                dns.max_qname_octets.into(),
                ceiling.max_qname_octets.into(),
            ),
            (
                "max_labels",
                dns.max_labels.into(),
                ceiling.max_labels.into(),
            ),
            (
                "max_label_octets",
                dns.max_label_octets.into(),
                ceiling.max_label_octets.into(),
            ),
            (
                "max_response_records",
                dns.max_response_records.into(),
                ceiling.max_response_records.into(),
            ),
            (
                "budget.max_queries",
                dns.budget.max_queries.into(),
                ceiling.budget_max_queries.into(),
            ),
            (
                "budget.max_query_octets",
                dns.budget.max_query_octets,
                ceiling.budget_max_query_octets,
            ),
            (
                "budget.max_unique_names",
                dns.budget.max_unique_names.into(),
                ceiling.budget_max_unique_names.into(),
            ),
            (
                "budget.max_dynamic_labels",
                dns.budget.max_dynamic_labels.into(),
                ceiling.budget_max_dynamic_labels.into(),
            ),
        ];
        for (field, value, maximum) in limits {
            if value > maximum {
                self.widening(
                    format!("policy.network.dns.{field}"),
                    format!("{value} exceeds the maximum {maximum}"),
                );
            }
        }
        if dns.budget.window_secs != ceiling.budget_window_secs {
            self.widening(
                "policy.network.dns.budget.window_secs",
                format!("must equal {}", ceiling.budget_window_secs),
            );
        }
        for record in &dns.allowed_record_types {
            let name = match record {
                DnsRecordType::A => "A",
                DnsRecordType::Aaaa => "AAAA",
            };
            if !ceiling.allowed_record_types.iter().any(|kind| kind == name) {
                self.widening(
                    "policy.network.dns.allowed_record_types",
                    format!("{name} queries are not permitted"),
                );
            }
        }
    }

    fn boundaries(&mut self, profile: &GovernanceProfile, policy: &PolicyConfiguration) {
        let ceiling = &profile.ceiling.mcp;
        let boundaries = &policy.boundaries;
        if !boundaries.enabled && ceiling.require_boundaries {
            self.widening(
                "policy.boundaries.enabled",
                "the MCP and syscall boundary must stay enabled",
            );
        }
        let tools = &boundaries.tool_calls;
        if tools.uses_legacy_fields() {
            self.unsupported(
                "policy.boundaries.tool_calls",
                "legacy flat MCP rules are not supported; declare hierarchical `servers` instead",
            );
        }
        for (id, server) in &tools.servers {
            let path = format!("policy.boundaries.tool_calls.servers.{id}");
            let Some(permitted) = ceiling.servers.get(id) else {
                self.widening(path, "MCP server is not permitted");
                continue;
            };
            let transport = match server.transport() {
                ToolTransport::Stdio => McpTransportCeiling::Stdio,
                ToolTransport::StreamableHttp => McpTransportCeiling::StreamableHttp,
                ToolTransport::StreamableHttp2025 => McpTransportCeiling::StreamableHttp2025,
            };
            if transport != permitted.transport {
                self.widening(&path, "transport differs from the permitted server");
                continue;
            }
            match server {
                McpServerPolicy::Stdio {
                    command,
                    authorization,
                    ..
                } => {
                    if *command != permitted.command {
                        self.widening(
                            format!("{path}.command"),
                            "command differs from the permitted server",
                        );
                    }
                    for secret in authorization
                        .iter()
                        .flat_map(|authorization| authorization.secret_names())
                    {
                        if !permitted.stdio_secrets.contains(secret) {
                            self.widening(
                                format!("{path}.authorization"),
                                format!("secret `{secret}` is not permitted for this server"),
                            );
                        }
                    }
                }
                McpServerPolicy::StreamableHttp { url, http, .. }
                | McpServerPolicy::StreamableHttp2025 { url, http, .. } => {
                    let same_url = permitted.url.as_deref().is_some_and(|permitted| {
                        matches!(
                            (
                                normalize_mcp_http_endpoint(url),
                                normalize_mcp_http_endpoint(permitted),
                            ),
                            (Ok(left), Ok(right)) if left == right
                        )
                    });
                    if !same_url {
                        self.widening(
                            format!("{path}.url"),
                            "endpoint differs from the permitted server",
                        );
                    }
                    for (field, requested, allowed) in [
                        (
                            "allow_plaintext_local",
                            http.allow_plaintext_local,
                            permitted.allow_plaintext_local,
                        ),
                        (
                            "allow_private_networks",
                            http.allow_private_networks,
                            permitted.allow_private_networks,
                        ),
                        (
                            "allow_redirects",
                            http.allow_redirects,
                            permitted.allow_redirects,
                        ),
                    ] {
                        if requested && !allowed {
                            self.widening(format!("{path}.http.{field}"), "is not permitted");
                        }
                    }
                    for redirect in &http.redirect_allowlist {
                        if !permitted.redirect_allowlist.contains(redirect) {
                            self.widening(
                                format!("{path}.http.redirect_allowlist"),
                                format!("`{redirect}` is not permitted"),
                            );
                        }
                    }
                    if let Some(authorization) = &http.authorization
                        && permitted.bearer_secret.as_deref()
                            != Some(authorization.bearer_secret.as_str())
                    {
                        self.widening(
                            format!("{path}.http.authorization"),
                            "bearer credential is not permitted for this server",
                        );
                    }
                }
            }
            let tool_rules = server.tools();
            if permitted.tools.default_action == CeilingAction::Deny {
                if tool_rules.default_action == Action::Allow {
                    self.widening(
                        format!("{path}.tools.default_action"),
                        "allow-by-default tools are not permitted",
                    );
                }
                for tool in &tool_rules.allowlist {
                    if !permitted.tools.allowlist.contains(tool) {
                        self.widening(
                            format!("{path}.tools.allowlist"),
                            format!("tool `{tool}` is not permitted"),
                        );
                    }
                }
            }
        }
    }

    fn packages(&mut self, profile: &GovernanceProfile, policy: &PolicyConfiguration) {
        let ceiling = &profile.ceiling.packages;
        let packages = &policy.packages;
        if !packages.enabled {
            if ceiling.require_supply_chain {
                self.widening(
                    "policy.packages.enabled",
                    "package supply-chain inspection is required",
                );
            }
            return;
        }
        for (index, registry) in packages.registries.iter().enumerate() {
            let path = format!("policy.packages.registries[{index}]");
            if !ceiling.allowed_registries.contains(&registry.url) {
                self.widening(
                    &path,
                    format!("registry `{}` is not permitted", registry.url),
                );
            }
            if registry.allow_insecure_http && !ceiling.allow_insecure_http {
                self.widening(
                    format!("{path}.allow_insecure_http"),
                    "plaintext registries are not permitted",
                );
            }
            if let Some(secret) = &registry.credential_secret
                && !ceiling.registry_credentials.contains(secret)
            {
                self.widening(
                    format!("{path}.credential_secret"),
                    format!("registry credential `{secret}` is not permitted"),
                );
            }
        }
        let overrides = packages.default_finding_action == PackageAction::Allow
            || packages
                .finding_actions
                .iter()
                .any(|rule| rule.action == PackageAction::Allow);
        if overrides && !ceiling.allow_finding_overrides {
            self.widening(
                "policy.packages.finding_actions",
                "allowing packages with findings is not permitted",
            );
        }
        if !packages.exceptions.is_empty() && !ceiling.allow_exceptions {
            self.widening(
                "policy.packages.exceptions",
                "package exceptions are not permitted",
            );
        }
    }

    fn secrets(&mut self, profile: &GovernanceProfile, configuration: &SandboxConfiguration) {
        for secret in &configuration.secrets {
            if profile
                .credential_services
                .iter()
                .any(|service| service.secret.eq_ignore_ascii_case(secret))
            {
                self.unsupported(
                    "secrets",
                    format!("`{secret}` is a brokered credential and can never enter the guest"),
                );
            } else if !profile.ceiling.secrets.workload.contains(secret) {
                self.widening(
                    "secrets",
                    format!("`{secret}` may not be delivered to the guest"),
                );
            }
        }
    }

    fn github(&mut self, profile: &GovernanceProfile, configuration: &SandboxConfiguration) {
        let ceiling = &profile.ceiling.github;
        let github = &configuration.github;
        for (path, requested, allowed) in [
            (
                "github.forward_auth",
                github.forward_auth,
                ceiling.forward_auth,
            ),
            (
                "github.forward_copilot_auth",
                github.forward_copilot_auth,
                ceiling.forward_copilot_auth,
            ),
            (
                "github.allow_private_repository_access",
                github.allow_private_repository_access,
                ceiling.allow_private_repository_access,
            ),
            (
                "github.ssh_key_path",
                github.ssh_key_path.is_some(),
                ceiling.ssh_key,
            ),
        ] {
            if requested && !allowed {
                self.widening(path, "is not permitted");
            }
        }
        if !github.branch_protection.enabled && ceiling.require_branch_protection {
            self.widening(
                "github.branch_protection.enabled",
                "branch protection must stay enabled",
            );
        }
        let safe_outputs = &github.safe_outputs;
        if safe_outputs.enabled {
            if !ceiling.safe_outputs.enabled {
                self.widening(
                    "github.safe_outputs.enabled",
                    "Safe Outputs is not permitted",
                );
            }
            if safe_outputs.mode == SafeOutputsMode::Apply && !ceiling.safe_outputs.allow_apply {
                self.widening(
                    "github.safe_outputs.mode",
                    "apply mode is not permitted; use staged",
                );
            }
            if !ceiling.safe_outputs.repositories.is_empty() {
                for repository in &safe_outputs.allowed_repositories {
                    if !ceiling
                        .safe_outputs
                        .repositories
                        .iter()
                        .any(|permitted| permitted.eq_ignore_ascii_case(repository))
                    {
                        self.widening(
                            "github.safe_outputs.allowed_repositories",
                            format!("`{repository}` is not a permitted target"),
                        );
                    }
                }
            }
        }
    }

    fn credential_services(
        &mut self,
        profile: &GovernanceProfile,
        configuration: &SandboxConfiguration,
        facts: &SessionFacts<'_>,
    ) {
        if let Err(message) = selected_services(profile, configuration) {
            self.widening("credential_services", message);
            return;
        }
        if !configuration.credential_services.is_empty() && facts.runtime == RuntimeKind::Hyperlight
        {
            self.unsupported(
                "credential_services",
                "brokered credentials require a persistent Apple or Kata session",
            );
        }
    }
}

fn normalize_all(patterns: &[String]) -> Result<Vec<String>, String> {
    patterns
        .iter()
        .map(|pattern| normalize_pattern(pattern).map_err(|error| format!("`{pattern}`: {error}")))
        .collect()
}

/// Whether every name `pattern` can match is matched by some `covering` pattern.
fn pattern_covered(covering: &[String], pattern: &str) -> bool {
    match pattern.strip_prefix("*.") {
        None => covering
            .iter()
            .any(|candidate| pattern_matches(candidate, pattern)),
        Some(suffix) => covering.iter().any(|candidate| {
            candidate == pattern
                || (candidate.starts_with("*.") && pattern_matches(candidate, suffix))
        }),
    }
}

fn parse_networks(values: &[String]) -> Result<Vec<IpNet>, String> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
                .map(|net| net.trunc())
                .map_err(|_| format!("`{value}` is not an IP address or CIDR"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sendbox_config::{PolicyPreset, RuntimeProvider};
    use sendbox_policy::{DnsPolicy, PortRule};

    use super::*;

    const PROFILE: &str = r#"
format: sendbox.governance-profile
version: 1
id: acme
revision: 1
not_before_unix: 0
expires_at_unix: 30000000
ceiling:
  runtimes: [apple, kata]
  workspace_roots: [/work]
  resources: { max_cpus: 4 }
  commands:
    default_action: deny
    allowlist: ["git *", "/usr/local/bin/claude"]
  network:
    default_action: deny
    allowed_domains: ["*.github.com", "registry.npmjs.org", "api.example.com"]
    allowed_networks: ["10.0.0.0/8"]
    allow_dns: true
  github:
    forward_copilot_auth: true
  secrets:
    workload: [NPM_TOKEN]
denials:
  domains: [pastebin.com]
  commands: ["git push"]
credential_services:
  - id: anthropic
    provider: anthropic
    secret: SENDBOX_ANTHROPIC_API_KEY
"#;

    fn profile() -> GovernanceProfile {
        GovernanceProfile::parse(PROFILE.as_bytes()).expect("profile")
    }

    fn configuration() -> SandboxConfiguration {
        let mut configuration = SandboxConfiguration::for_project(
            PathBuf::from("/work/app"),
            PolicyPreset::Strict,
            RuntimeProvider::Apple,
        );
        configuration.github.forward_auth = false;
        configuration.policy.network.allowed_domains = vec!["*.github.com".to_owned()];
        configuration.policy.commands.allowlist = vec!["git status".to_owned()];
        configuration
    }

    fn facts() -> SessionFacts<'static> {
        SessionFacts {
            runtime: RuntimeKind::Apple,
            image: Some("ghcr.io/acme/agent@sha256:00"),
            workspace_root: Path::new("/work/app"),
        }
    }

    fn paths(violations: &[Violation]) -> Vec<&str> {
        violations
            .iter()
            .map(|violation| violation.path.as_str())
            .collect()
    }

    #[test]
    fn narrowed_configuration_is_admitted() {
        let violations = check(&profile(), &configuration(), &facts());
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn denials_only_narrow_and_block_brokered_provider_hosts() {
        let profile = profile();
        let mut policy = configuration().policy;
        let before = policy.clone();
        apply_denials(&profile, &mut policy);
        apply_denials(&profile, &mut policy);
        assert!(
            before
                .network
                .blocked_domains
                .iter()
                .all(|domain| policy.network.blocked_domains.contains(domain))
        );
        assert!(
            policy
                .network
                .blocked_domains
                .contains(&"api.anthropic.com".to_owned())
        );
        assert!(
            policy
                .network
                .blocked_domains
                .contains(&"pastebin.com".to_owned())
        );
        assert_eq!(
            policy
                .commands
                .denylist
                .iter()
                .filter(|rule| *rule == "git push")
                .count(),
            1
        );
        assert_eq!(
            policy.network.allowed_domains,
            before.network.allowed_domains
        );
    }

    #[test]
    fn implicit_github_meta_delegation_is_a_widening() {
        let mut configuration = configuration();
        configuration
            .policy
            .network
            .allowed_domains
            .push("github.com".to_owned());
        let violations = check(&profile(), &configuration, &facts());
        assert!(
            violations
                .iter()
                .any(|violation| violation.message.contains("GitHub Meta")),
            "{violations:?}"
        );
        configuration
            .policy
            .network
            .blocked_domains
            .push("github.com".to_owned());
        let violations = check(&profile(), &configuration, &facts());
        assert!(
            !violations
                .iter()
                .any(|violation| violation.message.contains("GitHub Meta"))
        );
    }

    #[test]
    fn default_allow_presets_and_uncovered_rules_are_rejected() {
        let mut configuration = SandboxConfiguration::for_project(
            PathBuf::from("/work/app"),
            PolicyPreset::Permissive,
            RuntimeProvider::Apple,
        );
        configuration.github.forward_auth = false;
        let violations = check(&profile(), &configuration, &facts());
        let found = paths(&violations);
        assert!(found.contains(&"policy.commands.default_action"));
        assert!(found.contains(&"policy.network.default_action"));
        assert!(found.contains(&"policy.boundaries.tool_calls"));

        let mut configuration = self::configuration();
        configuration.policy.commands.allowlist = vec!["curl *".to_owned()];
        configuration.policy.network.allowed_domains =
            vec!["*.example.com".to_owned(), "evil.com".to_owned()];
        configuration.policy.network.allowed_networks = vec!["192.168.0.0/16".to_owned()];
        configuration.policy.network.allowed_ports = vec![PortRule {
            protocol: Protocol::Tcp,
            port: 22,
        }];
        let violations = check(&profile(), &configuration, &facts());
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.path == "policy.network.allowed_domains")
                .count(),
            2,
            "{violations:?}"
        );
        let found = paths(&violations);
        assert!(found.contains(&"policy.commands.allowlist"));
        assert!(found.contains(&"policy.network.allowed_networks"));
    }

    #[test]
    fn wildcard_domains_need_a_wildcard_ceiling() {
        let ceiling = vec!["*.github.com".to_owned(), "api.example.com".to_owned()];
        assert!(pattern_covered(&ceiling, "api.github.com"));
        assert!(pattern_covered(&ceiling, "*.api.github.com"));
        assert!(pattern_covered(&ceiling, "*.github.com"));
        assert!(!pattern_covered(&ceiling, "github.com"));
        assert!(!pattern_covered(&ceiling, "*.example.com"));
        assert!(pattern_covered(&ceiling, "api.example.com"));
    }

    #[test]
    fn github_secrets_runtime_and_workspace_dimensions_are_checked() {
        let mut configuration = configuration();
        configuration.github.forward_auth = true;
        configuration.github.ssh_key_path = Some(PathBuf::from("/home/me/.ssh/id"));
        configuration.github.branch_protection.enabled = false;
        configuration.secrets = vec![
            "NPM_TOKEN".to_owned(),
            "OTHER".to_owned(),
            "SENDBOX_ANTHROPIC_API_KEY".to_owned(),
        ];
        configuration.resources.cpus = 8;
        configuration
            .runtime
            .as_mut()
            .expect("runtime")
            .kata
            .executable = "/tmp/nerdctl".to_owned();
        configuration.credential_services = vec!["openai".to_owned()];
        let facts = SessionFacts {
            runtime: RuntimeKind::Apple,
            image: None,
            workspace_root: Path::new("/elsewhere"),
        };
        let violations = check(&profile(), &configuration, &facts);
        let found = paths(&violations);
        for expected in [
            "github.forward_auth",
            "github.ssh_key_path",
            "github.branch_protection.enabled",
            "resources.cpus",
            "runtime.kata",
            "workspace_path",
            "credential_services",
        ] {
            assert!(found.contains(&expected), "{expected}: {violations:?}");
        }
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.path == "secrets")
                .count(),
            2
        );
        assert!(violations.iter().any(|violation| {
            violation.kind == ViolationKind::Unsupported
                && violation.message.contains("brokered credential")
        }));

        let hyperlight = SessionFacts {
            runtime: RuntimeKind::Hyperlight,
            ..self::facts()
        };
        assert!(
            check(&profile(), &self::configuration(), &hyperlight)
                .iter()
                .any(|violation| violation.kind == ViolationKind::Unsupported)
        );
    }

    #[test]
    fn dns_defaults_match_the_runtime_policy_and_limits_are_checked() {
        let defaults = DnsPolicy::default();
        let ceiling = DnsCeiling::default();
        assert_eq!(
            (
                ceiling.max_ttl_secs,
                ceiling.max_qname_octets,
                ceiling.max_labels,
                ceiling.max_label_octets,
                ceiling.max_response_records,
            ),
            (
                defaults.max_ttl_secs,
                defaults.max_qname_octets,
                defaults.max_labels,
                defaults.max_label_octets,
                defaults.max_response_records,
            )
        );
        assert_eq!(
            (
                ceiling.budget_window_secs,
                ceiling.budget_max_queries,
                ceiling.budget_max_query_octets,
                ceiling.budget_max_unique_names,
                ceiling.budget_max_dynamic_labels,
            ),
            (
                defaults.budget.window_secs,
                defaults.budget.max_queries,
                defaults.budget.max_query_octets,
                defaults.budget.max_unique_names,
                defaults.budget.max_dynamic_labels,
            )
        );

        let mut configuration = configuration();
        configuration.policy.network.dns.max_ttl_secs = 3600;
        configuration.policy.network.dns.budget.window_secs = 1;
        let violations = check(&profile(), &configuration, &facts());
        let found = paths(&violations);
        assert!(found.contains(&"policy.network.dns.max_ttl_secs"));
        assert!(found.contains(&"policy.network.dns.budget.window_secs"));
    }
}
