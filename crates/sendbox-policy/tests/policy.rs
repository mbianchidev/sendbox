use std::fs;
use std::path::PathBuf;

use sendbox_policy::{
    Action, BoundaryPolicy, DnsPolicy, DnsRecordType, EvidenceRequirement, NetworkPolicy,
    PackageAction, PackageEcosystem, PackageFindingKind, PackageRegistryPolicy,
    PackageSupplyChainPolicy, PolicyConfiguration, Protocol,
};

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn loads_and_validates_shipped_default_policy() {
    let yaml = fs::read_to_string(workspace_path("config/default-policy.yaml")).unwrap();
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(&yaml).unwrap();

    policy.validate().unwrap();
    assert_eq!(policy.commands.default_action, Action::Deny);
    assert!(policy.commands.allowlist.contains(&"cargo *".to_owned()));
    assert_eq!(policy.boundaries, BoundaryPolicy::default());
}

#[test]
fn shipped_default_policy_uses_default_egress_extensions() {
    // The shipped default policy predates the egress extensions and carries
    // no `allowed_networks`/`blocked_networks`/`allowed_ports`/`dns` keys, so
    // every one of those must resolve to its serde default without error.
    let yaml = fs::read_to_string(workspace_path("config/default-policy.yaml")).unwrap();
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(&yaml).unwrap();
    policy.validate().unwrap();
    assert!(policy.network.allowed_networks.is_empty());
    assert!(policy.network.blocked_networks.is_empty());
    assert!(policy.network.allowed_ports.is_empty());
    assert_eq!(policy.network.dns, DnsPolicy::default());
}

#[test]
fn legacy_network_yaml_without_new_fields_still_parses() {
    // Exactly the pre-extension network shape: no networks, ports, or dns.
    let yaml = r#"
commands:
  default_action: deny
  allowlist: []
  denylist: []
  log_blocked: true
network:
  default_action: deny
  allowed_domains: ["github.com"]
  blocked_domains: []
  allow_dns: true
  max_connections: 100
"#;
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(yaml).unwrap();
    policy.validate().unwrap();
    assert_eq!(policy.network.max_connections, Some(100));
    assert!(policy.network.allowed_networks.is_empty());
    assert_eq!(policy.network.dns.max_ttl_secs, 300);
    assert_eq!(
        policy.network.dns.allowed_record_types,
        vec![DnsRecordType::A, DnsRecordType::Aaaa]
    );
}

#[test]
fn new_egress_fields_parse_when_present() {
    let yaml = r#"
commands:
  default_action: deny
  allowlist: []
  denylist: []
  log_blocked: true
network:
  default_action: deny
  allowed_domains: ["example.com"]
  blocked_domains: []
  allow_dns: true
  max_connections: 8
  allowed_networks: ["93.184.216.34/32", "2001:db8::/32"]
  blocked_networks: ["203.0.113.0/24"]
  allowed_ports:
    - { protocol: tcp, port: 443 }
    - { protocol: tcp, port: 22 }
  dns:
    max_ttl_secs: 30
    max_qname_octets: 120
    max_labels: 8
    max_label_octets: 40
    allowed_record_types: ["A"]
    max_response_records: 4
    budget:
      window_secs: 10
      max_queries: 20
      max_query_octets: 512
      max_unique_names: 16
      max_dynamic_labels: 16
"#;
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(yaml).unwrap();
    policy.validate().unwrap();
    let network: &NetworkPolicy = &policy.network;
    assert_eq!(network.allowed_networks.len(), 2);
    assert_eq!(network.blocked_networks, vec!["203.0.113.0/24".to_owned()]);
    assert_eq!(network.allowed_ports.len(), 2);
    assert_eq!(network.allowed_ports[0].protocol, Protocol::Tcp);
    assert_eq!(network.allowed_ports[0].port, 443);
    assert_eq!(network.dns.max_ttl_secs, 30);
    assert_eq!(network.dns.allowed_record_types, vec![DnsRecordType::A]);
    assert_eq!(network.dns.budget.window_secs, 10);
}

#[test]
fn rejects_zero_dns_ttl_and_window() {
    let yaml = r#"
commands:
  default_action: deny
  allowlist: []
  denylist: []
  log_blocked: true
network:
  default_action: deny
  allowed_domains: []
  blocked_domains: []
  allow_dns: true
  dns:
    max_ttl_secs: 0
    budget:
      window_secs: 0
"#;
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(yaml).unwrap();
    let diagnostics = policy.validate().unwrap_err().into_diagnostics();
    assert!(
        diagnostics
            .iter()
            .any(|d| d.path == "policy.network.dns.max_ttl_secs")
    );
    assert!(
        diagnostics
            .iter()
            .any(|d| d.path == "policy.network.dns.budget.window_secs")
    );
}

#[test]
fn rejects_out_of_range_dns_structural_and_budget_fields() {
    let yaml = r#"
commands:
  default_action: deny
  allowlist: []
  denylist: []
  log_blocked: true
network:
  default_action: deny
  allowed_domains: []
  blocked_domains: []
  allow_dns: true
  dns:
    max_qname_octets: 300
    max_labels: 0
    max_label_octets: 100
    max_response_records: 0
    allowed_record_types: []
    budget:
      max_queries: 0
      max_query_octets: 0
      max_unique_names: 0
      max_dynamic_labels: 0
"#;
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(yaml).unwrap();
    let diagnostics = policy.validate().unwrap_err().into_diagnostics();
    for field in [
        "policy.network.dns.max_qname_octets",
        "policy.network.dns.max_labels",
        "policy.network.dns.max_label_octets",
        "policy.network.dns.max_response_records",
        "policy.network.dns.allowed_record_types",
        "policy.network.dns.budget.max_queries",
        "policy.network.dns.budget.max_query_octets",
        "policy.network.dns.budget.max_unique_names",
        "policy.network.dns.budget.max_dynamic_labels",
    ] {
        assert!(
            diagnostics.iter().any(|d| d.path == field),
            "missing diagnostic for {field}"
        );
    }
}

#[test]
fn boundary_defaults_are_stable_and_canonical() {
    let boundary = BoundaryPolicy::default();
    let first = serde_json::to_string(&boundary).unwrap();
    let second = serde_json::to_string(&boundary).unwrap();

    assert_eq!(first, second);
    assert_eq!(boundary.tool_calls.max_frame_bytes, 1_048_576);
    assert_eq!(boundary.log_path, "/var/log/sendbox/boundary.log");
}

#[test]
fn rejects_unsafe_allowed_server_commands() {
    let yaml = r#"
commands:
  default_action: deny
  allowlist: []
  denylist: []
  log_blocked: true
network:
  default_action: deny
  allowed_domains: []
  blocked_domains: []
  allow_dns: true
boundaries:
  tool_calls:
    allowed_server_commands:
      - ["/usr/bin/npx", "@modelcontextprotocol/server-filesystem"]
"#;
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(yaml).unwrap();
    let diagnostics = policy.validate().unwrap_err().into_diagnostics();

    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.path == "policy.boundaries.tool_calls.allowed_server_commands[0]"
            && diagnostic.message.contains("non-shell")
    }));
}

#[test]
fn package_policy_defaults_disabled_and_fail_closed_when_enabled() {
    let disabled = PackageSupplyChainPolicy::default();
    assert!(!disabled.enabled);
    assert_eq!(disabled.default_finding_action, PackageAction::Deny);
    assert!(disabled.cache.enabled);

    let policy = PackageSupplyChainPolicy {
        enabled: true,
        registries: vec![PackageRegistryPolicy::default()],
        ..PackageSupplyChainPolicy::default()
    };
    let config = PolicyConfiguration {
        commands: sendbox_policy::CommandPolicy {
            default_action: Action::Deny,
            allowlist: Vec::new(),
            denylist: Vec::new(),
            log_blocked: true,
        },
        network: NetworkPolicy {
            default_action: Action::Deny,
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
            allow_dns: true,
            max_connections: None,
            allowed_networks: Vec::new(),
            blocked_networks: Vec::new(),
            allowed_ports: Vec::new(),
            dns: DnsPolicy::default(),
        },
        boundaries: BoundaryPolicy::default(),
        packages: policy,
    };
    config.validate().unwrap();
    assert_eq!(
        config.packages.registries[0].signature,
        EvidenceRequirement::IfPresent
    );
}

#[test]
fn package_policy_rejects_insecure_remote_registries_and_weak_exceptions() {
    let yaml = r#"
commands:
  default_action: deny
  allowlist: []
  denylist: []
  log_blocked: true
network:
  default_action: deny
  allowed_domains: []
  blocked_domains: []
  allow_dns: true
packages:
  enabled: true
  registries:
    - ecosystem: npm
      url: http://registry.example.com/
      allow_insecure_http: true
  exceptions:
    - ecosystem: npm
      package: risky
      artifact_digest: latest
      findings: []
      action: allow
"#;
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(yaml).unwrap();
    let diagnostics = policy.validate().unwrap_err().into_diagnostics();
    for path in [
        "policy.packages.registries[0].url",
        "policy.packages.exceptions[0].artifact_digest",
        "policy.packages.exceptions[0].findings",
    ] {
        assert!(
            diagnostics.iter().any(|diagnostic| diagnostic.path == path),
            "missing diagnostic for {path}"
        );
    }
}

#[test]
fn package_policy_accepts_digest_bound_lifecycle_exception() {
    let digest = format!("sha512:{}", "a".repeat(128));
    let yaml = format!(
        r#"
commands:
  default_action: deny
  allowlist: []
  denylist: []
  log_blocked: true
network:
  default_action: deny
  allowed_domains: []
  blocked_domains: []
  allow_dns: true
packages:
  enabled: true
  registries:
    - ecosystem: npm
      url: https://registry.npmjs.org/
      signature: required
      provenance: if_present
  exceptions:
    - ecosystem: npm
      package: "@acme/build"
      version: 1.2.3
      artifact_digest: "{digest}"
      findings: [lifecycle_script]
      action: allow
"#
    );
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(&yaml).unwrap();
    policy.validate().unwrap();
    let exception = &policy.packages.exceptions[0];
    assert_eq!(exception.ecosystem, PackageEcosystem::Npm);
    assert_eq!(
        exception.findings,
        vec![PackageFindingKind::LifecycleScript]
    );
}

#[test]
fn package_policy_rejects_overrides_for_fail_closed_findings() {
    let digest = format!("sha512:{}", "b".repeat(128));
    let yaml = format!(
        r#"
commands:
  default_action: deny
  allowlist: []
  denylist: []
  log_blocked: true
network:
  default_action: deny
  allowed_domains: []
  blocked_domains: []
  allow_dns: true
packages:
  enabled: true
  registries:
    - ecosystem: npm
      url: https://registry.npmjs.org/
  finding_actions:
    - finding: scanner_failure
      action: allow
  exceptions:
    - ecosystem: npm
      package: risky
      artifact_digest: "{digest}"
      findings: [integrity_failure]
      action: quarantine
"#
    );
    let policy: PolicyConfiguration = serde_yaml_ng::from_str(&yaml).unwrap();
    let diagnostics = policy.validate().unwrap_err().into_diagnostics();
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.path == "policy.packages.finding_actions[0].action" })
    );
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.path == "policy.packages.exceptions[0].action" })
    );
}
