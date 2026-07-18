use std::fs;
use std::path::PathBuf;

use sendbox_policy::{Action, BoundaryPolicy, PolicyConfiguration};

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
