use std::path::PathBuf;

use sendbox_config::{RuntimeProvider, SandboxConfiguration};
use sendbox_core::DiagnosticCode;
use sendbox_policy::Action;

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn load_fixture(name: &str) -> SandboxConfiguration {
    SandboxConfiguration::load(workspace_path(&format!("test-fixtures/config/{name}"))).unwrap()
}

#[test]
fn loads_current_example_configuration() {
    let config = SandboxConfiguration::load(workspace_path("config/example-sandbox.yaml")).unwrap();

    config.validate().unwrap();
    assert_eq!(config.name, "my-project-sandbox");
    assert_eq!(
        config.runtime.as_ref().unwrap().provider,
        RuntimeProvider::Auto
    );
    assert_eq!(config.policy.commands.default_action, Action::Deny);
    assert_eq!(
        config.policy.boundaries.tool_calls.max_frame_bytes,
        1_048_576
    );
    assert!(config.github.branch_protection.enabled);
}

#[test]
fn represents_every_shipped_configuration_section() {
    let config = load_fixture("full-schema.yaml");

    config.validate().unwrap();
    assert_eq!(
        config.runtime.as_ref().unwrap().kata.namespace,
        "sendbox-tests"
    );
    assert_eq!(config.devcontainer.as_ref().unwrap().extensions.len(), 1);
    assert_eq!(
        config
            .observability
            .as_ref()
            .unwrap()
            .mcp_inspection
            .max_payload_bytes,
        32_768
    );
}

#[test]
fn applies_partial_runtime_defaults() {
    let config = load_fixture("partial-runtime.yaml");
    let runtime = config.runtime.unwrap();

    assert_eq!(runtime.provider, RuntimeProvider::Kata);
    assert_eq!(runtime.kata.executable, "nerdctl");
    assert_eq!(runtime.kata.runtime_handler, "io.containerd.kata.v2");
    assert_eq!(runtime.kata.namespace, "sendbox");
}

#[test]
fn applies_nested_boundary_defaults() {
    let config = load_fixture("partial-boundaries.yaml");

    assert!(config.policy.boundaries.enabled);
    assert_eq!(
        config.policy.boundaries.tool_calls.allowlist,
        ["read_*".to_owned()]
    );
    assert_eq!(
        config.policy.boundaries.tool_calls.default_action,
        Action::Deny
    );
    assert!(config.policy.boundaries.syscalls.log_blocked);
}

#[test]
fn applies_partial_branch_protection_defaults() {
    let config = load_fixture("partial-branch-protection.yaml");
    let branch = config.github.branch_protection;

    assert!(branch.enabled);
    assert_eq!(branch.username.as_deref(), Some("octocat"));
    assert_eq!(branch.protected_branches, ["main", "master"]);
    assert_eq!(
        branch.allowed_branch_patterns,
        ["{username}/*", "copilot/*", "feature/*"]
    );
}

#[test]
fn canonical_json_round_trips_deterministically() {
    let config = load_fixture("full-schema.yaml");
    let first = config.to_canonical_json().unwrap();
    let second = config.to_canonical_json().unwrap();
    let decoded: SandboxConfiguration = serde_json::from_str(&first).unwrap();

    assert_eq!(first, second);
    assert_eq!(decoded, config);
}

#[test]
fn rejects_unknown_fields_instead_of_ignoring_them() {
    let error = SandboxConfiguration::load(workspace_path(
        "test-fixtures/config/invalid-unknown-field.yaml",
    ))
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("unknown field `unexpected_section`")
    );
}

#[test]
fn rejects_invalid_runtime_enums() {
    let error = SandboxConfiguration::load(workspace_path(
        "test-fixtures/config/invalid-runtime-provider.yaml",
    ))
    .unwrap_err();

    assert!(error.to_string().contains("unknown variant `docker`"));
}

#[test]
fn rejects_non_positive_resources_with_field_diagnostics() {
    let diagnostics = load_fixture("invalid-zero-resources.yaml")
        .validate()
        .unwrap_err()
        .into_diagnostics();

    for path in [
        "resources.cpus",
        "resources.memory_mb",
        "resources.disk_size_mb",
    ] {
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == DiagnosticCode::InvalidValue && diagnostic.path == path
        }));
    }
}

#[test]
fn rejects_invalid_boundary_frame_size() {
    let diagnostics = load_fixture("invalid-boundary-frame.yaml")
        .validate()
        .unwrap_err()
        .into_diagnostics();

    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.path == "policy.boundaries.tool_calls.max_frame_bytes"
            && diagnostic.message.contains("greater than zero")
    }));
}

#[test]
fn rejects_relative_required_project_path() {
    let diagnostics = load_fixture("invalid-relative-project-path.yaml")
        .validate()
        .unwrap_err()
        .into_diagnostics();

    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::InvalidPath && diagnostic.path == "project_path"
    }));
}

#[test]
fn rejects_hyperlight_with_boundaries() {
    let diagnostics = load_fixture("invalid-hyperlight-boundaries.yaml")
        .validate()
        .unwrap_err()
        .into_diagnostics();

    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::IncompatibleConfiguration
            && diagnostic.message.contains("hyperlight requires")
    }));
}

#[test]
fn rejects_branch_protection_without_boundaries() {
    let diagnostics = load_fixture("invalid-branch-without-boundaries.yaml")
        .validate()
        .unwrap_err()
        .into_diagnostics();

    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.path == "github.branch_protection.enabled"
            && diagnostic
                .message
                .contains("requires policy.boundaries.enabled")
    }));
}
