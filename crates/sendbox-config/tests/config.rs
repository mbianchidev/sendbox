use std::fs;
use std::path::PathBuf;

use proptest::prelude::*;
use sendbox_config::{AtomicWriteMode, PolicyPreset, RuntimeProvider, SandboxConfiguration};
use sendbox_core::DiagnosticCode;
use sendbox_policy::Action;
use tempfile::tempdir;

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
    // The example predates the egress extensions: its network block carries
    // no networks/ports/dns keys, so they must resolve to serde defaults.
    assert!(config.policy.network.allowed_networks.is_empty());
    assert!(config.policy.network.allowed_ports.is_empty());
    assert_eq!(
        config.policy.network.dns,
        sendbox_policy::DnsPolicy::default()
    );
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
fn canonical_yaml_round_trips_with_snake_case_and_omitted_options() {
    let config = SandboxConfiguration::for_project(
        PathBuf::from("/projects/example"),
        PolicyPreset::Default,
        RuntimeProvider::Auto,
    );
    let first = config.to_canonical_yaml().unwrap();
    let second = config.to_canonical_yaml().unwrap();
    let decoded = SandboxConfiguration::parse(&first).unwrap();

    assert_eq!(first, second);
    assert_eq!(decoded, config);
    assert!(first.contains("project_path: /projects/example\n"));
    assert!(first.contains("memory_mb: 4096\n"));
    assert!(first.contains("default_action: deny\n"));
    assert!(!first.contains("projectPath"));
    assert!(!first.contains(": null"));
}

#[test]
fn migration_accepts_implicit_and_explicit_v1_and_rejects_future_versions() {
    let implicit =
        fs::read_to_string(workspace_path("test-fixtures/config/partial-runtime.yaml")).unwrap();
    let implicit_result = SandboxConfiguration::migrate(&implicit).unwrap();
    assert_eq!(implicit_result.migration.source_version, 1);
    assert!(!implicit_result.migration.explicit_source_version);
    assert!(!implicit_result.migration.schema_changed);
    assert!(implicit_result.migration.canonicalized);

    let explicit = format!("schema_version: 1\n{implicit}");
    let explicit_result = SandboxConfiguration::migrate(&explicit).unwrap();
    assert!(explicit_result.migration.explicit_source_version);
    assert_eq!(explicit_result.configuration, implicit_result.configuration);
    assert!(!explicit_result.yaml.contains("schema_version"));

    let future = explicit.replacen("schema_version: 1", "schema_version: 2", 1);
    let error = SandboxConfiguration::migrate(&future).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported configuration schema version 2")
    );
}

#[test]
fn secure_atomic_write_refuses_existing_files_and_replaces_explicitly() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let mut config = SandboxConfiguration::for_project(
        PathBuf::from("/projects/one"),
        PolicyPreset::Default,
        RuntimeProvider::Auto,
    );

    config.write(&path, AtomicWriteMode::CreateNew).unwrap();
    let original = fs::read_to_string(&path).unwrap();
    let error = config.write(&path, AtomicWriteMode::CreateNew).unwrap_err();
    assert_eq!(error.diagnostic().code, DiagnosticCode::Io);
    assert_eq!(fs::read_to_string(&path).unwrap(), original);

    config.name = "replacement".to_owned();
    config.write(&path, AtomicWriteMode::Replace).unwrap();
    let replaced = fs::read_to_string(&path).unwrap();
    assert!(replaced.starts_with("name: replacement\n"));
}

#[cfg(unix)]
#[test]
fn configuration_files_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    SandboxConfiguration::for_project(
        PathBuf::from("/projects/private"),
        PolicyPreset::Strict,
        RuntimeProvider::Kata,
    )
    .write(&path, AtomicWriteMode::CreateNew)
    .unwrap();

    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn invalid_configuration_is_not_written() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let mut config = SandboxConfiguration::for_project(
        PathBuf::from("/projects/invalid"),
        PolicyPreset::Default,
        RuntimeProvider::Auto,
    );
    config.resources.cpus = 0;

    let error = config.write(&path, AtomicWriteMode::CreateNew).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("configuration validation failed")
    );
    assert!(!path.exists());
}

proptest! {
    #[test]
    fn generated_configs_round_trip_through_yaml(
        name in "[a-z][a-z0-9-]{0,31}",
        cpus in 1_i64..64,
        memory_mb in 1_i64..131_072,
        disk_size_mb in 1_i64..1_048_576,
        preset_index in 0_u8..3,
        runtime_index in 0_u8..4,
    ) {
        let preset = match preset_index {
            0 => PolicyPreset::Default,
            1 => PolicyPreset::Permissive,
            _ => PolicyPreset::Strict,
        };
        let runtime = match runtime_index {
            0 => RuntimeProvider::Auto,
            1 => RuntimeProvider::Apple,
            2 => RuntimeProvider::Kata,
            _ => RuntimeProvider::Hyperlight,
        };
        let mut config = SandboxConfiguration::for_project(
            PathBuf::from(format!("/projects/{name}")),
            preset,
            runtime,
        );
        config.name = name;
        config.resources.cpus = cpus;
        config.resources.memory_mb = memory_mb;
        config.resources.disk_size_mb = disk_size_mb;

        let yaml = config.to_canonical_yaml().unwrap();
        let decoded = SandboxConfiguration::parse(&yaml).unwrap();
        prop_assert_eq!(decoded, config);
    }
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
