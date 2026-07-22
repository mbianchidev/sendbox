use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sendbox-rs"))
        .current_dir(workspace_root())
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn prints_version() {
    let output = run(&["--version"]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "sendbox-rs 0.1.0\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn experimental_run_rejects_relative_guest_commands_deterministically() {
    let temporary = tempdir().unwrap();
    let config = temporary.path().join("sandbox.yaml");
    let source = std::fs::read_to_string(workspace_root().join("config/example-sandbox.yaml"))
        .unwrap()
        .replace("secrets:\n  - NPM_TOKEN\n  - DATABASE_URL", "secrets: []");
    std::fs::write(&config, source).unwrap();
    let output = run(&[
        "run",
        "--config",
        config.to_str().unwrap(),
        "--runtime",
        "kata",
        "--image",
        "example.invalid/workload@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--bundle",
        ".",
        "--trust-root",
        "Cargo.toml",
        "--json",
        "--",
        "echo",
        "hello",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).expect("JSON error");
    assert_eq!(result["event"], "error");
    assert_eq!(result["exit_code"], 2);
    assert_eq!(
        result["message"],
        "experimental Kata command must use an absolute guest executable path"
    );
}

#[test]
fn validates_the_current_example() {
    let output = run(&[
        "policy",
        "validate",
        "--config",
        "config/example-sandbox.yaml",
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "valid configuration: config/example-sandbox.yaml (sandbox: my-project-sandbox)\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn emits_deterministic_machine_readable_output() {
    let arguments = [
        "policy",
        "validate",
        "--config",
        "config/example-sandbox.yaml",
        "--json",
    ];
    let first = run(&arguments);
    let second = run(&arguments);

    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());

    let result: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["valid"], true);
    assert_eq!(result["sandbox"], "my-project-sandbox");
    assert_eq!(result["runtime"], "auto");
    assert!(result["diagnostics"].as_array().unwrap().is_empty());
    assert_eq!(
        result["configuration"]["policy"]["commands"]["default_action"],
        "deny"
    );
}

#[test]
fn invalid_fixture_has_actionable_error_and_nonzero_exit() {
    let output = run(&[
        "policy",
        "validate",
        "--config",
        "test-fixtures/config/invalid-boundary-frame.yaml",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("policy.boundaries.tool_calls.max_frame_bytes"));
    assert!(stderr.contains("greater than zero"));
}

#[test]
fn invalid_json_result_remains_machine_readable() {
    let output = run(&[
        "policy",
        "validate",
        "--config",
        "test-fixtures/config/invalid-unknown-field.yaml",
        "--json",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["valid"], false);
    assert_eq!(result["configuration"], Value::Null);
    assert_eq!(result["diagnostics"][0]["code"], "invalid_yaml");
    assert!(
        result["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("unexpected_section")
    );
}

#[test]
fn analyzes_projects_with_stable_bridge_compatible_json() {
    let arguments = [
        "analyze",
        "--project",
        "crates/sendbox-project/tests/fixtures/node-ts",
        "--json",
    ];
    let first = run(&arguments);
    let second = run(&arguments);
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let result: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(result["language"], "typescript");
    assert_eq!(result["framework"], "Next.js");
    assert_eq!(result["packageManager"], "npm");
    assert_eq!(result["refinement"]["status"], "not_requested");
    assert!(result["scan"]["errors"].as_array().unwrap().is_empty());
}

#[test]
fn analysis_errors_use_a_stable_exit_and_json_shape() {
    let output = run(&["analyze", "--project", "does-not-exist", "--json"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["exit_code"], 3);
    assert!(
        result["error"]
            .as_str()
            .unwrap()
            .contains("could not access")
    );
}

#[test]
fn generates_and_merges_devcontainer_with_typed_overrides() {
    let project = tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"react":"19"}}"#,
    )
    .unwrap();
    std::fs::create_dir(project.path().join(".devcontainer")).unwrap();
    std::fs::write(
        project.path().join(".devcontainer/devcontainer.json"),
        r#"{
          // existing config
          "containerEnv": {"EXISTING": "true"},
          "customizations": {"vscode": {"extensions": ["example.existing",],},},
        }"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sendbox-rs"))
        .args([
            "devcontainer",
            "generate",
            "--project",
            project.path().to_str().unwrap(),
            "--image",
            "example/image:1",
            "--extension",
            "example.override",
            "--container-env",
            "OVERRIDE=true",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["mergedExisting"], true);
    assert_eq!(result["commentsPreserved"], false);
    assert_eq!(result["spec"]["image"], "example/image:1");
    assert_eq!(result["spec"]["containerEnv"]["EXISTING"], "true");
    assert_eq!(result["spec"]["containerEnv"]["OVERRIDE"], "true");
    assert!(
        result["spec"]["customizations"]["vscode"]["extensions"]
            .as_array()
            .unwrap()
            .contains(&Value::String("example.existing".to_owned()))
    );
    let written: Value = serde_json::from_slice(
        &std::fs::read(project.path().join(".devcontainer/devcontainer.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(written, result["spec"]);
}
