use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

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
