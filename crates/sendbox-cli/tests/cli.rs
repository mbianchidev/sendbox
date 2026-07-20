use std::path::PathBuf;
use std::process::{Command, Output};

use sendbox_config::SandboxConfiguration;
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

fn run_in(arguments: &[&str], current_dir: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sendbox-rs"))
        .current_dir(current_dir)
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn prints_version() {
    let output = run(&["--version"]);

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "sendbox 0.1.0\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn root_help_uses_the_final_command_name_and_only_implemented_surfaces() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Usage: sendbox <COMMAND>"));
    for command in ["analyze", "completions", "devcontainer", "init", "policy"] {
        assert!(stdout.contains(command));
    }
    for deferred in ["run", "secret", "mcp", "boundary"] {
        assert!(
            !stdout
                .lines()
                .any(|line| line.trim_start().starts_with(deferred))
        );
    }
}

#[test]
fn init_writes_a_private_valid_config_and_json_result() {
    use std::os::unix::fs::PermissionsExt;

    let project = tempdir().unwrap();
    let output = run_in(
        &[
            "init",
            "--project",
            project.path().to_str().unwrap(),
            "--policy",
            "strict",
            "--runtime",
            "kata",
            "--json",
        ],
        project.path(),
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["policy"], "strict");
    assert_eq!(result["runtime"], "kata");
    let path = project.path().canonicalize().unwrap().join(".sendbox.yaml");
    assert_eq!(result["config"], path.display().to_string());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let config = SandboxConfiguration::load(path).unwrap();
    config.validate().unwrap();
    assert_eq!(config.policy.network.max_connections, Some(10));
}

#[test]
fn init_refuses_to_overwrite_an_existing_configuration() {
    let project = tempdir().unwrap();
    let path = project.path().join(".sendbox.yaml");
    std::fs::write(&path, "keep me\n").unwrap();
    let output = run_in(
        &[
            "init",
            "--project",
            project.path().to_str().unwrap(),
            "--json",
        ],
        project.path(),
    );
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "keep me\n");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["exit_code"], 4);
    assert_eq!(result["diagnostics"][0]["code"], "io");
    assert!(
        result["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("refusing to overwrite")
    );
}

#[test]
fn init_rejects_invalid_project_paths_with_stable_exit() {
    let output = run(&["init", "--project", "does-not-exist", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["exit_code"], 2);
    assert_eq!(result["diagnostics"][0]["code"], "invalid_path");
}

#[cfg(unix)]
#[test]
fn init_rejects_unreadable_project_directories_before_writing() {
    use std::os::unix::fs::PermissionsExt;

    let project = tempdir().unwrap();
    std::fs::set_permissions(project.path(), std::fs::Permissions::from_mode(0o300)).unwrap();
    let output = run(&[
        "init",
        "--project",
        project.path().to_str().unwrap(),
        "--json",
    ]);
    std::fs::set_permissions(project.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["diagnostics"][0]["code"], "invalid_path");
    assert!(
        result["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("readable and searchable")
    );
    assert!(!project.path().join(".sendbox.yaml").exists());
}

#[test]
fn hyperlight_init_produces_a_valid_compatible_configuration() {
    let project = tempdir().unwrap();
    let output = run_in(
        &[
            "init",
            "--project",
            project.path().to_str().unwrap(),
            "--runtime",
            "hyperlight",
        ],
        project.path(),
    );
    assert!(output.status.success());
    let config =
        SandboxConfiguration::load(project.path().canonicalize().unwrap().join(".sendbox.yaml"))
            .unwrap();
    config.validate().unwrap();
    assert!(!config.policy.boundaries.enabled);
    assert!(!config.github.branch_protection.enabled);
    assert!(
        config
            .policy
            .network
            .allowed_domains
            .iter()
            .all(|domain| !domain.contains('*'))
    );
}

#[test]
fn policy_show_has_stable_text_and_deterministic_json() {
    let text = run(&["policy", "show"]);
    assert!(text.status.success());
    assert!(text.stderr.is_empty());
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(stdout.starts_with("default policy\n\nCommand Policy:\n"));
    assert!(stdout.contains("\nNetwork Policy:\n"));
    assert!(stdout.contains("\nBoundary Policy:\n"));

    let first = run(&["policy", "show", "--json"]);
    let second = run(&["policy", "show", "--json"]);
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    let result: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(result["source"], "default");
    assert_eq!(result["policy"]["commands"]["default_action"], "deny");
    assert_eq!(result["migration"], Value::Null);
}

#[test]
fn policy_show_reads_versioned_v1_without_rejecting_unrelated_validation() {
    let directory = tempdir().unwrap();
    let fixture =
        std::fs::read_to_string(workspace_root().join("config/example-sandbox.yaml")).unwrap();
    let fixture = fixture
        .replacen(
            "name: my-project-sandbox",
            "schema_version: 1\nname: shown",
            1,
        )
        .replacen(
            "project_path: /Users/developer/my-project",
            "project_path: relative/is-allowed-for-policy-show",
            1,
        );
    let path = directory.path().join("config.yaml");
    std::fs::write(&path, fixture).unwrap();
    let output = run(&[
        "policy",
        "show",
        "--config",
        path.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["source"], "config");
    assert_eq!(result["migration"]["source_version"], 1);
    assert_eq!(result["migration"]["explicit_source_version"], true);
}

#[test]
fn completion_scripts_are_generated_from_the_sendbox_command_tree() {
    for shell in ["bash", "zsh", "fish"] {
        let first = run(&["completions", "print", "--shell", shell]);
        let second = run(&["completions", "print", "--shell", shell]);
        assert!(first.status.success(), "{shell}");
        assert_eq!(first.stdout, second.stdout, "{shell}");
        assert!(first.stderr.is_empty(), "{shell}");
        let script = String::from_utf8(first.stdout).unwrap();
        assert!(script.contains("sendbox"), "{shell}");
        assert!(script.contains("completions"), "{shell}");
        assert!(script.contains("policy"), "{shell}");
        assert!(script.contains("init"), "{shell}");
        assert!(!script.contains("sendbox-rs"), "{shell}");
    }
}

#[cfg(unix)]
#[test]
fn completion_install_uses_stable_path_and_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempdir().unwrap();
    let canonical_home = home.path().canonicalize().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sendbox-rs"))
        .args(["completions", "install", "--shell", "fish", "--json"])
        .env("HOME", &canonical_home)
        .env("SHELL", "/bin/fish")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let path = canonical_home.join(".config/fish/completions/sendbox.fish");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["path"], path.display().to_string());
    assert_eq!(result["shell"], "fish");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(std::fs::read_to_string(path).unwrap().contains("sendbox"));
}

#[test]
fn completion_install_detects_shell_without_spawning_it() {
    let home = tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let fake_shell = home.join("zsh");
    std::fs::write(&fake_shell, "this is not executable\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sendbox-rs"))
        .args(["completions", "install", "--json"])
        .env("HOME", &home)
        .env("SHELL", &fake_shell)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(home.join(".zsh/completions/_sendbox").exists());
}

#[test]
fn completion_detection_falls_back_to_zsh_and_explicit_unknown_shell_is_rejected() {
    let home = tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let fallback = Command::new(env!("CARGO_BIN_EXE_sendbox-rs"))
        .args(["completions", "install", "--json"])
        .env("HOME", &home)
        .env("SHELL", "/bin/tcsh")
        .output()
        .unwrap();
    assert!(fallback.status.success());
    assert!(home.join(".zsh/completions/_sendbox").exists());

    let unknown = run(&["completions", "install", "--shell", "powershell", "--json"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(unknown.stdout.is_empty());
    assert!(
        String::from_utf8(unknown.stderr)
            .unwrap()
            .contains("invalid value 'powershell'")
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
