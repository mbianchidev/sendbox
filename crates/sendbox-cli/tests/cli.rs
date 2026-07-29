use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sendbox_config::SandboxConfiguration;
use sendbox_policy::{Action, DnsPolicy};
use serde_json::Value;
use tempfile::tempdir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sendbox"))
        .current_dir(workspace_root())
        .args(arguments)
        .output()
        .unwrap()
}

fn run_in(arguments: &[&str], current_dir: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sendbox"))
        .current_dir(current_dir)
        .args(arguments)
        .output()
        .unwrap()
}

fn run_with_home(arguments: &[&str], home: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sendbox"))
        .current_dir(workspace_root())
        .env("HOME", home)
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
    for command in [
        "analyze",
        "completions",
        "devcontainer",
        "init",
        "mcp",
        "package",
        "policy",
        "run",
        "secrets",
        "boundary",
    ] {
        assert!(stdout.contains(command));
    }

    let mcp = String::from_utf8(run(&["mcp", "--help"]).stdout).unwrap();
    assert!(mcp.contains("parse"));
    assert!(mcp.contains("report"));
    assert!(
        !mcp.lines()
            .any(|line| line.trim_start().starts_with("script"))
    );
    let boundary = String::from_utf8(run(&["boundary", "--help"]).stdout).unwrap();
    assert!(boundary.contains("inspect"));
    assert!(
        !boundary
            .lines()
            .any(|line| line.trim_start().starts_with("script"))
    );
    let run_help = String::from_utf8(run(&["run", "--help"]).stdout).unwrap();
    assert!(run_help.contains("--interactive"));
    assert!(run_help.contains("--separate-stderr"));
}

#[test]
fn separate_stderr_requires_an_interactive_run() {
    let output = run(&[
        "run",
        "--config",
        "config/example-sandbox.yaml",
        "--bundle",
        ".",
        "--trust-root",
        "Cargo.toml",
        "--separate-stderr",
        "--",
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--interactive"),
        "clap did not name the required flag: {stderr}"
    );
}

#[test]
fn package_status_and_report_read_the_latest_persisted_session() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().unwrap();
    let session_id = "a".repeat(32);
    let session = temporary
        .path()
        .join(".sendbox/run/sessions")
        .join(&session_id);
    std::fs::create_dir_all(&session).unwrap();
    let path = session.join(sendbox_host::PACKAGE_SECURITY_REPORT_FILE);
    let report = sendbox_registry::PackageSecurityReport::enabled();
    std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let status = run_with_home(&["package", "status", "--json"], temporary.path());
    assert!(status.status.success(), "{status:?}");
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["session_id"], session_id);
    assert_eq!(status["verdict"], "allow");
    assert_eq!(status["records"], 0);

    let output = run_with_home(&["package", "report", "--json"], temporary.path());
    assert!(output.status.success(), "{output:?}");
    let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, serde_json::to_value(report).unwrap());
}

#[test]
fn production_run_rejects_relative_guest_commands_deterministically() {
    let temporary = tempdir().unwrap();
    let config = temporary.path().join("sandbox.yaml");
    let source = std::fs::read_to_string(workspace_root().join("config/example-sandbox.yaml"))
        .unwrap()
        .replace("secrets:\n  - DATABASE_URL", "secrets: []");
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
        "guest command must use an absolute executable path"
    );
}

#[test]
fn production_run_no_longer_rejects_the_native_git_guard_as_unwired() {
    let temporary = tempdir().unwrap();
    let config = temporary.path().join("sandbox.yaml");
    let mut configuration =
        SandboxConfiguration::load(workspace_root().join("config/example-sandbox.yaml")).unwrap();
    configuration.secrets.clear();
    configuration.github.forward_auth = false;
    configuration.github.forward_copilot_auth = false;
    configuration.github.allow_private_repository_access = false;
    configuration.github.ssh_key_path = None;
    configuration.project_path = temporary.path().join("missing-project");
    make_network_permissive(&mut configuration);
    std::fs::write(&config, serde_json::to_vec(&configuration).unwrap()).unwrap();
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
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["message"].is_string());
    assert_ne!(
        result["message"],
        "production run does not yet wire the native Git branch guard"
    );
}

#[test]
fn production_run_no_longer_rejects_guarded_credentials_as_unwired() {
    let temporary = tempdir().unwrap();
    let config = temporary.path().join("sandbox.yaml");
    let mut configuration =
        SandboxConfiguration::load(workspace_root().join("config/example-sandbox.yaml")).unwrap();
    configuration.secrets.clear();
    configuration.project_path = temporary.path().join("missing-project");
    configuration.github.forward_auth = true;
    configuration.github.forward_copilot_auth = false;
    configuration.github.allow_private_repository_access = false;
    configuration.github.branch_protection.enabled = false;
    configuration.github.ssh_key_path = None;
    make_network_permissive(&mut configuration);
    std::fs::write(&config, serde_json::to_vec(&configuration).unwrap()).unwrap();
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
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["message"].is_string());
    assert_ne!(
        result["message"],
        "production run does not yet wire the credential broker"
    );
}

#[test]
fn production_run_no_longer_rejects_mcp_as_unwired() {
    let temporary = tempdir().unwrap();
    let config = temporary.path().join("sandbox.yaml");
    let mut configuration =
        SandboxConfiguration::load(workspace_root().join("config/example-sandbox.yaml")).unwrap();
    configuration.secrets.clear();
    configuration.project_path = temporary.path().join("missing-project");
    configuration.github.forward_auth = false;
    configuration.github.forward_copilot_auth = false;
    configuration.github.allow_private_repository_access = false;
    configuration.github.branch_protection.enabled = false;
    configuration.github.ssh_key_path = None;
    make_network_permissive(&mut configuration);
    configuration
        .observability
        .get_or_insert_with(Default::default)
        .mcp_inspection
        .enabled = true;
    std::fs::write(&config, serde_json::to_vec(&configuration).unwrap()).unwrap();

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
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(
        result["message"],
        "production run does not yet wire the native MCP subsystem"
    );
}

#[test]
fn production_run_no_longer_rejects_restrictive_egress_as_unwired() {
    let temporary = tempdir().unwrap();
    let config = temporary.path().join("sandbox.yaml");
    let mut configuration =
        SandboxConfiguration::load(workspace_root().join("config/example-sandbox.yaml")).unwrap();
    configuration.secrets.clear();
    configuration.project_path = temporary.path().join("missing-project");
    configuration.github.forward_auth = false;
    configuration.github.forward_copilot_auth = false;
    configuration.github.allow_private_repository_access = false;
    configuration.github.branch_protection.enabled = false;
    configuration.github.ssh_key_path = None;
    if let Some(observability) = &mut configuration.observability {
        observability.mcp_inspection.enabled = false;
    }
    std::fs::write(&config, serde_json::to_vec(&configuration).unwrap()).unwrap();

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
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(
        result["message"],
        "production run does not yet wire production egress enforcement"
    );
}

fn make_network_permissive(configuration: &mut SandboxConfiguration) {
    let network = &mut configuration.policy.network;
    network.default_action = Action::Allow;
    network.allowed_domains.clear();
    network.blocked_domains.clear();
    network.allowed_networks.clear();
    network.blocked_networks.clear();
    network.allowed_ports.clear();
    network.allow_dns = true;
    network.max_connections = None;
    network.dns = DnsPolicy::default();
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
        assert!(script.contains("run"), "{shell}");
    }
}

#[cfg(unix)]
#[test]
fn completion_install_uses_stable_path_and_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempdir().unwrap();
    let canonical_home = home.path().canonicalize().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sendbox"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_sendbox"))
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
    let fallback = Command::new(env!("CARGO_BIN_EXE_sendbox"))
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
        "Validating config/example-sandbox.yaml...\n✅ Configuration is valid\n"
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
fn analyze_can_write_the_swift_compatible_devcontainer_output() {
    let project = tempdir().unwrap();
    let output_root = tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"react":"19"}}"#,
    )
    .unwrap();
    let output = run_in(
        &[
            "analyze",
            "--project",
            project.path().to_str().unwrap(),
            "--output",
            output_root.path().to_str().unwrap(),
            "--json",
        ],
        project.path(),
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["language"], "node");
    let generated = output_root.path().join(".devcontainer/devcontainer.json");
    assert!(generated.is_file());
    let spec: Value = serde_json::from_slice(&std::fs::read(generated).unwrap()).unwrap();
    assert_eq!(
        spec["image"],
        "mcr.microsoft.com/devcontainers/javascript-node:1-22-bookworm"
    );
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
    let output = Command::new(env!("CARGO_BIN_EXE_sendbox"))
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn secrets_round_trip_never_prints_secret_values() {
    #[cfg(target_os = "linux")]
    let home = tempdir().unwrap();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let service = format!("com.sendbox.tests.cli.{}.{}", std::process::id(), nonce);
    let first_secret = "never-print-this-secret";
    let second_secret = "never-print-this-updated-secret";

    let command = |arguments: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sendbox"));
        command
            .args(arguments)
            .env("SENDBOX_SECRET_SERVICE", &service);
        #[cfg(target_os = "linux")]
        command.env("HOME", home.path());
        command
    };
    let write_secret = |value: &str| {
        let mut add = command(&["secrets", "add", "TEST_TOKEN", "--stdin", "--json"]);
        add.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = add.spawn().unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("{value}\n").as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let empty = write_secret("");
    assert_eq!(empty.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&empty.stdout).contains("no secret value provided"));

    let added = write_secret(first_secret);
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(added.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&added.stdout).contains(first_secret));
    let added_result: Value = serde_json::from_slice(&added.stdout).unwrap();
    assert_eq!(added_result["action"], "added");

    let updated = write_secret(second_secret);
    assert!(updated.status.success());
    let updated_stdout = String::from_utf8_lossy(&updated.stdout);
    assert!(!updated_stdout.contains(first_secret));
    assert!(!updated_stdout.contains(second_secret));
    let updated_result: Value = serde_json::from_slice(&updated.stdout).unwrap();
    assert_eq!(updated_result["action"], "updated");

    let listed = command(&["secrets", "list", "--json"]).output().unwrap();
    assert!(listed.status.success());
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(first_secret));
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(second_secret));
    let result: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(result["secrets"][0]["name"], "TEST_TOKEN");

    let removed = command(&["secrets", "remove", "TEST_TOKEN", "--json"])
        .output()
        .unwrap();
    assert!(removed.status.success());
    let removed_result: Value = serde_json::from_slice(&removed.stdout).unwrap();
    assert_eq!(removed_result["removed"], true);

    let already_absent = command(&["secrets", "remove", "TEST_TOKEN", "--json"])
        .output()
        .unwrap();
    assert!(already_absent.status.success());
    let absent_result: Value = serde_json::from_slice(&already_absent.stdout).unwrap();
    assert_eq!(absent_result["removed"], false);
}

#[test]
fn mcp_parse_and_report_use_native_bounded_observation_data() {
    let fixture = workspace_root().join("crates/sendbox-mcp/tests/fixtures/native-events-v1.log");
    let parsed = run(&[
        "mcp",
        "parse",
        fixture.to_str().unwrap(),
        "--redact",
        "--json",
    ]);
    assert!(parsed.status.success());
    assert!(parsed.stderr.is_empty());
    let calls: Value = serde_json::from_slice(&parsed.stdout).unwrap();
    assert_eq!(calls.as_array().unwrap().len(), 3);
    assert_eq!(calls[1]["method"], "tools/call");
    assert_eq!(calls[1]["subject"], "delete_file");
    assert!(!String::from_utf8_lossy(&parsed.stdout).contains("/private/project"));

    let report = run(&["mcp", "report", fixture.to_str().unwrap(), "--json"]);
    assert!(report.status.success());
    assert!(report.stderr.is_empty());
    let summary: Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(summary["total_calls"], 3);
    assert_eq!(summary["tool_call_count"], 1);
    assert_eq!(summary["error_count"], 1);
    assert_eq!(summary["tool_invocations"]["delete_file"], 1);
}

#[test]
fn boundary_inspection_is_structured_and_never_emits_executable_scripts() {
    let project = tempdir().unwrap();
    let config_path = project.path().join("sandbox.yaml");
    let configuration = SandboxConfiguration::for_project(
        project.path().canonicalize().unwrap(),
        sendbox_config::PolicyPreset::Default,
        sendbox_config::RuntimeProvider::Kata,
    );
    std::fs::write(&config_path, serde_json::to_vec(&configuration).unwrap()).unwrap();

    let output = run(&[
        "boundary",
        "inspect",
        "--config",
        config_path.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("#!/"));
    assert!(!stdout.contains("bpftrace"));
    let inspection: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        inspection["artifact_kind"],
        "sendbox.boundary-plan-inspection"
    );
    assert_eq!(inspection["generated_executables"], false);
    assert_eq!(
        inspection["observer"]["artifact_kind"],
        "sendbox.native-mcp-observer-description"
    );
}
