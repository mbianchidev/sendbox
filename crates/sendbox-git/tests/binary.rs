#![cfg(unix)]

use std::{
    fs,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Command,
};

use sendbox_git::{
    BranchPolicyConfiguration, EnvironmentPolicy, GuardLimits, GuardPolicyDocument,
    PolicySchemaVersion, RepositoryIdentity,
};

fn git_path() -> PathBuf {
    ["/usr/bin/git", "/bin/git"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("system Git")
}

fn policy(workspace: &Path) -> GuardPolicyDocument {
    GuardPolicyDocument {
        schema_version: PolicySchemaVersion::V1,
        selected_repository: RepositoryIdentity::new("github.com", "acme", "project").unwrap(),
        selected_workspace: workspace.to_owned(),
        branch_protection: BranchPolicyConfiguration::default(),
        environment: EnvironmentPolicy::default(),
        limits: GuardLimits::default(),
    }
}

#[test]
fn guard_binary_exec_preserves_git_output_and_exit_status() {
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join("policy.json");
    fs::write(
        &policy_path,
        serde_json::to_vec(&policy(root.path())).unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sendbox-git-guard"))
        .args([
            "--policy",
            policy_path.to_str().unwrap(),
            "--git",
            git_path().to_str().unwrap(),
            "--",
            "--version",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("git version "));

    let direct = Command::new(git_path())
        .args(["rev-parse", "--verify", "definitely-missing-ref"])
        .current_dir(root.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .status()
        .unwrap();
    let guarded = Command::new(env!("CARGO_BIN_EXE_sendbox-git-guard"))
        .current_dir(root.path())
        .args([
            "--policy",
            policy_path.to_str().unwrap(),
            "--git",
            git_path().to_str().unwrap(),
            "--",
            "rev-parse",
            "--verify",
            "definitely-missing-ref",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .status()
        .unwrap();
    assert_eq!(guarded.code(), direct.code());
    assert_eq!(guarded.signal(), direct.signal());
}
