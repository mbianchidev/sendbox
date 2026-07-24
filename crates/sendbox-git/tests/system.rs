#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

use sendbox_git::{
    Admission, BranchPolicyConfiguration, EnvironmentPolicy, GitProcessRunner, GuardError,
    GuardLimits, GuardPolicyDocument, GuardService, PolicySchemaVersion, ProcessRequest,
    RepositoryIdentity, SystemGitProcessRunner, TrustedGitBinary,
};

fn git_path() -> PathBuf {
    ["/usr/bin/git", "/bin/git"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("system Git")
}

fn run_git(directory: &Path, arguments: &[&str]) {
    let status = Command::new(git_path())
        .current_dir(directory)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?} failed");
}

fn repository() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    run_git(root.path(), &["init", "-b", "feature/topic"]);
    run_git(root.path(), &["config", "user.name", "SendBox Test"]);
    run_git(
        root.path(),
        &["config", "user.email", "sendbox@example.invalid"],
    );
    fs::write(root.path().join("README"), "fixture\n").unwrap();
    run_git(root.path(), &["add", "README"]);
    run_git(root.path(), &["commit", "-m", "fixture"]);
    run_git(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/project.git",
        ],
    );
    root
}

fn policy(workspace: &Path) -> GuardPolicyDocument {
    GuardPolicyDocument {
        schema_version: PolicySchemaVersion::V1,
        selected_repository: RepositoryIdentity::new("github.com", "acme", "project").unwrap(),
        selected_workspace: workspace.to_owned(),
        branch_protection: BranchPolicyConfiguration {
            username: Some("mbianchidev".to_owned()),
            ..BranchPolicyConfiguration::default()
        },
        environment: EnvironmentPolicy::default(),
        limits: GuardLimits::default(),
    }
}

#[test]
fn system_runner_observes_real_git_config_and_symlinked_workspace() {
    let repository = repository();
    let link_root = tempfile::tempdir().unwrap();
    let link = link_root.path().join("workspace-link");
    symlink(repository.path(), &link).unwrap();
    let service = GuardService::new(
        policy(repository.path()),
        TrustedGitBinary::verify(git_path()).unwrap(),
        SystemGitProcessRunner,
        &link,
        [("HOME".to_owned(), link_root.path().display().to_string())],
    )
    .unwrap();
    assert_eq!(
        service
            .admit(&strings(&[
                "-c",
                "credential.helper=",
                "push",
                "origin",
                "feature/topic",
            ]))
            .unwrap(),
        Admission::Guarded
    );
    assert!(matches!(
        service
            .admit(&strings(&[
                "-c",
                "credential.helper=",
                "-c",
                "remote.origin.pushurl=https://github.com/open-source/library.git",
                "push",
                "origin",
                "main",
            ]))
            .unwrap(),
        Admission::PassThrough { .. }
    ));

    run_git(
        repository.path(),
        &["config", "url.https://github.com/acme/.insteadOf", "gh:"],
    );
    assert!(
        service
            .admit(&strings(&[
                "-c",
                "credential.helper=",
                "push",
                "gh:project.git",
                "feature/topic:main",
            ]))
            .is_err()
    );
}

#[test]
fn system_runner_enforces_probe_timeout_and_output_bound() {
    let repository = repository();
    let script = repository.path().join("fake-git");
    fs::write(
        &script,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'git version fake\\n'; exit 0; fi\nsleep 1\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let script = fs::canonicalize(script).unwrap();
    let runner = SystemGitProcessRunner;
    let executable = TrustedGitBinary::verify(&script).unwrap();
    let environment = BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]);
    let timeout_arguments = strings(&["branch", "--show-current"]);
    let timeout = runner.query(&ProcessRequest {
        executable: &executable,
        arguments: &timeout_arguments,
        environment: &environment,
        current_directory: repository.path(),
        timeout: std::time::Duration::from_millis(20),
        output_limit: 1024,
    });
    assert!(matches!(timeout, Err(GuardError::ProbeTimeout)));

    fs::write(
        &script,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'git version fake\\n'; exit 0; fi\nprintf '0123456789\\n'\n",
    )
    .unwrap();
    let executable = TrustedGitBinary::verify(&script).unwrap();
    let output_arguments = strings(&["branch", "--show-current"]);
    let output = runner.query(&ProcessRequest {
        executable: &executable,
        arguments: &output_arguments,
        environment: &environment,
        current_directory: repository.path(),
        timeout: std::time::Duration::from_secs(1),
        output_limit: 4,
    });
    assert!(matches!(output, Err(GuardError::ProbeOutputLimit)));
}

#[test]
fn trusted_git_rejects_symlinks_and_writable_binaries() {
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("git-link");
    symlink(git_path(), &link).unwrap();
    assert!(TrustedGitBinary::verify(&link).is_err());

    let writable = root.path().join("git-writable");
    fs::copy(git_path(), &writable).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(TrustedGitBinary::verify(&writable).is_err());
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
