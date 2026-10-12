#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::{TempDir, tempdir};

const MOCK_GH: &str = r#"#!/usr/bin/env bash
set -euo pipefail
printf 'gh' >>"$RELEASE_TEST_TRACE"
printf ' %s' "$@" >>"$RELEASE_TEST_TRACE"
printf '\n' >>"$RELEASE_TEST_TRACE"

case "$1 $2" in
    "auth status") ;;
    "repo view")
        if [[ "$RELEASE_TEST_SCENARIO" == wrong_repo ]]; then
            printf 'example/another-repository\n'
        else
            printf 'mbianchidev/sendbox\n'
        fi
        ;;
    "pr create") printf 'https://github.com/mbianchidev/sendbox/pull/1\n' ;;
    "pr view")
        if [[ "$*" == *statusCheckRollup* ]]; then
            if [[ "$RELEASE_TEST_SCENARIO" == no_checks ]]; then
                printf '0\n'
            elif [[ ! -f "$RELEASE_TEST_STATE/checks" ]]; then
                touch "$RELEASE_TEST_STATE/checks"
                printf '0\n'
            else
                printf '2\n'
            fi
        else
            head="$(git -C "$RELEASE_TEST_ORIGIN" rev-parse release/v0.2.0)"
            if [[ "$*" == *mergeCommit* ]]; then
                printf 'MERGED\t%s\t%s\n' "$head" "$(cat "$RELEASE_TEST_STATE/merge")"
            elif [[ "$RELEASE_TEST_SCENARIO" == changed_head ]]; then
                printf '%040d\n' 0
            else
                printf '%s\n' "$head"
            fi
        fi
        ;;
    "pr checks")
        if [[ "$RELEASE_TEST_SCENARIO" == ci_failure ]]; then
            printf 'Mock CI failed\n' >&2
            exit 1
        fi
        ;;
    "pr merge")
        head="$(git -C "$RELEASE_TEST_ORIGIN" rev-parse release/v0.2.0)"
        [[ " $* " == *" --match-head-commit $head "* ]]
        git -C "$RELEASE_TEST_ORIGIN" merge --quiet --no-ff --no-commit release/v0.2.0
        if [[ "$RELEASE_TEST_SCENARIO" == version_mismatch ]]; then
            git -C "$RELEASE_TEST_ORIGIN" show release/v0.2.0:Cargo.toml \
                | sed 's/0\.2\.0/9.9.9/' >"$RELEASE_TEST_ORIGIN/Cargo.toml"
            git -C "$RELEASE_TEST_ORIGIN" add Cargo.toml
        fi
        git -C "$RELEASE_TEST_ORIGIN" commit --quiet --no-gpg-sign -m "Merge release"
        git -C "$RELEASE_TEST_ORIGIN" rev-parse HEAD >"$RELEASE_TEST_STATE/merge"
        git -C "$RELEASE_TEST_ORIGIN" commit --quiet --no-gpg-sign --allow-empty \
            -m "Later main commit"
        ;;
    "run list")
        [[ " $* " == *" --workflow release.yaml "* ]]
        [[ " $* " == *" --event push "* ]]
        [[ " $* " == *" --branch v0.2.0 "* ]]
        [[ " $* " == *" --commit $(cat "$RELEASE_TEST_STATE/merge") "* ]]
        if [[ "$RELEASE_TEST_SCENARIO" == no_release_run ]]; then
            exit 0
        elif [[ ! -f "$RELEASE_TEST_STATE/run" ]]; then
            touch "$RELEASE_TEST_STATE/run"
        else
            printf '123\n'
        fi
        ;;
    "run watch")
        [[ " $* " == *" --exit-status "* ]]
        if [[ "$RELEASE_TEST_SCENARIO" == release_failure ]]; then
            printf 'Mock Release workflow failed\n' >&2
            exit 1
        fi
        ;;
    "release view") printf 'https://github.com/mbianchidev/sendbox/releases/tag/v0.2.0\n' ;;
    *)
        printf 'Unexpected GitHub command: %s\n' "$*" >&2
        exit 1
        ;;
esac
"#;

struct ReleaseRepository {
    _directory: TempDir,
    checkout: PathBuf,
    origin: PathBuf,
    bin: PathBuf,
    state: PathBuf,
    trace: PathBuf,
    temporary: PathBuf,
}

fn write(path: impl AsRef<Path>, contents: &str) {
    let path = path.as_ref();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn executable(path: impl AsRef<Path>, contents: &str) {
    write(&path, contents);
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn output(mut command: Command) -> String {
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{command:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

fn git(directory: &Path, arguments: &[&str]) -> String {
    let mut command = Command::new("git");
    command
        .current_dir(directory)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(arguments);
    output(command)
}

impl ReleaseRepository {
    fn new() -> Self {
        let directory = tempdir().unwrap();
        let origin = directory.path().join("origin");
        let checkout = directory.path().join("checkout");
        let bin = directory.path().join("bin");
        let state = directory.path().join("state");
        let trace = directory.path().join("trace");
        let temporary = directory.path().join("temporary");
        for path in [&origin, &bin, &state, &temporary] {
            fs::create_dir(path).unwrap();
        }
        git(&origin, &["init", "--quiet", "--initial-branch", "main"]);
        git(&origin, &["config", "user.name", "Release Test"]);
        git(
            &origin,
            &["config", "user.email", "release@example.invalid"],
        );
        write(
            origin.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/sendbox-cli", "crates/sendbox-common"]
resolver = "2"

[workspace.package]
version = "0.1.0" # release version
edition = "2021"
"#,
        );
        for name in ["sendbox-cli", "sendbox-common"] {
            write(
                origin.join(format!("crates/{name}/Cargo.toml")),
                &format!(
                    "[package]\nname = \"{name}\"\nversion.workspace = true\nedition.workspace = true\n"
                ),
            );
            write(origin.join(format!("crates/{name}/src/lib.rs")), "");
        }
        write(
            origin.join("crates/sendbox-cli/tests/cli.rs"),
            r#"#[test]
fn prints_version() {
    let stdout = String::new();
    assert_eq!(stdout, "sendbox 0.1.0\n");
}
"#,
        );
        for (path, name, version) in [
            ("fuzz/example", "sendbox-fuzz-example", "0.0.0"),
            ("tools/qualification", "sendbox-qualification", "0.1.0"),
            ("spikes/example", "sendbox-spike-example", "0.1.0"),
        ] {
            write(
                origin.join(format!("{path}/Cargo.toml")),
                &format!(
                    "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n\n\
                     [dependencies]\nsendbox-common = {{ path = \"../../crates/sendbox-common\" }}\n\n\
                     [workspace]\nmembers = [\".\"]\n"
                ),
            );
            write(origin.join(format!("{path}/src/lib.rs")), "");
        }
        fs::create_dir(origin.join("scripts")).unwrap();
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/release.sh"),
            origin.join("scripts/release.sh"),
        )
        .unwrap();
        for manifest in [
            "Cargo.toml",
            "fuzz/example/Cargo.toml",
            "tools/qualification/Cargo.toml",
            "spikes/example/Cargo.toml",
        ] {
            let mut command = Command::new(env!("CARGO"));
            command.current_dir(&origin).args([
                "generate-lockfile",
                "--offline",
                "--manifest-path",
                manifest,
            ]);
            output(command);
        }
        git(&origin, &["add", "."]);
        git(
            &origin,
            &[
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "Initial fixture",
            ],
        );
        git(
            directory.path(),
            &[
                "clone",
                "--quiet",
                origin.to_str().unwrap(),
                checkout.to_str().unwrap(),
            ],
        );
        git(&checkout, &["config", "user.name", "Release Test"]);
        git(
            &checkout,
            &["config", "user.email", "release@example.invalid"],
        );
        git(&checkout, &["config", "commit.gpgsign", "true"]);
        git(&checkout, &["config", "tag.gpgsign", "true"]);
        git(&checkout, &["switch", "--quiet", "-c", "unrelated-feature"]);
        executable(bin.join("gh"), MOCK_GH);
        executable(bin.join("sleep"), "#!/bin/sh\nexit 0\n");
        executable(
            bin.join("cargo"),
            r#"#!/usr/bin/env bash
set -euo pipefail
printf 'cargo' >>"$RELEASE_TEST_TRACE"
printf ' %s' "$@" >>"$RELEASE_TEST_TRACE"
printf '\n' >>"$RELEASE_TEST_TRACE"
if [[ "$RELEASE_TEST_SCENARIO" == lock_failure && "$1" == update && "$*" == *fuzz/example* ]]; then
    printf 'Mock lockfile refresh failed\n' >&2
    exit 1
fi
exec "$RELEASE_TEST_CARGO" "$@"
"#,
        );
        Self {
            _directory: directory,
            checkout,
            origin,
            bin,
            state,
            trace,
            temporary,
        }
    }

    fn run(&self, arguments: &[&str], scenario: &str) -> Output {
        let path = std::env::join_paths(
            std::iter::once(self.bin.clone())
                .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        Command::new("bash")
            .arg(self.checkout.join("scripts/release.sh"))
            .args(arguments)
            .current_dir(self.checkout.join("crates/sendbox-cli"))
            .env("PATH", path)
            .env("TMPDIR", &self.temporary)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("CARGO_NET_OFFLINE", "true")
            .env("RELEASE_TEST_CARGO", env!("CARGO"))
            .env("RELEASE_TEST_ORIGIN", &self.origin)
            .env("RELEASE_TEST_STATE", &self.state)
            .env("RELEASE_TEST_TRACE", &self.trace)
            .env("RELEASE_TEST_SCENARIO", scenario)
            .output()
            .unwrap()
    }

    fn trace(&self) -> String {
        match fs::read_to_string(&self.trace) {
            Ok(trace) => trace,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!("could not read command trace: {error}"),
        }
    }

    fn assert_failed(&self, result: &Output, message: &str) {
        assert!(!result.status.success(), "release unexpectedly succeeded");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(message),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }

    fn assert_no_tag(&self) {
        assert!(git(&self.origin, &["tag", "--list", "v0.2.0"]).is_empty());
    }
}

#[test]
fn releases_the_merged_commit_and_refreshes_every_lockfile_without_switching_the_caller() {
    let repository = ReleaseRepository::new();
    let original_head = git(&repository.checkout, &["rev-parse", "HEAD"]);
    let result = repository.run(&["0.2.0"], "success");
    assert!(
        result.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let merge = fs::read_to_string(repository.state.join("merge")).unwrap();
    let tag = git(
        &repository.origin,
        &["rev-parse", "refs/tags/v0.2.0^{commit}"],
    );
    assert_eq!(tag, merge.trim());
    assert_ne!(tag, git(&repository.origin, &["rev-parse", "main"]));
    assert_eq!(
        git(&repository.origin, &["cat-file", "-t", "refs/tags/v0.2.0"]),
        "tag"
    );
    for lock in [
        "Cargo.lock",
        "fuzz/example/Cargo.lock",
        "tools/qualification/Cargo.lock",
        "spikes/example/Cargo.lock",
    ] {
        let contents = git(&repository.origin, &["show", &format!("v0.2.0:{lock}")]);
        assert!(
            contents.contains("name = \"sendbox-common\"\nversion = \"0.2.0\""),
            "{lock} was not refreshed: {contents}"
        );
    }
    assert!(
        git(
            &repository.origin,
            &["show", "v0.2.0:tools/qualification/Cargo.lock"]
        )
        .contains("name = \"sendbox-qualification\"\nversion = \"0.1.0\"")
    );
    assert!(
        git(
            &repository.origin,
            &["show", "v0.2.0:crates/sendbox-cli/tests/cli.rs"]
        )
        .contains("\"sendbox 0.2.0\\n\"")
    );
    assert_eq!(
        git(&repository.checkout, &["branch", "--show-current"]),
        "unrelated-feature"
    );
    assert_eq!(
        git(&repository.checkout, &["rev-parse", "HEAD"]),
        original_head
    );
    assert!(git(&repository.checkout, &["status", "--porcelain"]).is_empty());
    assert_eq!(fs::read_dir(&repository.temporary).unwrap().count(), 0);
    let trace = repository.trace();
    assert!(trace.find("gh pr checks").unwrap() < trace.find("gh pr merge").unwrap());
    assert!(trace.find("gh pr merge").unwrap() < trace.find("gh run watch").unwrap());
    assert!(trace.contains("gh release view v0.2.0"));
}

#[test]
fn rejects_invalid_versions_without_creating_a_release_branch() {
    let repository = ReleaseRepository::new();
    for version in ["", "0.2", "00.2.0", "0.2.0+build", "0.2.0;echo unsafe"] {
        let result = repository.run(&[version], "success");
        repository.assert_failed(&result, "version");
    }
    assert!(git(&repository.checkout, &["branch", "--list", "release/v*"]).is_empty());
    assert!(repository.trace().is_empty());
}

#[test]
fn rejects_a_dirty_checkout_and_non_increasing_versions() {
    let repository = ReleaseRepository::new();
    for version in ["0.1.0", "0.0.9"] {
        let result = repository.run(&[version], "success");
        repository.assert_failed(&result, "greater");
    }
    write(repository.checkout.join("uncommitted.txt"), "keep this\n");
    let result = repository.run(&["0.2.0"], "success");
    repository.assert_failed(&result, "clean");
    assert_eq!(
        fs::read_to_string(repository.checkout.join("uncommitted.txt")).unwrap(),
        "keep this\n"
    );
    assert!(!repository.trace().contains("gh pr create"));
}

#[test]
fn refuses_to_merge_when_ci_fails_or_never_starts_or_the_head_changes() {
    for (scenario, message) in [
        ("ci_failure", "Mock CI failed"),
        ("no_checks", "checks"),
        ("changed_head", "changed"),
    ] {
        let repository = ReleaseRepository::new();
        let result = repository.run(&["0.2.0"], scenario);
        repository.assert_failed(&result, message);
        assert!(!repository.trace().contains("gh pr merge"));
        repository.assert_no_tag();
        assert_eq!(fs::read_dir(&repository.temporary).unwrap().count(), 0);
    }
}

#[test]
fn refuses_to_tag_a_merge_with_a_different_cargo_version() {
    let repository = ReleaseRepository::new();
    let result = repository.run(&["0.2.0"], "version_mismatch");
    repository.assert_failed(&result, "does not match");
    repository.assert_no_tag();
}

#[test]
fn reports_a_missing_or_failed_release_workflow_after_pushing_the_tag() {
    for (scenario, message) in [
        ("no_release_run", "Release workflow"),
        ("release_failure", "Mock Release workflow failed"),
    ] {
        let repository = ReleaseRepository::new();
        let result = repository.run(&["0.2.0"], scenario);
        repository.assert_failed(&result, message);
        assert_eq!(git(&repository.origin, &["tag", "--list"]), "v0.2.0");
        assert!(!repository.trace().contains("gh release view"));
    }
}

#[test]
fn refuses_an_existing_tag_or_a_different_repository() {
    let repository = ReleaseRepository::new();
    let result = repository.run(&["0.2.0"], "wrong_repo");
    repository.assert_failed(&result, "origin");
    git(&repository.origin, &["tag", "v0.2.0"]);
    let result = repository.run(&["0.2.0"], "success");
    repository.assert_failed(&result, "already exists");
    assert!(!repository.trace().contains("gh pr create"));
}

#[test]
fn refuses_multiple_push_urls_without_pushing_a_release_branch() {
    let repository = ReleaseRepository::new();
    for path in [&repository.origin, &repository.state] {
        git(
            &repository.checkout,
            &[
                "remote",
                "set-url",
                "--add",
                "--push",
                "origin",
                path.to_str().unwrap(),
            ],
        );
    }
    let result = repository.run(&["0.2.0"], "success");
    repository.assert_failed(&result, "exactly one push URL");
    assert!(!repository.trace().contains("gh pr create"));
    assert!(git(&repository.origin, &["branch", "--list", "release/v*"]).is_empty());
}

#[test]
fn refuses_an_unexpected_version_assertion_without_partially_editing_files() {
    let repository = ReleaseRepository::new();
    write(
        repository.origin.join("crates/sendbox-cli/tests/cli.rs"),
        "// missing version assertion\n",
    );
    git(
        &repository.origin,
        &["add", "crates/sendbox-cli/tests/cli.rs"],
    );
    git(
        &repository.origin,
        &[
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "Unexpected version assertion",
        ],
    );
    let result = repository.run(&["0.2.0"], "success");
    repository.assert_failed(&result, "CLI version assertion");
    assert_eq!(fs::read_dir(&repository.temporary).unwrap().count(), 0);
    assert!(!repository.trace().contains("gh pr create"));
    repository.assert_no_tag();
}

#[test]
fn preserves_uncommitted_version_changes_when_lockfile_refresh_fails() {
    let repository = ReleaseRepository::new();
    let result = repository.run(&["0.2.0"], "lock_failure");
    repository.assert_failed(&result, "Mock lockfile refresh failed");
    repository.assert_failed(&result, "worktree retained for recovery");
    let temporary = fs::read_dir(&repository.temporary)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let manifest = fs::read_to_string(temporary.join("checkout/Cargo.toml")).unwrap();
    assert!(manifest.contains("version = \"0.2.0\" # release version"));
    assert!(
        fs::read_to_string(repository.checkout.join("Cargo.toml"))
            .unwrap()
            .contains("version = \"0.1.0\"")
    );
    assert!(!repository.trace().contains("gh pr create"));
    repository.assert_no_tag();
}
