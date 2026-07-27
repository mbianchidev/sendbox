use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use sendbox_git::{
    Admission, BranchPolicyConfiguration, EnvironmentPolicy, GitProcessRunner, GuardError,
    GuardLimits, GuardPolicyDocument, GuardService, PolicySchemaVersion, ProcessOutput,
    ProcessRequest, RepositoryIdentity, TrustedGitBinary, parse_invocation,
};
use tempfile::TempDir;

#[derive(Debug, Clone)]
struct FakeGit {
    state: Arc<Mutex<FakeGitState>>,
}

#[derive(Debug)]
struct FakeGitState {
    branch: String,
    repository_root: PathBuf,
    remote_urls: Vec<String>,
    upstream: Option<String>,
    push_default: Option<String>,
    aliases: BTreeMap<String, String>,
    config_values: BTreeMap<String, Vec<String>>,
    local_branches: BTreeSet<String>,
    queries: Vec<Vec<String>>,
    executions: Vec<Vec<String>>,
}

impl FakeGit {
    fn new(repository_root: PathBuf) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeGitState {
                branch: "feature/topic".to_owned(),
                repository_root,
                remote_urls: vec!["https://github.com/acme/project.git".to_owned()],
                upstream: Some("origin/feature/topic".to_owned()),
                push_default: None,
                aliases: BTreeMap::new(),
                config_values: BTreeMap::new(),
                local_branches: BTreeSet::from(["feature/topic".to_owned(), "main".to_owned()]),
                queries: Vec::new(),
                executions: Vec::new(),
            })),
        }
    }

    fn update(&self, update: impl FnOnce(&mut FakeGitState)) {
        update(
            &mut self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        );
    }

    fn queries(&self) -> Vec<Vec<String>> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .queries
            .clone()
    }
}

impl GitProcessRunner for FakeGit {
    fn query(&self, request: &ProcessRequest<'_>) -> Result<ProcessOutput, GuardError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.queries.push(request.arguments.to_vec());
        if request.arguments == ["--version"] {
            return Ok(ProcessOutput {
                exit_code: Some(0),
                stdout: b"git version 2.51.0\n".to_vec(),
                stderr: Vec::new(),
            });
        }
        let invocation = parse_invocation(request.arguments)?;
        let command = invocation.command.as_deref();
        let arguments = invocation.command_arguments.as_slice();
        let nul_output =
            command == Some("config") && arguments.first().is_some_and(|v| v == "--null");
        let values = match (command, arguments) {
            (Some("branch"), [show]) if show == "--show-current" => {
                nonempty(state.branch.clone()).map(|value| vec![value])
            }
            (Some("rev-parse"), [show]) if show == "--show-toplevel" => {
                Some(vec![state.repository_root.display().to_string()])
            }
            (Some("rev-parse"), [abbrev, symbolic, upstream])
                if abbrev == "--abbrev-ref"
                    && symbolic == "--symbolic-full-name"
                    && upstream == "@{upstream}" =>
            {
                state.upstream.clone().map(|value| vec![value])
            }
            (Some("remote"), remote_arguments)
                if remote_arguments.starts_with(&["get-url".to_owned(), "--all".to_owned()]) =>
            {
                Some(state.remote_urls.clone())
            }
            (Some("ls-remote"), [get_url, repository]) if get_url == "--get-url" => {
                Some(vec![repository.clone()])
            }
            (Some("config"), [null, get_all, key])
                if null == "--null" && get_all == "--get-all" && key.starts_with("alias.") =>
            {
                state
                    .aliases
                    .get(key.trim_start_matches("alias."))
                    .cloned()
                    .map(|value| vec![value])
            }
            (Some("config"), [null, get_all, key])
                if null == "--null" && get_all == "--get-all" && key == "push.default" =>
            {
                state.push_default.clone().map(|value| vec![value])
            }
            (Some("config"), [null, get_all, key])
                if null == "--null" && get_all == "--get-all" =>
            {
                state.config_values.get(key).cloned()
            }
            (Some("show-ref"), [verify, quiet, reference])
                if verify == "--verify" && quiet == "--quiet" =>
            {
                state
                    .local_branches
                    .contains(reference.trim_start_matches("refs/heads/"))
                    .then(Vec::new)
            }
            _ => None,
        };
        let Some(values) = values else {
            return Ok(ProcessOutput {
                exit_code: Some(1),
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        };
        let stdout = if values.is_empty() {
            Vec::new()
        } else if nul_output {
            format!("{}\0", values.join("\0")).into_bytes()
        } else {
            format!("{}\n", values.join("\n")).into_bytes()
        };
        Ok(ProcessOutput {
            exit_code: Some(0),
            stdout,
            stderr: Vec::new(),
        })
    }

    fn execute(&self, request: &ProcessRequest<'_>) -> Result<(), GuardError> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .executions
            .push(request.arguments.to_vec());
        Ok(())
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

struct Fixture {
    _root: TempDir,
    selected_workspace: PathBuf,
    runner: FakeGit,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let selected_workspace = root.path().join("selected");
        std::fs::create_dir(&selected_workspace).unwrap();
        let runner = FakeGit::new(selected_workspace.clone());
        Self {
            _root: root,
            selected_workspace,
            runner,
        }
    }

    fn service(&self) -> GuardService<FakeGit> {
        GuardService::new(
            GuardPolicyDocument {
                schema_version: PolicySchemaVersion::V1,
                selected_repository: selected_repository(),
                selected_workspace: self.selected_workspace.clone(),
                branch_protection: BranchPolicyConfiguration {
                    username: Some("mbianchidev".to_owned()),
                    ..BranchPolicyConfiguration::default()
                },
                environment: EnvironmentPolicy::default(),
                limits: GuardLimits::default(),
            },
            trusted_git(),
            self.runner.clone(),
            &self.selected_workspace,
            std::iter::empty::<(String, String)>(),
        )
        .unwrap()
    }
}

fn selected_repository() -> RepositoryIdentity {
    RepositoryIdentity::new("github.com", "acme", "project").unwrap()
}

fn trusted_git() -> TrustedGitBinary {
    ["/usr/bin/git", "/bin/git"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(TrustedGitBinary::verify)
        .expect("system Git path")
        .expect("trusted system Git")
}

fn assert_denied(result: Result<Admission, GuardError>, message: &str) {
    let error = result.expect_err("operation should be denied");
    assert!(
        error.to_string().contains(message),
        "expected `{message}` in `{error}`"
    );
}

#[test]
fn rejects_protected_destination_refspec() {
    let fixture = Fixture::new();
    assert_denied(
        fixture.service().admit(&strings(&[
            "push",
            "origin",
            "feature/topic:refs/heads/main",
        ])),
        "protected branch `main`",
    );
}

#[test]
fn allows_feature_push() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .service()
            .admit(&strings(&["push", "origin", "feature/topic"]))
            .unwrap(),
        Admission::Guarded
    );
}

#[test]
fn allows_other_repository_even_on_protected_branch() {
    let fixture = Fixture::new();
    fixture
        .runner
        .update(|state| state.branch = "main".to_owned());
    assert_eq!(
        fixture
            .service()
            .admit(&strings(&[
                "pull",
                "https://github.com/open-source/library.git",
                "main",
            ]))
            .unwrap(),
        Admission::PassThrough {
            reason: "operation targets another repository"
        }
    );
}

#[test]
fn allows_explicit_other_remote_from_selected_workspace() {
    let fixture = Fixture::new();
    fixture.runner.update(|state| {
        state.branch = "release/1.0".to_owned();
        state.local_branches.insert("release/1.0".to_owned());
    });
    assert!(matches!(
        fixture.service().admit(&strings(&[
            "push",
            "https://github.com/open-source/library.git",
            "release/1.0",
        ])),
        Ok(Admission::PassThrough { .. })
    ));
}

#[test]
fn guards_selected_repository_clone_elsewhere() {
    let fixture = Fixture::new();
    let clone = fixture._root.path().join("clone");
    std::fs::create_dir(&clone).unwrap();
    fixture.runner.update(|state| {
        state.repository_root = clone;
    });
    assert_denied(
        fixture
            .service()
            .admit(&strings(&["push", "origin", "feature/topic:main"])),
        "protected branch `main`",
    );
}

#[test]
fn rejects_pull_from_protected_branch() {
    let fixture = Fixture::new();
    assert_denied(
        fixture
            .service()
            .admit(&strings(&["pull", "origin", "main"])),
        "protected branch `main`",
    );
}

#[test]
fn rejects_protected_current_branch() {
    let fixture = Fixture::new();
    fixture
        .runner
        .update(|state| state.branch = "main".to_owned());
    assert_denied(
        fixture
            .service()
            .admit(&strings(&["push", "origin", "feature/topic"])),
        "protected branch `main`",
    );
}

#[test]
fn rejects_matching_push_default_and_broad_options() {
    let fixture = Fixture::new();
    fixture
        .runner
        .update(|state| state.push_default = Some("matching".to_owned()));
    assert_denied(
        fixture.service().admit(&strings(&["push"])),
        "push.default=matching",
    );
    assert_denied(
        fixture
            .service()
            .admit(&strings(&["push", "--mirror", "origin"])),
        "unbounded set of refs",
    );
}

#[test]
fn rejects_protected_deletion_and_ambiguous_push_urls() {
    let fixture = Fixture::new();
    assert_denied(
        fixture
            .service()
            .admit(&strings(&["push", "--delete", "origin", "main"])),
        "protected branch `main`",
    );
    fixture.runner.update(|state| {
        state.remote_urls = vec![
            "https://github.com/acme/project.git".to_owned(),
            "https://github.com/open-source/library.git".to_owned(),
        ];
    });
    assert!(matches!(
        fixture
            .service()
            .admit(&strings(&["push", "origin", "feature/topic"])),
        Err(GuardError::AmbiguousRepository)
    ));
    fixture.runner.update(|state| {
        state.remote_urls = vec![
            "https://github.com/acme/project.git".to_owned(),
            "https://github.com/acme/project.git".to_owned(),
        ];
    });
    assert!(matches!(
        fixture
            .service()
            .admit(&strings(&["push", "origin", "feature/topic"])),
        Err(GuardError::AmbiguousRepository)
    ));
}

#[test]
fn resolves_bounded_aliases_and_rejects_shell_aliases() {
    let fixture = Fixture::new();
    fixture.runner.update(|state| {
        state
            .aliases
            .insert("publish".to_owned(), "push origin".to_owned());
    });
    assert_eq!(
        fixture
            .service()
            .admit(&strings(&["publish", "feature/topic"]))
            .unwrap(),
        Admission::Guarded
    );
    fixture.runner.update(|state| {
        state
            .aliases
            .insert("publish".to_owned(), " !echo bypass".to_owned());
    });
    assert_denied(
        fixture
            .service()
            .admit(&strings(&["publish", "feature/topic"])),
        "shell Git alias",
    );
    fixture.runner.update(|state| {
        state.aliases.insert(
            "publish".to_owned(),
            "push origin feature/topic\nfeature/topic:main".to_owned(),
        );
    });
    assert_denied(
        fixture.service().admit(&strings(&["publish"])),
        "protected branch `main`",
    );
}

#[test]
fn rejects_config_environment_injection_and_preserves_path_globals() {
    let fixture = Fixture::new();
    assert_denied(
        fixture.service().admit(&strings(&[
            "--config-env=remote.origin.url=URL",
            "push",
            "origin",
            "feature/topic",
        ])),
        "--config-env",
    );
    assert_denied(
        fixture.service().admit(&strings(&[
            "--exec-path=/tmp/helpers",
            "push",
            "origin",
            "feature/topic",
        ])),
        "--exec-path",
    );
    assert_denied(
        fixture.service().admit(&strings(&[
            "-c",
            "credential.helper=!payload",
            "push",
            "origin",
            "feature/topic",
        ])),
        "outside the modeled",
    );
    let query_count = fixture.runner.queries().len();
    fixture
        .service()
        .admit(&strings(&[
            "-C",
            fixture.selected_workspace.to_str().unwrap(),
            "--git-dir=.git",
            "--work-tree=.",
            "-c",
            "push.default=current",
            "push",
            "origin",
            "feature/topic",
        ]))
        .unwrap();
    assert!(
        fixture
            .runner
            .queries()
            .iter()
            .skip(query_count)
            .filter(|query| query.as_slice() != ["--version"])
            .all(|query| {
                query
                    .windows(2)
                    .any(|window| window == ["-c", "push.default=current"])
                    && query.iter().any(|argument| argument == "--git-dir=.git")
                    && query.iter().any(|argument| argument == "--work-tree=.")
            })
    );
}

#[test]
fn rejects_configured_credential_helpers() {
    let fixture = Fixture::new();
    fixture.runner.update(|state| {
        state
            .config_values
            .insert("credential.helper".to_owned(), vec!["!payload".to_owned()]);
    });
    assert_denied(
        fixture
            .service()
            .admit(&strings(&["push", "origin", "feature/topic"])),
        "credential helpers require later credential-broker integration",
    );
}

#[test]
fn rejects_detached_selected_repository_but_passes_non_guarded_commands() {
    let fixture = Fixture::new();
    fixture.runner.update(|state| state.branch.clear());
    assert_denied(
        fixture
            .service()
            .admit(&strings(&["push", "origin", "feature/topic"])),
        "non-detached current branch",
    );
    assert!(matches!(
        fixture.service().admit(&strings(&["status"])),
        Ok(Admission::PassThrough { .. })
    ));
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
