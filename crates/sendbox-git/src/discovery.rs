use std::{collections::BTreeMap, path::Path, time::Duration};

use crate::{
    EnvironmentPolicy, GitProcessRunner, GuardError, ProcessRequest, RepositoryIdentity,
    TrustedGitBinary,
};

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
const DISCOVERY_OUTPUT_LIMIT: usize = 256 * 1024;

pub fn discover_repository_identity<I, K, V>(
    executable: &TrustedGitBinary,
    runner: &dyn GitProcessRunner,
    current_directory: &Path,
    environment: I,
) -> Result<RepositoryIdentity, GuardError>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let environment = EnvironmentPolicy::default().sanitize(environment)?;
    let mut remotes = query_values(
        executable,
        runner,
        current_directory,
        &environment,
        &["remote"],
    )?;
    remotes.sort();
    remotes.dedup();
    let remote = remotes
        .iter()
        .find(|remote| remote.as_str() == "origin")
        .or_else(|| remotes.first())
        .ok_or(GuardError::AmbiguousRepository)?;
    let urls = query_values(
        executable,
        runner,
        current_directory,
        &environment,
        &["remote", "get-url", "--all", remote],
    )?;
    let mut identities = urls
        .iter()
        .map(|url| RepositoryIdentity::parse(url, None))
        .collect::<Result<Vec<_>, _>>()?;
    let selected = identities.pop().ok_or(GuardError::AmbiguousRepository)?;
    if identities.iter().all(|identity| identity == &selected) {
        Ok(selected)
    } else {
        Err(GuardError::AmbiguousRepository)
    }
}

fn query_values(
    executable: &TrustedGitBinary,
    runner: &dyn GitProcessRunner,
    current_directory: &Path,
    environment: &BTreeMap<String, String>,
    arguments: &[&str],
) -> Result<Vec<String>, GuardError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    let output = runner.query(&ProcessRequest {
        executable,
        arguments: &arguments,
        environment,
        current_directory,
        timeout: DISCOVERY_TIMEOUT,
        output_limit: DISCOVERY_OUTPUT_LIMIT,
    })?;
    if output.exit_code != Some(0) {
        return Err(GuardError::UnresolvedState(
            "selected Git repository could not be queried".to_owned(),
        ));
    }
    let output = String::from_utf8(output.stdout).map_err(|_| {
        GuardError::UnresolvedState("Git repository query returned non-UTF-8 output".to_owned())
    })?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        fs,
        os::unix::fs::PermissionsExt,
        sync::Mutex,
    };

    use crate::{GitProcessRunner, ProcessOutput};

    use super::*;

    struct FakeRunner {
        outputs: Mutex<VecDeque<ProcessOutput>>,
    }

    impl GitProcessRunner for FakeRunner {
        fn query(&self, _request: &ProcessRequest<'_>) -> Result<ProcessOutput, GuardError> {
            self.outputs
                .lock()
                .expect("outputs")
                .pop_front()
                .ok_or_else(|| GuardError::UnresolvedState("missing fake output".to_owned()))
        }

        fn execute(&self, _request: &ProcessRequest<'_>) -> Result<(), GuardError> {
            unreachable!("discovery does not execute Git")
        }
    }

    fn trusted_git(temporary: &tempfile::TempDir) -> TrustedGitBinary {
        let path = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary")
            .join("git");
        fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write git");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("mode");
        TrustedGitBinary::verify(path).expect("trusted git")
    }

    fn output(value: &str) -> ProcessOutput {
        ProcessOutput {
            exit_code: Some(0),
            stdout: value.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn discovers_origin_and_requires_consistent_urls() {
        let temporary = tempfile::tempdir().expect("temporary");
        let runner = FakeRunner {
            outputs: Mutex::new(VecDeque::from([
                output("upstream\norigin\n"),
                output("git@github.com:owner/repo.git\nhttps://github.com/owner/repo.git\n"),
            ])),
        };
        let repository = discover_repository_identity(
            &trusted_git(&temporary),
            &runner,
            temporary.path(),
            BTreeMap::<String, String>::new(),
        )
        .expect("repository");
        assert_eq!(repository.to_string(), "github.com/owner/repo");
    }

    #[test]
    fn rejects_remotes_that_resolve_to_different_repositories() {
        let temporary = tempfile::tempdir().expect("temporary");
        let runner = FakeRunner {
            outputs: Mutex::new(VecDeque::from([
                output("origin\n"),
                output("https://github.com/owner/repo.git\nhttps://github.com/other/repo.git\n"),
            ])),
        };
        assert!(matches!(
            discover_repository_identity(
                &trusted_git(&temporary),
                &runner,
                temporary.path(),
                BTreeMap::<String, String>::new(),
            ),
            Err(GuardError::AmbiguousRepository)
        ));
    }
}
