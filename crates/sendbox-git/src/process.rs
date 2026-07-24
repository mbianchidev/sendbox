use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{GuardError, TrustedGitBinary};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvironmentPolicy {
    pub fixed_path: String,
    pub inherited_keys: BTreeSet<String>,
}

impl Default for EnvironmentPolicy {
    fn default() -> Self {
        Self {
            fixed_path: "/usr/bin:/bin".to_owned(),
            inherited_keys: BTreeSet::from([
                "GIT_TERMINAL_PROMPT".to_owned(),
                "HOME".to_owned(),
                "LANG".to_owned(),
                "LOGNAME".to_owned(),
                "SSH_AUTH_SOCK".to_owned(),
                "TERM".to_owned(),
                "TMPDIR".to_owned(),
                "USER".to_owned(),
            ]),
        }
    }
}

impl EnvironmentPolicy {
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.fixed_path.is_empty()
            || !self.fixed_path.split(':').all(|path| path.starts_with('/'))
        {
            return Err(GuardError::InvalidPolicy(
                "environment PATH must contain only absolute entries".to_owned(),
            ));
        }
        if let Some(key) = self
            .inherited_keys
            .iter()
            .find(|key| key.is_empty() || dangerous_environment_key(key) || key.as_str() == "PATH")
        {
            return Err(GuardError::InvalidPolicy(format!(
                "environment inheritance key `{key}` is not allowed"
            )));
        }
        Ok(())
    }

    pub fn sanitize<I, K, V>(&self, environment: I) -> Result<BTreeMap<String, String>, GuardError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.validate()?;
        let mut sanitized = BTreeMap::from([("PATH".to_owned(), self.fixed_path.clone())]);
        for (key, value) in environment {
            let key = key.into();
            let value = value.into();
            if dangerous_environment_key(&key) {
                return Err(GuardError::InvalidInvocation(format!(
                    "environment variable `{key}` is not allowed for guarded Git"
                )));
            }
            if self.inherited_keys.contains(&key) || key.starts_with("LC_") {
                sanitized.insert(key, value);
            }
        }
        Ok(sanitized)
    }
}

fn dangerous_environment_key(key: &str) -> bool {
    matches!(
        key,
        "GIT_ALTERNATE_OBJECT_DIRECTORIES"
            | "GIT_ASKPASS"
            | "GIT_CEILING_DIRECTORIES"
            | "GIT_COMMON_DIR"
            | "GIT_CONFIG"
            | "GIT_CONFIG_COUNT"
            | "GIT_CONFIG_GLOBAL"
            | "GIT_CONFIG_NOSYSTEM"
            | "GIT_CONFIG_PARAMETERS"
            | "GIT_CONFIG_SYSTEM"
            | "GIT_DIR"
            | "GIT_DISCOVERY_ACROSS_FILESYSTEM"
            | "GIT_EXEC_PATH"
            | "GIT_INDEX_FILE"
            | "GIT_NAMESPACE"
            | "GIT_OBJECT_DIRECTORY"
            | "GIT_PROXY_COMMAND"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_WORK_TREE"
            | "LD_PRELOAD"
            | "SSH_ASKPASS"
            | "SSH_ASKPASS_REQUIRE"
    ) || key.starts_with("DYLD_")
        || key.starts_with("GIT_CONFIG_KEY_")
        || key.starts_with("GIT_CONFIG_VALUE_")
}

#[derive(Debug, Clone)]
pub struct ProcessRequest<'a> {
    pub executable: &'a TrustedGitBinary,
    pub arguments: &'a [String],
    pub environment: &'a BTreeMap<String, String>,
    pub current_directory: &'a std::path::Path,
    pub timeout: Duration,
    pub output_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait GitProcessRunner: Send + Sync {
    fn query(&self, request: &ProcessRequest<'_>) -> Result<ProcessOutput, GuardError>;
    fn execute(&self, request: &ProcessRequest<'_>) -> Result<(), GuardError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemGitProcessRunner;

impl GitProcessRunner for SystemGitProcessRunner {
    fn query(&self, request: &ProcessRequest<'_>) -> Result<ProcessOutput, GuardError> {
        request.executable.verify_unchanged()?;
        let mut child = command(request)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| GuardError::UnresolvedState("Git stdout pipe is missing".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| GuardError::UnresolvedState("Git stderr pipe is missing".to_owned()))?;
        let output_limit = request.output_limit;
        let stdout_thread = thread::spawn(move || read_bounded(stdout, output_limit));
        let stderr_thread = thread::spawn(move || read_bounded(stderr, output_limit));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= request.timeout {
                child.kill()?;
                child.wait()?;
                return Err(GuardError::ProbeTimeout);
            }
            thread::sleep(Duration::from_millis(5));
        };
        let stdout = stdout_thread
            .join()
            .map_err(|_| GuardError::UnresolvedState("Git stdout reader panicked".to_owned()))??;
        let stderr = stderr_thread
            .join()
            .map_err(|_| GuardError::UnresolvedState("Git stderr reader panicked".to_owned()))??;
        if stdout.exceeded || stderr.exceeded {
            return Err(GuardError::ProbeOutputLimit);
        }
        Ok(ProcessOutput {
            exit_code: status.code(),
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }

    fn execute(&self, request: &ProcessRequest<'_>) -> Result<(), GuardError> {
        request.executable.verify_unchanged()?;
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let error = command(request)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .exec();
            Err(GuardError::Process(error))
        }
        #[cfg(not(unix))]
        {
            let status = command(request)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err(GuardError::UnresolvedState(format!(
                    "Git exited with status {status}"
                )))
            }
        }
    }
}

fn command(request: &ProcessRequest<'_>) -> Command {
    let mut command = Command::new(request.executable.path());
    command
        .args(request.arguments)
        .current_dir(request.current_directory)
        .env_clear()
        .envs(request.environment);
    command
}

struct BoundedRead {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<BoundedRead, GuardError> {
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut exceeded = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(BoundedRead {
                bytes: output,
                exceeded,
            });
        }
        let remaining = limit.saturating_sub(output.len());
        if read > remaining {
            exceeded = true;
        }
        output.extend_from_slice(&buffer[..read.min(remaining)]);
    }
}

#[cfg(test)]
mod tests {
    use super::EnvironmentPolicy;

    #[test]
    fn rejects_git_config_and_loader_injection() {
        let policy = EnvironmentPolicy::default();
        for key in [
            "GIT_CONFIG_COUNT",
            "GIT_DIR",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
        ] {
            assert!(
                policy
                    .sanitize([(key.to_owned(), "value".to_owned())])
                    .is_err()
            );
        }
    }

    #[test]
    fn never_includes_secret_values_in_environment_errors() {
        let error = EnvironmentPolicy::default()
            .sanitize([("GIT_CONFIG_PARAMETERS", "top-secret-token")])
            .expect_err("dangerous environment must be rejected");
        assert!(!error.to_string().contains("top-secret-token"));
    }

    #[test]
    fn rejects_caller_selected_askpass_programs() {
        let policy = EnvironmentPolicy::default();
        assert!(policy.sanitize([("GIT_ASKPASS", "/tmp/payload")]).is_err());
        assert!(policy.sanitize([("SSH_ASKPASS", "/tmp/payload")]).is_err());
    }
}
