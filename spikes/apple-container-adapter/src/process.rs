use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

const REDACTED: &str = "<redacted>";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    secrets: Vec<String>,
}

impl CommandSpec {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>, arguments: Vec<String>) -> Self {
        Self {
            executable: executable.into(),
            arguments,
            environment: minimal_environment(),
            secrets: Vec::new(),
        }
    }

    pub fn add_secret_environment(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let value = value.into();
        self.secrets.push(value.clone());
        self.environment.insert(key.into(), value);
    }

    pub fn add_secret(&mut self, value: impl Into<String>) {
        self.secrets.push(value.into());
    }

    #[must_use]
    pub fn diagnostic(&self) -> String {
        let mut rendered = self.executable.display().to_string();
        for argument in &self.arguments {
            rendered.push(' ');
            rendered.push_str(&redact_text(argument, &self.secrets));
        }
        rendered
    }
}

#[must_use]
pub fn minimal_environment() -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([
        (
            "PATH".to_owned(),
            "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin".to_owned(),
        ),
        ("LANG".to_owned(), "C".to_owned()),
        ("LC_ALL".to_owned(), "C".to_owned()),
    ]);

    for key in ["HOME", "USER", "TMPDIR"] {
        if let Ok(value) = std::env::var(key) {
            environment.insert(key.to_owned(), value);
        }
    }
    environment
}

#[derive(Clone, Debug)]
pub struct ProcessControls {
    pub timeout: Duration,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub cancellation: CancellationToken,
}

impl Default for ProcessControls {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            stdout_limit: 64 * 1024,
            stderr_limit: 64 * 1024,
            cancellation: CancellationToken::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTermination {
    Exited,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitStatusRecord {
    pub success: bool,
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapturedOutput {
    pub text: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessOutput {
    pub termination: ProcessTermination,
    pub status: ExitStatusRecord,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("failed to spawn `{diagnostic}`: {source}")]
    Spawn {
        diagnostic: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed while waiting for `{diagnostic}`: {source}")]
    Wait {
        diagnostic: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to capture {stream} from `{diagnostic}`: {source}")]
    Capture {
        diagnostic: String,
        stream: &'static str,
        #[source]
        source: std::io::Error,
    },
}

#[async_trait]
pub trait ProcessRunner: Send + Sync {
    async fn run(
        &self,
        specification: &CommandSpec,
        controls: ProcessControls,
    ) -> Result<ProcessOutput, ProcessError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TokioProcessRunner;

#[async_trait]
impl ProcessRunner for TokioProcessRunner {
    async fn run(
        &self,
        specification: &CommandSpec,
        controls: ProcessControls,
    ) -> Result<ProcessOutput, ProcessError> {
        let diagnostic = specification.diagnostic();
        let mut command = Command::new(&specification.executable);
        command
            .args(&specification.arguments)
            .env_clear()
            .envs(&specification.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|source| ProcessError::Spawn {
            diagnostic: diagnostic.clone(),
            source,
        })?;
        let stdout = child.stdout.take().expect("stdout was configured as piped");
        let stderr = child.stderr.take().expect("stderr was configured as piped");
        let stdout_task = tokio::spawn(read_bounded(stdout, controls.stdout_limit));
        let stderr_task = tokio::spawn(read_bounded(stderr, controls.stderr_limit));

        let mut termination = ProcessTermination::Exited;
        let status = tokio::select! {
            biased;
            () = controls.cancellation.cancelled() => {
                termination = ProcessTermination::Cancelled;
                let _ = child.start_kill();
                child.wait().await
            }
            () = tokio::time::sleep(controls.timeout) => {
                termination = ProcessTermination::TimedOut;
                let _ = child.start_kill();
                child.wait().await
            }
            status = child.wait() => status,
        }
        .map_err(|source| ProcessError::Wait {
            diagnostic: diagnostic.clone(),
            source,
        })?;

        let stdout = stdout_task
            .await
            .expect("bounded stdout capture task must not panic")
            .map_err(|source| ProcessError::Capture {
                diagnostic: diagnostic.clone(),
                stream: "stdout",
                source,
            })?;
        let stderr = stderr_task
            .await
            .expect("bounded stderr capture task must not panic")
            .map_err(|source| ProcessError::Capture {
                diagnostic,
                stream: "stderr",
                source,
            })?;

        Ok(ProcessOutput {
            termination,
            status: status_record(status),
            stdout: redact_output(stdout, &specification.secrets),
            stderr: redact_output(stderr, &specification.secrets),
        })
    }
}

fn status_record(status: std::process::ExitStatus) -> ExitStatusRecord {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ExitStatusRecord {
            success: status.success(),
            code: status.code(),
            signal: status.signal(),
        }
    }
    #[cfg(not(unix))]
    {
        ExitStatusRecord {
            success: status.success(),
            code: status.code(),
            signal: None,
        }
    }
}

async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: usize,
) -> std::io::Result<CapturedOutput> {
    let mut retained = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;

    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(retained.len());
        let copy = remaining.min(read);
        retained.extend_from_slice(&buffer[..copy]);
        truncated |= copy < read;
    }

    Ok(CapturedOutput {
        text: String::from_utf8_lossy(&retained).into_owned(),
        truncated,
    })
}

fn redact_output(mut output: CapturedOutput, secrets: &[String]) -> CapturedOutput {
    output.text = redact_text(&output.text, secrets);
    output
}

fn redact_text(text: &str, secrets: &[String]) -> String {
    secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .fold(text.to_owned(), |value, secret| {
            value.replace(secret, REDACTED)
        })
}

#[must_use]
pub fn command(executable: &Path, arguments: &[&str]) -> CommandSpec {
    CommandSpec::new(
        executable,
        arguments.iter().map(ToString::to_string).collect(),
    )
}
