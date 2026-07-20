use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub current_dir: PathBuf,
    pub timeout: Duration,
    pub output_cap_bytes: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CommandOutcome {
    pub status: CommandStatus,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Completed,
    Unavailable,
    TimedOut,
    OutputLimitExceeded,
    SpawnFailed,
}

#[must_use]
pub fn run_command(spec: &CommandSpec) -> CommandOutcome {
    let Some(executable) = resolve_executable(&spec.executable, &spec.current_dir) else {
        return outcome(
            CommandStatus::Unavailable,
            None,
            Vec::new(),
            Vec::new(),
            Some(format!(
                "executable is unavailable: {}",
                spec.executable.display()
            )),
        );
    };
    let mut child = match Command::new(&executable)
        .args(&spec.args)
        .current_dir(&spec.current_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return outcome(
                CommandStatus::SpawnFailed,
                None,
                Vec::new(),
                Vec::new(),
                Some(error.to_string()),
            );
        }
    };

    let exceeded = Arc::new(AtomicBool::new(false));
    let total = Arc::new(Mutex::new(0usize));
    let stdout_thread = read_bounded(
        child.stdout.take().expect("piped stdout"),
        spec.output_cap_bytes,
        Arc::clone(&total),
        Arc::clone(&exceeded),
    );
    let stderr_thread = read_bounded(
        child.stderr.take().expect("piped stderr"),
        spec.output_cap_bytes,
        total,
        Arc::clone(&exceeded),
    );

    let started = Instant::now();
    let (status, exit_code, error) = loop {
        if exceeded.load(Ordering::Relaxed) {
            let kill_error = child.kill().err().map(|value| value.to_string());
            let waited = child.wait().ok();
            break (
                CommandStatus::OutputLimitExceeded,
                waited.and_then(|value| value.code()),
                kill_error
                    .or_else(|| Some("combined stdout/stderr exceeded output cap".to_owned())),
            );
        }
        if started.elapsed() >= spec.timeout {
            let kill_error = child.kill().err().map(|value| value.to_string());
            let waited = child.wait().ok();
            break (
                CommandStatus::TimedOut,
                waited.and_then(|value| value.code()),
                kill_error.or_else(|| Some("command exceeded timeout".to_owned())),
            );
        }
        match child.try_wait() {
            Ok(Some(status)) => break (CommandStatus::Completed, status.code(), None),
            Ok(None) => thread::sleep(Duration::from_millis(2)),
            Err(wait_error) => {
                let _ = child.kill();
                let _ = child.wait();
                break (
                    CommandStatus::SpawnFailed,
                    None,
                    Some(wait_error.to_string()),
                );
            }
        }
    };

    let stdout = stdout_thread
        .join()
        .map_err(|_| "stdout reader thread panicked".to_owned())
        .and_then(|result| result);
    let stderr = stderr_thread
        .join()
        .map_err(|_| "stderr reader thread panicked".to_owned())
        .and_then(|result| result);
    let (mut stdout, mut stderr) = match (stdout, stderr) {
        (Ok(stdout), Ok(stderr)) => (stdout, stderr),
        (Err(error), Ok(stderr)) => {
            return outcome(
                CommandStatus::SpawnFailed,
                exit_code,
                Vec::new(),
                stderr,
                Some(error),
            );
        }
        (Ok(stdout), Err(error)) => {
            return outcome(
                CommandStatus::SpawnFailed,
                exit_code,
                stdout,
                Vec::new(),
                Some(error),
            );
        }
        (Err(stdout_error), Err(stderr_error)) => {
            return outcome(
                CommandStatus::SpawnFailed,
                exit_code,
                Vec::new(),
                Vec::new(),
                Some(format!("{stdout_error}; {stderr_error}")),
            );
        }
    };
    if stdout.len() + stderr.len() > spec.output_cap_bytes {
        let stdout_length = stdout.len().min(spec.output_cap_bytes);
        stdout.truncate(stdout_length);
        stderr.truncate(spec.output_cap_bytes.saturating_sub(stdout_length));
    }
    outcome(status, exit_code, stdout, stderr, error)
}

fn read_bounded(
    mut stream: impl Read + Send + 'static,
    cap: usize,
    total: Arc<Mutex<usize>>,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>, String>> {
    thread::spawn(move || {
        let mut retained = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return Ok(retained),
                Err(error) => return Err(error.to_string()),
                Ok(count) => {
                    let mut total = total.lock().expect("output counter lock");
                    *total = total.saturating_add(count);
                    if *total > cap {
                        exceeded.store(true, Ordering::Relaxed);
                    }
                    let remaining = cap.saturating_sub(retained.len());
                    retained.extend_from_slice(&buffer[..count.min(remaining)]);
                }
            }
        }
    })
}

fn resolve_executable(executable: &Path, current_dir: &Path) -> Option<PathBuf> {
    if executable.components().count() > 1 {
        let candidate = if executable.is_absolute() {
            executable.to_path_buf()
        } else {
            current_dir.join(executable)
        };
        return candidate.is_file().then_some(candidate);
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(executable))
            .find(|candidate| candidate.is_file())
    })
}

fn outcome(
    status: CommandStatus,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    error: Option<String>,
) -> CommandOutcome {
    CommandOutcome {
        status,
        exit_code,
        stdout,
        stderr,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_is_not_success() {
        let result = run_command(&CommandSpec {
            executable: PathBuf::from("/definitely/missing/sendbox"),
            args: Vec::new(),
            current_dir: PathBuf::from("."),
            timeout: Duration::from_millis(10),
            output_cap_bytes: 100,
        });
        assert_eq!(result.status, CommandStatus::Unavailable);
    }

    #[test]
    fn enforces_timeout() {
        let result = run_command(&CommandSpec {
            executable: PathBuf::from("/bin/sleep"),
            args: vec!["1".to_owned()],
            current_dir: PathBuf::from("."),
            timeout: Duration::from_millis(10),
            output_cap_bytes: 100,
        });
        assert_eq!(result.status, CommandStatus::TimedOut);
    }

    #[test]
    fn enforces_combined_output_cap() {
        let result = run_command(&CommandSpec {
            executable: PathBuf::from("/usr/bin/yes"),
            args: Vec::new(),
            current_dir: PathBuf::from("."),
            timeout: Duration::from_secs(2),
            output_cap_bytes: 128,
        });
        assert_eq!(result.status, CommandStatus::OutputLimitExceeded);
        assert!(result.stdout.len() <= 128);
    }

    #[test]
    fn resolves_relative_executable_against_command_directory() {
        let root = std::env::temp_dir().join(format!(
            "sendbox-qualification-resolve-{}",
            std::process::id()
        ));
        let executable = root.join("bin").join("tool");
        std::fs::create_dir_all(executable.parent().expect("parent")).expect("create directory");
        std::fs::write(&executable, b"fixture").expect("write fixture");
        assert_eq!(
            resolve_executable(&PathBuf::from("bin/tool"), &root),
            Some(executable)
        );
        std::fs::remove_dir_all(root).expect("remove fixture");
    }
}
