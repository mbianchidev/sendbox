use std::{
    collections::BTreeSet,
    fmt,
    future::pending,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    task::JoinHandle,
};
use zeroize::Zeroizing;

use crate::{
    CancellationToken, Clock, MonotonicTime, OutputStats, OutputStream, OutputSubscription,
    RuntimeError, SystemClock,
    output::{OutputPublisher, output_channel},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Program {
    Absolute(PathBuf),
    Named(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandArgument {
    pub value: String,
    pub sensitive: bool,
}

impl CommandArgument {
    #[must_use]
    pub fn plain(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitive: false,
        }
    }

    #[must_use]
    pub fn sensitive(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitive: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentVariable {
    pub key: String,
    pub value: String,
    pub sensitive: bool,
}

impl EnvironmentVariable {
    #[must_use]
    pub fn plain(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            sensitive: false,
        }
    }

    #[must_use]
    pub fn sensitive(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            sensitive: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: Program,
    pub arguments: Vec<CommandArgument>,
    pub environment: Vec<EnvironmentVariable>,
    pub current_directory: Option<PathBuf>,
    pub clear_environment: bool,
}

impl CommandSpec {
    #[must_use]
    pub fn new(program: Program) -> Self {
        Self {
            program,
            arguments: Vec::new(),
            environment: Vec::new(),
            current_directory: None,
            clear_environment: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessOptions {
    pub stdout_capture_bytes: usize,
    pub stderr_capture_bytes: usize,
    pub output_channel_capacity: usize,
    pub read_chunk_bytes: usize,
    pub timeout: Option<Duration>,
    pub termination_grace: Duration,
    pub publish_output: bool,
}

impl Default for ProcessOptions {
    fn default() -> Self {
        Self {
            stdout_capture_bytes: 1024 * 1024,
            stderr_capture_bytes: 1024 * 1024,
            output_channel_capacity: 64,
            read_chunk_bytes: 8 * 1024,
            timeout: None,
            termination_grace: Duration::from_millis(500),
            publish_output: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedOutput {
    pub bytes: Vec<u8>,
    pub total_bytes: u64,
    pub truncated_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    pub success: bool,
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    Exited,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    pub status: ExitStatus,
    pub termination: TerminationReason,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
    pub output: OutputStats,
    pub started_at: MonotonicTime,
    pub finished_at: MonotonicTime,
    pub elapsed: Duration,
}

impl ProcessOutcome {
    #[must_use]
    pub fn successful(stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        let stdout_len = stdout.len() as u64;
        let stderr_len = stderr.len() as u64;
        Self {
            status: ExitStatus {
                success: true,
                code: Some(0),
                signal: None,
            },
            termination: TerminationReason::Exited,
            stdout: CapturedOutput {
                bytes: stdout,
                total_bytes: stdout_len,
                truncated_bytes: 0,
            },
            stderr: CapturedOutput {
                bytes: stderr,
                total_bytes: stderr_len,
                truncated_bytes: 0,
            },
            output: OutputStats::default(),
            started_at: MonotonicTime::default(),
            finished_at: MonotonicTime::default(),
            elapsed: Duration::ZERO,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSignal {
    Interrupt,
    Terminate,
    Kill,
    Hangup,
    User1,
    User2,
}

impl fmt::Display for ProcessSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Interrupt => "interrupt",
            Self::Terminate => "terminate",
            Self::Kill => "kill",
            Self::Hangup => "hangup",
            Self::User1 => "user1",
            Self::User2 => "user2",
        })
    }
}

pub trait ProgramResolver: Send + Sync {
    fn resolve(&self, name: &str) -> Result<PathBuf, RuntimeError>;
}

#[derive(Debug, Clone)]
pub struct SearchPathResolver {
    search_paths: Vec<PathBuf>,
}

impl SearchPathResolver {
    pub fn new(search_paths: impl IntoIterator<Item = PathBuf>) -> Result<Self, RuntimeError> {
        let search_paths = search_paths.into_iter().collect::<Vec<_>>();
        if let Some(path) = search_paths.iter().find(|path| !path.is_absolute()) {
            return Err(RuntimeError::InvalidCommand {
                reason: format!("resolver search path `{}` is not absolute", path.display()),
            });
        }
        Ok(Self { search_paths })
    }
}

impl ProgramResolver for SearchPathResolver {
    fn resolve(&self, name: &str) -> Result<PathBuf, RuntimeError> {
        self.search_paths
            .iter()
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| RuntimeError::ProgramNotFound {
                name: name.to_owned(),
            })
    }
}

pub struct ProcessRunner {
    resolver: Arc<dyn ProgramResolver>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for ProcessRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessRunner")
            .finish_non_exhaustive()
    }
}

impl ProcessRunner {
    #[must_use]
    pub fn new(resolver: Arc<dyn ProgramResolver>) -> Self {
        Self {
            resolver,
            clock: Arc::new(SystemClock::new()),
        }
    }

    #[must_use]
    pub fn with_clock(resolver: Arc<dyn ProgramResolver>, clock: Arc<dyn Clock>) -> Self {
        Self { resolver, clock }
    }

    pub async fn run(
        &self,
        command: CommandSpec,
        options: ProcessOptions,
        cancellation: &CancellationToken,
    ) -> Result<ProcessOutcome, RuntimeError> {
        self.spawn(command, options, cancellation)
            .await?
            .wait(cancellation)
            .await
    }

    pub async fn spawn(
        &self,
        command_spec: CommandSpec,
        options: ProcessOptions,
        cancellation: &CancellationToken,
    ) -> Result<RunningProcess, RuntimeError> {
        if cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        validate_options(&options)?;
        validate_command(&command_spec)?;
        let program = resolve_program(self.resolver.as_ref(), &command_spec.program)?;
        let diagnostic = redacted_diagnostic(&program, &command_spec);

        let mut command = Command::new(&program);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        if command_spec.clear_environment {
            command.env_clear();
        }
        for argument in &command_spec.arguments {
            command.arg(&argument.value);
        }
        for variable in &command_spec.environment {
            command.env(&variable.key, &variable.value);
        }
        if let Some(directory) = &command_spec.current_directory {
            command.current_dir(directory);
        }
        configure_process_group(&mut command);

        let mut child = command
            .spawn()
            .map_err(|source| RuntimeError::Spawn { diagnostic, source })?;
        let pid = child.id().ok_or_else(|| {
            RuntimeError::Provider("spawned process has no process ID".to_owned())
        })?;
        let process_group = process_group_id(pid)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Provider("stdout pipe was not created".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| RuntimeError::Provider("stderr pipe was not created".to_owned()))?;

        let stdout_capture = Arc::new(Mutex::new(CaptureBuffer::new(options.stdout_capture_bytes)));
        let stderr_capture = Arc::new(Mutex::new(CaptureBuffer::new(options.stderr_capture_bytes)));
        let (publisher, subscription) = if options.publish_output {
            let (publisher, subscription) = output_channel(options.output_channel_capacity);
            (
                Some(publisher),
                Some(Box::new(subscription) as Box<dyn OutputSubscription>),
            )
        } else {
            (None, None)
        };
        let stdout_task = tokio::spawn(drain_pipe(
            stdout,
            OutputStream::Stdout,
            Arc::clone(&stdout_capture),
            publisher.clone(),
            options.read_chunk_bytes,
        ));
        let stderr_task = tokio::spawn(drain_pipe(
            stderr,
            OutputStream::Stderr,
            Arc::clone(&stderr_capture),
            publisher.clone(),
            options.read_chunk_bytes,
        ));

        Ok(RunningProcess {
            child: Some(child),
            pid,
            process_group,
            options,
            clock: Arc::clone(&self.clock),
            started_at: self.clock.now(),
            stdout_capture,
            stderr_capture,
            stdout_task: Some(stdout_task),
            stderr_task: Some(stderr_task),
            publisher,
            subscription,
        })
    }
}

pub struct RunningProcess {
    child: Option<Child>,
    pid: u32,
    process_group: Option<i32>,
    options: ProcessOptions,
    clock: Arc<dyn Clock>,
    started_at: MonotonicTime,
    stdout_capture: Arc<Mutex<CaptureBuffer>>,
    stderr_capture: Arc<Mutex<CaptureBuffer>>,
    stdout_task: Option<JoinHandle<Result<(), RuntimeError>>>,
    stderr_task: Option<JoinHandle<Result<(), RuntimeError>>>,
    publisher: Option<OutputPublisher>,
    subscription: Option<Box<dyn OutputSubscription>>,
}

impl fmt::Debug for RunningProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunningProcess")
            .field("pid", &self.pid)
            .field("process_group", &self.process_group)
            .finish_non_exhaustive()
    }
}

impl RunningProcess {
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub fn take_output_subscription(&mut self) -> Option<Box<dyn OutputSubscription>> {
        self.subscription.take()
    }

    pub fn send_signal(&self, signal: ProcessSignal) -> Result<(), RuntimeError> {
        send_process_group_signal(self.process_group, signal)
    }

    pub async fn wait(
        mut self,
        cancellation: &CancellationToken,
    ) -> Result<ProcessOutcome, RuntimeError> {
        enum Trigger {
            Exited(std::process::ExitStatus),
            Cancelled,
            TimedOut,
        }

        let timeout = self.options.timeout;
        let timeout_future = async move {
            match timeout {
                Some(duration) => tokio::time::sleep(duration).await,
                None => pending::<()>().await,
            }
        };
        tokio::pin!(timeout_future);

        let trigger = {
            let child = self
                .child
                .as_mut()
                .ok_or_else(|| RuntimeError::Provider("process was already reaped".to_owned()))?;
            tokio::select! {
                result = child.wait() => Trigger::Exited(result.map_err(RuntimeError::Wait)?),
                () = cancellation.cancelled() => Trigger::Cancelled,
                () = &mut timeout_future => Trigger::TimedOut,
            }
        };

        let (status, termination) = match trigger {
            Trigger::Exited(status) => (status, TerminationReason::Exited),
            Trigger::Cancelled => (
                self.terminate_and_wait().await?,
                TerminationReason::Cancelled,
            ),
            Trigger::TimedOut => (
                self.terminate_and_wait().await?,
                TerminationReason::TimedOut,
            ),
        };
        self.child = None;

        await_drain(self.stdout_task.take(), "stdout").await?;
        await_drain(self.stderr_task.take(), "stderr").await?;
        let finished_at = self.clock.now();
        let stdout = self
            .stdout_capture
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .snapshot();
        let stderr = self
            .stderr_capture
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .snapshot();
        let output = self
            .publisher
            .as_ref()
            .map_or_else(OutputStats::default, OutputPublisher::stats);
        self.publisher = None;

        Ok(ProcessOutcome {
            status: decode_exit_status(status),
            termination,
            stdout,
            stderr,
            output,
            started_at: self.started_at,
            finished_at,
            elapsed: finished_at - self.started_at,
        })
    }

    async fn terminate_and_wait(&mut self) -> Result<std::process::ExitStatus, RuntimeError> {
        terminate_process(self.child.as_mut(), self.process_group)?;
        let grace = self.options.termination_grace;
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| RuntimeError::Provider("process was already reaped".to_owned()))?;
        tokio::select! {
            result = child.wait() => result.map_err(RuntimeError::Wait),
            () = tokio::time::sleep(grace) => {
                force_kill_process(Some(child), self.process_group)?;
                child.wait().await.map_err(RuntimeError::Wait)
            }
        }
    }
}

impl Drop for RunningProcess {
    fn drop(&mut self) {
        if self.child.is_some() {
            force_kill_process(self.child.as_mut(), self.process_group).ok();
        }
        if let Some(task) = self.stdout_task.take() {
            task.abort();
        }
        if let Some(task) = self.stderr_task.take() {
            task.abort();
        }
    }
}

#[derive(Debug)]
struct CaptureBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    total_bytes: u64,
}

impl CaptureBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit.min(64 * 1024))),
            limit,
            total_bytes: 0,
        }
    }

    fn record(&mut self, chunk: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(chunk.len() as u64);
        let remaining = self.limit.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }

    fn snapshot(&self) -> CapturedOutput {
        CapturedOutput {
            bytes: self.bytes.to_vec(),
            total_bytes: self.total_bytes,
            truncated_bytes: self.total_bytes.saturating_sub(self.bytes.len() as u64),
        }
    }
}

async fn drain_pipe(
    mut pipe: impl AsyncRead + Unpin,
    stream: OutputStream,
    capture: Arc<Mutex<CaptureBuffer>>,
    publisher: Option<OutputPublisher>,
    read_chunk_bytes: usize,
) -> Result<(), RuntimeError> {
    let mut buffer = Zeroizing::new(vec![0; read_chunk_bytes]);
    loop {
        let read = pipe
            .read(&mut buffer)
            .await
            .map_err(|source| RuntimeError::ProcessIo {
                stream: match stream {
                    OutputStream::Stdout => "stdout",
                    OutputStream::Stderr => "stderr",
                },
                source,
            })?;
        if read == 0 {
            return Ok(());
        }
        let chunk = &buffer[..read];
        capture
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .record(chunk);
        if let Some(publisher) = &publisher {
            publisher.publish(stream, chunk.to_vec())?;
        }
    }
}

async fn await_drain(
    task: Option<JoinHandle<Result<(), RuntimeError>>>,
    stream: &'static str,
) -> Result<(), RuntimeError> {
    let task =
        task.ok_or_else(|| RuntimeError::Provider(format!("{stream} drain task was missing")))?;
    task.await
        .map_err(|error| RuntimeError::ProcessTask(error.to_string()))?
}

fn validate_options(options: &ProcessOptions) -> Result<(), RuntimeError> {
    if options.read_chunk_bytes == 0 {
        return Err(RuntimeError::InvalidCommand {
            reason: "process read chunk size must be greater than zero".to_owned(),
        });
    }
    if options.output_channel_capacity == 0 {
        return Err(RuntimeError::InvalidCommand {
            reason: "output channel capacity must be greater than zero".to_owned(),
        });
    }
    Ok(())
}

fn validate_command(command: &CommandSpec) -> Result<(), RuntimeError> {
    match &command.program {
        Program::Absolute(path) => {
            if !path.is_absolute() {
                return Err(RuntimeError::InvalidCommand {
                    reason: format!("absolute program `{}` is not absolute", path.display()),
                });
            }
            if path_contains_nul(path) {
                return Err(RuntimeError::InvalidCommand {
                    reason: "program path contains NUL".to_owned(),
                });
            }
        }
        Program::Named(name) => {
            if name.is_empty() {
                return Err(RuntimeError::InvalidCommand {
                    reason: "named program must not be empty".to_owned(),
                });
            }
            if name.contains(['/', '\\']) {
                return Err(RuntimeError::InvalidCommand {
                    reason: "named program must not contain path separators".to_owned(),
                });
            }
            if name.contains('\0') {
                return Err(RuntimeError::InvalidCommand {
                    reason: "named program contains NUL".to_owned(),
                });
            }
        }
    }

    if command
        .arguments
        .iter()
        .any(|argument| argument.value.contains('\0'))
    {
        return Err(RuntimeError::InvalidCommand {
            reason: "command argument contains NUL".to_owned(),
        });
    }

    let mut environment_keys = BTreeSet::new();
    for variable in &command.environment {
        if variable.key.is_empty()
            || variable.key.contains(['=', '\0'])
            || variable.value.contains('\0')
        {
            return Err(RuntimeError::InvalidCommand {
                reason: format!("environment variable `{}` is invalid", variable.key),
            });
        }
        if !environment_keys.insert(&variable.key) {
            return Err(RuntimeError::InvalidCommand {
                reason: format!("environment variable `{}` is duplicated", variable.key),
            });
        }
    }

    if let Some(directory) = &command.current_directory {
        if path_contains_nul(directory) {
            return Err(RuntimeError::InvalidWorkingDirectory {
                path: directory.clone(),
                reason: "path contains NUL".to_owned(),
            });
        }
        let metadata = directory
            .metadata()
            .map_err(|source| RuntimeError::WorkingDirectoryIo {
                path: directory.clone(),
                source,
            })?;
        if !metadata.is_dir() {
            return Err(RuntimeError::InvalidWorkingDirectory {
                path: directory.clone(),
                reason: "path is not a directory".to_owned(),
            });
        }
    }
    Ok(())
}

fn resolve_program(
    resolver: &dyn ProgramResolver,
    program: &Program,
) -> Result<PathBuf, RuntimeError> {
    match program {
        Program::Absolute(path) => Ok(path.clone()),
        Program::Named(name) => {
            let path = resolver.resolve(name)?;
            if !path.is_absolute() {
                return Err(RuntimeError::ResolverReturnedRelative {
                    name: name.clone(),
                    path,
                });
            }
            if path_contains_nul(&path) {
                return Err(RuntimeError::InvalidCommand {
                    reason: "resolved program path contains NUL".to_owned(),
                });
            }
            Ok(path)
        }
    }
}

fn redacted_diagnostic(program: &Path, command: &CommandSpec) -> String {
    let arguments = command
        .arguments
        .iter()
        .map(|argument| {
            if argument.sensitive {
                "<redacted>".to_owned()
            } else {
                format!("{:?}", argument.value)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let environment = command
        .environment
        .iter()
        .map(|variable| {
            let value = if variable.sensitive {
                "<redacted>".to_owned()
            } else {
                format!("{:?}", variable.value)
            };
            format!("{}={value}", variable.key)
        })
        .collect::<Vec<_>>()
        .join(", ");
    let directory = command
        .current_directory
        .as_ref()
        .map_or_else(|| "<inherit>".to_owned(), |path| path.display().to_string());
    format!(
        "program `{}` with args [{arguments}], env [{environment}], cwd `{directory}`",
        program.display()
    )
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.as_std_mut().process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn process_group_id(pid: u32) -> Result<Option<i32>, RuntimeError> {
    i32::try_from(pid)
        .map(Some)
        .map_err(|_| RuntimeError::Provider(format!("process ID {pid} exceeds i32")))
}

#[cfg(not(unix))]
fn process_group_id(_pid: u32) -> Result<Option<i32>, RuntimeError> {
    Ok(None)
}

#[cfg(unix)]
fn send_process_group_signal(
    process_group: Option<i32>,
    signal: ProcessSignal,
) -> Result<(), RuntimeError> {
    use nix::{
        sys::signal::{Signal, killpg},
        unistd::Pid,
    };

    let process_group = process_group.ok_or(RuntimeError::UnsupportedProcessGroup)?;
    let signal_name = signal.to_string();
    let signal = match signal {
        ProcessSignal::Interrupt => Signal::SIGINT,
        ProcessSignal::Terminate => Signal::SIGTERM,
        ProcessSignal::Kill => Signal::SIGKILL,
        ProcessSignal::Hangup => Signal::SIGHUP,
        ProcessSignal::User1 => Signal::SIGUSR1,
        ProcessSignal::User2 => Signal::SIGUSR2,
    };
    killpg(Pid::from_raw(process_group), signal).map_err(|error| RuntimeError::Signal {
        process_group,
        signal: signal_name,
        source: std::io::Error::from_raw_os_error(error as i32),
    })
}

#[cfg(not(unix))]
fn send_process_group_signal(
    _process_group: Option<i32>,
    signal: ProcessSignal,
) -> Result<(), RuntimeError> {
    Err(RuntimeError::UnsupportedSignal {
        signal: signal.to_string(),
    })
}

#[cfg(unix)]
fn terminate_process(
    _child: Option<&mut Child>,
    process_group: Option<i32>,
) -> Result<(), RuntimeError> {
    ignore_missing_group(send_process_group_signal(
        process_group,
        ProcessSignal::Terminate,
    ))
}

#[cfg(not(unix))]
fn terminate_process(
    child: Option<&mut Child>,
    _process_group: Option<i32>,
) -> Result<(), RuntimeError> {
    child
        .ok_or_else(|| RuntimeError::Provider("process was already reaped".to_owned()))?
        .start_kill()
        .map_err(RuntimeError::Wait)
}

#[cfg(unix)]
fn force_kill_process(
    child: Option<&mut Child>,
    process_group: Option<i32>,
) -> Result<(), RuntimeError> {
    let result = ignore_missing_group(send_process_group_signal(
        process_group,
        ProcessSignal::Kill,
    ));
    if let Some(child) = child {
        child.start_kill().ok();
    }
    result
}

#[cfg(not(unix))]
fn force_kill_process(
    child: Option<&mut Child>,
    _process_group: Option<i32>,
) -> Result<(), RuntimeError> {
    child
        .ok_or_else(|| RuntimeError::Provider("process was already reaped".to_owned()))?
        .start_kill()
        .map_err(RuntimeError::Wait)
}

#[cfg(unix)]
fn ignore_missing_group(result: Result<(), RuntimeError>) -> Result<(), RuntimeError> {
    match result {
        Err(RuntimeError::Signal { source, .. })
            if source.raw_os_error() == Some(nix::errno::Errno::ESRCH as i32) =>
        {
            Ok(())
        }
        other => other,
    }
}

fn decode_exit_status(status: std::process::ExitStatus) -> ExitStatus {
    ExitStatus {
        success: status.success(),
        code: status.code(),
        signal: exit_signal(&status),
    }
}

#[cfg(unix)]
fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

#[cfg(unix)]
fn path_contains_nul(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().contains(&0)
}

#[cfg(windows)]
fn path_contains_nul(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str().encode_wide().any(|unit| unit == 0)
}

#[cfg(not(any(unix, windows)))]
fn path_contains_nul(path: &Path) -> bool {
    path.to_string_lossy().contains('\0')
}
