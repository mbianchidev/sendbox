//! One-shot dedicated launcher and bounded output streaming.

#![forbid(unsafe_code)]

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::api::{
    CleanupFailure, CleanupReport, CleanupStep, ExecutionDecision, ExecutionEvent,
    ExecutionRequest, ExecutionResult, LaunchFailure, RootId, StreamKind, TerminalState,
};
use crate::broker::{CancellationCause, CancellationFlag, EventSink, ExecutionBackend, SinkError};
use crate::error::{PlatformError, UnsupportedKernel};

use super::cgroup::{CgroupLeaf, CgroupManager};
use super::resolver::{ResolvedCommand, RootSet};
use super::{capabilities, raw, rlimits, seccomp};

const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
const OUTPUT_CHANNEL_DEPTH: usize = 16;
pub const MAX_LAUNCHER_FRAME_BYTES: usize = 1024 * 1024;

/// Trusted one-shot input sent by the broker to the dedicated launcher
/// process over a private inherited pipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherInvocation {
    pub request: ExecutionRequest,
    pub decision: ExecutionDecision,
    pub roots: Vec<LauncherRoot>,
    pub cgroup_parent: std::path::PathBuf,
    pub cleanup_bound_ms: u64,
    /// Optional supervisor-side output event bound. Reaching the bound is a
    /// typed saturation terminal state, never an unbounded buffer.
    pub output_event_limit: Option<u64>,
    pub environment_authority: EnvironmentAuthority,
}

/// Marks the request environment as the broker's immutable sanitized output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentAuthority {
    BrokerSanitizedV1,
}

/// One trusted root path opened by the dedicated launcher before processing
/// the descriptor-relative request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherRoot {
    pub id: RootId,
    pub path: std::path::PathBuf,
}

/// Bounded line-delimited controls sent over the launcher's stdin pipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "control", rename_all = "snake_case")]
pub enum LauncherControl {
    Start {
        invocation: Box<LauncherInvocation>,
    },
    Cancel {
        correlation_id: crate::api::CorrelationId,
    },
    ClientDisconnected {
        correlation_id: crate::api::CorrelationId,
    },
    OutputSaturated {
        correlation_id: crate::api::CorrelationId,
    },
    BrokerShutdown,
    SupervisorDied,
}

/// Real broker-side process backend for the dedicated launcher binary.
#[derive(Debug, Clone)]
pub struct LauncherProcessBackend {
    launcher_path: PathBuf,
    roots: Vec<LauncherRoot>,
    cgroup_parent: PathBuf,
    cleanup_bound: Duration,
    output_event_limit: Option<u64>,
}

impl LauncherProcessBackend {
    #[must_use]
    pub fn new(
        launcher_path: impl Into<PathBuf>,
        roots: Vec<LauncherRoot>,
        cgroup_parent: impl Into<PathBuf>,
        cleanup_bound: Duration,
    ) -> Self {
        Self {
            launcher_path: launcher_path.into(),
            roots,
            cgroup_parent: cgroup_parent.into(),
            cleanup_bound,
            output_event_limit: None,
        }
    }

    #[must_use]
    pub const fn with_output_event_limit(mut self, limit: Option<u64>) -> Self {
        self.output_event_limit = limit;
        self
    }
}

impl ExecutionBackend for LauncherProcessBackend {
    fn execute(
        &self,
        request: &ExecutionRequest,
        decision: &ExecutionDecision,
        sink: &mut dyn EventSink,
        cancellation: &CancellationFlag,
    ) -> ExecutionResult {
        let mut child = match Command::new(&self.launcher_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                return ExecutionResult {
                    terminal: TerminalState::LaunchFailed(LaunchFailure::LauncherBoundary {
                        message: format!(
                            "failed to spawn {}: {error}",
                            self.launcher_path.display()
                        ),
                    }),
                    cleanup: CleanupReport::no_child(),
                };
            }
        };
        let Some(control) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return launcher_setup_failure("launcher stdin pipe was not created");
        };
        let Some(events) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return launcher_setup_failure("launcher stdout pipe was not created");
        };
        let stderr_thread = child.stderr.take().map(spawn_stderr_reader);
        let control = Arc::new(Mutex::new(control));
        let invocation = LauncherInvocation {
            request: request.clone(),
            decision: decision.clone(),
            roots: self.roots.clone(),
            cgroup_parent: self.cgroup_parent.clone(),
            cleanup_bound_ms: u64::try_from(self.cleanup_bound.as_millis()).unwrap_or(u64::MAX),
            output_event_limit: self.output_event_limit,
            environment_authority: EnvironmentAuthority::BrokerSanitizedV1,
        };
        if let Err(error) = send_control_shared(
            &control,
            &LauncherControl::Start {
                invocation: Box::new(invocation),
            },
        ) {
            let _ = child.kill();
            let _ = child.wait();
            return launcher_setup_failure(&format!("write launcher invocation: {error}"));
        }

        let done = Arc::new(AtomicBool::new(false));
        let watcher = spawn_cancellation_watcher(
            Arc::clone(&control),
            Arc::clone(&done),
            cancellation.clone(),
            request.correlation_id.clone(),
        );
        let mut reader = BufReader::new(events);
        let mut terminal = None;
        let mut sink_failed = false;
        loop {
            let line = match read_bounded_line(&mut reader) {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(error) => {
                    let _ = send_control_shared(&control, &LauncherControl::BrokerShutdown);
                    done.store(true, Ordering::Release);
                    let _ = watcher.join();
                    let _ = child.wait();
                    return launcher_lost_failure(&format!("read launcher event frame: {error}"));
                }
            };
            let event: ExecutionEvent = match serde_json::from_slice(&line) {
                Ok(event) => event,
                Err(error) => {
                    let _ = send_control_shared(&control, &LauncherControl::BrokerShutdown);
                    done.store(true, Ordering::Release);
                    let _ = watcher.join();
                    let _ = child.wait();
                    return launcher_lost_failure(&format!("decode launcher event frame: {error}"));
                }
            };
            if event_correlation(&event) != &request.correlation_id {
                let _ = send_control_shared(&control, &LauncherControl::BrokerShutdown);
                break;
            }
            match event {
                ExecutionEvent::Terminal { result, .. } => {
                    terminal = Some(result);
                    break;
                }
                other if sink_failed => drop(other),
                other => {
                    if let Err(error) = sink.emit(other) {
                        sink_failed = true;
                        let control_message = match error {
                            SinkError::Disconnected => LauncherControl::ClientDisconnected {
                                correlation_id: request.correlation_id.clone(),
                            },
                            SinkError::Saturated => LauncherControl::OutputSaturated {
                                correlation_id: request.correlation_id.clone(),
                            },
                            SinkError::SupervisorDied => LauncherControl::SupervisorDied,
                        };
                        let _ = send_control_shared(&control, &control_message);
                    }
                }
            }
        }

        done.store(true, Ordering::Release);
        let _ = watcher.join();
        drop(control);
        let status = child.wait();
        let stderr = stderr_thread
            .and_then(|thread| thread.join().ok())
            .unwrap_or_default();
        if let Some(result) = terminal {
            return result;
        }
        let status = status
            .map(|value| value.to_string())
            .unwrap_or_else(|error| error.to_string());
        launcher_lost_failure(&format!(
            "launcher exited without Terminal event ({status}): {}",
            String::from_utf8_lossy(&stderr)
        ))
    }
}

/// Backend intended to live in a dedicated, single-threaded launcher process.
///
/// It fails closed if `/proc/self/task` shows any additional thread. This
/// prevents raw clone3 child work from ever running inside a Tokio
/// multithreaded broker process.
#[derive(Debug)]
pub struct DedicatedLauncherBackend {
    roots: RootSet,
    cgroups: CgroupManager,
    cleanup_bound: Duration,
    used: AtomicBool,
}

impl DedicatedLauncherBackend {
    #[must_use]
    pub fn new(roots: RootSet, cgroups: CgroupManager, cleanup_bound: Duration) -> Self {
        Self {
            roots,
            cgroups,
            cleanup_bound,
            used: AtomicBool::new(false),
        }
    }

    /// Removes the supervisor cgroup subtree after the one-shot command leaf
    /// has been cleaned.
    pub fn remove_cgroup(self) -> Result<(), PlatformError> {
        self.cgroups.remove()
    }

    pub fn execute_with_control<R>(
        &self,
        request: &ExecutionRequest,
        sink: &mut dyn EventSink,
        cancellation: &CancellationFlag,
        control: R,
    ) -> ExecutionResult
    where
        R: BufRead + Send + 'static,
    {
        self.execute_inner(request, sink, cancellation, Some(Box::new(control)))
    }

    fn execute_inner(
        &self,
        request: &ExecutionRequest,
        sink: &mut dyn EventSink,
        cancellation: &CancellationFlag,
        control: Option<Box<dyn BufRead + Send>>,
    ) -> ExecutionResult {
        if self.used.swap(true, Ordering::AcqRel) {
            return ExecutionResult {
                terminal: TerminalState::LaunchFailed(LaunchFailure::LauncherBoundary {
                    message: "dedicated launcher is one-shot and has already been used".into(),
                }),
                cleanup: CleanupReport::no_child(),
            };
        }
        let resolved = match self.roots.resolve(&request.executable, &request.cwd) {
            Ok(resolved) => resolved,
            Err(error) => return launch_error(error, CleanupReport::no_child()),
        };
        let leaf = match self.cgroups.create_leaf(&request.containment) {
            Ok(leaf) => leaf,
            Err(error) => return launch_error(error, CleanupReport::no_child()),
        };
        run(
            request,
            resolved,
            leaf,
            sink,
            cancellation,
            self.cleanup_bound,
            control,
        )
    }
}

impl ExecutionBackend for DedicatedLauncherBackend {
    fn execute(
        &self,
        request: &ExecutionRequest,
        _decision: &ExecutionDecision,
        sink: &mut dyn EventSink,
        cancellation: &CancellationFlag,
    ) -> ExecutionResult {
        self.execute_inner(request, sink, cancellation, None)
    }
}

fn run(
    request: &ExecutionRequest,
    resolved: ResolvedCommand,
    leaf: CgroupLeaf,
    sink: &mut dyn EventSink,
    cancellation: &CancellationFlag,
    cleanup_bound: Duration,
    control: Option<Box<dyn BufRead + Send>>,
) -> ExecutionResult {
    if let Err(error) = require_single_threaded_launcher() {
        return launch_error(error, leaf.remove_unlaunched());
    }
    if let Err(error) = raw::set_child_subreaper()
        .and_then(|()| raw::set_no_new_privs())
        .and_then(|()| rlimits::apply(&request.containment.rlimits))
        .and_then(|()| {
            if request.containment.run_as.is_none() {
                capabilities::drop_all()
            } else {
                Ok(())
            }
        })
        .and_then(|()| {
            seccomp::install(seccomp::Profile::Command {
                additional_denied_syscalls: &request.containment.additional_denied_syscalls,
            })
        })
    {
        return launch_error(error, leaf.remove_unlaunched());
    }

    let argv = match prepare_argv(&request.argv) {
        Ok(argv) => argv,
        Err(error) => return launch_error(error, leaf.remove_unlaunched()),
    };
    let environment = match prepare_environment(request) {
        Ok(environment) => environment,
        Err(error) => return launch_error(error, leaf.remove_unlaunched()),
    };
    let process = match raw::clone3_exec(
        leaf.as_raw_fd(),
        resolved.executable_fd.as_raw_fd(),
        resolved.cwd_fd.as_raw_fd(),
        &argv,
        &environment,
        request.containment.run_as,
    ) {
        Ok(process) => process,
        Err(error) => return launch_error(error, leaf.remove_unlaunched()),
    };
    let raw::SpawnedProcess {
        pidfd,
        stdout,
        stderr,
        exec_error,
    } = process;
    if let Some(control) = control {
        spawn_launcher_control_monitor(
            control,
            cancellation.clone(),
            request.correlation_id.clone(),
        );
    }

    if let Err(error) = confirm_exec(exec_error) {
        let (cleanup, _) = leaf.cleanup(pidfd.as_raw_fd(), cleanup_bound);
        return launch_error(error, cleanup);
    }
    if let Some(terminal) = terminal_from_cancellation(cancellation.cause()) {
        let (cleanup, _) = leaf.cleanup(pidfd.as_raw_fd(), cleanup_bound);
        return ExecutionResult { terminal, cleanup };
    }

    if let Err(error) = sink.emit(ExecutionEvent::Started {
        correlation_id: request.correlation_id.clone(),
        executable_identity: resolved.executable_identity,
        cwd_identity: resolved.cwd_identity,
    }) {
        let terminal = terminal_from_sink_error(error);
        let (cleanup, _) = leaf.cleanup(pidfd.as_raw_fd(), cleanup_bound);
        return ExecutionResult { terminal, cleanup };
    }

    let (sender, receiver) = mpsc::sync_channel(OUTPUT_CHANNEL_DEPTH);
    let stdout_thread = spawn_reader(stdout, StreamKind::Stdout, sender.clone());
    let stderr_thread = spawn_reader(stderr, StreamKind::Stderr, sender);
    let deadline = Instant::now() + request.timeout.as_duration();
    let mut sequence = 0u64;
    let mut terminal = loop {
        if let Some(terminal) = terminal_from_cancellation(cancellation.cause()) {
            break terminal;
        }
        if Instant::now() >= deadline {
            break TerminalState::TimedOut;
        }
        match raw::pidfd_has_exited(pidfd.as_raw_fd()) {
            Ok(true) => {
                break TerminalState::Exited(crate::api::ExitStatus {
                    exit_code: None,
                    signal: None,
                });
            }
            Ok(false) => {}
            Err(error) => {
                break TerminalState::LaunchFailed(platform_launch_failure(error));
            }
        }
        if let Some(next) = receive_output(&receiver) {
            sequence = sequence.saturating_add(1);
            let event = ExecutionEvent::Output {
                correlation_id: request.correlation_id.clone(),
                stream: next.stream,
                sequence,
                data: next.data,
            };
            if let Err(error) = sink.emit(event) {
                break terminal_from_sink_error(error);
            }
        }
    };

    let (cleanup, exit_status) = leaf.cleanup(pidfd.as_raw_fd(), cleanup_bound);
    if matches!(terminal, TerminalState::Exited(_))
        && let Some(status) = exit_status
    {
        terminal = TerminalState::Exited(status);
    }

    drain_after_cleanup(
        &receiver,
        sink,
        request,
        &mut sequence,
        &mut terminal,
        Duration::from_millis(250),
    );
    drop(receiver);
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();
    ExecutionResult { terminal, cleanup }
}

#[derive(Debug)]
struct OutputChunk {
    stream: StreamKind,
    data: Vec<u8>,
}

fn spawn_reader(
    descriptor: OwnedFd,
    stream: StreamKind,
    sender: SyncSender<OutputChunk>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut file = File::from(descriptor);
        let mut buffer = vec![0u8; OUTPUT_CHUNK_BYTES];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    if sender
                        .send(OutputChunk {
                            stream,
                            data: buffer[..length].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    })
}

fn receive_output(receiver: &Receiver<OutputChunk>) -> Option<OutputChunk> {
    receiver.recv_timeout(Duration::from_millis(10)).ok()
}

fn drain_after_cleanup(
    receiver: &Receiver<OutputChunk>,
    sink: &mut dyn EventSink,
    request: &ExecutionRequest,
    sequence: &mut u64,
    terminal: &mut TerminalState,
    bound: Duration,
) {
    if matches!(
        terminal,
        TerminalState::ClientDisconnected | TerminalState::OutputSaturated
    ) {
        return;
    }
    let deadline = Instant::now() + bound;
    loop {
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(output) => {
                *sequence = sequence.saturating_add(1);
                if let Err(error) = sink.emit(ExecutionEvent::Output {
                    correlation_id: request.correlation_id.clone(),
                    stream: output.stream,
                    sequence: *sequence,
                    data: output.data,
                }) {
                    *terminal = terminal_from_sink_error(error);
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
                if matches!(terminal, TerminalState::Exited(_)) {
                    *terminal = TerminalState::OutputSaturated;
                }
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn confirm_exec(descriptor: OwnedFd) -> Result<(), PlatformError> {
    let mut file = File::from(descriptor);
    let mut bytes = [0u8; 5];
    let mut offset = 0;
    loop {
        match file.read(&mut bytes[offset..]) {
            Ok(0) if offset == 0 => return Ok(()),
            Ok(0) => {
                return Err(PlatformError::io(
                    "read child exec status",
                    io::Error::new(io::ErrorKind::UnexpectedEof, "partial errno"),
                ));
            }
            Ok(length) => {
                offset += length;
                if offset == bytes.len() {
                    let errno = i32::from_ne_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
                    if bytes[0] == 2 {
                        return Err(UnsupportedKernel::new(
                            crate::error::KernelPrimitive::Seccomp,
                            Some(errno),
                            "child-only clone3 seccomp filter could not be installed",
                        )
                        .into());
                    }
                    if bytes[0] == 3 && errno == libc::ENOSYS {
                        return Err(UnsupportedKernel::new(
                            crate::error::KernelPrimitive::ExecveatEmptyPath,
                            Some(errno),
                            "execveat(AT_EMPTY_PATH) is unavailable",
                        )
                        .into());
                    }
                    if bytes[0] != 3 {
                        return Err(PlatformError::SecuritySetup(format!(
                            "post-clone child setup stage {} failed: {}",
                            bytes[0],
                            io::Error::from_raw_os_error(errno)
                        )));
                    }
                    return Err(PlatformError::ChildExec { errno });
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(PlatformError::io("read child exec status", error)),
        }
    }
}

fn prepare_argv(argv: &[String]) -> Result<Vec<CString>, PlatformError> {
    argv.iter()
        .map(|argument| {
            CString::new(argument.as_str()).map_err(|_| {
                PlatformError::io(
                    "prepare argv",
                    io::Error::new(io::ErrorKind::InvalidInput, "argument contains NUL"),
                )
            })
        })
        .collect()
}

fn prepare_environment(request: &ExecutionRequest) -> Result<Vec<CString>, PlatformError> {
    request
        .environment
        .iter()
        .map(|entry| {
            CString::new(format!("{}={}", entry.name, entry.value)).map_err(|_| {
                PlatformError::io(
                    "prepare environment",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "environment entry contains NUL",
                    ),
                )
            })
        })
        .collect()
}

pub fn write_control_frame(writer: &mut impl Write, control: &LauncherControl) -> io::Result<()> {
    let encoded = serde_json::to_vec(control).map_err(io::Error::other)?;
    if encoded.len() > MAX_LAUNCHER_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher control frame exceeds limit",
        ));
    }
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

pub fn read_control_frame(reader: &mut impl BufRead) -> io::Result<Option<LauncherControl>> {
    let Some(line) = read_bounded_line(reader)? else {
        return Ok(None);
    };
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(io::Error::other)
}

pub fn write_event_frame(writer: &mut impl Write, event: &ExecutionEvent) -> io::Result<()> {
    let encoded = serde_json::to_vec(event).map_err(io::Error::other)?;
    if encoded.len() > MAX_LAUNCHER_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher event frame exceeds limit",
        ));
    }
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn read_bounded_line(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "launcher frame ended without newline",
                ))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(consumed) > MAX_LAUNCHER_FRAME_BYTES + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "launcher frame exceeds limit",
            ));
        }
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

fn send_control_shared(
    writer: &Arc<Mutex<ChildStdin>>,
    control: &LauncherControl,
) -> io::Result<()> {
    let mut writer = writer
        .lock()
        .map_err(|_| io::Error::other("launcher control mutex poisoned"))?;
    write_control_frame(&mut *writer, control)
}

fn spawn_cancellation_watcher(
    control: Arc<Mutex<ChildStdin>>,
    done: Arc<AtomicBool>,
    cancellation: CancellationFlag,
    correlation_id: crate::api::CorrelationId,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !done.load(Ordering::Acquire) {
            let message = match cancellation.cause() {
                CancellationCause::None => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                CancellationCause::Cancelled => LauncherControl::Cancel {
                    correlation_id: correlation_id.clone(),
                },
                CancellationCause::ClientDisconnected => LauncherControl::ClientDisconnected {
                    correlation_id: correlation_id.clone(),
                },
                CancellationCause::BrokerShutdown => LauncherControl::BrokerShutdown,
                CancellationCause::SupervisorDied => LauncherControl::SupervisorDied,
                CancellationCause::OutputSaturated => LauncherControl::OutputSaturated {
                    correlation_id: correlation_id.clone(),
                },
            };
            let _ = send_control_shared(&control, &message);
            return;
        }
    })
}

fn spawn_launcher_control_monitor(
    mut reader: Box<dyn BufRead + Send>,
    cancellation: CancellationFlag,
    correlation_id: crate::api::CorrelationId,
) {
    thread::spawn(move || {
        let control = match read_control_frame(&mut reader) {
            Ok(Some(control)) => control,
            Ok(None) | Err(_) => {
                cancellation.supervisor_died();
                return;
            }
        };
        match control {
            LauncherControl::Cancel {
                correlation_id: requested,
            } if requested == correlation_id => {
                cancellation.cancel();
            }
            LauncherControl::ClientDisconnected {
                correlation_id: requested,
            } if requested == correlation_id => {
                cancellation.disconnect();
            }
            LauncherControl::OutputSaturated {
                correlation_id: requested,
            } if requested == correlation_id => {
                cancellation.saturate();
            }
            LauncherControl::BrokerShutdown => {
                cancellation.shutdown();
            }
            LauncherControl::SupervisorDied => {
                cancellation.supervisor_died();
            }
            LauncherControl::Start { .. }
            | LauncherControl::Cancel { .. }
            | LauncherControl::ClientDisconnected { .. }
            | LauncherControl::OutputSaturated { .. } => {
                cancellation.supervisor_died();
            }
        }
    });
}

fn spawn_stderr_reader(mut stderr: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut output = Vec::new();
        let _ = stderr
            .by_ref()
            .take(MAX_LAUNCHER_FRAME_BYTES as u64)
            .read_to_end(&mut output);
        output
    })
}

fn event_correlation(event: &ExecutionEvent) -> &crate::api::CorrelationId {
    match event {
        ExecutionEvent::Started { correlation_id, .. }
        | ExecutionEvent::Output { correlation_id, .. }
        | ExecutionEvent::Terminal { correlation_id, .. } => correlation_id,
    }
}

fn launcher_setup_failure(message: &str) -> ExecutionResult {
    ExecutionResult {
        terminal: TerminalState::LaunchFailed(LaunchFailure::LauncherBoundary {
            message: message.to_owned(),
        }),
        cleanup: CleanupReport::no_child(),
    }
}

fn launcher_lost_failure(message: &str) -> ExecutionResult {
    ExecutionResult {
        terminal: TerminalState::SupervisorDied,
        cleanup: CleanupReport::from_attempts(
            Vec::new(),
            vec![CleanupFailure {
                step: CleanupStep::CgroupKill,
                message: format!("launcher cleanup could not be confirmed: {message}"),
            }],
        ),
    }
}

fn require_single_threaded_launcher() -> Result<(), PlatformError> {
    let threads = fs::read_dir("/proc/self/task")
        .map_err(|source| PlatformError::io("enumerate launcher threads", source))?
        .count();
    if threads != 1 {
        return Err(PlatformError::MultithreadedLauncher { threads });
    }
    Ok(())
}

fn terminal_from_sink_error(error: SinkError) -> TerminalState {
    match error {
        SinkError::Disconnected => TerminalState::ClientDisconnected,
        SinkError::Saturated => TerminalState::OutputSaturated,
        SinkError::SupervisorDied => TerminalState::SupervisorDied,
    }
}

fn terminal_from_cancellation(cause: CancellationCause) -> Option<TerminalState> {
    match cause {
        CancellationCause::None => None,
        CancellationCause::Cancelled => Some(TerminalState::Cancelled),
        CancellationCause::ClientDisconnected => Some(TerminalState::ClientDisconnected),
        CancellationCause::BrokerShutdown => Some(TerminalState::BrokerShutdown),
        CancellationCause::SupervisorDied => Some(TerminalState::SupervisorDied),
        CancellationCause::OutputSaturated => Some(TerminalState::OutputSaturated),
    }
}

fn launch_error(error: PlatformError, cleanup: CleanupReport) -> ExecutionResult {
    ExecutionResult {
        terminal: TerminalState::LaunchFailed(platform_launch_failure(error)),
        cleanup,
    }
}

fn platform_launch_failure(error: PlatformError) -> LaunchFailure {
    match error {
        PlatformError::UnsupportedKernel(error) => LaunchFailure::UnsupportedKernel(error),
        PlatformError::ChildExec { errno } => LaunchFailure::Exec {
            errno: Some(errno),
            message: io::Error::from_raw_os_error(errno).to_string(),
        },
        PlatformError::MultithreadedLauncher { threads } => LaunchFailure::LauncherBoundary {
            message: format!("dedicated launcher has {threads} threads"),
        },
        other => LaunchFailure::PolicySetup {
            message: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_channel_classifies_output_saturation() {
        assert_eq!(
            terminal_from_sink_error(SinkError::Saturated),
            TerminalState::OutputSaturated
        );
    }

    #[test]
    fn unsupported_kernel_remains_typed_at_terminal_boundary() {
        let error = PlatformError::UnsupportedKernel(UnsupportedKernel::new(
            crate::error::KernelPrimitive::Clone3IntoCgroup,
            Some(libc::ENOSYS),
            "test",
        ));
        assert!(matches!(
            platform_launch_failure(error),
            LaunchFailure::UnsupportedKernel(UnsupportedKernel {
                primitive: crate::error::KernelPrimitive::Clone3IntoCgroup,
                ..
            })
        ));
    }
}
