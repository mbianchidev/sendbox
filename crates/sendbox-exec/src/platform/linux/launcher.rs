//! One-shot dedicated launcher and bounded output streaming.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
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
use crate::broker::{
    CancellationCause, CancellationFlag, ChannelInput, EventSink, ExecutionBackend,
    InputOfferError, InputSender, InputSource, SinkError, TerminalCommand,
};
use crate::error::{PlatformError, UnsupportedKernel};

use super::cgroup::{CgroupLeaf, CgroupManager};
use super::resolver::{ResolvedCommand, RootSet};
use super::{capabilities, raw, rlimits, seccomp};

const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
const OUTPUT_CHANNEL_DEPTH: usize = 16;
const INPUT_CONTROL_RESERVE: usize = 8;
const INPUT_CHANNEL_DEPTH: usize =
    sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS as usize + INPUT_CONTROL_RESERVE;
/// Hard bound on queuing one terminal command, so the control reader keeps
/// observing cancellation even while the workload ignores its terminal.
const INPUT_OFFER_BOUND: Duration = Duration::from_millis(250);
const REQUIRED_INPUT_BOUND: Duration = Duration::from_secs(5);
/// How long one pass waits for a non-draining workload to accept more input
/// before letting the writer thread look at cancellation again.
const INPUT_WRITE_SLICE: Duration = Duration::from_millis(10);
/// Largest terminal backlog held for a workload that is not reading it.
const MAX_PENDING_INPUT: usize =
    sendbox_core::TERMINAL_INPUT_CHUNK_BYTES * sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS as usize;
/// Largest terminal chunk forwarded in one control frame.
pub const MAX_TERMINAL_INPUT_BYTES: usize = sendbox_core::TERMINAL_INPUT_CHUNK_BYTES;
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
///
/// `Input` carries raw terminal bytes, so its [`std::fmt::Debug`] reports only
/// a length; pasted credentials must never reach a log.
#[derive(Clone, Serialize, Deserialize)]
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
    /// Terminal bytes for an interactive workload.
    Input {
        correlation_id: crate::api::CorrelationId,
        data: Vec<u8>,
    },
    /// The host input stream ended.
    InputEof {
        correlation_id: crate::api::CorrelationId,
    },
    /// The host terminal was resized.
    Resize {
        correlation_id: crate::api::CorrelationId,
        columns: u16,
        rows: u16,
    },
}

impl std::fmt::Debug for LauncherControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start { invocation } => formatter
                .debug_struct("Start")
                .field("invocation", invocation)
                .finish(),
            Self::Cancel { correlation_id } => formatter
                .debug_struct("Cancel")
                .field("correlation_id", correlation_id)
                .finish(),
            Self::ClientDisconnected { correlation_id } => formatter
                .debug_struct("ClientDisconnected")
                .field("correlation_id", correlation_id)
                .finish(),
            Self::OutputSaturated { correlation_id } => formatter
                .debug_struct("OutputSaturated")
                .field("correlation_id", correlation_id)
                .finish(),
            Self::BrokerShutdown => formatter.write_str("BrokerShutdown"),
            Self::SupervisorDied => formatter.write_str("SupervisorDied"),
            Self::Input {
                correlation_id,
                data,
            } => formatter
                .debug_struct("Input")
                .field("correlation_id", correlation_id)
                .field("data", &format_args!("<{} bytes>", data.len()))
                .finish(),
            Self::InputEof { correlation_id } => formatter
                .debug_struct("InputEof")
                .field("correlation_id", correlation_id)
                .finish(),
            Self::Resize {
                correlation_id,
                columns,
                rows,
            } => formatter
                .debug_struct("Resize")
                .field("correlation_id", correlation_id)
                .field("columns", columns)
                .field("rows", rows)
                .finish(),
        }
    }
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
        input: &dyn InputSource,
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
        // Terminal input is forwarded on its own scoped thread so a stalled
        // workload never delays the cancellation watcher or the event loop.
        let outcome = thread::scope(|scope| {
            let forwarder = request.stdin.is_terminal().then(|| {
                let control = Arc::clone(&control);
                let done = Arc::clone(&done);
                let cancellation = cancellation.clone();
                let correlation_id = request.correlation_id.clone();
                scope.spawn(move || {
                    forward_terminal_input(&control, &done, &cancellation, &correlation_id, input);
                })
            });
            let outcome =
                pump_launcher_events(&mut reader, &control, sink, &request.correlation_id);
            done.store(true, Ordering::Release);
            if let Some(forwarder) = forwarder {
                let _ = forwarder.join();
            }
            outcome
        });
        let _ = watcher.join();
        let terminal = match outcome {
            LauncherOutcome::Terminal(result) => Some(result),
            LauncherOutcome::EventStreamEnded => None,
            LauncherOutcome::Lost(message) => {
                let _ = child.wait();
                drop(control);
                return launcher_lost_failure(&message);
            }
        };
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
        _input: &dyn InputSource,
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
    if let Err(error) = admit_terminal_request(request) {
        return launch_error(error, leaf.remove_unlaunched());
    }
    // The pair must exist before the launcher's own seccomp filter is
    // installed, so a profile that denies ioctl still permits allocation while
    // failing closed at admission above.
    let mut terminal_device = match open_terminal_device(request) {
        Ok(device) => device,
        Err(error) => return launch_error(error, leaf.remove_unlaunched()),
    };
    let mut terminal_input: Option<Arc<ChannelInput>> = None;
    if let (Some(device), Some(user)) = (terminal_device.as_ref(), request.containment.run_as)
        && let Err(error) = device.transfer_secondaries_to(user)
    {
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
    let terminal_stdio = match terminal_device
        .as_ref()
        .map(super::pty::TerminalDevices::secondary_raw_fds)
        .transpose()
    {
        Ok(Some((controlling_secondary, stderr_secondary))) => Some(raw::TerminalStdio {
            controlling_secondary,
            stderr_secondary,
        }),
        Ok(None) => None,
        Err(error) => return launch_error(error, leaf.remove_unlaunched()),
    };
    let process = match raw::clone3_exec(
        leaf.as_raw_fd(),
        resolved.executable_fd.as_raw_fd(),
        resolved.cwd_fd.as_raw_fd(),
        &argv,
        &environment,
        request.containment.run_as,
        terminal_stdio,
    ) {
        Ok(process) => process,
        Err(error) => return launch_error(error, leaf.remove_unlaunched()),
    };
    // Dropping the launcher's secondary is what lets the primary report EOF
    // once the workload exits; holding it would hang the output pump forever.
    if let Some(device) = terminal_device.as_mut() {
        device.release_secondaries();
    }
    let raw::SpawnedProcess {
        pidfd,
        stdout,
        stderr,
        exec_error,
    } = process;
    if let Some(control) = control {
        let (input_sender, input_queue) = if request.stdin.is_terminal() {
            let (sender, queue) = ChannelInput::bounded(INPUT_CHANNEL_DEPTH);
            (Some(sender), Some(Arc::new(queue)))
        } else {
            (None, None)
        };
        terminal_input = input_queue;
        spawn_launcher_control_monitor(
            control,
            cancellation.clone(),
            request.correlation_id.clone(),
            input_sender,
            request.stdin.uses_flow_control(),
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
    // All pump threads start only after clone3, so the single-thread guard
    // above still holds for the raw child branch.
    let mut readers = Vec::new();
    let writer_done = Arc::new(AtomicBool::new(false));
    let mut terminal_writer = None;
    if let Some(device) = terminal_device {
        let writer = match TerminalWriter::new(device, request.stdin.uses_flow_control()) {
            Ok(writer) => writer,
            Err(error) => {
                let (cleanup, _) = leaf.cleanup(pidfd.as_raw_fd(), cleanup_bound);
                return launch_error(error, cleanup);
            }
        };
        let primary = match writer.devices.controlling_primary().try_clone() {
            Ok(primary) => primary,
            Err(error) => {
                let (cleanup, _) = leaf.cleanup(pidfd.as_raw_fd(), cleanup_bound);
                return launch_error(
                    PlatformError::io("duplicate pseudoterminal primary", error),
                    cleanup,
                );
            }
        };
        readers.push(spawn_terminal_reader(
            primary,
            StreamKind::Stdout,
            sender.clone(),
        ));
        if let Some(stderr) = writer.devices.stderr_primary() {
            let primary = match stderr.try_clone() {
                Ok(primary) => primary,
                Err(error) => {
                    let (cleanup, _) = leaf.cleanup(pidfd.as_raw_fd(), cleanup_bound);
                    return launch_error(
                        PlatformError::io("duplicate stderr pseudoterminal primary", error),
                        cleanup,
                    );
                }
            };
            readers.push(spawn_terminal_reader(
                primary,
                StreamKind::Stderr,
                sender.clone(),
            ));
        }
        if let Some(queue) = terminal_input {
            terminal_writer = Some(spawn_terminal_writer(
                writer,
                queue,
                cancellation.clone(),
                Arc::clone(&writer_done),
                sender.clone(),
                request.stdin.uses_flow_control(),
            ));
        }
        drop(sender);
    } else {
        if let Some(stdout) = stdout {
            readers.push(spawn_reader(stdout, StreamKind::Stdout, sender.clone()));
        }
        if let Some(stderr) = stderr {
            readers.push(spawn_reader(stderr, StreamKind::Stderr, sender.clone()));
        }
        drop(sender);
    }
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
            let event = match next {
                LauncherEvent::Output(next) => {
                    sequence = sequence.saturating_add(1);
                    ExecutionEvent::Output {
                        correlation_id: request.correlation_id.clone(),
                        stream: next.stream,
                        sequence,
                        data: next.data,
                    }
                }
                LauncherEvent::TerminalInputCredit(credits) => {
                    ExecutionEvent::TerminalInputCredit {
                        correlation_id: request.correlation_id.clone(),
                        credits,
                    }
                }
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
    writer_done.store(true, Ordering::Release);
    if let Some(writer) = terminal_writer {
        let _ = writer.join();
    }
    for reader in readers {
        let _ = reader.join();
    }
    ExecutionResult { terminal, cleanup }
}

/// Rejects an interactive request whose seccomp profile would make the child's
/// controlling-terminal setup fail opaquely inside the post-clone branch.
fn admit_terminal_request(request: &ExecutionRequest) -> Result<(), PlatformError> {
    if !request.stdin.is_terminal() {
        return Ok(());
    }
    const TERMINAL_SYSCALLS: &[&str] = &["ioctl", "setsid", "dup2", "dup3"];
    let denied: Vec<&str> = TERMINAL_SYSCALLS
        .iter()
        .copied()
        .filter(|syscall| {
            request
                .containment
                .additional_denied_syscalls
                .iter()
                .any(|denied| denied == syscall)
        })
        .collect();
    if denied.is_empty() {
        return Ok(());
    }
    Err(PlatformError::SecuritySetup(format!(
        "interactive execution needs a controlling terminal, but the command policy denies: {}. \
         Remove these syscalls from denied_syscalls or run without a terminal",
        denied.join(", ")
    )))
}

fn open_terminal_device(
    request: &ExecutionRequest,
) -> Result<Option<super::pty::TerminalDevices>, PlatformError> {
    match request.stdin.terminal_size() {
        None => Ok(None),
        Some((columns, rows)) => {
            super::pty::TerminalDevices::open(columns, rows, request.stdin.separates_stderr())
                .map(Some)
        }
    }
}

#[derive(Debug)]
struct OutputChunk {
    stream: StreamKind,
    data: Vec<u8>,
}

#[derive(Debug)]
enum LauncherEvent {
    Output(OutputChunk),
    TerminalInputCredit(u16),
}

fn spawn_reader(
    descriptor: OwnedFd,
    stream: StreamKind,
    sender: SyncSender<LauncherEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut file = File::from(descriptor);
        let mut buffer = vec![0u8; OUTPUT_CHUNK_BYTES];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    if sender
                        .send(LauncherEvent::Output(OutputChunk {
                            stream,
                            data: buffer[..length].to_vec(),
                        }))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // A pseudoterminal primary reports EIO rather than a zero-length
                // read once the last secondary is closed; that is normal EOF.
                Err(_) => break,
            }
        }
    })
}

/// Reads merged pseudoterminal output.
///
/// The primary is non-blocking so the writer's bound is real, which means this
/// reader has to wait for readiness itself. `poll` returns on hangup too, so
/// the following read still reports the EIO that ends the stream.
fn spawn_terminal_reader(
    descriptor: OwnedFd,
    stream: StreamKind,
    sender: SyncSender<LauncherEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut file = File::from(descriptor);
        let mut buffer = vec![0u8; OUTPUT_CHUNK_BYTES];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    if sender
                        .send(LauncherEvent::Output(OutputChunk {
                            stream,
                            data: buffer[..length].to_vec(),
                        }))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !wait_readable(&file) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

fn wait_readable(primary: &File) -> bool {
    let primary = primary.as_fd();
    let mut fds = [rustix::event::PollFd::new(
        &primary,
        rustix::event::PollFlags::IN,
    )];
    loop {
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => return true,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return false,
        }
    }
}

fn receive_output(receiver: &Receiver<LauncherEvent>) -> Option<LauncherEvent> {
    receiver.recv_timeout(Duration::from_millis(10)).ok()
}

fn drain_after_cleanup(
    receiver: &Receiver<LauncherEvent>,
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
            Ok(LauncherEvent::Output(output)) => {
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
            Ok(LauncherEvent::TerminalInputCredit(_)) => {}
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
                    if bytes[0] == 4 {
                        return Err(PlatformError::SecuritySetup(format!(
                            "child could not claim the pseudoterminal as its controlling \
                             terminal: {}. Interactive runs require setsid and the TIOCSCTTY \
                             ioctl to be permitted by the command seccomp profile",
                            io::Error::from_raw_os_error(errno)
                        )));
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

/// Reads launcher controls until a terminal cause arrives.
///
/// Terminal input is handed to a separate writer thread through a bounded
/// queue with a hard offer bound, so a workload that stops reading its terminal
/// can never stop this loop from observing a later cancel.
fn spawn_launcher_control_monitor(
    mut reader: Box<dyn BufRead + Send>,
    cancellation: CancellationFlag,
    correlation_id: crate::api::CorrelationId,
    terminal: Option<InputSender>,
    flow_controlled: bool,
) {
    thread::spawn(move || {
        loop {
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
                    return;
                }
                LauncherControl::ClientDisconnected {
                    correlation_id: requested,
                } if requested == correlation_id => {
                    cancellation.disconnect();
                    return;
                }
                LauncherControl::OutputSaturated {
                    correlation_id: requested,
                } if requested == correlation_id => {
                    cancellation.saturate();
                    return;
                }
                LauncherControl::BrokerShutdown => {
                    cancellation.shutdown();
                    return;
                }
                LauncherControl::SupervisorDied => {
                    cancellation.supervisor_died();
                    return;
                }
                LauncherControl::Input {
                    correlation_id: requested,
                    data,
                } if requested == correlation_id => {
                    if !offer_terminal(
                        terminal.as_ref(),
                        TerminalCommand::Input(data),
                        &cancellation,
                        flow_controlled,
                    ) {
                        return;
                    }
                }
                LauncherControl::InputEof {
                    correlation_id: requested,
                } if requested == correlation_id => {
                    if !offer_terminal(
                        terminal.as_ref(),
                        TerminalCommand::InputEof,
                        &cancellation,
                        flow_controlled,
                    ) {
                        return;
                    }
                }
                LauncherControl::Resize {
                    correlation_id: requested,
                    columns,
                    rows,
                } if requested == correlation_id => {
                    if !offer_terminal(
                        terminal.as_ref(),
                        TerminalCommand::Resize { columns, rows },
                        &cancellation,
                        flow_controlled,
                    ) {
                        return;
                    }
                }
                LauncherControl::Start { .. }
                | LauncherControl::Cancel { .. }
                | LauncherControl::ClientDisconnected { .. }
                | LauncherControl::OutputSaturated { .. }
                | LauncherControl::Input { .. }
                | LauncherControl::InputEof { .. }
                | LauncherControl::Resize { .. } => {
                    cancellation.supervisor_died();
                    return;
                }
            }
        }
    });
}

/// Queues one terminal command. Returns `false` when the monitor must stop.
fn offer_terminal(
    terminal: Option<&InputSender>,
    command: TerminalCommand,
    cancellation: &CancellationFlag,
    flow_controlled: bool,
) -> bool {
    let Some(sender) = terminal else {
        // Terminal traffic for a headless launch is a supervisor protocol bug.
        eprintln!("sendbox-launcher: terminal control received for a non-interactive launch");
        cancellation.supervisor_died();
        return false;
    };
    let required = matches!(command, TerminalCommand::InputEof);
    let offered = if flow_controlled {
        sender.try_offer(command)
    } else {
        sender.offer(
            command,
            if required {
                REQUIRED_INPUT_BOUND
            } else {
                INPUT_OFFER_BOUND
            },
        )
    };
    match offered {
        Ok(()) => true,
        Err(InputOfferError::Saturated) if !flow_controlled && !required => {
            eprintln!(
                "sendbox-launcher: workload stopped reading its terminal for {}ms; dropping input",
                INPUT_OFFER_BOUND.as_millis()
            );
            true
        }
        Err(InputOfferError::Saturated) => {
            eprintln!(
                "sendbox-launcher: required terminal input could not be queued without blocking control"
            );
            cancellation.supervisor_died();
            false
        }
        Err(InputOfferError::Disconnected) => false,
    }
}

/// Writes queued terminal commands to the pseudoterminal primary.
fn spawn_terminal_writer(
    device: TerminalWriter,
    input: Arc<ChannelInput>,
    cancellation: CancellationFlag,
    done: Arc<AtomicBool>,
    events: SyncSender<LauncherEvent>,
    flow_controlled: bool,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut device = device;
        if flow_controlled
            && events
                .send(LauncherEvent::TerminalInputCredit(
                    sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS,
                ))
                .is_err()
        {
            return;
        }
        while !done.load(Ordering::Acquire) {
            if !matches!(cancellation.cause(), CancellationCause::None) {
                return;
            }
            match device.pump() {
                Ok(credits) => {
                    if !send_terminal_input_credit(&events, credits, flow_controlled) {
                        return;
                    }
                }
                Err(error) => {
                    eprintln!("sendbox-launcher: terminal input failed: {error}");
                    return;
                }
            }
            let Some(command) = input.poll(Duration::from_millis(10)) else {
                continue;
            };
            match device.apply(command) {
                Ok(credits) => {
                    if !send_terminal_input_credit(&events, credits, flow_controlled) {
                        return;
                    }
                }
                Err(error) => {
                    eprintln!("sendbox-launcher: terminal input failed: {error}");
                    return;
                }
            }
        }
    })
}

fn send_terminal_input_credit(
    events: &SyncSender<LauncherEvent>,
    credits: u16,
    flow_controlled: bool,
) -> bool {
    !flow_controlled
        || credits == 0
        || events
            .send(LauncherEvent::TerminalInputCredit(credits))
            .is_ok()
}

/// Applies terminal commands to the pseudoterminal primary.
struct TerminalWriter {
    devices: super::pty::TerminalDevices,
    primary: File,
    end_of_file: u8,
    end_of_file_sent: bool,
    flow_controlled: bool,
    pending_bytes: usize,
    pending: VecDeque<PendingTerminalInput>,
}

struct PendingTerminalInput {
    data: Vec<u8>,
    offset: usize,
    returns_credit: bool,
}

impl TerminalWriter {
    fn new(
        devices: super::pty::TerminalDevices,
        flow_controlled: bool,
    ) -> Result<Self, PlatformError> {
        let end_of_file = devices.end_of_file_byte()?;
        let primary = devices
            .controlling_primary()
            .try_clone()
            .map(File::from)
            .map_err(|error| PlatformError::io("duplicate pseudoterminal primary", error))?;
        Ok(Self {
            devices,
            primary,
            end_of_file,
            end_of_file_sent: false,
            flow_controlled,
            pending_bytes: 0,
            pending: VecDeque::new(),
        })
    }

    fn apply(&mut self, command: TerminalCommand) -> io::Result<u16> {
        match command {
            TerminalCommand::Input(data) => {
                if self.end_of_file_sent {
                    return Ok(0);
                }
                if !self.queue(data)? {
                    return Ok(0);
                }
                self.pump()
            }
            TerminalCommand::InputEof => {
                if self.end_of_file_sent {
                    return Ok(0);
                }
                self.end_of_file_sent = true;
                // Never close the primary here: that would raise SIGHUP and
                // kill a workload that is still producing output. The byte
                // ignores the backlog bound because a workload waiting for end
                // of input is by definition still reading, so it will arrive as
                // soon as the backlog ahead of it drains.
                self.pending_bytes = self.pending_bytes.saturating_add(1);
                self.pending.push_back(PendingTerminalInput {
                    data: vec![self.end_of_file],
                    offset: 0,
                    returns_credit: false,
                });
                self.pump()
            }
            // Resizing is an ioctl, so it overtakes a backlog the workload has
            // not read yet. `SIGWINCH` is out of band anyway.
            TerminalCommand::Resize { columns, rows } => {
                self.devices
                    .resize(columns, rows)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                Ok(0)
            }
        }
    }

    fn queue(&mut self, data: Vec<u8>) -> io::Result<bool> {
        if data.is_empty() || data.len() > MAX_TERMINAL_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("terminal input chunk must contain 1..={MAX_TERMINAL_INPUT_BYTES} bytes"),
            ));
        }
        let window_full =
            self.pending.len() >= usize::from(sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS);
        let bytes_full = self.pending_bytes.saturating_add(data.len()) > MAX_PENDING_INPUT;
        if window_full || bytes_full {
            if self.flow_controlled {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "terminal input credit invariant failed: launcher backlog is full",
                ));
            }
            eprintln!(
                "sendbox-launcher: workload is not reading its terminal; dropping {} bytes of input",
                data.len()
            );
            return Ok(false);
        }
        self.pending_bytes += data.len();
        self.pending.push_back(PendingTerminalInput {
            data,
            offset: 0,
            returns_credit: true,
        });
        Ok(true)
    }

    /// Writes as much of the backlog as the workload is willing to accept right
    /// now. Never parks for longer than one slice, so cancellation and resizes
    /// keep flowing while a workload ignores its terminal.
    fn pump(&mut self) -> io::Result<u16> {
        let mut credits = 0_u16;
        while let Some(front) = self.pending.front() {
            let chunk = &front.data[front.offset..];
            match self.primary.write(chunk) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(written) => {
                    self.pending_bytes = self.pending_bytes.saturating_sub(written);
                    let complete = {
                        let front = self.pending.front_mut().expect("pending input exists");
                        front.offset += written;
                        front.offset == front.data.len()
                    };
                    if complete {
                        let completed = self.pending.pop_front().expect("pending input exists");
                        if completed.returns_credit {
                            credits = credits.checked_add(1).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "terminal input credit counter overflowed",
                                )
                            })?;
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // The primary is non-blocking, so a workload that stops
                // draining its terminal surfaces here instead of parking this
                // thread in the kernel for as long as it takes every byte to
                // fit. That is what keeps the backlog in user space, where it
                // can be bounded and where later commands can overtake it.
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !Self::writable(&self.primary, INPUT_WRITE_SLICE)? {
                        return Ok(credits);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        self.primary.flush()?;
        Ok(credits)
    }

    fn writable(primary: &File, slice: Duration) -> io::Result<bool> {
        let timeout = rustix::event::Timespec {
            tv_sec: i64::try_from(slice.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(slice.subsec_nanos()),
        };
        let primary = primary.as_fd();
        let mut fds = [rustix::event::PollFd::new(
            &primary,
            rustix::event::PollFlags::OUT,
        )];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(error) => Err(io::Error::from_raw_os_error(error.raw_os_error())),
        }
    }
}

/// Result of draining the launcher's event stream.
enum LauncherOutcome {
    Terminal(ExecutionResult),
    /// The launcher closed its event stream without a terminal event.
    EventStreamEnded,
    /// The launcher connection itself failed.
    Lost(String),
}

fn pump_launcher_events(
    reader: &mut BufReader<std::process::ChildStdout>,
    control: &Arc<Mutex<ChildStdin>>,
    sink: &mut dyn EventSink,
    correlation_id: &crate::api::CorrelationId,
) -> LauncherOutcome {
    let mut sink_failed = false;
    loop {
        let line = match read_bounded_line(reader) {
            Ok(Some(line)) => line,
            Ok(None) => return LauncherOutcome::EventStreamEnded,
            Err(error) => {
                let _ = send_control_shared(control, &LauncherControl::BrokerShutdown);
                return LauncherOutcome::Lost(format!("read launcher event frame: {error}"));
            }
        };
        let event: ExecutionEvent = match serde_json::from_slice(&line) {
            Ok(event) => event,
            Err(error) => {
                let _ = send_control_shared(control, &LauncherControl::BrokerShutdown);
                return LauncherOutcome::Lost(format!("decode launcher event frame: {error}"));
            }
        };
        if event_correlation(&event) != correlation_id {
            let _ = send_control_shared(control, &LauncherControl::BrokerShutdown);
            return LauncherOutcome::EventStreamEnded;
        }
        match event {
            ExecutionEvent::Terminal { result, .. } => return LauncherOutcome::Terminal(result),
            other if sink_failed => drop(other),
            other => {
                if let Err(error) = sink.emit(other) {
                    sink_failed = true;
                    let control_message = match error {
                        SinkError::Disconnected => LauncherControl::ClientDisconnected {
                            correlation_id: correlation_id.clone(),
                        },
                        SinkError::Saturated => LauncherControl::OutputSaturated {
                            correlation_id: correlation_id.clone(),
                        },
                        SinkError::SupervisorDied => LauncherControl::SupervisorDied,
                    };
                    let _ = send_control_shared(control, &control_message);
                }
            }
        }
    }
}

/// Relays host terminal commands to the launcher process until the run ends.
///
/// Oversized input chunks are split rather than rejected, so a large paste
/// still reaches the workload without exceeding the control frame bound.
fn forward_terminal_input(
    control: &Arc<Mutex<ChildStdin>>,
    done: &AtomicBool,
    cancellation: &CancellationFlag,
    correlation_id: &crate::api::CorrelationId,
    input: &dyn InputSource,
) {
    while !done.load(Ordering::Acquire) {
        if !matches!(cancellation.cause(), CancellationCause::None) {
            return;
        }
        let Some(command) = input.poll(Duration::from_millis(10)) else {
            continue;
        };
        let messages = match command {
            TerminalCommand::Input(data) => data
                .chunks(MAX_TERMINAL_INPUT_BYTES)
                .map(|chunk| LauncherControl::Input {
                    correlation_id: correlation_id.clone(),
                    data: chunk.to_vec(),
                })
                .collect(),
            TerminalCommand::InputEof => vec![LauncherControl::InputEof {
                correlation_id: correlation_id.clone(),
            }],
            TerminalCommand::Resize { columns, rows } => vec![LauncherControl::Resize {
                correlation_id: correlation_id.clone(),
                columns,
                rows,
            }],
        };
        for message in messages {
            if send_control_shared(control, &message).is_err() {
                return;
            }
        }
    }
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
        | ExecutionEvent::TerminalInputCredit { correlation_id, .. }
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
    fn terminal_input_never_stalls_on_a_workload_that_does_not_read_it() {
        let device = super::super::pty::TerminalDevices::open(80, 24, false).expect("allocate pty");
        // Raw mode is what makes the line discipline throttle instead of
        // silently discarding, which is the shape a full-screen agent has.
        let secondary = device.controlling_secondary().expect("secondary");
        let mut attributes = rustix::termios::tcgetattr(secondary).expect("read attributes");
        attributes.make_raw();
        rustix::termios::tcsetattr(
            secondary,
            rustix::termios::OptionalActions::Now,
            &attributes,
        )
        .expect("set raw");

        let mut writer = TerminalWriter::new(device, true).expect("terminal writer");
        let mut credits = sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS;
        let chunks = usize::from(sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS) * 2;
        let mut slowest = Duration::ZERO;
        for _ in 0..chunks {
            if credits == 0 {
                break;
            }
            credits -= 1;
            let started = Instant::now();
            credits += writer
                .apply(TerminalCommand::Input(vec![b'x'; MAX_TERMINAL_INPUT_BYTES]))
                .expect("a workload that stops reading is not a broken session");
            slowest = slowest.max(started.elapsed());
        }
        // End of file is one-shot on every layer above, so it has to be
        // accepted even when the backlog is already at its bound.
        let started = Instant::now();
        writer
            .apply(TerminalCommand::InputEof)
            .expect("end of file must never be refused");
        slowest = slowest.max(started.elapsed());

        assert!(writer.end_of_file_sent);
        assert_eq!(
            writer.pending.back().expect("a queued backlog").data,
            vec![writer.end_of_file],
            "end of file must stay behind the input it follows"
        );
        assert!(
            writer.pending_bytes <= MAX_PENDING_INPUT + 1,
            "the byte backlog bound was not enforced: {}",
            writer.pending_bytes
        );
        assert!(
            writer.pending.len() <= usize::from(sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS) + 1,
            "the chunk backlog bound was not enforced: {}",
            writer.pending.len(),
        );
        // A blocking primary parks here for as long as the workload declines to
        // read, which is the whole point of this bound.
        assert!(
            slowest < INPUT_WRITE_SLICE * 8,
            "terminal input parked on a workload that does not read it: {slowest:?}"
        );
    }

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
