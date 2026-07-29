//! Portable broker admission, validation, cancellation, and event plumbing.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::api::{
    AdmissionDisposition, CleanupReport, ExecutionDecision, ExecutionEvent, ExecutionRequest,
    ExecutionResult, LaunchFailure, SemanticScope, TerminalState,
};
use crate::environment::EnvironmentPolicy;
use crate::error::{ExecError, RequestValidationError};
use crate::policy::CompiledCommandPolicy;
use crate::session::BrokerSession;

/// Structural request limits checked again after deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    pub max_argc: usize,
    pub max_arg_bytes: usize,
    pub max_argv_bytes: usize,
    pub max_env_entries: usize,
    pub max_env_entry_bytes: usize,
    pub max_env_bytes: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_argc: 64,
            max_arg_bytes: 4 * 1024,
            max_argv_bytes: 32 * 1024,
            max_env_entries: 64,
            max_env_entry_bytes: 4 * 1024,
            max_env_bytes: 16 * 1024,
        }
    }
}

impl RequestLimits {
    pub fn validate(self, request: &ExecutionRequest) -> Result<(), RequestValidationError> {
        crate::api::CorrelationId::new(request.correlation_id.as_str())?;
        validate_root_id(&request.executable.root)?;
        validate_root_id(&request.cwd.root)?;
        crate::api::RelativePath::new(request.executable.relative.as_str())?;
        crate::api::RelativePath::new(request.cwd.relative.as_str())?;
        crate::api::ExecutionTimeout::new(request.timeout.as_duration())?;
        if request.argv.is_empty() {
            return Err(RequestValidationError::EmptyArgv);
        }
        if request.argv.len() > self.max_argc {
            return Err(RequestValidationError::TooManyArguments);
        }
        let mut argv_bytes = 0usize;
        for argument in &request.argv {
            if argument.as_bytes().contains(&0) {
                return Err(RequestValidationError::NulByte { field: "argv" });
            }
            if argument.len() > self.max_arg_bytes {
                return Err(RequestValidationError::ArgumentTooLarge);
            }
            argv_bytes = argv_bytes.saturating_add(argument.len());
        }
        if argv_bytes > self.max_argv_bytes {
            return Err(RequestValidationError::ArgumentsTooLarge);
        }
        if request.environment.len() > self.max_env_entries {
            return Err(RequestValidationError::TooManyEnvironmentEntries);
        }
        let mut env_bytes = 0usize;
        for entry in &request.environment {
            let size = entry
                .name
                .len()
                .saturating_add(entry.value.len())
                .saturating_add(1);
            if size > self.max_env_entry_bytes {
                return Err(RequestValidationError::EnvironmentEntryTooLarge);
            }
            env_bytes = env_bytes.saturating_add(size);
        }
        if env_bytes > self.max_env_bytes {
            return Err(RequestValidationError::EnvironmentTooLarge);
        }
        if request.containment.pids_max == 0 {
            return Err(RequestValidationError::InvalidProcessLimit);
        }
        if let Some(cpu_max) = &request.containment.cpu_max
            && !valid_cpu_max(cpu_max)
        {
            return Err(RequestValidationError::InvalidCpuLimit);
        }
        for syscall in &request.containment.additional_denied_syscalls {
            if syscall.is_empty()
                || !syscall
                    .bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
            {
                return Err(RequestValidationError::InvalidSyscallName(syscall.clone()));
            }
        }
        request.environment_map()?;
        Ok(())
    }
}

fn validate_root_id(root: &crate::api::RootId) -> Result<(), RequestValidationError> {
    if let crate::api::RootId::Named(name) = root {
        crate::api::RootId::named(name.clone())?;
    }
    Ok(())
}

fn valid_cpu_max(value: &str) -> bool {
    let mut parts = value.split_ascii_whitespace();
    let Some(quota) = parts.next() else {
        return false;
    };
    let Some(period) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    let Ok(period) = period.parse::<u64>() else {
        return false;
    };
    period > 0 && (quota == "max" || quota.parse::<u64>().is_ok_and(|quota| quota > 0))
}

/// Backpressure/disconnect signal from a streaming consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkError {
    Disconnected,
    Saturated,
    SupervisorDied,
}

/// Consumer for started/output events.
pub trait EventSink {
    fn emit(&mut self, event: ExecutionEvent) -> Result<(), SinkError>;
}

impl<F> EventSink for F
where
    F: FnMut(ExecutionEvent) -> Result<(), SinkError>,
{
    fn emit(&mut self, event: ExecutionEvent) -> Result<(), SinkError> {
        self(event)
    }
}

/// Cooperative cancellation shared with a backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum CancellationCause {
    #[default]
    None = 0,
    Cancelled = 1,
    ClientDisconnected = 2,
    BrokerShutdown = 3,
    SupervisorDied = 4,
    OutputSaturated = 5,
}

#[derive(Debug, Clone, Default)]
pub struct CancellationFlag(Arc<AtomicU8>);

impl CancellationFlag {
    pub fn cancel(&self) {
        self.set(CancellationCause::Cancelled);
    }

    pub fn disconnect(&self) {
        self.set(CancellationCause::ClientDisconnected);
    }

    pub fn shutdown(&self) {
        self.set(CancellationCause::BrokerShutdown);
    }

    pub fn supervisor_died(&self) {
        self.set(CancellationCause::SupervisorDied);
    }

    pub fn saturate(&self) {
        self.set(CancellationCause::OutputSaturated);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cause() != CancellationCause::None
    }

    #[must_use]
    pub fn cause(&self) -> CancellationCause {
        match self.0.load(Ordering::Acquire) {
            1 => CancellationCause::Cancelled,
            2 => CancellationCause::ClientDisconnected,
            3 => CancellationCause::BrokerShutdown,
            4 => CancellationCause::SupervisorDied,
            5 => CancellationCause::OutputSaturated,
            _ => CancellationCause::None,
        }
    }

    fn set(&self, cause: CancellationCause) {
        let _ = self.0.compare_exchange(
            CancellationCause::None as u8,
            cause as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

/// One host-originated terminal command for an interactive workload.
///
/// Input bytes may contain pasted credentials, so the [`std::fmt::Debug`]
/// implementation reports only a length.
#[derive(Clone, PartialEq, Eq)]
pub enum TerminalCommand {
    /// Raw bytes to write to the workload's terminal.
    Input(Vec<u8>),
    /// The host input stream ended; write the terminal's configured `VEOF`
    /// byte once and refuse further input.
    InputEof,
    /// The host terminal was resized.
    Resize { columns: u16, rows: u16 },
}

impl std::fmt::Debug for TerminalCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(bytes) => formatter
                .debug_tuple("Input")
                .field(&format_args!("<{} bytes>", bytes.len()))
                .finish(),
            Self::InputEof => formatter.write_str("InputEof"),
            Self::Resize { columns, rows } => formatter
                .debug_struct("Resize")
                .field("columns", columns)
                .field("rows", rows)
                .finish(),
        }
    }
}

/// Source of host-originated terminal commands.
///
/// Implementations must never block longer than `bound`, so a backend polling
/// for input still observes cancellation promptly.
pub trait InputSource: Send + Sync {
    fn poll(&self, bound: std::time::Duration) -> Option<TerminalCommand>;
}

/// Input source for headless runs, which never deliver terminal commands.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullInput;

impl InputSource for NullInput {
    fn poll(&self, _bound: std::time::Duration) -> Option<TerminalCommand> {
        None
    }
}

/// Bounded queue of terminal commands fed by a reader thread.
///
/// Input and EOF retain FIFO ordering. EOF has a dedicated reservation, while
/// resizes are coalesced to the latest value so neither can be crowded out by
/// bulk input.
#[derive(Debug)]
pub struct ChannelInput {
    shared: Arc<InputQueue>,
}

/// Producer half of a [`ChannelInput`].
#[derive(Debug, Clone)]
pub struct InputSender {
    shared: Arc<InputQueue>,
}

#[derive(Debug)]
struct InputQueue {
    capacity: usize,
    state: Mutex<InputQueueState>,
    ready: Condvar,
}

#[derive(Debug, Default)]
struct InputQueueState {
    ordered: VecDeque<TerminalCommand>,
    input_count: usize,
    input_ended: bool,
    latest_resize: Option<TerminalCommand>,
    receiver_alive: bool,
}

/// Why a terminal command could not be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InputOfferError {
    #[error("terminal input queue stayed full")]
    Saturated,
    #[error("terminal input consumer is gone")]
    Disconnected,
}

impl ChannelInput {
    /// Creates a bounded pair with the given queue depth.
    #[must_use]
    pub fn bounded(depth: usize) -> (InputSender, Self) {
        let shared = Arc::new(InputQueue {
            capacity: depth,
            state: Mutex::new(InputQueueState {
                receiver_alive: true,
                ..InputQueueState::default()
            }),
            ready: Condvar::new(),
        });
        (
            InputSender {
                shared: Arc::clone(&shared),
            },
            Self { shared },
        )
    }
}

impl InputSender {
    /// Queues a command without blocking a control reader.
    pub fn try_offer(&self, command: TerminalCommand) -> Result<(), InputOfferError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| InputOfferError::Disconnected)?;
        self.enqueue(&mut state, command)?;
        self.shared.ready.notify_one();
        Ok(())
    }

    /// Queues a command, giving up after `bound` rather than blocking.
    pub fn offer(
        &self,
        command: TerminalCommand,
        bound: std::time::Duration,
    ) -> Result<(), InputOfferError> {
        if !matches!(&command, TerminalCommand::Input(_)) {
            return self.try_offer(command);
        }
        let deadline = std::time::Instant::now() + bound;
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| InputOfferError::Disconnected)?;
        loop {
            if !state.receiver_alive {
                return Err(InputOfferError::Disconnected);
            }
            if state.input_ended {
                return Err(InputOfferError::Saturated);
            }
            if state.input_count < self.shared.capacity {
                state.input_count += 1;
                state.ordered.push_back(command);
                self.shared.ready.notify_one();
                return Ok(());
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(InputOfferError::Saturated);
            }
            let (next, timeout) = self
                .shared
                .ready
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .map_err(|_| InputOfferError::Disconnected)?;
            state = next;
            if timeout.timed_out() && state.input_count >= self.shared.capacity {
                return Err(InputOfferError::Saturated);
            }
        }
    }

    fn enqueue(
        &self,
        state: &mut InputQueueState,
        command: TerminalCommand,
    ) -> Result<(), InputOfferError> {
        if !state.receiver_alive {
            return Err(InputOfferError::Disconnected);
        }
        match command {
            TerminalCommand::Input(_) if state.input_ended => Err(InputOfferError::Saturated),
            TerminalCommand::Input(_) if state.input_count >= self.shared.capacity => {
                Err(InputOfferError::Saturated)
            }
            command @ TerminalCommand::Input(_) => {
                state.input_count += 1;
                state.ordered.push_back(command);
                Ok(())
            }
            TerminalCommand::InputEof if state.input_ended => Err(InputOfferError::Saturated),
            TerminalCommand::InputEof => {
                state.input_ended = true;
                state.ordered.push_back(TerminalCommand::InputEof);
                Ok(())
            }
            command @ TerminalCommand::Resize { .. } => {
                state.latest_resize = Some(command);
                Ok(())
            }
        }
    }
}

impl InputSource for ChannelInput {
    fn poll(&self, bound: std::time::Duration) -> Option<TerminalCommand> {
        let deadline = std::time::Instant::now() + bound;
        let mut state = self.shared.state.lock().ok()?;
        loop {
            if let Some(resize) = state.latest_resize.take() {
                return Some(resize);
            }
            if let Some(command) = state.ordered.pop_front() {
                if matches!(&command, TerminalCommand::Input(_)) {
                    state.input_count -= 1;
                    self.shared.ready.notify_one();
                }
                return Some(command);
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            let (next, timeout) = self
                .shared
                .ready
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .ok()?;
            state = next;
            if timeout.timed_out() && state.ordered.is_empty() && state.latest_resize.is_none() {
                return None;
            }
        }
    }
}

impl Drop for ChannelInput {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.receiver_alive = false;
            self.shared.ready.notify_all();
        }
    }
}

/// Platform execution boundary. Implementations must not perform policy.
pub trait ExecutionBackend: Send + Sync {
    fn execute(
        &self,
        request: &ExecutionRequest,
        decision: &ExecutionDecision,
        sink: &mut dyn EventSink,
        input: &dyn InputSource,
        cancellation: &CancellationFlag,
    ) -> ExecutionResult;
}

/// Explicit fail-closed backend for builds or deployments without a qualified
/// launcher process.
#[derive(Debug, Clone, Copy)]
pub struct UnsupportedExecutionBackend {
    primitive: crate::error::KernelPrimitive,
}

impl UnsupportedExecutionBackend {
    #[must_use]
    pub const fn new(primitive: crate::error::KernelPrimitive) -> Self {
        Self { primitive }
    }
}

impl ExecutionBackend for UnsupportedExecutionBackend {
    fn execute(
        &self,
        _request: &ExecutionRequest,
        _decision: &ExecutionDecision,
        _sink: &mut dyn EventSink,
        _input: &dyn InputSource,
        _cancellation: &CancellationFlag,
    ) -> ExecutionResult {
        ExecutionResult {
            terminal: TerminalState::LaunchFailed(LaunchFailure::UnsupportedKernel(
                crate::error::UnsupportedKernel::new(
                    self.primitive,
                    None,
                    "no qualified execution backend is configured",
                ),
            )),
            cleanup: CleanupReport::no_child(),
        }
    }
}

/// Top-level production broker state.
pub struct Broker<B> {
    session: Arc<BrokerSession>,
    command_policy: CompiledCommandPolicy,
    environment_policy: EnvironmentPolicy,
    limits: RequestLimits,
    backend: B,
}

impl<B: ExecutionBackend> Broker<B> {
    #[must_use]
    pub fn new(
        session: Arc<BrokerSession>,
        command_policy: CompiledCommandPolicy,
        environment_policy: EnvironmentPolicy,
        limits: RequestLimits,
        backend: B,
    ) -> Self {
        Self {
            session,
            command_policy,
            environment_policy,
            limits,
            backend,
        }
    }

    pub fn decide(&self, request: &ExecutionRequest) -> Result<ExecutionDecision, ExecError> {
        self.limits.validate(request)?;
        if !self
            .session
            .authenticate(request.session_id, &request.authentication)
        {
            return Err(ExecError::Authentication(
                "request session credentials do not match broker session".into(),
            ));
        }
        let admission = self.command_policy.evaluate(&request.argv);
        Ok(ExecutionDecision {
            session_id: request.session_id,
            correlation_id: request.correlation_id.clone(),
            disposition: admission.disposition,
            matched_rule: admission.matched.source,
            semantic_scope: SemanticScope::TopLevelOnly,
        })
    }

    /// Admits and executes a request. Correlation ids are single-use for the
    /// lifetime of the broker session, including rejected requests.
    pub fn execute(
        &self,
        request: &ExecutionRequest,
        sink: &mut dyn EventSink,
        cancellation: &CancellationFlag,
    ) -> Result<ExecutionResult, ExecError> {
        self.execute_with_input(request, sink, &NullInput, cancellation)
    }

    /// Executes with a live terminal input source for interactive workloads.
    pub fn execute_with_input(
        &self,
        request: &ExecutionRequest,
        sink: &mut dyn EventSink,
        input: &dyn InputSource,
        cancellation: &CancellationFlag,
    ) -> Result<ExecutionResult, ExecError> {
        let decision = self.decide(request)?;
        if !self.session.register(request.correlation_id.clone()) {
            return Err(ExecError::Authentication("duplicate correlation id".into()));
        }
        if decision.disposition == AdmissionDisposition::Deny {
            let result = ExecutionResult {
                terminal: TerminalState::Rejected {
                    reason: decision
                        .matched_rule
                        .unwrap_or_else(|| "default command policy denied request".into()),
                },
                cleanup: CleanupReport::no_child(),
            };
            let _ = sink.emit(ExecutionEvent::Terminal {
                correlation_id: request.correlation_id.clone(),
                result: result.clone(),
            });
            return Ok(result);
        }

        let requested_environment = request.environment_map()?;
        let environment = self.environment_policy.sanitize(&requested_environment)?;
        let mut sanitized = request.clone();
        sanitized.environment = environment
            .into_iter()
            .map(|(name, value)| crate::api::EnvironmentEntry { name, value })
            .collect();

        let result = self
            .backend
            .execute(&sanitized, &decision, sink, input, cancellation);
        let _ = sink.emit(ExecutionEvent::Terminal {
            correlation_id: request.correlation_id.clone(),
            result: result.clone(),
        });
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use sendbox_policy::{Action, CommandPolicy};

    use super::*;
    use crate::api::{
        ContainmentProfile, CorrelationId, DescriptorPath, EnvironmentEntry, ExecutionTimeout,
        RelativePath, RootId,
    };

    #[test]
    fn terminal_input_queue_reserves_eof_and_coalesces_resizes() {
        let (sender, queue) = ChannelInput::bounded(2);
        sender
            .try_offer(TerminalCommand::Input(vec![b'a']))
            .expect("first input");
        sender
            .try_offer(TerminalCommand::Input(vec![b'b']))
            .expect("second input");
        assert_eq!(
            sender.try_offer(TerminalCommand::Input(vec![b'c'])),
            Err(InputOfferError::Saturated)
        );

        sender
            .try_offer(TerminalCommand::Resize {
                columns: 80,
                rows: 24,
            })
            .expect("first resize");
        sender
            .try_offer(TerminalCommand::Resize {
                columns: 120,
                rows: 40,
            })
            .expect("replacement resize");
        sender
            .try_offer(TerminalCommand::InputEof)
            .expect("reserved end of file");

        assert_eq!(
            queue.poll(std::time::Duration::ZERO),
            Some(TerminalCommand::Resize {
                columns: 120,
                rows: 40,
            })
        );
        assert!(matches!(
            queue.poll(std::time::Duration::ZERO),
            Some(TerminalCommand::Input(data)) if data == vec![b'a']
        ));
        assert!(matches!(
            queue.poll(std::time::Duration::ZERO),
            Some(TerminalCommand::Input(data)) if data == vec![b'b']
        ));
        assert_eq!(
            queue.poll(std::time::Duration::ZERO),
            Some(TerminalCommand::InputEof)
        );
        assert_eq!(queue.poll(std::time::Duration::ZERO), None);
    }

    #[derive(Default)]
    struct RecordingBackend {
        environment: Mutex<Vec<EnvironmentEntry>>,
    }

    impl ExecutionBackend for RecordingBackend {
        fn execute(
            &self,
            request: &ExecutionRequest,
            _decision: &ExecutionDecision,
            _sink: &mut dyn EventSink,
            _input: &dyn InputSource,
            _cancellation: &CancellationFlag,
        ) -> ExecutionResult {
            self.environment
                .lock()
                .expect("environment mutex")
                .clone_from(&request.environment);
            ExecutionResult {
                terminal: TerminalState::Exited(crate::api::ExitStatus {
                    exit_code: Some(0),
                    signal: None,
                }),
                cleanup: CleanupReport::complete(vec![
                    crate::api::CleanupStep::CgroupKill,
                    crate::api::CleanupStep::PidfdReap,
                    crate::api::CleanupStep::ObserveUnpopulated,
                    crate::api::CleanupStep::RemoveLeaf,
                ]),
            }
        }
    }

    struct LateCancellationBackend;

    impl ExecutionBackend for LateCancellationBackend {
        fn execute(
            &self,
            _request: &ExecutionRequest,
            _decision: &ExecutionDecision,
            _sink: &mut dyn EventSink,
            _input: &dyn InputSource,
            cancellation: &CancellationFlag,
        ) -> ExecutionResult {
            cancellation.cancel();
            ExecutionResult {
                terminal: TerminalState::Exited(crate::api::ExitStatus {
                    exit_code: Some(0),
                    signal: None,
                }),
                cleanup: CleanupReport::complete(vec![
                    crate::api::CleanupStep::CgroupKill,
                    crate::api::CleanupStep::PidfdReap,
                    crate::api::CleanupStep::ObserveUnpopulated,
                    crate::api::CleanupStep::RemoveLeaf,
                ]),
            }
        }
    }

    fn request(session: &BrokerSession, correlation: &str) -> ExecutionRequest {
        ExecutionRequest {
            session_id: session.id(),
            authentication: session.authentication(),
            correlation_id: CorrelationId::new(correlation).expect("correlation"),
            cancellation_id: None,
            executable: DescriptorPath {
                root: RootId::System,
                relative: RelativePath::new("usr/bin/git").expect("path"),
            },
            argv: vec!["git".into(), "status".into()],
            cwd: DescriptorPath {
                root: RootId::Workspace,
                relative: RelativePath::new(".").expect("cwd"),
            },
            environment: vec![
                EnvironmentEntry {
                    name: "PATH".into(),
                    value: "/attacker".into(),
                },
                EnvironmentEntry {
                    name: "SAFE".into(),
                    value: "yes".into(),
                },
            ],
            stdin: crate::api::StandardInput::Null,
            timeout: ExecutionTimeout::new(std::time::Duration::from_secs(1)).expect("timeout"),
            containment: ContainmentProfile::default(),
        }
    }

    fn policy() -> CompiledCommandPolicy {
        CompiledCommandPolicy::compile(&CommandPolicy {
            default_action: Action::Deny,
            allowlist: vec!["git status".into()],
            denylist: Vec::new(),
            log_blocked: true,
        })
        .expect("policy")
    }

    #[test]
    fn broker_authenticates_sanitizes_and_rejects_duplicate_correlations() {
        let session = Arc::new(BrokerSession::generate().expect("session"));
        let broker = Broker::new(
            Arc::clone(&session),
            policy(),
            EnvironmentPolicy::default(),
            RequestLimits::default(),
            RecordingBackend::default(),
        );
        let request = request(&session, "corr-1");
        let mut events = Vec::new();
        let mut sink = |event| {
            events.push(event);
            Ok(())
        };
        let result = broker
            .execute(&request, &mut sink, &CancellationFlag::default())
            .expect("execute");
        assert!(matches!(result.terminal, TerminalState::Exited(_)));
        assert!(matches!(
            broker.execute(&request, &mut sink, &CancellationFlag::default()),
            Err(ExecError::Authentication(_))
        ));
    }

    #[test]
    fn broker_rejects_wrong_authentication_before_backend() {
        let session = Arc::new(BrokerSession::generate().expect("session"));
        let broker = Broker::new(
            Arc::clone(&session),
            policy(),
            EnvironmentPolicy::default(),
            RequestLimits::default(),
            RecordingBackend::default(),
        );
        let mut request = request(&session, "corr-2");
        request.authentication = crate::api::SessionAuthentication::from_bytes([0; 32]);
        assert!(matches!(
            broker.decide(&request),
            Err(ExecError::Authentication(_))
        ));
    }

    #[test]
    fn broker_does_not_replace_a_finalized_backend_result() {
        let session = Arc::new(BrokerSession::generate().expect("session"));
        let broker = Broker::new(
            Arc::clone(&session),
            policy(),
            EnvironmentPolicy::default(),
            RequestLimits::default(),
            LateCancellationBackend,
        );
        let request = request(&session, "corr-finalized");
        let mut sink = |_event| Ok(());
        let result = broker
            .execute(&request, &mut sink, &CancellationFlag::default())
            .expect("execute");
        assert_eq!(
            result.terminal,
            TerminalState::Exited(crate::api::ExitStatus {
                exit_code: Some(0),
                signal: None,
            })
        );
    }

    #[test]
    fn validation_rechecks_deserialized_root_and_cpu_limit_values() {
        let session = BrokerSession::generate().expect("session");
        let mut request = request(&session, "corr-invalid");
        request.executable.root = RootId::Named("../escape".into());
        assert_eq!(
            RequestLimits::default().validate(&request),
            Err(RequestValidationError::InvalidRootId)
        );
        request.executable.root = RootId::System;
        request.containment.cpu_max = Some("1000\n+memory".into());
        assert_eq!(
            RequestLimits::default().validate(&request),
            Err(RequestValidationError::InvalidCpuLimit)
        );
    }
}
