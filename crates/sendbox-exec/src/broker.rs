//! Portable broker admission, validation, cancellation, and event plumbing.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

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

/// Platform execution boundary. Implementations must not perform policy.
pub trait ExecutionBackend: Send + Sync {
    fn execute(
        &self,
        request: &ExecutionRequest,
        decision: &ExecutionDecision,
        sink: &mut dyn EventSink,
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
            .execute(&sanitized, &decision, sink, cancellation);
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
