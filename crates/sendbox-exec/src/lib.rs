//! Production command-execution admission and Linux containment primitives.
//!
//! Semantic command policy is intentionally evaluated only for a top-level
//! broker request. Descendants inherit kernel containment, resource limits,
//! capability removal, and the dangerous-syscall filter, but their argv is
//! not recursively parsed or assigned new semantic policy decisions.
//!
//! # Unsafe code
//!
//! Unsafe code is denied crate-wide. The sole exception is the audited Linux
//! syscall adapter in `platform::linux::raw`; every other module explicitly
//! forbids unsafe code.

#![deny(unsafe_code)]

pub mod api;
pub mod broker;
pub mod environment;
pub mod error;
pub mod platform;
pub mod policy;
pub mod runtime;
pub mod service;
pub mod session;

pub use api::{
    AdmissionDisposition, CancellationId, CleanupFailure, CleanupReport, CleanupStatus,
    CleanupStep, ContainmentProfile, CorrelationId, DescriptorPath, EnvironmentEntry,
    ExecutionDecision, ExecutionEvent, ExecutionRequest, ExecutionResult, ExecutionTimeout,
    ExitStatus, FileIdentity, LaunchFailure, RelativePath, ResourceLimits, RootId, SemanticScope,
    SessionAuthentication, StandardInput, StreamKind, TerminalState,
};
pub use broker::{
    Broker, CancellationCause, CancellationFlag, EventSink, ExecutionBackend, RequestLimits,
    SinkError, UnsupportedExecutionBackend,
};
pub use error::{
    ExecError, KernelPrimitive, PlatformError, RequestValidationError, UnsupportedKernel,
};
pub use policy::{
    CommandAdmission, CommandPolicyCompileError, CompiledCommandPolicy, MatchKind, MatchedRule,
};
pub use sendbox_core::SessionId;
