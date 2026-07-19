//! Portable, serialization-friendly execution broker types.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path};
use std::time::Duration;

use sendbox_core::SessionId;
use serde::{Deserialize, Serialize};

use crate::error::{KernelPrimitive, RequestValidationError, UnsupportedKernel};

/// Maximum identifier length accepted by the portable constructors.
const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const SESSION_AUTHENTICATION_BYTES: usize = 32;

/// An opaque caller-selected correlation identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CorrelationId(String);

impl CorrelationId {
    /// Creates a validated correlation identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, RequestValidationError> {
        let value = value.into();
        validate_identifier("correlation_id", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An opaque caller-selected cancellation identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CancellationId(String);

impl CancellationId {
    /// Creates a validated cancellation identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, RequestValidationError> {
        let value = value.into();
        validate_identifier("cancellation_id", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A trusted, pre-opened filesystem root known to the broker.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "name")]
pub enum RootId {
    Workspace,
    Toolchain,
    System,
    Named(String),
}

impl RootId {
    /// Creates a named root while rejecting path-like or empty names.
    pub fn named(value: impl Into<String>) -> Result<Self, RequestValidationError> {
        let value = value.into();
        validate_identifier("root_id", &value)?;
        if value.contains(['/', '\\']) {
            return Err(RequestValidationError::InvalidRootId);
        }
        Ok(Self::Named(value))
    }
}

/// A path resolved strictly below a pre-opened root descriptor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelativePath(String);

impl RelativePath {
    /// Validates a descriptor-relative path.
    ///
    /// `.` is accepted for a working directory. Absolute paths, empty paths,
    /// parent traversal, platform prefixes, and NUL bytes are rejected.
    pub fn new(value: impl Into<String>) -> Result<Self, RequestValidationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(RequestValidationError::EmptyRelativePath);
        }
        if value.as_bytes().contains(&0) {
            return Err(RequestValidationError::NulByte {
                field: "descriptor_path",
            });
        }
        let path = Path::new(&value);
        if path.is_absolute() {
            return Err(RequestValidationError::AbsoluteDescriptorPath);
        }
        for component in path.components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => return Err(RequestValidationError::ParentTraversal),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(RequestValidationError::AbsoluteDescriptorPath);
                }
            }
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A path paired with the pre-opened root used to resolve it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorPath {
    pub root: RootId,
    pub relative: RelativePath,
}

/// One explicitly supplied environment entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEntry {
    pub name: String,
    pub value: String,
}

/// Standard input supplied to the executed command.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardInput {
    /// Connect fd 0 to a freshly opened `/dev/null`.
    #[default]
    Null,
}

/// Opaque per-session bearer material.
///
/// This value uses binary bytes in memory and on the broker protocol. It is
/// lowercase hexadecimal only in the owner-only credentials file.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionAuthentication([u8; SESSION_AUTHENTICATION_BYTES]);

impl SessionAuthentication {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SESSION_AUTHENTICATION_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_AUTHENTICATION_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SessionAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionAuthentication(<redacted>)")
    }
}

/// A bounded execution timeout stored in milliseconds for stable wire use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionTimeout(u64);

impl ExecutionTimeout {
    pub const MIN: Duration = Duration::from_millis(10);
    pub const MAX: Duration = Duration::from_secs(300);

    /// Creates a timeout within the production bounds.
    pub fn new(duration: Duration) -> Result<Self, RequestValidationError> {
        if !(Self::MIN..=Self::MAX).contains(&duration) {
            return Err(RequestValidationError::TimeoutOutOfRange);
        }
        let millis = u64::try_from(duration.as_millis())
            .map_err(|_| RequestValidationError::TimeoutOutOfRange)?;
        Ok(Self(millis))
    }

    #[must_use]
    pub const fn from_millis_unchecked(millis: u64) -> Self {
        Self(millis)
    }

    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn as_duration(self) -> Duration {
        Duration::from_millis(self.0)
    }
}

/// Per-command POSIX resource limits inherited by every descendant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceLimits {
    pub open_files: u64,
    pub processes: u64,
    pub core_bytes: u64,
    pub file_bytes: u64,
    pub address_space_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            open_files: 256,
            processes: 256,
            core_bytes: 0,
            file_bytes: 512 * 1024 * 1024,
            address_space_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Kernel containment requested for a command and all descendants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContainmentProfile {
    pub pids_max: u32,
    pub memory_max_bytes: Option<u64>,
    pub memory_swap_max_bytes: Option<u64>,
    pub cpu_max: Option<String>,
    pub additional_denied_syscalls: Vec<String>,
    pub rlimits: ResourceLimits,
}

impl Default for ContainmentProfile {
    fn default() -> Self {
        Self {
            pids_max: 256,
            memory_max_bytes: Some(2 * 1024 * 1024 * 1024),
            memory_swap_max_bytes: Some(0),
            cpu_max: None,
            additional_denied_syscalls: Vec::new(),
            rlimits: ResourceLimits::default(),
        }
    }
}

/// A complete top-level broker request.
///
/// `argv` is retained as a vector throughout admission and launch. It is
/// never joined into a command string and never interpreted by a shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub session_id: SessionId,
    pub authentication: SessionAuthentication,
    pub correlation_id: CorrelationId,
    pub cancellation_id: Option<CancellationId>,
    pub executable: DescriptorPath,
    pub argv: Vec<String>,
    pub cwd: DescriptorPath,
    pub environment: Vec<EnvironmentEntry>,
    #[serde(default)]
    pub stdin: StandardInput,
    pub timeout: ExecutionTimeout,
    pub containment: ContainmentProfile,
}

impl ExecutionRequest {
    /// Returns an environment map while rejecting duplicate names.
    pub fn environment_map(&self) -> Result<BTreeMap<String, String>, RequestValidationError> {
        let mut environment = BTreeMap::new();
        for entry in &self.environment {
            if environment
                .insert(entry.name.clone(), entry.value.clone())
                .is_some()
            {
                return Err(RequestValidationError::DuplicateEnvironmentVariable(
                    entry.name.clone(),
                ));
            }
        }
        Ok(environment)
    }
}

/// Whether semantic command policy admitted the top-level request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDisposition {
    Allow,
    Deny,
}

/// Immutable admission output passed to a launcher boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDecision {
    pub session_id: SessionId,
    pub correlation_id: CorrelationId,
    pub disposition: AdmissionDisposition,
    pub matched_rule: Option<String>,
    pub semantic_scope: SemanticScope,
}

/// Scope of semantic policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticScope {
    TopLevelOnly,
}

/// Stable descriptor identity captured immediately after `openat2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
}

/// A streamed output source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    Stdout,
    Stderr,
}

/// Events emitted in monotonically increasing sequence order per request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ExecutionEvent {
    Started {
        correlation_id: CorrelationId,
        executable_identity: FileIdentity,
        cwd_identity: FileIdentity,
    },
    Output {
        correlation_id: CorrelationId,
        stream: StreamKind,
        sequence: u64,
        data: Vec<u8>,
    },
    Terminal {
        correlation_id: CorrelationId,
        result: ExecutionResult,
    },
}

/// Exit information obtained while reaping the pidfd-owned leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitStatus {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

/// Typed failures before a command successfully begins execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
pub enum LaunchFailure {
    UnsupportedKernel(UnsupportedKernel),
    DescriptorResolution { message: String },
    PolicySetup { message: String },
    CgroupSetup { message: String },
    Clone { message: String },
    Exec { errno: Option<i32>, message: String },
    LauncherBoundary { message: String },
}

/// Terminal execution cause, recorded before cleanup starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TerminalState {
    Exited(ExitStatus),
    Rejected { reason: String },
    LaunchFailed(LaunchFailure),
    TimedOut,
    Cancelled,
    ClientDisconnected,
    OutputSaturated,
    BrokerShutdown,
    SupervisorDied,
}

/// Ordered cleanup steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStep {
    CgroupKill,
    PidfdReap,
    ObserveUnpopulated,
    RemoveLeaf,
}

/// One cleanup failure; incomplete cleanup is never represented as success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupFailure {
    pub step: CleanupStep,
    pub message: String,
}

/// Truthful classification of cleanup applicability and completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    /// No child was created and therefore child-tree cleanup was not needed.
    NoChild,
    /// Every required cleanup step for a created child completed.
    Complete,
    /// At least one required step failed or could not be confirmed.
    Incomplete,
}

/// Structured report for the mandatory cleanup sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupReport {
    pub status: CleanupStatus,
    pub attempted: Vec<CleanupStep>,
    pub failures: Vec<CleanupFailure>,
}

impl CleanupReport {
    #[must_use]
    pub const fn no_child() -> Self {
        Self {
            status: CleanupStatus::NoChild,
            attempted: Vec::new(),
            failures: Vec::new(),
        }
    }

    #[must_use]
    pub fn complete(attempted: Vec<CleanupStep>) -> Self {
        Self {
            status: CleanupStatus::Complete,
            attempted,
            failures: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_attempts(attempted: Vec<CleanupStep>, failures: Vec<CleanupFailure>) -> Self {
        let status = if failures.is_empty() {
            CleanupStatus::Complete
        } else {
            CleanupStatus::Incomplete
        };
        Self {
            status,
            attempted,
            failures,
        }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.status == CleanupStatus::Complete
            && self.failures.is_empty()
            && self.attempted
                == [
                    CleanupStep::CgroupKill,
                    CleanupStep::PidfdReap,
                    CleanupStep::ObserveUnpopulated,
                    CleanupStep::RemoveLeaf,
                ]
    }

    #[must_use]
    pub const fn is_no_child(&self) -> bool {
        matches!(self.status, CleanupStatus::NoChild)
    }
}

/// Final result combines the terminal cause with cleanup evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResult {
    pub terminal: TerminalState,
    pub cleanup: CleanupReport,
}

impl From<KernelPrimitive> for CleanupFailure {
    fn from(primitive: KernelPrimitive) -> Self {
        Self {
            step: CleanupStep::CgroupKill,
            message: format!("required primitive unavailable: {primitive}"),
        }
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), RequestValidationError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(RequestValidationError::InvalidIdentifier { field });
    }
    if value.as_bytes().contains(&0) {
        return Err(RequestValidationError::NulByte { field });
    }
    Ok(())
}
