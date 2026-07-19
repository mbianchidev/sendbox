//! Stable error and unsupported-primitive diagnostics.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Kernel primitives required by the no-fallback Linux execution path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelPrimitive {
    OpenAt2,
    ExecveatEmptyPath,
    Clone3IntoCgroup,
    Pidfd,
    PidfdSendSignal,
    WaitidPidfd,
    CgroupV2,
    CgroupDelegation,
    CgroupKill,
    Seccomp,
    SeccompTsync,
    PeerCredentials,
}

impl fmt::Display for KernelPrimitive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// Precise fail-closed diagnostic for an unavailable Linux primitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{primitive} unavailable (errno={errno:?}): {detail}")]
pub struct UnsupportedKernel {
    pub primitive: KernelPrimitive,
    pub errno: Option<i32>,
    pub detail: String,
}

impl UnsupportedKernel {
    #[must_use]
    pub fn new(primitive: KernelPrimitive, errno: Option<i32>, detail: impl Into<String>) -> Self {
        Self {
            primitive,
            errno,
            detail: detail.into(),
        }
    }
}

/// Portable request validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RequestValidationError {
    #[error("{field} must contain between 1 and 128 bytes")]
    InvalidIdentifier { field: &'static str },
    #[error("root id must be a simple non-path identifier")]
    InvalidRootId,
    #[error("{field} contains a NUL byte")]
    NulByte { field: &'static str },
    #[error("descriptor-relative path cannot be empty")]
    EmptyRelativePath,
    #[error("descriptor-relative path cannot be absolute")]
    AbsoluteDescriptorPath,
    #[error("descriptor-relative path cannot contain parent traversal")]
    ParentTraversal,
    #[error("execution timeout is outside the supported range")]
    TimeoutOutOfRange,
    #[error("argv must contain at least one token")]
    EmptyArgv,
    #[error("argv contains too many tokens")]
    TooManyArguments,
    #[error("argv token exceeds the configured byte limit")]
    ArgumentTooLarge,
    #[error("combined argv exceeds the configured byte limit")]
    ArgumentsTooLarge,
    #[error("environment contains too many entries")]
    TooManyEnvironmentEntries,
    #[error("environment entry exceeds the configured byte limit")]
    EnvironmentEntryTooLarge,
    #[error("combined environment exceeds the configured byte limit")]
    EnvironmentTooLarge,
    #[error("environment variable {0:?} is duplicated")]
    DuplicateEnvironmentVariable(String),
    #[error("environment variable {0:?} is dangerous and denied")]
    DangerousEnvironmentVariable(String),
    #[error("environment variable name {0:?} is invalid")]
    InvalidEnvironmentVariableName(String),
    #[error("containment pids.max must be greater than zero")]
    InvalidProcessLimit,
    #[error("cpu.max must be 'max PERIOD' or 'QUOTA PERIOD' with positive integers")]
    InvalidCpuLimit,
    #[error("additional syscall name {0:?} is invalid")]
    InvalidSyscallName(String),
}

/// Platform operation failures.
#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("production execution is unsupported on target_os={0}")]
    UnsupportedPlatform(&'static str),
    #[error(transparent)]
    UnsupportedKernel(#[from] UnsupportedKernel),
    #[error("{operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("security setup failed: {0}")]
    SecuritySetup(String),
    #[error("launcher must be a dedicated single-threaded process; observed {threads} threads")]
    MultithreadedLauncher { threads: usize },
    #[error("child exec failed with errno {errno}")]
    ChildExec { errno: i32 },
}

impl PlatformError {
    #[must_use]
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

/// Top-level broker error.
#[derive(Debug, Error)]
pub enum ExecError {
    #[error(transparent)]
    InvalidRequest(#[from] RequestValidationError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error("command policy could not be compiled: {0}")]
    PolicyCompile(String),
    #[error("runtime authentication failed: {0}")]
    Authentication(String),
    #[error("runtime path is unsafe: {0}")]
    UnsafeRuntime(String),
    #[error("session error: {0}")]
    Session(String),
}
