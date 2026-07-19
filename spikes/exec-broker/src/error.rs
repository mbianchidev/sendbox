//! Crate-wide error types.
//!
//! This module is pure and forbids `unsafe`.

#![forbid(unsafe_code)]

use crate::protocol::MAX_FRAME_BYTES;
use thiserror::Error;

/// Errors from encoding/decoding the length-delimited JSON wire protocol.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The encoded JSON payload would exceed [`MAX_FRAME_BYTES`].
    #[error("encoded frame of {0} bytes exceeds the {MAX_FRAME_BYTES} byte limit")]
    FrameTooLarge(usize),
    /// Failed to serialize a message to JSON.
    #[error("failed to encode message as JSON: {0}")]
    Encode(#[source] serde_json::Error),
    /// Failed to deserialize a message from JSON.
    #[error("failed to decode message as JSON: {0}")]
    Decode(#[source] serde_json::Error),
}

/// Errors from the platform adapter (Linux hardening primitives) or from
/// attempting to use them on an unsupported platform.
#[derive(Debug, Error)]
pub enum PlatformError {
    /// The current binary was built for / is running on a platform other
    /// than Linux, which is the only platform this spike supports at runtime.
    #[error(
        "exec-broker requires Linux (PR_SET_NO_NEW_PRIVS + seccomp); \
         this process is running on target_os = \"{0}\""
    )]
    UnsupportedPlatform(&'static str),
    /// A `prctl` call failed.
    #[error("prctl({operation}) failed: {source}")]
    Prctl {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    /// Building or loading the seccomp filter failed.
    #[error("seccomp filter setup failed: {0}")]
    Seccomp(String),
    /// Dropping capabilities failed.
    #[error("capability operation failed: {0}")]
    Capabilities(String),
    /// Setting a resource limit failed.
    #[error("rlimit operation failed: {0}")]
    Rlimit(std::io::Error),
    /// A raw syscall probe attempt could not even be issued (distinct from
    /// the attempt being *denied*, which is a successful, expected outcome).
    #[error("syscall probe attempt could not be issued: {0}")]
    ProbeSetup(String),
}

/// Errors surfaced by the policy allowlist evaluator.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Filesystem access needed to canonicalize or stat a path failed.
    #[error("failed to resolve path {path}: {source}")]
    PathResolution {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Top level broker error type.
#[derive(Debug, Error)]
pub enum BrokerError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime directory is unsafe to use: {0}")]
    UnsafeRuntimeDir(String),
    #[error("failed to establish session: {0}")]
    SessionSetup(String),
    #[error("restart is not supported: {0}")]
    RestartUnsupported(&'static str),
    /// Deliberate, documented acknowledgment that a narrow TOCTOU window
    /// remains between the broker/launcher's final `lstat`/canonicalize
    /// check and the kernel's own path resolution inside the `execve`
    /// syscall. Eliminating it fully would require O_PATH + fstat-by-fd +
    /// `fexecve`-style "exec exactly this already-opened inode" primitives
    /// that are out of scope for this Phase 1 spike. See
    /// `policy::Policy::revalidate_before_spawn` for the mitigation that is
    /// implemented (an immediate re-check right before spawn, which closes
    /// the window to the greatest extent practical without those
    /// primitives).
    #[error(
        "residual TOCTOU: path was validated and re-validated immediately before spawn, but a \
         symlink swap racing the kernel's own path resolution inside execve cannot be fully \
         eliminated without O_PATH/fexecve-style primitives (not implemented in this spike)"
    )]
    ResidualToctou,
    /// The supervisor's post-broker-death cleanup could not fully confirm
    /// every registered process group was killed. Surfaced explicitly
    /// (never silently swallowed) so a non-zero supervisor exit status is
    /// the caller-visible signal that an orphan may remain.
    #[error("supervisor cleanup failed to confirm {0} registered process group(s) were killed")]
    CleanupFailed(String),
}
