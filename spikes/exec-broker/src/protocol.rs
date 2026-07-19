//! Bounded, length-delimited JSON wire protocol between an agent (client)
//! and the exec broker (server).
//!
//! Framing is a 4-byte big-endian length prefix followed by exactly that
//! many bytes of UTF-8 JSON, capped at [`MAX_FRAME_BYTES`] (64 KiB) in both
//! directions. This module is pure (no I/O, no filesystem, no sockets) and
//! forbids `unsafe`.

#![forbid(unsafe_code)]

use crate::error::ProtocolError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio_util::codec::LengthDelimitedCodec;

/// Maximum size, in bytes, of a single JSON frame (excluding the 4-byte
/// length prefix itself), in either direction.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Width, in bytes, of the big-endian length prefix.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// Structural limits enforced on an [`ClientMessage::Execute`] request
/// before any policy/allowlist evaluation happens. These bound the shape of
/// the request itself, independent of whether it is ultimately approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum number of correlation-id bytes.
    pub max_correlation_id_bytes: usize,
    /// Maximum number of argv elements (argc).
    pub max_argc: usize,
    /// Maximum length, in bytes, of any single argv element.
    pub max_arg_bytes: usize,
    /// Maximum combined length, in bytes, of all argv elements.
    pub max_argv_total_bytes: usize,
    /// Maximum number of environment variable entries.
    pub max_env_entries: usize,
    /// Maximum length, in bytes, of a single env `key=value` pair.
    pub max_env_entry_bytes: usize,
    /// Maximum combined length, in bytes, of all env entries.
    pub max_env_total_bytes: usize,
    /// Maximum length, in bytes, of the requested working directory string.
    pub max_cwd_bytes: usize,
    /// Minimum accepted timeout.
    pub min_timeout: Duration,
    /// Maximum accepted timeout.
    pub max_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_correlation_id_bytes: 128,
            max_argc: 64,
            max_arg_bytes: 4 * 1024,
            max_argv_total_bytes: 32 * 1024,
            max_env_entries: 64,
            max_env_entry_bytes: 4 * 1024,
            max_env_total_bytes: 16 * 1024,
            max_cwd_bytes: 4 * 1024,
            min_timeout: Duration::from_millis(10),
            max_timeout: Duration::from_secs(300),
        }
    }
}

/// Messages an agent (client) may send to the broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Request execution of a command. `argv[0]` is both the executable
    /// path and the first argument, matching POSIX `exec*` semantics
    /// exactly: there is no separate "executable" field.
    ///
    /// `session_id`/`token` are the broker-instance-wide session
    /// credential (see [`crate::session::Session`]), read by the caller
    /// from the broker's private credential file. The broker
    /// authenticates these *before* registering `correlation_id` or
    /// spawning anything; a mismatch is rejected with
    /// [`RejectionCode::SessionUnauthorized`] and never reaches the
    /// spawn path.
    Execute {
        correlation_id: String,
        session_id: String,
        token: String,
        argv: Vec<String>,
        cwd: String,
        env: BTreeMap<String, String>,
        timeout_ms: u64,
    },
    /// Cancel a previously started (or still-starting) execution. Carries
    /// the same session credential as `Execute`, authenticated the same
    /// way before the broker acts on it.
    Cancel {
        correlation_id: String,
        session_id: String,
        token: String,
    },
}

/// Events the broker may send to an agent (client).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    /// The requested command was accepted and spawned.
    Started {
        correlation_id: String,
        pid: i32,
        pgid: i32,
    },
    /// A chunk of standard output. `data` is base64-encoded because child
    /// output is not guaranteed to be valid UTF-8.
    Stdout {
        correlation_id: String,
        data: String,
        truncated: bool,
    },
    /// A chunk of standard error, encoded like [`ServerEvent::Stdout`].
    Stderr {
        correlation_id: String,
        data: String,
        truncated: bool,
    },
    /// The execution reached a terminal state.
    Completed {
        correlation_id: String,
        outcome: Outcome,
    },
    /// The request was rejected before (or instead of) being spawned.
    Rejected {
        correlation_id: String,
        code: RejectionCode,
        message: String,
    },
}

/// Terminal states for a completed execution. Every non-happy-path is named
/// explicitly rather than folded into a generic "error" bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Outcome {
    /// The process ran to completion and exited or was signaled.
    Exited {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    /// The process exceeded its requested timeout and its process group was
    /// killed.
    TimedOut,
    /// The client sent `Cancel` for this correlation id.
    Cancelled,
    /// The client's connection was lost while the command was running.
    ClientDisconnected,
    /// The broker is shutting down and killed all in-flight process groups.
    BrokerShutdown,
    /// The contained-launcher process could not be spawned at all.
    SpawnFailed {
        code: RejectionCode,
        message: String,
    },
    /// Draining stdout/stderr stalled writing back to the client for longer
    /// than the configured bound; the process group was killed as a result.
    StreamStalled,
}

/// Deterministic, machine-readable rejection codes. These are stable
/// identifiers a client/test can match on, independent of the human-readable
/// `message` string that accompanies a [`ServerEvent::Rejected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCode {
    FrameTooLarge,
    MalformedMessage,
    InvalidCorrelationId,
    DuplicateCorrelationId,
    UnknownCorrelationId,
    SessionUnauthorized,
    ArgvEmpty,
    ArgcExceeded,
    ArgumentTooLarge,
    ArgvTotalTooLarge,
    EnvEntriesExceeded,
    EnvEntryTooLarge,
    EnvTotalTooLarge,
    NulByte,
    DangerousEnvVar,
    CwdNotAbsolute,
    CwdTooLarge,
    CwdNotApproved,
    CwdNotDirectory,
    ExecutableNotAbsolute,
    ExecutableNotAllowlisted,
    ExecutableNotCanonical,
    ExecutableNotRegularFile,
    ExecutableInterpreterDenied,
    ExecutableChangedSinceValidation,
    TimeoutOutOfRange,
    PolicyDenied,
    PlatformUnsupported,
    SpawnFailed,
}

/// Structural (allowlist-independent) validation of a `Execute` request's
/// shape against [`Limits`]. This never touches the filesystem; it only
/// inspects the message as received. Allowlist/canonical-path evaluation
/// happens separately in `policy::Policy::evaluate`.
pub fn validate_structure(
    correlation_id: &str,
    argv: &[String],
    cwd: &str,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    limits: &Limits,
) -> Result<(), RejectionCode> {
    if correlation_id.is_empty() || correlation_id.len() > limits.max_correlation_id_bytes {
        return Err(RejectionCode::InvalidCorrelationId);
    }
    if contains_nul(correlation_id) {
        return Err(RejectionCode::NulByte);
    }

    if argv.is_empty() {
        return Err(RejectionCode::ArgvEmpty);
    }
    if argv.len() > limits.max_argc {
        return Err(RejectionCode::ArgcExceeded);
    }
    let mut argv_total = 0usize;
    for arg in argv {
        if contains_nul(arg) {
            return Err(RejectionCode::NulByte);
        }
        if arg.len() > limits.max_arg_bytes {
            return Err(RejectionCode::ArgumentTooLarge);
        }
        argv_total += arg.len();
    }
    if argv_total > limits.max_argv_total_bytes {
        return Err(RejectionCode::ArgvTotalTooLarge);
    }

    if contains_nul(cwd) {
        return Err(RejectionCode::NulByte);
    }
    if cwd.len() > limits.max_cwd_bytes {
        return Err(RejectionCode::CwdTooLarge);
    }
    if !cwd.starts_with('/') {
        return Err(RejectionCode::CwdNotAbsolute);
    }

    if env.len() > limits.max_env_entries {
        return Err(RejectionCode::EnvEntriesExceeded);
    }
    let mut env_total = 0usize;
    for (key, value) in env {
        if contains_nul(key) || contains_nul(value) {
            return Err(RejectionCode::NulByte);
        }
        let entry_len = key.len() + 1 + value.len();
        if entry_len > limits.max_env_entry_bytes {
            return Err(RejectionCode::EnvEntryTooLarge);
        }
        env_total += entry_len;
    }
    if env_total > limits.max_env_total_bytes {
        return Err(RejectionCode::EnvTotalTooLarge);
    }

    if timeout < limits.min_timeout || timeout > limits.max_timeout {
        return Err(RejectionCode::TimeoutOutOfRange);
    }

    Ok(())
}

/// Returns true if `s` contains an embedded NUL byte. `serde_json` happily
/// decodes a JSON string containing `\u0000` into a Rust `String` with an
/// embedded `\0`, which must never reach a C string boundary (argv/envp) or
/// path API, so every string field is explicitly checked.
#[must_use]
pub fn contains_nul(s: &str) -> bool {
    s.as_bytes().contains(&0)
}

/// Builds the shared length-delimited codec configuration used by both the
/// broker and any client: a 4-byte big-endian length prefix, capped at
/// [`MAX_FRAME_BYTES`].
#[must_use]
pub fn framed_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(LENGTH_PREFIX_BYTES)
        .big_endian()
        .max_frame_length(MAX_FRAME_BYTES)
        .new_codec()
}

/// Serializes `value` to JSON and rejects it up front if it would exceed
/// [`MAX_FRAME_BYTES`], rather than relying solely on the codec's own
/// enforcement at write time.
pub fn encode_message<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let json = serde_json::to_vec(value).map_err(ProtocolError::Encode)?;
    if json.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(json.len()));
    }
    Ok(json)
}

/// Deserializes `bytes` as JSON, rejecting oversized input up front.
pub fn decode_message<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(bytes.len()));
    }
    serde_json::from_slice(bytes).map_err(ProtocolError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    #[test]
    fn round_trips_execute_message() {
        let msg = ClientMessage::Execute {
            correlation_id: "corr-1".into(),
            session_id: "session-1".into(),
            token: "aa".into(),
            argv: vec!["/usr/bin/true".into()],
            cwd: "/tmp/work".into(),
            env: BTreeMap::new(),
            timeout_ms: 1000,
        };
        let bytes = encode_message(&msg).expect("encode");
        let decoded: ClientMessage = decode_message(&bytes).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn rejects_oversized_frame_on_encode() {
        let huge_arg = "a".repeat(MAX_FRAME_BYTES + 10);
        let msg = ClientMessage::Execute {
            correlation_id: "corr-1".into(),
            session_id: "session-1".into(),
            token: "aa".into(),
            argv: vec![huge_arg],
            cwd: "/tmp".into(),
            env: BTreeMap::new(),
            timeout_ms: 1000,
        };
        let err = encode_message(&msg).expect_err("must reject");
        assert!(matches!(err, ProtocolError::FrameTooLarge(_)));
    }

    #[test]
    fn rejects_oversized_frame_on_decode() {
        let bytes = vec![b'a'; MAX_FRAME_BYTES + 1];
        let err = decode_message::<ClientMessage>(&bytes).expect_err("must reject");
        assert!(matches!(err, ProtocolError::FrameTooLarge(_)));
    }

    #[test]
    fn detects_embedded_nul_bytes() {
        assert!(contains_nul("abc\0def"));
        assert!(!contains_nul("abcdef"));
    }

    #[test]
    fn structural_validation_rejects_nul_in_argv() {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let err = validate_structure(
            "corr",
            &["/bin/echo".to_string(), "bad\0arg".to_string()],
            "/tmp",
            &env,
            Duration::from_secs(1),
            &limits(),
        )
        .expect_err("must reject");
        assert_eq!(err, RejectionCode::NulByte);
    }

    #[test]
    fn structural_validation_rejects_empty_argv() {
        let err = validate_structure(
            "corr",
            &[],
            "/tmp",
            &BTreeMap::new(),
            Duration::from_secs(1),
            &limits(),
        )
        .expect_err("must reject");
        assert_eq!(err, RejectionCode::ArgvEmpty);
    }

    #[test]
    fn structural_validation_rejects_relative_cwd() {
        let err = validate_structure(
            "corr",
            &["/bin/echo".to_string()],
            "relative/path",
            &BTreeMap::new(),
            Duration::from_secs(1),
            &limits(),
        )
        .expect_err("must reject");
        assert_eq!(err, RejectionCode::CwdNotAbsolute);
    }

    #[test]
    fn structural_validation_rejects_timeout_out_of_range() {
        let err = validate_structure(
            "corr",
            &["/bin/echo".to_string()],
            "/tmp",
            &BTreeMap::new(),
            Duration::from_secs(3600),
            &limits(),
        )
        .expect_err("must reject");
        assert_eq!(err, RejectionCode::TimeoutOutOfRange);
    }

    #[test]
    fn structural_validation_rejects_argc_exceeded() {
        let mut limits = limits();
        limits.max_argc = 2;
        let err = validate_structure(
            "corr",
            &["/bin/echo".to_string(), "a".to_string(), "b".to_string()],
            "/tmp",
            &BTreeMap::new(),
            Duration::from_secs(1),
            &limits,
        )
        .expect_err("must reject");
        assert_eq!(err, RejectionCode::ArgcExceeded);
    }

    #[test]
    fn structural_validation_accepts_well_formed_request() {
        validate_structure(
            "corr",
            &["/bin/echo".to_string(), "hello".to_string()],
            "/tmp",
            &BTreeMap::new(),
            Duration::from_secs(1),
            &limits(),
        )
        .expect("must accept");
    }
}
