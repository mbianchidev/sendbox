use sendbox_core::BoundaryPlanDigest;
use serde::{Deserialize, Serialize};

use crate::{Capability, CapabilitySet};

pub const OPERATION_SCHEMA_VERSION: u32 = 2;
pub const AGENT_LAUNCH_OPERATION: &str = "agent.launch";
/// Interactive launches use a distinct operation so an older guest replies
/// `Rejected` with `operation-not-supported` instead of silently running the
/// workload with null stdin.
pub const INTERACTIVE_LAUNCH_OPERATION: &str = "agent.launch.interactive";
pub const INTERACTIVE_OPERATION_SCHEMA_VERSION: u32 = 1;
pub const HEALTH_OPERATION: &str = "health";

/// Longest accepted `TERM` value; real terminfo names are far shorter.
const MAX_TERM_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEntryV2 {
    pub name: String,
    pub value: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretEnvelopeV2 {
    pub reference: String,
    pub sequence: u64,
    pub expires_at_unix_ms: u64,
    pub policy_digest: [u8; 32],
    pub boundary_plan_digest: BoundaryPlanDigest,
    pub envelope: Vec<u8>,
}

impl std::fmt::Debug for SecretEnvelopeV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretEnvelopeV2")
            .field("reference", &self.reference)
            .field("sequence", &self.sequence)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("policy_digest", &self.policy_digest)
            .field("boundary_plan_digest", &self.boundary_plan_digest)
            .field("envelope", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequestV2 {
    pub schema_version: u32,
    pub boundary_plan_digest: BoundaryPlanDigest,
    pub program: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub environment: Vec<EnvironmentEntryV2>,
    pub secrets: Vec<SecretEnvelopeV2>,
    pub timeout_ms: u64,
}

/// Terminal dimensions in character cells. Both fields must be non-zero: a
/// zero dimension is what an unset winsize looks like, and forwarding it would
/// leave the guest terminal misconfigured rather than failing loudly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalSizeV1 {
    pub columns: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InteractiveLaunchError {
    #[error("terminal dimensions must be non-zero")]
    EmptyTerminalSize,
    #[error("TERM must be a non-empty value of at most {MAX_TERM_BYTES} bytes")]
    TermLength,
    #[error("TERM must contain only alphanumeric, '-', '.', '_' or '+' characters")]
    TermCharset,
    #[error("interactive launch schema version is unsupported")]
    SchemaVersion,
}

impl TerminalSizeV1 {
    pub fn new(columns: u16, rows: u16) -> Result<Self, InteractiveLaunchError> {
        if columns == 0 || rows == 0 {
            return Err(InteractiveLaunchError::EmptyTerminalSize);
        }
        Ok(Self { columns, rows })
    }

    pub fn validate(self) -> Result<(), InteractiveLaunchError> {
        Self::new(self.columns, self.rows).map(|_| ())
    }
}

/// Interactive launch request.
///
/// The exact-argv, environment and secret-envelope semantics are reused by
/// embedding [`LaunchRequestV2`] verbatim rather than restating them, so the
/// interactive and headless paths can never drift apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractiveLaunchRequestV1 {
    pub schema_version: u32,
    pub launch: LaunchRequestV2,
    pub terminal: TerminalSizeV1,
    pub term: String,
}

impl InteractiveLaunchRequestV1 {
    /// Validates the interactive envelope. The embedded [`LaunchRequestV2`]
    /// keeps its own existing validation at the guest boundary.
    pub fn validate(&self) -> Result<(), InteractiveLaunchError> {
        if self.schema_version != INTERACTIVE_OPERATION_SCHEMA_VERSION {
            return Err(InteractiveLaunchError::SchemaVersion);
        }
        self.terminal.validate()?;
        if self.term.is_empty() || self.term.len() > MAX_TERM_BYTES {
            return Err(InteractiveLaunchError::TermLength);
        }
        if !self
            .term
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'+'))
        {
            return Err(InteractiveLaunchError::TermCharset);
        }
        Ok(())
    }
}

#[must_use]
pub fn agent_host_capabilities() -> CapabilitySet {
    CapabilitySet::from([
        Capability::Lifecycle,
        Capability::Exec,
        Capability::StreamedIo,
        Capability::Signals,
        Capability::Health,
    ])
}

#[must_use]
pub fn agent_host_required_capabilities() -> CapabilitySet {
    CapabilitySet::from([
        Capability::Exec,
        Capability::StreamedIo,
        Capability::Signals,
        Capability::Health,
    ])
}

#[must_use]
pub fn agent_guest_capabilities() -> CapabilitySet {
    CapabilitySet::from([
        Capability::Lifecycle,
        Capability::Exec,
        Capability::StreamedIo,
        Capability::Signals,
        Capability::Audit,
        Capability::Health,
    ])
}

#[must_use]
pub fn agent_guest_required_capabilities() -> CapabilitySet {
    CapabilitySet::from([Capability::Lifecycle, Capability::Health])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalStateV1 {
    Exited {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    Cancelled,
    TimedOut,
    OutputSaturated,
    ClientDisconnected,
    BrokerShutdown,
    SupervisorDied,
    Rejected {
        reason: String,
    },
    LaunchFailed {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalResultV2 {
    pub schema_version: u32,
    pub terminal: TerminalStateV1,
    pub cleanup_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponseV2 {
    pub schema_version: u32,
    pub ready: bool,
    pub broker_live: bool,
    pub release_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_schema_preserves_exact_argv_boundaries() {
        let request = LaunchRequestV2 {
            schema_version: OPERATION_SCHEMA_VERSION,
            boundary_plan_digest: BoundaryPlanDigest::from_bytes([2; 32]),
            program: "/usr/bin/tool".to_owned(),
            arguments: vec!["one value".to_owned(), "two".to_owned()],
            working_directory: "/workspace".to_owned(),
            environment: vec![EnvironmentEntryV2 {
                name: "SAFE".to_owned(),
                value: "value".to_owned(),
            }],
            secrets: vec![SecretEnvelopeV2 {
                reference: "TOKEN".to_owned(),
                sequence: 1,
                expires_at_unix_ms: 2_000,
                policy_digest: [3; 32],
                boundary_plan_digest: BoundaryPlanDigest::from_bytes([2; 32]),
                envelope: vec![4; 48],
            }],
            timeout_ms: 1_000,
        };
        let encoded = serde_json::to_vec(&request).expect("encode");
        let decoded: LaunchRequestV2 = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, request);
        assert_eq!(decoded.arguments, ["one value", "two"]);
    }

    #[test]
    fn agent_capability_profiles_are_mutually_satisfiable() {
        let negotiated = agent_host_capabilities().intersection(&agent_guest_capabilities());
        assert!(agent_host_required_capabilities().is_subset(&negotiated));
        assert!(agent_guest_required_capabilities().is_subset(&negotiated));
    }

    fn launch_request() -> LaunchRequestV2 {
        LaunchRequestV2 {
            schema_version: OPERATION_SCHEMA_VERSION,
            boundary_plan_digest: BoundaryPlanDigest::from_bytes([2; 32]),
            program: "/usr/bin/copilot".to_owned(),
            arguments: vec!["--banner".to_owned()],
            working_directory: "/workspace".to_owned(),
            environment: Vec::new(),
            secrets: Vec::new(),
            timeout_ms: 1_000,
        }
    }

    fn interactive_request() -> InteractiveLaunchRequestV1 {
        InteractiveLaunchRequestV1 {
            schema_version: INTERACTIVE_OPERATION_SCHEMA_VERSION,
            launch: launch_request(),
            terminal: TerminalSizeV1 {
                columns: 120,
                rows: 40,
            },
            term: "xterm-256color".to_owned(),
        }
    }

    #[test]
    fn interactive_request_round_trips_and_embeds_launch_verbatim() {
        let request = interactive_request();
        let encoded = serde_json::to_vec(&request).expect("encode");
        let decoded: InteractiveLaunchRequestV1 = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, request);
        assert_eq!(decoded.launch, launch_request());
        decoded.validate().expect("valid request");
    }

    #[test]
    fn interactive_request_rejects_unknown_fields() {
        let mut value = serde_json::to_value(interactive_request()).expect("encode");
        value
            .as_object_mut()
            .expect("object")
            .insert("extra".to_owned(), serde_json::Value::Bool(true));
        let error = serde_json::from_value::<InteractiveLaunchRequestV1>(value)
            .expect_err("unknown fields must fail");
        assert!(error.to_string().contains("extra"), "error: {error}");
    }

    #[test]
    fn interactive_request_rejects_zero_terminal_dimensions() {
        for (columns, rows) in [(0_u16, 40_u16), (120, 0), (0, 0)] {
            let mut request = interactive_request();
            request.terminal = TerminalSizeV1 { columns, rows };
            assert_eq!(
                request.validate().expect_err("zero dimension must fail"),
                InteractiveLaunchError::EmptyTerminalSize
            );
        }
        assert_eq!(
            TerminalSizeV1::new(0, 24).expect_err("zero columns must fail"),
            InteractiveLaunchError::EmptyTerminalSize
        );
    }

    #[test]
    fn interactive_request_rejects_hostile_term_values() {
        let cases = [
            ("", InteractiveLaunchError::TermLength),
            (
                &"x".repeat(MAX_TERM_BYTES + 1),
                InteractiveLaunchError::TermLength,
            ),
            ("xterm;rm -rf /", InteractiveLaunchError::TermCharset),
            ("xterm\nTERM=evil", InteractiveLaunchError::TermCharset),
            ("xterm\0", InteractiveLaunchError::TermCharset),
        ];
        for (term, expected) in cases {
            let mut request = interactive_request();
            request.term = term.to_owned();
            assert_eq!(
                request.validate().expect_err("hostile TERM must fail"),
                expected,
                "term: {term:?}"
            );
        }
    }

    #[test]
    fn interactive_request_rejects_foreign_schema_version() {
        let mut request = interactive_request();
        request.schema_version = INTERACTIVE_OPERATION_SCHEMA_VERSION + 1;
        assert_eq!(
            request.validate().expect_err("version mismatch must fail"),
            InteractiveLaunchError::SchemaVersion
        );
    }

    #[test]
    fn interactive_operation_name_differs_from_headless_launch() {
        assert_ne!(INTERACTIVE_LAUNCH_OPERATION, AGENT_LAUNCH_OPERATION);
        assert_eq!(AGENT_LAUNCH_OPERATION, "agent.launch");
    }
}
