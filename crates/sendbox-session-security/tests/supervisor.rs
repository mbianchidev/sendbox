use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use sendbox_core::SessionId;
use sendbox_session_security::lifecycle::AuditRecorder;
use sendbox_session_security::supervisor::{
    ApprovalDecision, ApprovalHandler, ApprovalHandlerError, AuditPermissionEventSink,
    AutoApproveRule, NoopPermissionEventSink, PermissionCategory, PermissionPattern,
    PermissionRequest, PermissionSupervisor, RiskLevel, SupervisorCheckpoint, SupervisorClock,
    SupervisorConfig, SupervisorError, classify_risk, glob_matches,
};

const SESSION: SessionId = SessionId::from_bytes([0x34; 16]);

struct SequenceClock {
    values: Mutex<VecDeque<u64>>,
}

impl SequenceClock {
    fn new(values: impl IntoIterator<Item = u64>) -> Self {
        Self {
            values: Mutex::new(values.into_iter().collect()),
        }
    }
}

impl SupervisorClock for SequenceClock {
    fn now_unix_ms(&self) -> u64 {
        self.values
            .lock()
            .expect("clock")
            .pop_front()
            .expect("clock value")
    }
}

struct Handler {
    decisions: VecDeque<Result<ApprovalDecision, ApprovalHandlerError>>,
    deadlines: Vec<u64>,
}

impl Handler {
    fn new(decisions: impl IntoIterator<Item = ApprovalDecision>) -> Self {
        Self {
            decisions: decisions.into_iter().map(Ok).collect(),
            deadlines: Vec::new(),
        }
    }
}

impl ApprovalHandler for Handler {
    fn approve(
        &mut self,
        _request: &PermissionRequest,
        _risk: RiskLevel,
        deadline_unix_ms: u64,
    ) -> Result<ApprovalDecision, ApprovalHandlerError> {
        self.deadlines.push(deadline_unix_ms);
        self.decisions.pop_front().expect("decision")
    }
}

fn make_supervisor(config: SupervisorConfig) -> PermissionSupervisor {
    PermissionSupervisor::new(SESSION, config, Arc::new(NoopPermissionEventSink))
        .expect("supervisor")
}

fn request(id: &str, category: PermissionCategory, subject: &str) -> PermissionRequest {
    PermissionRequest {
        request_id: id.to_owned(),
        category,
        subject: subject.to_owned(),
        timestamp_unix_ms: 5,
    }
}

#[test]
fn swift_risk_literals_and_globs_match_expected_behavior() {
    assert_eq!(
        classify_risk(PermissionCategory::SystemCall, "mount"),
        RiskLevel::Critical
    );
    assert_eq!(
        classify_risk(PermissionCategory::SystemCall, "MOUNT"),
        RiskLevel::High
    );
    assert_eq!(
        classify_risk(PermissionCategory::SecretAccess, "TOKEN"),
        RiskLevel::High
    );
    assert_eq!(
        classify_risk(PermissionCategory::Network, "github.com"),
        RiskLevel::Medium
    );
    assert_eq!(
        classify_risk(PermissionCategory::Network, "https://pypi.org/simple"),
        RiskLevel::Medium
    );
    assert_eq!(
        classify_risk(PermissionCategory::Network, "unknown.example"),
        RiskLevel::High
    );
    assert_eq!(
        classify_risk(PermissionCategory::Command, "sudo rm -rf build"),
        RiskLevel::High
    );
    assert_eq!(
        classify_risk(PermissionCategory::Command, "cargo test"),
        RiskLevel::Medium
    );
    assert_eq!(
        classify_risk(PermissionCategory::FileWrite, "/etc/hosts"),
        RiskLevel::High
    );
    assert_eq!(
        classify_risk(PermissionCategory::FileWrite, "target/result"),
        RiskLevel::Low
    );
    assert!(glob_matches("cargo * --?", "cargo test --x"));
    assert!(glob_matches("hé?lo*", "héllo世界"));
    assert!(!glob_matches("cargo ?", "cargo test"));
}

#[test]
fn approve_once_does_not_leave_an_extra_use() {
    let mut supervisor = make_supervisor(SupervisorConfig::default());
    let mut handler = Handler::new([ApprovalDecision::ApproveOnce]);
    let allowed = supervisor
        .evaluate(
            request("once-1", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([10, 10]),
            Some(&mut handler),
        )
        .expect("decision");
    assert!(allowed.allowed);
    assert!(supervisor.grants().is_empty());

    let denied = supervisor
        .evaluate(
            request("once-2", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([11]),
            None,
        )
        .expect("decision");
    assert!(!denied.allowed);
}

#[test]
fn session_and_pattern_grants_consume_limits_and_expire() {
    let mut supervisor = make_supervisor(SupervisorConfig::default());
    let mut handler = Handler::new([ApprovalDecision::ApproveSession {
        expires_at_unix_ms: Some(100),
        max_uses: Some(3),
    }]);
    assert!(
        supervisor
            .evaluate(
                request("session-1", PermissionCategory::Command, "cargo test"),
                &SequenceClock::new([10, 10]),
                Some(&mut handler),
            )
            .expect("session approval")
            .allowed
    );
    assert_eq!(supervisor.grants().len(), 1);
    for id in ["session-2", "session-3"] {
        assert!(
            supervisor
                .evaluate(
                    request(id, PermissionCategory::Command, "cargo test"),
                    &SequenceClock::new([20]),
                    None,
                )
                .expect("grant")
                .allowed
        );
    }
    assert!(supervisor.grants().is_empty());
    assert!(
        !supervisor
            .evaluate(
                request("session-4", PermissionCategory::Command, "cargo test"),
                &SequenceClock::new([20]),
                None,
            )
            .expect("no grant")
            .allowed
    );

    let mut pattern_supervisor = make_supervisor(SupervisorConfig::default());
    let mut pattern_handler = Handler::new([ApprovalDecision::ApprovePattern {
        pattern: "cargo *".to_owned(),
        expires_at_unix_ms: Some(50),
        max_uses: None,
    }]);
    assert!(
        pattern_supervisor
            .evaluate(
                request("pattern-1", PermissionCategory::Command, "cargo test"),
                &SequenceClock::new([10, 10]),
                Some(&mut pattern_handler),
            )
            .expect("pattern approval")
            .allowed
    );
    assert!(
        pattern_supervisor
            .evaluate(
                request("pattern-2", PermissionCategory::Command, "cargo fmt"),
                &SequenceClock::new([20]),
                None,
            )
            .expect("pattern grant")
            .allowed
    );
    assert!(
        !pattern_supervisor
            .evaluate(
                request("pattern-3", PermissionCategory::Command, "cargo clippy"),
                &SequenceClock::new([50]),
                None,
            )
            .expect("expired")
            .allowed
    );
}

#[test]
fn timeout_replay_prompt_budget_and_noninteractive_are_denied() {
    let config = SupervisorConfig {
        approval_timeout_ms: 10,
        prompt_budget: 1,
        ..SupervisorConfig::default()
    };
    let mut supervisor = make_supervisor(config);
    let mut handler = Handler::new([ApprovalDecision::ApproveOnce]);
    let timeout = supervisor
        .evaluate(
            request("timeout", PermissionCategory::Network, "unknown.example"),
            &SequenceClock::new([100, 111]),
            Some(&mut handler),
        )
        .expect("timeout");
    assert!(!timeout.allowed);
    assert_eq!(timeout.reason, "approval_timeout");
    assert_eq!(handler.deadlines, vec![110]);
    assert!(matches!(
        supervisor.evaluate(
            request("timeout", PermissionCategory::Network, "unknown.example"),
            &SequenceClock::new([112]),
            None
        ),
        Err(SupervisorError::Replay(_))
    ));
    let budget = supervisor
        .evaluate(
            request("budget", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([112]),
            None,
        )
        .expect("budget");
    assert_eq!(budget.reason, "prompt_budget_exhausted");

    let config = SupervisorConfig {
        interactive: false,
        ..SupervisorConfig::default()
    };
    let mut noninteractive = make_supervisor(config);
    let decision = noninteractive
        .evaluate(
            request("batch", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([1]),
            None,
        )
        .expect("noninteractive");
    assert_eq!(decision.reason, "noninteractive");
}

#[test]
fn auto_rules_are_bounded_and_exact_denies_take_precedence() {
    let config = SupervisorConfig {
        auto_approve: vec![AutoApproveRule {
            matcher: PermissionPattern {
                category: PermissionCategory::Network,
                pattern: "*.github.com".to_owned(),
            },
            max_uses: Some(1),
        }],
        ..SupervisorConfig::default()
    };
    let mut supervisor = make_supervisor(config);
    assert!(
        supervisor
            .evaluate(
                request("auto-1", PermissionCategory::Network, "api.github.com"),
                &SequenceClock::new([1]),
                None,
            )
            .expect("auto")
            .allowed
    );
    assert!(
        !supervisor
            .evaluate(
                request("auto-2", PermissionCategory::Network, "api.github.com"),
                &SequenceClock::new([2]),
                None,
            )
            .expect("auto exhausted")
            .allowed
    );

    let mut grants = make_supervisor(SupervisorConfig::default());
    let mut handler = Handler::new([ApprovalDecision::ApprovePattern {
        pattern: "cargo *".to_owned(),
        expires_at_unix_ms: None,
        max_uses: None,
    }]);
    grants
        .evaluate(
            request("grant", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([1, 1]),
            Some(&mut handler),
        )
        .expect("grant");
    grants
        .add_exact_deny(PermissionCategory::Command, "cargo test".to_owned(), 2)
        .expect("deny");
    let denied = grants
        .evaluate(
            request("denied", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([3]),
            None,
        )
        .expect("deny precedence");
    assert_eq!(denied.reason, "exact_deny_rule");
}

#[test]
fn deny_always_is_literal_and_session_grants_can_be_disabled() {
    let mut supervisor = make_supervisor(SupervisorConfig::default());
    let mut handler = Handler::new([ApprovalDecision::DenyAlways]);
    assert!(
        !supervisor
            .evaluate(
                request("deny-always", PermissionCategory::Command, "cargo test"),
                &SequenceClock::new([1, 1]),
                Some(&mut handler),
            )
            .expect("deny always")
            .allowed
    );
    assert!(
        !supervisor
            .evaluate(
                request("exact-deny", PermissionCategory::Command, "cargo test"),
                &SequenceClock::new([2]),
                None,
            )
            .expect("exact deny")
            .allowed
    );
    assert_eq!(
        supervisor
            .evaluate(
                request(
                    "literal-only",
                    PermissionCategory::Command,
                    "cargo test --all"
                ),
                &SequenceClock::new([2]),
                None,
            )
            .expect("literal deny only")
            .reason,
        "no_approval_handler"
    );

    let config = SupervisorConfig {
        allow_session_grants: false,
        ..SupervisorConfig::default()
    };
    let mut disabled = make_supervisor(config);
    let mut handler = Handler::new([ApprovalDecision::ApproveSession {
        expires_at_unix_ms: None,
        max_uses: None,
    }]);
    let decision = disabled
        .evaluate(
            request("disabled", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([1, 1]),
            Some(&mut handler),
        )
        .expect("disabled session grant");
    assert!(!decision.allowed);
    assert!(disabled.grants().is_empty());
}

#[test]
fn revocation_removes_grants_and_is_recorded() {
    let mut supervisor = make_supervisor(SupervisorConfig::default());
    let mut handler = Handler::new([ApprovalDecision::ApproveSession {
        expires_at_unix_ms: None,
        max_uses: None,
    }]);
    supervisor
        .evaluate(
            request("grant", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([1, 1]),
            Some(&mut handler),
        )
        .expect("grant");
    let grant_id = supervisor.grants().keys().next().expect("id").clone();
    supervisor.revoke_grant(&grant_id, 2).expect("revoke");
    assert!(supervisor.grants().is_empty());
    assert!(
        !supervisor
            .evaluate(
                request("after-revoke", PermissionCategory::Command, "cargo test"),
                &SequenceClock::new([3]),
                None,
            )
            .expect("denied")
            .allowed
    );
    supervisor.revoke_all_grants(4).expect("revoke all");
}

#[test]
fn handler_errors_are_recorded_denials_and_returned() {
    let mut supervisor = make_supervisor(SupervisorConfig::default());
    let mut handler = Handler {
        decisions: VecDeque::from([Err(ApprovalHandlerError {
            message: "ui unavailable".to_owned(),
        })]),
        deadlines: Vec::new(),
    };
    let error = supervisor
        .evaluate(
            request("handler-error", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([1, 1]),
            Some(&mut handler),
        )
        .expect_err("handler error");
    assert_eq!(
        error,
        SupervisorError::ApprovalHandler("ui unavailable".to_owned())
    );
    assert!(matches!(
        supervisor.evaluate(
            request("handler-error", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([2]),
            None
        ),
        Err(SupervisorError::Replay(_))
    ));
}

#[test]
fn persistence_is_deterministic_strict_and_hash_checked() {
    let mut left = make_supervisor(SupervisorConfig::default());
    let mut right = make_supervisor(SupervisorConfig::default());
    for supervisor in [&mut left, &mut right] {
        let mut handler = Handler::new([ApprovalDecision::DenyAlways]);
        supervisor
            .evaluate(
                request("same", PermissionCategory::Command, "cargo test"),
                &SequenceClock::new([1, 1]),
                Some(&mut handler),
            )
            .expect("decision");
    }
    let bytes = left.encode_canonical().expect("encode");
    assert_eq!(bytes, right.encode_canonical().expect("encode"));
    let decoded = PermissionSupervisor::decode_unanchored_first_import(
        &bytes,
        Arc::new(NoopPermissionEventSink),
    )
    .expect("decode");
    assert_eq!(decoded.checkpoint(), left.checkpoint());

    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let pretty = serde_json::to_vec_pretty(&value).expect("pretty");
    assert!(matches!(
        PermissionSupervisor::decode_unanchored_first_import(
            &pretty,
            Arc::new(NoopPermissionEventSink)
        ),
        Err(SupervisorError::Corrupt(_))
    ));

    let mut corrupt = bytes.clone();
    let marker = b"\"state_hash\":\"";
    let start = corrupt
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("state hash")
        + marker.len();
    corrupt[start] = if corrupt[start] == b'a' { b'b' } else { b'a' };
    assert_eq!(
        PermissionSupervisor::decode_unanchored_first_import(
            &corrupt,
            Arc::new(NoopPermissionEventSink)
        )
        .expect_err("hash"),
        SupervisorError::HashMismatch
    );
}

#[test]
fn checkpoints_reject_replay_equivocation_jumps_and_wrong_links() {
    let initial = make_supervisor(SupervisorConfig::default());
    let initial_bytes = initial.encode_canonical().expect("initial");
    let initial_checkpoint = initial.checkpoint();

    let mut branch_a = PermissionSupervisor::decode_unanchored_first_import(
        &initial_bytes,
        Arc::new(NoopPermissionEventSink),
    )
    .expect("branch a");
    let mut deny = Handler::new([ApprovalDecision::Deny]);
    branch_a
        .evaluate(
            request("a1", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([1, 1]),
            Some(&mut deny),
        )
        .expect("a1");
    let checkpoint_a1 = branch_a.checkpoint();
    let bytes_a1 = branch_a.encode_canonical().expect("a1 bytes");
    PermissionSupervisor::decode_with_checkpoint(
        &bytes_a1,
        &initial_checkpoint,
        Arc::new(NoopPermissionEventSink),
    )
    .expect("one advance");

    assert!(matches!(
        PermissionSupervisor::decode_with_checkpoint(
            &initial_bytes,
            &checkpoint_a1,
            Arc::new(NoopPermissionEventSink)
        ),
        Err(SupervisorError::CheckpointReplay { .. })
    ));

    let mut branch_b = PermissionSupervisor::decode_unanchored_first_import(
        &initial_bytes,
        Arc::new(NoopPermissionEventSink),
    )
    .expect("branch b");
    let mut deny_always = Handler::new([ApprovalDecision::DenyAlways]);
    branch_b
        .evaluate(
            request("b1", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([1, 1]),
            Some(&mut deny_always),
        )
        .expect("b1");
    assert!(matches!(
        PermissionSupervisor::decode_with_checkpoint(
            &branch_b.encode_canonical().expect("b1 bytes"),
            &checkpoint_a1,
            Arc::new(NoopPermissionEventSink)
        ),
        Err(SupervisorError::CheckpointEquivocation { .. })
    ));

    let mut second = Handler::new([ApprovalDecision::Deny]);
    branch_b
        .evaluate(
            request("b2", PermissionCategory::Command, "cargo fmt"),
            &SequenceClock::new([2, 2]),
            Some(&mut second),
        )
        .expect("b2");
    let bytes_b2 = branch_b.encode_canonical().expect("b2 bytes");
    assert!(matches!(
        PermissionSupervisor::decode_with_checkpoint(
            &bytes_b2,
            &initial_checkpoint,
            Arc::new(NoopPermissionEventSink)
        ),
        Err(SupervisorError::CheckpointJump { .. })
    ));
    assert_eq!(
        PermissionSupervisor::decode_with_checkpoint(
            &bytes_b2,
            &checkpoint_a1,
            Arc::new(NoopPermissionEventSink)
        )
        .expect_err("wrong branch"),
        SupervisorError::CheckpointLink
    );
}

#[test]
fn audit_sink_anchors_each_permission_generation() {
    let recorder = AuditRecorder::new(SESSION).expect("audit");
    let sink = Arc::new(AuditPermissionEventSink::new(recorder.clone()));
    let config = SupervisorConfig {
        interactive: false,
        ..SupervisorConfig::default()
    };
    let mut supervisor = PermissionSupervisor::new(SESSION, config, sink).expect("supervisor");
    let decision = supervisor
        .evaluate(
            request("audit", PermissionCategory::SecretAccess, "TOKEN"),
            &SequenceClock::new([1]),
            None,
        )
        .expect("decision");
    let records = recorder.records().expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].event.metadata.get("generation"),
        Some(&decision.generation.to_string())
    );
    assert_eq!(
        records[0].event.metadata.get("state_hash"),
        Some(&decision.state_hash)
    );
}

#[test]
fn equal_exact_checkpoint_is_accepted() {
    let supervisor = make_supervisor(SupervisorConfig::default());
    let checkpoint: SupervisorCheckpoint = supervisor.checkpoint();
    let decoded = PermissionSupervisor::decode_with_checkpoint(
        &supervisor.encode_canonical().expect("bytes"),
        &checkpoint,
        Arc::new(NoopPermissionEventSink),
    )
    .expect("equal checkpoint");
    assert_eq!(decoded.checkpoint(), checkpoint);
}
