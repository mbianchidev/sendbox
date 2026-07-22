use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use proptest::prelude::*;
use sendbox_core::SessionId;
use sendbox_session_security::lifecycle::AuditRecorder;
use sendbox_session_security::supervisor::{
    ApprovalCancellation, ApprovalContext, ApprovalDecision, ApprovalHandler, ApprovalHandlerError,
    AuditPermissionEventSink, AutoApproveRule, GrantMatcher, GrantType, NoopPermissionEventSink,
    PermissionCategory, PermissionGrant, PermissionPattern, PermissionRequest,
    PermissionSupervisor, RiskLevel, SharedPermissionSupervisor, SupervisorCheckpoint,
    SupervisorClock, SupervisorConfig, SupervisorError, classify_risk, glob_matches,
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
        context: &ApprovalContext,
    ) -> Result<ApprovalDecision, ApprovalHandlerError> {
        self.deadlines.push(context.deadline_unix_ms);
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
        context: "test context".to_owned(),
        timestamp_unix_ms: 5,
    }
}

#[test]
fn defaults_and_presets_match_swift_configuration() {
    let default = SupervisorConfig::default();
    assert!(default.interactive);
    assert!(default.auto_approve.is_empty());
    assert_eq!(default.prompt_budget, 50);
    assert!(default.allow_session_grants);
    assert_eq!(default.approval_timeout_ms, 30_000);

    let strict = SupervisorConfig::strict();
    assert!(strict.interactive);
    assert_eq!(strict.prompt_budget, 100);
    assert!(!strict.allow_session_grants);
    assert_eq!(strict.approval_timeout_ms, 15_000);

    let autonomous = SupervisorConfig::autonomous();
    assert!(!autonomous.interactive);
    assert_eq!(autonomous.auto_approve.len(), 3);
    assert_eq!(autonomous.prompt_budget, 0);
    assert!(autonomous.allow_session_grants);
    assert_eq!(autonomous.approval_timeout_ms, 0);
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
fn approve_once_preserves_the_swift_single_use_grant() {
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
    assert_eq!(supervisor.grants().len(), 1);

    let granted = supervisor
        .evaluate(
            request("once-2", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([11]),
            None,
        )
        .expect("decision");
    assert!(granted.allowed);
    assert!(supervisor.grants().is_empty());

    let denied = supervisor
        .evaluate(
            request("once-3", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([12]),
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
fn cancellation_fails_closed_before_the_approval_handler() {
    let mut supervisor = make_supervisor(SupervisorConfig::default());
    let cancellation = ApprovalCancellation::new();
    cancellation.cancel();
    let mut handler = Handler::new([ApprovalDecision::ApproveOnce]);
    let decision = supervisor
        .evaluate_with_cancellation(
            request("cancelled", PermissionCategory::Command, "cargo test"),
            &SequenceClock::new([1]),
            Some(&mut handler),
            cancellation,
        )
        .expect("cancelled decision");
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "approval_cancelled");
    assert!(handler.deadlines.is_empty());
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
    assert!(decision.allowed);
    assert_eq!(decision.reason, "approval_once");
    assert_eq!(disabled.grants().len(), 1);
}

#[test]
fn manual_grants_history_and_summary_are_public_and_deterministic() {
    let mut supervisor = make_supervisor(SupervisorConfig::default());
    supervisor
        .grant(
            PermissionGrant {
                id: "manual-1".to_owned(),
                category: PermissionCategory::Command,
                matcher: GrantMatcher::Exact {
                    subject: "cargo test".to_owned(),
                },
                granted_at_unix_ms: 1,
                expires_at_unix_ms: Some(100),
                uses_remaining: Some(2),
                grant_type: GrantType::Session,
            },
            1,
        )
        .expect("manual grant");
    assert_eq!(supervisor.active_grants(2).len(), 1);
    assert!(
        supervisor
            .evaluate(
                request("manual-use", PermissionCategory::Command, "cargo test"),
                &SequenceClock::new([2]),
                None,
            )
            .expect("manual use")
            .allowed
    );
    let history = supervisor.history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].request_id, "manual-use");
    let summary = supervisor.summary(2);
    assert_eq!(summary.total_requests, 1);
    assert_eq!(summary.approved, 1);
    assert_eq!(summary.denied, 0);
    assert_eq!(summary.active_grant_count, 1);
    assert_eq!(
        summary.category_counts.get(&PermissionCategory::Command),
        Some(&1)
    );
}

struct FixedClock(u64);

impl SupervisorClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

#[test]
fn shared_supervisor_consumes_use_limits_atomically() {
    let mut supervisor = make_supervisor(SupervisorConfig::default());
    supervisor
        .grant(
            PermissionGrant {
                id: "concurrent".to_owned(),
                category: PermissionCategory::Command,
                matcher: GrantMatcher::Exact {
                    subject: "cargo test".to_owned(),
                },
                granted_at_unix_ms: 1,
                expires_at_unix_ms: None,
                uses_remaining: Some(10),
                grant_type: GrantType::Session,
            },
            1,
        )
        .expect("grant");
    let shared = Arc::new(SharedPermissionSupervisor::new(supervisor));
    let allowed = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for index in 0..32 {
        let shared = Arc::clone(&shared);
        let allowed = Arc::clone(&allowed);
        threads.push(thread::spawn(move || {
            let decision = shared
                .evaluate(
                    request(
                        &format!("concurrent-{index}"),
                        PermissionCategory::Command,
                        "cargo test",
                    ),
                    &FixedClock(2),
                )
                .expect("decision");
            if decision.allowed {
                allowed.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for thread in threads {
        thread.join().expect("join");
    }
    assert_eq!(allowed.load(Ordering::SeqCst), 10);
}

#[test]
fn manual_grants_cannot_collide_with_reserved_generated_ids() {
    let mut supervisor = make_supervisor(SupervisorConfig::default());
    let error = supervisor
        .grant(
            PermissionGrant {
                id: "grant-2".to_owned(),
                category: PermissionCategory::Network,
                matcher: GrantMatcher::Exact {
                    subject: "important.example.com".to_owned(),
                },
                granted_at_unix_ms: 1,
                expires_at_unix_ms: None,
                uses_remaining: None,
                grant_type: GrantType::Session,
            },
            1,
        )
        .expect_err("reserved prefix");
    assert!(matches!(error, SupervisorError::InvalidDecision(_)));
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

#[test]
fn empty_supervisor_matches_v1_golden_fixture() {
    let supervisor = make_supervisor(SupervisorConfig::default());
    let fixture = include_bytes!("fixtures/supervisor-state-v1-empty.json");
    let fixture = fixture.strip_suffix(b"\n").unwrap_or(fixture);
    assert_eq!(supervisor.encode_canonical().expect("bytes"), fixture);
    PermissionSupervisor::decode_unanchored_first_import(
        fixture,
        Arc::new(NoopPermissionEventSink),
    )
    .expect("golden fixture decodes");
}

#[test]
fn persisted_versions_reject_upgrade_and_downgrade_without_migration() {
    let supervisor = make_supervisor(SupervisorConfig::default());
    let bytes = supervisor.encode_canonical().expect("bytes");
    for version in [0, 2] {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        value["version"] = serde_json::Value::from(version);
        let changed = serde_json::to_vec(&value).expect("changed JSON");
        assert!(matches!(
            PermissionSupervisor::decode_unanchored_first_import(
                &changed,
                Arc::new(NoopPermissionEventSink)
            ),
            Err(SupervisorError::Corrupt(_))
        ));
    }
}

proptest! {
    #[test]
    fn permission_state_machine_round_trips_after_each_transition(
        maximum_uses in 1_u32..32,
        attempts in prop::collection::vec(any::<bool>(), 1..64),
    ) {
        let mut supervisor = make_supervisor(SupervisorConfig::default());
        supervisor
            .grant(
                PermissionGrant {
                    id: "property-grant".to_owned(),
                    category: PermissionCategory::Command,
                    matcher: GrantMatcher::Exact {
                        subject: "cargo test".to_owned(),
                    },
                    granted_at_unix_ms: 1,
                    expires_at_unix_ms: None,
                    uses_remaining: Some(maximum_uses),
                    grant_type: GrantType::Session,
                },
                1,
            )
            .expect("grant");
        let mut allowed = 0_u32;
        for (index, matches_grant) in attempts.into_iter().enumerate() {
            let subject = if matches_grant { "cargo test" } else { "cargo fmt" };
            let decision = supervisor
                .evaluate(
                    request(
                        &format!("property-{index}"),
                        PermissionCategory::Command,
                        subject,
                    ),
                    &FixedClock(2),
                    None,
                )
                .expect("decision");
            if decision.allowed {
                allowed += 1;
            }
            prop_assert!(allowed <= maximum_uses);
            let bytes = supervisor.encode_canonical().expect("encode");
            let checkpoint = supervisor.checkpoint();
            supervisor = PermissionSupervisor::decode_with_checkpoint(
                &bytes,
                &checkpoint,
                Arc::new(NoopPermissionEventSink),
            )
            .expect("round trip");
        }
    }
}
