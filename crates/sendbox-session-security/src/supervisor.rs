//! Deterministic, UI-free permission supervision and persistence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use sendbox_core::SessionId;
use sendbox_security::audit::{AuditCategory, AuditResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::lifecycle::AuditRecorder;

const SUPERVISOR_FORMAT: &str = "sendbox-permission-supervisor";
const SUPERVISOR_VERSION: u16 = 1;
const STATE_HASH_DOMAIN: &[u8] = b"sendbox-permission-supervisor-state-v1\0";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_PERSISTED_BYTES: usize = 1024 * 1024;
const HARD_MAX_RULES: usize = 4096;
const HARD_MAX_HISTORY: usize = 100_000;
const HARD_MAX_REQUEST_IDS: usize = 100_000;
const HARD_MAX_PATTERN_BYTES: usize = 1024;
const HARD_MAX_SUBJECT_BYTES: usize = 16 * 1024;
const HARD_MAX_ID_BYTES: usize = 256;
const HARD_MAX_PROMPTS: u32 = 100_000;
const HARD_MAX_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionCategory {
    Command,
    Network,
    FileWrite,
    SecretAccess,
    SystemCall,
}

impl PermissionCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Network => "network",
            Self::FileWrite => "file_write",
            Self::SecretAccess => "secret_access",
            Self::SystemCall => "system_call",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[must_use]
pub fn classify_risk(category: PermissionCategory, subject: &str) -> RiskLevel {
    match category {
        PermissionCategory::SystemCall => {
            const CRITICAL: [&str; 6] =
                ["mount", "umount", "reboot", "shutdown", "kexec", "insmod"];
            if CRITICAL.iter().any(|pattern| subject.contains(pattern)) {
                RiskLevel::Critical
            } else {
                RiskLevel::High
            }
        }
        PermissionCategory::SecretAccess => RiskLevel::High,
        PermissionCategory::Network => {
            const KNOWN: [&str; 6] = [
                "github.com",
                "npmjs.org",
                "pypi.org",
                "crates.io",
                "docker.io",
                "docker.com",
            ];
            if KNOWN.iter().any(|known| subject.contains(known)) {
                RiskLevel::Medium
            } else {
                RiskLevel::High
            }
        }
        PermissionCategory::Command => {
            const DANGEROUS: [&str; 9] = [
                "sudo",
                "su",
                "chmod",
                "chown",
                "dd",
                "mkfs",
                "fdisk",
                "iptables",
                "systemctl",
            ];
            if DANGEROUS.iter().any(|prefix| subject.starts_with(prefix)) {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            }
        }
        PermissionCategory::FileWrite => {
            if ["/etc", "/usr", "/sys", "/proc"]
                .iter()
                .any(|prefix| subject.starts_with(prefix))
            {
                RiskLevel::High
            } else {
                RiskLevel::Low
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionPattern {
    pub category: PermissionCategory,
    pub pattern: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApproveRule {
    pub matcher: PermissionPattern,
    pub max_uses: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorLimits {
    pub max_grants: usize,
    pub max_deny_rules: usize,
    pub max_history: usize,
    pub max_request_ids: usize,
    pub max_pattern_bytes: usize,
    pub max_subject_bytes: usize,
}

impl Default for SupervisorLimits {
    fn default() -> Self {
        Self {
            max_grants: 1024,
            max_deny_rules: 1024,
            max_history: 10_000,
            max_request_ids: 10_000,
            max_pattern_bytes: 512,
            max_subject_bytes: 4096,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorConfig {
    pub interactive: bool,
    pub auto_approve: Vec<AutoApproveRule>,
    pub prompt_budget: u32,
    pub allow_session_grants: bool,
    pub approval_timeout_ms: u64,
    pub limits: SupervisorLimits,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            interactive: true,
            auto_approve: Vec::new(),
            prompt_budget: 32,
            allow_session_grants: true,
            approval_timeout_ms: 30_000,
            limits: SupervisorLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionRequest {
    pub request_id: String,
    pub category: PermissionCategory,
    pub subject: String,
    pub timestamp_unix_ms: u64,
}

pub trait SupervisorClock {
    fn now_unix_ms(&self) -> u64;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    ApproveOnce,
    ApproveSession {
        expires_at_unix_ms: Option<u64>,
        max_uses: Option<u32>,
    },
    ApprovePattern {
        pattern: String,
        expires_at_unix_ms: Option<u64>,
        max_uses: Option<u32>,
    },
    Deny,
    DenyAlways,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct ApprovalHandlerError {
    pub message: String,
}

pub trait ApprovalHandler {
    /// Handler failures are recorded as denied requests and then returned as explicit errors.
    fn approve(
        &mut self,
        request: &PermissionRequest,
        risk: RiskLevel,
        deadline_unix_ms: u64,
    ) -> Result<ApprovalDecision, ApprovalHandlerError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionDecision {
    pub allowed: bool,
    pub reason: String,
    pub risk: RiskLevel,
    pub generation: u64,
    pub state_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionEvent {
    pub timestamp_unix_ms: u64,
    pub category: PermissionCategory,
    pub subject: String,
    pub action: String,
    pub allowed: bool,
    pub generation: u64,
    pub state_hash: String,
}

pub trait PermissionEventSink: Send + Sync {
    fn record(&self, event: &PermissionEvent) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopPermissionEventSink;

impl PermissionEventSink for NoopPermissionEventSink {
    fn record(&self, _event: &PermissionEvent) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AuditPermissionEventSink {
    recorder: AuditRecorder,
}

impl AuditPermissionEventSink {
    #[must_use]
    pub const fn new(recorder: AuditRecorder) -> Self {
        Self { recorder }
    }
}

impl PermissionEventSink for AuditPermissionEventSink {
    fn record(&self, event: &PermissionEvent) -> Result<(), String> {
        let timestamp = event
            .timestamp_unix_ms
            .checked_mul(1_000_000)
            .ok_or_else(|| "permission event timestamp overflows nanoseconds".to_owned())?;
        self.recorder
            .record(
                timestamp,
                AuditCategory::Permission,
                &event.action,
                &event.subject,
                if event.allowed {
                    AuditResult::Allowed
                } else {
                    AuditResult::Denied
                },
                BTreeMap::from([
                    ("category".to_owned(), event.category.as_str().to_owned()),
                    ("generation".to_owned(), event.generation.to_string()),
                    ("state_hash".to_owned(), event.state_hash.clone()),
                ]),
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SupervisorError {
    #[error("invalid supervisor configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid permission request: {0}")]
    InvalidRequest(String),
    #[error("permission request {0} is a replay")]
    Replay(String),
    #[error("approval handler failed: {0}")]
    ApprovalHandler(String),
    #[error("approval decision is invalid: {0}")]
    InvalidDecision(String),
    #[error("permission event sink failed: {0}")]
    EventSink(String),
    #[error("persisted supervisor state exceeds {MAX_PERSISTED_BYTES} bytes")]
    PersistedTooLarge,
    #[error("malformed persisted supervisor state: {0}")]
    Corrupt(String),
    #[error("supervisor state hash mismatch")]
    HashMismatch,
    #[error("checkpoint rejected stale generation {actual}; anchored generation is {anchored}")]
    CheckpointReplay { actual: u64, anchored: u64 },
    #[error("checkpoint detected equivocation at generation {generation}")]
    CheckpointEquivocation { generation: u64 },
    #[error("checkpoint rejected generation jump from {anchored} to {actual}")]
    CheckpointJump { actual: u64, anchored: u64 },
    #[error("checkpoint previous hash does not match the anchored state")]
    CheckpointLink,
    #[error("grant {0} does not exist")]
    UnknownGrant(String),
    #[error("deny rule does not exist")]
    UnknownDenyRule,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactDenyRule {
    pub category: PermissionCategory,
    pub subject: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantMatcher {
    Exact { subject: String },
    Pattern { pattern: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionGrant {
    pub id: String,
    pub category: PermissionCategory,
    pub matcher: GrantMatcher,
    pub expires_at_unix_ms: Option<u64>,
    pub uses_remaining: Option<u32>,
}

impl PermissionGrant {
    fn matches(&self, request: &PermissionRequest, now_unix_ms: u64) -> bool {
        if self.category != request.category
            || self
                .expires_at_unix_ms
                .is_some_and(|expiry| expiry <= now_unix_ms)
            || self.uses_remaining == Some(0)
        {
            return false;
        }
        match &self.matcher {
            GrantMatcher::Exact { subject } => subject == &request.subject,
            GrantMatcher::Pattern { pattern } => glob_matches(pattern, &request.subject),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum HistoryKind {
    AllowedGrant,
    AllowedAuto,
    AllowedApproval,
    DeniedRule,
    DeniedNoninteractive,
    DeniedBudget,
    DeniedNoHandler,
    DeniedApproval,
    DeniedTimeout,
    HandlerError,
    GrantRevoked,
    GrantsRevokedAll,
    DenyAdded,
    DenyRevoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoryEntry {
    generation: u64,
    previous_state_hash: String,
    timestamp_unix_ms: u64,
    kind: HistoryKind,
    request_id: Option<String>,
    category: Option<PermissionCategory>,
    subject: Option<String>,
    detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    format: String,
    version: u16,
    session_id: String,
    generation: u64,
    previous_state_hash: String,
    state_hash: String,
    config: SupervisorConfig,
    grants: BTreeMap<String, PermissionGrant>,
    deny_rules: BTreeSet<ExactDenyRule>,
    auto_use_counters: BTreeMap<u32, u32>,
    request_ids: BTreeSet<String>,
    prompts_used: u32,
    history: Vec<HistoryEntry>,
}

#[derive(Serialize)]
struct StateHashPayload<'a> {
    format: &'a str,
    version: u16,
    session_id: &'a str,
    generation: u64,
    previous_state_hash: &'a str,
    config: &'a SupervisorConfig,
    grants: &'a BTreeMap<String, PermissionGrant>,
    deny_rules: &'a BTreeSet<ExactDenyRule>,
    auto_use_counters: &'a BTreeMap<u32, u32>,
    request_ids: &'a BTreeSet<String>,
    prompts_used: u32,
    history: &'a [HistoryEntry],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorCheckpoint {
    /// Persist this checkpoint in the lifecycle audit log to anchor the imported state.
    pub generation: u64,
    pub state_hash: String,
}

pub struct PermissionSupervisor {
    session_id: SessionId,
    state: PersistedState,
    sink: Arc<dyn PermissionEventSink>,
}

impl fmt::Debug for PermissionSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionSupervisor")
            .field("session_id", &self.session_id)
            .field("generation", &self.state.generation)
            .field("state_hash", &self.state.state_hash)
            .finish_non_exhaustive()
    }
}

impl PermissionSupervisor {
    pub fn new(
        session_id: SessionId,
        config: SupervisorConfig,
        sink: Arc<dyn PermissionEventSink>,
    ) -> Result<Self, SupervisorError> {
        validate_config(&config)?;
        let mut state = PersistedState {
            format: SUPERVISOR_FORMAT.to_owned(),
            version: SUPERVISOR_VERSION,
            session_id: session_id.to_string(),
            generation: 0,
            previous_state_hash: ZERO_HASH.to_owned(),
            state_hash: String::new(),
            config,
            grants: BTreeMap::new(),
            deny_rules: BTreeSet::new(),
            auto_use_counters: BTreeMap::new(),
            request_ids: BTreeSet::new(),
            prompts_used: 0,
            history: Vec::new(),
        };
        state.state_hash = compute_state_hash(&state)?;
        Ok(Self {
            session_id,
            state,
            sink,
        })
    }

    #[must_use]
    pub fn checkpoint(&self) -> SupervisorCheckpoint {
        SupervisorCheckpoint {
            generation: self.state.generation,
            state_hash: self.state.state_hash.clone(),
        }
    }

    #[must_use]
    pub fn grants(&self) -> &BTreeMap<String, PermissionGrant> {
        &self.state.grants
    }

    #[must_use]
    pub fn deny_rules(&self) -> &BTreeSet<ExactDenyRule> {
        &self.state.deny_rules
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn evaluate(
        &mut self,
        request: PermissionRequest,
        clock: &dyn SupervisorClock,
        mut handler: Option<&mut dyn ApprovalHandler>,
    ) -> Result<PermissionDecision, SupervisorError> {
        validate_request(&request, &self.state.config.limits)?;
        if self.state.request_ids.contains(&request.request_id) {
            return Err(SupervisorError::Replay(request.request_id));
        }
        let risk = classify_risk(request.category, &request.subject);
        let now = clock.now_unix_ms();

        if self.state.deny_rules.contains(&ExactDenyRule {
            category: request.category,
            subject: request.subject.clone(),
        }) {
            return self.record_request_decision(
                &request,
                risk,
                false,
                "exact_deny_rule",
                HistoryKind::DeniedRule,
                now,
                |_| Ok(()),
            );
        }

        if let Some(grant_id) = self
            .state
            .grants
            .iter()
            .find_map(|(id, grant)| grant.matches(&request, now).then(|| id.clone()))
        {
            return self.record_request_decision(
                &request,
                risk,
                true,
                &format!("grant:{grant_id}"),
                HistoryKind::AllowedGrant,
                now,
                move |state| {
                    let grant = state
                        .grants
                        .get_mut(&grant_id)
                        .ok_or_else(|| SupervisorError::UnknownGrant(grant_id.clone()))?;
                    match grant.uses_remaining {
                        Some(1) => {
                            state.grants.remove(&grant_id);
                        }
                        Some(remaining) => grant.uses_remaining = Some(remaining - 1),
                        None => {}
                    }
                    Ok(())
                },
            );
        }

        if let Some((index, _)) =
            self.state
                .config
                .auto_approve
                .iter()
                .enumerate()
                .find(|(index, rule)| {
                    let used = self
                        .state
                        .auto_use_counters
                        .get(&u32::try_from(*index).unwrap_or(u32::MAX))
                        .copied()
                        .unwrap_or(0);
                    rule.matcher.category == request.category
                        && glob_matches(&rule.matcher.pattern, &request.subject)
                        && rule.max_uses.is_none_or(|maximum| used < maximum)
                })
        {
            let index = u32::try_from(index)
                .map_err(|_| SupervisorError::InvalidConfig("too many auto rules".to_owned()))?;
            return self.record_request_decision(
                &request,
                risk,
                true,
                &format!("auto_rule:{index}"),
                HistoryKind::AllowedAuto,
                now,
                move |state| {
                    let used = state.auto_use_counters.entry(index).or_default();
                    *used = used.checked_add(1).ok_or_else(|| {
                        SupervisorError::Corrupt("auto-use counter overflow".to_owned())
                    })?;
                    Ok(())
                },
            );
        }

        if !self.state.config.interactive {
            return self.record_request_decision(
                &request,
                risk,
                false,
                "noninteractive",
                HistoryKind::DeniedNoninteractive,
                now,
                |_| Ok(()),
            );
        }
        if self.state.prompts_used >= self.state.config.prompt_budget {
            return self.record_request_decision(
                &request,
                risk,
                false,
                "prompt_budget_exhausted",
                HistoryKind::DeniedBudget,
                now,
                |_| Ok(()),
            );
        }
        let Some(approval_handler) = handler.as_mut() else {
            return self.record_request_decision(
                &request,
                risk,
                false,
                "no_approval_handler",
                HistoryKind::DeniedNoHandler,
                now,
                |_| Ok(()),
            );
        };
        let deadline = now
            .checked_add(self.state.config.approval_timeout_ms)
            .ok_or_else(|| {
                SupervisorError::InvalidConfig("approval deadline overflow".to_owned())
            })?;
        let handler_result = approval_handler.approve(&request, risk, deadline);
        let after = clock.now_unix_ms();

        let decision = match handler_result {
            Ok(decision) if after <= deadline => decision,
            Ok(_) => {
                return self.record_request_decision(
                    &request,
                    risk,
                    false,
                    "approval_timeout",
                    HistoryKind::DeniedTimeout,
                    after,
                    |state| {
                        state.prompts_used += 1;
                        Ok(())
                    },
                );
            }
            Err(error) => {
                self.record_request_decision(
                    &request,
                    risk,
                    false,
                    "approval_handler_error",
                    HistoryKind::HandlerError,
                    after,
                    |state| {
                        state.prompts_used += 1;
                        Ok(())
                    },
                )?;
                return Err(SupervisorError::ApprovalHandler(error.message));
            }
        };

        self.apply_approval_decision(request, risk, decision, after)
    }

    pub fn add_exact_deny(
        &mut self,
        category: PermissionCategory,
        subject: String,
        timestamp_unix_ms: u64,
    ) -> Result<SupervisorCheckpoint, SupervisorError> {
        validate_subject(&subject, &self.state.config.limits)?;
        if self.state.deny_rules.len() >= self.state.config.limits.max_deny_rules {
            return Err(SupervisorError::InvalidConfig(
                "deny-rule limit reached".to_owned(),
            ));
        }
        let rule = ExactDenyRule {
            category,
            subject: subject.clone(),
        };
        let mut next = self.state.clone();
        next.deny_rules.insert(rule);
        self.commit(
            next,
            HistoryDraft {
                timestamp_unix_ms,
                kind: HistoryKind::DenyAdded,
                request_id: None,
                category: Some(category),
                subject: Some(subject.clone()),
                detail: "manual_exact_deny".to_owned(),
            },
            PermissionEvent {
                timestamp_unix_ms,
                category,
                subject,
                action: "deny_added".to_owned(),
                allowed: false,
                generation: 0,
                state_hash: String::new(),
            },
        )?;
        Ok(self.checkpoint())
    }

    pub fn revoke_exact_deny(
        &mut self,
        category: PermissionCategory,
        subject: &str,
        timestamp_unix_ms: u64,
    ) -> Result<SupervisorCheckpoint, SupervisorError> {
        let rule = ExactDenyRule {
            category,
            subject: subject.to_owned(),
        };
        if !self.state.deny_rules.contains(&rule) {
            return Err(SupervisorError::UnknownDenyRule);
        }
        let mut next = self.state.clone();
        next.deny_rules.remove(&rule);
        self.commit(
            next,
            HistoryDraft {
                timestamp_unix_ms,
                kind: HistoryKind::DenyRevoked,
                request_id: None,
                category: Some(category),
                subject: Some(subject.to_owned()),
                detail: "manual_exact_deny_revoked".to_owned(),
            },
            PermissionEvent {
                timestamp_unix_ms,
                category,
                subject: subject.to_owned(),
                action: "deny_revoked".to_owned(),
                allowed: false,
                generation: 0,
                state_hash: String::new(),
            },
        )?;
        Ok(self.checkpoint())
    }

    pub fn revoke_grant(
        &mut self,
        grant_id: &str,
        timestamp_unix_ms: u64,
    ) -> Result<SupervisorCheckpoint, SupervisorError> {
        let grant = self
            .state
            .grants
            .get(grant_id)
            .cloned()
            .ok_or_else(|| SupervisorError::UnknownGrant(grant_id.to_owned()))?;
        let mut next = self.state.clone();
        next.grants.remove(grant_id);
        let subject = match grant.matcher {
            GrantMatcher::Exact { subject } => subject,
            GrantMatcher::Pattern { pattern } => pattern,
        };
        self.commit(
            next,
            HistoryDraft {
                timestamp_unix_ms,
                kind: HistoryKind::GrantRevoked,
                request_id: None,
                category: Some(grant.category),
                subject: Some(subject.clone()),
                detail: grant_id.to_owned(),
            },
            PermissionEvent {
                timestamp_unix_ms,
                category: grant.category,
                subject,
                action: "grant_revoked".to_owned(),
                allowed: false,
                generation: 0,
                state_hash: String::new(),
            },
        )?;
        Ok(self.checkpoint())
    }

    pub fn revoke_all_grants(
        &mut self,
        timestamp_unix_ms: u64,
    ) -> Result<SupervisorCheckpoint, SupervisorError> {
        let removed = self.state.grants.len();
        let mut next = self.state.clone();
        next.grants.clear();
        self.commit(
            next,
            HistoryDraft {
                timestamp_unix_ms,
                kind: HistoryKind::GrantsRevokedAll,
                request_id: None,
                category: None,
                subject: None,
                detail: removed.to_string(),
            },
            PermissionEvent {
                timestamp_unix_ms,
                category: PermissionCategory::SystemCall,
                subject: "all_grants".to_owned(),
                action: "grants_revoked_all".to_owned(),
                allowed: false,
                generation: 0,
                state_hash: String::new(),
            },
        )?;
        Ok(self.checkpoint())
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, SupervisorError> {
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
        if bytes.len() > MAX_PERSISTED_BYTES {
            return Err(SupervisorError::PersistedTooLarge);
        }
        Ok(bytes)
    }

    /// Import without an external anchor. Use only for the first trusted import.
    pub fn decode_unanchored_first_import(
        bytes: &[u8],
        sink: Arc<dyn PermissionEventSink>,
    ) -> Result<Self, SupervisorError> {
        decode_state(bytes, sink)
    }

    pub fn decode_with_checkpoint(
        bytes: &[u8],
        checkpoint: &SupervisorCheckpoint,
        sink: Arc<dyn PermissionEventSink>,
    ) -> Result<Self, SupervisorError> {
        validate_hash(&checkpoint.state_hash)?;
        let supervisor = decode_state(bytes, sink)?;
        let actual = supervisor.state.generation;
        if actual < checkpoint.generation {
            return Err(SupervisorError::CheckpointReplay {
                actual,
                anchored: checkpoint.generation,
            });
        }
        if actual == checkpoint.generation {
            if supervisor.state.state_hash != checkpoint.state_hash {
                return Err(SupervisorError::CheckpointEquivocation { generation: actual });
            }
            return Ok(supervisor);
        }
        if actual != checkpoint.generation.saturating_add(1) {
            return Err(SupervisorError::CheckpointJump {
                actual,
                anchored: checkpoint.generation,
            });
        }
        if supervisor.state.previous_state_hash != checkpoint.state_hash {
            return Err(SupervisorError::CheckpointLink);
        }
        Ok(supervisor)
    }

    fn apply_approval_decision(
        &mut self,
        request: PermissionRequest,
        risk: RiskLevel,
        decision: ApprovalDecision,
        timestamp_unix_ms: u64,
    ) -> Result<PermissionDecision, SupervisorError> {
        match decision {
            ApprovalDecision::ApproveOnce => self.record_request_decision(
                &request,
                risk,
                true,
                "approval_once",
                HistoryKind::AllowedApproval,
                timestamp_unix_ms,
                |state| {
                    state.prompts_used += 1;
                    Ok(())
                },
            ),
            ApprovalDecision::ApproveSession {
                expires_at_unix_ms,
                max_uses,
            } => {
                if !self.state.config.allow_session_grants {
                    return self.record_request_decision(
                        &request,
                        risk,
                        false,
                        "session_grants_disabled",
                        HistoryKind::DeniedApproval,
                        timestamp_unix_ms,
                        |state| {
                            state.prompts_used += 1;
                            Ok(())
                        },
                    );
                }
                validate_grant_limits(max_uses, expires_at_unix_ms, timestamp_unix_ms)?;
                let grant_id = format!("grant-{}", self.state.generation.saturating_add(1));
                let category = request.category;
                let subject = request.subject.clone();
                self.record_request_decision(
                    &request,
                    risk,
                    true,
                    "approval_session",
                    HistoryKind::AllowedApproval,
                    timestamp_unix_ms,
                    move |state| {
                        state.prompts_used += 1;
                        state.grants.retain(|_, grant| {
                            grant
                                .expires_at_unix_ms
                                .is_none_or(|expiry| expiry > timestamp_unix_ms)
                        });
                        insert_grant(
                            state,
                            PermissionGrant {
                                id: grant_id.clone(),
                                category,
                                matcher: GrantMatcher::Exact {
                                    subject: subject.clone(),
                                },
                                expires_at_unix_ms,
                                uses_remaining: current_consumed_uses(max_uses),
                            },
                        )
                    },
                )
            }
            ApprovalDecision::ApprovePattern {
                pattern,
                expires_at_unix_ms,
                max_uses,
            } => {
                if !self.state.config.allow_session_grants {
                    return self.record_request_decision(
                        &request,
                        risk,
                        false,
                        "session_grants_disabled",
                        HistoryKind::DeniedApproval,
                        timestamp_unix_ms,
                        |state| {
                            state.prompts_used += 1;
                            Ok(())
                        },
                    );
                }
                validate_pattern(&pattern, &self.state.config.limits)?;
                validate_grant_limits(max_uses, expires_at_unix_ms, timestamp_unix_ms)?;
                if !glob_matches(&pattern, &request.subject) {
                    self.record_request_decision(
                        &request,
                        risk,
                        false,
                        "approval_pattern_does_not_match_request",
                        HistoryKind::DeniedApproval,
                        timestamp_unix_ms,
                        |state| {
                            state.prompts_used += 1;
                            Ok(())
                        },
                    )?;
                    return Err(SupervisorError::InvalidDecision(
                        "approved pattern does not match the current request".to_owned(),
                    ));
                }
                let grant_id = format!("grant-{}", self.state.generation.saturating_add(1));
                self.record_request_decision(
                    &request,
                    risk,
                    true,
                    "approval_pattern",
                    HistoryKind::AllowedApproval,
                    timestamp_unix_ms,
                    move |state| {
                        state.prompts_used += 1;
                        state.grants.retain(|_, grant| {
                            grant
                                .expires_at_unix_ms
                                .is_none_or(|expiry| expiry > timestamp_unix_ms)
                        });
                        insert_grant(
                            state,
                            PermissionGrant {
                                id: grant_id.clone(),
                                category: request.category,
                                matcher: GrantMatcher::Pattern {
                                    pattern: pattern.clone(),
                                },
                                expires_at_unix_ms,
                                uses_remaining: current_consumed_uses(max_uses),
                            },
                        )
                    },
                )
            }
            ApprovalDecision::Deny => self.record_request_decision(
                &request,
                risk,
                false,
                "approval_denied",
                HistoryKind::DeniedApproval,
                timestamp_unix_ms,
                |state| {
                    state.prompts_used += 1;
                    Ok(())
                },
            ),
            ApprovalDecision::DenyAlways => {
                if self.state.deny_rules.len() >= self.state.config.limits.max_deny_rules {
                    return Err(SupervisorError::InvalidDecision(
                        "deny-rule limit reached".to_owned(),
                    ));
                }
                self.record_request_decision(
                    &request,
                    risk,
                    false,
                    "approval_deny_always",
                    HistoryKind::DeniedApproval,
                    timestamp_unix_ms,
                    |state| {
                        state.prompts_used += 1;
                        state.deny_rules.insert(ExactDenyRule {
                            category: request.category,
                            subject: request.subject.clone(),
                        });
                        Ok(())
                    },
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_request_decision<F>(
        &mut self,
        request: &PermissionRequest,
        risk: RiskLevel,
        allowed: bool,
        reason: &str,
        kind: HistoryKind,
        timestamp_unix_ms: u64,
        mutate: F,
    ) -> Result<PermissionDecision, SupervisorError>
    where
        F: FnOnce(&mut PersistedState) -> Result<(), SupervisorError>,
    {
        if self.state.request_ids.len() >= self.state.config.limits.max_request_ids {
            return Err(SupervisorError::InvalidConfig(
                "request replay-set limit reached".to_owned(),
            ));
        }
        let mut next = self.state.clone();
        mutate(&mut next)?;
        next.request_ids.insert(request.request_id.clone());
        self.commit(
            next,
            HistoryDraft {
                timestamp_unix_ms,
                kind,
                request_id: Some(request.request_id.clone()),
                category: Some(request.category),
                subject: Some(request.subject.clone()),
                detail: reason.to_owned(),
            },
            PermissionEvent {
                timestamp_unix_ms: request.timestamp_unix_ms,
                category: request.category,
                subject: request.subject.clone(),
                action: reason.to_owned(),
                allowed,
                generation: 0,
                state_hash: String::new(),
            },
        )?;
        Ok(PermissionDecision {
            allowed,
            reason: reason.to_owned(),
            risk,
            generation: self.state.generation,
            state_hash: self.state.state_hash.clone(),
        })
    }

    fn commit(
        &mut self,
        mut next: PersistedState,
        history: HistoryDraft,
        mut event: PermissionEvent,
    ) -> Result<(), SupervisorError> {
        if next.history.len() >= next.config.limits.max_history {
            return Err(SupervisorError::InvalidConfig(
                "history limit reached".to_owned(),
            ));
        }
        let previous = self.state.state_hash.clone();
        next.generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or_else(|| SupervisorError::Corrupt("generation overflow".to_owned()))?;
        next.previous_state_hash = previous.clone();
        next.history.push(HistoryEntry {
            generation: next.generation,
            previous_state_hash: previous,
            timestamp_unix_ms: history.timestamp_unix_ms,
            kind: history.kind,
            request_id: history.request_id,
            category: history.category,
            subject: history.subject,
            detail: history.detail,
        });
        next.state_hash = compute_state_hash(&next)?;
        validate_state(&next)?;
        event.generation = next.generation;
        event.state_hash.clone_from(&next.state_hash);
        self.sink
            .record(&event)
            .map_err(SupervisorError::EventSink)?;
        self.state = next;
        Ok(())
    }
}

struct HistoryDraft {
    timestamp_unix_ms: u64,
    kind: HistoryKind,
    request_id: Option<String>,
    category: Option<PermissionCategory>,
    subject: Option<String>,
    detail: String,
}

fn insert_grant(state: &mut PersistedState, grant: PermissionGrant) -> Result<(), SupervisorError> {
    if grant.uses_remaining == Some(0) {
        return Ok(());
    }
    if state.grants.len() >= state.config.limits.max_grants {
        return Err(SupervisorError::InvalidDecision(
            "grant limit reached".to_owned(),
        ));
    }
    state.grants.insert(grant.id.clone(), grant);
    Ok(())
}

const fn current_consumed_uses(max_uses: Option<u32>) -> Option<u32> {
    match max_uses {
        Some(uses) => Some(uses - 1),
        None => None,
    }
}

fn validate_grant_limits(
    max_uses: Option<u32>,
    expiry: Option<u64>,
    now: u64,
) -> Result<(), SupervisorError> {
    if max_uses == Some(0) {
        return Err(SupervisorError::InvalidDecision(
            "grant max_uses must be positive".to_owned(),
        ));
    }
    if expiry.is_some_and(|value| value <= now) {
        return Err(SupervisorError::InvalidDecision(
            "grant expiry must be in the future".to_owned(),
        ));
    }
    Ok(())
}

fn validate_config(config: &SupervisorConfig) -> Result<(), SupervisorError> {
    let limits = &config.limits;
    if limits.max_grants == 0
        || limits.max_grants > HARD_MAX_RULES
        || limits.max_deny_rules == 0
        || limits.max_deny_rules > HARD_MAX_RULES
        || limits.max_history == 0
        || limits.max_history > HARD_MAX_HISTORY
        || limits.max_request_ids == 0
        || limits.max_request_ids > HARD_MAX_REQUEST_IDS
        || limits.max_pattern_bytes == 0
        || limits.max_pattern_bytes > HARD_MAX_PATTERN_BYTES
        || limits.max_subject_bytes == 0
        || limits.max_subject_bytes > HARD_MAX_SUBJECT_BYTES
        || config.prompt_budget > HARD_MAX_PROMPTS
        || config.approval_timeout_ms == 0
        || config.approval_timeout_ms > HARD_MAX_TIMEOUT_MS
        || config.auto_approve.len() > limits.max_grants
    {
        return Err(SupervisorError::InvalidConfig(
            "one or more bounded limits are invalid".to_owned(),
        ));
    }
    for rule in &config.auto_approve {
        validate_pattern(&rule.matcher.pattern, limits)?;
        if rule.max_uses == Some(0) {
            return Err(SupervisorError::InvalidConfig(
                "auto-approve max_uses must be positive".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_request(
    request: &PermissionRequest,
    limits: &SupervisorLimits,
) -> Result<(), SupervisorError> {
    validate_id(&request.request_id).map_err(SupervisorError::InvalidRequest)?;
    validate_subject(&request.subject, limits)
}

fn validate_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > HARD_MAX_ID_BYTES || value.chars().any(char::is_control) {
        return Err("identifier is empty, too long, or contains control characters".to_owned());
    }
    Ok(())
}

fn validate_subject(subject: &str, limits: &SupervisorLimits) -> Result<(), SupervisorError> {
    if subject.is_empty()
        || subject.len() > limits.max_subject_bytes
        || subject.chars().any(char::is_control)
    {
        return Err(SupervisorError::InvalidRequest(
            "subject is empty, too long, or contains control characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_pattern(pattern: &str, limits: &SupervisorLimits) -> Result<(), SupervisorError> {
    if pattern.is_empty()
        || pattern.len() > limits.max_pattern_bytes
        || pattern.chars().any(char::is_control)
    {
        return Err(SupervisorError::InvalidConfig(
            "pattern is empty, too long, or contains control characters".to_owned(),
        ));
    }
    Ok(())
}

fn compute_state_hash(state: &PersistedState) -> Result<String, SupervisorError> {
    let payload = StateHashPayload {
        format: &state.format,
        version: state.version,
        session_id: &state.session_id,
        generation: state.generation,
        previous_state_hash: &state.previous_state_hash,
        config: &state.config,
        grants: &state.grants,
        deny_rules: &state.deny_rules,
        auto_use_counters: &state.auto_use_counters,
        request_ids: &state.request_ids,
        prompts_used: state.prompts_used,
        history: &state.history,
    };
    let encoded = serde_json::to_vec(&payload)
        .map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(STATE_HASH_DOMAIN);
    hasher.update(encoded);
    Ok(hex_encode(&hasher.finalize()))
}

fn decode_state(
    bytes: &[u8],
    sink: Arc<dyn PermissionEventSink>,
) -> Result<PermissionSupervisor, SupervisorError> {
    if bytes.len() > MAX_PERSISTED_BYTES {
        return Err(SupervisorError::PersistedTooLarge);
    }
    let state: PersistedState = serde_json::from_slice(bytes)
        .map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
    let canonical =
        serde_json::to_vec(&state).map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
    if canonical != bytes {
        return Err(SupervisorError::Corrupt(
            "input is not canonical JSON".to_owned(),
        ));
    }
    validate_state(&state)?;
    if compute_state_hash(&state)? != state.state_hash {
        return Err(SupervisorError::HashMismatch);
    }
    let session_id = decode_session_id(&state.session_id)?;
    Ok(PermissionSupervisor {
        session_id,
        state,
        sink,
    })
}

fn validate_state(state: &PersistedState) -> Result<(), SupervisorError> {
    if state.format != SUPERVISOR_FORMAT || state.version != SUPERVISOR_VERSION {
        return Err(SupervisorError::Corrupt(
            "unsupported format or version".to_owned(),
        ));
    }
    validate_config(&state.config)?;
    validate_hash(&state.previous_state_hash)?;
    validate_hash(&state.state_hash)?;
    if state.generation == 0 {
        if state.previous_state_hash != ZERO_HASH || !state.history.is_empty() {
            return Err(SupervisorError::Corrupt(
                "generation zero has an invalid link or history".to_owned(),
            ));
        }
    } else if state.previous_state_hash == ZERO_HASH {
        return Err(SupervisorError::Corrupt(
            "nonzero generation links to the zero hash".to_owned(),
        ));
    }
    if state.history.len() != usize::try_from(state.generation).unwrap_or(usize::MAX)
        || state.history.len() > state.config.limits.max_history
        || state.grants.len() > state.config.limits.max_grants
        || state.deny_rules.len() > state.config.limits.max_deny_rules
        || state.request_ids.len() > state.config.limits.max_request_ids
        || state.prompts_used > state.config.prompt_budget
        || state.auto_use_counters.len() > state.config.auto_approve.len()
    {
        return Err(SupervisorError::Corrupt(
            "persisted collection count exceeds limits".to_owned(),
        ));
    }
    let mut history_request_ids = BTreeSet::new();
    let mut history_prompts = 0_u32;
    for (index, history) in state.history.iter().enumerate() {
        if history.generation != (index as u64) + 1 {
            return Err(SupervisorError::Corrupt(
                "history generations are not contiguous".to_owned(),
            ));
        }
        validate_hash(&history.previous_state_hash)?;
        if history.previous_state_hash == ZERO_HASH {
            return Err(SupervisorError::Corrupt(
                "history links to the zero hash".to_owned(),
            ));
        }
        if index + 1 == state.history.len()
            && history.previous_state_hash != state.previous_state_hash
        {
            return Err(SupervisorError::Corrupt(
                "latest history link does not match state link".to_owned(),
            ));
        }
        if let Some(request_id) = &history.request_id {
            validate_id(request_id).map_err(SupervisorError::Corrupt)?;
            history_request_ids.insert(request_id.clone());
        }
        if let Some(subject) = &history.subject {
            validate_subject(subject, &state.config.limits)
                .map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
        }
        if history.detail.len() > HARD_MAX_PATTERN_BYTES
            || history.detail.chars().any(char::is_control)
        {
            return Err(SupervisorError::Corrupt(
                "history detail is invalid".to_owned(),
            ));
        }
        if matches!(
            history.kind,
            HistoryKind::AllowedApproval
                | HistoryKind::DeniedApproval
                | HistoryKind::DeniedTimeout
                | HistoryKind::HandlerError
        ) {
            history_prompts = history_prompts
                .checked_add(1)
                .ok_or_else(|| SupervisorError::Corrupt("prompt count overflow".to_owned()))?;
        }
    }
    if history_request_ids != state.request_ids || history_prompts != state.prompts_used {
        return Err(SupervisorError::Corrupt(
            "replay set or prompt count does not match history".to_owned(),
        ));
    }
    for request_id in &state.request_ids {
        validate_id(request_id).map_err(SupervisorError::Corrupt)?;
    }
    for deny in &state.deny_rules {
        validate_subject(&deny.subject, &state.config.limits)
            .map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
    }
    for (id, grant) in &state.grants {
        validate_id(id).map_err(SupervisorError::Corrupt)?;
        if &grant.id != id || grant.uses_remaining == Some(0) {
            return Err(SupervisorError::Corrupt(
                "grant key, identifier, or use count is invalid".to_owned(),
            ));
        }
        match &grant.matcher {
            GrantMatcher::Exact { subject } => {
                validate_subject(subject, &state.config.limits)
                    .map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
            }
            GrantMatcher::Pattern { pattern } => {
                validate_pattern(pattern, &state.config.limits)
                    .map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
            }
        }
    }
    for (index, used) in &state.auto_use_counters {
        let rule = state
            .config
            .auto_approve
            .get(*index as usize)
            .ok_or_else(|| SupervisorError::Corrupt("unknown auto-rule counter".to_owned()))?;
        if *used == 0 || rule.max_uses.is_some_and(|maximum| *used > maximum) {
            return Err(SupervisorError::Corrupt(
                "auto-rule use counter is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_hash(value: &str) -> Result<(), SupervisorError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SupervisorError::Corrupt(
            "hash is not lowercase 64-character hexadecimal".to_owned(),
        ));
    }
    Ok(())
}

fn decode_session_id(value: &str) -> Result<SessionId, SupervisorError> {
    if value.len() != 32 {
        return Err(SupervisorError::Corrupt(
            "session ID is not 32-character hexadecimal".to_owned(),
        ));
    }
    let mut bytes = [0_u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
        bytes[index] = u8::from_str_radix(text, 16)
            .map_err(|error| SupervisorError::Corrupt(error.to_string()))?;
    }
    let session_id = SessionId::from_bytes(bytes);
    if session_id.to_string() != value {
        return Err(SupervisorError::Corrupt(
            "session ID is not canonical lowercase hexadecimal".to_owned(),
        ));
    }
    Ok(session_id)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Swift-compatible `*` (zero or more characters) and `?` (one character) matching.
#[must_use]
pub fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let value = value.chars().collect::<Vec<_>>();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut current = vec![false; value.len() + 1];
        if token == '*' {
            current[0] = previous[0];
        }
        for index in 1..=value.len() {
            current[index] = match token {
                '*' => previous[index] || current[index - 1],
                '?' => previous[index - 1],
                literal => previous[index - 1] && literal == value[index - 1],
            };
        }
        previous = current;
    }
    previous[value.len()]
}
