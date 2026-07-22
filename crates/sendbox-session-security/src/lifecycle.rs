//! Deterministic session lifecycle orchestration.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use sendbox_core::SessionId;
use sendbox_secrets::{CredentialPolicy, EnvelopeBinding, EnvelopeCipher, SecretStore};
use sendbox_security::audit::{
    AUDIT_FORMAT_VERSION, AuditCategory, AuditLog, AuditRecord, AuditResult,
};
use sendbox_security::provenance::{
    DetachedSignature, SubjectKind, TrustStore, VerificationResult,
};
use sendbox_security::snapshot::{SnapshotDiff, SnapshotManifest};
use thiserror::Error;

use crate::supervisor::SupervisorCheckpoint;

/// Errors from lifecycle hooks are intentionally reduced to an adapter-neutral stage and message.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionSecurityError {
    #[error("{stage} failed: {message}")]
    Operation {
        stage: &'static str,
        message: String,
    },
    #[error("invalid lifecycle state: expected {expected}, found {actual}")]
    InvalidState {
        expected: &'static str,
        actual: &'static str,
    },
    #[error("{stage} failed: {primary}; rollback: {rollback:?}; cleanup: {cleanup:?}")]
    FailureAggregate {
        stage: &'static str,
        primary: String,
        rollback: Option<String>,
        cleanup: Option<String>,
    },
}

pub type SessionSecurityResult<T> = Result<T, SessionSecurityError>;

fn operation(stage: &'static str, error: impl fmt::Display) -> SessionSecurityError {
    SessionSecurityError::Operation {
        stage,
        message: error.to_string(),
    }
}

/// Caller-injected deterministic time source.
pub trait LifecycleClock: Send + Sync {
    fn now_unix_nanos(&self) -> u64;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceDocument {
    pub content: Vec<u8>,
    pub kind: SubjectKind,
    pub signatures: Vec<DetachedSignature>,
    pub now_unix: u64,
}

pub trait ProvenanceVerifier: Send + Sync {
    fn verify_policy(
        &self,
        document: &ProvenanceDocument,
    ) -> SessionSecurityResult<VerificationResult>;
    fn verify_config(
        &self,
        document: &ProvenanceDocument,
    ) -> SessionSecurityResult<VerificationResult>;
}

pub struct TrustStoreProvenanceVerifier<'a> {
    policy_trust: &'a TrustStore,
    config_trust: &'a TrustStore,
}

impl<'a> TrustStoreProvenanceVerifier<'a> {
    #[must_use]
    pub const fn new(policy_trust: &'a TrustStore, config_trust: &'a TrustStore) -> Self {
        Self {
            policy_trust,
            config_trust,
        }
    }
}

impl ProvenanceVerifier for TrustStoreProvenanceVerifier<'_> {
    fn verify_policy(
        &self,
        document: &ProvenanceDocument,
    ) -> SessionSecurityResult<VerificationResult> {
        verify_document(self.policy_trust, document, "policy_provenance")
    }

    fn verify_config(
        &self,
        document: &ProvenanceDocument,
    ) -> SessionSecurityResult<VerificationResult> {
        verify_document(self.config_trust, document, "config_provenance")
    }
}

pub trait SnapshotController: Send + Sync {
    fn capture_before(&self, session_id: SessionId) -> SessionSecurityResult<SnapshotManifest>;
    fn capture_after(&self, session_id: SessionId) -> SessionSecurityResult<SnapshotManifest>;
    fn diff(
        &self,
        before: &SnapshotManifest,
        after: &SnapshotManifest,
    ) -> SessionSecurityResult<SnapshotDiff>;
    fn rollback(&self, before: &SnapshotManifest) -> SessionSecurityResult<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedCredentialRules {
    pub rule_count: usize,
    pub preparation_id: String,
}

pub trait CredentialRulePreparer: Send + Sync {
    fn prepare(
        &self,
        policies: &[CredentialPolicy],
    ) -> SessionSecurityResult<PreparedCredentialRules>;
}

/// Host adapters may bind a bounded listener later. This hook never opens sockets itself.
pub trait CredentialListener: Send + Sync {
    fn ready(
        &self,
        prepared: &PreparedCredentialRules,
        maximum_requests: u32,
    ) -> SessionSecurityResult<()>;
}

pub trait PermissionSupervisorReady: Send + Sync {
    fn ready(
        &self,
        session_id: SessionId,
        audit: AuditRecorder,
    ) -> SessionSecurityResult<SupervisorCheckpoint>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPublication {
    pub signature: Option<String>,
}

pub trait AuditPublicationHook: Send + Sync {
    fn publish(
        &self,
        session_id: SessionId,
        merkle_root: &str,
        head_hash: &str,
    ) -> SessionSecurityResult<AuditPublication>;
}

pub trait CleanupHook: Send + Sync {
    fn cleanup(&self, session_id: SessionId) -> SessionSecurityResult<()>;
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreparedSecretEnvelope {
    pub secret_name: String,
    pub sequence: u64,
    pub expires_at_unix_ms: u64,
    encoded: Vec<u8>,
}

impl PreparedSecretEnvelope {
    #[must_use]
    pub fn from_encoded(binding: &EnvelopeBinding, encoded: Vec<u8>) -> Self {
        Self {
            secret_name: binding.secret_name.as_str().to_owned(),
            sequence: binding.sequence,
            expires_at_unix_ms: binding.expires_at_unix_ms,
            encoded,
        }
    }

    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

impl fmt::Debug for PreparedSecretEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSecretEnvelope")
            .field("secret_name", &self.secret_name)
            .field("sequence", &self.sequence)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretEnvelopeRequest {
    pub binding: EnvelopeBinding,
}

pub trait SecretEnvelopeProducer: Send + Sync {
    fn prepare(
        &self,
        request: &SecretEnvelopeRequest,
    ) -> SessionSecurityResult<PreparedSecretEnvelope>;
}

/// Default envelope producer that verifies both existence and retrieval before sealing.
pub struct StoreEnvelopeProducer<'a> {
    store: &'a dyn SecretStore,
    cipher: Mutex<EnvelopeCipher>,
}

impl<'a> StoreEnvelopeProducer<'a> {
    #[must_use]
    pub fn new(store: &'a dyn SecretStore, cipher: EnvelopeCipher) -> Self {
        Self {
            store,
            cipher: Mutex::new(cipher),
        }
    }
}

impl SecretEnvelopeProducer for StoreEnvelopeProducer<'_> {
    fn prepare(
        &self,
        request: &SecretEnvelopeRequest,
    ) -> SessionSecurityResult<PreparedSecretEnvelope> {
        let name = &request.binding.secret_name;
        let exists = self
            .store
            .exists(name)
            .map_err(|error| operation("secret_exists", error))?;
        if !exists {
            return Err(SessionSecurityError::Operation {
                stage: "secret_exists",
                message: format!("secret reference {name} does not exist"),
            });
        }
        let secret = self
            .store
            .retrieve(name)
            .map_err(|error| operation("secret_retrieve", error))?;
        if secret.metadata.name != *name {
            return Err(SessionSecurityError::Operation {
                stage: "secret_retrieve",
                message: "secret store returned mismatched metadata".to_owned(),
            });
        }
        let mut cipher = self
            .cipher
            .lock()
            .map_err(|_| operation("secret_cipher_lock", "cipher mutex poisoned"))?;
        let encoded = cipher
            .seal(&request.binding, &secret.value)
            .map_err(|error| operation("secret_envelope", error))?;
        Ok(PreparedSecretEnvelope::from_encoded(
            &request.binding,
            encoded,
        ))
    }
}

/// Thread-safe wrapper around the existing tamper-evident audit log.
#[derive(Clone, Debug)]
pub struct AuditRecorder {
    inner: Arc<Mutex<AuditLog>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditSummary {
    pub event_count: usize,
    pub merkle_root: String,
    pub head_hash: String,
}

impl AuditRecorder {
    pub fn new(session_id: SessionId) -> SessionSecurityResult<Self> {
        let log = AuditLog::new(session_id.to_string())
            .map_err(|error| operation("audit_initialize", error))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(log)),
        })
    }

    pub fn record(
        &self,
        timestamp_unix_nanos: u64,
        category: AuditCategory,
        action: impl Into<String>,
        subject: impl Into<String>,
        result: AuditResult,
        metadata: BTreeMap<String, String>,
    ) -> SessionSecurityResult<AuditRecord> {
        let mut log = self
            .inner
            .lock()
            .map_err(|_| operation("audit_lock", "audit mutex poisoned"))?;
        log.append(
            timestamp_unix_nanos,
            category,
            action,
            subject,
            result,
            metadata,
        )
        .cloned()
        .map_err(|error| operation("audit_append", error))
    }

    pub fn records(&self) -> SessionSecurityResult<Vec<AuditRecord>> {
        let log = self
            .inner
            .lock()
            .map_err(|_| operation("audit_lock", "audit mutex poisoned"))?;
        Ok(log.records().to_vec())
    }

    pub fn verify(&self) -> SessionSecurityResult<()> {
        let log = self
            .inner
            .lock()
            .map_err(|_| operation("audit_lock", "audit mutex poisoned"))?;
        log.verify()
            .map_err(|error| operation("audit_verify", error))
    }

    pub fn summary(&self) -> SessionSecurityResult<AuditSummary> {
        let log = self
            .inner
            .lock()
            .map_err(|_| operation("audit_lock", "audit mutex poisoned"))?;
        log.verify()
            .map_err(|error| operation("audit_verify", error))?;
        Ok(AuditSummary {
            event_count: log.records().len(),
            merkle_root: log.merkle_root(),
            head_hash: log
                .records()
                .last()
                .map_or_else(String::new, |record| record.hash.clone()),
        })
    }
}

pub struct LifecycleHooks<'a> {
    pub provenance: &'a dyn ProvenanceVerifier,
    pub snapshots: &'a dyn SnapshotController,
    pub secrets: &'a dyn SecretEnvelopeProducer,
    pub credential_rules: &'a dyn CredentialRulePreparer,
    pub credential_listener: &'a dyn CredentialListener,
    pub permission_supervisor: &'a dyn PermissionSupervisorReady,
    pub audit_publication: &'a dyn AuditPublicationHook,
    pub cleanup: &'a dyn CleanupHook,
    pub clock: &'a dyn LifecycleClock,
}

pub struct PrepareRequest {
    pub policy_provenance: ProvenanceDocument,
    pub config_provenance: ProvenanceDocument,
    pub secret_requests: Vec<SecretEnvelopeRequest>,
    pub credential_policies: Vec<CredentialPolicy>,
    pub credential_listener_maximum_requests: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSession {
    pub policy_verification: VerificationResult,
    pub config_verification: VerificationResult,
    pub before_snapshot: SnapshotManifest,
    pub secret_envelopes: Vec<PreparedSecretEnvelope>,
    pub credential_rules: PreparedCredentialRules,
    pub supervisor_checkpoint: SupervisorCheckpoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    Completed,
    Failed { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizationReport {
    pub outcome: SessionOutcome,
    pub after_snapshot: SnapshotManifest,
    pub diff: SnapshotDiff,
    pub audit: AuditSummary,
    pub publication: AuditPublication,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LifecycleState {
    Running,
    Completed,
    Failed,
}

impl LifecycleState {
    const fn name(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

pub struct SecuritySession<'a> {
    session_id: SessionId,
    hooks: LifecycleHooks<'a>,
    prepared: PreparedSession,
    audit: AuditRecorder,
    state: LifecycleState,
}

impl<'a> SecuritySession<'a> {
    pub fn prepare(
        session_id: SessionId,
        request: PrepareRequest,
        hooks: LifecycleHooks<'a>,
    ) -> SessionSecurityResult<Self> {
        let audit = AuditRecorder::new(session_id)?;
        let mut before_snapshot = None;
        let result: SessionSecurityResult<PreparedSession> = (|| {
            let policy_verification = hooks.provenance.verify_policy(&request.policy_provenance)?;
            let config_verification = hooks.provenance.verify_config(&request.config_provenance)?;
            let captured = hooks.snapshots.capture_before(session_id)?;
            before_snapshot = Some(captured.clone());

            record_lifecycle(
                &audit,
                hooks.clock,
                "session_prepare",
                &session_id.to_string(),
                AuditResult::Success,
            )?;
            record_lifecycle(
                &audit,
                hooks.clock,
                "policy_provenance_verified",
                &policy_verification.subject.sha256,
                AuditResult::Success,
            )?;
            record_lifecycle(
                &audit,
                hooks.clock,
                "config_provenance_verified",
                &config_verification.subject.sha256,
                AuditResult::Success,
            )?;
            audit.record(
                hooks.clock.now_unix_nanos(),
                AuditCategory::Snapshot,
                "before_snapshot_captured",
                &captured.id,
                AuditResult::Success,
                BTreeMap::new(),
            )?;

            let mut secret_envelopes = Vec::with_capacity(request.secret_requests.len());
            for secret_request in &request.secret_requests {
                let envelope = hooks.secrets.prepare(secret_request)?;
                audit.record(
                    hooks.clock.now_unix_nanos(),
                    AuditCategory::Secret,
                    "secret_envelope_prepared",
                    &envelope.secret_name,
                    AuditResult::Success,
                    BTreeMap::from([("sequence".to_owned(), envelope.sequence.to_string())]),
                )?;
                secret_envelopes.push(envelope);
            }

            let credential_rules = hooks
                .credential_rules
                .prepare(&request.credential_policies)?;
            hooks.credential_listener.ready(
                &credential_rules,
                request.credential_listener_maximum_requests,
            )?;
            let supervisor_checkpoint = hooks
                .permission_supervisor
                .ready(session_id, audit.clone())?;
            audit.record(
                hooks.clock.now_unix_nanos(),
                AuditCategory::Permission,
                "permission_supervisor_ready",
                session_id.to_string(),
                AuditResult::Success,
                BTreeMap::from([
                    (
                        "generation".to_owned(),
                        supervisor_checkpoint.generation.to_string(),
                    ),
                    (
                        "state_hash".to_owned(),
                        supervisor_checkpoint.state_hash.clone(),
                    ),
                ]),
            )?;

            Ok(PreparedSession {
                policy_verification,
                config_verification,
                before_snapshot: captured,
                secret_envelopes,
                credential_rules,
                supervisor_checkpoint,
            })
        })();

        match result {
            Ok(prepared) => Ok(Self {
                session_id,
                hooks,
                prepared,
                audit,
                state: LifecycleState::Running,
            }),
            Err(primary) => {
                let rollback = before_snapshot
                    .as_ref()
                    .and_then(|snapshot| hooks.snapshots.rollback(snapshot).err())
                    .map(|error| error.to_string());
                let cleanup = hooks
                    .cleanup
                    .cleanup(session_id)
                    .err()
                    .map(|error| error.to_string());
                Err(SessionSecurityError::FailureAggregate {
                    stage: "prepare",
                    primary: primary.to_string(),
                    rollback,
                    cleanup,
                })
            }
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub fn prepared(&self) -> &PreparedSession {
        &self.prepared
    }

    #[must_use]
    pub fn audit_recorder(&self) -> AuditRecorder {
        self.audit.clone()
    }

    pub fn record_event(
        &self,
        timestamp_unix_nanos: u64,
        category: AuditCategory,
        action: impl Into<String>,
        subject: impl Into<String>,
        result: AuditResult,
        metadata: BTreeMap<String, String>,
    ) -> SessionSecurityResult<AuditRecord> {
        if self.state != LifecycleState::Running {
            return Err(SessionSecurityError::InvalidState {
                expected: "running",
                actual: self.state.name(),
            });
        }
        self.audit.record(
            timestamp_unix_nanos,
            category,
            action,
            subject,
            result,
            metadata,
        )
    }

    pub fn complete(&mut self) -> SessionSecurityResult<FinalizationReport> {
        self.finalize(SessionOutcome::Completed)
    }

    pub fn fail(&mut self, reason: impl Into<String>) -> SessionSecurityResult<FinalizationReport> {
        self.finalize(SessionOutcome::Failed {
            reason: reason.into(),
        })
    }

    fn finalize(&mut self, outcome: SessionOutcome) -> SessionSecurityResult<FinalizationReport> {
        if self.state != LifecycleState::Running {
            return Err(SessionSecurityError::InvalidState {
                expected: "running",
                actual: self.state.name(),
            });
        }

        let after_snapshot = match self.hooks.snapshots.capture_after(self.session_id) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self.abort(
                    "finalize",
                    finalization_primary(&outcome, &error.to_string()),
                );
            }
        };
        let diff = match self
            .hooks
            .snapshots
            .diff(&self.prepared.before_snapshot, &after_snapshot)
        {
            Ok(diff) => diff,
            Err(error) => {
                return self.abort(
                    "finalize",
                    finalization_primary(&outcome, &error.to_string()),
                );
            }
        };
        let (audit_result, outcome_name) = match &outcome {
            SessionOutcome::Completed => (AuditResult::Success, "completed"),
            SessionOutcome::Failed { .. } => (AuditResult::Error, "failed"),
        };
        if let Err(error) = self.audit.record(
            self.hooks.clock.now_unix_nanos(),
            AuditCategory::Lifecycle,
            "session_finalized",
            outcome_name,
            audit_result,
            BTreeMap::from([
                ("added".to_owned(), diff.added.len().to_string()),
                ("deleted".to_owned(), diff.deleted.len().to_string()),
                ("modified".to_owned(), diff.modified.len().to_string()),
            ]),
        ) {
            return self.abort(
                "finalize",
                finalization_primary(&outcome, &error.to_string()),
            );
        }
        if let SessionOutcome::Failed { reason } = &outcome {
            let rollback = self.rollback_with_audit();
            let cleanup = self.cleanup_with_audit();
            self.state = LifecycleState::Failed;
            let audit = self.audit.summary()?;
            let publication = self.publish_audit(&audit);
            if rollback.is_some() || cleanup.is_some() || publication.is_err() {
                return Err(SessionSecurityError::FailureAggregate {
                    stage: "failure_finalize",
                    primary: publication.as_ref().err().map_or_else(
                        || reason.clone(),
                        |error| format!("{reason}; audit publication also failed: {error}"),
                    ),
                    rollback,
                    cleanup,
                });
            }
            return Ok(FinalizationReport {
                outcome,
                after_snapshot,
                diff,
                audit,
                publication: publication.expect("publication checked above"),
            });
        }

        let cleanup = self.cleanup_with_audit();
        if let Some(cleanup_error) = cleanup {
            let rollback = self.rollback_with_audit();
            let audit = self.audit.summary()?;
            let publication = self.publish_audit(&audit).err();
            self.state = LifecycleState::Failed;
            return Err(SessionSecurityError::FailureAggregate {
                stage: "finalize_cleanup",
                primary: publication.map_or_else(
                    || cleanup_error.clone(),
                    |error| format!("{cleanup_error}; audit publication also failed: {error}"),
                ),
                rollback,
                cleanup: Some(cleanup_error),
            });
        }

        let audit = self.audit.summary()?;
        let publication = match self.publish_audit(&audit) {
            Ok(publication) => publication,
            Err(error) => {
                let rollback = self.rollback_with_audit();
                self.state = LifecycleState::Failed;
                return Err(SessionSecurityError::FailureAggregate {
                    stage: "audit_publication",
                    primary: error.to_string(),
                    rollback,
                    cleanup: None,
                });
            }
        };
        self.state = LifecycleState::Completed;
        Ok(FinalizationReport {
            outcome,
            after_snapshot,
            diff,
            audit,
            publication,
        })
    }

    fn abort<T>(&mut self, stage: &'static str, primary: String) -> SessionSecurityResult<T> {
        let mut primary = primary;
        if let Err(error) = self.audit.record(
            self.hooks.clock.now_unix_nanos(),
            AuditCategory::Lifecycle,
            "session_abort",
            stage,
            AuditResult::Error,
            BTreeMap::from([("primary".to_owned(), primary.clone())]),
        ) {
            primary.push_str("; failure audit recording also failed: ");
            primary.push_str(&error.to_string());
        }
        let rollback = self.rollback_with_audit();
        let cleanup = self.cleanup_with_audit();
        if let Ok(audit) = self.audit.summary()
            && let Err(error) = self.publish_audit(&audit)
        {
            primary.push_str("; audit publication also failed: ");
            primary.push_str(&error.to_string());
        }
        self.state = LifecycleState::Failed;
        Err(SessionSecurityError::FailureAggregate {
            stage,
            primary,
            rollback,
            cleanup,
        })
    }

    fn rollback_with_audit(&self) -> Option<String> {
        let result = self
            .hooks
            .snapshots
            .rollback(&self.prepared.before_snapshot);
        let (audit_result, error) = match result {
            Ok(()) => (AuditResult::Success, None),
            Err(error) => (AuditResult::Error, Some(error.to_string())),
        };
        let audit_error = self
            .audit
            .record(
                self.hooks.clock.now_unix_nanos(),
                AuditCategory::Snapshot,
                "snapshot_rollback",
                &self.prepared.before_snapshot.id,
                audit_result,
                error.as_ref().map_or_else(BTreeMap::new, |message| {
                    BTreeMap::from([("error".to_owned(), message.clone())])
                }),
            )
            .err()
            .map(|audit_error| audit_error.to_string());
        combine_operation_and_audit_error(error, audit_error)
    }

    fn cleanup_with_audit(&self) -> Option<String> {
        let result = self.hooks.cleanup.cleanup(self.session_id);
        let (audit_result, error) = match result {
            Ok(()) => (AuditResult::Success, None),
            Err(error) => (AuditResult::Error, Some(error.to_string())),
        };
        let audit_error = self
            .audit
            .record(
                self.hooks.clock.now_unix_nanos(),
                AuditCategory::Lifecycle,
                "session_cleanup",
                self.session_id.to_string(),
                audit_result,
                error.as_ref().map_or_else(BTreeMap::new, |message| {
                    BTreeMap::from([("error".to_owned(), message.clone())])
                }),
            )
            .err()
            .map(|audit_error| audit_error.to_string());
        combine_operation_and_audit_error(error, audit_error)
    }

    fn publish_audit(&self, audit: &AuditSummary) -> SessionSecurityResult<AuditPublication> {
        self.hooks
            .audit_publication
            .publish(self.session_id, &audit.merkle_root, &audit.head_hash)
    }
}

fn record_lifecycle(
    audit: &AuditRecorder,
    clock: &dyn LifecycleClock,
    action: &str,
    subject: &str,
    result: AuditResult,
) -> SessionSecurityResult<()> {
    let record = audit.record(
        clock.now_unix_nanos(),
        AuditCategory::Lifecycle,
        action,
        subject,
        result,
        BTreeMap::from([("audit_version".to_owned(), AUDIT_FORMAT_VERSION.to_string())]),
    )?;
    if record.event.session_id.len() != 32 {
        return Err(operation(
            "audit_session_identity",
            "audit session ID is not canonical 32-character hexadecimal",
        ));
    }

    Ok(())
}

fn finalization_primary(outcome: &SessionOutcome, operation_error: &str) -> String {
    match outcome {
        SessionOutcome::Completed => operation_error.to_owned(),
        SessionOutcome::Failed { reason } => {
            format!("session failed: {reason}; finalization also failed: {operation_error}")
        }
    }
}

fn verify_document(
    trust_store: &TrustStore,
    document: &ProvenanceDocument,
    stage: &'static str,
) -> SessionSecurityResult<VerificationResult> {
    trust_store
        .verify(
            &document.content,
            document.kind,
            &document.signatures,
            document.now_unix,
        )
        .map_err(|error| operation(stage, error))
}

fn combine_operation_and_audit_error(
    operation_error: Option<String>,
    audit_error: Option<String>,
) -> Option<String> {
    match (operation_error, audit_error) {
        (Some(operation), Some(audit)) => {
            Some(format!("{operation}; audit recording also failed: {audit}"))
        }
        (Some(operation), None) => Some(operation),
        (None, Some(audit)) => Some(format!("audit recording failed: {audit}")),
        (None, None) => None,
    }
}
