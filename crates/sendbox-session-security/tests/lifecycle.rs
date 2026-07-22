use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use sendbox_core::SessionId;
use sendbox_secrets::{
    CredentialPolicy, EnvelopeBinding, EnvelopeCipher, RecipientRole, RecordVersion, Secret,
    SecretMetadata, SecretName, SecretStore, SecretStoreError, SecretValue, SessionKeyMaterial,
};
use sendbox_security::audit::{AuditCategory, AuditResult};
use sendbox_security::provenance::{
    SignedSubject, SubjectKind, TrustPolicy, TrustStore, VerificationResult,
};
use sendbox_security::snapshot::{SnapshotDiff, SnapshotManifest};
use sendbox_session_security::lifecycle::{
    AuditPublication, AuditPublicationHook, AuditRecorder, CleanupHook, CredentialListener,
    CredentialRulePreparer, LifecycleClock, LifecycleHooks, PermissionSupervisorReady,
    PrepareRequest, PreparedCredentialRules, PreparedSecretEnvelope, ProvenanceDocument,
    ProvenanceVerifier, SecretEnvelopeProducer, SecretEnvelopeRequest, SecuritySession,
    SessionOutcome, SessionSecurityError, SessionSecurityResult, SnapshotController,
    StoreEnvelopeProducer, TrustStoreProvenanceVerifier,
};
use sendbox_session_security::supervisor::SupervisorCheckpoint;

const SESSION: SessionId = SessionId::from_bytes([0x12; 16]);

#[derive(Default)]
struct TestClock(AtomicU64);

impl LifecycleClock for TestClock {
    fn now_unix_nanos(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

struct FakeHooks {
    failures: BTreeSet<&'static str>,
    calls: Mutex<Vec<&'static str>>,
}

impl FakeHooks {
    fn new(failures: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            failures: failures.into_iter().collect(),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn call(&self, stage: &'static str) -> SessionSecurityResult<()> {
        self.calls.lock().expect("calls").push(stage);
        if self.failures.contains(stage) {
            Err(SessionSecurityError::Operation {
                stage,
                message: "injected".to_owned(),
            })
        } else {
            Ok(())
        }
    }

    fn manifest(id: &str) -> SnapshotManifest {
        SnapshotManifest {
            format: "test".to_owned(),
            version: 1,
            id: id.to_owned(),
            entries: Vec::new(),
            total_size: 0,
        }
    }
}

impl ProvenanceVerifier for FakeHooks {
    fn verify_policy(
        &self,
        document: &ProvenanceDocument,
    ) -> SessionSecurityResult<VerificationResult> {
        self.call("policy")?;
        Ok(VerificationResult {
            subject: SignedSubject::from_bytes(document.kind, None, &document.content),
            valid_signers: BTreeSet::from(["policy-signer".to_owned()]),
        })
    }

    fn verify_config(
        &self,
        document: &ProvenanceDocument,
    ) -> SessionSecurityResult<VerificationResult> {
        self.call("config")?;
        Ok(VerificationResult {
            subject: SignedSubject::from_bytes(document.kind, None, &document.content),
            valid_signers: BTreeSet::from(["config-signer".to_owned()]),
        })
    }
}

impl SnapshotController for FakeHooks {
    fn capture_before(&self, _session_id: SessionId) -> SessionSecurityResult<SnapshotManifest> {
        self.call("before")?;
        Ok(Self::manifest("before"))
    }

    fn capture_after(&self, _session_id: SessionId) -> SessionSecurityResult<SnapshotManifest> {
        self.call("after")?;
        Ok(Self::manifest("after"))
    }

    fn diff(
        &self,
        _before: &SnapshotManifest,
        _after: &SnapshotManifest,
    ) -> SessionSecurityResult<SnapshotDiff> {
        self.call("diff")?;
        Ok(SnapshotDiff {
            added: vec!["new".to_owned()],
            ..SnapshotDiff::default()
        })
    }

    fn rollback(&self, _before: &SnapshotManifest) -> SessionSecurityResult<()> {
        self.call("rollback")
    }
}

impl SecretEnvelopeProducer for FakeHooks {
    fn prepare(
        &self,
        request: &SecretEnvelopeRequest,
    ) -> SessionSecurityResult<PreparedSecretEnvelope> {
        self.call("secret")?;
        Ok(PreparedSecretEnvelope::from_encoded(
            &request.binding,
            vec![1, 2, 3],
        ))
    }
}

impl CredentialRulePreparer for FakeHooks {
    fn prepare(
        &self,
        policies: &[CredentialPolicy],
    ) -> SessionSecurityResult<PreparedCredentialRules> {
        self.call("credential_rules")?;
        Ok(PreparedCredentialRules {
            rule_count: policies.len(),
            preparation_id: "rules".to_owned(),
        })
    }
}

impl CredentialListener for FakeHooks {
    fn ready(
        &self,
        _prepared: &PreparedCredentialRules,
        maximum_requests: u32,
    ) -> SessionSecurityResult<()> {
        assert_eq!(maximum_requests, 4);
        self.call("credential_listener")
    }
}

impl PermissionSupervisorReady for FakeHooks {
    fn ready(
        &self,
        _session_id: SessionId,
        _audit: AuditRecorder,
    ) -> SessionSecurityResult<SupervisorCheckpoint> {
        self.call("permission")?;
        Ok(SupervisorCheckpoint {
            generation: 0,
            state_hash: "a".repeat(64),
        })
    }
}

impl AuditPublicationHook for FakeHooks {
    fn publish(
        &self,
        _session_id: SessionId,
        merkle_root: &str,
        head_hash: &str,
    ) -> SessionSecurityResult<AuditPublication> {
        assert_eq!(merkle_root.len(), 64);
        assert_eq!(head_hash.len(), 64);
        self.call("publication")?;
        Ok(AuditPublication {
            signature: Some("signature".to_owned()),
        })
    }
}

impl CleanupHook for FakeHooks {
    fn cleanup(&self, _session_id: SessionId) -> SessionSecurityResult<()> {
        self.call("cleanup")
    }
}

fn provenance(name: &str) -> ProvenanceDocument {
    ProvenanceDocument {
        content: name.as_bytes().to_vec(),
        kind: SubjectKind::Configuration,
        signatures: Vec::new(),
        now_unix: 1,
    }
}

fn secret_request() -> SecretEnvelopeRequest {
    SecretEnvelopeRequest {
        binding: EnvelopeBinding {
            session_id: SESSION,
            recipient: RecipientRole::Guest,
            secret_name: SecretName::new("TOKEN").expect("name"),
            sequence: 7,
            expires_at_unix_ms: 10_000,
            policy_digest: [3; 32],
        },
    }
}

fn request() -> PrepareRequest {
    PrepareRequest {
        policy_provenance: provenance("policy"),
        config_provenance: provenance("config"),
        secret_requests: vec![secret_request()],
        credential_policies: Vec::new(),
        credential_listener_maximum_requests: 4,
    }
}

fn hooks<'a>(fake: &'a FakeHooks, clock: &'a TestClock) -> LifecycleHooks<'a> {
    LifecycleHooks {
        provenance: fake,
        snapshots: fake,
        secrets: fake,
        credential_rules: fake,
        credential_listener: fake,
        permission_supervisor: fake,
        audit_publication: fake,
        cleanup: fake,
        clock,
    }
}

#[test]
fn prepare_failures_rollback_and_cleanup_at_every_injected_stage() {
    for stage in [
        "policy",
        "config",
        "before",
        "secret",
        "credential_rules",
        "credential_listener",
        "permission",
    ] {
        let fake = FakeHooks::new([stage]);
        let clock = TestClock::default();
        let error = match SecuritySession::prepare(SESSION, request(), hooks(&fake, &clock)) {
            Ok(_) => panic!("expected {stage} failure"),
            Err(error) => error,
        };
        let SessionSecurityError::FailureAggregate { primary, .. } = error else {
            panic!("unexpected error");
        };
        assert!(primary.contains(stage));
        let calls = fake.calls.lock().expect("calls");
        assert_eq!(calls.last(), Some(&"cleanup"));
        if matches!(
            stage,
            "secret" | "credential_rules" | "credential_listener" | "permission"
        ) {
            assert!(calls.contains(&"rollback"));
        } else {
            assert!(!calls.contains(&"rollback"));
        }
    }
}

#[test]
fn prepare_preserves_primary_rollback_and_cleanup_failures() {
    let fake = FakeHooks::new(["secret", "rollback", "cleanup"]);
    let clock = TestClock::default();
    let error = match SecuritySession::prepare(SESSION, request(), hooks(&fake, &clock)) {
        Ok(_) => panic!("expected failure"),
        Err(error) => error,
    };
    let SessionSecurityError::FailureAggregate {
        primary,
        rollback,
        cleanup,
        ..
    } = error
    else {
        panic!("unexpected error");
    };
    assert!(primary.contains("secret"));
    assert!(rollback.expect("rollback").contains("rollback"));
    assert!(cleanup.expect("cleanup").contains("cleanup"));
}

#[test]
fn finalization_fault_aggregates_rollback_and_cleanup() {
    let fake = FakeHooks::new(["publication", "rollback", "cleanup"]);
    let clock = TestClock::default();
    let mut session =
        SecuritySession::prepare(SESSION, request(), hooks(&fake, &clock)).expect("prepare");
    let error = session.complete().expect_err("publication failure");
    let SessionSecurityError::FailureAggregate {
        primary,
        rollback,
        cleanup,
        ..
    } = error
    else {
        panic!("unexpected error");
    };
    assert!(primary.contains("publication"));
    assert!(rollback.is_some());
    assert!(cleanup.is_some());
    assert!(session.complete().is_err());
}

#[test]
fn every_finalization_hook_failure_attempts_rollback_cleanup_and_publication() {
    for stage in ["after", "diff", "publication", "cleanup"] {
        let fake = FakeHooks::new([stage]);
        let clock = TestClock::default();
        let mut session =
            SecuritySession::prepare(SESSION, request(), hooks(&fake, &clock)).expect("prepare");
        assert!(session.complete().is_err(), "expected {stage} failure");
        let calls = fake.calls.lock().expect("calls");
        assert!(calls.contains(&"rollback"), "{stage} did not roll back");
        assert!(calls.contains(&"cleanup"), "{stage} did not clean up");
        if stage != "publication" {
            assert!(
                calls.contains(&"publication"),
                "{stage} did not attempt final audit publication"
            );
        }
    }
}

#[test]
fn failure_finalization_rolls_back_and_reports_outcome() {
    let fake = FakeHooks::new([]);
    let clock = TestClock::default();
    let mut session =
        SecuritySession::prepare(SESSION, request(), hooks(&fake, &clock)).expect("prepare");
    let report = session
        .fail("runtime failed")
        .expect("failure finalization");
    assert_eq!(
        report.outcome,
        SessionOutcome::Failed {
            reason: "runtime failed".to_owned()
        }
    );
    assert!(fake.calls.lock().expect("calls").contains(&"rollback"));
    let records = session.audit_recorder().records().expect("records");
    let actions = records
        .iter()
        .map(|record| record.event.action.as_str())
        .collect::<Vec<_>>();
    assert!(actions.ends_with(&["snapshot_rollback", "session_cleanup"]));
    assert_eq!(report.audit.event_count, records.len());
    assert!(
        session
            .record_event(
                1,
                AuditCategory::Command,
                "late",
                "late",
                AuditResult::Denied,
                BTreeMap::new()
            )
            .is_err()
    );
}

#[test]
fn concurrent_audit_events_have_contiguous_sequences_and_valid_chain() {
    let recorder = AuditRecorder::new(SESSION).expect("recorder");
    let mut threads = Vec::new();
    for worker in 0..8_u64 {
        let recorder = recorder.clone();
        threads.push(thread::spawn(move || {
            for event in 0..64_u64 {
                recorder
                    .record(
                        worker * 64 + event,
                        AuditCategory::Command,
                        "execute",
                        format!("{worker}:{event}"),
                        AuditResult::Allowed,
                        BTreeMap::new(),
                    )
                    .expect("record");
            }
        }));
    }
    for thread in threads {
        thread.join().expect("join");
    }
    recorder.verify().expect("chain");
    let records = recorder.records().expect("records");
    assert_eq!(records.len(), 512);
    assert!(
        records
            .iter()
            .enumerate()
            .all(|(index, record)| record.event.sequence == index as u64)
    );
    assert!(
        records
            .iter()
            .all(|record| record.event.session_id == SESSION.to_string())
    );
}

#[derive(Default)]
struct MemorySecretStore {
    values: Mutex<BTreeMap<SecretName, Vec<u8>>>,
}

impl MemorySecretStore {
    fn with(name: &str, value: &[u8]) -> Self {
        Self {
            values: Mutex::new(BTreeMap::from([(
                SecretName::new(name).expect("name"),
                value.to_vec(),
            )])),
        }
    }
}

impl SecretStore for MemorySecretStore {
    fn store(
        &self,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError> {
        self.values
            .lock()
            .expect("values")
            .insert(name.clone(), value.expose_secret().to_vec());
        metadata(name)
    }

    fn update(
        &self,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError> {
        self.store(name, value)
    }

    fn retrieve(&self, name: &SecretName) -> Result<Secret, SecretStoreError> {
        let value = self
            .values
            .lock()
            .expect("values")
            .get(name)
            .cloned()
            .ok_or_else(|| SecretStoreError::NotFound(name.clone()))?;
        Ok(Secret {
            metadata: metadata(name)?,
            value: SecretValue::new(value)?,
        })
    }

    fn delete(&self, name: &SecretName) -> Result<(), SecretStoreError> {
        self.values.lock().expect("values").remove(name);
        Ok(())
    }

    fn list(&self) -> Result<Vec<SecretMetadata>, SecretStoreError> {
        self.values
            .lock()
            .expect("values")
            .keys()
            .map(metadata)
            .collect()
    }

    fn exists(&self, name: &SecretName) -> Result<bool, SecretStoreError> {
        Ok(self.values.lock().expect("values").contains_key(name))
    }

    fn migrate(&self, name: &SecretName) -> Result<SecretMetadata, SecretStoreError> {
        metadata(name)
    }
}

fn metadata(name: &SecretName) -> Result<SecretMetadata, SecretStoreError> {
    Ok(SecretMetadata {
        name: name.clone(),
        created_at_unix_ms: 1,
        updated_at_unix_ms: 1,
        version: RecordVersion::V1,
    })
}

#[test]
fn default_secret_envelope_is_redacted_and_missing_references_fail() {
    let material = SessionKeyMaterial::new(vec![9; 32]).expect("material");
    let store = MemorySecretStore::with("TOKEN", b"never-print-this");
    let producer = StoreEnvelopeProducer::new(
        &store,
        EnvelopeCipher::new(&material, SESSION).expect("cipher"),
    );
    let prepared = producer.prepare(&secret_request()).expect("envelope");
    let debug = format!("{prepared:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("never-print-this"));
    assert!(!prepared.encoded().is_empty());

    let empty = MemorySecretStore::default();
    let missing = StoreEnvelopeProducer::new(
        &empty,
        EnvelopeCipher::new(&material, SESSION).expect("cipher"),
    );
    assert!(missing.prepare(&secret_request()).is_err());
}

#[test]
fn trust_store_verifier_checks_the_supplied_content() {
    let trust = TrustStore::new(TrustPolicy::default());
    let verifier = TrustStoreProvenanceVerifier::new(&trust, &trust);
    let document = provenance("policy");
    let result = verifier.verify_policy(&document).expect("verification");
    assert_eq!(
        result.subject,
        SignedSubject::from_bytes(SubjectKind::Configuration, None, b"policy")
    );
}
