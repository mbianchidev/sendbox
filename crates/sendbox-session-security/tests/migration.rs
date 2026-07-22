use std::sync::atomic::{AtomicUsize, Ordering};

use sendbox_secrets::{
    RecordVersion, Secret, SecretMetadata, SecretName, SecretStore, SecretStoreError, SecretValue,
};
use sendbox_session_security::migration::{
    MigrationAuthorization, MigrationError, MigrationLimits, MigrationSourceKind, PermissionImpact,
    inspect_legacy_audit, inspect_legacy_provenance_signature, inspect_legacy_snapshot,
    inspect_secret_metadata, inspect_swift_codable_grants, inspect_swift_trust_store,
    propose_conversion,
};

#[test]
fn legacy_readers_are_bounded_and_report_structural_findings() {
    let limits = MigrationLimits::default();
    let tree = br#"{"root_hash":"","leaf_count":0,"nodes":[]}"#;
    let (audit, entries) = inspect_legacy_audit(b"[]", Some(tree), &limits).expect("audit");
    assert!(entries.is_empty());
    assert_eq!(audit.source_kind, MigrationSourceKind::LegacyAudit);
    assert!(audit.findings.is_empty());

    let snapshot = format!(
        "{{\"id\":\"{}\",\"timestamp\":\"2025-01-01T00:00:00Z\",\"session_name\":\"s\",\"workspace_path\":\"/workspace\",\"files\":[],\"total_size\":0}}",
        "0".repeat(64)
    );
    let (snapshot_report, manifest) =
        inspect_legacy_snapshot(snapshot.as_bytes(), &limits).expect("snapshot");
    assert_eq!(snapshot_report.item_count, 0);
    assert!(manifest.files.is_empty());

    let trust = br#"{"identities":[],"requireSignature":false,"minimumSigners":0}"#;
    let (trust_report, store) = inspect_swift_trust_store(trust, &limits).expect("trust store");
    assert!(store.identities.is_empty());
    assert_eq!(trust_report.permission_impact, PermissionImpact::Broadening);

    let signature = format!(
        "{{\"fileHash\":\"{}\",\"signature\":\"AA==\",\"signerFingerprint\":\"fingerprint\",\"timestamp\":\"2025-01-01T00:00:00Z\",\"metadata\":{{\"toolVersion\":\"1\",\"purpose\":\"policy\"}}}}",
        "a".repeat(64)
    );
    let (signature_report, _) =
        inspect_legacy_provenance_signature(signature.as_bytes(), &limits).expect("signature");
    assert!(!signature_report.conversion_available);
    assert!(
        signature_report
            .findings
            .iter()
            .any(|finding| finding.code == "cryptographic_verification_deferred")
    );

    let tiny = MigrationLimits {
        max_bytes: 2,
        ..MigrationLimits::default()
    };
    assert!(matches!(
        inspect_legacy_snapshot(snapshot.as_bytes(), &tiny),
        Err(MigrationError::Bounds(_))
    ));
}

#[test]
fn swift_grants_are_observational_and_permission_broadening_is_gated() {
    let bytes = br#"{"version":1,"grants":[{"category":"command","pattern":"cargo *","expiresAtUnixMs":null,"maxUses":2}]}"#;
    let (report, grants) =
        inspect_swift_codable_grants(bytes, &MigrationLimits::default()).expect("grants");
    assert_eq!(grants.grants.len(), 1);
    assert!(report.observational_only);
    assert_eq!(report.permission_impact, PermissionImpact::Broadening);
    let authorization = MigrationAuthorization::from_report(&report).expect("authorization");
    assert_eq!(
        propose_conversion(&report, &authorization, false).expect_err("ack"),
        MigrationError::BroadeningAcknowledgementRequired
    );
    let proposal = propose_conversion(&report, &authorization, true).expect("proposal");
    assert_eq!(proposal.item_count, 1);

    let (other_report, _) =
        inspect_legacy_audit(b"[]", None, &MigrationLimits::default()).expect("audit");
    let wrong = MigrationAuthorization::from_report(&other_report).expect("wrong auth");
    assert_eq!(
        propose_conversion(&report, &wrong, true).expect_err("wrong auth"),
        MigrationError::Unauthorized
    );

    let unknown = br#"{"version":1,"grants":[{"category":"command","pattern":"cargo *","expiresAtUnixMs":null,"maxUses":2,"unexpected":true}]}"#;
    assert!(matches!(
        inspect_swift_codable_grants(unknown, &MigrationLimits::default()),
        Err(MigrationError::Malformed(_))
    ));

    let actual_codable = include_bytes!("fixtures/swift-supervisor-grants-v1.json");
    let (actual_report, actual) =
        inspect_swift_codable_grants(actual_codable, &MigrationLimits::default())
            .expect("actual Codable grants");
    assert_eq!(actual_report.item_count, 1);
    assert_eq!(actual.grants[0].id.as_deref(), Some("grant-1"));

    let camel_case = br#"[{"id":"grant-2","category":"fileWrite","pattern":"/tmp/*","grantedAt":765432100.0,"expiresAt":null,"usesRemaining":1,"grantType":"once"}]"#;
    inspect_swift_codable_grants(camel_case, &MigrationLimits::default())
        .expect("Swift camelCase category");
}

struct ObservedStore {
    list_calls: AtomicUsize,
    mutation_calls: AtomicUsize,
}

impl ObservedStore {
    fn new() -> Self {
        Self {
            list_calls: AtomicUsize::new(0),
            mutation_calls: AtomicUsize::new(0),
        }
    }
}

impl SecretStore for ObservedStore {
    fn store(
        &self,
        _name: &SecretName,
        _value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        Err(SecretStoreError::AccessDenied)
    }

    fn update(
        &self,
        _name: &SecretName,
        _value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        Err(SecretStoreError::AccessDenied)
    }

    fn retrieve(&self, _name: &SecretName) -> Result<Secret, SecretStoreError> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        Err(SecretStoreError::AccessDenied)
    }

    fn delete(&self, _name: &SecretName) -> Result<(), SecretStoreError> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        Err(SecretStoreError::AccessDenied)
    }

    fn list(&self) -> Result<Vec<SecretMetadata>, SecretStoreError> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![
            SecretMetadata {
                name: SecretName::new("CURRENT").expect("name"),
                created_at_unix_ms: 1,
                updated_at_unix_ms: 1,
                version: RecordVersion::V1,
            },
            SecretMetadata {
                name: SecretName::new("LEGACY").expect("name"),
                created_at_unix_ms: 1,
                updated_at_unix_ms: 1,
                version: RecordVersion::SwiftLegacy,
            },
        ])
    }

    fn exists(&self, _name: &SecretName) -> Result<bool, SecretStoreError> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        Err(SecretStoreError::AccessDenied)
    }

    fn migrate(&self, _name: &SecretName) -> Result<SecretMetadata, SecretStoreError> {
        self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        Err(SecretStoreError::MigrationNotAuthorized)
    }
}

#[test]
fn secret_metadata_dry_run_never_mutates_and_has_no_false_conversion() {
    let store = ObservedStore::new();
    let report =
        inspect_secret_metadata(&store, &MigrationLimits::default()).expect("metadata report");
    assert_eq!(report.item_count, 2);
    assert_eq!(store.list_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.mutation_calls.load(Ordering::SeqCst), 0);
    assert!(!report.conversion_available);
    let authorization = MigrationAuthorization::from_report(&report).expect("authorization");
    assert_eq!(
        propose_conversion(&report, &authorization, false).expect_err("unavailable"),
        MigrationError::ConversionUnavailable
    );
}

#[test]
fn conversion_authorization_is_derived_from_exact_report() {
    let (report, _) =
        inspect_legacy_audit(b"[]", None, &MigrationLimits::default()).expect("audit");
    let authorization = MigrationAuthorization::from_report(&report).expect("authorization");
    let proposal = propose_conversion(&report, &authorization, false).expect("proposal");
    assert_eq!(proposal.source_kind, MigrationSourceKind::LegacyAudit);

    let mut changed = report.clone();
    changed.item_count = 1;
    assert_eq!(
        propose_conversion(&changed, &authorization, false).expect_err("changed report"),
        MigrationError::Unauthorized
    );
}
