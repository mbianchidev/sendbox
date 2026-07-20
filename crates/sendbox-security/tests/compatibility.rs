use sendbox_security::audit::{decode_legacy_swift_entries, decode_legacy_swift_tree};
use sendbox_security::provenance::{
    decode_legacy_swift_trust_store, verify_legacy_swift_signature,
};
use sendbox_security::snapshot::decode_legacy_swift_manifest_default;

const AUDIT_ENTRIES: &[u8] =
    include_bytes!("../../../test-fixtures/security/swift-v1/audit/entries.json");
const AUDIT_TREE: &[u8] =
    include_bytes!("../../../test-fixtures/security/swift-v1/audit/tree.json");
const LEGACY_SIGNATURE: &[u8] =
    include_bytes!("../../../test-fixtures/security/swift-v1/provenance/empty.sig");
const LEGACY_TRUST: &[u8] =
    include_bytes!("../../../test-fixtures/security/swift-v1/provenance/trust-store.json");
const LEGACY_SNAPSHOT: &[u8] = include_bytes!(
    "../../../test-fixtures/security/swift-v1/snapshots/ec8607806b535ee57fef2ca2581537cbe56e2cf98cf2c2325bc2f5e4be884090.json"
);

#[test]
fn verifies_swift_audit_entries_and_tree() {
    let entries =
        decode_legacy_swift_entries(AUDIT_ENTRIES, 1024 * 1024, 100).expect("decode entries");
    let tree = decode_legacy_swift_tree(AUDIT_TREE, &entries, 1024 * 1024).expect("decode tree");
    assert_eq!(entries.len(), 2);
    assert_eq!(tree.leaf_count, entries.len());
}

#[test]
fn verifies_swift_detached_signature_and_trust_store() {
    let trust = decode_legacy_swift_trust_store(LEGACY_TRUST, 1024 * 1024).expect("decode trust");
    let now = time::OffsetDateTime::parse(
        "2026-01-01T00:00:00Z",
        &time::format_description::well_known::Iso8601::DEFAULT,
    )
    .expect("parse time");
    let signer = verify_legacy_swift_signature(b"", LEGACY_SIGNATURE, &trust.identities, now)
        .expect("verify signature");
    assert_eq!(signer, trust.identities[0].fingerprint);
}

#[test]
fn reads_swift_snapshot_manifest_without_extracting_archive() {
    let snapshot = decode_legacy_swift_manifest_default(LEGACY_SNAPSHOT).expect("decode snapshot");
    assert_eq!(snapshot.files.len(), 1);
    assert_eq!(snapshot.files[0].relative_path, "README.txt");
}
