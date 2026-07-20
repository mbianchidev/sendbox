#![forbid(unsafe_code)]

pub mod audit;
pub mod fs;
pub mod provenance;
pub mod snapshot;

mod canonical;
mod error;
mod legacy;

pub use error::{SecurityError, SecurityResult};

#[doc(hidden)]
pub mod fuzzing {
    use crate::audit::{AuditLog, decode_legacy_swift_entries};
    use crate::canonical;
    use crate::provenance::{DetachedSignature, TrustStore, decode_legacy_swift_trust_store};
    use crate::snapshot::{SnapshotManifest, decode_legacy_swift_manifest};

    pub fn decode_audit(bytes: &[u8]) {
        let _ = AuditLog::decode(bytes, 4096);
        let _ = decode_legacy_swift_entries(bytes, 4 * 1024 * 1024, 4096);
    }

    pub fn decode_provenance(bytes: &[u8]) {
        let _ = DetachedSignature::decode(bytes);
        let _ = TrustStore::decode(bytes);
        let _ = decode_legacy_swift_trust_store(bytes, 4 * 1024 * 1024);
    }

    pub fn decode_snapshot(bytes: &[u8]) {
        let _: crate::SecurityResult<SnapshotManifest> =
            canonical::decode_canonical(bytes, "sendbox-snapshot");
        let _ = decode_legacy_swift_manifest(bytes, 4 * 1024 * 1024, 4096);
    }
}
