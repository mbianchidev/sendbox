#![forbid(unsafe_code)]

//! Adapter-agnostic orchestration for session lifecycle security, permission supervision, and
//! bounded legacy migration inspection.

pub mod lifecycle;
pub mod migration;
pub mod supervisor;

pub use lifecycle::{
    AuditRecorder, AuditSummary, ProvenanceDocument, SecuritySession, SessionSecurityError,
    SessionSecurityResult, TrustStoreProvenanceVerifier,
};
pub use migration::{
    MigrationAuthorization, MigrationError, MigrationLimits, MigrationProposal, MigrationReport,
};
pub use supervisor::{
    PermissionCategory, PermissionRequest, PermissionSupervisor, RiskLevel, SupervisorCheckpoint,
    SupervisorError,
};

#[doc(hidden)]
pub mod fuzzing {
    use std::sync::Arc;

    use crate::migration::{
        MigrationLimits, inspect_legacy_audit, inspect_legacy_provenance_signature,
        inspect_legacy_snapshot, inspect_swift_codable_grants, inspect_swift_trust_store,
    };
    use crate::supervisor::{NoopPermissionEventSink, PermissionSupervisor};

    pub fn decode_supervisor(bytes: &[u8]) {
        let _ = PermissionSupervisor::decode_unanchored_first_import(
            bytes,
            Arc::new(NoopPermissionEventSink),
        );
    }

    pub fn decode_migrations(bytes: &[u8]) {
        let limits = MigrationLimits::default();
        let _ = inspect_legacy_audit(bytes, None, &limits);
        let _ = inspect_legacy_snapshot(bytes, &limits);
        let _ = inspect_swift_trust_store(bytes, &limits);
        let _ = inspect_legacy_provenance_signature(bytes, &limits);
        let _ = inspect_swift_codable_grants(bytes, &limits);
    }
}
