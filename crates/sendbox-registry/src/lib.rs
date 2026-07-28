#![forbid(unsafe_code)]

mod adapter;
mod engine;
mod model;
mod report;

pub use adapter::{
    AdapterCapabilities, PackageProvenanceVerifier, RegistryAdapter, TrustMetadata, UpstreamClient,
    UpstreamRequest, UpstreamResponse,
};
pub use engine::{PolicyDecision, RawFinding, evaluate_findings, package_policy_digest};
pub use model::{
    ArchiveEntry, ArchiveEntryKind, ArtifactDescriptor, ArtifactDigest, IntegrityAlgorithm,
    IntegrityClaim, NormalizedManifest, PackageIdentity, RegistryError, RegistryResult,
    ResolvedMetadata, VerificationEvidence,
};
pub use report::{
    CacheOutcome, PackageFinding, PackageSecurityReport, PackageVerdictRecord, Verdict,
};

pub const REGISTRY_REPORT_SCHEMA_VERSION: u32 = 1;
pub const REGISTRY_SCANNER_VERSION: &str = env!("CARGO_PKG_VERSION");
