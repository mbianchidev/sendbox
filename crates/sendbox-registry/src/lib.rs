#![forbid(unsafe_code)]

mod adapter;
mod cache;
mod client;
mod engine;
mod model;
mod npm;
mod provenance;
mod report;
mod scanner;
mod service;

pub use adapter::{
    AdapterCapabilities, PackageProvenanceVerifier, RegistryAdapter, TrustMetadata, UpstreamClient,
    UpstreamRequest, UpstreamResponse,
};
pub use cache::{CacheEntry, CacheKey, PackageCache};
pub use client::ReqwestUpstreamClient;
pub use engine::{PolicyDecision, RawFinding, evaluate_findings, package_policy_digest};
pub use model::{
    ArchiveEntry, ArchiveEntryKind, ArtifactDescriptor, ArtifactDigest, IntegrityAlgorithm,
    IntegrityClaim, IntegritySource, NormalizedManifest, PackageIdentity, ProvenanceClaim,
    RegistryError, RegistryResult, ResolvedMetadata, SignatureClaim, VerificationEvidence,
};
pub use npm::NpmAdapter;
pub use provenance::NpmPackageProvenanceVerifier;
pub use report::{
    CacheOutcome, PackageFinding, PackageSecurityReport, PackageVerdictRecord, Verdict,
};
pub use scanner::{enumerate_npm_archive, inspect_npm_archive};
pub use service::{ArtifactAnalysis, RegistryProxy, RegistryProxyConfiguration};

pub const REGISTRY_REPORT_SCHEMA_VERSION: u32 = 1;
pub const REGISTRY_SCANNER_VERSION: &str = env!("CARGO_PKG_VERSION");
