use std::fmt;
use std::path::Path;

use async_trait::async_trait;
use sendbox_policy::PackageEcosystem;

use crate::{
    ArchiveEntry, ArtifactDescriptor, NormalizedManifest, PackageIdentity, RawFinding,
    RegistryResult, ResolvedMetadata, VerificationEvidence,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterCapabilities {
    pub metadata_rewrite: bool,
    pub signatures: bool,
    pub provenance: bool,
    pub layered_artifacts: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamRequest {
    pub url: String,
    pub accept: Option<String>,
    pub authorization: Option<Vec<u8>>,
    pub maximum_bytes: u64,
}

impl fmt::Debug for UpstreamRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamRequest")
            .field("url", &self.url)
            .field("accept", &self.accept)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "[REDACTED]"),
            )
            .field("maximum_bytes", &self.maximum_bytes)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait UpstreamClient: Send + Sync {
    async fn fetch(&self, request: UpstreamRequest) -> RegistryResult<UpstreamResponse>;

    async fn download(&self, request: UpstreamRequest, destination: &Path) -> RegistryResult<u64>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustMetadata {
    pub registry_keys: Vec<u8>,
    pub package_trust_root: Vec<u8>,
    pub provenance_bundle: Option<Vec<u8>>,
    pub digest: String,
}

#[async_trait]
pub trait PackageProvenanceVerifier: Send + Sync {
    async fn verify(
        &self,
        identity: &PackageIdentity,
        artifact_digest: &str,
        bundle: &[u8],
        trust_root: &[u8],
    ) -> RegistryResult<Vec<String>>;
}

#[async_trait]
pub trait RegistryAdapter: Send + Sync {
    fn ecosystem(&self) -> PackageEcosystem;

    fn capabilities(&self) -> AdapterCapabilities;

    async fn resolve(
        &self,
        package: &str,
        upstream: &dyn UpstreamClient,
    ) -> RegistryResult<ResolvedMetadata>;

    fn rewrite_metadata(
        &self,
        metadata: &ResolvedMetadata,
        proxy_base_url: &str,
    ) -> RegistryResult<Vec<u8>>;

    async fn fetch_artifact(
        &self,
        descriptor: &ArtifactDescriptor,
        destination: &Path,
        upstream: &dyn UpstreamClient,
    ) -> RegistryResult<u64>;

    async fn fetch_trust_metadata(
        &self,
        descriptor: &ArtifactDescriptor,
        upstream: &dyn UpstreamClient,
    ) -> RegistryResult<TrustMetadata>;

    async fn verify_artifact(
        &self,
        descriptor: &ArtifactDescriptor,
        artifact: &Path,
        trust: &TrustMetadata,
        provenance: &dyn PackageProvenanceVerifier,
    ) -> RegistryResult<VerificationEvidence>;

    fn normalize_manifest(
        &self,
        descriptor: &ArtifactDescriptor,
        artifact: &Path,
    ) -> RegistryResult<NormalizedManifest>;

    fn enumerate_artifact(
        &self,
        descriptor: &ArtifactDescriptor,
        artifact: &Path,
    ) -> RegistryResult<Vec<ArchiveEntry>>;

    fn inspect_risks(
        &self,
        descriptor: &ArtifactDescriptor,
        manifest: &NormalizedManifest,
        entries: &[ArchiveEntry],
        artifact: &Path,
    ) -> RegistryResult<Vec<RawFinding>>;
}
