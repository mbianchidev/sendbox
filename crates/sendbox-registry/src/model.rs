use std::collections::BTreeMap;

use sendbox_policy::PackageEcosystem;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("invalid package request: {0}")]
    Invalid(String),
    #[error("upstream registry request failed: {0}")]
    Upstream(String),
    #[error("package verification failed: {0}")]
    Verification(String),
    #[error("package inspection failed: {0}")]
    Inspection(String),
    #[error("package cache failed: {0}")]
    Cache(String),
    #[error("package operation timed out: {0}")]
    Timeout(String),
    #[error("unsupported package content: {0}")]
    Unsupported(String),
}

pub type RegistryResult<T> = Result<T, RegistryError>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    pub ecosystem: PackageEcosystem,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityClaim {
    pub algorithm: IntegrityAlgorithm,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub algorithm: String,
    pub hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    pub identity: PackageIdentity,
    pub source_url: String,
    pub integrity: Vec<IntegrityClaim>,
    pub metadata_revision: String,
    pub signatures_present: bool,
    pub provenance_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedMetadata {
    pub content_type: String,
    pub body: Vec<u8>,
    pub artifacts: Vec<ArtifactDescriptor>,
    pub revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedManifest {
    pub identity: PackageIdentity,
    pub scripts: BTreeMap<String, String>,
    pub executable_paths: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveEntryKind {
    File,
    Directory,
    Symlink,
    Hardlink,
    CharacterDevice,
    BlockDevice,
    Fifo,
    Sparse,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveEntry {
    pub path: String,
    pub kind: ArchiveEntryKind,
    pub size: u64,
    pub mode: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationEvidence {
    pub artifact_digest: ArtifactDigest,
    pub verified_integrity: Vec<String>,
    pub signature_key_ids: Vec<String>,
    pub provenance_subjects: Vec<String>,
    pub trust_metadata_digest: String,
}
