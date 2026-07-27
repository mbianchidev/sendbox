//! Bounded, dry-run-only inspection of legacy security artifacts.

use std::collections::BTreeSet;

use sendbox_secrets::{RecordVersion, SecretStore};
use sendbox_security::audit::{
    LegacyAuditEntry, decode_legacy_swift_entries, decode_legacy_swift_tree,
};
use sendbox_security::provenance::{
    LegacySwiftSignature, LegacySwiftTrustStore, decode_legacy_swift_trust_store,
};
use sendbox_security::snapshot::{LegacySwiftSnapshot, decode_legacy_swift_manifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;

const AUTHORIZATION_DOMAIN: &[u8] = b"sendbox-session-security-migration-authorization-v1\0";
const MAX_HARD_BYTES: usize = 64 * 1024 * 1024;
const MAX_HARD_ITEMS: usize = 100_000;
const MAX_HARD_STRING_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationLimits {
    pub max_bytes: usize,
    pub max_items: usize,
    pub max_string_bytes: usize,
}

impl Default for MigrationLimits {
    fn default() -> Self {
        Self {
            max_bytes: 16 * 1024 * 1024,
            max_items: 10_000,
            max_string_bytes: 4096,
        }
    }
}

impl MigrationLimits {
    fn validate(&self) -> Result<(), MigrationError> {
        if self.max_bytes == 0
            || self.max_bytes > MAX_HARD_BYTES
            || self.max_items == 0
            || self.max_items > MAX_HARD_ITEMS
            || self.max_string_bytes == 0
            || self.max_string_bytes > MAX_HARD_STRING_BYTES
        {
            return Err(MigrationError::InvalidLimits);
        }
        Ok(())
    }

    fn check_bytes(&self, bytes: &[u8]) -> Result<(), MigrationError> {
        self.validate()?;
        if bytes.len() > self.max_bytes {
            return Err(MigrationError::Bounds(format!(
                "input has {} bytes; maximum is {}",
                bytes.len(),
                self.max_bytes
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationSourceKind {
    LegacyAudit,
    LegacySnapshot,
    SwiftTrustStore,
    LegacyProvenanceSignature,
    SecretMetadata,
    SwiftCodableGrants,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionImpact {
    None,
    Equivalent,
    Restricting,
    Broadening,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationFinding {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReport {
    pub source_kind: MigrationSourceKind,
    pub source_version: String,
    pub item_count: usize,
    pub findings: Vec<MigrationFinding>,
    pub permission_impact: PermissionImpact,
    pub authorization_required: bool,
    pub conversion_available: bool,
    pub observational_only: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MigrationAuthorization {
    token: String,
}

impl std::fmt::Debug for MigrationAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MigrationAuthorization")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl MigrationAuthorization {
    pub fn from_report(report: &MigrationReport) -> Result<Self, MigrationError> {
        let encoded = serde_json::to_vec(report)
            .map_err(|error| MigrationError::Malformed(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(AUTHORIZATION_DOMAIN);
        hasher.update(encoded);
        Ok(Self {
            token: hex_encode(&hasher.finalize()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrationProposalAction {
    ImportAuditRecords { count: usize },
    ImportSnapshotManifest { entries: usize },
    ImportTrustedIdentities { count: usize },
    ImportPermissionGrants { count: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationProposal {
    pub source_kind: MigrationSourceKind,
    pub source_version: String,
    pub item_count: usize,
    pub actions: Vec<MigrationProposalAction>,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum MigrationError {
    #[error("invalid migration limits")]
    InvalidLimits,
    #[error("migration input exceeds bounds: {0}")]
    Bounds(String),
    #[error("malformed migration input: {0}")]
    Malformed(String),
    #[error("legacy security verification failed: {0}")]
    Verification(String),
    #[error("secret metadata inspection failed: {0}")]
    SecretStore(String),
    #[error("migration authorization does not match the dry-run report")]
    Unauthorized,
    #[error("permission-broadening conversion requires explicit acknowledgement")]
    BroadeningAcknowledgementRequired,
    #[error("conversion is not available for this report")]
    ConversionUnavailable,
}

pub fn inspect_legacy_audit(
    entries_bytes: &[u8],
    tree_bytes: Option<&[u8]>,
    limits: &MigrationLimits,
) -> Result<(MigrationReport, Vec<LegacyAuditEntry>), MigrationError> {
    limits.check_bytes(entries_bytes)?;
    if let Some(tree) = tree_bytes {
        limits.check_bytes(tree)?;
    }
    let entries =
        decode_legacy_swift_entries(entries_bytes, limits.max_bytes as u64, limits.max_items)
            .map_err(|error| MigrationError::Verification(error.to_string()))?;
    if let Some(tree) = tree_bytes {
        decode_legacy_swift_tree(tree, &entries, limits.max_bytes as u64)
            .map_err(|error| MigrationError::Verification(error.to_string()))?;
    }
    let mut findings = Vec::new();
    if tree_bytes.is_none() {
        findings.push(finding(
            "merkle_tree_absent",
            "entries are chain-verified, but no legacy Merkle tree was supplied",
        ));
    }
    Ok((
        report(
            MigrationSourceKind::LegacyAudit,
            "swift-audit-v1",
            entries.len(),
            findings,
            PermissionImpact::None,
            true,
            false,
        ),
        entries,
    ))
}

pub fn inspect_legacy_snapshot(
    bytes: &[u8],
    limits: &MigrationLimits,
) -> Result<(MigrationReport, LegacySwiftSnapshot), MigrationError> {
    limits.check_bytes(bytes)?;
    let snapshot = decode_legacy_swift_manifest(bytes, limits.max_bytes as u64, limits.max_items)
        .map_err(|error| MigrationError::Verification(error.to_string()))?;
    let findings = if snapshot.files.is_empty() {
        vec![finding(
            "empty_snapshot",
            "legacy snapshot contains no file entries",
        )]
    } else {
        Vec::new()
    };
    Ok((
        report(
            MigrationSourceKind::LegacySnapshot,
            "swift-snapshot-v1",
            snapshot.files.len(),
            findings,
            PermissionImpact::None,
            true,
            false,
        ),
        snapshot,
    ))
}

pub fn inspect_swift_trust_store(
    bytes: &[u8],
    limits: &MigrationLimits,
) -> Result<(MigrationReport, LegacySwiftTrustStore), MigrationError> {
    limits.check_bytes(bytes)?;
    let store = decode_legacy_swift_trust_store(bytes, limits.max_bytes as u64)
        .map_err(|error| MigrationError::Verification(error.to_string()))?;
    if store.identities.len() > limits.max_items {
        return Err(MigrationError::Bounds(
            "trusted identity count exceeds limit".to_owned(),
        ));
    }
    let impact = if !store.require_signature || store.minimum_signers == 0 {
        PermissionImpact::Broadening
    } else {
        PermissionImpact::Equivalent
    };
    let mut findings = Vec::new();
    if !store.require_signature {
        findings.push(finding(
            "signature_not_required",
            "legacy trust policy permits unsigned content",
        ));
    }
    Ok((
        report(
            MigrationSourceKind::SwiftTrustStore,
            "swift-provenance-v1",
            store.identities.len(),
            findings,
            impact,
            true,
            false,
        ),
        store,
    ))
}

pub fn inspect_legacy_provenance_signature(
    bytes: &[u8],
    limits: &MigrationLimits,
) -> Result<(MigrationReport, LegacySwiftSignature), MigrationError> {
    limits.check_bytes(bytes)?;
    let signature: StrictLegacySwiftSignature = serde_json::from_slice(bytes)
        .map_err(|error| MigrationError::Malformed(error.to_string()))?;
    signature.validate(limits)?;
    let legacy: LegacySwiftSignature = serde_json::from_slice(bytes)
        .map_err(|error| MigrationError::Malformed(error.to_string()))?;
    Ok((
        report(
            MigrationSourceKind::LegacyProvenanceSignature,
            "swift-provenance-v1",
            1,
            vec![finding(
                "cryptographic_verification_deferred",
                "structure is valid; verification still requires caller-supplied content and key",
            )],
            PermissionImpact::Unknown,
            false,
            false,
        ),
        legacy,
    ))
}

pub fn inspect_secret_metadata(
    store: &dyn SecretStore,
    limits: &MigrationLimits,
) -> Result<MigrationReport, MigrationError> {
    limits.validate()?;
    let mut metadata = store
        .list()
        .map_err(|error| MigrationError::SecretStore(error.to_string()))?;
    if metadata.len() > limits.max_items {
        return Err(MigrationError::Bounds(
            "secret metadata count exceeds limit".to_owned(),
        ));
    }
    metadata.sort_by(|left, right| left.name.cmp(&right.name));
    let legacy_count = metadata
        .iter()
        .filter(|item| item.version == RecordVersion::SwiftLegacy)
        .count();
    for item in &metadata {
        if item.name.as_str().len() > limits.max_string_bytes {
            return Err(MigrationError::Bounds(
                "secret name exceeds migration string limit".to_owned(),
            ));
        }
    }
    let findings = if legacy_count == 0 {
        vec![finding(
            "no_legacy_records",
            "all listed secret records already use the current format",
        )]
    } else {
        vec![finding(
            "legacy_records_present",
            &format!("{legacy_count} secret records require store-managed migration"),
        )]
    };
    Ok(report(
        MigrationSourceKind::SecretMetadata,
        "secret-record-metadata",
        metadata.len(),
        findings,
        PermissionImpact::None,
        false,
        false,
    ))
}

pub fn inspect_swift_codable_grants(
    bytes: &[u8],
    limits: &MigrationLimits,
) -> Result<(MigrationReport, SwiftCodableGrantStore), MigrationError> {
    limits.check_bytes(bytes)?;
    let input: SwiftGrantInput = serde_json::from_slice(bytes)
        .map_err(|error| MigrationError::Malformed(error.to_string()))?;
    let grants = match input {
        SwiftGrantInput::Versioned(grants) => grants,
        SwiftGrantInput::Array(grants) => SwiftCodableGrantStore { version: 1, grants },
    };
    if grants.version != 1 {
        return Err(MigrationError::Malformed(
            "unsupported Swift grant version".to_owned(),
        ));
    }
    if grants.grants.len() > limits.max_items {
        return Err(MigrationError::Bounds(
            "Swift grant count exceeds limit".to_owned(),
        ));
    }
    let mut identities = BTreeSet::new();
    for grant in &grants.grants {
        grant.validate(limits)?;
        if let Some(id) = &grant.id
            && !identities.insert(id.clone())
        {
            return Err(MigrationError::Malformed(
                "duplicate Swift grant ID".to_owned(),
            ));
        }
    }
    let impact = if grants.grants.is_empty() {
        PermissionImpact::None
    } else {
        PermissionImpact::Broadening
    };
    Ok((
        report(
            MigrationSourceKind::SwiftCodableGrants,
            "swift-codable-grants-v1",
            grants.grants.len(),
            vec![finding(
                "observational_import_only",
                "this reader observes caller-supplied Codable data; no persisted Swift grant store is assumed",
            )],
            impact,
            true,
            true,
        ),
        grants,
    ))
}

pub fn propose_conversion(
    report: &MigrationReport,
    authorization: &MigrationAuthorization,
    acknowledge_permission_broadening: bool,
) -> Result<MigrationProposal, MigrationError> {
    if !report.conversion_available {
        return Err(MigrationError::ConversionUnavailable);
    }
    let expected = MigrationAuthorization::from_report(report)?;
    if expected.token != authorization.token {
        return Err(MigrationError::Unauthorized);
    }
    if report.permission_impact == PermissionImpact::Broadening
        && !acknowledge_permission_broadening
    {
        return Err(MigrationError::BroadeningAcknowledgementRequired);
    }
    let action = match report.source_kind {
        MigrationSourceKind::LegacyAudit => MigrationProposalAction::ImportAuditRecords {
            count: report.item_count,
        },
        MigrationSourceKind::LegacySnapshot => MigrationProposalAction::ImportSnapshotManifest {
            entries: report.item_count,
        },
        MigrationSourceKind::SwiftTrustStore => MigrationProposalAction::ImportTrustedIdentities {
            count: report.item_count,
        },
        MigrationSourceKind::SwiftCodableGrants => {
            MigrationProposalAction::ImportPermissionGrants {
                count: report.item_count,
            }
        }
        MigrationSourceKind::LegacyProvenanceSignature | MigrationSourceKind::SecretMetadata => {
            return Err(MigrationError::ConversionUnavailable);
        }
    };
    Ok(MigrationProposal {
        source_kind: report.source_kind,
        source_version: report.source_version.clone(),
        item_count: report.item_count,
        actions: vec![action],
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct StrictLegacySwiftSignature {
    #[serde(rename = "fileHash")]
    file_hash: String,
    signature: String,
    #[serde(rename = "signerFingerprint")]
    signer_fingerprint: String,
    timestamp: String,
    metadata: Option<StrictLegacySignatureMetadata>,
}

impl StrictLegacySwiftSignature {
    fn validate(&self, limits: &MigrationLimits) -> Result<(), MigrationError> {
        for value in [
            self.file_hash.as_str(),
            self.signature.as_str(),
            self.signer_fingerprint.as_str(),
            self.timestamp.as_str(),
        ] {
            validate_string(value, limits)?;
        }
        validate_sha256(&self.file_hash)?;
        OffsetDateTime::parse(&self.timestamp, &Iso8601::DEFAULT)
            .map_err(|error| MigrationError::Malformed(error.to_string()))?;
        if let Some(metadata) = &self.metadata {
            validate_string(&metadata.tool_version, limits)?;
            validate_string(&metadata.purpose, limits)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct StrictLegacySignatureMetadata {
    #[serde(rename = "toolVersion")]
    tool_version: String,
    purpose: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SwiftCodableGrantStore {
    pub version: u16,
    pub grants: Vec<SwiftCodableGrant>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SwiftGrantInput {
    Versioned(SwiftCodableGrantStore),
    Array(Vec<SwiftCodableGrant>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SwiftCodableGrant {
    #[serde(default)]
    pub id: Option<String>,
    pub category: String,
    pub pattern: String,
    #[serde(default, rename = "grantedAt")]
    pub granted_at: Option<serde_json::Value>,
    #[serde(default, rename = "expiresAt")]
    pub expires_at: Option<serde_json::Value>,
    #[serde(default, rename = "usesRemaining")]
    pub uses_remaining: Option<u32>,
    #[serde(default, rename = "grantType")]
    pub grant_type: Option<String>,
    #[serde(default)]
    #[serde(rename = "expiresAtUnixMs")]
    pub expires_at_unix_ms: Option<u64>,
    #[serde(default)]
    #[serde(rename = "maxUses")]
    pub max_uses: Option<u32>,
}

impl SwiftCodableGrant {
    fn validate(&self, limits: &MigrationLimits) -> Result<(), MigrationError> {
        if let Some(id) = &self.id {
            validate_string(id, limits)?;
        }
        validate_string(&self.category, limits)?;
        validate_string(&self.pattern, limits)?;
        if !matches!(
            self.category.as_str(),
            "command"
                | "network"
                | "fileWrite"
                | "secretAccess"
                | "systemCall"
                | "file_write"
                | "secret_access"
                | "system_call"
        ) {
            return Err(MigrationError::Malformed(
                "unknown Swift permission category".to_owned(),
            ));
        }
        if self
            .grant_type
            .as_ref()
            .is_some_and(|kind| !matches!(kind.as_str(), "once" | "session" | "pattern"))
        {
            return Err(MigrationError::Malformed(
                "unknown Swift grant type".to_owned(),
            ));
        }
        if let Some(date) = &self.granted_at {
            validate_swift_date(date, limits)?;
        }
        if let Some(date) = &self.expires_at {
            validate_swift_date(date, limits)?;
        }
        if self.max_uses.is_some() && self.uses_remaining.is_some() {
            return Err(MigrationError::Malformed(
                "Swift grant has conflicting use-count fields".to_owned(),
            ));
        }
        if self.max_uses == Some(0) || self.uses_remaining == Some(0) {
            return Err(MigrationError::Malformed(
                "Swift grant use count must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

fn report(
    source_kind: MigrationSourceKind,
    source_version: &str,
    item_count: usize,
    findings: Vec<MigrationFinding>,
    permission_impact: PermissionImpact,
    conversion_available: bool,
    observational_only: bool,
) -> MigrationReport {
    MigrationReport {
        source_kind,
        source_version: source_version.to_owned(),
        item_count,
        findings,
        permission_impact,
        authorization_required: conversion_available,
        conversion_available,
        observational_only,
    }
}

fn finding(code: &str, message: &str) -> MigrationFinding {
    MigrationFinding {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

fn validate_string(value: &str, limits: &MigrationLimits) -> Result<(), MigrationError> {
    if value.is_empty()
        || value.len() > limits.max_string_bytes
        || value.chars().any(char::is_control)
    {
        return Err(MigrationError::Bounds(
            "legacy string is empty, too long, or contains controls".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), MigrationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MigrationError::Malformed(
            "expected lowercase SHA-256 hexadecimal".to_owned(),
        ));
    }

    Ok(())
}

fn validate_swift_date(
    value: &serde_json::Value,
    limits: &MigrationLimits,
) -> Result<(), MigrationError> {
    match value {
        serde_json::Value::Number(number) if number.as_f64().is_some_and(f64::is_finite) => Ok(()),
        serde_json::Value::String(text) => validate_string(text, limits),
        _ => Err(MigrationError::Malformed(
            "Swift Codable date must be a finite number or nonempty string".to_owned(),
        )),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
