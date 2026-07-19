//! Versioned audit record persistence.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::fs::{DEFAULT_MAX_FILE_BYTES, PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE, SecureRoot};
use crate::legacy::LEGACY_AUDIT_GENESIS;
use crate::{SecurityError, SecurityResult};

pub const AUDIT_FORMAT_VERSION: u16 = 1;
pub const DEFAULT_MAX_EVENTS: usize = 1_000_000;
pub const MAX_METADATA_ENTRIES: usize = 64;
pub const MAX_METADATA_KEY_BYTES: usize = 128;
pub const MAX_METADATA_VALUE_BYTES: usize = 4 * 1024;
pub const MAX_METADATA_TOTAL_BYTES: usize = 32 * 1024;

const AUDIT_FORMAT: &str = "sendbox-audit";
const CHAIN_DOMAIN: &[u8] = b"sendbox-audit-chain-v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    Command,
    FileAccess,
    Network,
    Permission,
    Secret,
    Lifecycle,
    Policy,
    Mcp,
    Provenance,
    Snapshot,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Allowed,
    Denied,
    Error,
    Success,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub version: u16,
    pub sequence: u64,
    pub session_id: String,
    pub timestamp_unix_nanos: u64,
    pub category: AuditCategory,
    pub action: String,
    pub subject: String,
    pub result: AuditResult,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub event: AuditEvent,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditHeader {
    format: String,
    version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLog {
    session_id: String,
    records: Vec<AuditRecord>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditQuery<'a> {
    pub category: Option<AuditCategory>,
    pub result: Option<AuditResult>,
    pub from_unix_nanos: Option<u64>,
    pub to_unix_nanos: Option<u64>,
    pub action: Option<&'a str>,
}

pub trait AuditRedactor {
    fn redact(&self, event: &AuditEvent) -> AuditEvent;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoRedaction;

impl AuditRedactor for NoRedaction {
    fn redact(&self, event: &AuditEvent) -> AuditEvent {
        event.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProofNode {
    pub hash: String,
    pub sibling_is_left: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: String,
    pub nodes: Vec<MerkleProofNode>,
    pub root_hash: String,
}

impl MerkleProof {
    pub fn verify(&self) -> bool {
        let Ok(mut current) = decode_hash(&self.leaf_hash) else {
            return false;
        };
        current = merkle_leaf(&current);
        for node in &self.nodes {
            let Ok(sibling) = decode_hash(&node.hash) else {
                return false;
            };
            current = if node.sibling_is_left {
                merkle_node(&sibling, &current)
            } else {
                merkle_node(&current, &sibling)
            };
        }
        encode_hash(&current) == self.root_hash
    }
}

impl AuditLog {
    pub fn new(session_id: impl Into<String>) -> SecurityResult<Self> {
        let session_id = session_id.into();
        validate_text("session id", &session_id, 256)?;
        Ok(Self {
            session_id,
            records: Vec::new(),
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn append(
        &mut self,
        timestamp_unix_nanos: u64,
        category: AuditCategory,
        action: impl Into<String>,
        subject: impl Into<String>,
        result: AuditResult,
        metadata: BTreeMap<String, String>,
    ) -> SecurityResult<&AuditRecord> {
        validate_metadata(&metadata)?;
        let action = action.into();
        let subject = subject.into();
        validate_text("action", &action, 512)?;
        validate_text("subject", &subject, 4096)?;
        let sequence =
            u64::try_from(self.records.len()).map_err(|error| SecurityError::Malformed {
                format: AUDIT_FORMAT,
                detail: error.to_string(),
            })?;
        let event = AuditEvent {
            version: AUDIT_FORMAT_VERSION,
            sequence,
            session_id: self.session_id.clone(),
            timestamp_unix_nanos,
            category,
            action,
            subject,
            result,
            metadata,
        };
        let previous_hash = self
            .records
            .last()
            .map_or_else(genesis_hash, |record| record.hash.clone());
        let hash = chain_hash(&previous_hash, &event)?;
        self.records.push(AuditRecord {
            event,
            previous_hash,
            hash,
        });
        self.records.last().ok_or_else(|| SecurityError::Malformed {
            format: AUDIT_FORMAT,
            detail: "append failed".to_owned(),
        })
    }

    pub fn verify(&self) -> SecurityResult<()> {
        if self.records.len() > DEFAULT_MAX_EVENTS {
            return Err(SecurityError::Malformed {
                format: AUDIT_FORMAT,
                detail: "event count exceeds limit".to_owned(),
            });
        }
        let mut previous = genesis_hash();
        for (index, record) in self.records.iter().enumerate() {
            if record.event.version != AUDIT_FORMAT_VERSION {
                return Err(SecurityError::UnsupportedVersion {
                    format: AUDIT_FORMAT,
                    version: record.event.version,
                });
            }
            if record.event.session_id != self.session_id {
                return Err(SecurityError::Integrity(format!(
                    "audit session mismatch at record {index}"
                )));
            }
            if record.event.sequence != index as u64 {
                return Err(SecurityError::Integrity(format!(
                    "audit sequence mismatch at record {index}"
                )));
            }
            validate_metadata(&record.event.metadata)?;
            validate_text("action", &record.event.action, 512)?;
            validate_text("subject", &record.event.subject, 4096)?;
            if record.previous_hash != previous {
                return Err(SecurityError::Integrity(format!(
                    "audit chain reordered or truncated before record {index}"
                )));
            }
            let expected = chain_hash(&previous, &record.event)?;
            if record.hash != expected {
                return Err(SecurityError::Integrity(format!(
                    "audit record {index} hash mismatch"
                )));
            }
            previous = record.hash.clone();
        }
        Ok(())
    }

    pub fn query(&self, query: &AuditQuery<'_>) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|record| {
                query
                    .category
                    .is_none_or(|value| record.event.category == value)
                    && query
                        .result
                        .is_none_or(|value| record.event.result == value)
                    && query
                        .from_unix_nanos
                        .is_none_or(|value| record.event.timestamp_unix_nanos >= value)
                    && query
                        .to_unix_nanos
                        .is_none_or(|value| record.event.timestamp_unix_nanos <= value)
                    && query
                        .action
                        .is_none_or(|value| record.event.action == value)
            })
            .collect()
    }

    pub fn export<R: AuditRedactor>(&self, redactor: &R) -> SecurityResult<Vec<u8>> {
        self.verify()?;
        let events = self
            .records
            .iter()
            .map(|record| redactor.redact(&record.event))
            .collect::<Vec<_>>();
        canonical::encode(&events, "audit export")
    }

    pub fn encode(&self) -> SecurityResult<Vec<u8>> {
        self.verify()?;
        let mut output = canonical::encode(
            &AuditHeader {
                format: AUDIT_FORMAT.to_owned(),
                version: AUDIT_FORMAT_VERSION,
            },
            AUDIT_FORMAT,
        )?;
        output.push(b'\n');
        for record in &self.records {
            output.extend_from_slice(&canonical::encode(record, AUDIT_FORMAT)?);
            output.push(b'\n');
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8], max_events: usize) -> SecurityResult<Self> {
        if bytes.is_empty() || !bytes.ends_with(b"\n") {
            return Err(SecurityError::Integrity(
                "audit log is empty or truncated".to_owned(),
            ));
        }
        let mut lines = bytes.split(|byte| *byte == b'\n');
        let header_bytes = lines.next().unwrap_or_default();
        let header: AuditHeader = canonical::decode_canonical(header_bytes, AUDIT_FORMAT)?;
        if header.format != AUDIT_FORMAT || header.version != AUDIT_FORMAT_VERSION {
            return Err(SecurityError::UnsupportedVersion {
                format: AUDIT_FORMAT,
                version: header.version,
            });
        }
        let mut records = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if records.len() >= max_events {
                return Err(SecurityError::Malformed {
                    format: AUDIT_FORMAT,
                    detail: "event count exceeds limit".to_owned(),
                });
            }
            records.push(canonical::decode_canonical(line, AUDIT_FORMAT)?);
        }
        let session_id = records
            .first()
            .map(|record: &AuditRecord| record.event.session_id.clone())
            .ok_or_else(|| SecurityError::Malformed {
                format: AUDIT_FORMAT,
                detail: "audit log has no records".to_owned(),
            })?;
        let log = Self {
            session_id,
            records,
        };
        log.verify()?;
        Ok(log)
    }

    pub fn merkle_root(&self) -> String {
        merkle_root(self.records.iter().map(|record| record.hash.as_str()))
    }

    pub fn merkle_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.records.len() {
            return None;
        }
        let mut level = self
            .records
            .iter()
            .map(|record| {
                decode_hash(&record.hash)
                    .ok()
                    .map(|hash| merkle_leaf(&hash))
            })
            .collect::<Option<Vec<_>>>()?;
        let mut cursor = index;
        let mut nodes = Vec::new();
        while level.len() > 1 {
            if cursor % 2 == 1 {
                nodes.push(MerkleProofNode {
                    hash: encode_hash(&level[cursor - 1]),
                    sibling_is_left: true,
                });
            } else if cursor + 1 < level.len() {
                nodes.push(MerkleProofNode {
                    hash: encode_hash(&level[cursor + 1]),
                    sibling_is_left: false,
                });
            }
            level = next_merkle_level(&level);
            cursor /= 2;
        }
        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: self.records[index].hash.clone(),
            nodes,
            root_hash: encode_hash(&level[0]),
        })
    }
}

pub struct AuditStore<'a> {
    root: &'a SecureRoot,
    directory: PathBuf,
    max_bytes: u64,
    max_events: usize,
}

impl<'a> AuditStore<'a> {
    pub fn new(root: &'a SecureRoot, directory: impl Into<PathBuf>) -> Self {
        Self {
            root,
            directory: directory.into(),
            max_bytes: DEFAULT_MAX_FILE_BYTES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    pub fn save(&self, log: &AuditLog) -> SecurityResult<()> {
        self.root
            .create_dir_all(&self.directory, PRIVATE_DIRECTORY_MODE)?;
        let _lock = self.root.lock_exclusive(self.lock_path(log.session_id()))?;
        self.root.write_atomic(
            self.log_path(log.session_id()),
            &log.encode()?,
            self.max_bytes,
            PRIVATE_FILE_MODE,
        )
    }

    pub fn load(&self, session_id: &str) -> SecurityResult<AuditLog> {
        let bytes = self
            .root
            .read_bounded(self.log_path(session_id), self.max_bytes)?;
        let log = AuditLog::decode(&bytes, self.max_events)?;
        if log.session_id() != session_id {
            return Err(SecurityError::Integrity(
                "audit filename does not match session".to_owned(),
            ));
        }
        Ok(log)
    }

    pub fn append<F>(&self, session_id: &str, append: F) -> SecurityResult<AuditLog>
    where
        F: FnOnce(&mut AuditLog) -> SecurityResult<()>,
    {
        self.root
            .create_dir_all(&self.directory, PRIVATE_DIRECTORY_MODE)?;
        let _lock = self.root.lock_exclusive(self.lock_path(session_id))?;
        let path = self.log_path(session_id);
        let mut log = match self.root.read_bounded(&path, self.max_bytes) {
            Ok(bytes) => AuditLog::decode(&bytes, self.max_events)?,
            Err(SecurityError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                AuditLog::new(session_id)?
            }
            Err(error) => return Err(error),
        };
        append(&mut log)?;
        self.root
            .write_atomic(path, &log.encode()?, self.max_bytes, PRIVATE_FILE_MODE)?;
        Ok(log)
    }

    fn log_path(&self, session_id: &str) -> PathBuf {
        self.directory.join(format!("{session_id}.audit.jsonl"))
    }

    fn lock_path(&self, session_id: &str) -> PathBuf {
        self.directory.join(format!("{session_id}.lock"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct LegacyAuditEntry {
    pub id: String,
    pub timestamp: String,
    #[serde(rename = "session_id")]
    pub session_id: String,
    pub category: String,
    pub action: String,
    pub subject: String,
    pub outcome: String,
    pub details: Option<BTreeMap<String, String>>,
    pub hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct LegacySwiftMerkleTree {
    pub root_hash: String,
    pub leaf_count: usize,
    pub nodes: Vec<String>,
}

pub fn decode_legacy_swift_entries(
    bytes: &[u8],
    max_bytes: u64,
    max_events: usize,
) -> SecurityResult<Vec<LegacyAuditEntry>> {
    if bytes.len() as u64 > max_bytes {
        return Err(SecurityError::SizeLimit {
            path: PathBuf::from("legacy entries.json"),
            limit: max_bytes,
        });
    }
    let entries: Vec<LegacyAuditEntry> =
        serde_json::from_slice(bytes).map_err(|error| SecurityError::Malformed {
            format: "swift-audit-v1",
            detail: error.to_string(),
        })?;
    if entries.len() > max_events {
        return Err(SecurityError::Malformed {
            format: "swift-audit-v1",
            detail: "event count exceeds limit".to_owned(),
        });
    }
    let mut previous = LEGACY_AUDIT_GENESIS.to_owned();
    let mut session = None;
    for (index, entry) in entries.iter().enumerate() {
        time::OffsetDateTime::parse(
            &entry.timestamp,
            &time::format_description::well_known::Iso8601::DEFAULT,
        )
        .map_err(|error| SecurityError::Malformed {
            format: "swift-audit-v1",
            detail: error.to_string(),
        })?;
        if let Some(details) = &entry.details {
            validate_metadata(details)?;
        }
        if session.get_or_insert_with(|| entry.session_id.clone()) != &entry.session_id {
            return Err(SecurityError::Integrity(format!(
                "legacy audit session mismatch at {index}"
            )));
        }
        let details = entry
            .details
            .as_ref()
            .map(|details| {
                details
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let content = [
            entry.id.as_str(),
            entry.timestamp.as_str(),
            entry.session_id.as_str(),
            entry.category.as_str(),
            entry.action.as_str(),
            entry.subject.as_str(),
            entry.outcome.as_str(),
            details.as_str(),
        ]
        .join("|");
        let expected =
            encode_hash(&Sha256::digest([previous.as_bytes(), content.as_bytes()].concat()).into());
        if entry.hash != expected {
            return Err(SecurityError::Integrity(format!(
                "legacy audit record {index} hash mismatch"
            )));
        }
        previous = entry.hash.clone();
    }
    Ok(entries)
}

pub fn decode_legacy_swift_tree(
    bytes: &[u8],
    entries: &[LegacyAuditEntry],
    max_bytes: u64,
) -> SecurityResult<LegacySwiftMerkleTree> {
    if bytes.len() as u64 > max_bytes {
        return Err(SecurityError::SizeLimit {
            path: PathBuf::from("legacy tree.json"),
            limit: max_bytes,
        });
    }
    let tree: LegacySwiftMerkleTree =
        serde_json::from_slice(bytes).map_err(|error| SecurityError::Malformed {
            format: "swift-audit-tree-v1",
            detail: error.to_string(),
        })?;
    if tree.leaf_count != entries.len() {
        return Err(SecurityError::Integrity(
            "legacy Merkle leaf count mismatch".to_owned(),
        ));
    }
    let expected = legacy_merkle_tree(entries.iter().map(|entry| entry.hash.as_str()));
    if tree != expected {
        return Err(SecurityError::Integrity(
            "legacy Merkle tree mismatch".to_owned(),
        ));
    }
    Ok(tree)
}

fn chain_hash(previous_hash: &str, event: &AuditEvent) -> SecurityResult<String> {
    let previous = decode_hash(previous_hash)?;
    let encoded = canonical::encode(event, AUDIT_FORMAT)?;
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_DOMAIN);
    hasher.update(previous);
    hasher.update(encoded);
    Ok(encode_hash(&hasher.finalize().into()))
}

fn genesis_hash() -> String {
    encode_hash(&Sha256::digest(b"sendbox-audit-genesis-v1").into())
}

fn merkle_root<'a>(hashes: impl Iterator<Item = &'a str>) -> String {
    let mut level = hashes
        .filter_map(|hash| decode_hash(hash).ok())
        .map(|hash| merkle_leaf(&hash))
        .collect::<Vec<_>>();
    if level.is_empty() {
        return encode_hash(&Sha256::digest(b"sendbox-audit-empty-merkle-v1").into());
    }
    while level.len() > 1 {
        level = next_merkle_level(&level);
    }
    encode_hash(&level[0])
}

fn next_merkle_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    level
        .chunks(2)
        .map(|pair| {
            if pair.len() == 2 {
                merkle_node(&pair[0], &pair[1])
            } else {
                pair[0]
            }
        })
        .collect()
}

fn legacy_merkle_tree<'a>(hashes: impl Iterator<Item = &'a str>) -> LegacySwiftMerkleTree {
    let leaves = hashes.map(str::to_owned).collect::<Vec<_>>();
    if leaves.is_empty() {
        return LegacySwiftMerkleTree {
            root_hash: String::new(),
            leaf_count: 0,
            nodes: Vec::new(),
        };
    }
    let target = leaves.len().next_power_of_two();
    let mut padded = leaves.clone();
    while padded.len() < target {
        if let Some(last) = padded.last().cloned() {
            padded.push(last);
        }
    }
    let mut nodes = vec![String::new(); target * 2 - 1];
    let leaf_start = target - 1;
    for (index, hash) in padded.into_iter().enumerate() {
        nodes[leaf_start + index] = hash;
    }
    for index in (0..leaf_start).rev() {
        nodes[index] = encode_hash(
            &Sha256::digest(
                [
                    nodes[index * 2 + 1].as_bytes(),
                    nodes[index * 2 + 2].as_bytes(),
                ]
                .concat(),
            )
            .into(),
        );
    }
    LegacySwiftMerkleTree {
        root_hash: nodes[0].clone(),
        leaf_count: leaves.len(),
        nodes,
    }
}

fn merkle_leaf(hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0_u8]);
    hasher.update(hash);
    hasher.finalize().into()
}

fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1_u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn validate_metadata(metadata: &BTreeMap<String, String>) -> SecurityResult<()> {
    if metadata.len() > MAX_METADATA_ENTRIES {
        return Err(SecurityError::Malformed {
            format: AUDIT_FORMAT,
            detail: "metadata entry count exceeds limit".to_owned(),
        });
    }
    let mut total = 0;
    for (key, value) in metadata {
        validate_text("metadata key", key, MAX_METADATA_KEY_BYTES)?;
        validate_text("metadata value", value, MAX_METADATA_VALUE_BYTES)?;
        total += key.len() + value.len();
    }
    if total > MAX_METADATA_TOTAL_BYTES {
        return Err(SecurityError::Malformed {
            format: AUDIT_FORMAT,
            detail: "metadata total size exceeds limit".to_owned(),
        });
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, max: usize) -> SecurityResult<()> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(SecurityError::Malformed {
            format: AUDIT_FORMAT,
            detail: format!("{label} is empty, oversized, or contains NUL"),
        });
    }
    Ok(())
}

pub(crate) fn encode_hash(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn decode_hash(value: &str) -> SecurityResult<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SecurityError::Malformed {
            format: "sha256",
            detail: "expected 64 hexadecimal characters".to_owned(),
        });
    }
    let mut result = [0_u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|error| {
            SecurityError::Malformed {
                format: "sha256",
                detail: error.to_string(),
            }
        })?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_log() -> AuditLog {
        let mut log = AuditLog::new("session-1").expect("create log");
        for index in 0..5 {
            log.append(
                100 + index,
                AuditCategory::Command,
                "execute",
                format!("command-{index}"),
                AuditResult::Allowed,
                BTreeMap::from([("cwd".to_owned(), "/workspace".to_owned())]),
            )
            .expect("append");
        }
        log
    }

    #[test]
    fn canonical_roundtrip_and_merkle_proofs() {
        let log = sample_log();
        let bytes = log.encode().expect("encode");
        let decoded = AuditLog::decode(&bytes, 10).expect("decode");
        assert_eq!(decoded, log);
        for index in 0..log.records().len() {
            let proof = log.merkle_proof(index).expect("proof");
            assert!(proof.verify());
            assert_eq!(proof.root_hash, log.merkle_root());
        }
    }

    #[test]
    fn detects_corruption_truncation_reordering_and_replay() {
        let log = sample_log();
        let mut corrupted = log.clone();
        corrupted.records[1].event.action = "changed".to_owned();
        assert!(corrupted.verify().is_err());

        let bytes = log.encode().expect("encode");
        assert!(AuditLog::decode(&bytes[..bytes.len() - 1], 10).is_err());

        let mut reordered = log.clone();
        reordered.records.swap(1, 2);
        assert!(reordered.verify().is_err());

        let mut replayed = log.clone();
        replayed.records.push(replayed.records[4].clone());
        assert!(replayed.verify().is_err());
    }

    #[test]
    fn metadata_limits_are_enforced() {
        let mut log = AuditLog::new("session").expect("create log");
        let metadata =
            BTreeMap::from([("key".to_owned(), "x".repeat(MAX_METADATA_VALUE_BYTES + 1))]);
        assert!(
            log.append(
                1,
                AuditCategory::Lifecycle,
                "start",
                "sandbox",
                AuditResult::Success,
                metadata
            )
            .is_err()
        );
    }

    #[test]
    fn redaction_does_not_change_committed_log() {
        struct Redact;
        impl AuditRedactor for Redact {
            fn redact(&self, event: &AuditEvent) -> AuditEvent {
                let mut copy = event.clone();
                copy.metadata.clear();
                copy
            }
        }

        let log = sample_log();
        let head = log.records().last().expect("head").hash.clone();
        let exported = log.export(&Redact).expect("export");
        assert!(
            !String::from_utf8(exported)
                .expect("utf8")
                .contains("/workspace")
        );
        assert_eq!(head, log.records().last().expect("head").hash);
        log.verify().expect("verify after export");
    }
}
