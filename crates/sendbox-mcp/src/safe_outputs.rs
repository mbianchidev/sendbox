use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sendbox_config::{
    AddCommentSafeOutputConfiguration, CreateIssueSafeOutputConfiguration,
    CreatePullRequestSafeOutputConfiguration, LabelSafeOutputConfiguration,
    SAFE_OUTPUTS_MAX_ARTIFACT_BYTES, SafeOutputsConfiguration,
};
use sendbox_core::{BoundaryPlanDigest, SessionId, glob_matches};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use url::Url;

use crate::jsonrpc::{IdPresence, MessageKind, validate_message};

pub const SAFE_OUTPUTS_SCHEMA_VERSION: u32 = 1;
pub const SAFE_OUTPUTS_MCP_PATH: &str = "/run/sendbox-boundary/safe-outputs-mcp";
pub const SAFE_OUTPUTS_RUNTIME_ROOT: &str = "/run/sendbox-safe-outputs";
pub const MAX_SAFE_OUTPUTS_FRAME_BYTES: usize = 96 * 1024;
pub const MAX_SAFE_OUTPUTS_SEAL_BYTES: usize = 4 * 1024;

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_TITLE_CHARS: usize = 256;
const MIN_ISSUE_BODY_CHARS: usize = 20;
const MAX_BODY_CHARS: usize = 65_000;
const MAX_META_CHARS: usize = 4_096;
const MAX_SYSTEM_OPERATIONS: u32 = 100;
const SEAL_KEY_INFO: &[u8] = b"sendbox-safe-outputs-seal-v1";
const REDACTED: &str = "[REDACTED]";
const BLOCKED_URL: &str = "[blocked-url]";
const NEUTRALIZED_PREFIX: &str = "[sendbox neutralized] ";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeOutputTool {
    CreateIssue,
    AddComment,
    CreatePullRequest,
    AddLabels,
    RemoveLabels,
    Noop,
    MissingTool,
    MissingData,
    ReportIncomplete,
}

impl SafeOutputTool {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CreateIssue => "create_issue",
            Self::AddComment => "add_comment",
            Self::CreatePullRequest => "create_pull_request",
            Self::AddLabels => "add_labels",
            Self::RemoveLabels => "remove_labels",
            Self::Noop => "noop",
            Self::MissingTool => "missing_tool",
            Self::MissingData => "missing_data",
            Self::ReportIncomplete => "report_incomplete",
        }
    }

    #[must_use]
    pub const fn is_system(self) -> bool {
        matches!(
            self,
            Self::Noop | Self::MissingTool | Self::MissingData | Self::ReportIncomplete
        )
    }

    pub fn parse(name: &str) -> Result<Self, SafeOutputsError> {
        match name {
            "create_issue" => Ok(Self::CreateIssue),
            "add_comment" => Ok(Self::AddComment),
            "create_pull_request" => Ok(Self::CreatePullRequest),
            "add_labels" => Ok(Self::AddLabels),
            "remove_labels" => Ok(Self::RemoveLabels),
            "noop" => Ok(Self::Noop),
            "missing_tool" => Ok(Self::MissingTool),
            "missing_data" => Ok(Self::MissingData),
            "report_incomplete" => Ok(Self::ReportIncomplete),
            _ => Err(SafeOutputsError::UnsupportedTool(name.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeOutputsRuntimePolicy {
    pub schema_version: u32,
    pub session_id: SessionId,
    pub writer_socket: PathBuf,
    pub max_artifact_bytes: usize,
    pub allowed_repositories: BTreeSet<String>,
    pub allowed_domains: BTreeSet<String>,
    pub allowed_mentions: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_issue: Option<CreateIssueSafeOutputConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_comment: Option<AddCommentSafeOutputConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_pull_request: Option<CreatePullRequestSafeOutputConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_labels: Option<LabelSafeOutputConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_labels: Option<LabelSafeOutputConfiguration>,
}

impl SafeOutputsRuntimePolicy {
    pub fn from_configuration(
        session_id: SessionId,
        configuration: &SafeOutputsConfiguration,
    ) -> Result<Self, SafeOutputsError> {
        if !configuration.enabled {
            return Err(SafeOutputsError::Policy(
                "Safe Outputs runtime policy requires an enabled configuration".to_owned(),
            ));
        }
        let runtime_root = PathBuf::from(SAFE_OUTPUTS_RUNTIME_ROOT).join(session_id.to_string());
        let policy = Self {
            schema_version: SAFE_OUTPUTS_SCHEMA_VERSION,
            session_id,
            writer_socket: runtime_root.join("writer.sock"),
            max_artifact_bytes: configuration.max_artifact_bytes,
            allowed_repositories: configuration.allowed_repositories.iter().cloned().collect(),
            allowed_domains: configuration.allowed_domains.iter().cloned().collect(),
            allowed_mentions: configuration.allowed_mentions.iter().cloned().collect(),
            create_issue: configuration
                .create_issue
                .enabled
                .then(|| configuration.create_issue.clone()),
            add_comment: configuration
                .add_comment
                .enabled
                .then(|| configuration.add_comment.clone()),
            create_pull_request: configuration
                .create_pull_request
                .enabled
                .then(|| configuration.create_pull_request.clone()),
            add_labels: configuration
                .add_labels
                .enabled
                .then(|| configuration.add_labels.clone()),
            remove_labels: configuration
                .remove_labels
                .enabled
                .then(|| configuration.remove_labels.clone()),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), SafeOutputsError> {
        if self.schema_version != SAFE_OUTPUTS_SCHEMA_VERSION {
            return Err(SafeOutputsError::Policy(format!(
                "unsupported Safe Outputs runtime schema version {}",
                self.schema_version
            )));
        }
        if self.max_artifact_bytes == 0 || self.max_artifact_bytes > SAFE_OUTPUTS_MAX_ARTIFACT_BYTES
        {
            return Err(SafeOutputsError::Policy(format!(
                "Safe Outputs artifact limit must be between 1 and {SAFE_OUTPUTS_MAX_ARTIFACT_BYTES}"
            )));
        }
        let expected_root =
            PathBuf::from(SAFE_OUTPUTS_RUNTIME_ROOT).join(self.session_id.to_string());
        if self.writer_socket != expected_root.join("writer.sock")
            || !normalized_absolute(&self.writer_socket)
        {
            return Err(SafeOutputsError::Policy(
                "Safe Outputs writer socket does not match the authenticated session".to_owned(),
            ));
        }
        if self.has_write_tools() && self.allowed_repositories.is_empty() {
            return Err(SafeOutputsError::Policy(
                "Safe Outputs write tools require at least one allowed repository".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn has_write_tools(&self) -> bool {
        self.create_issue.is_some()
            || self.add_comment.is_some()
            || self.create_pull_request.is_some()
            || self.add_labels.is_some()
            || self.remove_labels.is_some()
    }

    #[must_use]
    pub fn enabled_tools(&self) -> Vec<SafeOutputTool> {
        let mut tools = Vec::new();
        if self.create_issue.is_some() {
            tools.push(SafeOutputTool::CreateIssue);
        }
        if self.add_comment.is_some() {
            tools.push(SafeOutputTool::AddComment);
        }
        if self.create_pull_request.is_some() {
            tools.push(SafeOutputTool::CreatePullRequest);
        }
        if self.add_labels.is_some() {
            tools.push(SafeOutputTool::AddLabels);
        }
        if self.remove_labels.is_some() {
            tools.push(SafeOutputTool::RemoveLabels);
        }
        tools.extend([
            SafeOutputTool::Noop,
            SafeOutputTool::MissingTool,
            SafeOutputTool::MissingData,
            SafeOutputTool::ReportIncomplete,
        ]);
        tools
    }

    #[must_use]
    pub fn permits(&self, tool: SafeOutputTool) -> bool {
        tool.is_system()
            || match tool {
                SafeOutputTool::CreateIssue => self.create_issue.is_some(),
                SafeOutputTool::AddComment => self.add_comment.is_some(),
                SafeOutputTool::CreatePullRequest => self.create_pull_request.is_some(),
                SafeOutputTool::AddLabels => self.add_labels.is_some(),
                SafeOutputTool::RemoveLabels => self.remove_labels.is_some(),
                SafeOutputTool::Noop
                | SafeOutputTool::MissingTool
                | SafeOutputTool::MissingData
                | SafeOutputTool::ReportIncomplete => true,
            }
    }

    pub fn digest(&self) -> Result<[u8; 32], SafeOutputsError> {
        let encoded = serde_json::to_vec(self)
            .map_err(|error| SafeOutputsError::Encoding(error.to_string()))?;
        Ok(Sha256::digest(encoded).into())
    }

    fn max_for(&self, tool: SafeOutputTool) -> u32 {
        match tool {
            SafeOutputTool::CreateIssue => self.create_issue.as_ref().map_or(0, |value| value.max),
            SafeOutputTool::AddComment => self.add_comment.as_ref().map_or(0, |value| value.max),
            SafeOutputTool::CreatePullRequest => self
                .create_pull_request
                .as_ref()
                .map_or(0, |value| value.max),
            SafeOutputTool::AddLabels => self.add_labels.as_ref().map_or(0, |value| value.max),
            SafeOutputTool::RemoveLabels => {
                self.remove_labels.as_ref().map_or(0, |value| value.max)
            }
            SafeOutputTool::Noop
            | SafeOutputTool::MissingTool
            | SafeOutputTool::MissingData
            | SafeOutputTool::ReportIncomplete => MAX_SYSTEM_OPERATIONS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIssueOperation {
    pub repository: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub assignees: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddCommentOperation {
    pub repository: String,
    pub item_number: u64,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePullRequestOperation {
    pub repository: String,
    pub title: String,
    pub body: String,
    pub base: String,
    #[serde(default)]
    pub draft: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelOperation {
    pub repository: String,
    pub item_number: u64,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemOperation {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum SafeOutputOperation {
    CreateIssue(CreateIssueOperation),
    AddComment(AddCommentOperation),
    CreatePullRequest(CreatePullRequestOperation),
    AddLabels(LabelOperation),
    RemoveLabels(LabelOperation),
    Noop(SystemOperation),
    MissingTool(SystemOperation),
    MissingData(SystemOperation),
    ReportIncomplete(SystemOperation),
}

impl SafeOutputOperation {
    #[must_use]
    pub const fn tool(&self) -> SafeOutputTool {
        match self {
            Self::CreateIssue(_) => SafeOutputTool::CreateIssue,
            Self::AddComment(_) => SafeOutputTool::AddComment,
            Self::CreatePullRequest(_) => SafeOutputTool::CreatePullRequest,
            Self::AddLabels(_) => SafeOutputTool::AddLabels,
            Self::RemoveLabels(_) => SafeOutputTool::RemoveLabels,
            Self::Noop(_) => SafeOutputTool::Noop,
            Self::MissingTool(_) => SafeOutputTool::MissingTool,
            Self::MissingData(_) => SafeOutputTool::MissingData,
            Self::ReportIncomplete(_) => SafeOutputTool::ReportIncomplete,
        }
    }

    fn arguments(&self) -> Result<Value, SafeOutputsError> {
        match self {
            Self::CreateIssue(value) => encode_value(value),
            Self::AddComment(value) => encode_value(value),
            Self::CreatePullRequest(value) => encode_value(value),
            Self::AddLabels(value) | Self::RemoveLabels(value) => encode_value(value),
            Self::Noop(value)
            | Self::MissingTool(value)
            | Self::MissingData(value)
            | Self::ReportIncomplete(value) => encode_value(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedIntentV1 {
    pub schema_version: u32,
    pub session_id: SessionId,
    pub boundary_plan_digest: BoundaryPlanDigest,
    pub policy_digest: [u8; 32],
    pub sequence: u64,
    pub accepted_at_unix_ms: u64,
    pub idempotency_key: String,
    pub previous_hash: [u8; 32],
    pub operation: SafeOutputOperation,
    pub record_hash: [u8; 32],
}

#[derive(Serialize)]
struct UnsignedIntent<'a> {
    schema_version: u32,
    session_id: SessionId,
    boundary_plan_digest: BoundaryPlanDigest,
    policy_digest: [u8; 32],
    sequence: u64,
    accepted_at_unix_ms: u64,
    idempotency_key: &'a str,
    previous_hash: [u8; 32],
    operation: &'a SafeOutputOperation,
}

#[derive(Debug)]
pub struct PreparedIntent {
    pub record: AcceptedIntentV1,
    pub line: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IntentAccumulator {
    policy: SafeOutputsRuntimePolicy,
    boundary_plan_digest: BoundaryPlanDigest,
    policy_digest: [u8; 32],
    next_sequence: u64,
    chain_head: [u8; 32],
    artifact_bytes: usize,
    counts: BTreeMap<SafeOutputTool, u32>,
    idempotency_keys: BTreeSet<String>,
}

impl IntentAccumulator {
    pub fn new(
        policy: SafeOutputsRuntimePolicy,
        boundary_plan_digest: BoundaryPlanDigest,
    ) -> Result<Self, SafeOutputsError> {
        policy.validate()?;
        let policy_digest = policy.digest()?;
        Ok(Self {
            policy,
            boundary_plan_digest,
            policy_digest,
            next_sequence: 1,
            chain_head: [0; 32],
            artifact_bytes: 0,
            counts: BTreeMap::new(),
            idempotency_keys: BTreeSet::new(),
        })
    }

    pub fn prepare(
        &self,
        tool: SafeOutputTool,
        arguments: Value,
        accepted_at_unix_ms: u64,
    ) -> Result<PreparedIntent, SafeOutputsError> {
        if accepted_at_unix_ms == 0 {
            return Err(SafeOutputsError::Invalid(
                "accepted timestamp must be greater than zero".to_owned(),
            ));
        }
        let operation = validate_operation(&self.policy, tool, arguments)?;
        let count = self.counts.get(&tool).copied().unwrap_or_default();
        if count >= self.policy.max_for(tool) {
            return Err(SafeOutputsError::Limit(format!(
                "{} accepts at most {} operation(s)",
                tool.name(),
                self.policy.max_for(tool)
            )));
        }
        let idempotency_key = idempotency_key(
            self.policy.session_id,
            self.boundary_plan_digest,
            self.policy_digest,
            &operation,
        )?;
        if self.idempotency_keys.contains(&idempotency_key) {
            return Err(SafeOutputsError::Replay(idempotency_key));
        }
        let unsigned = UnsignedIntent {
            schema_version: SAFE_OUTPUTS_SCHEMA_VERSION,
            session_id: self.policy.session_id,
            boundary_plan_digest: self.boundary_plan_digest,
            policy_digest: self.policy_digest,
            sequence: self.next_sequence,
            accepted_at_unix_ms,
            idempotency_key: &idempotency_key,
            previous_hash: self.chain_head,
            operation: &operation,
        };
        let record_hash = Sha256::digest(
            serde_json::to_vec(&unsigned)
                .map_err(|error| SafeOutputsError::Encoding(error.to_string()))?,
        )
        .into();
        let record = AcceptedIntentV1 {
            schema_version: unsigned.schema_version,
            session_id: unsigned.session_id,
            boundary_plan_digest: unsigned.boundary_plan_digest,
            policy_digest: unsigned.policy_digest,
            sequence: unsigned.sequence,
            accepted_at_unix_ms: unsigned.accepted_at_unix_ms,
            idempotency_key: idempotency_key.clone(),
            previous_hash: unsigned.previous_hash,
            operation,
            record_hash,
        };
        let mut line = serde_json::to_vec(&record)
            .map_err(|error| SafeOutputsError::Encoding(error.to_string()))?;
        line.push(b'\n');
        if self.artifact_bytes.saturating_add(line.len()) > self.policy.max_artifact_bytes {
            return Err(SafeOutputsError::Limit(format!(
                "accepted operations exceed the {} byte artifact limit",
                self.policy.max_artifact_bytes
            )));
        }
        Ok(PreparedIntent { record, line })
    }

    pub fn commit(&mut self, prepared: &PreparedIntent) -> Result<(), SafeOutputsError> {
        if prepared.record.sequence != self.next_sequence
            || prepared.record.previous_hash != self.chain_head
            || prepared.record.session_id != self.policy.session_id
            || prepared.record.boundary_plan_digest != self.boundary_plan_digest
            || prepared.record.policy_digest != self.policy_digest
        {
            return Err(SafeOutputsError::Invalid(
                "prepared intent does not match the accumulator state".to_owned(),
            ));
        }
        if !self
            .idempotency_keys
            .insert(prepared.record.idempotency_key.clone())
        {
            return Err(SafeOutputsError::Replay(
                prepared.record.idempotency_key.clone(),
            ));
        }
        *self
            .counts
            .entry(prepared.record.operation.tool())
            .or_default() += 1;
        self.chain_head = prepared.record.record_hash;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| SafeOutputsError::Limit("intent sequence overflowed".to_owned()))?;
        self.artifact_bytes = self.artifact_bytes.saturating_add(prepared.line.len());
        Ok(())
    }

    #[must_use]
    pub const fn operation_count(&self) -> u64 {
        self.next_sequence - 1
    }

    #[must_use]
    pub const fn chain_head(&self) -> [u8; 32] {
        self.chain_head
    }

    #[must_use]
    pub const fn artifact_bytes(&self) -> usize {
        self.artifact_bytes
    }

    pub fn verify_artifact(
        &self,
        artifact: &[u8],
    ) -> Result<Vec<AcceptedIntentV1>, SafeOutputsError> {
        let records = validate_artifact(&self.policy, self.boundary_plan_digest, artifact, None)?;
        if records.len() as u64 != self.operation_count()
            || artifact.len() != self.artifact_bytes
            || records.last().map_or([0; 32], |record| record.record_hash) != self.chain_head
        {
            return Err(SafeOutputsError::Artifact(
                "artifact does not match the in-memory append state".to_owned(),
            ));
        }
        Ok(records)
    }

    #[must_use]
    pub const fn policy(&self) -> &SafeOutputsRuntimePolicy {
        &self.policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeOutputsSealV1 {
    pub schema_version: u32,
    pub session_id: SessionId,
    pub boundary_plan_digest: BoundaryPlanDigest,
    pub policy_digest: [u8; 32],
    pub operation_count: u64,
    pub artifact_bytes: usize,
    pub chain_head: [u8; 32],
    pub artifact_sha256: [u8; 32],
    pub mac: [u8; 32],
}

#[derive(Serialize)]
struct UnsignedSeal {
    schema_version: u32,
    session_id: SessionId,
    boundary_plan_digest: BoundaryPlanDigest,
    policy_digest: [u8; 32],
    operation_count: u64,
    artifact_bytes: usize,
    chain_head: [u8; 32],
    artifact_sha256: [u8; 32],
}

impl SafeOutputsSealV1 {
    pub fn create(
        accumulator: &IntentAccumulator,
        artifact: &[u8],
        seal_key: &[u8; 32],
    ) -> Result<Self, SafeOutputsError> {
        accumulator.verify_artifact(artifact)?;
        let unsigned = UnsignedSeal {
            schema_version: SAFE_OUTPUTS_SCHEMA_VERSION,
            session_id: accumulator.policy.session_id,
            boundary_plan_digest: accumulator.boundary_plan_digest,
            policy_digest: accumulator.policy_digest,
            operation_count: accumulator.operation_count(),
            artifact_bytes: artifact.len(),
            chain_head: accumulator.chain_head,
            artifact_sha256: Sha256::digest(artifact).into(),
        };
        let mac = seal_mac(&unsigned, seal_key)?;
        Ok(Self {
            schema_version: unsigned.schema_version,
            session_id: unsigned.session_id,
            boundary_plan_digest: unsigned.boundary_plan_digest,
            policy_digest: unsigned.policy_digest,
            operation_count: unsigned.operation_count,
            artifact_bytes: unsigned.artifact_bytes,
            chain_head: unsigned.chain_head,
            artifact_sha256: unsigned.artifact_sha256,
            mac,
        })
    }

    pub fn verify(
        &self,
        policy: &SafeOutputsRuntimePolicy,
        boundary_plan_digest: BoundaryPlanDigest,
        artifact: &[u8],
        seal_key: &[u8; 32],
    ) -> Result<Vec<AcceptedIntentV1>, SafeOutputsError> {
        let artifact_sha256: [u8; 32] = Sha256::digest(artifact).into();
        if self.schema_version != SAFE_OUTPUTS_SCHEMA_VERSION
            || self.session_id != policy.session_id
            || self.boundary_plan_digest != boundary_plan_digest
            || self.policy_digest != policy.digest()?
            || self.artifact_bytes != artifact.len()
            || self.artifact_sha256 != artifact_sha256
        {
            return Err(SafeOutputsError::Seal(
                "Safe Outputs seal binding does not match this session".to_owned(),
            ));
        }
        let unsigned = UnsignedSeal {
            schema_version: self.schema_version,
            session_id: self.session_id,
            boundary_plan_digest: self.boundary_plan_digest,
            policy_digest: self.policy_digest,
            operation_count: self.operation_count,
            artifact_bytes: self.artifact_bytes,
            chain_head: self.chain_head,
            artifact_sha256: self.artifact_sha256,
        };
        let expected = seal_mac(&unsigned, seal_key)?;
        if !constant_time_eq(&self.mac, &expected) {
            return Err(SafeOutputsError::Seal(
                "Safe Outputs seal authentication failed".to_owned(),
            ));
        }
        let records = validate_artifact(policy, boundary_plan_digest, artifact, None)?;
        if records.len() as u64 != self.operation_count
            || records.last().map_or([0; 32], |record| record.record_hash) != self.chain_head
        {
            return Err(SafeOutputsError::Seal(
                "Safe Outputs seal does not match the artifact chain".to_owned(),
            ));
        }
        Ok(records)
    }
}

pub fn derive_seal_key(
    bootstrap_secret: &[u8],
    session_id: SessionId,
) -> Result<[u8; 32], SafeOutputsError> {
    if bootstrap_secret.len() < 32 {
        return Err(SafeOutputsError::Seal(
            "bootstrap secret is too short for Safe Outputs key derivation".to_owned(),
        ));
    }
    let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), bootstrap_secret);
    let mut key = [0; 32];
    hkdf.expand(SEAL_KEY_INFO, &mut key)
        .map_err(|_| SafeOutputsError::Seal("Safe Outputs key derivation failed".to_owned()))?;
    Ok(key)
}

pub fn validate_artifact(
    policy: &SafeOutputsRuntimePolicy,
    boundary_plan_digest: BoundaryPlanDigest,
    artifact: &[u8],
    now_unix_ms: Option<u64>,
) -> Result<Vec<AcceptedIntentV1>, SafeOutputsError> {
    policy.validate()?;
    if artifact.len() > policy.max_artifact_bytes {
        return Err(SafeOutputsError::Artifact(format!(
            "artifact exceeds {} bytes",
            policy.max_artifact_bytes
        )));
    }
    if artifact.is_empty() {
        return Ok(Vec::new());
    }
    if !artifact.ends_with(b"\n") {
        return Err(SafeOutputsError::Artifact(
            "NDJSON artifact is missing its final newline".to_owned(),
        ));
    }
    let policy_digest = policy.digest()?;
    let mut records = Vec::new();
    let mut expected_sequence = 1_u64;
    let mut previous_hash = [0; 32];
    let mut counts = BTreeMap::<SafeOutputTool, u32>::new();
    let mut keys = BTreeSet::new();
    for line in artifact[..artifact.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(SafeOutputsError::Artifact(
                "NDJSON artifact contains an empty record".to_owned(),
            ));
        }
        let record: AcceptedIntentV1 = serde_json::from_slice(line)
            .map_err(|error| SafeOutputsError::Artifact(error.to_string()))?;
        if record.schema_version != SAFE_OUTPUTS_SCHEMA_VERSION
            || record.session_id != policy.session_id
            || record.boundary_plan_digest != boundary_plan_digest
            || record.policy_digest != policy_digest
            || record.sequence != expected_sequence
            || record.previous_hash != previous_hash
            || record.accepted_at_unix_ms == 0
        {
            return Err(SafeOutputsError::Artifact(format!(
                "record {} has invalid provenance, sequence, or chain binding",
                record.sequence
            )));
        }
        if let Some(now) = now_unix_ms
            && record.accepted_at_unix_ms > now.saturating_add(5 * 60 * 1_000)
        {
            return Err(SafeOutputsError::Artifact(format!(
                "record {} is dated too far in the future",
                record.sequence
            )));
        }
        let expected_operation = validate_operation(
            policy,
            record.operation.tool(),
            record.operation.arguments()?,
        )?;
        if expected_operation != record.operation {
            return Err(SafeOutputsError::Artifact(format!(
                "record {} is not canonically sanitized",
                record.sequence
            )));
        }
        let expected_key = idempotency_key(
            record.session_id,
            record.boundary_plan_digest,
            record.policy_digest,
            &record.operation,
        )?;
        if expected_key != record.idempotency_key || !keys.insert(expected_key) {
            return Err(SafeOutputsError::Artifact(format!(
                "record {} has an invalid or replayed idempotency key",
                record.sequence
            )));
        }
        let unsigned = UnsignedIntent {
            schema_version: record.schema_version,
            session_id: record.session_id,
            boundary_plan_digest: record.boundary_plan_digest,
            policy_digest: record.policy_digest,
            sequence: record.sequence,
            accepted_at_unix_ms: record.accepted_at_unix_ms,
            idempotency_key: &record.idempotency_key,
            previous_hash: record.previous_hash,
            operation: &record.operation,
        };
        let expected_hash: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&unsigned)
                .map_err(|error| SafeOutputsError::Encoding(error.to_string()))?,
        )
        .into();
        if expected_hash != record.record_hash {
            return Err(SafeOutputsError::Artifact(format!(
                "record {} hash is invalid",
                record.sequence
            )));
        }
        let count = counts.entry(record.operation.tool()).or_default();
        *count += 1;
        if *count > policy.max_for(record.operation.tool()) {
            return Err(SafeOutputsError::Limit(format!(
                "{} artifact count exceeds {}",
                record.operation.tool().name(),
                policy.max_for(record.operation.tool())
            )));
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| SafeOutputsError::Artifact("record sequence overflowed".to_owned()))?;
        previous_hash = record.record_hash;
        records.push(record);
    }
    Ok(records)
}

pub fn validate_operation(
    policy: &SafeOutputsRuntimePolicy,
    tool: SafeOutputTool,
    arguments: Value,
) -> Result<SafeOutputOperation, SafeOutputsError> {
    if !policy.permits(tool) {
        return Err(SafeOutputsError::UnsupportedTool(tool.name().to_owned()));
    }
    match tool {
        SafeOutputTool::CreateIssue => {
            let mut value: CreateIssueOperation = decode_arguments(tool, arguments)?;
            let configured = policy
                .create_issue
                .as_ref()
                .ok_or_else(|| SafeOutputsError::UnsupportedTool(tool.name().to_owned()))?;
            validate_repository_target(policy, &value.repository)?;
            if !value.title.starts_with(&configured.title_prefix) {
                value.title = format!("{}{}", configured.title_prefix, value.title);
            }
            value.title = sanitize_text(&value.title, MAX_TITLE_CHARS, policy);
            value.body = sanitize_text(&value.body, MAX_BODY_CHARS, policy);
            if value.title.trim().is_empty() {
                return Err(SafeOutputsError::Invalid(
                    "create_issue title is empty after sanitization".to_owned(),
                ));
            }
            if value.body.chars().count() < MIN_ISSUE_BODY_CHARS {
                return Err(SafeOutputsError::Invalid(format!(
                    "create_issue body must contain at least {MIN_ISSUE_BODY_CHARS} characters"
                )));
            }
            canonicalize_strings(&mut value.labels)?;
            canonicalize_strings(&mut value.assignees)?;
            require_subset("create_issue labels", &value.labels, &configured.labels)?;
            require_subset(
                "create_issue assignees",
                &value.assignees,
                &configured.assignees,
            )?;
            Ok(SafeOutputOperation::CreateIssue(value))
        }
        SafeOutputTool::AddComment => {
            let mut value: AddCommentOperation = decode_arguments(tool, arguments)?;
            validate_repository_target(policy, &value.repository)?;
            if value.item_number == 0 {
                return Err(SafeOutputsError::Invalid(
                    "add_comment item_number must be greater than zero".to_owned(),
                ));
            }
            value.body = sanitize_text(&value.body, MAX_BODY_CHARS, policy);
            if value.body.trim().is_empty() {
                return Err(SafeOutputsError::Invalid(
                    "add_comment body is empty after sanitization".to_owned(),
                ));
            }
            Ok(SafeOutputOperation::AddComment(value))
        }
        SafeOutputTool::CreatePullRequest => {
            let mut value: CreatePullRequestOperation = decode_arguments(tool, arguments)?;
            let configured = policy
                .create_pull_request
                .as_ref()
                .ok_or_else(|| SafeOutputsError::UnsupportedTool(tool.name().to_owned()))?;
            validate_repository_target(policy, &value.repository)?;
            if !configured.base_branches.contains(&value.base) {
                return Err(SafeOutputsError::Invalid(format!(
                    "create_pull_request base `{}` is not allowed",
                    value.base
                )));
            }
            if !value.title.starts_with(&configured.title_prefix) {
                value.title = format!("{}{}", configured.title_prefix, value.title);
            }
            value.title = sanitize_text(&value.title, MAX_TITLE_CHARS, policy);
            value.body = sanitize_text(&value.body, MAX_BODY_CHARS, policy);
            if value.title.trim().is_empty() || value.body.trim().is_empty() {
                return Err(SafeOutputsError::Invalid(
                    "create_pull_request title and body must not be empty".to_owned(),
                ));
            }
            Ok(SafeOutputOperation::CreatePullRequest(value))
        }
        SafeOutputTool::AddLabels | SafeOutputTool::RemoveLabels => {
            let mut value: LabelOperation = decode_arguments(tool, arguments)?;
            validate_repository_target(policy, &value.repository)?;
            if value.item_number == 0 {
                return Err(SafeOutputsError::Invalid(format!(
                    "{} item_number must be greater than zero",
                    tool.name()
                )));
            }
            canonicalize_strings(&mut value.labels)?;
            let configured = if tool == SafeOutputTool::AddLabels {
                policy.add_labels.as_ref()
            } else {
                policy.remove_labels.as_ref()
            }
            .ok_or_else(|| SafeOutputsError::UnsupportedTool(tool.name().to_owned()))?;
            if value.labels.is_empty()
                || value.labels.len()
                    > usize::try_from(configured.max_labels_per_call).unwrap_or(usize::MAX)
            {
                return Err(SafeOutputsError::Limit(format!(
                    "{} accepts between 1 and {} labels",
                    tool.name(),
                    configured.max_labels_per_call
                )));
            }
            for label in &value.labels {
                if label.len() > 100
                    || label
                        .chars()
                        .any(|character| matches!(character, '\r' | '\n' | '\0'))
                {
                    return Err(SafeOutputsError::Invalid(format!(
                        "invalid label `{label}`"
                    )));
                }
                if configured
                    .blocked
                    .iter()
                    .any(|pattern| glob_matches(label, pattern))
                {
                    return Err(SafeOutputsError::Invalid(format!(
                        "label `{label}` is blocked"
                    )));
                }
                if !configured.allowed.is_empty()
                    && !configured
                        .allowed
                        .iter()
                        .any(|pattern| glob_matches(label, pattern))
                {
                    return Err(SafeOutputsError::Invalid(format!(
                        "label `{label}` is not allowed"
                    )));
                }
            }
            if tool == SafeOutputTool::AddLabels {
                Ok(SafeOutputOperation::AddLabels(value))
            } else {
                Ok(SafeOutputOperation::RemoveLabels(value))
            }
        }
        SafeOutputTool::Noop
        | SafeOutputTool::MissingTool
        | SafeOutputTool::MissingData
        | SafeOutputTool::ReportIncomplete => {
            let mut value: SystemOperation = decode_arguments(tool, arguments)?;
            value.message = sanitize_text(&value.message, MAX_META_CHARS, policy);
            let operation = match tool {
                SafeOutputTool::Noop => SafeOutputOperation::Noop(value),
                SafeOutputTool::MissingTool => SafeOutputOperation::MissingTool(value),
                SafeOutputTool::MissingData => SafeOutputOperation::MissingData(value),
                SafeOutputTool::ReportIncomplete => SafeOutputOperation::ReportIncomplete(value),
                _ => unreachable!("system tools handled above"),
            };
            Ok(operation)
        }
    }
}

#[must_use]
pub fn sanitize_text(input: &str, max_chars: usize, policy: &SafeOutputsRuntimePolicy) -> String {
    let normalized = input.nfkc().collect::<String>();
    let redacted = redact_credentials(&normalized);
    let filtered_urls = filter_urls(&redacted, &policy.allowed_domains);
    let neutralized = neutralize_instructions(&filtered_urls);
    let mentions = neutralize_mentions(&neutralized, &policy.allowed_mentions);
    let markdown_safe = mentions.replace('<', "&lt;").replace('>', "&gt;");
    markdown_safe.chars().take(max_chars).collect()
}

#[derive(Debug, Clone)]
pub struct McpGateway {
    policy: SafeOutputsRuntimePolicy,
}

impl McpGateway {
    pub fn new(policy: SafeOutputsRuntimePolicy) -> Result<Self, SafeOutputsError> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub fn handle(
        &self,
        payload: &[u8],
        mut accept: impl FnMut(SafeOutputTool, Value) -> Result<AcceptedIntentV1, SafeOutputsError>,
    ) -> Result<Option<Vec<u8>>, SafeOutputsError> {
        let validated = validate_message(payload)
            .map_err(|error| SafeOutputsError::Protocol(error.to_string()))?;
        let value: Value = serde_json::from_slice(payload)
            .map_err(|error| SafeOutputsError::Protocol(error.to_string()))?;
        let object = value.as_object().ok_or_else(|| {
            SafeOutputsError::Protocol("JSON-RPC value is not an object".to_owned())
        })?;
        let method = validated
            .method
            .as_deref()
            .ok_or_else(|| SafeOutputsError::Protocol("client sent a response".to_owned()))?;
        validate_rpc_keys(object)?;
        if validated.kind == MessageKind::Notification {
            if method == "notifications/initialized" {
                return Ok(None);
            }
            return Err(SafeOutputsError::Protocol(format!(
                "unsupported MCP notification `{method}`"
            )));
        }
        let IdPresence::Present(id) = &validated.id else {
            return Err(SafeOutputsError::Protocol(
                "MCP request is missing an id".to_owned(),
            ));
        };
        match method {
            "initialize" => Ok(Some(result_response(
                id,
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {
                        "name": "sendbox-safe-outputs",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            ))),
            "ping" => Ok(Some(result_response(id, json!({})))),
            "tools/list" => Ok(Some(result_response(
                id,
                json!({"tools": tool_descriptions(&self.policy)}),
            ))),
            "tools/call" => {
                let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
                let call: ToolCallParams = serde_json::from_value(params)
                    .map_err(|error| SafeOutputsError::Invalid(error.to_string()))?;
                let tool = SafeOutputTool::parse(&call.name)?;
                match accept(tool, call.arguments) {
                    Ok(record) => Ok(Some(result_response(
                        id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": format!(
                                    "accepted {} as sequence {} ({})",
                                    record.operation.tool().name(),
                                    record.sequence,
                                    record.idempotency_key
                                )
                            }],
                            "isError": false
                        }),
                    ))),
                    Err(error) => Ok(Some(result_response(
                        id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": error.to_string()
                            }],
                            "isError": true
                        }),
                    ))),
                }
            }
            _ => Ok(Some(error_response(id, -32601, "MCP method not found"))),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolCallParams {
    name: String,
    #[serde(default = "empty_object")]
    arguments: Value,
}

fn empty_object() -> Value {
    json!({})
}

fn tool_descriptions(policy: &SafeOutputsRuntimePolicy) -> Vec<Value> {
    policy
        .enabled_tools()
        .into_iter()
        .map(|tool| {
            json!({
                "name": tool.name(),
                "description": tool_description(tool),
                "inputSchema": tool_schema(tool)
            })
        })
        .collect()
}

fn tool_description(tool: SafeOutputTool) -> &'static str {
    match tool {
        SafeOutputTool::CreateIssue => "Request creation of a constrained GitHub issue.",
        SafeOutputTool::AddComment => "Request a constrained issue or pull-request comment.",
        SafeOutputTool::CreatePullRequest => {
            "Request a pull request from the validated SendBox workspace changes."
        }
        SafeOutputTool::AddLabels => "Request allowed labels on an issue or pull request.",
        SafeOutputTool::RemoveLabels => "Request removal of allowed labels.",
        SafeOutputTool::Noop => "Record that no GitHub write is required.",
        SafeOutputTool::MissingTool => "Report that a required safe-output tool is unavailable.",
        SafeOutputTool::MissingData => "Report that required input data is unavailable.",
        SafeOutputTool::ReportIncomplete => "Report that the requested work is incomplete.",
    }
}

fn tool_schema(tool: SafeOutputTool) -> Value {
    let string = || json!({"type": "string"});
    match tool {
        SafeOutputTool::CreateIssue => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["repository", "title", "body"],
            "properties": {
                "repository": string(),
                "title": string(),
                "body": string(),
                "labels": {"type": "array", "items": string()},
                "assignees": {"type": "array", "items": string()}
            }
        }),
        SafeOutputTool::AddComment => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["repository", "item_number", "body"],
            "properties": {
                "repository": string(),
                "item_number": {"type": "integer", "minimum": 1},
                "body": string()
            }
        }),
        SafeOutputTool::CreatePullRequest => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["repository", "title", "body", "base"],
            "properties": {
                "repository": string(),
                "title": string(),
                "body": string(),
                "base": string(),
                "draft": {"type": "boolean"}
            }
        }),
        SafeOutputTool::AddLabels | SafeOutputTool::RemoveLabels => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["repository", "item_number", "labels"],
            "properties": {
                "repository": string(),
                "item_number": {"type": "integer", "minimum": 1},
                "labels": {"type": "array", "minItems": 1, "items": string()}
            }
        }),
        SafeOutputTool::Noop
        | SafeOutputTool::MissingTool
        | SafeOutputTool::MissingData
        | SafeOutputTool::ReportIncomplete => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["message"],
            "properties": {"message": string()}
        }),
    }
}

fn validate_rpc_keys(object: &serde_json::Map<String, Value>) -> Result<(), SafeOutputsError> {
    const ALLOWED: [&str; 4] = ["jsonrpc", "id", "method", "params"];
    if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(SafeOutputsError::Protocol(format!(
            "unexpected JSON-RPC field `{key}`"
        )));
    }
    Ok(())
}

fn result_response(id: &str, result: Value) -> Vec<u8> {
    format!(
        "{{\"id\":{id},\"jsonrpc\":\"2.0\",\"result\":{}}}",
        serde_json::to_string(&result).expect("JSON value serialization cannot fail")
    )
    .into_bytes()
}

fn error_response(id: &str, code: i64, message: &str) -> Vec<u8> {
    let message = serde_json::to_string(message).expect("string serialization cannot fail");
    format!(
        "{{\"error\":{{\"code\":{code},\"message\":{message}}},\"id\":{id},\"jsonrpc\":\"2.0\"}}"
    )
    .into_bytes()
}

fn decode_arguments<T>(tool: SafeOutputTool, arguments: Value) -> Result<T, SafeOutputsError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(arguments).map_err(|error| {
        SafeOutputsError::Invalid(format!("invalid {} arguments: {error}", tool.name()))
    })
}

fn encode_value<T: Serialize>(value: &T) -> Result<Value, SafeOutputsError> {
    serde_json::to_value(value).map_err(|error| SafeOutputsError::Encoding(error.to_string()))
}

fn validate_repository_target(
    policy: &SafeOutputsRuntimePolicy,
    repository: &str,
) -> Result<(), SafeOutputsError> {
    if policy.allowed_repositories.contains(repository) {
        Ok(())
    } else {
        Err(SafeOutputsError::Invalid(format!(
            "repository `{repository}` is not allowed"
        )))
    }
}

fn canonicalize_strings(values: &mut Vec<String>) -> Result<(), SafeOutputsError> {
    for value in values.iter_mut() {
        *value = value.trim().to_owned();
        if value.is_empty() {
            return Err(SafeOutputsError::Invalid(
                "list entries must not be empty".to_owned(),
            ));
        }
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SafeOutputsError::Invalid(
            "list entries must be unique".to_owned(),
        ));
    }
    Ok(())
}

fn require_subset(
    field: &str,
    requested: &[String],
    allowed: &[String],
) -> Result<(), SafeOutputsError> {
    if let Some(value) = requested.iter().find(|value| !allowed.contains(value)) {
        Err(SafeOutputsError::Invalid(format!(
            "{field} contains unauthorized value `{value}`"
        )))
    } else {
        Ok(())
    }
}

fn idempotency_key(
    session_id: SessionId,
    boundary_plan_digest: BoundaryPlanDigest,
    policy_digest: [u8; 32],
    operation: &SafeOutputOperation,
) -> Result<String, SafeOutputsError> {
    #[derive(Serialize)]
    struct Binding<'a> {
        schema_version: u32,
        session_id: SessionId,
        boundary_plan_digest: BoundaryPlanDigest,
        policy_digest: [u8; 32],
        operation: &'a SafeOutputOperation,
    }
    let encoded = serde_json::to_vec(&Binding {
        schema_version: SAFE_OUTPUTS_SCHEMA_VERSION,
        session_id,
        boundary_plan_digest,
        policy_digest,
        operation,
    })
    .map_err(|error| SafeOutputsError::Encoding(error.to_string()))?;
    Ok(hex(&Sha256::digest(encoded)))
}

fn seal_mac(unsigned: &UnsignedSeal, key: &[u8; 32]) -> Result<[u8; 32], SafeOutputsError> {
    let encoded = serde_json::to_vec(unsigned)
        .map_err(|error| SafeOutputsError::Encoding(error.to_string()))?;
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .map_err(|_| SafeOutputsError::Seal("invalid seal key".to_owned()))?;
    mac.update(&encoded);
    Ok(mac.finalize().into_bytes().into())
}

fn redact_credentials(input: &str) -> String {
    let mut redact_next = false;
    input
        .split_inclusive(char::is_whitespace)
        .map(|segment| {
            let token = segment.trim_end_matches(char::is_whitespace);
            let suffix = &segment[token.len()..];
            let keyword = token
                .trim_matches(|character: char| {
                    matches!(
                        character,
                        '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | '*' | '_'
                    )
                })
                .to_ascii_lowercase();
            if redact_next {
                if keyword == "bearer" {
                    return format!("{REDACTED}{suffix}");
                }
                redact_next = false;
                return format!("{REDACTED}{suffix}");
            }
            if keyword == "bearer" || keyword == "authorization:" {
                redact_next = true;
                return format!("{REDACTED}{suffix}");
            }
            if keyword == "authorization:bearer" {
                redact_next = true;
                return format!("{REDACTED}{suffix}");
            }
            if keyword.starts_with("bearer:") || keyword.starts_with("authorization:") {
                return format!("{REDACTED}{suffix}");
            }
            format!("{}{suffix}", redact_github_token_substrings(token))
        })
        .collect()
}

fn redact_github_token_substrings(input: &str) -> String {
    const PREFIXES: [&str; 6] = ["github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"];
    let lower = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut offset = 0;
    while offset < input.len() {
        let next = PREFIXES
            .iter()
            .filter_map(|prefix| lower[offset..].find(prefix).map(|index| (index, *prefix)))
            .min_by_key(|(index, _)| *index);
        let Some((index, prefix)) = next else {
            output.push_str(&input[offset..]);
            break;
        };
        let start = offset + index;
        output.push_str(&input[offset..start]);
        let token_start = start + prefix.len();
        let token_end = input[token_start..]
            .char_indices()
            .find_map(|(index, character)| {
                (!matches!(
                    character,
                    'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-'
                ))
                .then_some(token_start + index)
            })
            .unwrap_or(input.len());
        output.push_str(REDACTED);
        offset = token_end;
    }
    output
}

fn filter_urls(input: &str, allowed_domains: &BTreeSet<String>) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    while !remaining.is_empty() {
        let lower = remaining.to_ascii_lowercase();
        let next = ["https://", "http://", "javascript:", "data:"]
            .iter()
            .filter_map(|scheme| lower.find(scheme).map(|index| (index, *scheme)))
            .min_by_key(|(index, _)| *index);
        let Some((index, scheme)) = next else {
            output.push_str(remaining);
            break;
        };
        output.push_str(&remaining[..index]);
        let candidate = &remaining[index..];
        let end = candidate
            .char_indices()
            .find_map(|(offset, character)| {
                (offset > 0
                    && (character.is_whitespace()
                        || matches!(character, ')' | ']' | '}' | '>' | '"' | '\'')))
                .then_some(offset)
            })
            .unwrap_or(candidate.len());
        let raw = &candidate[..end];
        let allowed = matches!(scheme, "http://" | "https://")
            && Url::parse(raw)
                .ok()
                .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
                .is_some_and(|host| {
                    allowed_domains
                        .iter()
                        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
                });
        if allowed {
            output.push_str(raw);
        } else {
            output.push_str(BLOCKED_URL);
        }
        remaining = &candidate[end..];
    }
    output
}

fn neutralize_instructions(input: &str) -> String {
    input
        .lines()
        .map(|line| {
            if line.starts_with(NEUTRALIZED_PREFIX) {
                return line.to_owned();
            }
            let lower = line.to_ascii_lowercase();
            let hostile = [
                "ignore previous instruction",
                "ignore all instruction",
                "system prompt",
                "developer message",
                "reveal your secret",
                "execute this command",
                "run this command",
                "curl ",
                "wget ",
                "gh api",
                "rm -rf",
                "<script",
                "<iframe",
            ]
            .iter()
            .any(|needle| lower.contains(needle));
            if hostile {
                format!("{NEUTRALIZED_PREFIX}{line}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn neutralize_mentions(input: &str, allowed_mentions: &BTreeSet<String>) -> String {
    let chars = input.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(input.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '@' {
            output.push(chars[index]);
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < chars.len()
            && (chars[end].is_ascii_alphanumeric() || chars[end] == '-')
            && end - start < 100
        {
            end += 1;
        }
        if end == start {
            output.push('@');
            index += 1;
            continue;
        }
        let login = chars[start..end].iter().collect::<String>();
        if allowed_mentions.contains(&login) {
            output.push('@');
        } else {
            output.push_str("@\u{200b}");
        }
        output.push_str(&login);
        index = end;
    }
    output
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SafeOutputsError {
    #[error("Safe Outputs policy: {0}")]
    Policy(String),
    #[error("unsupported Safe Outputs tool `{0}`")]
    UnsupportedTool(String),
    #[error("invalid Safe Outputs request: {0}")]
    Invalid(String),
    #[error("Safe Outputs limit: {0}")]
    Limit(String),
    #[error("Safe Outputs replay rejected for idempotency key {0}")]
    Replay(String),
    #[error("Safe Outputs artifact: {0}")]
    Artifact(String),
    #[error("Safe Outputs seal: {0}")]
    Seal(String),
    #[error("Safe Outputs protocol: {0}")]
    Protocol(String),
    #[error("Safe Outputs encoding: {0}")]
    Encoding(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SafeOutputsRuntimePolicy {
        let mut configuration = SafeOutputsConfiguration {
            enabled: true,
            allowed_repositories: vec!["acme/widgets".to_owned()],
            allowed_domains: vec!["github.com".to_owned()],
            allowed_mentions: vec!["octocat".to_owned()],
            ..SafeOutputsConfiguration::default()
        };
        configuration.create_issue.enabled = true;
        configuration.create_issue.labels = vec!["automation".to_owned()];
        configuration.create_issue.assignees = vec!["octocat".to_owned()];
        configuration.add_comment.enabled = true;
        configuration.add_labels.enabled = true;
        configuration.add_labels.allowed = vec!["team-*".to_owned()];
        configuration.remove_labels.enabled = true;
        configuration.remove_labels.allowed = vec!["team-*".to_owned()];
        SafeOutputsRuntimePolicy::from_configuration(SessionId::from_bytes([7; 16]), &configuration)
            .expect("policy")
    }

    fn issue_arguments() -> Value {
        json!({
            "repository": "acme/widgets",
            "title": "Investigate parser",
            "body": "This issue contains enough detail for the configured minimum.",
            "labels": ["automation"],
            "assignees": ["octocat"]
        })
    }

    #[test]
    fn sanitization_is_idempotent_and_filters_credentials_urls_mentions_and_instructions() {
        let policy = policy();
        let input = "token=ghp_supersecret https://evil.example/x @everyone\nrun this command\nAuthorization: Bearer arbitrary.jwt.value\n\"pat\":\"github_pat_embedded\"";
        let once = sanitize_text(input, 1_000, &policy);
        let twice = sanitize_text(&once, 1_000, &policy);
        assert_eq!(once, twice);
        assert!(once.contains(REDACTED));
        assert!(once.contains(BLOCKED_URL));
        assert!(once.contains("@\u{200b}everyone"));
        assert!(once.contains(NEUTRALIZED_PREFIX));
        assert!(!once.contains("supersecret"));
        assert!(!once.contains("arbitrary.jwt.value"));
        assert!(!once.contains("embedded"));
    }

    #[test]
    fn gateway_exposes_only_enabled_and_system_tools() {
        let gateway = McpGateway::new(policy()).expect("gateway");
        let response = gateway
            .handle(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
                |_, _| unreachable!("list does not accept"),
            )
            .expect("list")
            .expect("response");
        let text = String::from_utf8(response).expect("utf8");
        assert!(text.contains("create_issue"));
        assert!(text.contains("noop"));
        assert!(!text.contains("create_pull_request"));
    }

    #[test]
    fn artifact_chain_and_authenticated_seal_reject_tampering_and_replay() {
        let policy = policy();
        let boundary = BoundaryPlanDigest::from_bytes([9; 32]);
        let mut accumulator =
            IntentAccumulator::new(policy.clone(), boundary).expect("accumulator");
        let prepared = accumulator
            .prepare(SafeOutputTool::CreateIssue, issue_arguments(), 1_000)
            .expect("prepare");
        accumulator.commit(&prepared).expect("commit");
        let artifact = prepared.line.clone();
        let key = derive_seal_key(&[3; 32], policy.session_id).expect("key");
        let seal = SafeOutputsSealV1::create(&accumulator, &artifact, &key).expect("seal");
        assert_eq!(
            seal.verify(&policy, boundary, &artifact, &key)
                .expect("verify")
                .len(),
            1
        );

        let mut tampered = artifact.clone();
        let index = tampered
            .iter()
            .position(|byte| *byte == b'I')
            .expect("body byte");
        tampered[index] = b'X';
        assert!(seal.verify(&policy, boundary, &tampered, &key).is_err());
        assert!(
            accumulator
                .prepare(SafeOutputTool::CreateIssue, issue_arguments(), 2_000)
                .is_err()
        );
    }

    #[test]
    fn labels_apply_blocked_patterns_before_allowed_patterns() {
        let mut policy = policy();
        policy.add_labels.as_mut().expect("labels").blocked = vec!["team-secret".to_owned()];
        let error = validate_operation(
            &policy,
            SafeOutputTool::AddLabels,
            json!({
                "repository": "acme/widgets",
                "item_number": 4,
                "labels": ["team-secret"]
            }),
        )
        .expect_err("blocked");
        assert!(error.to_string().contains("blocked"));
    }

    #[test]
    fn unknown_fields_and_foreign_repositories_fail_closed() {
        let policy = policy();
        let mut arguments = issue_arguments();
        arguments
            .as_object_mut()
            .expect("object")
            .insert("extra".to_owned(), Value::Bool(true));
        assert!(validate_operation(&policy, SafeOutputTool::CreateIssue, arguments).is_err());
        let mut foreign = issue_arguments();
        foreign["repository"] = Value::String("other/repository".to_owned());
        assert!(validate_operation(&policy, SafeOutputTool::CreateIssue, foreign).is_err());
    }
}
