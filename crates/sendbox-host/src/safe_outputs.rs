use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use reqwest::{Method, StatusCode, Url};
use sendbox_agent::CollectedSafeOutputs;
use sendbox_boundary::sha256_hex;
use sendbox_config::{SafeOutputsConfiguration, SafeOutputsMode};
use sendbox_core::{BoundaryPlanDigest, SessionId, glob_matches};
use sendbox_git::{GitProcessRunner, ProcessRequest, SystemGitProcessRunner, TrustedGitBinary};
use sendbox_mcp::safe_outputs::{
    AcceptedIntentV1, CreatePullRequestOperation, SafeOutputOperation, SafeOutputTool,
    SafeOutputsRuntimePolicy, SafeOutputsSealV1,
};
use sendbox_security::audit::{AuditCategory, AuditResult};
use sendbox_session_security::AuditRecorder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::{HostError, atomic_write, resolve_executable};

const LEDGER_SCHEMA_VERSION: u32 = 1;
const REPORT_SCHEMA_VERSION: u32 = 1;
const LEDGER_FILE: &str = "safe-outputs-ledger.json";
const REPORT_FILE: &str = "safe-outputs-report.json";
const MAX_GITHUB_RESPONSE_BYTES: usize = 1024 * 1024;
const GIT_OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct ProcessingContext {
    pub configuration: SafeOutputsConfiguration,
    pub policy: SafeOutputsRuntimePolicy,
    pub boundary_plan_digest: BoundaryPlanDigest,
    pub seal_key: [u8; 32],
    pub state_directory: PathBuf,
    pub workspace: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ActionStatus {
    Staged,
    Applied,
    AlreadyApplied,
    Reported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ActionReport {
    sequence: u64,
    tool: String,
    idempotency_key: String,
    operation: SafeOutputOperation,
    status: ActionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProcessingReport {
    schema_version: u32,
    session_id: SessionId,
    mode: SafeOutputsMode,
    boundary_plan_digest: String,
    policy_digest: String,
    artifact_sha256: String,
    chain_head: String,
    operation_count: usize,
    actions: Vec<ActionReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BatchProvenance {
    boundary_plan_digest: String,
    policy_digest: String,
    artifact_sha256: String,
    chain_head: String,
}

struct VerifiedCollection {
    records: Vec<AcceptedIntentV1>,
    provenance: BatchProvenance,
}

type WriterFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, HostError>> + Send + 'a>>;

trait GitHubWriter: Send + Sync {
    fn reconcile<'a>(
        &'a self,
        record: &'a AcceptedIntentV1,
    ) -> WriterFuture<'a, Option<AppliedWrite>>;

    fn apply<'a>(
        &'a self,
        record: &'a AcceptedIntentV1,
        pull_request: Option<&'a PullRequestPlan>,
    ) -> WriterFuture<'a, AppliedWrite>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedWrite {
    url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema_version: u32,
    session_id: SessionId,
    entries: BTreeMap<String, LedgerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerEntry {
    sequence: u64,
    tool: SafeOutputTool,
    state: LedgerState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LedgerState {
    Pending,
    Applied,
}

#[derive(Debug, Clone)]
struct PullRequestPlan {
    changes: Vec<PathChange>,
    patch_bytes: usize,
}

#[derive(Debug, Clone)]
struct PathChange {
    path: PathBuf,
    deleted: bool,
    source_sha256: Option<String>,
    mode: Option<u32>,
}

pub(crate) async fn process(
    context: &ProcessingContext,
    collection: &CollectedSafeOutputs,
    audit: &AuditRecorder,
) -> Result<ProcessingReport, HostError> {
    let verified = verify_collection(context, collection)?;
    let pull_requests = preflight_pull_requests(context, &verified.records)?;
    record_verified_audit(audit, context, &verified)?;
    if context.configuration.mode == SafeOutputsMode::Staged {
        let report = staged_report(context.policy.session_id, &verified);
        persist_report(context, &report)?;
        record_processed_audit(audit, context, &report)?;
        eprintln!(
            "sendbox: staged {} Safe Outputs operation(s) in {}",
            report.operation_count,
            context.state_directory.join(REPORT_FILE).display()
        );
        return Ok(report);
    }

    let has_writes = verified
        .records
        .iter()
        .any(|record| !record.operation.tool().is_system());
    if !has_writes {
        let report = applied_system_report(context.policy.session_id, &verified);
        persist_report(context, &report)?;
        record_processed_audit(audit, context, &report)?;
        return Ok(report);
    }
    let token = std::env::var(&context.configuration.write_token_env).map_err(|error| {
        HostError::SafeOutputs(format!(
            "read host-only GitHub token from {}: {error}",
            context.configuration.write_token_env
        ))
    })?;
    if token.is_empty() {
        return Err(HostError::SafeOutputs(format!(
            "host-only GitHub token {} is empty",
            context.configuration.write_token_env
        )));
    }
    let writer = GitHubRestWriter::new(context, Zeroizing::new(token))?;
    let report = process_with_writer(
        context,
        &verified.records,
        &verified.provenance,
        &pull_requests,
        &writer,
    )
    .await?;
    persist_report(context, &report)?;
    record_processed_audit(audit, context, &report)?;
    eprintln!(
        "sendbox: applied {} Safe Outputs operation(s)",
        report.operation_count
    );
    Ok(report)
}

fn record_verified_audit(
    audit: &AuditRecorder,
    context: &ProcessingContext,
    verified: &VerifiedCollection,
) -> Result<(), HostError> {
    record_audit(
        audit,
        context,
        "safe_outputs_verified",
        context.configuration.mode,
        verified.records.len(),
        &verified.provenance,
    )
}

fn record_processed_audit(
    audit: &AuditRecorder,
    context: &ProcessingContext,
    report: &ProcessingReport,
) -> Result<(), HostError> {
    record_audit(
        audit,
        context,
        "safe_outputs_processed",
        report.mode,
        report.operation_count,
        &BatchProvenance {
            boundary_plan_digest: report.boundary_plan_digest.clone(),
            policy_digest: report.policy_digest.clone(),
            artifact_sha256: report.artifact_sha256.clone(),
            chain_head: report.chain_head.clone(),
        },
    )
}

fn record_audit(
    audit: &AuditRecorder,
    context: &ProcessingContext,
    action: &'static str,
    mode: SafeOutputsMode,
    operation_count: usize,
    provenance: &BatchProvenance,
) -> Result<(), HostError> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| HostError::SafeOutputs(format!("read audit time: {error}")))?
        .as_nanos()
        .try_into()
        .map_err(|_| {
            HostError::SafeOutputs("Safe Outputs audit time is out of range".to_owned())
        })?;
    audit
        .record(
            timestamp,
            AuditCategory::Mcp,
            action,
            context.policy.session_id.to_string(),
            AuditResult::Success,
            BTreeMap::from([
                (
                    "boundary_plan_digest".to_owned(),
                    provenance.boundary_plan_digest.clone(),
                ),
                ("policy_digest".to_owned(), provenance.policy_digest.clone()),
                (
                    "artifact_sha256".to_owned(),
                    provenance.artifact_sha256.clone(),
                ),
                ("chain_head".to_owned(), provenance.chain_head.clone()),
                ("mode".to_owned(), mode_name(mode).to_owned()),
                ("operation_count".to_owned(), operation_count.to_string()),
            ]),
        )
        .map(|_| ())
        .map_err(HostError::SessionSecurity)
}

fn verify_collection(
    context: &ProcessingContext,
    collection: &CollectedSafeOutputs,
) -> Result<VerifiedCollection, HostError> {
    let expected = SafeOutputsRuntimePolicy::from_configuration(
        context.policy.session_id,
        &context.configuration,
    )
    .map_err(|error| HostError::SafeOutputs(format!("compile host policy: {error}")))?;
    if expected != context.policy {
        return Err(HostError::SafeOutputs(
            "host Safe Outputs configuration does not match the signed runtime policy".to_owned(),
        ));
    }
    context
        .policy
        .validate()
        .map_err(|error| HostError::SafeOutputs(error.to_string()))?;
    let seal: SafeOutputsSealV1 = serde_json::from_slice(&collection.seal)
        .map_err(|error| HostError::SafeOutputs(format!("decode authenticated seal: {error}")))?;
    let records = seal
        .verify(
            &context.policy,
            context.boundary_plan_digest,
            &collection.artifact,
            &context.seal_key,
        )
        .map_err(|error| {
            HostError::SafeOutputs(format!("verify authenticated artifact: {error}"))
        })?;
    Ok(VerifiedCollection {
        records,
        provenance: BatchProvenance {
            boundary_plan_digest: seal.boundary_plan_digest.to_string(),
            policy_digest: sha256_hex(&seal.policy_digest),
            artifact_sha256: sha256_hex(&seal.artifact_sha256),
            chain_head: sha256_hex(&seal.chain_head),
        },
    })
}

async fn process_with_writer(
    context: &ProcessingContext,
    records: &[AcceptedIntentV1],
    provenance: &BatchProvenance,
    pull_requests: &BTreeMap<String, PullRequestPlan>,
    writer: &dyn GitHubWriter,
) -> Result<ProcessingReport, HostError> {
    let mut ledger = load_ledger(context)?;
    let mut actions = Vec::with_capacity(records.len());
    for record in records {
        let tool = record.operation.tool();
        if tool.is_system() {
            actions.push(ActionReport {
                sequence: record.sequence,
                tool: tool.name().to_owned(),
                idempotency_key: record.idempotency_key.clone(),
                operation: record.operation.clone(),
                status: ActionStatus::Reported,
                url: None,
            });
            continue;
        }

        if let Some(entry) = ledger.entries.get(&record.idempotency_key) {
            if entry.sequence != record.sequence || entry.tool != tool {
                return Err(HostError::SafeOutputs(
                    "ledger entry does not match the authenticated operation".to_owned(),
                ));
            }
        }
        if let Some(entry) = ledger.entries.get(&record.idempotency_key)
            && entry.state == LedgerState::Applied
        {
            actions.push(ActionReport {
                sequence: record.sequence,
                tool: tool.name().to_owned(),
                idempotency_key: record.idempotency_key.clone(),
                operation: record.operation.clone(),
                status: ActionStatus::AlreadyApplied,
                url: entry.url.clone(),
            });
            continue;
        }

        if ledger
            .entries
            .get(&record.idempotency_key)
            .is_some_and(|entry| entry.state == LedgerState::Pending)
            && !matches!(
                tool,
                SafeOutputTool::AddLabels | SafeOutputTool::RemoveLabels
            )
            && let Some(applied) = writer.reconcile(record).await?
        {
            mark_applied(context, &mut ledger, record, applied.url.clone())?;
            actions.push(ActionReport {
                sequence: record.sequence,
                tool: tool.name().to_owned(),
                idempotency_key: record.idempotency_key.clone(),
                operation: record.operation.clone(),
                status: ActionStatus::AlreadyApplied,
                url: applied.url,
            });
            continue;
        }

        ledger
            .entries
            .entry(record.idempotency_key.clone())
            .or_insert(LedgerEntry {
                sequence: record.sequence,
                tool,
                state: LedgerState::Pending,
                url: None,
            });
        persist_ledger(context, &ledger)?;
        let applied = writer
            .apply(record, pull_requests.get(&record.idempotency_key))
            .await?;
        mark_applied(context, &mut ledger, record, applied.url.clone())?;
        actions.push(ActionReport {
            sequence: record.sequence,
            tool: tool.name().to_owned(),
            idempotency_key: record.idempotency_key.clone(),
            operation: record.operation.clone(),
            status: ActionStatus::Applied,
            url: applied.url,
        });
    }
    Ok(ProcessingReport {
        schema_version: REPORT_SCHEMA_VERSION,
        session_id: context.policy.session_id,
        mode: SafeOutputsMode::Apply,
        boundary_plan_digest: provenance.boundary_plan_digest.clone(),
        policy_digest: provenance.policy_digest.clone(),
        artifact_sha256: provenance.artifact_sha256.clone(),
        chain_head: provenance.chain_head.clone(),
        operation_count: records.len(),
        actions,
    })
}

fn mark_applied(
    context: &ProcessingContext,
    ledger: &mut Ledger,
    record: &AcceptedIntentV1,
    url: Option<String>,
) -> Result<(), HostError> {
    let entry = ledger
        .entries
        .get_mut(&record.idempotency_key)
        .ok_or_else(|| HostError::SafeOutputs("pending ledger entry disappeared".to_owned()))?;
    entry.state = LedgerState::Applied;
    entry.url = url;
    persist_ledger(context, ledger)
}

fn staged_report(session_id: SessionId, verified: &VerifiedCollection) -> ProcessingReport {
    ProcessingReport {
        schema_version: REPORT_SCHEMA_VERSION,
        session_id,
        mode: SafeOutputsMode::Staged,
        boundary_plan_digest: verified.provenance.boundary_plan_digest.clone(),
        policy_digest: verified.provenance.policy_digest.clone(),
        artifact_sha256: verified.provenance.artifact_sha256.clone(),
        chain_head: verified.provenance.chain_head.clone(),
        operation_count: verified.records.len(),
        actions: verified
            .records
            .iter()
            .map(|record| ActionReport {
                sequence: record.sequence,
                tool: record.operation.tool().name().to_owned(),
                idempotency_key: record.idempotency_key.clone(),
                operation: record.operation.clone(),
                status: ActionStatus::Staged,
                url: None,
            })
            .collect(),
    }
}

fn applied_system_report(session_id: SessionId, verified: &VerifiedCollection) -> ProcessingReport {
    ProcessingReport {
        schema_version: REPORT_SCHEMA_VERSION,
        session_id,
        mode: SafeOutputsMode::Apply,
        boundary_plan_digest: verified.provenance.boundary_plan_digest.clone(),
        policy_digest: verified.provenance.policy_digest.clone(),
        artifact_sha256: verified.provenance.artifact_sha256.clone(),
        chain_head: verified.provenance.chain_head.clone(),
        operation_count: verified.records.len(),
        actions: verified
            .records
            .iter()
            .map(|record| ActionReport {
                sequence: record.sequence,
                tool: record.operation.tool().name().to_owned(),
                idempotency_key: record.idempotency_key.clone(),
                operation: record.operation.clone(),
                status: ActionStatus::Reported,
                url: None,
            })
            .collect(),
    }
}

const fn mode_name(mode: SafeOutputsMode) -> &'static str {
    match mode {
        SafeOutputsMode::Staged => "staged",
        SafeOutputsMode::Apply => "apply",
    }
}

fn load_ledger(context: &ProcessingContext) -> Result<Ledger, HostError> {
    let path = context.state_directory.join(LEDGER_FILE);
    if !path.exists() {
        return Ok(Ledger {
            schema_version: LEDGER_SCHEMA_VERSION,
            session_id: context.policy.session_id,
            entries: BTreeMap::new(),
        });
    }
    let bytes = std::fs::read(&path).map_err(|source| HostError::Io {
        context: "read Safe Outputs ledger",
        path: path.clone(),
        source,
    })?;
    let ledger: Ledger = serde_json::from_slice(&bytes)
        .map_err(|error| HostError::SafeOutputs(format!("decode ledger: {error}")))?;
    if ledger.schema_version != LEDGER_SCHEMA_VERSION
        || ledger.session_id != context.policy.session_id
    {
        return Err(HostError::SafeOutputs(
            "ledger belongs to a different Safe Outputs session".to_owned(),
        ));
    }
    Ok(ledger)
}

fn persist_ledger(context: &ProcessingContext, ledger: &Ledger) -> Result<(), HostError> {
    let bytes = serde_json::to_vec_pretty(ledger)
        .map_err(|error| HostError::SafeOutputs(format!("encode ledger: {error}")))?;
    atomic_write(&context.state_directory.join(LEDGER_FILE), &bytes, 0o600)
}

fn persist_report(context: &ProcessingContext, report: &ProcessingReport) -> Result<(), HostError> {
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| HostError::SafeOutputs(format!("encode report: {error}")))?;
    atomic_write(&context.state_directory.join(REPORT_FILE), &bytes, 0o600)
}

fn preflight_pull_requests(
    context: &ProcessingContext,
    records: &[AcceptedIntentV1],
) -> Result<BTreeMap<String, PullRequestPlan>, HostError> {
    records
        .iter()
        .filter_map(|record| match &record.operation {
            SafeOutputOperation::CreatePullRequest(operation) => Some(
                preflight_pull_request(context, &operation.base)
                    .map(|plan| (record.idempotency_key.clone(), plan)),
            ),
            _ => None,
        })
        .collect()
}

fn preflight_pull_request(
    context: &ProcessingContext,
    base_branch: &str,
) -> Result<PullRequestPlan, HostError> {
    let configured = &context.configuration.create_pull_request;
    let git = trusted_git()?;
    let environment = safe_git_environment(&context.state_directory);
    validate_branch_name(base_branch)?;
    let base_commit =
        resolve_local_base_commit(&git, &context.workspace, &environment, base_branch)?;
    let status = run_git(
        &git,
        &context.workspace,
        &environment,
        &[
            "--no-optional-locks",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ],
        GIT_OUTPUT_LIMIT,
    )?;
    let parsed = parse_status(&status)?;
    let mut changes = BTreeMap::<PathBuf, (bool, Option<String>, Option<u32>)>::new();
    let mut untracked = BTreeSet::new();
    for change in parsed {
        if change.untracked {
            untracked.insert(change.path.clone());
        }
        add_preflight_change(context, configured, &mut changes, change.path)?;
        if let Some(original) = change.original {
            add_deleted_preflight_change(configured, &mut changes, original)?;
        }
    }
    let baseline_changes = run_git(
        &git,
        &context.workspace,
        &environment,
        &[
            "--no-optional-locks",
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            &base_commit,
            "--",
        ],
        GIT_OUTPUT_LIMIT,
    )?;
    for change in parse_name_status(&baseline_changes)? {
        add_preflight_change(context, configured, &mut changes, change.path)?;
        if let Some(original) = change.original {
            add_deleted_preflight_change(configured, &mut changes, original)?;
        }
    }
    if changes.is_empty() {
        return Err(HostError::SafeOutputs(
            "create_pull_request requires at least one workspace change".to_owned(),
        ));
    }
    if changes.len() > usize::try_from(configured.max_changed_files).unwrap_or(usize::MAX) {
        return Err(HostError::SafeOutputs(format!(
            "pull request changes {} files, exceeding the {} file limit",
            changes.len(),
            configured.max_changed_files
        )));
    }
    let paths = changes.keys().cloned().collect::<Vec<_>>();
    let mut arguments = vec![
        "--no-optional-locks".to_owned(),
        "diff".to_owned(),
        "--binary".to_owned(),
        "--no-ext-diff".to_owned(),
        "--no-textconv".to_owned(),
        base_commit,
        "--".to_owned(),
    ];
    arguments.extend(paths.iter().map(|path| path.display().to_string()));
    let argument_refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let tracked_patch = run_git(
        &git,
        &context.workspace,
        &environment,
        &argument_refs,
        configured.max_patch_bytes.saturating_add(1),
    )?;
    let untracked_bytes = untracked.iter().try_fold(0_usize, |total, path| {
        reject_symlinked_parents(
            &context.workspace,
            path,
            "untracked Safe Outputs workspace path",
        )?;
        let source_path = context.workspace.join(path);
        let metadata = std::fs::symlink_metadata(&source_path).map_err(|source| HostError::Io {
            context: "measure untracked Safe Outputs file",
            path: source_path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HostError::SafeOutputs(format!(
                "untracked pull-request path `{}` is not a regular file",
                path.display()
            )));
        }
        let length = metadata.len();
        let length = usize::try_from(length).map_err(|_| {
            HostError::SafeOutputs("untracked file size is out of range".to_owned())
        })?;
        Ok::<_, HostError>(total.saturating_add(length))
    })?;
    let patch_bytes = tracked_patch.len().saturating_add(untracked_bytes);
    if patch_bytes > configured.max_patch_bytes {
        return Err(HostError::SafeOutputs(format!(
            "pull request patch is {patch_bytes} bytes, exceeding the {} byte limit",
            configured.max_patch_bytes
        )));
    }

    fn resolve_local_base_commit(
        git: &TrustedGitBinary,
        workspace: &Path,
        environment: &BTreeMap<String, String>,
        base_branch: &str,
    ) -> Result<String, HostError> {
        for reference in [
            format!("refs/remotes/origin/{base_branch}"),
            format!("refs/heads/{base_branch}"),
        ] {
            let commitish = format!("{reference}^{{commit}}");
            if let Some(output) = run_git_optional(
                git,
                workspace,
                environment,
                &[
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    "--end-of-options",
                    &commitish,
                ],
                128,
            )? {
                let commit = String::from_utf8(output)
                    .map_err(|_| HostError::SafeOutputs("base commit ID is not UTF-8".to_owned()))?
                    .trim()
                    .to_owned();
                if commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Ok(commit);
                }
                return Err(HostError::SafeOutputs(
                    "Git returned an invalid base commit ID".to_owned(),
                ));
            }
        }
        Err(HostError::SafeOutputs(format!(
            "base branch `{base_branch}` is not available in the local repository"
        )))
    }

    fn add_preflight_change(
        context: &ProcessingContext,
        configured: &sendbox_config::CreatePullRequestSafeOutputConfiguration,
        changes: &mut BTreeMap<PathBuf, (bool, Option<String>, Option<u32>)>,
        path: PathBuf,
    ) -> Result<(), HostError> {
        validate_changed_path(&path, configured)?;
        reject_symlinked_parents(&context.workspace, &path, "Safe Outputs workspace path")?;
        let source = context.workspace.join(&path);
        let state = match std::fs::symlink_metadata(&source) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(HostError::SafeOutputs(format!(
                        "pull-request path `{}` is not a regular file",
                        path.display()
                    )));
                }
                let bytes = std::fs::read(&source).map_err(|source_error| HostError::Io {
                    context: "read Safe Outputs pull-request path",
                    path: source,
                    source: source_error,
                })?;
                (
                    false,
                    Some(sha256_hex(&bytes)),
                    Some(metadata.permissions().mode() & 0o777),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (true, None, None),
            Err(source_error) => {
                return Err(HostError::Io {
                    context: "inspect Safe Outputs pull-request path",
                    path: source,
                    source: source_error,
                });
            }
        };
        changes.insert(path, state);
        Ok(())
    }

    fn add_deleted_preflight_change(
        configured: &sendbox_config::CreatePullRequestSafeOutputConfiguration,
        changes: &mut BTreeMap<PathBuf, (bool, Option<String>, Option<u32>)>,
        path: PathBuf,
    ) -> Result<(), HostError> {
        validate_changed_path(&path, configured)?;
        changes.insert(path, (true, None, None));
        Ok(())
    }
    Ok(PullRequestPlan {
        changes: changes
            .into_iter()
            .map(|(path, (deleted, source_sha256, mode))| PathChange {
                path,
                deleted,
                source_sha256,
                mode,
            })
            .collect(),
        patch_bytes,
    })
}

struct ParsedChange {
    path: PathBuf,
    original: Option<PathBuf>,
    untracked: bool,
}

fn parse_name_status(bytes: &[u8]) -> Result<Vec<ParsedChange>, HostError> {
    let mut offset = 0;
    let mut changes = Vec::new();
    while offset < bytes.len() {
        let status = take_nul_text(bytes, &mut offset, "Git diff status")?;
        let kind = status.as_bytes().first().copied().ok_or_else(|| {
            HostError::SafeOutputs("Git diff returned an empty status".to_owned())
        })?;
        if !matches!(kind, b'A' | b'C' | b'D' | b'M' | b'R' | b'T') {
            return Err(HostError::SafeOutputs(format!(
                "Git diff returned unsupported status `{status}`"
            )));
        }
        let first = take_nul_path(bytes, &mut offset)?;
        let (path, original) = if matches!(kind, b'R' | b'C') {
            let second = take_nul_path(bytes, &mut offset)?;
            (second, (kind == b'R').then_some(first))
        } else {
            (first, None)
        };
        changes.push(ParsedChange {
            path,
            original,
            untracked: false,
        });
    }
    Ok(changes)
}

fn take_nul_text(bytes: &[u8], offset: &mut usize, subject: &str) -> Result<String, HostError> {
    let end = bytes[*offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| *offset + position)
        .ok_or_else(|| HostError::SafeOutputs(format!("{subject} is missing its delimiter")))?;
    let value = std::str::from_utf8(&bytes[*offset..end])
        .map_err(|_| HostError::SafeOutputs(format!("{subject} is not UTF-8")))?
        .to_owned();
    *offset = end + 1;
    Ok(value)
}

fn parse_status(bytes: &[u8]) -> Result<Vec<ParsedChange>, HostError> {
    let mut offset = 0;
    let mut changes = Vec::new();
    while offset < bytes.len() {
        if bytes.len().saturating_sub(offset) < 4 || bytes[offset + 2] != b' ' {
            return Err(HostError::SafeOutputs(
                "Git returned malformed porcelain status".to_owned(),
            ));
        }
        let status = [bytes[offset], bytes[offset + 1]];
        if status.contains(&b'U') {
            return Err(HostError::SafeOutputs(
                "pull-request creation rejects unresolved merge conflicts".to_owned(),
            ));
        }
        offset += 3;
        let path = take_nul_path(bytes, &mut offset)?;
        let original = if status.iter().any(|status| matches!(status, b'R' | b'C')) {
            let original = take_nul_path(bytes, &mut offset)?;
            status.contains(&b'R').then_some(original)
        } else {
            None
        };
        changes.push(ParsedChange {
            path,
            original,
            untracked: status == [b'?', b'?'],
        });
    }
    Ok(changes)
}

fn take_nul_path(bytes: &[u8], offset: &mut usize) -> Result<PathBuf, HostError> {
    let end = bytes[*offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| *offset + position)
        .ok_or_else(|| {
            HostError::SafeOutputs("Git status path is missing its delimiter".to_owned())
        })?;
    let value = std::str::from_utf8(&bytes[*offset..end])
        .map_err(|_| HostError::SafeOutputs("pull-request paths must be valid UTF-8".to_owned()))?;
    *offset = end + 1;
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(HostError::SafeOutputs(format!(
            "pull-request path `{value}` is not normalized"
        )));
    }
    Ok(path)
}

fn validate_changed_path(
    path: &Path,
    configured: &sendbox_config::CreatePullRequestSafeOutputConfiguration,
) -> Result<(), HostError> {
    let value = path.to_str().ok_or_else(|| {
        HostError::SafeOutputs("pull-request paths must be valid UTF-8".to_owned())
    })?;
    if configured
        .protected_paths
        .iter()
        .any(|pattern| glob_matches(value, pattern))
    {
        return Err(HostError::SafeOutputs(format!(
            "pull-request path `{value}` is protected"
        )));
    }
    if !configured
        .allowed_paths
        .iter()
        .any(|pattern| glob_matches(value, pattern))
    {
        return Err(HostError::SafeOutputs(format!(
            "pull-request path `{value}` is not allowed"
        )));
    }
    Ok(())
}

fn reject_symlinked_parents(root: &Path, relative: &Path, subject: &str) -> Result<(), HostError> {
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    for component in parent.components() {
        let Component::Normal(value) = component else {
            return Err(HostError::SafeOutputs(format!(
                "{subject} contains an invalid component"
            )));
        };
        current.push(value);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {}
            Ok(_) => {
                return Err(HostError::SafeOutputs(format!(
                    "{subject} parent `{}` is not a regular directory",
                    current.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(HostError::Io {
                    context: "inspect Safe Outputs path parent",
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn create_isolated_parents(root: &Path, relative: &Path) -> Result<(), HostError> {
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    for component in parent.components() {
        let Component::Normal(value) = component else {
            return Err(HostError::SafeOutputs(
                "isolated pull-request path contains an invalid component".to_owned(),
            ));
        };
        current.push(value);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {}
            Ok(_) => {
                return Err(HostError::SafeOutputs(format!(
                    "isolated pull-request parent `{}` is not a regular directory",
                    current.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|source| HostError::Io {
                    context: "create isolated pull-request directory",
                    path: current.clone(),
                    source,
                })?;
            }
            Err(source) => {
                return Err(HostError::Io {
                    context: "inspect isolated pull-request directory",
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn write_isolated_file(
    root: &Path,
    relative: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), HostError> {
    create_isolated_parents(root, relative)?;
    let destination = root.join(relative);
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
            std::fs::remove_file(&destination).map_err(|source| HostError::Io {
                context: "replace isolated pull-request file",
                path: destination.clone(),
                source,
            })?;
        }
        Ok(_) => {
            return Err(HostError::SafeOutputs(format!(
                "isolated pull-request path `{}` is not a regular file",
                relative.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(HostError::Io {
                context: "inspect isolated pull-request file",
                path: destination.clone(),
                source,
            });
        }
    }
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&destination)
            .map_err(|source| HostError::Io {
                context: "create isolated pull-request file",
                path: destination.clone(),
                source,
            })?;
        std::io::Write::write_all(&mut file, bytes).map_err(|source| HostError::Io {
            context: "write isolated pull-request file",
            path: destination.clone(),
            source,
        })?;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(mode)).map_err(
            |source| HostError::Io {
                context: "set isolated pull-request path mode",
                path: destination.clone(),
                source,
            },
        )
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&destination);
    }
    result
}

struct GitHubRestWriter<'a> {
    context: &'a ProcessingContext,
    client: reqwest::Client,
    token: Zeroizing<String>,
}

impl<'a> GitHubRestWriter<'a> {
    fn new(context: &'a ProcessingContext, token: Zeroizing<String>) -> Result<Self, HostError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| HostError::SafeOutputs(format!("build GitHub client: {error}")))?;
        Ok(Self {
            context,
            client,
            token,
        })
    }

    async fn find_marker(
        &self,
        record: &AcceptedIntentV1,
    ) -> Result<Option<AppliedWrite>, HostError> {
        let marker = marker(&record.idempotency_key);
        let response = match &record.operation {
            SafeOutputOperation::CreateIssue(value) => {
                self.request(
                    Method::GET,
                    &value.repository,
                    &["issues"],
                    &[
                        ("state", "all"),
                        ("sort", "created"),
                        ("direction", "desc"),
                        ("per_page", "100"),
                    ],
                    None,
                )
                .await?
            }
            SafeOutputOperation::AddComment(value) => {
                let number = value.item_number.to_string();
                self.request(
                    Method::GET,
                    &value.repository,
                    &["issues", &number, "comments"],
                    &[("per_page", "100")],
                    None,
                )
                .await?
            }
            SafeOutputOperation::CreatePullRequest(value) => {
                self.request(
                    Method::GET,
                    &value.repository,
                    &["pulls"],
                    &[
                        ("state", "all"),
                        ("sort", "created"),
                        ("direction", "desc"),
                        ("per_page", "100"),
                    ],
                    None,
                )
                .await?
            }
            _ => return Ok(None),
        };
        let Some(items) = response.as_array() else {
            return Err(HostError::SafeOutputs(
                "GitHub reconciliation response is not an array".to_owned(),
            ));
        };
        Ok(items.iter().find_map(|item| {
            item.get("body")
                .and_then(Value::as_str)
                .filter(|body| body.contains(&marker))
                .map(|_| AppliedWrite {
                    url: item
                        .get("html_url")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                })
        }))
    }

    async fn apply_record(
        &self,
        record: &AcceptedIntentV1,
        pull_request: Option<&PullRequestPlan>,
    ) -> Result<AppliedWrite, HostError> {
        match &record.operation {
            SafeOutputOperation::CreateIssue(value) => {
                let response = self
                    .request(
                        Method::POST,
                        &value.repository,
                        &["issues"],
                        &[],
                        Some(json!({
                            "title": value.title,
                            "body": marked_body(&value.body, &record.idempotency_key),
                            "labels": value.labels,
                            "assignees": value.assignees
                        })),
                    )
                    .await?;
                Ok(applied_url(&response))
            }
            SafeOutputOperation::AddComment(value) => {
                let number = value.item_number.to_string();
                let response = self
                    .request(
                        Method::POST,
                        &value.repository,
                        &["issues", &number, "comments"],
                        &[],
                        Some(json!({
                            "body": marked_body(&value.body, &record.idempotency_key)
                        })),
                    )
                    .await?;
                Ok(applied_url(&response))
            }
            SafeOutputOperation::AddLabels(value) => {
                let number = value.item_number.to_string();
                let response = self
                    .request(
                        Method::POST,
                        &value.repository,
                        &["issues", &number, "labels"],
                        &[],
                        Some(json!({ "labels": value.labels })),
                    )
                    .await?;
                Ok(applied_url(&response))
            }
            SafeOutputOperation::RemoveLabels(value) => {
                let number = value.item_number.to_string();
                for label in &value.labels {
                    let (status, response) = self
                        .request_status(
                            Method::DELETE,
                            &value.repository,
                            &["issues", &number, "labels", label],
                            &[],
                            None,
                        )
                        .await?;
                    if !status.is_success() && status != StatusCode::NOT_FOUND {
                        return Err(github_status_error(status, &response));
                    }
                }
                Ok(AppliedWrite { url: None })
            }
            SafeOutputOperation::CreatePullRequest(value) => {
                let plan = pull_request.ok_or_else(|| {
                    HostError::SafeOutputs(
                        "pull-request operation is missing its preflight plan".to_owned(),
                    )
                })?;
                self.create_pull_request(record, value, plan).await
            }
            SafeOutputOperation::Noop(_)
            | SafeOutputOperation::MissingTool(_)
            | SafeOutputOperation::MissingData(_)
            | SafeOutputOperation::ReportIncomplete(_) => Err(HostError::SafeOutputs(
                "system output reached the GitHub writer".to_owned(),
            )),
        }
    }

    async fn create_pull_request(
        &self,
        record: &AcceptedIntentV1,
        operation: &CreatePullRequestOperation,
        plan: &PullRequestPlan,
    ) -> Result<AppliedWrite, HostError> {
        let prepared = PreparedPullRequest::build(
            self.context,
            operation,
            &record.idempotency_key,
            record.accepted_at_unix_ms,
            plan,
            self.token.as_str(),
        )?;
        let remote = self
            .remote_ref(&operation.repository, &prepared.branch)
            .await?;
        match remote {
            Some(remote_sha) if remote_sha != prepared.commit_sha => {
                return Err(HostError::SafeOutputs(format!(
                    "remote Safe Outputs branch {} has an unexpected commit",
                    prepared.branch
                )));
            }
            Some(_) => {}
            None => prepared.push(&operation.repository, self.token.as_str())?,
        }
        let response = self
            .request(
                Method::POST,
                &operation.repository,
                &["pulls"],
                &[],
                Some(json!({
                    "title": operation.title,
                    "body": marked_body(&operation.body, &record.idempotency_key),
                    "head": prepared.branch,
                    "base": operation.base,
                    "draft": operation.draft
                })),
            )
            .await?;
        Ok(applied_url(&response))
    }

    async fn remote_ref(
        &self,
        repository: &str,
        branch: &str,
    ) -> Result<Option<String>, HostError> {
        let mut suffix = vec!["git", "ref", "heads"];
        suffix.extend(branch.split('/'));
        let (status, value) = self
            .request_status(Method::GET, repository, &suffix, &[], None)
            .await?;
        parse_remote_ref(status, &value)
    }

    async fn request(
        &self,
        method: Method,
        repository: &str,
        suffix: &[&str],
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, HostError> {
        let (status, value) = self
            .request_status(method, repository, suffix, query, body)
            .await?;
        if status.is_success() {
            Ok(value)
        } else {
            Err(github_status_error(status, &value))
        }
    }

    async fn request_status(
        &self,
        method: Method,
        repository: &str,
        suffix: &[&str],
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<(StatusCode, Value), HostError> {
        let mut url = github_url(repository, suffix)?;
        url.query_pairs_mut().extend_pairs(query.iter().copied());
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(self.token.as_str())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "sendbox-safe-outputs");
        if let Some(body) = body {
            let encoded = serde_json::to_vec(&body).map_err(|error| {
                HostError::SafeOutputs(format!("encode GitHub request: {error}"))
            })?;
            request = request
                .header("Content-Type", "application/json")
                .body(encoded);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| HostError::SafeOutputs(format!("GitHub request failed: {error}")))?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| HostError::SafeOutputs(format!("read GitHub response: {error}")))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_GITHUB_RESPONSE_BYTES {
                return Err(HostError::SafeOutputs(format!(
                    "GitHub response exceeded {MAX_GITHUB_RESPONSE_BYTES} bytes"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|error| {
                HostError::SafeOutputs(format!("decode GitHub response: {error}"))
            })?
        };
        Ok((status, value))
    }
}

impl GitHubWriter for GitHubRestWriter<'_> {
    fn reconcile<'a>(
        &'a self,
        record: &'a AcceptedIntentV1,
    ) -> WriterFuture<'a, Option<AppliedWrite>> {
        Box::pin(self.find_marker(record))
    }

    fn apply<'a>(
        &'a self,
        record: &'a AcceptedIntentV1,
        pull_request: Option<&'a PullRequestPlan>,
    ) -> WriterFuture<'a, AppliedWrite> {
        Box::pin(self.apply_record(record, pull_request))
    }
}

fn parse_remote_ref(status: StatusCode, value: &Value) -> Result<Option<String>, HostError> {
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(github_status_error(status, value));
    }
    let sha = value
        .get("object")
        .and_then(|object| object.get("sha"))
        .and_then(Value::as_str)
        .filter(|sha| sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            HostError::SafeOutputs("GitHub returned an invalid remote ref object".to_owned())
        })?;
    Ok(Some(sha.to_owned()))
}

fn github_url(repository: &str, suffix: &[&str]) -> Result<Url, HostError> {
    let (owner, name) = repository.split_once('/').ok_or_else(|| {
        HostError::SafeOutputs(format!("invalid GitHub repository `{repository}`"))
    })?;
    let mut url = Url::parse("https://api.github.com")
        .map_err(|error| HostError::SafeOutputs(format!("build GitHub URL: {error}")))?;
    {
        let mut segments = url.path_segments_mut().map_err(|()| {
            HostError::SafeOutputs("GitHub base URL cannot be extended".to_owned())
        })?;
        segments.extend(["repos", owner, name]);
        segments.extend(suffix.iter().copied());
    }
    Ok(url)
}

fn github_status_error(status: StatusCode, value: &Value) -> HostError {
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("GitHub request failed")
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect::<String>();
    HostError::SafeOutputs(format!("GitHub returned {status}: {message}"))
}

fn applied_url(response: &Value) -> AppliedWrite {
    AppliedWrite {
        url: response
            .get("html_url")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

fn marker(idempotency_key: &str) -> String {
    format!("<!-- sendbox-safe-output:{idempotency_key} -->")
}

fn marked_body(body: &str, idempotency_key: &str) -> String {
    format!("{body}\n\n{}", marker(idempotency_key))
}

struct SensitiveGitEnvironment {
    values: BTreeMap<String, String>,
    token_environment: String,
}

impl SensitiveGitEnvironment {
    fn new(base: &BTreeMap<String, String>, token_environment: &str, token: &str) -> Self {
        let mut values = base.clone();
        values.insert(token_environment.to_owned(), token.to_owned());
        Self {
            values,
            token_environment: token_environment.to_owned(),
        }
    }

    fn values(&self) -> &BTreeMap<String, String> {
        &self.values
    }
}

impl Drop for SensitiveGitEnvironment {
    fn drop(&mut self) {
        if let Some(value) = self.values.get_mut(&self.token_environment) {
            zeroize::Zeroize::zeroize(value);
        }
    }
}

struct PreparedPullRequest {
    _temporary: TempDir,
    git: TrustedGitBinary,
    environment: BTreeMap<String, String>,
    repository: PathBuf,
    askpass: PathBuf,
    token_environment: String,
    branch: String,
    commit_sha: String,
}

impl PreparedPullRequest {
    fn build(
        context: &ProcessingContext,
        operation: &CreatePullRequestOperation,
        idempotency_key: &str,
        accepted_at_unix_ms: u64,
        plan: &PullRequestPlan,
        token: &str,
    ) -> Result<Self, HostError> {
        validate_branch_name(&operation.base)?;
        let git = trusted_git()?;
        let temporary = tempfile::Builder::new()
            .prefix("safe-outputs-pr-")
            .tempdir_in(&context.state_directory)
            .map_err(|source| HostError::Io {
                context: "create isolated Safe Outputs Git repository",
                path: context.state_directory.clone(),
                source,
            })?;
        let repository = temporary.path().join("repository");
        std::fs::create_dir(&repository).map_err(|source| HostError::Io {
            context: "create isolated Git worktree",
            path: repository.clone(),
            source,
        })?;
        let askpass = temporary.path().join("askpass");
        write_askpass(&askpass, &context.configuration.write_token_env)?;
        let mut environment = safe_git_environment(temporary.path());
        environment.insert("GIT_ASKPASS".to_owned(), askpass.display().to_string());
        environment.insert("GIT_ASKPASS_REQUIRE".to_owned(), "force".to_owned());
        environment.insert("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned());
        let remote = format!("https://github.com/{}.git", operation.repository);
        run_git_ok(&git, &repository, &environment, &["init", "--quiet"])?;
        let refspec = format!(
            "refs/heads/{}:refs/remotes/origin/{}",
            operation.base, operation.base
        );
        let authenticated_environment = SensitiveGitEnvironment::new(
            &environment,
            &context.configuration.write_token_env,
            token,
        );
        run_git_ok(
            &git,
            &repository,
            authenticated_environment.values(),
            &["fetch", "--depth=1", "--", &remote, &refspec],
        )?;
        drop(authenticated_environment);
        let branch = format!(
            "safe-outputs/{}-{}",
            &context.policy.session_id.to_string()[..12],
            &idempotency_key[..12]
        );
        run_git_ok(
            &git,
            &repository,
            &environment,
            &["checkout", "--quiet", "-b", &branch, "FETCH_HEAD"],
        )?;
        for change in &plan.changes {
            let source = context.workspace.join(&change.path);
            let destination = repository.join(&change.path);
            reject_symlinked_parents(
                &context.workspace,
                &change.path,
                "Safe Outputs workspace path",
            )?;
            reject_symlinked_parents(&repository, &change.path, "isolated pull-request path")?;
            if change.deleted {
                match std::fs::symlink_metadata(&source) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => {
                        return Err(HostError::SafeOutputs(format!(
                            "deleted pull-request path `{}` reappeared after preflight",
                            change.path.display()
                        )));
                    }
                    Err(source_error) => {
                        return Err(HostError::Io {
                            context: "reverify deleted Safe Outputs path",
                            path: source,
                            source: source_error,
                        });
                    }
                }
                match std::fs::remove_file(&destination) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(HostError::Io {
                            context: "remove deleted Safe Outputs path",
                            path: destination,
                            source,
                        });
                    }
                }
                continue;
            }
            let metadata = source
                .symlink_metadata()
                .map_err(|source_error| HostError::Io {
                    context: "reverify Safe Outputs source path",
                    path: source.clone(),
                    source: source_error,
                })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(HostError::SafeOutputs(format!(
                    "pull-request path `{}` changed type after preflight",
                    change.path.display()
                )));
            }
            let bytes = std::fs::read(&source).map_err(|source_error| HostError::Io {
                context: "read reverified Safe Outputs source path",
                path: source.clone(),
                source: source_error,
            })?;
            let mode = metadata.permissions().mode() & 0o777;
            if change.source_sha256.as_deref() != Some(sha256_hex(&bytes).as_str()) {
                return Err(HostError::SafeOutputs(format!(
                    "pull-request path `{}` changed after preflight",
                    change.path.display()
                )));
            }
            if change.mode != Some(mode) {
                return Err(HostError::SafeOutputs(format!(
                    "pull-request path `{}` changed mode after preflight",
                    change.path.display()
                )));
            }
            write_isolated_file(
                &repository,
                &change.path,
                &bytes,
                change.mode.unwrap_or(0o644),
            )?;
        }
        let mut add = vec!["add".to_owned(), "-A".to_owned(), "--".to_owned()];
        add.extend(
            plan.changes
                .iter()
                .map(|change| change.path.display().to_string()),
        );
        let add_refs = add.iter().map(String::as_str).collect::<Vec<_>>();
        run_git_ok(&git, &repository, &environment, &add_refs)?;
        let patch = run_git(
            &git,
            &repository,
            &environment,
            &[
                "diff",
                "--cached",
                "--binary",
                "--no-ext-diff",
                "--no-textconv",
            ],
            context
                .configuration
                .create_pull_request
                .max_patch_bytes
                .saturating_add(1),
        )?;
        if patch.is_empty()
            || patch.len() > context.configuration.create_pull_request.max_patch_bytes
        {
            return Err(HostError::SafeOutputs(
                "isolated pull-request patch is empty or exceeds its configured limit".to_owned(),
            ));
        }
        if patch.len() != plan.patch_bytes && plan.patch_bytes != 0 {
            let maximum = context.configuration.create_pull_request.max_patch_bytes;
            if patch.len() > maximum {
                return Err(HostError::SafeOutputs(
                    "pull-request patch changed after preflight".to_owned(),
                ));
            }
        }
        let seconds = accepted_at_unix_ms / 1_000;
        environment.insert("GIT_AUTHOR_DATE".to_owned(), format!("@{seconds} +0000"));
        environment.insert("GIT_COMMITTER_DATE".to_owned(), format!("@{seconds} +0000"));
        let message = format!(
            "Safe Outputs: {}\n\nSendBox-Idempotency-Key: {idempotency_key}",
            operation.title
        );
        run_git_ok(
            &git,
            &repository,
            &environment,
            &[
                "-c",
                "user.name=SendBox Safe Outputs",
                "-c",
                "user.email=safe-outputs@sendbox.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                &message,
            ],
        )?;
        let commit_sha = String::from_utf8(run_git(
            &git,
            &repository,
            &environment,
            &["rev-parse", "HEAD"],
            128,
        )?)
        .map_err(|_| HostError::SafeOutputs("Git commit ID is not UTF-8".to_owned()))?
        .trim()
        .to_owned();
        if commit_sha.len() != 40 || !commit_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HostError::SafeOutputs(
                "Git returned an invalid commit ID".to_owned(),
            ));
        }
        Ok(Self {
            _temporary: temporary,
            git,
            environment,
            repository,
            askpass,
            token_environment: context.configuration.write_token_env.clone(),
            branch,
            commit_sha,
        })
    }

    fn push(&self, repository: &str, token: &str) -> Result<(), HostError> {
        let metadata = self
            .askpass
            .symlink_metadata()
            .map_err(|source| HostError::Io {
                context: "reverify Safe Outputs askpass",
                path: self.askpass.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(HostError::SafeOutputs(
                "Safe Outputs askpass integrity check failed".to_owned(),
            ));
        }
        let environment =
            SensitiveGitEnvironment::new(&self.environment, &self.token_environment, token);
        let remote = format!("https://github.com/{repository}.git");
        let refspec = format!("HEAD:refs/heads/{}", self.branch);
        run_git_ok(
            &self.git,
            &self.repository,
            environment.values(),
            &["push", "--porcelain", "--", &remote, &refspec],
        )
    }
}

fn validate_branch_name(branch: &str) -> Result<(), HostError> {
    if branch.is_empty()
        || branch.starts_with('-')
        || branch.ends_with('.')
        || branch.contains("..")
        || branch.contains("@{")
        || branch.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
    {
        return Err(HostError::SafeOutputs(format!(
            "base branch `{branch}` is not a safe Git ref"
        )));
    }
    Ok(())
}

fn write_askpass(path: &Path, token_environment: &str) -> Result<(), HostError> {
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n  *Username*) printf '%s\\n' x-access-token ;;\n  *Password*) exec /usr/bin/printenv {token_environment} ;;\n  *) exit 1 ;;\nesac\n"
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(path)
        .map_err(|source| HostError::Io {
            context: "create Safe Outputs askpass",
            path: path.to_path_buf(),
            source,
        })?;
    std::io::Write::write_all(&mut file, script.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| HostError::Io {
            context: "write Safe Outputs askpass",
            path: path.to_path_buf(),
            source,
        })
}

fn trusted_git() -> Result<TrustedGitBinary, HostError> {
    TrustedGitBinary::verify(resolve_executable("git")?).map_err(HostError::GitGuard)
}

fn safe_git_environment(home: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("GIT_CONFIG_GLOBAL".to_owned(), "/dev/null".to_owned()),
        ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
        ("GIT_CONFIG_SYSTEM".to_owned(), "/dev/null".to_owned()),
        ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
        ("HOME".to_owned(), home.display().to_string()),
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned()),
    ])
}

fn run_git_ok(
    git: &TrustedGitBinary,
    current_directory: &Path,
    environment: &BTreeMap<String, String>,
    arguments: &[&str],
) -> Result<(), HostError> {
    let output = run_git(
        git,
        current_directory,
        environment,
        arguments,
        GIT_OUTPUT_LIMIT,
    )?;
    let _ = output;
    Ok(())
}

fn run_git_optional(
    git: &TrustedGitBinary,
    current_directory: &Path,
    environment: &BTreeMap<String, String>,
    arguments: &[&str],
    output_limit: usize,
) -> Result<Option<Vec<u8>>, HostError> {
    let safe_arguments = safe_git_arguments(arguments);
    let output = SystemGitProcessRunner.query(&ProcessRequest {
        executable: git,
        arguments: &safe_arguments,
        environment,
        current_directory,
        timeout: GIT_TIMEOUT,
        output_limit,
    })?;
    match output.exit_code {
        Some(0) => Ok(Some(output.stdout)),
        Some(1) => Ok(None),
        status => {
            let detail = String::from_utf8_lossy(&output.stderr)
                .chars()
                .filter(|character| !character.is_control())
                .take(512)
                .collect::<String>();
            Err(HostError::SafeOutputs(format!(
                "isolated Git command failed with status {status:?}: {detail}"
            )))
        }
    }
}

fn run_git(
    git: &TrustedGitBinary,
    current_directory: &Path,
    environment: &BTreeMap<String, String>,
    arguments: &[&str],
    output_limit: usize,
) -> Result<Vec<u8>, HostError> {
    let safe_arguments = safe_git_arguments(arguments);
    let output = SystemGitProcessRunner.query(&ProcessRequest {
        executable: git,
        arguments: &safe_arguments,
        environment,
        current_directory,
        timeout: GIT_TIMEOUT,
        output_limit,
    })?;
    if output.exit_code != Some(0) {
        let detail = String::from_utf8_lossy(&output.stderr)
            .chars()
            .filter(|character| !character.is_control())
            .take(512)
            .collect::<String>();
        return Err(HostError::SafeOutputs(format!(
            "isolated Git command failed with status {:?}: {detail}",
            output.exit_code
        )));
    }
    Ok(output.stdout)
}

fn safe_git_arguments(arguments: &[&str]) -> Vec<String> {
    let mut safe_arguments = vec![
        "--no-pager".to_owned(),
        "-c".to_owned(),
        "core.hooksPath=/dev/null".to_owned(),
        "-c".to_owned(),
        "core.fsmonitor=false".to_owned(),
        "-c".to_owned(),
        "credential.helper=".to_owned(),
        "-c".to_owned(),
        "diff.external=".to_owned(),
        "-c".to_owned(),
        "commit.gpgSign=false".to_owned(),
        "-c".to_owned(),
        "http.followRedirects=false".to_owned(),
        "-c".to_owned(),
        "http.proxy=".to_owned(),
        "-c".to_owned(),
        "protocol.file.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.ext.allow=never".to_owned(),
    ];
    safe_arguments.extend(arguments.iter().map(|argument| (*argument).to_owned()));
    safe_arguments
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use sendbox_config::{CreateIssueSafeOutputConfiguration, SafeOutputsConfiguration};
    use sendbox_mcp::safe_outputs::{
        IntentAccumulator, SafeOutputTool, SafeOutputsSealV1, derive_seal_key,
    };

    use super::*;

    struct FakeWriter {
        writes: AtomicUsize,
        reconcile_existing: bool,
    }

    impl GitHubWriter for FakeWriter {
        fn reconcile<'a>(
            &'a self,
            _record: &'a AcceptedIntentV1,
        ) -> WriterFuture<'a, Option<AppliedWrite>> {
            Box::pin(async move {
                Ok(self.reconcile_existing.then(|| AppliedWrite {
                    url: Some("https://github.com/example/repo/issues/1".to_owned()),
                }))
            })
        }

        fn apply<'a>(
            &'a self,
            _record: &'a AcceptedIntentV1,
            _pull_request: Option<&'a PullRequestPlan>,
        ) -> WriterFuture<'a, AppliedWrite> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(AppliedWrite {
                    url: Some("https://github.com/example/repo/issues/1".to_owned()),
                })
            })
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        ProcessingContext,
        CollectedSafeOutputs,
        Vec<AcceptedIntentV1>,
    ) {
        let temporary = tempfile::tempdir().expect("tempdir");
        let session_id = SessionId::from_bytes([1; 16]);
        let boundary_plan_digest = BoundaryPlanDigest::from_bytes([2; 32]);
        let configuration = SafeOutputsConfiguration {
            enabled: true,
            create_issue: CreateIssueSafeOutputConfiguration {
                enabled: true,
                max: 1,
                ..CreateIssueSafeOutputConfiguration::default()
            },
            allowed_repositories: vec!["example/repo".to_owned()],
            ..SafeOutputsConfiguration::default()
        };
        let policy = SafeOutputsRuntimePolicy::from_configuration(session_id, &configuration)
            .expect("policy");
        let mut accumulator =
            IntentAccumulator::new(policy.clone(), boundary_plan_digest).expect("accumulator");
        let prepared = accumulator
            .prepare(
                SafeOutputTool::CreateIssue,
                json!({
                    "repository": "example/repo",
                    "title": "Issue",
                    "body": "This body is long enough for validation."
                }),
                1,
            )
            .expect("intent");
        accumulator.commit(&prepared).expect("commit");
        let artifact = prepared.line;
        let seal_key = derive_seal_key(&[9; 32], session_id).expect("seal key");
        let seal = SafeOutputsSealV1::create(&accumulator, &artifact, &seal_key).expect("seal");
        let context = ProcessingContext {
            configuration,
            policy,
            boundary_plan_digest,
            seal_key,
            state_directory: temporary.path().to_path_buf(),
            workspace: temporary.path().to_path_buf(),
        };
        (
            temporary,
            context,
            CollectedSafeOutputs {
                artifact,
                seal: serde_json::to_vec(&seal).expect("seal JSON"),
            },
            vec![prepared.record],
        )
    }

    #[tokio::test]
    async fn staged_mode_verifies_audits_and_persists_without_a_token() {
        let (_temporary, context, collection, records) = fixture();
        let audit = AuditRecorder::new(context.policy.session_id).expect("audit");
        let report = process(&context, &collection, &audit)
            .await
            .expect("staged processing");
        assert_eq!(report.operation_count, records.len());
        assert!(context.state_directory.join(REPORT_FILE).is_file());
        assert!(!context.state_directory.join(LEDGER_FILE).exists());
        let persisted: Value = serde_json::from_slice(
            &std::fs::read(context.state_directory.join(REPORT_FILE)).expect("report"),
        )
        .expect("report JSON");
        assert_eq!(
            persisted["actions"][0]["operation"]["payload"]["repository"],
            "example/repo"
        );
        let actions = audit
            .records()
            .expect("audit records")
            .into_iter()
            .map(|record| record.event.action)
            .collect::<Vec<_>>();
        assert_eq!(actions, ["safe_outputs_verified", "safe_outputs_processed"]);
    }

    #[tokio::test]
    async fn apply_mode_is_idempotent_through_the_ledger() {
        let (_temporary, mut context, collection, records) = fixture();
        context.configuration.mode = SafeOutputsMode::Apply;
        let verified = verify_collection(&context, &collection).expect("verify");
        let writer = FakeWriter {
            writes: AtomicUsize::new(0),
            reconcile_existing: false,
        };
        let first = process_with_writer(
            &context,
            &verified.records,
            &verified.provenance,
            &BTreeMap::new(),
            &writer,
        )
        .await
        .expect("first apply");
        let second = process_with_writer(
            &context,
            &verified.records,
            &verified.provenance,
            &BTreeMap::new(),
            &writer,
        )
        .await
        .expect("second apply");
        assert_eq!(writer.writes.load(Ordering::SeqCst), 1);
        assert_eq!(first.actions[0].status, ActionStatus::Applied);
        assert_eq!(second.actions[0].status, ActionStatus::AlreadyApplied);
        assert_eq!(records.len(), 1);
    }

    #[tokio::test]
    async fn pending_ledger_entries_are_reconciled_before_retrying() {
        let (_temporary, mut context, collection, records) = fixture();
        context.configuration.mode = SafeOutputsMode::Apply;
        let verified = verify_collection(&context, &collection).expect("verify");
        persist_ledger(
            &context,
            &Ledger {
                schema_version: LEDGER_SCHEMA_VERSION,
                session_id: context.policy.session_id,
                entries: BTreeMap::from([(
                    records[0].idempotency_key.clone(),
                    LedgerEntry {
                        sequence: records[0].sequence,
                        tool: records[0].operation.tool(),
                        state: LedgerState::Pending,
                        url: None,
                    },
                )]),
            },
        )
        .expect("pending ledger");
        let writer = FakeWriter {
            writes: AtomicUsize::new(0),
            reconcile_existing: true,
        };

        let report = process_with_writer(
            &context,
            &verified.records,
            &verified.provenance,
            &BTreeMap::new(),
            &writer,
        )
        .await
        .expect("reconcile");

        assert_eq!(writer.writes.load(Ordering::SeqCst), 0);
        assert_eq!(report.actions[0].status, ActionStatus::AlreadyApplied);
        assert_eq!(
            load_ledger(&context)
                .expect("ledger")
                .entries
                .get(&records[0].idempotency_key)
                .expect("entry")
                .state,
            LedgerState::Applied
        );
    }

    #[test]
    fn tampering_is_rejected_before_processing() {
        let (_temporary, context, mut collection, _records) = fixture();
        collection.artifact[0] ^= 1;
        assert!(verify_collection(&context, &collection).is_err());
    }

    #[test]
    fn protected_and_non_normalized_paths_are_rejected() {
        let configured = sendbox_config::CreatePullRequestSafeOutputConfiguration {
            allowed_paths: vec!["**".to_owned()],
            ..sendbox_config::CreatePullRequestSafeOutputConfiguration::default()
        };
        assert!(validate_changed_path(Path::new(".github/workflows/ci.yml"), &configured).is_err());
        assert!(take_nul_path(b"../secret\0", &mut 0).is_err());
    }

    #[test]
    fn symlinked_parents_cannot_escape_workspace_or_isolated_repository() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("tempdir");
        let workspace = temporary.path().join("workspace");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&workspace).expect("workspace");
        std::fs::create_dir(&outside).expect("outside");
        std::fs::write(outside.join("secret"), b"unchanged").expect("outside file");
        symlink(&outside, workspace.join("linked")).expect("symlink");

        assert!(
            reject_symlinked_parents(
                &workspace,
                Path::new("linked/secret"),
                "test workspace path"
            )
            .is_err()
        );
        assert!(
            write_isolated_file(&workspace, Path::new("linked/secret"), b"changed", 0o644).is_err()
        );
        assert_eq!(
            std::fs::read(outside.join("secret")).expect("outside file"),
            b"unchanged"
        );
    }

    #[test]
    fn remote_refs_require_valid_sha_and_encode_slash_segments() {
        let sha = "a".repeat(40);
        assert_eq!(
            parse_remote_ref(StatusCode::OK, &json!({"object": {"sha": sha.clone()}}))
                .expect("remote ref"),
            Some(sha)
        );
        assert!(parse_remote_ref(StatusCode::OK, &json!({"object": {}})).is_err());
        assert_eq!(
            parse_remote_ref(StatusCode::NOT_FOUND, &Value::Null).expect("missing ref"),
            None
        );
        assert_eq!(
            github_url(
                "example/repo",
                &["git", "ref", "heads", "safe-outputs", "session"]
            )
            .expect("URL")
            .path(),
            "/repos/example/repo/git/ref/heads/safe-outputs/session"
        );
    }

    #[test]
    fn pull_request_preflight_includes_committed_changes_from_the_base_branch() {
        let (temporary, mut context, _collection, _records) = fixture();
        let workspace = temporary.path().join("workspace");
        let state = temporary.path().join("state");
        std::fs::create_dir_all(workspace.join("src")).expect("workspace");
        std::fs::create_dir(&state).expect("state");
        context.workspace = workspace.clone();
        context.state_directory = state;
        context.configuration.create_pull_request.enabled = true;
        context.configuration.create_pull_request.allowed_paths = vec!["src/**".to_owned()];
        context.configuration.create_pull_request.base_branches = vec!["main".to_owned()];
        let git = trusted_git().expect("trusted Git");
        let environment = safe_git_environment(temporary.path());
        run_git_ok(&git, &workspace, &environment, &["init", "--quiet"]).expect("init");
        run_git_ok(&git, &workspace, &environment, &["checkout", "-b", "main"])
            .expect("main branch");
        std::fs::write(workspace.join("src/lib.rs"), b"base\n").expect("base file");
        run_git_ok(&git, &workspace, &environment, &["add", "src/lib.rs"]).expect("add base");
        run_git_ok(
            &git,
            &workspace,
            &environment,
            &[
                "-c",
                "user.name=SendBox Test",
                "-c",
                "user.email=test@sendbox.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "base",
            ],
        )
        .expect("base commit");
        run_git_ok(
            &git,
            &workspace,
            &environment,
            &["checkout", "-b", "feature"],
        )
        .expect("feature branch");
        std::fs::write(workspace.join("src/lib.rs"), b"feature\n").expect("feature file");
        run_git_ok(&git, &workspace, &environment, &["add", "src/lib.rs"]).expect("add feature");
        run_git_ok(
            &git,
            &workspace,
            &environment,
            &[
                "-c",
                "user.name=SendBox Test",
                "-c",
                "user.email=test@sendbox.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "feature",
            ],
        )
        .expect("feature commit");

        let plan = preflight_pull_request(&context, "main").expect("preflight");
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].path, PathBuf::from("src/lib.rs"));
        assert!(!plan.changes[0].deleted);
        assert!(plan.patch_bytes > 0);
    }

    #[test]
    fn pull_request_preflight_never_executes_configured_textconv() {
        let (temporary, mut context, _collection, _records) = fixture();
        let workspace = temporary.path().join("workspace-textconv");
        let state = temporary.path().join("state-textconv");
        std::fs::create_dir_all(workspace.join("src")).expect("workspace");
        std::fs::create_dir(&state).expect("state");
        context.workspace = workspace.clone();
        context.state_directory = state;
        context.configuration.create_pull_request.enabled = true;
        context.configuration.create_pull_request.allowed_paths = vec!["src/**".to_owned()];
        context.configuration.create_pull_request.base_branches = vec!["main".to_owned()];
        let git = trusted_git().expect("trusted Git");
        let environment = safe_git_environment(temporary.path());
        run_git_ok(&git, &workspace, &environment, &["init", "--quiet"]).expect("init");
        run_git_ok(&git, &workspace, &environment, &["checkout", "-b", "main"])
            .expect("main branch");
        std::fs::write(workspace.join("src/lib.rs"), b"base\n").expect("base file");
        run_git_ok(&git, &workspace, &environment, &["add", "src/lib.rs"]).expect("add base");
        run_git_ok(
            &git,
            &workspace,
            &environment,
            &[
                "-c",
                "user.name=SendBox Test",
                "-c",
                "user.email=test@sendbox.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "base",
            ],
        )
        .expect("base commit");
        run_git_ok(
            &git,
            &workspace,
            &environment,
            &["checkout", "-b", "feature"],
        )
        .expect("feature branch");
        std::fs::write(workspace.join("src/lib.rs"), b"feature\n").expect("feature file");

        let sentinel = temporary.path().join("textconv-ran");
        let script = temporary.path().join("textconv.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n/usr/bin/touch {}\n/bin/cat \"$1\"\n",
                sentinel.display()
            ),
        )
        .expect("script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("script mode");
        run_git_ok(
            &git,
            &workspace,
            &environment,
            &[
                "config",
                "diff.sendbox-attack.textconv",
                script.to_str().expect("script path"),
            ],
        )
        .expect("textconv config");
        std::fs::write(
            workspace.join(".git/info/attributes"),
            b"src/lib.rs diff=sendbox-attack\n",
        )
        .expect("attributes");

        preflight_pull_request(&context, "main").expect("preflight");
        assert!(!sentinel.exists(), "untrusted textconv was executed");
    }
}
