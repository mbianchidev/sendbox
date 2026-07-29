use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    future::Future,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sendbox_boundary::{VerifiedBoundaryPlan, sha256_hex};
use sendbox_core::SessionId;
use sendbox_runtime::{CancellationToken, RuntimeError};
use sendbox_secrets::CredentialPolicy;
use sendbox_security::{
    SecurityError, SecurityResult,
    audit::{AuditCategory, AuditRecord, AuditResult},
    fs::{EntryMetadata, EntryType, ExclusiveLock, PRIVATE_DIRECTORY_MODE, SecureRoot},
    provenance::{
        DetachedSignature, SignedSubject, SigningKeyMaterial, SubjectKind, VerificationResult,
    },
    snapshot::{ExclusionPolicy, SnapshotDiff, SnapshotManager, SnapshotManifest},
};
use sendbox_session_security::{
    AuditRecorder, SecuritySession, SessionSecurityError, SessionSecurityResult,
    lifecycle::{
        AuditPublication, AuditPublicationHook, CleanupHook, CredentialListener,
        CredentialRulePreparer, LifecycleClock, LifecycleHooks, PermissionSupervisorReady,
        PrepareRequest, PreparedCredentialRules, PreparedSecretEnvelope, ProvenanceDocument,
        ProvenanceVerifier, SecretEnvelopeProducer, SecretEnvelopeRequest, SnapshotController,
    },
    supervisor::{
        AuditPermissionEventSink, PermissionEventSink, PermissionSupervisor,
        SharedPermissionSupervisor, SupervisorCheckpoint, SupervisorConfig,
    },
};
use serde::Serialize;

use crate::{
    HostError, HostRunReport, PACKAGE_SECURITY_REPORT_FILE, PersistedPackageReport, atomic_write,
    unix_time,
};

const SNAPSHOT_DIRECTORY: &str = "snapshots";
const SUPERVISOR_STATE_FILE: &str = "permission-supervisor.json";
const AUDIT_LOG_FILE: &str = "audit-log.json";
const AUDIT_SIGNATURE_FILE: &str = "audit-log.signature.json";
const AUDIT_PUBLICATION_FORMAT: &str = "sendbox-host-audit-publication";
const AUDIT_PUBLICATION_VERSION: u16 = 1;
const WORKSPACE_LOCK_DIRECTORY: &str = ".sendbox-workspace-locks";
const WORKSPACE_LOCK_RETRY: Duration = Duration::from_millis(25);
const MAX_TRACKED_EXCLUDED_ENTRIES: usize = 2_000_000;
const ROLLBACK_SCOPE: &str = "included_restored_excluded_mutations_quarantined";
const HOST_SNAPSHOT_EXCLUSIONS: [&str; 7] = [
    ".DS_Store",
    ".build",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "target",
];

pub(crate) struct HostSecurityContext {
    verified_plan: VerifiedBoundaryPlan,
    configuration_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
    workspace: PathBuf,
    state_directory: PathBuf,
    signing_key: SigningKeyMaterial,
    planned_secret_count: usize,
    package_report_validation: Option<PackageReportValidation>,
}

#[derive(Debug, Clone)]
pub(crate) struct PackageReportValidation {
    maximum_bytes: usize,
    maximum_findings: usize,
    policy_digest: String,
}

impl PackageReportValidation {
    pub(crate) fn from_policy(
        policy: &sendbox_policy::PackageSupplyChainPolicy,
    ) -> Result<Option<Self>, HostError> {
        if !policy.enabled {
            return Ok(None);
        }
        Ok(Some(Self {
            maximum_bytes: usize::try_from(policy.limits.max_report_bytes).map_err(|_| {
                HostError::Invalid("package report byte limit is out of range".to_owned())
            })?,
            maximum_findings: usize::try_from(policy.limits.max_report_findings).map_err(|_| {
                HostError::Invalid("package report finding limit is out of range".to_owned())
            })?,
            policy_digest: sendbox_registry::package_policy_digest(policy)
                .map_err(|error| HostError::Invalid(error.to_string()))?,
        }))
    }
}

impl HostSecurityContext {
    pub(crate) fn new(
        verified_plan: VerifiedBoundaryPlan,
        configuration_bytes: Vec<u8>,
        policy_bytes: Vec<u8>,
        workspace: PathBuf,
        state_directory: PathBuf,
        signing_key: SigningKeyMaterial,
        package_report_validation: Option<PackageReportValidation>,
    ) -> Self {
        let planned_secret_count = verified_plan.plan().secrets.len();
        Self {
            verified_plan,
            configuration_bytes,
            policy_bytes,
            workspace,
            state_directory,
            signing_key,
            planned_secret_count,
            package_report_validation,
        }
    }
}

pub(crate) fn validate_state_workspace_disjoint(
    workspace: &Path,
    state_directory: &Path,
) -> Result<(), HostError> {
    if workspace.starts_with(state_directory) || state_directory.starts_with(workspace) {
        return Err(HostError::Invalid(format!(
            "session state directory `{}` must be disjoint from workspace `{}`",
            state_directory.display(),
            workspace.display()
        )));
    }
    Ok(())
}

pub(crate) async fn execute<Factory, F>(
    context: HostSecurityContext,
    runtime: Factory,
    cancellation: &CancellationToken,
) -> Result<HostRunReport, HostError>
where
    Factory: FnOnce(AuditRecorder) -> F,
    F: Future<Output = Result<HostRunReport, HostError>>,
{
    let _workspace_lease = acquire_workspace_lease(&context, cancellation).await?;
    let clock = SystemLifecycleClock;
    let provenance = BoundaryProvenance {
        plan: &context.verified_plan,
        configuration_bytes: &context.configuration_bytes,
        policy_bytes: &context.policy_bytes,
        workspace: &context.workspace,
    };
    let snapshots = WorkspaceSnapshots::open(&context)?;
    let rejected_secrets = RejectedLifecycleSecrets;
    let credential_rules = EmptyCredentialRules::new(context.verified_plan.digest().to_string());
    let credential_listener = EmptyCredentialListener {
        expected_preparation_id: credential_rules.preparation_id.clone(),
    };
    let shared = Arc::new(SharedLifecycleState::default());
    let permission_supervisor = HostPermissionSupervisor {
        state_directory: context.state_directory.clone(),
        shared: Arc::clone(&shared),
    };
    let audit_publication = SignedAuditPublication {
        session_id: context.verified_plan.plan().session_id,
        boundary_plan_digest: context.verified_plan.digest().to_string(),
        state_directory: context.state_directory.clone(),
        signing_key: &context.signing_key,
        excluded_components: snapshots.excluded_components.clone(),
        shared: Arc::clone(&shared),
    };
    let cleanup = HostCleanup {
        shared: Arc::clone(&shared),
    };
    let hooks = LifecycleHooks {
        provenance: &provenance,
        snapshots: &snapshots,
        secrets: &rejected_secrets,
        credential_rules: &credential_rules,
        credential_listener: &credential_listener,
        permission_supervisor: &permission_supervisor,
        audit_publication: &audit_publication,
        cleanup: &cleanup,
        clock: &clock,
    };
    let now_unix = unix_time()?;
    let session_id = context.verified_plan.plan().session_id;
    let request = PrepareRequest {
        policy_provenance: ProvenanceDocument {
            content: context.policy_bytes.clone(),
            kind: SubjectKind::Content,
            signatures: Vec::new(),
            now_unix,
        },
        config_provenance: ProvenanceDocument {
            content: context.configuration_bytes.clone(),
            kind: SubjectKind::Configuration,
            signatures: Vec::new(),
            now_unix,
        },
        secret_requests: Vec::new(),
        credential_policies: Vec::new(),
        credential_listener_maximum_requests: 0,
    };
    let mut session = SecuritySession::prepare(session_id, request, hooks)?;
    record_or_abort(
        &mut session,
        &clock,
        AuditCategory::Snapshot,
        "workspace_snapshot_scope_bound",
        context.workspace.display().to_string(),
        AuditResult::Success,
        BTreeMap::from([
            (
                "excluded_components".to_owned(),
                snapshots.excluded_components.join(","),
            ),
            ("rollback_scope".to_owned(), ROLLBACK_SCOPE.to_owned()),
        ]),
    )?;
    record_or_abort(
        &mut session,
        &clock,
        AuditCategory::Secret,
        "protocol_secret_delivery_planned",
        context.verified_plan.digest().to_string(),
        AuditResult::Success,
        BTreeMap::from([(
            "planned_secret_count".to_owned(),
            context.planned_secret_count.to_string(),
        )]),
    )?;
    record_or_abort(
        &mut session,
        &clock,
        AuditCategory::Lifecycle,
        "runtime_execution_started",
        context.verified_plan.digest().to_string(),
        AuditResult::Success,
        BTreeMap::new(),
    )?;

    match runtime(session.audit_recorder()).await {
        Ok(mut report) => {
            if let Err(error) = persist_package_report(&mut report, &context) {
                return finalize_runtime_error(session, &clock, error);
            }
            finalize_report(session, &clock, report)
        }
        Err(runtime_error) => finalize_runtime_error(session, &clock, runtime_error),
    }
}

fn persist_package_report(
    report: &mut HostRunReport,
    context: &HostSecurityContext,
) -> Result<(), HostError> {
    let raw = match report {
        HostRunReport::Persistent(report) => report.agent.package_report.take(),
        HostRunReport::OneShot(_) => None,
    };
    let Some(validation) = context.package_report_validation.as_ref() else {
        if raw.is_some() {
            return Err(HostError::Invalid(
                "guest returned an unexpected package security report".to_owned(),
            ));
        }
        return Ok(());
    };
    let raw = raw.ok_or_else(|| {
        HostError::Invalid("guest omitted the required package security report".to_owned())
    })?;
    if raw.json.len() > validation.maximum_bytes {
        return Err(HostError::Invalid(format!(
            "package security report exceeds the configured {}-byte limit",
            validation.maximum_bytes
        )));
    }
    let actual_digest = format!("sha256:{}", sha256_hex(&raw.json));
    if raw.sha256 != actual_digest {
        return Err(HostError::Invalid(
            "package security report digest does not match its contents".to_owned(),
        ));
    }
    let parsed: sendbox_registry::PackageSecurityReport = serde_json::from_slice(&raw.json)
        .map_err(|error| HostError::Invalid(format!("decode package security report: {error}")))?;
    parsed
        .validate(validation.maximum_findings, validation.maximum_findings)
        .map_err(|error| {
            HostError::Invalid(format!("validate package security report: {error}"))
        })?;
    if !parsed.proxy_enabled {
        return Err(HostError::Invalid(
            "package security report says the required proxy was disabled".to_owned(),
        ));
    }
    let expected_session = context.verified_plan.plan().session_id.to_string();
    for record in &parsed.records {
        if record.requested_by_session != expected_session {
            return Err(HostError::Invalid(
                "package security report references a different session".to_owned(),
            ));
        }
        if record.policy_digest != validation.policy_digest {
            return Err(HostError::Invalid(
                "package security report references a different package policy".to_owned(),
            ));
        }
    }
    let canonical = serde_json::to_vec(&parsed)
        .map_err(|error| HostError::Invalid(format!("encode package security report: {error}")))?;
    if canonical != raw.json {
        return Err(HostError::Invalid(
            "package security report is not in canonical transport form".to_owned(),
        ));
    }
    let path = context.state_directory.join(PACKAGE_SECURITY_REPORT_FILE);
    atomic_write(&path, &canonical, 0o600)?;
    let records = u32::try_from(parsed.records.len()).map_err(|_| {
        HostError::Invalid("package report record count is out of range".to_owned())
    })?;
    let persisted = PersistedPackageReport {
        path,
        sha256: actual_digest,
        proxy_enabled: parsed.proxy_enabled,
        records,
        allowed: parsed.allowed,
        denied: parsed.denied,
        quarantined: parsed.quarantined,
    };
    let HostRunReport::Persistent(report) = report else {
        return Err(HostError::Invalid(
            "package report cannot be attached to a one-shot run".to_owned(),
        ));
    };
    report.package_report = Some(persisted);
    Ok(())
}

fn finalize_report(
    mut session: SecuritySession<'_>,
    clock: &dyn LifecycleClock,
    report: HostRunReport,
) -> Result<HostRunReport, HostError> {
    if let Some(package) = report.package_report() {
        record_or_abort(
            &mut session,
            clock,
            AuditCategory::Provenance,
            "package_security_report_persisted",
            package.sha256().to_owned(),
            AuditResult::Success,
            BTreeMap::from([
                ("file".to_owned(), PACKAGE_SECURITY_REPORT_FILE.to_owned()),
                ("records".to_owned(), package.records().to_string()),
                ("allowed".to_owned(), package.allowed().to_string()),
                ("denied".to_owned(), package.denied().to_string()),
                ("quarantined".to_owned(), package.quarantined().to_string()),
            ]),
        )?;
    }
    let successful = report.successful();
    let result = if successful {
        AuditResult::Success
    } else {
        AuditResult::Error
    };
    if let Err(audit_error) = session.record_event(
        clock.now_unix_nanos(),
        AuditCategory::Command,
        "runtime_execution_finished",
        report.kind(),
        result,
        BTreeMap::from([("exit_code".to_owned(), report.exit_code().to_string())]),
    ) {
        let finalization = session.fail(format!("runtime outcome audit failed: {audit_error}"));
        return Err(HostError::SessionSecurity(combine_security_errors(
            audit_error,
            finalization.err(),
        )));
    }
    if successful {
        session.complete()?;
    } else {
        session.fail(format!(
            "{} runtime exited with status {}",
            report.kind(),
            report.exit_code()
        ))?;
    }
    Ok(report)
}

fn finalize_runtime_error(
    mut session: SecuritySession<'_>,
    clock: &dyn LifecycleClock,
    runtime_error: HostError,
) -> Result<HostRunReport, HostError> {
    let audit_error = session
        .record_event(
            clock.now_unix_nanos(),
            AuditCategory::Command,
            "runtime_execution_failed",
            runtime_error.kind(),
            AuditResult::Error,
            BTreeMap::from([("error".to_owned(), runtime_error.to_string())]),
        )
        .err();
    let finalization_error = session.fail(runtime_error.to_string()).err();
    match (audit_error, finalization_error) {
        (None, None) => Err(runtime_error),
        (audit_error, finalization_error) => Err(HostError::RuntimeSecurity {
            runtime: Box::new(runtime_error),
            security: combine_optional_security_errors(audit_error, finalization_error),
        }),
    }
}

fn record_or_abort(
    session: &mut SecuritySession<'_>,
    clock: &dyn LifecycleClock,
    category: AuditCategory,
    action: &'static str,
    subject: String,
    result: AuditResult,
    metadata: BTreeMap<String, String>,
) -> Result<(), HostError> {
    if let Err(primary) = session.record_event(
        clock.now_unix_nanos(),
        category,
        action,
        subject,
        result,
        metadata,
    ) {
        let finalization = session.fail(format!("{action} audit failed: {primary}"));
        return Err(HostError::SessionSecurity(combine_security_errors(
            primary,
            finalization.err(),
        )));
    }
    Ok(())
}

fn combine_optional_security_errors(
    primary: Option<SessionSecurityError>,
    secondary: Option<SessionSecurityError>,
) -> SessionSecurityError {
    match (primary, secondary) {
        (Some(primary), secondary) => combine_security_errors(primary, secondary),
        (None, Some(secondary)) => secondary,
        (None, None) => SessionSecurityError::Operation {
            stage: "runtime_failure",
            message: "missing session security failure detail".to_owned(),
        },
    }
}

fn combine_security_errors(
    primary: SessionSecurityError,
    secondary: Option<SessionSecurityError>,
) -> SessionSecurityError {
    secondary.map_or(primary.clone(), |secondary| {
        SessionSecurityError::FailureAggregate {
            stage: "runtime_failure_security",
            primary: primary.to_string(),
            rollback: Some(secondary.to_string()),
            cleanup: None,
        }
    })
}

async fn acquire_workspace_lease(
    context: &HostSecurityContext,
    cancellation: &CancellationToken,
) -> Result<ExclusiveLock, HostError> {
    if cancellation.is_cancelled() {
        return Err(HostError::Runtime(RuntimeError::Cancelled));
    }
    let parent_path = context.workspace.parent().ok_or_else(|| {
        HostError::Invalid(format!(
            "workspace `{}` has no parent directory",
            context.workspace.display()
        ))
    })?;
    let parent_path = parent_path.to_path_buf();
    let lock_name = format!(
        "{}.lock",
        sha256_hex(context.workspace.as_os_str().as_bytes())
    );
    let lock_path = Path::new(WORKSPACE_LOCK_DIRECTORY).join(lock_name);
    let setup_parent = parent_path.clone();
    tokio::task::spawn_blocking(move || {
        let root = SecureRoot::open(&setup_parent)?;
        root.create_dir_all(WORKSPACE_LOCK_DIRECTORY, PRIVATE_DIRECTORY_MODE)
    })
    .await
    .map_err(|error| HostError::Invalid(format!("workspace lease task failed: {error}")))?
    .map_err(HostError::Security)?;

    loop {
        let attempt_parent = parent_path.clone();
        let attempt_path = lock_path.clone();
        let attempt = tokio::task::spawn_blocking(move || {
            SecureRoot::open(&attempt_parent)?.try_lock_exclusive(attempt_path)
        })
        .await
        .map_err(|error| HostError::Invalid(format!("workspace lease task failed: {error}")))?
        .map_err(HostError::Security)?;
        if cancellation.is_cancelled() {
            drop(attempt);
            return Err(HostError::Runtime(RuntimeError::Cancelled));
        }
        if let Some(lease) = attempt {
            return Ok(lease);
        }
        tokio::select! {
            () = cancellation.cancelled() => {
                return Err(HostError::Runtime(RuntimeError::Cancelled));
            }
            () = tokio::time::sleep(WORKSPACE_LOCK_RETRY) => {}
        }
    }
}

struct BoundaryProvenance<'a> {
    plan: &'a VerifiedBoundaryPlan,
    configuration_bytes: &'a [u8],
    policy_bytes: &'a [u8],
    workspace: &'a Path,
}

impl BoundaryProvenance<'_> {
    fn verify(
        &self,
        document: &ProvenanceDocument,
        expected_kind: SubjectKind,
        expected_bytes: &[u8],
        expected_sha256: &str,
        stage: &'static str,
    ) -> SessionSecurityResult<VerificationResult> {
        self.plan
            .reverify(document.now_unix)
            .map_err(|error| operation(stage, error))?;
        if self.plan.plan().workspace.source != self.workspace {
            return Err(operation(
                stage,
                "verified boundary workspace does not match the secured workspace",
            ));
        }
        if document.kind != expected_kind {
            return Err(operation(stage, "provenance subject kind does not match"));
        }
        if !document.signatures.is_empty() {
            return Err(operation(
                stage,
                "boundary-backed provenance does not accept detached document signatures",
            ));
        }
        if document.content != expected_bytes {
            return Err(operation(
                stage,
                "provenance content differs from the signed execution input",
            ));
        }
        let subject = SignedSubject::from_bytes(document.kind, None, &document.content);
        if subject.sha256 != expected_sha256 {
            return Err(operation(
                stage,
                "provenance digest differs from the verified boundary plan",
            ));
        }
        Ok(VerificationResult {
            subject,
            valid_signers: BTreeSet::from([self.plan.signer_fingerprint().to_owned()]),
        })
    }
}

impl ProvenanceVerifier for BoundaryProvenance<'_> {
    fn verify_policy(
        &self,
        document: &ProvenanceDocument,
    ) -> SessionSecurityResult<VerificationResult> {
        self.verify(
            document,
            SubjectKind::Content,
            self.policy_bytes,
            &self.plan.plan().policy_sha256,
            "policy_provenance",
        )
    }

    fn verify_config(
        &self,
        document: &ProvenanceDocument,
    ) -> SessionSecurityResult<VerificationResult> {
        self.verify(
            document,
            SubjectKind::Configuration,
            self.configuration_bytes,
            &self.plan.plan().configuration_sha256,
            "config_provenance",
        )
    }
}

struct WorkspaceSnapshots {
    store: SecureRoot,
    workspace: SecureRoot,
    workspace_path: PathBuf,
    parent: SecureRoot,
    workspace_name: PathBuf,
    expected_session_id: SessionId,
    exclusions: ExclusionPolicy,
    excluded_components: Vec<String>,
    excluded_before: Mutex<Option<BTreeMap<PathBuf, EntryMetadata>>>,
}

impl WorkspaceSnapshots {
    fn open(context: &HostSecurityContext) -> Result<Self, HostError> {
        let parent_path = context.workspace.parent().ok_or_else(|| {
            HostError::Invalid(format!(
                "workspace `{}` has no parent directory",
                context.workspace.display()
            ))
        })?;
        let workspace_name = context
            .workspace
            .file_name()
            .map(PathBuf::from)
            .ok_or_else(|| {
                HostError::Invalid(format!(
                    "workspace `{}` has no directory name",
                    context.workspace.display()
                ))
            })?;
        let exclusions = ExclusionPolicy::new(HOST_SNAPSHOT_EXCLUSIONS)?;
        Ok(Self {
            store: SecureRoot::open(&context.state_directory)?,
            workspace: SecureRoot::open(&context.workspace)?,
            workspace_path: context.workspace.clone(),
            parent: SecureRoot::open(parent_path)?,
            workspace_name,
            expected_session_id: context.verified_plan.plan().session_id,
            excluded_components: exclusions.components().map(str::to_owned).collect(),
            exclusions,
            excluded_before: Mutex::new(None),
        })
    }

    fn manager(&self) -> SnapshotManager<'_> {
        SnapshotManager::new(&self.store, SNAPSHOT_DIRECTORY)
            .with_exclusion_policy(self.exclusions.clone())
    }

    fn require_session(&self, session_id: SessionId) -> SessionSecurityResult<()> {
        if session_id != self.expected_session_id {
            return Err(operation(
                "snapshot_session",
                "snapshot request session does not match the verified boundary plan",
            ));
        }
        Ok(())
    }
}

impl SnapshotController for WorkspaceSnapshots {
    fn capture_before(&self, session_id: SessionId) -> SessionSecurityResult<SnapshotManifest> {
        self.require_session(session_id)?;
        let manifest = self
            .manager()
            .capture(&self.workspace)
            .map_err(|error| operation("snapshot_before", error))?;
        let excluded = collect_excluded_state(&self.workspace, &self.exclusions)
            .map_err(|error| operation("snapshot_excluded_before", error))?;
        *self
            .excluded_before
            .lock()
            .map_err(|_| operation("snapshot_excluded_before", "snapshot mutex poisoned"))? =
            Some(excluded);
        Ok(manifest)
    }

    fn capture_after(&self, session_id: SessionId) -> SessionSecurityResult<SnapshotManifest> {
        self.require_session(session_id)?;
        self.manager()
            .capture(&self.workspace)
            .map_err(|error| operation("snapshot_after", error))
    }

    fn diff(
        &self,
        before: &SnapshotManifest,
        after: &SnapshotManifest,
    ) -> SessionSecurityResult<SnapshotDiff> {
        self.manager()
            .diff(&before.id, &after.id)
            .map_err(|error| operation("snapshot_diff", error))
    }

    fn rollback(&self, before: &SnapshotManifest) -> SessionSecurityResult<()> {
        self.manager()
            .restore(&before.id, &self.parent, &self.workspace_name)
            .map_err(|error| operation("snapshot_rollback", error))?;
        let baseline = self
            .excluded_before
            .lock()
            .map_err(|_| operation("snapshot_excluded_rollback", "snapshot mutex poisoned"))?
            .take()
            .ok_or_else(|| {
                operation(
                    "snapshot_excluded_rollback",
                    "excluded-path baseline is unavailable",
                )
            })?;
        let restored = SecureRoot::open(&self.workspace_path)
            .map_err(|error| operation("snapshot_excluded_rollback", error))?;
        quarantine_excluded_mutations(&restored, &self.exclusions, &baseline)
            .map_err(|error| operation("snapshot_excluded_rollback", error))?;
        Ok(())
    }
}

fn collect_excluded_state(
    root: &SecureRoot,
    exclusions: &ExclusionPolicy,
) -> SecurityResult<BTreeMap<PathBuf, EntryMetadata>> {
    let mut entries = BTreeMap::new();
    collect_excluded_directory(root, Path::new(""), false, exclusions, &mut entries)?;
    Ok(entries)
}

fn collect_excluded_directory(
    root: &SecureRoot,
    directory: &Path,
    inside_excluded: bool,
    exclusions: &ExclusionPolicy,
    entries: &mut BTreeMap<PathBuf, EntryMetadata>,
) -> SecurityResult<()> {
    for entry in root.list_dir(directory)? {
        let path = directory.join(&entry.name);
        let excluded = inside_excluded
            || entry
                .name
                .to_str()
                .is_some_and(|name| exclusions.excludes(name));
        if excluded {
            if entries.len() >= MAX_TRACKED_EXCLUDED_ENTRIES {
                return Err(SecurityError::Integrity(format!(
                    "excluded-path baseline exceeds {MAX_TRACKED_EXCLUDED_ENTRIES} entries"
                )));
            }
            entries.insert(path.clone(), entry.metadata.clone());
        }
        if entry.metadata.entry_type == EntryType::Directory {
            collect_excluded_directory(root, &path, excluded, exclusions, entries)?;
        }
    }
    Ok(())
}

fn quarantine_excluded_mutations(
    root: &SecureRoot,
    exclusions: &ExclusionPolicy,
    baseline: &BTreeMap<PathBuf, EntryMetadata>,
) -> SecurityResult<usize> {
    quarantine_excluded_directory(root, Path::new(""), false, exclusions, baseline)
}

fn quarantine_excluded_directory(
    root: &SecureRoot,
    directory: &Path,
    inside_excluded: bool,
    exclusions: &ExclusionPolicy,
    baseline: &BTreeMap<PathBuf, EntryMetadata>,
) -> SecurityResult<usize> {
    let mut removed: usize = 0;
    for entry in root.list_dir(directory)? {
        let path = directory.join(&entry.name);
        let excluded = inside_excluded
            || entry
                .name
                .to_str()
                .is_some_and(|name| exclusions.excludes(name));
        if !excluded {
            if entry.metadata.entry_type == EntryType::Directory {
                removed = removed.saturating_add(quarantine_excluded_directory(
                    root, &path, false, exclusions, baseline,
                )?);
            }
            continue;
        }

        let Some(original) = baseline.get(&path) else {
            root.remove_tree(&path)?;
            removed = removed.saturating_add(1);
            continue;
        };
        if entry.metadata.entry_type == EntryType::Directory
            && original.entry_type == EntryType::Directory
            && same_directory_identity(original, &entry.metadata)
        {
            removed = removed.saturating_add(quarantine_excluded_directory(
                root, &path, true, exclusions, baseline,
            )?);
        } else if &entry.metadata != original {
            root.remove_tree(&path)?;
            removed = removed.saturating_add(1);
        }
    }
    Ok(removed)
}

fn same_directory_identity(original: &EntryMetadata, current: &EntryMetadata) -> bool {
    original.entry_type == current.entry_type
        && original.mode == current.mode
        && original.owner == current.owner
        && original.device == current.device
        && original.inode == current.inode
}

struct RejectedLifecycleSecrets;

impl SecretEnvelopeProducer for RejectedLifecycleSecrets {
    fn prepare(
        &self,
        _request: &SecretEnvelopeRequest,
    ) -> SessionSecurityResult<PreparedSecretEnvelope> {
        Err(operation(
            "secret_envelope",
            "session lifecycle secret requests must use authenticated protocol delivery",
        ))
    }
}

struct EmptyCredentialRules {
    preparation_id: String,
}

impl EmptyCredentialRules {
    fn new(boundary_plan_digest: String) -> Self {
        Self {
            preparation_id: sha256_hex(
                format!("empty-credential-rules:{boundary_plan_digest}").as_bytes(),
            ),
        }
    }
}

impl CredentialRulePreparer for EmptyCredentialRules {
    fn prepare(
        &self,
        policies: &[CredentialPolicy],
    ) -> SessionSecurityResult<PreparedCredentialRules> {
        if !policies.is_empty() {
            return Err(operation(
                "credential_rules",
                "credential policies require the production credential broker",
            ));
        }
        Ok(PreparedCredentialRules {
            rule_count: 0,
            preparation_id: self.preparation_id.clone(),
        })
    }
}

struct EmptyCredentialListener {
    expected_preparation_id: String,
}

impl CredentialListener for EmptyCredentialListener {
    fn ready(
        &self,
        prepared: &PreparedCredentialRules,
        maximum_requests: u32,
    ) -> SessionSecurityResult<()> {
        if prepared.rule_count != 0
            || prepared.preparation_id != self.expected_preparation_id
            || maximum_requests != 0
        {
            return Err(operation(
                "credential_listener",
                "credential listener cannot start without the production credential broker",
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct SharedLifecycleState {
    audit: Mutex<Option<AuditRecorder>>,
    supervisor: Mutex<Option<SharedPermissionSupervisor>>,
}

struct HostPermissionSupervisor {
    state_directory: PathBuf,
    shared: Arc<SharedLifecycleState>,
}

impl PermissionSupervisorReady for HostPermissionSupervisor {
    fn ready(
        &self,
        session_id: SessionId,
        audit: AuditRecorder,
    ) -> SessionSecurityResult<SupervisorCheckpoint> {
        let sink: Arc<dyn PermissionEventSink> =
            Arc::new(AuditPermissionEventSink::new(audit.clone()));
        let supervisor =
            PermissionSupervisor::new(session_id, SupervisorConfig::strict(), Arc::clone(&sink))
                .map_err(|error| operation("permission_supervisor", error))?;
        let checkpoint = supervisor.checkpoint();
        let encoded = supervisor
            .encode_canonical()
            .map_err(|error| operation("permission_supervisor_encode", error))?;
        atomic_write(
            &self.state_directory.join(SUPERVISOR_STATE_FILE),
            &encoded,
            0o600,
        )
        .map_err(|error| operation("permission_supervisor_persist", error))?;
        let persisted = fs::read(self.state_directory.join(SUPERVISOR_STATE_FILE))
            .map_err(|error| operation("permission_supervisor_readback", error))?;
        let supervisor = PermissionSupervisor::decode_with_checkpoint(
            &persisted,
            &checkpoint,
            Arc::clone(&sink),
        )
        .map_err(|error| operation("permission_supervisor_readback", error))?;
        *self
            .shared
            .audit
            .lock()
            .map_err(|_| operation("permission_supervisor", "audit mutex poisoned"))? = Some(audit);
        *self
            .shared
            .supervisor
            .lock()
            .map_err(|_| operation("permission_supervisor", "supervisor mutex poisoned"))? =
            Some(SharedPermissionSupervisor::new(supervisor));
        Ok(checkpoint)
    }
}

struct SignedAuditPublication<'a> {
    session_id: SessionId,
    boundary_plan_digest: String,
    state_directory: PathBuf,
    signing_key: &'a SigningKeyMaterial,
    excluded_components: Vec<String>,
    shared: Arc<SharedLifecycleState>,
}

#[derive(Serialize)]
struct PersistedAuditPublication {
    format: &'static str,
    version: u16,
    session_id: String,
    boundary_plan_digest: String,
    event_count: usize,
    merkle_root: String,
    head_hash: String,
    rollback_scope: &'static str,
    excluded_components: Vec<String>,
    records: Vec<AuditRecord>,
}

impl AuditPublicationHook for SignedAuditPublication<'_> {
    fn publish(
        &self,
        session_id: SessionId,
        merkle_root: &str,
        head_hash: &str,
    ) -> SessionSecurityResult<AuditPublication> {
        if session_id != self.session_id {
            return Err(operation(
                "audit_publication",
                "audit session does not match the verified boundary plan",
            ));
        }
        let recorder = self
            .shared
            .audit
            .lock()
            .map_err(|_| operation("audit_publication", "audit mutex poisoned"))?
            .clone()
            .ok_or_else(|| operation("audit_publication", "audit recorder is unavailable"))?;
        let snapshot = recorder.snapshot()?;
        if snapshot.summary.merkle_root != merkle_root || snapshot.summary.head_hash != head_hash {
            return Err(operation(
                "audit_publication",
                "audit summary changed before publication",
            ));
        }
        let publication = PersistedAuditPublication {
            format: AUDIT_PUBLICATION_FORMAT,
            version: AUDIT_PUBLICATION_VERSION,
            session_id: session_id.to_string(),
            boundary_plan_digest: self.boundary_plan_digest.clone(),
            event_count: snapshot.summary.event_count,
            merkle_root: snapshot.summary.merkle_root,
            head_hash: snapshot.summary.head_hash,
            rollback_scope: ROLLBACK_SCOPE,
            excluded_components: self.excluded_components.clone(),
            records: snapshot.records,
        };
        let content = serde_json::to_vec(&publication)
            .map_err(|error| operation("audit_publication_encode", error))?;
        let signature = DetachedSignature::sign(
            SignedSubject::from_bytes(
                SubjectKind::Artifact,
                Some(AUDIT_LOG_FILE.to_owned()),
                &content,
            ),
            self.signing_key,
            unix_time().map_err(|error| operation("audit_publication_time", error))?,
            None,
            BTreeMap::from([
                ("session_id".to_owned(), session_id.to_string()),
                (
                    "boundary_plan_digest".to_owned(),
                    self.boundary_plan_digest.clone(),
                ),
            ]),
        )
        .map_err(|error| operation("audit_publication_sign", error))?;
        let signature_bytes = signature
            .encode()
            .map_err(|error| operation("audit_publication_signature_encode", error))?;
        let audit_path = self.state_directory.join(AUDIT_LOG_FILE);
        atomic_write(&audit_path, &content, 0o600)
            .map_err(|error| operation("audit_publication_write", error))?;
        let signature_path = self.state_directory.join(AUDIT_SIGNATURE_FILE);
        if let Err(error) = atomic_write(&signature_path, &signature_bytes, 0o600) {
            let cleanup = fs::remove_file(&audit_path);
            return Err(operation(
                "audit_publication_write",
                cleanup.map_or_else(
                    |cleanup| format!("{error}; audit cleanup also failed: {cleanup}"),
                    |()| error.to_string(),
                ),
            ));
        }
        Ok(AuditPublication {
            signature: Some(signature.signature_id),
        })
    }
}

struct HostCleanup {
    shared: Arc<SharedLifecycleState>,
}

impl CleanupHook for HostCleanup {
    fn cleanup(&self, _session_id: SessionId) -> SessionSecurityResult<()> {
        self.shared
            .supervisor
            .lock()
            .map_err(|_| operation("cleanup", "supervisor mutex poisoned"))?
            .take();
        Ok(())
    }
}

struct SystemLifecycleClock;

impl LifecycleClock for SystemLifecycleClock {
    fn now_unix_nanos(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                duration.as_nanos().try_into().unwrap_or(u64::MAX)
            })
    }
}

fn operation(stage: &'static str, error: impl std::fmt::Display) -> SessionSecurityError {
    SessionSecurityError::Operation {
        stage,
        message: error.to_string(),
    }
}

impl HostError {
    fn kind(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid",
            Self::Boundary(_) => "boundary",
            Self::Runtime(_) => "runtime",
            Self::Security(_) => "security",
            Self::SessionSecurity(_) => "session_security",
            Self::RuntimeSecurity { .. } => "runtime_security",
            Self::AgentPlan(_) => "agent_plan",
            Self::AgentRun(_) => "agent_run",
            Self::Credentials(_) => "credentials",
            Self::GitGuard(_) => "git_guard",
            Self::SecretStore(_) => "secret_store",
            Self::SafeOutputs(_) => "safe_outputs",
            Self::Io { .. } => "io",
            Self::Bundle(_) => "bundle",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use sendbox_agent::{AgentReport, GuestPackageReport, GuestTerminal};
    use sendbox_boundary::{
        Architecture, ArtifactIdentity, ArtifactKind, BOUNDARY_PLAN_FORMAT, BOUNDARY_PLAN_VERSION,
        BoundaryPlan, CommandDeclaration, ControlTransport, EnvironmentDeclaration, HostPlatform,
        MountDeclaration, OperatingSystem, ProviderDeclaration, ResourceDeclaration,
        SignedBoundaryPlan, TrustDeclaration, WorkloadIdentity, select_runtime,
    };
    use sendbox_config::RuntimeProvider;
    use sendbox_runtime::ProcessOutcome;
    use sendbox_security::provenance::{Identity, TrustPolicy, TrustStore};
    use tempfile::TempDir;

    use super::*;

    fn persistent_report(session_id: SessionId, json: Vec<u8>, sha256: String) -> HostRunReport {
        HostRunReport::Persistent(crate::PersistentHostRunReport {
            session_id,
            agent: AgentReport {
                terminal: GuestTerminal::Exited { code: 0 },
                states: Vec::new(),
                package_report: Some(GuestPackageReport { json, sha256 }),
                safe_outputs: None,
            },
            package_report: None,
        })
    }

    #[test]
    fn package_report_is_revalidated_and_persisted_atomically() {
        let temp = TempDir::new().expect("temporary directory");
        let (mut context, _) = context(&temp, 10, 100);
        context.package_report_validation = Some(PackageReportValidation {
            maximum_bytes: 1024,
            maximum_findings: 10,
            policy_digest: "unused-for-empty-report".to_owned(),
        });
        let session_id = context.verified_plan.plan().session_id;
        let json = serde_json::to_vec(&sendbox_registry::PackageSecurityReport::enabled())
            .expect("report");
        let digest = format!("sha256:{}", sha256_hex(&json));
        let mut report = persistent_report(session_id, json.clone(), digest.clone());

        persist_package_report(&mut report, &context).expect("persist report");

        let persisted = report.package_report().expect("report metadata");
        assert_eq!(persisted.sha256(), digest);
        assert_eq!(fs::read(persisted.path()).expect("read persisted"), json);
        assert_eq!(
            fs::metadata(persisted.path())
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn package_report_rejects_digest_tampering_and_oversize() {
        let temp = TempDir::new().expect("temporary directory");
        let (mut context, _) = context(&temp, 10, 100);
        context.package_report_validation = Some(PackageReportValidation {
            maximum_bytes: 1024,
            maximum_findings: 10,
            policy_digest: "unused-for-empty-report".to_owned(),
        });
        let session_id = context.verified_plan.plan().session_id;
        let json = serde_json::to_vec(&sendbox_registry::PackageSecurityReport::enabled())
            .expect("report");
        let mut tampered = persistent_report(
            session_id,
            json.clone(),
            format!("sha256:{}", "0".repeat(64)),
        );
        assert!(persist_package_report(&mut tampered, &context).is_err());

        context
            .package_report_validation
            .as_mut()
            .expect("validation")
            .maximum_bytes = 1;
        let mut oversized = persistent_report(
            session_id,
            json.clone(),
            format!("sha256:{}", sha256_hex(&json)),
        );
        assert!(persist_package_report(&mut oversized, &context).is_err());
    }

    fn context(
        temp: &TempDir,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> (HostSecurityContext, Identity) {
        context_with_session(temp, now_unix, expires_at_unix, 9)
    }

    fn context_with_session(
        temp: &TempDir,
        now_unix: u64,
        expires_at_unix: u64,
        session_byte: u8,
    ) -> (HostSecurityContext, Identity) {
        let state_root = temp.path().join(format!("state-{session_byte}"));
        let state_directory = state_root.join(format!("session-{session_byte}"));
        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&state_root).expect("create state");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).expect("secure state");
        fs::create_dir(&state_directory).expect("create session state");
        fs::create_dir_all(&workspace).expect("create workspace");
        let configuration_bytes = br#"{"configuration":"test"}"#.to_vec();
        let policy_bytes = br#"{"policy":"test"}"#.to_vec();
        let session_id = SessionId::from_bytes([session_byte; 16]);
        let key = SigningKeyMaterial::generate().expect("generate signing key");
        let identity = key.identity("test", None, 0, None);
        let plan = BoundaryPlan {
            format: BOUNDARY_PLAN_FORMAT.to_owned(),
            version: BOUNDARY_PLAN_VERSION,
            session_id,
            created_at_unix: now_unix,
            expires_at_unix,
            selection: select_runtime(
                RuntimeProvider::Auto,
                HostPlatform {
                    operating_system: OperatingSystem::Linux,
                    architecture: Architecture::X86_64,
                },
            )
            .expect("runtime selection"),
            configuration_sha256: sha256_hex(&configuration_bytes),
            policy_sha256: sha256_hex(&policy_bytes),
            trust: TrustDeclaration {
                trust_root_id: "test-root".to_owned(),
                minimum_release_sequence: 1,
                host_version: "0.1.0".to_owned(),
                guest_version: "0.1.0".to_owned(),
            },
            workload: WorkloadIdentity::OciImage {
                reference: format!("registry.example/workload@sha256:{}", "3".repeat(64)),
                digest: format!("sha256:{}", "3".repeat(64)),
            },
            provider: ProviderDeclaration::Kata {
                executable: PathBuf::from("/usr/bin/nerdctl"),
                runtime_handler: "io.containerd.kata.v2".to_owned(),
                namespace: "sendbox".to_owned(),
                address: None,
                snapshotter: None,
                configuration_path: None,
                transport: ControlTransport::RuntimeExecStdio,
            },
            command: CommandDeclaration {
                program: "/usr/bin/agent".to_owned(),
                arguments: vec!["run".to_owned()],
                working_directory: "/workspace".to_owned(),
            },
            workspace: MountDeclaration {
                source: workspace.clone(),
                destination: PathBuf::from("/workspace"),
                writable: true,
            },
            mounts: Vec::new(),
            environment: Vec::<EnvironmentDeclaration>::new(),
            secrets: Vec::new(),
            gateway_secrets: Vec::new(),
            artifacts: vec![
                ArtifactIdentity {
                    kind: ArtifactKind::RuntimeExecutable,
                    path: PathBuf::from("/usr/bin/nerdctl"),
                    sha256: "7".repeat(64),
                },
                ArtifactIdentity {
                    kind: ArtifactKind::GuestBundleManifest,
                    path: PathBuf::from("/opt/sendbox/bundle/manifest.json"),
                    sha256: "5".repeat(64),
                },
                ArtifactIdentity {
                    kind: ArtifactKind::TrustRoot,
                    path: PathBuf::from("/opt/sendbox/trust/root.pub"),
                    sha256: "6".repeat(64),
                },
            ],
            resources: ResourceDeclaration {
                cpus: 2,
                memory_bytes: 512 * 1024 * 1024,
            },
            features: BTreeMap::new(),
        };
        let signed = SignedBoundaryPlan::sign(plan, &key, now_unix).expect("sign plan");
        let verified = signed
            .verify(&identity.fingerprint, now_unix)
            .expect("verify plan");
        (
            HostSecurityContext::new(
                verified,
                configuration_bytes,
                policy_bytes,
                workspace,
                state_directory,
                key,
                None,
            ),
            identity,
        )
    }

    async fn execute_uncancelled<F>(
        context: HostSecurityContext,
        runtime: F,
    ) -> Result<HostRunReport, HostError>
    where
        F: Future<Output = Result<HostRunReport, HostError>>,
    {
        let cancellation = CancellationToken::new();
        execute(context, move |_| runtime, &cancellation).await
    }

    #[tokio::test]
    async fn successful_run_keeps_changes_and_publishes_signed_audit() {
        let temp = TempDir::new().expect("temp dir");
        let now = unix_time().expect("current time");
        let (context, identity) = context(&temp, now, now + 300);
        let workspace = context.workspace.clone();
        let state_directory = context.state_directory.clone();
        fs::write(workspace.join("file"), b"before").expect("write before");

        let report = execute_uncancelled(context, async move {
            fs::write(workspace.join("file"), b"after").expect("write after");
            Ok(HostRunReport::OneShot(ProcessOutcome::successful(
                Vec::new(),
                Vec::new(),
            )))
        })
        .await
        .expect("execute secured run");

        assert_eq!(report.exit_code(), 0);
        assert_eq!(
            fs::read(temp.path().join("workspace/file")).expect("read workspace"),
            b"after"
        );
        let audit = fs::read(state_directory.join(AUDIT_LOG_FILE)).expect("read audit");
        let signature = DetachedSignature::decode(
            &fs::read(state_directory.join(AUDIT_SIGNATURE_FILE)).expect("read signature"),
        )
        .expect("decode signature");
        assert_eq!(signature.subject.sha256, sha256_hex(&audit));
        assert_eq!(signature.signer_fingerprint, identity.fingerprint);
        let mut trust = TrustStore::new(TrustPolicy {
            allow_unsigned: false,
            threshold: 1,
            required_signers: BTreeSet::from([identity.fingerprint.clone()]),
        });
        trust.add_identity(identity).expect("add audit signer");
        trust
            .verify(
                &audit,
                SubjectKind::Artifact,
                &[signature],
                unix_time().expect("verification time"),
            )
            .expect("verify audit signature");
        for path in [
            state_directory.join(AUDIT_LOG_FILE),
            state_directory.join(AUDIT_SIGNATURE_FILE),
            state_directory.join(SUPERVISOR_STATE_FILE),
        ] {
            assert_eq!(
                fs::metadata(path)
                    .expect("artifact metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn runtime_error_rolls_back_workspace_and_preserves_primary_error() {
        let temp = TempDir::new().expect("temp dir");
        let now = unix_time().expect("current time");
        let (context, _) = context(&temp, now, now + 300);
        let workspace = context.workspace.clone();
        let state_directory = context.state_directory.clone();
        fs::write(workspace.join("file"), b"before").expect("write before");
        fs::create_dir_all(workspace.join(".git/hooks")).expect("create Git hooks");
        fs::write(workspace.join(".git/hooks/pre-commit"), b"safe").expect("write safe hook");
        fs::create_dir_all(workspace.join("node_modules/pkg")).expect("create dependency");
        fs::write(workspace.join("node_modules/pkg/index.js"), b"safe")
            .expect("write safe dependency");

        let error = execute_uncancelled(context, async move {
            fs::write(workspace.join("file"), b"after").expect("write after");
            fs::write(workspace.join(".git/hooks/pre-commit"), b"evil").expect("replace Git hook");
            fs::write(workspace.join("node_modules/pkg/index.js"), b"evil")
                .expect("replace dependency");
            Err(HostError::Invalid("runtime failed".to_owned()))
        })
        .await
        .expect_err("runtime must fail");

        assert!(matches!(error, HostError::Invalid(message) if message == "runtime failed"));
        assert_eq!(
            fs::read(temp.path().join("workspace/file")).expect("read workspace"),
            b"before"
        );
        assert_eq!(
            fs::read(temp.path().join("workspace/.git/hooks/pre-commit"))
                .expect("read restored Git hook"),
            b"safe"
        );
        assert!(
            !temp
                .path()
                .join("workspace/node_modules/pkg/index.js")
                .exists()
        );
        let publication: serde_json::Value = serde_json::from_slice(
            &fs::read(state_directory.join(AUDIT_LOG_FILE)).expect("read failure audit"),
        )
        .expect("decode failure audit");
        let runtime_failure = publication["records"]
            .as_array()
            .expect("audit records")
            .iter()
            .find(|record| record["event"]["action"] == "runtime_execution_failed")
            .expect("runtime failure audit record");
        assert_eq!(
            runtime_failure["event"]["metadata"]["error"],
            "runtime failed"
        );
    }

    #[tokio::test]
    async fn nonzero_report_rolls_back_but_preserves_exit_status() {
        let temp = TempDir::new().expect("temp dir");
        let now = unix_time().expect("current time");
        let (context, _) = context(&temp, now, now + 300);
        let workspace = context.workspace.clone();
        fs::write(workspace.join("file"), b"before").expect("write before");

        let report = execute_uncancelled(context, async move {
            fs::write(workspace.join("file"), b"after").expect("write after");
            let mut outcome = ProcessOutcome::successful(Vec::new(), Vec::new());
            outcome.status.success = false;
            outcome.status.code = Some(7);
            Ok(HostRunReport::OneShot(outcome))
        })
        .await
        .expect("nonzero runtime report");

        assert_eq!(report.exit_code(), 7);
        assert_eq!(
            fs::read(temp.path().join("workspace/file")).expect("read workspace"),
            b"before"
        );
    }

    #[tokio::test]
    async fn expired_plan_fails_before_runtime_or_snapshot() {
        let temp = TempDir::new().expect("temp dir");
        let now = unix_time().expect("current time");
        let (context, _) = context(&temp, now - 10, now - 1);
        let state_directory = context.state_directory.clone();
        let ran = Arc::new(AtomicBool::new(false));
        let runtime_ran = Arc::clone(&ran);

        let error = execute_uncancelled(context, async move {
            runtime_ran.store(true, Ordering::SeqCst);
            Ok(HostRunReport::OneShot(ProcessOutcome::successful(
                Vec::new(),
                Vec::new(),
            )))
        })
        .await
        .expect_err("expired plan must fail");

        assert!(matches!(error, HostError::SessionSecurity(_)));
        assert!(!ran.load(Ordering::SeqCst));
        assert!(!state_directory.join(SNAPSHOT_DIRECTORY).exists());
    }

    #[tokio::test]
    async fn workspace_lease_serializes_concurrent_runs() {
        let temp = TempDir::new().expect("temp dir");
        let now = unix_time().expect("current time");
        let (first_context, _) = context_with_session(&temp, now, now + 300, 1);
        let (second_context, _) = context_with_session(&temp, now, now + 300, 2);
        let workspace = temp.path().join("workspace");
        fs::write(workspace.join("file"), b"before").expect("write before");
        let first_started = Arc::new(AtomicBool::new(false));
        let second_started = Arc::new(AtomicBool::new(false));
        let release_first = Arc::new(tokio::sync::Notify::new());

        let first = {
            let workspace = workspace.clone();
            let first_started = Arc::clone(&first_started);
            let release_first = Arc::clone(&release_first);
            execute_uncancelled(first_context, async move {
                first_started.store(true, Ordering::SeqCst);
                release_first.notified().await;
                fs::write(workspace.join("file"), b"first").expect("write first");
                Ok(HostRunReport::OneShot(ProcessOutcome::successful(
                    Vec::new(),
                    Vec::new(),
                )))
            })
        };
        let first_task = tokio::spawn(first);
        while !first_started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        let second = {
            let workspace = workspace.clone();
            let second_started = Arc::clone(&second_started);
            execute_uncancelled(second_context, async move {
                second_started.store(true, Ordering::SeqCst);
                fs::write(workspace.join("file"), b"second").expect("write second");
                Ok(HostRunReport::OneShot(ProcessOutcome::successful(
                    Vec::new(),
                    Vec::new(),
                )))
            })
        };
        let controller = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let started_before_release = second_started.load(Ordering::SeqCst);
            release_first.notify_one();
            assert!(!started_before_release);
        };

        let (second_result, ()) = tokio::join!(second, controller);
        first_task
            .await
            .expect("join first run")
            .expect("first run");
        second_result.expect("second run");
        assert!(second_started.load(Ordering::SeqCst));
        assert_eq!(
            fs::read(workspace.join("file")).expect("read serialized workspace"),
            b"second"
        );
    }

    #[tokio::test]
    async fn workspace_lease_wait_observes_cancellation_across_state_roots() {
        let temp = TempDir::new().expect("temp dir");
        let now = unix_time().expect("current time");
        let (owner_context, _) = context_with_session(&temp, now, now + 300, 3);
        let (waiting_context, _) = context_with_session(&temp, now, now + 300, 4);
        let owner_cancellation = CancellationToken::new();
        let held = acquire_workspace_lease(&owner_context, &owner_cancellation)
            .await
            .expect("hold workspace lease");
        let waiting_cancellation = CancellationToken::new();
        let runtime_started = Arc::new(AtomicBool::new(false));
        let waiting_task = {
            let cancellation = waiting_cancellation.clone();
            let runtime_started = Arc::clone(&runtime_started);
            tokio::spawn(async move {
                execute(
                    waiting_context,
                    move |_| async move {
                        runtime_started.store(true, Ordering::SeqCst);
                        Ok(HostRunReport::OneShot(ProcessOutcome::successful(
                            Vec::new(),
                            Vec::new(),
                        )))
                    },
                    &cancellation,
                )
                .await
            })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;
        waiting_cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), waiting_task)
            .await
            .expect("cancelled waiter must return promptly")
            .expect("join cancelled waiter")
            .expect_err("cancelled waiter must fail");
        assert!(matches!(error, HostError::Runtime(RuntimeError::Cancelled)));
        assert!(!runtime_started.load(Ordering::SeqCst));
        drop(held);
    }

    #[test]
    fn persisted_supervisor_round_trips_against_returned_checkpoint() {
        let temp = TempDir::new().expect("temp dir");
        let state_directory = temp.path().join("state");
        fs::create_dir(&state_directory).expect("create state");
        fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700))
            .expect("secure state");
        let shared = Arc::new(SharedLifecycleState::default());
        let ready = HostPermissionSupervisor {
            state_directory: state_directory.clone(),
            shared,
        };
        let session_id = SessionId::from_bytes([5; 16]);
        let audit = AuditRecorder::new(session_id).expect("create audit");
        let checkpoint = ready
            .ready(session_id, audit.clone())
            .expect("persist supervisor");
        let persisted =
            fs::read(state_directory.join(SUPERVISOR_STATE_FILE)).expect("read supervisor");
        let sink = Arc::new(AuditPermissionEventSink::new(audit));
        let decoded = PermissionSupervisor::decode_with_checkpoint(&persisted, &checkpoint, sink)
            .expect("decode persisted supervisor");

        assert_eq!(decoded.checkpoint(), checkpoint);
    }

    #[test]
    fn rejects_overlapping_state_and_workspace_paths() {
        let workspace = Path::new("/tmp/project");
        assert!(validate_state_workspace_disjoint(workspace, workspace).is_err());
        assert!(validate_state_workspace_disjoint(workspace, &workspace.join("state")).is_err());
        assert!(validate_state_workspace_disjoint(&workspace.join("nested"), workspace).is_err());
        assert!(
            validate_state_workspace_disjoint(workspace, Path::new("/tmp/state/session")).is_ok()
        );
    }

    #[test]
    fn lifecycle_clock_is_bounded() {
        let now = SystemLifecycleClock.now_unix_nanos();
        assert!(now > Duration::from_secs(1).as_nanos() as u64);
    }
}
