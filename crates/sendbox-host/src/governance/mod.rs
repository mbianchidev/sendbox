//! Governed sessions: operator-signed profile admission, effective-policy
//! binding, and brokered credential grants.

pub mod composition;
pub mod operator;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sendbox_config::{RuntimeProvider as ConfiguredRuntime, SandboxConfiguration};
use sendbox_core::SessionId;
use sendbox_governance::profile::RuntimeKind;
use sendbox_governance::{
    CONTRACT_VERSION, GovernanceBinding, PrincipalId, ProjectId, ServiceId, SessionRef,
    Sha256Digest,
};
use sendbox_security::audit::{AuditCategory, AuditResult};
use sendbox_session_security::AuditRecorder;
use serde::Serialize;

pub use composition::{SessionFacts, Violation, ViolationKind};
pub use operator::{
    GovernanceMode, GovernanceSource, MANAGED_CONFIGURATION_PATH, OperatorConfiguration,
    SIGNATURES_FORMAT, VerifiedProfile, encode_signatures, verify_profile,
};

use crate::HostError;

/// Governance state for one admitted run.
pub(crate) struct GovernedSession {
    pub(crate) mode: GovernanceMode,
    pub(crate) source: GovernanceSource,
    pub(crate) verified: VerifiedProfile,
    pub(crate) principal: PrincipalId,
}

impl GovernedSession {
    /// Discovers, loads, and verifies governance, then applies profile
    /// denials to `configuration`. Returns `None` for standalone sessions.
    pub(crate) fn prepare(
        configuration: &mut SandboxConfiguration,
        managed_path: &Path,
        opt_in: Option<&Path>,
        bundle: BundleSelection<'_>,
        state_root: &Path,
        now_unix: u64,
    ) -> Result<Option<Self>, HostError> {
        let uid = crate::current_uid();
        let Some(source) = GovernanceSource::discover(managed_path, opt_in, uid)? else {
            if !configuration.credential_services.is_empty() {
                return Err(HostError::Governance(
                    "credential_services require a governed session; select a governance configuration"
                        .to_owned(),
                ));
            }
            return Ok(None);
        };
        let operator = source.load()?;
        operator.verify_bundle(
            bundle.trust_root,
            bundle.trust_root_id,
            bundle.minimum_release_sequence,
        )?;
        let verified = verify_profile(&source, &operator, now_unix)?;
        crate::ensure_private_directory(state_root)?;
        operator::RevisionHighWater::open(state_root)?
            .check(&verified.authority, &verified.reference)?;
        composition::apply_denials(&verified.profile, &mut configuration.policy);
        Ok(Some(Self {
            mode: source.mode,
            source,
            verified,
            principal: PrincipalId::local_user(uid),
        }))
    }

    /// Rejects the session unless its effective configuration stays within
    /// the profile.
    pub(crate) fn admit(
        &self,
        configuration: &SandboxConfiguration,
        facts: &SessionFacts<'_>,
    ) -> Result<(), HostError> {
        let violations = composition::check(&self.verified.profile, configuration, facts);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(HostError::GovernanceRejected {
                profile: format!(
                    "{} revision {}",
                    self.verified.reference.id, self.verified.reference.revision
                ),
                violations,
            })
        }
    }

    pub(crate) fn binding(
        &self,
        project: ProjectId,
        effective_policy_sha256: &str,
        configuration: &SandboxConfiguration,
    ) -> Result<GovernanceBinding, HostError> {
        let mut brokered_services =
            composition::selected_services(&self.verified.profile, configuration)
                .map_err(HostError::Governance)?
                .into_iter()
                .map(|service| service.id.clone())
                .collect::<Vec<ServiceId>>();
        brokered_services.sort();
        let binding = GovernanceBinding {
            contract_version: CONTRACT_VERSION,
            authority: self.verified.authority.clone(),
            profile: self.verified.reference.clone(),
            principal: self.principal.clone(),
            project,
            effective_policy_sha256: Sha256Digest::parse_hex(effective_policy_sha256)
                .map_err(operator::governance_error)?,
            brokered_services,
        };
        binding.validate().map_err(operator::governance_error)?;
        Ok(binding)
    }

    pub(crate) fn record_admission(&self, state_root: &Path) -> Result<(), HostError> {
        operator::RevisionHighWater::open(state_root)?
            .record(&self.verified.authority, &self.verified.reference)
    }
}

/// An admitted governed run: the verified profile plus the exact binding
/// signed into the boundary plan.
pub(crate) struct GovernedRun {
    pub(crate) session: GovernedSession,
    pub(crate) binding: GovernanceBinding,
    pub(crate) binding_sha256: Sha256Digest,
    pub(crate) session_ref: SessionRef,
}

impl GovernedRun {
    pub(crate) fn new(
        session: GovernedSession,
        binding: GovernanceBinding,
        session_id: SessionId,
    ) -> Result<Self, HostError> {
        let binding_sha256 = binding.digest().map_err(operator::governance_error)?;
        Ok(Self {
            session,
            binding,
            binding_sha256,
            session_ref: SessionRef::from_session_id(session_id),
        })
    }

    /// Identity metadata shared by every governance audit record. It never
    /// contains credential material.
    pub(crate) fn audit_metadata(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("principal".to_owned(), self.binding.principal.to_string()),
            ("project".to_owned(), self.binding.project.to_string()),
            ("session".to_owned(), self.session_ref.to_string()),
            ("authority".to_owned(), self.binding.authority.id.clone()),
            ("profile".to_owned(), self.binding.profile.id.to_string()),
            (
                "profile_revision".to_owned(),
                self.binding.profile.revision.to_string(),
            ),
            (
                "profile_sha256".to_owned(),
                self.binding.profile.sha256.to_string(),
            ),
            (
                "effective_policy_sha256".to_owned(),
                self.binding.effective_policy_sha256.to_string(),
            ),
            ("binding_sha256".to_owned(), self.binding_sha256.to_string()),
        ])
    }

    pub(crate) fn record_admission(&self, audit: &AuditRecorder) -> Result<(), HostError> {
        let mut metadata = self.audit_metadata();
        metadata.insert(
            "mode".to_owned(),
            match self.session.mode {
                GovernanceMode::Managed => "managed",
                GovernanceMode::OptIn => "opt_in",
            }
            .to_owned(),
        );
        metadata.insert(
            "trust_sha256".to_owned(),
            self.binding.authority.trust_sha256.to_string(),
        );
        metadata.insert(
            "valid_signers".to_owned(),
            self.session
                .verified
                .signers
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        );
        metadata.insert(
            "brokered_services".to_owned(),
            self.binding
                .brokered_services
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        record_audit(
            audit,
            AuditCategory::Policy,
            "governance.admission.accepted",
            &self.session_ref.to_string(),
            AuditResult::Allowed,
            metadata,
        )
    }
}

pub(crate) fn record_audit(
    audit: &AuditRecorder,
    category: AuditCategory,
    action: &str,
    subject: &str,
    result: AuditResult,
    metadata: BTreeMap<String, String>,
) -> Result<(), HostError> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| HostError::Governance(format!("read audit time: {error}")))?
        .as_nanos()
        .try_into()
        .map_err(|_| HostError::Governance("audit time is out of range".to_owned()))?;
    audit
        .record(timestamp, category, action, subject, result, metadata)
        .map(|_| ())
        .map_err(HostError::SessionSecurity)
}

/// CLI-selected guest bundle trust that the operator may pin.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BundleSelection<'a> {
    pub trust_root: &'a Path,
    pub trust_root_id: &'a str,
    pub minimum_release_sequence: u64,
}

/// Project identity used for bindings and grants.
pub(crate) fn project_id(
    repository: Option<&sendbox_git::RepositoryIdentity>,
    workspace_root: &Path,
) -> Result<ProjectId, HostError> {
    use std::os::unix::ffi::OsStrExt;
    match repository {
        Some(repository) if repository.host() == "github.com" => {
            ProjectId::github(repository.owner(), repository.name())
                .map_err(operator::governance_error)
        }
        _ => Ok(ProjectId::from_canonical_path(
            workspace_root.as_os_str().as_bytes(),
        )),
    }
}

/// Maps the runtime a session resolved to the profile vocabulary.
pub(crate) const fn runtime_kind(runtime: sendbox_boundary::ResolvedRuntime) -> RuntimeKind {
    match runtime {
        sendbox_boundary::ResolvedRuntime::Apple => RuntimeKind::Apple,
        sendbox_boundary::ResolvedRuntime::Kata => RuntimeKind::Kata,
        sendbox_boundary::ResolvedRuntime::Hyperlight => RuntimeKind::Hyperlight,
    }
}

/// The active, verified governance configuration for this host.
#[derive(Debug, Clone)]
pub struct ActiveGovernance {
    pub source: GovernanceSource,
    pub operator: OperatorConfiguration,
    pub verified: VerifiedProfile,
}

/// Loads and verifies the active governance profile, if governance applies.
pub fn verify_active(
    managed_path: &Path,
    opt_in: Option<&Path>,
) -> Result<Option<ActiveGovernance>, HostError> {
    let Some(source) = GovernanceSource::discover(managed_path, opt_in, crate::current_uid())?
    else {
        return Ok(None);
    };
    let operator = source.load()?;
    let verified = verify_profile(&source, &operator, crate::unix_time()?)?;
    Ok(Some(ActiveGovernance {
        source,
        operator,
        verified,
    }))
}

/// Inputs for `sendbox governance check`.
#[derive(Debug, Clone)]
pub struct GovernanceCheckRequest {
    pub configuration: SandboxConfiguration,
    pub managed_path: PathBuf,
    pub governance_config: Option<PathBuf>,
    pub runtime: Option<RuntimeKind>,
    pub image: Option<String>,
}

/// Explains how a configuration composes with the active governance profile.
#[derive(Debug, Clone, Serialize)]
pub struct GovernanceCheckReport {
    pub mode: Option<GovernanceMode>,
    pub authority: Option<String>,
    pub profile: Option<String>,
    pub profile_revision: Option<u64>,
    pub profile_sha256: Option<String>,
    pub admitted: bool,
    pub violations: Vec<String>,
    pub applied_denials: AppliedDenials,
    pub brokered_services: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AppliedDenials {
    pub commands: Vec<String>,
    pub domains: Vec<String>,
    pub networks: Vec<String>,
}

/// Evaluates a configuration against the active governance profile without
/// starting a session.
pub fn check(request: GovernanceCheckRequest) -> Result<GovernanceCheckReport, HostError> {
    let mut configuration = request.configuration;
    configuration
        .validate()
        .map_err(|error| HostError::Invalid(error.to_string()))?;
    let Some(ActiveGovernance {
        source, verified, ..
    }) = verify_active(&request.managed_path, request.governance_config.as_deref())?
    else {
        return Ok(GovernanceCheckReport {
            mode: None,
            authority: None,
            profile: None,
            profile_revision: None,
            profile_sha256: None,
            admitted: configuration.credential_services.is_empty(),
            violations: if configuration.credential_services.is_empty() {
                Vec::new()
            } else {
                vec!["credential_services require a governed session".to_owned()]
            },
            applied_denials: AppliedDenials::default(),
            brokered_services: Vec::new(),
        });
    };
    let before = configuration.policy.clone();
    composition::apply_denials(&verified.profile, &mut configuration.policy);
    let added = |after: &[String], before: &[String]| {
        after
            .iter()
            .filter(|entry| !before.contains(entry))
            .cloned()
            .collect::<Vec<_>>()
    };
    let applied_denials = AppliedDenials {
        commands: added(
            &configuration.policy.commands.denylist,
            &before.commands.denylist,
        ),
        domains: added(
            &configuration.policy.network.blocked_domains,
            &before.network.blocked_domains,
        ),
        networks: added(
            &configuration.policy.network.blocked_networks,
            &before.network.blocked_networks,
        ),
    };
    let runtime = request.runtime.unwrap_or_else(|| {
        match configuration
            .runtime
            .as_ref()
            .map_or(ConfiguredRuntime::Auto, |runtime| runtime.provider)
        {
            ConfiguredRuntime::Kata => RuntimeKind::Kata,
            ConfiguredRuntime::Hyperlight => RuntimeKind::Hyperlight,
            ConfiguredRuntime::Apple | ConfiguredRuntime::Auto => {
                if cfg!(target_os = "macos") {
                    RuntimeKind::Apple
                } else {
                    RuntimeKind::Kata
                }
            }
        }
    });
    let workspace_root = configuration.workspace_root().to_path_buf();
    let violations = composition::check(
        &verified.profile,
        &configuration,
        &SessionFacts {
            runtime,
            image: request.image.as_deref(),
            workspace_root: &workspace_root,
        },
    );
    Ok(GovernanceCheckReport {
        mode: Some(source.mode),
        authority: Some(verified.authority.id.clone()),
        profile: Some(verified.reference.id.to_string()),
        profile_revision: Some(verified.reference.revision),
        profile_sha256: Some(verified.reference.sha256.to_string()),
        admitted: violations.is_empty(),
        violations: violations.iter().map(ToString::to_string).collect(),
        applied_denials,
        brokered_services: configuration.credential_services.clone(),
    })
}
