//! Governed sessions: operator-signed profile admission, effective-policy
//! binding, and brokered credential grants.

pub mod composition;
pub(crate) mod fleet;
pub mod operator;
pub(crate) mod relay;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sendbox_agent::EnvironmentIntent;
use sendbox_bootstrap::CredentialRelayBootstrap;
use sendbox_config::{RuntimeProvider as ConfiguredRuntime, SandboxConfiguration};
use sendbox_core::SessionId;
use sendbox_egress::runtime::DEFAULT_CREDENTIAL_RELAY_PORT;
use sendbox_governance::api::SessionOutcome;
use sendbox_governance::exception::MAX_SESSION_EXCEPTIONS;
use sendbox_governance::profile::{CredentialServiceProfile, RuntimeKind};
use sendbox_governance::{
    CONTRACT_VERSION, ExceptionScope, GovernanceBinding, PolicyException, PrincipalId, ProjectId,
    ServiceId, SessionRef, Sha256Digest,
};
use sendbox_secrets::{SecretName, SecretStore};
use sendbox_security::audit::{AuditCategory, AuditResult};
use sendbox_session_security::AuditRecorder;
use serde::Serialize;

pub use composition::{SessionFacts, Violation, ViolationKind};
pub use operator::{
    DEFAULT_FLEET_TOKEN_SECRET, FleetSettings, GovernanceMode, GovernanceSource,
    MANAGED_CONFIGURATION_PATH, OperatorConfiguration, SIGNATURES_FORMAT, VerifiedProfile,
    encode_signatures, verify_profile,
};

use crate::HostError;

/// Governance state for one admitted run.
pub(crate) struct GovernedSession {
    pub(crate) mode: GovernanceMode,
    pub(crate) source: GovernanceSource,
    pub(crate) verified: VerifiedProfile,
    pub(crate) principal: PrincipalId,
    operator: OperatorConfiguration,
    project: Option<ProjectId>,
    /// Approved exceptions whose denials this session lifts, sorted by id.
    pub(crate) exceptions: Vec<PolicyException>,
    pub(crate) fleet: Option<Arc<fleet::FleetClient>>,
}

/// Opens the host secret store that holds the caller's fleet token.
pub(crate) type SecretStoreOpener<'a> =
    &'a (dyn Fn() -> Result<Arc<dyn SecretStore>, HostError> + Sync);

impl GovernedSession {
    /// Discovers, loads, and verifies governance. Returns `None` for
    /// standalone sessions. Profile denials are applied later by
    /// [`Self::apply`], once the project is known.
    pub(crate) fn prepare(
        configuration: &SandboxConfiguration,
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
            source.ownership,
            bundle.trust_root_id,
            bundle.minimum_release_sequence,
        )?;
        let verified = verify_profile(&source, &operator, now_unix)?;
        crate::ensure_private_directory(state_root)?;
        operator::RevisionHighWater::open(state_root)?
            .check(&verified.authority, &verified.reference)?;
        Ok(Some(Self {
            mode: source.mode,
            source,
            verified,
            principal: PrincipalId::local_user(uid),
            operator,
            project: None,
            exceptions: Vec::new(),
            fleet: None,
        }))
    }

    /// Binds the project and applies the profile denials to `configuration`.
    ///
    /// With a shared governance service, the service first authenticates the
    /// caller (who becomes the session principal) and reports the project's
    /// active exceptions. Only approved exceptions bound to this exact profile
    /// revision, for this principal or the whole project, and permitted by the
    /// profile, lift a denial. The ceiling check still applies afterwards.
    pub(crate) async fn apply(
        &mut self,
        configuration: &mut SandboxConfiguration,
        project: ProjectId,
        open_secrets: SecretStoreOpener<'_>,
        now_unix: u64,
    ) -> Result<(), HostError> {
        if let Some(settings) = &self.operator.fleet {
            if configuration
                .secrets
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&settings.token_secret))
            {
                return Err(HostError::Governance(format!(
                    "the fleet token `{}` can never be a workload secret",
                    settings.token_secret
                )));
            }
            let token = open_secrets()?
                .retrieve(&SecretName::new(settings.token_secret.clone())?)
                .map_err(|error| {
                    HostError::Governance(format!(
                        "fleet token `{0}` is unavailable in the host secret store ({error}); add it with `sendbox secrets add {0}`",
                        settings.token_secret
                    ))
                })?;
            let client = Arc::new(fleet::FleetClient::new(settings, &token.value)?);
            let caller = client.whoami().await?;
            let active = client.active_exceptions(&project).await?;
            self.exceptions = select_exceptions(
                active,
                &project,
                &caller.principal,
                &self.verified,
                now_unix,
            )?;
            self.principal = caller.principal;
            self.fleet = Some(client);
        }
        let lifted = self
            .exceptions
            .iter()
            .map(|exception| exception.scope.clone())
            .collect::<Vec<ExceptionScope>>();
        composition::apply_denials(&self.verified.profile, &lifted, &mut configuration.policy);
        self.project = Some(project);
        configuration
            .validate()
            .map_err(|error| HostError::Invalid(error.to_string()))
    }

    /// The earliest expiry among lifted exceptions. The session must stop
    /// then, because its egress and command rules are fixed at start.
    pub(crate) fn exception_deadline(&self) -> Option<&PolicyException> {
        self.exceptions
            .iter()
            .min_by_key(|exception| exception.expires_at_unix)
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
        effective_policy_sha256: &str,
        configuration: &SandboxConfiguration,
    ) -> Result<GovernanceBinding, HostError> {
        let project = self.project.clone().ok_or_else(|| {
            HostError::Governance("governance denials were not applied".to_owned())
        })?;
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
            exceptions: self
                .exceptions
                .iter()
                .map(|exception| exception.id.clone())
                .collect(),
        };
        binding.validate().map_err(operator::governance_error)?;
        Ok(binding)
    }

    pub(crate) fn record_admission(&self, state_root: &Path) -> Result<(), HostError> {
        operator::RevisionHighWater::open(state_root)?
            .record(&self.verified.authority, &self.verified.reference)
    }

    /// Profile definitions of the services this session brokers, sorted by id.
    pub(crate) fn brokered_services(
        &self,
        configuration: &SandboxConfiguration,
    ) -> Result<Vec<CredentialServiceProfile>, HostError> {
        composition::selected_services(&self.verified.profile, configuration)
            .map(|services| services.into_iter().cloned().collect())
            .map_err(HostError::Governance)
    }

    /// Guest relay listener configuration. It names services and limits only.
    pub(crate) fn relay_bootstrap(
        &self,
        services: &[CredentialServiceProfile],
    ) -> Option<CredentialRelayBootstrap> {
        (!services.is_empty()).then(|| CredentialRelayBootstrap {
            port: DEFAULT_CREDENTIAL_RELAY_PORT,
            services: services
                .iter()
                .map(|service| service.id.to_string())
                .collect(),
            max_streams: self.verified.profile.grants.max_concurrent_streams,
            max_request_bytes: services
                .iter()
                .map(|service| service.max_request_bytes)
                .max()
                .unwrap_or(1),
        })
    }
}

/// Provider-standard endpoint variables for compatible agents. The key is a
/// fixed placeholder: the host broker discards it and injects the real one.
pub(crate) fn relay_environment(
    services: &[CredentialServiceProfile],
    port: u16,
) -> Vec<EnvironmentIntent> {
    services
        .iter()
        .flat_map(|service| {
            [
                EnvironmentIntent {
                    name: service.provider.base_url_environment().to_owned(),
                    value: format!(
                        "http://127.0.0.1:{port}/{}{}",
                        service.id,
                        service.provider.base_url_suffix()
                    ),
                    sensitive: false,
                },
                EnvironmentIntent {
                    name: service.provider.api_key_environment().to_owned(),
                    value: sendbox_governance::BROKERED_CREDENTIAL_PLACEHOLDER.to_owned(),
                    sensitive: false,
                },
            ]
        })
        .collect()
}

/// Picks the exceptions a session lifts: for each permitted scope, the
/// applicable exception that lasts longest. Sorted by id for the binding.
fn select_exceptions(
    active: Vec<PolicyException>,
    project: &ProjectId,
    principal: &PrincipalId,
    verified: &VerifiedProfile,
    now_unix: u64,
) -> Result<Vec<PolicyException>, HostError> {
    let mut by_scope = BTreeMap::<ExceptionScope, PolicyException>::new();
    for exception in active {
        if !exception.applies_to(project, principal, &verified.reference, now_unix)
            || !verified.profile.permits_exception(&exception.scope)
        {
            continue;
        }
        let replace = by_scope.get(&exception.scope).is_none_or(|kept| {
            (exception.expires_at_unix, std::cmp::Reverse(&exception.id))
                > (kept.expires_at_unix, std::cmp::Reverse(&kept.id))
        });
        if replace {
            by_scope.insert(exception.scope.clone(), exception);
        }
    }
    if by_scope.len() > MAX_SESSION_EXCEPTIONS {
        return Err(HostError::Governance(format!(
            "more than {MAX_SESSION_EXCEPTIONS} policy exceptions apply to this session"
        )));
    }
    let mut selected = by_scope.into_values().collect::<Vec<_>>();
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(selected)
}

/// An admitted governed run: the verified profile plus the exact binding
/// signed into the boundary plan.
pub(crate) struct GovernedRun {
    pub(crate) session: GovernedSession,
    pub(crate) binding: GovernanceBinding,
    pub(crate) binding_sha256: Sha256Digest,
    pub(crate) session_ref: SessionRef,
    brokered: Option<(Vec<CredentialServiceProfile>, relay::BrokeredSecrets)>,
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
            brokered: None,
        })
    }

    /// Registers the session with the shared governance service, which
    /// checks the caller's project role, the profile revision, and every
    /// bound exception. A local authority has nothing to register.
    pub(crate) async fn admit_remote(&self) -> Result<(), HostError> {
        if let Some(client) = &self.session.fleet {
            client.admit(&self.session_ref, &self.binding).await?;
        }
        Ok(())
    }

    /// Tells the shared governance service that the session ended, which
    /// revokes any grant it still holds.
    pub(crate) async fn end_remote(&self, outcome: SessionOutcome) -> Result<(), HostError> {
        if let Some(client) = &self.session.fleet {
            client.end(&self.session_ref, outcome).await?;
        }
        Ok(())
    }

    pub(crate) fn authority(
        &self,
        local: impl FnOnce() -> Arc<dyn sendbox_governance::GrantAuthority>,
    ) -> Arc<dyn sendbox_governance::GrantAuthority> {
        match &self.session.fleet {
            Some(client) => Arc::new(fleet::FleetGrantAuthority::new(Arc::clone(client))),
            None => local(),
        }
    }

    pub(crate) fn attach_brokered(
        &mut self,
        services: Vec<CredentialServiceProfile>,
        secrets: relay::BrokeredSecrets,
    ) {
        self.brokered = Some((services, secrets));
    }

    /// Starts the host credential relay for a brokered session.
    pub(crate) async fn start_relay(
        &mut self,
        audit: &AuditRecorder,
    ) -> Result<Option<std::sync::Arc<relay::HostCredentialRelay>>, HostError> {
        let Some((services, secrets)) = self.brokered.take() else {
            return Ok(None);
        };
        relay::HostCredentialRelay::start(self, &services, secrets, audit.clone())
            .await
            .map(|relay| Some(std::sync::Arc::new(relay)))
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

    /// Records a session stopped because a lifted exception expired.
    pub(crate) fn record_exception_expiry(
        &self,
        audit: &AuditRecorder,
        exception: &PolicyException,
    ) -> Result<(), HostError> {
        let mut metadata = self.audit_metadata();
        metadata.extend([
            ("exception".to_owned(), exception.id.to_string()),
            ("scope".to_owned(), exception.scope.to_string()),
            (
                "expires_at_unix".to_owned(),
                exception.expires_at_unix.to_string(),
            ),
        ]);
        record_audit(
            audit,
            AuditCategory::Policy,
            "governance.exception.expired",
            &self.session_ref.to_string(),
            AuditResult::Denied,
            metadata,
        )
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
        if let Some(settings) = &self.session.operator.fleet {
            metadata.insert("authority_url".to_owned(), settings.url.clone());
        }
        if !self.session.exceptions.is_empty() {
            metadata.insert(
                "exceptions".to_owned(),
                self.binding
                    .exceptions
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        for exception in &self.session.exceptions {
            let key = |field: &str| format!("exception.{}.{field}", exception.id);
            metadata.insert(key("scope"), exception.scope.to_string());
            metadata.insert(key("requested_by"), exception.requested_by.to_string());
            if let Some(approver) = &exception.decided_by {
                metadata.insert(key("approved_by"), approver.to_string());
            }
            metadata.insert(
                key("expires_at_unix"),
                exception.expires_at_unix.to_string(),
            );
        }
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
    composition::apply_denials(&verified.profile, &[], &mut configuration.policy);
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

#[cfg(test)]
pub(crate) mod tests {
    use sendbox_config::{PolicyPreset, RuntimeProvider};
    use sendbox_governance::profile::GovernanceProfile;
    use sendbox_secrets::{RecordVersion, Secret, SecretMetadata, SecretStoreError, SecretValue};

    use super::operator::tests::{Fixture, fixture, private_directory, protected_test_tree};
    use super::*;

    pub(crate) fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs()
    }

    /// A profile valid now, brokering both supported providers.
    pub(crate) fn brokered_profile() -> String {
        let now = now_unix();
        format!(
            r#"format: sendbox.governance-profile
version: 1
id: acme
revision: 4
not_before_unix: {}
expires_at_unix: {}
ceiling:
  runtimes: [apple, kata]
  commands:
    default_action: deny
    allowlist: ["git *"]
  network:
    default_action: deny
    allowed_domains: ["*.github.com"]
    allow_dns: true
credential_services:
  - id: openai
    provider: openai
    secret: SENDBOX_OPENAI_API_KEY
  - id: anthropic
    provider: anthropic
    secret: SENDBOX_ANTHROPIC_API_KEY
"#,
            now - 60,
            now + 86_400
        )
    }

    pub(crate) fn configuration(services: &[&str]) -> SandboxConfiguration {
        let mut configuration = SandboxConfiguration::for_project(
            PathBuf::from("/work/app"),
            PolicyPreset::Strict,
            RuntimeProvider::Apple,
        );
        configuration.github.forward_auth = false;
        configuration.github.forward_copilot_auth = false;
        configuration.policy.network.allowed_domains = vec!["*.github.com".to_owned()];
        configuration.policy.commands.allowlist = vec!["git status".to_owned()];
        configuration.credential_services = services.iter().map(|&s| s.to_owned()).collect();
        configuration
    }

    fn bundle() -> BundleSelection<'static> {
        BundleSelection {
            trust_root: Path::new("/nonexistent/trust.json"),
            trust_root_id: "test",
            minimum_release_sequence: 0,
        }
    }

    pub(crate) struct FakeStore(pub(crate) BTreeMap<&'static str, &'static str>);

    impl FakeStore {
        fn unsupported<T>() -> Result<T, SecretStoreError> {
            Err(SecretStoreError::AccessDenied)
        }
    }

    impl SecretStore for FakeStore {
        fn store(
            &self,
            _: &SecretName,
            _: SecretValue,
        ) -> Result<SecretMetadata, SecretStoreError> {
            Self::unsupported()
        }
        fn update(
            &self,
            _: &SecretName,
            _: SecretValue,
        ) -> Result<SecretMetadata, SecretStoreError> {
            Self::unsupported()
        }
        fn retrieve(&self, name: &SecretName) -> Result<Secret, SecretStoreError> {
            let value = self
                .0
                .get(name.as_str())
                .ok_or_else(|| SecretStoreError::NotFound(name.clone()))?;
            Ok(Secret {
                metadata: SecretMetadata {
                    name: name.clone(),
                    created_at_unix_ms: 0,
                    updated_at_unix_ms: 0,
                    version: RecordVersion::V1,
                },
                value: SecretValue::try_from(*value)?,
            })
        }
        fn delete(&self, _: &SecretName) -> Result<(), SecretStoreError> {
            Self::unsupported()
        }
        fn list(&self) -> Result<Vec<SecretMetadata>, SecretStoreError> {
            Self::unsupported()
        }
        fn exists(&self, name: &SecretName) -> Result<bool, SecretStoreError> {
            Ok(self.0.contains_key(name.as_str()))
        }
        fn migrate(&self, _: &SecretName) -> Result<SecretMetadata, SecretStoreError> {
            Self::unsupported()
        }
    }

    pub(crate) fn no_secret_store() -> Result<Arc<dyn SecretStore>, HostError> {
        Err(HostError::Invalid(
            "no secret store in this test".to_owned(),
        ))
    }

    pub(crate) async fn prepare(
        fixture: &Fixture,
        configuration: &mut SandboxConfiguration,
        open_secrets: SecretStoreOpener<'_>,
    ) -> Result<GovernedSession, HostError> {
        let mut session = GovernedSession::prepare(
            configuration,
            &fixture.directory.path().join("absent-managed.yaml"),
            Some(&fixture.source.path),
            bundle(),
            &fixture.directory.path().join("state"),
            now_unix(),
        )?
        .expect("governed");
        session
            .apply(
                configuration,
                ProjectId::github("acme", "app").expect("project"),
                open_secrets,
                now_unix(),
            )
            .await?;
        Ok(session)
    }

    pub(crate) async fn admitted_run(
        fixture: &Fixture,
        configuration: &mut SandboxConfiguration,
    ) -> GovernedRun {
        let session = prepare(fixture, configuration, &no_secret_store)
            .await
            .expect("prepare");
        run_for(session, configuration)
    }

    pub(crate) fn run_for(
        session: GovernedSession,
        configuration: &SandboxConfiguration,
    ) -> GovernedRun {
        let facts = SessionFacts {
            runtime: RuntimeKind::Apple,
            image: None,
            workspace_root: Path::new("/work/app"),
        };
        session.admit(configuration, &facts).expect("admit");
        let binding = session
            .binding(&"ab".repeat(32), configuration)
            .expect("binding");
        GovernedRun::new(session, binding, SessionId::from_bytes([7; 16])).expect("run")
    }

    #[test]
    fn standalone_sessions_cannot_request_brokered_credentials() {
        let directory = private_directory();
        let managed = directory.path().join("absent.yaml");
        let state = directory.path().join("state");
        let standalone = configuration(&[]);
        assert!(
            GovernedSession::prepare(&standalone, &managed, None, bundle(), &state, 0)
                .expect("standalone")
                .is_none()
        );
        let brokered = configuration(&["anthropic"]);
        let error = GovernedSession::prepare(&brokered, &managed, None, bundle(), &state, 0)
            .err()
            .expect("brokered services without governance are rejected");
        assert!(
            matches!(error, HostError::Governance(message) if message.contains("credential_services"))
        );
    }

    #[test]
    fn relay_environment_points_agents_at_the_loopback_relay() {
        let profile = GovernanceProfile::parse(brokered_profile().as_bytes()).expect("profile");
        let environment = relay_environment(&profile.credential_services, 15_084)
            .into_iter()
            .map(|intent| {
                assert!(!intent.sensitive);
                (intent.name, intent.value)
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment,
            BTreeMap::from([
                (
                    "ANTHROPIC_BASE_URL".to_owned(),
                    "http://127.0.0.1:15084/anthropic".to_owned()
                ),
                (
                    "ANTHROPIC_API_KEY".to_owned(),
                    sendbox_governance::BROKERED_CREDENTIAL_PLACEHOLDER.to_owned()
                ),
                (
                    "OPENAI_BASE_URL".to_owned(),
                    "http://127.0.0.1:15084/openai/v1".to_owned()
                ),
                (
                    "OPENAI_API_KEY".to_owned(),
                    sendbox_governance::BROKERED_CREDENTIAL_PLACEHOLDER.to_owned()
                ),
            ])
        );
    }

    #[tokio::test]
    async fn governed_session_binds_admission_and_brokered_services() {
        if !protected_test_tree() {
            return;
        }
        let fixture = fixture(&brokered_profile(), 1);
        let mut configuration = configuration(&["openai", "anthropic"]);
        let run = admitted_run(&fixture, &mut configuration).await;
        for host in ["api.anthropic.com", "api.openai.com"] {
            assert!(
                configuration
                    .policy
                    .network
                    .blocked_domains
                    .contains(&host.to_owned()),
                "{host} must be denied to the workload"
            );
        }
        let ids =
            |services: &[ServiceId]| services.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(ids(&run.binding.brokered_services), ["anthropic", "openai"]);
        assert_eq!(run.binding_sha256, run.binding.digest().expect("digest"));

        let services = run
            .session
            .brokered_services(&configuration)
            .expect("services");
        let relay = run.session.relay_bootstrap(&services).expect("relay");
        assert_eq!(relay.port, DEFAULT_CREDENTIAL_RELAY_PORT);
        assert_eq!(relay.services, ["anthropic", "openai"]);
        assert!(run.session.relay_bootstrap(&[]).is_none());

        let audit = AuditRecorder::new(SessionId::from_bytes([7; 16])).expect("audit");
        run.record_admission(&audit).expect("record");
        let records = audit.records().expect("records");
        let admission = &records.last().expect("admission record").event;
        assert_eq!(admission.action, "governance.admission.accepted");
        assert_eq!(admission.metadata["mode"], "opt_in");
        assert_eq!(admission.metadata["brokered_services"], "anthropic,openai");
        assert_eq!(
            admission.metadata["binding_sha256"],
            run.binding_sha256.to_string()
        );
    }
}
