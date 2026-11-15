//! Governed sessions: operator-signed profile admission, effective-policy
//! binding, and brokered credential grants.

pub mod composition;
pub mod operator;
pub(crate) mod relay;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sendbox_agent::EnvironmentIntent;
use sendbox_bootstrap::CredentialRelayBootstrap;
use sendbox_config::{RuntimeProvider as ConfiguredRuntime, SandboxConfiguration};
use sendbox_core::SessionId;
use sendbox_egress::runtime::DEFAULT_CREDENTIAL_RELAY_PORT;
use sendbox_governance::profile::{CredentialServiceProfile, RuntimeKind};
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
            source.ownership,
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

#[cfg(test)]
pub(crate) mod tests {
    use sendbox_config::{PolicyPreset, RuntimeProvider};
    use sendbox_governance::profile::GovernanceProfile;

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

    pub(crate) fn prepare(
        fixture: &Fixture,
        configuration: &mut SandboxConfiguration,
    ) -> GovernedSession {
        GovernedSession::prepare(
            configuration,
            &fixture.directory.path().join("absent-managed.yaml"),
            Some(&fixture.source.path),
            bundle(),
            &fixture.directory.path().join("state"),
            now_unix(),
        )
        .expect("prepare")
        .expect("governed")
    }

    pub(crate) fn admitted_run(
        fixture: &Fixture,
        configuration: &mut SandboxConfiguration,
    ) -> GovernedRun {
        let session = prepare(fixture, configuration);
        let facts = SessionFacts {
            runtime: RuntimeKind::Apple,
            image: None,
            workspace_root: Path::new("/work/app"),
        };
        session.admit(configuration, &facts).expect("admit");
        let binding = session
            .binding(
                ProjectId::github("acme", "app").expect("project"),
                &"ab".repeat(32),
                configuration,
            )
            .expect("binding");
        GovernedRun::new(session, binding, SessionId::from_bytes([7; 16])).expect("run")
    }

    #[test]
    fn standalone_sessions_cannot_request_brokered_credentials() {
        let directory = private_directory();
        let managed = directory.path().join("absent.yaml");
        let state = directory.path().join("state");
        let mut standalone = configuration(&[]);
        assert!(
            GovernedSession::prepare(&mut standalone, &managed, None, bundle(), &state, 0)
                .expect("standalone")
                .is_none()
        );
        let mut brokered = configuration(&["anthropic"]);
        let error = GovernedSession::prepare(&mut brokered, &managed, None, bundle(), &state, 0)
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

    #[test]
    fn governed_session_binds_admission_and_brokered_services() {
        if !protected_test_tree() {
            return;
        }
        let fixture = fixture(&brokered_profile(), 1);
        let mut configuration = configuration(&["openai", "anthropic"]);
        let run = admitted_run(&fixture, &mut configuration);
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
