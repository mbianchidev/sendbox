//! Host wiring for brokered credential services: grants from the local
//! authority, per-request authorization, host-held secrets, and audit.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sendbox_agent::{AgentError, BoxFuture, CredentialRelayHandler, CredentialRelayOutbound};
use sendbox_credentials::relay::{
    RelayAuditEvent, RelayAuditSink, RelayAuthorization, RelayAuthorizer, RelayEndpoint,
    RelayFuture, RelayLimits, RelayOutbound, RelayService, RelayStreamOutcome,
};
use sendbox_credentials::{CredentialBrokerError, PinnedHttpsTransport, SecretResolver};
use sendbox_governance::api::{ReportedOutcome, RequestOutcomeReport};
use sendbox_governance::profile::CredentialServiceProfile;
use sendbox_governance::{
    CredentialGrant, Decision, GrantAuthority, GrantId, GrantRequest, LocalAuthorityLimits,
    LocalGrantAuthority, RequestContext, RevocationReason, ServiceId, SystemClock,
};
use sendbox_protocol::Event;
use sendbox_secrets::{SecretName, SecretStore, SecretValue};
use sendbox_security::audit::{AuditCategory, AuditResult};
use sendbox_session_security::AuditRecorder;
use tokio::task::JoinHandle;

use super::fleet::FleetClient;
use super::{GovernedRun, operator::OperatorRevisionSource, record_audit};
use crate::HostError;

/// Longest the relay waits for queued outcome reports at session end.
const OUTCOME_FLUSH_TIMEOUT: Duration = Duration::from_secs(30);

/// Provider credentials resolved from the host secret store before the
/// session starts. They are held only in this process.
pub(crate) struct BrokeredSecrets {
    values: BTreeMap<String, SecretValue>,
}

impl std::fmt::Debug for BrokeredSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokeredSecrets")
            .field("names", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BrokeredSecrets {
    pub(crate) fn resolve(
        services: &[CredentialServiceProfile],
        store: &dyn SecretStore,
        masker: &sendbox_secrets::CredentialMasker,
    ) -> Result<Self, HostError> {
        let mut values = BTreeMap::new();
        for service in services {
            if values.contains_key(&service.secret) {
                continue;
            }
            let name = SecretName::new(service.secret.clone())?;
            let secret = store.retrieve(&name).map_err(|error| {
                HostError::Governance(format!(
                    "brokered credential `{}` for service `{}` is unavailable in the host secret store: {error}",
                    service.secret, service.id
                ))
            })?;
            masker.register(secret.value.expose_secret())?;
            values.insert(service.secret.clone(), secret.value);
        }
        Ok(Self { values })
    }
}

impl SecretResolver for BrokeredSecrets {
    fn retrieve(&self, name: &SecretName) -> Result<SecretValue, CredentialBrokerError> {
        let value = self.values.get(name.as_str()).ok_or_else(|| {
            CredentialBrokerError::InvalidConfiguration(
                "brokered credential was not resolved for this session".to_owned(),
            )
        })?;
        SecretValue::new(value.expose_secret().to_vec()).map_err(CredentialBrokerError::from)
    }
}

/// Authorizes relay requests against the session's grants. Identity comes
/// from the admitted binding, never from the workload request.
struct GrantAuthorizer {
    authority: Arc<dyn GrantAuthority>,
    grants: BTreeMap<String, GrantId>,
    context: RequestContext,
}

impl RelayAuthorizer for GrantAuthorizer {
    fn authorize<'a>(
        &'a self,
        service: &'a str,
        method: &'a str,
        path: &'a str,
    ) -> RelayFuture<'a, RelayAuthorization> {
        Box::pin(async move {
            let (Some(grant), Ok(service)) =
                (self.grants.get(service), ServiceId::new(service.to_owned()))
            else {
                return RelayAuthorization::Denied {
                    reason: "service_not_granted",
                };
            };
            let context = RequestContext {
                grant_id: grant.clone(),
                service,
                method: method.to_owned(),
                path: path.to_owned(),
                ..self.context.clone()
            };
            match self.authority.authorize(&context).await {
                Decision::Allow(allowed) => RelayAuthorization::Allowed {
                    grant: allowed.grant_id.to_string(),
                    generation: allowed.generation,
                },
                Decision::Deny { reason } => RelayAuthorization::Denied {
                    reason: reason.code(),
                },
            }
        })
    }
}

enum OutcomeMessage {
    Report(GrantId, RequestOutcomeReport),
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Sends stream outcomes to a shared governance service in order. A failed
/// report is recorded in the session audit; the local record stays
/// authoritative.
struct OutcomeReporter {
    sender: tokio::sync::mpsc::UnboundedSender<OutcomeMessage>,
    grants: BTreeMap<String, GrantId>,
    task: JoinHandle<()>,
}

impl OutcomeReporter {
    fn start(
        client: Arc<FleetClient>,
        grants: BTreeMap<String, GrantId>,
        audit: AuditRecorder,
        metadata: BTreeMap<String, String>,
        failed: Arc<AtomicBool>,
    ) -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Some(message) = receiver.recv().await {
                match message {
                    OutcomeMessage::Report(grant, report) => {
                        if let Err(error) = client.report_outcome(&grant, &report).await {
                            eprintln!(
                                "sendbox: reporting a credential request outcome to the governance service failed: {error}"
                            );
                            let mut metadata = metadata.clone();
                            metadata.extend([
                                ("grant".to_owned(), grant.to_string()),
                                ("outcome".to_owned(), report.outcome.code().to_owned()),
                                ("error".to_owned(), error.to_string()),
                            ]);
                            if record_audit(
                                &audit,
                                AuditCategory::Secret,
                                "credential.request.outcome_report_failed",
                                report.service.as_str(),
                                AuditResult::Error,
                                metadata,
                            )
                            .is_err()
                            {
                                failed.store(true, Ordering::SeqCst);
                            }
                        }
                    }
                    OutcomeMessage::Flush(done) => {
                        let _ = done.send(());
                    }
                }
            }
        });
        Self {
            sender,
            grants,
            task,
        }
    }

    fn report(&self, report: RequestOutcomeReport) {
        let Some(grant) = self.grants.get(report.service.as_str()) else {
            return;
        };
        if self
            .sender
            .send(OutcomeMessage::Report(grant.clone(), report))
            .is_err()
        {
            eprintln!("sendbox: the outcome reporter stopped before the session ended");
        }
    }

    /// Waits until every queued report was attempted, then stops the task.
    async fn finish(&self) -> bool {
        let (done, wait) = tokio::sync::oneshot::channel();
        let flushed = self.sender.send(OutcomeMessage::Flush(done)).is_ok()
            && tokio::time::timeout(OUTCOME_FLUSH_TIMEOUT, wait)
                .await
                .is_ok_and(|result| result.is_ok());
        self.task.abort();
        flushed
    }
}

/// Maps a relay stream outcome to the central audit vocabulary.
fn reported_outcome(outcome: RelayStreamOutcome) -> ReportedOutcome {
    match outcome {
        RelayStreamOutcome::Complete => ReportedOutcome::Succeeded,
        RelayStreamOutcome::AbortedUncertain => ReportedOutcome::Unknown,
        RelayStreamOutcome::Denied | RelayStreamOutcome::Failed | RelayStreamOutcome::Aborted => {
            ReportedOutcome::Failed
        }
    }
}

/// Writes relay evidence into the signed session audit chain and, with a
/// shared governance service, reports stream outcomes to it.
struct RelayAudit {
    audit: AuditRecorder,
    metadata: BTreeMap<String, String>,
    failed: Arc<AtomicBool>,
    reporter: Option<Arc<OutcomeReporter>>,
}

impl RelayAuditSink for RelayAudit {
    fn record(&self, event: RelayAuditEvent) {
        let mut metadata = self.metadata.clone();
        let (action, result, subject) = match event {
            RelayAuditEvent::Decision {
                stream,
                service,
                method,
                path,
                allowed,
                reason,
                grant,
                generation,
            } => {
                metadata.extend([
                    ("stream".to_owned(), stream.to_string()),
                    ("service".to_owned(), service.clone()),
                    ("method".to_owned(), method),
                    ("target_path".to_owned(), path),
                    ("reason".to_owned(), reason.to_owned()),
                ]);
                if let Some(grant) = grant {
                    metadata.insert("grant".to_owned(), grant);
                }
                if let Some(generation) = generation {
                    metadata.insert("grant_generation".to_owned(), generation.to_string());
                }
                if allowed {
                    ("credential.request.allowed", AuditResult::Allowed, service)
                } else {
                    ("credential.request.denied", AuditResult::Denied, service)
                }
            }
            RelayAuditEvent::Outcome {
                stream,
                service,
                method,
                path,
                outcome,
                reason,
                status,
                request_bytes,
                response_bytes,
                duration_ms,
            } => {
                if let (Some(reporter), Ok(service_id)) =
                    (&self.reporter, ServiceId::new(service.clone()))
                {
                    let report = RequestOutcomeReport {
                        service: service_id,
                        method: method.clone(),
                        path: path.clone(),
                        outcome: reported_outcome(outcome),
                        reason: reason.to_owned(),
                        status,
                        request_bytes,
                        response_bytes,
                        duration_ms,
                    };
                    if report.validate().is_ok() {
                        reporter.report(report);
                    }
                }
                metadata.extend([
                    ("stream".to_owned(), stream.to_string()),
                    ("service".to_owned(), service.clone()),
                    ("method".to_owned(), method),
                    ("target_path".to_owned(), path),
                    ("outcome".to_owned(), outcome.code().to_owned()),
                    ("reason".to_owned(), reason.to_owned()),
                    ("request_bytes".to_owned(), request_bytes.to_string()),
                    ("response_bytes".to_owned(), response_bytes.to_string()),
                    ("duration_ms".to_owned(), duration_ms.to_string()),
                ]);
                if let Some(status) = status {
                    metadata.insert("upstream_status".to_owned(), status.to_string());
                }
                let result = match outcome {
                    RelayStreamOutcome::Complete => AuditResult::Success,
                    RelayStreamOutcome::Denied => AuditResult::Denied,
                    _ => AuditResult::Error,
                };
                ("credential.request.outcome", result, service)
            }
        };
        if let Err(error) = record_audit(
            &self.audit,
            AuditCategory::Secret,
            action,
            &subject,
            result,
            metadata,
        ) {
            self.failed.store(true, Ordering::SeqCst);
            eprintln!("sendbox: recording credential relay audit failed: {error}");
        }
    }
}

struct OutboundAdapter(Arc<dyn CredentialRelayOutbound>);

impl RelayOutbound for OutboundAdapter {
    fn send(&self, event: Event) -> RelayFuture<'_, Result<(), CredentialBrokerError>> {
        Box::pin(async move {
            self.0
                .send(event)
                .await
                .map_err(|error| CredentialBrokerError::Upstream(error.to_string()))
        })
    }
}

/// The host credential relay for one governed session.
pub(crate) struct HostCredentialRelay {
    endpoint: Arc<RelayEndpoint>,
    authority: Arc<dyn GrantAuthority>,
    grants: Vec<CredentialGrant>,
    audit: AuditRecorder,
    metadata: BTreeMap<String, String>,
    audit_failed: Arc<AtomicBool>,
    renewal: Mutex<Option<JoinHandle<()>>>,
    lease: Duration,
    revocation_grace: Duration,
    finished: AtomicBool,
    reporter: Option<Arc<OutcomeReporter>>,
}

impl HostCredentialRelay {
    pub(crate) async fn start(
        run: &GovernedRun,
        services: &[CredentialServiceProfile],
        secrets: BrokeredSecrets,
        audit: AuditRecorder,
    ) -> Result<Self, HostError> {
        let limits = &run.session.verified.profile.grants;
        let authority = run.authority(|| {
            Arc::new(LocalGrantAuthority::new(
                Arc::new(OperatorRevisionSource::new(
                    run.session.source.clone(),
                    Arc::new(SystemClock),
                )),
                Arc::new(SystemClock),
                LocalAuthorityLimits {
                    lease_seconds: limits.lease_seconds,
                    max_grants: services.len(),
                },
                Box::new(|| {
                    let mut bytes = [0_u8; 16];
                    getrandom::fill(&mut bytes).map_err(|error| {
                        sendbox_governance::GovernanceError::AuthorityUnavailable(error.to_string())
                    })?;
                    Ok(bytes)
                }),
            ))
        });
        let metadata = run.audit_metadata();
        let mut grants = Vec::with_capacity(services.len());
        let mut grant_ids = BTreeMap::new();
        for service in services {
            let grant = authority
                .issue(GrantRequest {
                    principal: run.binding.principal.clone(),
                    project: run.binding.project.clone(),
                    session: run.session_ref.clone(),
                    binding: run.binding.clone(),
                    service: service.id.clone(),
                    methods: service.effective_methods(),
                    path_prefixes: service.effective_path_prefixes(),
                    max_ttl_seconds: limits.max_ttl_seconds,
                })
                .await
                .map_err(|error| {
                    HostError::Governance(format!(
                        "issue credential grant for `{}`: {error}",
                        service.id
                    ))
                })?;
            let mut grant_metadata = metadata.clone();
            grant_metadata.extend([
                ("service".to_owned(), service.id.to_string()),
                ("grant".to_owned(), grant.grant_id.to_string()),
                ("grant_generation".to_owned(), grant.generation.to_string()),
                (
                    "lease_expires_at_unix".to_owned(),
                    grant.lease_expires_at_unix.to_string(),
                ),
                (
                    "max_expires_at_unix".to_owned(),
                    grant.max_expires_at_unix.to_string(),
                ),
                (
                    "methods".to_owned(),
                    grant.methods.iter().cloned().collect::<Vec<_>>().join(","),
                ),
                ("path_prefixes".to_owned(), grant.path_prefixes.join(",")),
            ]);
            record_audit(
                &audit,
                AuditCategory::Secret,
                "credential.grant.issued",
                service.id.as_str(),
                AuditResult::Allowed,
                grant_metadata,
            )?;
            grant_ids.insert(service.id.to_string(), grant.grant_id.clone());
            grants.push(grant);
        }
        let relay_services = services
            .iter()
            .map(RelayService::from_profile)
            .collect::<Result<Vec<_>, _>>()?;
        let audit_failed = Arc::new(AtomicBool::new(false));
        let reporter = run.session.fleet.as_ref().map(|client| {
            Arc::new(OutcomeReporter::start(
                Arc::clone(client),
                grant_ids.clone(),
                audit.clone(),
                metadata.clone(),
                Arc::clone(&audit_failed),
            ))
        });
        let endpoint = RelayEndpoint::new(
            relay_services,
            Arc::new(GrantAuthorizer {
                authority: Arc::clone(&authority),
                grants: grant_ids,
                context: RequestContext {
                    grant_id: grants
                        .first()
                        .map(|grant| grant.grant_id.clone())
                        .ok_or_else(|| {
                            HostError::Governance("no brokered service was granted".to_owned())
                        })?,
                    principal: run.binding.principal.clone(),
                    project: run.binding.project.clone(),
                    session: run.session_ref.clone(),
                    binding_sha256: run.binding_sha256,
                    service: grants[0].service.clone(),
                    method: String::new(),
                    path: String::new(),
                },
            }),
            Arc::new(secrets),
            Arc::new(PinnedHttpsTransport::default()),
            Arc::new(RelayAudit {
                audit: audit.clone(),
                metadata: metadata.clone(),
                failed: Arc::clone(&audit_failed),
                reporter: reporter.clone(),
            }),
            RelayLimits {
                max_streams: usize::try_from(limits.max_concurrent_streams).unwrap_or(1),
                ..RelayLimits::default()
            },
        )?;
        Ok(Self {
            endpoint: Arc::new(endpoint),
            authority,
            grants,
            audit,
            metadata,
            audit_failed,
            renewal: Mutex::new(None),
            lease: Duration::from_secs(limits.lease_seconds),
            revocation_grace: Duration::from_secs(limits.revocation_grace_seconds),
            finished: AtomicBool::new(false),
            reporter,
        })
    }

    fn start_renewal(&self) {
        let authority = Arc::clone(&self.authority);
        let endpoint = Arc::clone(&self.endpoint);
        let audit = self.audit.clone();
        let metadata = self.metadata.clone();
        let grants = self
            .grants
            .iter()
            .map(|grant| (grant.grant_id.clone(), grant.service.to_string()))
            .collect::<Vec<_>>();
        let interval = (self.lease / 3).max(Duration::from_secs(10));
        let grace = self.revocation_grace;
        let audit_failed = Arc::clone(&self.audit_failed);
        let task = tokio::spawn(async move {
            let mut live = grants;
            while !live.is_empty() {
                tokio::time::sleep(interval).await;
                let mut lapsed = Vec::new();
                let mut remaining = Vec::with_capacity(live.len());
                for (grant, service) in live {
                    match authority.renew(&grant).await {
                        Ok(_) => remaining.push((grant, service)),
                        Err(error) => {
                            let mut metadata = metadata.clone();
                            metadata.extend([
                                ("service".to_owned(), service.clone()),
                                ("grant".to_owned(), grant.to_string()),
                                ("reason".to_owned(), error.to_string()),
                                (
                                    "in_flight_grace_seconds".to_owned(),
                                    grace.as_secs().to_string(),
                                ),
                            ]);
                            if let Err(error) = record_audit(
                                &audit,
                                AuditCategory::Secret,
                                "credential.grant.lapsed",
                                &service,
                                AuditResult::Denied,
                                metadata,
                            ) {
                                audit_failed.store(true, Ordering::SeqCst);
                                eprintln!(
                                    "sendbox: recording credential grant lapse failed: {error}"
                                );
                            }
                            lapsed.push(service);
                        }
                    }
                }
                if !lapsed.is_empty() {
                    let services = lapsed.iter().map(String::as_str).collect::<Vec<_>>();
                    endpoint.expire_in_flight(&services, grace);
                }
                live = remaining;
            }
        });
        *self
            .renewal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    }

    fn stop_renewal(&self) {
        if let Some(task) = self
            .renewal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }

    /// Ends the session's grants after the workload finished and reports
    /// whether audit evidence could not be recorded.
    pub(crate) async fn finish(&self, reason: RevocationReason) -> Result<(), HostError> {
        if self.finished.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.stop_renewal();
        self.endpoint.close(Duration::ZERO).await;
        if let Some(reporter) = &self.reporter
            && !reporter.finish().await
        {
            eprintln!(
                "sendbox: some credential request outcomes were not reported to the governance service; the session audit keeps them"
            );
        }
        let mut failures = Vec::new();
        for grant in &self.grants {
            let mut metadata = self.metadata.clone();
            metadata.extend([
                ("service".to_owned(), grant.service.to_string()),
                ("grant".to_owned(), grant.grant_id.to_string()),
                ("reason".to_owned(), reason.code().to_owned()),
            ]);
            let revoked = self.authority.revoke(&grant.grant_id, reason).await;
            if let Err(error) = &revoked {
                failures.push(format!("revoke grant {}: {error}", grant.grant_id));
            }
            if let Err(error) = record_audit(
                &self.audit,
                AuditCategory::Secret,
                "credential.grant.revoked",
                grant.service.as_str(),
                if revoked.is_ok() {
                    AuditResult::Success
                } else {
                    AuditResult::Error
                },
                metadata,
            ) {
                failures.push(error.to_string());
            }
        }
        if self.audit_failed.load(Ordering::SeqCst) {
            failures.push("credential relay audit evidence could not be recorded".to_owned());
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(HostError::Governance(failures.join("; ")))
        }
    }
}

impl CredentialRelayHandler for HostCredentialRelay {
    fn attach(&self, outbound: Arc<dyn CredentialRelayOutbound>) {
        self.endpoint.attach(Arc::new(OutboundAdapter(outbound)));
        self.start_renewal();
    }

    fn handle(&self, event: Event) -> Result<(), AgentError> {
        self.endpoint
            .handle(event)
            .map_err(|error| AgentError::Guest(error.to_string()))
    }

    fn close(&self, grace: Duration) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.stop_renewal();
            self.endpoint.close(grace).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use sendbox_core::SessionId;
    use sendbox_secrets::{CredentialMasker, SecretValue};

    use super::super::operator::tests::{fixture, protected_test_tree};
    use super::super::tests::{FakeStore, admitted_run, brokered_profile, configuration};
    use super::*;

    const ANTHROPIC_KEY: &str = "sk-ant-test-0123456789";
    const OPENAI_KEY: &str = "sk-openai-test-0123456789";

    fn store() -> FakeStore {
        FakeStore(BTreeMap::from([
            ("SENDBOX_ANTHROPIC_API_KEY", ANTHROPIC_KEY),
            ("SENDBOX_OPENAI_API_KEY", OPENAI_KEY),
        ]))
    }

    fn services() -> Vec<CredentialServiceProfile> {
        sendbox_governance::profile::GovernanceProfile::parse(brokered_profile().as_bytes())
            .expect("profile")
            .credential_services
    }

    #[test]
    fn brokered_secrets_are_masked_and_missing_secrets_fail_closed() {
        let masker = CredentialMasker::default();
        let secrets = BrokeredSecrets::resolve(&services(), &store(), &masker).expect("resolve");
        assert!(!format!("{secrets:?}").contains(ANTHROPIC_KEY));
        let masked = masker
            .mask_complete(format!("leak {OPENAI_KEY}").as_bytes())
            .expect("mask");
        assert!(!String::from_utf8_lossy(&masked).contains(OPENAI_KEY));
        let resolved = SecretResolver::retrieve(
            &secrets,
            &SecretName::new("SENDBOX_ANTHROPIC_API_KEY".to_owned()).expect("name"),
        )
        .expect("resolved");
        assert_eq!(resolved.expose_secret(), ANTHROPIC_KEY.as_bytes());
        assert!(
            SecretResolver::retrieve(
                &secrets,
                &SecretName::new("SENDBOX_OTHER".to_owned()).expect("name")
            )
            .is_err()
        );

        let partial = FakeStore(BTreeMap::from([("SENDBOX_OPENAI_API_KEY", OPENAI_KEY)]));
        let error =
            BrokeredSecrets::resolve(&services(), &partial, &masker).expect_err("missing secret");
        assert!(error.to_string().contains("SENDBOX_ANTHROPIC_API_KEY"));
    }

    #[tokio::test]
    async fn relay_issues_and_revokes_audited_grants_without_secret_material() {
        if !protected_test_tree() {
            return;
        }
        let fixture = fixture(&brokered_profile(), 1);
        let mut configuration = configuration(&["anthropic", "openai"]);
        let run = admitted_run(&fixture, &mut configuration).await;
        let services = run
            .session
            .brokered_services(&configuration)
            .expect("services");
        let secrets = BrokeredSecrets::resolve(&services, &store(), &CredentialMasker::default())
            .expect("secrets");
        let audit = AuditRecorder::new(SessionId::from_bytes([7; 16])).expect("audit");
        let relay = HostCredentialRelay::start(&run, &services, secrets, audit.clone())
            .await
            .expect("relay");
        relay
            .finish(RevocationReason::SessionCompleted)
            .await
            .expect("finish");
        relay
            .finish(RevocationReason::SessionFailed)
            .await
            .expect("finish is idempotent");

        let records = audit.records().expect("records");
        let actions = records
            .iter()
            .map(|record| (record.event.action.as_str(), record.event.result))
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            [
                ("credential.grant.issued", AuditResult::Allowed),
                ("credential.grant.issued", AuditResult::Allowed),
                ("credential.grant.revoked", AuditResult::Success),
                ("credential.grant.revoked", AuditResult::Success),
            ]
        );
        for record in &records {
            assert_eq!(
                record.event.metadata["binding_sha256"],
                run.binding_sha256.to_string()
            );
            let serialized = serde_json::to_string(&record.event).expect("json");
            assert!(!serialized.contains(ANTHROPIC_KEY) && !serialized.contains(OPENAI_KEY));
        }
        assert_eq!(records[2].event.metadata["reason"], "session_completed");
    }

    #[test]
    fn stream_outcomes_map_to_the_central_vocabulary() {
        assert_eq!(
            reported_outcome(RelayStreamOutcome::Complete),
            ReportedOutcome::Succeeded
        );
        assert_eq!(
            reported_outcome(RelayStreamOutcome::AbortedUncertain),
            ReportedOutcome::Unknown
        );
        for failed in [
            RelayStreamOutcome::Denied,
            RelayStreamOutcome::Failed,
            RelayStreamOutcome::Aborted,
        ] {
            assert_eq!(reported_outcome(failed), ReportedOutcome::Failed);
        }
    }

    #[tokio::test]
    async fn outcomes_are_reported_in_order_and_failed_reports_are_audited() {
        use super::super::fleet::tests::{Handler, Recorded, TOKEN, serve, settings};
        let handler: Arc<Handler> = Arc::new(|request: &Recorded| {
            if String::from_utf8_lossy(&request.body).contains("/v1/fail") {
                (503, r#"{"detail":"unavailable"}"#.to_owned())
            } else {
                (204, String::new())
            }
        });
        let (address, recorded) = serve(handler).await;
        let client = Arc::new(
            FleetClient::new(&settings(address), &SecretValue::try_from(TOKEN).unwrap())
                .expect("client"),
        );
        let audit = AuditRecorder::new(SessionId::from_bytes([7; 16])).expect("audit");
        let grant = GrantId::from_bytes([3; 16]);
        let failed = Arc::new(AtomicBool::new(false));
        let reporter = OutcomeReporter::start(
            client,
            BTreeMap::from([("anthropic".to_owned(), grant.clone())]),
            audit.clone(),
            BTreeMap::from([("session".to_owned(), "s".to_owned())]),
            Arc::clone(&failed),
        );
        let report = |path: &str, outcome| RequestOutcomeReport {
            service: ServiceId::new("anthropic").unwrap(),
            method: "POST".to_owned(),
            path: path.to_owned(),
            outcome,
            reason: "complete".to_owned(),
            status: Some(200),
            request_bytes: 1,
            response_bytes: 2,
            duration_ms: 3,
        };
        reporter.report(report("/v1/messages", ReportedOutcome::Succeeded));
        reporter.report(report("/v1/fail", ReportedOutcome::Unknown));
        let mut unknown_service = report("/v1/messages", ReportedOutcome::Failed);
        unknown_service.service = ServiceId::new("openai").unwrap();
        reporter.report(unknown_service);
        assert!(reporter.finish().await);

        let requests = recorded.lock().unwrap().clone();
        assert_eq!(requests.len(), 2, "only granted services are reported");
        assert!(
            requests
                .iter()
                .all(|request| request.target == format!("/v1/grants/{grant}:outcome"))
        );
        let first: RequestOutcomeReport = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(first.path, "/v1/messages");
        let records = audit.records().expect("records");
        let failure = &records.last().expect("failure record").event;
        assert_eq!(failure.action, "credential.request.outcome_report_failed");
        assert_eq!(failure.metadata["outcome"], "unknown");
        assert!(failure.metadata["error"].contains("503"));
        assert!(!failed.load(Ordering::SeqCst));
    }
}
