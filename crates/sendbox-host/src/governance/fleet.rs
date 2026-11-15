//! Client for a shared governance service (`sendbox-fleet`).
//!
//! The service authenticates the caller with a bearer token from the host
//! secret store, enforces project roles and exceptions at admission, and acts
//! as the grant authority. Every failure is explicit: an unreachable or
//! refusing service denies admission and brokered requests, and never falls
//! back to the local authority or to credential delivery.

use std::time::Duration;

use reqwest::{Method, StatusCode, Url, header};
use sendbox_governance::api::{
    CallerIdentity, ExceptionList, RevokeGrantRequest, SessionAdmission, SessionAdmissionRequest,
    SessionEnd, SessionOutcome,
};
use sendbox_governance::{
    AuthorityFuture, CredentialGrant, Decision, DenyReason, GovernanceBinding, GovernanceError,
    GrantAuthority, GrantId, GrantRequest, PolicyException, ProjectId, RequestContext,
    RevocationReason, SessionRef,
};
use sendbox_secrets::SecretValue;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::operator::FleetSettings;
use crate::HostError;

const MAX_DETAIL_CHARS: usize = 300;

/// Why a fleet call failed. `detail` never contains the bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FleetError {
    pub(crate) status: Option<u16>,
    pub(crate) detail: String,
}

impl std::fmt::Display for FleetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(status) => write!(formatter, "HTTP {status}: {}", self.detail),
            None => formatter.write_str(&self.detail),
        }
    }
}

impl From<FleetError> for HostError {
    fn from(error: FleetError) -> Self {
        Self::Governance(format!("governance service: {error}"))
    }
}

impl From<FleetError> for GovernanceError {
    fn from(error: FleetError) -> Self {
        Self::AuthorityUnavailable(error.to_string())
    }
}

pub(crate) struct FleetClient {
    client: reqwest::Client,
    base: Url,
    token: Zeroizing<String>,
}

impl std::fmt::Debug for FleetClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FleetClient")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl FleetClient {
    pub(crate) fn new(settings: &FleetSettings, token: &SecretValue) -> Result<Self, HostError> {
        let base = settings.base_url()?;
        let token = Zeroizing::new(
            std::str::from_utf8(token.expose_secret())
                .map_err(|_| {
                    HostError::Governance(format!(
                        "fleet token `{}` is not UTF-8",
                        settings.token_secret
                    ))
                })?
                .trim()
                .to_owned(),
        );
        let valid_token = !token.is_empty()
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte));
        if !valid_token {
            return Err(HostError::Governance(format!(
                "fleet token `{}` is not a bearer token",
                settings.token_secret
            )));
        }
        let client = reqwest::Client::builder()
            .https_only(base.scheme() == "https")
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(settings.timeout_seconds))
            .build()
            .map_err(|error| HostError::Governance(format!("build fleet client: {error}")))?;
        Ok(Self {
            client,
            base,
            token,
        })
    }

    fn url(&self, path: &str) -> Url {
        let mut url = self.base.clone();
        let prefix = self.base.path().trim_end_matches('/');
        url.set_path(&format!("{prefix}{path}"));
        url
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&(dyn erased::Body + Sync)>,
    ) -> Result<Option<T>, FleetError> {
        let mut url = self.url(path);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let mut bearer = header::HeaderValue::from_str(&format!("Bearer {}", *self.token))
            .map_err(|_| FleetError {
                status: None,
                detail: "fleet token cannot be sent as a header".to_owned(),
            })?;
        bearer.set_sensitive(true);
        let mut request = self
            .client
            .request(method, url)
            .header(header::AUTHORIZATION, bearer)
            .header(header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.to_json().map_err(|error| FleetError {
                    status: None,
                    detail: format!("encode request: {error}"),
                })?);
        }
        let response = request.send().await.map_err(|error| FleetError {
            status: None,
            detail: format!(
                "request failed: {}",
                error
                    .without_url()
                    .to_string()
                    .replace(self.token.as_str(), "***")
            ),
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|error| FleetError {
            status: Some(status.as_u16()),
            detail: format!("read response: {}", error.without_url()),
        })?;
        if !status.is_success() {
            return Err(FleetError {
                status: Some(status.as_u16()),
                detail: problem_detail(status, &bytes),
            });
        }
        if status == StatusCode::NO_CONTENT || bytes.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| FleetError {
                status: Some(status.as_u16()),
                detail: format!("unexpected response body: {error}"),
            })
    }

    async fn call_required<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&(dyn erased::Body + Sync)>,
    ) -> Result<T, FleetError> {
        self.call(method, path, query, body)
            .await?
            .ok_or_else(|| FleetError {
                status: None,
                detail: "the service returned an empty response".to_owned(),
            })
    }

    pub(crate) async fn whoami(&self) -> Result<CallerIdentity, FleetError> {
        self.call_required(Method::GET, "/v1/whoami", &[], None)
            .await
    }

    /// Approved exceptions currently active for `project`.
    pub(crate) async fn active_exceptions(
        &self,
        project: &ProjectId,
    ) -> Result<Vec<PolicyException>, FleetError> {
        let list: ExceptionList = self
            .call_required(
                Method::GET,
                "/v1/exceptions",
                &[("project", project.as_str()), ("state", "active")],
                None,
            )
            .await?;
        Ok(list.exceptions)
    }

    pub(crate) async fn admit(
        &self,
        session: &SessionRef,
        binding: &GovernanceBinding,
    ) -> Result<SessionAdmission, FleetError> {
        let admission: SessionAdmission = self
            .call_required(
                Method::POST,
                "/v1/sessions:admit",
                &[],
                Some(&SessionAdmissionRequest {
                    session: session.clone(),
                    binding: binding.clone(),
                }),
            )
            .await?;
        let expected = binding.digest().map_err(|error| FleetError {
            status: None,
            detail: error.to_string(),
        })?;
        if &admission.session != session || admission.binding_sha256 != expected {
            return Err(FleetError {
                status: None,
                detail: "the service admitted a different session or binding".to_owned(),
            });
        }
        Ok(admission)
    }

    pub(crate) async fn end(
        &self,
        session: &SessionRef,
        outcome: SessionOutcome,
    ) -> Result<(), FleetError> {
        self.call::<serde_json::Value>(
            Method::POST,
            &format!("/v1/sessions/{session}:end"),
            &[],
            Some(&SessionEnd { outcome }),
        )
        .await
        .map(drop)
    }
}

/// The shared service as the session's grant authority.
pub(crate) struct FleetGrantAuthority {
    client: std::sync::Arc<FleetClient>,
}

impl FleetGrantAuthority {
    pub(crate) const fn new(client: std::sync::Arc<FleetClient>) -> Self {
        Self { client }
    }
}

impl GrantAuthority for FleetGrantAuthority {
    fn issue<'a>(
        &'a self,
        request: GrantRequest,
    ) -> AuthorityFuture<'a, Result<CredentialGrant, GovernanceError>> {
        Box::pin(async move {
            let grant: CredentialGrant = self
                .client
                .call_required(Method::POST, "/v1/grants", &[], Some(&request))
                .await?;
            grant.validate()?;
            let matches = grant.principal == request.principal
                && grant.project == request.project
                && grant.session == request.session
                && grant.service == request.service
                && grant.binding_sha256 == request.binding.digest()?
                && grant.profile == request.binding.profile
                && grant.methods.is_subset(&request.methods)
                && grant
                    .path_prefixes
                    .iter()
                    .all(|prefix| request.path_prefixes.contains(prefix));
            if matches {
                Ok(grant)
            } else {
                Err(GovernanceError::InvalidGrant(
                    "the service issued a grant outside the request".to_owned(),
                ))
            }
        })
    }

    fn authorize<'a>(&'a self, context: &'a RequestContext) -> AuthorityFuture<'a, Decision> {
        Box::pin(async move {
            match self
                .client
                .call_required::<Decision>(Method::POST, "/v1/authorize", &[], Some(context))
                .await
            {
                Ok(Decision::Allow(allowed)) if allowed.grant_id != context.grant_id => {
                    Decision::Deny {
                        reason: DenyReason::AuthorityUnavailable,
                    }
                }
                Ok(decision) => decision,
                Err(_) => Decision::Deny {
                    reason: DenyReason::AuthorityUnavailable,
                },
            }
        })
    }

    fn renew<'a>(
        &'a self,
        grant: &'a GrantId,
    ) -> AuthorityFuture<'a, Result<CredentialGrant, GovernanceError>> {
        Box::pin(async move {
            let renewed: CredentialGrant = self
                .client
                .call_required(
                    Method::POST,
                    &format!("/v1/grants/{grant}:renew"),
                    &[],
                    None,
                )
                .await?;
            renewed.validate()?;
            if &renewed.grant_id == grant {
                Ok(renewed)
            } else {
                Err(GovernanceError::InvalidGrant(
                    "the service renewed a different grant".to_owned(),
                ))
            }
        })
    }

    fn revoke<'a>(
        &'a self,
        grant: &'a GrantId,
        reason: RevocationReason,
    ) -> AuthorityFuture<'a, Result<(), GovernanceError>> {
        Box::pin(async move {
            self.client
                .call::<serde_json::Value>(
                    Method::POST,
                    &format!("/v1/grants/{grant}:revoke"),
                    &[],
                    Some(&RevokeGrantRequest { reason }),
                )
                .await?;
            Ok(())
        })
    }
}

/// Extracts a bounded, printable `detail` from an RFC 9457 problem body.
fn problem_detail(status: StatusCode, bytes: &[u8]) -> String {
    let detail = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| value.get("detail")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("request refused")
                .to_owned()
        });
    detail
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_DETAIL_CHARS)
        .collect()
}

/// Object-safe JSON bodies so one request path serves every payload type.
mod erased {
    pub(super) trait Body {
        fn to_json(&self) -> Result<Vec<u8>, serde_json::Error>;
    }

    impl<T: super::Serialize> Body for T {
        fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use sendbox_governance::api::{CallerKind, SessionOutcome};
    use sendbox_governance::{
        ExceptionId, ExceptionKind, ExceptionScope, ExceptionStatus, PrincipalId, ProfileRef,
        ServiceId, Sha256Digest,
    };
    use sendbox_secrets::SecretStore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::operator::tests::{Fixture, fixture, protected_test_tree, write_private};
    use super::super::operator::{DEFAULT_FLEET_TOKEN_SECRET, FleetSettings};
    use super::super::tests::{
        FakeStore, brokered_profile, configuration, no_secret_store, prepare, run_for,
    };
    use super::*;

    const TOKEN: &str = "sbf_synthetic-test-token";
    const ALICE: &str = "oidc:alice@example.com";

    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        target: String,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    type Handler = dyn Fn(&Recorded) -> (u16, String) + Send + Sync;

    /// A loopback HTTP/1.1 stand-in for the governance service.
    async fn serve(handler: Arc<Handler>) -> (SocketAddr, Arc<Mutex<Vec<Recorded>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&recorded);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let handler = Arc::clone(&handler);
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    let header_end = loop {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        buffer.extend_from_slice(&chunk[..read]);
                        if let Some(position) =
                            buffer.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            break position + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
                    let mut lines = head.split("\r\n");
                    let mut request_line = lines.next().unwrap_or_default().split(' ');
                    let method = request_line.next().unwrap_or_default().to_owned();
                    let target = request_line.next().unwrap_or_default().to_owned();
                    let headers = lines
                        .filter_map(|line| line.split_once(':'))
                        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                        .collect::<BTreeMap<_, _>>();
                    let length = headers
                        .get("content-length")
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut body = buffer[header_end..].to_vec();
                    while body.len() < length {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        body.extend_from_slice(&chunk[..read]);
                    }
                    let request = Recorded {
                        method,
                        target,
                        authorization: headers.get("authorization").cloned(),
                        body,
                    };
                    let (status, payload) = handler(&request);
                    log.lock().unwrap().push(request);
                    let content_type = if status >= 400 {
                        "application/problem+json"
                    } else {
                        "application/json"
                    };
                    let location = if status == 307 {
                        "Location: http://127.0.0.1:9/elsewhere\r\n"
                    } else {
                        ""
                    };
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (address, recorded)
    }

    fn fleet_profile() -> String {
        format!(
            "{}denials:\n  domains: [gist.github.com, pastebin.com]\nexceptions:\n  max_ttl_seconds: 3600\n  domains: [gist.github.com]\n",
            brokered_profile()
        )
    }

    fn use_fleet(fixture: &Fixture, address: SocketAddr) {
        let mut operator = fixture.source.load().expect("operator");
        operator.authority = "fleet.example.com".to_owned();
        operator.fleet = Some(FleetSettings {
            url: format!("http://{address}"),
            token_secret: DEFAULT_FLEET_TOKEN_SECRET.to_owned(),
            timeout_seconds: 5,
        });
        write_private(
            &fixture.source.path,
            serde_yaml_ng::to_string(&operator).unwrap().as_bytes(),
        );
    }

    fn token_store() -> Result<Arc<dyn SecretStore>, HostError> {
        Ok(Arc::new(FakeStore(BTreeMap::from([(
            DEFAULT_FLEET_TOKEN_SECRET,
            TOKEN,
        )]))))
    }

    fn exception(
        byte: u8,
        principal: Option<&str>,
        profile: &ProfileRef,
        value: &str,
        expires_at_unix: u64,
    ) -> PolicyException {
        PolicyException {
            id: ExceptionId::from_bytes([byte; 16]),
            project: ProjectId::github("acme", "app").unwrap(),
            principal: principal.map(|principal| PrincipalId::new(principal).unwrap()),
            profile: profile.clone(),
            scope: ExceptionScope {
                kind: ExceptionKind::Domain,
                value: value.to_owned(),
            },
            reason: "synthetic".to_owned(),
            status: ExceptionStatus::Approved,
            requested_by: PrincipalId::new(ALICE).unwrap(),
            requested_at_unix: 1,
            decided_by: Some(PrincipalId::new("oidc:bob@example.com").unwrap()),
            decided_at_unix: Some(2),
            expires_at_unix,
            revoked_by: None,
            revoked_at_unix: None,
        }
    }

    fn json(value: &impl Serialize) -> String {
        serde_json::to_string(value).unwrap()
    }

    #[tokio::test]
    async fn fleet_mode_authenticates_the_caller_and_lifts_only_applicable_exceptions() {
        if !protected_test_tree() {
            return;
        }
        let profile_text = fleet_profile();
        let profile =
            sendbox_governance::profile::GovernanceProfile::parse(profile_text.as_bytes())
                .unwrap()
                .reference(profile_text.as_bytes());
        let mut stale = profile.clone();
        stale.revision -= 1;
        let later = super::super::tests::now_unix() + 3_000;
        let exceptions = vec![
            exception(1, Some(ALICE), &profile, "gist.github.com", later - 100),
            exception(2, None, &profile, "gist.github.com", later),
            exception(
                3,
                Some("oidc:bob@example.com"),
                &profile,
                "pastebin.com",
                later,
            ),
            exception(4, None, &profile, "pastebin.com", later),
            exception(5, None, &stale, "gist.github.com", later + 100),
        ];
        let handler: Arc<Handler> = Arc::new(move |request: &Recorded| {
            match (request.method.as_str(), request.target.as_str()) {
                ("GET", "/v1/whoami") => (
                    200,
                    json(&CallerIdentity {
                        principal: PrincipalId::new(ALICE).unwrap(),
                        kind: CallerKind::User,
                        operator: false,
                    }),
                ),
                ("GET", "/v1/exceptions?project=github%3Aacme%2Fapp&state=active") => (
                    200,
                    json(&ExceptionList {
                        exceptions: exceptions.clone(),
                    }),
                ),
                ("POST", "/v1/sessions:admit") => {
                    let admission: SessionAdmissionRequest =
                        serde_json::from_slice(&request.body).unwrap();
                    (
                        200,
                        json(&SessionAdmission {
                            binding_sha256: admission.binding.digest().unwrap(),
                            session: admission.session,
                            admitted_at_unix: 10,
                        }),
                    )
                }
                ("POST", target) if target.ends_with(":end") => (204, String::new()),
                _ => (404, r#"{"detail":"no route"}"#.to_owned()),
            }
        });
        let (address, recorded) = serve(handler).await;
        let fixture = fixture(&profile_text, 1);
        use_fleet(&fixture, address);
        let mut configuration = configuration(&["anthropic"]);
        configuration
            .policy
            .network
            .allowed_domains
            .push("gist.github.com".to_owned());

        let session = prepare(&fixture, &mut configuration, &token_store)
            .await
            .expect("prepare");
        assert_eq!(session.principal.as_str(), ALICE);
        let ids = session
            .exceptions
            .iter()
            .map(|exception| exception.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(ids, [ExceptionId::from_bytes([2; 16])]);
        let blocked = &configuration.policy.network.blocked_domains;
        assert!(!blocked.contains(&"gist.github.com".to_owned()));
        assert!(blocked.contains(&"pastebin.com".to_owned()));
        assert!(blocked.contains(&"api.anthropic.com".to_owned()));
        assert_eq!(
            session.exception_deadline().map(|e| e.expires_at_unix),
            Some(later)
        );

        let run = run_for(session, &configuration);
        assert_eq!(run.binding.principal.as_str(), ALICE);
        assert_eq!(run.binding.exceptions, ids);
        assert_eq!(run.binding.authority.id, "fleet.example.com");
        run.admit_remote().await.expect("admitted");
        run.end_remote(SessionOutcome::Completed)
            .await
            .expect("ended");

        let requests = recorded.lock().unwrap().clone();
        assert_eq!(requests.len(), 4);
        assert!(
            requests
                .iter()
                .all(|request| request.authorization.as_deref() == Some(&format!("Bearer {TOKEN}")))
        );
        let admitted: SessionAdmissionRequest =
            serde_json::from_slice(&requests[2].body).expect("admission body");
        assert_eq!(admitted.binding, run.binding);
        assert_eq!(admitted.session, run.session_ref);
        assert_eq!(
            requests[3].body, br#"{"outcome":"completed"}"#,
            "{}",
            requests[3].target
        );
    }

    #[tokio::test]
    async fn fleet_failures_deny_explicitly_without_fallback() {
        if !protected_test_tree() {
            return;
        }
        let handler: Arc<Handler> = Arc::new(|request: &Recorded| {
            match (request.method.as_str(), request.target.as_str()) {
                ("GET", "/v1/whoami") => (
                    401,
                    r#"{"detail":"bearer token was not accepted"}"#.to_owned(),
                ),
                ("POST", "/v1/authorize") => (307, String::new()),
                ("POST", "/v1/sessions:admit") => (
                    200,
                    json(&SessionAdmission {
                        session: SessionRef::new("ab".repeat(16)).unwrap(),
                        binding_sha256: Sha256Digest::of(b"other"),
                        admitted_at_unix: 1,
                    }),
                ),
                _ => (503, r#"{"detail":"unavailable"}"#.to_owned()),
            }
        });
        let (address, _) = serve(handler).await;
        let fixture = fixture(&fleet_profile(), 1);
        use_fleet(&fixture, address);

        let error = prepare(&fixture, &mut configuration(&[]), &no_secret_store)
            .await
            .err()
            .expect("no secret store");
        assert!(error.to_string().contains("no secret store"), "{error}");
        let empty = || -> Result<Arc<dyn SecretStore>, HostError> {
            Ok(Arc::new(FakeStore(BTreeMap::new())))
        };
        let error = prepare(&fixture, &mut configuration(&[]), &empty)
            .await
            .err()
            .expect("missing token");
        assert!(error.to_string().contains("sendbox secrets add"), "{error}");
        let error = prepare(&fixture, &mut configuration(&[]), &token_store)
            .await
            .err()
            .expect("rejected token");
        assert!(error.to_string().contains("HTTP 401"), "{error}");
        assert!(!error.to_string().contains(TOKEN));
        let mut leaking = configuration(&[]);
        leaking.secrets.push(DEFAULT_FLEET_TOKEN_SECRET.to_owned());
        let error = prepare(&fixture, &mut leaking, &token_store)
            .await
            .err()
            .expect("token as workload secret");
        assert!(error.to_string().contains("workload secret"), "{error}");

        let settings = FleetSettings {
            url: format!("http://{address}"),
            token_secret: DEFAULT_FLEET_TOKEN_SECRET.to_owned(),
            timeout_seconds: 5,
        };
        let client = Arc::new(
            FleetClient::new(&settings, &SecretValue::try_from(TOKEN).unwrap()).expect("client"),
        );
        assert!(FleetClient::new(&settings, &SecretValue::try_from("bad token").unwrap()).is_err());
        let authority = FleetGrantAuthority::new(Arc::clone(&client));
        let context = RequestContext {
            grant_id: GrantId::from_bytes([9; 16]),
            principal: PrincipalId::new(ALICE).unwrap(),
            project: ProjectId::github("acme", "app").unwrap(),
            session: SessionRef::new("ab".repeat(16)).unwrap(),
            binding_sha256: Sha256Digest::of(b"binding"),
            service: ServiceId::new("anthropic").unwrap(),
            method: "POST".to_owned(),
            path: "/v1/messages".to_owned(),
        };
        assert_eq!(
            authority.authorize(&context).await,
            Decision::Deny {
                reason: DenyReason::AuthorityUnavailable
            },
            "a redirect is never followed"
        );
        assert!(matches!(
            authority.renew(&context.grant_id).await,
            Err(GovernanceError::AuthorityUnavailable(message)) if message.contains("HTTP 503")
        ));

        let binding = GovernanceBinding {
            contract_version: sendbox_governance::CONTRACT_VERSION,
            authority: sendbox_governance::AuthorityRef {
                id: "fleet.example.com".to_owned(),
                trust_sha256: Sha256Digest::of(b"trust"),
            },
            profile: ProfileRef {
                id: sendbox_governance::ProfileId::new("acme").unwrap(),
                revision: 4,
                sha256: Sha256Digest::of(b"profile"),
            },
            principal: PrincipalId::new(ALICE).unwrap(),
            project: ProjectId::github("acme", "app").unwrap(),
            effective_policy_sha256: Sha256Digest::of(b"policy"),
            brokered_services: Vec::new(),
            exceptions: Vec::new(),
        };
        let error = client
            .admit(&SessionRef::new("ab".repeat(16)).unwrap(), &binding)
            .await
            .expect_err("mismatched admission");
        assert!(error.detail.contains("different session or binding"));
    }
}
