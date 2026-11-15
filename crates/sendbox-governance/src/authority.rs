//! Grant authority contract and the single-host implementation.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    CONTRACT_VERSION, GovernanceError, GrantId,
    grant::{
        AllowedRequest, CredentialGrant, Decision, DenyReason, GrantRequest, RequestContext,
        RevocationReason, path_permitted, validate_method, validate_path_prefix,
    },
    profile::ProfileRef,
};

pub type AuthorityFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }
}

/// The current, trusted revision of a profile as seen by the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentProfile {
    pub reference: ProfileRef,
    pub minimum_revision: u64,
    pub expires_at_unix: u64,
}

/// Reports the authority's current view of a profile. Implementations must
/// re-verify the profile rather than trust cached workload-visible state, and
/// return an error when the authority cannot be consulted.
pub trait RevisionSource: Send + Sync {
    fn current(&self, profile: &crate::ProfileId) -> Result<CurrentProfile, GovernanceError>;
}

/// Issues, checks, renews, and revokes credential grants.
///
/// `authorize` must be called for every brokered request and must deny when
/// the authority cannot establish that the grant is current.
pub trait GrantAuthority: Send + Sync {
    fn issue<'a>(
        &'a self,
        request: GrantRequest,
    ) -> AuthorityFuture<'a, Result<CredentialGrant, GovernanceError>>;

    fn authorize<'a>(&'a self, context: &'a RequestContext) -> AuthorityFuture<'a, Decision>;

    fn renew<'a>(
        &'a self,
        grant: &'a GrantId,
    ) -> AuthorityFuture<'a, Result<CredentialGrant, GovernanceError>>;

    fn revoke<'a>(
        &'a self,
        grant: &'a GrantId,
        reason: RevocationReason,
    ) -> AuthorityFuture<'a, Result<(), GovernanceError>>;
}

#[derive(Debug, Clone)]
pub struct LocalAuthorityLimits {
    pub lease_seconds: u64,
    pub max_grants: usize,
}

impl Default for LocalAuthorityLimits {
    fn default() -> Self {
        Self {
            lease_seconds: 300,
            max_grants: 64,
        }
    }
}

#[derive(Debug, Clone)]
struct GrantState {
    grant: CredentialGrant,
    revoked: Option<RevocationReason>,
}

/// In-process authority for one host. It holds no credentials; it only
/// decides whether a request is covered by a current grant.
pub struct LocalGrantAuthority {
    grants: Mutex<BTreeMap<GrantId, GrantState>>,
    revisions: Arc<dyn RevisionSource>,
    clock: Arc<dyn Clock>,
    limits: LocalAuthorityLimits,
    random: Box<dyn Fn() -> Result<[u8; 16], GovernanceError> + Send + Sync>,
}

impl LocalGrantAuthority {
    #[must_use]
    pub fn new(
        revisions: Arc<dyn RevisionSource>,
        clock: Arc<dyn Clock>,
        limits: LocalAuthorityLimits,
        random: Box<dyn Fn() -> Result<[u8; 16], GovernanceError> + Send + Sync>,
    ) -> Self {
        Self {
            grants: Mutex::new(BTreeMap::new()),
            revisions,
            clock,
            limits,
            random,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<GrantId, GrantState>> {
        self.grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn current_revision(
        &self,
        reference: &ProfileRef,
        now: u64,
    ) -> Result<CurrentProfile, DenyReason> {
        let current = self
            .revisions
            .current(&reference.id)
            .map_err(|_| DenyReason::AuthorityUnavailable)?;
        check_current(reference, &current, now)?;
        Ok(current)
    }

    fn issue_sync(&self, request: GrantRequest) -> Result<CredentialGrant, GovernanceError> {
        let binding_sha256 = request.binding.digest()?;
        if request.binding.principal != request.principal
            || request.binding.project != request.project
        {
            return Err(GovernanceError::InvalidGrant(
                "grant identity does not match the session binding".to_owned(),
            ));
        }
        if !request.binding.brokered_services.contains(&request.service) {
            return Err(GovernanceError::InvalidGrant(
                "service is not admitted by the session binding".to_owned(),
            ));
        }
        if request.methods.is_empty() || request.path_prefixes.is_empty() {
            return Err(GovernanceError::InvalidGrant(
                "grants require at least one method and path prefix".to_owned(),
            ));
        }
        for method in &request.methods {
            validate_method(method)?;
        }
        for prefix in &request.path_prefixes {
            validate_path_prefix(prefix)?;
        }
        let now = self.clock.now_unix();
        let current = self
            .current_revision(&request.binding.profile, now)
            .map_err(|reason| GovernanceError::Denied(reason.code()))?;
        let max_expires_at_unix = now
            .saturating_add(request.max_ttl_seconds)
            .min(current.expires_at_unix);
        if max_expires_at_unix <= now {
            return Err(GovernanceError::InvalidGrant(
                "grant would expire immediately".to_owned(),
            ));
        }
        let grant = CredentialGrant {
            contract_version: CONTRACT_VERSION,
            grant_id: GrantId::from_bytes((self.random)()?),
            principal: request.principal,
            project: request.project,
            session: request.session,
            binding_sha256,
            profile: request.binding.profile,
            service: request.service,
            methods: request.methods,
            path_prefixes: request.path_prefixes,
            issued_at_unix: now,
            lease_expires_at_unix: now
                .saturating_add(self.limits.lease_seconds)
                .min(max_expires_at_unix),
            max_expires_at_unix,
            generation: 1,
        };
        grant.validate()?;
        let mut grants = self.lock();
        grants.retain(|_, state| state.revoked.is_none() && state.grant.max_expires_at_unix > now);
        if grants.len() >= self.limits.max_grants {
            return Err(GovernanceError::InvalidGrant(
                "local grant capacity is exhausted".to_owned(),
            ));
        }
        if grants.contains_key(&grant.grant_id) {
            return Err(GovernanceError::InvalidGrant(
                "grant identifier collision".to_owned(),
            ));
        }
        grants.insert(
            grant.grant_id.clone(),
            GrantState {
                grant: grant.clone(),
                revoked: None,
            },
        );
        Ok(grant)
    }

    fn authorize_sync(&self, context: &RequestContext) -> Decision {
        let now = self.clock.now_unix();
        let (grant, revoked) = {
            let grants = self.lock();
            let Some(state) = grants.get(&context.grant_id) else {
                return deny(DenyReason::UnknownGrant);
            };
            (state.grant.clone(), state.revoked.is_some())
        };
        let current = self.revisions.current(&grant.profile.id).ok();
        evaluate_request(&grant, revoked, context, now, current.as_ref())
    }

    fn renew_sync(&self, grant_id: &GrantId) -> Result<CredentialGrant, GovernanceError> {
        let now = self.clock.now_unix();
        let profile = {
            let grants = self.lock();
            let state = grants
                .get(grant_id)
                .ok_or(GovernanceError::Denied(DenyReason::UnknownGrant.code()))?;
            if state.revoked.is_some() {
                return Err(GovernanceError::Denied(DenyReason::Revoked.code()));
            }
            if now >= state.grant.max_expires_at_unix {
                return Err(GovernanceError::Denied(DenyReason::Expired.code()));
            }
            if now >= state.grant.lease_expires_at_unix {
                return Err(GovernanceError::Denied(DenyReason::LeaseExpired.code()));
            }
            state.grant.profile.clone()
        };
        self.current_revision(&profile, now)
            .map_err(|reason| GovernanceError::Denied(reason.code()))?;
        let mut grants = self.lock();
        let state = grants
            .get_mut(grant_id)
            .ok_or(GovernanceError::Denied(DenyReason::UnknownGrant.code()))?;
        if state.revoked.is_some() {
            return Err(GovernanceError::Denied(DenyReason::Revoked.code()));
        }
        state.grant.lease_expires_at_unix = now
            .saturating_add(self.limits.lease_seconds)
            .min(state.grant.max_expires_at_unix);
        state.grant.generation = state.grant.generation.saturating_add(1);
        Ok(state.grant.clone())
    }

    fn revoke_sync(
        &self,
        grant_id: &GrantId,
        reason: RevocationReason,
    ) -> Result<(), GovernanceError> {
        let mut grants = self.lock();
        let state = grants
            .get_mut(grant_id)
            .ok_or(GovernanceError::Denied(DenyReason::UnknownGrant.code()))?;
        if state.revoked.is_none() {
            state.revoked = Some(reason);
            state.grant.generation = state.grant.generation.saturating_add(1);
        }
        Ok(())
    }
}

fn deny(reason: DenyReason) -> Decision {
    Decision::Deny { reason }
}

/// Rejects a profile reference that is not the authority's current, unexpired
/// revision at or above the minimum.
pub fn check_current(
    reference: &ProfileRef,
    current: &CurrentProfile,
    now_unix: u64,
) -> Result<(), DenyReason> {
    if current.reference != *reference
        || reference.revision < current.minimum_revision
        || now_unix >= current.expires_at_unix
    {
        return Err(DenyReason::StalePolicy);
    }
    Ok(())
}

/// Decides one brokered request against a stored grant. Every authority uses
/// this so local and shared authorities deny for the same reasons. `current`
/// is `None` when the authority cannot establish the current profile.
#[must_use]
pub fn evaluate_request(
    grant: &CredentialGrant,
    revoked: bool,
    context: &RequestContext,
    now_unix: u64,
    current: Option<&CurrentProfile>,
) -> Decision {
    if context.grant_id != grant.grant_id {
        return deny(DenyReason::UnknownGrant);
    }
    if revoked {
        return deny(DenyReason::Revoked);
    }
    let checks = [
        (now_unix >= grant.max_expires_at_unix, DenyReason::Expired),
        (
            now_unix >= grant.lease_expires_at_unix,
            DenyReason::LeaseExpired,
        ),
        (
            context.principal != grant.principal,
            DenyReason::PrincipalMismatch,
        ),
        (
            context.project != grant.project,
            DenyReason::ProjectMismatch,
        ),
        (
            context.session != grant.session,
            DenyReason::SessionMismatch,
        ),
        (
            context.binding_sha256 != grant.binding_sha256,
            DenyReason::BindingMismatch,
        ),
        (
            context.service != grant.service,
            DenyReason::ServiceNotGranted,
        ),
        (
            !grant.methods.contains(&context.method),
            DenyReason::MethodNotGranted,
        ),
    ];
    if let Some((_, reason)) = checks.iter().find(|(failed, _)| *failed) {
        return deny(*reason);
    }
    if crate::grant::validate_request_path(&context.path).is_err() {
        return deny(DenyReason::InvalidPath);
    }
    if !path_permitted(&grant.path_prefixes, &context.path) {
        return deny(DenyReason::PathNotGranted);
    }
    let Some(current) = current else {
        return deny(DenyReason::AuthorityUnavailable);
    };
    if let Err(reason) = check_current(&grant.profile, current, now_unix) {
        return deny(reason);
    }
    Decision::Allow(AllowedRequest {
        grant_id: grant.grant_id.clone(),
        generation: grant.generation,
        profile: grant.profile.clone(),
        lease_expires_at_unix: grant.lease_expires_at_unix,
    })
}

impl GrantAuthority for LocalGrantAuthority {
    fn issue<'a>(
        &'a self,
        request: GrantRequest,
    ) -> AuthorityFuture<'a, Result<CredentialGrant, GovernanceError>> {
        Box::pin(async move { self.issue_sync(request) })
    }

    fn authorize<'a>(&'a self, context: &'a RequestContext) -> AuthorityFuture<'a, Decision> {
        Box::pin(async move { self.authorize_sync(context) })
    }

    fn renew<'a>(
        &'a self,
        grant: &'a GrantId,
    ) -> AuthorityFuture<'a, Result<CredentialGrant, GovernanceError>> {
        Box::pin(async move { self.renew_sync(grant) })
    }

    fn revoke<'a>(
        &'a self,
        grant: &'a GrantId,
        reason: RevocationReason,
    ) -> AuthorityFuture<'a, Result<(), GovernanceError>> {
        Box::pin(async move { self.revoke_sync(grant, reason) })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

    use super::*;
    use crate::{
        AuthorityRef, GovernanceBinding, PrincipalId, ProfileId, ProjectId, ServiceId, SessionRef,
        digest::Sha256Digest,
    };

    struct TestClock(AtomicU64);

    impl Clock for TestClock {
        fn now_unix(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct TestRevisions {
        current: Mutex<Option<CurrentProfile>>,
    }

    impl RevisionSource for TestRevisions {
        fn current(&self, _profile: &ProfileId) -> Result<CurrentProfile, GovernanceError> {
            self.current
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| GovernanceError::AuthorityUnavailable("offline".to_owned()))
        }
    }

    fn profile_ref(revision: u64) -> ProfileRef {
        ProfileRef {
            id: ProfileId::new("acme").unwrap(),
            revision,
            sha256: Sha256Digest::of(&revision.to_be_bytes()),
        }
    }

    fn binding() -> GovernanceBinding {
        GovernanceBinding {
            contract_version: CONTRACT_VERSION,
            authority: AuthorityRef {
                id: "local".to_owned(),
                trust_sha256: Sha256Digest::of(b"trust"),
            },
            profile: profile_ref(1),
            principal: PrincipalId::new("local-user:501:alice").unwrap(),
            project: ProjectId::new("github:octo/api").unwrap(),
            effective_policy_sha256: Sha256Digest::of(b"policy"),
            brokered_services: vec![ServiceId::new("anthropic").unwrap()],
            exceptions: Vec::new(),
        }
    }

    struct Fixture {
        authority: LocalGrantAuthority,
        clock: Arc<TestClock>,
        revisions: Arc<TestRevisions>,
    }

    fn fixture() -> Fixture {
        let clock = Arc::new(TestClock(AtomicU64::new(1_000)));
        let revisions = Arc::new(TestRevisions {
            current: Mutex::new(Some(CurrentProfile {
                reference: profile_ref(1),
                minimum_revision: 1,
                expires_at_unix: 100_000,
            })),
        });
        let counter = Arc::new(AtomicU8::new(0));
        let authority = LocalGrantAuthority::new(
            revisions.clone(),
            clock.clone(),
            LocalAuthorityLimits {
                lease_seconds: 60,
                max_grants: 4,
            },
            Box::new(move || Ok([counter.fetch_add(1, Ordering::SeqCst); 16])),
        );
        Fixture {
            authority,
            clock,
            revisions,
        }
    }

    fn request() -> GrantRequest {
        let binding = binding();
        GrantRequest {
            principal: binding.principal.clone(),
            project: binding.project.clone(),
            session: SessionRef::new("ab".repeat(16)).unwrap(),
            service: ServiceId::new("anthropic").unwrap(),
            methods: ["POST".to_owned()].into(),
            path_prefixes: vec!["/v1/messages".to_owned()],
            max_ttl_seconds: 600,
            binding,
        }
    }

    fn context(grant: &CredentialGrant) -> RequestContext {
        RequestContext {
            grant_id: grant.grant_id.clone(),
            principal: grant.principal.clone(),
            project: grant.project.clone(),
            session: grant.session.clone(),
            binding_sha256: grant.binding_sha256,
            service: grant.service.clone(),
            method: "POST".to_owned(),
            path: "/v1/messages".to_owned(),
        }
    }

    fn reason(decision: Decision) -> DenyReason {
        match decision {
            Decision::Deny { reason } => reason,
            Decision::Allow(_) => panic!("unexpected allow"),
        }
    }

    #[test]
    fn current_grant_authorizes_exact_binding_only() {
        let fixture = fixture();
        let grant = fixture.authority.issue_sync(request()).unwrap();
        assert!(
            fixture
                .authority
                .authorize_sync(&context(&grant))
                .is_allowed()
        );

        let mut wrong = context(&grant);
        wrong.principal = PrincipalId::new("local-user:502:mallory").unwrap();
        assert_eq!(
            reason(fixture.authority.authorize_sync(&wrong)),
            DenyReason::PrincipalMismatch
        );
        let mut wrong = context(&grant);
        wrong.project = ProjectId::new("github:octo/other").unwrap();
        assert_eq!(
            reason(fixture.authority.authorize_sync(&wrong)),
            DenyReason::ProjectMismatch
        );
        let mut wrong = context(&grant);
        wrong.session = SessionRef::new("cd".repeat(16)).unwrap();
        assert_eq!(
            reason(fixture.authority.authorize_sync(&wrong)),
            DenyReason::SessionMismatch
        );
        let mut wrong = context(&grant);
        wrong.binding_sha256 = Sha256Digest::of(b"changed");
        assert_eq!(
            reason(fixture.authority.authorize_sync(&wrong)),
            DenyReason::BindingMismatch
        );
        let mut wrong = context(&grant);
        wrong.method = "DELETE".to_owned();
        assert_eq!(
            reason(fixture.authority.authorize_sync(&wrong)),
            DenyReason::MethodNotGranted
        );
        let mut wrong = context(&grant);
        wrong.path = "/v1/files".to_owned();
        assert_eq!(
            reason(fixture.authority.authorize_sync(&wrong)),
            DenyReason::PathNotGranted
        );
        let mut wrong = context(&grant);
        wrong.path = "/v1/messages/../files".to_owned();
        assert_eq!(
            reason(fixture.authority.authorize_sync(&wrong)),
            DenyReason::InvalidPath
        );
        let mut wrong = context(&grant);
        wrong.grant_id = GrantId::new("ff".repeat(16)).unwrap();
        assert_eq!(
            reason(fixture.authority.authorize_sync(&wrong)),
            DenyReason::UnknownGrant
        );
    }

    #[test]
    fn leases_expire_unless_renewed_and_never_exceed_the_ttl() {
        let fixture = fixture();
        let grant = fixture.authority.issue_sync(request()).unwrap();
        fixture.clock.0.store(1_059, Ordering::SeqCst);
        let renewed = fixture.authority.renew_sync(&grant.grant_id).unwrap();
        assert_eq!(renewed.generation, 2);
        assert_eq!(renewed.lease_expires_at_unix, 1_119);
        fixture.clock.0.store(1_119, Ordering::SeqCst);
        assert_eq!(
            reason(fixture.authority.authorize_sync(&context(&grant))),
            DenyReason::LeaseExpired
        );
        assert!(fixture.authority.renew_sync(&grant.grant_id).is_err());

        let grant = fixture.authority.issue_sync(request()).unwrap();
        assert_eq!(grant.max_expires_at_unix, 1_119 + 600);
        for now in (1_150..1_719).step_by(50) {
            fixture.clock.0.store(now, Ordering::SeqCst);
            fixture.authority.renew_sync(&grant.grant_id).unwrap();
        }
        fixture.clock.0.store(1_719, Ordering::SeqCst);
        assert_eq!(
            reason(fixture.authority.authorize_sync(&context(&grant))),
            DenyReason::Expired
        );
    }

    #[test]
    fn revocation_stale_policy_and_unavailable_authority_deny() {
        let fixture = fixture();
        let grant = fixture.authority.issue_sync(request()).unwrap();
        *fixture.revisions.current.lock().unwrap() = Some(CurrentProfile {
            reference: profile_ref(2),
            minimum_revision: 1,
            expires_at_unix: 100_000,
        });
        assert_eq!(
            reason(fixture.authority.authorize_sync(&context(&grant))),
            DenyReason::StalePolicy
        );
        assert!(fixture.authority.renew_sync(&grant.grant_id).is_err());

        *fixture.revisions.current.lock().unwrap() = Some(CurrentProfile {
            reference: profile_ref(1),
            minimum_revision: 2,
            expires_at_unix: 100_000,
        });
        assert_eq!(
            reason(fixture.authority.authorize_sync(&context(&grant))),
            DenyReason::StalePolicy
        );

        *fixture.revisions.current.lock().unwrap() = None;
        assert_eq!(
            reason(fixture.authority.authorize_sync(&context(&grant))),
            DenyReason::AuthorityUnavailable
        );
        assert!(fixture.authority.issue_sync(request()).is_err());

        *fixture.revisions.current.lock().unwrap() = Some(CurrentProfile {
            reference: profile_ref(1),
            minimum_revision: 1,
            expires_at_unix: 100_000,
        });
        assert!(
            fixture
                .authority
                .authorize_sync(&context(&grant))
                .is_allowed()
        );
        fixture
            .authority
            .revoke_sync(&grant.grant_id, RevocationReason::SessionCompleted)
            .unwrap();
        assert_eq!(
            reason(fixture.authority.authorize_sync(&context(&grant))),
            DenyReason::Revoked
        );
    }

    #[test]
    fn issuance_requires_an_admitted_service_and_matching_identity() {
        let fixture = fixture();
        let mut wrong_service = request();
        wrong_service.service = ServiceId::new("openai").unwrap();
        assert!(fixture.authority.issue_sync(wrong_service).is_err());
        let mut wrong_principal = request();
        wrong_principal.principal = PrincipalId::new("local-user:502:mallory").unwrap();
        assert!(fixture.authority.issue_sync(wrong_principal).is_err());
        for _ in 0..4 {
            fixture.authority.issue_sync(request()).unwrap();
        }
        assert!(fixture.authority.issue_sync(request()).is_err());
    }
}
