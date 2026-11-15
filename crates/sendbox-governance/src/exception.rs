//! Bounded, expiring policy exceptions.
//!
//! An operator-signed profile lists which of its own denials a project may
//! lift ([`ExceptionPolicy`]). A governance service records requests and
//! approvals for those entries ([`PolicyException`]); a host lifts a denial
//! only for an approved, unexpired exception bound to the exact profile
//! revision it runs under. Lifting a denial never adds a capability: the
//! session must still fit the profile ceiling.

use serde::{Deserialize, Serialize};

use crate::{
    ExceptionId, GovernanceError, PrincipalId, ProjectId,
    profile::{Denials, ProfileRef},
};

/// Longest lifetime of one exception, from request to expiry.
pub const MAX_EXCEPTION_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const MAX_EXCEPTION_REASON_CHARS: usize = 1000;
/// Most exceptions one session binding may carry.
pub const MAX_SESSION_EXCEPTIONS: usize = 32;
const MAX_SCOPE_VALUE_BYTES: usize = 1024;
const DEFAULT_EXCEPTION_TTL_SECONDS: u64 = 24 * 60 * 60;

/// The profile denial list an exception lifts an entry from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionKind {
    Command,
    Domain,
    Network,
}

impl ExceptionKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Domain => "domain",
            Self::Network => "network",
        }
    }
}

/// Exactly one profile denial entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionScope {
    pub kind: ExceptionKind,
    pub value: String,
}

impl ExceptionScope {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if valid_scope_value(&self.value) {
            Ok(())
        } else {
            Err(GovernanceError::InvalidException(format!(
                "scope value must be 1-{MAX_SCOPE_VALUE_BYTES} printable ASCII bytes without leading or trailing spaces"
            )))
        }
    }
}

impl std::fmt::Display for ExceptionScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.kind.code(), self.value)
    }
}

/// The operator's opt-in, signed into the profile: the denial entries that an
/// approved exception may lift, and the longest an exception may last. An
/// empty policy permits no exceptions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExceptionPolicy {
    pub max_ttl_seconds: u64,
    pub commands: Vec<String>,
    pub domains: Vec<String>,
    pub networks: Vec<String>,
}

impl Default for ExceptionPolicy {
    fn default() -> Self {
        Self {
            max_ttl_seconds: DEFAULT_EXCEPTION_TTL_SECONDS,
            commands: Vec::new(),
            domains: Vec::new(),
            networks: Vec::new(),
        }
    }
}

impl ExceptionPolicy {
    #[must_use]
    pub fn permits(&self, scope: &ExceptionScope) -> bool {
        self.entries(scope.kind).contains(&scope.value)
    }

    fn entries(&self, kind: ExceptionKind) -> &[String] {
        match kind {
            ExceptionKind::Command => &self.commands,
            ExceptionKind::Domain => &self.domains,
            ExceptionKind::Network => &self.networks,
        }
    }

    pub(crate) fn validate(&self, denials: &Denials, problems: &mut Vec<String>) {
        if !(1..=MAX_EXCEPTION_TTL_SECONDS).contains(&self.max_ttl_seconds) {
            problems.push(format!(
                "exceptions.max_ttl_seconds must be 1..={MAX_EXCEPTION_TTL_SECONDS}"
            ));
        }
        for (kind, denied) in [
            (ExceptionKind::Command, &denials.commands),
            (ExceptionKind::Domain, &denials.domains),
            (ExceptionKind::Network, &denials.networks),
        ] {
            let entries = self.entries(kind);
            let mut seen = std::collections::BTreeSet::new();
            for entry in entries {
                let path = format!("exceptions.{}s", kind.code());
                if !seen.insert(entry) {
                    problems.push(format!("{path} contains duplicate `{entry}`"));
                } else if !valid_scope_value(entry) {
                    problems.push(format!(
                        "{path} entries must be 1-{MAX_SCOPE_VALUE_BYTES} printable ASCII bytes"
                    ));
                } else if !denied.contains(entry) {
                    problems.push(format!(
                        "{path} entry `{entry}` must also be listed in denials.{}s",
                        kind.code()
                    ));
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionStatus {
    Pending,
    Approved,
    Rejected,
}

/// An exception as recorded by a governance service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyException {
    pub id: ExceptionId,
    pub project: ProjectId,
    /// `None` covers every principal with a role in the project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,
    /// The exact profile revision the exception was reviewed against.
    pub profile: ProfileRef,
    pub scope: ExceptionScope,
    pub reason: String,
    pub status: ExceptionStatus,
    pub requested_by: PrincipalId,
    pub requested_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<PrincipalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at_unix: Option<u64>,
    pub expires_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<PrincipalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix: Option<u64>,
}

impl PolicyException {
    /// Whether this exception currently lifts its denial for one session.
    #[must_use]
    pub fn applies_to(
        &self,
        project: &ProjectId,
        principal: &PrincipalId,
        profile: &ProfileRef,
        now_unix: u64,
    ) -> bool {
        self.status == ExceptionStatus::Approved
            && self.revoked_at_unix.is_none()
            && now_unix < self.expires_at_unix
            && &self.project == project
            && self
                .principal
                .as_ref()
                .is_none_or(|bound| bound == principal)
            && &self.profile == profile
    }
}

/// Validates a free-text exception reason.
pub fn validate_reason(reason: &str) -> Result<(), GovernanceError> {
    if reason.trim().is_empty()
        || reason.chars().count() > MAX_EXCEPTION_REASON_CHARS
        || reason.chars().any(char::is_control)
    {
        return Err(GovernanceError::InvalidException(format!(
            "reason must be 1 to {MAX_EXCEPTION_REASON_CHARS} characters without control characters"
        )));
    }
    Ok(())
}

fn valid_scope_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_VALUE_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProfileId, digest::Sha256Digest};

    fn denials() -> Denials {
        Denials {
            commands: vec!["git push --force *".to_owned()],
            domains: vec!["gist.github.com".to_owned()],
            networks: vec!["169.254.0.0/16".to_owned()],
        }
    }

    #[test]
    fn policy_entries_must_be_profile_denials() {
        let mut problems = Vec::new();
        ExceptionPolicy {
            commands: vec!["git push --force *".to_owned()],
            domains: vec!["gist.github.com".to_owned(), "example.com".to_owned()],
            ..ExceptionPolicy::default()
        }
        .validate(&denials(), &mut problems);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("example.com"));

        let mut problems = Vec::new();
        ExceptionPolicy {
            max_ttl_seconds: MAX_EXCEPTION_TTL_SECONDS + 1,
            ..ExceptionPolicy::default()
        }
        .validate(&denials(), &mut problems);
        assert!(problems[0].contains("max_ttl_seconds"));
    }

    #[test]
    fn scopes_match_exact_entries_of_their_kind() {
        let policy = ExceptionPolicy {
            domains: vec!["gist.github.com".to_owned()],
            ..ExceptionPolicy::default()
        };
        let scope = |kind, value: &str| ExceptionScope {
            kind,
            value: value.to_owned(),
        };
        assert!(policy.permits(&scope(ExceptionKind::Domain, "gist.github.com")));
        assert!(!policy.permits(&scope(ExceptionKind::Command, "gist.github.com")));
        assert!(!policy.permits(&scope(ExceptionKind::Domain, "*.github.com")));
        assert!(
            scope(ExceptionKind::Command, "git push --force *")
                .validate()
                .is_ok()
        );
        assert!(scope(ExceptionKind::Command, " git").validate().is_err());
        assert!(scope(ExceptionKind::Domain, "a\nb").validate().is_err());
    }

    #[test]
    fn only_approved_current_matching_exceptions_apply() {
        let profile = ProfileRef {
            id: ProfileId::new("acme").unwrap(),
            revision: 2,
            sha256: Sha256Digest::of(b"profile"),
        };
        let project = ProjectId::new("github:octo/api").unwrap();
        let alice = PrincipalId::new("oidc:alice@example.com").unwrap();
        let bob = PrincipalId::new("oidc:bob@example.com").unwrap();
        let exception = PolicyException {
            id: ExceptionId::from_bytes([1; 16]),
            project: project.clone(),
            principal: Some(alice.clone()),
            profile: profile.clone(),
            scope: ExceptionScope {
                kind: ExceptionKind::Domain,
                value: "gist.github.com".to_owned(),
            },
            reason: "release".to_owned(),
            status: ExceptionStatus::Approved,
            requested_by: alice.clone(),
            requested_at_unix: 100,
            decided_by: Some(bob.clone()),
            decided_at_unix: Some(110),
            expires_at_unix: 200,
            revoked_by: None,
            revoked_at_unix: None,
        };
        assert!(exception.applies_to(&project, &alice, &profile, 150));
        assert!(!exception.applies_to(&project, &bob, &profile, 150));
        assert!(!exception.applies_to(&project, &alice, &profile, 200));
        let mut newer = profile.clone();
        newer.revision = 3;
        assert!(!exception.applies_to(&project, &alice, &newer, 150));
        let revoked = PolicyException {
            revoked_by: Some(bob.clone()),
            revoked_at_unix: Some(120),
            ..exception.clone()
        };
        assert!(!revoked.applies_to(&project, &alice, &profile, 150));
        let pending = PolicyException {
            status: ExceptionStatus::Pending,
            decided_by: None,
            decided_at_unix: None,
            ..exception.clone()
        };
        assert!(!pending.applies_to(&project, &alice, &profile, 150));
        let project_wide = PolicyException {
            principal: None,
            ..exception
        };
        assert!(project_wide.applies_to(&project, &bob, &profile, 150));
    }

    #[test]
    fn reasons_are_bounded_text() {
        assert!(validate_reason("Mirror outage during release").is_ok());
        assert!(validate_reason("  ").is_err());
        assert!(validate_reason("line\nbreak").is_err());
        assert!(validate_reason(&"x".repeat(MAX_EXCEPTION_REASON_CHARS + 1)).is_err());
    }
}
