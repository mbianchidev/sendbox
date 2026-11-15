use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    CONTRACT_VERSION, GovernanceError, PrincipalId, ProjectId, ServiceId,
    digest::{Sha256Digest, canonical_digest},
    profile::ProfileRef,
};

/// The policy authority a session was admitted under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRef {
    /// `local` for a root-owned operator configuration, otherwise the
    /// governance service identifier.
    pub id: String,
    /// Digest of the trusted signer set and threshold that verified the profile.
    pub trust_sha256: Sha256Digest,
}

/// Binds one session to the principal, project, profile revision, and
/// effective policy it was admitted with. Embedded in the signed boundary plan
/// and repeated in every credential grant as its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceBinding {
    pub contract_version: u32,
    pub authority: AuthorityRef,
    pub profile: ProfileRef,
    pub principal: PrincipalId,
    pub project: ProjectId,
    pub effective_policy_sha256: Sha256Digest,
    pub brokered_services: Vec<ServiceId>,
}

impl GovernanceBinding {
    pub fn validate(&self) -> Result<(), GovernanceError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(GovernanceError::UnsupportedContract(self.contract_version));
        }
        if self.authority.id.is_empty()
            || self.authority.id.len() > 128
            || !self
                .authority
                .id
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
        {
            return Err(GovernanceError::InvalidBinding(
                "authority id must be 1-128 printable ASCII bytes".to_owned(),
            ));
        }
        let unique = self.brokered_services.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.brokered_services.len()
            || !self
                .brokered_services
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(GovernanceError::InvalidBinding(
                "brokered services must be sorted and unique".to_owned(),
            ));
        }
        Ok(())
    }

    /// RFC 8785 canonical digest used to bind grants to this exact admission.
    pub fn digest(&self) -> Result<Sha256Digest, GovernanceError> {
        self.validate()?;
        canonical_digest(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProfileId;

    pub(crate) fn binding() -> GovernanceBinding {
        GovernanceBinding {
            contract_version: CONTRACT_VERSION,
            authority: AuthorityRef {
                id: "local".to_owned(),
                trust_sha256: Sha256Digest::of(b"trust"),
            },
            profile: ProfileRef {
                id: ProfileId::new("acme").unwrap(),
                revision: 1,
                sha256: Sha256Digest::of(b"profile"),
            },
            principal: PrincipalId::new("local-user:501:alice").unwrap(),
            project: ProjectId::new("github:octo/api").unwrap(),
            effective_policy_sha256: Sha256Digest::of(b"policy"),
            brokered_services: vec![
                ServiceId::new("anthropic").unwrap(),
                ServiceId::new("openai").unwrap(),
            ],
        }
    }

    #[test]
    fn digest_changes_with_any_bound_field() {
        let original = binding();
        let digest = original.digest().unwrap();
        let mut changed = original.clone();
        changed.profile.revision = 2;
        assert_ne!(changed.digest().unwrap(), digest);
        let mut changed = original.clone();
        changed.project = ProjectId::new("github:octo/other").unwrap();
        assert_ne!(changed.digest().unwrap(), digest);
        let mut changed = original;
        changed.effective_policy_sha256 = Sha256Digest::of(b"other");
        assert_ne!(changed.digest().unwrap(), digest);
    }

    #[test]
    fn unsorted_services_are_rejected() {
        let mut binding = binding();
        binding.brokered_services.reverse();
        assert!(binding.digest().is_err());
    }
}
