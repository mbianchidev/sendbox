use std::collections::BTreeMap;

use sendbox_policy::{PackageAction, PackageFindingKind, PackageSupplyChainPolicy};
use sha2::{Digest, Sha256};

use crate::{PackageFinding, PackageIdentity, RegistryError, RegistryResult, Verdict};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RawFinding {
    pub kind: PackageFindingKind,
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub verdict: Verdict,
    pub findings: Vec<PackageFinding>,
}

pub fn package_policy_digest(policy: &PackageSupplyChainPolicy) -> RegistryResult<String> {
    let encoded = serde_json::to_vec(policy)
        .map_err(|error| RegistryError::Invalid(format!("encode package policy: {error}")))?;
    let mut digest = Sha256::new();
    digest.update(b"sendbox-package-policy-v1\0");
    digest.update(&encoded);
    Ok(format!("sha256:{}", encode_hex(&digest.finalize())))
}

#[must_use]
pub fn evaluate_findings(
    policy: &PackageSupplyChainPolicy,
    identity: &PackageIdentity,
    artifact_digest: &str,
    findings: Vec<RawFinding>,
) -> PolicyDecision {
    let configured = policy
        .finding_actions
        .iter()
        .map(|rule| (rule.finding, rule.action))
        .collect::<BTreeMap<_, _>>();
    let exception = policy.exceptions.iter().find(|rule| {
        rule.ecosystem == identity.ecosystem
            && rule.package == identity.name
            && rule
                .version
                .as_deref()
                .is_none_or(|version| version == identity.version)
            && rule.artifact_digest == artifact_digest
    });

    let mut verdict = Verdict::Allow;
    let findings = findings
        .into_iter()
        .map(|finding| {
            let mut action = configured
                .get(&finding.kind)
                .copied()
                .unwrap_or(policy.default_finding_action);
            if let Some(exception) = exception
                && exception.findings.contains(&finding.kind)
            {
                action = exception.action;
            }
            if finding.kind.is_fail_closed() {
                action = PackageAction::Deny;
            }
            verdict = combine(verdict, action.into());
            PackageFinding {
                kind: finding.kind,
                action,
                path: finding.path,
                detail: finding.detail,
            }
        })
        .collect();
    PolicyDecision { verdict, findings }
}

fn combine(current: Verdict, next: Verdict) -> Verdict {
    match (current, next) {
        (Verdict::Deny, _) | (_, Verdict::Deny) => Verdict::Deny,
        (Verdict::Quarantine, _) | (_, Verdict::Quarantine) => Verdict::Quarantine,
        _ => Verdict::Allow,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use sendbox_policy::{
        PackageAction, PackageEcosystem, PackageExceptionRule, PackageFindingKind,
        PackageFindingPolicy, PackageRegistryPolicy, PackageSupplyChainPolicy,
    };

    use super::*;

    fn identity() -> PackageIdentity {
        PackageIdentity {
            ecosystem: PackageEcosystem::Npm,
            name: "@acme/build".to_owned(),
            version: "1.2.3".to_owned(),
        }
    }

    #[test]
    fn digest_is_stable_and_domain_separated() {
        let policy = PackageSupplyChainPolicy {
            enabled: true,
            registries: vec![PackageRegistryPolicy::default()],
            ..PackageSupplyChainPolicy::default()
        };
        let first = package_policy_digest(&policy).unwrap();
        let second = package_policy_digest(&policy).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
    }

    #[test]
    fn exact_digest_exception_allows_only_listed_findings() {
        let digest = format!("sha512:{}", "a".repeat(128));
        let policy = PackageSupplyChainPolicy {
            enabled: true,
            registries: vec![PackageRegistryPolicy::default()],
            exceptions: vec![PackageExceptionRule {
                ecosystem: PackageEcosystem::Npm,
                package: "@acme/build".to_owned(),
                version: Some("1.2.3".to_owned()),
                artifact_digest: digest.clone(),
                findings: vec![PackageFindingKind::LifecycleScript],
                action: PackageAction::Allow,
            }],
            ..PackageSupplyChainPolicy::default()
        };
        let decision = evaluate_findings(
            &policy,
            &identity(),
            &digest,
            vec![
                RawFinding {
                    kind: PackageFindingKind::LifecycleScript,
                    path: Some("package.json".to_owned()),
                    detail: "install script".to_owned(),
                },
                RawFinding {
                    kind: PackageFindingKind::SubprocessApi,
                    path: Some("index.js".to_owned()),
                    detail: "child_process.exec".to_owned(),
                },
            ],
        );
        assert_eq!(decision.findings[0].action, PackageAction::Allow);
        assert_eq!(decision.findings[1].action, PackageAction::Deny);
        assert_eq!(decision.verdict, Verdict::Deny);
    }

    #[test]
    fn fail_closed_findings_ignore_policy_overrides() {
        let policy = PackageSupplyChainPolicy {
            finding_actions: vec![PackageFindingPolicy {
                finding: PackageFindingKind::IntegrityFailure,
                action: PackageAction::Allow,
            }],
            default_finding_action: PackageAction::Allow,
            ..PackageSupplyChainPolicy::default()
        };
        let decision = evaluate_findings(
            &policy,
            &identity(),
            "sha512:invalid",
            vec![RawFinding {
                kind: PackageFindingKind::IntegrityFailure,
                path: None,
                detail: "mismatch".to_owned(),
            }],
        );
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.findings[0].action, PackageAction::Deny);
    }
}
