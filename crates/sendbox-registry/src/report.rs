use sendbox_policy::{PackageAction, PackageFindingKind};
use serde::{Deserialize, Serialize};

use crate::{
    ArtifactDigest, PackageIdentity, REGISTRY_REPORT_SCHEMA_VERSION, VerificationEvidence,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
    Quarantine,
}

impl From<PackageAction> for Verdict {
    fn from(action: PackageAction) -> Self {
        match action {
            PackageAction::Allow => Self::Allow,
            PackageAction::Deny => Self::Deny,
            PackageAction::Quarantine => Self::Quarantine,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheOutcome {
    Disabled,
    Miss,
    Hit,
    SharedAnalysis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFinding {
    pub kind: PackageFindingKind,
    pub action: PackageAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageVerdictRecord {
    pub identity: PackageIdentity,
    pub upstream: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<ArtifactDigest>,
    pub policy_digest: String,
    pub scanner_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationEvidence>,
    pub findings: Vec<PackageFinding>,
    pub verdict: Verdict,
    pub cache: CacheOutcome,
    pub requested_by_session: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSecurityReport {
    pub schema_version: u32,
    pub proxy_enabled: bool,
    pub records: Vec<PackageVerdictRecord>,
    pub allowed: u32,
    pub denied: u32,
    pub quarantined: u32,
}

impl PackageSecurityReport {
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            schema_version: REGISTRY_REPORT_SCHEMA_VERSION,
            proxy_enabled: false,
            records: Vec::new(),
            allowed: 0,
            denied: 0,
            quarantined: 0,
        }
    }

    #[must_use]
    pub const fn enabled() -> Self {
        Self {
            schema_version: REGISTRY_REPORT_SCHEMA_VERSION,
            proxy_enabled: true,
            records: Vec::new(),
            allowed: 0,
            denied: 0,
            quarantined: 0,
        }
    }

    pub fn push(&mut self, record: PackageVerdictRecord) {
        match record.verdict {
            Verdict::Allow => self.allowed = self.allowed.saturating_add(1),
            Verdict::Deny => self.denied = self.denied.saturating_add(1),
            Verdict::Quarantine => self.quarantined = self.quarantined.saturating_add(1),
        }
        self.records.push(record);
    }

    pub fn validate(&self, maximum_records: usize, maximum_findings: usize) -> Result<(), String> {
        if self.schema_version != REGISTRY_REPORT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported package report schema {}",
                self.schema_version
            ));
        }
        if self.records.len() > maximum_records {
            return Err("package report exceeds the configured record limit".to_owned());
        }
        let mut allowed = 0_u32;
        let mut denied = 0_u32;
        let mut quarantined = 0_u32;
        let mut findings = 0_usize;
        for record in &self.records {
            findings = findings
                .checked_add(record.findings.len())
                .ok_or_else(|| "package report finding count overflowed".to_owned())?;
            match record.verdict {
                Verdict::Allow => allowed = allowed.saturating_add(1),
                Verdict::Deny => denied = denied.saturating_add(1),
                Verdict::Quarantine => quarantined = quarantined.saturating_add(1),
            }
        }
        if findings > maximum_findings {
            return Err("package report exceeds the configured finding limit".to_owned());
        }
        if (allowed, denied, quarantined) != (self.allowed, self.denied, self.quarantined) {
            return Err("package report summary does not match its records".to_owned());
        }
        Ok(())
    }
}
