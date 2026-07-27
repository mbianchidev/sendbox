#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sendbox_config::RuntimeProvider;
use sendbox_core::{BoundaryPlanDigest, SessionId};
use sendbox_security::SecurityError;
use sendbox_security::provenance::{
    DetachedSignature, Identity, SignedSubject, SigningKeyMaterial, SubjectKind, TrustPolicy,
    TrustStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const BOUNDARY_PLAN_FORMAT: &str = "sendbox-boundary-plan";
pub const SIGNED_BOUNDARY_PLAN_FORMAT: &str = "sendbox-signed-boundary-plan";
pub const BOUNDARY_PLAN_VERSION: u16 = 1;
pub const MAX_BOUNDARY_PLAN_BYTES: usize = 1024 * 1024;
pub const MAX_BOUNDARY_PLAN_LIFETIME_SECS: u64 = 60 * 60;

#[derive(Debug, Error)]
pub enum BoundaryError {
    #[error("invalid boundary plan: {0}")]
    Invalid(String),
    #[error("unsupported host: {0}")]
    UnsupportedHost(String),
    #[error("boundary plan encoding failed: {0}")]
    Encoding(#[source] serde_json::Error),
    #[error(transparent)]
    Security(#[from] SecurityError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Macos,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    Aarch64,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPlatform {
    pub operating_system: OperatingSystem,
    pub architecture: Architecture,
}

impl HostPlatform {
    pub fn current() -> Result<Self, BoundaryError> {
        let operating_system = match std::env::consts::OS {
            "macos" => OperatingSystem::Macos,
            "linux" => OperatingSystem::Linux,
            value => {
                return Err(BoundaryError::UnsupportedHost(format!(
                    "operating system `{value}` is not supported"
                )));
            }
        };
        let architecture = match std::env::consts::ARCH {
            "aarch64" => Architecture::Aarch64,
            "x86_64" => Architecture::X86_64,
            value => {
                return Err(BoundaryError::UnsupportedHost(format!(
                    "architecture `{value}` is not supported"
                )));
            }
        };
        Ok(Self {
            operating_system,
            architecture,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedRuntime {
    Apple,
    Kata,
    Hyperlight,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRejection {
    pub runtime: ResolvedRuntime,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSelection {
    pub requested: RuntimeProvider,
    pub selected: ResolvedRuntime,
    pub host: HostPlatform,
    pub reason: String,
    pub rejected: Vec<RuntimeRejection>,
}

pub fn select_runtime(
    requested: RuntimeProvider,
    host: HostPlatform,
) -> Result<RuntimeSelection, BoundaryError> {
    let selected = match requested {
        RuntimeProvider::Auto => match host {
            HostPlatform {
                operating_system: OperatingSystem::Macos,
                architecture: Architecture::Aarch64,
            } => ResolvedRuntime::Apple,
            HostPlatform {
                operating_system: OperatingSystem::Linux,
                ..
            } => ResolvedRuntime::Kata,
            _ => {
                return Err(BoundaryError::UnsupportedHost(
                    "automatic runtime selection supports macOS arm64 or Linux".to_owned(),
                ));
            }
        },
        RuntimeProvider::Apple => {
            require_host(
                host,
                OperatingSystem::Macos,
                Some(Architecture::Aarch64),
                "Apple runtime requires macOS arm64",
            )?;
            ResolvedRuntime::Apple
        }
        RuntimeProvider::Kata => {
            require_host(
                host,
                OperatingSystem::Linux,
                None,
                "Kata runtime requires Linux",
            )?;
            ResolvedRuntime::Kata
        }
        RuntimeProvider::Hyperlight => {
            require_host(
                host,
                OperatingSystem::Linux,
                None,
                "Hyperlight runtime requires Linux with KVM",
            )?;
            ResolvedRuntime::Hyperlight
        }
    };
    let reason = match (requested, selected) {
        (RuntimeProvider::Auto, ResolvedRuntime::Apple) => {
            "auto selected Apple on macOS arm64".to_owned()
        }
        (RuntimeProvider::Auto, ResolvedRuntime::Kata) => "auto selected Kata on Linux".to_owned(),
        _ => format!("explicitly selected {}", runtime_name(selected)),
    };
    let rejected = if requested == RuntimeProvider::Auto {
        ResolvedRuntime::all()
            .into_iter()
            .filter(|candidate| *candidate != selected)
            .map(|runtime| RuntimeRejection {
                runtime,
                reason: rejection_reason(runtime, host),
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(RuntimeSelection {
        requested,
        selected,
        host,
        reason,
        rejected,
    })
}

impl ResolvedRuntime {
    const fn all() -> [Self; 3] {
        [Self::Apple, Self::Kata, Self::Hyperlight]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageIdentity {
    pub reference: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDeclaration {
    pub program: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountDeclaration {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentDeclaration {
    pub name: String,
    pub value_sha256: String,
    pub sensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    RuntimeExecutable,
    GuestBundleManifest,
    TrustRoot,
    Kernel,
    Initrd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub kind: ArtifactKind,
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureDecision {
    Enforced,
    Rejected,
    NotRequested,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureAdmission {
    pub decision: FeatureDecision,
    pub mechanism: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDeclaration {
    pub cpus: u32,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryPlan {
    pub format: String,
    pub version: u16,
    pub session_id: SessionId,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub selection: RuntimeSelection,
    pub configuration_sha256: String,
    pub policy_sha256: String,
    pub image: ImageIdentity,
    pub command: CommandDeclaration,
    pub workspace: MountDeclaration,
    pub mounts: Vec<MountDeclaration>,
    pub environment: Vec<EnvironmentDeclaration>,
    pub secrets: Vec<String>,
    pub artifacts: Vec<ArtifactIdentity>,
    pub resources: ResourceDeclaration,
    pub features: BTreeMap<String, FeatureAdmission>,
}

impl BoundaryPlan {
    pub fn validate(&self, now_unix: u64) -> Result<(), BoundaryError> {
        if self.format != BOUNDARY_PLAN_FORMAT || self.version != BOUNDARY_PLAN_VERSION {
            return Err(BoundaryError::Invalid(
                "unsupported boundary plan format or version".to_owned(),
            ));
        }
        if self.created_at_unix > now_unix
            || self.expires_at_unix < now_unix
            || self.expires_at_unix < self.created_at_unix
            || self.expires_at_unix.saturating_sub(self.created_at_unix)
                > MAX_BOUNDARY_PLAN_LIFETIME_SECS
        {
            return Err(BoundaryError::Invalid(
                "boundary plan validity window is invalid".to_owned(),
            ));
        }
        validate_selection(&self.selection)?;
        validate_digest(&self.configuration_sha256, "configuration")?;
        validate_digest(&self.policy_sha256, "policy")?;
        validate_image(&self.image)?;
        validate_command(&self.command)?;
        validate_mount(&self.workspace, "workspace")?;
        for mount in &self.mounts {
            validate_mount(mount, "mount")?;
        }
        validate_environment(&self.environment)?;
        validate_secret_names(&self.secrets)?;
        validate_artifacts(&self.artifacts)?;
        if self.resources.cpus == 0 || self.resources.memory_bytes == 0 {
            return Err(BoundaryError::Invalid(
                "runtime resources must be greater than zero".to_owned(),
            ));
        }
        for (feature, admission) in &self.features {
            if feature.is_empty()
                || feature.chars().any(char::is_control)
                || admission.mechanism.is_empty()
                || admission.mechanism.chars().any(char::is_control)
            {
                return Err(BoundaryError::Invalid(
                    "feature admissions must have printable names and mechanisms".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, BoundaryError> {
        encode_canonical(self)
    }

    pub fn digest(&self) -> Result<BoundaryPlanDigest, BoundaryError> {
        Ok(BoundaryPlanDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    pub fn digest_hex(&self) -> Result<String, BoundaryError> {
        self.digest().map(|digest| digest.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBoundaryPlan {
    pub format: String,
    pub version: u16,
    pub plan: BoundaryPlan,
    pub signer: Identity,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBoundaryPlan {
    signed: SignedBoundaryPlan,
    plan_digest: BoundaryPlanDigest,
    signer_fingerprint: String,
}

impl SignedBoundaryPlan {
    pub fn sign(
        plan: BoundaryPlan,
        key: &SigningKeyMaterial,
        signed_at_unix: u64,
    ) -> Result<Self, BoundaryError> {
        plan.validate(signed_at_unix)?;
        let plan_bytes = plan.encode()?;
        let signer = key.identity("SendBox local runtime", None, 0, None);
        let mut metadata = BTreeMap::new();
        metadata.insert("format".to_owned(), BOUNDARY_PLAN_FORMAT.to_owned());
        metadata.insert("session_id".to_owned(), plan.session_id.to_string());
        metadata.insert(
            "runtime".to_owned(),
            runtime_name(plan.selection.selected).to_owned(),
        );
        let signature = DetachedSignature::sign(
            SignedSubject::from_bytes(
                SubjectKind::Configuration,
                Some(format!("boundary-plan:{}", plan.session_id)),
                &plan_bytes,
            ),
            key,
            signed_at_unix,
            Some(plan.expires_at_unix),
            metadata,
        )?;
        Ok(Self {
            format: SIGNED_BOUNDARY_PLAN_FORMAT.to_owned(),
            version: BOUNDARY_PLAN_VERSION,
            plan,
            signer,
            signature,
        })
    }

    pub fn verify(
        &self,
        expected_signer_fingerprint: &str,
        now_unix: u64,
    ) -> Result<VerifiedBoundaryPlan, BoundaryError> {
        let plan_digest = self.verify_inner(expected_signer_fingerprint, now_unix)?;
        Ok(VerifiedBoundaryPlan {
            signed: self.clone(),
            plan_digest,
            signer_fingerprint: expected_signer_fingerprint.to_owned(),
        })
    }

    fn verify_inner(
        &self,
        expected_signer_fingerprint: &str,
        now_unix: u64,
    ) -> Result<BoundaryPlanDigest, BoundaryError> {
        if self.format != SIGNED_BOUNDARY_PLAN_FORMAT || self.version != BOUNDARY_PLAN_VERSION {
            return Err(BoundaryError::Invalid(
                "unsupported signed boundary plan format or version".to_owned(),
            ));
        }
        if self.signer.fingerprint != expected_signer_fingerprint
            || self.signature.signer_fingerprint != expected_signer_fingerprint
        {
            return Err(BoundaryError::Invalid(
                "boundary plan signer does not match the expected host identity".to_owned(),
            ));
        }
        self.plan.validate(now_unix)?;
        let plan_bytes = self.plan.encode()?;
        let expected_subject_name = format!("boundary-plan:{}", self.plan.session_id);
        if self.signature.subject.name.as_deref() != Some(expected_subject_name.as_str()) {
            return Err(BoundaryError::Invalid(
                "boundary plan signature subject name is invalid".to_owned(),
            ));
        }
        let mut required_signers = BTreeSet::new();
        required_signers.insert(expected_signer_fingerprint.to_owned());
        let mut trust = TrustStore::new(TrustPolicy {
            allow_unsigned: false,
            threshold: 1,
            required_signers,
        });
        trust.add_identity(self.signer.clone())?;
        trust.verify(
            &plan_bytes,
            SubjectKind::Configuration,
            std::slice::from_ref(&self.signature),
            now_unix,
        )?;
        Ok(BoundaryPlanDigest::from_bytes(
            Sha256::digest(&plan_bytes).into(),
        ))
    }

    pub fn encode(&self) -> Result<Vec<u8>, BoundaryError> {
        encode_canonical(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BoundaryError> {
        if bytes.len() > MAX_BOUNDARY_PLAN_BYTES {
            return Err(BoundaryError::Invalid(format!(
                "signed boundary plan exceeds {MAX_BOUNDARY_PLAN_BYTES} bytes"
            )));
        }
        let plan: Self = serde_json::from_slice(bytes).map_err(BoundaryError::Encoding)?;
        if plan.encode()? != bytes {
            return Err(BoundaryError::Invalid(
                "signed boundary plan uses non-canonical encoding".to_owned(),
            ));
        }
        Ok(plan)
    }
}

impl VerifiedBoundaryPlan {
    #[must_use]
    pub const fn plan(&self) -> &BoundaryPlan {
        &self.signed.plan
    }

    #[must_use]
    pub const fn digest(&self) -> BoundaryPlanDigest {
        self.plan_digest
    }

    #[must_use]
    pub fn signer_fingerprint(&self) -> &str {
        &self.signer_fingerprint
    }

    #[must_use]
    pub const fn signed_plan(&self) -> &SignedBoundaryPlan {
        &self.signed
    }

    pub fn reverify(&self, now_unix: u64) -> Result<(), BoundaryError> {
        let digest = self
            .signed
            .verify_inner(&self.signer_fingerprint, now_unix)?;
        if digest != self.plan_digest {
            return Err(BoundaryError::Invalid(
                "verified boundary plan digest changed".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn require_host(
    host: HostPlatform,
    operating_system: OperatingSystem,
    architecture: Option<Architecture>,
    message: &str,
) -> Result<(), BoundaryError> {
    if host.operating_system != operating_system
        || architecture.is_some_and(|required| host.architecture != required)
    {
        return Err(BoundaryError::UnsupportedHost(message.to_owned()));
    }
    Ok(())
}

fn rejection_reason(runtime: ResolvedRuntime, host: HostPlatform) -> String {
    match runtime {
        ResolvedRuntime::Apple => {
            if host.operating_system == OperatingSystem::Macos
                && host.architecture == Architecture::Aarch64
            {
                "not selected because auto admits one provider".to_owned()
            } else {
                "Apple requires macOS arm64".to_owned()
            }
        }
        ResolvedRuntime::Kata => {
            if host.operating_system == OperatingSystem::Linux {
                "not selected because auto admits one provider".to_owned()
            } else {
                "Kata requires Linux".to_owned()
            }
        }
        ResolvedRuntime::Hyperlight => "Hyperlight is explicit-only".to_owned(),
    }
}

const fn runtime_name(runtime: ResolvedRuntime) -> &'static str {
    match runtime {
        ResolvedRuntime::Apple => "apple",
        ResolvedRuntime::Kata => "kata",
        ResolvedRuntime::Hyperlight => "hyperlight",
    }
}

fn validate_selection(selection: &RuntimeSelection) -> Result<(), BoundaryError> {
    let expected = select_runtime(selection.requested, selection.host)?;
    if &expected != selection {
        return Err(BoundaryError::Invalid(
            "runtime selection does not match fail-closed host rules".to_owned(),
        ));
    }
    Ok(())
}

fn validate_image(image: &ImageIdentity) -> Result<(), BoundaryError> {
    let digest = image
        .digest
        .strip_prefix("sha256:")
        .ok_or_else(|| BoundaryError::Invalid("image digest must use sha256".to_owned()))?;
    validate_digest(digest, "image")?;
    let suffix = format!("@{}", image.digest);
    if image.reference.trim().is_empty() || !image.reference.ends_with(&suffix) {
        return Err(BoundaryError::Invalid(
            "image reference must end with its immutable digest".to_owned(),
        ));
    }
    Ok(())
}

fn validate_command(command: &CommandDeclaration) -> Result<(), BoundaryError> {
    if !Path::new(&command.program).is_absolute()
        || !Path::new(&command.working_directory).is_absolute()
        || command.program.as_bytes().contains(&0)
        || command.working_directory.as_bytes().contains(&0)
        || command
            .arguments
            .iter()
            .any(|argument| argument.as_bytes().contains(&0))
    {
        return Err(BoundaryError::Invalid(
            "command paths must be absolute and argv must not contain NUL".to_owned(),
        ));
    }
    Ok(())
}

fn validate_mount(mount: &MountDeclaration, subject: &str) -> Result<(), BoundaryError> {
    if !mount.source.is_absolute() || !mount.destination.is_absolute() {
        return Err(BoundaryError::Invalid(format!(
            "{subject} paths must be absolute"
        )));
    }
    Ok(())
}

fn validate_environment(environment: &[EnvironmentDeclaration]) -> Result<(), BoundaryError> {
    let mut names = BTreeSet::new();
    for entry in environment {
        if entry.name.is_empty()
            || entry.name.contains('=')
            || entry.name.chars().any(char::is_control)
            || !names.insert(entry.name.as_str())
        {
            return Err(BoundaryError::Invalid(
                "environment names must be unique and valid".to_owned(),
            ));
        }
        validate_digest(&entry.value_sha256, "environment value")?;
    }
    Ok(())
}

fn validate_secret_names(secrets: &[String]) -> Result<(), BoundaryError> {
    let mut names = BTreeSet::new();
    if secrets.iter().any(|name| {
        name.is_empty() || name.chars().any(char::is_control) || !names.insert(name.as_str())
    }) {
        return Err(BoundaryError::Invalid(
            "secret names must be unique and valid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_artifacts(artifacts: &[ArtifactIdentity]) -> Result<(), BoundaryError> {
    let mut kinds = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for artifact in artifacts {
        if !artifact.path.is_absolute()
            || !kinds.insert(artifact.kind)
            || !paths.insert(artifact.path.as_path())
        {
            return Err(BoundaryError::Invalid(
                "artifact kinds and absolute paths must be unique".to_owned(),
            ));
        }
        validate_digest(&artifact.sha256, "artifact")?;
    }
    Ok(())
}

fn validate_digest(value: &str, subject: &str) -> Result<(), BoundaryError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BoundaryError::Invalid(format!(
            "{subject} digest must contain 64 hexadecimal characters"
        )));
    }
    Ok(())
}

fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, BoundaryError> {
    let encoded = serde_json::to_vec(value).map_err(BoundaryError::Encoding)?;
    if encoded.len() > MAX_BOUNDARY_PLAN_BYTES {
        return Err(BoundaryError::Invalid(format!(
            "boundary plan exceeds {MAX_BOUNDARY_PLAN_BYTES} bytes"
        )));
    }
    Ok(encoded)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux() -> HostPlatform {
        HostPlatform {
            operating_system: OperatingSystem::Linux,
            architecture: Architecture::X86_64,
        }
    }

    fn macos() -> HostPlatform {
        HostPlatform {
            operating_system: OperatingSystem::Macos,
            architecture: Architecture::Aarch64,
        }
    }

    fn plan(now: u64) -> BoundaryPlan {
        BoundaryPlan {
            format: BOUNDARY_PLAN_FORMAT.to_owned(),
            version: BOUNDARY_PLAN_VERSION,
            session_id: SessionId::from_bytes([5; 16]),
            created_at_unix: now,
            expires_at_unix: now + 300,
            selection: select_runtime(RuntimeProvider::Auto, linux()).expect("selection"),
            configuration_sha256: "1".repeat(64),
            policy_sha256: "2".repeat(64),
            image: ImageIdentity {
                reference: format!("registry.example/workload@sha256:{}", "3".repeat(64)),
                digest: format!("sha256:{}", "3".repeat(64)),
            },
            command: CommandDeclaration {
                program: "/usr/bin/agent".to_owned(),
                arguments: vec!["run".to_owned()],
                working_directory: "/workspace".to_owned(),
            },
            workspace: MountDeclaration {
                source: PathBuf::from("/home/user/project"),
                destination: PathBuf::from("/workspace"),
                writable: true,
            },
            mounts: Vec::new(),
            environment: vec![EnvironmentDeclaration {
                name: "MODE".to_owned(),
                value_sha256: "4".repeat(64),
                sensitive: false,
            }],
            secrets: vec!["TOKEN".to_owned()],
            artifacts: vec![
                ArtifactIdentity {
                    kind: ArtifactKind::GuestBundleManifest,
                    path: PathBuf::from("/opt/sendbox/bundle/manifest.json"),
                    sha256: "5".repeat(64),
                },
                ArtifactIdentity {
                    kind: ArtifactKind::TrustRoot,
                    path: PathBuf::from("/opt/sendbox/trust/root.pub"),
                    sha256: "6".repeat(64),
                },
            ],
            resources: ResourceDeclaration {
                cpus: 2,
                memory_bytes: 512 * 1024 * 1024,
            },
            features: BTreeMap::from([(
                "command_policy".to_owned(),
                FeatureAdmission {
                    decision: FeatureDecision::Enforced,
                    mechanism: "authenticated guest broker".to_owned(),
                },
            )]),
        }
    }

    #[test]
    fn selection_is_host_specific_and_hyperlight_is_explicit_only() {
        let apple = select_runtime(RuntimeProvider::Auto, macos()).expect("Apple auto selection");
        assert_eq!(apple.selected, ResolvedRuntime::Apple);
        assert!(apple.rejected.iter().any(|rejection| {
            rejection.runtime == ResolvedRuntime::Hyperlight
                && rejection.reason == "Hyperlight is explicit-only"
        }));

        let kata = select_runtime(RuntimeProvider::Auto, linux()).expect("Kata auto selection");
        assert_eq!(kata.selected, ResolvedRuntime::Kata);
        assert!(
            select_runtime(RuntimeProvider::Apple, linux()).is_err(),
            "explicit providers must not fall back"
        );
        assert_eq!(
            select_runtime(RuntimeProvider::Hyperlight, linux())
                .expect("explicit Hyperlight")
                .selected,
            ResolvedRuntime::Hyperlight
        );
    }

    #[test]
    fn signed_plan_verifies_only_for_the_expected_host_identity() {
        let now = 10_000;
        let key = SigningKeyMaterial::generate().expect("signing key");
        let expected = key.identity("expected", None, 0, None).fingerprint;
        let signed = SignedBoundaryPlan::sign(plan(now), &key, now).expect("signed plan");
        let verified = signed.verify(&expected, now).expect("verified plan");
        assert_eq!(verified.digest(), signed.plan.digest().expect("digest"));
        assert_eq!(verified.plan(), &signed.plan);
        assert_eq!(verified.signer_fingerprint(), expected);
        verified.reverify(now).expect("reverify");
        assert!(signed.verify(&"f".repeat(64), now).is_err());
    }

    #[test]
    fn signature_detects_plan_mutation() {
        let now = 20_000;
        let key = SigningKeyMaterial::generate().expect("signing key");
        let expected = key.identity("expected", None, 0, None).fingerprint;
        let mut signed = SignedBoundaryPlan::sign(plan(now), &key, now).expect("signed plan");
        signed.plan.resources.cpus = 4;
        assert!(signed.verify(&expected, now).is_err());
    }

    #[test]
    fn decode_rejects_noncanonical_and_mutable_inputs() {
        let now = 30_000;
        let key = SigningKeyMaterial::generate().expect("signing key");
        let signed = SignedBoundaryPlan::sign(plan(now), &key, now).expect("signed plan");
        let encoded = signed.encode().expect("encode");
        assert_eq!(
            SignedBoundaryPlan::decode(&encoded)
                .expect("canonical signed plan")
                .plan,
            signed.plan
        );

        let mut value: serde_json::Value =
            serde_json::from_slice(&encoded).expect("signed plan JSON");
        let object = value.as_object_mut().expect("signed plan object");
        let format = object.remove("format").expect("format");
        object.insert("format".to_owned(), format);
        let reordered = serde_json::to_vec(&value).expect("reordered JSON");
        assert!(SignedBoundaryPlan::decode(&reordered).is_err());

        let mut mutable = plan(now);
        mutable.image.reference = "registry.example/workload:latest".to_owned();
        assert!(mutable.validate(now).is_err());
    }

    #[test]
    fn verified_plan_rejects_expiry_on_revalidation() {
        let now = 40_000;
        let key = SigningKeyMaterial::generate().expect("signing key");
        let expected = key.identity("expected", None, 0, None).fingerprint;
        let verified = SignedBoundaryPlan::sign(plan(now), &key, now)
            .expect("signed plan")
            .verify(&expected, now)
            .expect("verified plan");
        assert!(verified.reverify(now + 301).is_err());
    }
}
