//! Operator governance configuration, signed profile verification, and
//! rollback protection.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sendbox_governance::{
    AuthorityRef, Clock, CurrentProfile, GovernanceError, GovernanceProfile, ProfileId, ProfileRef,
    RevisionSource, Sha256Digest, canonical_digest, profile::MAX_PROFILE_BYTES,
};
use sendbox_security::fs::{TrustedOwnership, read_trusted_file};
use sendbox_security::provenance::{
    DetachedSignature, Identity, SubjectKind, TrustPolicy, TrustStore,
};
use serde::{Deserialize, Serialize};

use crate::HostError;

#[cfg(target_os = "macos")]
pub const MANAGED_CONFIGURATION_PATH: &str = "/Library/Application Support/SendBox/governance.yaml";
#[cfg(not(target_os = "macos"))]
pub const MANAGED_CONFIGURATION_PATH: &str = "/etc/sendbox/governance.yaml";

pub const OPERATOR_FORMAT: &str = "sendbox.governance-operator";
pub const SIGNATURES_FORMAT: &str = "sendbox.governance-signatures";
const FORMAT_VERSION: u32 = 1;
const MAX_OPERATOR_BYTES: u64 = 256 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 256 * 1024;
const MAX_TRUST_ROOT_BYTES: u64 = 64 * 1024;
const MAX_SIGNERS: usize = 32;
const MAX_REVISION_CACHE_SECONDS: u64 = 300;
const SIGNATURE_SUFFIX: &str = ".sig.json";

/// How governance was selected for this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceMode {
    /// A root-owned operator configuration exists; governance is mandatory.
    Managed,
    /// The user selected a configuration explicitly on an unmanaged host.
    OptIn,
}

/// Where the operator configuration comes from and who may own it.
#[derive(Debug, Clone)]
pub struct GovernanceSource {
    pub mode: GovernanceMode,
    pub path: PathBuf,
    pub ownership: TrustedOwnership,
}

impl GovernanceSource {
    /// Selects the governance authority. A managed configuration always wins
    /// and cannot be replaced by a caller-supplied path.
    pub fn discover(
        managed_path: &Path,
        opt_in: Option<&Path>,
        uid: u32,
    ) -> Result<Option<Self>, HostError> {
        match std::fs::symlink_metadata(managed_path) {
            Ok(_) => {
                if opt_in.is_some_and(|path| path != managed_path) {
                    return Err(HostError::Governance(format!(
                        "this host is managed by {}; --governance-config cannot select a different policy authority",
                        managed_path.display()
                    )));
                }
                Ok(Some(Self {
                    mode: GovernanceMode::Managed,
                    path: managed_path.to_path_buf(),
                    ownership: TrustedOwnership::Root,
                }))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(opt_in.map(|path| Self {
                    mode: GovernanceMode::OptIn,
                    path: path.to_path_buf(),
                    ownership: TrustedOwnership::RootOrUser(uid),
                }))
            }
            Err(source) => Err(HostError::Governance(format!(
                "cannot determine whether {} requires governance: {source}",
                managed_path.display()
            ))),
        }
    }

    pub fn load(&self) -> Result<OperatorConfiguration, HostError> {
        let bytes = read_trusted_file(&self.path, self.ownership, MAX_OPERATOR_BYTES)
            .map_err(|error| HostError::Governance(format!("operator configuration: {error}")))?;
        OperatorConfiguration::parse(&bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorConfiguration {
    pub format: String,
    pub version: u32,
    #[serde(default = "local_authority")]
    pub authority: String,
    pub profile: ProfileId,
    pub profile_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures_path: Option<PathBuf>,
    pub minimum_revision: u64,
    pub trust: OperatorTrust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<BundlePin>,
    #[serde(default = "default_revision_cache_seconds")]
    pub revision_cache_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorTrust {
    pub threshold: usize,
    pub signers: Vec<Identity>,
}

/// Pins the guest bundle trust root that `sendbox run` may use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundlePin {
    pub trust_root_sha256: Vec<Sha256Digest>,
    pub trust_root_ids: Vec<String>,
    pub minimum_release_sequence: u64,
}

fn local_authority() -> String {
    "local".to_owned()
}

const fn default_revision_cache_seconds() -> u64 {
    30
}

#[derive(Serialize)]
struct TrustDigestInput<'a> {
    threshold: usize,
    signers: BTreeSet<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureBundle {
    format: String,
    version: u32,
    signatures: Vec<serde_json::Value>,
}

impl OperatorConfiguration {
    pub fn parse(bytes: &[u8]) -> Result<Self, HostError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| HostError::Governance("operator configuration is not UTF-8".to_owned()))?;
        let configuration: Self = serde_yaml_ng::from_str(text)
            .map_err(|error| HostError::Governance(format!("operator configuration: {error}")))?;
        configuration.validate()?;
        Ok(configuration)
    }

    fn validate(&self) -> Result<(), HostError> {
        let invalid = |message: &str| {
            Err(HostError::Governance(format!(
                "operator configuration: {message}"
            )))
        };
        if self.format != OPERATOR_FORMAT || self.version != FORMAT_VERSION {
            return invalid(&format!(
                "format must be `{OPERATOR_FORMAT}` version {FORMAT_VERSION}"
            ));
        }
        if self.authority.is_empty()
            || self.authority.len() > 128
            || !self.authority.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return invalid("authority must be 1-128 printable ASCII bytes");
        }
        if !self.profile_path.is_absolute()
            || self
                .signatures_path
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
        {
            return invalid("profile and signature paths must be absolute");
        }
        if self.minimum_revision == 0 {
            return invalid("minimum_revision must be at least 1");
        }
        let fingerprints = self
            .trust
            .signers
            .iter()
            .map(|signer| signer.fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        if self.trust.signers.is_empty()
            || self.trust.signers.len() > MAX_SIGNERS
            || fingerprints.len() != self.trust.signers.len()
        {
            return invalid(&format!(
                "trust.signers must list 1-{MAX_SIGNERS} distinct identities"
            ));
        }
        if self.trust.threshold == 0 || self.trust.threshold > self.trust.signers.len() {
            return invalid("trust.threshold must be between 1 and the number of signers");
        }
        if !(1..=MAX_REVISION_CACHE_SECONDS).contains(&self.revision_cache_seconds) {
            return invalid(&format!(
                "revision_cache_seconds must be 1..={MAX_REVISION_CACHE_SECONDS}"
            ));
        }
        if let Some(bundle) = &self.bundle
            && (bundle.trust_root_sha256.is_empty() || bundle.trust_root_ids.is_empty())
        {
            return invalid("bundle pins require at least one trust root digest and id");
        }
        self.trust_store()?;
        Ok(())
    }

    #[must_use]
    pub fn signatures_path(&self) -> PathBuf {
        self.signatures_path.clone().unwrap_or_else(|| {
            let mut path = self.profile_path.clone().into_os_string();
            path.push(SIGNATURE_SUFFIX);
            PathBuf::from(path)
        })
    }

    fn trust_store(&self) -> Result<TrustStore, HostError> {
        let mut store = TrustStore::new(TrustPolicy {
            allow_unsigned: false,
            threshold: self.trust.threshold,
            required_signers: BTreeSet::new(),
        });
        for signer in &self.trust.signers {
            store.add_identity(signer.clone()).map_err(|error| {
                HostError::Governance(format!("operator trust signer: {error}"))
            })?;
        }
        Ok(store)
    }

    pub fn authority(&self) -> Result<AuthorityRef, HostError> {
        let trust_sha256 = canonical_digest(&TrustDigestInput {
            threshold: self.trust.threshold,
            signers: self
                .trust
                .signers
                .iter()
                .map(|signer| signer.fingerprint.as_str())
                .collect(),
        })
        .map_err(governance_error)?;
        Ok(AuthorityRef {
            id: self.authority.clone(),
            trust_sha256,
        })
    }

    /// Rejects a guest bundle trust root the operator has not pinned.
    ///
    /// The pinned file must meet the same ownership rule as the governance
    /// configuration. In managed mode that means root-owned with protected
    /// ancestors, so the caller cannot replace it after this check and before
    /// the bundle is verified and launched from the same path.
    pub fn verify_bundle(
        &self,
        trust_root: &Path,
        ownership: TrustedOwnership,
        trust_root_id: &str,
        minimum_release_sequence: u64,
    ) -> Result<(), HostError> {
        let Some(pin) = &self.bundle else {
            return Ok(());
        };
        let canonical = std::fs::canonicalize(trust_root).map_err(|source| HostError::Io {
            context: "resolve bundle trust root",
            path: trust_root.to_path_buf(),
            source,
        })?;
        let bytes = read_trusted_file(&canonical, ownership, MAX_TRUST_ROOT_BYTES)
            .map_err(|error| HostError::Governance(format!("bundle trust root: {error}")))?;
        if !pin.trust_root_sha256.contains(&Sha256Digest::of(&bytes)) {
            return Err(HostError::Governance(
                "the guest bundle trust root is not pinned by the operator".to_owned(),
            ));
        }
        if !pin.trust_root_ids.iter().any(|id| id == trust_root_id) {
            return Err(HostError::Governance(format!(
                "bundle trust root id `{trust_root_id}` is not pinned by the operator"
            )));
        }
        if minimum_release_sequence < pin.minimum_release_sequence {
            return Err(HostError::Governance(format!(
                "--minimum-release-sequence must be at least {}",
                pin.minimum_release_sequence
            )));
        }
        Ok(())
    }
}

/// A profile whose exact bytes were verified against the operator trust.
#[derive(Debug, Clone)]
pub struct VerifiedProfile {
    pub profile: GovernanceProfile,
    pub reference: ProfileRef,
    pub authority: AuthorityRef,
    pub minimum_revision: u64,
    pub signers: BTreeSet<String>,
}

pub fn verify_profile(
    source: &GovernanceSource,
    operator: &OperatorConfiguration,
    now_unix: u64,
) -> Result<VerifiedProfile, HostError> {
    let bytes = read_trusted_file(
        &operator.profile_path,
        source.ownership,
        MAX_PROFILE_BYTES as u64,
    )
    .map_err(|error| HostError::Governance(format!("governance profile: {error}")))?;
    let signatures = read_signatures(&operator.signatures_path(), source.ownership)?;
    let verified = operator
        .trust_store()?
        .verify(&bytes, SubjectKind::Configuration, &signatures, now_unix)
        .map_err(|error| {
            HostError::Governance(format!(
                "governance profile signature verification failed: {error}"
            ))
        })?;
    let profile = GovernanceProfile::parse(&bytes).map_err(governance_error)?;
    if profile.id != operator.profile {
        return Err(HostError::Governance(format!(
            "profile `{}` is not the required profile `{}`",
            profile.id, operator.profile
        )));
    }
    if profile.revision < operator.minimum_revision {
        return Err(HostError::Governance(format!(
            "profile `{}` revision {} is older than the operator minimum {}",
            profile.id, profile.revision, operator.minimum_revision
        )));
    }
    profile.check_validity(now_unix).map_err(governance_error)?;
    Ok(VerifiedProfile {
        reference: profile.reference(&bytes),
        profile,
        authority: operator.authority()?,
        minimum_revision: operator.minimum_revision,
        signers: verified.valid_signers,
    })
}

fn read_signatures(
    path: &Path,
    ownership: TrustedOwnership,
) -> Result<Vec<DetachedSignature>, HostError> {
    let bytes = read_trusted_file(path, ownership, MAX_SIGNATURE_BYTES)
        .map_err(|error| HostError::Governance(format!("governance signatures: {error}")))?;
    let bundle: SignatureBundle = serde_json::from_slice(&bytes)
        .map_err(|error| HostError::Governance(format!("governance signatures: {error}")))?;
    if bundle.format != SIGNATURES_FORMAT || bundle.version != FORMAT_VERSION {
        return Err(HostError::Governance(format!(
            "governance signatures must use format `{SIGNATURES_FORMAT}` version {FORMAT_VERSION}"
        )));
    }
    bundle
        .signatures
        .into_iter()
        .map(|value| {
            let signature: DetachedSignature = serde_json::from_value(value)
                .map_err(|error| HostError::Governance(format!("governance signature: {error}")))?;
            let canonical = signature
                .encode()
                .map_err(|error| HostError::Governance(format!("governance signature: {error}")))?;
            DetachedSignature::decode(&canonical)
                .map_err(|error| HostError::Governance(format!("governance signature: {error}")))
        })
        .collect()
}

/// Encodes signatures in the bundle format `verify_profile` reads.
pub fn encode_signatures(signatures: &[DetachedSignature]) -> Result<Vec<u8>, HostError> {
    #[derive(Serialize)]
    struct Output<'a> {
        format: &'static str,
        version: u32,
        signatures: &'a [DetachedSignature],
    }
    let mut bytes = serde_json::to_vec_pretty(&Output {
        format: SIGNATURES_FORMAT,
        version: FORMAT_VERSION,
        signatures,
    })
    .map_err(|error| HostError::Governance(format!("encode signatures: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Highest admitted revision per authority and profile. Rejects a profile
/// rollback that is still inside its validity window. The operator minimum
/// revision is authoritative; this record adds per-host protection.
pub struct RevisionHighWater {
    path: PathBuf,
}

impl RevisionHighWater {
    pub fn open(state_root: &Path) -> Result<Self, HostError> {
        let directory = state_root.join("governance");
        crate::ensure_private_directory(&directory)?;
        Ok(Self {
            path: directory.join("revision-high-water.json"),
        })
    }

    fn key(authority: &AuthorityRef, profile: &ProfileRef) -> String {
        format!("{}/{}/{}", authority.id, authority.trust_sha256, profile.id)
    }

    fn read(&self) -> Result<BTreeMap<String, u64>, HostError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                HostError::Governance(format!(
                    "revision record {} is corrupt: {error}",
                    self.path.display()
                ))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(source) => Err(HostError::Io {
                context: "read governance revision record",
                path: self.path.clone(),
                source,
            }),
        }
    }

    pub fn check(&self, authority: &AuthorityRef, profile: &ProfileRef) -> Result<(), HostError> {
        let recorded = self
            .read()?
            .get(&Self::key(authority, profile))
            .copied()
            .unwrap_or(0);
        if profile.revision < recorded {
            return Err(HostError::Governance(format!(
                "profile `{}` revision {} is older than revision {recorded} already admitted on this host",
                profile.id, profile.revision
            )));
        }
        Ok(())
    }

    pub fn record(&self, authority: &AuthorityRef, profile: &ProfileRef) -> Result<(), HostError> {
        let mut records = self.read()?;
        let entry = records.entry(Self::key(authority, profile)).or_insert(0);
        if profile.revision > *entry {
            *entry = profile.revision;
            let bytes = serde_json::to_vec_pretty(&records).map_err(|error| {
                HostError::Governance(format!("encode revision record: {error}"))
            })?;
            crate::atomic_write(&self.path, &bytes, 0o600)?;
        }
        Ok(())
    }
}

/// Re-verifies the operator configuration and profile for the local grant
/// authority, so revocation by revision or removal takes effect within the
/// configured cache interval.
pub struct OperatorRevisionSource {
    source: GovernanceSource,
    clock: Arc<dyn Clock>,
    cache: Mutex<Option<(Instant, CurrentProfile)>>,
}

impl OperatorRevisionSource {
    #[must_use]
    pub fn new(source: GovernanceSource, clock: Arc<dyn Clock>) -> Self {
        Self {
            source,
            clock,
            cache: Mutex::new(None),
        }
    }

    fn reload(&self) -> Result<(CurrentProfile, Duration), HostError> {
        let operator = self.source.load()?;
        let verified = verify_profile(&self.source, &operator, self.clock.now_unix())?;
        Ok((
            CurrentProfile {
                reference: verified.reference,
                minimum_revision: verified.minimum_revision,
                expires_at_unix: verified.profile.expires_at_unix,
            },
            Duration::from_secs(operator.revision_cache_seconds),
        ))
    }
}

impl RevisionSource for OperatorRevisionSource {
    fn current(&self, _profile: &ProfileId) -> Result<CurrentProfile, GovernanceError> {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((valid_until, current)) = cache.as_ref()
            && Instant::now() < *valid_until
        {
            return Ok(current.clone());
        }
        *cache = None;
        let (current, ttl) = self
            .reload()
            .map_err(|error| GovernanceError::AuthorityUnavailable(error.to_string()))?;
        *cache = Some((Instant::now() + ttl, current.clone()));
        Ok(current)
    }
}

pub(crate) fn governance_error(error: GovernanceError) -> HostError {
    HostError::Governance(error.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt;

    use sendbox_security::provenance::{SignedSubject, SigningKeyMaterial};

    use super::*;

    pub(crate) const PROFILE: &str = r#"format: sendbox.governance-profile
version: 1
id: acme
revision: 4
not_before_unix: 0
expires_at_unix: 30000000
ceiling:
  runtimes: [apple, kata]
  commands:
    default_action: deny
    allowlist: ["git *"]
  network:
    default_action: deny
    allowed_domains: ["*.github.com"]
credential_services:
  - id: anthropic
    provider: anthropic
    secret: SENDBOX_ANTHROPIC_API_KEY
"#;

    pub(crate) struct Fixture {
        pub directory: tempfile::TempDir,
        pub key: SigningKeyMaterial,
        pub source: GovernanceSource,
    }

    pub(crate) fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::Builder::new()
            .prefix(".governance-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        directory
    }

    pub(crate) fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }

    pub(crate) fn sign(key: &SigningKeyMaterial, bytes: &[u8]) -> Vec<u8> {
        let signature = DetachedSignature::sign(
            SignedSubject::from_bytes(SubjectKind::Configuration, None, bytes),
            key,
            1,
            None,
            BTreeMap::new(),
        )
        .expect("sign");
        encode_signatures(&[signature]).expect("encode")
    }

    pub(crate) fn test_operator(
        identity: Identity,
        profile_path: PathBuf,
        minimum_revision: u64,
    ) -> OperatorConfiguration {
        OperatorConfiguration {
            format: OPERATOR_FORMAT.to_owned(),
            version: FORMAT_VERSION,
            authority: "local".to_owned(),
            profile: ProfileId::new("acme").unwrap(),
            profile_path,
            signatures_path: None,
            minimum_revision,
            trust: OperatorTrust {
                threshold: 1,
                signers: vec![identity],
            },
            bundle: None,
            revision_cache_seconds: 1,
        }
    }

    pub(crate) fn fixture(profile: &str, minimum_revision: u64) -> Fixture {
        let directory = private_directory();
        let key = SigningKeyMaterial::generate().expect("key");
        let identity = key.identity("Operator", None, 0, None);
        let profile_path = directory.path().join("acme.yaml");
        write_private(&profile_path, profile.as_bytes());
        write_private(
            &directory.path().join("acme.yaml.sig.json"),
            &sign(&key, profile.as_bytes()),
        );
        let operator = test_operator(
            identity,
            std::fs::canonicalize(directory.path())
                .unwrap()
                .join("acme.yaml"),
            minimum_revision,
        );
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("governance.yaml");
        write_private(
            &path,
            serde_yaml_ng::to_string(&operator).unwrap().as_bytes(),
        );
        let source = GovernanceSource {
            mode: GovernanceMode::OptIn,
            path,
            ownership: TrustedOwnership::RootOrUser(crate::current_uid()),
        };
        Fixture {
            directory,
            key,
            source,
        }
    }

    pub(crate) fn protected_test_tree() -> bool {
        use std::os::unix::fs::MetadataExt;
        let uid = crate::current_uid();
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .all(|ancestor| {
                std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                    (metadata.uid() == 0 || metadata.uid() == uid) && metadata.mode() & 0o022 == 0
                })
            })
    }

    #[test]
    fn managed_configuration_cannot_be_replaced_by_the_caller() {
        let directory = private_directory();
        let managed = directory.path().join("managed.yaml");
        assert!(
            GovernanceSource::discover(&managed, None, 501)
                .unwrap()
                .is_none()
        );
        let opt_in = directory.path().join("mine.yaml");
        let selected = GovernanceSource::discover(&managed, Some(&opt_in), 501)
            .unwrap()
            .unwrap();
        assert_eq!(selected.mode, GovernanceMode::OptIn);
        assert_eq!(selected.ownership, TrustedOwnership::RootOrUser(501));

        write_private(&managed, b"x");
        let managed_source = GovernanceSource::discover(&managed, None, 501)
            .unwrap()
            .unwrap();
        assert_eq!(managed_source.mode, GovernanceMode::Managed);
        assert_eq!(managed_source.ownership, TrustedOwnership::Root);
        assert!(GovernanceSource::discover(&managed, Some(&opt_in), 501).is_err());
        if crate::current_uid() != 0 {
            assert!(managed_source.load().is_err());
        }
    }

    #[test]
    fn signed_profiles_verify_and_tampering_or_rollback_is_rejected() {
        if !protected_test_tree() {
            return;
        }
        let fixture = fixture(PROFILE, 1);
        let operator = fixture.source.load().expect("operator");
        let verified = verify_profile(&fixture.source, &operator, 100).expect("verified");
        assert_eq!(verified.reference.revision, 4);
        assert_eq!(verified.signers.len(), 1);

        assert!(verify_profile(&fixture.source, &operator, 30_000_000).is_err());

        let mut stale = operator.clone();
        stale.minimum_revision = 5;
        assert!(verify_profile(&fixture.source, &stale, 100).is_err());

        let tampered = PROFILE.replace("*.github.com", "*.example.com");
        write_private(&operator.profile_path, tampered.as_bytes());
        let error = verify_profile(&fixture.source, &operator, 100).expect_err("tampered");
        assert!(error.to_string().contains("signature"), "{error}");

        let other = SigningKeyMaterial::generate().unwrap();
        write_private(
            &operator.signatures_path(),
            &sign(&other, tampered.as_bytes()),
        );
        assert!(verify_profile(&fixture.source, &operator, 100).is_err());

        write_private(
            &operator.signatures_path(),
            &sign(&fixture.key, tampered.as_bytes()),
        );
        assert!(verify_profile(&fixture.source, &operator, 100).is_ok());
        drop(fixture.directory);
    }

    #[test]
    fn high_water_mark_rejects_admitted_revision_rollback() {
        let directory = private_directory();
        let state = directory.path().join("state");
        let records = RevisionHighWater::open(&state).unwrap();
        let authority = AuthorityRef {
            id: "local".to_owned(),
            trust_sha256: Sha256Digest::of(b"trust"),
        };
        let reference = |revision| ProfileRef {
            id: ProfileId::new("acme").unwrap(),
            revision,
            sha256: Sha256Digest::of(b"profile"),
        };
        records.check(&authority, &reference(3)).unwrap();
        records.record(&authority, &reference(3)).unwrap();
        records.check(&authority, &reference(3)).unwrap();
        records.check(&authority, &reference(4)).unwrap();
        assert!(records.check(&authority, &reference(2)).is_err());
    }

    #[test]
    fn revision_source_reports_unavailable_authority() {
        if !protected_test_tree() {
            return;
        }
        let fixture = fixture(PROFILE, 1);
        struct FixedClock;
        impl Clock for FixedClock {
            fn now_unix(&self) -> u64 {
                100
            }
        }
        let source = OperatorRevisionSource::new(fixture.source.clone(), Arc::new(FixedClock));
        let current = source
            .current(&ProfileId::new("acme").unwrap())
            .expect("current");
        assert_eq!(current.reference.revision, 4);
        std::fs::remove_file(&fixture.source.path).unwrap();
        *source.cache.lock().unwrap() = None;
        assert!(matches!(
            source.current(&ProfileId::new("acme").unwrap()),
            Err(GovernanceError::AuthorityUnavailable(_))
        ));
    }

    #[test]
    fn bundle_pins_are_enforced() {
        let directory = private_directory();
        let root = directory.path().join("root.pub");
        write_private(&root, b"public key");
        let key = SigningKeyMaterial::generate().unwrap();
        let mut operator = OperatorConfiguration::parse(
            serde_yaml_ng::to_string(&test_operator(
                key.identity("Operator", None, 0, None),
                PathBuf::from("/governance/acme.yaml"),
                1,
            ))
            .unwrap()
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            operator.signatures_path(),
            PathBuf::from("/governance/acme.yaml.sig.json")
        );
        let user = TrustedOwnership::RootOrUser(crate::current_uid());
        operator.verify_bundle(&root, user, "any", 0).unwrap();
        operator.bundle = Some(BundlePin {
            trust_root_sha256: vec![Sha256Digest::of(b"public key")],
            trust_root_ids: vec!["release".to_owned()],
            minimum_release_sequence: 5,
        });
        if crate::current_uid() != 0 {
            assert!(
                operator
                    .verify_bundle(&root, TrustedOwnership::Root, "release", 5)
                    .is_err(),
                "managed mode requires a root-owned trust root"
            );
        }
        if !protected_test_tree() {
            return;
        }
        operator.verify_bundle(&root, user, "release", 5).unwrap();
        assert!(operator.verify_bundle(&root, user, "other", 5).is_err());
        assert!(operator.verify_bundle(&root, user, "release", 4).is_err());
        write_private(&root, b"different");
        assert!(operator.verify_bundle(&root, user, "release", 5).is_err());
    }
}
