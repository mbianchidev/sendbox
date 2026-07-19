//! Versioned Ed25519 provenance persistence.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::encode_hash;
use crate::canonical;
use crate::fs::{DEFAULT_MAX_FILE_BYTES, PRIVATE_FILE_MODE, SecureRoot};
use crate::{SecurityError, SecurityResult};

pub const PROVENANCE_FORMAT_VERSION: u16 = 1;
pub const MAX_TRUSTED_IDENTITIES: usize = 1024;
pub const MAX_SIGNATURES: usize = 256;

const PROVENANCE_FORMAT: &str = "sendbox-provenance";
const TRUST_FORMAT: &str = "sendbox-trust-store";
const SIGNING_DOMAIN: &[u8] = b"sendbox-provenance-signature-v1\0";
const PRIVATE_KEY_PREFIX: &str = "sendbox-ed25519-v1:";

pub struct SigningKeyMaterial {
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigningKeyMaterial([REDACTED])")
    }
}

impl SigningKeyMaterial {
    pub fn generate() -> SecurityResult<Self> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|error| SecurityError::Malformed {
            format: "Ed25519 private key",
            detail: error.to_string(),
        })?;
        Ok(Self { bytes })
    }

    pub fn import(representation: &str) -> SecurityResult<Self> {
        let encoded = representation
            .strip_prefix(PRIVATE_KEY_PREFIX)
            .ok_or_else(|| SecurityError::Malformed {
                format: "Ed25519 private key",
                detail: "unsupported key representation".to_owned(),
            })?;
        let decoded =
            Zeroizing::new(
                BASE64
                    .decode(encoded)
                    .map_err(|error| SecurityError::Malformed {
                        format: "Ed25519 private key",
                        detail: error.to_string(),
                    })?,
            );
        let bytes = decoded
            .as_slice()
            .try_into()
            .map_err(|_| SecurityError::Malformed {
                format: "Ed25519 private key",
                detail: "expected 32 key bytes".to_owned(),
            })?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    pub fn export(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{PRIVATE_KEY_PREFIX}{}",
            BASE64.encode(self.bytes.as_ref())
        ))
    }

    pub fn identity(
        &self,
        name: impl Into<String>,
        email: Option<String>,
        valid_from_unix: u64,
        expires_at_unix: Option<u64>,
    ) -> Identity {
        let verifying = SigningKey::from_bytes(&self.bytes).verifying_key();
        Identity {
            version: PROVENANCE_FORMAT_VERSION,
            fingerprint: fingerprint(&verifying),
            name: name.into(),
            email,
            public_key_base64: BASE64.encode(verifying.as_bytes()),
            valid_from_unix,
            expires_at_unix,
            revoked_at_unix: None,
        }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub version: u16,
    pub fingerprint: String,
    pub name: String,
    pub email: Option<String>,
    pub public_key_base64: String,
    pub valid_from_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub revoked_at_unix: Option<u64>,
}

impl Identity {
    pub fn revoke(&mut self, revoked_at_unix: u64) {
        self.revoked_at_unix = Some(revoked_at_unix);
    }

    fn verifying_key(&self) -> SecurityResult<VerifyingKey> {
        if self.version != PROVENANCE_FORMAT_VERSION {
            return Err(SecurityError::UnsupportedVersion {
                format: PROVENANCE_FORMAT,
                version: self.version,
            });
        }
        let bytes =
            BASE64
                .decode(&self.public_key_base64)
                .map_err(|error| SecurityError::Malformed {
                    format: PROVENANCE_FORMAT,
                    detail: error.to_string(),
                })?;
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| SecurityError::Malformed {
            format: PROVENANCE_FORMAT,
            detail: "expected 32 public-key bytes".to_owned(),
        })?;
        let key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|error| SecurityError::Malformed {
                format: PROVENANCE_FORMAT,
                detail: error.to_string(),
            })?;
        if fingerprint(&key) != self.fingerprint {
            return Err(SecurityError::Integrity(format!(
                "identity {} fingerprint mismatch",
                self.name
            )));
        }
        Ok(key)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Content,
    Configuration,
    Artifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSubject {
    pub kind: SubjectKind,
    pub sha256: String,
    pub name: Option<String>,
}

impl SignedSubject {
    pub fn from_bytes(kind: SubjectKind, name: Option<String>, bytes: &[u8]) -> Self {
        Self {
            kind,
            sha256: encode_hash(&Sha256::digest(bytes).into()),
            name,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SignaturePayload {
    format: String,
    version: u16,
    signature_id: String,
    subject: SignedSubject,
    signer_fingerprint: String,
    signed_at_unix: u64,
    expires_at_unix: Option<u64>,
    metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    pub format: String,
    pub version: u16,
    pub signature_id: String,
    pub subject: SignedSubject,
    pub signer_fingerprint: String,
    pub signed_at_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub metadata: BTreeMap<String, String>,
    pub signature_base64: String,
}

impl DetachedSignature {
    pub fn sign(
        subject: SignedSubject,
        key: &SigningKeyMaterial,
        signed_at_unix: u64,
        expires_at_unix: Option<u64>,
        metadata: BTreeMap<String, String>,
    ) -> SecurityResult<Self> {
        validate_signature_metadata(&metadata)?;
        if expires_at_unix.is_some_and(|expires| expires < signed_at_unix) {
            return Err(SecurityError::Malformed {
                format: PROVENANCE_FORMAT,
                detail: "signature expires before it is created".to_owned(),
            });
        }
        let mut id_bytes = [0_u8; 16];
        getrandom::fill(&mut id_bytes).map_err(|error| SecurityError::Malformed {
            format: PROVENANCE_FORMAT,
            detail: error.to_string(),
        })?;
        let signature_id = id_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let signing = key.signing_key();
        let payload = SignaturePayload {
            format: PROVENANCE_FORMAT.to_owned(),
            version: PROVENANCE_FORMAT_VERSION,
            signature_id: signature_id.clone(),
            subject: subject.clone(),
            signer_fingerprint: fingerprint(&signing.verifying_key()),
            signed_at_unix,
            expires_at_unix,
            metadata: metadata.clone(),
        };
        let signature = signing.sign(&signing_bytes(&payload)?);
        Ok(Self {
            format: payload.format,
            version: payload.version,
            signature_id,
            subject,
            signer_fingerprint: payload.signer_fingerprint,
            signed_at_unix,
            expires_at_unix,
            metadata,
            signature_base64: BASE64.encode(signature.to_bytes()),
        })
    }

    pub fn encode(&self) -> SecurityResult<Vec<u8>> {
        canonical::encode(self, PROVENANCE_FORMAT)
    }

    pub fn decode(bytes: &[u8]) -> SecurityResult<Self> {
        let signature: Self = canonical::decode_canonical(bytes, PROVENANCE_FORMAT)?;
        signature.validate_shape()?;
        Ok(signature)
    }

    fn payload(&self) -> SignaturePayload {
        SignaturePayload {
            format: self.format.clone(),
            version: self.version,
            signature_id: self.signature_id.clone(),
            subject: self.subject.clone(),
            signer_fingerprint: self.signer_fingerprint.clone(),
            signed_at_unix: self.signed_at_unix,
            expires_at_unix: self.expires_at_unix,
            metadata: self.metadata.clone(),
        }
    }

    fn validate_shape(&self) -> SecurityResult<()> {
        if self.format != PROVENANCE_FORMAT || self.version != PROVENANCE_FORMAT_VERSION {
            return Err(SecurityError::UnsupportedVersion {
                format: PROVENANCE_FORMAT,
                version: self.version,
            });
        }
        if self.signature_id.len() != 32
            || !self
                .signature_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SecurityError::Malformed {
                format: PROVENANCE_FORMAT,
                detail: "invalid signature id".to_owned(),
            });
        }
        validate_signature_metadata(&self.metadata)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub allow_unsigned: bool,
    pub threshold: usize,
    pub required_signers: BTreeSet<String>,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            allow_unsigned: true,
            threshold: 0,
            required_signers: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    pub format: String,
    pub version: u16,
    pub identities: BTreeMap<String, Identity>,
    pub policy: TrustPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    pub subject: SignedSubject,
    pub valid_signers: BTreeSet<String>,
}

impl TrustStore {
    pub fn new(policy: TrustPolicy) -> Self {
        Self {
            format: TRUST_FORMAT.to_owned(),
            version: PROVENANCE_FORMAT_VERSION,
            identities: BTreeMap::new(),
            policy,
        }
    }

    pub fn add_identity(&mut self, identity: Identity) -> SecurityResult<()> {
        identity.verifying_key()?;
        if self.identities.len() >= MAX_TRUSTED_IDENTITIES
            && !self.identities.contains_key(&identity.fingerprint)
        {
            return Err(SecurityError::Malformed {
                format: TRUST_FORMAT,
                detail: "identity count exceeds limit".to_owned(),
            });
        }
        self.identities
            .insert(identity.fingerprint.clone(), identity);
        Ok(())
    }

    pub fn verify(
        &self,
        content: &[u8],
        kind: SubjectKind,
        signatures: &[DetachedSignature],
        now_unix: u64,
    ) -> SecurityResult<VerificationResult> {
        self.validate()?;
        if signatures.len() > MAX_SIGNATURES {
            return Err(SecurityError::Policy(
                "signature count exceeds limit".to_owned(),
            ));
        }
        let expected = SignedSubject::from_bytes(kind, None, content);
        if signatures.is_empty() {
            if self.policy.allow_unsigned
                && self.policy.threshold == 0
                && self.policy.required_signers.is_empty()
            {
                return Ok(VerificationResult {
                    subject: expected,
                    valid_signers: BTreeSet::new(),
                });
            }
            return Err(SecurityError::Policy("signature is required".to_owned()));
        }

        let mut signature_ids = HashSet::new();
        let mut valid_signers = BTreeSet::new();
        for detached in signatures {
            detached.validate_shape()?;
            if !signature_ids.insert(&detached.signature_id) {
                return Err(SecurityError::Policy(
                    "replayed detached signature".to_owned(),
                ));
            }
            if detached.subject.sha256 != expected.sha256 || detached.subject.kind != kind {
                return Err(SecurityError::Integrity(
                    "signature subject does not match content".to_owned(),
                ));
            }
            if detached
                .expires_at_unix
                .is_some_and(|expires| expires < now_unix)
            {
                return Err(SecurityError::Policy(format!(
                    "signature {} is expired",
                    detached.signature_id
                )));
            }
            let identity = self
                .identities
                .get(&detached.signer_fingerprint)
                .ok_or_else(|| {
                    SecurityError::Policy(format!(
                        "untrusted signer {}",
                        detached.signer_fingerprint
                    ))
                })?;
            if identity.valid_from_unix > detached.signed_at_unix {
                return Err(SecurityError::Policy(format!(
                    "signature predates signer {} validity",
                    identity.fingerprint
                )));
            }
            if identity
                .expires_at_unix
                .is_some_and(|expires| expires < detached.signed_at_unix || expires < now_unix)
            {
                return Err(SecurityError::Policy(format!(
                    "signer {} is expired",
                    identity.fingerprint
                )));
            }
            if identity.revoked_at_unix.is_some() {
                return Err(SecurityError::Policy(format!(
                    "signer {} is revoked",
                    identity.fingerprint
                )));
            }
            let signature_bytes = BASE64.decode(&detached.signature_base64).map_err(|error| {
                SecurityError::Malformed {
                    format: PROVENANCE_FORMAT,
                    detail: error.to_string(),
                }
            })?;
            let signature = Signature::from_slice(&signature_bytes).map_err(|error| {
                SecurityError::Malformed {
                    format: PROVENANCE_FORMAT,
                    detail: error.to_string(),
                }
            })?;
            identity
                .verifying_key()?
                .verify(&signing_bytes(&detached.payload())?, &signature)
                .map_err(|error| SecurityError::Integrity(error.to_string()))?;
            valid_signers.insert(identity.fingerprint.clone());
        }

        if valid_signers.len() < self.policy.threshold {
            return Err(SecurityError::Policy(format!(
                "required {} distinct signers, found {}",
                self.policy.threshold,
                valid_signers.len()
            )));
        }
        if !self.policy.required_signers.is_subset(&valid_signers) {
            return Err(SecurityError::Policy(
                "required signer policy is not satisfied".to_owned(),
            ));
        }
        Ok(VerificationResult {
            subject: expected,
            valid_signers,
        })
    }

    pub fn save(&self, root: &SecureRoot, path: impl AsRef<Path>) -> SecurityResult<()> {
        self.validate()?;
        root.write_atomic(
            path,
            &canonical::encode(self, TRUST_FORMAT)?,
            DEFAULT_MAX_FILE_BYTES,
            PRIVATE_FILE_MODE,
        )
    }

    pub fn load(root: &SecureRoot, path: impl AsRef<Path>) -> SecurityResult<Self> {
        let bytes = root.read_bounded(path.as_ref(), DEFAULT_MAX_FILE_BYTES)?;
        Self::decode(&bytes)
    }

    #[doc(hidden)]
    pub fn decode(bytes: &[u8]) -> SecurityResult<Self> {
        let store: Self = canonical::decode_canonical(bytes, TRUST_FORMAT)?;
        store.validate()?;
        Ok(store)
    }

    fn validate(&self) -> SecurityResult<()> {
        if self.format != TRUST_FORMAT || self.version != PROVENANCE_FORMAT_VERSION {
            return Err(SecurityError::UnsupportedVersion {
                format: TRUST_FORMAT,
                version: self.version,
            });
        }
        if self.identities.len() > MAX_TRUSTED_IDENTITIES {
            return Err(SecurityError::Malformed {
                format: TRUST_FORMAT,
                detail: "identity count exceeds limit".to_owned(),
            });
        }
        if self.policy.threshold > self.identities.len()
            || self.policy.required_signers.len() > self.identities.len()
        {
            return Err(SecurityError::Policy(
                "trust policy exceeds available identities".to_owned(),
            ));
        }
        for (fingerprint, identity) in &self.identities {
            if fingerprint != &identity.fingerprint {
                return Err(SecurityError::Integrity(
                    "trust-store key does not match identity".to_owned(),
                ));
            }
            identity.verifying_key()?;
        }
        if !self
            .policy
            .required_signers
            .iter()
            .all(|fingerprint| self.identities.contains_key(fingerprint))
        {
            return Err(SecurityError::Policy(
                "required signer is absent from trust store".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct LegacySwiftIdentity {
    pub fingerprint: String,
    pub name: String,
    pub email: Option<String>,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "addedAt")]
    pub added_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LegacySwiftSignatureMetadata {
    #[serde(rename = "toolVersion")]
    pub tool_version: String,
    pub purpose: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LegacySwiftSignature {
    #[serde(rename = "fileHash")]
    pub file_hash: String,
    pub signature: String,
    #[serde(rename = "signerFingerprint")]
    pub signer_fingerprint: String,
    pub timestamp: String,
    pub metadata: Option<LegacySwiftSignatureMetadata>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LegacySwiftTrustStore {
    pub identities: Vec<LegacySwiftIdentity>,
    #[serde(rename = "requireSignature")]
    pub require_signature: bool,
    #[serde(rename = "minimumSigners")]
    pub minimum_signers: usize,
}

pub fn decode_legacy_swift_trust_store(
    bytes: &[u8],
    max_bytes: u64,
) -> SecurityResult<LegacySwiftTrustStore> {
    if bytes.len() as u64 > max_bytes {
        return Err(SecurityError::SizeLimit {
            path: PathBuf::from("legacy trust store"),
            limit: max_bytes,
        });
    }
    let store: LegacySwiftTrustStore =
        serde_json::from_slice(bytes).map_err(|error| SecurityError::Malformed {
            format: "swift-provenance-v1",
            detail: error.to_string(),
        })?;
    if store.identities.len() > MAX_TRUSTED_IDENTITIES
        || store.minimum_signers > store.identities.len()
    {
        return Err(SecurityError::Policy(
            "legacy trust-store policy is unsatisfiable".to_owned(),
        ));
    }
    let mut fingerprints = HashSet::new();
    for identity in &store.identities {
        if !fingerprints.insert(&identity.fingerprint) {
            return Err(SecurityError::Integrity(
                "duplicate legacy identity fingerprint".to_owned(),
            ));
        }
        let bytes =
            BASE64
                .decode(&identity.public_key)
                .map_err(|error| SecurityError::Malformed {
                    format: "swift-provenance-v1",
                    detail: error.to_string(),
                })?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| SecurityError::Malformed {
            format: "swift-provenance-v1",
            detail: "expected 32 public-key bytes".to_owned(),
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|error| SecurityError::Malformed {
            format: "swift-provenance-v1",
            detail: error.to_string(),
        })?;
        if fingerprint(&key) != identity.fingerprint {
            return Err(SecurityError::Integrity(
                "legacy identity fingerprint mismatch".to_owned(),
            ));
        }
    }
    Ok(store)
}

pub fn verify_legacy_swift_signature(
    content: &[u8],
    signature_bytes: &[u8],
    identities: &[LegacySwiftIdentity],
    now: time::OffsetDateTime,
) -> SecurityResult<String> {
    if signature_bytes.len() as u64 > DEFAULT_MAX_FILE_BYTES {
        return Err(SecurityError::SizeLimit {
            path: PathBuf::from("legacy .sig"),
            limit: DEFAULT_MAX_FILE_BYTES,
        });
    }
    let detached: LegacySwiftSignature =
        serde_json::from_slice(signature_bytes).map_err(|error| SecurityError::Malformed {
            format: "swift-provenance-v1",
            detail: error.to_string(),
        })?;
    let expected_hash = encode_hash(&Sha256::digest(content).into());
    if detached.file_hash != expected_hash {
        return Err(SecurityError::Integrity(
            "legacy signature file hash mismatch".to_owned(),
        ));
    }
    let identity = identities
        .iter()
        .find(|identity| identity.fingerprint == detached.signer_fingerprint)
        .ok_or_else(|| SecurityError::Policy("legacy signer is untrusted".to_owned()))?;
    let public_bytes =
        BASE64
            .decode(&identity.public_key)
            .map_err(|error| SecurityError::Malformed {
                format: "swift-provenance-v1",
                detail: error.to_string(),
            })?;
    let public_bytes: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| SecurityError::Malformed {
            format: "swift-provenance-v1",
            detail: "expected 32 public-key bytes".to_owned(),
        })?;
    let key =
        VerifyingKey::from_bytes(&public_bytes).map_err(|error| SecurityError::Malformed {
            format: "swift-provenance-v1",
            detail: error.to_string(),
        })?;
    if fingerprint(&key) != identity.fingerprint {
        return Err(SecurityError::Integrity(
            "legacy identity fingerprint mismatch".to_owned(),
        ));
    }
    if let Some(expires_at) = &identity.expires_at {
        let expires = time::OffsetDateTime::parse(
            expires_at,
            &time::format_description::well_known::Iso8601::DEFAULT,
        )
        .map_err(|error| SecurityError::Malformed {
            format: "swift-provenance-v1",
            detail: error.to_string(),
        })?;
        if expires < now {
            return Err(SecurityError::Policy("legacy signer is expired".to_owned()));
        }
    }
    let raw_signature =
        BASE64
            .decode(&detached.signature)
            .map_err(|error| SecurityError::Malformed {
                format: "swift-provenance-v1",
                detail: error.to_string(),
            })?;
    let raw_signature =
        Signature::from_slice(&raw_signature).map_err(|error| SecurityError::Malformed {
            format: "swift-provenance-v1",
            detail: error.to_string(),
        })?;
    key.verify(content, &raw_signature)
        .map_err(|error| SecurityError::Integrity(error.to_string()))?;
    Ok(identity.fingerprint.clone())
}

fn signing_bytes(payload: &SignaturePayload) -> SecurityResult<Vec<u8>> {
    let encoded = canonical::encode(payload, PROVENANCE_FORMAT)?;
    Ok([SIGNING_DOMAIN, encoded.as_slice()].concat())
}

fn fingerprint(key: &VerifyingKey) -> String {
    encode_hash(&Sha256::digest(key.as_bytes()).into())
}

fn validate_signature_metadata(metadata: &BTreeMap<String, String>) -> SecurityResult<()> {
    if metadata.len() > 32
        || metadata
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 128 || value.len() > 4096)
    {
        return Err(SecurityError::Malformed {
            format: PROVENANCE_FORMAT,
            detail: "signature metadata exceeds limits".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted_pair(name: &str) -> (SigningKeyMaterial, Identity) {
        let key = SigningKeyMaterial::generate().expect("generate key");
        let identity = key.identity(name, None, 10, Some(1000));
        (key, identity)
    }

    #[test]
    fn private_key_debug_is_redacted_and_import_roundtrips() {
        let key = SigningKeyMaterial::generate().expect("generate key");
        assert_eq!(format!("{key:?}"), "SigningKeyMaterial([REDACTED])");
        let exported = key.export();
        let imported = SigningKeyMaterial::import(&exported).expect("import key");
        assert_eq!(
            key.identity("a", None, 0, None).fingerprint,
            imported.identity("a", None, 0, None).fingerprint
        );
    }

    #[test]
    fn verifies_threshold_and_required_signers() {
        let content = b"artifact";
        let (key_a, identity_a) = trusted_pair("a");
        let (key_b, identity_b) = trusted_pair("b");
        let required = identity_a.fingerprint.clone();
        let mut store = TrustStore::new(TrustPolicy {
            allow_unsigned: false,
            threshold: 2,
            required_signers: BTreeSet::from([required]),
        });
        store.add_identity(identity_a).expect("add a");
        store.add_identity(identity_b).expect("add b");
        let subject = SignedSubject::from_bytes(SubjectKind::Artifact, None, content);
        let a = DetachedSignature::sign(subject.clone(), &key_a, 20, Some(100), BTreeMap::new())
            .expect("sign a");
        let b = DetachedSignature::sign(subject, &key_b, 20, Some(100), BTreeMap::new())
            .expect("sign b");
        let verified = store
            .verify(content, SubjectKind::Artifact, &[a, b], 30)
            .expect("verify");
        assert_eq!(verified.valid_signers.len(), 2);
    }

    #[test]
    fn rejects_wrong_revoked_expired_and_replayed_signers() {
        let content = b"config";
        let (key, identity) = trusted_pair("trusted");
        let (_, wrong_identity) = trusted_pair("wrong");
        let mut store = TrustStore::new(TrustPolicy {
            allow_unsigned: false,
            threshold: 1,
            required_signers: BTreeSet::new(),
        });
        store.add_identity(identity.clone()).expect("add trusted");
        let signature = DetachedSignature::sign(
            SignedSubject::from_bytes(SubjectKind::Configuration, None, content),
            &key,
            20,
            Some(50),
            BTreeMap::new(),
        )
        .expect("sign");
        assert!(
            store
                .verify(
                    content,
                    SubjectKind::Configuration,
                    std::slice::from_ref(&signature),
                    60
                )
                .is_err()
        );
        assert!(
            store
                .verify(
                    content,
                    SubjectKind::Configuration,
                    &[signature.clone(), signature.clone()],
                    30
                )
                .is_err()
        );

        let mut revoked_store = store.clone();
        revoked_store
            .identities
            .get_mut(&identity.fingerprint)
            .expect("identity")
            .revoke(25);
        assert!(
            revoked_store
                .verify(
                    content,
                    SubjectKind::Configuration,
                    std::slice::from_ref(&signature),
                    30
                )
                .is_err()
        );

        let mut wrong_store = TrustStore::new(TrustPolicy {
            allow_unsigned: false,
            threshold: 1,
            required_signers: BTreeSet::new(),
        });
        wrong_store.add_identity(wrong_identity).expect("add wrong");
        assert!(
            wrong_store
                .verify(content, SubjectKind::Configuration, &[signature], 30)
                .is_err()
        );
    }

    #[test]
    fn signature_decoder_rejects_noncanonical_json() {
        let (key, _) = trusted_pair("a");
        let signature = DetachedSignature::sign(
            SignedSubject::from_bytes(SubjectKind::Content, None, b"x"),
            &key,
            1,
            None,
            BTreeMap::new(),
        )
        .expect("sign");
        let pretty = serde_json::to_vec_pretty(&signature).expect("pretty");
        assert!(DetachedSignature::decode(&pretty).is_err());
    }
}
