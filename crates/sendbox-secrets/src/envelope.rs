use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use getrandom::fill;
use hkdf::Hkdf;
use minicbor::{Decoder, Encoder};
use sendbox_core::SessionId;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{MAX_SECRET_VALUE_BYTES, SecretName, SecretValue};

const ENVELOPE_MAGIC: &[u8] = b"\xffSBXENVELOPE\x01";
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_DOMAIN: &[u8] = b"sendbox session secret envelope v1";
const ENVELOPE_SALT_DOMAIN: &[u8] = b"sendbox session secret envelope hkdf salt v1";
const ENVELOPE_KEY_DOMAIN: &[u8] = b"sendbox session secret envelope key v1";
const NONCE_BYTES: usize = 24;
const POLICY_DIGEST_BYTES: usize = 32;
const MAX_ENVELOPE_BYTES: usize = MAX_SECRET_VALUE_BYTES + 2048;
const DEFAULT_REPLAY_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecipientRole {
    Host,
    Guest,
}

impl RecipientRole {
    const fn code(self) -> u8 {
        match self {
            Self::Host => 1,
            Self::Guest => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, EnvelopeError> {
        match code {
            1 => Ok(Self::Host),
            2 => Ok(Self::Guest),
            _ => Err(EnvelopeError::Malformed(format!(
                "unknown recipient role {code}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeBinding {
    pub session_id: SessionId,
    pub recipient: RecipientRole,
    pub secret_name: SecretName,
    pub sequence: u64,
    pub expires_at_unix_ms: u64,
    pub policy_digest: [u8; POLICY_DIGEST_BYTES],
}

pub struct SessionKeyMaterial(Zeroizing<Vec<u8>>);

impl SessionKeyMaterial {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, EnvelopeError> {
        let bytes = bytes.into();
        if bytes.len() < 32 {
            return Err(EnvelopeError::KeyMaterialTooShort);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl fmt::Debug for SessionKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionKeyMaterial([REDACTED])")
    }
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("session key material must contain at least 32 bytes")]
    KeyMaterialTooShort,
    #[error("secret envelope exceeds the maximum size")]
    TooLarge,
    #[error("secret envelope is malformed: {0}")]
    Malformed(String),
    #[error("secret envelope binding does not match the expected context")]
    BindingMismatch,
    #[error("secret envelope authentication failed")]
    AuthenticationFailed,
    #[error("secret envelope has expired")]
    Expired,
    #[error("secret envelope replay detected")]
    Replay,
    #[error("secret envelope replay window is full")]
    ReplayWindowFull,
    #[error("secret envelope nonce or sequence was already issued")]
    DuplicateIssuance,
    #[error("secure random number generation failed: {0}")]
    Random(String),
    #[error("secret envelope key derivation failed")]
    KeyDerivation,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplayIdentity {
    session_id: [u8; 16],
    recipient: RecipientRole,
    secret_name: SecretName,
    sequence: u64,
    nonce: [u8; NONCE_BYTES],
}

pub struct ReplayGuard {
    maximum_entries: usize,
    accepted: Mutex<HashMap<ReplayIdentity, u64>>,
}

impl ReplayGuard {
    #[must_use]
    pub fn new(maximum_entries: usize) -> Self {
        Self {
            maximum_entries,
            accepted: Mutex::new(HashMap::new()),
        }
    }

    fn accept(
        &self,
        identity: ReplayIdentity,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), EnvelopeError> {
        let mut accepted = self
            .accepted
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        accepted.retain(|_, expiry| *expiry > now_unix_ms);
        if accepted.contains_key(&identity) {
            return Err(EnvelopeError::Replay);
        }
        if accepted.len() >= self.maximum_entries {
            return Err(EnvelopeError::ReplayWindowFull);
        }
        accepted.insert(identity, expires_at_unix_ms);
        Ok(())
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_ENTRIES)
    }
}

pub struct EnvelopeCipher {
    session_id: SessionId,
    key: Zeroizing<[u8; 32]>,
    issued_sequences: HashSet<u64>,
    issued_nonces: HashSet<[u8; NONCE_BYTES]>,
}

impl fmt::Debug for EnvelopeCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeCipher")
            .field("session_id", &self.session_id)
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl EnvelopeCipher {
    pub fn new(
        material: &SessionKeyMaterial,
        session_id: SessionId,
    ) -> Result<Self, EnvelopeError> {
        Ok(Self {
            session_id,
            key: derive_key(material.0.as_ref(), session_id)?,
            issued_sequences: HashSet::new(),
            issued_nonces: HashSet::new(),
        })
    }

    pub fn seal(
        &mut self,
        binding: &EnvelopeBinding,
        value: &SecretValue,
    ) -> Result<Vec<u8>, EnvelopeError> {
        let mut nonce = [0_u8; NONCE_BYTES];
        fill(&mut nonce).map_err(|error| EnvelopeError::Random(error.to_string()))?;
        self.seal_with_nonce(binding, value, nonce)
    }

    pub fn open(
        &self,
        encoded: &[u8],
        expected: &EnvelopeBinding,
        replay_guard: &ReplayGuard,
        now_unix_ms: u64,
    ) -> Result<SecretValue, EnvelopeError> {
        let envelope = decode_envelope(encoded)?;
        if envelope.binding != *expected || envelope.binding.session_id != self.session_id {
            return Err(EnvelopeError::BindingMismatch);
        }
        if envelope.binding.expires_at_unix_ms <= now_unix_ms {
            return Err(EnvelopeError::Expired);
        }

        let aad = encode_aad(&envelope.binding)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| EnvelopeError::KeyDerivation)?;
        let nonce = XNonce::try_from(envelope.nonce.as_slice())
            .map_err(|_| EnvelopeError::Malformed("nonce has invalid length".to_owned()))?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| EnvelopeError::AuthenticationFailed)?;
        let value = SecretValue::new(plaintext).map_err(|_| EnvelopeError::TooLarge)?;
        replay_guard.accept(
            ReplayIdentity {
                session_id: *envelope.binding.session_id.as_bytes(),
                recipient: envelope.binding.recipient,
                secret_name: envelope.binding.secret_name,
                sequence: envelope.binding.sequence,
                nonce: envelope.nonce,
            },
            envelope.binding.expires_at_unix_ms,
            now_unix_ms,
        )?;
        Ok(value)
    }

    fn seal_with_nonce(
        &mut self,
        binding: &EnvelopeBinding,
        value: &SecretValue,
        nonce: [u8; NONCE_BYTES],
    ) -> Result<Vec<u8>, EnvelopeError> {
        if binding.session_id != self.session_id {
            return Err(EnvelopeError::BindingMismatch);
        }
        if !self.issued_sequences.insert(binding.sequence) || !self.issued_nonces.insert(nonce) {
            return Err(EnvelopeError::DuplicateIssuance);
        }

        let aad = encode_aad(binding)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| EnvelopeError::KeyDerivation)?;
        let xnonce = XNonce::try_from(nonce.as_slice())
            .map_err(|_| EnvelopeError::Malformed("nonce has invalid length".to_owned()))?;
        let ciphertext = cipher
            .encrypt(
                &xnonce,
                Payload {
                    msg: value.expose_secret(),
                    aad: &aad,
                },
            )
            .map_err(|_| EnvelopeError::AuthenticationFailed)?;
        encode_envelope(&DecodedEnvelope {
            binding: binding.clone(),
            nonce,
            ciphertext,
        })
    }
}

struct DecodedEnvelope {
    binding: EnvelopeBinding,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

fn derive_key(
    material: &[u8],
    session_id: SessionId,
) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(ENVELOPE_SALT_DOMAIN);
    salt_hasher.update(session_id.as_bytes());
    let salt = salt_hasher.finalize();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), material);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(ENVELOPE_KEY_DOMAIN, key.as_mut())
        .map_err(|_| EnvelopeError::KeyDerivation)?;
    Ok(key)
}

fn encode_aad(binding: &EnvelopeBinding) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    let mut aad = Zeroizing::new(Vec::with_capacity(256));
    let mut encoder = Encoder::new(&mut *aad);
    encoder
        .array(7)
        .and_then(|encoder| encoder.bytes(ENVELOPE_DOMAIN))
        .and_then(|encoder| encoder.bytes(binding.session_id.as_bytes()))
        .and_then(|encoder| encoder.u8(binding.recipient.code()))
        .and_then(|encoder| encoder.str(binding.secret_name.as_str()))
        .and_then(|encoder| encoder.u64(binding.sequence))
        .and_then(|encoder| encoder.u64(binding.expires_at_unix_ms))
        .and_then(|encoder| encoder.bytes(&binding.policy_digest))
        .map_err(|error| EnvelopeError::Malformed(error.to_string()))?;
    Ok(aad)
}

fn encode_envelope(envelope: &DecodedEnvelope) -> Result<Vec<u8>, EnvelopeError> {
    let mut encoded = Vec::with_capacity(ENVELOPE_MAGIC.len() + envelope.ciphertext.len() + 256);
    encoded.extend_from_slice(ENVELOPE_MAGIC);
    let mut encoder = Encoder::new(&mut encoded);
    encoder
        .array(9)
        .and_then(|encoder| encoder.u8(ENVELOPE_VERSION))
        .and_then(|encoder| encoder.bytes(envelope.binding.session_id.as_bytes()))
        .and_then(|encoder| encoder.u8(envelope.binding.recipient.code()))
        .and_then(|encoder| encoder.str(envelope.binding.secret_name.as_str()))
        .and_then(|encoder| encoder.u64(envelope.binding.sequence))
        .and_then(|encoder| encoder.u64(envelope.binding.expires_at_unix_ms))
        .and_then(|encoder| encoder.bytes(&envelope.binding.policy_digest))
        .and_then(|encoder| encoder.bytes(&envelope.nonce))
        .and_then(|encoder| encoder.bytes(&envelope.ciphertext))
        .map_err(|error| EnvelopeError::Malformed(error.to_string()))?;
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(EnvelopeError::TooLarge);
    }
    Ok(encoded)
}

pub(crate) fn validate_encoded_envelope(encoded: &[u8]) -> Result<(), EnvelopeError> {
    decode_envelope(encoded).map(|_| ())
}

fn decode_envelope(encoded: &[u8]) -> Result<DecodedEnvelope, EnvelopeError> {
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(EnvelopeError::TooLarge);
    }
    let payload = encoded
        .strip_prefix(ENVELOPE_MAGIC)
        .ok_or_else(|| EnvelopeError::Malformed("invalid envelope magic".to_owned()))?;
    let mut decoder = Decoder::new(payload);
    if decoder
        .array()
        .map_err(malformed)?
        .is_some_and(|length| length != 9)
    {
        return Err(EnvelopeError::Malformed(
            "invalid envelope field count".to_owned(),
        ));
    }
    let version = decoder.u8().map_err(malformed)?;
    if version != ENVELOPE_VERSION {
        return Err(EnvelopeError::Malformed(format!(
            "unsupported envelope version {version}"
        )));
    }
    let session_id = copy_array::<16>(decoder.bytes().map_err(malformed)?, "session ID")?;
    let recipient = RecipientRole::from_code(decoder.u8().map_err(malformed)?)?;
    let secret_name = SecretName::new(decoder.str().map_err(malformed)?.to_owned())
        .map_err(|error| EnvelopeError::Malformed(error.to_string()))?;
    let sequence = decoder.u64().map_err(malformed)?;
    let expires_at_unix_ms = decoder.u64().map_err(malformed)?;
    let policy_digest =
        copy_array::<POLICY_DIGEST_BYTES>(decoder.bytes().map_err(malformed)?, "policy digest")?;
    let nonce = copy_array::<NONCE_BYTES>(decoder.bytes().map_err(malformed)?, "nonce")?;
    let ciphertext = decoder.bytes().map_err(malformed)?.to_vec();
    if ciphertext.len() < 16 || ciphertext.len() > MAX_SECRET_VALUE_BYTES + 16 {
        return Err(EnvelopeError::Malformed(
            "ciphertext size is outside allowed bounds".to_owned(),
        ));
    }
    if decoder.position() != payload.len() {
        return Err(EnvelopeError::Malformed(
            "envelope contains trailing data".to_owned(),
        ));
    }
    Ok(DecodedEnvelope {
        binding: EnvelopeBinding {
            session_id: SessionId::from_bytes(session_id),
            recipient,
            secret_name,
            sequence,
            expires_at_unix_ms,
            policy_digest,
        },
        nonce,
        ciphertext,
    })
}

fn copy_array<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N], EnvelopeError> {
    bytes
        .try_into()
        .map_err(|_| EnvelopeError::Malformed(format!("{field} has invalid length")))
}

fn malformed(error: minicbor::decode::Error) -> EnvelopeError {
    EnvelopeError::Malformed(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> EnvelopeBinding {
        EnvelopeBinding {
            session_id: SessionId::from_bytes([0x11; 16]),
            recipient: RecipientRole::Guest,
            secret_name: SecretName::new("API_TOKEN").expect("name"),
            sequence: 7,
            expires_at_unix_ms: 10_000,
            policy_digest: [0x22; 32],
        }
    }

    fn cipher() -> EnvelopeCipher {
        EnvelopeCipher::new(
            &SessionKeyMaterial::new(vec![0x33; 32]).expect("material"),
            binding().session_id,
        )
        .expect("cipher")
    }

    #[test]
    fn deterministic_vector_is_stable() {
        #[derive(serde::Deserialize)]
        struct Vector {
            encoded_hex: String,
        }
        let vector: Vector = serde_json::from_str(include_str!(
            "../../../test-fixtures/secrets/session-envelope-v1.json"
        ))
        .expect("fixture");
        let mut cipher = cipher();
        let encoded = cipher
            .seal_with_nonce(
                &binding(),
                &SecretValue::try_from("secret-value").expect("value"),
                [0x44; 24],
            )
            .expect("seal");
        assert_eq!(hex(&encoded), vector.encoded_hex);
    }

    #[test]
    fn round_trip_replay_expiry_and_wrong_bindings_fail_closed() {
        let mut cipher = cipher();
        let expected = binding();
        let encoded = cipher
            .seal_with_nonce(
                &expected,
                &SecretValue::try_from("secret-value").expect("value"),
                [0x55; 24],
            )
            .expect("seal");
        let replay = ReplayGuard::default();
        let opened = cipher
            .open(&encoded, &expected, &replay, 9_999)
            .expect("open");
        assert_eq!(opened.expose_secret(), b"secret-value");
        assert!(matches!(
            cipher.open(&encoded, &expected, &replay, 9_999),
            Err(EnvelopeError::Replay)
        ));
        assert!(matches!(
            cipher.open(&encoded, &expected, &ReplayGuard::default(), 10_000),
            Err(EnvelopeError::Expired)
        ));

        let mut wrong = expected.clone();
        wrong.sequence += 1;
        assert!(matches!(
            cipher.open(&encoded, &wrong, &ReplayGuard::default(), 9_999),
            Err(EnvelopeError::BindingMismatch)
        ));
        wrong = expected.clone();
        wrong.policy_digest[0] ^= 1;
        assert!(matches!(
            cipher.open(&encoded, &wrong, &ReplayGuard::default(), 9_999),
            Err(EnvelopeError::BindingMismatch)
        ));
        wrong = expected.clone();
        wrong.session_id = SessionId::from_bytes([0x99; 16]);
        assert!(matches!(
            cipher.open(&encoded, &wrong, &ReplayGuard::default(), 9_999),
            Err(EnvelopeError::BindingMismatch)
        ));
        wrong = expected;
        wrong.secret_name = SecretName::new("OTHER_TOKEN").expect("name");
        assert!(matches!(
            cipher.open(&encoded, &wrong, &ReplayGuard::default(), 9_999),
            Err(EnvelopeError::BindingMismatch)
        ));
    }

    #[test]
    fn tampering_and_duplicate_nonce_or_sequence_are_rejected() {
        let mut cipher = cipher();
        let expected = binding();
        let mut encoded = cipher
            .seal_with_nonce(
                &expected,
                &SecretValue::try_from("secret-value").expect("value"),
                [0x66; 24],
            )
            .expect("seal");
        let last = encoded.last_mut().expect("ciphertext");
        *last ^= 1;
        assert!(matches!(
            cipher.open(&encoded, &expected, &ReplayGuard::default(), 9_999),
            Err(EnvelopeError::AuthenticationFailed)
        ));

        assert!(matches!(
            cipher.seal_with_nonce(
                &expected,
                &SecretValue::try_from("again").expect("value"),
                [0x77; 24]
            ),
            Err(EnvelopeError::DuplicateIssuance)
        ));

        let mut next = expected;
        next.sequence += 1;
        assert!(matches!(
            cipher.seal_with_nonce(
                &next,
                &SecretValue::try_from("again").expect("value"),
                [0x66; 24]
            ),
            Err(EnvelopeError::DuplicateIssuance)
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
