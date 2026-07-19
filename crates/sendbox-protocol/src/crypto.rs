use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ProtocolError;
use crate::types::MAC_BYTES;

const TRANSCRIPT_DOMAIN: &[u8] = b"sendbox protocol transcript v1";
const NEGOTIATION_DOMAIN: &[u8] = b"sendbox protocol negotiation v1";
const READINESS_DOMAIN: &[u8] = b"sendbox protocol readiness v1";
const FRAME_DOMAIN: &[u8] = b"sendbox protocol frame v1";
const HKDF_SALT_DOMAIN: &[u8] = b"sendbox protocol hkdf salt v1";

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct SessionKeys {
    negotiation: Zeroizing<[u8; MAC_BYTES]>,
    host_to_guest: Zeroizing<[u8; MAC_BYTES]>,
    guest_to_host: Zeroizing<[u8; MAC_BYTES]>,
}

impl SessionKeys {
    pub(crate) fn derive(
        bootstrap_secret: &[u8],
        hello_bytes: &[u8],
        negotiation_core: &[u8],
    ) -> Result<(Self, [u8; 32]), ProtocolError> {
        let transcript_hash = transcript_hash(hello_bytes, negotiation_core);
        let mut salt_hasher = Sha256::new();
        salt_hasher.update(HKDF_SALT_DOMAIN);
        salt_hasher.update(transcript_hash);
        let salt = salt_hasher.finalize();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), bootstrap_secret);

        let mut negotiation = Zeroizing::new([0_u8; MAC_BYTES]);
        let mut host_to_guest = Zeroizing::new([0_u8; MAC_BYTES]);
        let mut guest_to_host = Zeroizing::new([0_u8; MAC_BYTES]);
        hkdf.expand(b"sendbox protocol negotiation key v1", negotiation.as_mut())
            .map_err(|error| ProtocolError::MalformedEncoding(error.to_string()))?;
        hkdf.expand(
            b"sendbox protocol host-to-guest key v1",
            host_to_guest.as_mut(),
        )
        .map_err(|error| ProtocolError::MalformedEncoding(error.to_string()))?;
        hkdf.expand(
            b"sendbox protocol guest-to-host key v1",
            guest_to_host.as_mut(),
        )
        .map_err(|error| ProtocolError::MalformedEncoding(error.to_string()))?;

        Ok((
            Self {
                negotiation,
                host_to_guest,
                guest_to_host,
            },
            transcript_hash,
        ))
    }

    pub(crate) fn negotiation_proof(
        &self,
        hello_bytes: &[u8],
        negotiation_core: &[u8],
    ) -> Result<[u8; MAC_BYTES], ProtocolError> {
        mac_parts(
            self.negotiation.as_ref(),
            &[NEGOTIATION_DOMAIN, hello_bytes, negotiation_core],
        )
    }

    pub(crate) fn verify_negotiation_proof(
        &self,
        hello_bytes: &[u8],
        negotiation_core: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        verify_mac_parts(
            self.negotiation.as_ref(),
            &[NEGOTIATION_DOMAIN, hello_bytes, negotiation_core],
            proof,
        )
    }

    pub(crate) fn readiness_proof(
        &self,
        host_to_guest: bool,
        transcript_hash: &[u8; 32],
        readiness_core: &[u8],
    ) -> Result<[u8; MAC_BYTES], ProtocolError> {
        mac_parts(
            self.directional_key(host_to_guest),
            &[READINESS_DOMAIN, transcript_hash, readiness_core],
        )
    }

    pub(crate) fn verify_readiness_proof(
        &self,
        host_to_guest: bool,
        transcript_hash: &[u8; 32],
        readiness_core: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        verify_mac_parts(
            self.directional_key(host_to_guest),
            &[READINESS_DOMAIN, transcript_hash, readiness_core],
            proof,
        )
    }

    pub(crate) fn into_directional(
        self,
    ) -> (Zeroizing<[u8; MAC_BYTES]>, Zeroizing<[u8; MAC_BYTES]>) {
        (self.host_to_guest, self.guest_to_host)
    }

    fn directional_key(&self, host_to_guest: bool) -> &[u8] {
        if host_to_guest {
            self.host_to_guest.as_ref()
        } else {
            self.guest_to_host.as_ref()
        }
    }
}

pub(crate) fn frame_mac(
    key: &[u8],
    unsigned_frame: &[u8],
) -> Result<[u8; MAC_BYTES], ProtocolError> {
    mac_parts(key, &[FRAME_DOMAIN, unsigned_frame])
}

pub(crate) fn verify_frame_mac(
    key: &[u8],
    unsigned_frame: &[u8],
    proof: &[u8],
) -> Result<(), ProtocolError> {
    verify_mac_parts(key, &[FRAME_DOMAIN, unsigned_frame], proof)
}

fn transcript_hash(hello_bytes: &[u8], negotiation_core: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TRANSCRIPT_DOMAIN);
    hasher.update(hello_bytes);
    hasher.update(negotiation_core);
    hasher.finalize().into()
}

fn mac_parts(key: &[u8], parts: &[&[u8]]) -> Result<[u8; MAC_BYTES], ProtocolError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|error| ProtocolError::MalformedEncoding(error.to_string()))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn verify_mac_parts(key: &[u8], parts: &[&[u8]], proof: &[u8]) -> Result<(), ProtocolError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|error| ProtocolError::MalformedEncoding(error.to_string()))?;
    for part in parts {
        mac.update(part);
    }
    mac.verify_slice(proof)
        .map_err(|_| ProtocolError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use sendbox_core::SessionId;
    use serde::Deserialize;

    use super::*;
    use crate::codec::encode_negotiation_core;
    use crate::{
        Capability, CapabilitySet, Hello, Message, Negotiation, PROTOCOL_MAGIC, PeerRole,
        VersionRange,
    };

    #[derive(Deserialize)]
    struct Vector {
        session_id: String,
        bootstrap_secret: String,
        client_nonce: String,
        server_nonce: String,
        hello_hex: String,
        negotiation_core_hex: String,
        transcript_hash: String,
        negotiation_mac: String,
        host_to_guest_key: String,
        guest_to_host_key: String,
        negotiated_capabilities: Vec<u16>,
    }

    #[test]
    fn deterministic_session_vector_is_stable() {
        let vector: Vector = serde_json::from_str(include_str!(
            "../../../test-fixtures/protocol/v1-authenticated-session.json"
        ))
        .expect("fixture");
        assert_eq!(vector.negotiated_capabilities, vec![1, 2, 9]);
        let session_id = SessionId::from_bytes(decode_hex_array(&vector.session_id));
        let client_nonce = decode_hex_array(&vector.client_nonce);
        let server_nonce = decode_hex_array(&vector.server_nonce);
        let bootstrap_secret = decode_hex(&vector.bootstrap_secret);
        let hello = Message::Hello(Hello {
            magic: PROTOCOL_MAGIC,
            versions: VersionRange::new(1, 2),
            session_id,
            role: PeerRole::HostClient,
            nonce: client_nonce,
            capabilities: [
                Capability::Lifecycle,
                Capability::Exec,
                Capability::StreamedIo,
                Capability::Health,
            ]
            .into(),
            required_capabilities: [Capability::Lifecycle].into(),
            max_frame_bytes: 65_536,
        });
        let hello_bytes = crate::encode_message(&hello).expect("hello encoding");
        let negotiation = Negotiation {
            magic: PROTOCOL_MAGIC,
            versions: VersionRange::new(1, 2),
            selected_version: 2,
            session_id,
            role: PeerRole::GuestServer,
            client_nonce,
            server_nonce,
            capabilities: [
                Capability::Lifecycle,
                Capability::Exec,
                Capability::Audit,
                Capability::Health,
            ]
            .into(),
            required_capabilities: [Capability::Health].into(),
            negotiated_capabilities: [Capability::Lifecycle, Capability::Exec, Capability::Health]
                .into(),
            max_frame_bytes: 65_536,
            proof: [0; MAC_BYTES],
        };
        let negotiation_core =
            encode_negotiation_core(&negotiation).expect("negotiation core encoding");
        let (keys, transcript_hash) =
            SessionKeys::derive(&bootstrap_secret, &hello_bytes, &negotiation_core)
                .expect("derive keys");
        let negotiation_mac = keys
            .negotiation_proof(&hello_bytes, &negotiation_core)
            .expect("negotiation proof");

        let actual = [
            ("hello_hex", hex(&hello_bytes), vector.hello_hex),
            (
                "negotiation_core_hex",
                hex(&negotiation_core),
                vector.negotiation_core_hex,
            ),
            (
                "transcript_hash",
                hex(&transcript_hash),
                vector.transcript_hash,
            ),
            (
                "negotiation_mac",
                hex(&negotiation_mac),
                vector.negotiation_mac,
            ),
            (
                "host_to_guest_key",
                hex(keys.host_to_guest.as_ref()),
                vector.host_to_guest_key,
            ),
            (
                "guest_to_host_key",
                hex(keys.guest_to_host.as_ref()),
                vector.guest_to_host_key,
            ),
        ];
        let mismatches = actual
            .into_iter()
            .filter(|(_, actual, expected)| actual != expected)
            .map(|(name, actual, _)| format!("{name}={actual}"))
            .collect::<Vec<_>>();
        if !mismatches.is_empty() {
            panic!("{}", mismatches.join("\n"));
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hex utf8");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }

    fn decode_hex_array<const N: usize>(value: &str) -> [u8; N] {
        decode_hex(value).try_into().expect("fixed-size hex")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn directional_keys_are_separated() {
        let (keys, _) = SessionKeys::derive(b"0123456789abcdef0123456789abcdef", b"hello", b"core")
            .expect("keys");
        assert_ne!(keys.host_to_guest.as_ref(), keys.guest_to_host.as_ref());
        assert_ne!(keys.negotiation.as_ref(), keys.host_to_guest.as_ref());
    }

    #[test]
    fn negotiated_capability_fixture_is_typed() {
        let capabilities: CapabilitySet =
            [Capability::Lifecycle, Capability::Exec, Capability::Health].into();
        assert!(capabilities.contains(Capability::Health));
    }
}
