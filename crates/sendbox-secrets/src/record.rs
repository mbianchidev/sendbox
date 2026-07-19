use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

use crate::{
    MAX_SECRET_VALUE_BYTES, RecordVersion, Secret, SecretMetadata, SecretName, SecretStoreError,
    SecretValue,
};

const RECORD_MAGIC: &[u8] = b"\xffSBXSECRET\x01";
const RECORD_VERSION: u8 = 1;
const MAX_RECORD_BYTES: usize = MAX_SECRET_VALUE_BYTES + 1024;

pub(crate) fn encode_record(secret: &Secret) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        RECORD_MAGIC.len() + secret.value.expose_secret().len() + 128,
    ));
    bytes.extend_from_slice(RECORD_MAGIC);
    let mut encoder = Encoder::new(&mut *bytes);
    encoder
        .array(5)
        .and_then(|encoder| encoder.u8(RECORD_VERSION))
        .and_then(|encoder| encoder.str(secret.metadata.name.as_str()))
        .and_then(|encoder| encoder.u64(secret.metadata.created_at_unix_ms))
        .and_then(|encoder| encoder.u64(secret.metadata.updated_at_unix_ms))
        .and_then(|encoder| encoder.bytes(secret.value.expose_secret()))
        .map_err(|error| SecretStoreError::Corrupt(error.to_string()))?;
    Ok(bytes)
}

pub(crate) fn decode_record(bytes: &[u8]) -> Result<Secret, SecretStoreError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(SecretStoreError::Corrupt(
            "record exceeds maximum encoded size".to_owned(),
        ));
    }
    if !bytes.starts_with(RECORD_MAGIC) {
        let value = SecretValue::new(bytes.to_vec())?;
        let now = crate::types::unix_time_ms();
        return Ok(Secret {
            metadata: SecretMetadata {
                name: SecretName::new("legacy-placeholder")?,
                created_at_unix_ms: now,
                updated_at_unix_ms: now,
                version: RecordVersion::SwiftLegacy,
            },
            value,
        });
    }

    let mut decoder = Decoder::new(&bytes[RECORD_MAGIC.len()..]);
    if decoder
        .array()
        .map_err(corrupt)?
        .is_some_and(|length| length != 5)
    {
        return Err(SecretStoreError::Corrupt(
            "record field count is invalid".to_owned(),
        ));
    }
    let version = decoder.u8().map_err(corrupt)?;
    if version != RECORD_VERSION {
        return Err(SecretStoreError::Corrupt(format!(
            "unsupported record version {version}"
        )));
    }
    let name = SecretName::new(decoder.str().map_err(corrupt)?.to_owned())?;
    let created_at_unix_ms = decoder.u64().map_err(corrupt)?;
    let updated_at_unix_ms = decoder.u64().map_err(corrupt)?;
    if updated_at_unix_ms < created_at_unix_ms {
        return Err(SecretStoreError::Corrupt(
            "updated timestamp predates creation".to_owned(),
        ));
    }
    let value = SecretValue::new(decoder.bytes().map_err(corrupt)?.to_vec())?;
    if decoder.position() != bytes.len() - RECORD_MAGIC.len() {
        return Err(SecretStoreError::Corrupt(
            "record contains trailing data".to_owned(),
        ));
    }
    Ok(Secret {
        metadata: SecretMetadata {
            name,
            created_at_unix_ms,
            updated_at_unix_ms,
            version: RecordVersion::V1,
        },
        value,
    })
}

pub(crate) fn decode_for_name(
    name: &SecretName,
    bytes: &[u8],
    legacy_created_at_unix_ms: u64,
    legacy_updated_at_unix_ms: u64,
) -> Result<Secret, SecretStoreError> {
    let mut secret = decode_record(bytes)?;
    if secret.metadata.version == RecordVersion::SwiftLegacy {
        secret.metadata.name = name.clone();
        secret.metadata.created_at_unix_ms = legacy_created_at_unix_ms;
        secret.metadata.updated_at_unix_ms = legacy_updated_at_unix_ms;
    } else if &secret.metadata.name != name {
        return Err(SecretStoreError::Corrupt(
            "record name does not match encoded filename or account".to_owned(),
        ));
    }
    Ok(secret)
}

fn corrupt(error: minicbor::decode::Error) -> SecretStoreError {
    SecretStoreError::Corrupt(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip_and_corruption_detection() {
        let secret = Secret {
            metadata: SecretMetadata {
                name: SecretName::new("TOKEN_日本語").expect("name"),
                created_at_unix_ms: 10,
                updated_at_unix_ms: 20,
                version: RecordVersion::V1,
            },
            value: SecretValue::new(b"\0binary\xff".to_vec()).expect("value"),
        };
        let encoded = encode_record(&secret).expect("encode");
        let decoded = decode_record(&encoded).expect("decode");
        assert_eq!(decoded.metadata, secret.metadata);
        assert_eq!(decoded.value.expose_secret(), secret.value.expose_secret());

        let mut truncated = encoded.to_vec();
        truncated.pop();
        assert!(matches!(
            decode_record(&truncated),
            Err(SecretStoreError::Corrupt(_))
        ));
    }

    #[test]
    fn legacy_values_cannot_collide_with_record_magic() {
        let legacy = "plain Swift UTF-8 secret".as_bytes();
        let decoded = decode_record(legacy).expect("legacy");
        assert_eq!(decoded.metadata.version, RecordVersion::SwiftLegacy);
        assert_eq!(decoded.value.expose_secret(), legacy);

        let corrupt = RECORD_MAGIC.to_vec();
        assert!(matches!(
            decode_record(&corrupt),
            Err(SecretStoreError::Corrupt(_))
        ));
    }
}
