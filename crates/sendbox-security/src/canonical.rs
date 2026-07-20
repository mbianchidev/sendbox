use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{SecurityError, SecurityResult};

pub(crate) fn encode<T: Serialize>(value: &T, format: &'static str) -> SecurityResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|error| SecurityError::Malformed {
        format,
        detail: error.to_string(),
    })
}

pub(crate) fn decode_canonical<T>(bytes: &[u8], format: &'static str) -> SecurityResult<T>
where
    T: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice(bytes).map_err(|error| SecurityError::Malformed {
        format,
        detail: error.to_string(),
    })?;
    if encode(&value, format)? != bytes {
        return Err(SecurityError::Malformed {
            format,
            detail: "non-canonical encoding".to_owned(),
        });
    }
    Ok(value)
}
