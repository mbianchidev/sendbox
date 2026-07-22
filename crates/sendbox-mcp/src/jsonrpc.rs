use std::collections::BTreeSet;
use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::error::JsonRpcError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Notification,
    Response,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMessage {
    pub kind: MessageKind,
    pub method: Option<String>,
    pub id: IdPresence,
    pub subject: Option<String>,
    pub error_code: Option<i64>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdPresence {
    Missing,
    Present(String),
}

impl IdPresence {
    #[must_use]
    pub fn raw(&self) -> Option<&str> {
        match self {
            Self::Missing => None,
            Self::Present(raw) => Some(raw),
        }
    }
}

#[derive(Debug, Default)]
enum Presence<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T> Deserialize<'de> for Presence<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Debug, Deserialize)]
struct RawFields {
    #[serde(default)]
    id: Presence<Box<RawValue>>,
}

pub fn validate_message(payload: &[u8]) -> Result<ValidatedMessage, JsonRpcError> {
    let text = std::str::from_utf8(payload).map_err(|_| JsonRpcError::InvalidUtf8)?;
    let value = serde_json::from_str::<StrictValue>(text)
        .map_err(|error| JsonRpcError::InvalidJson(error.to_string()))?
        .0;
    if value.is_array() {
        return Err(JsonRpcError::BatchUnsupported);
    }

    struct StrictValue(Value);

    impl<'de> Deserialize<'de> for StrictValue {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(StrictValueVisitor)
        }
    }

    struct StrictValueVisitor;

    impl<'de> Visitor<'de> for StrictValueVisitor {
        type Value = StrictValue;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON value without duplicate object keys")
        }

        fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
            Ok(StrictValue(Value::Bool(value)))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
            Ok(StrictValue(Value::Number(value.into())))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(StrictValue(Value::Number(value.into())))
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .map(StrictValue)
                .ok_or_else(|| E::custom("non-finite JSON number"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
            Ok(StrictValue(Value::String(value.to_owned())))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
            Ok(StrictValue(Value::String(value)))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(StrictValue(Value::Null))
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(StrictValue(Value::Null))
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element::<StrictValue>()? {
                values.push(value.0);
            }
            Ok(StrictValue(Value::Array(values)))
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut keys = BTreeSet::new();
            let mut values = serde_json::Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if !keys.insert(key.clone()) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate object key '{key}'"
                    )));
                }
                values.insert(key, map.next_value::<StrictValue>()?.0);
            }
            Ok(StrictValue(Value::Object(values)))
        }
    }
    let object = value.as_object().ok_or(JsonRpcError::NotObject)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(JsonRpcError::InvalidVersion);
    }

    let raw_fields: RawFields =
        serde_json::from_str(text).map_err(|error| JsonRpcError::InvalidJson(error.to_string()))?;
    let id = match raw_fields.id {
        Presence::Missing => IdPresence::Missing,
        Presence::Present(raw) => {
            validate_raw_id(raw.get())?;
            IdPresence::Present(raw.get().to_owned())
        }
    };

    let method = match object.get("method") {
        Some(Value::String(method)) if !method.is_empty() => Some(method.clone()),
        Some(_) => {
            return Err(JsonRpcError::InvalidShape(
                "method must be a non-empty string".into(),
            ));
        }
        None => None,
    };

    if let Some(params) = object.get("params")
        && !params.is_object()
        && !params.is_array()
    {
        return Err(JsonRpcError::InvalidShape(
            "params must be an object or array".into(),
        ));
    }

    if let Some(method) = method {
        if object.contains_key("result") || object.contains_key("error") {
            return Err(JsonRpcError::InvalidShape(
                "requests and notifications cannot contain result or error".into(),
            ));
        }
        let subject = object
            .get("params")
            .and_then(Value::as_object)
            .and_then(|params| {
                params
                    .get("name")
                    .and_then(Value::as_str)
                    .or_else(|| params.get("uri").and_then(Value::as_str))
                    .or_else(|| {
                        params
                            .get("ref")
                            .and_then(Value::as_object)
                            .and_then(|reference| reference.get("name"))
                            .and_then(Value::as_str)
                    })
            })
            .map(str::to_owned);
        let kind = if matches!(id, IdPresence::Missing) {
            MessageKind::Notification
        } else {
            MessageKind::Request
        };
        return Ok(ValidatedMessage {
            kind,
            method: Some(method),
            id,
            subject,
            error_code: None,
            error_message: None,
        });
    }

    if matches!(id, IdPresence::Missing) {
        return Err(JsonRpcError::InvalidShape(
            "responses must contain an id".into(),
        ));
    }
    if object.contains_key("params") {
        return Err(JsonRpcError::InvalidShape(
            "responses cannot contain params".into(),
        ));
    }
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    if has_result == has_error {
        return Err(JsonRpcError::InvalidShape(
            "responses must contain exactly one of result or error".into(),
        ));
    }
    if has_error {
        let error = object
            .get("error")
            .and_then(Value::as_object)
            .ok_or_else(|| JsonRpcError::InvalidShape("error must be an object".into()))?;
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .ok_or_else(|| JsonRpcError::InvalidShape("error.code must be an integer".into()))?;
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::InvalidShape("error.message must be a string".into()))?;
        return Ok(ValidatedMessage {
            kind: MessageKind::Error,
            method: None,
            id,
            subject: None,
            error_code: Some(code),
            error_message: Some(message.to_owned()),
        });
    }

    Ok(ValidatedMessage {
        kind: MessageKind::Response,
        method: None,
        id,
        subject: None,
        error_code: None,
        error_message: None,
    })
}

fn validate_raw_id(raw: &str) -> Result<(), JsonRpcError> {
    if raw == "null" {
        return Ok(());
    }
    if raw.starts_with('"') {
        return serde_json::from_str::<String>(raw)
            .map(|_| ())
            .map_err(|_| JsonRpcError::InvalidId);
    }
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(JsonRpcError::InvalidId);
    }
    Ok(())
}

pub fn denial_response(id_raw: &str, tool: &str, reason: &str) -> Vec<u8> {
    let tool = serde_json::to_string(tool).expect("string serialization cannot fail");
    let reason = serde_json::to_string(reason).expect("string serialization cannot fail");
    format!(
        "{{\"error\":{{\"code\":-32001,\"data\":{{\"reason\":{reason},\"tool\":{tool}}},\"message\":\"Tool call denied by SendBox boundary policy\"}},\"id\":{id_raw},\"jsonrpc\":\"2.0\"}}"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_id_is_a_request_not_a_notification() {
        let message =
            validate_message(br#"{"jsonrpc":"2.0","id":null,"method":"tools/call"}"#).unwrap();
        assert_eq!(message.kind, MessageKind::Request);
        assert_eq!(message.id.raw(), Some("null"));
    }

    #[test]
    fn denial_preserves_large_numeric_id_lexically() {
        let message = validate_message(
            br#"{"jsonrpc":"2.0","id":184467440737095516160,"method":"tools/call","params":{"name":"x"}}"#,
        )
        .unwrap();
        let response = denial_response(message.id.raw().unwrap(), "x", "denied");
        assert!(
            String::from_utf8(response)
                .unwrap()
                .contains("\"id\":184467440737095516160")
        );
    }

    #[test]
    fn rejects_fractional_id_and_batches() {
        assert_eq!(
            validate_message(br#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#),
            Err(JsonRpcError::InvalidId)
        );
        assert_eq!(
            validate_message(br#"[{"jsonrpc":"2.0","method":"ping"}]"#),
            Err(JsonRpcError::BatchUnsupported)
        );
    }

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        assert!(
            validate_message(br#"{"jsonrpc":"2.0","method":"tools/call","method":"ping"}"#)
                .is_err()
        );
        assert!(validate_message(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read","name":"delete"}}"#
        )
        .is_err());
    }
}
