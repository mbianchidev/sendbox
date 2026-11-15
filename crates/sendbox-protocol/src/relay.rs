//! Wire payloads for the brokered credential relay.
//!
//! A relay stream carries one HTTP request from the guest to the host broker
//! and one streamed response back. Stream identifiers are chosen by the guest,
//! start at [`CREDENTIAL_RELAY_STREAM_BASE`] so they never collide with request
//! identifiers, and increase strictly. Response body chunks are flow
//! controlled: the host may only send a chunk for which the guest granted
//! credit, and the guest grants at most [`CREDENTIAL_RELAY_WINDOW_CHUNKS`]
//! outstanding chunks per stream.

use serde::{Deserialize, Serialize};

pub const CREDENTIAL_RELAY_SCHEMA_VERSION: u32 = 1;
pub const CREDENTIAL_RELAY_STREAM_BASE: u64 = 1 << 32;
pub const CREDENTIAL_RELAY_CHUNK_BYTES: usize = 32 * 1024;
pub const CREDENTIAL_RELAY_WINDOW_CHUNKS: u16 = 16;
pub const MAX_CREDENTIAL_RELAY_HEADERS: usize = 64;
pub const MAX_CREDENTIAL_RELAY_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_CREDENTIAL_RELAY_PATH_BYTES: usize = 4096;
const MAX_REASON_BYTES: usize = 64;
const MAX_SERVICE_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialRelayError {
    #[error("unsupported credential relay schema version")]
    UnsupportedSchema,
    #[error("credential relay service identifier is invalid")]
    InvalidService,
    #[error("credential relay method is invalid")]
    InvalidMethod,
    #[error("credential relay path must be an origin-form path")]
    InvalidPath,
    #[error("credential relay headers exceed the configured limits or are malformed")]
    InvalidHeaders,
    #[error("credential relay status code is invalid")]
    InvalidStatus,
    #[error("credential relay credit must be within the stream window")]
    InvalidCredit,
    #[error("credential relay reason is invalid")]
    InvalidReason,
}

/// One HTTP header carried across the relay. Values are bytes-safe strings
/// that already passed HTTP header validation at the sender.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRelayHeaderV1 {
    pub name: String,
    pub value: String,
}

impl std::fmt::Debug for CredentialRelayHeaderV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialRelayHeaderV1")
            .field("name", &self.name)
            .field("value", &format_args!("<{} bytes>", self.value.len()))
            .finish()
    }
}

/// Guest to host: opens a relay stream for one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRelayRequestV1 {
    pub schema_version: u32,
    pub service: String,
    pub method: String,
    /// Upstream origin-form target: absolute path plus optional query.
    pub path: String,
    pub headers: Vec<CredentialRelayHeaderV1>,
    pub body_bytes: u64,
}

/// Host to guest: the upstream response status and forwarded headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRelayResponseHeadV1 {
    pub schema_version: u32,
    pub status: u16,
    pub headers: Vec<CredentialRelayHeaderV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRelayOutcomeV1 {
    /// The upstream response completed.
    Complete,
    /// Authorization denied the request before any upstream contact.
    Denied,
    /// The request failed. If a response head was already sent the upstream
    /// may have processed the request.
    Failed,
    /// The stream was aborted by the peer or by session teardown.
    Aborted,
}

/// Either direction: terminates a relay stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRelayEndV1 {
    pub schema_version: u32,
    pub outcome: CredentialRelayOutcomeV1,
    /// Stable machine-readable reason code; never contains request data.
    pub reason: String,
}

/// Guest to host: permits more response body chunks for one stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRelayCreditV1 {
    pub schema_version: u32,
    pub credits: u16,
}

#[must_use]
pub const fn valid_credential_relay_stream(stream_id: u64) -> bool {
    stream_id >= CREDENTIAL_RELAY_STREAM_BASE
}

fn validate_schema(version: u32) -> Result<(), CredentialRelayError> {
    if version == CREDENTIAL_RELAY_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CredentialRelayError::UnsupportedSchema)
    }
}

fn validate_headers(headers: &[CredentialRelayHeaderV1]) -> Result<(), CredentialRelayError> {
    let bytes = headers.iter().fold(0_usize, |total, header| {
        total
            .saturating_add(header.name.len())
            .saturating_add(header.value.len())
            .saturating_add(4)
    });
    let malformed = headers.iter().any(|header| {
        header.name.is_empty()
            || !header
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || header
                .value
                .bytes()
                .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    });
    if headers.len() > MAX_CREDENTIAL_RELAY_HEADERS
        || bytes > MAX_CREDENTIAL_RELAY_HEADER_BYTES
        || malformed
    {
        Err(CredentialRelayError::InvalidHeaders)
    } else {
        Ok(())
    }
}

impl CredentialRelayRequestV1 {
    pub fn validate(&self) -> Result<(), CredentialRelayError> {
        validate_schema(self.schema_version)?;
        let service = self.service.as_bytes();
        if service.is_empty()
            || service.len() > MAX_SERVICE_BYTES
            || !service[0].is_ascii_lowercase()
            || !service
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(CredentialRelayError::InvalidService);
        }
        if self.method.is_empty()
            || self.method.len() > 16
            || !self.method.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(CredentialRelayError::InvalidMethod);
        }
        if !self.path.starts_with('/')
            || self.path.starts_with("//")
            || self.path.len() > MAX_CREDENTIAL_RELAY_PATH_BYTES
            || !self
                .path
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'#')
        {
            return Err(CredentialRelayError::InvalidPath);
        }
        validate_headers(&self.headers)
    }
}

impl CredentialRelayResponseHeadV1 {
    pub fn validate(&self) -> Result<(), CredentialRelayError> {
        validate_schema(self.schema_version)?;
        if !(100..=599).contains(&self.status) {
            return Err(CredentialRelayError::InvalidStatus);
        }
        validate_headers(&self.headers)
    }
}

impl CredentialRelayEndV1 {
    pub fn new(outcome: CredentialRelayOutcomeV1, reason: &str) -> Self {
        Self {
            schema_version: CREDENTIAL_RELAY_SCHEMA_VERSION,
            outcome,
            reason: reason.to_owned(),
        }
    }

    pub fn validate(&self) -> Result<(), CredentialRelayError> {
        validate_schema(self.schema_version)?;
        if self.reason.is_empty()
            || self.reason.len() > MAX_REASON_BYTES
            || !self
                .reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(CredentialRelayError::InvalidReason);
        }
        Ok(())
    }
}

impl CredentialRelayCreditV1 {
    pub fn new(credits: u16) -> Result<Self, CredentialRelayError> {
        let credit = Self {
            schema_version: CREDENTIAL_RELAY_SCHEMA_VERSION,
            credits,
        };
        credit.validate()?;
        Ok(credit)
    }

    pub fn validate(self) -> Result<(), CredentialRelayError> {
        validate_schema(self.schema_version)?;
        if self.credits == 0 || self.credits > CREDENTIAL_RELAY_WINDOW_CHUNKS {
            return Err(CredentialRelayError::InvalidCredit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> CredentialRelayRequestV1 {
        CredentialRelayRequestV1 {
            schema_version: CREDENTIAL_RELAY_SCHEMA_VERSION,
            service: "anthropic".to_owned(),
            method: "POST".to_owned(),
            path: "/v1/messages?beta=true".to_owned(),
            headers: vec![CredentialRelayHeaderV1 {
                name: "content-type".to_owned(),
                value: "application/json".to_owned(),
            }],
            body_bytes: 12,
        }
    }

    #[test]
    fn relay_requests_are_bounded_and_origin_form() {
        assert!(request().validate().is_ok());
        for mutate in [
            (|request: &mut CredentialRelayRequestV1| request.schema_version = 2)
                as fn(&mut CredentialRelayRequestV1),
            |request| request.service = "Anthropic".to_owned(),
            |request| request.method = "post".to_owned(),
            |request| request.path = "https://evil.example/v1".to_owned(),
            |request| request.path = "//evil.example/v1".to_owned(),
            |request| request.path = "/v1/messages#x".to_owned(),
            |request| request.headers[0].value = "a\r\nx-api-key: leak".to_owned(),
            |request| request.headers[0].name = "bad header".to_owned(),
            |request| {
                request.headers = (0..=MAX_CREDENTIAL_RELAY_HEADERS)
                    .map(|index| CredentialRelayHeaderV1 {
                        name: format!("x-{index}"),
                        value: String::new(),
                    })
                    .collect();
            },
        ] {
            let mut candidate = request();
            mutate(&mut candidate);
            assert!(candidate.validate().is_err(), "{candidate:?}");
        }
    }

    #[test]
    fn credit_end_and_head_payloads_are_validated() {
        assert!(CredentialRelayCreditV1::new(CREDENTIAL_RELAY_WINDOW_CHUNKS).is_ok());
        assert!(CredentialRelayCreditV1::new(0).is_err());
        assert!(CredentialRelayCreditV1::new(CREDENTIAL_RELAY_WINDOW_CHUNKS + 1).is_err());
        assert!(
            CredentialRelayEndV1::new(CredentialRelayOutcomeV1::Denied, "stale_policy")
                .validate()
                .is_ok()
        );
        assert!(
            CredentialRelayEndV1::new(CredentialRelayOutcomeV1::Failed, "Bearer abc")
                .validate()
                .is_err()
        );
        let head = CredentialRelayResponseHeadV1 {
            schema_version: CREDENTIAL_RELAY_SCHEMA_VERSION,
            status: 99,
            headers: Vec::new(),
        };
        assert!(head.validate().is_err());
        assert!(!valid_credential_relay_stream(7));
        assert!(valid_credential_relay_stream(CREDENTIAL_RELAY_STREAM_BASE));
    }

    #[test]
    fn header_debug_redacts_values() {
        let header = CredentialRelayHeaderV1 {
            name: "authorization".to_owned(),
            value: "Bearer secret".to_owned(),
        };
        assert!(!format!("{header:?}").contains("secret"));
    }
}
