use std::convert::Infallible;

use minicbor::data::Type;
use minicbor::decode;
use minicbor::encode;
use minicbor::{Decoder, Encoder};
use sendbox_core::SessionId;

use crate::{
    Cancellation, Capability, CapabilitySet, CloseCode, Event, EventKind, GracefulClose, Hello,
    Message, MessageKind, Negotiation, PeerRole, ProtocolError, ProtocolErrorCode,
    ProtocolErrorMessage, Readiness, Request, Response, ResponseStatus, VersionRange,
};

pub fn encode_message(message: &Message) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_message_to(&mut encoder, message)?;
    Ok(encoder.into_writer())
}

pub fn decode_message(bytes: &[u8]) -> Result<Message, ProtocolError> {
    let mut decoder = Decoder::new(bytes);
    let message = decode_message_from(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::MalformedEncoding(
            "trailing bytes after message".to_owned(),
        ));
    }
    if encode_message(&message)? != bytes {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    Ok(message)
}

pub(crate) fn encode_negotiation_core(negotiation: &Negotiation) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_array(&mut encoder, 13)?;
    encode_u8(&mut encoder, MessageKind::CapabilityNegotiation as u8)?;
    encode_bytes(&mut encoder, &negotiation.magic)?;
    encode_u16(&mut encoder, negotiation.versions.minimum)?;
    encode_u16(&mut encoder, negotiation.versions.maximum)?;
    encode_u16(&mut encoder, negotiation.selected_version)?;
    encode_bytes(&mut encoder, negotiation.session_id.as_bytes())?;
    encode_u8(&mut encoder, negotiation.role as u8)?;
    encode_bytes(&mut encoder, &negotiation.client_nonce)?;
    encode_bytes(&mut encoder, &negotiation.server_nonce)?;
    encode_capabilities(&mut encoder, &negotiation.capabilities)?;
    encode_capabilities(&mut encoder, &negotiation.required_capabilities)?;
    encode_capabilities(&mut encoder, &negotiation.negotiated_capabilities)?;
    encode_u32(&mut encoder, negotiation.max_frame_bytes)?;
    Ok(encoder.into_writer())
}

pub(crate) fn encode_readiness_core(readiness: &Readiness) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_array(&mut encoder, 6)?;
    encode_u8(&mut encoder, MessageKind::Readiness as u8)?;
    encode_u8(&mut encoder, readiness.role as u8)?;
    encode_bytes(&mut encoder, readiness.session_id.as_bytes())?;
    encode_u16(&mut encoder, readiness.selected_version)?;
    encode_capabilities(&mut encoder, &readiness.negotiated_capabilities)?;
    encode_u32(&mut encoder, readiness.max_frame_bytes)?;
    Ok(encoder.into_writer())
}

pub(crate) fn encode_message_to(
    encoder: &mut Encoder<Vec<u8>>,
    message: &Message,
) -> Result<(), ProtocolError> {
    match message {
        Message::Hello(hello) => {
            encode_array(encoder, 10)?;
            encode_u8(encoder, MessageKind::Hello as u8)?;
            encode_bytes(encoder, &hello.magic)?;
            encode_u16(encoder, hello.versions.minimum)?;
            encode_u16(encoder, hello.versions.maximum)?;
            encode_bytes(encoder, hello.session_id.as_bytes())?;
            encode_u8(encoder, hello.role as u8)?;
            encode_bytes(encoder, &hello.nonce)?;
            encode_capabilities(encoder, &hello.capabilities)?;
            encode_capabilities(encoder, &hello.required_capabilities)?;
            encode_u32(encoder, hello.max_frame_bytes)?;
        }
        Message::CapabilityNegotiation(negotiation) => {
            encode_array(encoder, 14)?;
            encode_u8(encoder, MessageKind::CapabilityNegotiation as u8)?;
            encode_bytes(encoder, &negotiation.magic)?;
            encode_u16(encoder, negotiation.versions.minimum)?;
            encode_u16(encoder, negotiation.versions.maximum)?;
            encode_u16(encoder, negotiation.selected_version)?;
            encode_bytes(encoder, negotiation.session_id.as_bytes())?;
            encode_u8(encoder, negotiation.role as u8)?;
            encode_bytes(encoder, &negotiation.client_nonce)?;
            encode_bytes(encoder, &negotiation.server_nonce)?;
            encode_capabilities(encoder, &negotiation.capabilities)?;
            encode_capabilities(encoder, &negotiation.required_capabilities)?;
            encode_capabilities(encoder, &negotiation.negotiated_capabilities)?;
            encode_u32(encoder, negotiation.max_frame_bytes)?;
            encode_bytes(encoder, &negotiation.proof)?;
        }
        Message::Readiness(readiness) => {
            encode_array(encoder, 7)?;
            encode_u8(encoder, MessageKind::Readiness as u8)?;
            encode_u8(encoder, readiness.role as u8)?;
            encode_bytes(encoder, readiness.session_id.as_bytes())?;
            encode_u16(encoder, readiness.selected_version)?;
            encode_capabilities(encoder, &readiness.negotiated_capabilities)?;
            encode_u32(encoder, readiness.max_frame_bytes)?;
            encode_bytes(encoder, &readiness.proof)?;
        }
        Message::Request(request) => {
            encode_array(encoder, 4)?;
            encode_u8(encoder, MessageKind::Request as u8)?;
            encode_u64(encoder, request.request_id)?;
            encode_str(encoder, &request.operation)?;
            encode_bytes(encoder, &request.payload)?;
        }
        Message::Response(response) => {
            encode_array(encoder, 4)?;
            encode_u8(encoder, MessageKind::Response as u8)?;
            encode_u64(encoder, response.request_id)?;
            encode_u8(encoder, response.status as u8)?;
            encode_bytes(encoder, &response.payload)?;
        }
        Message::Event(event) => {
            encode_array(encoder, 4)?;
            encode_u8(encoder, MessageKind::Event as u8)?;
            encode_u64(encoder, event.stream_id)?;
            encode_u8(encoder, event.kind as u8)?;
            encode_bytes(encoder, &event.payload)?;
        }
        Message::Cancellation(cancellation) => {
            encode_array(encoder, 3)?;
            encode_u8(encoder, MessageKind::Cancellation as u8)?;
            encode_u64(encoder, cancellation.request_id)?;
            match &cancellation.reason {
                Some(reason) => encode_str(encoder, reason)?,
                None => {
                    encoder.null().map_err(encode_error)?;
                }
            }
        }
        Message::GracefulClose(close) => {
            encode_array(encoder, 3)?;
            encode_u8(encoder, MessageKind::GracefulClose as u8)?;
            encode_u8(encoder, close.code as u8)?;
            encode_str(encoder, &close.reason)?;
        }
        Message::ProtocolError(error) => {
            encode_array(encoder, 3)?;
            encode_u8(encoder, MessageKind::ProtocolError as u8)?;
            encode_u16(encoder, error.code as u16)?;
            encode_str(encoder, &error.detail)?;
        }
    }
    Ok(())
}

pub(crate) fn decode_message_from(decoder: &mut Decoder<'_>) -> Result<Message, ProtocolError> {
    let length = decode_array_length(decoder)?;
    let kind = decoder.u8().map_err(decode_error)?;
    match kind {
        value if value == MessageKind::Hello as u8 => {
            require_array_length(length, 10)?;
            Ok(Message::Hello(Hello {
                magic: decode_fixed_bytes(decoder)?,
                versions: VersionRange::new(
                    decoder.u16().map_err(decode_error)?,
                    decoder.u16().map_err(decode_error)?,
                ),
                session_id: SessionId::from_bytes(decode_fixed_bytes(decoder)?),
                role: decode_role(decoder)?,
                nonce: decode_fixed_bytes(decoder)?,
                capabilities: decode_capabilities(decoder)?,
                required_capabilities: decode_capabilities(decoder)?,
                max_frame_bytes: decoder.u32().map_err(decode_error)?,
            }))
        }
        value if value == MessageKind::CapabilityNegotiation as u8 => {
            require_array_length(length, 14)?;
            Ok(Message::CapabilityNegotiation(Negotiation {
                magic: decode_fixed_bytes(decoder)?,
                versions: VersionRange::new(
                    decoder.u16().map_err(decode_error)?,
                    decoder.u16().map_err(decode_error)?,
                ),
                selected_version: decoder.u16().map_err(decode_error)?,
                session_id: SessionId::from_bytes(decode_fixed_bytes(decoder)?),
                role: decode_role(decoder)?,
                client_nonce: decode_fixed_bytes(decoder)?,
                server_nonce: decode_fixed_bytes(decoder)?,
                capabilities: decode_capabilities(decoder)?,
                required_capabilities: decode_capabilities(decoder)?,
                negotiated_capabilities: decode_capabilities(decoder)?,
                max_frame_bytes: decoder.u32().map_err(decode_error)?,
                proof: decode_fixed_bytes(decoder)?,
            }))
        }
        value if value == MessageKind::Readiness as u8 => {
            require_array_length(length, 7)?;
            Ok(Message::Readiness(Readiness {
                role: decode_role(decoder)?,
                session_id: SessionId::from_bytes(decode_fixed_bytes(decoder)?),
                selected_version: decoder.u16().map_err(decode_error)?,
                negotiated_capabilities: decode_capabilities(decoder)?,
                max_frame_bytes: decoder.u32().map_err(decode_error)?,
                proof: decode_fixed_bytes(decoder)?,
            }))
        }
        value if value == MessageKind::Request as u8 => {
            require_array_length(length, 4)?;
            Ok(Message::Request(Request {
                request_id: decoder.u64().map_err(decode_error)?,
                operation: decoder.str().map_err(decode_error)?.to_owned(),
                payload: decoder.bytes().map_err(decode_error)?.to_vec(),
            }))
        }
        value if value == MessageKind::Response as u8 => {
            require_array_length(length, 4)?;
            Ok(Message::Response(Response {
                request_id: decoder.u64().map_err(decode_error)?,
                status: decode_response_status(decoder)?,
                payload: decoder.bytes().map_err(decode_error)?.to_vec(),
            }))
        }
        value if value == MessageKind::Event as u8 => {
            require_array_length(length, 4)?;
            Ok(Message::Event(Event {
                stream_id: decoder.u64().map_err(decode_error)?,
                kind: decode_event_kind(decoder)?,
                payload: decoder.bytes().map_err(decode_error)?.to_vec(),
            }))
        }
        value if value == MessageKind::Cancellation as u8 => {
            require_array_length(length, 3)?;
            let request_id = decoder.u64().map_err(decode_error)?;
            let reason = match decoder.datatype().map_err(decode_error)? {
                Type::Null => {
                    decoder.null().map_err(decode_error)?;
                    None
                }
                Type::String => Some(decoder.str().map_err(decode_error)?.to_owned()),
                other => {
                    return Err(ProtocolError::MalformedEncoding(format!(
                        "invalid cancellation reason type {other:?}"
                    )));
                }
            };
            Ok(Message::Cancellation(Cancellation { request_id, reason }))
        }
        value if value == MessageKind::GracefulClose as u8 => {
            require_array_length(length, 3)?;
            Ok(Message::GracefulClose(GracefulClose {
                code: decode_close_code(decoder)?,
                reason: decoder.str().map_err(decode_error)?.to_owned(),
            }))
        }
        value if value == MessageKind::ProtocolError as u8 => {
            require_array_length(length, 3)?;
            Ok(Message::ProtocolError(ProtocolErrorMessage {
                code: decode_protocol_error_code(decoder)?,
                detail: decoder.str().map_err(decode_error)?.to_owned(),
            }))
        }
        value => Err(ProtocolError::UnsupportedMessageKind(value)),
    }
}

fn encode_capabilities(
    encoder: &mut Encoder<Vec<u8>>,
    capabilities: &CapabilitySet,
) -> Result<(), ProtocolError> {
    encode_array(
        encoder,
        u64::try_from(capabilities.iter().len())
            .map_err(|error| ProtocolError::MalformedEncoding(error.to_string()))?,
    )?;
    for capability in capabilities.iter() {
        encode_u16(encoder, capability as u16)?;
    }
    Ok(())
}

fn decode_capabilities(decoder: &mut Decoder<'_>) -> Result<CapabilitySet, ProtocolError> {
    let length = decode_array_length(decoder)?;
    if length > Capability::COUNT {
        return Err(ProtocolError::MalformedEncoding(format!(
            "capability array length {length} exceeds {}",
            Capability::COUNT
        )));
    }
    let capacity = usize::try_from(length)
        .map_err(|error| ProtocolError::MalformedEncoding(error.to_string()))?;
    let mut capabilities = Vec::with_capacity(capacity);
    for _ in 0..length {
        capabilities.push(decode_capability(decoder)?);
    }
    let set = CapabilitySet::new(capabilities.iter().copied());
    if set.iter().len() != capabilities.len() {
        return Err(ProtocolError::MalformedEncoding(
            "duplicate capabilities are invalid".to_owned(),
        ));
    }
    Ok(set)
}

fn decode_capability(decoder: &mut Decoder<'_>) -> Result<Capability, ProtocolError> {
    match decoder.u16().map_err(decode_error)? {
        1 => Ok(Capability::Lifecycle),
        2 => Ok(Capability::Exec),
        3 => Ok(Capability::StreamedIo),
        4 => Ok(Capability::Signals),
        5 => Ok(Capability::Mounts),
        6 => Ok(Capability::Network),
        7 => Ok(Capability::Mcp),
        8 => Ok(Capability::Audit),
        9 => Ok(Capability::Health),
        value => Err(ProtocolError::MalformedEncoding(format!(
            "unsupported capability {value}"
        ))),
    }
}

fn decode_role(decoder: &mut Decoder<'_>) -> Result<PeerRole, ProtocolError> {
    match decoder.u8().map_err(decode_error)? {
        1 => Ok(PeerRole::HostClient),
        2 => Ok(PeerRole::GuestServer),
        value => Err(ProtocolError::MalformedEncoding(format!(
            "unsupported peer role {value}"
        ))),
    }
}

fn decode_response_status(decoder: &mut Decoder<'_>) -> Result<ResponseStatus, ProtocolError> {
    match decoder.u8().map_err(decode_error)? {
        1 => Ok(ResponseStatus::Ok),
        2 => Ok(ResponseStatus::Rejected),
        3 => Ok(ResponseStatus::Failed),
        value => Err(ProtocolError::MalformedEncoding(format!(
            "unsupported response status {value}"
        ))),
    }
}

fn decode_event_kind(decoder: &mut Decoder<'_>) -> Result<EventKind, ProtocolError> {
    match decoder.u8().map_err(decode_error)? {
        1 => Ok(EventKind::StandardOutput),
        2 => Ok(EventKind::StandardError),
        3 => Ok(EventKind::Audit),
        4 => Ok(EventKind::Health),
        5 => Ok(EventKind::Lifecycle),
        value => Err(ProtocolError::MalformedEncoding(format!(
            "unsupported event kind {value}"
        ))),
    }
}

fn decode_close_code(decoder: &mut Decoder<'_>) -> Result<CloseCode, ProtocolError> {
    match decoder.u8().map_err(decode_error)? {
        1 => Ok(CloseCode::Normal),
        2 => Ok(CloseCode::Shutdown),
        3 => Ok(CloseCode::ProtocolFailure),
        value => Err(ProtocolError::MalformedEncoding(format!(
            "unsupported close code {value}"
        ))),
    }
}

fn decode_protocol_error_code(
    decoder: &mut Decoder<'_>,
) -> Result<ProtocolErrorCode, ProtocolError> {
    match decoder.u16().map_err(decode_error)? {
        1 => Ok(ProtocolErrorCode::MalformedFrame),
        2 => Ok(ProtocolErrorCode::Authentication),
        3 => Ok(ProtocolErrorCode::UnsupportedVersion),
        4 => Ok(ProtocolErrorCode::UnsupportedCapability),
        5 => Ok(ProtocolErrorCode::InvalidState),
        6 => Ok(ProtocolErrorCode::Internal),
        value => Err(ProtocolError::MalformedEncoding(format!(
            "unsupported protocol error code {value}"
        ))),
    }
}

fn decode_fixed_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], ProtocolError> {
    decoder
        .bytes()
        .map_err(decode_error)?
        .try_into()
        .map_err(|_| ProtocolError::MalformedEncoding(format!("expected {N} bytes")))
}

fn decode_array_length(decoder: &mut Decoder<'_>) -> Result<u64, ProtocolError> {
    decoder
        .array()
        .map_err(decode_error)?
        .ok_or_else(|| ProtocolError::MalformedEncoding("indefinite arrays are invalid".to_owned()))
}

fn require_array_length(actual: u64, expected: u64) -> Result<(), ProtocolError> {
    if actual != expected {
        return Err(ProtocolError::MalformedEncoding(format!(
            "expected array length {expected}, received {actual}"
        )));
    }
    Ok(())
}

fn encode_array(encoder: &mut Encoder<Vec<u8>>, length: u64) -> Result<(), ProtocolError> {
    encoder.array(length).map_err(encode_error)?;
    Ok(())
}

fn encode_bytes(encoder: &mut Encoder<Vec<u8>>, value: &[u8]) -> Result<(), ProtocolError> {
    encoder.bytes(value).map_err(encode_error)?;
    Ok(())
}

fn encode_str(encoder: &mut Encoder<Vec<u8>>, value: &str) -> Result<(), ProtocolError> {
    encoder.str(value).map_err(encode_error)?;
    Ok(())
}

fn encode_u8(encoder: &mut Encoder<Vec<u8>>, value: u8) -> Result<(), ProtocolError> {
    encoder.u8(value).map_err(encode_error)?;
    Ok(())
}

fn encode_u16(encoder: &mut Encoder<Vec<u8>>, value: u16) -> Result<(), ProtocolError> {
    encoder.u16(value).map_err(encode_error)?;
    Ok(())
}

fn encode_u32(encoder: &mut Encoder<Vec<u8>>, value: u32) -> Result<(), ProtocolError> {
    encoder.u32(value).map_err(encode_error)?;
    Ok(())
}

fn encode_u64(encoder: &mut Encoder<Vec<u8>>, value: u64) -> Result<(), ProtocolError> {
    encoder.u64(value).map_err(encode_error)?;
    Ok(())
}

fn encode_error(error: encode::Error<Infallible>) -> ProtocolError {
    ProtocolError::MalformedEncoding(error.to_string())
}

fn decode_error(error: decode::Error) -> ProtocolError {
    ProtocolError::MalformedEncoding(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MAC_BYTES, NONCE_BYTES};

    #[test]
    fn rejects_unknown_message_kind() {
        let error = decode_message(&[0x81, 0x18, 0x63]).expect_err("unknown kind must fail");
        assert!(matches!(error, ProtocolError::UnsupportedMessageKind(99)));
    }

    #[test]
    fn rejects_indefinite_message_array() {
        let error = decode_message(&[0x9f, 0x01, 0xff]).expect_err("indefinite array must fail");
        assert!(matches!(error, ProtocolError::MalformedEncoding(_)));
    }

    #[test]
    fn fixed_sizes_are_enforced() {
        let error = decode_message(&[0x8a, 0x01, 0x40]).expect_err("short hello must fail");
        assert!(matches!(error, ProtocolError::MalformedEncoding(_)));
    }

    #[test]
    fn constants_match_wire_sizes() {
        assert_eq!(NONCE_BYTES, 32);
        assert_eq!(MAC_BYTES, 32);
    }

    #[test]
    fn capability_array_length_is_bounded_before_allocation() {
        let mut decoder = Decoder::new(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let error = decode_capabilities(&mut decoder).expect_err("huge length must fail");
        assert!(matches!(error, ProtocolError::MalformedEncoding(_)));
    }
}
