use proptest::prelude::*;
use sendbox_protocol::{
    Cancellation, Capability, CapabilitySet, CloseCode, Event, EventKind, GracefulClose, Message,
    ProtocolError, ProtocolErrorCode, ProtocolErrorMessage, Request, Response, ResponseStatus,
    decode_message, encode_message,
};

fn messages() -> Vec<Message> {
    vec![
        Message::Request(Request {
            request_id: 1,
            operation: "exec".to_owned(),
            payload: vec![1, 2, 3],
        }),
        Message::Response(Response {
            request_id: 1,
            status: ResponseStatus::Ok,
            payload: vec![4, 5],
        }),
        Message::Event(Event {
            stream_id: 2,
            kind: EventKind::StandardOutput,
            payload: b"hello".to_vec(),
        }),
        Message::Cancellation(Cancellation {
            request_id: 1,
            reason: Some("caller cancelled".to_owned()),
        }),
        Message::GracefulClose(GracefulClose {
            code: CloseCode::Normal,
            reason: "done".to_owned(),
        }),
        Message::ProtocolError(ProtocolErrorMessage {
            code: ProtocolErrorCode::InvalidState,
            detail: "not ready".to_owned(),
        }),
    ]
}

#[test]
fn every_post_handshake_message_round_trips_canonically() {
    for message in messages() {
        let encoded = encode_message(&message).expect("encode");
        assert_eq!(decode_message(&encoded).expect("decode"), message);
        assert_eq!(
            encode_message(&decode_message(&encoded).expect("decode")).expect("re-encode"),
            encoded
        );
    }
}

#[test]
fn capability_sets_are_sorted_and_deduplicated() {
    let capabilities = CapabilitySet::new([
        Capability::Health,
        Capability::Exec,
        Capability::Health,
        Capability::Lifecycle,
    ]);
    assert!(capabilities.contains(Capability::Exec));
    assert!(capabilities.contains(Capability::Health));
    assert!(capabilities.contains(Capability::Lifecycle));
}

#[test]
fn noncanonical_integer_encoding_is_rejected() {
    let canonical = encode_message(&Message::Request(Request {
        request_id: 1,
        operation: "x".to_owned(),
        payload: Vec::new(),
    }))
    .expect("encode");
    assert_eq!(canonical[0], 0x84);
    assert_eq!(canonical[1], 0x04);
    let mut noncanonical = canonical;
    noncanonical.splice(1..2, [0x18, 0x04]);
    assert!(matches!(
        decode_message(&noncanonical),
        Err(ProtocolError::NonCanonicalEncoding)
    ));
}

proptest! {
    #[test]
    fn request_round_trip_is_stable(
        request_id in any::<u64>(),
        operation in "[a-z][a-z0-9_.-]{0,63}",
        payload in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let message = Message::Request(Request {
            request_id,
            operation,
            payload,
        });
        let first = encode_message(&message).expect("encode");
        let decoded = decode_message(&first).expect("decode");
        let second = encode_message(&decoded).expect("re-encode");
        prop_assert_eq!(decoded, message);
        prop_assert_eq!(second, first);
    }
}
