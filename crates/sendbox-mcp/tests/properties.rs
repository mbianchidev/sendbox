use proptest::prelude::*;
use sendbox_mcp::framing::{FrameDecoder, FramingMode, encode_frame};
use sendbox_mcp::jsonrpc::validate_message;
use sendbox_mcp::policy::glob_matches;

fn decode_in_chunks(frame: &[u8], mode: FramingMode, chunks: &[usize]) -> Vec<Vec<u8>> {
    let mut decoder = FrameDecoder::new(mode, 16 * 1024);
    let mut frames = Vec::new();
    let mut offset = 0usize;
    for chunk in chunks {
        if offset == frame.len() {
            break;
        }
        let end = offset.saturating_add((*chunk).max(1)).min(frame.len());
        frames.extend(
            decoder
                .feed(&frame[offset..end])
                .expect("valid framed input"),
        );
        offset = end;
    }
    if offset < frame.len() {
        frames.extend(decoder.feed(&frame[offset..]).expect("remaining input"));
    }
    decoder.finish().expect("complete input");
    frames.into_iter().map(|frame| frame.payload).collect()
}

proptest! {
    #[test]
    fn framing_is_invariant_to_chunk_boundaries(
        tool in "[a-z][a-z0-9_.-]{0,63}",
        chunks in prop::collection::vec(1usize..32, 0..64),
        content_length in any::<bool>(),
    ) {
        let payload = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool},
        })).expect("JSON");
        let mode = if content_length {
            FramingMode::ContentLength
        } else {
            FramingMode::Newline
        };
        let frame = encode_frame(&payload, mode);
        prop_assert_eq!(decode_in_chunks(&frame, mode, &chunks), vec![payload]);
    }

    #[test]
    fn validated_messages_survive_arbitrary_string_ids(
        id in ".{0,128}",
    ) {
        let payload = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "ping",
        })).expect("JSON");
        let message = validate_message(&payload).expect("valid request");
        prop_assert!(message.id.raw().is_some());
    }

    #[test]
    fn exact_globs_match_themselves(value in ".{0,128}") {
        prop_assert!(glob_matches(&value, &value));
    }
}

#[test]
fn oversized_newline_and_content_length_frames_fail_closed() {
    let mut newline = FrameDecoder::new(FramingMode::Newline, 8);
    assert!(newline.feed(b"123456789\n").is_err());

    let mut content_length = FrameDecoder::new(FramingMode::ContentLength, 8);
    assert!(content_length.feed(b"Content-Length: 9\r\n\r\n").is_err());
}
