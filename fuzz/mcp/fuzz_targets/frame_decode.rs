#![no_main]

use libfuzzer_sys::fuzz_target;
use sendbox_mcp::framing::{FrameDecoder, FramingMode};

fuzz_target!(|data: &[u8]| {
    for mode in [
        FramingMode::Newline,
        FramingMode::ContentLength,
        FramingMode::Auto,
    ] {
        let mut decoder = FrameDecoder::new(mode, 4096);
        for chunk in data.chunks(17) {
            if decoder.feed(chunk).is_err() {
                break;
            }
        }
        let _ = decoder.finish();
    }
});
