#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sendbox_protocol::fuzzing::decode_handshake_message(data);
});
