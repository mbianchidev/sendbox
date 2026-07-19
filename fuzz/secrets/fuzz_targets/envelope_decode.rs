#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sendbox_secrets::fuzzing::decode_envelope(data);
});
