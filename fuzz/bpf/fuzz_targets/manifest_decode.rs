#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    sendbox_bundle::fuzzing::decode_manifest(bytes);
});
