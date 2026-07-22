#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = sendbox_secrets::fuzzing::decode_persisted_record(bytes);
});
