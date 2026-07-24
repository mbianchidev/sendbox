#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sendbox_credentials::fuzzing::parse_http1_request(data);
});
