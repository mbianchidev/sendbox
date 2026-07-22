#![no_main]

use libfuzzer_sys::fuzz_target;
use sendbox_mcp::observation::ObservationParser;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = ObservationParser::new(false).parse_log(&input);
});
