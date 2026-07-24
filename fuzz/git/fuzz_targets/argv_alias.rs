#![no_main]

use libfuzzer_sys::fuzz_target;
use sendbox_git::{
    Operation, parse_alias_words, parse_invocation, parse_operation_arguments,
};

fuzz_target!(|data: &[u8]| {
    let value = String::from_utf8_lossy(data);
    let arguments = value
        .split('\0')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let _ = parse_alias_words(&value);
    let _ = parse_invocation(&arguments);
    let _ = parse_operation_arguments(Operation::Push, &arguments);
    let _ = parse_operation_arguments(Operation::Pull, &arguments);
});
