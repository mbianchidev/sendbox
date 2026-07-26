#![no_main]

use libfuzzer_sys::fuzz_target;
use sendbox_git::{RepositoryIdentity, parse_push_refspec};

fuzz_target!(|data: &[u8]| {
    let value = String::from_utf8_lossy(data);
    let (remote, current) = value.split_once('\0').unwrap_or((&value, "feature/fuzz"));
    let _ = RepositoryIdentity::parse(remote, Some("github.com"));
    let _ = parse_push_refspec(remote, current);
});
