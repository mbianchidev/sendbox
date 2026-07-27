#![no_main]

use libfuzzer_sys::fuzz_target;
use sendbox_config::SandboxConfiguration;

fuzz_target!(|bytes: &[u8]| {
    let Ok(yaml) = std::str::from_utf8(bytes) else {
        return;
    };
    let Ok(migrated) = SandboxConfiguration::migrate(yaml) else {
        return;
    };
    let decoded = SandboxConfiguration::parse(&migrated.yaml)
        .expect("canonical YAML produced by the writer must parse");
    assert_eq!(decoded, migrated.configuration);
});
