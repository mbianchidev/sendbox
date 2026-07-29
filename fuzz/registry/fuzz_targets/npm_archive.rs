#![no_main]

use std::io::Write as _;

use libfuzzer_sys::fuzz_target;
use sendbox_policy::PackageAnalysisLimits;
use sendbox_registry::enumerate_npm_archive;

fuzz_target!(|data: &[u8]| {
    let mut artifact = tempfile::NamedTempFile::new().expect("temporary artifact");
    artifact.write_all(data).expect("write fuzz artifact");
    let limits = PackageAnalysisLimits {
        max_download_bytes: 1024 * 1024,
        max_unpacked_bytes: 4 * 1024 * 1024,
        max_entry_bytes: 512 * 1024,
        max_entries: 4096,
        max_source_scan_bytes: 1024 * 1024,
        scan_timeout_secs: 2,
        ..PackageAnalysisLimits::default()
    };
    let _ = enumerate_npm_archive(artifact.path(), &limits);
});
