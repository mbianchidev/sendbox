#![no_main]

use std::fs;

use libfuzzer_sys::fuzz_target;
use sendbox_project::{Analyzer, ScanLimits};

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let names = [
        "package.json",
        "pyproject.toml",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "Gemfile",
        "Package.swift",
    ];
    let name = names[data.first().copied().unwrap_or_default() as usize % names.len()];
    if fs::write(directory.path().join(name), source).is_err() {
        return;
    }
    let _ = Analyzer::new(ScanLimits {
        max_depth: 2,
        max_files: 4,
        max_bytes: 64 * 1024,
        max_file_bytes: 64 * 1024,
    })
    .analyze(directory.path());
});
