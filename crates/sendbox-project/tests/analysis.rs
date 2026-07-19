use std::fs;
use std::path::PathBuf;

use proptest::prelude::*;
use sendbox_project::{Analyzer, ScanIssueKind, ScanLimits};
use serde_json::Value;
use tempfile::tempdir;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn fixture_cases_match_checked_in_bridge_expectations() {
    let expected: Value =
        serde_json::from_slice(&fs::read(fixtures().join("bridge-expected.json")).unwrap())
            .unwrap();
    for (case, expected) in expected.as_object().unwrap() {
        let analysis = Analyzer::default().analyze(fixtures().join(case)).unwrap();
        let actual = serde_json::to_value(&analysis).unwrap();
        for (key, expected_value) in expected.as_object().unwrap() {
            assert_eq!(
                actual.get(key),
                Some(expected_value),
                "fixture {case}, field {key}"
            );
        }
    }
}

#[test]
fn malformed_manifests_are_reported_without_success_shaped_dependencies() {
    let analysis = Analyzer::default()
        .analyze(fixtures().join("malformed"))
        .unwrap();
    assert_eq!(analysis.language, "typescript");
    assert!(analysis.dependencies.is_empty());
    assert!(
        analysis
            .scan
            .errors
            .iter()
            .any(|issue| issue.kind == ScanIssueKind::ManifestParse)
    );
}

#[test]
fn repeated_analysis_is_byte_for_byte_deterministic() {
    let analyzer = Analyzer::default();
    let first = analyzer.analyze(fixtures().join("polyglot")).unwrap();
    let second = analyzer.analyze(fixtures().join("polyglot")).unwrap();
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(first.languages, vec!["node", "rust", "typescript"]);
}

#[test]
fn scan_limits_report_enormous_files_and_file_count_cutoffs() {
    let directory = tempdir().unwrap();
    fs::write(directory.path().join("package.json"), vec![b'x'; 128]).unwrap();
    fs::write(directory.path().join("tsconfig.json"), "{}").unwrap();
    let analysis = Analyzer::new(ScanLimits {
        max_depth: 2,
        max_files: 1,
        max_bytes: 64,
        max_file_bytes: 64,
    })
    .analyze(directory.path())
    .unwrap();
    assert!(
        analysis
            .scan
            .skipped
            .iter()
            .any(|issue| issue.kind == ScanIssueKind::FileTooLarge)
    );
    assert!(
        analysis
            .scan
            .skipped
            .iter()
            .any(|issue| issue.kind == ScanIssueKind::FileLimit)
    );
}

#[cfg(unix)]
#[test]
fn symlink_loops_are_skipped() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    fs::write(
        directory.path().join("Cargo.toml"),
        "[package]\nname='x'\nversion='0.1.0'\n",
    )
    .unwrap();
    symlink(directory.path(), directory.path().join("loop")).unwrap();
    let analysis = Analyzer::default().analyze(directory.path()).unwrap();
    assert_eq!(analysis.language, "rust");
    assert!(
        analysis
            .scan
            .skipped
            .iter()
            .any(|issue| issue.kind == ScanIssueKind::Symlink && issue.path == "loop")
    );
}

#[cfg(unix)]
#[test]
fn permission_errors_are_explicit() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let denied = directory.path().join("denied");
    fs::create_dir(&denied).unwrap();
    fs::write(denied.join("package.json"), "{}").unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
    let analysis = Analyzer::default().analyze(directory.path()).unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    if !is_root() {
        assert!(
            analysis
                .scan
                .errors
                .iter()
                .any(|issue| issue.kind == ScanIssueKind::PermissionDenied)
        );
    }
}

#[cfg(unix)]
fn is_root() -> bool {
    std::env::var_os("USER").is_some_and(|user| user == "root")
}

proptest! {
    #[test]
    fn requirements_parsing_never_executes_or_loses_valid_names(
        packages in prop::collection::vec("[a-z][a-z0-9_-]{0,15}", 1..20)
    ) {
        let directory = tempdir().unwrap();
        let requirements = packages
            .iter()
            .map(|name| format!("{name}>=1.0"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(directory.path().join("requirements.txt"), requirements).unwrap();
        let analysis = Analyzer::default().analyze(directory.path()).unwrap();
        let expected = packages.into_iter().collect::<std::collections::BTreeSet<_>>();
        prop_assert_eq!(
            analysis.dependencies.into_iter().collect::<std::collections::BTreeSet<_>>(),
            expected
        );
    }
}
