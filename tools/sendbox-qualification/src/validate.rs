use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::model::{
    BenchmarkSpecification, ConformanceManifest, Disposition, FeatureInventory, FixtureStatus,
    QualificationState, ValidationReport,
};

const SCHEMA_VERSION: u32 = 1;
const HISTORICAL_EVIDENCE_MANIFEST: &str = "Tests/qualification/historical/swift-to-rust.v1.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalEvidenceManifest {
    schema_version: u32,
    migration: String,
    source_revision: String,
    removed_paths: BTreeSet<String>,
    blob_ids: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum QualificationError {
    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not decode {path}: {source}")]
    Decode {
        path: String,
        source: serde_json::Error,
    },
}

pub fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, QualificationError> {
    let bytes = fs::read(path).map_err(|source| QualificationError::Read {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| QualificationError::Decode {
        path: path.display().to_string(),
        source,
    })
}

#[must_use]
pub fn validate_all(
    root: &Path,
    inventory: &FeatureInventory,
    conformance: &ConformanceManifest,
    benchmark: &BenchmarkSpecification,
) -> ValidationReport {
    let mut errors = Vec::new();
    if inventory.schema_version != SCHEMA_VERSION {
        errors.push("inventory schema_version must be 1".to_owned());
    }
    if conformance.schema_version != SCHEMA_VERSION {
        errors.push("conformance schema_version must be 1".to_owned());
    }
    if benchmark.schema_version != SCHEMA_VERSION {
        errors.push("benchmark schema_version must be 1".to_owned());
    }

    let mut fixture_ids = BTreeSet::new();
    for fixture in &conformance.fixtures {
        unique(&mut fixture_ids, &fixture.id, "fixture", &mut errors);
        require_id(&fixture.id, "fixture", &mut errors);
        require_path(root, &fixture.data_path, &mut errors);
        match load_json::<serde_json::Value>(&root.join(&fixture.data_path)) {
            Ok(value)
                if value
                    .get("schema_version")
                    .and_then(serde_json::Value::as_u64)
                    == Some(1) => {}
            Ok(_) => errors.push(format!(
                "fixture {} must be a JSON object with schema_version 1",
                fixture.id
            )),
            Err(error) => errors.push(format!("fixture {} is invalid: {error}", fixture.id)),
        }
    }

    let mut entry_ids = BTreeSet::new();
    let mut evidence_paths = BTreeSet::new();
    let mut dispositions = BTreeMap::new();
    let historical_evidence = load_historical_evidence(root, &mut errors);
    let live_target_modules: BTreeSet<&str> = inventory
        .entries
        .iter()
        .filter(|entry| {
            entry.category == "source_module"
                && entry.conformance.status == FixtureStatus::Implemented
                && entry.evidence.iter().any(|evidence| {
                    evidence
                        .split_once('#')
                        .is_some_and(|(path, _)| path != HISTORICAL_EVIDENCE_MANIFEST)
                })
        })
        .map(|entry| entry.target_crate.as_str())
        .collect();
    for entry in &inventory.entries {
        unique(&mut entry_ids, &entry.id, "inventory entry", &mut errors);
        require_id(&entry.id, "inventory entry", &mut errors);
        if entry.rationale.trim().is_empty() {
            errors.push(format!("inventory entry {} has no rationale", entry.id));
        }
        if entry.target_crate.trim().is_empty() || entry.target_phase == 0 {
            errors.push(format!(
                "inventory entry {} must name a target crate and phase",
                entry.id
            ));
        }
        if entry.evidence.is_empty() {
            errors.push(format!("inventory entry {} has no evidence", entry.id));
        }
        let mut has_live_evidence = false;
        for evidence in &entry.evidence {
            let Some((path, anchor)) = evidence.split_once('#') else {
                errors.push(format!(
                    "inventory entry {} evidence must use path#symbol-or-claim",
                    entry.id
                ));
                continue;
            };
            require_path(root, Path::new(path), &mut errors);
            if anchor.trim().is_empty() {
                errors.push(format!(
                    "inventory entry {} has an empty evidence anchor",
                    entry.id
                ));
            }
            if path == HISTORICAL_EVIDENCE_MANIFEST {
                validate_historical_anchor(
                    &entry.id,
                    anchor,
                    historical_evidence.as_ref(),
                    &mut errors,
                );
            } else {
                has_live_evidence = true;
                evidence_paths.insert(path.to_owned());
            }
        }
        if entry.conformance.status == FixtureStatus::Implemented
            && !has_live_evidence
            && !live_target_modules.contains(entry.target_crate.as_str())
        {
            errors.push(format!(
                "implemented inventory entry {} requires live repository or target-module evidence",
                entry.id
            ));
        }
        for fixture_id in &entry.conformance.fixture_ids {
            if !fixture_ids.contains(fixture_id) {
                errors.push(format!(
                    "inventory entry {} references missing fixture {}",
                    entry.id, fixture_id
                ));
            }
        }
        match entry.disposition {
            Disposition::Preserve if entry.conformance.status == FixtureStatus::NotApplicable => {
                errors.push(format!(
                    "preserved entry {} cannot be marked not_applicable",
                    entry.id
                ));
            }
            Disposition::Redesign
                if entry
                    .conformance
                    .compatibility_note
                    .as_deref()
                    .is_none_or(str::is_empty) =>
            {
                errors.push(format!(
                    "redesigned entry {} requires a compatibility note",
                    entry.id
                ));
            }
            _ => {}
        }
        *dispositions
            .entry(format!("{:?}", entry.disposition).to_lowercase())
            .or_insert(0) += 1;
    }
    if inventory.entries.is_empty() {
        errors.push("inventory must contain entries".to_owned());
    }
    validate_source_coverage(root, &evidence_paths, &mut errors);

    validate_benchmark(benchmark, &mut errors);
    let unqualified_workloads = benchmark
        .workloads
        .iter()
        .filter(|workload| workload.availability == QualificationState::Unqualified)
        .map(|workload| workload.id.clone())
        .collect();
    let implemented_fixtures = conformance
        .fixtures
        .iter()
        .filter(|fixture| fixture.status == FixtureStatus::Implemented)
        .count();

    ValidationReport {
        schema_version: SCHEMA_VERSION,
        valid: errors.is_empty(),
        inventory_entries: inventory.entries.len(),
        dispositions,
        conformance_fixtures: conformance.fixtures.len(),
        implemented_fixtures,
        benchmark_workloads: benchmark.workloads.len(),
        unqualified_workloads,
        errors,
    }
}

fn load_historical_evidence(
    root: &Path,
    errors: &mut Vec<String>,
) -> Option<HistoricalEvidenceManifest> {
    let path = root.join(HISTORICAL_EVIDENCE_MANIFEST);
    let manifest = match load_json::<HistoricalEvidenceManifest>(&path) {
        Ok(manifest) => manifest,
        Err(error) => {
            errors.push(format!("historical evidence manifest is invalid: {error}"));
            return None;
        }
    };
    if manifest.schema_version != SCHEMA_VERSION {
        errors.push("historical evidence schema_version must be 1".to_owned());
    }
    if manifest.migration != "swift-to-rust" {
        errors.push("historical evidence migration must be swift-to-rust".to_owned());
    }
    if manifest.source_revision.len() != 40
        || !manifest
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        errors.push("historical evidence source_revision must be a full Git object id".to_owned());
    }
    if manifest.removed_paths.is_empty() {
        errors.push("historical evidence must list removed paths".to_owned());
    }
    validate_historical_repository(root, &manifest, errors);
    Some(manifest)
}

fn validate_historical_repository(
    root: &Path,
    manifest: &HistoricalEvidenceManifest,
    errors: &mut Vec<String>,
) {
    let blob_paths: BTreeSet<&str> = manifest.blob_ids.keys().map(String::as_str).collect();
    let removed_paths: BTreeSet<&str> = manifest.removed_paths.iter().map(String::as_str).collect();
    if blob_paths != removed_paths {
        errors
            .push("historical evidence blob_ids must exactly cover every removed path".to_owned());
    }
    for path in &manifest.removed_paths {
        let relative = Path::new(path);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            errors.push(format!(
                "historical evidence path must be repository-relative: {path}"
            ));
        }
        if root.join(relative).exists() {
            errors.push(format!(
                "historical evidence path still exists in the current tree: {path}"
            ));
        }
    }

    let revision = format!("{}^{{commit}}", manifest.source_revision);
    let Ok(resolved_revision) = git_output(root, &["rev-parse", "--verify", &revision]) else {
        errors.push(format!(
            "historical evidence source revision is unavailable: {}",
            manifest.source_revision
        ));
        return;
    };
    if resolved_revision != manifest.source_revision {
        errors.push(format!(
            "historical evidence source revision resolved to {resolved_revision}, expected {}",
            manifest.source_revision
        ));
        return;
    }

    for (path, expected_blob) in &manifest.blob_ids {
        if expected_blob.len() != 40 || !expected_blob.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            errors.push(format!(
                "historical evidence blob id for {path} must be a full Git object id"
            ));
            continue;
        }
        let object = format!("{}:{path}", manifest.source_revision);
        match git_output(root, &["rev-parse", "--verify", &object]) {
            Ok(actual_blob) if actual_blob == *expected_blob => {}
            Ok(actual_blob) => errors.push(format!(
                "historical evidence blob mismatch for {path}: expected {expected_blob}, found {actual_blob}"
            )),
            Err(error) => errors.push(format!(
                "historical evidence path is unavailable at {}: {path} ({error})",
                manifest.source_revision
            )),
        }
    }
}

fn git_output(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| error.to_string())
}

fn validate_historical_anchor(
    entry_id: &str,
    anchor: &str,
    manifest: Option<&HistoricalEvidenceManifest>,
    errors: &mut Vec<String>,
) {
    let Some((removed_path, claim)) = anchor.split_once('#') else {
        errors.push(format!(
            "inventory entry {entry_id} historical evidence must use removed-path#symbol-or-claim"
        ));
        return;
    };
    if claim.trim().is_empty() {
        errors.push(format!(
            "inventory entry {entry_id} has an empty historical evidence claim"
        ));
    }
    if manifest.is_some_and(|manifest| !manifest.removed_paths.contains(removed_path)) {
        errors.push(format!(
            "inventory entry {entry_id} references an unlisted historical path: {removed_path}"
        ));
    }
}

fn validate_source_coverage(
    root: &Path,
    evidence_paths: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let mut source_directories = BTreeSet::new();
    for relative_root in ["Sources", "copilot-bridge/src"] {
        let directory = root.join(relative_root);
        if directory.is_dir() {
            source_directories.insert(directory);
        }
    }
    if let Ok(entries) = fs::read_dir(root.join("crates")) {
        for entry in entries.flatten() {
            let source_directory = entry.path().join("src");
            if source_directory.is_dir() {
                source_directories.insert(source_directory);
            }
        }
    }

    let mut files = BTreeSet::new();
    for directory in source_directories {
        collect_source_files(&directory, &mut files);
    }
    for file in files {
        let Ok(relative) = file.strip_prefix(root) else {
            continue;
        };
        let relative = relative.to_string_lossy().replace('\\', "/");
        if !evidence_paths.contains(&relative) {
            errors.push(format!(
                "source module is not represented in the inventory: {relative}"
            ));
        }
    }
}

fn collect_source_files(directory: &Path, files: &mut BTreeSet<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_source_files(&path, files);
        } else if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("swift" | "rs" | "ts")
        ) {
            files.insert(path);
        }
    }
}

fn validate_benchmark(benchmark: &BenchmarkSpecification, errors: &mut Vec<String>) {
    if benchmark.methodology.warmups == 0 || benchmark.methodology.repetitions == 0 {
        errors.push("benchmark warmups and repetitions must be greater than zero".to_owned());
    }
    if (benchmark.methodology.confidence_level - 0.95).abs() > f64::EPSILON {
        errors.push("benchmark confidence_level must be 0.95".to_owned());
    }
    let mut workload_ids = BTreeSet::new();
    for workload in &benchmark.workloads {
        unique(
            &mut workload_ids,
            &workload.id,
            "benchmark workload",
            errors,
        );
        if workload.workload_sizes.is_empty() {
            errors.push(format!("workload {} has no workload sizes", workload.id));
        }
        if workload.availability == QualificationState::Unqualified
            && workload
                .unqualified_reason
                .as_deref()
                .is_none_or(str::is_empty)
        {
            errors.push(format!(
                "unqualified workload {} requires a reason",
                workload.id
            ));
        }
    }
    let mut threshold_ids = BTreeSet::new();
    for threshold in &benchmark.thresholds {
        unique(
            &mut threshold_ids,
            &threshold.id,
            "benchmark threshold",
            errors,
        );
        if !workload_ids.contains(&threshold.workload_id) {
            errors.push(format!(
                "threshold {} references missing workload {}",
                threshold.id, threshold.workload_id
            ));
        }
        if !threshold.value.is_finite() || threshold.value < 0.0 {
            errors.push(format!("threshold {} has an invalid value", threshold.id));
        }
    }
    if benchmark.minimum_supported_bpf_event_rate.status == QualificationState::Qualified
        && benchmark
            .minimum_supported_bpf_event_rate
            .value
            .as_ref()
            .is_none()
    {
        errors.push("qualified BPF event rate must include a value".to_owned());
    }
}

fn require_path(root: &Path, path: &Path, errors: &mut Vec<String>) {
    if path.is_absolute() || !root.join(path).exists() {
        errors.push(format!(
            "evidence/fixture path must exist under repository root: {}",
            path.display()
        ));
    }
}

fn require_id(id: &str, kind: &str, errors: &mut Vec<String>) {
    if id.is_empty()
        || id.chars().any(|character| {
            !(character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '-' | '_'))
        })
    {
        errors.push(format!("{kind} id is not stable lowercase ASCII: {id}"));
    }
}

fn unique(ids: &mut BTreeSet<String>, id: &str, kind: &str, errors: &mut Vec<String>) {
    if !ids.insert(id.to_owned()) {
        errors.push(format!("duplicate {kind} id: {id}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn detects_duplicate_ids_and_missing_evidence() {
        let fixture = ConformanceFixture {
            id: "same".to_owned(),
            area: "cli".to_owned(),
            description: "x".to_owned(),
            oracle: Oracle::IntendedBehavior,
            status: FixtureStatus::Specified,
            negative_case: false,
            data_path: "missing.json".into(),
        };
        let report = validate_all(
            Path::new("."),
            &FeatureInventory {
                schema_version: 1,
                inventory_version: "1.0.0".to_owned(),
                generated_from: "main".to_owned(),
                entries: Vec::new(),
            },
            &ConformanceManifest {
                schema_version: 1,
                fixture_version: "1.0.0".to_owned(),
                fixtures: vec![fixture.clone(), fixture],
            },
            &minimal_benchmark(),
        );
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("duplicate fixture"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("inventory must contain"))
        );
    }

    #[test]
    fn source_coverage_checks_each_file_once() {
        let root = std::env::temp_dir().join(format!(
            "sendbox-qualification-source-coverage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let swift_source = root.join("Sources/Example.swift");
        let rust_source = root.join("crates/example/src/lib.rs");
        fs::create_dir_all(swift_source.parent().expect("Swift source parent"))
            .expect("create Swift source directory");
        fs::create_dir_all(rust_source.parent().expect("Rust source parent"))
            .expect("create Rust source directory");
        fs::write(&swift_source, "").expect("write Swift source");
        fs::write(&rust_source, "").expect("write Rust source");

        let mut errors = Vec::new();
        validate_source_coverage(&root, &BTreeSet::new(), &mut errors);

        fs::remove_dir_all(&root).expect("remove source fixture");
        assert_eq!(errors.len(), 2);
        assert_eq!(
            errors
                .iter()
                .filter(|error| error.contains("crates/example/src/lib.rs"))
                .count(),
            1
        );
        assert_eq!(
            errors
                .iter()
                .filter(|error| error.contains("Sources/Example.swift"))
                .count(),
            1
        );
    }

    #[test]
    fn historical_repository_rejects_blob_mismatch() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut manifest: HistoricalEvidenceManifest =
            load_json(&root.join(HISTORICAL_EVIDENCE_MANIFEST)).expect("historical manifest");
        manifest.blob_ids.insert(
            "Package.swift".to_owned(),
            "0000000000000000000000000000000000000000".to_owned(),
        );
        let mut errors = Vec::new();

        validate_historical_repository(&root, &manifest, &mut errors);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("blob mismatch for Package.swift"))
        );
    }

    fn minimal_benchmark() -> BenchmarkSpecification {
        BenchmarkSpecification {
            schema_version: 1,
            specification_version: "1.0.0".to_owned(),
            owner: "test".to_owned(),
            reference_hosts: Vec::new(),
            methodology: Methodology {
                warmups: 1,
                repetitions: 1,
                cache_states: vec!["warm".to_owned()],
                confidence_level: 0.95,
                confidence_interval: "normal".to_owned(),
                percentile_method: "nearest_rank".to_owned(),
                outlier_policy: "none".to_owned(),
            },
            build_controls: BuildControls {
                rust_profile: "release".to_owned(),
                c_optimization: "-O3".to_owned(),
                linker: QualificationValue {
                    status: QualificationState::Unqualified,
                    value: None,
                    reason: Some("test".to_owned()),
                },
                allocator: QualificationValue {
                    status: QualificationState::Unqualified,
                    value: None,
                    reason: Some("test".to_owned()),
                },
                logging: "disabled".to_owned(),
            },
            workloads: Vec::new(),
            thresholds: Vec::new(),
            c_references: Vec::new(),
            fixed_adapter_baselines: Vec::new(),
            minimum_supported_bpf_event_rate: QualificationValue {
                status: QualificationState::Unqualified,
                value: None,
                reason: Some("test".to_owned()),
            },
        }
    }
}
