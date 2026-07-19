use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::model::{
    BenchmarkSpecification, ConformanceManifest, Disposition, FeatureInventory, FixtureStatus,
    Oracle, QualificationState, ValidationReport,
};

const SCHEMA_VERSION: u32 = 1;

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
        if fixture.oracle == Oracle::SwiftObservationOnly && fixture.swift_observation.is_none() {
            errors.push(format!(
                "fixture {} marks Swift as observation but has no observation metadata",
                fixture.id
            ));
        }
        if let Some(observation) = &fixture.swift_observation {
            require_path(root, &observation.evidence_path, &mut errors);
            if observation.note.trim().is_empty() {
                errors.push(format!(
                    "fixture {} has an empty observation note",
                    fixture.id
                ));
            }
        }
    }

    let mut entry_ids = BTreeSet::new();
    let mut evidence_paths = BTreeSet::new();
    let mut dispositions = BTreeMap::new();
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
        for evidence in &entry.evidence {
            let Some((path, anchor)) = evidence.split_once('#') else {
                errors.push(format!(
                    "inventory entry {} evidence must use path#symbol-or-claim",
                    entry.id
                ));
                continue;
            };
            require_path(root, Path::new(path), &mut errors);
            evidence_paths.insert(path.to_owned());
            if anchor.trim().is_empty() {
                errors.push(format!(
                    "inventory entry {} has an empty evidence anchor",
                    entry.id
                ));
            }
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

fn validate_source_coverage(
    root: &Path,
    evidence_paths: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for relative_root in ["Sources", "copilot-bridge/src"] {
        let directory = root.join(relative_root);
        if !directory.exists() {
            continue;
        }
        let mut files = Vec::new();
        collect_source_files(&directory, &mut files);
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
        let crates = root.join("crates");
        if let Ok(entries) = fs::read_dir(crates) {
            for entry in entries.flatten() {
                let source_directory = entry.path().join("src");
                if !source_directory.is_dir() {
                    continue;
                }
                let mut files = Vec::new();
                collect_source_files(&source_directory, &mut files);
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
        }
    }
}

fn collect_source_files(directory: &Path, files: &mut Vec<std::path::PathBuf>) {
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
            files.push(path);
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
            swift_observation: None,
            command: None,
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
                swift_configuration: "release".to_owned(),
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
