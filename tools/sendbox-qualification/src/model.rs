use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureInventory {
    pub schema_version: u32,
    pub inventory_version: String,
    pub generated_from: String,
    pub entries: Vec<FeatureEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureEntry {
    pub id: String,
    pub category: String,
    pub name: String,
    pub disposition: Disposition,
    pub rationale: String,
    pub evidence: Vec<String>,
    pub target_crate: String,
    pub target_phase: u8,
    pub conformance: ConformanceStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Preserve,
    Redesign,
    Defer,
    Remove,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceStatus {
    pub status: FixtureStatus,
    pub fixture_ids: Vec<String>,
    pub compatibility_note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStatus {
    Implemented,
    Specified,
    NotApplicable,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceManifest {
    pub schema_version: u32,
    pub fixture_version: String,
    pub fixtures: Vec<ConformanceFixture>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceFixture {
    pub id: String,
    pub area: String,
    pub description: String,
    pub oracle: Oracle,
    pub status: FixtureStatus,
    pub negative_case: bool,
    pub data_path: PathBuf,
    pub swift_observation: Option<SwiftObservation>,
    pub command: Option<ComparisonCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Oracle {
    IntendedBehavior,
    SwiftObservationOnly,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftObservation {
    pub evidence_path: PathBuf,
    pub note: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonCommand {
    pub args: Vec<String>,
    pub timeout_ms: u64,
    pub output_cap_bytes: usize,
    #[serde(default)]
    pub replacements: Vec<Replacement>,
    #[serde(default)]
    pub redact_json_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replacement {
    pub find: String,
    pub replace: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkSpecification {
    pub schema_version: u32,
    pub specification_version: String,
    pub owner: String,
    pub reference_hosts: Vec<ReferenceHost>,
    pub methodology: Methodology,
    pub build_controls: BuildControls,
    pub workloads: Vec<WorkloadSpecification>,
    pub thresholds: Vec<Threshold>,
    pub c_references: Vec<CReference>,
    pub fixed_adapter_baselines: Vec<FixedAdapterBaseline>,
    pub minimum_supported_bpf_event_rate: QualificationValue,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceHost {
    pub id: String,
    pub os: QualificationValue,
    pub architecture: QualificationValue,
    pub cpu: QualificationValue,
    pub memory_bytes: QualificationValue,
    pub kernel: QualificationValue,
    pub runtime_versions: BTreeMap<String, QualificationValue>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationValue {
    pub status: QualificationState,
    pub value: Option<serde_json::Value>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationState {
    Qualified,
    Unqualified,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Methodology {
    pub warmups: u32,
    pub repetitions: u32,
    pub cache_states: Vec<String>,
    pub confidence_level: f64,
    pub confidence_interval: String,
    pub percentile_method: String,
    pub outlier_policy: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildControls {
    pub rust_profile: String,
    pub swift_configuration: String,
    pub c_optimization: String,
    pub linker: QualificationValue,
    pub allocator: QualificationValue,
    pub logging: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSpecification {
    pub id: String,
    pub path: String,
    pub availability: QualificationState,
    pub unqualified_reason: Option<String>,
    pub workload_sizes: Vec<u64>,
    pub adapter_baseline: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Threshold {
    pub id: String,
    pub workload_id: String,
    pub metric: String,
    pub comparator: Comparator,
    pub value: f64,
    pub unit: String,
    pub relative_to: Option<String>,
    pub owner: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparator {
    LessThanOrEqual,
    GreaterThanOrEqual,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CReference {
    pub id: String,
    pub interface: String,
    pub source_path: Option<PathBuf>,
    pub status: QualificationState,
    pub unqualified_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedAdapterBaseline {
    pub id: String,
    pub runtime: String,
    pub definition: String,
    pub status: QualificationState,
    pub unqualified_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValidationReport {
    pub schema_version: u32,
    pub valid: bool,
    pub inventory_entries: usize,
    pub dispositions: BTreeMap<String, usize>,
    pub conformance_fixtures: usize,
    pub implemented_fixtures: usize,
    pub benchmark_workloads: usize,
    pub unqualified_workloads: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CommandComparison {
    pub schema_version: u32,
    pub fixture_id: String,
    pub matched: bool,
    pub swift: ComparableOutcome,
    pub rust: ComparableOutcome,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ComparableOutcome {
    pub status: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReport {
    pub schema_version: u32,
    pub specification_version: String,
    pub profile: String,
    pub host: HostMetadata,
    pub workloads: Vec<WorkloadResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostMetadata {
    pub os: String,
    pub architecture: String,
    pub rustc: String,
    pub swift: String,
    pub qualification_tool: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkloadResult {
    pub id: String,
    pub status: WorkloadStatus,
    pub unit: String,
    pub raw_samples: Vec<f64>,
    pub summary: Option<crate::stats::Summary>,
    pub threshold_results: Vec<ThresholdResult>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadStatus {
    Measured,
    Unqualified,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThresholdResult {
    pub threshold_id: String,
    pub status: ThresholdStatus,
    pub observed: Option<f64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdStatus {
    Pass,
    Fail,
    Unqualified,
    NotEnforced,
}
