#![forbid(unsafe_code)]

mod benchmark;
mod model;
mod normalize;
mod process;
mod stats;
mod validate;

pub use benchmark::{BenchmarkOptions, run_benchmarks};
pub use model::{
    BenchmarkReport, BenchmarkSpecification, CommandComparison, ComparableOutcome,
    ComparisonCommand, ConformanceManifest, FeatureInventory, QualificationState, ThresholdStatus,
    ValidationReport, WorkloadStatus,
};
pub use normalize::normalize_output;
pub use process::{CommandOutcome, CommandSpec, CommandStatus, run_command};
pub use stats::{Summary, summarize};
pub use validate::{load_json, validate_all};
