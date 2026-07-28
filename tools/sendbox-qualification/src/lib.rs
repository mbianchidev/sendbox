#![forbid(unsafe_code)]

mod benchmark;
mod model;
mod process;
mod stats;
mod validate;

pub use benchmark::{BenchmarkOptions, run_benchmarks};
pub use model::{
    BenchmarkReport, BenchmarkSpecification, ConformanceManifest, FeatureInventory,
    QualificationState, ThresholdStatus, ValidationReport, WorkloadStatus,
};
pub use process::{CommandOutcome, CommandSpec, CommandStatus, run_command};
pub use stats::{Summary, summarize};
pub use validate::{load_json, validate_all};
