#![forbid(unsafe_code)]

mod analysis;
mod devcontainer;
mod error;
mod jsonc;
mod refinement;
mod scan;

pub use analysis::{Analyzer, ProjectAnalysis};
pub use devcontainer::{
    DevContainerOverrides, GeneratedDevContainer, generate_devcontainer, write_devcontainer,
};
pub use error::{ProjectError, Result};
pub use jsonc::{parse_jsonc, parse_jsonc_as};
pub use refinement::{AnalysisRefinement, RefinementProvider, RefinementReport, RefinementStatus};
pub use scan::{ScanIssue, ScanIssueKind, ScanLimits, ScanReport};
