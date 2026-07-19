use serde::{Deserialize, Serialize};

use crate::{ProjectAnalysis, ProjectError, Result};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRefinement {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_features: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_extensions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
}

pub trait RefinementProvider {
    fn name(&self) -> &str;
    fn refine(&self, analysis: &ProjectAnalysis)
    -> std::result::Result<AnalysisRefinement, String>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefinementStatus {
    NotRequested,
    Applied,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefinementReport {
    pub status: RefinementStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Default for RefinementReport {
    fn default() -> Self {
        Self {
            status: RefinementStatus::NotRequested,
            provider: None,
            message: None,
        }
    }
}

pub(crate) fn apply_refinement(
    analysis: &mut ProjectAnalysis,
    provider: &dyn RefinementProvider,
) -> Result<()> {
    match provider.refine(analysis) {
        Ok(refinement) => {
            if let Some(value) = refinement.suggested_image {
                analysis.suggested_image = value;
            }
            if let Some(value) = refinement.suggested_features {
                analysis.suggested_features = stable_strings(value);
            }
            if let Some(value) = refinement.suggested_extensions {
                analysis.suggested_extensions = stable_strings(value);
            }
            if let Some(value) = refinement.framework {
                analysis.framework = Some(value);
            }
            if let Some(value) = refinement.runtime_version {
                analysis.runtime_version = Some(value);
            }
            analysis.refinement = RefinementReport {
                status: RefinementStatus::Applied,
                provider: Some(provider.name().to_owned()),
                message: None,
            };
            Ok(())
        }
        Err(message) => {
            analysis.refinement = RefinementReport {
                status: RefinementStatus::Failed,
                provider: Some(provider.name().to_owned()),
                message: Some(message.clone()),
            };
            Err(ProjectError::Refinement {
                provider: provider.name().to_owned(),
                message,
            })
        }
    }
}

fn stable_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}
