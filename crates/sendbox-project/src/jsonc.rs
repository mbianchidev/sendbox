use std::path::Path;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{ProjectError, Result};

pub fn parse_jsonc(source: &str) -> Result<Value> {
    parse_jsonc_at(source, Path::new("<memory>"))
}

pub fn parse_jsonc_as<T: DeserializeOwned>(source: &str) -> Result<T> {
    jsonc_parser::parse_to_serde_value(source, &Default::default()).map_err(|error| {
        ProjectError::InvalidJsonc {
            path: "<memory>".into(),
            message: error.to_string(),
        }
    })
}

pub(crate) fn parse_jsonc_at(source: &str, path: &Path) -> Result<Value> {
    jsonc_parser::parse_to_serde_value(source, &Default::default()).map_err(|error| {
        ProjectError::InvalidJsonc {
            path: path.to_path_buf(),
            message: error.to_string(),
        }
    })
}
