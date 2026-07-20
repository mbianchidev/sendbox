//! Environment construction and dynamic-loader/runtime hook denial.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::error::RequestValidationError;

const DANGEROUS_ENV_EXACT: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "PS4",
    "PROMPT_COMMAND",
    "IFS",
    "RUBYOPT",
    "RUBYLIB",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_REPL_HISTORY",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
    "CLASSPATH",
    "GCONV_PATH",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "TCLLIBPATH",
    "R_PROFILE",
    "R_PROFILE_USER",
    "R_ENVIRON",
    "R_ENVIRON_USER",
    "PYTHONSTARTUP",
    "GLIBC_TUNABLES",
    "LOCPATH",
    "NLSPATH",
    "MALLOC_CHECK_",
    "GIT_SSH_COMMAND",
];
const DANGEROUS_ENV_PREFIXES: &[&str] = &["LD_", "PYTHON", "RUBY", "JAVA_", "NODE_"];

/// Immutable environment policy applied before a launcher sees a request.
#[derive(Debug, Clone)]
pub struct EnvironmentPolicy {
    fixed: BTreeMap<String, String>,
}

impl Default for EnvironmentPolicy {
    fn default() -> Self {
        Self::new([
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ])
    }
}

impl EnvironmentPolicy {
    #[must_use]
    pub fn new(fixed: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            fixed: fixed.into_iter().collect(),
        }
    }

    /// Produces the complete child environment without inheriting the broker
    /// process environment.
    pub fn sanitize(
        &self,
        requested: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, RequestValidationError> {
        let mut result = self.fixed.clone();
        for (name, value) in requested {
            validate_name(name)?;
            if value.as_bytes().contains(&0) {
                return Err(RequestValidationError::NulByte {
                    field: "environment_value",
                });
            }
            if self.fixed.contains_key(name) {
                continue;
            }
            if is_dangerous(name) {
                return Err(RequestValidationError::DangerousEnvironmentVariable(
                    name.clone(),
                ));
            }
            result.insert(name.clone(), value.clone());
        }
        Ok(result)
    }
}

fn validate_name(name: &str) -> Result<(), RequestValidationError> {
    if name.is_empty()
        || name.contains('=')
        || name.as_bytes().contains(&0)
        || !name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Err(RequestValidationError::InvalidEnvironmentVariableName(
            name.to_owned(),
        ));
    }
    Ok(())
}

fn is_dangerous(name: &str) -> bool {
    DANGEROUS_ENV_EXACT.contains(&name)
        || DANGEROUS_ENV_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_values_override_callers_and_input_is_not_inherited() {
        let mut requested = BTreeMap::new();
        requested.insert("PATH".into(), "/attacker".into());
        requested.insert("SAFE".into(), "yes".into());
        let sanitized = EnvironmentPolicy::default()
            .sanitize(&requested)
            .expect("sanitize");
        assert_eq!(
            sanitized.get("PATH").map(String::as_str),
            Some("/usr/bin:/bin")
        );
        assert_eq!(sanitized.get("SAFE").map(String::as_str), Some("yes"));
    }

    #[test]
    fn dangerous_loader_and_runtime_hooks_are_denied() {
        for name in ["LD_PRELOAD", "PYTHONPATH", "NODE_OPTIONS", "BASH_ENV"] {
            let requested = BTreeMap::from([(name.to_owned(), "bad".to_owned())]);
            assert!(matches!(
                EnvironmentPolicy::default().sanitize(&requested),
                Err(RequestValidationError::DangerousEnvironmentVariable(value)) if value == name
            ));
        }
    }
}
