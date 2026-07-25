use serde::{Deserialize, Serialize};

use crate::{GuardError, Operation};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BranchPolicyConfiguration {
    pub enabled: bool,
    pub username: Option<String>,
    pub protected_branches: Vec<String>,
    pub allowed_branch_patterns: Vec<String>,
}

impl Default for BranchPolicyConfiguration {
    fn default() -> Self {
        Self {
            enabled: true,
            username: None,
            protected_branches: vec!["main".to_owned(), "master".to_owned()],
            allowed_branch_patterns: vec![
                "{username}/*".to_owned(),
                "copilot/*".to_owned(),
                "feature/*".to_owned(),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct BranchPolicy {
    enabled: bool,
    protected_branches: Vec<String>,
    allowed_patterns: Vec<String>,
}

impl BranchPolicy {
    pub fn compile(configuration: &BranchPolicyConfiguration) -> Result<Self, GuardError> {
        let username = configuration
            .username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(username) = username
            && !valid_github_login(username)
        {
            return Err(GuardError::InvalidPolicy(
                "branch protection username is invalid".to_owned(),
            ));
        }
        let protected_branches = configuration
            .protected_branches
            .iter()
            .map(|branch| {
                normalize_branch(branch).ok_or_else(|| {
                    GuardError::InvalidPolicy(format!("protected branch `{branch}` is invalid"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allowed_patterns = configuration
            .allowed_branch_patterns
            .iter()
            .filter_map(|pattern| {
                let pattern = pattern.trim();
                if pattern.is_empty() {
                    return Some(Err(GuardError::InvalidPolicy(
                        "allowed branch pattern is empty".to_owned(),
                    )));
                }
                if pattern.contains('\0') || pattern.contains('[') || pattern.contains(']') {
                    return Some(Err(GuardError::InvalidPolicy(format!(
                        "allowed branch pattern `{pattern}` is unsupported"
                    ))));
                }
                if pattern.contains("{username}") {
                    username.map(|username| Ok(pattern.replace("{username}", username)))
                } else {
                    Some(Ok(pattern.to_owned()))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            enabled: configuration.enabled,
            protected_branches,
            allowed_patterns,
        })
    }

    pub fn check(
        &self,
        branch: &str,
        operation: Operation,
        label: &str,
    ) -> Result<String, GuardError> {
        if !self.enabled {
            return normalize_branch(branch).ok_or_else(|| {
                GuardError::denied(
                    operation,
                    format!("cannot safely resolve {label} branch `{branch}`"),
                )
            });
        }
        let normalized = normalize_branch(branch).ok_or_else(|| {
            GuardError::denied(
                operation,
                format!("cannot safely resolve {label} branch `{branch}`"),
            )
        })?;
        if self
            .protected_branches
            .iter()
            .any(|protected| protected.eq_ignore_ascii_case(&normalized))
        {
            return Err(GuardError::denied(
                operation,
                format!("protected branch `{normalized}`"),
            ));
        }
        if !self
            .allowed_patterns
            .iter()
            .any(|pattern| glob_matches(&normalized, pattern))
        {
            return Err(GuardError::denied(
                operation,
                format!("{label} branch `{normalized}` does not match an allowed branch pattern"),
            ));
        }
        Ok(normalized)
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

#[must_use]
pub fn normalize_branch(branch: &str) -> Option<String> {
    let mut value = branch.trim();
    while let Some(remainder) = value.strip_prefix('+') {
        value = remainder;
    }
    if matches!(value, "HEAD" | "@") {
        return None;
    }
    if let Some(remainder) = value.strip_prefix("refs/heads/") {
        value = remainder;
    } else if let Some(remainder) = value.strip_prefix("refs/remotes/") {
        value = remainder.split_once('/')?.1;
    } else if value.starts_with("refs/") {
        return None;
    }
    valid_branch_name(value).then(|| value.to_owned())
}

fn valid_branch_name(value: &str) -> bool {
    !value.is_empty()
        && value != "@"
        && !value.starts_with(['.', '/'])
        && !value.ends_with(['.', '/'])
        && !value.ends_with(".lock")
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && !value
            .chars()
            .any(|character| character.is_control() || " ~^:?*[\\\u{7f}".contains(character))
}

fn valid_github_login(value: &str) -> bool {
    value.len() <= 39
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn glob_matches(value: &str, pattern: &str) -> bool {
    let value = value.chars().collect::<Vec<_>>();
    let pattern = pattern.chars().collect::<Vec<_>>();
    let mut value_index = 0;
    let mut pattern_index = 0;
    let mut star_value = None;
    let mut star_pattern = None;
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == '?' || pattern[pattern_index] == value[value_index])
        {
            value_index += 1;
            pattern_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_pattern = Some(pattern_index);
            star_value = Some(value_index);
            pattern_index += 1;
        } else if let (Some(pattern_star), Some(value_star)) = (star_pattern, star_value) {
            let next_value = value_star + 1;
            star_value = Some(next_value);
            value_index = next_value;
            pattern_index = pattern_star + 1;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{BranchPolicy, BranchPolicyConfiguration, normalize_branch};
    use crate::Operation;

    #[test]
    fn protected_branches_override_wildcard_allow() {
        let policy = BranchPolicy::compile(&BranchPolicyConfiguration {
            allowed_branch_patterns: vec!["*".to_owned()],
            ..BranchPolicyConfiguration::default()
        })
        .unwrap();
        assert!(
            policy
                .check("main", Operation::Push, "destination")
                .is_err()
        );
    }

    #[test]
    fn expands_username_and_drops_unresolved_pattern() {
        let policy = BranchPolicy::compile(&BranchPolicyConfiguration {
            username: Some("mbianchidev".to_owned()),
            ..BranchPolicyConfiguration::default()
        })
        .unwrap();
        assert!(
            policy
                .check("mbianchidev/topic", Operation::Push, "current")
                .is_ok()
        );
        let unresolved = BranchPolicy::compile(&BranchPolicyConfiguration::default()).unwrap();
        assert!(
            unresolved
                .check("mbianchidev/topic", Operation::Push, "current")
                .is_err()
        );
    }

    #[test]
    fn normalizes_supported_branch_refs() {
        assert_eq!(
            normalize_branch("+refs/heads/feature/a").as_deref(),
            Some("feature/a")
        );
        assert_eq!(
            normalize_branch("refs/remotes/origin/feature/a").as_deref(),
            Some("feature/a")
        );
        assert!(normalize_branch("HEAD").is_none());
        assert!(normalize_branch("refs/tags/v1").is_none());
        assert!(normalize_branch("feature/*").is_none());
    }

    proptest! {
        #[test]
        fn normalization_is_idempotent(value in any::<String>()) {
            if let Some(normalized) = normalize_branch(&value) {
                let second = normalize_branch(&normalized);
                prop_assert_eq!(second.as_deref(), Some(normalized.as_str()));
            }
        }
    }
}
