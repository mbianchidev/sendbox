//! Immutable compilation of `sendbox_policy::CommandPolicy`.
//!
//! Rule grammar is deliberately smaller than a shell grammar:
//!
//! * ASCII whitespace separates argv tokens.
//! * Backslash escapes exactly the next character, including whitespace,
//!   `*`, `?`, and backslash itself.
//! * Unescaped `*` matches zero or more characters within one argv token.
//! * Unescaped `?` matches exactly one character within one argv token.
//! * A rule always matches the same number of argv tokens it declares.
//! * There are no quotes, expansions, substitutions, or shell reparsing.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use sendbox_policy::{Action, CommandPolicy};
use thiserror::Error;

use crate::api::AdmissionDisposition;

/// Whether a matched rule was literal or used per-token wildcards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Exact,
    TokenWildcard,
    Default,
}

/// Metadata for the rule that determined an admission result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    pub action: AdmissionDisposition,
    pub kind: MatchKind,
    pub source: Option<String>,
}

/// Result of evaluating one exact argv vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandAdmission {
    pub disposition: AdmissionDisposition,
    pub matched: MatchedRule,
}

/// Configuration-time rule grammar errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CommandPolicyCompileError {
    #[error("{list}[{index}] is empty")]
    EmptyRule { list: &'static str, index: usize },
    #[error("{list}[{index}] ends with an incomplete backslash escape")]
    TrailingEscape { list: &'static str, index: usize },
    #[error("{list}[{index}] contains a NUL byte")]
    NulByte { list: &'static str, index: usize },
}

/// Immutable, thread-safe command admission rules.
#[derive(Debug, Clone)]
pub struct CompiledCommandPolicy {
    default_action: AdmissionDisposition,
    allow: Arc<[CompiledRule]>,
    deny: Arc<[CompiledRule]>,
}

impl CompiledCommandPolicy {
    /// Compiles legacy string rules once at broker startup.
    pub fn compile(policy: &CommandPolicy) -> Result<Self, CommandPolicyCompileError> {
        let allow = compile_list("allowlist", &policy.allowlist)?;
        let deny = compile_list("denylist", &policy.denylist)?;
        Ok(Self {
            default_action: convert_action(policy.default_action),
            allow: allow.into(),
            deny: deny.into(),
        })
    }

    /// Evaluates an argv vector without joining or reparsing its tokens.
    #[must_use]
    pub fn evaluate(&self, argv: &[String]) -> CommandAdmission {
        if let Some(rule) = self.deny.iter().find(|rule| rule.matches(argv)) {
            return admission(AdmissionDisposition::Deny, rule);
        }
        if let Some(rule) = self.allow.iter().find(|rule| rule.matches(argv)) {
            return admission(AdmissionDisposition::Allow, rule);
        }
        CommandAdmission {
            disposition: self.default_action,
            matched: MatchedRule {
                action: self.default_action,
                kind: MatchKind::Default,
                source: None,
            },
        }
    }

    #[must_use]
    pub const fn default_action(&self) -> AdmissionDisposition {
        self.default_action
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    source: String,
    tokens: Vec<TokenPattern>,
    exact: Option<Vec<String>>,
}

impl CompiledRule {
    fn matches(&self, argv: &[String]) -> bool {
        if let Some(exact) = &self.exact {
            return exact == argv;
        }
        self.tokens.len() == argv.len()
            && self
                .tokens
                .iter()
                .zip(argv)
                .all(|(pattern, argument)| pattern.matches(argument))
    }

    const fn kind(&self) -> MatchKind {
        if self.exact.is_some() {
            MatchKind::Exact
        } else {
            MatchKind::TokenWildcard
        }
    }
}

#[derive(Debug, Clone)]
struct TokenPattern(Vec<PatternAtom>);

impl TokenPattern {
    fn matches(&self, value: &str) -> bool {
        let value: Vec<char> = value.chars().collect();
        let mut reachable = vec![vec![false; value.len() + 1]; self.0.len() + 1];
        reachable[0][0] = true;
        for pattern_index in 0..self.0.len() {
            for value_index in 0..=value.len() {
                if !reachable[pattern_index][value_index] {
                    continue;
                }
                match self.0[pattern_index] {
                    PatternAtom::Literal(expected) => {
                        if value.get(value_index) == Some(&expected) {
                            reachable[pattern_index + 1][value_index + 1] = true;
                        }
                    }
                    PatternAtom::AnyCharacter => {
                        if value_index < value.len() {
                            reachable[pattern_index + 1][value_index + 1] = true;
                        }
                    }
                    PatternAtom::AnySequence => {
                        reachable[pattern_index + 1][value_index] = true;
                        if value_index < value.len() {
                            reachable[pattern_index][value_index + 1] = true;
                        }
                    }
                }
            }
        }
        reachable[self.0.len()][value.len()]
    }
}

#[derive(Debug, Clone, Copy)]
enum PatternAtom {
    Literal(char),
    AnyCharacter,
    AnySequence,
}

fn compile_list(
    name: &'static str,
    sources: &[String],
) -> Result<Vec<CompiledRule>, CommandPolicyCompileError> {
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| compile_rule(name, index, source))
        .collect()
}

fn compile_rule(
    list: &'static str,
    index: usize,
    source: &str,
) -> Result<CompiledRule, CommandPolicyCompileError> {
    if source.as_bytes().contains(&0) {
        return Err(CommandPolicyCompileError::NulByte { list, index });
    }

    let mut parsed_tokens: Vec<Vec<(char, bool)>> = Vec::new();
    let mut token = Vec::new();
    let mut escaped = false;
    for character in source.chars() {
        if escaped {
            token.push((character, true));
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character.is_ascii_whitespace() {
            if !token.is_empty() {
                parsed_tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push((character, false));
        }
    }
    if escaped {
        return Err(CommandPolicyCompileError::TrailingEscape { list, index });
    }
    if !token.is_empty() {
        parsed_tokens.push(token);
    }
    if parsed_tokens.is_empty() {
        return Err(CommandPolicyCompileError::EmptyRule { list, index });
    }

    let has_wildcards = parsed_tokens
        .iter()
        .flatten()
        .any(|(character, escaped)| !escaped && matches!(character, '*' | '?'));
    let exact = (!has_wildcards).then(|| {
        parsed_tokens
            .iter()
            .map(|token| token.iter().map(|(character, _)| character).collect())
            .collect()
    });
    let tokens = parsed_tokens
        .into_iter()
        .map(|token| {
            let mut atoms = Vec::with_capacity(token.len());
            for (character, escaped) in token {
                let atom = match (character, escaped) {
                    ('*', false) => PatternAtom::AnySequence,
                    ('?', false) => PatternAtom::AnyCharacter,
                    _ => PatternAtom::Literal(character),
                };
                if matches!(atom, PatternAtom::AnySequence)
                    && matches!(atoms.last(), Some(PatternAtom::AnySequence))
                {
                    continue;
                }
                atoms.push(atom);
            }
            TokenPattern(atoms)
        })
        .collect();

    Ok(CompiledRule {
        source: source.to_owned(),
        tokens,
        exact,
    })
}

fn admission(disposition: AdmissionDisposition, rule: &CompiledRule) -> CommandAdmission {
    CommandAdmission {
        disposition,
        matched: MatchedRule {
            action: disposition,
            kind: rule.kind(),
            source: Some(rule.source.clone()),
        },
    }
}

const fn convert_action(action: Action) -> AdmissionDisposition {
    match action {
        Action::Allow => AdmissionDisposition::Allow,
        Action::Deny => AdmissionDisposition::Deny,
    }
}

impl fmt::Display for MatchKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(default_action: Action, allow: &[&str], deny: &[&str]) -> CompiledCommandPolicy {
        CompiledCommandPolicy::compile(&CommandPolicy {
            default_action,
            allowlist: allow.iter().map(|value| (*value).to_owned()).collect(),
            denylist: deny.iter().map(|value| (*value).to_owned()).collect(),
            log_blocked: true,
        })
        .expect("compile")
    }

    #[test]
    fn exact_rules_compare_the_full_argv_vector() {
        let policy = compile(Action::Deny, &["git status"], &[]);
        assert_eq!(
            policy
                .evaluate(&["git".into(), "status".into()])
                .disposition,
            AdmissionDisposition::Allow
        );
        assert_eq!(
            policy.evaluate(&["git status".into()]).disposition,
            AdmissionDisposition::Deny
        );
        assert_eq!(
            policy
                .evaluate(&["git".into(), "status".into(), "--short".into()])
                .disposition,
            AdmissionDisposition::Deny
        );
    }

    #[test]
    fn wildcard_never_crosses_an_argv_token_boundary() {
        let policy = compile(Action::Deny, &["git *"], &[]);
        assert_eq!(
            policy
                .evaluate(&["git".into(), "status --short".into()])
                .disposition,
            AdmissionDisposition::Allow
        );
        assert_eq!(
            policy
                .evaluate(&["git".into(), "status".into(), "--short".into()])
                .disposition,
            AdmissionDisposition::Deny
        );
    }

    #[test]
    fn escaped_whitespace_and_wildcards_are_literals() {
        let policy = compile(
            Action::Deny,
            &[r"tool argument\ with\ spaces literal\*"],
            &[],
        );
        assert_eq!(
            policy
                .evaluate(&[
                    "tool".into(),
                    "argument with spaces".into(),
                    "literal*".into()
                ])
                .disposition,
            AdmissionDisposition::Allow
        );
    }

    #[test]
    fn deny_rules_win_even_when_an_allow_rule_matches() {
        let policy = compile(Action::Deny, &["git *"], &["git push"]);
        assert_eq!(
            policy.evaluate(&["git".into(), "push".into()]).disposition,
            AdmissionDisposition::Deny
        );
        assert_eq!(
            policy
                .evaluate(&["git".into(), "status".into()])
                .disposition,
            AdmissionDisposition::Allow
        );
    }

    #[test]
    fn default_action_is_preserved() {
        let policy = compile(Action::Allow, &[], &["sudo *"]);
        let admission = policy.evaluate(&["cargo".into(), "test".into()]);
        assert_eq!(admission.disposition, AdmissionDisposition::Allow);
        assert_eq!(admission.matched.kind, MatchKind::Default);
    }

    #[test]
    fn malformed_patterns_fail_at_compile_time() {
        let error = CompiledCommandPolicy::compile(&CommandPolicy {
            default_action: Action::Deny,
            allowlist: vec!["tool\\".into()],
            denylist: Vec::new(),
            log_blocked: false,
        })
        .expect_err("trailing escape");
        assert!(matches!(
            error,
            CommandPolicyCompileError::TrailingEscape { .. }
        ));
    }
}
