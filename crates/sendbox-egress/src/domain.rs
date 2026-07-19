//! Domain normalization and pattern matching.
//!
//! Exact patterns match only the identical normalized name. A `*.example.com`
//! pattern matches any strict subdomain of `example.com` but never the apex
//! `example.com` itself, and never an unrelated name that merely shares a
//! suffix such as `evilexample.com`.

use thiserror::Error;

/// RFC 1035 maximum total domain length (octets).
pub const MAX_DOMAIN_OCTETS: usize = 253;
/// RFC 1035 maximum single-label length (octets).
pub const MAX_LABEL_OCTETS: usize = 63;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("domain name is empty")]
    Empty,
    #[error("domain name exceeds 253 octets")]
    TooLong,
    #[error("domain label '{0}' is empty or exceeds 63 octets")]
    InvalidLabel(String),
    #[error("domain name contains an invalid character in label '{0}'")]
    InvalidCharacter(String),
}

/// Normalizes a domain name: lowercases, strips a single trailing root dot,
/// and validates label structure (RFC 1035 length limits, alphanumeric plus
/// internal hyphens). Returns the canonical form used for all policy
/// comparisons.
pub fn normalize_domain(raw: &str) -> Result<String, DomainError> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(DomainError::Empty);
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.len() > MAX_DOMAIN_OCTETS {
        return Err(DomainError::TooLong);
    }
    for label in lower.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_OCTETS {
            return Err(DomainError::InvalidLabel(label.to_owned()));
        }
        let bytes = label.as_bytes();
        let valid = bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-';
        if !valid {
            return Err(DomainError::InvalidCharacter(label.to_owned()));
        }
    }
    Ok(lower)
}

/// Normalizes a wildcard policy pattern (`*.example.com` or an exact name).
/// The wildcard label itself is not subject to label validation; the
/// remainder of the pattern is normalized as a domain name.
pub fn normalize_pattern(raw: &str) -> Result<String, DomainError> {
    let trimmed = raw.trim().trim_end_matches('.');
    if let Some(rest) = trimmed.strip_prefix("*.") {
        let normalized_rest = normalize_domain(rest)?;
        Ok(format!("*.{normalized_rest}"))
    } else {
        normalize_domain(trimmed)
    }
}

/// Returns true if `candidate` (already normalized) matches `pattern`
/// (already normalized via [`normalize_pattern`]).
#[must_use]
pub fn pattern_matches(pattern: &str, candidate: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            let dotted_suffix = format!(".{suffix}");
            candidate.len() > dotted_suffix.len() && candidate.ends_with(&dotted_suffix)
        }
        None => pattern == candidate,
    }
}

/// Returns the leftmost ("dynamic") label of a normalized domain name. DNS
/// tunneling encodes exfiltrated data primarily in this label, so the DNS
/// budget engine bounds the distinct count of these across a window. Returns
/// an empty string only for an already-normalized name that (by construction)
/// always has at least one label.
#[must_use]
pub fn leftmost_label(normalized: &str) -> &str {
    normalized.split('.').next().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(normalize_domain("Example.COM.").unwrap(), "example.com");
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert_eq!(normalize_domain("").unwrap_err(), DomainError::Empty);
        assert_eq!(normalize_domain(".").unwrap_err(), DomainError::Empty);
        let long_label = "a".repeat(64);
        assert!(matches!(
            normalize_domain(&format!("{long_label}.com")),
            Err(DomainError::InvalidLabel(_))
        ));
    }

    #[test]
    fn rejects_invalid_characters_and_hyphen_edges() {
        assert!(matches!(
            normalize_domain("exa_mple.com"),
            Err(DomainError::InvalidCharacter(_))
        ));
        assert!(matches!(
            normalize_domain("-example.com"),
            Err(DomainError::InvalidCharacter(_))
        ));
        assert!(matches!(
            normalize_domain("example-.com"),
            Err(DomainError::InvalidCharacter(_))
        ));
    }

    #[test]
    fn wildcard_matches_subdomains_only_not_apex() {
        let pattern = normalize_pattern("*.example.com").unwrap();
        assert!(pattern_matches(&pattern, "foo.example.com"));
        assert!(pattern_matches(&pattern, "a.b.example.com"));
        assert!(!pattern_matches(&pattern, "example.com"));
    }

    #[test]
    fn wildcard_does_not_match_unrelated_suffix_confusion() {
        let pattern = normalize_pattern("*.github.com").unwrap();
        assert!(!pattern_matches(&pattern, "evilgithub.com"));
        assert!(!pattern_matches(&pattern, "githubx.com"));
        assert!(pattern_matches(&pattern, "api.github.com"));
    }

    #[test]
    fn exact_pattern_matches_only_identical_name() {
        let pattern = normalize_pattern("example.com").unwrap();
        assert!(pattern_matches(&pattern, "example.com"));
        assert!(!pattern_matches(&pattern, "sub.example.com"));
    }

    #[test]
    fn leftmost_label_extracts_first_label() {
        assert_eq!(leftmost_label("data.attacker.example"), "data");
        assert_eq!(leftmost_label("example"), "example");
    }
}
