//! Deterministic, bounded DNS query-exfiltration controls.
//!
//! Even when every CNAME hop, the final owner name, and every returned
//! address is validated against policy, an agent allowed to resolve an
//! attacker-controlled domain can still exfiltrate data by encoding it in the
//! query name itself (`<base32-secret>.attacker.example`). This module bounds
//! that channel deterministically, with **no entropy heuristics**:
//!
//! * Structural limits (per query): maximum total QNAME octets, maximum label
//!   count, and maximum single-label octets.
//! * A QTYPE allowlist.
//! * A response-record cap.
//! * Four per-window budgets that reset on a fixed monotonic boundary and
//!   whose state is bounded by construction: total query count, total QNAME
//!   octets, distinct normalized names, and distinct leftmost ("dynamic")
//!   labels. A single budget governs the whole sandbox agent.
//!
//! The distinct-name and distinct-label sets never grow past their configured
//! maxima: reaching a maximum with a *new* distinct entry is itself a denial,
//! never an unbounded insert. A denied query never consumes budget, so a flood
//! of rejected queries cannot itself grow state.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sendbox_policy::{DnsPolicy, DnsRecordType};
use serde::Serialize;

use crate::domain;

/// The specific structural limit or per-window budget a query violated.
/// Serialized (snake_case) into audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsLimit {
    /// Total normalized QNAME length exceeded `max_qname_octets`.
    QnameOctets,
    /// QNAME label count exceeded `max_labels`.
    LabelCount,
    /// A single label exceeded `max_label_octets`.
    LabelOctets,
    /// Per-window query-count budget exhausted.
    QueryCount,
    /// Per-window total-QNAME-octet budget exhausted.
    QueryOctets,
    /// Per-window distinct-name budget exhausted.
    UniqueNames,
    /// Per-window distinct-dynamic-label budget exhausted.
    DynamicLabels,
}

impl DnsLimit {
    /// True for the fixed-window rate budgets (as opposed to per-query
    /// structural limits). Used by the broker to distinguish an audit
    /// `rate_limited` event from a structural `denied` event.
    #[must_use]
    pub fn is_rate_budget(self) -> bool {
        matches!(
            self,
            DnsLimit::QueryCount
                | DnsLimit::QueryOctets
                | DnsLimit::UniqueNames
                | DnsLimit::DynamicLabels
        )
    }

    /// Stable snake_case name for diagnostics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DnsLimit::QnameOctets => "qname_octets",
            DnsLimit::LabelCount => "label_count",
            DnsLimit::LabelOctets => "label_octets",
            DnsLimit::QueryCount => "query_count",
            DnsLimit::QueryOctets => "query_octets",
            DnsLimit::UniqueNames => "unique_names",
            DnsLimit::DynamicLabels => "dynamic_labels",
        }
    }
}

struct WindowState {
    window_start: Option<Instant>,
    queries: u32,
    query_octets: u64,
    unique_names: HashSet<String>,
    dynamic_labels: HashSet<String>,
}

impl WindowState {
    fn empty() -> Self {
        Self {
            window_start: None,
            queries: 0,
            query_octets: 0,
            unique_names: HashSet::new(),
            dynamic_labels: HashSet::new(),
        }
    }

    fn reset(&mut self, now: Instant) {
        self.window_start = Some(now);
        self.queries = 0;
        self.query_octets = 0;
        self.unique_names.clear();
        self.dynamic_labels.clear();
    }
}

/// Compiled DNS exfiltration guard. Structural limits are pure; the budget
/// carries bounded, mutable per-window state behind a mutex.
pub struct DnsGuard {
    max_qname_octets: usize,
    max_labels: usize,
    max_label_octets: usize,
    allowed_record_types: Vec<DnsRecordType>,
    max_response_records: usize,
    window: Duration,
    max_queries: u32,
    max_query_octets: u64,
    max_unique_names: usize,
    max_dynamic_labels: usize,
    state: Mutex<WindowState>,
}

impl DnsGuard {
    /// Compiles a guard from the DNS policy.
    #[must_use]
    pub fn from_policy(policy: &DnsPolicy) -> Self {
        Self {
            max_qname_octets: policy.max_qname_octets as usize,
            max_labels: policy.max_labels as usize,
            max_label_octets: policy.max_label_octets as usize,
            allowed_record_types: policy.allowed_record_types.clone(),
            max_response_records: policy.max_response_records as usize,
            window: Duration::from_secs(u64::from(policy.budget.window_secs)),
            max_queries: policy.budget.max_queries,
            max_query_octets: policy.budget.max_query_octets,
            max_unique_names: policy.budget.max_unique_names as usize,
            max_dynamic_labels: policy.budget.max_dynamic_labels as usize,
            state: Mutex::new(WindowState::empty()),
        }
    }

    /// The maximum number of address records the broker may return.
    #[must_use]
    pub fn max_response_records(&self) -> usize {
        self.max_response_records
    }

    /// True if the given record type is on the QTYPE allowlist.
    #[must_use]
    pub fn record_type_allowed(&self, record_type: DnsRecordType) -> bool {
        self.allowed_record_types.contains(&record_type)
    }

    /// Pure, stateless structural validation of a normalized QNAME.
    pub fn check_structure(&self, normalized: &str) -> Result<(), DnsLimit> {
        if normalized.len() > self.max_qname_octets {
            return Err(DnsLimit::QnameOctets);
        }
        let mut label_count = 0usize;
        for label in normalized.split('.') {
            label_count += 1;
            if label.len() > self.max_label_octets {
                return Err(DnsLimit::LabelOctets);
            }
        }
        if label_count > self.max_labels {
            return Err(DnsLimit::LabelCount);
        }
        Ok(())
    }

    /// Admits (or rejects) one query against the per-window budgets. `now`
    /// is supplied by the caller so behavior is deterministic and testable.
    /// A rejected query consumes no budget; on success the query's octets,
    /// name, and dynamic label are recorded. The distinct-name/label sets are
    /// never grown past their maxima.
    pub fn admit(&self, normalized: &str, now: Instant) -> Result<(), DnsLimit> {
        let octets = normalized.len() as u64;
        let label = domain::leftmost_label(normalized);
        let mut state = self.state.lock().expect("dns budget mutex poisoned");

        let expired = match state.window_start {
            None => true,
            Some(start) => {
                self.window.is_zero() || now.saturating_duration_since(start) >= self.window
            }
        };
        if expired {
            state.reset(now);
        }

        if state.queries.saturating_add(1) > self.max_queries {
            return Err(DnsLimit::QueryCount);
        }
        if state.query_octets.saturating_add(octets) > self.max_query_octets {
            return Err(DnsLimit::QueryOctets);
        }
        let name_is_new = !state.unique_names.contains(normalized);
        if name_is_new && state.unique_names.len() >= self.max_unique_names {
            return Err(DnsLimit::UniqueNames);
        }
        let label_is_new = !state.dynamic_labels.contains(label);
        if label_is_new && state.dynamic_labels.len() >= self.max_dynamic_labels {
            return Err(DnsLimit::DynamicLabels);
        }

        state.queries += 1;
        state.query_octets += octets;
        if name_is_new {
            state.unique_names.insert(normalized.to_owned());
        }
        if label_is_new {
            state.dynamic_labels.insert(label.to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sendbox_policy::DnsQueryBudget;

    fn guard(policy: DnsPolicy) -> DnsGuard {
        DnsGuard::from_policy(&policy)
    }

    fn tight_budget() -> DnsPolicy {
        DnsPolicy {
            max_ttl_secs: 300,
            max_qname_octets: 60,
            max_labels: 5,
            max_label_octets: 20,
            allowed_record_types: vec![DnsRecordType::A],
            max_response_records: 4,
            budget: DnsQueryBudget {
                window_secs: 60,
                max_queries: 3,
                max_query_octets: 1_000,
                max_unique_names: 2,
                max_dynamic_labels: 2,
            },
        }
    }

    #[test]
    fn structural_limits_reject_oversized_qname_and_labels() {
        let g = guard(tight_budget());
        assert_eq!(
            g.check_structure(&"a".repeat(61)),
            Err(DnsLimit::QnameOctets)
        );
        assert_eq!(
            g.check_structure(&format!("{}.example.com", "a".repeat(21))),
            Err(DnsLimit::LabelOctets)
        );
        assert_eq!(
            g.check_structure("a.b.c.d.e.f.example"),
            Err(DnsLimit::LabelCount)
        );
        assert!(g.check_structure("api.example.com").is_ok());
    }

    #[test]
    fn qtype_allowlist_enforced() {
        let g = guard(tight_budget());
        assert!(g.record_type_allowed(DnsRecordType::A));
        assert!(!g.record_type_allowed(DnsRecordType::Aaaa));
    }

    #[test]
    fn query_count_budget_is_bounded_and_denies_flood() {
        let g = guard(tight_budget());
        let base = Instant::now();
        assert!(g.admit("a.example", base).is_ok());
        assert!(g.admit("b.example", base).is_ok());
        assert!(g.admit("a.example", base).is_ok()); // 3rd query, name reused
        // 4th query exceeds max_queries=3; a denied query must not consume
        // budget nor grow state.
        assert_eq!(g.admit("a.example", base), Err(DnsLimit::QueryCount));
        assert_eq!(g.admit("a.example", base), Err(DnsLimit::QueryCount));
    }

    #[test]
    fn window_resets_on_fixed_boundary() {
        let g = guard(tight_budget());
        let base = Instant::now();
        // Reuse one name so the query-count budget (3) is the binding limit,
        // not the unique-name budget (2).
        assert!(g.admit("a.example", base).is_ok());
        assert!(g.admit("a.example", base).is_ok());
        assert!(g.admit("a.example", base).is_ok());
        assert_eq!(g.admit("a.example", base), Err(DnsLimit::QueryCount));
        // A query one full window later starts fresh.
        let later = base + Duration::from_secs(61);
        assert!(g.admit("a.example", later).is_ok());
    }

    #[test]
    fn unique_name_budget_bounds_distinct_names() {
        let g = guard(tight_budget());
        let base = Instant::now();
        assert!(g.admit("one.example", base).is_ok());
        assert!(g.admit("two.example", base).is_ok());
        // A third *distinct* name exceeds max_unique_names=2.
        assert_eq!(g.admit("three.example", base), Err(DnsLimit::UniqueNames));
        // A previously-seen name is still admitted (until the query budget).
        assert!(g.admit("one.example", base).is_ok());
    }

    #[test]
    fn dynamic_label_budget_bounds_distinct_leftmost_labels() {
        let mut policy = tight_budget();
        // Loosen everything except the dynamic-label budget so it is the
        // binding constraint.
        policy.budget.max_queries = 100;
        policy.budget.max_unique_names = 100;
        policy.budget.max_dynamic_labels = 2;
        let g = guard(policy);
        let base = Instant::now();
        assert!(g.admit("aaa.tunnel.example", base).is_ok());
        assert!(g.admit("bbb.tunnel.example", base).is_ok());
        // A third distinct leftmost label is the exfiltration signal.
        assert_eq!(
            g.admit("ccc.tunnel.example", base),
            Err(DnsLimit::DynamicLabels)
        );
        // Reusing an already-seen dynamic label is fine.
        assert!(g.admit("aaa.other.example", base).is_ok());
    }

    #[test]
    fn octet_budget_denies_high_volume_names() {
        let mut policy = tight_budget();
        policy.budget.max_queries = 100;
        policy.budget.max_unique_names = 100;
        policy.budget.max_dynamic_labels = 100;
        policy.budget.max_query_octets = 40;
        let g = guard(policy);
        let base = Instant::now();
        assert!(g.admit("aaaaaaaaaa.example", base).is_ok()); // 18 octets
        assert!(g.admit("bbbbbbbbbb.example", base).is_ok()); // 36 octets total
        assert_eq!(g.admit("cccc.example", base), Err(DnsLimit::QueryOctets));
    }

    #[test]
    fn rate_budget_classification_is_correct() {
        assert!(DnsLimit::QueryCount.is_rate_budget());
        assert!(DnsLimit::DynamicLabels.is_rate_budget());
        assert!(!DnsLimit::QnameOctets.is_rate_budget());
        assert!(!DnsLimit::LabelCount.is_rate_budget());
    }
}
