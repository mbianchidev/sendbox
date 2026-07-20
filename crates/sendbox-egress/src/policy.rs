//! Deterministic, side-effect-free evaluation of egress decisions compiled
//! canonically from [`sendbox_policy::NetworkPolicy`].
//!
//! `sendbox_policy::NetworkPolicy` is the single source of truth. This module
//! compiles it once into a [`PolicyEngine`] and never mutates it. Precedence
//! rules, in order:
//! 1. An explicit blocked IP/CIDR entry always denies.
//! 2. A restricted [`AddressClass`] (loopback, link-local, multicast,
//!    RFC 1918, ULA, cloud metadata) is denied unless the exact destination
//!    is covered by an explicit allowed IP/CIDR grant. A domain allow rule
//!    can never unlock a restricted address class by itself.
//! 3. A blocked domain pattern always denies (hostname connections only).
//! 4. Port/protocol constraints, when configured, must match.
//! 5. Remaining decisions fall back to an allowed-domain match or the
//!    policy's `default_action` (hostname connections), or to an explicit
//!    network grant or `default_action` (direct-IP connections, which never
//!    consult domain rules).

use std::net::IpAddr;

use ipnet::IpNet;
use sendbox_policy::{Action, DnsPolicy, NetworkPolicy, PortRule, Protocol};
use serde::Serialize;
use thiserror::Error;

use crate::address::{AddressClass, classify};
use crate::domain::{self, DomainError};

/// Default concurrent-connection cap applied when `max_connections` is unset
/// (or non-positive). Chosen to match the shipped default policy comment.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 100;
/// Upper bound applied to any configured connection cap so the compiled
/// semaphore and nftables identity can never be sized absurdly.
pub const MAX_CONNECTIONS_CEILING: u32 = 65_535;

/// Resolves the existing `sendbox_policy::NetworkPolicy::max_connections`
/// (`Option<i64>`) into a bounded, positive `u32`, failing closed rather than
/// substituting a success-shaped default for an invalid value. `None` maps to
/// [`DEFAULT_MAX_CONNECTIONS`]; a non-positive value or one above
/// [`MAX_CONNECTIONS_CEILING`] (or `u32`) is a deterministic error. The
/// existing policy field therefore remains the single source of truth.
pub fn resolve_max_connections(max_connections: Option<i64>) -> Result<u32, PolicyError> {
    let Some(value) = max_connections else {
        return Ok(DEFAULT_MAX_CONNECTIONS);
    };
    if value <= 0 {
        return Err(PolicyError::NonPositiveMaxConnections);
    }
    match u32::try_from(value) {
        Ok(resolved) if resolved <= MAX_CONNECTIONS_CEILING => Ok(resolved),
        _ => Err(PolicyError::MaxConnectionsTooLarge {
            value,
            ceiling: MAX_CONNECTIONS_CEILING,
        }),
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy.network.{field}: {source}")]
    InvalidDomainPattern {
        field: &'static str,
        #[source]
        source: DomainError,
    },
    #[error("policy.network.{field}: invalid IP/CIDR literal '{value}': {message}")]
    InvalidNetworkLiteral {
        field: &'static str,
        value: String,
        message: String,
    },
    #[error("policy.network.max_connections must be greater than zero when configured")]
    NonPositiveMaxConnections,
    #[error("policy.network.max_connections {value} exceeds the supported ceiling {ceiling}")]
    MaxConnectionsTooLarge { value: i64, ceiling: u32 },
    #[error("policy.network.dns.{field}: {message}")]
    InvalidDnsControl {
        field: &'static str,
        message: &'static str,
    },
}

/// Validates every DNS structural limit and per-window budget field, returning
/// the first out-of-range field deterministically. Fail-closed: a zero or
/// out-of-range control is an error, never a silently accepted value.
fn validate_dns_controls(dns: &sendbox_policy::DnsPolicy) -> Result<(), PolicyError> {
    let invalid = |field, message| PolicyError::InvalidDnsControl { field, message };
    if dns.max_ttl_secs == 0 {
        return Err(invalid("max_ttl_secs", "must be greater than zero"));
    }
    if dns.max_qname_octets < 1 || dns.max_qname_octets > 253 {
        return Err(invalid("max_qname_octets", "must be between 1 and 253"));
    }
    if dns.max_labels < 1 {
        return Err(invalid("max_labels", "must be greater than zero"));
    }
    if dns.max_label_octets < 1 || dns.max_label_octets > 63 {
        return Err(invalid("max_label_octets", "must be between 1 and 63"));
    }
    if dns.max_response_records < 1 {
        return Err(invalid("max_response_records", "must be greater than zero"));
    }
    if dns.allowed_record_types.is_empty() {
        return Err(invalid(
            "allowed_record_types",
            "must list at least one record type",
        ));
    }
    if dns.budget.window_secs == 0 {
        return Err(invalid("budget.window_secs", "must be greater than zero"));
    }
    if dns.budget.max_queries < 1 {
        return Err(invalid("budget.max_queries", "must be greater than zero"));
    }
    if dns.budget.max_query_octets < 1 {
        return Err(invalid(
            "budget.max_query_octets",
            "must be greater than zero",
        ));
    }
    if dns.budget.max_unique_names < 1 {
        return Err(invalid(
            "budget.max_unique_names",
            "must be greater than zero",
        ));
    }
    if dns.budget.max_dynamic_labels < 1 {
        return Err(invalid(
            "budget.max_dynamic_labels",
            "must be greater than zero",
        ));
    }
    Ok(())
}

/// Deterministic decision output. Field order is fixed for stable JSON
/// diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
    pub address_class: AddressClass,
}

impl Decision {
    fn allow(reason: impl Into<String>, address_class: AddressClass) -> Self {
        Self {
            allowed: true,
            reason: reason.into(),
            address_class,
        }
    }

    fn deny(reason: impl Into<String>, address_class: AddressClass) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            address_class,
        }
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }
}

struct DomainDecision {
    allowed: bool,
    reason: String,
}

/// Compiled, normalized policy ready for repeatable, side-effect-free
/// evaluation.
pub struct PolicyEngine {
    default_action: Action,
    allow_dns: bool,
    allowed_domains: Vec<String>,
    blocked_domains: Vec<String>,
    allowed_networks: Vec<IpNet>,
    blocked_networks: Vec<IpNet>,
    allowed_ports: Vec<PortRule>,
    max_concurrent_connections: u32,
    dns: DnsPolicy,
}

impl PolicyEngine {
    /// Canonically compiles a [`sendbox_policy::NetworkPolicy`] into an
    /// evaluatable engine, validating every domain pattern and IP/CIDR
    /// literal up front and failing closed on any error.
    pub fn compile(policy: &NetworkPolicy) -> Result<Self, PolicyError> {
        let allowed_domains = normalize_patterns(&policy.allowed_domains, "allowed_domains")?;
        let blocked_domains = normalize_patterns(&policy.blocked_domains, "blocked_domains")?;
        let allowed_networks = parse_networks(&policy.allowed_networks, "allowed_networks")?;
        let blocked_networks = parse_networks(&policy.blocked_networks, "blocked_networks")?;

        validate_dns_controls(&policy.dns)?;
        let max_concurrent_connections = resolve_max_connections(policy.max_connections)?;

        Ok(Self {
            default_action: policy.default_action,
            allow_dns: policy.allow_dns,
            allowed_domains,
            blocked_domains,
            allowed_networks,
            blocked_networks,
            allowed_ports: policy.allowed_ports.clone(),
            max_concurrent_connections,
            dns: policy.dns.clone(),
        })
    }

    #[must_use]
    pub fn max_concurrent_connections(&self) -> u32 {
        self.max_concurrent_connections
    }

    /// Whether DNS resolution is exposed at all. When `false`, the supervisor
    /// binds no DNS broker and installs no nftables DNS accept rule.
    #[must_use]
    pub fn allow_dns(&self) -> bool {
        self.allow_dns
    }

    /// The compiled DNS controls (TTL cap, structural limits, QTYPE
    /// allowlist, response cap, exfiltration budget).
    #[must_use]
    pub fn dns_policy(&self) -> &DnsPolicy {
        &self.dns
    }

    #[must_use]
    pub fn max_dns_ttl_secs(&self) -> u32 {
        self.dns.max_ttl_secs
    }

    #[must_use]
    pub fn cap_ttl(&self, ttl_secs: u32) -> u32 {
        ttl_secs.min(self.dns.max_ttl_secs)
    }

    /// Evaluates a domain name in isolation (used by the DNS broker to
    /// validate every CNAME hop and the final owner name before any address
    /// is considered).
    pub fn evaluate_domain_name(&self, name: &str) -> Result<bool, DomainError> {
        let normalized = domain::normalize_domain(name)?;
        Ok(self.evaluate_domain(&normalized).allowed)
    }

    fn evaluate_domain(&self, normalized: &str) -> DomainDecision {
        if let Some(pattern) = self
            .blocked_domains
            .iter()
            .find(|p| domain::pattern_matches(p, normalized))
        {
            return DomainDecision {
                allowed: false,
                reason: format!("domain '{normalized}' matches blocked pattern '{pattern}'"),
            };
        }
        if let Some(pattern) = self
            .allowed_domains
            .iter()
            .find(|p| domain::pattern_matches(p, normalized))
        {
            return DomainDecision {
                allowed: true,
                reason: format!("domain '{normalized}' matches allowed pattern '{pattern}'"),
            };
        }
        match self.default_action {
            Action::Allow => DomainDecision {
                allowed: true,
                reason: format!("domain '{normalized}' allowed by default action"),
            },
            Action::Deny => DomainDecision {
                allowed: false,
                reason: format!("domain '{normalized}' denied by default action"),
            },
        }
    }

    fn network_blocked(&self, ip: IpAddr) -> bool {
        self.blocked_networks.iter().any(|net| net.contains(&ip))
    }

    fn network_allowed(&self, ip: IpAddr) -> bool {
        self.allowed_networks.iter().any(|net| net.contains(&ip))
    }

    fn port_allowed(&self, protocol: Protocol, port: u16) -> bool {
        self.allowed_ports.is_empty()
            || self
                .allowed_ports
                .iter()
                .any(|rule| rule.protocol == protocol && rule.port == port)
    }

    /// Public, port-independent address-class/network check. Used by the DNS
    /// broker to validate every resolved address before authorizing it,
    /// before any port/protocol is known. Returns a decision computed
    /// against the canonicalized address (see [`crate::address::canonicalize`]).
    #[must_use]
    pub fn address_permitted(&self, ip: IpAddr) -> Decision {
        match self.check_address(ip) {
            Ok((canonical, class)) => {
                Decision::allow(format!("ip '{canonical}' is not restricted"), class)
            }
            Err(decision) => decision,
        }
    }

    /// Mandatory address-class and explicit-network check shared by both
    /// hostname and direct-IP evaluation. Independent of any domain
    /// decision, so a domain grant can never unlock a restricted class.
    ///
    /// `ip` is canonicalized first (collapsing an IPv4-mapped IPv6 literal
    /// to its plain IPv4 form) so CIDR containment checks, the unspecified
    /// hard-block below, and the returned [`AddressClass`] are all computed
    /// against a single stable representation of the address.
    fn check_address(&self, ip: IpAddr) -> Result<(IpAddr, AddressClass), Decision> {
        let ip = crate::address::canonicalize(ip);
        let class = classify(ip);
        if class == AddressClass::Unspecified {
            return Err(Decision::deny(
                format!(
                    "ip '{ip}' is the unspecified address and can never be a valid destination"
                ),
                class,
            ));
        }
        if self.network_blocked(ip) {
            return Err(Decision::deny(
                format!("ip '{ip}' matches an explicit blocked network"),
                class,
            ));
        }
        if class.is_restricted() && !self.network_allowed(ip) {
            return Err(Decision::deny(
                format!(
                    "ip '{ip}' is address class {class:?}, which requires an explicit allowed network grant"
                ),
                class,
            ));
        }
        Ok((ip, class))
    }

    /// Decision for a hostname-driven connection: the resolved `ip` must
    /// clear address-class/network checks unconditionally, then the
    /// `name`'s domain policy governs remaining reachability.
    #[must_use]
    pub fn decide_hostname(
        &self,
        name: &str,
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
    ) -> Decision {
        let (_ip, class) = match self.check_address(ip) {
            Ok(result) => result,
            Err(decision) => return decision,
        };
        if !self.port_allowed(protocol, port) {
            return Decision::deny(
                format!("port {port}/{protocol:?} is not permitted by policy"),
                class,
            );
        }
        let normalized = match domain::normalize_domain(name) {
            Ok(normalized) => normalized,
            Err(err) => return Decision::deny(format!("domain name invalid: {err}"), class),
        };
        let domain_decision = self.evaluate_domain(&normalized);
        if domain_decision.allowed {
            Decision::allow(domain_decision.reason, class)
        } else {
            Decision::deny(domain_decision.reason, class)
        }
    }

    /// Decision for a direct-IP connection. Domain rules never apply;
    /// reachability is governed solely by network/address-class policy.
    #[must_use]
    pub fn decide_direct_ip(&self, ip: IpAddr, port: u16, protocol: Protocol) -> Decision {
        let (ip, class) = match self.check_address(ip) {
            Ok(result) => result,
            Err(decision) => return decision,
        };
        if !self.port_allowed(protocol, port) {
            return Decision::deny(
                format!("port {port}/{protocol:?} is not permitted by policy"),
                class,
            );
        }
        if self.network_allowed(ip) {
            return Decision::allow(
                format!("ip '{ip}' matches an explicit allowed network"),
                class,
            );
        }
        match self.default_action {
            Action::Allow => Decision::allow(format!("ip '{ip}' allowed by default action"), class),
            Action::Deny => Decision::deny(format!("ip '{ip}' denied by default action"), class),
        }
    }
}

fn normalize_patterns(raw: &[String], field: &'static str) -> Result<Vec<String>, PolicyError> {
    raw.iter()
        .map(|p| {
            domain::normalize_pattern(p)
                .map_err(|source| PolicyError::InvalidDomainPattern { field, source })
        })
        .collect()
}

fn parse_networks(raw: &[String], field: &'static str) -> Result<Vec<IpNet>, PolicyError> {
    raw.iter()
        .map(|literal| {
            parse_ip_or_cidr(literal).ok_or_else(|| PolicyError::InvalidNetworkLiteral {
                field,
                value: literal.clone(),
                message: "expected an IPv4/IPv6 address or CIDR".to_owned(),
            })
        })
        .collect()
}

fn parse_ip_or_cidr(literal: &str) -> Option<IpNet> {
    if let Ok(net) = literal.parse::<IpNet>() {
        return Some(net);
    }
    literal.parse::<IpAddr>().ok().map(IpNet::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sendbox_policy::DnsPolicy;
    use std::net::Ipv4Addr;

    fn policy(default_action: Action) -> NetworkPolicy {
        NetworkPolicy {
            default_action,
            allowed_domains: vec!["example.com".to_owned(), "*.trusted.example".to_owned()],
            blocked_domains: vec!["evil.example.com".to_owned()],
            allow_dns: true,
            max_connections: Some(4),
            allowed_networks: vec!["93.184.216.34/32".to_owned()],
            blocked_networks: vec!["203.0.113.0/24".to_owned()],
            allowed_ports: vec![PortRule {
                protocol: Protocol::Tcp,
                port: 443,
            }],
            dns: DnsPolicy {
                max_ttl_secs: 60,
                ..DnsPolicy::default()
            },
        }
    }

    #[test]
    fn max_connections_mapping_is_bounded_and_fails_closed() {
        assert_eq!(
            resolve_max_connections(None).unwrap(),
            DEFAULT_MAX_CONNECTIONS
        );
        assert_eq!(resolve_max_connections(Some(8)).unwrap(), 8);
        assert_eq!(
            resolve_max_connections(Some(i64::from(MAX_CONNECTIONS_CEILING))).unwrap(),
            MAX_CONNECTIONS_CEILING
        );
        assert!(matches!(
            resolve_max_connections(Some(0)),
            Err(PolicyError::NonPositiveMaxConnections)
        ));
        assert!(matches!(
            resolve_max_connections(Some(-5)),
            Err(PolicyError::NonPositiveMaxConnections)
        ));
        assert!(matches!(
            resolve_max_connections(Some(i64::from(MAX_CONNECTIONS_CEILING) + 1)),
            Err(PolicyError::MaxConnectionsTooLarge { .. })
        ));
        assert!(matches!(
            resolve_max_connections(Some(i64::MAX)),
            Err(PolicyError::MaxConnectionsTooLarge { .. })
        ));
    }

    #[test]
    fn compile_rejects_non_positive_and_oversized_max_connections() {
        let mut zero = policy(Action::Allow);
        zero.max_connections = Some(0);
        assert!(matches!(
            PolicyEngine::compile(&zero),
            Err(PolicyError::NonPositiveMaxConnections)
        ));
        let mut huge = policy(Action::Allow);
        huge.max_connections = Some(i64::from(MAX_CONNECTIONS_CEILING) + 1);
        assert!(matches!(
            PolicyEngine::compile(&huge),
            Err(PolicyError::MaxConnectionsTooLarge { .. })
        ));
    }

    #[test]
    fn default_deny_blocks_unmatched_domain() {
        let engine = PolicyEngine::compile(&policy(Action::Deny)).unwrap();
        let decision = engine.decide_hostname(
            "unknown.example",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        assert!(!decision.allowed);
    }

    #[test]
    fn default_allow_permits_unmatched_domain_with_global_ip() {
        let engine = PolicyEngine::compile(&policy(Action::Allow)).unwrap();
        let decision = engine.decide_hostname(
            "unknown.example",
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            Protocol::Tcp,
        );
        assert!(decision.allowed);
    }

    #[test]
    fn exact_allowed_domain_permits() {
        let engine = PolicyEngine::compile(&policy(Action::Deny)).unwrap();
        let decision = engine.decide_hostname(
            "example.com",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        assert!(decision.allowed);
    }

    #[test]
    fn wildcard_allowed_domain_matches_subdomain_only() {
        let engine = PolicyEngine::compile(&policy(Action::Deny)).unwrap();
        let sub = engine.decide_hostname(
            "api.trusted.example",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        assert!(sub.allowed);
        let apex = engine.decide_hostname(
            "trusted.example",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        assert!(!apex.allowed);
    }

    #[test]
    fn blocked_domain_takes_precedence_over_allow() {
        let mut raw = policy(Action::Allow);
        raw.allowed_domains.push("evil.example.com".to_owned());
        let engine = PolicyEngine::compile(&raw).unwrap();
        let decision = engine.decide_hostname(
            "evil.example.com",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        assert!(!decision.allowed);
    }

    #[test]
    fn blocked_network_takes_precedence_over_allowed_domain() {
        let engine = PolicyEngine::compile(&policy(Action::Deny)).unwrap();
        let decision = engine.decide_hostname(
            "example.com",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            443,
            Protocol::Tcp,
        );
        assert!(!decision.allowed);
    }

    #[test]
    fn domain_allow_never_unlocks_restricted_address_class() {
        let engine = PolicyEngine::compile(&policy(Action::Deny)).unwrap();
        for ip in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        ] {
            let decision = engine.decide_hostname("example.com", ip, 443, Protocol::Tcp);
            assert!(
                !decision.allowed,
                "expected {ip} denied despite domain allow"
            );
        }
    }

    #[test]
    fn explicit_network_grant_unlocks_restricted_class() {
        let mut raw = policy(Action::Deny);
        raw.allowed_networks.push("127.0.0.1/32".to_owned());
        let engine = PolicyEngine::compile(&raw).unwrap();
        let decision = engine.decide_hostname(
            "example.com",
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            443,
            Protocol::Tcp,
        );
        assert!(decision.allowed);
    }

    #[test]
    fn direct_ip_never_consults_domain_rules() {
        let engine = PolicyEngine::compile(&policy(Action::Deny)).unwrap();
        let decision =
            engine.decide_direct_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443, Protocol::Tcp);
        assert!(!decision.allowed);

        let granted = engine.decide_direct_ip(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        assert!(granted.allowed);
    }

    #[test]
    fn direct_ip_restricted_class_requires_explicit_grant() {
        let engine = PolicyEngine::compile(&policy(Action::Allow)).unwrap();
        let decision = engine.decide_direct_ip(
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            443,
            Protocol::Tcp,
        );
        assert!(!decision.allowed);
    }

    #[test]
    fn port_constraint_enforced() {
        let engine = PolicyEngine::compile(&policy(Action::Allow)).unwrap();
        let decision = engine.decide_hostname(
            "example.com",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            8080,
            Protocol::Tcp,
        );
        assert!(!decision.allowed);
    }

    #[test]
    fn ttl_is_capped() {
        let engine = PolicyEngine::compile(&policy(Action::Allow)).unwrap();
        assert_eq!(engine.cap_ttl(3600), 60);
        assert_eq!(engine.cap_ttl(10), 10);
    }

    #[test]
    fn decision_json_is_deterministic() {
        let engine = PolicyEngine::compile(&policy(Action::Deny)).unwrap();
        let decision = engine.decide_hostname(
            "example.com",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
        );
        let json = decision.to_json();
        assert!(json.starts_with("{\"allowed\":true,\"reason\":"));
    }

    #[test]
    fn compile_rejects_invalid_network_literal() {
        let mut raw = policy(Action::Allow);
        raw.allowed_networks.push("not-an-ip".to_owned());
        assert!(matches!(
            PolicyEngine::compile(&raw),
            Err(PolicyError::InvalidNetworkLiteral { .. })
        ));
    }

    #[test]
    fn compile_rejects_invalid_dns_controls() {
        let mut ttl = policy(Action::Allow);
        ttl.dns.max_ttl_secs = 0;
        assert!(matches!(
            PolicyEngine::compile(&ttl),
            Err(PolicyError::InvalidDnsControl {
                field: "max_ttl_secs",
                ..
            })
        ));

        let mut window = policy(Action::Allow);
        window.dns.budget.window_secs = 0;
        assert!(matches!(
            PolicyEngine::compile(&window),
            Err(PolicyError::InvalidDnsControl {
                field: "budget.window_secs",
                ..
            })
        ));

        let mut qname = policy(Action::Allow);
        qname.dns.max_qname_octets = 300;
        assert!(matches!(
            PolicyEngine::compile(&qname),
            Err(PolicyError::InvalidDnsControl {
                field: "max_qname_octets",
                ..
            })
        ));

        let mut empty_qtypes = policy(Action::Allow);
        empty_qtypes.dns.allowed_record_types = vec![];
        assert!(matches!(
            PolicyEngine::compile(&empty_qtypes),
            Err(PolicyError::InvalidDnsControl {
                field: "allowed_record_types",
                ..
            })
        ));

        let mut budget = policy(Action::Allow);
        budget.dns.budget.max_dynamic_labels = 0;
        assert!(matches!(
            PolicyEngine::compile(&budget),
            Err(PolicyError::InvalidDnsControl {
                field: "budget.max_dynamic_labels",
                ..
            })
        ));
    }

    #[test]
    fn unspecified_address_is_always_denied_even_with_default_allow() {
        let engine = PolicyEngine::compile(&policy(Action::Allow)).unwrap();
        let v4 = engine.decide_direct_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443, Protocol::Tcp);
        assert!(!v4.allowed);
        let v6 = engine.decide_direct_ip(
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            443,
            Protocol::Tcp,
        );
        assert!(!v6.allowed);
    }

    #[test]
    fn unspecified_address_is_denied_even_with_a_covering_explicit_grant() {
        let mut raw = policy(Action::Deny);
        raw.allowed_networks.push("0.0.0.0/0".to_owned());
        let engine = PolicyEngine::compile(&raw).unwrap();
        let decision =
            engine.decide_direct_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443, Protocol::Tcp);
        assert!(!decision.allowed);
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_bypass_a_blocked_ipv4_cidr() {
        let engine = PolicyEngine::compile(&policy(Action::Allow)).unwrap();
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped());
        let decision = engine.decide_direct_ip(mapped, 443, Protocol::Tcp);
        assert!(
            !decision.allowed,
            "v4-mapped-v6 encoding must not bypass a blocked IPv4 CIDR"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_benefits_from_an_allowed_ipv4_cidr_grant() {
        let engine = PolicyEngine::compile(&policy(Action::Deny)).unwrap();
        let mapped = IpAddr::V6(Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped());
        let decision = engine.decide_direct_ip(mapped, 443, Protocol::Tcp);
        assert!(
            decision.allowed,
            "v4-mapped-v6 encoding of an explicitly allowed IPv4 must still be allowed"
        );
    }

    #[test]
    fn allow_dns_flag_is_carried_from_policy() {
        let mut raw = policy(Action::Deny);
        raw.allow_dns = false;
        let engine = PolicyEngine::compile(&raw).unwrap();
        assert!(!engine.allow_dns());
    }
}
