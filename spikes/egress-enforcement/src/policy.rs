//! Typed, canonical network egress policy with deterministic decisions and
//! JSON diagnostics.
//!
//! Precedence rules, in order:
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
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::address::{AddressClass, classify};
use crate::domain::{self, DomainError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRule {
    pub protocol: Protocol,
    pub port: u16,
}

/// Raw, serializable policy configuration (e.g. loaded from JSON on disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub default_action: Action,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    /// Exact IP or CIDR literals (v4 or v6), e.g. "93.184.216.34/32" or
    /// "2001:db8::/32". This is the only mechanism that can authorize a
    /// restricted address class.
    #[serde(default)]
    pub allowed_networks: Vec<String>,
    #[serde(default)]
    pub blocked_networks: Vec<String>,
    #[serde(default)]
    pub allowed_ports: Vec<PortRule>,
    pub max_concurrent_connections: u32,
    /// Upper bound applied to every DNS TTL before it is used to compute an
    /// authorization expiry.
    pub max_dns_ttl_secs: u32,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy.{field}: {source}")]
    InvalidDomainPattern {
        field: &'static str,
        #[source]
        source: DomainError,
    },
    #[error("policy.{field}: invalid IP/CIDR literal '{value}': {message}")]
    InvalidNetworkLiteral {
        field: &'static str,
        value: String,
        message: String,
    },
    #[error("policy.max_concurrent_connections must be greater than zero")]
    ZeroConcurrentConnections,
    #[error("policy.max_dns_ttl_secs must be greater than zero")]
    ZeroDnsTtl,
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
    allowed_domains: Vec<String>,
    blocked_domains: Vec<String>,
    allowed_networks: Vec<IpNet>,
    blocked_networks: Vec<IpNet>,
    allowed_ports: Vec<PortRule>,
    max_concurrent_connections: u32,
    max_dns_ttl_secs: u32,
}

impl PolicyEngine {
    pub fn compile(policy: &NetworkPolicy) -> Result<Self, PolicyError> {
        let allowed_domains = normalize_patterns(&policy.allowed_domains, "allowed_domains")?;
        let blocked_domains = normalize_patterns(&policy.blocked_domains, "blocked_domains")?;
        let allowed_networks = parse_networks(&policy.allowed_networks, "allowed_networks")?;
        let blocked_networks = parse_networks(&policy.blocked_networks, "blocked_networks")?;

        if policy.max_concurrent_connections == 0 {
            return Err(PolicyError::ZeroConcurrentConnections);
        }
        if policy.max_dns_ttl_secs == 0 {
            return Err(PolicyError::ZeroDnsTtl);
        }

        Ok(Self {
            default_action: policy.default_action,
            allowed_domains,
            blocked_domains,
            allowed_networks,
            blocked_networks,
            allowed_ports: policy.allowed_ports.clone(),
            max_concurrent_connections: policy.max_concurrent_connections,
            max_dns_ttl_secs: policy.max_dns_ttl_secs,
        })
    }

    pub fn max_concurrent_connections(&self) -> u32 {
        self.max_concurrent_connections
    }

    pub fn max_dns_ttl_secs(&self) -> u32 {
        self.max_dns_ttl_secs
    }

    pub fn cap_ttl(&self, ttl_secs: u32) -> u32 {
        ttl_secs.min(self.max_dns_ttl_secs)
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
    /// against a single stable representation of the address — an attacker
    /// cannot bypass a blocked IPv4 CIDR, or fail to benefit from an
    /// allowed one, purely by re-encoding the same address as IPv6.
    fn check_address(&self, ip: IpAddr) -> Result<(IpAddr, AddressClass), Decision> {
        let ip = crate::address::canonicalize(ip);
        let class = classify(ip);
        // The unspecified address (0.0.0.0 / ::) is never a valid dial
        // destination: it is a wildcard/bind-only address, and on Linux,
        // connecting to it is treated as a request for the local host. It
        // is hard-rejected unconditionally rather than merely "restricted",
        // since no explicit IP/CIDR grant could ever make dialing it mean
        // what the policy author intended.
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
    use std::net::Ipv4Addr;

    fn policy(default_action: Action) -> NetworkPolicy {
        NetworkPolicy {
            default_action,
            allowed_domains: vec!["example.com".to_owned(), "*.trusted.example".to_owned()],
            blocked_domains: vec!["evil.example.com".to_owned()],
            allowed_networks: vec!["93.184.216.34/32".to_owned()],
            blocked_networks: vec!["203.0.113.0/24".to_owned()],
            allowed_ports: vec![PortRule {
                protocol: Protocol::Tcp,
                port: 443,
            }],
            max_concurrent_connections: 4,
            max_dns_ttl_secs: 60,
        }
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
        // Global IP not covered by any network rule and default_action is
        // Deny: direct-IP must deny even though `allowed_domains` would
        // otherwise permit `example.com`.
        let decision =
            engine.decide_direct_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443, Protocol::Tcp);
        assert!(!decision.allowed);

        let allow_engine = PolicyEngine::compile(&policy(Action::Deny)).unwrap();
        let granted = allow_engine.decide_direct_ip(
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
    fn compile_rejects_zero_limits() {
        let mut raw = policy(Action::Allow);
        raw.max_concurrent_connections = 0;
        assert!(matches!(
            PolicyEngine::compile(&raw),
            Err(PolicyError::ZeroConcurrentConnections)
        ));

        let mut raw2 = policy(Action::Allow);
        raw2.max_dns_ttl_secs = 0;
        assert!(matches!(
            PolicyEngine::compile(&raw2),
            Err(PolicyError::ZeroDnsTtl)
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
        // 0.0.0.0/0 would technically "contain" the unspecified address in
        // CIDR arithmetic; the unspecified hard-block must still win.
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
        // policy() blocks 203.0.113.0/24; encode an address in that range as
        // an IPv4-mapped IPv6 literal and confirm it is still denied.
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
        // policy() explicitly allows 93.184.216.34/32; the same address
        // encoded as IPv4-mapped IPv6 must be recognized as identical.
        let mapped = IpAddr::V6(Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped());
        let decision = engine.decide_direct_ip(mapped, 443, Protocol::Tcp);
        assert!(
            decision.allowed,
            "v4-mapped-v6 encoding of an explicitly allowed IPv4 must still be allowed"
        );
    }
}
