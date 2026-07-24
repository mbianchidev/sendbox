use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use sendbox_egress::address::{AddressClass, canonicalize, classify};
use sendbox_secrets::{CredentialPolicy, SecretName};

use crate::CredentialBrokerError;

const MAX_RULES: usize = 128;
const MAX_CONNECTIONS: usize = 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_COUNT: usize = 256;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_REDIRECTS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerBind {
    LoopbackV4 { port: u16 },
    LoopbackV6 { port: u16 },
    Explicit(SocketAddr),
}

impl Default for BrokerBind {
    fn default() -> Self {
        Self::LoopbackV4 { port: 0 }
    }
}

impl BrokerBind {
    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        match self {
            Self::LoopbackV4 { port } => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            Self::LoopbackV6 { port } => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
            Self::Explicit(address) => address,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrokerLimits {
    pub max_request_line_bytes: usize,
    pub max_header_bytes: usize,
    pub max_header_count: usize,
    pub max_connections: usize,
    pub request_read_timeout: Duration,
    pub upstream_connect_timeout: Duration,
    pub upstream_read_timeout: Duration,
    pub upstream_total_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub max_redirects: usize,
}

impl Default for BrokerLimits {
    fn default() -> Self {
        Self {
            max_request_line_bytes: 8 * 1024,
            max_header_bytes: 32 * 1024,
            max_header_count: 64,
            max_connections: 64,
            request_read_timeout: Duration::from_secs(10),
            upstream_connect_timeout: Duration::from_secs(5),
            upstream_read_timeout: Duration::from_secs(15),
            upstream_total_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(5),
            max_redirects: 5,
        }
    }
}

impl BrokerLimits {
    pub(crate) fn validate(&self) -> Result<(), CredentialBrokerError> {
        if self.max_request_line_bytes == 0
            || self.max_request_line_bytes > MAX_REQUEST_LINE_BYTES
            || self.max_header_bytes == 0
            || self.max_header_bytes > MAX_HEADER_BYTES
            || self.max_header_count == 0
            || self.max_header_count > MAX_HEADER_COUNT
            || self.max_connections == 0
            || self.max_connections > MAX_CONNECTIONS
            || self.request_read_timeout.is_zero()
            || self.upstream_connect_timeout.is_zero()
            || self.upstream_read_timeout.is_zero()
            || self.upstream_total_timeout.is_zero()
            || self.shutdown_timeout.is_zero()
            || self.max_redirects > MAX_REDIRECTS
        {
            return Err(CredentialBrokerError::InvalidConfiguration(
                "one or more broker limits are zero or exceed the hard maximum".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct UpstreamAddressPolicy {
    allowed_restricted_addresses: BTreeSet<IpAddr>,
}

impl UpstreamAddressPolicy {
    #[must_use]
    pub fn allowing_restricted(
        addresses: impl IntoIterator<Item = IpAddr>,
    ) -> UpstreamAddressPolicy {
        Self {
            allowed_restricted_addresses: addresses.into_iter().map(canonicalize).collect(),
        }
    }

    pub(crate) fn authorize(&self, address: IpAddr) -> Result<IpAddr, CredentialBrokerError> {
        let address = canonicalize(address);
        let class = classify(address);
        if class == AddressClass::Unspecified
            || class.is_restricted() && !self.allowed_restricted_addresses.contains(&address)
        {
            return Err(CredentialBrokerError::Upstream(format!(
                "resolved address class {class:?} is not approved"
            )));
        }
        Ok(address)
    }
}

#[derive(Debug, Clone)]
pub struct CredentialRule {
    id: String,
    secret_name: SecretName,
    policy: CredentialPolicy,
}

impl CredentialRule {
    pub fn new(
        id: impl Into<String>,
        secret_name: SecretName,
        policy: CredentialPolicy,
    ) -> Result<Self, CredentialBrokerError> {
        let id = id.into();
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CredentialBrokerError::InvalidConfiguration(
                "credential rule IDs must use 1-64 ASCII letters, digits, '-' or '_'".to_owned(),
            ));
        }
        Ok(Self {
            id,
            secret_name,
            policy,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn secret_name(&self) -> &SecretName {
        &self.secret_name
    }

    #[must_use]
    pub fn policy(&self) -> &CredentialPolicy {
        &self.policy
    }

    #[must_use]
    pub(crate) fn route_prefix(&self) -> String {
        format!("/credentials/{}", self.id)
    }
}

#[derive(Debug, Clone)]
pub struct BrokerConfiguration {
    pub bind: BrokerBind,
    pub limits: BrokerLimits,
    pub address_policy: UpstreamAddressPolicy,
    pub rules: Vec<CredentialRule>,
}

impl BrokerConfiguration {
    pub(crate) fn validate(&self) -> Result<(), CredentialBrokerError> {
        self.limits.validate()?;
        if let BrokerBind::Explicit(address) = self.bind
            && (address.ip().is_unspecified() || address.ip().is_multicast())
        {
            return Err(CredentialBrokerError::InvalidConfiguration(
                "explicit broker bind addresses cannot be wildcard or multicast addresses"
                    .to_owned(),
            ));
        }
        if self.rules.is_empty() || self.rules.len() > MAX_RULES {
            return Err(CredentialBrokerError::InvalidConfiguration(format!(
                "credential broker requires 1-{MAX_RULES} rules"
            )));
        }
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            if !ids.insert(rule.id()) {
                return Err(CredentialBrokerError::InvalidConfiguration(format!(
                    "credential rule ID `{}` is duplicated",
                    rule.id()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use http::Method;
    use sendbox_secrets::{CredentialInjection, CredentialPolicy, RedirectPolicy};

    use super::*;

    fn rule() -> CredentialRule {
        let name = SecretName::new("TOKEN").expect("name");
        let policy = CredentialPolicy::new(
            "api.example.com",
            "/v1/",
            CredentialInjection::Bearer,
            [Method::GET],
            0,
            1024,
            RedirectPolicy::Deny,
            name.clone(),
        )
        .expect("policy");
        CredentialRule::new("api", name, policy).expect("rule")
    }

    #[test]
    fn wildcard_explicit_bind_is_rejected() {
        let configuration = BrokerConfiguration {
            bind: BrokerBind::Explicit(SocketAddr::from(([0, 0, 0, 0], 0))),
            limits: BrokerLimits::default(),
            address_policy: UpstreamAddressPolicy::default(),
            rules: vec![rule()],
        };
        assert!(configuration.validate().is_err());
    }
}
