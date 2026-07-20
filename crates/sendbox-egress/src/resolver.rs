//! Injectable upstream DNS resolution used by the DNS broker.
//!
//! The broker performs real DNS message decode/encode via `hickory-proto` and
//! delegates the actual name→address lookup to an [`UpstreamResolver`]. The
//! production implementation is
//! [`crate::forwarding_resolver::ForwardingResolver`]; tests and the local
//! harness use [`crate::fixture_resolver::StaticResolver`].

use std::net::IpAddr;

use async_trait::async_trait;
use hickory_proto::rr::Name;
use thiserror::Error;

/// A resolved address with its authoritative TTL, prior to any policy TTL
/// cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedAddress {
    pub ip: IpAddr,
    pub ttl_secs: u32,
}

/// The full result of resolving a name: every intermediate CNAME hop (in
/// query order, excluding the original queried name and the final owner
/// name), the final canonical owner name, and every address record returned
/// for that final name.
#[derive(Debug, Clone)]
pub struct ResolvedChain {
    pub cname_chain: Vec<Name>,
    pub final_name: Name,
    pub addresses: Vec<ResolvedAddress>,
}

impl ResolvedChain {
    /// Every domain name that must be validated against policy: each CNAME
    /// hop plus the final owner name. The originally queried name is
    /// validated separately by the caller since it is known before
    /// resolution begins.
    pub fn names_to_validate(&self) -> impl Iterator<Item = &Name> {
        self.cname_chain
            .iter()
            .chain(std::iter::once(&self.final_name))
    }
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("name '{0}' does not exist")]
    NxDomain(Name),
    #[error("upstream resolution failed: {0}")]
    Upstream(String),
    #[error("resolution exceeded the configured timeout")]
    Timeout,
}

/// Injectable upstream resolver. Implementations may be a real forwarding DNS
/// client, a static fixture map, or a test double that simulates rebinding.
#[async_trait]
pub trait UpstreamResolver: Send + Sync {
    async fn resolve(&self, name: &Name) -> Result<ResolvedChain, ResolveError>;
}
