//! Deterministic, injectable resolver fixture used by tests and by the
//! standalone `dns-broker` binary for runnable local behavior without
//! depending on a live upstream DNS server.

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use hickory_proto::rr::Name;

use crate::resolver::{ResolveError, ResolvedChain, UpstreamResolver};

/// A resolver backed by an in-memory map that can be mutated at runtime,
/// which is what makes it possible to simulate DNS rebinding: the same name
/// resolves to a different chain/address on a later lookup.
#[derive(Default)]
pub struct StaticResolver {
    entries: RwLock<HashMap<Name, ResolvedChain>>,
}

impl StaticResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs (or replaces) the resolution result for `name`.
    pub fn set(&self, name: Name, chain: ResolvedChain) {
        self.entries
            .write()
            .expect("fixture resolver lock poisoned")
            .insert(name, chain);
    }
}

#[async_trait]
impl UpstreamResolver for StaticResolver {
    async fn resolve(&self, name: &Name) -> Result<ResolvedChain, ResolveError> {
        self.entries
            .read()
            .expect("fixture resolver lock poisoned")
            .get(name)
            .cloned()
            .ok_or_else(|| ResolveError::NxDomain(name.clone()))
    }
}
