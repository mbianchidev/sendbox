//! JSON file loaders used by the standalone `dns-broker` and
//! `egress-broker` binaries so the spike is runnable locally without a real
//! upstream DNS server: a policy file and a fixture resolution map.

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use hickory_proto::rr::Name;
use serde::Deserialize;
use thiserror::Error;

use crate::fixture_resolver::StaticResolver;
use crate::policy::NetworkPolicy;
use crate::resolver::{ResolvedAddress, ResolvedChain};

#[derive(Debug, Deserialize)]
struct FixtureAddress {
    ip: String,
    ttl_secs: u32,
}

#[derive(Debug, Deserialize)]
struct FixtureEntry {
    #[serde(default)]
    cname_chain: Vec<String>,
    final_name: String,
    addresses: Vec<FixtureAddress>,
}

#[derive(Debug, Error)]
pub enum FixtureLoadError {
    #[error("failed to read fixture file '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse fixture file '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("fixture entry '{name}' has an invalid domain name: {source}")]
    InvalidName {
        name: String,
        #[source]
        source: hickory_proto::ProtoError,
    },
    #[error("fixture entry '{name}' has an invalid IP address literal '{value}'")]
    InvalidAddress { name: String, value: String },
}

/// Loads a JSON map of `{ "queried.name.": { "cname_chain": [...], "final_name": "...", "addresses": [{"ip": "...", "ttl_secs": N}] } }`
/// into a runnable [`StaticResolver`].
pub fn load_fixtures(path: &Path) -> Result<Arc<StaticResolver>, FixtureLoadError> {
    let path_str = path.to_string_lossy().into_owned();
    let raw = std::fs::read_to_string(path).map_err(|source| FixtureLoadError::Read {
        path: path_str.clone(),
        source,
    })?;
    let entries: HashMap<String, FixtureEntry> =
        serde_json::from_str(&raw).map_err(|source| FixtureLoadError::Parse {
            path: path_str.clone(),
            source,
        })?;

    let resolver = StaticResolver::new();
    for (queried, entry) in entries {
        let name = Name::from_str(&queried).map_err(|source| FixtureLoadError::InvalidName {
            name: queried.clone(),
            source,
        })?;
        let final_name =
            Name::from_str(&entry.final_name).map_err(|source| FixtureLoadError::InvalidName {
                name: entry.final_name.clone(),
                source,
            })?;
        let mut cname_chain = Vec::with_capacity(entry.cname_chain.len());
        for hop in &entry.cname_chain {
            cname_chain.push(Name::from_str(hop).map_err(|source| {
                FixtureLoadError::InvalidName {
                    name: hop.clone(),
                    source,
                }
            })?);
        }
        let mut addresses = Vec::with_capacity(entry.addresses.len());
        for addr in &entry.addresses {
            let ip = addr
                .ip
                .parse()
                .map_err(|_| FixtureLoadError::InvalidAddress {
                    name: queried.clone(),
                    value: addr.ip.clone(),
                })?;
            addresses.push(ResolvedAddress {
                ip,
                ttl_secs: addr.ttl_secs,
            });
        }
        resolver.set(
            name,
            ResolvedChain {
                cname_chain,
                final_name,
                addresses,
            },
        );
    }
    Ok(Arc::new(resolver))
}

#[derive(Debug, Error)]
pub enum PolicyLoadError {
    #[error("failed to read policy file '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse policy file '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

pub fn load_policy(path: &Path) -> Result<NetworkPolicy, PolicyLoadError> {
    let path_str = path.to_string_lossy().into_owned();
    let raw = std::fs::read_to_string(path).map_err(|source| PolicyLoadError::Read {
        path: path_str.clone(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| PolicyLoadError::Parse {
        path: path_str,
        source,
    })
}
