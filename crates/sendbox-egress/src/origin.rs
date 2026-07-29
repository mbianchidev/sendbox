use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::RwLock;

use sendbox_policy::McpHttpOrigin;
use thiserror::Error;

use crate::address::canonicalize;
use crate::domain;

const MAX_OBSERVED_NAMES_PER_ORIGIN: usize = 64;
const MAX_OBSERVED_ADDRESSES_PER_ORIGIN: usize = 256;

#[derive(Debug, Error)]
pub enum OriginReservationError {
    #[error("invalid reserved MCP origin host '{0}'")]
    InvalidHost(String),
    #[error("reserved MCP origin port must be non-zero")]
    InvalidPort,
    #[error("reserved MCP origin state is unavailable")]
    Poisoned,
    #[error("reserved MCP origin state exceeded its configured bound")]
    CapacityExceeded,
}

#[derive(Debug, Default)]
struct ReservationState {
    names: BTreeSet<(String, u16)>,
    addresses: BTreeSet<(IpAddr, u16)>,
}

#[derive(Debug)]
pub struct OriginReservations {
    remote_mcp_active: bool,
    max_names: usize,
    max_addresses: usize,
    state: RwLock<ReservationState>,
}

impl Default for OriginReservations {
    fn default() -> Self {
        Self {
            remote_mcp_active: false,
            max_names: 0,
            max_addresses: 0,
            state: RwLock::new(ReservationState::default()),
        }
    }
}

impl OriginReservations {
    pub fn new(origins: &[McpHttpOrigin]) -> Result<Self, OriginReservationError> {
        let max_names = origins
            .len()
            .checked_mul(MAX_OBSERVED_NAMES_PER_ORIGIN + 1)
            .ok_or(OriginReservationError::CapacityExceeded)?;
        let max_addresses = origins
            .len()
            .checked_mul(MAX_OBSERVED_ADDRESSES_PER_ORIGIN)
            .ok_or(OriginReservationError::CapacityExceeded)?;
        let reservations = Self {
            remote_mcp_active: !origins.is_empty(),
            max_names,
            max_addresses,
            state: RwLock::new(ReservationState::default()),
        };
        for origin in origins {
            reservations.reserve_configured(&origin.host, origin.port)?;
        }
        Ok(reservations)
    }

    #[must_use]
    pub const fn remote_mcp_active(&self) -> bool {
        self.remote_mcp_active
    }

    pub fn reserve_resolution(
        &self,
        host: &str,
        port: u16,
        aliases: &[String],
        addresses: &[IpAddr],
    ) -> Result<(), OriginReservationError> {
        if port == 0 {
            return Err(OriginReservationError::InvalidPort);
        }
        let mut names = aliases
            .iter()
            .map(|alias| normalize_host(alias).map(|alias| (alias, port)))
            .collect::<Result<BTreeSet<_>, _>>()?;
        names.insert((normalize_host(host)?, port));
        let addresses = addresses
            .iter()
            .copied()
            .map(canonicalize)
            .map(|address| (address, port))
            .collect::<BTreeSet<_>>();
        let mut state = self
            .state
            .write()
            .map_err(|_| OriginReservationError::Poisoned)?;
        let new_names = names
            .iter()
            .filter(|name| !state.names.contains(*name))
            .count();
        let new_addresses = addresses
            .iter()
            .filter(|address| !state.addresses.contains(*address))
            .count();
        if state.names.len().saturating_add(new_names) > self.max_names
            || state.addresses.len().saturating_add(new_addresses) > self.max_addresses
        {
            return Err(OriginReservationError::CapacityExceeded);
        }
        state.names.extend(names);
        state.addresses.extend(addresses);
        Ok(())
    }

    pub fn denies_hostname(&self, host: &str, port: u16) -> Result<bool, OriginReservationError> {
        let host = normalize_host(host)?;
        let state = self
            .state
            .read()
            .map_err(|_| OriginReservationError::Poisoned)?;
        Ok(state.names.contains(&(host, port)))
    }

    pub fn denies_direct_ip(
        &self,
        address: IpAddr,
        port: u16,
    ) -> Result<bool, OriginReservationError> {
        if self.remote_mcp_active {
            return Ok(true);
        }
        let state = self
            .state
            .read()
            .map_err(|_| OriginReservationError::Poisoned)?;
        Ok(state.addresses.contains(&(canonicalize(address), port)))
    }

    fn reserve_configured(&self, host: &str, port: u16) -> Result<(), OriginReservationError> {
        if port == 0 {
            return Err(OriginReservationError::InvalidPort);
        }
        let host = normalize_host(host)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| OriginReservationError::Poisoned)?;
        if !state.names.contains(&(host.clone(), port)) && state.names.len() >= self.max_names {
            return Err(OriginReservationError::CapacityExceeded);
        }
        state.names.insert((host, port));
        Ok(())
    }
}

fn normalize_host(host: &str) -> Result<String, OriginReservationError> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(canonicalize(address).to_string());
    }
    domain::normalize_domain(host).map_err(|_| OriginReservationError::InvalidHost(host.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_names_aliases_and_direct_ips_fail_closed() {
        let reservations = OriginReservations::new(&[McpHttpOrigin {
            host: "api.example.com".to_owned(),
            port: 443,
        }])
        .unwrap();
        assert!(
            reservations
                .denies_hostname("API.EXAMPLE.COM.", 443)
                .unwrap()
        );
        assert!(
            reservations
                .denies_direct_ip("203.0.113.9".parse().unwrap(), 443)
                .unwrap()
        );

        reservations
            .reserve_resolution(
                "api.example.com",
                443,
                &["edge.example.net".to_owned()],
                &["203.0.113.9".parse().unwrap()],
            )
            .unwrap();
        assert!(
            reservations
                .denies_hostname("edge.example.net", 443)
                .unwrap()
        );
        assert!(
            !reservations
                .denies_hostname("edge.example.net", 8443)
                .unwrap()
        );
    }

    #[test]
    fn observed_origin_state_is_bounded_and_updated_atomically() {
        let reservations = OriginReservations::new(&[McpHttpOrigin {
            host: "api.example.com".to_owned(),
            port: 443,
        }])
        .unwrap();
        let aliases = (0..=MAX_OBSERVED_NAMES_PER_ORIGIN)
            .map(|index| format!("edge-{index}.example.net"))
            .collect::<Vec<_>>();
        assert!(matches!(
            reservations.reserve_resolution("api.example.com", 443, &aliases, &[]),
            Err(OriginReservationError::CapacityExceeded)
        ));
        assert!(
            !reservations
                .denies_hostname("edge-0.example.net", 443)
                .unwrap()
        );
    }
}
