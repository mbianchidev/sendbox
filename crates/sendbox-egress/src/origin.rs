use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::RwLock;

use sendbox_policy::McpHttpOrigin;
use thiserror::Error;

use crate::address::canonicalize;
use crate::domain;

#[derive(Debug, Error)]
pub enum OriginReservationError {
    #[error("invalid reserved MCP origin host '{0}'")]
    InvalidHost(String),
    #[error("reserved MCP origin port must be non-zero")]
    InvalidPort,
    #[error("reserved MCP origin state is unavailable")]
    Poisoned,
}

#[derive(Debug, Default)]
struct ReservationState {
    names: BTreeSet<(String, u16)>,
    addresses: BTreeSet<(IpAddr, u16)>,
}

#[derive(Debug, Default)]
pub struct OriginReservations {
    remote_mcp_active: bool,
    state: RwLock<ReservationState>,
}

impl OriginReservations {
    pub fn new(origins: &[McpHttpOrigin]) -> Result<Self, OriginReservationError> {
        let reservations = Self {
            remote_mcp_active: !origins.is_empty(),
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
        self.reserve_configured(host, port)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| OriginReservationError::Poisoned)?;
        for alias in aliases {
            state.names.insert((normalize_host(alias)?, port));
        }
        state.addresses.extend(
            addresses
                .iter()
                .copied()
                .map(canonicalize)
                .map(|address| (address, port)),
        );
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
        self.state
            .write()
            .map_err(|_| OriginReservationError::Poisoned)?
            .names
            .insert((host, port));
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
}
