//! Expiring `(normalized name, IpAddr)` authorization cache.
//!
//! A DNS answer only authorizes the CONNECT broker to dial the exact address
//! that was validated and returned, for a bounded, policy-capped duration.
//! This closes the gap between "the domain was allowed" and "this specific
//! address is the one that was actually validated," which is what defeats
//! DNS rebinding: a later CONNECT can only use an address that was itself
//! seen and validated in a DNS answer within its TTL window.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct AuthorizationCache {
    entries: Mutex<HashMap<(String, IpAddr), Instant>>,
}

impl AuthorizationCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `name` (already normalized) is authorized to resolve to
    /// `ip` until `now + ttl`.
    pub fn authorize(&self, name: &str, ip: IpAddr, ttl: Duration) {
        let expires_at = Instant::now() + ttl;
        let mut entries = self
            .entries
            .lock()
            .expect("authorization cache mutex poisoned");
        entries.insert((name.to_owned(), ip), expires_at);
    }

    /// Returns true if `(name, ip)` has a live, unexpired authorization.
    /// Expired entries are pruned lazily on lookup.
    pub fn is_authorized(&self, name: &str, ip: IpAddr) -> bool {
        let mut entries = self
            .entries
            .lock()
            .expect("authorization cache mutex poisoned");
        let key = (name.to_owned(), ip);
        match entries.get(&key) {
            Some(expires_at) if *expires_at > Instant::now() => true,
            Some(_) => {
                entries.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Returns every still-authorized address for `name`, sorted
    /// deterministically (ascending `IpAddr` order — IPv4 before IPv6, then
    /// by value). Used by the CONNECT broker both to check whether a
    /// client-declared `expected_ip` is actually among the validated
    /// addresses, and, absent that, to pick a pinned IP deterministically
    /// rather than relying on hash-map/resolver iteration order.
    pub fn authorized_addresses(&self, name: &str) -> Vec<IpAddr> {
        let mut entries = self
            .entries
            .lock()
            .expect("authorization cache mutex poisoned");
        let now = Instant::now();
        entries.retain(|_, expires_at| *expires_at > now);
        let mut addresses: Vec<IpAddr> = entries
            .keys()
            .filter(|(n, _)| n == name)
            .map(|(_, ip)| *ip)
            .collect();
        addresses.sort();
        addresses
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("authorization cache mutex poisoned")
            .len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread::sleep;

    #[test]
    fn authorizes_and_expires() {
        let cache = AuthorizationCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert!(!cache.is_authorized("example.com", ip));
        cache.authorize("example.com", ip, Duration::from_millis(50));
        assert!(cache.is_authorized("example.com", ip));
        sleep(Duration::from_millis(80));
        assert!(!cache.is_authorized("example.com", ip));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn distinct_names_and_ips_are_independent() {
        let cache = AuthorizationCache::new();
        let ip_a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        cache.authorize("a.example", ip_a, Duration::from_secs(60));
        assert!(cache.is_authorized("a.example", ip_a));
        assert!(!cache.is_authorized("a.example", ip_b));
        assert!(!cache.is_authorized("b.example", ip_a));
    }

    #[test]
    fn authorized_addresses_finds_live_entries_only() {
        let cache = AuthorizationCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!(
            cache.authorized_addresses("example.com"),
            Vec::<IpAddr>::new()
        );
        cache.authorize("example.com", ip, Duration::from_millis(50));
        assert_eq!(cache.authorized_addresses("example.com"), vec![ip]);
        sleep(Duration::from_millis(80));
        assert_eq!(
            cache.authorized_addresses("example.com"),
            Vec::<IpAddr>::new()
        );
    }

    #[test]
    fn authorized_addresses_returns_all_live_entries_sorted() {
        let cache = AuthorizationCache::new();
        let ip_high = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        let ip_low = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        // Authorize in descending order to prove the returned order is
        // sorted, not insertion order.
        cache.authorize("multi.example", ip_high, Duration::from_secs(60));
        cache.authorize("multi.example", ip_low, Duration::from_secs(60));
        assert_eq!(
            cache.authorized_addresses("multi.example"),
            vec![ip_low, ip_high]
        );
    }
}
