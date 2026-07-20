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

/// Default hard capacity when a policy-derived bound is not supplied.
pub const DEFAULT_CAPACITY: usize = 4096;

pub struct AuthorizationCache {
    entries: Mutex<HashMap<(String, IpAddr), Instant>>,
    capacity: usize,
}

impl Default for AuthorizationCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl AuthorizationCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a cache with a deterministic hard capacity. The capacity bounds
    /// total `(name, ip)` entries so a DNS-only workload cannot grow the cache
    /// without bound; callers derive it from policy (see
    /// [`AuthorizationCache::capacity_for`]). A capacity of zero is clamped to
    /// one.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Derives a hard capacity from the DNS budget: at most `max_unique_names`
    /// distinct names per window, each with at most `max_response_records`
    /// pinned addresses, with a small floor so a tiny budget still leaves room
    /// for direct-IP authorizations.
    #[must_use]
    pub fn capacity_for(max_unique_names: u32, max_response_records: u32) -> usize {
        let product = (max_unique_names as usize).saturating_mul(max_response_records as usize);
        product.max(64)
    }

    /// The hard capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Records that `name` (already normalized) is authorized to resolve to
    /// `ip` until `now + ttl`. Expired entries are pruned on every insert, and
    /// if the cache is still at capacity a deterministic eviction (the entry
    /// with the earliest expiry, ties broken by key order) makes room, so the
    /// cache never exceeds [`AuthorizationCache::capacity`].
    pub fn authorize(&self, name: &str, ip: IpAddr, ttl: Duration) {
        let now = Instant::now();
        let expires_at = now + ttl;
        let mut entries = self
            .entries
            .lock()
            .expect("authorization cache mutex poisoned");
        entries.retain(|_, exp| *exp > now);
        let key = (name.to_owned(), ip);
        if !entries.contains_key(&key)
            && entries.len() >= self.capacity
            && let Some(evict) = entries
                .iter()
                .min_by(|(ka, ea), (kb, eb)| ea.cmp(eb).then_with(|| ka.cmp(kb)))
                .map(|(k, _)| k.clone())
        {
            entries.remove(&evict);
        }
        entries.insert(key, expires_at);
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

    /// The current number of live entries (may include not-yet-pruned expired
    /// entries; those are pruned on the next `authorize`/lookup).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("authorization cache mutex poisoned")
            .len()
    }

    #[must_use]
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
        cache.authorize("multi.example", ip_high, Duration::from_secs(60));
        cache.authorize("multi.example", ip_low, Duration::from_secs(60));
        assert_eq!(
            cache.authorized_addresses("multi.example"),
            vec![ip_low, ip_high]
        );
    }

    #[test]
    fn capacity_is_a_hard_bound_under_dns_only_growth() {
        let cache = AuthorizationCache::with_capacity(8);
        assert_eq!(cache.capacity(), 8);
        // Insert far more distinct (name, ip) authorizations than the cap.
        for i in 0..1000u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8));
            cache.authorize(&format!("name{i}.example"), ip, Duration::from_secs(60));
            assert!(
                cache.len() <= 8,
                "cache exceeded its hard capacity at insert {i}: {}",
                cache.len()
            );
        }
        assert_eq!(cache.len(), 8);
    }

    #[test]
    fn eviction_prefers_the_earliest_expiring_entry() {
        let cache = AuthorizationCache::with_capacity(2);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        // `short` expires soonest; when a third entry needs room it must be
        // evicted first.
        cache.authorize("short.example", ip, Duration::from_millis(60));
        cache.authorize("long.example", ip, Duration::from_secs(60));
        cache.authorize("newer.example", ip, Duration::from_secs(60));
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_authorized("short.example", ip));
        assert!(cache.is_authorized("long.example", ip));
        assert!(cache.is_authorized("newer.example", ip));
    }

    #[test]
    fn expired_entries_are_pruned_on_insert() {
        let cache = AuthorizationCache::with_capacity(1000);
        let ip = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        cache.authorize("gone.example", ip, Duration::from_millis(40));
        assert_eq!(cache.len(), 1);
        sleep(Duration::from_millis(70));
        // A later insert prunes the now-expired entry.
        cache.authorize("fresh.example", ip, Duration::from_secs(60));
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_authorized("gone.example", ip));
        assert!(cache.is_authorized("fresh.example", ip));
    }

    #[test]
    fn capacity_for_derives_a_positive_bound_with_a_floor() {
        assert_eq!(AuthorizationCache::capacity_for(256, 32), 256 * 32);
        // A tiny budget still leaves a usable floor.
        assert_eq!(AuthorizationCache::capacity_for(1, 1), 64);
    }
}
