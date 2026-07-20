//! IP address classification for special ranges that must never be reachable
//! through a domain grant alone. An address must additionally be explicitly
//! granted by an exact IP or CIDR policy entry before it can be dialed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Classification of a resolved or directly requested destination address.
/// `Global` is the only class that is reachable purely on the strength of a
/// domain grant or a permissive default action; every other class requires an
/// explicit IP/CIDR grant regardless of domain policy outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressClass {
    /// The unspecified address (`0.0.0.0` / `::`). Never a valid dial
    /// destination: on Linux, connecting to `0.0.0.0`/`::` is treated as a
    /// request for the local host and silently resolves to a loopback-class
    /// destination, which would otherwise let a resolved/dialed address
    /// bypass every other address-class check.
    Unspecified,
    /// Cloud provider instance metadata endpoints (e.g. 169.254.169.254).
    CloudMetadata,
    Loopback,
    LinkLocal,
    Multicast,
    /// RFC 1918 private IPv4 space.
    PrivateRfc1918,
    /// IPv6 Unique Local Address space (RFC 4193, fc00::/7).
    UniqueLocalIpv6,
    /// Everything else: routable/global unicast space.
    Global,
}

impl AddressClass {
    /// Every class other than `Global` is address-class restricted and
    /// requires an explicit IP/CIDR grant to be reachable.
    #[must_use]
    pub fn is_restricted(self) -> bool {
        !matches!(self, AddressClass::Global)
    }
}

/// Deterministic, documented list of known cloud-provider instance-metadata
/// IPv4 addresses. AWS, Microsoft Azure, Oracle Cloud, and Google Cloud's
/// metadata services all use the same well-known link-local address,
/// `169.254.169.254` (Google's `metadata.google.internal` hostname resolves
/// to this same address, so it is covered by address-based blocking without
/// any hostname-specific logic). Alibaba Cloud uses a distinct address,
/// `100.100.100.200`, which falls inside the RFC 6598 shared/carrier-grade
/// NAT range (`100.64.0.0/10`) rather than any range this classifier
/// otherwise flags (it is neither RFC 1918 private space nor link-local),
/// so it needs its own explicit entry — without it, Alibaba's metadata
/// endpoint would be classified `Global` and reachable by default.
///
/// This list is necessarily incomplete: it is not a substitute for a
/// hostname-level block (`blocked_domains`) of any metadata hostname that
/// might resolve to an address *not* on this list, now or in the future. If
/// a provider ever serves metadata purely by hostname over an address this
/// list does not cover, address-based blocking cannot catch it and the
/// domain policy is the only mechanism that can; see
/// `docs/security/egress-enforcement-trust-boundary.md` for this
/// residual-risk note.
pub const METADATA_V4_ADDRESSES: &[Ipv4Addr] = &[
    Ipv4Addr::new(169, 254, 169, 254), // AWS, Azure, Oracle Cloud, GCP
    Ipv4Addr::new(100, 100, 100, 200), // Alibaba Cloud
];

/// Known IPv6 cloud-provider metadata addresses. AWS IMDSv2 documents
/// `fd00:ec2::254` as its IPv6 metadata convention; other major providers'
/// metadata services are IPv4-only as of this writing. Like
/// [`METADATA_V4_ADDRESSES`], this list is not exhaustive.
pub const METADATA_V6_ADDRESSES: &[Ipv6Addr] =
    &[Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)];

/// Classifies an [`IpAddr`] into the most specific applicable
/// [`AddressClass`]. Classification is total and never panics.
#[must_use]
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    if ip.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if METADATA_V4_ADDRESSES.contains(&ip) {
        return AddressClass::CloudMetadata;
    }
    if ip.is_loopback() {
        return AddressClass::Loopback;
    }
    if ip.is_link_local() {
        return AddressClass::LinkLocal;
    }
    if ip.is_multicast() {
        return AddressClass::Multicast;
    }
    if is_rfc1918(ip) {
        return AddressClass::PrivateRfc1918;
    }
    AddressClass::Global
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    if ip.is_unspecified() {
        return AddressClass::Unspecified;
    }
    // IPv4-mapped/compatible addresses are evaluated using IPv4 semantics so
    // policy cannot be bypassed by encoding a private/metadata address as an
    // IPv6-mapped literal.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    if is_metadata_v6(ip) {
        return AddressClass::CloudMetadata;
    }
    if ip.is_loopback() {
        return AddressClass::Loopback;
    }
    if is_link_local_v6(ip) {
        return AddressClass::LinkLocal;
    }
    if ip.is_multicast() {
        return AddressClass::Multicast;
    }
    if is_unique_local_v6(ip) {
        return AddressClass::UniqueLocalIpv6;
    }
    AddressClass::Global
}

fn is_rfc1918(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// fe80::/10
fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// fc00::/7
fn is_unique_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// Well-known IPv6 metadata endpoints used by major cloud providers. See
/// [`METADATA_V6_ADDRESSES`] for the documented, non-exhaustive list.
fn is_metadata_v6(ip: Ipv6Addr) -> bool {
    METADATA_V6_ADDRESSES.contains(&ip)
}

/// Canonicalizes an [`IpAddr`] so a single underlying address always has a
/// single representation before it is used in any CIDR containment check,
/// authorization-cache key, diagnostic, or dial. Concretely, an IPv4-mapped
/// IPv6 address (`::ffff:a.b.c.d`) is collapsed to its plain IPv4 form.
/// Without this, an IPv4 CIDR in `blocked_networks`/`allowed_networks` would
/// never match the same address re-encoded as IPv4-mapped IPv6 (the two
/// `IpAddr` variants are never `==` and `IpNet::contains` never crosses
/// families), letting a client bypass a blocked CIDR — or fail to benefit
/// from an allowed one — purely through address encoding.
#[must_use]
pub fn canonicalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_loopback() {
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            AddressClass::Loopback
        );
        assert_eq!(
            classify(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            AddressClass::Loopback
        );
    }

    #[test]
    fn classifies_metadata() {
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
            AddressClass::CloudMetadata
        );
        assert_eq!(
            classify(IpAddr::V6(Ipv6Addr::new(
                0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254
            ))),
            AddressClass::CloudMetadata
        );
    }

    #[test]
    fn classifies_alibaba_metadata_outside_rfc1918_and_link_local() {
        let alibaba = Ipv4Addr::new(100, 100, 100, 200);
        assert_eq!(classify(IpAddr::V4(alibaba)), AddressClass::CloudMetadata);
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 201))),
            AddressClass::Global
        );
    }

    #[test]
    fn classifies_link_local_distinct_from_metadata() {
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))),
            AddressClass::LinkLocal
        );
    }

    #[test]
    fn classifies_rfc1918() {
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(172, 31, 255, 255),
            Ipv4Addr::new(192, 168, 1, 1),
        ] {
            assert_eq!(classify(IpAddr::V4(ip)), AddressClass::PrivateRfc1918);
        }
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))),
            AddressClass::Global
        );
    }

    #[test]
    fn classifies_ula_and_multicast_v6() {
        assert_eq!(
            classify(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))),
            AddressClass::UniqueLocalIpv6
        );
        assert_eq!(
            classify(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))),
            AddressClass::Multicast
        );
    }

    #[test]
    fn classifies_ipv4_mapped_ipv6_using_v4_rules() {
        let mapped = Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped();
        assert_eq!(classify(IpAddr::V6(mapped)), AddressClass::CloudMetadata);
    }

    #[test]
    fn classifies_public_addresses_as_global() {
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            AddressClass::Global
        );
    }

    #[test]
    fn classifies_unspecified_addresses() {
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            AddressClass::Unspecified
        );
        assert_eq!(
            classify(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            AddressClass::Unspecified
        );
    }

    #[test]
    fn unspecified_is_restricted() {
        assert!(AddressClass::Unspecified.is_restricted());
    }

    #[test]
    fn canonicalize_collapses_ipv4_mapped_ipv6() {
        let v4 = Ipv4Addr::new(203, 0, 113, 5);
        let mapped = IpAddr::V6(v4.to_ipv6_mapped());
        assert_eq!(canonicalize(mapped), IpAddr::V4(v4));
    }

    #[test]
    fn canonicalize_leaves_plain_addresses_unchanged() {
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        assert_eq!(canonicalize(v4), v4);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(canonicalize(v6), v6);
    }
}
