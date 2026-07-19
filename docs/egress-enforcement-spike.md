# Egress enforcement spike (Phase 1)

This Phase 1 spike implements a Linux kernel-level network-egress
enforcement mechanism for SendBox: a typed policy engine, a DNS broker that
decodes, validates, and re-encodes real DNS traffic through a maintained
crate, a small versioned CONNECT-style egress broker, and a deterministic
nftables ruleset applied inside a throwaway network namespace. It is
isolated under `spikes/egress-enforcement/` and is **not** a production
runtime. It targets proving only the underlying Linux mechanism (network
namespaces + nftables + UID separation); it makes no claim about Kata, Apple
`container`, Hyperlight, or any other SendBox provider's production
integration.

**Verification status: the kernel-level mechanism passed the privileged
Ubuntu 24.04 CI suite.** The portable suite proves the typed policy, DNS,
CONNECT, authorization, and deterministic nftables-generation behavior. The
root CI suite separately proved the generated rules in a real Linux network
namespace; see "Live test result" for the exact runner capabilities and
adversarial result.

Safe Rust only: the crate sets `#![forbid(unsafe_code)]` and
`unsafe_code = "forbid"`/`clippy::all = "deny"` lints. No C, BPF, seccomp, TLS
interception, credential injection, runtime adapter, or supervisor is in
scope. Rust 1.93.1, edition 2024, own `Cargo.toml`/`Cargo.lock`, excluded from
the root workspace (`[workspace]` in its own manifest).

## Trust boundaries and architecture

```
                 unprivileged "agent" UID              unprivileged "broker" UID
                 (sandboxed workload)                  (trusted enforcement point)
  ┌────────────────────────────────┐        ┌───────────────────────────────────────┐
  │ agent process                  │        │ egress-gateway (single process)        │
  │  - no direct IPv4/IPv6 sockets │  nft:   │  - dns broker: hickory-proto           │
  │    reach anything but the two  │  skuid  │    decode/encode, validates every      │
  │    loopback broker ports below │  scoped │    CNAME hop + final name + every IP   │
  │                                │  allow  │  - caps TTL, records expiring          │
  │  --(exact loopback UDP/TCP)--> │ ------> │    (name, IpAddr) authorization        │
  │  --(exact loopback TCP)------> │         │  - connect broker: resolves via the    │
  └────────────────────────────────┘        │    SAME shared authorization cache      │
                                             │  - dials the exact validated IP only   │
                                             │  - never re-resolves the hostname      │
                                             │  - metadata blocked in kernel too       │
                                             └───────────────────┬─────────────────────┘
                                                                  │ fixture/external traffic
                                                                  ▼
                                                        veth-attached fixtures
                                                        (never loopback)
```

- The **agent UID** can reach only the DNS broker's exact loopback UDP/TCP
  port and the CONNECT broker's exact loopback TCP port. Everything else —
  direct IPv4/IPv6 TCP, all UDP/QUIC, alternate DNS ports — is
  default-dropped by nftables before any userspace policy is even consulted.
- Both broker listeners run **inside one process** (`egress-gateway`),
  sharing one `PolicyEngine`, one injectable resolver, and — critically —
  one `AuthorizationCache`. Running the DNS and CONNECT brokers as two
  independent OS processes (as an earlier iteration of this spike did) would
  give each its own, disjoint cache, silently contradicting the design's
  claim that a CONNECT request can reuse an authorization the DNS broker
  already recorded. See "Runnable local behavior" below.
- The **broker UID** is the only identity nftables lets originate
  fixture/external traffic, and even the broker UID is kernel-blocked from
  cloud metadata addresses as defense-in-depth, independent of the broker's
  own userspace SSRF guard (`PolicyEngine::address_permitted`).
- Agent and broker UIDs are always required to differ
  (`NftConfig::validate`), and the harness runs them via
  `setpriv --reuid --regid --clear-groups --no-new-privs`.

## Protocol: CONNECT instead of SOCKS5

`src/connect_proto.rs` defines a small, explicit, versioned, bounded framing
protocol (see the module doc for the exact byte layout). A request carries a
protocol (TCP only is ever accepted; UDP is parsed but always answered
`UnsupportedProtocol`), a port, and either a hostname or a literal IP, plus
an **optional** client-supplied `expected_ip`. That field is a consistency
*filter*, never a substitute for validation: it can only ever narrow which
already-validated address is dialed, and a value absent from the validated
set is always rejected rather than silently substituted or ignored. For a
hostname target, the broker:

1. Normalizes and policy-checks the domain name itself.
2. Builds the candidate address set from a live, unexpired authorization
   already recorded by a DNS-broker resolution; if that set is empty, or if
   `expected_ip` was supplied but is not among those cached candidates, it
   also performs a fresh policy-aware resolution (through the same
   injectable resolver path the DNS broker uses), validating every CNAME
   hop, the final owner name, and every returned address, and adds each
   validated address — with a fresh capped-TTL authorization recorded for
   it — to the candidate set.
3. Selects the dialed address from that set: if `expected_ip` (already
   canonicalized) is present in the set, that is the address dialed;
   if `expected_ip` was supplied but is absent from the set, the request is
   rejected (`ExpectedIpMismatch`); otherwise selection is **deterministic**
   — the smallest address in ascending `IpAddr` order (IPv4 before IPv6,
   then by value) — never resolver/hash-map iteration order.
4. Immediately before dialing, re-runs the full, port-aware
   `PolicyEngine::decide_hostname(name, selected_ip, port, protocol)` (or
   `decide_direct_ip` for a literal-IP target) as the single authoritative
   gate — this is what stops a hostname request from bypassing
   `allowed_ports`/protocol constraints purely because the domain/address
   were validated during resolution.
5. Dials the resulting `SocketAddr` directly with a timeout — **never**
   hostname re-resolution, and never the client's address.

The connection permit (`max_concurrent_connections`) is acquired in the
accept loop itself, *before* any task is spawned to handle the new
connection: a saturated broker never spawns *any* task for a rejected
connection. The `LimitExceeded` status is written inline, directly in the
accept loop, bounded by a short (250ms) timeout — not spawned, even as a
short-lived task. Spawning a task per rejection (even one bounded to a
couple of seconds) would let a sustained connection flood grow the number
of in-flight tasks without bound, which is exactly the resource
exhaustion the connection cap exists to prevent; writing inline instead
means a flood can, at worst, backpressure the accept loop itself (each
non-reading malicious peer costs at most one timeout's worth of
accept-loop time), never unbounded task/memory growth. A bare
non-blocking `try_write` was tried and rejected during review: immediately
after `accept`, a socket's write-readiness is not always established with
the async reactor yet, so `try_write` can spuriously fail to send even on
a healthy connection; the bounded async write correctly awaits genuine
writability instead. `saturated_broker_handles_flood_of_rejections_without_unbounded_delay`
regression-tests this by flooding a saturated broker with 250 concurrent
connections and asserting the whole flood completes in a small fraction
of `250 × 250ms`, and that the broker remains fully responsive to a
legitimate connection immediately afterward. Once
a tunnel is established, `tokio::io::copy_bidirectional` is used (not two
independently-driven `tokio::io::copy` futures) so a client that finishes
sending and half-closes its write side has that half-close correctly
propagated to the upstream connection instead of the proxy silently
deadlocking; the whole session is additionally bounded by a configurable
`session_timeout` so a peer that never closes either direction cannot hold
the connection open forever.

## Policy semantics (`src/policy.rs`, `src/address.rs`, `src/domain.rs`)

- **Default allow/deny** plus **exact** allowed/blocked domain lists.
  `*.example.com` matches only strict subdomains (`api.example.com`), never
  the apex (`example.com`) and never an unrelated suffix collision
  (`evilexample.com`, `evilgithub.com`). Domain names are normalized
  (lowercased, trailing dot stripped, label-length validated) before every
  comparison.
- **Blocked precedence**: a blocked domain or blocked IP/CIDR always denies,
  even if an allow rule would otherwise match.
- **Address-class precedence is unconditional**: loopback, link-local,
  multicast, RFC 1918, IPv6 ULA, and cloud metadata addresses are always
  denied *regardless of any domain allow rule* unless the exact
  IP/CIDR is separately, explicitly granted via `allowed_networks`. A domain
  grant can never unlock a restricted address class by itself
  (`PolicyEngine::decide_hostname`, `domain_allow_never_unlocks_restricted_address_class`
  test).
- **The unspecified address (`0.0.0.0` / `::`) is hard-rejected
  unconditionally**, even by an explicit grant that would technically cover
  it (e.g. `0.0.0.0/0`). It is never a valid dial destination — on Linux,
  connecting to it is treated as a request for the local host — so no
  IP/CIDR grant can sensibly authorize it
  (`unspecified_address_is_denied_even_with_a_covering_explicit_grant` test).
- **IPv4-mapped IPv6 addresses are canonicalized to plain IPv4** before every
  CIDR containment check, authorization-cache key, diagnostic, and dial
  (`address::canonicalize`, applied inside `PolicyEngine::check_address` and
  again at the DNS/CONNECT resolver and CONNECT-protocol wire boundaries).
  Without this, encoding a blocked IPv4 address as `::ffff:a.b.c.d` would
  never match an IPv4 CIDR in `blocked_networks` (the two `IpAddr` variants
  are never equal and `IpNet::contains` never crosses families), bypassing
  the block; the `ipv4_mapped_ipv6_cannot_bypass_a_blocked_ipv4_cidr` test
  is the regression for this.
- **Direct-IP connections never consult domain rules** — they are governed
  solely by the IP/address-class policy (`PolicyEngine::decide_direct_ip`).
- Explicit TCP/UDP protocol+port constraints (`allowed_ports`), a
  `max_concurrent_connections` cap, and a `max_dns_ttl_secs` cap are all
  part of the typed policy.
- Every decision is a small `Decision { allowed, reason, address_class }`
  struct with a fixed field order, serialized via `serde_json` for
  deterministic diagnostics (`Decision::to_json`).

## DNS broker (`src/dns_broker.rs`)

Binds loopback UDP and TCP DNS listeners and decodes/encodes real DNS
messages through `hickory-proto` (a maintained crate) — there is no
hand-rolled wire parser. Upstream resolution itself is injectable
(`UpstreamResolver` trait) so this spike can run fully locally and
deterministically without depending on a live upstream resolver; the
decode/encode/validate/authorize path is real.

- Bounded message sizes (4096-byte UDP datagrams dropped unparsed if larger;
  a 2-byte length-prefixed TCP frame capped at 65535). The in-flight
  concurrency permit is acquired in the receive/accept loop itself, *before*
  any task is spawned to handle the datagram/connection (a
  `try_acquire_owned` at UDP receive time / at TCP accept time) — a
  saturated broker never spawns a task for rejected work at all; it drops
  the UDP datagram or lets the accepted TCP socket close immediately
  (`saturated_udp_capacity_drops_rather_than_queues_datagrams`,
  `saturated_tcp_capacity_rejects_new_connections_without_reading`).
- Every CNAME hop, the final owner name, and the originally queried name are
  each independently policy-checked; every returned address is
  canonicalized (`address::canonicalize`) then checked against
  address-class/network policy before being placed in an answer.
- TTLs are capped by `max_dns_ttl_secs` before being used both in the
  DNS answer and in the authorization expiry.
- A multi-hop CNAME chain preserves each record's true owner name
  (`a CNAME b`, `b CNAME c`, `c A ...`), not all records owned by the
  original query name (`multi_hop_cname_chain_preserves_each_record_owner`).
- **NODATA vs NXDOMAIN (RFC 2308)**: if the resolver confirms a name exists
  but has no record of the queried type (e.g. only an AAAA address for an A
  query), the response is NOERROR with an empty answer section, not
  NXDOMAIN (`nodata_is_noerror_with_empty_answers_not_nxdomain`). NXDOMAIN is
  reserved for a resolver reporting the name does not exist at all.
- Malformed/oversized/multi-question/wrong-opcode queries return a
  well-formed `FormErr`/`NotImp`/`Refused` response (or are silently dropped
  if the input cannot even be parsed as a DNS header) — the broker never
  panics on attacker input (`malformed_bytes_are_dropped_without_panic`,
  `oversized_udp_datagram_is_never_parsed`).
- Rebinding and CNAME-to-special-range tests
  (`rebinding_to_loopback_via_cname_is_refused`,
  `special_ranges_are_refused_via_direct_answers`) assert that a resolver
  answer pointing at loopback/RFC1918/link-local/multicast/ULA/metadata is
  refused and never authorized, even when the *domain name* is allowed.

## Runnable local behavior

```bash
# One process: DNS broker (UDP+TCP) and CONNECT broker (TCP), sharing one
# PolicyEngine, resolver, and AuthorizationCache.
cargo run --manifest-path spikes/egress-enforcement/Cargo.toml --release --bin egress-gateway -- \
  --policy spikes/egress-enforcement/examples/policy.json \
  --fixtures spikes/egress-enforcement/examples/dns-fixtures.json \
  --dns-listen 127.0.0.1:15353 \
  --connect-listen 127.0.0.1:15380

# A real DNS client works against it:
dig @127.0.0.1 -p 15353 example.com A            # NOERROR, capped TTL
dig @127.0.0.1 -p 15353 evil.example.com A       # REFUSED (blocked domain)
dig @127.0.0.1 -p 15353 demo.internal.test A     # NOERROR; also records a shared authorization

# The CONNECT broker reuses that same authorization — no fresh resolution
# needed for a name the DNS broker already validated:
cargo run --manifest-path spikes/egress-enforcement/Cargo.toml --release --bin netns-harness -- \
  connect-attempt --broker 127.0.0.1:15380 --target demo.internal.test --port 19443
```

This was executed on this spike's local macOS development host against a
plain TCP echo fixture bound to `127.0.0.1:19443`, and produced exactly the
results above plus:

```
{"outcome":"ok","status":"ok","echo_verified":true}
```
for the CONNECT attempt,
```
{"outcome":"denied","status":"policy_denied"}
```
for a hostname not in `allowed_domains`, and
```
{"outcome":"denied","status":"expected_ip_mismatch"}
```
for a client-declared `expected_ip` that does not match the broker's own
resolution — confirming the client's claim is never accepted as resolution
proof. Colocating both listeners in one process is what makes the
"CONNECT reuses a DNS-broker authorization" line above literally true: an
earlier iteration of this spike ran `dns-broker` and `egress-broker` as two
separate processes, which — despite documentation claiming a shared cache —
actually gave each broker its own, disjoint `AuthorizationCache`. That
mismatch between claim and implementation was corrected by merging both
listeners into the single `egress-gateway` binary used above, which is also
what the live namespace harness now spawns.

## nftables ruleset (`src/nft.rs`)

- Single spike-owned `inet` table (covers IPv4 and IPv6 together) with a
  sanitized, unique name (`^[a-z][a-z0-9_]{0,30}$`, validated).
- Applied as **one atomic transaction**: `NftConfig::render_transaction()`
  (a `destroy table inet <name>` statement followed by a full, fresh table
  definition) is written to a temp file and passed as `nft -f <path>` via
  `std::process::Command` **argv only** — never a shell string. `destroy`
  (not `delete`) is used so the same transaction text is correct for both
  the very first apply (the table does not exist yet; `destroy` is a
  documented no-op in that case) and a reapply (the previous table's chains
  and rules are torn down *inside the same transaction* before the new ones
  are added, so no rule from an earlier configuration can survive into the
  new ruleset — reapplying with, say, a different broker port cannot leave
  a stale accept rule for the old port behind). Because `nft -f` applies
  the whole file as one transaction, a syntax/reference error anywhere
  aborts the entire update and leaves the *previous* table completely
  intact, rather than partially destroyed. Native `nft` text syntax was
  used instead of the JSON frontend because it needed no extra
  parsing/serialization layer and stayed simpler for this scope.
- `input`/`output` chains both default to `policy drop;` with
  `ct state established,related accept` first, so reply traffic for
  permitted connections always works. The **input** side additionally needs
  a narrow accept for the brand-new (not-yet-established) inbound
  SYN/datagram that reaches a broker's listening socket: `meta skuid` is
  only ever populated for locally-*originated* packets (output/postrouting),
  so it cannot identify the sender of an inbound packet, and the very first
  packet of a new flow is `ct state new`, not `established`. Without an
  explicit accept for it, that first packet is dropped by the default-drop
  input policy before the broker's socket ever sees it and the whole
  mechanism does not work. This input accept is therefore scoped by
  `iif lo` plus the exact destination address/port instead of `skuid` — the
  strongest identity nftables can express for a locally-destined packet. It
  does *not* restrict who may originate that inbound traffic; see the
  UID-based-isolation limitation below for the consequence.
- The agent UID gets narrow `meta skuid <uid> ip[6] daddr 127.0.0.1|::1
  <proto> dport <exact port> accept` **output** rules for the two broker
  ports only — **no blanket loopback allow**.
- The broker UID gets an explicit `drop` for every address in the
  deterministic cloud-metadata list (see "Cloud metadata addresses" below)
  before a general `accept`, so even a hypothetical bug in the broker's own
  SSRF guard cannot reach metadata.
- When a fixture veth interface is configured, ICMPv6 neighbor discovery —
  **types 135 (neighbor solicitation) and 136 (neighbor advertisement)
  only** — is permitted on that interface alone, in both `input` and
  `output`, with no `skuid` condition (NDP is kernel-generated, not
  attributable to a sending socket). Without this, IPv6 does not work over
  the veth link at all: the guest and host cannot resolve each other's
  link-layer addresses, so every IPv6 packet — including ones a policy
  would otherwise allow — silently fails to be delivered. No other ICMPv6
  type (echo request/reply, router solicitation/advertisement, etc.) is
  permitted, and the rule is scoped to the fixture interface only, never
  loopback or any other interface.
- `nft::apply`/`nft::cleanup` are unit-tested against a `FakeNftRunner` for
  deterministic rendering, argv-only invocation, non-zero-exit propagation,
  and idempotent/absent-safe cleanup — `cleanup` now issues `destroy table`
  directly rather than `delete table` plus stderr pattern-matching, so
  idempotency is a property of the command itself, not of guessing `nft`'s
  error text.
- The ruleset persists independently of broker process lifetime — killing
  the gateway does not remove or loosen the table; the netns harness (not
  the gateway) owns cleanup, and only after the harness itself finishes.

### `destroy` command availability

The atomic apply/cleanup strategy above depends on `nft destroy table`
being supported. Ubuntu 24.04 ("noble") ships `nftables` **1.0.9** (package
`nftables_1.0.9-1build1`, per `packages.ubuntu.com`/`ubuntuupdates.org`),
and `destroy` as an idempotent-delete variant for tables/chains/rules/sets
has been present since early in the 1.0.x series. The live CI run used
`nftables v1.0.9` and successfully applied, re-applied, inspected, and
removed the spike-owned table, directly confirming compatibility on the
pinned runner.

### Cloud metadata addresses (`src/address.rs`)

`METADATA_V4_ADDRESSES`/`METADATA_V6_ADDRESSES` are the single, deterministic
source of truth used by *both* `PolicyEngine`'s address classification and
`nft.rs`'s broker-UID `drop` rules, so the two can never silently diverge:

| Provider | Address | Notes |
|---|---|---|
| AWS, Azure, Oracle Cloud, GCP | `169.254.169.254` | Shared well-known link-local metadata address. GCP's `metadata.google.internal` hostname resolves to this same address, so it is covered by address-based blocking without any hostname-specific logic. |
| Alibaba Cloud | `100.100.100.200` | Falls inside RFC 6598 shared/carrier-grade-NAT space (`100.64.0.0/10`) — neither RFC 1918 private space nor link-local — so without this explicit entry it would classify as `Global` and be reachable by default. |
| AWS IMDSv2 (IPv6) | `fd00:ec2::254` | Documented AWS convention; other major providers' metadata services are IPv4-only as of this writing. |

This list is **not exhaustive**. It is not a substitute for a hostname-level
block: if any provider ever serves metadata purely by a hostname that
resolves to an address not on this list (now or in the future),
address-based blocking cannot catch it, and an explicit `blocked_domains`
entry for that hostname is the only mechanism that can. This is a
documented residual gap, not a claim that every conceivable metadata
endpoint is covered.

### Known limitation: raw sockets

nftables' `inet` family filter hooks operate at the IP layer and cannot see
or block `AF_PACKET` raw sockets, which operate below IP. This spike does
**not** claim raw-socket denial is enforced by the generated ruleset. The
mitigation is capability removal, not nftables rules: the harness runs the
agent (and the broker) via
`setpriv --reuid <uid> --regid <uid> --clear-groups --inh-caps=-all
--ambient-caps=-all --bounding-set=-all --no-new-privs`
(`netns_harness::setpriv_argv`), which actually clears the inheritable,
ambient, and bounding capability sets — not merely changing the UID — since
dropping `CAP_NET_RAW` from all of them is what would prevent raw-socket
creation.

This is independently verified, not just asserted: the live suite runs a
`caps-probe` subcommand under the same `setpriv` invocation used for the
agent and asserts every `/proc/self/status` `Cap*` field (`CapInh`,
`CapPrm`, `CapEff`, `CapBnd`, `CapAmb`) is the all-zero 16-hex-digit
bitmask `0000000000000000`. What this spike does *not* do is independently
attempt to open a raw socket and observe the kernel reject it — doing that
portably and safely from inside CI would require assumptions about the
runner's kernel/capability configuration (e.g. seccomp, LSM policy) that
cannot be honestly guaranteed across hosted runners. So the precise, honest
claim is: the capability sets that gate raw-socket creation are
demonstrably cleared for the agent process; that raw-socket creation
itself then fails is a well-established kernel property of `CAP_NET_RAW`
removal, not something this spike additionally re-verifies with its own
probe.

## UDP/QUIC: explicitly unsupported, not transparently proxied

The CONNECT protocol parses a UDP protocol byte but the broker always
answers `UnsupportedProtocol` and never proxies it
(`udp_protocol_is_always_denied`). nftables additionally has no allow rule
for UDP from the agent UID at all (only the DNS broker's UDP port, and only
from the agent to loopback). There is no transparent UDP/QUIC support in
this spike, and none is claimed.

## UID-based isolation: known weakness

The kernel-level isolation implemented here is **UID-based**: nftables rules
key on `meta skuid`. This means *any other process that shares the broker's
UID* — not just the intended broker binary — could originate the same
"broker-class" traffic, including reaching whatever the broker UID is
allowed to reach. UID separation is necessary but not sufficient for a
strong trust boundary in a multi-process environment. For a production
integration, the ADR-004 consequence below records that this needs either:

- a dedicated **cgroup v2** classification combined with `SO_MARK`/`nft
  meta mark` socket-mark-based rules instead of (or in addition to) UID, so
  the enforcement point is tied to a specific process's socket rather than
  to "whichever process currently holds this UID", or
- some other strong broker identity mechanism (e.g. a dedicated network
  namespace *per broker instance* with no other process ever granted that
  UID, which is what the live harness approximates for the duration of one
  test run, but is not itself a production identity guarantee).

## ADR-004 consequence

This spike is Phase 1 evidence for the ADR-004 network-enforcement decision
track. Two different kinds of evidence back it, and they should not be
conflated:

**Proven now, by portable unit/integration tests already run on this host**
(see the "Verified in this session" table below for the exact commands):

- a typed policy engine can express default allow/deny, exact and wildcard
  domain rules, blocked precedence, explicit IP/CIDR grants, address-class
  precedence that a domain grant cannot override, an unconditional
  unspecified-address hard-block, IPv4-mapped-IPv6 canonicalization that a
  blocked/allowed CIDR cannot be bypassed or missed through, and a
  deterministic, documented cloud-metadata address list shared by policy
  and nft generation;
- a DNS broker can decode/encode real DNS traffic through a maintained crate
  while validating every CNAME hop and address against that policy,
  preserving correct per-record owners, distinguishing NODATA from
  NXDOMAIN, and capping/expiring authorizations to defeat rebinding;
- a small versioned CONNECT protocol can replace SOCKS5 for this purpose
  without ever trusting client-supplied resolution, deterministically
  selecting among multiple validated addresses (or honoring a
  client-declared `expected_ip` only when it is itself among them),
  re-checking the full port-aware policy decision immediately before
  dialing, and correctly propagating a half-close instead of deadlocking;
- the nftables ruleset generation is deterministic and its atomic
  destroy-then-redefine strategy is structurally proof against stale rules
  surviving a reapply.

**Proven on the pinned Ubuntu CI runner** — network namespaces + the atomic
nftables transaction + UID separation enforced "agent reaches only the two
broker ports." The live suite proved brokered IPv4 and IPv6 success; direct
allowed-address and arbitrary-address IPv4/IPv6 denial; alternate TCP/UDP
DNS denial; general UDP denial with reachable positive controls; agent and
broker metadata denial; empty agent capability sets; firewall persistence
after gateway death; brokered recovery after restart; and namespace,
process, nftables, veth, socket, and temporary-resource cleanup after both
normal completion and an injected panic.

ADR-004 can therefore accept the **Linux namespace/nftables mechanism** as
proven for this isolated topology. Production design must still replace or
strengthen UID identity with dedicated cgroup v2/socket-mark enforcement,
address DNS query-name exfiltration, and qualify the same controls inside
Kata and Apple guests. Hyperlight and gVisor integration also remain
unproven. Raw-socket creation was not attempted directly; the suite instead
proved all agent capability sets, including the `CAP_NET_RAW` bounding set,
were empty.

## DNS exfiltration: explicit residual risk

Even with every CNAME hop, the final name, and every address validated, an
agent that is allowed to resolve *any* attacker-controlled domain at all
(e.g. because `default_action = allow` or a broad wildcard grant is
configured) can still exfiltrate data by encoding it in the query name
itself (classic DNS-tunneling exfiltration: `<base32-secret>.attacker.example`).
This spike's DNS broker validates *destinations*, not the *information
content* of the query name a client chooses to send. Mitigating this
requires either a strict, narrow `allowed_domains` allowlist (which this
spike's policy model supports and recommends) or additional query-name-entropy/
rate-limiting heuristics that are out of scope here. This is recorded as a
residual risk, not something this spike claims to close.

## Live namespace harness (`src/netns_harness.rs`)

- IPv6 addresses on the veth pair are assigned with `nodad`. This is a
  throwaway, point-to-point link with exactly one peer, so duplicate
  address detection could never usefully detect a real conflict; without
  `nodad`, an address sits in the kernel's "tentative" state (unusable for
  bind/connect) for the DAD window, which would otherwise make an
  immediately-following fixture bind flaky.
- Teardown (`teardown`) independently existence-checks each of the three
  resources it can remove — the nft table, the host-side veth link, the
  namespace itself — *before* attempting to remove it, rather than relying
  on the removal command's own exit code to distinguish "already absent"
  from "a genuine error". `namespace_exists`/`link_exists`/
  `nft_table_exists` each return `Result<bool, HarnessError>`, not a bare
  `bool`: `Ok(true)` means confirmed present, `Ok(false)` means confirmed
  absent (a stable, `C`-locale stderr pattern — e.g. `ip link show` on a
  nonexistent interface — is how iproute2 itself reports absence, so
  pattern-matching it is the correct, not a fallback, mechanism here), and
  `Err(_)` means the check itself failed for some other reason (tool
  missing, permission denied, unexpected output) and must not be silently
  treated as "absent". This is implemented via a small pure function,
  `classify_presence_output`, that maps an already-obtained
  `std::process::Output` to this three-way result and is unit-tested
  directly with synthetic outputs (including a non-matching-stderr case
  that must surface as a genuine error, not a false "absent"). `teardown`
  matches on all three outcomes per resource: only `Ok(false)` short-circuits
  that resource's removal step as already-done; `Err` is collected into the
  returned error list instead of masking a real problem as success. All
  `run()`/`run_checked()` invocations force `LC_ALL=C`/`LANG=C` so this
  stderr matching stays locale-independent. Both the explicit
  `live_netns_enforcement_proof` test and the injected-failure test call
  `teardown()` a second time after the first and assert it stays clean,
  proving idempotency concretely rather than by inspection.
- Both the agent and broker UIDs are spawned via `setpriv_argv`, which
  clears the inheritable, ambient, and bounding capability sets
  (`--inh-caps=-all --ambient-caps=-all --bounding-set=-all`) in addition to
  changing the UID/GID and setting `--no-new-privs` — see "Known
  limitation: raw sockets" above for how this is independently verified via
  `caps-probe`.
- The raw UDP probe (`netns-harness raw-attempt --protocol udp`) must
  account for one asymmetry versus TCP: a blocked TCP SYN is simply never
  answered (indistinguishable, from the client alone, from "nothing is
  listening"), but a netfilter `OUTPUT`-chain drop for a UDP socket can
  surface *synchronously* as `EPERM`/`ErrorKind::PermissionDenied` from
  `sendto()` itself. `classify_udp_send_error` treats that specific error
  as the `blocked_or_unreachable` signal, not an unrelated `local_error`
  (unit-tested for both the `PermissionDenied` case and every other error
  kind, which must still map to `local_error`). Because UDP is
  connectionless, every UDP/alternate-DNS-port denial assertion in the live
  suite is paired with a genuine UDP echo fixture and a positive control at
  the *exact same address/port tuple* reachable from the broker UID (or
  before the firewall is even applied), so a silent/unreachable false
  negative cannot be mistaken for a real firewall block.
- Gateway readiness (used before every scenario that depends on a freshly
  spawned `egress-gateway`) is a genuine liveness probe, not a fixed sleep:
  `wait_for_gateway_ready` polls, from inside the target namespace as the
  agent UID (the real consumer of these ports), the `netns-harness
  gateway-probe` subcommand, which performs an actual TCP connect to the
  CONNECT port and actual DNS queries (both UDP and TCP framing) against
  the DNS port, decoding the response through the same DNS crate the
  broker uses — a response is only counted as "ready" if it decodes as a
  syntactically valid DNS message, not merely "some bytes came back". Two
  failure modes are treated as hard, loud failures rather than silently
  retried: if the spawned gateway `Child` has already exited (checked via
  `try_wait()` on every poll iteration), the wait fails immediately with
  the captured stderr and exit status instead of continuing to poll a dead
  process; and if the `gateway-probe` command itself exits non-zero (a
  tooling failure — the binary is designed to always exit successfully and
  report per-protocol readiness in its JSON body, so a non-zero exit here
  means the invocation itself is broken, e.g. `ip`/`setpriv` failing), that
  is also a hard failure, not another "not ready yet" retry. Overall
  timeout is a panic, not a silent return, so a hung gateway cannot make a
  later assertion pass or fail for the wrong reason.

## Kernel/tool requirements

Linux kernel with network namespace and nftables (`nf_tables`) support,
plus the `ip` (iproute2), `nft` (nftables), and `setpriv` (util-linux)
binaries on `PATH`. Effective UID 0 (root) is required to create namespaces,
veth pairs, and to apply/remove the nftables table.

## Live test result

- **Local (this development session)**: macOS (arm64, Darwin 25.5.0). Both
  live Linux network-namespace tests (`live_netns_enforcement_proof`,
  `live_netns_injected_failure_cleanup` in `tests/live_netns.rs`) are gated
  to self-skip with an explicit, printed reason on any non-Linux host — they
  were executed locally and correctly reported the skip
  (`SKIP (documented limitation): ... current host OS is 'macos'`) rather
  than silently passing or claiming proof they did not perform. All portable
  unit/property/integration tests were run directly on this host and pass;
  see the "Verified in this session" table below. The local skip is not the
  proof result; the separate privileged Ubuntu CI execution below is.
- **CI (`ubuntu-24.04`, hosted GitHub Actions runner)**: **passed** in
  workflow run `29672453900`, job `88154015071`. The root capability verdict
  was `is_linux=true`, `is_root=true`, `iproute2=6.1.0`,
  `nftables=1.0.9`, and `setpriv=util-linux 2.39.3`; all required tools were
  available. `live_netns_enforcement_proof` and
  `live_netns_injected_failure_cleanup` both passed in 7.10 seconds with
  `SENDBOX_EGRESS_LIVE_REQUIRE=1`, so no capability skip was possible. The
  first test exercised the IPv4/IPv6 allow and bypass-deny matrix,
  alternate DNS, UDP, metadata, capability clearing, gateway crash,
  fail-closed ruleset persistence, and restart. The second intentionally
  panicked mid-run and then verified the gateway process and unique
  namespace were removed. The published capability artifact is
  `egress-enforcement-live-capability-verdict` from that run.

## Verified in this session (macOS host, no Linux/root available)

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | Clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | Clean |
| `cargo test --all-targets --all-features` | 111 lib tests + 4 `netns-harness` bin tests + 2 gated live-netns tests, all pass |
| `cargo build --release` | Succeeds; `egress-gateway` and `netns-harness` binaries produced |
| `cargo check --target x86_64-unknown-linux-gnu --all-targets --all-features` | Clean type-check of the Linux-only harness/live-test code paths from macOS |
| `cargo clippy --target x86_64-unknown-linux-gnu --all-targets --all-features -- -D warnings` | Clean |
| `cargo audit --file Cargo.lock` | 0 vulnerabilities (after pinning `hickory-proto` to `0.26.1`, which fixes RUSTSEC-2026-0119/0118 present in 0.25.x) |
| Manual `egress-gateway` + `dig` + `connect-attempt` end-to-end | Real DNS decode/encode/validate/authorize and CONNECT allow/deny/mismatch, and shared-authorization reuse across the two listeners, proven live — see "Runnable local behavior" above |
| Manual `netns-harness caps-probe`/`probe` | Correctly report `"unavailable"`/all-capabilities-false on macOS (no `/proc/self/status`, no `ip`/`nft`/`setpriv`) rather than panicking or fabricating a result |
| `gateway_probe_helpers_detect_a_real_running_broker_pair` / `..._report_not_ready_with_nothing_listening` (`src/bin/netns_harness.rs`) | Directly exercise the `gateway-probe` DNS (UDP+TCP) and CONNECT readiness checks against a real running broker pair and against nothing listening, without needing a namespace |
| `tests/live_netns.rs` (both tests: the netns/nftables/UID proof and the injected-failure cleanup proof) | Correctly self-skip locally on macOS; both passed under root on Ubuntu 24.04 in CI run `29672453900` |
