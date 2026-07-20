# Egress enforcement trust boundary and runtime integration contract

Status: **production foundation**. Companion to
[`docs/architecture/egress-enforcement.md`](../architecture/egress-enforcement.md).
This document defines the trust boundary of `sendbox-egress`, its threat model,
the residual risks it does *not* close, and the contract a runtime supervisor
must satisfy to integrate it.

## Trust boundary

```text
┌─────────────────────────── sandbox network namespace ───────────────────────────┐
│                                                                                  │
│  UNTRUSTED                          TRUSTED (this crate)                          │
│  ┌───────────────┐   loopback only  ┌──────────────────────────────────────┐     │
│  │ agent process │ ───────────────▶ │ egress gateway (DNS + CONNECT brokers)│──┐  │
│  │ (agent cgroup)│ ◀─────────────── │ (broker cgroup + SO_MARK)             │  │  │
│  └───────────────┘                  └──────────────────────────────────────┘  │  │
│         │  ▲  everything else dropped by nftables default policy               │  │
│         ▼  │  (cgroup identity + mark enforced in the kernel)                  ▼  │
│     ✗ direct egress                                             external network │
└──────────────────────────────────────────────────────────────────────────────────┘
```

- **Untrusted:** the agent process and anything it spawns. It is confined to the
  agent cgroup and may reach *only* the loopback DNS and CONNECT broker ports.
- **Trusted:** the broker/gateway (in the broker cgroup, marking its external
  sockets) and the supervisor that arms enforcement. The broker enforces
  `PolicyEngine` in userspace; nftables enforces identity + reachability in the
  kernel as defense in depth.
- The boundary is a Linux network namespace with the crate-owned nftables table.
  The crate never modifies anything outside its owned table, cgroup subtree, and
  namespace.

## What the kernel layer enforces

- The agent cgroup can originate traffic **only** to the exact loopback broker
  ports (CONNECT always; DNS only when `allow_dns = true`).
- The broker cgroup can originate external traffic **only** when the socket
  carries the fixed `SO_MARK`, and never to cloud-metadata addresses.
- Any other process (a sibling in neither cgroup) is denied both the broker
  ports and external egress. This is the concrete improvement over UID-based
  isolation: sharing a UID no longer grants broker-class reachability.
- New inbound to the broker's own loopback ports is scoped by `iif lo` + exact
  destination + port. The originating identity is not visible at the input hook,
  but the **output** chain already prevents any non-agent cgroup from
  originating that traffic in the first place.
- All UDP/QUIC from the agent (other than DNS to the broker) is dropped; the
  CONNECT broker additionally answers `UnsupportedProtocol` (native protocol) or
  `Command not supported` (SOCKS5 `BIND`/`UDP ASSOCIATE`) for any non-TCP
  request. Raw `AF_PACKET` sockets operate below the IP layer and are **not**
  visible to the `inet` filter hooks — dropping `CAP_NET_RAW` from the agent is
  the runtime's responsibility (see contract below).

## What the userspace brokers enforce

- A selectable client-facing front end (`ConnectFrontend`): the crate's native
  bounded CONNECT framing (default) or standard SOCKS5 (RFC 1928, no-auth,
  `CONNECT` only). The front end is fixed per instance from configuration, never
  auto-detected from client bytes. Both front ends enforce policy through the
  identical resolve/pin/decide/dial path; only the wire framing differs.
- Domain allow/deny with blocked-domain precedence and wildcard rules that never
  match an apex or an unrelated suffix.
- An address-class check no domain grant can override; a restricted class
  (loopback, link-local, RFC 1918, ULA, multicast, metadata, unspecified) needs
  an explicit IP/CIDR grant.
- IPv4-mapped-IPv6 canonicalization so a blocked/allowed CIDR cannot be bypassed
  or missed through address encoding.
- DNS validation of every CNAME hop and returned address, TTL capping, and an
  expiring `(name, ip)` authorization that pins the exact validated address —
  a later CONNECT can only use an address a DNS answer actually validated,
  defeating rebinding.
- Deterministic DNS query-name exfiltration budgets: total QNAME/label limits, a
  QTYPE allowlist, a response-record cap, and per-window query-count, query-octet,
  distinct-name, and distinct-dynamic-label budgets with bounded state. Every
  structural/budget field is range-validated (fail closed) at compile time.

## Threat model and mitigations

| Threat | Mitigation |
|---|---|
| Direct outbound bypassing the broker | Kernel default-drop; agent cgroup reaches only loopback broker ports. |
| Sharing the broker's identity to egress | cgroup v2 identity + required `SO_MARK`; a sibling process is denied. |
| DNS rebinding | Expiring `(name, ip)` authorization pins the exact validated address. |
| SSRF to cloud metadata | Address-class denial in policy **and** an explicit kernel drop for the broker. |
| DNS-tunneling exfiltration | Deterministic, bounded structural limits and per-window budgets. |
| Broker crash leaving traffic open | Rules persist on broker death (fail closed); the guard re-arms on restart. |
| Partial/failed ruleset update | Atomic `destroy + create` transaction; a failed update leaves the previous table intact. A failed **re-arm** never runs `nft` cleanup, so a live instance's table is preserved rather than destroyed. |
| Lingering process during teardown | Fail-closed teardown removes cgroups first; if a cgroup still holds a process, the nftables table is **retained** (the process cannot regain egress) and the error is surfaced. Teardown is retryable: cgroup and nftables removal are tracked independently, so a later call retries whichever stage failed. |
| Off-path DNS response spoofing | The forwarding resolver connects its UDP socket to the exact upstream, so the kernel drops any reply whose source is not the full upstream `SocketAddr` (address **and** port), not merely the same IP. |
| Symlink race on cgroup paths | All cgroup filesystem operations are descriptor-relative via `cap-std` (`RESOLVE_BENEATH`); an escaping symlink under the root is refused. |
| Raw-socket egress bypass | The agent runs unprivileged with `CAP_NET_RAW` dropped; the live suite asserts every capability set is empty and that raw-socket creation is denied. |
| Unbounded DNS-only cache growth | The authorization cache prunes expired entries on insert and enforces a deterministic hard capacity derived from the DNS budget. |
| CONNECT resolution bypassing DNS controls | A fresh CONNECT-path resolution applies the same `DnsGuard` (structural limits, QTYPE allowlist, response cap, budget); with `allow_dns = false` it does not resolve at all. |
| Slowloris / floods | Bounded handshakes, per-message caps, bounded concurrency, inline (never spawned) rejections. |

## Residual risks (explicitly not closed)

- **Metadata by hostname over an uncovered address.** The metadata address list
  (`address::METADATA_V4_ADDRESSES` / `METADATA_V6_ADDRESSES`) is deterministic
  but not exhaustive. A provider that serves metadata purely by a hostname
  resolving to an address not on the list must be blocked with `blocked_domains`.
- **Query-name exfiltration within budget.** The budgets bound exfiltration
  bandwidth deterministically; they do not make a broad `allowed_domains` policy
  safe. A narrow allowlist remains the primary control.
- **Raw sockets.** `AF_PACKET` is below the IP filter hooks; the runtime must
  drop `CAP_NET_RAW` (and generally run the agent unprivileged). The live suite
  proves this by running the agent under `setpriv` with all capability sets
  cleared and `no_new_privs`, then asserting raw-socket creation is denied — but
  the *production* runtime is still responsible for the equivalent privilege
  drop.
- **Loopback upstream resolvers.** The forwarding resolver's upstream must be
  external (reached via the marked broker path), not a loopback service inside
  the sandbox namespace, which the input chain does not admit.
- **Capability/privilege of the agent.** cgroup identity does not drop
  capabilities; privilege drop is the runtime supervisor's job.
- **Inherited configuration descriptors.** The harness accepts a pre-opened
  `--policy-fd` / `--fixtures-fd` and otherwise reads with `O_NOFOLLOW` before
  any namespace/cgroup transition. Stable Rust's `std::process::Command` cannot
  pass an arbitrary inherited fd to a child across a `setpriv`/`ip netns exec`
  re-exec, so the live path reads config in-process before transitions rather
  than reopening a predictable path afterward.

## Runtime integration contract

A runtime supervisor integrating this crate must:

1. Create the sandbox network namespace and any veth/routing before arming.
2. Call `ArmedEgress::arm` (or `arm_under` with a namespace-scoped `NftRunner`).
   It refuses to arm unless enforcement is fully installed and verified.
3. Retain `CAP_NET_ADMIN` in the namespace for the broker (to set `SO_MARK` and
   load nftables); preflight probes this.
4. Start the **broker** placed in the broker cgroup (`place_broker`), configured
   with the `MarkDialer` and a `ForwardingResolver` carrying the same mark. Pick
   the CONNECT front end (`ConnectFrontend::Custom` or `Socks5`) to match the
   agent toolchain (e.g. SOCKS5 when the agent honors `ALL_PROXY=socks5h://…`);
   the choice is fixed configuration, never negotiated from client bytes.
5. Only **after** the guard is armed and verified, place and start the **agent**
   in the agent cgroup (`place_agent`). Never start the agent behind an
   unverified ruleset.
6. Run the agent unprivileged with `CAP_NET_RAW` dropped (raw sockets are out of
   the `inet` hooks' scope) and `no_new_privs` set.
7. Keep the broker cgroup stable across broker process restarts — re-place the
   new pid, do not recreate the cgroup, so the loaded nftables cgroup ids stay
   valid.
8. On shutdown, stop the agent, then drop/`teardown` the guard. Teardown is
   fail-closed ordered (cgroups before nftables), idempotent, and absent-safe;
   a surfaced error means enforcement was deliberately retained and must be
   logged and retried, not ignored.

The crate deliberately does **not** integrate any specific runtime or guest
supervisor, implement credentials or TLS interception, or use BPF or seccomp;
those remain the responsibility of the surrounding system.
