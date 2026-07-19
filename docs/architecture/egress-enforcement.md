# Production egress enforcement architecture (`sendbox-egress`)

Status: **production foundation**. This document describes the architecture of
the `sendbox-egress` crate, which promotes the proven
`spikes/egress-enforcement` mechanism into a production workspace crate. The
spike is left intact for reference; nothing here depends on it.

The companion document
[`docs/security/egress-enforcement-trust-boundary.md`](../security/egress-enforcement-trust-boundary.md)
covers the trust boundary, threat model, residual risks, and the runtime
integration contract.

## Goals

Constrain a sandboxed agent's outbound network access to exactly what a
[`sendbox_policy::NetworkPolicy`](../../crates/sendbox-policy/src/lib.rs)
permits, and do so with a mechanism that:

- fails closed — no agent traffic is possible until every control is armed and
  verified;
- ties enforcement to a **kernel-stable process identity** (cgroup v2), not a
  shared UID that any process could assume;
- validates DNS answers and pins the exact validated address, defeating DNS
  rebinding;
- bounds DNS query-name exfiltration deterministically, without entropy
  heuristics;
- forbids `unsafe` Rust and never shells out.

## Two layers

### Portable policy core (all platforms)

| Module | Responsibility |
|---|---|
| `address` | Classifies destination addresses (loopback, link-local, RFC 1918, ULA, multicast, cloud metadata, unspecified) and canonicalizes IPv4-mapped IPv6. |
| `domain` | RFC 1035 domain normalization and exact/wildcard pattern matching. |
| `policy` | Compiles `sendbox_policy::NetworkPolicy` into a `PolicyEngine` of deterministic, side-effect-free decisions. |
| `authorization` | Bounded, expiring `(name, ip)` authorization cache — the anti-rebinding pin. Prunes expired entries on insert and enforces a deterministic hard capacity derived from the DNS budget. |
| `resolver` | The injectable `UpstreamResolver` trait and `ResolvedChain`. |
| `forwarding_resolver` | Bounded, fixed-upstream forwarding resolver: connects its UDP socket to the exact upstream so a reply must match the full address **and** port (not just IP), validates response id/question, bounds records/CNAME depth, retries over TCP on truncation, and merges A/AAAA only when their CNAME chain and final owner agree. |
| `dns_budget` | Deterministic, bounded DNS exfiltration controls (structural limits, QTYPE allowlist, response cap, per-window budgets). |
| `connect_proto` | The small, versioned, bounded CONNECT framing protocol. |
| `socks5` | A bounded SOCKS5 (RFC 1928) front end: no-auth negotiation, CONNECT only. |
| `dns_broker` | Loopback DNS broker: decodes/validates/authorizes, applies budgets, emits audit events. |
| `connect_broker` | Loopback CONNECT broker: selectable front end, pins the validated address, re-checks the port-aware decision, dials via a `Dialer`, proxies bytes. |
| `gateway` | Colocates both brokers so they share one `AuthorizationCache`, engine, guard, and audit sink. |
| `audit` | Typed, deterministic, serializable audit events and sinks. |
| `dialer` | The `Dialer` abstraction and `SO_MARK`-aware socket helpers. |

The core performs no privileged operations and is exercised by the unit tests in
each module plus the portable `tests/gateway_integration.rs` suite.

### Linux enforcement layer (`cfg(target_os = "linux")`)

| Module | Responsibility |
|---|---|
| `linux::cgroup` | Supervisor-owned stable cgroup v2 hierarchy (`sendbox/<instance>/{agent,broker}`); creates, places pids, and tears down. |
| `linux::mark` | `SO_MARK` socket helpers (via `socket2`) and the `MarkDialer`. |
| `linux::nft` | Deterministic nftables rendering keyed on `socket cgroupv2` + `meta mark`; atomic apply/validate/cleanup/verify via `nft -f -` (stdin, no shell, no temp files). |
| `linux::preflight` | cgroup v2, `nft socket cgroupv2` support, `CAP_NET_ADMIN`, and `SO_MARK` probes. |
| `linux::supervisor` | The armed guard enforcing setup ordering, teardown, and atomic update/rollback. |

## Identity: cgroup v2 + `SO_MARK`, never `meta cgroup`

The spike keyed nftables on `meta skuid` (UID). Any process sharing that UID
could originate broker-class traffic. The production layer instead keys on
`socket cgroupv2 level N "path"`:

- The supervisor owns a stable hierarchy `sendbox/<instance>/agent` and
  `sendbox/<instance>/broker` under the cgroup v2 root. The `level` in each
  nftables rule equals the number of path components.
- The **agent cgroup** may only originate traffic to the loopback DNS and
  CONNECT broker ports.
- The **broker cgroup** may originate external traffic **only when the socket
  also carries the fixed `SO_MARK`** (`meta mark`), and never to cloud-metadata
  addresses.

`meta cgroup` (cgroup v1 `net_cls`) is deliberately never emitted; a test
asserts its absence.

Because SO_MARK must be set on *every* broker-originated external socket, both
the CONNECT broker's dials (`MarkDialer`) and the DNS forwarding resolver's
upstream sockets (`ForwardingResolverConfig::with_socket_mark`) apply the mark.

## Broker front ends

The CONNECT broker speaks one of two client-facing protocols, selected once per
instance via `ConnectBrokerConfig::frontend` (never auto-detected from the first
bytes, which would be ambiguous and attacker-influenceable):

- `ConnectFrontend::Custom` (default) — the crate's small, versioned, bounded
  framing (`connect_proto`), which also carries an optional client `expected_ip`
  consistency check.
- `ConnectFrontend::Socks5` — standard SOCKS5 (RFC 1928), no-authentication
  negotiation, `CONNECT` only. `BIND` and `UDP ASSOCIATE` are refused with
  `Command not supported`, which is how UDP/QUIC is denied at the SOCKS layer.

Both front ends funnel through the *same* `authorize_and_dial` path: resolve and
pin a hostname (or validate a direct IP), re-check the full port-aware policy
decision, and dial the exact validated `SocketAddr` through the `Dialer`. Only
the wire framing and the reply-code mapping differ. A runtime selects the SOCKS5
front end when the agent toolchain speaks standard SOCKS5 (e.g. an
`ALL_PROXY=socks5h://host:port` environment), and the default custom front end
otherwise. The SOCKS5 success reply reports the broker's *upstream* socket local
endpoint in `BND.ADDR`/`BND.PORT` (`upstream.local_addr()`, per RFC 1928 §6),
not the requested destination; the custom front end sends no bound address, so
this does not weaken it.

A fresh hostname resolution on the CONNECT path is not a policy bypass: it runs
the name through the *same* shared `DnsGuard` as the DNS broker — structural
QNAME limits, the QTYPE allowlist, the response-record cap, and the
deterministic exfiltration budget — and audits any denial or rate limit. When
`allow_dns = false` the CONNECT broker performs no fresh resolution at all and
relies solely on prior cached authorizations, so disabling DNS truly closes the
resolution path.

## Descriptor-relative cgroup operations

Every cgroup filesystem operation is **descriptor-relative and symlink-race
resistant**. `linux::cgroup` opens the cgroup v2 root once as a capability
`cap_std::fs::Dir` and performs all hierarchy creation, `cgroup.procs` writes,
and removals relative to that descriptor. `cap-std` confines resolution beneath
the opened root (Linux `openat2`/`RESOLVE_BENEATH`), so a symlink planted under
the root can never redirect an operation outside it; a regression test proves an
escaping symlink is refused.

## Safe setup ordering (never fail open)

`ArmedEgress::arm` performs, in order:

1. **Preflight** — cgroup v2 mounted, `nft socket cgroupv2` supported,
   `CAP_NET_ADMIN` held, `SO_MARK` settable. Any gap is a hard error.
2. **Create the stable cgroup hierarchy.**
3. **Validate** the rendered ruleset with `nft --check -f -` against the real
   cgroup paths (the definitive `socket cgroupv2` support/resolution check).
4. **Apply** the ruleset atomically with `nft -f -`.
5. **Verify** the owned table is installed (`nft list table`).
6. Only then return the `ArmedEgress` guard.

Any failure at or after step 2 best-effort unwinds only what *this call* created
and returns an error. Because a failed `nft` apply is atomic (the whole
transaction rolls back), a failed **re-arm** of an already-live instance
preserves the previous owned table — the supervisor never runs `nft` cleanup on
an apply failure — and leaves that instance's cgroups untouched, so a transient
re-arm failure cannot strip live enforcement. Holding the guard is the
precondition for placing and starting the agent. Dropping the guard tears
everything down.

## Atomic apply / update / rollback and fail-closed teardown

`NftConfig::render_transaction` emits `destroy table` followed by a fresh table
definition, applied as one `nft -f -` transaction. `nft` applies a file
atomically, so any error aborts the whole update and leaves the **previous**
table intact — never a partial ruleset. `ArmedEgress` keeps the last-known-good
`NftConfig` in memory:

- `update(new)` validates then applies; on success it becomes the new
  last-known-good, on failure the previous table survives untouched;
- `rollback()` re-applies the last-known-good;
- `teardown()` is **fail-closed ordered** and **retryable**: it removes/verifies
  the owned cgroups *first*; only once they are gone does it remove the nftables
  table. The cgroup and nftables stages are tracked independently, so if cgroup
  cleanup reports any real error (e.g. a process still occupies a cgroup) the
  nftables table is **retained** so that process cannot regain unrestricted
  egress, the error is surfaced, and a later call retries; likewise, if the
  cgroups are gone but the nftables `destroy` fails, a later `teardown()` skips
  the completed cgroup step and retries only the table removal. The top-level
  owned `sendbox` cgroup directory is removed when empty and tolerated when a
  sibling instance still owns it. It is idempotent and absent-safe.

## Data flow (armed sandbox)

```text
agent ──(loopback)──▶ DNS broker ──validate name/CNAME/addr, budget, cap TTL──▶ resolver
     ◀── pinned answer ── records (name,ip) authorization ──┐
                                                            │ shared AuthorizationCache
agent ──(loopback CONNECT)──▶ CONNECT broker ──pin validated ip, re-check policy──▶
                                    dial (SO_MARK) ──▶ upstream
```

nftables drops any agent packet that is not headed to a loopback broker port,
and any broker external packet that lacks the mark or targets metadata.

## Policy source of truth

`sendbox_policy::NetworkPolicy` remains authoritative. The crate adds only
`#[serde(default)]` fields (`allowed_networks`, `blocked_networks`,
`allowed_ports`, and a nested `dns` block), so every previously valid policy
document still parses unchanged. `allow_dns = false` binds no DNS broker and
installs no nftables DNS accept rule.

Compilation and validation fail closed rather than substituting a
success-shaped default for an invalid value:

- `max_connections: Option<i64>` maps via `resolve_max_connections` — `None` to
  the documented default (100), but a non-positive value or one above the
  supported ceiling (`MAX_CONNECTIONS_CEILING`, or `u32`) is a deterministic
  `PolicyError`, never silently clamped or defaulted.
- Every DNS structural limit and per-window budget is range-checked at both
  `sendbox_policy::PolicyConfiguration::validate` and `PolicyEngine::compile`:
  `max_qname_octets` ∈ 1..=253, `max_label_octets` ∈ 1..=63, positive
  `max_labels`/`max_response_records`/all budget counters, a positive
  `max_ttl_secs`/`window_secs`, and a non-empty QTYPE allowlist. Any zero or
  out-of-range field is a deterministic error.

## Testing and qualification

- Portable unit tests live beside each module; portable integration tests are in
  `tests/gateway_integration.rs`. Both run on macOS and Linux.
- The privileged live proof is `tests/live_netns.rs`, gated by
  `target_os = "linux"`, `SENDBOX_EGRESS_LIVE=1`, and a full `Preflight` (plus
  `setpriv`). It proves cgroup identity isolation, the mark requirement,
  sibling/identity-spoof denial, direct-egress bypass denial, non-vacuous
  IPv6/UDP denial with reachable positive controls, an **unprivileged agent**
  (dropped via `setpriv` with all capabilities cleared and `no_new_privs`, whose
  raw-socket creation is denied), **marked upstream DNS with a UDP-truncation →
  TCP fallback** through a real `ForwardingResolver`, a **real kernel
  apply-time-failure rollback** (an update ruleset references a candidate cgroup
  that passes `--check`, is deleted immediately before the genuine `nft -f -`
  commit so the real transaction fails to resolve it, and the previous table is
  shown to survive before an explicit disrupt/rollback restores enforcement),
  and broker restart. Teardown surfaces errors, which the test asserts are
  empty, then verifies every namespace/veth/table/cgroup resource is absent
  after normal, repeated, and injected-panic cleanup. On a host that cannot
  enforce it fails loudly when `SENDBOX_EGRESS_LIVE_REQUIRE=1` (the CI job),
  never a silent skip.
- The harness itself reads its policy/fixture config with `O_NOFOLLOW` (or an
  inherited descriptor) **before** any cgroup/namespace transition, so a symlink
  swap or predictable-path reopen after a transition cannot influence it. The
  live harness's config files are exclusive, unpredictable, mode-0600 temporary
  files (via `tempfile`, `O_EXCL`), retained for the run and cleaned up — with
  absence assertions — in teardown, never predictable `/tmp/<name>-<pid>` paths.
- The macOS development host cannot run the privileged suite; CI runs it on a
  privileged Ubuntu x86_64 runner.
