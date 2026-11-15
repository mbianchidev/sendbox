# Production egress enforcement architecture (`sendbox-egress`)

Status: **production runtime integration**. This document describes the
`sendbox-egress` crate and its authenticated host/guest composition, which
promotes the proven
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
- gives the package registry proxy a third kernel identity that can reach only
  its trusted loopback SOCKS gateway;
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
| `forwarding_resolver` | Bounded, fixed-upstream forwarding resolver: connects UDP to the exact upstream address **and** port, validates response id/question, bounds records/CNAME depth, recovers over the same upstream's TCP on truncation or UDP silence within the original deadline, and merges A/AAAA only when their CNAME chain and final owner agree. |
| `dns_budget` | Deterministic, bounded DNS exfiltration controls (structural limits, QTYPE allowlist, response cap, per-window budgets). |
| `connect_proto` | The small, versioned, bounded CONNECT framing protocol. |
| `socks5` | A bounded SOCKS5 (RFC 1928) front end: no-auth negotiation, CONNECT only. |
| `dns_broker` | Loopback DNS broker: decodes/validates/authorizes, applies budgets, emits audit events. |
| `connect_broker` | Loopback CONNECT broker: selectable front end, pins the validated address, re-checks the port-aware decision, dials via a `Dialer`, proxies bytes. |
| `gateway` | Colocates both brokers so they share one `AuthorizationCache`, engine, guard, and audit sink. |
| `github_meta` | Validates whole official Meta documents and host-supplied seeds; owns expiring immutable snapshots and provenance. |
| `github_meta_client` | Host-side anonymous fixed-origin HTTPS: system DNS, exact-IP direct dials, verified TLS, bounded bodies, rate-limit detection, and no redirects or environment proxy. |
| `audit` | Typed, deterministic, serializable audit events and sinks. |
| `dialer` | The `Dialer` abstraction and `SO_MARK`-aware socket helpers. |
| `runtime` | Session-derived authenticated runtime policy, stable instance/table/mark identity, execution-cgroup parent, and exact proxy environment. |

The core performs no privileged operations and is exercised by the unit tests in
each module plus the portable `tests/gateway_integration.rs` suite.

### Linux enforcement layer (`cfg(target_os = "linux")`)

| Module | Responsibility |
|---|---|
| `linux::cgroup` | Supervisor-owned stable cgroup v2 hierarchy (`sendbox/<instance>/{agent,broker,registry}`), with optional `pids`/`memory`/`cpu` delegation through the agent ancestor for descendant execution leaves. |
| `linux::mark` | `SO_MARK` socket helpers (via `socket2`) and the `MarkDialer`. |
| `linux::nft` | Deterministic nftables rendering keyed on `socket cgroupv2` + `meta mark`; atomic apply/validate/cleanup/verify via `nft -f -` (stdin, no shell, no temp files). |
| `linux::preflight` | cgroup v2, `nft socket cgroupv2` support, `CAP_NET_ADMIN`, and `SO_MARK` probes. |
| `linux::supervisor` | The armed guard enforcing setup ordering, teardown, and atomic update/rollback. |

## Identity: cgroup v2 + `SO_MARK`, never `meta cgroup`

The spike keyed nftables on `meta skuid` (UID). Any process sharing that UID
could originate broker-class traffic. The production layer instead keys on
`socket cgroupv2 level N "path"`:

- The supervisor owns a stable hierarchy `sendbox/<instance>/agent`,
  `sendbox/<instance>/broker`, and `sendbox/<instance>/registry` under the
  cgroup v2 root. The `level` in each nftables rule equals the number of path
  components.
- The **agent cgroup ancestor**, including every nested execution leaf beneath
  it, may only originate traffic to the loopback DNS and public CONNECT broker
  ports plus the workload-facing npm proxy port when package analysis is
  enabled.
- The **broker cgroup** may originate external traffic **only when the socket
  also carries the fixed `SO_MARK`** (`meta mark`), and never to cloud-metadata
  addresses.
- The **registry cgroup** may originate traffic only to the registry-only
  loopback SOCKS port. It cannot reach the public broker ports, external
  destinations, or obtain the broker mark.

`meta cgroup` (cgroup v1 `net_cls`) is deliberately never emitted; a test
asserts its absence.

Production execution uses:

```text
/sys/fs/cgroup/sendbox/<instance>/agent/<session>/<command>
```

The nftables identity remains the level-3 `agent` ancestor, so every execution
descendant inherits the same network boundary. The agent ancestor is an internal
cgroup: direct process placement is rejected once controllers are delegated.

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
- `ConnectFrontend::Http` — bounded HTTP/1.x CONNECT plus absolute-form HTTP
  forwarding, with matching authority/Host validation and strict body framing.
  Proxy credentials and ambiguous framing are rejected.

All front ends funnel through the *same* `authorize_and_dial` path: resolve and
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

### Resolver loss handling and diagnostics

The forwarding resolver gives each concurrent A/AAAA query one absolute
three-second deadline. A missing UDP reply is retransmitted once halfway
through that budget, preserving the connected socket, upstream, socket mark,
question and ID. If UDP is still pending at that halfway boundary, one TCP
exchange also starts against the same numeric upstream and port, with the same
question/ID and socket mark. UDP remains live; a TCP transport failure cannot
discard its later valid reply. A validated UDP truncation flag starts TCP
immediately instead. Socket setup, both UDP sends and that one TCP exchange
consume the original budget; no phase restarts it. Complete TCP responses still
require exact header/question validation and a clear truncation bit. Permanent
response errors and invalid replies fail closed, not a later-answer fallback.

Both family results must complete before CNAME agreement and policy validation
can authorize any address. A timeout, cancellation, or denied CNAME does not
prime the shared authorization cache. The brokers retain their separate
five-second upstream-resolution bounds and cancellation gates.

Resolver failures retain typed, sanitized query/transport/operation and OS-code
metadata in `DnsResolutionFailed` audit events. HTTP CONNECT keeps status 502
but returns a DNS `Proxy-Status` and bounded JSON diagnostic; free-form upstream
errors and packet contents are excluded. SOCKS/native status bytes do not
change. See [cold-start qualification](../dns-cold-start.md) for the distinction
between local service readiness, an external DNS failure and controlled loss
testing.

## Descriptor-relative cgroup operations

Every cgroup filesystem operation is **descriptor-relative and symlink-race
resistant**. `linux::cgroup` opens the cgroup v2 root once as a capability
`cap_std::fs::Dir` and performs all hierarchy creation, `cgroup.procs` writes,
and removals relative to that descriptor. `cap-std` confines resolution beneath
the opened root (Linux `openat2`/`RESOLVE_BENEATH`), so a symlink planted under
the root can never redirect an operation outside it; a regression test proves an
escaping symlink is refused.

### cgroup identity and the required nft mount view

The hierarchy is created directly under the mounted cgroup v2 root
(`<root>/sendbox/<instance>/…`), so the `CgroupIdentity` nftables matches on is
exactly that **mount-relative** path: nftables userspace *stats*
`/sys/fs/cgroup/<identifier>` to resolve a `socket cgroupv2` rule, and the kernel
adds the current cgroup-namespace subtree level internally — it is not a
process-cgroup-prefixed global path. The same mount-relative path is reused for
the filesystem operations and for the agent, broker, and registry process
placement accessors.

Because that resolution is a userspace `stat` in nft's *own* mount namespace,
whatever executes `nft` must keep the supervisor's mount view of
`/sys/fs/cgroup`. The live harness therefore runs nft with
`nsenter --net=/var/run/netns/<ns> -- nft …`, which enters only the target
**network** namespace. `ip netns exec` must **not** be used here: it additionally
unshares the mount namespace and remounts `/sys`, hiding the owned cgroups from
nft's `stat` and yielding `cgroupv2 path fails: No such file or directory` even
though the network namespace is correct. The live suite gates on `nsenter`
availability (util-linux).

## Safe setup ordering (never fail open)

`ArmedEgress::arm` performs, in order:

1. **Preflight** — cgroup v2 mounted, `nft socket cgroupv2` supported,
   `CAP_NET_ADMIN` held, `SO_MARK` settable. Any gap is a hard error.
2. **Create the stable cgroup hierarchy** and, for production execution,
   delegate required controllers through
   `root -> sendbox -> instance -> agent`.
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

## Authenticated production composition

The host derives a schema-v5 `RuntimePolicyDocument` from the authenticated
session ID, configured `NetworkPolicy`, any remote MCP origins, and any package
registry isolation. Apple and Kata bind that exact document into guest bootstrap
together with the matching execution broker cgroup parent. The guest rejects
session, cgroup, gateway-port, reserved-origin, registry, or direct-IP-policy
drift before starting any service.

The guest supervisor makes Egress a mandatory service and makes Exec depend on
it. The egress supervisor:

1. validates and consumes its root-owned configuration;
2. recovers the original resolver from root-owned state under `/run/sendbox`;
3. starts gateway children that bind the public DNS/SOCKS listeners, the
   optional trusted MCP HTTP listener, and the optional registry-only SOCKS
   listener, but do not serve yet;
4. arms delegated cgroups and nftables, then places only the gateways in the
   broker cgroup;
5. starts the npm proxy as UID/GID 65532 in the registry cgroup with cleared
   capabilities, no `SO_MARK`, and a bounded seccomp/resource profile;
6. authorizes the gateways and proxy to serve, installs loopback resolver
   configuration, and only then publishes readiness.

Workloads receive exact upper- and lower-case `ALL_PROXY`/`NO_PROXY` and
`HTTP_PROXY`/`HTTPS_PROXY` variables, plus fixed `NODE_USE_ENV_PROXY=1`.
The HTTP listener on port 15083 and SOCKS listener on 15080 share the same
authorization cache, DNS guard, semaphore, and marked dialer. Both ports are
signed and pairwise distinct from DNS, MCP, and package ports.
A brokered [governed session](governed-sessions.md) adds the signed credential
relay port 15084, also pairwise distinct, which nftables admits only from the
agent cgroup to loopback.
The authenticated stdio MCP broker receives the same fixed proxy environment,
so local servers remain descendants of execution leaves and cannot bypass
enforcement. The remote MCP gateway remains in the broker cgroup and uses
marked exact-address dials rather than the agent-facing CONNECT cache.
Package-enabled workloads also receive upper- and lower-case npm registry and
`ignore-scripts` variables. The public gateway uses a derived policy that denies
the configured npm upstream; the trusted registry gateway keeps the original
policy and is reachable only from the registry cgroup.
Shutdown runs in reverse dependency order: Exec is fully stopped before Egress
restores resolver state and attempts cgroup-then-nftables teardown. All service
shutdown failures are aggregated rather than abandoning later cleanup.

### GitHub Meta delegation and refresh

An effective exact `github.com` grant delegates to the fixed official Meta API.
Compilation stays offline and immutable for configured rules.

**The host owns the only fetch.** Each gateway used to fetch Meta before
readiness, so every session cost one or two anonymous requests against
GitHub's limit of 60 per hour per IP address. Many short sessions exhausted it
and then failed with HTTP 403. Now `sendbox-host` keeps one machine-wide cache
in the private runtime state root (`~/.sendbox/run/github-meta.json`, mode
`0600`, guarded by an exclusive `flock` on `github-meta.lock`):

- A response validated less than an hour ago is reused without a request, so
  concurrent and back-to-back sessions share it.
- An older response is revalidated with its ETag: a `304` renews it, a `200`
  replaces it after full validation, and the cache costs at most one request
  per hour per machine.
- A failed refresh is recorded with its time and typed error. Retries wait 60
  seconds, or until the published reset for a rate limit (403/429 with
  `x-ratelimit-remaining: 0` or `retry-after`), capped at one hour.
- During a failure the previous document is reused only while at least 15
  minutes remain before its 24-hour expiry, so it outlives guest boot plus one
  bounded execution. Otherwise the session fails with the typed error,
  including the rate-limit reset time.
- Every cached document is reparsed with the strict validator on read. A
  corrupt or tampered cache is discarded, never granted.

The host also refuses delegation when a role denies the fixed source: an
explicit `api.github.com` deny, disabled DNS, or a TCP/443 exclusion. Role
address and network controls govern guest traffic, not this host request.

The validated body, ETag, validation time, and latest attempt and error form a
`GitHubMetaSeed`. Its SHA-256 is bound into the signed `network_github_meta`
admission (`host_seeded_official_https_meta_v2:sha256=...`). The seed travels in
bootstrap schema v5, whose limit grows from 2 MiB to 5 MiB to fit a maximum
document. The guest supervisor writes it once to a root-owned `0400` file beside
the egress configuration. Each gateway reads it, revalidates the full document,
and installs it **after** its marked identity is armed and **before**
readiness. Guests never contact GitHub, and no refresh task runs in the guest:
an execution is capped at 300 seconds, far below the hourly interval.

The parser explicitly reviews the documented CIDR fields plus the live
`shared_ingress` field, the arrays under `domains`, the full/wildcard inbound
Actions domains, and artifact-attestation `services`. SSH/commit keys and
`trust_domain` identities never become routes. Unknown fields or any invalid
destination reject the complete candidate. Limits are 2 MiB, 16,384 network
entries and 4,096 domain entries before deduplication; default routes are
rejected. The source is API version `2022-11-28`, not a caller-supplied URL.

Each request evaluates one immutable scope view. DNS pins carry its revision;
every installed seed changes that revision, and an expiry produces a
scope-less view. New CONNECTs therefore cannot reuse authorizations for removed
CNAMEs. In-flight resolutions and dials recheck their revision. Explicit
domain/network denies, restricted-address checks, ports, DNS controls, MCP
reservations and trusted-registry separation remain authoritative. Published
networks only add public direct-IP reachability; they never unlock a
restricted address class or authorize an unlisted hostname.

A missing or invalid seed is fatal to the gateway. Expiry is 24 hours after the
host's last successful fetch or conditional revalidation. The gateway converts
the remaining time into a monotonic deadline at install time, because a freshly
booted guest cannot backdate an `Instant`, and checks it on every new view.
Seeds validated more than five minutes in the guest's future are rejected. The
status distinguishes pending, fresh, degraded (the host reused last-good after
a failed revalidation), unavailable and expired. The previous digest/scope
remains diagnostic after expiry, but has no granting power. Existing tunnels
retain their original 300-second bound.

Before activating a seed, production atomically publishes its full status to a
root-owned `0600` file under the existing private session directory.
Publication failure revokes derived scope and is fatal to the gateway.
`AuditSink::record_github_meta` is fallible; the normal typed JSON event is also
emitted. Unlike ordinary captured stderr counts, these files feed the bounded
authenticated `network.report` operation and final CLI JSON evidence. The
report includes the configured policy next to the latest published scope and
its URL, API version, digest, ETag, revision, timestamps and failure state.
It is a latest-attempt snapshot, not an append-only audit history.

The boundary-plan format remains v3. Its `network_github_meta` feature binds
the seed digest and the schema-v5 egress document digest, and requires
authenticated report collection. Matching updated host/guest artifacts are
necessary: older guests reject the new bootstrap field, and newer guests
reject a delegation without a seed.

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

agent ──(loopback /mcp/<server-id>)──▶ MCP gateway
       ──separate marked DNS, classify, reserve aliases/addresses, exact-IP dial──▶
       configured upstream

agent ──(loopback HTTP)──▶ npm proxy ──verify/scan/cache──▶ trusted SOCKS broker
                                                      ──(SO_MARK)──▶ npm upstream
```

nftables drops any agent packet that is not headed to a loopback broker port,
the optional MCP gateway port, or the optional npm proxy port, and any broker
external packet that lacks the mark or targets metadata. It drops every
registry-cgroup packet except TCP to the trusted registry SOCKS port.

## Remote MCP reservation and bypass protection

Remote MCP is admitted only through the trusted application-layer gateway.
Primary and redirect origins are normalized into the signed runtime policy.
The agent-facing CONNECT broker checks those configured names and observed
aliases before ordinary domain authorization and denies them first.

While any remote MCP server is configured:

- authenticated egress is mandatory even if the ordinary network policy would
  otherwise be permissive;
- nftables admits the exact MCP loopback port in addition to DNS and CONNECT;
- all agent-facing direct-IP CONNECT is denied, preventing literal-IP and
  shared-address bypasses;
- gateway DNS uses a separate marked resolver and never grants authorization in
  the agent cache;
- every observed address is classified before reservation or dialing, metadata
  addresses are always rejected, and reservation updates are bounded and
  atomic;
- only the broker cgroup can emit marked upstream packets.

There is no direct-origin fallback if the gateway, DNS validation, TLS,
reservation update, audit sink, or egress control fails.

## Policy source of truth

`sendbox_policy::NetworkPolicy` remains authoritative for ordinary workload
egress. The signed runtime document additionally carries policy-derived remote
MCP origins, the trusted gateway port, and direct-IP denial. These fields must
exactly match the signed MCP policy. `allow_dns = false` binds no agent-facing
DNS broker and installs no nftables DNS accept rule; the trusted MCP gateway
still uses its separate marked resolver when remote MCP is configured.

When package analysis is enabled, `sendbox-egress::runtime` derives a
workload-facing policy that removes direct access to every configured npm
upstream while preserving the original policy for the registry-only gateway.
The package proxy is therefore mandatory rather than a convention expressed
only through npm environment variables.

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
  `tests/gateway_integration.rs`. Both run on macOS and Linux. Deterministic
  nftables tests also prove that the workload can reach the npm proxy but not
  the trusted registry SOCKS listener, that the registry cgroup can reach only
  that trusted listener, and that no registry rule accepts `SO_MARK`.
- The privileged live proof is `tests/live_netns.rs`, gated by
  `target_os = "linux"`, `SENDBOX_EGRESS_LIVE=1`, and a full `Preflight` (plus
  `setpriv`). It proves cgroup identity isolation, the mark requirement, a
  nested execution leaf that can reach the loopback broker but cannot connect
  directly externally, sibling/identity-spoof denial, direct-egress bypass
  denial, non-vacuous
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
