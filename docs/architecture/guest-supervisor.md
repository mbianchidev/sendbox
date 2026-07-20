# Guest Bootstrap and Supervisor

Status: **production foundation**. This document defines the trust, bootstrap,
readiness, service, and fail-closed semantics implemented by
`guest/sendbox-guest`. Runtime adapters and the exec, MCP, DNS, egress, audit, and
BPF service implementations are intentionally outside this foundation.

## Process and command model

`sendbox-guest` is a static multi-call binary with these entrypoints:

- `bootstrap` and `supervisor` both run the complete lifecycle in one long-lived
  process. They are not separate stages because the bootstrap secret must never
  cross a process boundary or be persisted.
- `health` reads the local atomic readiness marker. The authenticated control
  protocol remains authoritative to a remote host.
- `service-run` is hidden and exists only for deterministic process-supervision
  qualification.

Typed service identifiers reserve `exec`, `mcp`, `dns`, `egress`, `audit`, and
`bpf`. Reserving an identifier does not claim that its service is implemented.

## Trust and immutable bootstrap

The runtime stages a prebuilt artifact tree before guest startup. The guest does
not download, generate, or replace artifacts.

The release trust root is injected as a separate root-owned, single-link, `0444`
file containing exactly 32 raw Ed25519 public-key bytes. The guest never creates a
trust root. The one-time bootstrap input is a root-owned, single-link, `0400`
regular file under a symlink-free absolute path. It is opened once with
`O_NOFOLLOW`, inspected through the open descriptor, atomically renamed to a
consumed name, bounded to 64 KiB, parsed with unknown-field rejection, zeroized,
and unlinked. A persistent nonce digest in the root-owned replay ledger rejects a
copied bootstrap input. The replay ledger is provisioned separately from volatile
runtime state (default `/var/lib/sendbox/replay`), and its marker plus directory
are synced after bounded bootstrap validation but before the consumed source is
unlinked or artifact-manifest processing begins.

The bootstrap secret is at least 32 bytes, redacted by the protocol type, zeroized
on drop, never logged, and never written to runtime state. Bootstrap and supervisor
remain one process so the secret reaches the authenticated handshake only in
memory.

## Signed artifact manifest

The signed envelope contains UTF-8 manifest payload bytes and an Ed25519
signature. Signature verification precedes payload decoding. The signed payload
binds:

- schema and signature domain;
- trust-root identity;
- monotonic release sequence and minimum accepted sequence;
- expected host and guest versions;
- target architecture;
- guest binaries, service binaries, and BPF object paths;
- SHA-256 digest, file mode, UID, and GID for every artifact.

Artifact paths must be relative and contain only normal components. Verification
walks from an already-open artifact-root descriptor. Every directory component is
opened with `O_DIRECTORY | O_NOFOLLOW`; every artifact is opened with
`O_NOFOLLOW`, checked as a single-link regular file with `fstat`, and hashed from
that descriptor. Absolute paths, parent traversal, symlinks, hard links, digest
mismatches, owner/mode mismatches, architecture drift, version drift, forged
signatures, and rollback sequences fail closed.

Verified service executable descriptors remain open. Linux service launch uses
the descriptor through `/proc/self/fd` rather than reopening the mutable artifact
pathname, so a post-verification rename or symlink swap cannot select new code.

## Startup and readiness contract

The only valid startup sequence is:

1. `awaiting_bootstrap`
2. `bootstrap_consumed`
3. `manifest_verified`
4. `runtime_prepared`
5. `controls_verified`
6. `services_starting`
7. `self_testing`
8. `ready`
9. optionally `agent_launch_permitted`
10. `shutting_down`
11. `terminated`

Any other transition is rejected. Failure enters `failed`, revokes readiness, and
can only continue through shutdown and termination.

The per-session runtime directory is created with exclusive `0700` semantics.
Existing session state is stale and rejected. State and readiness files are
written through a synced temporary file and atomic rename. Readiness is published
only after:

- the bootstrap was consumed and its nonce registered;
- the signed manifest and every artifact passed verification;
- the runtime directory passed ownership and mode checks;
- every required platform control reported `verified = true`;
- every mandatory service started in dependency order and passed health checks;
- platform and service self-tests passed;
- the control socket was bound.

The guest then performs the existing `sendbox-protocol` mutual authenticated
handshake. Its first authenticated lifecycle event contains the exact release
sequence, verified control reports, service health, and deterministic audit
events. Mandatory-service liveness is rechecked after the handshake and before
every authenticated health or launch response. `agent.launch` is authorized once
and only while the local state is
`ready`; this foundation returns `executed = false` because production execution
brokering is a separate scope. No marker, handshake, health response, or launch
response reports success for a control that was not verified.

## Service supervision and failure behavior

Each service has a typed identifier, verified executable path, dependencies,
mandatory flag, restart budget/backoff, health probe, graceful/forced shutdown
timeouts, and bounded stdout/stderr storage. Dependency cycles and missing
dependencies are rejected before spawn. A mandatory service cannot depend on an
optional service. Services run in dedicated process groups.
Output is drained concurrently and retained only up to the configured bound.

Optional services restart only within their declared budget, and dependents are
re-health-checked after an optional dependency restart. Any mandatory service
exit revokes the launch gate immediately; mandatory services are never restarted
inside an already-ready session. A mandatory service that cannot start, cannot
pass health, or exits causes:

1. atomic readiness revocation;
2. protocol termination;
3. SIGTERM to every supervised process group;
4. SIGKILL after the grace limit;
5. direct-child reaping;
6. socket and per-session runtime cleanup.

The same fail-closed path applies to authenticated protocol loss. Drop guards send
SIGKILL to process groups and remove runtime state if an async task is cancelled.
The replay ledger is intentional persistent security state and is not session
garbage.

## Platform-control boundary

Privilege drop, capabilities, and seccomp are represented by the injected
`PlatformControls` trait. The production foundation adapter reports them as
unavailable. If bootstrap marks any unavailable control required, startup fails.
Tests inject a deterministic adapter that can verify requested controls without
privilege. This separation permits unprivileged qualification without pretending
that Linux controls are armed.

Remaining Linux integration must implement and live-test dedicated UID/GID
transitions, capability sets, `no_new_privs`, architecture-specific seccomp
profiles, cgroups, mounts, rlimits, sysctls, nftables, and BPF attachment. Those
implementations must preserve the readiness gates above.

## Static delivery

`guest/sendbox-guest/Dockerfile` builds with the pinned Rust 1.93.1 Alpine image
for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`. The CI job builds
each architecture twice without cache, compares same-architecture binaries, and
uses `file`, `readelf`, and `ldd` evidence to reject an ELF interpreter or shared
dependency.
