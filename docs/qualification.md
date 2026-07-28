# Qualification inventory, conformance, and benchmarks

The Phase 0/1 qualification data lives under `Tests/qualification/` and is
validated by the isolated Rust tool in `tools/sendbox-qualification/`. The tool
has its own workspace and lockfile so qualification dependencies do not become
product dependencies.

## Inventory gate

`inventory.v1.json` is the countable rewrite scope. It covers current Rust
source modules, historical implementation decisions, CLI commands,
configuration sections and defaults, runtime operations and capabilities,
security modules, persisted formats, setup/completion/release surfaces, and
top-level documented claims.

Every entry has a stable ID, one of `preserve`, `redesign`, `defer`, or
`remove`, repository evidence in `path#symbol-or-claim` form, a target Rust
crate and phase, and a conformance status. Redesigns also require a
compatibility note. Validation fails on duplicate IDs, missing evidence,
unknown fields, missing fixtures, or an unresolved disposition.

The production records include adapter-neutral session lifecycle, audit
anchoring, snapshot rollback, secret envelopes, provenance verification,
permission grants, and bounded migration reports. `sendbox-host` composes those
records with verified runtime plans and authenticated Apple/Kata guest services.
All inventory and conformance entries are implemented or explicitly
not-applicable.

Deleted implementation paths are represented through
`Tests/qualification/historical/swift-to-rust.v1.json`, which binds each
historical evidence path to the exact pre-cutover commit and Git blob object.
Validation resolves the commit and every blob from repository history, rejects
paths still present in the current tree, and requires a full-history checkout.
The text after the second `#` is a stable semantic claim label rather than a
source-code selector. Implemented entries must also resolve to live repository
evidence directly or through their implemented target source module.

Inventory coverage scans `crates/*/src` only; the Swift package and the
TypeScript copilot bridge no longer exist. Validation therefore rejects the tree
outright if `Package.swift`, `Package.resolved`, `Sources/`, or
`copilot-bridge/` reappears, and still flags any non-Rust source module that
turns up inside a crate.

For a PR, changed behavior must update the corresponding inventory and fixture.
Cutover requires every preserved entry to have a passing implementation test
and every redesign to have its compatibility note satisfied.

## Conformance gate

`conformance.v1.json` indexes intended-behavior fixtures. Intended behavior is
the only oracle; the production qualification tool no longer executes or
compares a legacy implementation.

Fixtures specify CLI channels and exits, config defaults and errors, policy
decisions, protocol contracts, runtime capabilities, persisted formats,
setup/release behavior, and known-defect negative cases. Existing config and
protocol fixtures remain the executable implementation tests where available;
qualification fixtures define the cross-implementation contract.

`scripts/qualify-setup-release.sh` is the executable `setup.release` gate. The
macOS and Linux CI matrix runs real setup configuration/build flows, a staged
Make install, host tar assembly, checksum verification, and archive inspection;
the macOS leg additionally builds and inspects the unsigned pkg and dmg.

`policy.decisions` is implemented across the native command broker, egress
engine, MCP broker, repository-scope authorization, and Git guard. The Git
evidence covers repository/workspace identity, aliases, options, remote
rewrites, refspecs, timeouts, output limits, environment/config injection,
trusted binary paths, and native exit preservation.

`mcp.contracts` records native framing, JSON-RPC, policy, exact-command,
project-validation, authenticated guest delivery, legacy-trace,
versioned-observation, redaction, backpressure, and cancellation contracts.
Remote HTTP/SSE authorization remains intentionally unsupported and fails
closed.

## Benchmark gate

`benchmark-spec.v1.json` records reference-host fields, workload sizes,
warmups/repetitions, cache states, compiler/linker/allocator/logging controls,
statistics and confidence intervals, absolute plan thresholds, C-reference
interfaces, fixed-adapter definitions, and the BPF no-loss event-rate gate.
Unknown environmental values are `unqualified`; they must not be guessed.

Available pure/control-plane paths measure CLI startup, config validation,
policy structural validation, protocol encode/decode, and authenticated
in-memory protocol RTT including MAC work. Exec broker, policy decisions, MCP,
egress, BPF decode, guest bootstrap, RSS/binary release measurements, and
vendor runtime paths remain explicit hooks until stable production interfaces
and reference hosts exist.

The harness emits raw samples and summaries at benchmark report schema version 2,
which records host OS, architecture, `rustc`, and the qualification tool version.
Shared-runner smoke tests only
check execution and output shape; they never enforce noisy latency thresholds.
Qualification enforcement is reserved for declared reference hosts:

```bash
cargo run --manifest-path tools/sendbox-qualification/Cargo.toml -- validate

cargo run --manifest-path tools/sendbox-qualification/Cargo.toml -- \
  benchmark --profile smoke --rust-binary target/release/sendbox

cargo run --manifest-path tools/sendbox-qualification/Cargo.toml -- \
  benchmark --profile qualification --enforce-thresholds \
  --rust-binary target/release/sendbox
```

The portable harness never starts Apple container services, containerd, Kata,
Hyperlight, guest services, or BPF programs. Production Kata has a separate,
non-skipping self-hosted gate:

```bash
SENDBOX_KATA_LIVE=1 \
SENDBOX_KATA_CONFIG=/absolute/config.yaml \
SENDBOX_KATA_IMAGE=registry/workload@sha256:<digest> \
SENDBOX_KATA_BUNDLE=/absolute/bundle \
SENDBOX_KATA_TRUST_ROOT=/absolute/release-public.key \
./scripts/qualify-kata-live.sh
```

`.github/workflows/kata-live.yaml` requires a runner labeled
`self-hosted, linux, x64, kvm, kata`. Missing inputs or prerequisites fail; they
are never reported as a successful skip. Vendor baselines must still be run on
prepared hosts using the pinned fixed-adapter definition. A result cannot be
published while any required workload, reference host field, relative C
baseline, fixed-adapter baseline, BPF event rate, or live Kata evidence remains
`unqualified`.

## Apple runtime qualification

The production Apple entry is `module.rust-apple-runtime`. Its portable gate
uses the shared runtime conformance suite, a stateful fake `container` CLI,
exact-argv assertions, bounded stream/output tests, cancellation and failure
tests, signed-bundle verification, and a real local authenticated Unix-stream
fixture.

The vendor gate is opt-in only because GitHub-hosted runners do not provide an
already registered Apple container service or repository trust artifacts. When
the repository variable `SENDBOX_APPLE_CONTAINER_LIVE=1` configures the
prepared self-hosted runner, `.github/workflows/apple-runtime.yaml` runs the
live test without a skip path. The test verifies the pre-existing service,
creates unique container and guest socket identities, authenticates through the
official CLI stdio relay, and performs targeted cleanup. It never registers,
starts, stops, or unregisters the Apple service.

See [Apple runtime adapter](apple-runtime.md) for required variables, the live
command, transport evidence, and unsupported capabilities.

## Hyperlight runtime qualification

`module.hyperlight-runtime` and `claim.hyperlight` are implemented by
`crates/sendbox-runtime-hyperlight`. Ordinary qualification validates the
portable lifecycle subset, exact argv construction, signed bundle verification,
network rejection rules, fresh read-only staging, cancellation, output, and
cleanup. It does not claim a persistent guest broker, stdio forwarding, eBPF or
seccomp guest bootstrap, OCI support, environment injection, DNS budgets,
connection limits, or wildcard/CIDR enforcement.

The vendor gate is opt-in because it requires a prepared Linux KVM host, a
root-owned pinned `hyperlight-unikraft`, and a signed Unikraft bundle. When
designated with `SENDBOX_HYPERLIGHT_LIVE=1`, missing prerequisites fail the
test rather than producing a success-shaped skip. The complete command and
required variables are documented in [the Hyperlight guide](hyperlight.md).
