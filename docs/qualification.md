# Qualification inventory, conformance, and benchmarks

The Phase 0/1 qualification data lives under `Tests/qualification/` and is
validated by the isolated Rust tool in `tools/sendbox-qualification/`. The tool
has its own workspace and lockfile so qualification dependencies do not become
product dependencies.

## Inventory gate

`inventory.v1.json` is the countable migration scope. It covers all current
Swift, Rust, and bridge source modules, CLI commands, configuration sections/keys/defaults,
runtime operations and capabilities, security modules, persisted formats,
setup/completion/release surfaces, and top-level documented claims.

Every entry has a stable ID, one of `preserve`, `redesign`, `defer`, or
`remove`, repository evidence in `path#symbol-or-claim` form, a target Rust
crate and phase, and a conformance status. Redesigns also require a
compatibility note. Validation fails on duplicate IDs, missing evidence,
unknown fields, missing fixtures, or an unresolved disposition.

For a PR, changed behavior must update the corresponding inventory and fixture.
Cutover requires every preserved entry to have a passing implementation test
and every redesign to have its compatibility note satisfied.

## Conformance gate

`conformance.v1.json` indexes intended-behavior fixtures. Intended behavior is
the oracle. Current Swift output is explicitly labeled `swift_observation_only`
and is used only for a feature already marked `preserve`; untested Swift
behavior is never copied automatically.

Fixtures specify CLI channels and exits, config defaults and errors, policy
decisions, protocol contracts, runtime capabilities, persisted formats,
setup/release behavior, and known-defect negative cases. Existing config and
protocol fixtures remain the executable implementation tests where available;
qualification fixtures define the cross-implementation contract.

The comparison runner invokes binaries directly, never through a shell. It
normalizes declared paths and JSON fields, enforces a timeout and combined
output cap, and emits deterministic JSON. Missing binaries, timeouts, and
output-limit violations are explicit outcomes rather than passes:

```bash
cargo run --manifest-path tools/sendbox-qualification/Cargo.toml -- \
  compare \
  --fixture cli.policy-validate-common \
  --swift-binary .build/release/sendbox \
  --rust-binary target/release/sendbox-rs
```

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

The harness emits raw samples and summaries. Shared-runner smoke tests only
check execution and output shape; they never enforce noisy latency thresholds.
Qualification enforcement is reserved for declared reference hosts:

```bash
cargo run --manifest-path tools/sendbox-qualification/Cargo.toml -- validate

cargo run --manifest-path tools/sendbox-qualification/Cargo.toml -- \
  benchmark --profile smoke --rust-binary target/release/sendbox-rs

cargo run --manifest-path tools/sendbox-qualification/Cargo.toml -- \
  benchmark --profile qualification --enforce-thresholds \
  --rust-binary target/release/sendbox-rs
```

The harness never starts Apple container services, containerd, Kata,
Hyperlight, guest services, or BPF programs. Vendor baselines must be run
manually on prepared hosts using the pinned fixed-adapter definition. A result
cannot be published while any required workload, reference host field,
relative C baseline, fixed-adapter baseline, or BPF event rate remains
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
