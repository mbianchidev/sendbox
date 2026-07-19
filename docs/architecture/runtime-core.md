# Runtime Core Contract

Status: **pre-1.0 foundation**. `sendbox-runtime` defines the behavior shared by
future Apple, Kata, Hyperlight, and other adapters. It does not implement an
adapter, guest service, egress control, execution broker, project analyzer, or
security store.

`sendbox-config::RuntimeProvider` is the configured provider **kind**. The
`sendbox_runtime::RuntimeProvider` trait is the object-safe asynchronous behavior
contract implemented by an adapter. They intentionally have the same domain term
but no type dependency.

## Provider contract and concurrency

The provider lifecycle is:

1. `initialize` prepares host-side provider state.
2. `preflight` validates required capabilities before resource creation.
3. `create` creates a stopped container or VM.
4. `start` starts its supervised workload.
5. `status`, `exec`, and `attach` observe or interact with it.
6. `signal` and `stop` terminate work.
7. `cleanup` compensates all resources.

Every asynchronous method returns an explicit `Send` boxed future and receives an
explicit `CancellationToken`. Providers are `Send + Sync`. Calls for different
containers may run concurrently. A provider must serialize or reject mutating
calls for the same container, while status, capability reporting, and output
consumption may run concurrently. A lifecycle update must validate and commit in
one critical section; duplicate transitions are errors rather than implicit
successes.

The foundation state machine permits only these transitions:

- `New` to `Initialized`, `Cleaning`, or `Failed`
- `Initialized` to `Created`, `Cleaning`, or `Failed`
- `Created` to `Running`, `Stopped`, `Cleaning`, or `Failed`
- `Running` to `Stopping`, `Stopped`, or `Failed`
- `Stopping` to `Stopped` or `Failed`
- `Stopped` to `Cleaning`, `Cleaned`, or `Failed`
- `Cleaning` to `Cleaned` or `Failed`
- `Failed` to `Cleaning` or `Cleaned`
- `Cleaned` is terminal

`RuntimeId` and `ContainerId` are validated, bounded identifiers rather than
unstructured strings.

## Capability layering

Runtime capabilities map explicitly to the authenticated protocol:

| Runtime capability | Protocol capability ID |
|---|---:|
| Lifecycle | 1 |
| Exec | 2 |
| Streamed I/O | 3 |
| Signals | 4 |
| Mounts | 5 |
| Network | 6 |
| MCP | 7 |
| Audit | 8 |
| Health | 9 |

`TransportProvisioning` is runtime-local. It describes whether an adapter can
provision its selected host/guest transport and is deliberately filtered out of
`sendbox_protocol::CapabilitySet`. `sendbox-runtime` depends on
`sendbox-protocol` for this mapping; the protocol crate has no runtime dependency,
so the layering is acyclic.

An unavailable platform implementation uses `UnavailableRuntimeProvider`. It
advertises no capabilities and returns a structured unavailable error rather
than selecting a fallback.

## Cancellation

Cancellation is an explicit atomic state plus notification. It is not represented
by a watch or sender channel. Dropping one token, or every token, does not cancel
anything and cannot be confused with channel closure. Only `cancel()` changes the
state.

Dropping an operation future is not success. Adapters remain responsible for
registering compensation before a partial resource becomes externally visible.

## Host process execution

The process runner never invokes a shell. A command selects either an absolute
program path or a named program resolved through an injected `ProgramResolver`.
The runner rejects a relative resolver result. Arguments and environment values
carry explicit sensitive flags used by diagnostics. The environment is cleared
by default, and invalid NULs, environment keys, duplicate keys, program forms,
and missing or non-directory working directories fail before spawn.

Stdout and stderr have independent drain tasks. Each task writes directly to a
bounded capture buffer and performs a nonblocking publish while holding only a
short ordering lock. There is no bounded intermediate collector that can stall
pipe reads. Captures report total and truncated bytes.

Unix children start in a new process group using the standard library
`process_group(0)` configuration. Signals use the safe `nix::killpg` API.
Cancellation and timeout send `SIGTERM`, wait the configured grace period, then
send `SIGKILL` and reap. `RunningProcess::drop` directly sends `SIGKILL` to the
group synchronously as a last-resort fallback; it does not depend on an async
command channel.

A process can escape this containment by successfully calling `setsid` or
`setpgid`. Process groups are lifecycle hygiene, not a sandbox boundary. Later
guest and kernel enforcement must prevent or contain escape where policy
requires it. Non-Unix code paths avoid the Unix dependency and return an explicit
unsupported signal error. Cancellation and timeout can only kill the direct
child there. Those paths were not platform-qualified by this change, so no
descendant or graceful-signal guarantee is claimed.

## Output ordering and loss

Every data event identifies stdout or stderr and contains a monotonic global
sequence plus a monotonic per-stream sequence. Publishing to the bounded client
channel uses `try_send`; a slow or dropped client can never block either pipe
drain.

Dropped events are not hidden. The next delivered data event carries
`dropped_before` metadata with event, byte, sequence-range, and per-stream counts.
If no later event can be delivered, the subscription emits a final loss event
after queued data. Process outcomes also retain aggregate delivered and dropped
statistics. Channel closure means end-of-stream, while cancellation returns a
separate cancellation error.

## Cleanup transaction

A cleanup transaction is a reverse-order compensation stack:

- every incomplete step is attempted in a pass, even after failures;
- all failures are returned with their step names;
- successful steps are permanently marked complete;
- failed steps remain pending and are retried by later calls;
- a fully completed transaction is idempotent and performs no further work;
- each step must treat an already-absent resource as success.

`OperationFailure` preserves the primary runtime error as its error source and
attaches the structured cleanup report. Cleanup failures therefore never replace
or flatten the initiating failure.

## Clock boundary

Process start, finish, and elapsed metadata use the injected `Clock`.
`SystemClock` is monotonic, while `sendbox-testkit::ManualClock` makes metadata
tests deterministic. OS timeout selection necessarily uses Tokio time; advancing
`ManualClock` does not advance or trigger a process timeout, and the API makes no
claim that it does.
