# Apple `container` CLI adapter spike

This Phase 1 spike evaluates whether SendBox can replace its first-party Swift
Apple runtime adapter with a Rust adapter over Apple's official `container`
CLI/service. It is isolated under `spikes/apple-container-adapter/` and is not a
production runtime.

## Tested environment

- macOS 26.5.2 on arm64
- `container` CLI 0.10.0, release commit `6bdb647`
- Rust 1.93.1
- `container system status --format json`: `unregistered`

The local qualification was deliberately non-mutating. The probe did not start,
stop, or register the service and did not create, alter, or delete containers,
images, networks, or volumes.

## Run the probe

```bash
cargo run \
  --manifest-path spikes/apple-container-adapter/Cargo.toml \
  --release -- \
  --executable /usr/local/bin/container
```

The command prints deterministic JSON. `supported` means the exact behavior was
executed successfully, `unsupported` means complete help evidence lacks a
required surface, and `unverified` means the CLI advertises the surface but the
behavior was not exercised.

## Capability result

| RuntimeProvider behavior | Verdict | Evidence |
|---|---|---|
| initialize/preflight | Supported | Trusted executable, CLI version, and service JSON status were queried directly |
| create and start/run | Unverified | `create`, `run`, `start`, and `--detach` are advertised; service was stopped |
| status | Unverified | `inspect` emits JSON and `list --format json` is advertised; no container was inspected |
| exec | Unverified | `exec` is advertised; no guest process was started |
| attach logs/output | Unverified | `start --attach` and `logs --follow` are advertised; stream ordering and cancellation were not exercised |
| signal | Unverified | `kill --signal` is advertised; signal delivery was not exercised |
| stop and cleanup | Unverified | `stop --time` and `delete` are advertised; idempotence and failure cleanup were not exercised |
| mounts and environment | Unverified | `--mount`, `--volume`, and `--env` are advertised |
| DNS and network | Unverified | `--dns`, `--dns-search`, `--no-dns`, and `--network` are advertised |
| resource limits | Unverified | `--cpus`, `--memory`, and `--ulimit` are advertised |
| kernel selection | Unverified | `--kernel` is advertised |
| structured output | Unverified | service/list JSON and inspect JSON exist, but lifecycle schemas were not qualified |
| host/guest transport | Unverified | `--publish-socket host_path:container_path` is advertised; bidirectional traffic, authentication, streaming, cancellation, and backpressure were not exercised |

The Rust process layer itself is verified by tests for direct argv execution,
minimal explicit environment, exit status preservation, timeout, cancellation,
bounded output, output truncation reporting, and secret redaction.

## Socket publication safety

Apple 0.10.0 parses `--publish-socket` in
[`Parser.publishSocket`](https://github.com/apple/container/blob/0.10.0/Sources/Services/ContainerAPIService/Client/Parser.swift#L720-L785).
That implementation rejects an existing Unix socket but removes an existing
non-socket path before creating the endpoint. The spike therefore rejects every
pre-existing host path and never delegates replacement to the CLI. This is
source-derived evidence; live socket behavior remains unverified.

Socket endpoints must be absolute UTF-8 paths without `:`, NUL, or `..`, and
must fit the conservative macOS Unix-domain socket path limit. Container IDs,
mounts, environment keys, signals, networks, and resources are also validated
before argv construction. Sensitive guest environment values are placed only in
the child process environment; argv contains `--env KEY`, never `KEY=value`.

## Opt-in live qualification

The live test runs only when explicitly enabled and only if the service is
already running. It never starts or stops the service. The selected image may be
pulled and cached, so both the image and guest server argv must be explicit:

```bash
export SENDBOX_APPLE_CONTAINER_LIVE=1
export SENDBOX_APPLE_CONTAINER_LIVE_IMAGE=python:3.13-alpine
export SENDBOX_APPLE_CONTAINER_LIVE_COMMAND_JSON='["python3","-c","import os,socket,time; p=\"/run/sendbox/control.sock\"; os.makedirs(\"/run/sendbox\",exist_ok=True); s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen(); s.accept(); time.sleep(30)"]'
cargo test \
  --manifest-path spikes/apple-container-adapter/Cargo.toml \
  --test live -- --nocapture
```

The test uses a unique container name and temporary host socket. It always
attempts targeted stop, signal fallback, delete, and socket removal; it never
uses `--all`, prune, or image deletion.

## ADR consequence

The 0.10.0 CLI surface is **provisionally viable but not qualified**. It exposes
every required lifecycle option and a promising Unix-socket transport, so the
spike does not yet justify a direct Rust Virtualization.framework adapter.
However, the stopped service prevents proof of lifecycle semantics, stream
ordering, cancellation, cleanup, and the authenticated control channel.

ADR-003 must therefore retain the current Swift path, or a temporary narrow
Swift IPC bridge during migration, until the opt-in live qualification passes.
Only then can the CLI adapter be accepted as viable. If live qualification shows
that `--publish-socket` or lifecycle streaming cannot satisfy ADR-002, proceed
to the direct Rust Virtualization.framework option.
