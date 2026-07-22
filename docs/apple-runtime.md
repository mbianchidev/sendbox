# Apple runtime adapter

`sendbox-runtime-apple` is the production Rust `RuntimeProvider` for the
official Apple `container` CLI and service. It invokes the executable directly
with exact argv, clears the inherited environment, supplies only `PATH`,
`LANG`, `LC_ALL`, and explicitly marked secret variables, and never invokes a
shell or Swift bridge.

## Requirements

- macOS on arm64
- official `container` CLI **0.10.0**
- a root-owned executable, root-owned/non-writable bundle and optional kernel,
  and a root-owned mode `0444` Ed25519 public key
- the `container` service already registered and running
- a signed arm64 guest bundle whose signature, trust-root ID, host/guest
  versions, artifact digests, modes, owners, architecture, and release sequence
  pass `sendbox-bundle` verification
- an explicit Linux arm64 image and any configured kernel, mounts, network,
  DNS, CPU, memory, and ulimit values

Preflight is non-mutating. It queries version, complete command help, and
`container system status --format json`. It never runs `container system
start`, `stop`, or registration commands.

## Lifecycle and control transport

The adapter checks or pulls the image according to policy, creates a named
container with the verified bundle mounted read-only, starts it, parses inspect
status, supports bounded log following, maps signals, stops with a grace
period, and deletes only the owned container. Workload exec is rejected;
`container exec` is reserved for bootstrap/control operations because workload
commands must pass through the authenticated guest broker.

Apple 0.10.0 advertises `--publish-socket`, but the available development host
reported an unregistered service, so no live VM evidence established its
replacement, ownership, cancellation, or bidirectional semantics. The
production adapter therefore **does not advertise published Unix sockets**.
It uses another official CLI surface:

1. `container exec --interactive` injects the bounded bootstrap bytes into a
   root-created, mode `0400` guest file.
2. A detached bootstrap/control exec starts the verified guest supervisor.
3. A second interactive exec runs the signed `stdio-bridge`, which connects to
   the session-unique guest Unix socket and relays raw stdin/stdout.
4. The merged SendBox handshake authenticates the byte stream before readiness
   or requests are accepted.

The bridge process and stream are owned by the provisioned channel and are
terminated during channel/runtime cleanup. There is no host-global socket,
daemon, port, or side channel. A real local Unix-stream fixture proves that the
relay preserves authenticated protocol bytes. The configured live gate proves
the same path across the Apple VM.

## Qualification

Unit and conformance tests:

```bash
cargo test -p sendbox-runtime-apple --all-targets
```

Live qualification requires a prepared host. The test never mutates service
registration or service lifecycle:

```bash
export SENDBOX_APPLE_CONTAINER_LIVE=1
export SENDBOX_APPLE_CONTAINER_BUNDLE=/absolute/path/to/verified/bundle
export SENDBOX_APPLE_CONTAINER_PUBLIC_KEY=/absolute/path/to/root.pub
export SENDBOX_APPLE_CONTAINER_TRUST_ROOT_ID=release-root-v1
export SENDBOX_APPLE_CONTAINER_MIN_RELEASE_SEQUENCE=1
export SENDBOX_APPLE_CONTAINER_LIVE_IMAGE=ghcr.io/example/sendbox-base@sha256:...
cargo test -p sendbox-runtime-apple --test live -- --nocapture
```

When `SENDBOX_APPLE_CONTAINER_LIVE=1`, missing configuration, a stopped service,
transport failure, authentication failure, or cleanup failure fails the test;
it is not converted to a skip. The test uses unique container and session/socket
identities and always attempts channel cleanup, stop, and targeted delete.

## Limitations

- Only CLI 0.10.0 is qualified; later versions fail preflight until their help
  and lifecycle schemas are reviewed.
- The adapter does not start/register/stop the Apple service.
- `--publish-socket`, Rosetta, virtualization passthrough, SSH forwarding, TTY
  mode, and arbitrary workload exec are not advertised.
- Runtime `Network` capability means Apple network/DNS configuration only. It
  does not claim domain egress enforcement; that requires the signed guest
  egress controls and must fail policy validation when those controls are not
  present.
- Bundle and trust-root mounts depend on official CLI bind-mount semantics and
  are fail-closed by guest-side mode, owner, digest, version, and rollback
  checks.
