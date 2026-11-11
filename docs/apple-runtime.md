# Apple runtime adapter

`sendbox-runtime-apple` is the production Rust `RuntimeProvider` for the
official Apple `container` CLI and service. It invokes the executable directly
with exact argv, clears the inherited environment, supplies `PATH`, `LANG`,
`LC_ALL`, the host `HOME`/`USER`/`TMPDIR` needed by the registered service, and
explicitly marked secret variables, and never invokes a shell or language
bridge. Supplying the host service environment does not mount the host home
inside the VM.

## Requirements

- macOS on arm64
- official `container` CLI and API server with exactly matching versions:
  **0.10.0 / 0.10.0** or **1.7.1 / 1.7.1**
- a root-owned executable, root-owned/non-writable bundle and optional kernel,
  and a root-owned mode `0444` Ed25519 public key
- the `container` service already registered and running
- a signed arm64 guest bundle whose signature, trust-root ID, host/guest
  versions, artifact digests, modes, owners, architecture, and release sequence
  pass `sendbox-bundle` verification
- an explicit Linux arm64 image and any configured kernel, mounts, network,
  DNS, CPU, memory, and ulimit values

The workload image must include `nft` and its runtime libraries, and the guest
kernel must support the mandatory
[egress enforcement prerequisites](installation.md#workload-image-versus-guest-bundle).
A plain Alpine base image does not include `nftables`.
Entrypoint and working-directory paths must also be symlink-free; see the
[workload image requirements](installation.md#workload-image-versus-guest-bundle).

The 1.7.1 adapter changes are source compatibility, not a new SendBox release
or completed consumer qualification. Released SendBox v0.2.5 does not contain
them. Keep using independently verified, compatible released host/guest bytes
for production; a source build or portable fixture pass is not equivalent.

`setup.sh` still installs only the pinned 0.10.0 signed package and verifies its
SHA-256 digest plus package signature. This compatibility change does not
update the installer, install 1.7.1, or change the registered service. All
other versions, prereleases, and mixed CLI/server pairs fail closed.

Preflight is non-mutating. It queries version, complete command help, and
`container system status --format json`. It checks the API server's version and
`container-apiserver` identity, not just `status: running`. The 1.7.1 payload
must also identify the client as `container` at the selected CLI version.
Creation repeats preflight before inspecting/pulling an image or creating a
container, including when a library caller omitted a separate preflight.
It never runs `container system start`, `stop`, or registration commands.

### Executable and service selection

The production host resolves `container` in this fixed order, independently of
the caller's `PATH`: `/usr/local/bin`, `/opt/homebrew/bin`, `/usr/bin`, `/bin`.
It does not skip an older installed executable to find a newer one. Diagnostics
identify the selected absolute path and observed CLI/server versions. A
user-owned Homebrew CLI or writable ancestor is still rejected.

`AppleRuntimeConfiguration.executable` is an explicit library API override.
`SENDBOX_APPLE_CONTAINER_EXECUTABLE` configures only the live test below; it is
not an override for `sendbox run`. The production CLI currently has no Apple
executable override. Do not copy an unsigned Homebrew binary into a trusted
location or relax ownership checks to make preflight pass.

Apple 1.7.1 discovers plugins from the **running server's** `installRoot`:
`libexec/container-plugins` first, then `libexec/container/plugins` beneath that
root. The official signed package installs `bin/container`,
`bin/container-apiserver`, and `libexec/container/plugins/<plugin>/` under
`/usr/local`; each plugin has its own `bin/` executable and `config.toml`.
Apple's `--install-root` option belongs to `container system start`, not a
per-container command. SendBox clears inherited `CONTAINER_*` variables and
does not offer a plugin-root override or restart services.

In the compatibility investigation, `/usr/local/bin/container` was 0.10.0
while the API server and Homebrew CLI were 1.7.1. The old CLI returned an empty
network list and failed creation with `builtin network is not present`; the
matching 1.7.1 CLI could see the existing built-in `default` NAT network. That
error was not evidence that a network should be created or reconfigured.
An operator must review and provision a matching trusted CLI explicitly.

### Reviewed JSON contracts

The 1.7.1 contracts were reviewed against upstream
[`a15b46097aa4c2325da13c1fb5192b9274aab083`](https://github.com/apple/container/tree/a15b46097aa4c2325da13c1fb5192b9274aab083):

- Image inspection accepts the 0.10.0 top-level `name`/`index.digest` layout
  and the 1.7.1 `configuration.name`/`configuration.descriptor.digest` layout.
  Exactly one image is required. The 1.7.1 raw-hex `id` must agree with the
  canonical SHA-256 descriptor. A requested digest must match that descriptor,
  never a tag, display name, annotation, or platform-variant digest. Inspection
  is repeated after a pull; malformed or truncated output fails.
- Container inspection requires exactly one record bound to the owned
  `configuration.id`. It reads the 0.10.0 top-level status string or the
  1.7.1 `status.state` plus matching top-level `id`. Missing, unknown, or
  ambiguous state is an error, never cached `running` health or a recursively
  discovered label.
- With the default network on 1.7.1, non-mutating
  `network inspect default` must identify `id` and `configuration.name` as
  `default`, mode `nat`, plugin `container-network-vmnet`, and label
  `com.apple.container.resource.role=builtin`. This is a prerequisite check,
  not network creation, migration, or an egress-policy exception.

## Lifecycle and control transport

The adapter checks or pulls the image according to policy, creates a named
container with the verified bundle mounted read-only, starts it, parses inspect
status, supports bounded log following, maps signals, stops with a grace
period, and deletes only the owned container. Workload exec is rejected;
`container exec` is reserved for bootstrap/control operations because workload
commands must pass through the authenticated guest broker.

Provider-neutral create requests are applied at container creation: dynamic
environment, mounts, DNS servers, CPU, memory, working directory, and labels
override or extend adapter defaults. Memory must be expressed in whole MiB, and
conflicting no-DNS/DNS settings fail before the CLI is invoked.

Both reviewed versions advertise `--publish-socket`, but no live VM evidence
establishes its replacement, ownership, cancellation, or bidirectional semantics.
The production adapter therefore **does not advertise published Unix sockets**.
It uses another official CLI surface:

1. The provider combines the per-session secret with the signed trust metadata,
   hardening requirements, and broker policy in the shared typed guest-bootstrap
   schema, then `container exec --interactive` installs it as a root-created,
   mode `0400` guest file. Before completing injection, the signed helper moves
   init into the trusted runtime cgroup without enabling any controllers.
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
# Optional explicit trusted CLI path, for this test only:
export SENDBOX_APPLE_CONTAINER_EXECUTABLE=/usr/local/bin/container
cargo test -p sendbox-runtime-apple --test live -- --nocapture
```

When `SENDBOX_APPLE_CONTAINER_LIVE=1`, missing configuration, a stopped service,
transport failure, authentication failure, or cleanup failure fails the test;
it is not converted to a skip. The image must already exist locally at its exact
index digest; the test never pulls it. It mounts only generated fixture data,
separate from host runtime state, uses unique container and session/socket
identities, and checks running and stopped inspect states. The primary live
operation has a 90-second deadline, followed by channel cleanup, stop, and
targeted delete even after failure. An ordinary test run without the live flag
does not provide physical qualification evidence.

The mixed-version physical host was verified to fail at preflight, before
creating a VM. A positive 1.7.1 live gate still requires an operator-provisioned
trusted matching CLI. Compatible SendBox release packaging and each consumer's
exact-image execution, cancellation, recovery, accounting, and checkpoint
qualification remain separate gates.

## Limitations

- Only exact matching 0.10.0 and 1.7.1 CLI/server pairs are supported by this
  source. No other version is accepted based on ordering or help similarity.
- The adapter does not start/register/stop the Apple service.
- `--publish-socket`, Rosetta, virtualization passthrough, SSH forwarding, TTY
  mode, and arbitrary workload exec are not advertised.
- Neither reviewed CLI has a hostname option. Container identity remains the
  session-unique container name rather than claiming a separately configured
  kernel hostname.
- Runtime `Network` capability covers Apple network/DNS provisioning.
  Restrictive policy is a separate signed guest admission: the provider binds
  the authenticated egress policy and delegated execution cgroup parent into
  bootstrap, and Exec cannot start until the guest DNS/SOCKS5 gateway reports
  readiness.
- Bundle and trust-root mounts depend on official CLI bind-mount semantics and
  are fail-closed by guest-side mode, owner, digest, version, and rollback
  checks.

## Guest readiness troubleshooting

Bootstrap injection moves guest init from `/` to `/sendbox-runtime` before
controller delegation, without changing the cgroup namespace root.
Guest admission checks the full writable
cgroup2 mount independently of this membership change. It still rejects
subtree mounts, read-only mounts, and unrelated init cgroups.

The v0.2.0 guest incorrectly required init to remain at `/` after moving it,
causing the mandatory egress service to exit before authenticated readiness.
Its execution broker also treated the supervisor's connect/disconnect socket
health probe as its sole execution connection and exited on the empty request.
The broker must survive that empty probe without accepting malformed requests
or weakening peer/session authentication.
The concurrent stdio relay can also repopulate the root cgroup during controller
delegation. Startup refreshes and migrates those processes when the kernel returns
`EBUSY`, retrying for at most five seconds rather than disabling the controllers.
Native exec also snapshots init's cgroup before attaching the new process.
Moving init only during concurrent supervisor startup leaves a window where
Apple targets the old root after controllers make it a non-leaf. The bootstrap
injection helpers now establish `/sendbox-runtime` before returning, so later
supervisor/control execs use a stable leaf. Controllers are still enabled and
verified by the supervisor, not by the injection helper.

In one retained failed run, Apple reported `vmexec ... read ack pipe` while
starting the control relay; the guest was locally ready but the relay never
reached the handshake. Apple 0.10.0 can also wait indefinitely after such a start
failure. The upstream [waiter fix](https://github.com/apple/container/pull/1289)
is included in 0.11.0. That does not qualify 0.11.0 or every later version;
this adapter separately reviews exact supported pairs. Do not infer that a
later successful retry repaired an earlier failed run or upgrade the host
service as an implicit workaround.

Replacing only the host CLI cannot correct that guest defect: rebuild and sign
the guest bundle as well. Host/guest manifest versions must match the binaries,
and trust-root identity, architecture, release sequence, digests, and ownership
must still verify. Never edit an installed signed bundle in place.

A Node `fetch` error saying `Request was cancelled` can wrap a proxy failure
rather than application cancellation. Inspect its nested cause or Undici
diagnostics: HTTP CONNECT 502 indicates upstream resolution/connection failure;
403 is a policy denial. Domain policy validates the complete CNAME chain, so
allowing a public API hostname does not implicitly authorize its canonical
backend names. Keep those denials intact and require explicit policy approval
for any additional names.

For first-request DNS failures, use the credential-free
[cold-start diagnostic](dns-cold-start.md). It measures a new VM's first
SOCKS/HTTP request without a lookup, warm-up or application retry, retains
sanitized resolver failure details, checks deny-first containment, and records
per-request latency and owned-VM cleanup. A successful later request is not
proof that the cold request worked.

If readiness succeeds but launch reports `openat2`/`Symbolic link loop`, fix the
workload image or select its actual regular executable path. For a minimal
qualification image, the original Alpine base can be extended without relaxing
the broker:

```dockerfile
FROM alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache nftables \
    && cp /bin/busybox /bin/sh.sendbox \
    && mv -f /bin/sh.sendbox /bin/sh
```

Build without cache and pin the resulting image digest. This image is only a
minimal shell qualification image; it does not install a coding agent.
