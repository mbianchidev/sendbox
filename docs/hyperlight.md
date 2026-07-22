# Hyperlight runtime adapter

`crates/sendbox-runtime-hyperlight` is the production Rust
`RuntimeProvider` for the official `hyperlight-unikraft` host CLI. It is
Linux/KVM-only and deliberately models Hyperlight as a one-shot runtime. This
crate is not wired into the Rust CLI run command.

## Trust and preflight

The adapter fails preflight unless all of the following hold:

- `/dev/kvm` opens read/write;
- the configured CLI is an absolute, single-link regular executable;
- the executable and every path component are root-owned and not group- or
  world-writable, with no symlinks;
- `--version` exactly matches the configured pinned CLI version;
- the public trust key is an absolute root-owned, non-writable regular file;
- runtime state ancestors are non-symlink directories owned by root or the
  runtime user and are not group/world-writable; state, container, and
  invocation directories are retained through anchored directory handles;
- the signed bundle, detached signatures, release metadata, inventory,
  architecture, versions, rollback floor, artifact owners, modes, and SHA-256
  digests verify;
- the configured kernel is a signed `unikraft_shell_kernel` artifact and the
  configured CPIO is a signed `initrd` artifact.

`CreateRequest.image` is the absolute signed bundle directory. OCI references
are rejected. Verified kernel and initrd descriptors are copied into a fresh
private invocation directory, so execution does not reopen an unverified
artifact pathname.

## Lifecycle and execution

`create` creates a logical handle. `start` either marks that handle running or
starts the configured initial command in a fresh micro-VM. Every direct
`BootstrapControl` exec starts another fresh micro-VM and returns its captured
stdout, stderr, exit status, timeout, or cancellation result. `Workload` exec is
rejected because the common contract requires workload execution to pass
through a persistent guest broker.

The exact host argv is:

```text
hyperlight-unikraft KERNEL
  [--initrd INITRD]
  --memory NMi --stack NMi --quiet
  [--mount HOST:GUEST]...
  [--net | --net-allow HOST_OR_IP... | --net-block HOST_OR_IP...]
  [--port PORT]...
  --exec "cd 'GUEST_DIRECTORY' && exec 'PROGRAM' 'ARG'..."
```

Arguments are passed directly to `execve`, never through a host shell. The
guest shell expression uses single-quote escaping. The host environment is
cleared and rebuilt as only `LANG=C` and `PATH=/usr/bin:/bin`.

Host stdin is always null. Initial-command stdout/stderr can be consumed once
through `attach`; direct exec returns bounded captured output. The adapter does
not advertise streamed I/O or signals. `StopRequest.grace` must equal the
launch-time `ProcessOptions.termination_grace`; a different value is rejected
rather than silently applying the wrong shutdown deadline.

Read-only mounts are copied into a new private staging directory for every
invocation. Symlinks, hard-linked files, special files, duplicate guest paths,
reserved guest paths, `:` mount ambiguity, and sources containing the runtime
staging root are rejected. Writable mounts are rejected because the CLI cannot
consume a securely anchored directory descriptor. All staging is removed on
normal exit, failure, timeout, cancellation, stop, cleanup, and dropped exec
futures; failed removals remain retryable through runtime cleanup.

## Control and MCP compatibility

`hyperlight-unikraft` does not provide the persistent supervisor transport
required by `sendbox-agent`. The adapter therefore advertises neither
`BrokeredExec` nor transport provisioning, and `provision_control_channel`
returns a structured transport-unavailable error. Agent planning fails before
container creation rather than receiving a fake in-process channel.

For a purpose-built one-shot guest, `execute_authenticated_once` copies
authenticated bootstrap material into an ephemeral mount at:

```text
/run/sendbox-control/bootstrap-material
```

The guest command must consume and erase that material. This is an explicit
single-launch bootstrap protocol, not a persistent MCP or supervisor channel.
Ports exist only for the lifetime of that one host process. Stdio MCP,
persistent network MCP sessions, and the full agent boundary are unsupported.

## Network policy

The adapter uses `HyperlightNetworkConfiguration`, not the full
`sendbox_policy::NetworkPolicy`, because the latter always carries DNS and
connection-budget semantics that the vendor CLI cannot enforce. Hyperlight can
enforce only its CLI disabled, allow-all, exact allow-list, or exact block-list
modes:

- hostnames are normalized and must be concrete;
- exact IPv4 `/32` and IPv6 `/128` entries are accepted and canonicalized;
- wildcard names, non-host CIDRs, destination port/protocol rules, custom DNS
  TTL/query budgets, and connection limits fail closed;
- blocked exact entries take precedence over identical allowed entries;
- hostname allows combined with blocked IPs, and IP allows combined with
  blocked hostnames, fail closed because the CLI cannot preserve that
  resolution-time precedence;
- networking with `allow_dns: false` fails closed because Hyperlight cannot
  guarantee resolver traffic is disabled;
- a listen port requires an explicit enabled network policy.

Hyperlight does not run the SendBox eBPF MCP inspector, guest eBPF bootstrap,
seccomp launcher, DNS broker, connection semaphore, or OCI environment
injection. The runtime must not be selected for a plan requiring those
features.

## Opt-in live qualification

The live test does nothing unless explicitly designated. Once
`SENDBOX_HYPERLIGHT_LIVE` is set, every missing variable, KVM failure,
signature failure, CLI mismatch, or guest failure is a test failure:

```bash
sudo env \
  SENDBOX_HYPERLIGHT_LIVE=1 \
  SENDBOX_HYPERLIGHT_EXECUTABLE=/usr/local/bin/hyperlight-unikraft \
  SENDBOX_HYPERLIGHT_CLI_VERSION=0.12.0 \
  SENDBOX_HYPERLIGHT_BUNDLE=/opt/sendbox/hyperlight-bundle \
  SENDBOX_HYPERLIGHT_PUBLIC_KEY=/etc/sendbox/release-public.key \
  SENDBOX_HYPERLIGHT_KERNEL=/opt/sendbox/hyperlight-bundle/kernel \
  SENDBOX_HYPERLIGHT_INITRD=/opt/sendbox/hyperlight-bundle/rootfs.cpio \
  SENDBOX_HYPERLIGHT_TRUST_ROOT_ID=production-v1 \
  SENDBOX_HYPERLIGHT_GUEST_VERSION=0.1.0 \
  SENDBOX_HYPERLIGHT_MIN_RELEASE=1 \
  SENDBOX_HYPERLIGHT_STATE=/var/lib/sendbox-live \
  cargo test -p sendbox-runtime-hyperlight --test live \
    -- --exact live_hyperlight_launch_when_designated --nocapture
```

Create `SENDBOX_HYPERLIGHT_STATE` before running the command, for example:

```bash
sudo install -d -m 0700 /var/lib/sendbox-live
```
