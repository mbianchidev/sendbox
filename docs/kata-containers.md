# Kata Containers Runtime

## Experimental Rust vertical slice

The Rust CLI now exposes one deliberately thin command:

```bash
sendbox-rs run \
  --config /absolute/path/.sendbox.yaml \
  --runtime kata \
  --image registry.example/workload@sha256:<digest> \
  --bundle /absolute/path/to/verified-bundle \
  --trust-root /absolute/path/to/release-public.key \
  --trust-root-id external-release-root \
  --minimum-release-sequence 1 \
  -- /usr/bin/printf '%s\n' hello
```

The command after `--` is an exact argv vector. The guest executable and working
directory must be absolute; no shell parses or joins the arguments. `--json`
emits deterministic `output`, `result`, and `error` records. Binary output is
hex encoded. The process exit code is propagated when broker cleanup is
complete; cancellation uses 130.

The workload image must be digest-pinned. The bundle and trust-root paths are
host paths, and the project path in the configuration must be absolute and
owned by a non-root uid/gid. The bundle must contain the signed static
`bin/sendbox-guest` and `bin/sendbox-exec-launcher` artifacts produced by
`packaging/guest/Dockerfile`.

This command never invokes or falls back to Swift.

SendBox can run sandboxes on Linux through [Kata Containers](https://katacontainers.io/), using `nerdctl` to create each workload with the Kata containerd shim. The agent runs in a dedicated hardware-virtualized guest rather than sharing the host kernel.

## Requirements

- Linux on bare metal or a VM with nested virtualization
- Rust 1.93.1
- Kata Containers 3.28 or newer
- containerd 1.7 or newer
- CNI plugins
- nerdctl
- Access to `/dev/kvm` and the containerd socket

Verify the host before running SendBox:

```bash
kata-runtime check
nerdctl info
nerdctl run --rm --runtime io.containerd.kata.v2 \
  docker.io/library/busybox:latest uname -a
```

Do not run SendBox with `sudo` merely to reach containerd. Grant the user access to the containerd socket or configure a rootless containerd installation with access to the host virtualization device.

## Configure containerd

Register the Kata shim as a containerd runtime. For containerd 2.x:

```toml
version = 3

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  privileged_without_host_devices = true
```

For containerd 1.7:

```toml
version = 2

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  privileged_without_host_devices = true
```

Restart containerd after changing its configuration. The default SendBox handler is the shim runtime type `io.containerd.kata.v2`; custom shims such as `io.containerd.kata-qemu.v2` are also supported.

## SendBox configuration

```yaml
runtime:
  provider: kata
  kata:
    executable: nerdctl
    runtime_handler: io.containerd.kata.v2
    namespace: sendbox
    # address: /run/containerd/containerd.sock
    # snapshotter: overlayfs
    # configuration_path: /etc/kata-containers/configuration.toml
```

The historical Swift command remains outside this slice. Use the explicit Rust
command and all trust inputs shown above:

```bash
sendbox-rs run --config .sendbox.yaml --runtime kata \
  --image "$IMAGE_DIGEST" --bundle "$BUNDLE" --trust-root "$TRUST_ROOT" \
  -- /usr/bin/true
```

`runtime.provider: auto` selects Apple Containerization on supported macOS hosts and Kata Containers on Linux.

### Kata options

| Key | Default | Description |
|---|---|---|
| `executable` | `nerdctl` | nerdctl executable name or absolute path |
| `runtime_handler` | `io.containerd.kata.v2` | containerd runtime v2 handler |
| `namespace` | `sendbox` | containerd namespace used for SendBox containers |
| `address` | nerdctl default | containerd socket address |
| `snapshotter` | nerdctl default | containerd snapshotter |
| `configuration_path` | Kata default | Absolute Kata configuration path on the containerd host |

`configuration_path` is passed as the supported `io.katacontainers.config_path` OCI annotation. The file must exist on the containerd host and be readable by the Kata shim.

## Runtime behavior

- CPU, memory, hostname, DNS, working directory, image, command, and bind mounts map to `nerdctl run`.
- `disk_size_mb` is delegated to the configured containerd snapshotter because nerdctl does not expose a portable per-container writable-layer quota.
- Single-line environment values are written to a mode `0600` temporary env file, passed with `--env-file`, and deleted immediately after container creation. Multi-line values are inherited by key through the nerdctl client environment, so secret values never appear in argv.
- SendBox adds `NET_ADMIN` only when the configured firewall script needs it.
- eBPF MCP inspection adds `BPF`, `PERFMON`, and `SYS_PTRACE`; the guest kernel must expose BTF and the image must support `bpftrace`.
- Firewall and MCP startup scripts remain best-effort and log explicit failures.
- Boundary mode runs the trusted bootstrap with the Kata VM's PID namespace,
  temporarily adds the BPF/sysctl capabilities it needs, and disables the outer
  container seccomp profile. SendBox then waits for the boundary readiness
  marker; the generated inner seccomp launcher and non-root UID constrain the
  agent and every later `nerdctl exec`.

## Secrets on Linux

The `sendbox secrets` commands use a file-backed store under `~/.sendbox/secrets`. Directories are mode `0700`, secret files are mode `0600`, and filenames are encoded so secret names cannot escape the store. Proxy credential mode currently requires Apple's Network framework; use environment credential injection on Linux.

## Troubleshooting

**`permission denied` from `nerdctl info`**

Configure access to the containerd socket or a rootless containerd service. Also verify access to `/dev/kvm`.

**`failed to create shim task` or runtime not found**

Confirm `containerd-shim-kata-v2` is installed in containerd's executable path and that `runtime_handler` matches the installed shim.

**No network in the guest**

Install CNI plugins and verify nerdctl can run a normal container with the default bridge network before testing Kata.

**Custom Kata configuration is ignored**

Use an absolute `configuration_path` that exists on the containerd host. Check the Kata shim logs with:

```bash
journalctl -t kata
```

Hosted GitHub Actions runners do not expose nested virtualization. Normal CI
compiles Linux and runs the fake-nerdctl/authenticated-channel conformance tests.
Live qualification is a separate required self-hosted gate:

```bash
cargo build --workspace --release
SENDBOX_KATA_LIVE=1 \
SENDBOX_KATA_CONFIG=/absolute/path/.sendbox.yaml \
SENDBOX_KATA_IMAGE=registry.example/workload@sha256:<digest> \
SENDBOX_KATA_BUNDLE=/absolute/path/to/bundle \
SENDBOX_KATA_TRUST_ROOT=/absolute/path/to/release-public.key \
./scripts/qualify-kata-live.sh
```

The script fails when any input, KVM, containerd, Kata, readiness, brokered
execution, exit propagation, or cleanup proof is missing. It never reports a
successful skip.
