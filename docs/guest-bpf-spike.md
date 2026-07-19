# Phase 1 guest BPF spike

`spikes/guest-bpf` is an isolated proof of concept for the riskiest guest build
assumption. It does not depend on the repository's root build and does not
implement authorization, enforcement, policy, seccomp, networking, MCP, or the
final guest supervisor.

The spike builds a Rust multi-call helper that embeds one C/libbpf CO-RE
`sched_process_exec` tracepoint program. The program only observes process-exec
metadata and submits bounded events through a ring buffer.

## Proof result

The static-link gate passes for both required targets in the pinned container:

| Target | `file` result | Interpreter | Shared `NEEDED` entries | Live proof |
|---|---|---|---|---|
| `x86_64-unknown-linux-musl` | static PIE | none | none | opt-in, not run on a native x86_64 kernel |
| `aarch64-unknown-linux-musl` | static executable | none | none | attach and self-exec event delivery passed |

The build uses Rust 1.93.1, clang/LLVM 21.1.2, bpftool 6.19.14,
libbpf-rs 0.26.2, and libbpf 1.7.0 from libbpf-sys. Architecture-specific
`vmlinux.h` files are generated during the build from Ubuntu 20.04
5.8.0-63-generic BTF archives pinned to BTFHub commit
`abbcdfab668b9a346a24cb0829f1cfbb80bc51db` and verified by SHA-256.
Generated headers and BPF objects are not committed.

- x86_64 generated header: `e1f227a1fdd24f5931d421dc52224c250ccbf1dd0e8cde9e7557417adaa921b7`
- arm64 generated header: `6dbb3784bde9a055e28d852dc628d60dbaca01d7260090a1c7eeb86b6f25b63c`

Fully vendored libelf was also tested and failed truthfully because elfutils
requires glibc `argp` under musl. The working static path vendors libbpf and
uses pinned musl-native static libelf, zlib, and zstd. Alpine's libelf archive
contains a one-symbol fallback `crc32.o`; the container removes that fallback
so pinned libz is the sole `crc32` provider. Arm64 also links the pinned GCC
atomic runtime required by optimized libbpf code. Static verification fails on
any dynamic interpreter or shared dependency.

Build/static delivery is proven on both architectures. Native arm64 attachment
and event delivery passed on the local Linux 7.0.11 OrbStack kernel after
mounting tracefs. Native x86_64 live delivery remains unverified. Live testing
is explicitly opt-in, and CI does not claim success when GitHub-hosted runners
cannot grant BPF privileges.

## Build

Run all formatting, clippy, unit, audit, and strict CO-RE compile checks:

```bash
docker build --no-cache --target quality spikes/guest-bpf
```

Export either static artifact:

```bash
docker buildx build \
  --no-cache \
  --platform linux/amd64 \
  --target artifact \
  --output type=local,dest=dist/amd64 \
  spikes/guest-bpf

docker buildx build \
  --no-cache \
  --platform linux/arm64 \
  --target artifact \
  --output type=local,dest=dist/arm64 \
  spikes/guest-bpf
```

Each output contains the binary, a `file`/`ldd`/`readelf` proof, and the
generated `vmlinux.h` checksum. The dedicated workflow builds every target
twice without cache and compares the resulting binaries byte for byte.

## Run

The commands emit compact JSON with stable field ordering:

```bash
./sendbox-guest-bpf preflight
sudo ./sendbox-guest-bpf attach
sudo ./sendbox-guest-bpf events --max-events 16 --timeout-ms 5000
sudo env SENDBOX_GUEST_BPF_LIVE=1 ./sendbox-guest-bpf self-test
```

`attach` is a load/attach probe: the link remains active only for that command's
scope. `self-test` copies the static guest helper to a unique temporary path,
executes that copy, and passes only after receiving the event for that exact
path. It reports both spawned and observed PIDs because BPF may report the
initial PID namespace while the process API reports a container PID.
Without `SENDBOX_GUEST_BPF_LIVE=1`, or without required kernel support and
privileges, it returns a typed unavailable or permission diagnostic instead of
a success-shaped fallback.

## Kernel and privilege requirements

- Linux 5.8 or newer with `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`,
  `CONFIG_DEBUG_INFO_BTF`, tracepoints, and ring-buffer maps.
- Readable `/sys/kernel/btf/vmlinux`.
- `CAP_BPF` plus `CAP_PERFMON`, or `CAP_SYS_ADMIN` for legacy capability
  models. The container/runtime must also permit the `bpf` syscall.
- The `sched:sched_process_exec` tracepoint.
- Mounted tracefs at `/sys/kernel/tracing` or `/sys/kernel/debug/tracing`.
- `/sys/fs/bpf` is reported but not required because this spike does not pin
  maps or links.
- `/sys/kernel/security/lsm` is reported when mounted. BPF LSM presence is not
  required for this observation-only tracepoint.

Diagnostics distinguish unsupported/unavailable hosts, permission denial,
best-effort CO-RE relocation identification from libbpf logs, verifier/load
failure, attach failure, malformed event decoding, and event timeout.

## Remaining enforcement questions

The enforcement ADR still must decide the supported kernel/BTF/BPF LSM matrix,
which hooks are mandatory, capability-drop sequencing, relocation diagnostics,
link/map lifetime and cleanup policy, artifact signing, and the fallback when a
required LSM hook is unavailable. This spike provides no authorization or
enforcement evidence.
