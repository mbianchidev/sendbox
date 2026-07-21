# Production guest BPF and artifact bundles

This document defines the production build and trust boundary for the guest
artifacts that future runtime adapters will consume. This surface does not
select a runtime, launch a guest, orchestrate agents, or configure guest
`PlatformControls`.

## Artifact flow

`packaging/guest/Dockerfile` uses immutable base-image and package pins to build:

1. `sendbox-guest` as a static musl binary;
2. `sendbox-exec-launcher` as a static musl binary linked against a pinned,
   source-built static libseccomp 2.6.0;
3. `native/bpf/observe.bpf.c` as a CO-RE eBPF object;
4. deterministic inventory, SPDX 2.3 SBOM, capability metadata, and the guest
   artifact manifest;
5. a deterministic rootfs tar and a scratch OCI image containing only the
   trusted runtime artifacts and metadata.

The final rootfs contains no Python, Node.js, compiler, bpftrace, development
headers, or shared runtime libraries. CI builds each architecture twice with
`--no-cache` and compares the rootfs, manifest, signature, inventory, SBOM,
static-link proofs, and pinned `vmlinux.h` digest byte for byte.

## Signing boundary

`sendbox-bundle stage` requires a caller-supplied 32-byte Ed25519 private key
through a file. The tool never creates a signing key, writes the private key
into the bundle, or provides a production key-custody mechanism. Docker accepts
the key only as the required BuildKit secret `release_signing_key`.

The guest artifact envelope remains exactly schema v1 verified by
`sendbox_guest::manifest`; its artifact-kind enum is unchanged and contains
only guest, service, and BPF objects. A matching detached `manifest.sig` is
emitted for release systems that store signatures separately.

Inventory, SBOM, build-input metadata, and the deterministic verification
report are covered by the separately versioned
`dev.sendbox.guest.release-metadata.v1` envelope and detached signature. This
avoids silently extending the guest manifest v1 wire contract.
The signer receives the verified BTF archive digest and the freshly generated
`vmlinux.h` digest from the build stages; it does not infer or hardcode them.
`release-public.key` in exported build artifacts is informational and useful
for CI; it is not a trust anchor. Runtime adapters must provision the expected
public key and `trust_root_id` through an independent trusted channel.

Release sequence, minimum accepted sequence, host version, guest version,
architecture, SHA-256 digest, mode, uid, gid, regular-file type, and single-link
expectations are verified before launch. Verification is descriptor-relative
and rejects symlinks, hardlinks, wrong architecture, rollback, tampering, and
mode or owner drift.

## BPF boundary

`sendbox-bpf` is a safe Rust facade over libbpf-rs. No SendBox Rust source uses
unsafe code. The facade provides:

- typed kernel, BTF, tracepoint, and capability probes;
- explicit unavailable, permission, relocation, load, attach, decode, timeout,
  invalid-input, and internal errors;
- owned object, link, ring-buffer, map, and callback lifecycle;
- bounded deterministic decoding for exec, syscall-entry, and reserved MCP
  observation ABIs;
- kernel ring-reservation, userspace queue-drop, and decode-failure accounting.

The production programs observe `sched:sched_process_exec` and
`raw_syscalls:sys_enter`. Attachment requires a non-zero target cgroup id, and
both programs discard events outside that cgroup. This prevents a guest-wide or
host-wide syscall firehose. The programs do not parse policy, network traffic,
daemon protocols, or MCP payloads.

The MCP event ABI is reserved and bounded for a later, explicitly proven
producer. This release attaches no generic MCP hook and makes no MCP capture
claim.

All BPF behavior in this release is **observation/audit only**. Tracepoints run
after or alongside kernel actions and cannot authorize or deny them. Nothing in
this crate should be described as command, syscall, network, or MCP
enforcement.

## Kernel and build requirements

Runtime requirements:

- Linux 5.8 or newer;
- `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`, tracepoints,
  and ring-buffer maps;
- readable `/sys/kernel/btf/vmlinux`;
- `sched:sched_process_exec` and `raw_syscalls:sys_enter` in tracefs;
- `CAP_BPF` plus `CAP_PERFMON`, or legacy `CAP_SYS_ADMIN`;
- a runtime policy that permits the `bpf` syscall;
- a cgroup v2 identity supplied by the future runtime adapter.

Build inputs:

- Rust 1.93.1 and Alpine 3.23;
- clang/LLVM 21.1.2 and bpftool 6.19.14;
- libbpf-rs 0.26.2 / libbpf 1.7.0;
- BTFHub archive commit
  `abbcdfab668b9a346a24cb0829f1cfbb80bc51db`;
- Ubuntu 20.04 `5.8.0-63-generic` BTF archives with architecture-specific
  SHA-256 verification;
- libseccomp 2.6.0 source archive with SHA-256 verification.

Generated `vmlinux.h` and BPF objects are build outputs, not checked-in source.
The C build enables strict warnings and compile-time ABI size assertions, then
checks for `.BTF`, `.BTF.ext`, and both required tracepoint sections.
`bpftool gen min_core_btf` resolves the object's CO-RE relocation requirements
against the pinned architecture BTF and emits a reproducible proof digest.

## Runtime integration API

A future runtime adapter must:

1. verify the bundle with an independently provisioned Ed25519 public key,
   expected versions, architecture, and rollback floor;
2. retain verified executable descriptors from the guest manifest verifier;
3. probe the target guest kernel before launch;
4. identify the sandbox cgroup v2 id;
5. call `EventStream::attach(object_bytes, AttachConfig { target_cgroup_id })`;
6. poll bounded batches, record `LossSnapshot`, and keep the `EventStream` alive
   for the intended observation lifetime;
7. treat any required observation failure according to explicit runtime policy,
   without upgrading observation into an enforcement claim.

No runtime adapter is wired by this change.

## Reproduce locally

Use an externally managed key:

```bash
docker buildx build \
  --no-cache \
  --platform linux/arm64 \
  --target artifact \
  --secret id=release_signing_key,src=/secure/path/release-ed25519.key \
  --output type=local,dest=dist/arm64 \
  -f packaging/guest/Dockerfile \
  .
```

Use `linux/amd64` for x86_64. Never place a production private key in the build
context, image, repository, CI variables exposed to pull requests, or command
line.
