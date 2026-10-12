# Kata runtime architecture

`sendbox-runtime-kata` is the production Linux/KVM runtime adapter.
`sendbox-host` composes it with the production broker, authenticated guest
bootstrap, egress, MCP, secrets, credentials, Git policy, audit, snapshots, and
session-security lifecycle.

## Lifecycle and trust

1. Host preflight requires Linux, `/dev/kvm`, a root-owned non-writable nerdctl
   executable, containerd connectivity, a supported Kata v2 handler, and an
   independently supplied trust root.
2. `sendbox-bundle::verify_bundle` validates signature, trust-root ID, host and
   guest versions, architecture, release rollback floor, metadata, artifact
   digests, modes, owners, and link invariants before image acquisition.
3. The runtime additionally rejects a guest supervisor or exec launcher with an
   ELF `PT_INTERP` segment. The verified bytes therefore do not execute through
   libraries supplied by the workload image.
4. The workload image must use an immutable `@sha256:` reference. The verified
   bundle is bind-mounted read-only at `/opt/sendbox`.
5. `nerdctl create` installs the static trusted supervisor as the container
   command. `nerdctl start` starts only that supervisor; it does not launch the
   requested workload.

The bundle verifier proves the mounted artifacts, not the Kata kernel, initrd,
hypervisor, containerd daemon, or workload image signature. Those remain host
operator trust inputs.

The handler allowlist includes `io.containerd.kata.v2` and the
`kata-qemu`, `kata-clh`, `kata-fc`, `kata-dragonball`, and `kata-qemu-coco` v2
variants. This preserves explicit Kata hypervisor selection while rejecting
shared-kernel or unrelated handler names. Operators must verify the installed
handler-to-shim/hypervisor mapping; its label alone is not an attestation.

## VM-crossing control channel

Kata does not inherit a host file descriptor into the guest. The adapter
therefore advertises `RuntimeExecStdioControlChannel` and uses two restricted
containerd exec operations:

- a one-shot `inject-bootstrap` process receives the bootstrap and public trust
  root over stdin and creates root-owned immutable files inside the guest;
- a persistent `tunnel` process connects to the guest-local supervisor Unix
  socket and copies authenticated protocol bytes over its exec stdin/stdout.

Containerd and the Kata shim carry exec stdio across the VM boundary. The Unix
socket never leaves the guest, no host-global socket is published, and the
runtime lifecycle owns and terminates the exec process. Tunnel stderr is bounded
and is never mixed with protocol stdout.

## Broker and guest controls

The supervisor verifies the signed manifest again, prepares root-owned runtime
and replay directories, creates a cgroup v2 broker parent, and starts a verified
`sendbox-guest exec-broker` process as mandatory `ServiceId::Exec`. Readiness is
published only after its owner-only Unix socket is live.

After services start, the supervisor installs the existing NNP/TSYNC agent
profile. Direct `execve`, `execveat`, `clone3`, and `memfd_create` are denied in
the agent process. The broker alone starts the verified one-shot launcher. The
launcher resolves executable and cwd beneath retained descriptors, places the
child atomically in a cgroup, drops to the non-root project uid/gid, removes
capabilities, applies rlimits and seccomp, streams sequenced output, and performs
bounded cgroup/pidfd cleanup.

Mandatory broker death revokes readiness and terminates the session. Runtime
workload exec remains rejected with `WorkloadExecRequiresGuestBroker`.

## Explicit exclusions

- no shared-kernel runtime handler or silent runtime downgrade;
- no Apple or Hyperlight fallback;
- no claim that hosted GitHub runners boot Kata;
- no global stdout/stderr chronology beyond broker event sequence.

The live proof must run on a dedicated self-hosted Linux/KVM runner.

Persistent sessions compose authenticated secret delivery, MCP stdio/HTTP
policy, DNS/SOCKS/HTTP egress, interactive terminals, and optional mandatory
cgroup-subtree BPF observation. `NET_ADMIN` is added only for trusted egress;
`BPF`, `PERFMON`, and `SYS_RESOURCE` are added only when tracing is requested.
The non-root workload launcher still clears all capability sets.
