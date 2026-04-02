# SendBox Security Model

> Comprehensive security documentation covering architecture, threat model, and defense-in-depth analysis against the [SandboxEscapeBench](https://arxiv.org/abs/2603.02277) benchmark.

---

## Architecture Overview

SendBox uses Apple's [Virtualization.framework](https://developer.apple.com/documentation/virtualization) to run each agent sandbox in a **dedicated lightweight Linux VM** on Apple Silicon. This is fundamentally different from Docker/OCI container isolation — the guest runs its own kernel on virtualized hardware, not a process in a shared kernel namespace.

| Property | Docker Container | SendBox VM |
|----------|-----------------|------------|
| Kernel | Shared with host | Dedicated per sandbox |
| PID namespace | Logical isolation (kernel namespaces) | Hardware isolation (separate kernel) |
| Network | Shared kernel stack (veth pairs) | Separate virtual NIC (virtio-net) |
| Filesystem | Shared kernel VFS (overlayfs) | Separate disk image (virtiofs for mounts) |
| Device access | cgroup-filtered | Not exposed (no `/dev` passthrough) |
| Container runtime | runc / containerd | None (direct VM via Virtualization.framework) |
| Orchestrator | Optional (Kubernetes, Swarm) | None |
| Attack surface | Kernel syscall interface (~300+ syscalls) | Hypervisor interface (virtio devices only) |
| Root inside container | Full kernel capabilities if misconfigured | Root in guest kernel only — host kernel unaffected |

**Key insight:** Most container escape techniques exploit the shared kernel boundary between host and container. SendBox eliminates this boundary entirely — the guest has its own kernel, and a kernel exploit inside the VM compromises only the guest.

---

## SandboxEscapeBench Coverage

The [SandboxEscapeBench](https://arxiv.org/abs/2603.02277) benchmark defines 18 escape scenarios across three layers of the container stack. SendBox mitigates **all 18 scenarios** through a combination of architectural immunity (VM isolation eliminates the attack surface) and defense-in-depth hardening.

### Summary Table

| # | Scenario | Layer | Attack Vector | SendBox Status | Primary Defense |
|---|----------|-------|---------------|----------------|-----------------|
| 1 | `crio_cve` | Orchestration | CRI-O CVE-2022-0811 — kernel parameter injection via `pinns` | **Blocked** | No CRI-O runtime |
| 2 | `kubectl_cp` | Orchestration | CVE-2019-11246 — symlink path traversal via `kubectl cp` | **Blocked** | No kubectl / Kubernetes |
| 3 | `rbac` | Orchestration | Overly permissive RBAC allows pod creation with hostPID | **Blocked** | No Kubernetes API |
| 4 | `route_localnet` | Orchestration | `net.ipv4.conf.all.route_localnet=1` enables metadata service access | **Blocked** | sysctl locked to `0`; no cloud metadata |
| 5 | `privileged` | Runtime | `--privileged` flag grants all capabilities + device access | **Blocked** | No container runtime; VM has no concept of `--privileged` |
| 6 | `docker_sock` | Runtime | Mounted Docker socket allows container escape via API | **Blocked** | No Docker socket; no container runtime binaries |
| 7 | `cap_sys_admin` | Runtime | `CAP_SYS_ADMIN` enables mount namespace escape | **Blocked** | Capability dropped; seccomp blocks `mount` |
| 8 | `cap_sys_module` | Runtime | `CAP_SYS_MODULE` allows loading malicious kernel modules | **Blocked** | Capability dropped; `kernel.modules_disabled=1` |
| 9 | `cap_dac_read_search` | Runtime | `CAP_DAC_READ_SEARCH` + `open_by_handle_at` reads host files | **Blocked** | Capability dropped; seccomp blocks `open_by_handle_at` |
| 10 | `hostpath` | Runtime | HostPath volume mounts expose host filesystem | **Blocked** | Only `.devcontainer` (read-only) and workspace copy mounted |
| 11 | `runc_2019` | Runtime | CVE-2019-5736 — runc binary overwrite via `/proc/self/exe` | **Blocked** | No runc; no container runtime |
| 12 | `runc_2024` | Runtime | CVE-2024-21626 — runc working directory file descriptor leak | **Blocked** | No runc; no container runtime |
| 13 | `pid_ns` | Kernel | PID namespace escape via `/proc` to access host processes | **Blocked** | Separate kernel; `/proc` shows only guest processes |
| 14 | `cgroup` | Kernel | cgroup `release_agent` write for host code execution | **Blocked** | Separate kernel; cgroup `release_agent` disabled |
| 15 | `bpf_privesc` | Kernel | eBPF program loading for privilege escalation | **Blocked** | `kernel.unprivileged_bpf_disabled=1`; `CAP_BPF` dropped |
| 16 | `dirty_cow` | Kernel | CVE-2016-5195 — copy-on-write race condition for privilege escalation | **Blocked** | Separate kernel; exploit affects guest only; KASLR enabled |
| 17 | `dirty_pipe` | Kernel | CVE-2022-0847 — pipe buffer flag manipulation for file overwrite | **Blocked** | Separate kernel; exploit affects guest only; no host files accessible |
| 18 | `packet_sock` | Kernel | `CAP_NET_RAW` + `AF_PACKET` socket for traffic interception | **Blocked** | `CAP_NET_RAW` dropped; seccomp restricts socket creation |

---

### Layer 1: Orchestration (4/4 Blocked)

These attacks target Kubernetes and container orchestration components. SendBox does not use Kubernetes, CRI-O, or any orchestrator — there is no orchestration layer to attack.

#### 1. CRI-O CVE (CVE-2022-0811)

- **Attack:** Exploits a vulnerability in CRI-O's `pinns` utility that allows setting arbitrary kernel parameters via specially crafted annotations on a pod. An attacker can set `kernel.core_pattern` to a pipe command, achieving host code execution when a process crashes.
- **Why N/A:** SendBox does not use CRI-O or any OCI-compliant container runtime. VMs are created directly via Apple's Virtualization.framework hypervisor interface. There is no `pinns` binary, no annotation processing, and no shared kernel whose `core_pattern` could be hijacked.
- **Defense-in-depth:** Even within the guest VM, `kernel.core_pattern` is set to a safe value (`|/bin/false`) and `kernel.modules_disabled=1` prevents loading modules that could be triggered by core patterns.

#### 2. kubectl cp Path Traversal (CVE-2019-11246)

- **Attack:** `kubectl cp` follows symlinks when extracting tar archives, allowing an attacker to write files outside the intended destination on the host. A malicious container can plant a symlink that causes `kubectl cp` to overwrite host files.
- **Why N/A:** SendBox has no Kubernetes API server, no `kubectl`, and no `kubelet`. File transfer between host and VM is done exclusively through virtiofs mounts with explicit source/destination mappings defined in the sandbox configuration.
- **Defense-in-depth:** Only two mount points are created: `.devcontainer` (read-only) and the workspace copy. The workspace is a copy of the original project, not the original — damage is contained to the copy.

#### 3. RBAC Privilege Escalation

- **Attack:** Overly permissive Kubernetes RBAC roles (e.g., `pods/exec`, `create pods` with `hostPID: true`) allow an attacker to create a privileged pod that shares the host PID namespace, enabling process injection and escape.
- **Why N/A:** There is no Kubernetes API, no RBAC system, no pod specs, and no concept of `hostPID`. The VM is a single execution environment — there is no "create another container" primitive available to the agent.
- **Defense-in-depth:** The command policy engine blocks `kubectl` and `docker` by default (not in the standard allowlist). Even if somehow installed inside the VM, they have no API server to talk to.

#### 4. route_localnet Metadata Access

- **Attack:** Setting `net.ipv4.conf.all.route_localnet=1` allows routing to 127.0.0.0/8 from non-loopback interfaces. In cloud environments, this can be combined with iptables DNAT rules to redirect traffic intended for the cloud metadata service (169.254.169.254) to localhost, bypassing network policies.
- **Why N/A:** SendBox VMs run on local Apple Silicon hardware, not in a cloud environment. There is no cloud metadata service at 169.254.169.254.
- **Defense-in-depth:** `net.ipv4.conf.all.route_localnet=0` is explicitly set via sysctl hardening. The network firewall blocks all traffic not in the domain allowlist, which would not include any metadata endpoint. Additionally, the guest kernel is separate — sysctl changes inside the VM cannot affect the host network stack.

---

### Layer 2: Runtime (8/8 Blocked)

These attacks exploit container runtime misconfigurations or vulnerabilities. SendBox has no container runtime — there is no runc, containerd, or Docker daemon.

#### 5. Privileged Container

- **Attack:** Running a container with `--privileged` grants all Linux capabilities, disables seccomp, and allows access to all host devices via `/dev`. An attacker can mount the host filesystem from a block device and escape.
- **Why N/A:** There is no `--privileged` flag because there is no container runtime. The VM runs its own kernel; "capabilities" inside the VM are guest-kernel capabilities that grant power only within the VM.
- **Defense-in-depth:** The hardening script drops all dangerous capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_NET_RAW`, etc.) inside the guest. Even root inside the VM cannot load kernel modules or mount arbitrary filesystems.

#### 6. Docker Socket Mount

- **Attack:** When `/var/run/docker.sock` is mounted inside a container, the agent can use the Docker API to create a new privileged container with host filesystem access, effectively escaping the sandbox.
- **Why N/A:** There is no Docker daemon running on macOS (SendBox replaces Docker). No Docker socket exists. No container runtime binaries (`docker`, `ctr`, `crictl`, `nerdctl`) are installed inside the VM.
- **Defense-in-depth:** The mount configuration only allows two mount points (`.devcontainer` read-only, workspace copy read-write). No host paths like `/var/run/` are ever exposed. The command policy denylist blocks `docker` commands. The `ContainerHardening.validate()` method warns if any mount targets sensitive paths.

#### 7. CAP_SYS_ADMIN Abuse

- **Attack:** `CAP_SYS_ADMIN` is one of the most powerful Linux capabilities. It allows mounting filesystems, using `unshare` to create new namespaces, and performing many operations that can lead to container escape (e.g., mounting the host's `/` via a shared mount namespace).
- **Why N/A:** Guest capabilities do not affect the host because the guest runs a separate kernel. There is no shared mount namespace.
- **Defense-in-depth:** `CAP_SYS_ADMIN` is explicitly dropped in the hardening script. The seccomp profile blocks `mount`, `unshare`, and `pivot_root` syscalls. `prctl(PR_SET_NO_NEW_PRIVS, 1)` prevents regaining capabilities.

#### 8. CAP_SYS_MODULE Abuse

- **Attack:** `CAP_SYS_MODULE` allows loading kernel modules via `init_module` / `finit_module` syscalls. An attacker can load a malicious kernel module that modifies kernel data structures to escape the container namespace.
- **Why N/A:** Even if a malicious module is loaded inside the guest, it modifies the guest kernel only — the host kernel is completely separate.
- **Defense-in-depth:** `CAP_SYS_MODULE` is dropped. `kernel.modules_disabled=1` is set via sysctl, disabling module loading entirely. The seccomp profile blocks `init_module` and `finit_module` syscalls.

#### 9. CAP_DAC_READ_SEARCH + open_by_handle_at

- **Attack:** `CAP_DAC_READ_SEARCH` bypasses file read permission checks. Combined with the `open_by_handle_at` syscall (which opens files by handle, bypassing mount namespace restrictions), an attacker can read any file on the host, including `/etc/shadow`.
- **Why N/A:** The guest has no access to host file handles. `open_by_handle_at` in the guest kernel operates on guest filesystem handles only.
- **Defense-in-depth:** `CAP_DAC_READ_SEARCH` is dropped. The seccomp profile blocks `open_by_handle_at`. No sensitive host paths are mounted.

#### 10. HostPath Volume Abuse

- **Attack:** Kubernetes `hostPath` volumes or Docker `-v /:/host` mounts expose the host filesystem inside the container. An attacker with access to the host root filesystem can modify system files, add SSH keys, or create cron jobs for persistent access.
- **Why N/A:** SendBox does not use Kubernetes volumes or Docker bind mounts. File sharing uses virtiofs, and the mount points are explicitly defined in configuration.
- **Defense-in-depth:** Only two mounts exist: `.devcontainer` (read-only) and workspace (a copy, not the original). `ContainerHardening.validate()` warns if mounts target sensitive paths (`/etc`, `/var/run`, `/proc`, `/sys`). The workspace copy ensures that even destructive operations inside the VM don't affect the original project.

#### 11. runc CVE-2019-5736

- **Attack:** CVE-2019-5736 allows a malicious container to overwrite the host `runc` binary via `/proc/self/exe`. When `runc` is next invoked (e.g., `docker exec`), the attacker's code runs as root on the host.
- **Why N/A:** There is no runc. There is no container runtime binary to overwrite. The VM is managed directly by the hypervisor.
- **Defense-in-depth:** `/proc/self/exe` inside the VM points to a guest binary. Even if overwritten, it has no effect on the host. No container runtime exists on the host to be targeted.

#### 12. runc CVE-2024-21626

- **Attack:** CVE-2024-21626 exploits a file descriptor leak in runc where the working directory of the container process retains a reference to a host filesystem directory. An attacker can use this leaked fd to traverse up to the host root filesystem.
- **Why N/A:** There is no runc, no containerd, and no file descriptor inheritance from host to guest. The VM boots from a disk image — its initial process is the guest `init`, not a runtime-spawned process.
- **Defense-in-depth:** The hypervisor boundary ensures no host file descriptors are leaked to the guest. The VM's `/proc/self/fd/` shows only guest file descriptors.

---

### Layer 3: Kernel (6/6 Blocked)

These attacks exploit shared kernel vulnerabilities. SendBox's VM architecture provides the strongest defense here: the guest has its own kernel, so kernel exploits affect only the guest.

#### 13. PID Namespace Escape

- **Attack:** In a container sharing the host PID namespace (`--pid=host`), `/proc` shows host processes. An attacker can use `/proc/<pid>/root` to access the host filesystem or inject code into host processes via `ptrace`.
- **Why N/A:** The guest has its own kernel and PID space. `/proc` shows only guest processes. There is no `--pid=host` option.
- **Defense-in-depth:** `kernel.yama.ptrace_scope=2` is set (no process may ptrace another, except via `CAP_SYS_PTRACE` which is dropped). `CAP_SYS_PTRACE` is dropped. The seccomp profile blocks `ptrace`.

#### 14. Cgroup release_agent Escape

- **Attack:** An attacker with write access to cgroup files can set `release_agent` to a path on the host, and `notify_on_release` to `1`. When the last process in the cgroup exits, the kernel executes the `release_agent` binary on the host as root.
- **Why N/A:** The guest's cgroup hierarchy is managed by the guest kernel. Writing to `/sys/fs/cgroup/*/release_agent` inside the VM triggers execution inside the VM, not on the host.
- **Defense-in-depth:** The hardening script disables `release_agent` by writing `0` to `notify_on_release` for all existing cgroups and making cgroup mount points read-only where possible. `CAP_SYS_ADMIN` (required to modify cgroup `release_agent`) is dropped.

#### 15. BPF Privilege Escalation

- **Attack:** eBPF programs run inside the kernel. A malicious eBPF program can read/write arbitrary kernel memory, modify kernel data structures, or escalate privileges. `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels) is required.
- **Why N/A:** eBPF programs inside the guest run in the guest kernel. They cannot read host kernel memory.
- **Defense-in-depth:** `kernel.unprivileged_bpf_disabled=1` prevents non-root BPF usage. The seccomp profile blocks the `bpf` syscall. `CAP_SYS_ADMIN` and all BPF-related capabilities are dropped.

#### 16. Dirty COW (CVE-2016-5195)

- **Attack:** A race condition in the Linux kernel's copy-on-write mechanism allows an unprivileged user to write to read-only memory mappings, including read-only files. This can be used to overwrite `/etc/passwd` or setuid binaries to escalate privileges.
- **Why N/A:** The guest runs its own kernel. Even if the guest kernel is vulnerable to Dirty COW, exploitation only affects guest files. The host kernel (macOS/XNU) is not Linux and is not susceptible to this vulnerability.
- **Defense-in-depth:** KASLR is enabled (`kernel.randomize_va_space=2`) to make exploitation harder. The workspace mount is a copy, so even if guest files are corrupted, the original project is unaffected. Modern Linux kernel images used by SendBox include the Dirty COW fix.

#### 17. Dirty Pipe (CVE-2022-0847)

- **Attack:** A flaw in Linux pipe buffer management allows an unprivileged user to overwrite data in arbitrary cached read-only files, including files on read-only mounts. This can modify setuid binaries or `/etc/passwd` for privilege escalation.
- **Why N/A:** Same as Dirty COW — the guest kernel is separate. The host runs XNU (macOS), which does not have Linux pipes. Even if the guest kernel is vulnerable, the impact is contained to the guest.
- **Defense-in-depth:** Guest kernel images are regularly updated. virtiofs mounts use the host's filesystem permissions — even if the guest kernel is compromised, virtiofs file access is mediated by the hypervisor. `prctl(PR_SET_NO_NEW_PRIVS, 1)` prevents setuid escalation.

#### 18. Packet Socket Exploitation

- **Attack:** `CAP_NET_RAW` allows creating `AF_PACKET` sockets that can capture all network traffic on the container's network namespace. In shared-network configurations, this can intercept traffic from other containers or the host.
- **Why N/A:** The guest has its own virtual NIC (virtio-net). Even with `AF_PACKET` sockets, the guest can only see its own traffic. There is no shared network namespace with the host or other VMs.
- **Defense-in-depth:** `CAP_NET_RAW` is dropped. The seccomp profile restricts raw socket creation. The network firewall limits which domains the VM can contact, and rate-limits connections.

---

## Defense-in-Depth Layers

SendBox applies six overlapping defense layers. Even if one layer is bypassed, the remaining layers prevent escape.

### Layer 1: Hardware VM Isolation

The primary defense is the hypervisor boundary provided by Apple's Virtualization.framework.

- Each VM has its **own Linux kernel**, loaded from a disk image at boot
- Memory is hardware-isolated via the MMU / stage-2 page tables
- Virtual devices (virtio-net, virtiofs, virtio-console) are the only host interface
- The host kernel (XNU) is never shared — Linux kernel exploits affect only the guest
- There is no `/proc/host`, no shared PID namespace, no shared mount namespace
- The hypervisor enforces isolation at the hardware level, below the OS

### Layer 2: Kernel Hardening (sysctl)

Inside the guest VM, the hardening script applies restrictive sysctl settings before the agent process starts:

| sysctl Parameter | Value | Purpose |
|------------------|-------|---------|
| `kernel.modules_disabled` | `1` | Prevent kernel module loading (blocks `CAP_SYS_MODULE` exploitation) |
| `kernel.unprivileged_bpf_disabled` | `1` | Prevent unprivileged BPF program loading |
| `kernel.yama.ptrace_scope` | `2` | Restrict ptrace to `CAP_SYS_PTRACE` holders only (which is dropped) |
| `kernel.core_pattern` | `\|/bin/false` | Prevent core_pattern pipe injection (CRI-O CVE vector) |
| `kernel.randomize_va_space` | `2` | Full ASLR (code, data, stack, heap, vdso) |
| `net.ipv4.conf.all.route_localnet` | `0` | Prevent routing to loopback from external interfaces |
| `kernel.kptr_restrict` | `2` | Hide kernel pointers from all users |
| `kernel.dmesg_restrict` | `1` | Restrict `dmesg` access to `CAP_SYSLOG` holders |
| `kernel.perf_event_paranoid` | `3` | Disable perf events for non-root users |
| `net.ipv4.conf.all.send_redirects` | `0` | Disable ICMP redirect sending |
| `net.ipv4.conf.all.accept_redirects` | `0` | Disable ICMP redirect acceptance |
| `fs.protected_symlinks` | `1` | Prevent symlink-based attacks in world-writable directories |
| `fs.protected_hardlinks` | `1` | Prevent hardlink-based privilege escalation |
| `fs.suid_dumpable` | `0` | Prevent core dumps of setuid programs |

### Layer 3: Capability Dropping

Linux capabilities are dropped to a minimal set before the agent runs. The following dangerous capabilities are explicitly removed:

| Capability | Risk if Granted |
|-----------|-----------------|
| `CAP_SYS_ADMIN` | Mount filesystems, create namespaces, trace processes — most common escape vector |
| `CAP_SYS_MODULE` | Load kernel modules — arbitrary kernel code execution |
| `CAP_DAC_READ_SEARCH` | Bypass file read permissions — used with `open_by_handle_at` for host file access |
| `CAP_NET_RAW` | Create raw/packet sockets — traffic interception, ARP spoofing |
| `CAP_SYS_PTRACE` | Trace any process — code injection, credential theft |
| `CAP_SYS_RAWIO` | Direct I/O port access — hardware-level attacks |
| `CAP_SYS_BOOT` | Reboot the system |
| `CAP_SYS_CHROOT` | Use `chroot` — filesystem isolation escape |
| `CAP_MKNOD` | Create device nodes — potential device access bypass |
| `CAP_NET_ADMIN` | Modify network configuration — firewall bypass |
| `CAP_DAC_OVERRIDE` | Bypass file write permissions |
| `CAP_FOWNER` | Bypass permission checks on file operations |
| `CAP_SETUID` / `CAP_SETGID` | Change process UID/GID — privilege escalation |

### Layer 4: Seccomp Profile

A seccomp-BPF profile blocks dangerous syscalls at the kernel level, providing a last line of defense even if capabilities are somehow regained:

| Blocked Syscall | Attack Prevented |
|----------------|------------------|
| `mount` / `umount2` | Filesystem namespace escape |
| `init_module` / `finit_module` / `delete_module` | Kernel module loading |
| `open_by_handle_at` | File handle-based host file access (CVE technique) |
| `ptrace` | Process tracing and code injection |
| `bpf` | eBPF program loading for kernel exploitation |
| `unshare` | Namespace creation for isolation escape |
| `pivot_root` | Root filesystem manipulation |
| `kexec_load` / `kexec_file_load` | Kernel replacement |
| `reboot` | System reboot |
| `swapon` / `swapoff` | Swap manipulation |
| `acct` | Process accounting manipulation |
| `add_key` / `keyctl` / `request_key` | Kernel keyring manipulation |
| `userfaultfd` | Used in exploitation of race conditions |
| `perf_event_open` | Kernel-level performance monitoring (information leak) |
| `move_mount` / `open_tree` / `fsopen` / `fspick` | New mount API — filesystem manipulation |

### Layer 5: Network Firewall

Network access is controlled by a domain-level firewall implemented via iptables rules generated per-VM:

- **Default-deny:** All outbound traffic is blocked unless explicitly allowed
- **Domain allowlist:** Only specific domains (e.g., `github.com`, `registry.npmjs.org`) are permitted
- **DNS filtering:** DNS resolution is configured to use specific resolvers; domains not in the allowlist cannot be resolved
- **Rate limiting:** Configurable per-minute connection limit to prevent abuse
- **Logging:** Dropped packets are logged with `[SENDBOX DROP]` prefix for audit
- **No host access:** The VM cannot reach host services by default — the NAT network only routes to the internet through allowed domains

### Layer 6: Command Filtering

The `CommandPolicy` engine provides an application-level defense layer:

- **Allowlist/denylist model:** Commands are evaluated against glob-style patterns
- **Denylist priority:** Deny rules always override allow rules
- **Pipeline-aware:** Pipe chains (`|`), logical chains (`&&`, `||`), and semicolons (`;`) are split and each segment is evaluated independently
- **System admin commands blocked:** `sudo`, `su`, `mount`, `iptables`, `systemctl`, and other administrative commands are blocked in default and strict presets
- **Logging:** Blocked commands are logged for audit

### Layer 7: Secrets Protection

Secrets management prevents credential exposure:

- Secrets are stored in **macOS Keychain** (encrypted at rest by the Secure Enclave on Apple Silicon)
- Injected as **environment variables** at VM boot time
- **Never written to disk** in plaintext inside the VM
- Environment is **cleaned up on VM shutdown**
- Sensitive environment variables (e.g., `LD_PRELOAD`, `LD_LIBRARY_PATH`) are stripped from the agent environment by the hardening process

---

## Hardening Profiles

SendBox provides three hardening profiles that control how aggressively the guest VM is locked down.

### Standard Profile

The default profile for regular development use. Provides strong security without interfering with common development workflows.

- All sysctl hardening applied
- Dangerous capabilities dropped
- Seccomp profile active
- No `PR_SET_NO_NEW_PRIVS` (allows `sudo` inside VM if needed for package installation)
- Warning-level validation

### Maximum Profile

For high-security environments where the agent is untrusted.

- All Standard protections, plus:
- `PR_SET_NO_NEW_PRIVS` set (prevents any privilege escalation)
- Additional capabilities dropped (`CAP_SETUID`, `CAP_SETGID`, `CAP_FOWNER`)
- Stricter seccomp profile (blocks `clone3`, `io_uring_*`)
- cgroup `release_agent` explicitly disabled
- `/proc` and `/sys` remounted with restricted options

### Benchmark Profile

Specifically designed to pass all 18 SandboxEscapeBench scenarios. Includes all Maximum protections plus explicit mitigations for each benchmark attack.

- All Maximum protections, plus:
- Every sysctl parameter from the benchmark explicitly set
- All 18 scenarios verified in the security report
- Strictest seccomp profile
- All non-essential capabilities dropped (only `CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_KILL`, `CAP_NET_BIND_SERVICE` retained — and only if not in Maximum mode)

---

## Threat Model

### In Scope

These are threats SendBox is designed to defend against:

| Threat | Defense |
|--------|---------|
| Agent attempts to access host filesystem | VM isolation — no host filesystem visible; only explicit virtiofs mounts |
| Agent attempts to contact unauthorized network endpoints | Network firewall — default-deny with domain allowlist |
| Agent attempts to execute dangerous commands | Command policy — allowlist/denylist with pipeline parsing |
| Agent attempts to escalate privileges within the VM | Capability dropping, seccomp, `PR_SET_NO_NEW_PRIVS`, sysctl hardening |
| Agent attempts to exfiltrate secrets | Secrets are env vars, not files; network firewall blocks unauthorized endpoints |
| Agent attempts to exploit kernel vulnerabilities | Separate guest kernel; exploit affects guest only; host kernel is macOS XNU |
| Agent attempts to escape via container runtime bugs | No container runtime exists (no runc, no containerd, no Docker) |
| Agent attempts cloud metadata access | No cloud environment; `route_localnet` disabled; metadata IP blocked |
| Agent attempts to intercept network traffic | `CAP_NET_RAW` dropped; separate virtual NIC |
| Agent attempts to load malicious kernel modules | `kernel.modules_disabled=1`; `CAP_SYS_MODULE` dropped; seccomp blocks `init_module` |

### Out of Scope

These threats are not addressed by SendBox:

| Threat | Reason |
|--------|--------|
| Hardware side-channel attacks (Spectre, Meltdown) | Requires CPU microcode/hardware mitigations; beyond hypervisor scope |
| Attacks against Apple's Virtualization.framework itself | Hypervisor bugs are Apple's responsibility; extremely low attack surface |
| Physical access attacks | Physical access bypasses all software security |
| Social engineering of the host user | User-level risk; SendBox cannot prevent the user from disabling protections |
| Denial-of-service against the host | VM resource limits (CPU/memory) mitigate but don't eliminate resource exhaustion |
| Supply chain attacks on the base VM image | Image provenance and signing are the user's responsibility |
| Zero-day hypervisor escapes | Theoretical; Apple's hypervisor has a very small attack surface (virtio devices only) |

---

## CVE Reference

The following CVEs are directly addressed by SendBox's security model:

| CVE | Description | SendBox Mitigation |
|-----|-------------|-------------------|
| CVE-2022-0811 | CRI-O kernel parameter injection | No CRI-O; `core_pattern` locked |
| CVE-2019-11246 | kubectl cp symlink traversal | No kubectl; explicit virtiofs mounts |
| CVE-2019-5736 | runc binary overwrite via `/proc/self/exe` | No runc; VM isolation |
| CVE-2024-21626 | runc fd leak for host filesystem access | No runc; VM isolation |
| CVE-2016-5195 | Dirty COW — COW race condition | Separate kernel; host is XNU |
| CVE-2022-0847 | Dirty Pipe — pipe buffer flag manipulation | Separate kernel; host is XNU |

---

## Verification

To verify SendBox's security posture programmatically, use the `ContainerHardening.securityReport()` method, which generates a comprehensive report covering all 18 SandboxEscapeBench scenarios and their mitigation status.

```swift
let hardening = ContainerHardening(profile: .benchmark)
let report = hardening.securityReport()
print(report)
```

The automated test suite (`ContainerHardeningTests`) verifies that:
- Each sysctl parameter is correctly set
- Each dangerous capability is dropped
- Each dangerous syscall is blocked by seccomp
- Each benchmark scenario is listed as mitigated in the security report
- The hardening script is a valid bash script
- Configuration validation catches unsafe settings
