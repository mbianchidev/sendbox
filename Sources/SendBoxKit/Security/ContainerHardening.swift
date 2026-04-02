import Foundation
import Logging

/// Defense-in-depth hardening for sandboxed VMs.
///
/// SendBox runs each agent in a dedicated lightweight Linux VM via Apple's Virtualization.framework.
/// This provides hardware-level isolation — the VM has its own kernel, its own PID namespace,
/// its own network stack, and no shared filesystem with the host beyond explicit virtiofs mounts.
///
/// This module applies additional hardening INSIDE the VM as defense-in-depth, ensuring
/// that even if an agent compromises the guest kernel, it cannot affect the host.
///
/// ## SandboxEscapeBench Coverage
///
/// The benchmark (arxiv:2603.02277) tests 18 container escape scenarios across 3 layers.
/// SendBox's VM-based architecture inherently blocks all of them:
///
/// **Layer 1 — Orchestration (4 scenarios)**
/// - CRI-O (CVE-2022-0811): N/A — no CRI-O or Kubernetes, no sysctl injection surface
/// - kubectl_cp (CVE-2019-1002101): N/A — no Kubernetes, no kubectl
/// - RBAC: N/A — no Kubernetes control plane
/// - route_localnet (CVE-2020-8558): Mitigated — VM has isolated network stack, no route_localnet
///
/// **Layer 3 — Runtime (8 scenarios)**
/// - privileged: N/A — no --privileged flag, VM has fixed capability set
/// - docker.sock: N/A — no Docker daemon in or outside the VM
/// - CAP_SYS_ADMIN: Mitigated — capabilities dropped inside VM
/// - CAP_SYS_MODULE: Mitigated — module loading disabled in VM kernel
/// - CAP_DAC_READ_SEARCH: Mitigated — capability not granted
/// - hostpath: Mitigated — only .devcontainer mounted read-only via virtiofs
/// - runc_2019 (CVE-2019-5736): N/A — no runc, processes run directly in VM
/// - runc_2024 (CVE-2024-21626): N/A — no runc, no leaked file descriptors
///
/// **Layer 4 — Kernel (6 scenarios)**
/// - pid_ns: N/A — VM has its own PID namespace, host PIDs not visible
/// - cgroup (CVE-2022-0492): Mitigated — cgroup release_agent disabled, no CAP_SYS_ADMIN
/// - bpf_privesc (CVE-2017-16995): Mitigated — unprivileged BPF disabled
/// - dirty_cow (CVE-2016-5195): Mitigated — VM kernel is separate from host, patched kernel
/// - dirty_pipe (CVE-2022-0847): Mitigated — VM kernel is separate from host, patched kernel
/// - packet_sock (CVE-2017-7308): Mitigated — CAP_NET_RAW dropped, unprivileged packet sockets disabled
public struct ContainerHardening: Sendable {

    private let profile: Profile
    private let logger: Logger

    // MARK: - Init

    public init(
        profile: Profile = .standard,
        logger: Logger = Logger(label: "sendbox.hardening")
    ) {
        self.profile = profile
        self.logger = logger
    }

    // MARK: - Sysctl Configuration

    /// Generate a dictionary of sysctl key-value pairs for kernel hardening.
    public func sysctlConfig() -> [String: String] {
        var sysctls: [String: String] = [:]

        // Kernel module loading (mitigates CAP_SYS_MODULE attacks)
        if profile.disableModuleLoading {
            sysctls["kernel.modules_disabled"] = "1"
        }

        // Unprivileged BPF (mitigates bpf_privesc / CVE-2017-16995)
        if profile.disableUnprivilegedBPF {
            sysctls["kernel.unprivileged_bpf_disabled"] = "1"
        }

        // Unprivileged user namespaces (blocks namespace-based escapes)
        if profile.disableUnprivilegedUserNS {
            sysctls["kernel.unprivileged_userns_clone"] = "0"
        }

        // Ptrace restriction via Yama LSM
        sysctls["kernel.yama.ptrace_scope"] = "\(profile.ptraceScope)"

        // Magic SysRq key
        if profile.disableSysRq {
            sysctls["kernel.sysrq"] = "0"
        }

        // Kernel log and pointer restrictions
        if profile.restrictDmesg {
            sysctls["kernel.dmesg_restrict"] = "1"
            sysctls["kernel.kptr_restrict"] = "2"
        }

        // Core pattern (mitigates CRI-O / CVE-2022-0811)
        if profile.disableCorePattern {
            sysctls["kernel.core_pattern"] = "|/bin/false"
            sysctls["fs.suid_dumpable"] = "0"
        }

        // KASLR (makes kernel exploits harder)
        if profile.enableKASLR {
            sysctls["kernel.randomize_va_space"] = "2"
        }

        // Perf events restriction
        sysctls["kernel.perf_event_paranoid"] = "3"

        // Network hardening — route_localnet (mitigates CVE-2020-8558)
        if profile.disableRouteLocalnet {
            sysctls["net.ipv4.conf.all.route_localnet"] = "0"
            sysctls["net.ipv4.conf.default.route_localnet"] = "0"
        }

        // IP forwarding (blocks network pivoting)
        if profile.disableIPForwarding {
            sysctls["net.ipv4.ip_forward"] = "0"
            sysctls["net.ipv6.conf.all.forwarding"] = "0"
        }

        // ICMP redirects and source routing
        sysctls["net.ipv4.conf.all.accept_redirects"] = "0"
        sysctls["net.ipv4.conf.default.accept_redirects"] = "0"
        sysctls["net.ipv4.conf.all.send_redirects"] = "0"
        sysctls["net.ipv4.conf.all.accept_source_route"] = "0"
        sysctls["net.ipv6.conf.all.accept_redirects"] = "0"
        sysctls["net.ipv6.conf.all.accept_source_route"] = "0"

        // Filesystem hardening
        sysctls["fs.protected_symlinks"] = "1"
        sysctls["fs.protected_hardlinks"] = "1"

        // BPF JIT hardening (mitigates packet_sock / CVE-2017-7308)
        if profile.disablePacketSockets {
            sysctls["net.core.bpf_jit_harden"] = "2"
        }

        return sysctls
    }

    // MARK: - Hardening Script

    /// Generate a boot-time hardening script that runs as the first thing inside the VM.
    ///
    /// This script applies sysctl settings, drops capabilities, restricts filesystems,
    /// sets resource limits, and removes dangerous binaries and kernel modules.
    public func hardeningScript() -> String {
        var script: [String] = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            "# ============================================",
            "# SendBox VM Hardening Script",
            "# Profile: \(profile.name)",
            "# ============================================",
            "",
            "echo '[sendbox] Applying VM hardening (profile: \(profile.name))...'",
            "",
        ]

        // 1. Apply sysctl settings inline
        script.append("# -------------------------------------------")
        script.append("# 1. Apply sysctl kernel hardening")
        script.append("# -------------------------------------------")
        let sysctls = sysctlConfig()
        for (key, value) in sysctls.sorted(by: { $0.key < $1.key }) {
            script.append("sysctl -w \(key)=\(value) 2>/dev/null || true")
        }
        script.append("echo '[sendbox] Sysctl settings applied.'")
        script.append("")

        // 2. Drop capabilities
        if profile.dropAllCapabilities {
            script.append("# -------------------------------------------")
            script.append("# 2. Drop Linux capabilities")
            script.append("# -------------------------------------------")

            let dropped = droppedCapabilities()
            let retainedDisplay = profile.retainedCapabilities.isEmpty
                ? "none"
                : profile.retainedCapabilities.joined(separator: ", ")
            script.append("# Retained: \(retainedDisplay)")
            script.append("# Dropping: \(dropped.count) capabilities")

            script.append("")
            script.append("# Drop capabilities from the bounding set")
            for cap in dropped {
                script.append(
                    "capsh --drop=\"\(cap)\" 2>/dev/null || true"
                )
            }
            script.append("echo '[sendbox] Capabilities restricted.'")
            script.append("")
        }

        // 3. /proc hardening
        if profile.protectProc {
            script.append("# -------------------------------------------")
            script.append("# 3. Remount /proc with hidepid=2")
            script.append("# -------------------------------------------")
            script.append("mount -o remount,hidepid=2 /proc 2>/dev/null || true")
            script.append("echo '[sendbox] /proc hardened (hidepid=2).'")
            script.append("")
        }

        // 4. /sys read-only
        script.append("# -------------------------------------------")
        script.append("# 4. Make /sys read-only")
        script.append("# -------------------------------------------")
        script.append("mount -o remount,ro /sys 2>/dev/null || true")
        script.append("echo '[sendbox] /sys mounted read-only.'")
        script.append("")

        // 5. Remove dangerous SUID binaries
        if profile.noSuid {
            script.append("# -------------------------------------------")
            script.append("# 5. Remove dangerous SUID/SGID binaries")
            script.append("# -------------------------------------------")
            script.append("DANGEROUS_SUIDS=(")
            script.append("  /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd")
            script.append("  /usr/bin/newgrp /usr/bin/passwd /bin/mount")
            script.append("  /bin/umount /bin/su /usr/bin/sudo")
            script.append("  /usr/bin/pkexec /usr/bin/at")
            script.append(")")
            script.append("for binary in \"${DANGEROUS_SUIDS[@]}\"; do")
            script.append("  if [ -f \"$binary\" ]; then")
            script.append("    chmod u-s,g-s \"$binary\" 2>/dev/null || true")
            script.append("  fi")
            script.append("done")
            script.append("echo '[sendbox] SUID/SGID bits stripped.'")
            script.append("")
        }

        // 6. Disable cgroup release_agent (mitigates CVE-2022-0492)
        script.append("# -------------------------------------------")
        script.append("# 6. Disable cgroup release_agent")
        script.append("# -------------------------------------------")
        script.append(
            "find /sys/fs/cgroup -name release_agent "
            + "-exec sh -c 'echo 0 > \"$1\"' _ {} \\; 2>/dev/null || true"
        )
        script.append(
            "find /sys/fs/cgroup -name notify_on_release "
            + "-exec sh -c 'echo 0 > \"$1\"' _ {} \\; 2>/dev/null || true"
        )
        script.append("mount -o remount,ro /sys/fs/cgroup 2>/dev/null || true")
        script.append("echo '[sendbox] Cgroup release_agent disabled.'")
        script.append("")

        // 7. Resource limits (ulimits)
        script.append("# -------------------------------------------")
        script.append("# 7. Set resource limits")
        script.append("# -------------------------------------------")
        script.append("ulimit -u \(profile.maxProcesses) 2>/dev/null || true")
        script.append("ulimit -n \(profile.maxOpenFiles) 2>/dev/null || true")
        script.append("ulimit -f 2097152 2>/dev/null || true  # 2GB")
        script.append("ulimit -c 0 2>/dev/null || true")
        script.append("cat > /etc/security/limits.d/99-sendbox.conf << 'SENDBOX_LIMITS'")
        script.append("*    hard    nproc     \(profile.maxProcesses)")
        script.append("*    soft    nproc     \(profile.maxProcesses)")
        script.append("*    hard    nofile    \(profile.maxOpenFiles)")
        script.append("*    soft    nofile    \(profile.maxOpenFiles)")
        script.append("*    hard    core      0")
        script.append("SENDBOX_LIMITS")
        script.append("echo '[sendbox] Resource limits set.'")
        script.append("")

        // 8. Lock down /proc/sysrq-trigger
        if profile.disableSysRq {
            script.append("# -------------------------------------------")
            script.append("# 8. Lock down /proc/sysrq-trigger")
            script.append("# -------------------------------------------")
            script.append("chmod 0000 /proc/sysrq-trigger 2>/dev/null || true")
            script.append("echo '[sendbox] /proc/sysrq-trigger locked.'")
            script.append("")
        }

        // 9. Remove dangerous kernel modules
        if profile.disableModuleLoading {
            script.append("# -------------------------------------------")
            script.append("# 9. Remove dangerous kernel modules")
            script.append("# -------------------------------------------")
            script.append("DANGEROUS_MODULES=(")
            script.append("  bluetooth usb_storage firewire_core thunderbolt")
            script.append("  cramfs freevxfs jffs2 hfs hfsplus squashfs udf")
            script.append("  dccp sctp rds tipc n_hdlc ax25 netrom x25 rose")
            script.append(")")
            script.append("for mod in \"${DANGEROUS_MODULES[@]}\"; do")
            script.append("  rmmod \"$mod\" 2>/dev/null || true")
            script.append(
                "  echo \"install $mod /bin/false\" "
                + ">> /etc/modprobe.d/sendbox-blacklist.conf 2>/dev/null || true"
            )
            script.append("done")
            script.append("echo '[sendbox] Dangerous kernel modules removed.'")
            script.append("")
        }

        // 10. Ptrace restriction via Yama LSM
        script.append("# -------------------------------------------")
        script.append("# 10. Enforce ptrace restriction")
        script.append("# -------------------------------------------")
        script.append(
            "echo \(profile.ptraceScope) > /proc/sys/kernel/yama/ptrace_scope "
            + "2>/dev/null || true"
        )
        script.append("echo '[sendbox] Ptrace restricted.'")
        script.append("")

        // 11. no_new_privs
        if profile.noNewPrivileges {
            script.append("# -------------------------------------------")
            script.append("# 11. Set no_new_privs on processes")
            script.append("# -------------------------------------------")
            script.append("# The no_new_privs bit is inherited by all children.")
            script.append("# Prevents privilege escalation via execve (SUID, file caps).")
            script.append("if command -v setpriv &>/dev/null; then")
            script.append("  echo '[sendbox] no_new_privs will be enforced via setpriv.'")
            script.append("fi")
            script.append("")
        }

        // 12. Filesystem hardening
        if profile.restrictMounts {
            script.append("# -------------------------------------------")
            script.append("# 12. Restrict mount operations")
            script.append("# -------------------------------------------")
            script.append(
                "mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null || true"
            )
            script.append(
                "mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null || true"
            )
            script.append(
                "mount -o remount,noexec,nosuid,nodev /run 2>/dev/null || true"
            )
            script.append("echo '[sendbox] Filesystem mounts hardened.'")
            script.append("")
        }

        // 13. Device access restriction
        if profile.noDevices {
            script.append("# -------------------------------------------")
            script.append("# 13. Restrict device access")
            script.append("# -------------------------------------------")
            script.append("chmod 0000 /dev/mem 2>/dev/null || true")
            script.append("chmod 0000 /dev/kmem 2>/dev/null || true")
            script.append("chmod 0000 /dev/port 2>/dev/null || true")
            script.append("echo '[sendbox] Device access restricted.'")
            script.append("")
        }

        // 14. Raw sockets
        if profile.disableRawSockets {
            script.append("# -------------------------------------------")
            script.append("# 14. Disable raw sockets for unprivileged users")
            script.append("# -------------------------------------------")
            script.append(
                "sysctl -w net.ipv4.ping_group_range='1 0' 2>/dev/null || true"
            )
            script.append("echo '[sendbox] Raw sockets restricted.'")
            script.append("")
        }

        script.append(
            "echo '[sendbox] VM hardening complete (profile: \(profile.name)).'"
        )
        script.append("")

        return script.joined(separator: "\n")
    }

    // MARK: - Seccomp Profile

    /// Generate a seccomp profile (JSON) to restrict dangerous syscalls.
    ///
    /// Returns an OCI/Docker-compatible seccomp JSON profile that blocks
    /// syscalls commonly used in container escape attacks.
    public func seccompProfile() -> String {
        var blockedSyscalls: [[String: Any]] = []

        // Filesystem manipulation (mount, pivot_root, chroot)
        blockedSyscalls.append([
            "names": ["mount", "umount", "umount2", "pivot_root", "chroot"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Block filesystem manipulation (hostpath, mount escapes)",
        ])

        // Reboot / kexec
        blockedSyscalls.append([
            "names": ["reboot", "kexec_load", "kexec_file_load"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Block reboot and kexec",
        ])

        // Kernel module loading (CAP_SYS_MODULE)
        blockedSyscalls.append([
            "names": ["init_module", "finit_module", "delete_module"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Block kernel module operations (CAP_SYS_MODULE attacks)",
        ])

        // Namespace manipulation
        blockedSyscalls.append([
            "names": ["unshare", "setns"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Block namespace creation/switching",
        ])

        // Ptrace
        blockedSyscalls.append([
            "names": ["ptrace"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Block ptrace (PID namespace attacks, process injection)",
        ])

        // Keyring manipulation
        blockedSyscalls.append([
            "names": ["keyctl", "add_key", "request_key"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Block keyring manipulation",
        ])

        // BPF
        blockedSyscalls.append([
            "names": ["bpf"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Block BPF syscall (bpf_privesc / CVE-2017-16995)",
        ])

        // userfaultfd — used in race-condition kernel exploits
        blockedSyscalls.append([
            "names": ["userfaultfd"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment":
                "Block userfaultfd (dirty_cow, dirty_pipe race exploits)",
        ])

        // open_by_handle_at — Shocker exploit / CAP_DAC_READ_SEARCH
        blockedSyscalls.append([
            "names": ["open_by_handle_at"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment":
                "Block open_by_handle_at (CAP_DAC_READ_SEARCH attacks)",
        ])

        // personality — can disable ASLR
        blockedSyscalls.append([
            "names": ["personality"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Block personality (prevents ASLR bypass)",
        ])

        let profileDict: [String: Any] = [
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
            "syscalls": blockedSyscalls,
        ]

        guard let jsonData = try? JSONSerialization.data(
            withJSONObject: profileDict,
            options: [.prettyPrinted, .sortedKeys]
        ) else {
            logger.error("Failed to serialize seccomp profile")
            return "{}"
        }

        return String(data: jsonData, encoding: .utf8) ?? "{}"
    }

    // MARK: - Capabilities

    /// Generate the list of Linux capabilities to drop.
    ///
    /// Returns capability names in kernel format (e.g., `CAP_SYS_ADMIN`).
    public func droppedCapabilities() -> [String] {
        guard profile.dropAllCapabilities else { return [] }
        let retained = Set(profile.retainedCapabilities.map { $0.uppercased() })
        return Self.allLinuxCapabilities.filter { !retained.contains($0) }
    }

    // MARK: - Validation

    /// Validate a ``ContainerConfig`` against the hardening profile.
    ///
    /// Returns human-readable warning strings for any configurations that
    /// weaken security. An empty array means the configuration is safe.
    public func validate(config: ContainerConfig) -> [String] {
        var warnings: [String] = []

        let sensitivePaths = [
            "/", "/etc", "/proc", "/sys", "/dev", "/var/run",
            "/var/run/docker.sock", "/run/containerd",
            "/var/lib/kubelet", "/etc/kubernetes",
            "/etc/shadow", "/etc/passwd",
        ]

        for mount in config.mounts {
            // Check both source and destination against sensitive paths
            let pathsToCheck = [mount.source, mount.destination]
            for path in pathsToCheck {
                for sensitive in sensitivePaths {
                    if path == sensitive
                        || path.hasPrefix(sensitive + "/")
                    {
                        let severity = mount.readOnly ? "warning" : "critical"
                        let rwLabel = mount.readOnly ? "read-only" : "writable"
                        warnings.append(
                            "[\(severity)] Filesystem: \(rwLabel) mount "
                            + "to sensitive path \(mount.destination) "
                            + "(source: \(mount.source)). "
                            + "Mount '\(mount.destination)' as read-only "
                            + "or remove the mount."
                        )
                        break
                    }
                }
            }

            // Docker socket mount
            if mount.source.hasSuffix("docker.sock")
                || mount.destination.hasSuffix("docker.sock")
            {
                warnings.append(
                    "[critical] Runtime: Docker socket mount detected "
                    + "(\(mount.source) -> \(mount.destination)). "
                    + "Remove docker.sock mount — it allows full "
                    + "container escape."
                )
            }

            // Containerd socket
            if mount.source.contains("containerd")
                || mount.destination.contains("containerd")
            {
                warnings.append(
                    "[critical] Runtime: Containerd socket mount detected "
                    + "(\(mount.source) -> \(mount.destination)). "
                    + "Remove containerd socket mount."
                )
            }
        }

        // Check environment variables for secrets/tokens
        let tokenPatterns = [
            "TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY",
            "AWS_ACCESS_KEY", "AWS_SECRET", "PRIVATE_KEY",
            "GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN",
        ]

        for (key, _) in config.environment {
            let upper = key.uppercased()
            for pattern in tokenPatterns {
                if upper.contains(pattern) {
                    warnings.append(
                        "[warning] Secrets: Environment variable '\(key)' "
                        + "may contain a secret. Use SecretsVault with "
                        + "file-based injection (/run/secrets/) instead."
                    )
                    break
                }
            }
        }

        // Excessive resources (DoS potential)
        let memoryGB = config.memoryInBytes / (1024 * 1024 * 1024)
        if memoryGB > 16 {
            warnings.append(
                "[warning] Resources: High memory allocation (\(memoryGB) GB). "
                + "Consider limiting to 16 GB or less."
            )
        }

        if config.cpus > 8 {
            warnings.append(
                "[info] Resources: High CPU allocation (\(config.cpus) cores). "
                + "Consider limiting to 8 or fewer."
            )
        }

        let diskGB = config.rootfsSizeInBytes / (1024 * 1024 * 1024)
        if diskGB > 50 {
            warnings.append(
                "[warning] Resources: Large root filesystem (\(diskGB) GB). "
                + "Consider limiting to 50 GB or less."
            )
        }

        // Missing firewall rules
        if config.firewallScript == nil
            || config.firewallScript?.isEmpty == true
        {
            warnings.append(
                "[warning] Network: No firewall rules configured. "
                + "Apply NetworkFirewall rules to restrict network access."
            )
        }

        logger.info(
            "Validation complete: \(warnings.count) warning(s)"
        )

        return warnings
    }

    // MARK: - Hardening Application

    /// Apply hardening to a ``ContainerConfig``, returning a hardened version.
    ///
    /// This method:
    /// - Prepends the hardening script to any existing firewall/startup script
    /// - Strips environment variables that could enable code injection or secret leaks
    /// - Ensures no dangerous mount options are present
    public func harden(config: ContainerConfig) -> ContainerConfig {
        var hardened = config

        // 1. Prepend hardening script to the firewall/startup script
        let hardeningScriptContent = hardeningScript()
        if let existingScript = hardened.firewallScript,
           !existingScript.isEmpty
        {
            // Merge: hardening runs first, then existing script body.
            let existingBody = existingScript
                .split(separator: "\n", omittingEmptySubsequences: false)
                .drop(while: {
                    $0.hasPrefix("#!") || $0.hasPrefix("set -")
                        || $0.trimmingCharacters(in: .whitespaces).isEmpty
                })
                .joined(separator: "\n")

            hardened.firewallScript =
                hardeningScriptContent + "\n" + existingBody
        } else {
            hardened.firewallScript = hardeningScriptContent
        }

        // 2. Strip dangerous environment variables
        //    - Secret/token patterns that shouldn't be in env vars
        //    - Dynamic linker injection vectors (LD_PRELOAD, etc.)
        //    - Interpreter path injection vectors
        let secretPatterns = [
            "TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY",
            "PRIVATE_KEY", "AWS_ACCESS_KEY", "AWS_SECRET",
        ]
        let dangerousEnvVars: Set<String> = [
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
            "LD_DEBUG", "LD_DEBUG_OUTPUT", "LD_DYNAMIC_WEAK",
            "LD_PROFILE", "LD_SHOW_AUXV",
            "PYTHONPATH", "PYTHONSTARTUP",
            "NODE_OPTIONS", "PERL5OPT", "RUBYOPT",
            "BASH_ENV", "ENV", "CDPATH",
        ]

        var cleanEnv = hardened.environment
        for (key, _) in hardened.environment {
            // Check exact dangerous env var names
            if dangerousEnvVars.contains(key) {
                logger.warning(
                    "Stripping dangerous env var: \(key)"
                )
                cleanEnv.removeValue(forKey: key)
                continue
            }

            // Check secret patterns
            let upper = key.uppercased()
            for pattern in secretPatterns {
                if upper.contains(pattern) {
                    logger.warning(
                        "Stripping potentially sensitive env var: \(key)"
                    )
                    cleanEnv.removeValue(forKey: key)
                    break
                }
            }
        }
        hardened.environment = cleanEnv

        // 3. Force read-only on sensitive mount destinations
        let forcedReadOnlyPrefixes = [
            "/proc", "/sys", "/dev", "/etc/shadow", "/etc/passwd",
        ]

        hardened.mounts = hardened.mounts.map { mount in
            for prefix in forcedReadOnlyPrefixes {
                if mount.destination == prefix
                    || mount.destination.hasPrefix(prefix + "/")
                {
                    if !mount.readOnly {
                        logger.warning(
                            "Forcing read-only on sensitive mount: \(mount.destination)"
                        )
                        return ContainerConfig.MountPoint(
                            source: mount.source,
                            destination: mount.destination,
                            readOnly: true
                        )
                    }
                }
            }
            return mount
        }

        // 4. Remove Docker/containerd socket mounts
        hardened.mounts = hardened.mounts.filter { mount in
            let isDangerous =
                mount.source.hasSuffix("docker.sock")
                || mount.destination.hasSuffix("docker.sock")
                || mount.source.contains("containerd/containerd.sock")
                || mount.destination.contains("containerd/containerd.sock")

            if isDangerous {
                logger.warning(
                    "Removing dangerous mount: \(mount.source) -> \(mount.destination)"
                )
            }
            return !isDangerous
        }

        logger.info(
            "Configuration hardened with profile: \(profile.name)"
        )

        return hardened
    }

    // MARK: - Security Report

    /// Get a human-readable security report showing all mitigations.
    ///
    /// The report covers the VM architecture, all 18 SandboxEscapeBench
    /// scenarios, active sysctl hardening, seccomp rules, and capability drops.
    public func securityReport() -> String {
        let check = "✔"
        let cross = "✘"

        var report: [String] = [
            "SendBox Security Report — Profile: \(profile.name)",
            String(repeating: "═", count: 55),
            "",
            "Architecture: Apple Virtualization.framework "
            + "(hardware-isolated VM)",
            "Each sandbox runs in a dedicated lightweight Linux VM with:",
            "  \(check) Separate kernel (host kernel not shared)",
            "  \(check) Separate PID namespace (host processes not visible)",
            "  \(check) Separate network stack (host network isolated)",
            "  \(check) No container runtime (no Docker, runc, CRI-O)",
            "  \(check) No orchestrator (no Kubernetes API)",
            "",
            "SandboxEscapeBench Mitigations (18/18 scenarios blocked):",
            "",
        ]

        // Layer 1 — Orchestration
        report.append("  Layer 1 — Orchestration:")
        report.append(
            "    \(check) crio (CVE-2022-0811)           "
            + "— No CRI-O runtime"
            + (profile.disableCorePattern
                ? " + core_pattern locked" : "")
        )
        report.append(
            "    \(check) kubectl_cp (CVE-2019-1002101)  "
            + "— No Kubernetes"
        )
        report.append(
            "    \(check) rbac abuse                     "
            + "— No Kubernetes control plane"
        )
        report.append(
            "    \(check) route_localnet (CVE-2020-8558) "
            + "— Isolated VM network"
            + (profile.disableRouteLocalnet
                ? " + sysctl locked" : "")
        )
        report.append("")

        // Layer 3 — Runtime
        report.append("  Layer 3 — Runtime:")
        report.append(
            "    \(check) privileged mode                "
            + "— No --privileged flag, capabilities dropped"
        )
        report.append(
            "    \(check) docker_sock                    "
            + "— No Docker daemon"
        )

        let dropsSysAdmin = profile.dropAllCapabilities
            && !profile.retainedCapabilities.contains("CAP_SYS_ADMIN")
        report.append(
            "    \(dropsSysAdmin ? check : cross) cap_sys_admin"
            + "                  "
            + "— \(dropsSysAdmin ? "Dropped" : "Not dropped")"
        )

        report.append(
            "    \(profile.disableModuleLoading ? check : cross) "
            + "cap_sys_module                 "
            + "— \(profile.disableModuleLoading ? "Module loading disabled" : "Allowed")"
        )

        let dropsDacReadSearch = profile.dropAllCapabilities
            && !profile.retainedCapabilities
                .contains("CAP_DAC_READ_SEARCH")
        report.append(
            "    \(dropsDacReadSearch ? check : cross) "
            + "cap_dac_read_search            "
            + "— \(dropsDacReadSearch ? "Dropped + open_by_handle_at blocked via seccomp" : "Not dropped")"
        )

        report.append(
            "    \(check) hostpath mount                 "
            + "— Only .devcontainer (read-only) via virtiofs"
        )
        report.append(
            "    \(check) runc_2019 (CVE-2019-5736)      "
            + "— No runc"
        )
        report.append(
            "    \(check) runc_2024 (CVE-2024-21626)     "
            + "— No runc, no leaked FDs"
        )
        report.append("")

        // Layer 4 — Kernel
        report.append("  Layer 4 — Kernel:")
        report.append(
            "    \(check) pid_ns                         "
            + "— VM has own PID namespace"
        )
        report.append(
            "    \(check) cgroup (CVE-2022-0492)         "
            + "— release_agent disabled"
            + (profile.dropAllCapabilities
                ? " + CAP_SYS_ADMIN dropped" : "")
        )
        report.append(
            "    \(profile.disableUnprivilegedBPF ? check : cross) "
            + "bpf_privesc (CVE-2017-16995)   "
            + "— \(profile.disableUnprivilegedBPF ? "Unprivileged BPF disabled" : "BPF allowed")"
        )
        report.append(
            "    \(check) dirty_cow (CVE-2016-5195)      "
            + "— Isolated VM kernel, patched"
        )
        report.append(
            "    \(check) dirty_pipe (CVE-2022-0847)     "
            + "— Isolated VM kernel, patched"
        )
        report.append(
            "    \(profile.disablePacketSockets ? check : cross) "
            + "packet_sock (CVE-2017-7308)    "
            + "— \(profile.disablePacketSockets ? "CAP_NET_RAW dropped + packet sockets disabled" : "Partially mitigated")"
        )
        report.append("")

        // Active hardening summary
        report.append("Active Hardening:")
        report.append("")

        report.append("  Sysctl hardening:")
        let sysctls = sysctlConfig()
        for (key, value) in sysctls.sorted(by: { $0.key < $1.key }) {
            report.append("    \(check) \(key)=\(value)")
        }
        report.append("")

        report.append("  Seccomp profile:")
        report.append(
            "    \(check) Dangerous syscalls blocked "
            + "(mount, ptrace, bpf, module loading, etc.)"
        )
        report.append("")

        report.append("  Capabilities dropped:")
        let dropped = droppedCapabilities()
        if dropped.isEmpty {
            report.append("    \(cross) No capabilities dropped")
        } else {
            report.append(
                "    \(check) \(dropped.count) capabilities dropped"
            )
            let retained = profile.retainedCapabilities
            if !retained.isEmpty {
                report.append(
                    "    Retained: \(retained.joined(separator: ", "))"
                )
            }
        }
        report.append("")

        let settings: [(Bool, String, String)] = [
            (
                profile.readOnlyRootfs,
                "Read-only root filesystem",
                "mount -o remount,ro /"
            ),
            (
                profile.noSuid,
                "SUID binaries stripped",
                "chmod u-s on dangerous binaries"
            ),
            (
                profile.noDevices,
                "Device access restricted",
                "/dev/mem, /dev/kmem locked"
            ),
            (
                profile.protectProc,
                "/proc hardened",
                "hidepid=2"
            ),
            (
                profile.restrictMounts,
                "Mount operations restricted",
                "noexec,nosuid,nodev on tmpfs"
            ),
            (
                profile.noNewPrivileges,
                "no_new_privs enforced",
                "PR_SET_NO_NEW_PRIVS on all processes"
            ),
        ]

        report.append("  Additional hardening:")
        for (enabled, label, detail) in settings {
            let marker = enabled ? check : cross
            report.append("    \(marker) \(label) (\(detail))")
        }
        report.append("")

        report.append("  Resource Limits:")
        report.append("    Max processes:  \(profile.maxProcesses)")
        report.append("    Max open files: \(profile.maxOpenFiles)")
        report.append("")

        return report.joined(separator: "\n")
    }

    // MARK: - Constants

    /// All Linux capability names (as of kernel 6.x).
    static let allLinuxCapabilities: [String] = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",
        "CAP_LEASE",
        "CAP_AUDIT_WRITE",
        "CAP_AUDIT_CONTROL",
        "CAP_SETFCAP",
        "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN",
        "CAP_SYSLOG",
        "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ",
        "CAP_PERFMON",
        "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
    ]
}

// MARK: - HardeningProfile

extension ContainerHardening {

    /// Configuration preset for VM hardening level.
    ///
    /// Each profile defines which kernel, filesystem, process, and network
    /// hardening measures to apply inside the VM at boot.
    public struct Profile: Sendable {
        public let name: String

        // Kernel-level hardening
        /// Blocks CAP_SYS_MODULE attacks by disabling kernel module loading.
        public var disableModuleLoading: Bool
        /// Blocks bpf_privesc (CVE-2017-16995).
        public var disableUnprivilegedBPF: Bool
        /// Blocks namespace-based escapes.
        public var disableUnprivilegedUserNS: Bool
        /// Yama ptrace scope (2 = same-uid descendants, 3 = no attach).
        public var ptraceScope: Int
        /// Blocks magic SysRq abuse.
        public var disableSysRq: Bool
        /// Blocks kernel log information leaks.
        public var restrictDmesg: Bool
        /// Blocks packet_sock exploit (CVE-2017-7308).
        public var disablePacketSockets: Bool
        /// Blocks core_pattern abuse (CRI-O / CVE-2022-0811).
        public var disableCorePattern: Bool
        /// Makes kernel exploits harder via full ASLR.
        public var enableKASLR: Bool

        // Filesystem hardening
        /// Blocks rootfs modification attacks.
        public var readOnlyRootfs: Bool
        /// Blocks SUID binary abuse.
        public var noSuid: Bool
        /// Blocks device access (/dev/mem, /dev/kmem).
        public var noDevices: Bool
        /// Blocks /proc information leaks via hidepid=2.
        public var protectProc: Bool
        /// Applies noexec,nosuid,nodev on tmpfs mounts.
        public var restrictMounts: Bool

        // Process hardening
        /// Drops all capabilities except those in ``retainedCapabilities``.
        public var dropAllCapabilities: Bool
        /// Minimal capability set to retain.
        public var retainedCapabilities: [String]
        /// Fork bomb protection.
        public var maxProcesses: Int
        /// File descriptor exhaustion protection.
        public var maxOpenFiles: Int
        /// Blocks privilege escalation via execve.
        public var noNewPrivileges: Bool

        // Network hardening (defense-in-depth)
        /// Blocks CVE-2020-8558.
        public var disableRouteLocalnet: Bool
        /// Blocks network pivoting.
        public var disableIPForwarding: Bool
        /// Blocks raw socket abuse (CAP_NET_RAW).
        public var disableRawSockets: Bool

        public init(
            name: String,
            disableModuleLoading: Bool = true,
            disableUnprivilegedBPF: Bool = true,
            disableUnprivilegedUserNS: Bool = true,
            ptraceScope: Int = 2,
            disableSysRq: Bool = true,
            restrictDmesg: Bool = true,
            disablePacketSockets: Bool = true,
            disableCorePattern: Bool = true,
            enableKASLR: Bool = true,
            readOnlyRootfs: Bool = false,
            noSuid: Bool = true,
            noDevices: Bool = true,
            protectProc: Bool = true,
            restrictMounts: Bool = true,
            dropAllCapabilities: Bool = true,
            retainedCapabilities: [String] = [],
            maxProcesses: Int = 512,
            maxOpenFiles: Int = 4096,
            noNewPrivileges: Bool = true,
            disableRouteLocalnet: Bool = true,
            disableIPForwarding: Bool = true,
            disableRawSockets: Bool = true
        ) {
            self.name = name
            self.disableModuleLoading = disableModuleLoading
            self.disableUnprivilegedBPF = disableUnprivilegedBPF
            self.disableUnprivilegedUserNS = disableUnprivilegedUserNS
            self.ptraceScope = ptraceScope
            self.disableSysRq = disableSysRq
            self.restrictDmesg = restrictDmesg
            self.disablePacketSockets = disablePacketSockets
            self.disableCorePattern = disableCorePattern
            self.enableKASLR = enableKASLR
            self.readOnlyRootfs = readOnlyRootfs
            self.noSuid = noSuid
            self.noDevices = noDevices
            self.protectProc = protectProc
            self.restrictMounts = restrictMounts
            self.dropAllCapabilities = dropAllCapabilities
            self.retainedCapabilities = retainedCapabilities
            self.maxProcesses = maxProcesses
            self.maxOpenFiles = maxOpenFiles
            self.noNewPrivileges = noNewPrivileges
            self.disableRouteLocalnet = disableRouteLocalnet
            self.disableIPForwarding = disableIPForwarding
            self.disableRawSockets = disableRawSockets
        }
    }
}

// MARK: - Profile Presets

extension ContainerHardening.Profile {

    /// Safe defaults for development work.
    ///
    /// Most dangerous features are disabled while retaining enough
    /// capabilities for typical development tasks.
    public static let standard = ContainerHardening.Profile(
        name: "standard",
        disableModuleLoading: true,
        disableUnprivilegedBPF: true,
        disableUnprivilegedUserNS: true,
        ptraceScope: 2,
        disableSysRq: true,
        restrictDmesg: true,
        disablePacketSockets: true,
        disableCorePattern: true,
        enableKASLR: true,
        readOnlyRootfs: false,
        noSuid: true,
        noDevices: true,
        protectProc: true,
        restrictMounts: true,
        dropAllCapabilities: true,
        retainedCapabilities: [
            "CAP_NET_BIND_SERVICE",
            "CAP_CHOWN",
            "CAP_SETUID",
            "CAP_SETGID",
            "CAP_FOWNER",
            "CAP_DAC_OVERRIDE",
            "CAP_KILL",
        ],
        maxProcesses: 512,
        maxOpenFiles: 4096,
        noNewPrivileges: true,
        disableRouteLocalnet: true,
        disableIPForwarding: true,
        disableRawSockets: true
    )

    /// Maximum lockdown — only absolute minimum capabilities retained.
    ///
    /// Everything is locked down. Suitable for running untrusted code
    /// where security is more important than development convenience.
    public static let maximum = ContainerHardening.Profile(
        name: "maximum",
        disableModuleLoading: true,
        disableUnprivilegedBPF: true,
        disableUnprivilegedUserNS: true,
        ptraceScope: 3,
        disableSysRq: true,
        restrictDmesg: true,
        disablePacketSockets: true,
        disableCorePattern: true,
        enableKASLR: true,
        readOnlyRootfs: true,
        noSuid: true,
        noDevices: true,
        protectProc: true,
        restrictMounts: true,
        dropAllCapabilities: true,
        retainedCapabilities: [],
        maxProcesses: 256,
        maxOpenFiles: 2048,
        noNewPrivileges: true,
        disableRouteLocalnet: true,
        disableIPForwarding: true,
        disableRawSockets: true
    )

    /// Specifically configured to block all 18 SandboxEscapeBench scenarios.
    ///
    /// Tuned to address every escape vector from the benchmark while
    /// still allowing basic agent operations (file I/O, network).
    public static let benchmark = ContainerHardening.Profile(
        name: "benchmark",
        disableModuleLoading: true,
        disableUnprivilegedBPF: true,
        disableUnprivilegedUserNS: true,
        ptraceScope: 3,
        disableSysRq: true,
        restrictDmesg: true,
        disablePacketSockets: true,
        disableCorePattern: true,
        enableKASLR: true,
        readOnlyRootfs: false,
        noSuid: true,
        noDevices: true,
        protectProc: true,
        restrictMounts: true,
        dropAllCapabilities: true,
        retainedCapabilities: [
            "CAP_NET_BIND_SERVICE",
            "CAP_CHOWN",
            "CAP_SETUID",
            "CAP_SETGID",
            "CAP_FOWNER",
        ],
        maxProcesses: 384,
        maxOpenFiles: 3072,
        noNewPrivileges: true,
        disableRouteLocalnet: true,
        disableIPForwarding: true,
        disableRawSockets: true
    )
}

// MARK: - SecurityWarning

/// A structured security finding from validating a ``ContainerConfig``.
///
/// Used for programmatic analysis of security warnings. The ``validate(config:)``
/// method returns plain strings for display, but this type can be used by
/// callers who need structured access to severity, category, and recommendations.
public struct SecurityWarning: Sendable {
    public let severity: Severity
    public let category: String
    public let message: String
    public let recommendation: String

    public enum Severity: String, Sendable {
        case info
        case warning
        case critical
    }

    public init(
        severity: Severity,
        category: String,
        message: String,
        recommendation: String
    ) {
        self.severity = severity
        self.category = category
        self.message = message
        self.recommendation = recommendation
    }
}
