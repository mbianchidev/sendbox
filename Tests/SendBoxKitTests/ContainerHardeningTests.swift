import Foundation
import Testing
@testable import SendBoxKit

struct ContainerHardeningTests {

    // MARK: - Helpers

    private func makeHardening(
        profile: ContainerHardening.Profile = .standard
    ) -> ContainerHardening {
        ContainerHardening(profile: profile)
    }

    private func makeConfig(
        mounts: [ContainerConfig.MountPoint] = [],
        cpus: Int = 2,
        memoryInBytes: UInt64 = 2 * 1024 * 1024 * 1024,
        firewallScript: String? = "#!/usr/bin/env bash\niptables -F",
        environment: [String: String] = [:]
    ) -> ContainerConfig {
        ContainerConfig(
            id: "test-container",
            hostname: "test",
            cpus: cpus,
            memoryInBytes: memoryInBytes,
            rootfsSizeInBytes: 10 * 1024 * 1024 * 1024,
            imageReference: "ghcr.io/test/image:latest",
            workingDirectory: "/workspaces/test",
            command: ["/bin/bash"],
            environment: environment,
            mounts: mounts,
            network: ContainerConfig.NetworkConfig(
                address: "192.168.64.2/24",
                gateway: "192.168.64.1",
                nameservers: ["1.1.1.1"]
            ),
            firewallScript: firewallScript,
            dnsConfig: nil
        )
    }

    // MARK: - Profile presets

    @Test func testStandardProfile() {
        let hardening = makeHardening(profile: .standard)
        let sysctls = hardening.sysctlConfig()
        // Standard should still include core hardening
        #expect(sysctls["kernel.modules_disabled"] == "1")
        #expect(sysctls["kernel.unprivileged_bpf_disabled"] == "1")
    }

    @Test func testMaximumProfile() {
        let hardening = makeHardening(profile: .maximum)
        let script = hardening.hardeningScript()
        // Maximum should set no_new_privs
        #expect(script.contains("no_new_privs"))
        let caps = hardening.droppedCapabilities()
        // Maximum should drop additional caps beyond standard
        #expect(caps.contains("CAP_SETUID"))
        #expect(caps.contains("CAP_SETGID"))
    }

    @Test func testBenchmarkProfile() {
        let hardening = makeHardening(profile: .benchmark)
        let report = hardening.securityReport()
        // Benchmark profile should cover all 18 scenarios
        #expect(report.contains("18/18"))
    }

    // MARK: - Sysctl generation

    @Test func testSysctlDisablesModuleLoading() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.modules_disabled"] == "1")
    }

    @Test func testSysctlDisablesBPF() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.unprivileged_bpf_disabled"] == "1")
    }

    @Test func testSysctlDisablesPtrace() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.yama.ptrace_scope"] == "2")
    }

    @Test func testSysctlDisablesRouteLocalnet() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["net.ipv4.conf.all.route_localnet"] == "0")
    }

    @Test func testSysctlDisablesCorePattern() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        let corePattern = sysctls["kernel.core_pattern"]
        #expect(corePattern != nil)
        #expect(corePattern!.contains("/bin/false"))
    }

    @Test func testSysctlEnablesKASLR() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.randomize_va_space"] == "2")
    }

    @Test func testSysctlRestrictsKernelPointers() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.kptr_restrict"] == "2")
    }

    @Test func testSysctlRestrictsDmesg() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.dmesg_restrict"] == "1")
    }

    @Test func testSysctlDisablesSendRedirects() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["net.ipv4.conf.all.send_redirects"] == "0")
    }

    @Test func testSysctlProtectsSymlinks() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["fs.protected_symlinks"] == "1")
    }

    // MARK: - Hardening script

    @Test func testHardeningScriptIsBashScript() {
        let hardening = makeHardening()
        let script = hardening.hardeningScript()
        #expect(script.hasPrefix("#!/usr/bin/env bash"))
    }

    @Test func testHardeningScriptAppliesSysctl() {
        let hardening = makeHardening()
        let script = hardening.hardeningScript()
        #expect(script.contains("sysctl -w"))
        #expect(script.contains("kernel.modules_disabled=1"))
        #expect(script.contains("kernel.unprivileged_bpf_disabled=1"))
    }

    @Test func testHardeningScriptDropsCapabilities() {
        let hardening = makeHardening()
        let script = hardening.hardeningScript()
        #expect(script.contains("capsh") || script.contains("setpriv") || script.contains("cap_drop"))
        #expect(script.contains("CAP_SYS_ADMIN"))
    }

    @Test func testHardeningScriptDisablesCgroupReleaseAgent() {
        let hardening = makeHardening(profile: .maximum)
        let script = hardening.hardeningScript()
        #expect(script.contains("release_agent") || script.contains("notify_on_release"))
    }

    @Test func testHardeningScriptSetsNoNewPrivs() {
        let hardening = makeHardening(profile: .maximum)
        let script = hardening.hardeningScript()
        #expect(script.contains("no_new_privs"))
    }

    @Test func testHardeningScriptUsesSetEuo() {
        let hardening = makeHardening()
        let script = hardening.hardeningScript()
        #expect(script.contains("set -euo pipefail"))
    }

    // MARK: - Seccomp profile

    @Test func testSeccompBlocksMountSyscall() {
        let hardening = makeHardening()
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("mount"))
    }

    @Test func testSeccompBlocksModuleLoading() {
        let hardening = makeHardening()
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("init_module"))
        #expect(seccomp.contains("finit_module"))
    }

    @Test func testSeccompBlocksOpenByHandleAt() {
        let hardening = makeHardening()
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("open_by_handle_at"))
    }

    @Test func testSeccompBlocksPtrace() {
        let hardening = makeHardening()
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("ptrace"))
    }

    @Test func testSeccompBlocksBPF() {
        let hardening = makeHardening()
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("bpf"))
    }

    @Test func testSeccompBlocksUnshare() {
        let hardening = makeHardening()
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("unshare"))
    }

    @Test func testSeccompBlocksKexecLoad() {
        let hardening = makeHardening()
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("kexec_load"))
    }

    @Test func testSeccompIsValidJSON() {
        let hardening = makeHardening()
        let seccomp = hardening.seccompProfile()
        let data = seccomp.data(using: .utf8)!
        let parsed = try? JSONSerialization.jsonObject(with: data)
        #expect(parsed != nil, "Seccomp profile must be valid JSON")
    }

    @Test func testSeccompHasDefaultDenyAction() {
        let hardening = makeHardening()
        let seccomp = hardening.seccompProfile()
        // OCI seccomp profiles use "defaultAction": "SCMP_ACT_ERRNO" or "SCMP_ACT_ALLOW"
        #expect(seccomp.contains("SCMP_ACT_ERRNO") || seccomp.contains("SCMP_ACT_ALLOW"))
    }

    // MARK: - Capability dropping

    @Test func testDropsCAP_SYS_ADMIN() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_SYS_ADMIN"))
    }

    @Test func testDropsCAP_SYS_MODULE() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_SYS_MODULE"))
    }

    @Test func testDropsCAP_DAC_READ_SEARCH() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_DAC_READ_SEARCH"))
    }

    @Test func testDropsCAP_NET_RAW() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_NET_RAW"))
    }

    @Test func testDropsCAP_SYS_PTRACE() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_SYS_PTRACE"))
    }

    @Test func testDropsCAP_SYS_RAWIO() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_SYS_RAWIO"))
    }

    @Test func testDropsCAP_NET_ADMIN() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_NET_ADMIN"))
    }

    @Test func testDropsCAP_MKNOD() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_MKNOD"))
    }

    // MARK: - Config validation

    @Test func testWarnsOnWritableSensitiveMount() {
        let config = makeConfig(mounts: [
            ContainerConfig.MountPoint(
                source: "/etc",
                destination: "/etc",
                readOnly: false
            ),
        ])
        let hardening = makeHardening()
        let warnings = hardening.validate(config: config)
        #expect(!warnings.isEmpty)
        #expect(warnings.contains { $0.contains("/etc") })
    }

    @Test func testWarnsOnDockerSockMount() {
        let config = makeConfig(mounts: [
            ContainerConfig.MountPoint(
                source: "/var/run/docker.sock",
                destination: "/var/run/docker.sock",
                readOnly: false
            ),
        ])
        let hardening = makeHardening()
        let warnings = hardening.validate(config: config)
        #expect(!warnings.isEmpty)
        #expect(warnings.contains { $0.contains("docker.sock") || $0.contains("/var/run") })
    }

    @Test func testWarnsOnProcMount() {
        let config = makeConfig(mounts: [
            ContainerConfig.MountPoint(
                source: "/proc",
                destination: "/proc/host",
                readOnly: true
            ),
        ])
        let hardening = makeHardening()
        let warnings = hardening.validate(config: config)
        #expect(!warnings.isEmpty)
    }

    @Test func testWarnsOnExcessiveResources() {
        let config = makeConfig(
            cpus: 64,
            memoryInBytes: 256 * 1024 * 1024 * 1024
        )
        let hardening = makeHardening()
        let warnings = hardening.validate(config: config)
        #expect(!warnings.isEmpty)
    }

    @Test func testWarnsOnMissingFirewall() {
        let config = makeConfig(firewallScript: nil)
        let hardening = makeHardening()
        let warnings = hardening.validate(config: config)
        #expect(!warnings.isEmpty)
        #expect(warnings.contains { $0.lowercased().contains("firewall") })
    }

    @Test func testNoWarningsOnGoodConfig() {
        let config = makeConfig(
            mounts: [
                ContainerConfig.MountPoint(
                    source: "/Users/test/project/.devcontainer",
                    destination: "/workspaces/project/.devcontainer",
                    readOnly: true
                ),
                ContainerConfig.MountPoint(
                    source: "/Users/test/project",
                    destination: "/workspaces/project",
                    readOnly: false
                ),
            ],
            cpus: 2,
            memoryInBytes: 4 * 1024 * 1024 * 1024,
            firewallScript: "#!/usr/bin/env bash\niptables -F"
        )
        let hardening = makeHardening()
        let warnings = hardening.validate(config: config)
        #expect(warnings.isEmpty, "Expected no warnings but got: \(warnings)")
    }

    // MARK: - Config hardening

    @Test func testHardenAddsScript() {
        var config = makeConfig(firewallScript: nil)
        let hardening = makeHardening()
        config = hardening.harden(config: config)
        #expect(config.firewallScript != nil)
        #expect(config.firewallScript!.contains("sysctl"))
    }

    @Test func testHardenStripsUnsafeEnvVars() {
        var config = makeConfig(environment: [
            "PATH": "/usr/bin",
            "HOME": "/root",
            "LD_PRELOAD": "/tmp/evil.so",
            "LD_LIBRARY_PATH": "/tmp/evil",
            "PYTHONPATH": "/tmp/evil",
        ])
        let hardening = makeHardening()
        config = hardening.harden(config: config)
        #expect(config.environment["LD_PRELOAD"] == nil)
        #expect(config.environment["LD_LIBRARY_PATH"] == nil)
        #expect(config.environment["PATH"] != nil)
        #expect(config.environment["HOME"] != nil)
    }

    @Test func testHardenPreservesExistingFirewallScript() {
        var config = makeConfig(
            firewallScript: "#!/usr/bin/env bash\necho custom"
        )
        let hardening = makeHardening()
        config = hardening.harden(config: config)
        // Should prepend hardening, not replace existing script
        #expect(config.firewallScript!.contains("sysctl"))
        #expect(config.firewallScript!.contains("custom") || config.firewallScript!.contains("echo"))
    }

    // MARK: - Security report

    @Test func testSecurityReportCoversAllBenchmarkScenarios() {
        let hardening = makeHardening(profile: .benchmark)
        let report = hardening.securityReport()

        let scenarios = [
            "crio", "kubectl_cp", "rbac", "route_localnet",
            "privileged", "docker_sock", "cap_sys_admin", "cap_sys_module",
            "cap_dac_read_search", "hostpath", "runc_2019", "runc_2024",
            "pid_ns", "cgroup", "bpf_privesc", "dirty_cow",
            "dirty_pipe", "packet_sock",
        ]

        for scenario in scenarios {
            #expect(
                report.lowercased().contains(scenario.lowercased()),
                "Security report missing scenario: \(scenario)"
            )
        }
    }

    @Test func testSecurityReportShowsActiveHardening() {
        let hardening = makeHardening(profile: .standard)
        let report = hardening.securityReport()
        #expect(report.contains("sysctl") || report.contains("Sysctl"))
        #expect(report.contains("seccomp") || report.contains("Seccomp"))
        #expect(report.contains("capabilit") || report.contains("Capabilit"))
    }

    @Test func testSecurityReportIncludesProfileName() {
        let standard = makeHardening(profile: .standard)
        #expect(standard.securityReport().lowercased().contains("standard"))

        let maximum = makeHardening(profile: .maximum)
        #expect(maximum.securityReport().lowercased().contains("maximum"))

        let benchmark = makeHardening(profile: .benchmark)
        #expect(benchmark.securityReport().lowercased().contains("benchmark"))
    }

    // MARK: - SandboxEscapeBench specific

    @Test func testBenchmarkCRIOBlocked() {
        let hardening = makeHardening(profile: .benchmark)
        let sysctls = hardening.sysctlConfig()
        // CRI-O CVE uses core_pattern injection — ensure it's locked down
        #expect(sysctls["kernel.core_pattern"] != nil)
        #expect(sysctls["kernel.core_pattern"]!.contains("/bin/false"))
    }

    @Test func testBenchmarkDockerSockBlocked() {
        let hardening = makeHardening()
        // Validate that docker.sock mount is flagged as dangerous
        let config = makeConfig(mounts: [
            ContainerConfig.MountPoint(
                source: "/var/run/docker.sock",
                destination: "/var/run/docker.sock",
                readOnly: false
            ),
        ])
        let warnings = hardening.validate(config: config)
        #expect(!warnings.isEmpty, "Docker socket mount should produce a warning")
    }

    @Test func testBenchmarkPrivilegedBlocked() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        // Privileged containers get ALL capabilities — we drop the dangerous ones
        #expect(caps.contains("CAP_SYS_ADMIN"))
        #expect(caps.contains("CAP_SYS_MODULE"))
        #expect(caps.contains("CAP_NET_RAW"))
        #expect(caps.contains("CAP_SYS_PTRACE"))
    }

    @Test func testBenchmarkCapSysAdminBlocked() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_SYS_ADMIN"))
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("mount"))
        #expect(seccomp.contains("unshare"))
    }

    @Test func testBenchmarkCapDacReadSearchBlocked() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_DAC_READ_SEARCH"))
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("open_by_handle_at"))
    }

    @Test func testBenchmarkDirtyCowBlocked() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        // KASLR makes exploitation harder
        #expect(sysctls["kernel.randomize_va_space"] == "2")
        // Kernel pointer restriction prevents info leak needed for exploitation
        #expect(sysctls["kernel.kptr_restrict"] == "2")
    }

    @Test func testBenchmarkDirtyPipeBlocked() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        // Dirty Pipe is a kernel vuln — VM isolation is primary defense
        // Defense-in-depth: no_new_privs prevents setuid escalation after overwrite
        #expect(sysctls["fs.suid_dumpable"] == "0")
        #expect(sysctls["fs.protected_symlinks"] == "1")
    }

    @Test func testBenchmarkBPFBlocked() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.unprivileged_bpf_disabled"] == "1")
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("bpf"))
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_SYS_ADMIN"))
    }

    @Test func testBenchmarkPacketSockBlocked() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_NET_RAW"))
    }

    @Test func testBenchmarkPidNsBlocked() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.yama.ptrace_scope"] == "2")
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_SYS_PTRACE"))
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("ptrace"))
    }

    @Test func testBenchmarkCgroupBlocked() {
        let hardening = makeHardening(profile: .maximum)
        let script = hardening.hardeningScript()
        #expect(script.contains("release_agent") || script.contains("notify_on_release"))
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_SYS_ADMIN"))
    }

    @Test func testBenchmarkRuncCVEsBlocked() {
        // runc CVE-2019-5736 and CVE-2024-21626 — no runc exists
        // Verify the security report acknowledges this
        let hardening = makeHardening(profile: .benchmark)
        let report = hardening.securityReport()
        #expect(report.lowercased().contains("runc_2019"))
        #expect(report.lowercased().contains("runc_2024"))
    }

    @Test func testBenchmarkHostpathBlocked() {
        let hardening = makeHardening()
        // Verify that sensitive host paths are flagged
        let sensitivePaths = ["/etc", "/var/run", "/proc", "/sys", "/dev"]
        for path in sensitivePaths {
            let config = makeConfig(mounts: [
                ContainerConfig.MountPoint(
                    source: path,
                    destination: path,
                    readOnly: false
                ),
            ])
            let warnings = hardening.validate(config: config)
            #expect(!warnings.isEmpty, "Mount to \(path) should produce a warning")
        }
    }

    @Test func testBenchmarkKubectlCpBlocked() {
        let hardening = makeHardening(profile: .benchmark)
        let report = hardening.securityReport()
        #expect(report.lowercased().contains("kubectl_cp"))
    }

    @Test func testBenchmarkRBACBlocked() {
        let hardening = makeHardening(profile: .benchmark)
        let report = hardening.securityReport()
        #expect(report.lowercased().contains("rbac"))
    }

    @Test func testBenchmarkCapSysModuleBlocked() {
        let hardening = makeHardening()
        let caps = hardening.droppedCapabilities()
        #expect(caps.contains("CAP_SYS_MODULE"))
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.modules_disabled"] == "1")
        let seccomp = hardening.seccompProfile()
        #expect(seccomp.contains("init_module"))
        #expect(seccomp.contains("finit_module"))
    }

    // MARK: - Comprehensive sysctl coverage

    @Test func testAllSysctlsProducedAsScript() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        // Must have a minimum number of hardening entries
        #expect(sysctls.count >= 10, "Expected at least 10 sysctl entries, got \(sysctls.count)")
    }

    @Test func testSysctlDisablesPerfEvents() {
        let hardening = makeHardening()
        let sysctls = hardening.sysctlConfig()
        #expect(sysctls["kernel.perf_event_paranoid"] == "3")
    }
}
