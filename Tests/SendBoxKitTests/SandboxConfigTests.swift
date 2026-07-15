import Foundation
import Testing
import Yams
@testable import SendBoxKit

struct SandboxConfigTests {

    private typealias Action = PolicyConfiguration.CommandPolicyConfig.Action

    // MARK: - Default configuration

    @Test func testDefaultConfig() {
        let config = SandboxConfiguration.default(projectPath: "/home/user/my-project")
        #expect(config.name == "my-project")
        #expect(config.projectPath == "/home/user/my-project")
        #expect(config.secrets.isEmpty)
        #expect(config.github.forwardAuth == true)
        #expect(config.github.forwardCopilotAuth == true)
        #expect(config.github.allowPrivateRepositoryAccess == false)
        #expect(config.devcontainer?.autoGenerate == true)
        #expect(config.runtime?.provider == .automatic)
        #expect(config.runtime?.kata.runtimeHandler == "io.containerd.kata.v2")
    }

    // MARK: - YAML serialization round-trip

    @Test func testSerializationRoundTrip() throws {
        let original = SandboxConfiguration.default(projectPath: "/projects/test")

        let encoder = YAMLEncoder()
        let yamlString = try encoder.encode(original)

        let decoder = YAMLDecoder()
        let decoded = try decoder.decode(SandboxConfiguration.self, from: yamlString)

        #expect(decoded.name == original.name)
        #expect(decoded.projectPath == original.projectPath)
        #expect(decoded.resources.cpus == original.resources.cpus)
        #expect(decoded.resources.memoryMB == original.resources.memoryMB)
        #expect(decoded.resources.diskSizeMB == original.resources.diskSizeMB)
        #expect(decoded.policy.commands.defaultAction == original.policy.commands.defaultAction)
        #expect(decoded.policy.network.defaultAction == original.policy.network.defaultAction)
        #expect(decoded.github.forwardAuth == original.github.forwardAuth)
        #expect(decoded.secrets == original.secrets)
        #expect(decoded.runtime == original.runtime)
    }

    // MARK: - Loading from YAML string

    @Test func testLoadFromYAML() throws {
        let yaml = """
        name: test-sandbox
        project_path: /home/user/project
        resources:
          cpus: 2
          memory_mb: 2048
          disk_size_mb: 5120
        policy:
          commands:
            default_action: allow
            allowlist: []
            denylist:
              - sudo
            log_blocked: true
          network:
            default_action: deny
            allowed_domains:
              - github.com
            blocked_domains: []
            allow_dns: true
        secrets: []
        github:
          forward_auth: false
          forward_copilot_auth: true
        """

        let data = Data(yaml.utf8)
        let config = try SandboxConfiguration.load(from: data)

        #expect(config.name == "test-sandbox")
        #expect(config.projectPath == "/home/user/project")
        #expect(config.resources.cpus == 2)
        #expect(config.resources.memoryMB == 2048)
        #expect(config.resources.diskSizeMB == 5120)
        #expect(config.policy.commands.defaultAction == Action.allow)
        #expect(config.policy.commands.denylist == ["sudo"])
        #expect(config.policy.network.allowedDomains == ["github.com"])
        #expect(config.github.forwardAuth == false)
        #expect(config.github.forwardCopilotAuth == true)
        #expect(config.github.allowPrivateRepositoryAccess == false)
        #expect(config.runtime == nil)
    }

    @Test func testLoadKataRuntimeFromYAML() throws {
        let yaml = """
            name: kata-sandbox
            project_path: /home/user/project
            runtime:
              provider: kata
              kata:
                executable: /usr/local/bin/nerdctl
                runtime_handler: io.containerd.kata-qemu.v2
                namespace: sendbox-ci
                address: /run/containerd/containerd.sock
                snapshotter: overlayfs
                configuration_path: /etc/kata-containers/configuration-qemu.toml
            resources:
              cpus: 2
              memory_mb: 2048
              disk_size_mb: 5120
            policy:
              commands:
                default_action: allow
                allowlist: []
                denylist: []
                log_blocked: true
              network:
                default_action: allow
                allowed_domains: []
                blocked_domains: []
                allow_dns: true
            secrets: []
            github:
              forward_auth: false
              forward_copilot_auth: false
            """

        let config = try SandboxConfiguration.load(from: Data(yaml.utf8))
        let runtime = try #require(config.runtime)

        #expect(runtime.provider == .kata)
        #expect(runtime.kata.executable == "/usr/local/bin/nerdctl")
        #expect(runtime.kata.runtimeHandler == "io.containerd.kata-qemu.v2")
        #expect(runtime.kata.namespace == "sendbox-ci")
        #expect(runtime.kata.address == "/run/containerd/containerd.sock")
        #expect(runtime.kata.snapshotter == "overlayfs")
        #expect(
            runtime.kata.configurationPath
                == "/etc/kata-containers/configuration-qemu.toml"
        )
    }

    @Test func testLoadPrivateRepositoryAccessOverride() throws {
        let original = SandboxConfiguration.default(projectPath: "/projects/private")
        var github = original.github
        github.allowPrivateRepositoryAccess = true

        let encoded = try YAMLEncoder().encode(github)
        let decoded = try YAMLDecoder().decode(
            SandboxConfiguration.GitHubConfig.self,
            from: encoded
        )

        #expect(decoded.allowPrivateRepositoryAccess)
    }

    @Test func testKataRuntimeDefaultsWhenSectionIsPartial() throws {
        let yaml = """
            name: kata-sandbox
            project_path: /home/user/project
            runtime:
              provider: kata
            resources:
              cpus: 2
              memory_mb: 2048
              disk_size_mb: 5120
            policy:
              commands:
                default_action: allow
                allowlist: []
                denylist: []
                log_blocked: true
              network:
                default_action: allow
                allowed_domains: []
                blocked_domains: []
                allow_dns: true
            secrets: []
            github:
              forward_auth: false
              forward_copilot_auth: false
            """

        let config = try SandboxConfiguration.load(from: Data(yaml.utf8))
        let runtime = try #require(config.runtime)

        #expect(runtime.kata == .default)
    }

    // MARK: - Policy presets

    @Test func testDefaultPolicyPreset() {
        let policy = PolicyConfiguration.default
        #expect(policy.commands.defaultAction == Action.deny)
        #expect(policy.commands.allowlist.contains("git"))
        #expect(policy.commands.allowlist.contains("npm"))
        #expect(policy.network.defaultAction == Action.deny)
        #expect(policy.network.allowedDomains.contains("github.com"))
        #expect(policy.network.allowDNS == true)
    }

    @Test func testPermissivePolicyPreset() {
        let policy = PolicyConfiguration.permissive
        #expect(policy.commands.defaultAction == Action.allow)
        #expect(policy.commands.denylist.contains("sudo"))
        #expect(policy.commands.denylist.contains("su"))
        #expect(policy.network.defaultAction == Action.allow)
        #expect(policy.network.blockedDomains.isEmpty)
    }

    @Test func testStrictPolicyPreset() {
        let policy = PolicyConfiguration.strict
        #expect(policy.commands.defaultAction == Action.deny)
        #expect(policy.commands.allowlist.contains("cat"))
        #expect(policy.commands.allowlist.contains("ls"))
        #expect(!policy.commands.allowlist.contains("curl"))
        #expect(!policy.commands.allowlist.contains("npm"))
        #expect(policy.network.maxConnections == 10)
        #expect(policy.network.allowedDomains.contains("github.com"))
    }

    // MARK: - Resource defaults

    @Test func testResourceDefaults() {
        let resources = SandboxConfiguration.ResourceConfig.default
        #expect(resources.cpus == 4)
        #expect(resources.memoryMB == 4096)
        #expect(resources.diskSizeMB == 10240)
    }
}
