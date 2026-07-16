import Foundation
import Testing

@testable import SendBoxKit

struct HyperlightRuntimeTests {
    @Test func testCommandBuilderMapsMicroVMConfiguration() throws {
        let configuration = HyperlightRuntimeConfiguration(
            executable: "hyperlight-unikraft",
            kernelPath: "/opt/hyperlight/shell-kernel",
            initrdPath: "/opt/hyperlight/shell.cpio",
            stackMB: 16
        )
        let builder = HyperlightCommandBuilder(configuration: configuration)

        let arguments = try builder.arguments(
            for: makeContainerConfig(
                allowedHosts: ["api.github.com", "registry.npmjs.org"]
            ),
            command: ["node", "/workspaces/project/server.js", "--http"]
        )

        #expect(arguments[0] == "/opt/hyperlight/shell-kernel")
        #expect(Self.flagValue("--initrd", in: arguments) == "/opt/hyperlight/shell.cpio")
        #expect(Self.flagValue("--memory", in: arguments) == "1024Mi")
        #expect(Self.flagValue("--stack", in: arguments) == "16Mi")
        #expect(
            Self.flagValues("--mount", in: arguments) == [
                "/host/project:/workspaces/project"
            ]
        )
        #expect(
            Self.flagValues("--net-allow", in: arguments) == [
                "api.github.com",
                "registry.npmjs.org",
            ]
        )
        #expect(
            arguments.suffix(2)
                == [
                    "--exec",
                    "cd '/workspaces/project' && exec 'node' '/workspaces/project/server.js' '--http'",
                ]
        )
    }

    @Test func testCommandBuilderLeavesNetworkDisabledByDefault() throws {
        let builder = HyperlightCommandBuilder(
            configuration: HyperlightRuntimeConfiguration(
                kernelPath: "/opt/hyperlight/shell-kernel"
            )
        )

        let arguments = try builder.arguments(
            for: makeContainerConfig(),
            command: ["echo", "hello"]
        )

        #expect(!arguments.contains("--net"))
        #expect(!arguments.contains("--net-allow"))
    }

    @Test func testCommandBuilderQuotesShellMetacharacters() throws {
        let builder = HyperlightCommandBuilder(
            configuration: HyperlightRuntimeConfiguration(kernelPath: "/kernel")
        )

        let arguments = try builder.arguments(
            for: makeContainerConfig(),
            command: ["printf", "%s", "value'; rm -rf /"]
        )

        #expect(
            arguments.last
                == #"cd '/workspaces/project' && exec 'printf' '%s' 'value'\''; rm -rf /'"#
        )
    }

    @Test func testCommandBuilderRejectsWildcardAllowEntries() {
        let builder = HyperlightCommandBuilder(
            configuration: HyperlightRuntimeConfiguration(kernelPath: "/kernel")
        )

        do {
            _ = try builder.arguments(
                for: makeContainerConfig(allowedHosts: ["*.github.com"]),
                command: ["git", "fetch"]
            )
            Issue.record("Expected wildcard network entry to be rejected")
        } catch {
            #expect(error.localizedDescription.contains("concrete hostnames"))
        }
    }

    @Test func testCommandBuilderAppliesBlockedHostPrecedence() throws {
        let builder = HyperlightCommandBuilder(
            configuration: HyperlightRuntimeConfiguration(kernelPath: "/kernel")
        )

        let arguments = try builder.arguments(
            for: makeContainerConfig(
                allowedHosts: ["github.com", "api.github.com", "registry.npmjs.org"],
                blockedHosts: ["*.github.com"]
            ),
            command: ["git", "fetch"]
        )

        #expect(Self.flagValues("--net-allow", in: arguments) == ["registry.npmjs.org"])
    }

    @Test func testCommandBuilderAddsMCPListenPort() throws {
        let builder = HyperlightCommandBuilder(
            configuration: HyperlightRuntimeConfiguration(kernelPath: "/kernel")
        )

        let arguments = try builder.arguments(
            for: makeContainerConfig(),
            command: ["node", "server.js"],
            listenPorts: [8080]
        )

        #expect(Self.flagValues("--port", in: arguments) == ["8080"])
    }

    @Test func testExecAndMCPCheckPolicyBeforeSpawningMicroVM() async throws {
        let recorder = HyperlightCommandRecorder()
        let runtime = HyperlightRuntime(
            configuration: HyperlightRuntimeConfiguration(kernelPath: "/kernel"),
            commandRunner: { executable, arguments, _ in
                await recorder.record(executable: executable, arguments: arguments)
                if arguments != ["--version"] {
                    try await Task.sleep(for: .seconds(10))
                }
                return HostCommandResult(exitCode: 0, stdout: "", stderr: "")
            },
            hostValidator: { _ in }
        )
        let policy = CommandPolicy(
            config: .init(
                defaultAction: .deny,
                allowlist: ["git *"],
                denylist: [],
                logBlocked: true
            )
        )

        try await runtime.initialize()
        let id = try await runtime.createContainer(
            makeContainerConfig(),
            policy: allowAllPolicy()
        )

        do {
            _ = try await runtime.exec(
                containerId: id,
                command: ["rm", "-rf", "/"],
                policy: policy
            )
            Issue.record("Expected command policy to deny execution")
        } catch {
            #expect(error.localizedDescription.contains("denied by policy"))
        }

        do {
            _ = try await runtime.mcpExec(
                containerId: id,
                command: ["rm", "-rf", "/"],
                listenPort: 8080,
                policy: policy
            )
            Issue.record("Expected command policy to deny MCP execution")
        } catch {
            #expect(error.localizedDescription.contains("denied by policy"))
        }

        let invocations = await recorder.snapshot()
        #expect(
            !invocations.contains { invocation in
                invocation.arguments.contains("'rm' '-rf' '/'")
            }
        )
        try await runtime.stopContainer(id: id)
    }

    @Test func testCreateChecksPolicyBeforeSpawningMicroVM() async throws {
        let recorder = HyperlightCommandRecorder()
        let runtime = HyperlightRuntime(
            configuration: HyperlightRuntimeConfiguration(kernelPath: "/kernel"),
            commandRunner: { executable, arguments, _ in
                await recorder.record(executable: executable, arguments: arguments)
                return HostCommandResult(exitCode: 0, stdout: "", stderr: "")
            },
            hostValidator: { _ in }
        )
        let policy = CommandPolicy(
            config: .init(
                defaultAction: .deny,
                allowlist: ["git *"],
                denylist: [],
                logBlocked: true
            )
        )

        try await runtime.initialize()
        do {
            _ = try await runtime.createContainer(
                makeContainerConfig(command: ["rm", "-rf", "/"]),
                policy: policy
            )
            Issue.record("Expected startup command policy to deny execution")
        } catch {
            #expect(error.localizedDescription.contains("denied by policy"))
        }

        let invocations = await recorder.snapshot()
        #expect(!invocations.contains { $0.arguments.contains("--exec") })
    }

    @Test func testRuntimeStagesFreshReadOnlyMountsForEachExec() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("sendbox-hyperlight-test-\(UUID().uuidString)")
        let protectedDirectory = root.appendingPathComponent(".devcontainer")
        try FileManager.default.createDirectory(
            at: protectedDirectory,
            withIntermediateDirectories: true
        )
        try Data("protected".utf8).write(
            to: protectedDirectory.appendingPathComponent("devcontainer.json")
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let recorder = HyperlightCommandRecorder()
        let runtime = HyperlightRuntime(
            configuration: HyperlightRuntimeConfiguration(kernelPath: "/kernel"),
            commandRunner: { executable, arguments, _ in
                var stagedFileContents: [String: String] = [:]
                for mount in Self.flagValues("--mount", in: arguments) {
                    let source = String(mount.split(separator: ":", maxSplits: 1)[0])
                    let file = (source as NSString).appendingPathComponent("devcontainer.json")
                    if let contents = try? String(contentsOfFile: file, encoding: .utf8) {
                        stagedFileContents[source] = contents
                    }
                }
                await recorder.record(
                    executable: executable,
                    arguments: arguments,
                    stagedFileContents: stagedFileContents
                )
                if arguments.last?.contains("exec '/bin/sh'") == true {
                    try await Task.sleep(for: .seconds(10))
                }
                return HostCommandResult(exitCode: 0, stdout: "", stderr: "")
            },
            hostValidator: { _ in }
        )
        var config = makeContainerConfig()
        config.mounts.insert(
            .init(
                source: protectedDirectory.path,
                destination: "/workspaces/project/.devcontainer",
                readOnly: true
            ),
            at: 0
        )

        try await runtime.initialize()
        let policy = allowAllPolicy()
        let id = try await runtime.createContainer(config, policy: policy)

        var invocations = await recorder.snapshot()
        for _ in 0..<100 where !invocations.contains(where: { $0.arguments.contains("--exec") }) {
            try await Task.sleep(for: .milliseconds(10))
            invocations = await recorder.snapshot()
        }
        let invocation = try #require(
            invocations.first { $0.arguments.contains("--exec") }
        )
        let stagedMount = try #require(
            Self.flagValues("--mount", in: invocation.arguments).first {
                $0.hasSuffix(":/workspaces/project/.devcontainer")
            }
        )
        let stagedPath = String(
            stagedMount.dropLast(":/workspaces/project/.devcontainer".count)
        )
        #expect(stagedPath != protectedDirectory.path)
        #expect(
            FileManager.default.fileExists(
                atPath: (stagedPath as NSString)
                    .appendingPathComponent("devcontainer.json")
            )
        )
        try Data("mutated".utf8).write(
            to: URL(fileURLWithPath: stagedPath)
                .appendingPathComponent("devcontainer.json")
        )

        _ = try await runtime.exec(
            containerId: id,
            command: ["echo", "fresh"],
            policy: policy
        )
        invocations = await recorder.snapshot()
        let execInvocation = try #require(
            invocations.first { $0.arguments.last?.contains("exec 'echo' 'fresh'") == true }
        )
        let execStagedPath = try #require(execInvocation.stagedFileContents.keys.first)
        #expect(execStagedPath != stagedPath)
        #expect(execInvocation.stagedFileContents[execStagedPath] == "protected")
        #expect(!FileManager.default.fileExists(atPath: execStagedPath))

        try await runtime.stopContainer(id: id)
        #expect(!FileManager.default.fileExists(atPath: stagedPath))
    }

    @Test func testMCPSessionCleansFreshStagedMountsAfterNaturalExit() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("sendbox-hyperlight-mcp-test-\(UUID().uuidString)")
        let protectedDirectory = root.appendingPathComponent(".devcontainer")
        try FileManager.default.createDirectory(
            at: protectedDirectory,
            withIntermediateDirectories: true
        )
        try Data("protected".utf8).write(
            to: protectedDirectory.appendingPathComponent("devcontainer.json")
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let recorder = HyperlightCommandRecorder()
        let runtime = HyperlightRuntime(
            configuration: HyperlightRuntimeConfiguration(
                executable: "/usr/bin/true",
                kernelPath: "/kernel"
            ),
            commandRunner: { executable, arguments, _ in
                await recorder.record(executable: executable, arguments: arguments)
                if arguments.last?.contains("exec '/bin/sh'") == true {
                    try await Task.sleep(for: .seconds(10))
                }
                return HostCommandResult(exitCode: 0, stdout: "", stderr: "")
            },
            hostValidator: { _ in }
        )
        var config = makeContainerConfig()
        config.mounts.insert(
            .init(
                source: protectedDirectory.path,
                destination: "/workspaces/project/.devcontainer",
                readOnly: true
            ),
            at: 0
        )
        let policy = allowAllPolicy()

        try await runtime.initialize()
        let id = try await runtime.createContainer(config, policy: policy)
        let session = try await runtime.mcpExec(
            containerId: id,
            command: ["node", "server.js"],
            listenPort: 8080,
            policy: policy
        )

        #expect(session.listenPort == 8080)
        let stagedPath = try #require(session.stagedMountPaths.first)
        for _ in 0..<100
        where session.isRunning || FileManager.default.fileExists(atPath: stagedPath)
        {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(!session.isRunning)
        #expect(!FileManager.default.fileExists(atPath: stagedPath))

        try await runtime.stopContainer(id: id)
    }

    @Test func testRuntimeRejectsNetworkWhenDNSIsDisabled() async throws {
        let runtime = HyperlightRuntime(
            configuration: HyperlightRuntimeConfiguration(kernelPath: "/kernel"),
            commandRunner: { _, _, _ in
                HostCommandResult(exitCode: 0, stdout: "", stderr: "")
            },
            hostValidator: { _ in }
        )
        var config = makeContainerConfig(allowedHosts: ["api.github.com"])
        config.network = .init(
            address: config.network.address,
            gateway: config.network.gateway,
            nameservers: config.network.nameservers,
            allowedHosts: config.network.allowedHosts,
            allowDNS: false
        )

        try await runtime.initialize()
        do {
            _ = try await runtime.createContainer(config, policy: allowAllPolicy())
            Issue.record("Expected unsupported DNS policy to fail closed")
        } catch {
            #expect(error.localizedDescription.contains("DNS disabled"))
        }
    }

    private func makeContainerConfig(
        allowedHosts: [String] = [],
        blockedHosts: [String] = [],
        command: [String] = ["/bin/sh"]
    ) -> ContainerConfig {
        ContainerConfig(
            id: "sandbox-id",
            hostname: "project",
            cpus: 2,
            memoryInBytes: 1_073_741_824,
            rootfsSizeInBytes: 10_737_418_240,
            imageReference: "unused-by-hyperlight",
            workingDirectory: "/workspaces/project",
            command: command,
            environment: [:],
            mounts: [
                .init(
                    source: "/host/project",
                    destination: "/workspaces/project",
                    readOnly: false
                ),
            ],
            network: .init(
                address: "192.168.64.2/24",
                gateway: "192.168.64.1",
                nameservers: ["1.1.1.1"],
                allowedHosts: allowedHosts,
                blockedHosts: blockedHosts
            ),
            firewallScript: nil,
            dnsConfig: nil,
            mcpInspectionScript: nil
        )
    }

    private func allowAllPolicy() -> CommandPolicy {
        CommandPolicy(
            config: .init(
                defaultAction: .allow,
                allowlist: [],
                denylist: [],
                logBlocked: false
            )
        )
    }

    private actor HyperlightCommandRecorder {
        struct Invocation: Sendable {
            let executable: String
            let arguments: [String]
            let stagedFileContents: [String: String]
        }

        private var invocations: [Invocation] = []

        func record(
            executable: String,
            arguments: [String],
            stagedFileContents: [String: String] = [:]
        ) {
            invocations.append(
                Invocation(
                    executable: executable,
                    arguments: arguments,
                    stagedFileContents: stagedFileContents
                )
            )
        }

        func snapshot() -> [Invocation] {
            invocations
        }
    }

    private static func flagValue(_ flag: String, in arguments: [String]) -> String? {
        flagValues(flag, in: arguments).first
    }

    private static func flagValues(_ flag: String, in arguments: [String]) -> [String] {
        arguments.indices.compactMap { index in
            guard arguments[index] == flag else {
                return nil
            }
            let valueIndex = arguments.index(after: index)
            guard valueIndex < arguments.endIndex else {
                return nil
            }
            return arguments[valueIndex]
        }
    }
}
