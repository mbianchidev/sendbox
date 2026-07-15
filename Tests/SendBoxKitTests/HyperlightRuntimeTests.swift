import Testing

@testable import SendBoxKit

struct HyperlightRuntimeTests {
    @Test func testCommandBuilderMapsMicroVMConfiguration() {
        let configuration = HyperlightRuntimeConfiguration(
            executable: "hyperlight-unikraft",
            kernelPath: "/opt/hyperlight/shell-kernel",
            initrdPath: "/opt/hyperlight/shell.cpio",
            stackMB: 16
        )
        let builder = HyperlightCommandBuilder(configuration: configuration)

        let arguments = builder.arguments(
            for: makeContainerConfig(
                allowedHosts: ["api.github.com", "registry.npmjs.org"]
            ),
            command: ["node", "/workspaces/project/server.js", "--stdio"]
        )

        #expect(arguments[0] == "/opt/hyperlight/shell-kernel")
        #expect(flagValue("--initrd", in: arguments) == "/opt/hyperlight/shell.cpio")
        #expect(flagValue("--memory", in: arguments) == "1024Mi")
        #expect(flagValue("--stack", in: arguments) == "16Mi")
        #expect(
            flagValues("--mount", in: arguments) == [
                "/host/project:/workspaces/project"
            ]
        )
        #expect(
            flagValues("--net-allow", in: arguments) == [
                "api.github.com",
                "registry.npmjs.org",
            ]
        )
        #expect(
            arguments.suffix(2)
                == [
                    "--exec",
                    "'node' '/workspaces/project/server.js' '--stdio'",
                ]
        )
    }

    @Test func testCommandBuilderLeavesNetworkDisabledByDefault() {
        let builder = HyperlightCommandBuilder(
            configuration: HyperlightRuntimeConfiguration(
                kernelPath: "/opt/hyperlight/shell-kernel"
            )
        )

        let arguments = builder.arguments(for: makeContainerConfig(), command: ["echo", "hello"])

        #expect(!arguments.contains("--net"))
        #expect(!arguments.contains("--net-allow"))
    }

    @Test func testCommandBuilderQuotesShellMetacharacters() {
        let builder = HyperlightCommandBuilder(
            configuration: HyperlightRuntimeConfiguration(kernelPath: "/kernel")
        )

        let arguments = builder.arguments(
            for: makeContainerConfig(),
            command: ["printf", "%s", "value'; rm -rf /"]
        )

        #expect(arguments.last == #"'printf' '%s' 'value'\''; rm -rf /'"#)
    }

    @Test func testExecChecksPolicyBeforeSpawningMicroVM() async throws {
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
        let id = try await runtime.createContainer(makeContainerConfig())

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

        let invocations = await recorder.snapshot()
        #expect(
            !invocations.contains { invocation in
                invocation.arguments.contains("'rm' '-rf' '/'")
            }
        )
    }

    private func makeContainerConfig(allowedHosts: [String] = []) -> ContainerConfig {
        ContainerConfig(
            id: "sandbox-id",
            hostname: "project",
            cpus: 2,
            memoryInBytes: 1_073_741_824,
            rootfsSizeInBytes: 10_737_418_240,
            imageReference: "unused-by-hyperlight",
            workingDirectory: "/workspaces/project",
            command: ["/bin/sh"],
            environment: [:],
            mounts: [
                .init(
                    source: "/host/project/.devcontainer",
                    destination: "/workspaces/project/.devcontainer",
                    readOnly: true
                ),
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
                allowedHosts: allowedHosts
            ),
            firewallScript: nil,
            dnsConfig: nil,
            mcpInspectionScript: nil
        )
    }

    private actor HyperlightCommandRecorder {
        struct Invocation: Sendable {
            let executable: String
            let arguments: [String]
        }

        private var invocations: [Invocation] = []

        func record(executable: String, arguments: [String]) {
            invocations.append(Invocation(executable: executable, arguments: arguments))
        }

        func snapshot() -> [Invocation] {
            invocations
        }
    }

    private func flagValue(_ flag: String, in arguments: [String]) -> String? {
        flagValues(flag, in: arguments).first
    }

    private func flagValues(_ flag: String, in arguments: [String]) -> [String] {
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
