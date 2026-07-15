import Testing

@testable import SendBoxKit

struct HyperlightRuntimeTests {
    @Test func testCommandBuilderMapsMicroVMConfiguration() {
        let configuration = HyperlightRuntimeConfiguration(
            executable: "hyperlight-unikraft",
            kernelPath: "/opt/hyperlight/shell-kernel",
            initrdPath: "/opt/hyperlight/shell.cpio",
            stackMB: 16,
            allowedHosts: ["api.github.com", "registry.npmjs.org"]
        )
        let builder = HyperlightCommandBuilder(configuration: configuration)

        let arguments = builder.arguments(
            for: makeContainerConfig(),
            command: ["node", "/workspaces/project/server.js", "--stdio"]
        )

        #expect(arguments[0] == "/opt/hyperlight/shell-kernel")
        #expect(flagValue("--initrd", in: arguments) == "/opt/hyperlight/shell.cpio")
        #expect(flagValue("--memory", in: arguments) == "1024Mi")
        #expect(flagValue("--stack", in: arguments) == "16Mi")
        #expect(
            flagValues("--mount", in: arguments) == [
                "/host/project/.devcontainer:/workspaces/project/.devcontainer",
                "/host/project:/workspaces/project",
            ]
        )
        #expect(
            flagValues("--net-allow", in: arguments) == [
                "api.github.com",
                "registry.npmjs.org",
            ]
        )
        #expect(
            arguments.suffix(4)
                == ["--", "node", "/workspaces/project/server.js", "--stdio"]
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

    private func makeContainerConfig() -> ContainerConfig {
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
                nameservers: ["1.1.1.1"]
            ),
            firewallScript: nil,
            dnsConfig: nil,
            mcpInspectionScript: nil
        )
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
