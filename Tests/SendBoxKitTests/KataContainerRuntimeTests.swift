import Foundation
import Testing

@testable import SendBoxKit

struct KataContainerRuntimeTests {
    @Test func testRuntimeFactoryResolvesHostDefault() {
        #if canImport(Containerization)
        #expect(RuntimeProviderFactory.resolvedProvider(for: .automatic) == .apple)
        #else
        #expect(RuntimeProviderFactory.resolvedProvider(for: .automatic) == .kata)
        #endif
    }

    @Test func testKataCommandBuilderMapsContainerConfiguration() {
        let runtimeConfiguration = KataRuntimeConfiguration(
            executable: "nerdctl",
            runtimeHandler: "io.containerd.kata-qemu.v2",
            namespace: "sendbox-test",
            address: "/run/containerd/containerd.sock",
            snapshotter: "overlayfs",
            configurationPath: "/etc/kata-containers/configuration-qemu.toml"
        )
        let builder = KataCommandBuilder(configuration: runtimeConfiguration)
        let config = makeContainerConfig(
            firewallScript: "#!/bin/sh\ntrue\n",
            mcpInspectionScript: "#!/bin/sh\ntrue\n"
        )

        #expect(
            builder.globalArguments == [
                "--address", "/run/containerd/containerd.sock",
                "--namespace", "sendbox-test",
                "--snapshotter", "overlayfs",
            ]
        )

        let arguments = builder.runArguments(
            config: config,
            environmentFile: "/tmp/sendbox-env",
            inheritedEnvironmentKeys: ["MULTILINE_SECRET"]
        )

        #expect(arguments.starts(with: ["run", "--detach", "--interactive"]))
        #expect(flagValue("--runtime", in: arguments) == "io.containerd.kata-qemu.v2")
        #expect(flagValue("--cpus", in: arguments) == "2")
        #expect(flagValue("--memory", in: arguments) == "1073741824")
        #expect(flagValue("--env-file", in: arguments) == "/tmp/sendbox-env")
        #expect(flagValues("--env", in: arguments) == ["MULTILINE_SECRET"])
        #expect(
            flagValues("--annotation", in: arguments).contains(
                "io.katacontainers.config_path=/etc/kata-containers/configuration-qemu.toml"
            )
        )
        #expect(flagValues("--cap-add", in: arguments).contains("NET_ADMIN"))
        #expect(flagValues("--cap-add", in: arguments).contains("BPF"))
        #expect(flagValues("--cap-add", in: arguments).contains("PERFMON"))
        #expect(flagValues("--cap-add", in: arguments).contains("SYS_PTRACE"))
        #expect(
            flagValues("--volume", in: arguments).contains(
                "/host/project:/workspaces/project"
            )
        )
        #expect(
            flagValues("--volume", in: arguments).contains(
                "/host/project/.devcontainer:/workspaces/project/.devcontainer:ro"
            )
        )
        #expect(flagValues("--dns", in: arguments) == ["1.1.1.1", "9.9.9.9"])
        #expect(!arguments.contains(where: { $0.contains("super-secret") }))
        #expect(arguments.suffix(2) == ["example/image:latest", "/bin/bash"])
    }

    @Test func testKataLifecycleUsesSecureTemporaryEnvironmentFile() async throws {
        let recorder = KataCommandRecorder()
        let runtime = KataContainerRuntime(
            configuration: .default,
            commandRunner: { executable, arguments, environment in
                await recorder.run(
                    executable: executable,
                    arguments: arguments,
                    environment: environment
                )
            }
        )

        try await runtime.initialize()
        let id = try await runtime.createContainer(
            makeContainerConfig(),
            policy: allowAllPolicy()
        )
        #expect(id == "sandbox-id")
        #expect(await runtime.containerStatus(id: id) == .running)

        let snapshot = await recorder.snapshot()
        let runInvocation = try #require(
            snapshot.invocations.first { invocation in
                invocation.arguments.contains("run")
            })
        let environmentFile = try #require(flagValue("--env-file", in: runInvocation.arguments))

        #expect(snapshot.environmentContents == "API_TOKEN=super-secret\nPATH=/usr/bin\n")
        #expect(snapshot.environmentOverrides["MULTILINE_SECRET"] == "line one\nline two")
        #expect(snapshot.environmentFilePermissions == 0o600)
        #expect(!FileManager.default.fileExists(atPath: environmentFile))
        #expect(!runInvocation.arguments.contains(where: { $0.contains("super-secret") }))
        #expect(flagValues("--env", in: runInvocation.arguments) == ["MULTILINE_SECRET"])

        try await runtime.stopContainer(id: id)
        let finalSnapshot = await recorder.snapshot()
        #expect(
            finalSnapshot.invocations.contains { invocation in
                invocation.arguments.suffix(3) == ["rm", "--force", "sandbox-id"]
            }
        )
    }

    @Test func testKataRejectsDeniedStartupBeforeRun() async throws {
        let recorder = KataCommandRecorder()
        let runtime = KataContainerRuntime(
            configuration: .default,
            commandRunner: { executable, arguments, environment in
                await recorder.run(
                    executable: executable,
                    arguments: arguments,
                    environment: environment
                )
            }
        )
        let policy = CommandPolicy(
            config: .init(
                defaultAction: .deny,
                allowlist: ["git *"],
                denylist: [],
                logBlocked: false
            )
        )

        try await runtime.initialize()
        do {
            _ = try await runtime.createContainer(
                makeContainerConfig(command: ["rm", "-rf", "/"]),
                policy: policy
            )
            Issue.record("Expected startup command to be denied")
        } catch {
            #expect(error.localizedDescription.contains("denied by policy"))
        }

        let snapshot = await recorder.snapshot()
        #expect(!snapshot.invocations.contains { $0.arguments.contains("run") })
    }

    @Test func testKataRuntimeAppliesBoundaryBootstrapAndExecPrefix() async throws {
        let recorder = KataCommandRecorder()
        let runtime = KataContainerRuntime(
            configuration: .default,
            commandRunner: { executable, arguments, environment in
                await recorder.run(
                    executable: executable,
                    arguments: arguments,
                    environment: environment
                )
            }
        )
        let config = makeContainerConfig(
            boundaryExecPrefix: ["/run/sendbox-boundary/seccomp-launcher", "--"],
            boundaryReadyPath: "/run/sendbox-boundary/ready"
        )

        try await runtime.initialize()
        _ = try await runtime.createContainer(config, policy: allowAllPolicy())
        _ = try await runtime.exec(
            containerId: config.id,
            command: ["echo", "ok"],
            policy: CommandPolicy(config: PolicyConfiguration.default.commands)
        )

        let snapshot = await recorder.snapshot()
        let runInvocation = try #require(
            snapshot.invocations.first { $0.arguments.contains("run") }
        )
        #expect(flagValue("--pid", in: runInvocation.arguments) == "host")
        #expect(
            flagValue("--security-opt", in: runInvocation.arguments)
                == "seccomp=unconfined"
        )
        #expect(flagValues("--cap-add", in: runInvocation.arguments).contains("BPF"))
        #expect(flagValues("--cap-add", in: runInvocation.arguments).contains("SYS_ADMIN"))
        #expect(snapshot.environmentContents?.contains("SENDBOX_AGENT_ENV_B64=") == true)
        #expect(
            snapshot.invocations.contains { invocation in
                invocation.arguments.suffix(5)
                    == [
                        "sandbox-id",
                        "/run/sendbox-boundary/seccomp-launcher",
                        "--",
                        "echo",
                        "ok",
                    ]
            }
        )
    }

    @Test func testKataInitializationExplainsContainerdPermissions() async {
        let runtime = KataContainerRuntime(
            configuration: .default,
            commandRunner: { _, arguments, _ in
                if arguments.contains("info") {
                    return HostCommandResult(
                        exitCode: 1,
                        stdout: "",
                        stderr: "permission denied"
                    )
                }
                return HostCommandResult(exitCode: 0, stdout: "nerdctl 2.2.0", stderr: "")
            }
        )

        do {
            try await runtime.initialize()
            Issue.record("Expected Kata initialization to fail")
        } catch {
            #expect(error.localizedDescription.contains("permission denied"))
            #expect(error.localizedDescription.contains("rootless containerd"))
        }
    }

    #if !canImport(Security)
    @Test func testLinuxSecretsVaultRoundTrip() throws {
        let key = "TOKEN_\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let serviceName = "sendbox-tests-\(UUID().uuidString)"
        let vault = SecretsVault(serviceName: serviceName)

        #expect(try vault.exists(key: key) == false)
        try vault.store(key: key, value: "secret-value")
        #expect(try vault.exists(key: key))
        #expect(try vault.retrieve(key: key) == "secret-value")
        #expect(try vault.list().map(\.key) == [key])

        let serviceDirectory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sendbox/secrets/\(hexEncoded(serviceName))")
        let secretFile = serviceDirectory.appendingPathComponent(hexEncoded(key))
        let directoryAttributes = try FileManager.default.attributesOfItem(
            atPath: serviceDirectory.path
        )
        let fileAttributes = try FileManager.default.attributesOfItem(atPath: secretFile.path)
        #expect((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
        #expect((fileAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)

        try vault.delete(key: key)
        #expect(try vault.exists(key: key) == false)
    }
    #endif

    private func makeContainerConfig(
        firewallScript: String? = nil,
        mcpInspectionScript: String? = nil,
        command: [String] = ["/bin/bash"],
        boundaryExecPrefix: [String] = [],
        boundaryReadyPath: String? = nil
    ) -> ContainerConfig {
        ContainerConfig(
            id: "sandbox-id",
            hostname: "project",
            cpus: 2,
            memoryInBytes: 1_073_741_824,
            rootfsSizeInBytes: 10_737_418_240,
            imageReference: "example/image:latest",
            workingDirectory: "/workspaces/project",
            command: command,
            environment: [
                "API_TOKEN": "super-secret",
                "MULTILINE_SECRET": "line one\nline two",
                "PATH": "/usr/bin",
            ],
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
                nameservers: ["1.1.1.1", "9.9.9.9"]
            ),
            firewallScript: firewallScript,
            dnsConfig: nil,
            mcpInspectionScript: mcpInspectionScript,
            boundaryExecPrefix: boundaryExecPrefix,
            boundaryReadyPath: boundaryReadyPath
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

    private func flagValue(_ flag: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: flag) else {
            return nil
        }
        let valueIndex = arguments.index(after: index)
        guard valueIndex < arguments.endIndex else {
            return nil
        }
        return arguments[valueIndex]
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

    #if !canImport(Security)
    private func hexEncoded(_ value: String) -> String {
        value.utf8.map { String(format: "%02x", $0) }.joined()
    }
    #endif
}

private actor KataCommandRecorder {
    struct Invocation: Sendable {
        let executable: String
        let arguments: [String]
        let environment: [String: String]
    }

    struct Snapshot: Sendable {
        let invocations: [Invocation]
        let environmentContents: String?
        let environmentOverrides: [String: String]
        let environmentFilePermissions: Int?
    }

    private var invocations: [Invocation] = []
    private var environmentContents: String?
    private var environmentOverrides: [String: String] = [:]
    private var environmentFilePermissions: Int?

    func run(
        executable: String,
        arguments: [String],
        environment: [String: String]
    ) -> HostCommandResult {
        invocations.append(
            Invocation(
                executable: executable,
                arguments: arguments,
                environment: environment
            )
        )

        if arguments.contains("run"),
            let envIndex = arguments.firstIndex(of: "--env-file")
        {
            let pathIndex = arguments.index(after: envIndex)
            if pathIndex < arguments.endIndex {
                environmentContents = try? String(
                    contentsOfFile: arguments[pathIndex],
                    encoding: .utf8
                )
                let attributes = try? FileManager.default.attributesOfItem(
                    atPath: arguments[pathIndex]
                )
                environmentFilePermissions =
                    (attributes?[.posixPermissions] as? NSNumber)?.intValue
            }
            environmentOverrides = environment
            return HostCommandResult(exitCode: 0, stdout: "sandbox-id\n", stderr: "")
        }

        if arguments.contains("inspect") {
            return HostCommandResult(exitCode: 0, stdout: "running\n", stderr: "")
        }

        return HostCommandResult(exitCode: 0, stdout: "", stderr: "")
    }

    func snapshot() -> Snapshot {
        Snapshot(
            invocations: invocations,
            environmentContents: environmentContents,
            environmentOverrides: environmentOverrides,
            environmentFilePermissions: environmentFilePermissions
        )
    }
}
