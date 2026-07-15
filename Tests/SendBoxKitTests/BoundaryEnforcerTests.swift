import Foundation
import Testing

@testable import SendBoxKit

struct BoundaryEnforcerTests {
    private typealias Action = PolicyConfiguration.CommandPolicyConfig.Action
    private typealias ToolConfig = PolicyConfiguration.ToolCallPolicyConfig

    private func makeToolConfig(
        defaultAction: Action = .deny,
        allowlist: [String] = [],
        denylist: [String] = [],
        maxFrameBytes: Int = 4096,
        allowedServerCommands: [[String]] = []
    ) -> ToolConfig {
        ToolConfig(
            defaultAction: defaultAction,
            allowlist: allowlist,
            denylist: denylist,
            maxFrameBytes: maxFrameBytes,
            allowedServerCommands: allowedServerCommands
        )
    }

    @Test func testPackageRunnerServerCommandIsRejected() {
        let enforcer = makeEnforcer(
            toolConfig: makeToolConfig(
                allowedServerCommands: [
                    ["/usr/local/bin/npx", "@modelcontextprotocol/server-filesystem"]
                ]
            )
        )
        #expect(throws: BoundaryEnforcer.ValidationError.self) {
            try enforcer.validate()
        }
    }

    private func makeEnforcer(
        toolConfig: ToolConfig? = nil,
        additionalSyscalls: [String] = []
    ) -> BoundaryEnforcer {
        let config = PolicyConfiguration.BoundaryPolicyConfig(
            enabled: true,
            toolCalls: toolConfig ?? makeToolConfig(),
            syscalls: .init(
                additionalDenylist: additionalSyscalls,
                logBlocked: true
            ),
            logPath: "/var/log/sendbox/boundary.log"
        )
        return BoundaryEnforcer(
            config: config,
            serverCommandPatterns: ["mcp-server"],
            runAsUID: 501,
            runAsGID: 20
        )
    }

    @Test func testToolPolicyDenylistOverridesAllowlist() {
        let policy = MCPToolPolicy(
            config: makeToolConfig(
                defaultAction: .allow,
                allowlist: ["filesystem.*"],
                denylist: ["filesystem.delete"]
            ))

        #expect(policy.evaluate(tool: "filesystem.read").isAllowed)
        #expect(!policy.evaluate(tool: "filesystem.delete").isAllowed)
    }

    @Test func testToolPolicyRejectsHTTPTransport() {
        let policy = MCPToolPolicy(config: makeToolConfig(defaultAction: .allow))
        let decision = policy.evaluate(tool: "read_file", transport: .http)
        #expect(!decision.isAllowed)
    }

    @Test func testFrameFilterReassemblesAndForwardsAllowedCall() {
        var filter = MCPStdioFrameFilter(
            config: makeToolConfig(
                allowlist: ["read_*"]
            ))
        let first = Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"#.utf8)
        let second = Data(#""name":"read_file"}}"#.utf8) + Data([0x0A])

        #expect(filter.consume(first).isEmpty)
        let actions = filter.consume(second)
        #expect(actions.count == 1)
        guard case .forward(let frame) = actions[0] else {
            Issue.record("Expected an allowed frame to be forwarded")
            return
        }
        #expect(String(data: frame, encoding: .utf8)?.contains("read_file") == true)
    }

    @Test func testFrameFilterReturnsJSONRPCErrorForDeniedCall() throws {
        var filter = MCPStdioFrameFilter(config: makeToolConfig())
        let frame =
            Data(
                #"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"shell"}}"#.utf8
            ) + Data([0x0A])

        let actions = filter.consume(frame)
        #expect(actions.count == 1)
        guard case .respond(let response) = actions[0] else {
            Issue.record("Expected a denied tool response")
            return
        }

        let object = try #require(
            JSONSerialization.jsonObject(with: response) as? [String: Any]
        )
        let error = try #require(object["error"] as? [String: Any])
        #expect(object["id"] as? Int == 7)
        #expect(error["code"] as? Int == -32001)
    }

    @Test func testFrameFilterFailsClosedOnOversizedFrame() {
        var filter = MCPStdioFrameFilter(config: makeToolConfig(maxFrameBytes: 8))
        let actions = filter.consume(Data("123456789".utf8))
        #expect(actions.count == 1)
        guard case .terminate = actions[0] else {
            Issue.record("Expected oversized frame to terminate the proxy")
            return
        }
    }

    @Test func testGeneratedProxyParsesCompleteFrames() {
        let script = makeEnforcer(
            toolConfig: makeToolConfig(
                allowedServerCommands: [
                    ["/usr/bin/node", "/opt/mcp-server-filesystem.js"]
                ]
            )
        ).generateProxyScript()
        #expect(script.contains("readline(MAX_FRAME_BYTES + 1)"))
        #expect(script.contains("message.get(\"method\") == \"tools/call\""))
        #expect(script.contains("Tool call denied by SendBox boundary policy"))
        #expect(script.contains("ALLOWED_SERVER_COMMANDS"))
        #expect(script.contains("[\"/usr/bin/node\",\"/opt/mcp-server-filesystem.js\"]"))
        #expect(!script.contains("\\/usr\\/bin"))
        #expect(script.contains("[LAUNCHER_PATH, \"--\"] + command"))
    }

    @Test func testGeneratedBPFDetectsProxyBypassWithoutTLSPayloadMatching() {
        let program = makeEnforcer().generateBpftraceProgram()
        #expect(program.contains("mcp_proxy_bypass"))
        #expect(program.contains("signal(\"SIGKILL\")"))
        #expect(program.contains("mcp-server"))
        #expect(program.contains("pid == \(BoundaryEnforcer.proxyDaemonPIDPlaceholder)"))
        #expect(!program.contains("@trusted[args->parent_pid]"))
        #expect(!program.contains("$filename == \"\(BoundaryEnforcer.proxyPath)\""))
        #expect(program.contains("sys_enter_*"))
        #expect(!program.contains("SSL_write"))
    }

    @Test func testSeccompLauncherUsesHardeningRulesAndDropsPrivileges() {
        let source = makeEnforcer(additionalSyscalls: ["io_uring_setup"])
            .generateSeccompLauncherSource()
        #expect(source.contains("\"mount\""))
        #expect(source.contains("\"bpf\""))
        #expect(source.contains("\"io_uring_setup\""))
        #expect(source.contains("\"execveat\""))
        #expect(source.contains("\"process_vm_writev\""))
        #expect(source.contains("setuid(target_uid)"))
        #expect(source.contains("seccomp_load(context)"))
        #expect(source.contains("load_agent_environment()"))
    }

    @Test func testBootstrapIsFailClosedAndCreatesReadinessMarker() {
        let script = makeEnforcer().generateBootstrapScript(
            command: ["/bin/bash"],
            preflightScripts: ["#!/usr/bin/env bash\necho firewall"]
        )
        #expect(script.contains("exit 126"))
        #expect(script.contains(BoundaryEnforcer.readyPath))
        #expect(script.contains("eBPF boundary did not become ready"))
        #expect(script.contains("seccomp launcher self-test failed"))
        #expect(script.contains("exec '\(BoundaryEnforcer.launcherPath)' '--' '/bin/bash'"))
        #expect(script.contains("bpftrace --unsafe"))
        #expect(script.contains("Yama ptrace_scope verification failed"))
        #expect(script.contains("-I -B '\(BoundaryEnforcer.proxyDaemonSourcePath)'"))
        #expect(script.contains("-I -B '\(BoundaryEnforcer.proxyClientSourcePath)'"))
        #expect(!script.contains("apt-get"))
        let selfTestIndex = script.range(of: "seccomp launcher self-test failed")?.lowerBound
        let restoreIndex = script.range(of: "encoded = os.environ.get")?.lowerBound
        #expect(selfTestIndex != nil)
        #expect(restoreIndex != nil)
        if let selfTestIndex, let restoreIndex {
            #expect(selfTestIndex < restoreIndex)
        }
    }

    @Test func testRequiredSyscallCannotBeDenied() {
        let enforcer = makeEnforcer(additionalSyscalls: ["execve"])
        #expect(throws: BoundaryEnforcer.ValidationError.requiredSyscallDenied("execve")) {
            try enforcer.validate()
        }
    }

    @Test func testAllowedServerMustMatchDetectionPattern() {
        let enforcer = makeEnforcer(
            toolConfig: makeToolConfig(
                allowedServerCommands: [["/usr/bin/python3", "/workspaces/server.py"]]
            )
        )
        #expect(throws: BoundaryEnforcer.ValidationError.self) {
            try enforcer.validate()
        }
    }

    @Test func testContainerConfigRunsBoundaryBeforeDeferredScripts() {
        let sandbox = SandboxConfiguration.default(projectPath: "/tmp/project")
        let firewall = NetworkFirewall(config: sandbox.policy.network)
        let enforcer = makeEnforcer()
        let config = ContainerConfig.from(
            sandbox: sandbox,
            imageReference: "example/image:latest",
            firewall: firewall,
            boundaryEnforcer: enforcer
        )

        #expect(
            config.command.prefix(4)
                == ["/bin/bash", "--noprofile", "--norc", "-c"]
        )
        #expect(config.command.last?.contains("SENDBOX_PREFLIGHT_0") == true)
        #expect(config.firewallScript == nil)
        #expect(config.boundaryExecPrefix == enforcer.execPrefix)
        #expect(config.boundaryReadyPath == BoundaryEnforcer.readyPath)
        #expect(config.environment["SENDBOX_MCP_PROXY"] == BoundaryEnforcer.proxyPath)
    }

    @Test func testMCPConfigValidatorAcceptsProxiedStdioServer() throws {
        let directory = try makeTemporaryProject()
        defer { try? FileManager.default.removeItem(at: directory) }
        let config = """
            {
              "mcpServers": {
                "filesystem": {
                  "command": "\(BoundaryEnforcer.proxyPath)",
                  "args": ["--", "/usr/bin/node", "/opt/mcp-server-filesystem.js"]
                }
              }
            }
            """
        try writeMCPConfig(config, to: directory)
        try MCPBoundaryValidator(
            allowedServerCommands: [
                ["/usr/bin/node", "/opt/mcp-server-filesystem.js"]
            ]
        ).validateProject(at: directory.path)
    }

    @Test func testMCPConfigValidatorRejectsRemoteServer() throws {
        let directory = try makeTemporaryProject()
        defer { try? FileManager.default.removeItem(at: directory) }
        let config = """
            {
              "servers": {
                "remote": {
                  "type": "http",
                  "url": "https://example.com/mcp"
                }
              }
            }
            """
        try writeMCPConfig(config, to: directory)

        #expect(throws: MCPBoundaryValidator.ValidationError.self) {
            try MCPBoundaryValidator().validateProject(at: directory.path)
        }
    }

    @Test func testMCPConfigValidatorRejectsUnproxiedStdioServer() throws {
        let directory = try makeTemporaryProject()
        defer { try? FileManager.default.removeItem(at: directory) }
        let config = """
            {
              "mcpServers": {
                "filesystem": {
                  "command": "npx",
                  "args": ["mcp-server-filesystem"]
                }
              }
            }
            """
        try writeMCPConfig(config, to: directory)

        #expect(throws: MCPBoundaryValidator.ValidationError.self) {
            try MCPBoundaryValidator().validateProject(at: directory.path)
        }
    }

    private func makeTemporaryProject() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("sendbox-boundary-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return directory
    }

    private func writeMCPConfig(_ config: String, to directory: URL) throws {
        let url = directory.appendingPathComponent(".mcp.json")
        try Data(config.utf8).write(to: url)
    }

    @Test func testBoundarySanitizesRootBootstrapEnvironment() {
        let bootstrap = BoundaryEnforcer.bootstrapEnvironment(
            agentEnvironment: [
                "BASH_ENV": "/workspace/payload.sh",
                "LD_PRELOAD": "/workspace/payload.so",
                "SAFE_VALUE": "kept",
            ],
            workingDirectory: "/workspaces/project"
        )

        #expect(bootstrap["BASH_ENV"] == nil)
        #expect(bootstrap["LD_PRELOAD"] == nil)
        #expect(bootstrap["SAFE_VALUE"] == nil)
        #expect(bootstrap["PATH"] == "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

        guard let encoded = bootstrap["SENDBOX_AGENT_ENV_B64"],
            let data = Data(base64Encoded: encoded)
        else {
            Issue.record("Expected a serialized agent environment")
            return
        }
        let restored = try? JSONSerialization.jsonObject(with: data) as? [String: String]
        #expect(restored?["BASH_ENV"] == "/workspace/payload.sh")
        #expect(restored?["SAFE_VALUE"] == "kept")
    }
}
