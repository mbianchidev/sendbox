import ArgumentParser
import Foundation
import SendBoxKit

#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

enum RuntimeOption: String, ExpressibleByArgument, CaseIterable {
    case automatic = "auto"
    case apple
    case kata
    case hyperlight

    var provider: RuntimeConfiguration.Provider {
        switch self {
        case .automatic: return .automatic
        case .apple: return .apple
        case .kata: return .kata
        case .hyperlight: return .hyperlight
        }
    }
}

@main
struct SendBox: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sendbox",
        abstract: "Secure hardware-isolated sandbox for AI agents",
        version: "0.1.0",
        subcommands: [
            Run.self, Init.self, Analyze.self, Secrets.self, Policy.self,
            Mcp.self, Boundary.self, Completions.self,
        ]
    )
}

// MARK: - Run

extension SendBox {
    struct Run: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Run an agent in a sandboxed container"
        )

        @Option(name: .long, help: "Path to sendbox config file")
        var config: String?

        @Option(name: .long, help: "Path to the project directory")
        var project: String?

        @Option(name: .long, help: "Security policy preset (default, permissive, strict)")
        var policy: PolicyPreset?

        @Option(name: .long, help: "Runtime provider (auto, apple, kata, hyperlight)")
        var runtime: RuntimeOption?

        enum PolicyPreset: String, ExpressibleByArgument, CaseIterable {
            case `default`
            case permissive
            case strict

            var policyConfiguration: PolicyConfiguration {
                switch self {
                case .default: return .default
                case .permissive: return .permissive
                case .strict: return .strict
                }
            }
        }

        func run() async throws {
            printStatus("🚀 SendBox – starting sandbox...")

            var sandboxConfig = try loadConfiguration(
                configPath: config,
                projectPath: project
            )

            if let projectPath = project {
                sandboxConfig.projectPath = projectPath
            }

            if let preset = policy {
                sandboxConfig.policy = preset.policyConfiguration
                printStatus("Using \(preset.rawValue) policy preset")
            }

            if let runtime {
                var runtimeConfiguration = sandboxConfig.runtime ?? .default
                runtimeConfiguration.provider = runtime.provider
                sandboxConfig.runtime = runtimeConfiguration
                printStatus("Using \(runtime.rawValue) runtime provider")
            }

            let runner = AgentRunner(config: sandboxConfig)

            do {
                let result = try await runner.run()

                printStatus("✅ Agent finished")
                printStatus("   Exit code: \(result.exitCode)")
                printStatus("   Duration:  \(formatDuration(result.duration))")
                printStatus("   Commands allowed: \(result.commandsAllowed)")
                printStatus("   Commands blocked: \(result.commandsBlocked)")

                if result.exitCode != 0 {
                    throw ExitCode(result.exitCode)
                }
            } catch let error as AgentRunner.RunnerError {
                printError("Agent error: \(error.localizedDescription)")
                throw ExitCode.failure
            }
        }
    }
}

// MARK: - Init

extension SendBox {
    struct Init: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "init",
            abstract: "Initialize a sendbox configuration for a project"
        )

        @Option(name: .long, help: "Path to the project directory")
        var project: String?

        @Option(name: .long, help: "Security policy preset (default, permissive, strict)")
        var policy: Run.PolicyPreset?

        @Option(name: .long, help: "Runtime provider (auto, apple, kata, hyperlight)")
        var runtime: RuntimeOption?

        func run() throws {
            let projectPath = project ?? FileManager.default.currentDirectoryPath
            let configFilePath = (projectPath as NSString)
                .appendingPathComponent(".sendbox.yaml")

            guard !FileManager.default.fileExists(atPath: configFilePath) else {
                printError("Configuration already exists at \(configFilePath)")
                printStatus("Use 'sendbox run --config \(configFilePath)' to run with this config")
                throw ExitCode.failure
            }

            printStatus("🔧 Initializing sendbox for \(projectPath)...")

            var config = SandboxConfiguration.default(projectPath: projectPath)

            if let preset = policy {
                config.policy = preset.policyConfiguration
            }

            if let runtime {
                var runtimeConfiguration = config.runtime ?? .default
                runtimeConfiguration.provider = runtime.provider
                config.runtime = runtimeConfiguration
            }

            try config.save(to: configFilePath)
            printStatus("✅ Created \(configFilePath)")
            printStatus("   Edit this file to customize your sandbox configuration.")
            printStatus("   Run 'sendbox run' to start the sandbox.")
        }
    }
}

// MARK: - Analyze

extension SendBox {
    struct Analyze: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Analyze a project and suggest sandbox configuration"
        )

        @Option(name: .long, help: "Path to the project directory")
        var project: String?

        @Option(name: .long, help: "Output directory for generated devcontainer.json")
        var output: String?

        func run() async throws {
            let projectPath = project ?? FileManager.default.currentDirectoryPath

            printStatus("🔍 Analyzing project at \(projectPath)...")

            let builder = DevContainerBuilder()
            let config = SandboxConfiguration.default(projectPath: projectPath)
            let spec = try await builder.generate(for: projectPath, config: config)

            printStatus("")
            printStatus("Image:       \(spec.image)")
            printStatus("Remote User: \(spec.remoteUser ?? "vscode")")

            if let features = spec.features, !features.isEmpty {
                printStatus("Features:")
                for (feature, _) in features {
                    printStatus("  • \(feature)")
                }
            }

            if let extensions = spec.customizations?.vscode?.extensions,
               !extensions.isEmpty {
                printStatus("Extensions:")
                for ext in extensions {
                    printStatus("  • \(ext)")
                }
            }

            if let cmd = spec.postCreateCommand {
                printStatus("Post-create: \(cmd)")
            }

            if let outputPath = output {
                let savedPath = try builder.save(spec, to: outputPath)
                printStatus("\n✅ Generated devcontainer.json at \(savedPath)")
            }
        }
    }
}

// MARK: - Secrets

extension SendBox {
    struct Secrets: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Manage secrets for sandbox injection",
            subcommands: [Add.self, Remove.self, List.self]
        )

        struct Add: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Add a secret to the vault"
            )

            @Argument(help: "Secret key name")
            var key: String

            func run() throws {
                FileHandle.standardOutput.write(Data("Enter value for '\(key)': ".utf8))

                // Disable terminal echo for secure input.
                var oldTermios = termios()
                tcgetattr(STDIN_FILENO, &oldTermios)
                var newTermios = oldTermios
                newTermios.c_lflag &= ~tcflag_t(ECHO)
                tcsetattr(STDIN_FILENO, TCSANOW, &newTermios)

                defer {
                    tcsetattr(STDIN_FILENO, TCSANOW, &oldTermios)
                    print("")
                }

                guard let value = readLine(), !value.isEmpty else {
                    printError("No value provided")
                    throw ExitCode.failure
                }

                let vault = SecretsVault()
                try vault.store(key: key, value: value)
                printStatus("✅ Secret '\(key)' stored")
            }
        }

        struct Remove: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Remove a secret from the vault"
            )

            @Argument(help: "Secret key name")
            var key: String

            func run() throws {
                let vault = SecretsVault()
                try vault.delete(key: key)
                printStatus("✅ Secret '\(key)' removed")
            }
        }

        struct List: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "list",
                abstract: "List all secret keys in the vault"
            )

            func run() throws {
                let vault = SecretsVault()
                let secrets = try vault.list()

                if secrets.isEmpty {
                    printStatus("No secrets stored")
                    return
                }

                let formatter = DateFormatter()
                formatter.dateStyle = .medium
                formatter.timeStyle = .short

                printStatus("Secrets (\(secrets.count)):")
                for secret in secrets {
                    let updated = formatter.string(from: secret.updatedAt)
                    printStatus("  • \(secret.key)  (updated: \(updated))")
                }
            }
        }
    }
}

// MARK: - Policy

extension SendBox {
    struct Policy: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "View and validate security policies",
            subcommands: [Show.self, Validate.self]
        )

        struct Show: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Display the effective security policy"
            )

            @Option(name: .long, help: "Path to sendbox config file")
            var config: String?

            func run() throws {
                let policy: PolicyConfiguration

                if let configPath = config {
                    let sandboxConfig = try SandboxConfiguration.load(from: configPath)
                    policy = sandboxConfig.policy
                    printStatus("Policy from: \(configPath)")
                } else {
                    policy = .default
                    printStatus("Default policy")
                }

                printStatus("")
                printStatus("Command Policy:")
                printStatus("  Default action: \(policy.commands.defaultAction.rawValue)")
                printStatus("  Log blocked:    \(policy.commands.logBlocked)")
                if !policy.commands.allowlist.isEmpty {
                    printStatus("  Allowlist:")
                    for cmd in policy.commands.allowlist {
                        printStatus("    ✓ \(cmd)")
                    }
                }
                if !policy.commands.denylist.isEmpty {
                    printStatus("  Denylist:")
                    for cmd in policy.commands.denylist {
                        printStatus("    ✗ \(cmd)")
                    }
                }

                printStatus("")
                printStatus("Network Policy:")
                printStatus("  Default action: \(policy.network.defaultAction.rawValue)")
                printStatus("  Allow DNS:      \(policy.network.allowDNS)")
                if let max = policy.network.maxConnections {
                    printStatus("  Max connections: \(max)")
                }
                if !policy.network.allowedDomains.isEmpty {
                    printStatus("  Allowed domains:")
                    for domain in policy.network.allowedDomains {
                        printStatus("    ✓ \(domain)")
                    }
                }
                if !policy.network.blockedDomains.isEmpty {
                    printStatus("  Blocked domains:")
                    for domain in policy.network.blockedDomains {
                        printStatus("    ✗ \(domain)")
                    }
                }

                printStatus("")
                printStatus("Boundary Policy:")
                printStatus("  Enabled:        \(policy.boundaries.enabled)")
                printStatus(
                    "  MCP transport:  \(policy.boundaries.toolCalls.transport.rawValue)"
                )
                printStatus(
                    "  Tool default:    \(policy.boundaries.toolCalls.defaultAction.rawValue)"
                )
                printStatus(
                    "  Max frame bytes: \(policy.boundaries.toolCalls.maxFrameBytes)"
                )
                printStatus("  Log path:       \(policy.boundaries.logPath)")
                if !policy.boundaries.toolCalls.allowlist.isEmpty {
                    printStatus("  Tool allowlist:")
                    for tool in policy.boundaries.toolCalls.allowlist {
                        printStatus("    ✓ \(tool)")
                    }
                }
                if !policy.boundaries.toolCalls.denylist.isEmpty {
                    printStatus("  Tool denylist:")
                    for tool in policy.boundaries.toolCalls.denylist {
                        printStatus("    ✗ \(tool)")
                    }
                }
                if !policy.boundaries.syscalls.additionalDenylist.isEmpty {
                    printStatus("  Additional denied syscalls:")
                    for syscall in policy.boundaries.syscalls.additionalDenylist {
                        printStatus("    ✗ \(syscall)")
                    }
                }
                if !policy.boundaries.toolCalls.allowedServerCommands.isEmpty {
                    printStatus("  Allowed MCP server commands:")
                    for command in policy.boundaries.toolCalls.allowedServerCommands {
                        printStatus("    ✓ \(command.joined(separator: " "))")
                    }
                }
            }
        }

        struct Validate: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Validate a configuration file's policy section"
            )

            @Option(name: .long, help: "Path to sendbox config file")
            var config: String?

            func run() throws {
                let configPath = config ?? defaultConfigPath()

                guard FileManager.default.fileExists(atPath: configPath) else {
                    printError("Config file not found: \(configPath)")
                    throw ExitCode.failure
                }

                printStatus("Validating \(configPath)...")

                do {
                    let sandboxConfig = try SandboxConfiguration.load(from: configPath)
                    let policy = sandboxConfig.policy
                    var warnings: [String] = []

                    if policy.commands.defaultAction == .allow
                        && policy.commands.denylist.isEmpty {
                        warnings.append(
                            "Command policy is fully permissive — consider adding a denylist"
                        )
                    }

                    if policy.network.defaultAction == .allow
                        && policy.network.blockedDomains.isEmpty {
                        warnings.append(
                            "Network policy allows all domains — consider restricting access"
                        )
                    }

                    if !policy.network.allowDNS
                        && policy.network.defaultAction == .allow {
                        warnings.append(
                            "DNS is disabled but network default is allow — outbound connections may fail"
                        )
                    }

                    if policy.commands.allowlist.isEmpty
                        && policy.commands.defaultAction == .deny {
                        warnings.append(
                            "Command allowlist is empty with default deny — no commands will be allowed"
                        )
                    }

                    if policy.boundaries.enabled {
                        let enforcer = BoundaryEnforcer(
                            config: policy.boundaries,
                            serverCommandPatterns: policy.boundaries.toolCalls
                                .serverCommandPatterns,
                            runAsUID: getuid(),
                            runAsGID: getgid()
                        )
                        try enforcer.validate()
                    } else {
                        warnings.append(
                            "Boundary enforcement is disabled — agent syscalls and MCP tools "
                                + "will not be fail-closed"
                        )
                    }

                    printStatus("✅ Configuration is valid")

                    if !warnings.isEmpty {
                        printStatus("")
                        printStatus("⚠️  Warnings:")
                        for warning in warnings {
                            printStatus("  • \(warning)")
                        }
                    }
                } catch {
                    printError("❌ Invalid configuration: \(error.localizedDescription)")
                    throw ExitCode.failure
                }
            }
        }
    }
}

// MARK: - MCP Inspection

extension SendBox {
    struct Mcp: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Inspect Model Context Protocol (MCP) calls via eBPF",
            subcommands: [Script.self, Parse.self, Report.self]
        )

        /// Build an inspection config from CLI flags, optionally seeded from a config file.
        static func makeConfig(
            configPath: String?,
            noStdio: Bool,
            noHttp: Bool,
            redact: Bool
        ) throws -> ObservabilityConfig.MCPInspectionConfig {
            var base = ObservabilityConfig.MCPInspectionConfig.default
            if let configPath {
                let sandbox = try SandboxConfiguration.load(from: configPath)
                if let mcp = sandbox.observability?.mcpInspection {
                    base = mcp
                }
            }
            var transports: [ObservabilityConfig.MCPInspectionConfig.Transport] = []
            if !noStdio { transports.append(.stdio) }
            if !noHttp { transports.append(.http) }
            if transports.isEmpty { transports = [.stdio] }
            return ObservabilityConfig.MCPInspectionConfig(
                enabled: true,
                transports: transports,
                capturePayloads: redact ? false : base.capturePayloads,
                maxPayloadBytes: base.maxPayloadBytes,
                logPath: base.logPath,
                serverCommandPatterns: base.serverCommandPatterns
            )
        }

        // MARK: script

        struct Script: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Print the bpftrace program (or guest startup script) for MCP inspection"
            )

            @Option(name: .long, help: "Path to sendbox config file")
            var config: String?

            @Flag(name: .long, help: "Print the guest startup bash script instead of the raw bpftrace program")
            var startup = false

            @Flag(name: .long, help: "Disable stdio (pipe) transport tracing")
            var noStdio = false

            @Flag(name: .long, help: "Disable HTTP/SSE (TLS) transport tracing")
            var noHttp = false

            func run() throws {
                let mcpConfig = try Mcp.makeConfig(
                    configPath: config, noStdio: noStdio, noHttp: noHttp, redact: false
                )
                let inspector = MCPInspector(config: mcpConfig)
                print(startup
                    ? inspector.generateStartupScript()
                    : inspector.generateBpftraceProgram())
            }
        }

        // MARK: parse

        struct Parse: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Parse a captured MCP trace log into structured calls"
            )

            @Argument(help: "Path to the trace log file written by the inspector")
            var logfile: String

            @Flag(name: .long, help: "Emit parsed calls as JSON")
            var json = false

            @Flag(name: .long, help: "Redact payloads, keeping only method/id/tool metadata")
            var redact = false

            func run() throws {
                guard FileManager.default.fileExists(atPath: logfile) else {
                    printError("Trace log not found: \(logfile)")
                    throw ExitCode.failure
                }
                let contents = try String(contentsOfFile: logfile, encoding: .utf8)
                let inspector = MCPInspector(config: try Mcp.makeConfig(
                    configPath: nil, noStdio: false, noHttp: false, redact: redact
                ))
                let calls = inspector.parseEvents(from: contents)

                if json {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                    let data = try encoder.encode(calls)
                    print(String(data: data, encoding: .utf8) ?? "[]")
                    return
                }

                if calls.isEmpty {
                    printStatus("No MCP calls found in \(logfile)")
                    return
                }
                for call in calls {
                    let method = call.method ?? (call.kind == .spawn ? "<spawn>" : "<response>")
                    let subject = call.subject.map { " (\($0))" } ?? ""
                    let id = call.id.map { " id=\($0)" } ?? ""
                    printStatus("[\(call.transport.rawValue)] \(call.kind.rawValue) "
                        + "\(call.category.rawValue)/\(method)\(subject)\(id)")
                }
            }
        }

        // MARK: report

        struct Report: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Summarise MCP activity from a captured trace log"
            )

            @Argument(help: "Path to the trace log file written by the inspector")
            var logfile: String

            func run() throws {
                guard FileManager.default.fileExists(atPath: logfile) else {
                    printError("Trace log not found: \(logfile)")
                    throw ExitCode.failure
                }
                let contents = try String(contentsOfFile: logfile, encoding: .utf8)
                let inspector = MCPInspector()
                let calls = inspector.parseEvents(from: contents)
                let summary = inspector.summarize(calls)

                printStatus("MCP Inspection Report — \(logfile)")
                printStatus("")
                printStatus("Total calls:    \(summary.totalCalls)")
                printStatus("Tool calls:     \(summary.toolCallCount)")
                printStatus("Errors:         \(summary.errorCount)")

                if !summary.servers.isEmpty {
                    printStatus("")
                    printStatus("MCP servers:")
                    for server in summary.servers {
                        printStatus("  • \(server)")
                    }
                }

                if !summary.byCategory.isEmpty {
                    printStatus("")
                    printStatus("By category:")
                    for (category, count) in summary.byCategory.sorted(by: { $0.value > $1.value }) {
                        printStatus("  \(category.rawValue.padded(to: 14)) \(count)")
                    }
                }

                if !summary.byTransport.isEmpty {
                    printStatus("")
                    printStatus("By transport:")
                    for (transport, count) in summary.byTransport.sorted(by: { $0.value > $1.value }) {
                        printStatus("  \(transport.rawValue.padded(to: 14)) \(count)")
                    }
                }

                if !summary.toolInvocations.isEmpty {
                    printStatus("")
                    printStatus("Tool invocations:")
                    for (tool, count) in summary.toolInvocations.sorted(by: { $0.value > $1.value }) {
                        printStatus("  \(tool.padded(to: 24)) \(count)")
                    }
                }

                if !summary.distinctMethods.isEmpty {
                    printStatus("")
                    printStatus("Distinct methods: \(summary.distinctMethods.joined(separator: ", "))")
                }
            }
        }
    }
}

// MARK: - Boundary Enforcement

extension SendBox {
    struct Boundary: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Inspect fail-closed syscall and MCP boundary artifacts",
            subcommands: [Script.self]
        )

        struct Script: ParsableCommand {
            enum Component: String, ExpressibleByArgument, CaseIterable {
                case bootstrap
                case bpftrace
                case proxy
                case proxyClient = "proxy-client"
                case seccomp
            }

            static let configuration = CommandConfiguration(
                abstract: "Print a generated boundary component"
            )

            @Option(name: .long, help: "Path to sendbox config file")
            var config: String?

            @Option(
                name: .long,
                help: "Component: bootstrap, bpftrace, proxy, proxy-client, or seccomp"
            )
            var component: Component = .bootstrap

            func run() throws {
                let sandbox = try loadConfiguration(configPath: config, projectPath: nil)
                guard sandbox.policy.boundaries.enabled else {
                    printError("Boundary enforcement is disabled in this configuration")
                    throw ExitCode.failure
                }

                let enforcer = BoundaryEnforcer(
                    config: sandbox.policy.boundaries,
                    serverCommandPatterns: sandbox.policy.boundaries.toolCalls
                        .serverCommandPatterns,
                    runAsUID: getuid(),
                    runAsGID: getgid()
                )
                try enforcer.validate()

                switch component {
                case .bootstrap:
                    let firewall = NetworkFirewall(config: sandbox.policy.network)
                    let inspector: MCPInspector?
                    if let mcpConfig = sandbox.observability?.mcpInspection,
                        mcpConfig.enabled
                    {
                        inspector = MCPInspector(config: mcpConfig)
                    } else {
                        inspector = nil
                    }
                    var scripts = [firewall.generateStartupScript()]
                    if let inspector {
                        scripts.append(inspector.generateStartupScript())
                    }
                    print(
                        enforcer.generateBootstrapScript(
                            command: ["/bin/bash"],
                            preflightScripts: scripts
                        ))
                case .bpftrace:
                    print(enforcer.generateBpftraceProgram())
                case .proxy:
                    print(enforcer.generateProxyScript())
                case .proxyClient:
                    print(enforcer.generateProxyClientScript())
                case .seccomp:
                    print(enforcer.generateSeccompLauncherSource())
                }
            }
        }
    }
}

private extension String {
    func padded(to width: Int) -> String {
        count >= width ? self : self + String(repeating: " ", count: width - count)
    }
}

// MARK: - Helpers

private func printStatus(_ message: String) {
    print(message)
}

private func printError(_ message: String) {
    FileHandle.standardError.write(Data("\u{001B}[31merror: \(message)\u{001B}[0m\n".utf8))
}

private func defaultConfigPath() -> String {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return (home as NSString).appendingPathComponent(".sendbox/config.yaml")
}

private func formatDuration(_ duration: TimeInterval) -> String {
    if duration < 60 {
        return String(format: "%.1fs", duration)
    }
    let minutes = Int(duration) / 60
    let seconds = Int(duration) % 60
    return "\(minutes)m \(seconds)s"
}

private func loadConfiguration(
    configPath: String?,
    projectPath: String?
) throws -> SandboxConfiguration {
    if let path = configPath {
        return try SandboxConfiguration.load(from: path)
    }

    let defaultPath = defaultConfigPath()
    if FileManager.default.fileExists(atPath: defaultPath) {
        return try SandboxConfiguration.load(from: defaultPath)
    }

    // Check for project-local config.
    let projectDir = projectPath ?? FileManager.default.currentDirectoryPath
    let localConfig = (projectDir as NSString).appendingPathComponent(".sendbox.yaml")
    if FileManager.default.fileExists(atPath: localConfig) {
        return try SandboxConfiguration.load(from: localConfig)
    }

    return SandboxConfiguration.default(projectPath: projectDir)
}

// MARK: - Completions

extension SendBox {
    struct Completions: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Install shell completions for sendbox",
            subcommands: [Install.self, Print.self],
            defaultSubcommand: Install.self
        )

        struct Install: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Install completions for your current shell"
            )

            @Option(name: .long, help: "Shell to install for (bash, zsh, fish). Auto-detected if omitted.")
            var shell: String?

            func run() throws {
                let detected = shell ?? detectShell()
                switch detected {
                case "bash":
                    try installBash()
                case "zsh":
                    try installZsh()
                case "fish":
                    try installFish()
                default:
                    printError("Unknown shell: \(detected). Use --shell bash|zsh|fish")
                    throw ExitCode.failure
                }
            }

            private func detectShell() -> String {
                let shellPath = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
                if shellPath.hasSuffix("zsh") { return "zsh" }
                if shellPath.hasSuffix("bash") { return "bash" }
                if shellPath.hasSuffix("fish") { return "fish" }
                return "zsh"
            }

            private func generateScript(_ shell: String) throws -> String {
                let process = Process()
                let pipe = Pipe()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
                process.arguments = [CommandLine.arguments[0], "--generate-completion-script", shell]
                process.standardOutput = pipe
                process.standardError = FileHandle.nullDevice
                try process.run()
                process.waitUntilExit()
                guard let data = try pipe.fileHandleForReading.readToEnd(),
                      let script = String(data: data, encoding: .utf8) else {
                    throw ExitCode.failure
                }
                return script
            }

            private func installBash() throws {
                let script = try generateScript("bash")
                let dir = NSHomeDirectory() + "/.local/share/bash-completion/completions"
                try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
                let path = dir + "/sendbox"
                try script.write(toFile: path, atomically: true, encoding: .utf8)
                print("✅ Bash completions installed to \(path)")
                print("")
                print("To activate now:")
                print("  source \(path)")
                print("")
                print("It will load automatically in new terminals if bash-completion is set up.")
                print("If not, add this to your ~/.bashrc:")
                print("  source \(path)")
            }

            private func installZsh() throws {
                let script = try generateScript("zsh")
                let dir = NSHomeDirectory() + "/.zsh/completions"
                try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
                let path = dir + "/_sendbox"
                try script.write(toFile: path, atomically: true, encoding: .utf8)
                print("✅ Zsh completions installed to \(path)")
                print("")
                print("To activate, add this to your ~/.zshrc (if not already present):")
                print("  fpath=(~/.zsh/completions $fpath)")
                print("  autoload -Uz compinit && compinit")
                print("")
                print("Then reload:")
                print("  exec zsh")
            }

            private func installFish() throws {
                let script = try generateScript("fish")
                let dir = NSHomeDirectory() + "/.config/fish/completions"
                try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
                let path = dir + "/sendbox.fish"
                try script.write(toFile: path, atomically: true, encoding: .utf8)
                print("✅ Fish completions installed to \(path)")
                print("They will load automatically in new fish sessions.")
            }
        }

        struct Print: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Print completions to stdout (for manual setup)"
            )

            @Option(name: .long, help: "Shell (bash, zsh, fish)")
            var shell: String = "bash"

            func run() throws {
                let process = Process()
                let pipe = Pipe()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
                process.arguments = [CommandLine.arguments[0], "--generate-completion-script", shell]
                process.standardOutput = pipe
                process.standardError = FileHandle.nullDevice
                try process.run()
                process.waitUntilExit()
                if let data = try pipe.fileHandleForReading.readToEnd(),
                   let script = String(data: data, encoding: .utf8) {
                    Swift.print(script, terminator: "")
                }
            }
        }
    }
}
