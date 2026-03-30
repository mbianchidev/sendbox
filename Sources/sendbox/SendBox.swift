import ArgumentParser
import Foundation
import SendBoxKit

@main
struct SendBox: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sendbox",
        abstract: "Secure sandbox for AI agents using Apple Virtualization",
        version: "0.1.0",
        subcommands: [Run.self, Init.self, Analyze.self, Secrets.self, Policy.self]
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
                print("Enter value for '\(key)': ", terminator: "")
                fflush(stdout)

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
