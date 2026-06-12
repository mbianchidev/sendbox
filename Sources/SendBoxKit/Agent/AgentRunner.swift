import Foundation
import Logging

/// Orchestrates the full agent sandbox lifecycle:
/// analyze project → generate devcontainer → build container → apply policies → inject secrets → run agent
public actor AgentRunner {
    private let config: SandboxConfiguration
    private let runtime: ContainerRuntime
    private let commandPolicy: CommandPolicy
    private let firewall: NetworkFirewall
    private let secrets: SecretsVault
    private let devcontainerBuilder: DevContainerBuilder
    private let mcpInspector: MCPInspector?
    private let logger: Logger

    public enum RunnerState: String, Sendable {
        case idle
        case analyzing
        case generatingDevContainer
        case buildingContainer
        case applyingPolicies
        case injectingSecrets
        case running
        case stopping
        case failed
        case completed
    }

    public struct RunResult: Sendable {
        public let exitCode: Int32
        public let state: RunnerState
        public let duration: TimeInterval
        public let commandsBlocked: Int
        public let commandsAllowed: Int
    }

    public enum RunnerError: Error, LocalizedError {
        case invalidProjectPath(String)
        case alreadyRunning
        case notRunning
        case runtimeInitializationFailed(String)
        case containerCreationFailed(String)
        case workspacePreparationFailed(String)
        case processExitedWithError(String, Int32)

        public var errorDescription: String? {
            switch self {
            case .invalidProjectPath(let path):
                return "Invalid project path: \(path)"
            case .alreadyRunning:
                return "Agent is already running"
            case .notRunning:
                return "Agent is not running"
            case .runtimeInitializationFailed(let msg):
                return "Runtime initialization failed: \(msg)"
            case .containerCreationFailed(let msg):
                return "Container creation failed: \(msg)"
            case .workspacePreparationFailed(let msg):
                return "Workspace preparation failed: \(msg)"
            case .processExitedWithError(let cmd, let code):
                return "Process '\(cmd)' exited with code \(code)"
            }
        }
    }

    public private(set) var state: RunnerState = .idle
    public private(set) var containerId: String?

    public init(
        config: SandboxConfiguration,
        logger: Logger = Logger(label: "sendbox.runner")
    ) {
        self.config = config
        self.runtime = ContainerRuntime(logger: logger)
        self.commandPolicy = CommandPolicy(config: config.policy.commands, logger: logger)
        self.firewall = NetworkFirewall(config: config.policy.network, logger: logger)
        self.secrets = SecretsVault(logger: logger)
        self.devcontainerBuilder = DevContainerBuilder(logger: logger)
        if let mcpConfig = config.observability?.mcpInspection, mcpConfig.enabled {
            self.mcpInspector = MCPInspector(config: mcpConfig, logger: logger)
        } else {
            self.mcpInspector = nil
        }
        self.logger = logger
    }

    // MARK: - Public API

    /// Run the full sandbox lifecycle.
    public func run() async throws -> RunResult {
        guard state == .idle || state == .completed || state == .failed else {
            throw RunnerError.alreadyRunning
        }

        let startTime = Date()

        // Set up signal handling for graceful shutdown.
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())

        sigintSource.setEventHandler { [weak self] in
            guard let runner = self else { return }
            Task { try? await runner.stop() }
        }
        sigtermSource.setEventHandler { [weak self] in
            guard let runner = self else { return }
            Task { try? await runner.stop() }
        }
        sigintSource.resume()
        sigtermSource.resume()

        defer {
            sigintSource.cancel()
            sigtermSource.cancel()
            signal(SIGINT, SIG_DFL)
            signal(SIGTERM, SIG_DFL)
        }

        do {
            // Step 1: Analyze project
            state = .analyzing
            logger.info("Step 1/6: Analyzing project...")
            try analyzeProject()

            // Step 2: Generate devcontainer specification
            state = .generatingDevContainer
            logger.info("Step 2/6: Generating devcontainer specification...")
            let spec = try await generateDevContainer()

            // Step 3: Build and start container
            state = .buildingContainer
            logger.info("Step 3/6: Building container...")
            try await runtime.initialize()
            let id = try await buildContainer(spec: spec)
            containerId = id

            // Step 4: Security policies (applied during container creation via firewallScript)
            state = .applyingPolicies
            logger.info("Step 4/6: Security policies applied via container configuration")

            // Step 5: Secrets (injected as environment variables during container creation)
            state = .injectingSecrets
            logger.info("Step 5/6: Secrets injected via container environment")
            if config.secrets.isEmpty {
                logger.info("No secrets configured")
            } else {
                logger.info("\(config.secrets.count) secret(s) injected")
            }

            // Step 6: Monitor the running agent
            state = .running
            logger.info("Step 6/6: Agent running...")
            let exitCode = try await monitorAgent(containerId: id)

            state = .completed
            logger.info("Agent completed", metadata: ["exitCode": "\(exitCode)"])

            try? await cleanup()

            let duration = Date().timeIntervalSince(startTime)
            return RunResult(
                exitCode: exitCode,
                state: .completed,
                duration: duration,
                commandsBlocked: 0,
                commandsAllowed: 0
            )
        } catch {
            state = .failed
            logger.error("Agent failed: \(error.localizedDescription)")
            try? await cleanup()
            throw error
        }
    }

    /// Stop the running agent gracefully.
    public func stop() async throws {
        guard state == .running, let id = containerId else {
            logger.info("Nothing to stop (state: \(state.rawValue))")
            return
        }

        state = .stopping
        logger.info("Stopping agent...")
        try await runtime.stopContainer(id: id)
        state = .completed
    }

    /// Get the current runner state.
    public func getState() -> RunnerState {
        state
    }

    // MARK: - Private Lifecycle Steps

    private func analyzeProject() throws {
        let fm = FileManager.default
        var isDir: ObjCBool = false

        guard fm.fileExists(atPath: config.projectPath, isDirectory: &isDir),
              isDir.boolValue else {
            throw RunnerError.invalidProjectPath(config.projectPath)
        }

        logger.info("Project path validated", metadata: ["path": "\(config.projectPath)"])
    }

    private func generateDevContainer() async throws -> DevContainerBuilder.DevContainerSpec {
        // Use existing devcontainer.json if configured and present.
        if let devcontainerConfig = config.devcontainer,
           let configPath = devcontainerConfig.configPath,
           FileManager.default.fileExists(atPath: configPath) {
            logger.info("Loading existing devcontainer config", metadata: ["path": "\(configPath)"])
            let spec = try devcontainerBuilder.load(from: configPath)
            return devcontainerBuilder.merge(spec, overrides: config.devcontainer)
        }

        // Generate via copilot bridge (falls back to a sensible default).
        let spec = try await devcontainerBuilder.generate(
            for: config.projectPath,
            config: config
        )

        logger.info("Generated devcontainer spec", metadata: ["image": "\(spec.image)"])
        return spec
    }

    private func buildContainer(
        spec: DevContainerBuilder.DevContainerSpec
    ) async throws -> String {
        try prepareWorkspace()
        let authEnv = try setupAuthForwarding()
        let secretsEnv = try loadSecrets()

        var containerConfig = ContainerConfig.from(
            sandbox: config,
            imageReference: spec.image,
            firewall: firewall,
            mcpInspector: mcpInspector
        )

        if mcpInspector != nil {
            logger.info("eBPF MCP inspection enabled")
        }

        // Merge authentication environment.
        for (key, value) in authEnv {
            containerConfig.environment[key] = value
        }

        // Merge secrets as environment variables.
        for (key, value) in secretsEnv {
            containerConfig.environment[key] = value
        }

        // Merge devcontainer environment.
        if let containerEnv = spec.containerEnv {
            for (key, value) in containerEnv {
                containerConfig.environment[key] = value
            }
        }

        do {
            let id = try await runtime.createContainer(containerConfig)
            logger.info("Container created and started", metadata: ["id": "\(id)"])
            return id
        } catch {
            throw RunnerError.containerCreationFailed(error.localizedDescription)
        }
    }

    private func monitorAgent(containerId: String) async throws -> Int32 {
        logger.info("Monitoring container \(containerId)")

        let outputStream = try await runtime.attachOutput(containerId: containerId)

        for await line in outputStream {
            logger.info("\(line)")
        }

        let status = await runtime.containerStatus(id: containerId)
        return status == .stopped ? 0 : 1
    }

    private func cleanup() async throws {
        logger.info("Cleaning up...")

        do {
            try await runtime.cleanup()
            logger.info("All containers cleaned up")
        } catch {
            logger.warning("Cleanup error: \(error.localizedDescription)")
        }

        containerId = nil
    }

    /// Ensure the workspace directory structure is ready for the container.
    @discardableResult
    private func prepareWorkspace() throws -> String {
        let fm = FileManager.default
        let projectURL = URL(fileURLWithPath: config.projectPath)

        // Ensure .devcontainer directory exists for mount source.
        let devcontainerDir = projectURL.appendingPathComponent(".devcontainer")
        if !fm.fileExists(atPath: devcontainerDir.path) {
            try fm.createDirectory(at: devcontainerDir, withIntermediateDirectories: true)
        }

        logger.info("Workspace prepared", metadata: ["path": "\(config.projectPath)"])
        return config.projectPath
    }

    /// Read configured secrets from the vault and return as key-value pairs.
    private func loadSecrets() throws -> [String: String] {
        var env: [String: String] = [:]
        for key in config.secrets {
            env[key] = try secrets.retrieve(key: key)
        }
        return env
    }

    /// Read GitHub / Copilot tokens and return as environment variables.
    private func setupAuthForwarding() throws -> [String: String] {
        var env: [String: String] = [:]

        if config.github.forwardAuth {
            if let token = try? executeProcess("gh", arguments: ["auth", "token"]) {
                env["GITHUB_TOKEN"] = token
                logger.info("GitHub auth forwarded")
            } else {
                logger.warning(
                    "Could not retrieve GitHub auth token (is `gh` installed and authenticated?)"
                )
            }
        }

        if config.github.forwardCopilotAuth {
            if let copilotToken = ProcessInfo.processInfo.environment["GITHUB_COPILOT_TOKEN"] {
                env["GITHUB_COPILOT_TOKEN"] = copilotToken
                logger.info("Copilot auth forwarded")
            }
        }

        return env
    }

    // MARK: - Helpers

    /// Run an external process synchronously and capture its stdout.
    private nonisolated func executeProcess(
        _ executable: String,
        arguments: [String]
    ) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [executable] + arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        try process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            throw RunnerError.processExitedWithError(
                executable, process.terminationStatus
            )
        }

        return String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }
}
