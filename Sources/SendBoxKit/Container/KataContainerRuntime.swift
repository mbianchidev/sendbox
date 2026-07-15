import Foundation
import Logging

/// Direct Kata Containers integration through nerdctl and containerd.
public actor KataContainerRuntime: RuntimeProvider {
    typealias CommandRunner =
        @Sendable (
            _ executable: String,
            _ arguments: [String],
            _ environment: [String: String]
        ) async throws -> HostCommandResult

    public enum RuntimeError: Error, LocalizedError {
        case notInitialized
        case invalidConfiguration(String)
        case containerNotFound(String)
        case containerAlreadyExists(String)
        case commandDenied(String)
        case commandFailed(action: String, exitCode: Int32, stderr: String)
        case environmentFileFailed(String)

        public var errorDescription: String? {
            switch self {
            case .notInitialized:
                return "Kata Containers runtime has not been initialized"
            case .invalidConfiguration(let reason):
                return "Invalid Kata Containers configuration: \(reason)"
            case .containerNotFound(let id):
                return "Kata container not found: \(id)"
            case .containerAlreadyExists(let id):
                return "Kata container already exists: \(id)"
            case .commandDenied(let reason):
                return "Command denied by policy: \(reason)"
            case .commandFailed(let action, let exitCode, let stderr):
                let detail = stderr.isEmpty ? "no diagnostic output" : stderr
                return "\(action) failed with exit code \(exitCode): \(detail)"
            case .environmentFileFailed(let reason):
                return "Failed to prepare container environment: \(reason)"
            }
        }
    }

    private let configuration: KataRuntimeConfiguration
    private let logger: Logger
    private let commandRunner: CommandRunner
    private var initialized = false
    private var activeContainers: [String: RuntimeContainerStatus] = [:]
    private var execPrefixes: [String: [String]] = [:]

    public init(
        configuration: KataRuntimeConfiguration = .default,
        logger: Logger = Logger(label: "sendbox.runtime.kata")
    ) {
        self.configuration = configuration
        self.logger = logger
        self.commandRunner = HostCommand.run
    }

    init(
        configuration: KataRuntimeConfiguration,
        logger: Logger = Logger(label: "sendbox.runtime.kata"),
        commandRunner: @escaping CommandRunner
    ) {
        self.configuration = configuration
        self.logger = logger
        self.commandRunner = commandRunner
    }

    public func initialize() async throws {
        try validateConfiguration()

        _ = try await runChecked(
            arguments: ["--version"],
            action: "Locating \(configuration.executable)"
        )

        _ = try await runChecked(
            arguments: KataCommandBuilder(configuration: configuration).globalArguments + ["info"],
            action: "Connecting to containerd"
        )

        initialized = true
        logger.info(
            "Kata Containers runtime initialized",
            metadata: [
                "executable": "\(configuration.executable)",
                "handler": "\(configuration.runtimeHandler)",
                "namespace": "\(configuration.namespace)",
            ]
        )
    }

    @discardableResult
    public func createContainer(_ config: ContainerConfig) async throws -> String {
        guard initialized else {
            throw RuntimeError.notInitialized
        }
        guard activeContainers[config.id] == nil else {
            throw RuntimeError.containerAlreadyExists(config.id)
        }

        let environment = config.boundaryReadyPath == nil
            ? config.environment
            : BoundaryEnforcer.bootstrapEnvironment(
                agentEnvironment: config.environment,
                workingDirectory: config.workingDirectory
            )
        let preparedEnvironment = try prepareEnvironment(environment)
        defer {
            try? FileManager.default.removeItem(at: preparedEnvironment.fileURL)
        }
        activeContainers[config.id] = .creating
        execPrefixes[config.id] = config.boundaryExecPrefix

        let builder = KataCommandBuilder(configuration: configuration)
        let arguments =
            builder.globalArguments
            + builder.runArguments(
                config: config,
                environmentFile: preparedEnvironment.fileURL.path,
                inheritedEnvironmentKeys: preparedEnvironment.inherited.keys.sorted()
            )

        do {
            _ = try await runChecked(
                arguments: arguments,
                action: "Starting Kata container \(config.id)",
                environment: preparedEnvironment.inherited
            )

            if let readyPath = config.boundaryReadyPath {
                try await waitForBoundaryReady(
                    at: readyPath,
                    containerId: config.id
                )
            }
            activeContainers[config.id] = .running

            if config.rootfsSizeInBytes > 0 {
                logger.debug(
                    "Kata root filesystem sizing is delegated to the configured containerd snapshotter"
                )
            }

            if let firewallScript = config.firewallScript, !firewallScript.isEmpty {
                await injectBootScript(
                    firewallScript,
                    name: "firewall",
                    guestPath: "/run/sendbox-firewall.sh",
                    containerId: config.id
                )
            }

            if let mcpScript = config.mcpInspectionScript, !mcpScript.isEmpty {
                await injectBootScript(
                    mcpScript,
                    name: "mcp-inspector",
                    guestPath: "/run/sendbox-mcp-setup.sh",
                    containerId: config.id
                )
            }

            logger.info("Kata container \(config.id) started")
            return config.id
        } catch {
            activeContainers[config.id] = .failed
            await removeContainerBestEffort(id: config.id)
            execPrefixes.removeValue(forKey: config.id)
            throw error
        }
    }

    public func stopContainer(id: String) async throws {
        guard activeContainers[id] != nil else {
            throw RuntimeError.containerNotFound(id)
        }

        let arguments =
            KataCommandBuilder(configuration: configuration).globalArguments
            + ["rm", "--force", id]
        _ = try await runChecked(
            arguments: arguments,
            action: "Stopping Kata container \(id)"
        )
        activeContainers[id] = .stopped
        execPrefixes.removeValue(forKey: id)
        logger.info("Kata container \(id) stopped")
    }

    public func containerStatus(id: String) async -> RuntimeContainerStatus {
        guard initialized else {
            return .unknown
        }

        let arguments =
            KataCommandBuilder(configuration: configuration).globalArguments
            + ["inspect", "--format", "{{.State.Status}}", id]

        do {
            let result = try await commandRunner(configuration.executable, arguments, [:])
            guard result.exitCode == 0 else {
                return activeContainers[id] ?? .unknown
            }

            let status = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let resolved: RuntimeContainerStatus
            switch status {
            case "created", "creating":
                resolved = .creating
            case "running":
                resolved = .running
            case "stopped", "exited", "dead":
                resolved = .stopped
            default:
                resolved = .unknown
            }
            activeContainers[id] = resolved
            return resolved
        } catch {
            logger.warning("Failed to inspect Kata container \(id): \(error.localizedDescription)")
            return activeContainers[id] ?? .unknown
        }
    }

    public func exec(
        containerId: String,
        command: [String],
        policy: CommandPolicy
    ) async throws -> ExecResult {
        guard activeContainers[containerId] != nil else {
            throw RuntimeError.containerNotFound(containerId)
        }

        let commandString = command.joined(separator: " ")
        let decision = await policy.evaluatePipeline(commandString)
        guard decision.isAllowed else {
            if case .denied(let reason) = decision {
                throw RuntimeError.commandDenied(reason)
            }
            throw RuntimeError.commandDenied("Command blocked by policy")
        }

        let arguments =
            KataCommandBuilder(configuration: configuration).globalArguments
            + ["exec", containerId] + (execPrefixes[containerId] ?? []) + command

        do {
            let result = try await commandRunner(configuration.executable, arguments, [:])
            return ExecResult(
                exitCode: result.exitCode,
                stdout: result.stdout,
                stderr: result.stderr
            )
        } catch {
            throw RuntimeError.commandFailed(
                action: "Executing command in Kata container \(containerId)",
                exitCode: -1,
                stderr: error.localizedDescription
            )
        }
    }

    public func attachOutput(containerId: String) async throws -> AsyncStream<String> {
        guard activeContainers[containerId] != nil else {
            throw RuntimeError.containerNotFound(containerId)
        }

        return AsyncStream { continuation in
            let task = Task {
                var emittedLineCount = 0

                while !Task.isCancelled {
                    let arguments =
                        KataCommandBuilder(configuration: self.configuration).globalArguments
                        + ["logs", containerId]

                    do {
                        let result = try await self.commandRunner(
                            self.configuration.executable,
                            arguments,
                            [:]
                        )
                        if result.exitCode != 0 {
                            continuation.yield(
                                "[sendbox] Kata log collection failed: "
                                    + result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                            )
                            break
                        }

                        let lines = result.stdout.split(
                            whereSeparator: \.isNewline
                        ).map(String.init)
                        if lines.count < emittedLineCount {
                            emittedLineCount = 0
                        }
                        for line in lines.dropFirst(emittedLineCount) {
                            continuation.yield(line)
                        }
                        emittedLineCount = lines.count
                    } catch {
                        continuation.yield(
                            "[sendbox] Kata log collection failed: \(error.localizedDescription)"
                        )
                        break
                    }

                    let status = await self.containerStatus(id: containerId)
                    if status != .running && status != .creating {
                        break
                    }

                    try? await Task.sleep(for: .seconds(1))
                }

                continuation.finish()
            }

            continuation.onTermination = { @Sendable _ in
                task.cancel()
            }
        }
    }

    public func cleanup() async throws {
        let containerIDs = Array(activeContainers.keys)
        for id in containerIDs {
            await removeContainerBestEffort(id: id)
        }
        activeContainers.removeAll()
        execPrefixes.removeAll()
        logger.info("All Kata containers cleaned up")
    }

    private func validateConfiguration() throws {
        guard !configuration.executable.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            throw RuntimeError.invalidConfiguration("executable cannot be empty")
        }
        guard !configuration.runtimeHandler.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            throw RuntimeError.invalidConfiguration("runtime_handler cannot be empty")
        }
        guard !configuration.namespace.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            throw RuntimeError.invalidConfiguration("namespace cannot be empty")
        }
        if let path = configuration.configurationPath, !path.hasPrefix("/") {
            throw RuntimeError.invalidConfiguration(
                "configuration_path must be absolute on the containerd host"
            )
        }
    }

    private func runChecked(
        arguments: [String],
        action: String,
        environment: [String: String] = [:]
    ) async throws -> HostCommandResult {
        let result: HostCommandResult
        do {
            result = try await commandRunner(
                configuration.executable,
                arguments,
                environment
            )
        } catch {
            throw RuntimeError.commandFailed(
                action: action,
                exitCode: -1,
                stderr: error.localizedDescription
            )
        }

        guard result.exitCode == 0 else {
            var stderr = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            if action == "Connecting to containerd" {
                stderr +=
                    " Ensure the current user can access the containerd socket or configure rootless containerd."
            }
            throw RuntimeError.commandFailed(
                action: action,
                exitCode: result.exitCode,
                stderr: stderr
            )
        }
        return result
    }

    private func waitForBoundaryReady(
        at path: String,
        containerId: String
    ) async throws {
        let globalArguments = KataCommandBuilder(configuration: configuration).globalArguments
        var lastError: Error?

        for _ in 0..<240 {
            do {
                let result = try await commandRunner(
                    configuration.executable,
                    globalArguments + ["exec", containerId, "/bin/test", "-f", path],
                    [:]
                )
                if result.exitCode == 0 {
                    logger.info("Boundary enforcement ready in Kata container \(containerId)")
                    return
                }
            } catch {
                lastError = error
            }
            try await Task.sleep(for: .milliseconds(500))
        }

        let suffix = lastError.map { ": \($0.localizedDescription)" } ?? ""
        throw RuntimeError.commandFailed(
            action: "Waiting for boundary enforcement in Kata container \(containerId)",
            exitCode: -1,
            stderr: "readiness marker \(path) was not created\(suffix)"
        )
    }

    private struct PreparedEnvironment: Sendable {
        let fileURL: URL
        let inherited: [String: String]
    }

    private func prepareEnvironment(
        _ environment: [String: String]
    ) throws -> PreparedEnvironment {
        var lines: [String] = []
        var inherited: [String: String] = [:]
        for (key, value) in environment.sorted(by: { $0.key < $1.key }) {
            guard isValidEnvironmentKey(key) else {
                throw RuntimeError.environmentFileFailed("invalid environment key '\(key)'")
            }
            if value.contains("\n") || value.contains("\r") {
                guard !Self.hostEnvironmentKeys.contains(key) else {
                    throw RuntimeError.environmentFileFailed(
                        "multi-line value cannot override host-sensitive key '\(key)'"
                    )
                }
                inherited[key] = value
            } else {
                lines.append("\(key)=\(value)")
            }
        }

        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("sendbox-env-\(UUID().uuidString)")
        let content = lines.joined(separator: "\n") + (lines.isEmpty ? "" : "\n")
        do {
            try SecureFile.create(at: fileURL, data: Data(content.utf8))
        } catch {
            throw RuntimeError.environmentFileFailed(error.localizedDescription)
        }
        return PreparedEnvironment(fileURL: fileURL, inherited: inherited)
    }

    private func isValidEnvironmentKey(_ key: String) -> Bool {
        guard let first = key.unicodeScalars.first,
            first == "_" || CharacterSet.letters.contains(first)
        else {
            return false
        }
        return key.unicodeScalars.dropFirst().allSatisfy {
            $0 == "_" || CharacterSet.alphanumerics.contains($0)
        }
    }

    private func injectBootScript(
        _ content: String,
        name: String,
        guestPath: String,
        containerId: String
    ) async {
        let hostURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)-\(containerId)-\(UUID().uuidString).sh")
        do {
            try SecureFile.create(
                at: hostURL,
                data: Data(content.utf8),
                permissions: 0o700
            )
        } catch {
            logger.warning("Failed to create temporary \(name) script for \(containerId)")
            return
        }
        defer {
            try? FileManager.default.removeItem(at: hostURL)
        }

        let globalArguments = KataCommandBuilder(configuration: configuration).globalArguments
        do {
            _ = try await runChecked(
                arguments: globalArguments + ["cp", hostURL.path, "\(containerId):\(guestPath)"],
                action: "Copying \(name) script into Kata container \(containerId)"
            )
            _ = try await runChecked(
                arguments: globalArguments + ["exec", containerId, "/bin/bash", guestPath],
                action: "Applying \(name) script in Kata container \(containerId)"
            )
        } catch {
            logger.warning(
                "Failed to inject \(name) script into Kata container \(containerId): \(error.localizedDescription)"
            )
        }
    }

    private func removeContainerBestEffort(id: String) async {
        let arguments =
            KataCommandBuilder(configuration: configuration).globalArguments
            + ["rm", "--force", id]
        do {
            let result = try await commandRunner(configuration.executable, arguments, [:])
            if result.exitCode != 0 {
                logger.warning(
                    "Failed to remove Kata container \(id): \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
                )
            }
        } catch {
            logger.warning("Failed to remove Kata container \(id): \(error.localizedDescription)")
        }
    }

    private static let hostEnvironmentKeys: Set<String> = [
        "CONTAINERD_ADDRESS",
        "CONTAINERD_NAMESPACE",
        "CONTAINERD_SNAPSHOTTER",
        "HOME",
        "NERDCTL_TOML",
        "PATH",
        "TMPDIR",
    ]
}

struct KataCommandBuilder: Sendable {
    let configuration: KataRuntimeConfiguration

    var globalArguments: [String] {
        var arguments: [String] = []
        if let address = configuration.address, !address.isEmpty {
            arguments += ["--address", address]
        }
        arguments += ["--namespace", configuration.namespace]
        if let snapshotter = configuration.snapshotter, !snapshotter.isEmpty {
            arguments += ["--snapshotter", snapshotter]
        }
        return arguments
    }

    func runArguments(
        config: ContainerConfig,
        environmentFile: String,
        inheritedEnvironmentKeys: [String] = []
    ) -> [String] {
        var arguments = [
            "run",
            "--detach",
            "--interactive",
            "--name", config.id,
            "--hostname", config.hostname,
            "--runtime", configuration.runtimeHandler,
            "--cpus", String(config.cpus),
            "--memory", String(config.memoryInBytes),
            "--user", "0:0",
            "--label", "io.sendbox.managed=true",
            "--label", "io.sendbox.runtime=kata",
            "--label", "io.sendbox.sandbox=\(config.hostname)",
            "--workdir", config.workingDirectory,
            "--env-file", environmentFile,
        ]

        for key in inheritedEnvironmentKeys {
            arguments += ["--env", key]
        }

        if let configurationPath = configuration.configurationPath {
            arguments += [
                "--annotation",
                "io.katacontainers.config_path=\(configurationPath)",
            ]
        }

        var capabilities = Set<String>()
        if config.firewallScript != nil {
            capabilities.insert("NET_ADMIN")
        }
        if config.mcpInspectionScript != nil {
            capabilities.formUnion(["BPF", "PERFMON", "SYS_PTRACE"])
        }
        if config.boundaryReadyPath != nil {
            capabilities.formUnion([
                "BPF", "NET_ADMIN", "PERFMON", "SYS_ADMIN",
                "SYS_PTRACE", "SYS_RESOURCE",
            ])
            arguments += [
                "--pid", "host",
                "--security-opt", "seccomp=unconfined",
            ]
        }
        for capability in capabilities.sorted() {
            arguments += ["--cap-add", capability]
        }

        for mount in config.mounts {
            var volume = "\(mount.source):\(mount.destination)"
            if mount.readOnly {
                volume += ":ro"
            }
            arguments += ["--volume", volume]
        }

        for nameserver in config.network.nameservers {
            arguments += ["--dns", nameserver]
        }

        arguments.append(config.imageReference)
        arguments.append(contentsOf: config.command)
        return arguments
    }
}
