import Foundation
import Logging

/// Runs Linux applications in one-shot Hyperlight micro-VMs through hyperlight-unikraft.
public actor HyperlightRuntime: RuntimeProvider {
    typealias CommandRunner =
        @Sendable (
            _ executable: String,
            _ arguments: [String],
            _ environment: [String: String]
        ) async throws -> HostCommandResult
    typealias HostValidator =
        @Sendable (_ configuration: HyperlightRuntimeConfiguration) throws -> Void

    public enum RuntimeError: Error, LocalizedError {
        case notInitialized
        case invalidConfiguration(String)
        case containerNotFound(String)
        case containerAlreadyExists(String)
        case commandDenied(String)
        case commandFailed(exitCode: Int32, stderr: String)
        case unsupported(String)

        public var errorDescription: String? {
            switch self {
            case .notInitialized:
                return "Hyperlight runtime has not been initialized"
            case .invalidConfiguration(let reason):
                return "Invalid Hyperlight configuration: \(reason)"
            case .containerNotFound(let id):
                return "Hyperlight micro-VM not found: \(id)"
            case .containerAlreadyExists(let id):
                return "Hyperlight micro-VM already exists: \(id)"
            case .commandDenied(let reason):
                return "Command denied by policy: \(reason)"
            case .commandFailed(let exitCode, let stderr):
                let detail = stderr.isEmpty ? "no diagnostic output" : stderr
                return "Hyperlight command failed with exit code \(exitCode): \(detail)"
            case .unsupported(let feature):
                return "Hyperlight runtime does not support \(feature)"
            }
        }
    }

    private struct ManagedVM: Sendable {
        let config: ContainerConfig
        var status: RuntimeContainerStatus
        var task: Task<HostCommandResult, Error>?
        var result: HostCommandResult?
    }

    private let configuration: HyperlightRuntimeConfiguration
    private let logger: Logger
    private let commandRunner: CommandRunner
    private let hostValidator: HostValidator
    private var initialized = false
    private var activeVMs: [String: ManagedVM] = [:]

    public init(
        configuration: HyperlightRuntimeConfiguration = .default,
        logger: Logger = Logger(label: "sendbox.runtime.hyperlight")
    ) {
        self.configuration = configuration
        self.logger = logger
        self.commandRunner = HostCommand.run
        self.hostValidator = Self.validateHost
    }

    init(
        configuration: HyperlightRuntimeConfiguration,
        logger: Logger = Logger(label: "sendbox.runtime.hyperlight"),
        commandRunner: @escaping CommandRunner,
        hostValidator: @escaping HostValidator = Self.validateHost
    ) {
        self.configuration = configuration
        self.logger = logger
        self.commandRunner = commandRunner
        self.hostValidator = hostValidator
    }

    public func initialize() async throws {
        try validateConfiguration()

        let result: HostCommandResult
        do {
            result = try await commandRunner(configuration.executable, ["--version"], [:])
        } catch {
            throw RuntimeError.invalidConfiguration(
                "could not execute \(configuration.executable): \(error.localizedDescription)"
            )
        }
        guard result.exitCode == 0 else {
            throw RuntimeError.commandFailed(
                exitCode: result.exitCode,
                stderr: result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }

        initialized = true
        logger.info(
            "Hyperlight runtime initialized",
            metadata: [
                "executable": "\(configuration.executable)",
                "kernel": "\(configuration.kernelPath)",
            ]
        )
    }

    @discardableResult
    public func createContainer(_ config: ContainerConfig) async throws -> String {
        guard initialized else {
            throw RuntimeError.notInitialized
        }
        guard activeVMs[config.id] == nil else {
            throw RuntimeError.containerAlreadyExists(config.id)
        }
        try validate(config)

        let arguments = HyperlightCommandBuilder(configuration: configuration)
            .arguments(for: config, command: config.command)
        let executable = configuration.executable
        let runner = commandRunner
        let task = Task {
            try await runner(executable, arguments, [:])
        }

        activeVMs[config.id] = ManagedVM(
            config: config,
            status: .running,
            task: task,
            result: nil
        )

        Task { [weak self] in
            do {
                let result = try await task.value
                await self?.recordCompletion(id: config.id, result: result)
            } catch {
                await self?.recordFailure(id: config.id, error: error)
            }
        }

        logger.info("Started Hyperlight micro-VM \(config.id)")
        return config.id
    }

    public func stopContainer(id: String) async throws {
        guard var vm = activeVMs[id] else {
            throw RuntimeError.containerNotFound(id)
        }
        vm.task?.cancel()
        vm.status = .stopped
        activeVMs[id] = vm
        logger.info("Stopped Hyperlight micro-VM \(id)")
    }

    public func containerStatus(id: String) async -> RuntimeContainerStatus {
        activeVMs[id]?.status ?? .unknown
    }

    public func exec(
        containerId: String,
        command: [String],
        policy: CommandPolicy
    ) async throws -> ExecResult {
        guard let vm = activeVMs[containerId] else {
            throw RuntimeError.containerNotFound(containerId)
        }
        guard !command.isEmpty else {
            throw RuntimeError.invalidConfiguration("command cannot be empty")
        }

        let commandString = command.joined(separator: " ")
        let decision = await policy.evaluatePipeline(commandString)
        guard decision.isAllowed else {
            if case .denied(let reason) = decision {
                throw RuntimeError.commandDenied(reason)
            }
            throw RuntimeError.commandDenied("Command blocked by policy")
        }

        let arguments = HyperlightCommandBuilder(configuration: configuration)
            .arguments(for: vm.config, command: command)
        let result: HostCommandResult
        do {
            result = try await commandRunner(configuration.executable, arguments, [:])
        } catch {
            throw RuntimeError.commandFailed(exitCode: -1, stderr: error.localizedDescription)
        }

        return ExecResult(
            exitCode: result.exitCode,
            stdout: result.stdout,
            stderr: result.stderr
        )
    }

    public func attachOutput(containerId: String) async throws -> AsyncStream<String> {
        guard let vm = activeVMs[containerId] else {
            throw RuntimeError.containerNotFound(containerId)
        }

        return AsyncStream { continuation in
            let reader = Task {
                do {
                    let result: HostCommandResult
                    if let completed = vm.result {
                        result = completed
                    } else if let task = vm.task {
                        result = try await task.value
                    } else {
                        result = HostCommandResult(exitCode: 0, stdout: "", stderr: "")
                    }

                    for line in result.stdout.split(whereSeparator: \.isNewline) {
                        continuation.yield(String(line))
                    }
                    for line in result.stderr.split(whereSeparator: \.isNewline) {
                        continuation.yield(String(line))
                    }
                } catch {
                    continuation.yield(
                        "[sendbox] Hyperlight output collection failed: \(error.localizedDescription)"
                    )
                }
                continuation.finish()
            }

            continuation.onTermination = { @Sendable _ in
                reader.cancel()
            }
        }
    }

    public func cleanup() async throws {
        for (_, vm) in activeVMs {
            vm.task?.cancel()
        }
        activeVMs.removeAll()
        logger.info("All Hyperlight micro-VMs cleaned up")
    }

    private func validateConfiguration() throws {
        guard !configuration.executable.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw RuntimeError.invalidConfiguration("executable cannot be empty")
        }
        guard !configuration.kernelPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw RuntimeError.invalidConfiguration("kernel_path is required")
        }
        guard configuration.stackMB > 0 else {
            throw RuntimeError.invalidConfiguration("stack_mb must be greater than zero")
        }
        try hostValidator(configuration)
    }

    private static func validateHost(_ configuration: HyperlightRuntimeConfiguration) throws {
        guard FileManager.default.fileExists(atPath: configuration.kernelPath) else {
            throw RuntimeError.invalidConfiguration(
                "kernel not found at \(configuration.kernelPath)"
            )
        }
        if let initrdPath = configuration.initrdPath,
            !FileManager.default.fileExists(atPath: initrdPath)
        {
            throw RuntimeError.invalidConfiguration("initrd not found at \(initrdPath)")
        }
        #if os(Linux)
        guard FileManager.default.isReadableFile(atPath: "/dev/kvm") else {
            throw RuntimeError.invalidConfiguration("/dev/kvm is not accessible")
        }
        #else
        throw RuntimeError.unsupported("hosts without Linux KVM")
        #endif
    }

    private func validate(_ config: ContainerConfig) throws {
        guard !config.command.isEmpty else {
            throw RuntimeError.invalidConfiguration("command cannot be empty")
        }
        let unsupportedEnvironmentKeys = Set(config.environment.keys).subtracting([
            "HOME", "LANG", "PATH", "TERM",
        ])
        guard unsupportedEnvironmentKeys.isEmpty else {
            throw RuntimeError.unsupported(
                "guest environment variables: \(unsupportedEnvironmentKeys.sorted().joined(separator: ", "))"
            )
        }
        if config.mcpInspectionScript != nil {
            throw RuntimeError.unsupported("eBPF MCP inspection in a unikernel guest")
        }
    }

    private func recordCompletion(id: String, result: HostCommandResult) {
        guard var vm = activeVMs[id], vm.status == .running else {
            return
        }
        vm.result = result
        vm.status = result.exitCode == 0 ? .stopped : .failed
        activeVMs[id] = vm
    }

    private func recordFailure(id: String, error: Error) {
        guard var vm = activeVMs[id], vm.status == .running else {
            return
        }
        vm.result = HostCommandResult(
            exitCode: -1,
            stdout: "",
            stderr: error.localizedDescription
        )
        vm.status = .failed
        activeVMs[id] = vm
    }
}

struct HyperlightCommandBuilder: Sendable {
    let configuration: HyperlightRuntimeConfiguration

    func arguments(for config: ContainerConfig, command: [String]) -> [String] {
        var arguments = [configuration.kernelPath]

        if let initrdPath = configuration.initrdPath {
            arguments += ["--initrd", initrdPath]
        }

        let mebibyte = UInt64(1024 * 1024)
        let memoryMB = max(1, config.memoryInBytes / mebibyte)
        arguments += [
            "--memory", "\(memoryMB)Mi",
            "--stack", "\(configuration.stackMB)Mi",
            "--quiet",
        ]

        for mount in config.mounts where !mount.readOnly {
            arguments += ["--mount", "\(mount.source):\(mount.destination)"]
        }

        if config.network.allowsUnrestrictedOutbound {
            if config.network.blockedHosts.isEmpty {
                arguments.append("--net")
            } else {
                for host in config.network.blockedHosts {
                    arguments += ["--net-block", host]
                }
            }
        } else {
            for host in config.network.allowedHosts {
                arguments += ["--net-allow", host]
            }
        }

        arguments += ["--exec", shellCommand(command)]
        return arguments
    }

    private func shellCommand(_ command: [String]) -> String {
        command.map { argument in
            "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }.joined(separator: " ")
    }
}
