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
        var execTasks: [UUID: Task<HostCommandResult, Error>]
        var mcpSessions: [UUID: HyperlightMCPSession]
        var result: HostCommandResult?
        var temporaryMounts: [URL]
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
        self.commandRunner = { executable, arguments, environment in
            try await HostCommand.run(
                executable: executable,
                arguments: arguments,
                environment: environment,
                inheritEnvironment: false
            )
        }
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
            result = try await commandRunner(
                configuration.executable,
                ["--version"],
                Self.hostEnvironment
            )
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
        let (preparedConfig, temporaryMounts) = try prepareMounts(for: config)

        let arguments = HyperlightCommandBuilder(configuration: configuration)
            .arguments(for: preparedConfig, command: preparedConfig.command)
        let executable = configuration.executable
        let runner = commandRunner
        let task = Task {
            try await runner(executable, arguments, Self.hostEnvironment)
        }

        activeVMs[config.id] = ManagedVM(
            config: preparedConfig,
            status: .running,
            task: task,
            execTasks: [:],
            mcpSessions: [:],
            result: nil,
            temporaryMounts: temporaryMounts
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
        for task in vm.execTasks.values {
            task.cancel()
        }
        for session in vm.mcpSessions.values {
            session.stop()
        }
        vm.status = .stopped
        activeVMs[id] = vm
        if let task = vm.task {
            _ = try? await task.value
        }
        for task in vm.execTasks.values {
            _ = try? await task.value
        }
        removeTemporaryMounts(vm.temporaryMounts)
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
        guard vm.status == .running else {
            throw RuntimeError.unsupported(
                "exec in a micro-VM with status \(vm.status.rawValue)"
            )
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
        let executable = configuration.executable
        let runner = commandRunner
        let task = Task {
            try await runner(executable, arguments, Self.hostEnvironment)
        }
        let execID = UUID()
        var updatedVM = vm
        updatedVM.execTasks[execID] = task
        activeVMs[containerId] = updatedVM
        defer {
            if var currentVM = activeVMs[containerId] {
                currentVM.execTasks.removeValue(forKey: execID)
                activeVMs[containerId] = currentVM
            }
        }

        let result: HostCommandResult
        do {
            result = try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                task.cancel()
            }
        } catch {
            throw RuntimeError.commandFailed(exitCode: -1, stderr: error.localizedDescription)
        }

        return ExecResult(
            exitCode: result.exitCode,
            stdout: result.stdout,
            stderr: result.stderr
        )
    }

    /// Start a network-transport MCP server in a fresh Hyperlight micro-VM.
    public func mcpExec(
        containerId: String,
        command: [String],
        policy: CommandPolicy
    ) async throws -> HyperlightMCPSession {
        guard var vm = activeVMs[containerId] else {
            throw RuntimeError.containerNotFound(containerId)
        }
        guard vm.status == .running else {
            throw RuntimeError.unsupported(
                "MCP exec in a micro-VM with status \(vm.status.rawValue)"
            )
        }
        guard !command.isEmpty else {
            throw RuntimeError.invalidConfiguration("MCP command cannot be empty")
        }

        let commandString = command.joined(separator: " ")
        let decision = await policy.evaluatePipeline(commandString)
        guard decision.isAllowed else {
            if case .denied(let reason) = decision {
                throw RuntimeError.commandDenied(reason)
            }
            throw RuntimeError.commandDenied("MCP command blocked by policy")
        }

        let arguments = HyperlightCommandBuilder(configuration: configuration)
            .arguments(for: vm.config, command: command)
        let session: HyperlightMCPSession
        do {
            session = try HyperlightMCPSession(
                executable: configuration.executable,
                arguments: arguments
            )
        } catch {
            throw RuntimeError.commandFailed(exitCode: -1, stderr: error.localizedDescription)
        }

        vm.mcpSessions[UUID()] = session
        activeVMs[containerId] = vm
        return session
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
        let vms = Array(activeVMs.values)
        for vm in vms {
            vm.task?.cancel()
            for task in vm.execTasks.values {
                task.cancel()
            }
            for session in vm.mcpSessions.values {
                session.stop()
            }
        }
        for vm in vms {
            if let task = vm.task {
                _ = try? await task.value
            }
            for task in vm.execTasks.values {
                _ = try? await task.value
            }
            removeTemporaryMounts(vm.temporaryMounts)
        }
        activeVMs.removeAll()
        logger.info("All Hyperlight micro-VMs cleaned up")
    }

    private func validateConfiguration() throws {
        guard !configuration.executable.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw RuntimeError.invalidConfiguration("executable cannot be empty")
        }
        guard configuration.executable.hasPrefix("/") else {
            throw RuntimeError.invalidConfiguration(
                "executable must be an administrator-controlled absolute path"
            )
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
        try validateTrustedExecutable(configuration.executable)
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

    private static func validateTrustedExecutable(_ path: String) throws {
        let configuredURL = URL(fileURLWithPath: path).standardizedFileURL
        let executableURL = configuredURL.resolvingSymlinksInPath()
        guard configuredURL.path == executableURL.path else {
            throw RuntimeError.invalidConfiguration(
                "executable path must not contain symbolic links"
            )
        }
        var currentURL = executableURL

        while currentURL.path != "/" {
            let attributes: [FileAttributeKey: Any]
            do {
                attributes = try FileManager.default.attributesOfItem(
                    atPath: currentURL.path
                )
            } catch {
                throw RuntimeError.invalidConfiguration(
                    "trusted executable path component not found: \(currentURL.path)"
                )
            }

            let ownerID = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
            let permissions =
                (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0o777
            guard ownerID == 0, permissions & 0o022 == 0 else {
                throw RuntimeError.invalidConfiguration(
                    "executable and parent directories must be root-owned and not group- or world-writable"
                )
            }
            currentURL = currentURL.deletingLastPathComponent()
        }

        let attributes = try FileManager.default.attributesOfItem(atPath: executableURL.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw RuntimeError.invalidConfiguration("executable must be a regular file")
        }
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
        let networkingEnabled =
            config.network.allowsUnrestrictedOutbound || !config.network.allowedHosts.isEmpty
        if networkingEnabled && !config.network.allowDNS {
            throw RuntimeError.unsupported(
                "network access with DNS disabled because Hyperlight permits resolver traffic"
            )
        }
        if networkingEnabled && config.network.maxConnections != nil {
            throw RuntimeError.unsupported(
                "network connection limits because Hyperlight cannot enforce them"
            )
        }
    }

    private static let hostEnvironment = [
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
    ]

    private func prepareMounts(for config: ContainerConfig) throws -> (ContainerConfig, [URL]) {
        var preparedConfig = config
        var temporaryMounts: [URL] = []

        do {
            for index in preparedConfig.mounts.indices
            where preparedConfig.mounts[index].readOnly {
                let mount = preparedConfig.mounts[index]
                let stagingRoot = FileManager.default.temporaryDirectory
                    .appendingPathComponent(
                        "sendbox-hyperlight-mount-\(UUID().uuidString)",
                        isDirectory: true
                    )
                try SecureFile.ensureDirectory(at: stagingRoot)
                temporaryMounts.append(stagingRoot)

                let sourceURL = URL(fileURLWithPath: mount.source)
                let stagedSource = stagingRoot.appendingPathComponent(
                    sourceURL.lastPathComponent,
                    isDirectory: sourceURL.hasDirectoryPath
                )
                try FileManager.default.copyItem(at: sourceURL, to: stagedSource)
                preparedConfig.mounts[index] = .init(
                    source: stagedSource.path,
                    destination: mount.destination,
                    readOnly: false
                )
            }
        } catch {
            removeTemporaryMounts(temporaryMounts)
            throw RuntimeError.invalidConfiguration(
                "could not stage a read-only mount: \(error.localizedDescription)"
            )
        }

        return (preparedConfig, temporaryMounts)
    }

    private func removeTemporaryMounts(_ mounts: [URL]) {
        for mount in mounts {
            try? FileManager.default.removeItem(at: mount)
        }
    }

    private func recordCompletion(id: String, result: HostCommandResult) {
        guard var vm = activeVMs[id], vm.status == .running else {
            return
        }
        vm.result = result
        vm.status = result.exitCode == 0 ? .stopped : .failed
        for task in vm.execTasks.values {
            task.cancel()
        }
        for session in vm.mcpSessions.values {
            session.stop()
        }
        removeTemporaryMounts(vm.temporaryMounts)
        vm.temporaryMounts.removeAll()
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
        for task in vm.execTasks.values {
            task.cancel()
        }
        for session in vm.mcpSessions.values {
            session.stop()
        }
        removeTemporaryMounts(vm.temporaryMounts)
        vm.temporaryMounts.removeAll()
        activeVMs[id] = vm
    }
}

/// A managed network-transport MCP server process running in Hyperlight.
public final class HyperlightMCPSession: @unchecked Sendable {
    private let process: Process
    private let lock = NSLock()

    fileprivate init(executable: String, arguments: [String]) throws {
        let process = Process()

        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [executable] + arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.standardError
        process.environment = [
            "LANG": "C",
            "PATH": "/usr/bin:/bin",
        ]
        try process.run()

        self.process = process
    }

    public var isRunning: Bool {
        process.isRunning
    }

    public func stop() {
        lock.lock()
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
        lock.unlock()
    }

    deinit {
        stop()
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
