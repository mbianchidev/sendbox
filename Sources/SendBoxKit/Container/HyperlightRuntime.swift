import Foundation
import Logging

#if os(Linux)
import Glibc
#endif

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
        hostValidator: @escaping HostValidator = HyperlightRuntime.validateHost
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
    public func createContainer(
        _ config: ContainerConfig,
        policy: CommandPolicy
    ) async throws -> String {
        guard initialized else {
            throw RuntimeError.notInitialized
        }
        guard activeVMs[config.id] == nil else {
            throw RuntimeError.containerAlreadyExists(config.id)
        }
        try validate(config)
        try await requireAllowed(
            config.command,
            policy: policy,
            fallbackReason: "Startup command blocked by policy"
        )

        let builder = HyperlightCommandBuilder(configuration: configuration)
        let (preparedConfig, temporaryMounts) = try prepareMounts(for: config)
        let arguments: [String]
        do {
            arguments = try builder.arguments(
                for: preparedConfig,
                command: preparedConfig.command
            )
        } catch {
            removeTemporaryMounts(temporaryMounts)
            throw error
        }
        let executable = configuration.executable
        let runner = commandRunner
        let task = Task {
            try await runner(executable, arguments, Self.hostEnvironment)
        }

        activeVMs[config.id] = ManagedVM(
            config: config,
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

        try await requireAllowed(
            command,
            policy: policy,
            fallbackReason: "Command blocked by policy"
        )

        let builder = HyperlightCommandBuilder(configuration: configuration)
        try builder.validate(config: vm.config)
        let (preparedConfig, temporaryMounts) = try prepareMounts(for: vm.config)
        let arguments: [String]
        do {
            arguments = try builder.arguments(for: preparedConfig, command: command)
        } catch {
            removeTemporaryMounts(temporaryMounts)
            throw error
        }
        defer {
            removeTemporaryMounts(temporaryMounts)
        }
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
    /// `listenPort` is the guest port Hyperlight permits the server to bind.
    public func mcpExec(
        containerId: String,
        command: [String],
        listenPort: UInt16,
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

        try await requireAllowed(
            command,
            policy: policy,
            fallbackReason: "MCP command blocked by policy"
        )

        let builder = HyperlightCommandBuilder(configuration: configuration)
        try builder.validate(config: vm.config, listenPorts: [listenPort])
        let (preparedConfig, temporaryMounts) = try prepareMounts(for: vm.config)
        let arguments: [String]
        do {
            arguments = try builder.arguments(
                for: preparedConfig,
                command: command,
                listenPorts: [listenPort]
            )
        } catch {
            removeTemporaryMounts(temporaryMounts)
            throw error
        }

        let sessionID = UUID()
        let session: HyperlightMCPSession
        do {
            session = try HyperlightMCPSession(
                executable: configuration.executable,
                arguments: arguments,
                listenPort: listenPort,
                temporaryMounts: temporaryMounts,
                logger: logger,
                onTermination: { [weak self] in
                    Task {
                        await self?.removeMCPSession(
                            containerId: containerId,
                            sessionID: sessionID
                        )
                    }
                }
            )
        } catch {
            removeTemporaryMounts(temporaryMounts)
            throw RuntimeError.commandFailed(exitCode: -1, stderr: error.localizedDescription)
        }

        vm.mcpSessions[sessionID] = session
        activeVMs[containerId] = vm
        if !session.isRunning {
            removeMCPSession(containerId: containerId, sessionID: sessionID)
        }
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
        let descriptor = Glibc.open("/dev/kvm", O_RDWR | O_CLOEXEC)
        guard descriptor >= 0 else {
            let detail = String(cString: Glibc.strerror(errno))
            throw RuntimeError.invalidConfiguration(
                "/dev/kvm must be readable and writable: \(detail)"
            )
        }
        _ = Glibc.close(descriptor)
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
        let builder = HyperlightCommandBuilder(configuration: configuration)
        try builder.validate(config: config)

        if config.boundaryReadyPath != nil || !config.boundaryExecPrefix.isEmpty {
            throw RuntimeError.unsupported(
                "eBPF/seccomp boundary enforcement in a unikernel guest; set policy.boundaries.enabled to false"
            )
        }
        let unsupportedEnvironmentKeys = Set(config.environment.keys).subtracting([
            "HOME", "LANG", "PATH", "SENDBOX_WORKING_DIRECTORY", "TERM",
        ])
        guard unsupportedEnvironmentKeys.isEmpty else {
            throw RuntimeError.unsupported(
                "guest environment variables: \(unsupportedEnvironmentKeys.sorted().joined(separator: ", "))"
            )
        }
        if config.mcpInspectionScript != nil {
            throw RuntimeError.unsupported("eBPF MCP inspection in a unikernel guest")
        }
        let networkingEnabled = try builder.networkingEnabled(for: config.network)
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

    private func requireAllowed(
        _ command: [String],
        policy: CommandPolicy,
        fallbackReason: String
    ) async throws {
        let decision = await policy.evaluate(command)
        guard decision.isAllowed else {
            if case .denied(let reason) = decision {
                throw RuntimeError.commandDenied(reason)
            }
            throw RuntimeError.commandDenied(fallbackReason)
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
            guard FileManager.default.fileExists(atPath: mount.path) else {
                continue
            }
            do {
                try FileManager.default.removeItem(at: mount)
            } catch {
                logger.warning(
                    "Failed to remove Hyperlight staged mount",
                    metadata: [
                        "path": "\(mount.path)",
                        "error": "\(error.localizedDescription)",
                    ]
                )
            }
        }
    }

    private func removeMCPSession(containerId: String, sessionID: UUID) {
        guard var vm = activeVMs[containerId] else {
            return
        }
        vm.mcpSessions.removeValue(forKey: sessionID)
        activeVMs[containerId] = vm
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
    private let logger: Logger
    private let onTermination: @Sendable () -> Void
    private var temporaryMounts: [URL]
    private var finished = false
    private var stopping = false

    public let listenPort: UInt16
    let stagedMountPaths: [String]

    fileprivate init(
        executable: String,
        arguments: [String],
        listenPort: UInt16,
        temporaryMounts: [URL],
        logger: Logger,
        onTermination: @escaping @Sendable () -> Void
    ) throws {
        let process = Process()

        self.process = process
        self.listenPort = listenPort
        self.temporaryMounts = temporaryMounts
        self.stagedMountPaths = temporaryMounts.map(\.path)
        self.logger = logger
        self.onTermination = onTermination

        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [executable] + arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.standardError
        process.environment = [
            "LANG": "C",
            "PATH": "/usr/bin:/bin",
        ]
        process.terminationHandler = { [weak self] _ in
            self?.finish()
        }
        try process.run()
    }

    public var isRunning: Bool {
        process.isRunning
    }

    public func stop() {
        let shouldTerminate: Bool
        let shouldWait: Bool
        lock.lock()
        shouldWait = process.isRunning
        shouldTerminate = !stopping && shouldWait
        if shouldWait {
            stopping = true
        }
        lock.unlock()

        if shouldTerminate {
            process.terminate()
        }
        if shouldWait {
            process.waitUntilExit()
        }
        finish()
    }

    private func finish() {
        let mounts: [URL]
        let shouldNotify: Bool

        lock.lock()
        if finished {
            mounts = []
            shouldNotify = false
        } else {
            finished = true
            mounts = temporaryMounts
            temporaryMounts.removeAll()
            shouldNotify = true
        }
        lock.unlock()

        for mount in mounts {
            guard FileManager.default.fileExists(atPath: mount.path) else {
                continue
            }
            do {
                try FileManager.default.removeItem(at: mount)
            } catch {
                logger.warning(
                    "Failed to remove Hyperlight MCP staged mount",
                    metadata: [
                        "path": "\(mount.path)",
                        "error": "\(error.localizedDescription)",
                    ]
                )
            }
        }

        if shouldNotify {
            onTermination()
        }
    }

    deinit {
        stop()
    }
}

struct HyperlightCommandBuilder: Sendable {
    let configuration: HyperlightRuntimeConfiguration

    func validate(
        config: ContainerConfig,
        listenPorts: [UInt16] = []
    ) throws {
        guard !config.workingDirectory.isEmpty else {
            throw HyperlightRuntime.RuntimeError.invalidConfiguration(
                "working directory cannot be empty"
            )
        }
        guard config.workingDirectory.hasPrefix("/") else {
            throw HyperlightRuntime.RuntimeError.invalidConfiguration(
                "working directory must be an absolute guest path"
            )
        }
        guard !listenPorts.contains(0) else {
            throw HyperlightRuntime.RuntimeError.invalidConfiguration(
                "MCP listen port must be between 1 and 65535"
            )
        }
        _ = try networkArguments(for: config.network)
    }

    func networkingEnabled(for network: ContainerConfig.NetworkConfig) throws -> Bool {
        !(try networkArguments(for: network)).isEmpty
    }

    func arguments(
        for config: ContainerConfig,
        command: [String],
        listenPorts: [UInt16] = []
    ) throws -> [String] {
        guard !command.isEmpty else {
            throw HyperlightRuntime.RuntimeError.invalidConfiguration(
                "command cannot be empty"
            )
        }
        try validate(config: config, listenPorts: listenPorts)

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

        arguments += try networkArguments(for: config.network)
        for port in listenPorts {
            arguments += ["--port", String(port)]
        }

        arguments += [
            "--exec",
            "cd \(quote(config.workingDirectory)) && exec \(shellCommand(command))",
        ]
        return arguments
    }

    func networkArguments(
        for network: ContainerConfig.NetworkConfig
    ) throws -> [String] {
        let allowedHosts = try normalize(network.allowedHosts)
        let blockedHosts = try normalize(network.blockedHosts)

        for entry in allowedHosts + blockedHosts
        where containsWildcard(entry) && !isDomainWildcard(entry)
        {
            throw HyperlightRuntime.RuntimeError.invalidConfiguration(
                "network entry '\(entry)' uses unsupported wildcard syntax; only '*.example.com' patterns are valid"
            )
        }

        if network.allowsUnrestrictedOutbound {
            if let wildcard = blockedHosts.first(where: containsWildcard) {
                throw HyperlightRuntime.RuntimeError.invalidConfiguration(
                    "Hyperlight network block entry '\(wildcard)' must use a concrete hostname or IP address"
                )
            }
            if blockedHosts.isEmpty {
                return ["--net"]
            }
            return blockedHosts.flatMap { ["--net-block", $0] }
        }

        let effectiveAllowedHosts = allowedHosts.filter { allowedHost in
            !blockedHosts.contains { blockedHost in
                blockedPattern(blockedHost, covers: allowedHost)
            }
        }
        if let wildcard = effectiveAllowedHosts.first(where: containsWildcard) {
            throw HyperlightRuntime.RuntimeError.invalidConfiguration(
                "Hyperlight network allow entry '\(wildcard)' must use concrete hostnames or IP addresses"
            )
        }
        return effectiveAllowedHosts.flatMap { ["--net-allow", $0] }
    }

    private func shellCommand(_ command: [String]) -> String {
        command.map(quote).joined(separator: " ")
    }

    private func quote(_ argument: String) -> String {
        "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private func normalize(_ entries: [String]) throws -> [String] {
        var seen: Set<String> = []
        var normalized: [String] = []

        for entry in entries {
            var value = entry.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if value.hasSuffix(".") {
                value.removeLast()
            }
            guard !value.isEmpty, !value.contains(where: \.isWhitespace) else {
                throw HyperlightRuntime.RuntimeError.invalidConfiguration(
                    "network host entries must be non-empty hostnames or IP addresses"
                )
            }
            if seen.insert(value).inserted {
                normalized.append(value)
            }
        }
        return normalized
    }

    private func containsWildcard(_ entry: String) -> Bool {
        entry.contains("*") || entry.contains("?")
    }

    private func isDomainWildcard(_ entry: String) -> Bool {
        guard entry.hasPrefix("*.") else {
            return false
        }
        let suffix = String(entry.dropFirst(2))
        return !suffix.isEmpty && !containsWildcard(suffix)
    }

    private func blockedPattern(_ blocked: String, covers allowed: String) -> Bool {
        if blocked == allowed {
            return true
        }

        if !containsWildcard(allowed) {
            return host(allowed, matches: blocked)
        }

        guard isDomainWildcard(allowed), isDomainWildcard(blocked) else {
            return false
        }
        let allowedSuffix = String(allowed.dropFirst(2))
        let blockedSuffix = String(blocked.dropFirst(2))
        return allowedSuffix == blockedSuffix
            || allowedSuffix.hasSuffix(".\(blockedSuffix)")
    }

    private func host(_ host: String, matches pattern: String) -> Bool {
        guard isDomainWildcard(pattern) else {
            return host == pattern
        }
        let suffix = String(pattern.dropFirst(2))
        return host == suffix || host.hasSuffix(".\(suffix)")
    }
}
