import Foundation
import Logging

#if canImport(Containerization)
import Containerization

/// Manages the lifecycle of sandboxed Linux containers using Apple's Containerization framework.
///
/// This actor wraps the `ContainerManager` from `apple/containerization` to provide
/// a higher-level API for creating, running, and managing sandbox containers with
/// integrated command-policy enforcement.
public actor ContainerRuntime: RuntimeProvider {
    private let logger: Logger
    private var manager: ContainerManager?
    private var activeContainers: [String: ContainerHandle]

    public typealias ContainerStatus = RuntimeContainerStatus

    public struct ContainerHandle: Sendable {
        public let id: String
        public let status: ContainerStatus
        /// Reference to the underlying container (held internally)
        let container: LinuxContainer?

        public init(id: String, status: ContainerStatus, container: LinuxContainer? = nil) {
            self.id = id
            self.status = status
            self.container = container
        }
    }

    public enum RuntimeError: Error, LocalizedError {
        case notInitialized
        case containerNotFound(String)
        case containerAlreadyExists(String)
        case imagePullFailed(String)
        case startFailed(String)
        case kernelNotFound
        case commandDenied(String)
        case execFailed(String)

        public var errorDescription: String? {
            switch self {
            case .notInitialized:
                return "Container runtime has not been initialized"
            case .containerNotFound(let id):
                return "Container not found: \(id)"
            case .containerAlreadyExists(let id):
                return "Container already exists: \(id)"
            case .imagePullFailed(let reason):
                return "Failed to pull image: \(reason)"
            case .startFailed(let reason):
                return "Failed to start container: \(reason)"
            case .kernelNotFound:
                return "Linux kernel binary not found at any known path"
            case .commandDenied(let reason):
                return "Command denied by policy: \(reason)"
            case .execFailed(let reason):
                return "Failed to execute command: \(reason)"
            }
        }
    }

    public init(logger: Logger = Logger(label: "sendbox.runtime")) {
        self.logger = logger
        self.activeContainers = [:]
    }

    // MARK: - Initialization

    /// Initialize the container manager with an optional kernel path.
    ///
    /// Locates a Linux kernel binary (or uses the provided path), then creates
    /// a `ContainerManager` backed by macOS Virtualization.framework.
    public func initialize() async throws {
        try await initialize(kernelPath: nil)
    }

    public func initialize(kernelPath: String?) async throws {
        let resolvedPath: String
        if let kernelPath {
            resolvedPath = kernelPath
        } else if let detected = findKernelPath() {
            resolvedPath = detected
        } else {
            throw RuntimeError.kernelNotFound
        }

        let kernelURL = URL(fileURLWithPath: resolvedPath)
        guard FileManager.default.fileExists(atPath: resolvedPath) else {
            throw RuntimeError.kernelNotFound
        }

        logger.info("Initializing container runtime with kernel: \(resolvedPath)")

        let kernel = Kernel(path: kernelURL, platform: .linuxArm)

        // The ContainerManager requires an initfs mount and optionally a network.
        // Use the default image store and set up a vmnet-backed NAT network.
        let imageStore = ImageStore.default

        // Build an initfs block from the image store's default init image.
        // The init image is pulled automatically if not present locally.
        let initfsPath = imageStore.path.appendingPathComponent("initfs.ext4")
        let initfs: Mount
        if FileManager.default.fileExists(atPath: initfsPath.path) {
            initfs = .block(
                format: "ext4",
                source: initfsPath.path,
                destination: "/",
                options: ["ro"]
            )
        } else {
            // Pull and unpack the default init image.
            // TODO: Make the init image reference configurable.
            let initImage = try await imageStore.getInitImage(
                reference: "ghcr.io/apple/containerization/init:latest"
            )
            initfs = try await initImage.initBlock(at: initfsPath, for: .linuxArm)
        }

        // Create the vmnet-backed NAT network (requires macOS 26+).
        // Falls back to no networking on earlier OS versions.
        if #available(macOS 26.0, *) {
            let network = try ContainerManager.VmnetNetwork()
            self.manager = try ContainerManager(
                kernel: kernel,
                initfs: initfs,
                imageStore: imageStore,
                network: network
            )
        } else {
            self.manager = try ContainerManager(
                kernel: kernel,
                initfs: initfs,
                imageStore: imageStore
            )
        }

        logger.info("Container runtime initialized successfully")
    }

    // MARK: - Container Lifecycle

    /// Create and start a container from a `ContainerConfig`.
    ///
    /// Pulls the image if needed, creates the container with the specified
    /// resources, mounts, and networking, then starts it.
    ///
    /// - Returns: The container ID.
    @discardableResult
    public func createContainer(
        _ config: ContainerConfig,
        policy: CommandPolicy
    ) async throws -> String {
        guard var mgr = manager else {
            throw RuntimeError.notInitialized
        }

        if activeContainers[config.id] != nil {
            throw RuntimeError.containerAlreadyExists(config.id)
        }

        let decision = await policy.evaluate(config.command)
        guard decision.isAllowed else {
            if case .denied(let reason) = decision {
                throw RuntimeError.commandDenied(reason)
            }
            throw RuntimeError.commandDenied("Startup command blocked by policy")
        }

        logger.info("Creating container \(config.id) from image \(config.imageReference)")

        activeContainers[config.id] = ContainerHandle(
            id: config.id,
            status: .creating
        )

        do {
            // Build environment in KEY=VALUE format expected by the runtime.
            let envVars = config.environment.map { "\($0.key)=\($0.value)" }

            let container = try await mgr.create(
                config.id,
                reference: config.imageReference,
                rootfsSizeInBytes: config.rootfsSizeInBytes
            ) { containerConfig in
                containerConfig.cpus = config.cpus
                containerConfig.memoryInBytes = config.memoryInBytes
                containerConfig.hostname = config.hostname

                containerConfig.process.arguments = config.command
                containerConfig.process.environmentVariables = envVars
                containerConfig.process.workingDirectory = config.workingDirectory

                // Add virtiofs mounts for host directories.
                for mount in config.mounts {
                    var options: [String] = []
                    if mount.readOnly {
                        options.append("ro")
                    }
                    containerConfig.mounts.append(
                        .share(
                            source: mount.source,
                            destination: mount.destination,
                            options: options
                        )
                    )
                }

                // DNS configuration
                containerConfig.dns = DNS(
                    nameservers: config.network.nameservers
                )
            }

            // Persist the manager state back (ContainerManager is a value type).
            self.manager = mgr

            try await container.create()
            try await container.start()

            // Inject firewall rules after container starts, if configured.
            if let firewallScript = config.firewallScript, !firewallScript.isEmpty {
                logger.info("Injecting firewall rules into container \(config.id)")
                await injectBootScript(
                    firewallScript,
                    name: "firewall",
                    guestPath: "/run/sendbox-firewall.sh",
                    container: container,
                    containerId: config.id
                )
            }

            // Inject and launch the eBPF MCP inspector, if configured.
            if let mcpScript = config.mcpInspectionScript, !mcpScript.isEmpty {
                logger.info("Injecting eBPF MCP inspector into container \(config.id)")
                await injectBootScript(
                    mcpScript,
                    name: "mcp-inspector",
                    guestPath: "/run/sendbox-mcp-setup.sh",
                    container: container,
                    containerId: config.id
                )
            }

            activeContainers[config.id] = ContainerHandle(
                id: config.id,
                status: .running,
                container: container
            )

            logger.info("Container \(config.id) started successfully")
            return config.id

        } catch {
            activeContainers[config.id] = ContainerHandle(
                id: config.id,
                status: .failed
            )
            self.manager = mgr
            logger.error("Failed to create container \(config.id): \(error)")
            throw RuntimeError.startFailed(error.localizedDescription)
        }
    }

    /// Stop a running container.
    public func stopContainer(id: String) async throws {
        guard let handle = activeContainers[id] else {
            throw RuntimeError.containerNotFound(id)
        }

        logger.info("Stopping container \(id)")

        if let container = handle.container {
            try await container.stop()
        }

        // Release network resources and clean up files.
        if var mgr = manager {
            try mgr.delete(id)
            self.manager = mgr
        }

        activeContainers[id] = ContainerHandle(
            id: id,
            status: .stopped
        )

        logger.info("Container \(id) stopped")
    }

    /// Get the current status of a container.
    public func containerStatus(id: String) async -> RuntimeContainerStatus {
        activeContainers[id]?.status ?? .unknown
    }

    // MARK: - Command Execution

    /// Execute a command inside a running container after checking the command policy.
    ///
    /// The command is first evaluated against the provided `CommandPolicy`. If denied,
    /// a `RuntimeError.commandDenied` is thrown without executing anything.
    public func exec(
        containerId: String,
        command: [String],
        policy: CommandPolicy
    ) async throws -> ExecResult {
        guard let handle = activeContainers[containerId],
              let container = handle.container else {
            throw RuntimeError.containerNotFound(containerId)
        }

        guard handle.status == .running else {
            throw RuntimeError.execFailed(
                "Container \(containerId) is not running (status: \(handle.status.rawValue))"
            )
        }

        let commandString = command.joined(separator: " ")
        let decision = await policy.evaluate(command)
        guard decision.isAllowed else {
            if case .denied(let reason) = decision {
                throw RuntimeError.commandDenied(reason)
            }
            throw RuntimeError.commandDenied("Command blocked by policy")
        }

        logger.info("Executing in \(containerId): \(commandString)")

        do {
            let execId = "exec-\(UUID().uuidString.prefix(8))"

            // Set up captured I/O via pipes.
            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()

            let process = try await container.exec(execId) { processConfig in
                processConfig.arguments = command
                processConfig.workingDirectory = "/workspaces"
                processConfig.terminal = false
            }

            try await process.start()
            let exitStatus = try await process.wait(timeoutInSeconds: 300)

            // Read captured output from pipes.
            // TODO: Wire up stdout/stderr readers once IO streaming is integrated.
            // For now, return the exit code with empty output placeholders.
            let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

            return ExecResult(
                exitCode: exitStatus.exitCode,
                stdout: String(data: stdoutData, encoding: .utf8) ?? "",
                stderr: String(data: stderrData, encoding: .utf8) ?? ""
            )

        } catch let error as RuntimeError {
            throw error
        } catch {
            throw RuntimeError.execFailed(error.localizedDescription)
        }
    }

    // MARK: - Boot Script Injection

    /// Write a boot script to a host temp file, copy it into the guest, and run it.
    ///
    /// Best-effort: failures are logged but never abort container startup, so a
    /// tracing or firewall hiccup cannot block the agent from running.
    private func injectBootScript(
        _ content: String,
        name: String,
        guestPath: String,
        container: LinuxContainer,
        containerId: String
    ) async {
        let hostURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("\(name)-\(containerId).sh")
        do {
            try Data(content.utf8).write(to: hostURL)
            try await container.copyIn(
                from: hostURL,
                to: URL(fileURLWithPath: guestPath),
                mode: 0o755
            )
            let execId = "\(name)-\(UUID().uuidString.prefix(8))"
            let process = try await container.exec(execId) { processConfig in
                processConfig.arguments = ["/bin/bash", guestPath]
                processConfig.workingDirectory = "/"
                processConfig.terminal = false
            }
            try await process.start()
            let status = try await process.wait(timeoutInSeconds: 60)
            if status.exitCode != 0 {
                logger.warning("Boot script \(name) exited with code \(status.exitCode) in \(containerId)")
            } else {
                logger.debug("Boot script \(name) applied in \(containerId)")
            }
        } catch {
            logger.warning("Failed to inject \(name) script into \(containerId): \(error)")
        }
        try? FileManager.default.removeItem(at: hostURL)
    }

    // MARK: - Output Streaming

    /// Attach to a container's output and stream lines as they arrive.
    ///
    /// Returns an `AsyncStream` that yields output lines from the container.
    /// The stream completes when the container stops or the caller cancels.
    public func attachOutput(containerId: String) async throws -> AsyncStream<String> {
        guard let handle = activeContainers[containerId],
              handle.container != nil else {
            throw RuntimeError.containerNotFound(containerId)
        }

        // TODO: Integrate with the container's stdout/stderr writers
        // to stream real output. For now, return a placeholder stream
        // that signals the attachment is active.
        return AsyncStream { continuation in
            continuation.yield("[sendbox] Attached to container \(containerId)")
            // The stream stays open until the consumer cancels.
            continuation.onTermination = { @Sendable _ in
                // Cleanup if needed when the stream consumer cancels.
            }
        }
    }

    // MARK: - Container Listing & Cleanup

    /// List all tracked containers.
    public func listContainers() -> [ContainerHandle] {
        Array(activeContainers.values)
    }

    /// Stop and remove all active containers.
    public func cleanup() async throws {
        logger.info("Cleaning up all containers")

        for (id, handle) in activeContainers {
            if handle.status == .running, let container = handle.container {
                do {
                    try await container.stop()
                } catch {
                    logger.warning("Failed to stop container \(id): \(error)")
                }
            }

            if var mgr = manager {
                do {
                    try mgr.delete(id)
                    self.manager = mgr
                } catch {
                    logger.warning("Failed to delete container \(id): \(error)")
                }
            }
        }

        activeContainers.removeAll()
        logger.info("All containers cleaned up")
    }

    // MARK: - Kernel Discovery

    /// Search common locations for a Linux kernel binary.
    private func findKernelPath() -> String? {
        let candidates = [
            "\(FileManager.default.homeDirectoryForCurrentUser.path)/.sendbox/kernel/vmlinux",
            "\(FileManager.default.homeDirectoryForCurrentUser.path)/.local/share/containerization/kernel/vmlinux",
            "/usr/local/share/containerization/kernel/vmlinux",
        ]

        for path in candidates {
            if FileManager.default.fileExists(atPath: path) {
                logger.debug("Found kernel at \(path)")
                return path
            }
        }

        logger.warning("No kernel binary found at any known path")
        return nil
    }
}
#endif
