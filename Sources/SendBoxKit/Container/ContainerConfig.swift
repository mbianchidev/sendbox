import Foundation

/// Internal container configuration derived from SandboxConfiguration.
/// Maps user-facing config to the low-level container runtime parameters.
public struct ContainerConfig: Sendable {
    /// Unique container identifier
    public let id: String
    /// Container hostname
    public let hostname: String
    /// Number of CPUs
    public let cpus: Int
    /// Memory in bytes
    public let memoryInBytes: UInt64
    /// Root filesystem size in bytes
    public let rootfsSizeInBytes: UInt64
    /// Container image reference (e.g., "docker.io/library/ubuntu:22.04")
    public let imageReference: String
    /// Working directory inside the container
    public let workingDirectory: String
    /// Initial command to run
    public let command: [String]
    /// Environment variables
    public var environment: [String: String]
    /// Host directories to mount (source -> destination)
    public var mounts: [MountPoint]
    /// Network configuration
    public var network: NetworkConfig
    /// Firewall startup script content
    public var firewallScript: String?
    /// DNS configuration content
    public var dnsConfig: String?
    /// eBPF MCP inspector startup script content
    public var mcpInspectionScript: String?
    /// Prefix applied to every runtime exec so seccomp is inherited.
    public let boundaryExecPrefix: [String]
    /// Guest readiness marker created only after fail-closed setup succeeds.
    public let boundaryReadyPath: String?

    public struct MountPoint: Sendable {
        public let source: String
        public let destination: String
        public let readOnly: Bool

        public init(source: String, destination: String, readOnly: Bool) {
            self.source = source
            self.destination = destination
            self.readOnly = readOnly
        }
    }

    public struct NetworkConfig: Sendable {
        public let address: String
        public let gateway: String
        public let nameservers: [String]

        public init(address: String, gateway: String, nameservers: [String]) {
            self.address = address
            self.gateway = gateway
            self.nameservers = nameservers
        }
    }

    public init(
        id: String,
        hostname: String,
        cpus: Int,
        memoryInBytes: UInt64,
        rootfsSizeInBytes: UInt64,
        imageReference: String,
        workingDirectory: String,
        command: [String],
        environment: [String: String],
        mounts: [MountPoint],
        network: NetworkConfig,
        firewallScript: String? = nil,
        dnsConfig: String? = nil,
        mcpInspectionScript: String? = nil,
        boundaryExecPrefix: [String] = [],
        boundaryReadyPath: String? = nil
    ) {
        self.id = id
        self.hostname = hostname
        self.cpus = cpus
        self.memoryInBytes = memoryInBytes
        self.rootfsSizeInBytes = rootfsSizeInBytes
        self.imageReference = imageReference
        self.workingDirectory = workingDirectory
        self.command = command
        self.environment = environment
        self.mounts = mounts
        self.network = network
        self.firewallScript = firewallScript
        self.dnsConfig = dnsConfig
        self.mcpInspectionScript = mcpInspectionScript
        self.boundaryExecPrefix = boundaryExecPrefix
        self.boundaryReadyPath = boundaryReadyPath
    }

    /// Create from a SandboxConfiguration.
    ///
    /// Maps user-facing sandbox settings to low-level container runtime parameters:
    /// - Generates a UUID-based container ID
    /// - Converts memory/disk from MB to bytes
    /// - Mounts the .devcontainer directory (read-only) and workspace copy (read-write)
    /// - Sets up default NAT networking on the 192.168.64.x subnet
    /// - Injects firewall rules and DNS config from the NetworkFirewall
    /// - Provides default environment variables (PATH, HOME, TERM, LANG)
    public static func from(
        sandbox: SandboxConfiguration,
        imageReference: String,
        firewall: NetworkFirewall,
        mcpInspector: MCPInspector? = nil,
        boundaryEnforcer: BoundaryEnforcer? = nil
    ) -> ContainerConfig {
        let containerId = UUID().uuidString.lowercased()

        let memoryBytes = UInt64(sandbox.resources.memoryMB).multiplied(by: 1024 * 1024)
        let diskBytes = UInt64(sandbox.resources.diskSizeMB).multiplied(by: 1024 * 1024)

        let projectURL = URL(fileURLWithPath: sandbox.projectPath)
        let devcontainerSource = projectURL
            .appendingPathComponent(".devcontainer")
            .path

        let workspaceSource = projectURL.path
        let workspaceName = projectURL.lastPathComponent
        let workspaceDestination = "/workspaces/\(workspaceName)"

        var mountPoints: [MountPoint] = []

        mountPoints.append(MountPoint(
            source: devcontainerSource,
            destination: "/workspaces/\(workspaceName)/.devcontainer",
            readOnly: true
        ))

        mountPoints.append(MountPoint(
            source: workspaceSource,
            destination: workspaceDestination,
            readOnly: false
        ))

        let networkConfig = NetworkConfig(
            address: "192.168.64.2/24",
            gateway: "192.168.64.1",
            nameservers: ["192.168.64.1", "1.1.1.1"]
        )

        var environment: [String: String] = [
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
            "SENDBOX_WORKING_DIRECTORY": workspaceDestination,
        ]

        let firewallScript = firewall.generateStartupScript()
        let dnsConfig = firewall.generateDNSConfig()
        let mcpScript = mcpInspector?.generateStartupScript()
        let baseCommand = ["/bin/bash"]

        let command: [String]
        let deferredFirewallScript: String?
        let deferredMCPInspectionScript: String?
        let boundaryExecPrefix: [String]
        let boundaryReadyPath: String?

        if let boundaryEnforcer {
            let preflightScripts = [firewallScript, mcpScript]
                .compactMap { $0 }
                .filter { !$0.isEmpty }
            command = [
                "/bin/bash",
                "-lc",
                boundaryEnforcer.generateBootstrapScript(
                    command: baseCommand,
                    preflightScripts: preflightScripts
                ),
            ]
            deferredFirewallScript = nil
            deferredMCPInspectionScript = nil
            boundaryExecPrefix = boundaryEnforcer.execPrefix
            boundaryReadyPath = BoundaryEnforcer.readyPath
            environment["HOME"] = "/home/sendbox"
            environment["SENDBOX_MCP_PROXY"] = BoundaryEnforcer.proxyPath
        } else {
            command = baseCommand
            deferredFirewallScript = firewallScript.isEmpty ? nil : firewallScript
            deferredMCPInspectionScript = (mcpScript?.isEmpty ?? true) ? nil : mcpScript
            boundaryExecPrefix = []
            boundaryReadyPath = nil
        }

        return ContainerConfig(
            id: containerId,
            hostname: sandbox.name,
            cpus: sandbox.resources.cpus,
            memoryInBytes: memoryBytes,
            rootfsSizeInBytes: diskBytes,
            imageReference: imageReference,
            workingDirectory: workspaceDestination,
            command: command,
            environment: environment,
            mounts: mountPoints,
            network: networkConfig,
            firewallScript: deferredFirewallScript,
            dnsConfig: dnsConfig.isEmpty ? nil : dnsConfig,
            mcpInspectionScript: deferredMCPInspectionScript,
            boundaryExecPrefix: boundaryExecPrefix,
            boundaryReadyPath: boundaryReadyPath
        )
    }
}

// MARK: - Helpers

extension UInt64 {
    fileprivate func multiplied(by factor: UInt64) -> UInt64 {
        let (result, overflow) = self.multipliedReportingOverflow(by: factor)
        precondition(!overflow, "UInt64 overflow when computing \(self) * \(factor)")
        return result
    }
}
