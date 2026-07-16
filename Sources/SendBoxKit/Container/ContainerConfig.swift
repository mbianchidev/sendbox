import Foundation

/// Internal container configuration derived from SandboxConfiguration.
/// Maps user-facing config to the low-level container runtime parameters.
public struct ContainerConfig: Sendable {
    static let runtimeBootstrapCommand = ["/bin/bash"]

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
        public let allowsUnrestrictedOutbound: Bool
        public let allowedHosts: [String]
        public let blockedHosts: [String]
        public let allowDNS: Bool
        public let maxConnections: Int?

        public init(
            address: String,
            gateway: String,
            nameservers: [String],
            allowsUnrestrictedOutbound: Bool = false,
            allowedHosts: [String] = [],
            blockedHosts: [String] = [],
            allowDNS: Bool = true,
            maxConnections: Int? = nil
        ) {
            self.address = address
            self.gateway = gateway
            self.nameservers = nameservers
            self.allowsUnrestrictedOutbound = allowsUnrestrictedOutbound
            self.allowedHosts = allowedHosts
            self.blockedHosts = blockedHosts
            self.allowDNS = allowDNS
            self.maxConnections = maxConnections
        }
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
        mcpInspector: MCPInspector? = nil
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
            nameservers: ["192.168.64.1", "1.1.1.1"],
            allowsUnrestrictedOutbound: sandbox.policy.network.defaultAction == .allow,
            allowedHosts: sandbox.policy.network.allowedDomains,
            blockedHosts: sandbox.policy.network.blockedDomains,
            allowDNS: sandbox.policy.network.allowDNS,
            maxConnections: sandbox.policy.network.maxConnections
        )

        let environment: [String: String] = [
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
        ]

        let firewallScript = firewall.generateStartupScript()
        let dnsConfig = firewall.generateDNSConfig()
        let mcpScript = mcpInspector?.generateStartupScript()

        return ContainerConfig(
            id: containerId,
            hostname: sandbox.name,
            cpus: sandbox.resources.cpus,
            memoryInBytes: memoryBytes,
            rootfsSizeInBytes: diskBytes,
            imageReference: imageReference,
            workingDirectory: workspaceDestination,
            command: runtimeBootstrapCommand,
            environment: environment,
            mounts: mountPoints,
            network: networkConfig,
            firewallScript: firewallScript.isEmpty ? nil : firewallScript,
            dnsConfig: dnsConfig.isEmpty ? nil : dnsConfig,
            mcpInspectionScript: (mcpScript?.isEmpty ?? true) ? nil : mcpScript
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
