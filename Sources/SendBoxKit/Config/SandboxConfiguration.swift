import Foundation
import Yams

/// Host runtime selection for a sandbox.
public struct RuntimeConfiguration: Codable, Sendable, Equatable {
    public enum Provider: String, Codable, Sendable, CaseIterable {
        case automatic = "auto"
        case apple
        case kata
    }

    public var provider: Provider
    public var kata: KataRuntimeConfiguration

    public static let `default` = RuntimeConfiguration()

    public init(
        provider: Provider = .automatic,
        kata: KataRuntimeConfiguration = .default
    ) {
        self.provider = provider
        self.kata = kata
    }

    private enum CodingKeys: String, CodingKey {
        case provider
        case kata
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.provider =
            try container.decodeIfPresent(Provider.self, forKey: .provider) ?? .automatic
        self.kata =
            try container.decodeIfPresent(KataRuntimeConfiguration.self, forKey: .kata) ?? .default
    }
}

/// nerdctl/containerd settings for the Kata Containers runtime provider.
public struct KataRuntimeConfiguration: Codable, Sendable, Equatable {
    public var executable: String
    public var runtimeHandler: String
    public var namespace: String
    public var address: String?
    public var snapshotter: String?
    public var configurationPath: String?

    public static let `default` = KataRuntimeConfiguration()

    public init(
        executable: String = "nerdctl",
        runtimeHandler: String = "io.containerd.kata.v2",
        namespace: String = "sendbox",
        address: String? = nil,
        snapshotter: String? = nil,
        configurationPath: String? = nil
    ) {
        self.executable = executable
        self.runtimeHandler = runtimeHandler
        self.namespace = namespace
        self.address = address
        self.snapshotter = snapshotter
        self.configurationPath = configurationPath
    }

    private enum CodingKeys: String, CodingKey {
        case executable
        case runtimeHandler = "runtime_handler"
        case namespace
        case address
        case snapshotter
        case configurationPath = "configuration_path"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.executable =
            try container.decodeIfPresent(String.self, forKey: .executable) ?? "nerdctl"
        self.runtimeHandler =
            try container.decodeIfPresent(String.self, forKey: .runtimeHandler)
            ?? "io.containerd.kata.v2"
        self.namespace = try container.decodeIfPresent(String.self, forKey: .namespace) ?? "sendbox"
        self.address = try container.decodeIfPresent(String.self, forKey: .address)
        self.snapshotter = try container.decodeIfPresent(String.self, forKey: .snapshotter)
        self.configurationPath = try container.decodeIfPresent(
            String.self,
            forKey: .configurationPath
        )
    }
}

/// Main configuration for a SendBox sandbox instance.
public struct SandboxConfiguration: Codable, Sendable {
    /// Name identifier for this sandbox
    public var name: String

    /// Path to the project to sandbox
    public var projectPath: String

    /// Host runtime provider and provider-specific settings
    public var runtime: RuntimeConfiguration?

    /// Container resource configuration
    public var resources: ResourceConfig

    /// Security policy configuration
    public var policy: PolicyConfiguration

    /// Secrets to inject into the container (references to secrets in the vault)
    public var secrets: [String]

    /// DevContainer configuration overrides
    public var devcontainer: DevContainerConfig?

    /// GitHub authentication configuration
    public var github: GitHubConfig

    /// Observability configuration (eBPF MCP inspection, etc.)
    public var observability: ObservabilityConfig?

    // MARK: - CodingKeys

    private enum CodingKeys: String, CodingKey {
        case name
        case projectPath = "project_path"
        case runtime
        case resources
        case policy
        case secrets
        case devcontainer
        case github
        case observability
    }

    // MARK: - Nested Types

    public struct ResourceConfig: Codable, Sendable {
        public var cpus: Int
        public var memoryMB: Int
        public var diskSizeMB: Int

        public static let `default` = ResourceConfig(cpus: 4, memoryMB: 4096, diskSizeMB: 10240)

        private enum CodingKeys: String, CodingKey {
            case cpus
            case memoryMB = "memory_mb"
            case diskSizeMB = "disk_size_mb"
        }
    }

    public struct DevContainerConfig: Codable, Sendable {
        /// Path to existing devcontainer.json (if any)
        public var configPath: String?
        /// Whether to auto-generate using Copilot SDK
        public var autoGenerate: Bool
        /// Additional VS Code extensions to install
        public var extensions: [String]

        private enum CodingKeys: String, CodingKey {
            case configPath = "config_path"
            case autoGenerate = "auto_generate"
            case extensions
        }
    }

    public struct GitHubConfig: Codable, Sendable {
        /// Whether to forward GitHub CLI auth to container
        public var forwardAuth: Bool
        /// Whether to forward Copilot CLI auth
        public var forwardCopilotAuth: Bool
        /// Allow credentials covering additional private repositories in the selected repo's organization.
        public var allowPrivateRepositoryAccess: Bool
        /// SSH key path to mount (optional)
        public var sshKeyPath: String?

        private enum CodingKeys: String, CodingKey {
            case forwardAuth = "forward_auth"
            case forwardCopilotAuth = "forward_copilot_auth"
            case allowPrivateRepositoryAccess = "allow_private_repository_access"
            case sshKeyPath = "ssh_key_path"
        }

        public init(
            forwardAuth: Bool,
            forwardCopilotAuth: Bool,
            allowPrivateRepositoryAccess: Bool = false,
            sshKeyPath: String? = nil
        ) {
            self.forwardAuth = forwardAuth
            self.forwardCopilotAuth = forwardCopilotAuth
            self.allowPrivateRepositoryAccess = allowPrivateRepositoryAccess
            self.sshKeyPath = sshKeyPath
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.forwardAuth = try container.decode(Bool.self, forKey: .forwardAuth)
            self.forwardCopilotAuth = try container.decode(Bool.self, forKey: .forwardCopilotAuth)
            self.allowPrivateRepositoryAccess =
                try container.decodeIfPresent(Bool.self, forKey: .allowPrivateRepositoryAccess)
                ?? false
            self.sshKeyPath = try container.decodeIfPresent(String.self, forKey: .sshKeyPath)
        }
    }
}

// MARK: - Loading & Saving

extension SandboxConfiguration {
    /// Load configuration from a YAML file at the given path.
    public static func load(from path: String) throws -> SandboxConfiguration {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        return try load(from: data)
    }

    /// Load configuration from raw YAML data.
    public static func load(from data: Data) throws -> SandboxConfiguration {
        let decoder = YAMLDecoder()
        return try decoder.decode(SandboxConfiguration.self, from: data)
    }

    /// Save configuration as YAML to the given path.
    public func save(to path: String) throws {
        let encoder = YAMLEncoder()
        let yamlString = try encoder.encode(self)
        let url = URL(fileURLWithPath: path)
        try yamlString.write(to: url, atomically: true, encoding: .utf8)
    }

    /// Returns a configuration with sensible defaults for the given project path.
    public static func `default`(projectPath: String) -> SandboxConfiguration {
        let projectName = URL(fileURLWithPath: projectPath).lastPathComponent
        return SandboxConfiguration(
            name: projectName,
            projectPath: projectPath,
            runtime: .default,
            resources: .default,
            policy: .default,
            secrets: [],
            devcontainer: DevContainerConfig(
                configPath: nil,
                autoGenerate: true,
                extensions: []
            ),
            github: GitHubConfig(
                forwardAuth: true,
                forwardCopilotAuth: true,
                allowPrivateRepositoryAccess: false,
                sshKeyPath: nil
            ),
            observability: .default
        )
    }
}
