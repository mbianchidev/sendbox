import Foundation
import Yams

/// Main configuration for a SendBox sandbox instance.
public struct SandboxConfiguration: Codable, Sendable {
    /// Name identifier for this sandbox
    public var name: String

    /// Path to the project to sandbox
    public var projectPath: String

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

    // MARK: - CodingKeys

    private enum CodingKeys: String, CodingKey {
        case name
        case projectPath = "project_path"
        case resources
        case policy
        case secrets
        case devcontainer
        case github
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
        /// SSH key path to mount (optional)
        public var sshKeyPath: String?

        private enum CodingKeys: String, CodingKey {
            case forwardAuth = "forward_auth"
            case forwardCopilotAuth = "forward_copilot_auth"
            case sshKeyPath = "ssh_key_path"
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
                sshKeyPath: nil
            )
        )
    }
}
