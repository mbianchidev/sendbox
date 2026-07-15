import Foundation

/// Security policy for command, network, syscall, and MCP tool-call access.
public struct PolicyConfiguration: Codable, Sendable {
    public var commands: CommandPolicyConfig
    public var network: NetworkPolicyConfig
    public var boundaries: BoundaryPolicyConfig

    private enum CodingKeys: String, CodingKey {
        case commands
        case network
        case boundaries
    }

    public init(
        commands: CommandPolicyConfig,
        network: NetworkPolicyConfig,
        boundaries: BoundaryPolicyConfig = .default
    ) {
        self.commands = commands
        self.network = network
        self.boundaries = boundaries
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.commands = try container.decode(CommandPolicyConfig.self, forKey: .commands)
        self.network = try container.decode(NetworkPolicyConfig.self, forKey: .network)
        self.boundaries =
            try container.decodeIfPresent(
                BoundaryPolicyConfig.self,
                forKey: .boundaries
            ) ?? .default
    }

    // MARK: - Command Policy

    public struct CommandPolicyConfig: Codable, Sendable {
        public var defaultAction: Action
        public var allowlist: [String]
        public var denylist: [String]
        public var logBlocked: Bool

        public enum Action: String, Codable, Sendable {
            case allow
            case deny
        }

        private enum CodingKeys: String, CodingKey {
            case defaultAction = "default_action"
            case allowlist
            case denylist
            case logBlocked = "log_blocked"
        }

        public init(
            defaultAction: Action,
            allowlist: [String],
            denylist: [String],
            logBlocked: Bool
        ) {
            self.defaultAction = defaultAction
            self.allowlist = allowlist
            self.denylist = denylist
            self.logBlocked = logBlocked
        }
    }

    // MARK: - Network Policy

    public struct NetworkPolicyConfig: Codable, Sendable {
        public var defaultAction: CommandPolicyConfig.Action
        public var allowedDomains: [String]
        public var blockedDomains: [String]
        public var allowDNS: Bool
        public var maxConnections: Int?

        private enum CodingKeys: String, CodingKey {
            case defaultAction = "default_action"
            case allowedDomains = "allowed_domains"
            case blockedDomains = "blocked_domains"
            case allowDNS = "allow_dns"
            case maxConnections = "max_connections"
        }

        public init(
            defaultAction: CommandPolicyConfig.Action,
            allowedDomains: [String],
            blockedDomains: [String],
            allowDNS: Bool,
            maxConnections: Int?
        ) {
            self.defaultAction = defaultAction
            self.allowedDomains = allowedDomains
            self.blockedDomains = blockedDomains
            self.allowDNS = allowDNS
            self.maxConnections = maxConnections
        }
    }

    // MARK: - Boundary Policy

    public struct BoundaryPolicyConfig: Codable, Sendable {
        public var enabled: Bool
        public var toolCalls: ToolCallPolicyConfig
        public var syscalls: SyscallPolicyConfig
        public var logPath: String

        private enum CodingKeys: String, CodingKey {
            case enabled
            case toolCalls = "tool_calls"
            case syscalls
            case logPath = "log_path"
        }

        public init(
            enabled: Bool,
            toolCalls: ToolCallPolicyConfig,
            syscalls: SyscallPolicyConfig,
            logPath: String
        ) {
            self.enabled = enabled
            self.toolCalls = toolCalls
            self.syscalls = syscalls
            self.logPath = logPath
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let base = BoundaryPolicyConfig.default
            self.enabled =
                try container.decodeIfPresent(Bool.self, forKey: .enabled)
                ?? base.enabled
            self.toolCalls =
                try container.decodeIfPresent(
                    ToolCallPolicyConfig.self,
                    forKey: .toolCalls
                ) ?? base.toolCalls
            self.syscalls =
                try container.decodeIfPresent(
                    SyscallPolicyConfig.self,
                    forKey: .syscalls
                ) ?? base.syscalls
            self.logPath =
                try container.decodeIfPresent(String.self, forKey: .logPath)
                ?? base.logPath
        }

        public static let `default` = BoundaryPolicyConfig(
            enabled: true,
            toolCalls: .default,
            syscalls: .default,
            logPath: "/var/log/sendbox/boundary.log"
        )

        public static let permissive = BoundaryPolicyConfig(
            enabled: true,
            toolCalls: .permissive,
            syscalls: .default,
            logPath: "/var/log/sendbox/boundary.log"
        )

        public static let strict = BoundaryPolicyConfig(
            enabled: true,
            toolCalls: .strict,
            syscalls: .default,
            logPath: "/var/log/sendbox/boundary.log"
        )
    }

    public struct ToolCallPolicyConfig: Codable, Sendable {
        public enum Transport: String, Codable, Sendable {
            case stdio
        }

        public var transport: Transport
        public var defaultAction: CommandPolicyConfig.Action
        public var allowlist: [String]
        public var denylist: [String]
        public var maxFrameBytes: Int
        public var serverCommandPatterns: [String]
        public var allowedServerCommands: [[String]]

        private enum CodingKeys: String, CodingKey {
            case transport
            case defaultAction = "default_action"
            case allowlist
            case denylist
            case maxFrameBytes = "max_frame_bytes"
            case serverCommandPatterns = "server_command_patterns"
            case allowedServerCommands = "allowed_server_commands"
        }

        public init(
            transport: Transport = .stdio,
            defaultAction: CommandPolicyConfig.Action,
            allowlist: [String],
            denylist: [String],
            maxFrameBytes: Int,
            serverCommandPatterns: [String] = ToolCallPolicyConfig
                .defaultServerCommandPatterns,
            allowedServerCommands: [[String]] = []
        ) {
            self.transport = transport
            self.defaultAction = defaultAction
            self.allowlist = allowlist
            self.denylist = denylist
            self.maxFrameBytes = maxFrameBytes
            self.serverCommandPatterns = serverCommandPatterns
            self.allowedServerCommands = allowedServerCommands
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let base = ToolCallPolicyConfig.default
            self.transport =
                try container.decodeIfPresent(Transport.self, forKey: .transport)
                ?? base.transport
            self.defaultAction =
                try container.decodeIfPresent(
                    CommandPolicyConfig.Action.self,
                    forKey: .defaultAction
                ) ?? base.defaultAction
            self.allowlist =
                try container.decodeIfPresent([String].self, forKey: .allowlist)
                ?? base.allowlist
            self.denylist =
                try container.decodeIfPresent([String].self, forKey: .denylist)
                ?? base.denylist
            self.maxFrameBytes =
                try container.decodeIfPresent(Int.self, forKey: .maxFrameBytes)
                ?? base.maxFrameBytes
            self.serverCommandPatterns =
                try container.decodeIfPresent(
                    [String].self,
                    forKey: .serverCommandPatterns
                ) ?? base.serverCommandPatterns
            self.allowedServerCommands =
                try container.decodeIfPresent(
                    [[String]].self,
                    forKey: .allowedServerCommands
                ) ?? base.allowedServerCommands
        }

        public static let defaultServerCommandPatterns = [
            "mcp-server",
            "mcp_server",
            "modelcontextprotocol",
            "model-context-protocol",
            "@modelcontextprotocol",
            "mcp-remote",
            "server-mcp",
            "mcp.server",
        ]

        public static let `default` = ToolCallPolicyConfig(
            defaultAction: .deny,
            allowlist: [],
            denylist: [],
            maxFrameBytes: 1_048_576,
            serverCommandPatterns: defaultServerCommandPatterns,
            allowedServerCommands: []
        )

        public static let permissive = ToolCallPolicyConfig(
            defaultAction: .allow,
            allowlist: [],
            denylist: [],
            maxFrameBytes: 1_048_576,
            serverCommandPatterns: defaultServerCommandPatterns,
            allowedServerCommands: []
        )

        public static let strict = ToolCallPolicyConfig(
            defaultAction: .deny,
            allowlist: [],
            denylist: [],
            maxFrameBytes: 262_144,
            serverCommandPatterns: defaultServerCommandPatterns,
            allowedServerCommands: []
        )
    }

    public struct SyscallPolicyConfig: Codable, Sendable {
        public var additionalDenylist: [String]
        public var logBlocked: Bool

        private enum CodingKeys: String, CodingKey {
            case additionalDenylist = "additional_denylist"
            case logBlocked = "log_blocked"
        }

        public init(additionalDenylist: [String], logBlocked: Bool) {
            self.additionalDenylist = additionalDenylist
            self.logBlocked = logBlocked
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let base = SyscallPolicyConfig.default
            self.additionalDenylist =
                try container.decodeIfPresent(
                    [String].self,
                    forKey: .additionalDenylist
                ) ?? base.additionalDenylist
            self.logBlocked =
                try container.decodeIfPresent(Bool.self, forKey: .logBlocked)
                ?? base.logBlocked
        }

        public static let `default` = SyscallPolicyConfig(
            additionalDenylist: [],
            logBlocked: true
        )
    }

    // MARK: - Presets

    public static let `default` = PolicyConfiguration(
        commands: CommandPolicyConfig(
            defaultAction: .deny,
            allowlist: [
                "git", "npm", "npx", "yarn", "pnpm",
                "pip", "pip3", "python", "python3", "node",
                "make", "cmake", "cargo", "go", "rustc", "gcc", "g++",
                "curl", "cat", "ls", "find", "grep", "sed", "awk",
                "head", "tail", "echo", "env", "which", "whoami",
                "mkdir", "cp", "mv", "touch", "rm",
                "swift", "swiftc", "xcodebuild",
            ],
            denylist: [],
            logBlocked: true
        ),
        network: NetworkPolicyConfig(
            defaultAction: .deny,
            allowedDomains: [
                "github.com",
                "*.github.com",
                "*.githubusercontent.com",
                "registry.npmjs.org",
                "pypi.org",
                "*.pypi.org",
                "rubygems.org",
                "crates.io",
                "proxy.golang.org",
                "*.docker.io",
                "*.docker.com",
            ],
            blockedDomains: [],
            allowDNS: true,
            maxConnections: nil
        ),
        boundaries: .default
    )

    public static let permissive = PolicyConfiguration(
        commands: CommandPolicyConfig(
            defaultAction: .allow,
            allowlist: [],
            denylist: [
                "sudo", "su",
                "mount", "umount",
                "fdisk", "mkfs", "dd",
                "shutdown", "reboot", "halt", "poweroff",
                "systemctl", "service",
                "iptables", "ip6tables", "nft",
                "passwd", "useradd", "userdel", "usermod",
                "groupadd", "groupdel",
                "chown", "chmod 777",
            ],
            logBlocked: true
        ),
        network: NetworkPolicyConfig(
            defaultAction: .allow,
            allowedDomains: [],
            blockedDomains: [],
            allowDNS: true,
            maxConnections: nil
        ),
        boundaries: .permissive
    )

    public static let strict = PolicyConfiguration(
        commands: CommandPolicyConfig(
            defaultAction: .deny,
            allowlist: [
                "cat", "ls", "find", "grep",
                "head", "tail", "echo", "env", "which", "whoami",
                "wc", "sort", "uniq", "diff",
                "git status", "git log", "git diff", "git show",
            ],
            denylist: [],
            logBlocked: true
        ),
        network: NetworkPolicyConfig(
            defaultAction: .deny,
            allowedDomains: [
                "github.com",
                "*.github.com",
            ],
            blockedDomains: [],
            allowDNS: true,
            maxConnections: 10
        ),
        boundaries: .strict
    )
}
