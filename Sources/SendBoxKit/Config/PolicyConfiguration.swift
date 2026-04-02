import Foundation

/// Security policy for command filtering and network access.
public struct PolicyConfiguration: Codable, Sendable {
    /// Command execution policy
    public var commands: CommandPolicyConfig

    /// Network access policy
    public var network: NetworkPolicyConfig

    // MARK: - Command Policy

    public struct CommandPolicyConfig: Codable, Sendable {
        /// Default action when no rule matches
        public var defaultAction: Action
        /// Allowed command patterns (glob-style)
        public var allowlist: [String]
        /// Denied command patterns (glob-style)
        public var denylist: [String]
        /// Whether to log blocked commands
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
    }

    // MARK: - Network Policy

    public struct NetworkPolicyConfig: Codable, Sendable {
        /// Default action for unmatched domains
        public var defaultAction: CommandPolicyConfig.Action
        /// Allowed domains (exact or wildcard like *.github.com)
        public var allowedDomains: [String]
        /// Blocked domains
        public var blockedDomains: [String]
        /// Whether to allow DNS resolution
        public var allowDNS: Bool
        /// Maximum outbound connections
        public var maxConnections: Int?

        private enum CodingKeys: String, CodingKey {
            case defaultAction = "default_action"
            case allowedDomains = "allowed_domains"
            case blockedDomains = "blocked_domains"
            case allowDNS = "allow_dns"
            case maxConnections = "max_connections"
        }
    }

    // MARK: - Presets

    /// Default-deny for commands (common dev tools allowed),
    /// default-deny for network (major registries and GitHub allowed).
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
        )
    )

    /// Default-allow with dangerous commands blocked.
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
        )
    )

    /// Very restrictive — only safe read-only commands,
    /// network limited to github.com.
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
        )
    )
}
