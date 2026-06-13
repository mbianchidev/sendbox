import Foundation

/// Observability configuration for a SendBox sandbox.
///
/// Currently exposes eBPF-based inspection of Model Context Protocol (MCP) traffic
/// exchanged between the sandboxed agent and the MCP servers it talks to.
public struct ObservabilityConfig: Codable, Sendable {
    /// MCP call inspection settings.
    public var mcpInspection: MCPInspectionConfig

    private enum CodingKeys: String, CodingKey {
        case mcpInspection = "mcp_inspection"
    }

    public init(mcpInspection: MCPInspectionConfig) {
        self.mcpInspection = mcpInspection
    }

    /// Decodes with sensible defaults so existing configs without an
    /// `observability` section keep working.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mcpInspection = try container.decodeIfPresent(
            MCPInspectionConfig.self, forKey: .mcpInspection
        ) ?? .default
    }

    // MARK: - MCP Inspection

    /// Settings controlling the eBPF MCP inspector.
    public struct MCPInspectionConfig: Codable, Sendable {
        /// MCP transports to inspect.
        public enum Transport: String, Codable, Sendable, CaseIterable {
            /// stdio JSON-RPC between the agent and a local MCP server child process.
            case stdio
            /// HTTP / SSE (streamable HTTP) JSON-RPC, captured as TLS plaintext.
            case http
        }

        /// Whether MCP inspection is enabled. When `false`, no eBPF program is loaded.
        public var enabled: Bool

        /// Transports to trace.
        public var transports: [Transport]

        /// When `false`, captured payloads are reduced to metadata only
        /// (JSON-RPC method, id, tool name) and argument/result values are redacted.
        public var capturePayloads: Bool

        /// Maximum number of payload bytes captured per message.
        public var maxPayloadBytes: Int

        /// Path (inside the guest) where the inspector writes its trace log.
        public var logPath: String

        /// argv substrings that identify an MCP server process at `execve` time.
        public var serverCommandPatterns: [String]

        private enum CodingKeys: String, CodingKey {
            case enabled
            case transports
            case capturePayloads = "capture_payloads"
            case maxPayloadBytes = "max_payload_bytes"
            case logPath = "log_path"
            case serverCommandPatterns = "server_command_patterns"
        }

        public init(
            enabled: Bool,
            transports: [Transport],
            capturePayloads: Bool,
            maxPayloadBytes: Int,
            logPath: String,
            serverCommandPatterns: [String]
        ) {
            self.enabled = enabled
            self.transports = transports
            self.capturePayloads = capturePayloads
            self.maxPayloadBytes = maxPayloadBytes
            self.logPath = logPath
            self.serverCommandPatterns = serverCommandPatterns
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            let base = MCPInspectionConfig.default
            self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? base.enabled
            self.transports = try c.decodeIfPresent([Transport].self, forKey: .transports)
                ?? base.transports
            self.capturePayloads = try c.decodeIfPresent(Bool.self, forKey: .capturePayloads)
                ?? base.capturePayloads
            self.maxPayloadBytes = try c.decodeIfPresent(Int.self, forKey: .maxPayloadBytes)
                ?? base.maxPayloadBytes
            self.logPath = try c.decodeIfPresent(String.self, forKey: .logPath) ?? base.logPath
            self.serverCommandPatterns = try c.decodeIfPresent(
                [String].self, forKey: .serverCommandPatterns
            ) ?? base.serverCommandPatterns
        }

        /// Disabled by default; opt-in via config or `--inspect-mcp`.
        public static let `default` = MCPInspectionConfig(
            enabled: false,
            transports: [.stdio, .http],
            capturePayloads: true,
            maxPayloadBytes: 16384,
            logPath: "/var/log/sendbox/mcp-trace.log",
            serverCommandPatterns: [
                "mcp-server",
                "mcp_server",
                "modelcontextprotocol",
                "model-context-protocol",
                "@modelcontextprotocol",
                "mcp-remote",
                "server-mcp",
                "--mcp",
                "mcp.server",
            ]
        )
    }

    /// Observability disabled by default.
    public static let `default` = ObservabilityConfig(mcpInspection: .default)
}
