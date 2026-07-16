import Foundation

/// Validates project-local MCP server definitions before boundary-enabled startup.
public struct MCPBoundaryValidator: Sendable {
    public static let configurationPaths = [
        ".mcp.json",
        ".vscode/mcp.json",
        ".github/copilot/mcp.json",
        ".cursor/mcp.json",
        ".claude/mcp.json",
    ]

    public enum ValidationError: Error, LocalizedError, Equatable {
        case invalidJSON(path: String)
        case remoteTransport(path: String, server: String)
        case missingProxy(path: String, server: String)
        case serverCommandNotAllowed(path: String, server: String)

        public var errorDescription: String? {
            switch self {
            case .invalidJSON(let path):
                return "Invalid MCP JSON configuration: \(path)"
            case .remoteTransport(let path, let server):
                return "Remote HTTP/SSE MCP server '\(server)' is not supported in boundary "
                    + "mode (\(path))"
            case .missingProxy(let path, let server):
                return "MCP server '\(server)' must use \(BoundaryEnforcer.proxyPath) -- "
                    + "as its stdio command prefix (\(path))"
            case .serverCommandNotAllowed(let path, let server):
                return "MCP server '\(server)' is not in boundary "
                    + "tool_calls.allowed_server_commands (\(path))"
            }
        }
    }

    private let allowedServerCommands: [[String]]

    public init(allowedServerCommands: [[String]] = []) {
        self.allowedServerCommands = allowedServerCommands
    }

    public func validateProject(at projectPath: String) throws {
        let root = URL(fileURLWithPath: projectPath, isDirectory: true)
        for relativePath in Self.configurationPaths {
            let url = root.appendingPathComponent(relativePath)
            guard FileManager.default.fileExists(atPath: url.path) else {
                continue
            }
            try validateFile(at: url)
        }
    }

    public func validateFile(at url: URL) throws {
        guard let data = try? Data(contentsOf: url),
            let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw ValidationError.invalidJSON(path: url.path)
        }

        let containers = serverContainers(in: root)
        for servers in containers {
            for (name, value) in servers {
                guard let server = value as? [String: Any] else {
                    continue
                }
                try validateServer(name: name, server: server, path: url.path)
            }
        }
    }

    private func serverContainers(in root: [String: Any]) -> [[String: Any]] {
        var containers: [[String: Any]] = []
        for key in ["mcpServers", "servers"] {
            if let servers = root[key] as? [String: Any] {
                containers.append(servers)
            }
        }
        if let mcp = root["mcp"] as? [String: Any] {
            for key in ["mcpServers", "servers"] {
                if let servers = mcp[key] as? [String: Any] {
                    containers.append(servers)
                }
            }
        }
        return containers
    }

    private func validateServer(
        name: String,
        server: [String: Any],
        path: String
    ) throws {
        let transport =
            (server["type"] as? String)?.lowercased()
            ?? (server["transport"] as? String)?.lowercased()
        let remoteTransports = Set(["http", "https", "sse", "streamable-http"])
        if server["url"] != nil || transport.map(remoteTransports.contains) == true {
            throw ValidationError.remoteTransport(path: path, server: name)
        }

        let command: [String]
        if let executable = server["command"] as? String {
            let arguments = server["args"] as? [String] ?? []
            command = [executable] + arguments
        } else if let arguments = server["command"] as? [String] {
            command = arguments
        } else {
            throw ValidationError.missingProxy(path: path, server: name)
        }

        guard command.count >= 2,
            command[0] == BoundaryEnforcer.proxyPath,
            command[1] == "--"
        else {
            throw ValidationError.missingProxy(path: path, server: name)
        }
        guard allowedServerCommands.contains(Array(command.dropFirst(2))) else {
            throw ValidationError.serverCommandNotAllowed(path: path, server: name)
        }
    }
}
