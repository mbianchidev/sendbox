import Foundation

/// Evaluates framed MCP tool calls before they reach a stdio server.
public struct MCPToolPolicy: Sendable {
    public typealias Configuration = PolicyConfiguration.ToolCallPolicyConfig

    private let config: Configuration

    public enum Decision: Sendable, Equatable {
        case allowed
        case denied(reason: String)

        public var isAllowed: Bool {
            if case .allowed = self {
                return true
            }
            return false
        }
    }

    public init(config: Configuration) {
        self.config = config
    }

    public func evaluate(
        tool name: String,
        transport: ObservabilityConfig.MCPInspectionConfig.Transport = .stdio
    ) -> Decision {
        guard transport == .stdio else {
            return .denied(
                reason: "Remote HTTP MCP is not supported while boundary enforcement is enabled"
            )
        }

        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .denied(reason: "MCP tools/call request is missing params.name")
        }

        for pattern in config.denylist where GlobPattern.matches(trimmed, pattern: pattern) {
            return .denied(reason: "Tool '\(trimmed)' matches deny pattern '\(pattern)'")
        }

        for pattern in config.allowlist where GlobPattern.matches(trimmed, pattern: pattern) {
            return .allowed
        }

        switch config.defaultAction {
        case .allow:
            return .allowed
        case .deny:
            return .denied(reason: "Tool '\(trimmed)' is not in the allowlist")
        }
    }

    public func evaluate(call: MCPInspector.MCPCall) -> Decision {
        guard call.method == "tools/call" else {
            return .allowed
        }
        guard let subject = call.subject else {
            return .denied(reason: "MCP tools/call request is missing params.name")
        }
        return evaluate(tool: subject, transport: call.transport)
    }
}

/// Stateful newline framing for MCP stdio JSON-RPC requests.
public struct MCPStdioFrameFilter: Sendable {
    public enum Action: Sendable, Equatable {
        case forward(Data)
        case respond(Data)
        case drop(reason: String)
        case terminate(reason: String)
    }

    private let policy: MCPToolPolicy
    private let maxFrameBytes: Int
    private var buffer = Data()

    public init(config: PolicyConfiguration.ToolCallPolicyConfig) {
        self.policy = MCPToolPolicy(config: config)
        self.maxFrameBytes = max(1, config.maxFrameBytes)
    }

    public mutating func consume(_ data: Data) -> [Action] {
        buffer.append(data)
        var actions: [Action] = []

        while let newlineIndex = buffer.firstIndex(of: 0x0A) {
            let frame = Data(buffer[buffer.startIndex...newlineIndex])
            buffer.removeSubrange(buffer.startIndex...newlineIndex)
            actions.append(process(frame: frame))
        }

        if buffer.count > maxFrameBytes {
            buffer.removeAll(keepingCapacity: false)
            actions.append(
                .terminate(
                    reason: "MCP frame exceeds max_frame_bytes (\(maxFrameBytes))"
                ))
        }

        return actions
    }

    public mutating func finish() -> [Action] {
        guard !buffer.isEmpty else {
            return []
        }
        buffer.removeAll(keepingCapacity: false)
        return [.terminate(reason: "MCP stdio stream ended with an incomplete JSON-RPC frame")]
    }

    private func process(frame: Data) -> Action {
        guard frame.count <= maxFrameBytes else {
            return .terminate(reason: "MCP frame exceeds max_frame_bytes (\(maxFrameBytes))")
        }

        var payload = frame
        if payload.last == 0x0A {
            payload.removeLast()
        }
        if payload.last == 0x0D {
            payload.removeLast()
        }
        guard !payload.isEmpty else {
            return .forward(frame)
        }

        guard let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
            object["jsonrpc"] as? String == "2.0"
        else {
            return .terminate(reason: "Invalid MCP stdio JSON-RPC frame")
        }

        guard object["method"] as? String == "tools/call" else {
            return .forward(frame)
        }
        guard let params = object["params"] as? [String: Any],
            let tool = params["name"] as? String
        else {
            return .terminate(reason: "MCP tools/call request is missing params.name")
        }

        switch policy.evaluate(tool: tool) {
        case .allowed:
            return .forward(frame)
        case .denied(let reason):
            guard let id = object["id"], !(id is NSNull) else {
                return .drop(reason: reason)
            }
            return .respond(denialResponse(id: id, tool: tool, reason: reason))
        }
    }

    private func denialResponse(id: Any, tool: String, reason: String) -> Data {
        let response: [String: Any] = [
            "jsonrpc": "2.0",
            "id": id,
            "error": [
                "code": -32001,
                "message": "Tool call denied by SendBox boundary policy",
                "data": [
                    "tool": tool,
                    "reason": reason,
                ],
            ],
        ]

        guard
            var data = try? JSONSerialization.data(
                withJSONObject: response,
                options: [.sortedKeys]
            )
        else {
            return Data()
        }
        data.append(0x0A)
        return data
    }
}
