import Foundation
import Logging

/// eBPF-based inspector for Model Context Protocol (MCP) traffic.
///
/// The sandboxed agent talks to MCP servers over one of two transports:
///
/// 1. **stdio** — the agent spawns a local MCP server child process and exchanges
///    newline-delimited JSON-RPC 2.0 messages over its stdin/stdout pipes.
/// 2. **HTTP / SSE** — the agent connects to a (possibly remote) MCP server over
///    TLS and exchanges JSON-RPC inside HTTP request/response bodies or SSE events.
///
/// Because the agent runs inside a Linux guest VM, eBPF can observe both transports
/// at the kernel boundary:
///
/// * stdio is captured by tracing `read`/`write` syscalls of the MCP server process.
/// * HTTP/SSE is captured as TLS plaintext via uprobes on `SSL_write`/`SSL_read`.
///
/// `MCPInspector` generates a `bpftrace` program plus a guest startup script, and
/// parses the resulting trace log back into structured ``MCPCall`` records that can
/// be summarised or appended to the audit trail.
///
/// ## Privilege model
///
/// SendBox hardening sets `kernel.unprivileged_bpf_disabled=1` and blocks the `bpf`
/// syscall via seccomp **for the agent**. The inspector is started as root early in
/// guest boot, before the agent drops privileges. `unprivileged_bpf_disabled` does
/// not affect root, so the inspector and the agent lockdown coexist: the agent still
/// cannot load its own BPF programs.
public struct MCPInspector: Sendable {

    public typealias Configuration = ObservabilityConfig.MCPInspectionConfig

    private let config: Configuration
    private let logger: Logger

    /// Marker prefix every inspector event line carries.
    public static let eventMarker = "SENDBOX_MCP"
    public static let beginMarker = "SENDBOX_MCP_BEGIN"
    public static let endMarker = "SENDBOX_MCP_END"

    /// Guest path where the generated bpftrace program is written.
    public static let programPath = "/run/sendbox-mcp.bt"
    /// Guest path where the inspector PID is recorded.
    public static let pidPath = "/run/sendbox-mcp.pid"

    public init(
        config: Configuration = .default,
        logger: Logger = Logger(label: "sendbox.mcp")
    ) {
        self.config = config
        self.logger = logger
    }

    // MARK: - Domain types

    /// JSON-RPC message shape.
    public enum MessageKind: String, Sendable, Codable {
        case request
        case response
        case notification
        case error
        /// An MCP server process being spawned (stdio transport detection).
        case spawn
    }

    /// High-level grouping of an MCP method.
    public enum MethodCategory: String, Sendable, Codable {
        case lifecycle
        case tools
        case resources
        case prompts
        case sampling
        case roots
        case completion
        case logging
        case notification
        case other
    }

    /// A single observed MCP message.
    public struct MCPCall: Sendable, Equatable, Codable {
        /// Monotonic timestamp (nanoseconds since boot) reported by bpftrace, if present.
        public let timestampNanos: UInt64?
        /// PID of the process that emitted the message.
        public let pid: Int?
        /// Process command name.
        public let comm: String?
        /// Transport the message was observed on.
        public let transport: Configuration.Transport
        /// JSON-RPC message shape.
        public let kind: MessageKind
        /// JSON-RPC method (nil for responses/errors that only carry an id).
        public let method: String?
        /// Method category.
        public let category: MethodCategory
        /// JSON-RPC id, stringified.
        public let id: String?
        /// Tool / resource / prompt name when applicable (e.g. `tools/call` → tool name).
        public let subject: String?
        /// Error code for error responses.
        public let errorCode: Int?
        /// Error message for error responses.
        public let errorMessage: String?
        /// Raw (possibly redacted) JSON payload.
        public let raw: String

        public init(
            timestampNanos: UInt64?,
            pid: Int?,
            comm: String?,
            transport: Configuration.Transport,
            kind: MessageKind,
            method: String?,
            category: MethodCategory,
            id: String?,
            subject: String?,
            errorCode: Int?,
            errorMessage: String?,
            raw: String
        ) {
            self.timestampNanos = timestampNanos
            self.pid = pid
            self.comm = comm
            self.transport = transport
            self.kind = kind
            self.method = method
            self.category = category
            self.id = id
            self.subject = subject
            self.errorCode = errorCode
            self.errorMessage = errorMessage
            self.raw = raw
        }
    }

    /// Aggregated view over a set of ``MCPCall`` records.
    public struct InspectionSummary: Sendable, Equatable {
        public let totalCalls: Int
        public let byCategory: [MethodCategory: Int]
        public let byKind: [MessageKind: Int]
        public let byTransport: [Configuration.Transport: Int]
        public let toolCallCount: Int
        public let toolInvocations: [String: Int]
        public let errorCount: Int
        public let distinctMethods: [String]
        public let servers: [String]
    }

    // MARK: - Program generation

    /// Generate the `bpftrace` program that captures MCP traffic.
    public func generateBpftraceProgram() -> String {
        let stdio = config.transports.contains(.stdio)
        let http = config.transports.contains(.http)
        let m = Self.eventMarker

        var lines: [String] = [
            "#!/usr/bin/env bpftrace",
            "/*",
            " * SendBox MCP inspector — captures Model Context Protocol (JSON-RPC 2.0)",
            " * traffic exchanged between the sandboxed agent and MCP servers.",
            " *",
            " * Event lines are TAB-separated and parsed by `sendbox mcp parse`:",
            " *   \(m)\\t<ts_ns>\\t<pid>\\t<comm>\\t<transport>\\t<direction>\\t<payload>",
            " *",
            " * Run as root at boot, before the agent drops privileges.",
            " */",
            "",
            "BEGIN {",
            "    printf(\"\(Self.beginMarker)\\t%lld\\n\", nsecs);",
            "}",
            "",
        ]

        if stdio {
            lines.append(contentsOf: stdioProbes())
        }
        if http {
            lines.append(contentsOf: tlsProbes())
        }

        lines.append(contentsOf: [
            "END {",
            "    clear(@mcp);",
            "    clear(@rbuf);",
            "    clear(@sslbuf);",
            "    printf(\"\(Self.endMarker)\\t%lld\\n\", nsecs);",
            "}",
            "",
        ])

        return lines.joined(separator: "\n")
    }

    private func stdioProbes() -> [String] {
        let m = Self.eventMarker
        let cap = max(1, config.maxPayloadBytes)
        let predicate = serverMatchPredicate()

        return [
            "// --- stdio transport: detect MCP server processes and trace their pipes ---",
            "tracepoint:syscalls:sys_enter_execve {",
            "    $c0 = str(args->argv[0]);",
            "    $c1 = str(args->argv[1]);",
            "    $c2 = str(args->argv[2]);",
            "    if (\(predicate)) {",
            "        @mcp[pid] = 1;",
            "        printf(\"\(m)\\t%lld\\t%d\\t%s\\tstdio\\tspawn\\t%s %s %s\\n\",",
            "               nsecs, pid, comm, $c0, $c1, $c2);",
            "    }",
            "}",
            "",
            "// Server writes responses to the agent (stdout/stderr).",
            "tracepoint:syscalls:sys_enter_write /@mcp[pid] && args->fd <= 2/ {",
            "    $n = (int64)args->count;",
            "    if ($n > \(cap)) { $n = \(cap); }",
            "    if ($n > 0) {",
            "        printf(\"\(m)\\t%lld\\t%d\\t%s\\tstdio\\tfrom_server\\t%s\\n\",",
            "               nsecs, pid, comm, str(args->buf, $n));",
            "    }",
            "}",
            "",
            "// Server reads requests from the agent (stdin). Buffer is valid on exit.",
            "tracepoint:syscalls:sys_enter_read /@mcp[pid]/ {",
            "    @rbuf[tid] = args->buf;",
            "}",
            "tracepoint:syscalls:sys_exit_read /@mcp[pid] && @rbuf[tid]/ {",
            "    $n = (int64)args->ret;",
            "    if ($n > \(cap)) { $n = \(cap); }",
            "    if ($n > 0) {",
            "        printf(\"\(m)\\t%lld\\t%d\\t%s\\tstdio\\tto_server\\t%s\\n\",",
            "               nsecs, pid, comm, str(@rbuf[tid], $n));",
            "    }",
            "    delete(@rbuf[tid]);",
            "}",
            "",
            "// Reap exited MCP servers.",
            "tracepoint:sched:sched_process_exit /@mcp[pid]/ {",
            "    delete(@mcp[pid]);",
            "}",
            "",
        ]
    }

    private func tlsProbes() -> [String] {
        let m = Self.eventMarker
        let cap = max(1, config.maxPayloadBytes)
        // libssl path differs by arch; the startup script resolves the real path and
        // substitutes it for this placeholder before loading the program.
        let lib = "__SENDBOX_LIBSSL__"

        return [
            "// --- HTTP/SSE transport: capture TLS plaintext via OpenSSL uprobes ---",
            "uprobe:\(lib):SSL_write {",
            "    $n = (int64)arg2;",
            "    if ($n > \(cap)) { $n = \(cap); }",
            "    if ($n > 0) {",
            "        printf(\"\(m)\\t%lld\\t%d\\t%s\\thttp\\tto_server\\t%s\\n\",",
            "               nsecs, pid, comm, str(arg1, $n));",
            "    }",
            "}",
            "uprobe:\(lib):SSL_read {",
            "    @sslbuf[tid] = arg1;",
            "}",
            "uretprobe:\(lib):SSL_read /@sslbuf[tid]/ {",
            "    $n = (int64)retval;",
            "    if ($n > \(cap)) { $n = \(cap); }",
            "    if ($n > 0) {",
            "        printf(\"\(m)\\t%lld\\t%d\\t%s\\thttp\\tfrom_server\\t%s\\n\",",
            "               nsecs, pid, comm, str(@sslbuf[tid], $n));",
            "    }",
            "    delete(@sslbuf[tid]);",
            "}",
            "",
        ]
    }

    /// Build the bpftrace boolean predicate matching MCP server argv substrings.
    private func serverMatchPredicate() -> String {
        let patterns = config.serverCommandPatterns.isEmpty
            ? Configuration.default.serverCommandPatterns
            : config.serverCommandPatterns

        var clauses: [String] = []
        for pattern in patterns {
            let escaped = pattern.replacingOccurrences(of: "\"", with: "\\\"")
            clauses.append("strcontains($c0, \"\(escaped)\")")
            clauses.append("strcontains($c1, \"\(escaped)\")")
            clauses.append("strcontains($c2, \"\(escaped)\")")
        }
        return clauses.joined(separator: " ||\n            ")
    }

    /// Generate the guest startup script that installs and launches the inspector.
    ///
    /// The script is idempotent and fails gracefully: if `bpftrace` cannot be
    /// installed or the kernel lacks BTF, it logs a warning and exits 0 so guest
    /// boot is never blocked by missing observability.
    public func generateStartupScript() -> String {
        let program = generateBpftraceProgram()
        let logPath = config.logPath
        let logDir = (logPath as NSString).deletingLastPathComponent
        let strlen = max(64, config.maxPayloadBytes + 64)

        var lines: [String] = [
            "#!/usr/bin/env bash",
            "set -uo pipefail",
            "",
            "# ============================================",
            "# SendBox MCP inspector (eBPF) bootstrap",
            "# ============================================",
            "",
            "log() { echo \"[sendbox-mcp] $*\"; }",
            "",
            "if ! command -v bpftrace >/dev/null 2>&1; then",
            "    log 'bpftrace not found; attempting install...'",
            "    if command -v apt-get >/dev/null 2>&1; then",
            "        apt-get update -qq && apt-get install -y -qq bpftrace || true",
            "    elif command -v apk >/dev/null 2>&1; then",
            "        apk add --no-cache bpftrace || true",
            "    elif command -v dnf >/dev/null 2>&1; then",
            "        dnf install -y -q bpftrace || true",
            "    fi",
            "fi",
            "",
            "if ! command -v bpftrace >/dev/null 2>&1; then",
            "    log 'bpftrace unavailable — MCP inspection disabled (continuing).'",
            "    exit 0",
            "fi",
            "",
            "if [ \"$(id -u)\" != \"0\" ]; then",
            "    log 'must run as root to load eBPF — MCP inspection disabled (continuing).'",
            "    exit 0",
            "fi",
            "",
            "mkdir -p \(ShellEscaping.quote(logDir))",
            "",
            "# Write the bpftrace program.",
            "cat > \(MCPInspector.programPath) << 'SENDBOX_MCP_PROG'",
            program.trimmingCharacters(in: .newlines),
            "SENDBOX_MCP_PROG",
            "",
        ]

        if config.transports.contains(.http) {
            lines.append(contentsOf: [
                "# Resolve the runtime libssl path for the TLS uprobes.",
                "LIBSSL=\"$(ldconfig -p 2>/dev/null | grep -oE '/[^ ]*libssl\\.so[^ ]*' | head -n1)\"",
                "if [ -z \"$LIBSSL\" ]; then",
                "    for c in /usr/lib/*/libssl.so.3 /usr/lib/libssl.so.3 \\",
                "             /usr/lib/*/libssl.so.1.1 /lib/*/libssl.so.3; do",
                "        [ -e \"$c\" ] && LIBSSL=\"$c\" && break",
                "    done",
                "fi",
                "if [ -n \"$LIBSSL\" ]; then",
                "    sed -i \"s#__SENDBOX_LIBSSL__#${LIBSSL}#g\" \(MCPInspector.programPath)",
                "    log \"TLS uprobes bound to ${LIBSSL}\"",
                "else",
                "    log 'libssl not found — stripping HTTP/TLS probes; stdio still traced.'",
                "    sed -i '/__SENDBOX_LIBSSL__/,/^}$/d' \(MCPInspector.programPath)",
                "fi",
                "",
            ])
        }

        lines.append(contentsOf: [
            "log 'starting eBPF MCP inspector...'",
            "export BPFTRACE_STRLEN=\(strlen)",
            "nohup bpftrace \(MCPInspector.programPath) >> \(ShellEscaping.quote(logPath)) 2>&1 &",
            "echo $! > \(MCPInspector.pidPath)",
            "log \"inspector running (pid $(cat \(MCPInspector.pidPath))), log: \(logPath)\"",
            "",
        ])

        return lines.joined(separator: "\n")
    }

    // MARK: - Parsing

    /// Parse a captured trace log into structured calls.
    ///
    /// Responses (which only carry an id) are correlated back to their originating
    /// request by `(pid, id)` so they inherit the request's method/category.
    public func parseEvents(from log: String) -> [MCPCall] {
        var calls: [MCPCall] = []
        var pending: [String: (method: String, category: MethodCategory)] = [:]

        for line in log.split(separator: "\n", omittingEmptySubsequences: true) {
            let raw = String(line)
            guard raw.hasPrefix(Self.eventMarker + "\t") else { continue }
            if raw.hasPrefix(Self.beginMarker) || raw.hasPrefix(Self.endMarker) { continue }

            // SENDBOX_MCP \t ts \t pid \t comm \t transport \t direction \t payload
            let fields = raw.split(separator: "\t", maxSplits: 6, omittingEmptySubsequences: false)
            guard fields.count == 7 else { continue }

            let ts = UInt64(fields[1])
            let pid = Int(fields[2])
            let comm = String(fields[3])
            let transport = Configuration.Transport(rawValue: String(fields[4])) ?? .stdio
            let direction = String(fields[5])
            let payload = String(fields[6])

            if direction == "spawn" {
                let cmd = payload.trimmingCharacters(in: .whitespaces)
                calls.append(MCPCall(
                    timestampNanos: ts, pid: pid, comm: comm, transport: transport,
                    kind: .spawn, method: nil, category: .lifecycle, id: nil,
                    subject: cmd, errorCode: nil, errorMessage: nil, raw: cmd
                ))
                continue
            }

            for object in Self.extractJSONObjects(from: payload) {
                guard var call = parseMessage(
                    object, transport: transport, pid: pid, comm: comm, timestampNanos: ts
                ) else { continue }

                let key = "\(pid ?? -1):\(call.id ?? "")"
                switch call.kind {
                case .request:
                    if let method = call.method {
                        pending[key] = (method, call.category)
                    }
                case .response, .error:
                    if call.method == nil, let match = pending[key] {
                        call = call.withMethod(match.method, category: match.category)
                        pending.removeValue(forKey: key)
                    }
                default:
                    break
                }
                calls.append(call)
            }
        }

        return calls
    }

    /// Parse a single JSON-RPC object string into an ``MCPCall``.
    public func parseMessage(
        _ json: String,
        transport: Configuration.Transport,
        pid: Int? = nil,
        comm: String? = nil,
        timestampNanos: UInt64? = nil
    ) -> MCPCall? {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              obj["jsonrpc"] != nil
        else { return nil }

        let method = obj["method"] as? String
        let id = Self.stringifyID(obj["id"])
        let hasError = obj["error"] != nil
        let hasResult = obj["result"] != nil

        let kind: MessageKind
        if hasError {
            kind = .error
        } else if let method, !method.isEmpty {
            kind = (id == nil) ? .notification : .request
        } else if hasResult {
            kind = .response
        } else {
            kind = (id == nil) ? .notification : .request
        }

        let category = Self.classify(method: method)

        var subject: String?
        if let params = obj["params"] as? [String: Any] {
            subject = (params["name"] as? String)
                ?? (params["uri"] as? String)
                ?? ((params["ref"] as? [String: Any])?["name"] as? String)
        }

        var errorCode: Int?
        var errorMessage: String?
        if let err = obj["error"] as? [String: Any] {
            errorCode = err["code"] as? Int
            errorMessage = err["message"] as? String
        }

        let storedRaw = config.capturePayloads
            ? json.trimmingCharacters(in: .whitespacesAndNewlines)
            : Self.redactedEnvelope(method: method, id: id, subject: subject, kind: kind)

        return MCPCall(
            timestampNanos: timestampNanos,
            pid: pid,
            comm: comm,
            transport: transport,
            kind: kind,
            method: method,
            category: category,
            id: id,
            subject: subject,
            errorCode: errorCode,
            errorMessage: config.capturePayloads ? errorMessage : nil,
            raw: storedRaw
        )
    }

    // MARK: - Summary

    /// Summarise a set of calls.
    public func summarize(_ calls: [MCPCall]) -> InspectionSummary {
        var byCategory: [MethodCategory: Int] = [:]
        var byKind: [MessageKind: Int] = [:]
        var byTransport: [Configuration.Transport: Int] = [:]
        var toolInvocations: [String: Int] = [:]
        var methods = Set<String>()
        var servers = Set<String>()
        var toolCallCount = 0
        var errorCount = 0

        for call in calls {
            byCategory[call.category, default: 0] += 1
            byKind[call.kind, default: 0] += 1
            byTransport[call.transport, default: 0] += 1
            if let method = call.method { methods.insert(method) }
            if call.kind == .error { errorCount += 1 }
            if call.kind == .spawn { servers.insert(call.subject ?? "unknown") }
            if call.method == "tools/call", call.kind == .request {
                toolCallCount += 1
                if let name = call.subject {
                    toolInvocations[name, default: 0] += 1
                }
            }
        }

        return InspectionSummary(
            totalCalls: calls.count,
            byCategory: byCategory,
            byKind: byKind,
            byTransport: byTransport,
            toolCallCount: toolCallCount,
            toolInvocations: toolInvocations,
            errorCount: errorCount,
            distinctMethods: methods.sorted(),
            servers: servers.sorted()
        )
    }

    // MARK: - Classification

    /// Map a JSON-RPC method to a high-level category.
    public static func classify(method: String?) -> MethodCategory {
        guard let method, !method.isEmpty else { return .other }
        if method.hasPrefix("notifications/") { return .notification }
        if method.hasPrefix("tools/") { return .tools }
        if method.hasPrefix("resources/") { return .resources }
        if method.hasPrefix("prompts/") { return .prompts }
        if method.hasPrefix("sampling/") { return .sampling }
        if method.hasPrefix("roots/") { return .roots }
        if method.hasPrefix("completion/") { return .completion }
        if method.hasPrefix("logging/") { return .logging }
        switch method {
        case "initialize", "initialized", "ping", "shutdown", "exit":
            return .lifecycle
        default:
            return .other
        }
    }

    // MARK: - Helpers

    private static func stringifyID(_ value: Any?) -> String? {
        switch value {
        case let s as String: return s
        case let i as Int: return String(i)
        case let d as Double: return d == d.rounded() ? String(Int(d)) : String(d)
        case let n as NSNumber: return n.stringValue
        default: return nil
        }
    }

    private static func redactedEnvelope(
        method: String?, id: String?, subject: String?, kind: MessageKind
    ) -> String {
        var parts: [String] = ["\"jsonrpc\":\"2.0\"", "\"_redacted\":true"]
        if let id { parts.append("\"id\":\"\(id)\"") }
        if let method { parts.append("\"method\":\"\(method)\"") }
        if let subject { parts.append("\"name\":\"\(subject)\"") }
        parts.append("\"kind\":\"\(kind.rawValue)\"")
        return "{" + parts.joined(separator: ",") + "}"
    }

    /// Extract zero or more balanced JSON objects embedded in an arbitrary payload.
    ///
    /// Handles raw stdio JSON, HTTP bodies preceded by headers, and SSE `data:` lines.
    static func extractJSONObjects(from payload: String) -> [String] {
        var results: [String] = []
        let scalars = Array(payload)
        var i = 0
        let n = scalars.count

        while i < n {
            guard scalars[i] == "{" else { i += 1; continue }

            var depth = 0
            var inString = false
            var escaped = false
            var j = i
            var closed = false

            while j < n {
                let ch = scalars[j]
                if inString {
                    if escaped {
                        escaped = false
                    } else if ch == "\\" {
                        escaped = true
                    } else if ch == "\"" {
                        inString = false
                    }
                } else {
                    switch ch {
                    case "\"": inString = true
                    case "{": depth += 1
                    case "}":
                        depth -= 1
                        if depth == 0 {
                            let candidate = String(scalars[i...j])
                            if candidate.contains("jsonrpc") {
                                results.append(candidate)
                            }
                            i = j + 1
                            closed = true
                        }
                    default: break
                    }
                }
                if closed { break }
                j += 1
            }

            if !closed { break }
        }

        return results
    }
}

// MARK: - MCPCall mutation helper

extension MCPInspector.MCPCall {
    fileprivate func withMethod(
        _ method: String, category: MCPInspector.MethodCategory
    ) -> MCPInspector.MCPCall {
        MCPInspector.MCPCall(
            timestampNanos: timestampNanos,
            pid: pid,
            comm: comm,
            transport: transport,
            kind: kind,
            method: method,
            category: category,
            id: id,
            subject: subject,
            errorCode: errorCode,
            errorMessage: errorMessage,
            raw: raw
        )
    }
}

// MARK: - Audit integration

extension AuditTrail {
    /// Append an observed MCP call to the audit trail.
    @discardableResult
    public func record(mcpCall call: MCPInspector.MCPCall) -> String {
        var details: [String: String] = [
            "transport": call.transport.rawValue,
            "kind": call.kind.rawValue,
            "category": call.category.rawValue,
        ]
        if let id = call.id { details["id"] = id }
        if let pid = call.pid { details["pid"] = String(pid) }
        if let code = call.errorCode { details["error_code"] = String(code) }
        if let message = call.errorMessage { details["error_message"] = message }

        let outcome: AuditEntry.Outcome = (call.kind == .error) ? .error : .allowed
        let action = call.method ?? (call.kind == .spawn ? "server/spawn" : "response")
        let subject = call.subject ?? call.comm ?? call.transport.rawValue

        return log(
            category: .mcp,
            action: action,
            subject: subject,
            outcome: outcome,
            details: details
        )
    }
}
