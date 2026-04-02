import Foundation
import Logging
@preconcurrency import Network

/// Credential injection via reverse proxy or environment variables.
///
/// Two modes of credential injection:
///
/// 1. **Proxy mode** (`--proxy-credential`): A lightweight HTTP/HTTPS reverse proxy runs
///    on the host. The agent's requests to API endpoints are routed through this proxy,
///    which injects Authorization headers transparently. The agent never sees raw tokens.
///
/// 2. **Env mode** (`--env-credential`): Secrets are loaded from the system keystore
///    and injected as environment variables into the container. Simpler but the agent
///    can read the values.
///
/// The proxy mode is preferred for security-sensitive credentials (API keys, tokens)
/// because the agent only knows the proxy URL, not the actual credential value.
public actor CredentialProxy {

    private let vault: SecretsVault
    private let logger: Logger
    private let proxyConfig: ProxyConfig
    private var proxyRules: [ProxyRule]
    private var listener: NWListener?
    private var activeConnections: [ObjectIdentifier: NWConnection] = [:]
    private var proxyPort: Int?
    private var requestsProxied: Int = 0
    private var requestsFailed: Int = 0
    private var startTime: Date?

    // MARK: - Types

    /// A rule mapping an API endpoint to a credential.
    public struct ProxyRule: Codable, Sendable {
        /// Target domain to intercept (e.g., "api.openai.com").
        public let target: String
        /// Secret key in the vault (e.g., "OPENAI_API_KEY").
        public let secretKey: String
        /// How to inject the credential into the outgoing request.
        public let injection: InjectionMethod
        /// Optional path prefix filter — only match requests whose path starts with this.
        public let pathPrefix: String?

        public init(
            target: String,
            secretKey: String,
            injection: InjectionMethod,
            pathPrefix: String? = nil
        ) {
            self.target = target
            self.secretKey = secretKey
            self.injection = injection
            self.pathPrefix = pathPrefix
        }

        public enum InjectionMethod: Codable, Sendable {
            /// Add/replace `Authorization: Bearer <token>` header.
            case bearerToken
            /// Add a custom header (e.g., `x-api-key` for Anthropic).
            case header(name: String)
            /// Append as a query parameter (e.g., `?key=<token>` for Google AI).
            case queryParam(name: String)
            /// Replace a placeholder segment in the URL path.
            case pathSegment(placeholder: String)
        }
    }

    /// Configuration for the credential proxy listener.
    public struct ProxyConfig: Codable, Sendable {
        /// Port to listen on (0 = auto-assign).
        public var port: Int
        /// Bind address (always localhost for security).
        public let bindAddress: String
        /// Request timeout in seconds.
        public var timeout: TimeInterval
        /// Whether to log proxied request metadata (never credentials).
        public var logRequests: Bool
        /// Maximum concurrent connections.
        public var maxConnections: Int
        /// Whether to verify TLS certificates for upstream connections.
        public var verifyUpstreamTLS: Bool

        public init(
            port: Int = 0,
            bindAddress: String = "127.0.0.1",
            timeout: TimeInterval = 30,
            logRequests: Bool = true,
            maxConnections: Int = 64,
            verifyUpstreamTLS: Bool = true
        ) {
            self.port = port
            self.bindAddress = bindAddress
            self.timeout = timeout
            self.logRequests = logRequests
            self.maxConnections = maxConnections
            self.verifyUpstreamTLS = verifyUpstreamTLS
        }

        public static let `default` = ProxyConfig()
    }

    /// Snapshot of proxy runtime status.
    public struct ProxyStatus: Sendable {
        public let isRunning: Bool
        public let port: Int?
        public let rulesCount: Int
        public let requestsProxied: Int
        public let requestsFailed: Int
        public let uptime: TimeInterval?
    }

    /// Result of credential injection configuration — everything the container needs.
    public struct InjectionResult: Sendable {
        /// Environment variables to set in the container.
        public let environmentVariables: [String: String]
        /// Proxy URL if proxy mode is active (e.g., `http://host.internal:9100`).
        public let proxyURL: String?
        /// iptables rules to transparently redirect API traffic through the proxy.
        public let redirectRules: String?
        /// DNS overrides to route target domains through the proxy.
        public let dnsOverrides: [String: String]?
    }

    /// How to inject credentials into the container.
    public enum InjectionMode: Sendable {
        /// Route through reverse proxy (agent never sees tokens).
        case proxy
        /// Inject as environment variables (agent can read values).
        case env
        /// Proxy for high-security credentials, env for low-security.
        case hybrid
    }

    public enum ProxyError: Error, LocalizedError {
        case alreadyRunning
        case notRunning
        case portInUse(Int)
        case secretNotFound(String)
        case upstreamError(String)
        case configurationError(String)

        public var errorDescription: String? {
            switch self {
            case .alreadyRunning:
                return "Credential proxy is already running"
            case .notRunning:
                return "Credential proxy is not running"
            case .portInUse(let port):
                return "Port \(port) is already in use"
            case .secretNotFound(let key):
                return "Secret not found in vault: \(key)"
            case .upstreamError(let message):
                return "Upstream request failed: \(message)"
            case .configurationError(let message):
                return "Proxy configuration error: \(message)"
            }
        }
    }

    // MARK: - Init

    public init(
        vault: SecretsVault,
        config: ProxyConfig = .default,
        logger: Logger = Logger(label: "sendbox.credential-proxy")
    ) {
        self.vault = vault
        self.proxyConfig = config
        self.logger = logger
        self.proxyRules = []
    }

    // MARK: - Rule Management

    /// Add a proxy rule for an API endpoint. Replaces any existing rule for the same target.
    public func addRule(_ rule: ProxyRule) {
        proxyRules.removeAll { $0.target == rule.target }
        proxyRules.append(rule)
        logger.info("Added proxy rule", metadata: [
            "target": "\(rule.target)",
            "secretKey": "\(rule.secretKey)",
        ])
    }

    /// Remove a proxy rule by target domain.
    public func removeRule(target: String) {
        proxyRules.removeAll { $0.target == target }
        logger.info("Removed proxy rule", metadata: ["target": "\(target)"])
    }

    /// List all active proxy rules.
    public func rules() -> [ProxyRule] {
        proxyRules
    }

    // MARK: - Proxy Lifecycle

    /// Start the credential proxy. Returns the port it's listening on.
    public func start() async throws -> Int {
        guard listener == nil else {
            throw ProxyError.alreadyRunning
        }

        // Validate that all referenced secrets exist before starting.
        for rule in proxyRules {
            guard (try? vault.exists(key: rule.secretKey)) == true else {
                throw ProxyError.secretNotFound(rule.secretKey)
            }
        }

        let port = try await startHTTPListener(port: proxyConfig.port)
        self.proxyPort = port
        self.startTime = Date()
        logger.info("Credential proxy started", metadata: ["port": "\(port)"])
        return port
    }

    /// Stop the credential proxy and close all connections.
    public func stop() async {
        listener?.cancel()
        listener = nil
        for (_, connection) in activeConnections {
            connection.cancel()
        }
        activeConnections.removeAll()
        let uptime = startTime.map { Date().timeIntervalSince($0) }
        proxyPort = nil
        startTime = nil
        logger.info("Credential proxy stopped", metadata: [
            "totalProxied": "\(requestsProxied)",
            "totalFailed": "\(requestsFailed)",
            "uptime": "\(uptime.map { String(format: "%.1fs", $0) } ?? "n/a")",
        ])
    }

    /// Get current proxy status.
    public func status() -> ProxyStatus {
        ProxyStatus(
            isRunning: listener != nil,
            port: proxyPort,
            rulesCount: proxyRules.count,
            requestsProxied: requestsProxied,
            requestsFailed: requestsFailed,
            uptime: startTime.map { Date().timeIntervalSince($0) }
        )
    }

    // MARK: - Injection Configuration

    /// Configure credential injection for a container.
    ///
    /// Registers the supplied rules, starts the proxy if needed (for `.proxy` / `.hybrid` mode),
    /// and returns environment variables, proxy URL, iptables rules, and DNS overrides.
    public func configureInjection(
        rules: [ProxyRule],
        mode: InjectionMode
    ) async throws -> InjectionResult {
        for rule in rules {
            addRule(rule)
        }

        switch mode {
        case .proxy:
            let port = try await start()
            return try buildProxyInjectionResult(port: port)

        case .env:
            let keys = rules.map(\.secretKey)
            let envVars = try generateEnvCredentials(keys: keys)
            return InjectionResult(
                environmentVariables: envVars,
                proxyURL: nil,
                redirectRules: nil,
                dnsOverrides: nil
            )

        case .hybrid:
            let port = try await start()
            var result = try buildProxyInjectionResult(port: port)
            // Merge env-var credentials as a fallback layer.
            let keys = rules.map(\.secretKey)
            let envVars = try generateEnvCredentials(keys: keys)
            var merged = result.environmentVariables
            for (key, value) in envVars { merged[key] = value }
            result = InjectionResult(
                environmentVariables: merged,
                proxyURL: result.proxyURL,
                redirectRules: result.redirectRules,
                dnsOverrides: result.dnsOverrides
            )
            return result
        }
    }

    /// Generate environment variables for env-mode injection.
    ///
    /// Retrieves each secret from the vault and returns a dictionary suitable
    /// for ``ContainerConfig/environment``.
    public func generateEnvCredentials(keys: [String]) throws -> [String: String] {
        var envVars: [String: String] = [:]
        for key in keys {
            let value = try vault.retrieve(key: key)
            envVars[key] = value
        }
        // Intentionally never log credential values.
        logger.info("Generated env credentials", metadata: ["count": "\(envVars.count)"])
        return envVars
    }

    /// Generate container configuration for proxy-mode injection.
    ///
    /// Includes:
    /// - `HTTP_PROXY` / `HTTPS_PROXY` env vars pointing to the proxy
    /// - iptables rules to transparently redirect API traffic
    /// - DNS overrides to route target domains through the proxy
    public func generateProxyConfig() throws -> InjectionResult {
        guard let port = proxyPort else {
            throw ProxyError.notRunning
        }
        return try buildProxyInjectionResult(port: port)
    }

    // MARK: - Predefined Rules

    /// Standard proxy rules for OpenAI API (`api.openai.com` → Bearer token).
    public static let openAIRules: [ProxyRule] = [
        ProxyRule(
            target: "api.openai.com",
            secretKey: "OPENAI_API_KEY",
            injection: .bearerToken
        ),
    ]

    /// Standard proxy rules for Anthropic API (`api.anthropic.com` → `x-api-key` header).
    public static let anthropicRules: [ProxyRule] = [
        ProxyRule(
            target: "api.anthropic.com",
            secretKey: "ANTHROPIC_API_KEY",
            injection: .header(name: "x-api-key")
        ),
    ]

    /// Standard proxy rules for GitHub API (`api.github.com` → Bearer token).
    public static let githubRules: [ProxyRule] = [
        ProxyRule(
            target: "api.github.com",
            secretKey: "GITHUB_TOKEN",
            injection: .bearerToken
        ),
    ]

    /// Standard proxy rules for Google AI / Gemini API (query parameter injection).
    public static let googleAIRules: [ProxyRule] = [
        ProxyRule(
            target: "generativelanguage.googleapis.com",
            secretKey: "GEMINI_API_KEY",
            injection: .queryParam(name: "key")
        ),
    ]

    /// Standard proxy rules for npm registry (`registry.npmjs.org` → Bearer token).
    public static let npmRules: [ProxyRule] = [
        ProxyRule(
            target: "registry.npmjs.org",
            secretKey: "NPM_TOKEN",
            injection: .bearerToken
        ),
    ]

    // MARK: - Internal — Injection Result Builder

    /// Build the ``InjectionResult`` for proxy-mode, given the listener port.
    private func buildProxyInjectionResult(port: Int) throws -> InjectionResult {
        let proxyURL = "http://host.internal:\(port)"

        var envVars: [String: String] = [
            "HTTP_PROXY": proxyURL,
            "HTTPS_PROXY": proxyURL,
            "http_proxy": proxyURL,
            "https_proxy": proxyURL,
        ]

        // Don't proxy local traffic.
        let noProxy = ["localhost", "127.0.0.1", "::1", "host.internal"]
            .joined(separator: ",")
        envVars["NO_PROXY"] = noProxy
        envVars["no_proxy"] = noProxy

        // iptables transparent redirect rules.
        var iptablesLines: [String] = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            "# --- SendBox credential proxy redirect rules ---",
            "",
        ]

        for rule in proxyRules {
            iptablesLines.append("# Redirect \(rule.target) through credential proxy")
            iptablesLines.append(
                "for ip in $(dig +short \(rule.target) A 2>/dev/null); do"
            )
            iptablesLines.append(
                "  iptables -t nat -A OUTPUT -d \"$ip\" -p tcp --dport 443"
                + " -j DNAT --to-destination 192.168.64.1:\(port)"
            )
            iptablesLines.append(
                "  iptables -t nat -A OUTPUT -d \"$ip\" -p tcp --dport 80"
                + " -j DNAT --to-destination 192.168.64.1:\(port)"
            )
            iptablesLines.append("done")
            iptablesLines.append("")
        }

        // DNS overrides route target domains to the host gateway.
        var dnsOverrides: [String: String] = [:]
        for rule in proxyRules {
            dnsOverrides[rule.target] = "192.168.64.1"
        }

        return InjectionResult(
            environmentVariables: envVars,
            proxyURL: proxyURL,
            redirectRules: iptablesLines.joined(separator: "\n"),
            dnsOverrides: dnsOverrides
        )
    }

    // MARK: - Internal — Request Handling

    /// Handle an incoming proxied request: match rules, inject credentials, forward upstream.
    private func handleRequest(
        method: String,
        url: URL,
        headers: [String: String],
        body: Data?
    ) async throws -> ProxiedResponse {
        guard let host = url.host else {
            throw ProxyError.upstreamError("No host in URL: \(url)")
        }

        // Find the first rule whose target matches the request host (and optional path prefix).
        let matchingRule = proxyRules.first { rule in
            guard host.lowercased() == rule.target.lowercased() else { return false }
            if let prefix = rule.pathPrefix {
                return url.path.hasPrefix(prefix)
            }
            return true
        }

        // Build upstream URL — upgrade to HTTPS for API endpoints.
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        if components?.scheme == "http" {
            components?.scheme = "https"
        }

        var upstreamHeaders = headers

        if let rule = matchingRule {
            let secret: String
            do {
                secret = try vault.retrieve(key: rule.secretKey)
            } catch {
                throw ProxyError.secretNotFound(rule.secretKey)
            }

            switch rule.injection {
            case .bearerToken:
                upstreamHeaders["Authorization"] = "Bearer \(secret)"

            case .header(let name):
                upstreamHeaders[name] = secret

            case .queryParam(let name):
                var items = components?.queryItems ?? []
                items.append(URLQueryItem(name: name, value: secret))
                components?.queryItems = items

            case .pathSegment(let placeholder):
                components?.path = url.path.replacingOccurrences(of: placeholder, with: secret)
            }

            if proxyConfig.logRequests {
                // Log metadata only — NEVER log the credential value.
                logger.info("Proxying request", metadata: [
                    "method": "\(method)",
                    "target": "\(rule.target)",
                    "path": "\(url.path)",
                ])
            }
        } else if proxyConfig.logRequests {
            logger.debug("Passing through (no matching rule)", metadata: [
                "method": "\(method)",
                "host": "\(host)",
            ])
        }

        guard let upstreamURL = components?.url else {
            throw ProxyError.upstreamError("Failed to construct upstream URL from \(url)")
        }

        // Forward to the real API endpoint using URLSession.
        var request = URLRequest(url: upstreamURL)
        request.httpMethod = method
        request.httpBody = body
        request.timeoutInterval = proxyConfig.timeout

        let hopByHop: Set<String> = [
            "connection", "proxy-connection", "keep-alive",
            "transfer-encoding", "upgrade", "proxy-authorization",
        ]
        for (key, value) in upstreamHeaders where !hopByHop.contains(key.lowercased()) {
            request.setValue(value, forHTTPHeaderField: key)
        }

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                throw ProxyError.upstreamError("Non-HTTP response from upstream")
            }

            var responseHeaders: [String: String] = [:]
            for (key, value) in httpResponse.allHeaderFields {
                if let k = key as? String, let v = value as? String {
                    responseHeaders[k] = v
                }
            }

            requestsProxied += 1

            if proxyConfig.logRequests {
                logger.info("Upstream response", metadata: [
                    "status": "\(httpResponse.statusCode)",
                    "host": "\(host)",
                    "path": "\(url.path)",
                ])
            }

            return ProxiedResponse(
                statusCode: httpResponse.statusCode,
                headers: responseHeaders,
                body: data
            )
        } catch let error as ProxyError {
            requestsFailed += 1
            throw error
        } catch {
            requestsFailed += 1
            throw ProxyError.upstreamError(error.localizedDescription)
        }
    }

    // MARK: - Internal — HTTP Server (Network.framework)

    /// Guards against double-resuming a checked continuation from NWListener / NWConnection
    /// state callbacks (which run on a serial dispatch queue).
    private final class OnceFlag: @unchecked Sendable {
        var fired = false
    }

    /// Parsed HTTP request components.
    private struct ParsedRequest: Sendable {
        let method: String
        let url: URL
        let headers: [String: String]
        let body: Data?
    }

    /// Upstream response components.
    private struct ProxiedResponse: Sendable {
        let statusCode: Int
        let headers: [String: String]
        let body: Data?
    }

    /// Create an `NWListener` on localhost, wait for it to become ready,
    /// and return the actual port it bound to.
    private func startHTTPListener(port requestedPort: Int) async throws -> Int {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true

        // Restrict to localhost.
        params.requiredLocalEndpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(proxyConfig.bindAddress),
            port: requestedPort == 0
                ? .any
                : NWEndpoint.Port(rawValue: UInt16(requestedPort)) ?? .any
        )

        let nwPort: NWEndpoint.Port
        if requestedPort == 0 {
            nwPort = .any
        } else {
            guard let p = NWEndpoint.Port(rawValue: UInt16(requestedPort)) else {
                throw ProxyError.configurationError("Invalid port number: \(requestedPort)")
            }
            nwPort = p
        }

        let newListener = try NWListener(using: params, on: nwPort)

        // Store immediately so `stop()` can cancel it even during startup.
        self.listener = newListener

        newListener.newConnectionHandler = { [weak self] connection in
            guard let self else {
                connection.cancel()
                return
            }
            Task { await self.acceptConnection(connection) }
        }

        let actualPort: Int = try await withCheckedThrowingContinuation { continuation in
            let flag = OnceFlag()
            newListener.stateUpdateHandler = { [weak self] state in
                guard !flag.fired else { return }
                switch state {
                case .ready:
                    flag.fired = true
                    let port = Int(newListener.port?.rawValue ?? 0)
                    continuation.resume(returning: port)

                case .failed(let error):
                    flag.fired = true
                    if case NWError.posix(let code) = error, code == .EADDRINUSE {
                        continuation.resume(throwing: ProxyError.portInUse(requestedPort))
                    } else {
                        continuation.resume(
                            throwing: ProxyError.configurationError(
                                "Listener failed: \(error.localizedDescription)"
                            )
                        )
                    }
                    Task { await self?.cleanUpListener() }

                case .cancelled:
                    flag.fired = true
                    continuation.resume(
                        throwing: ProxyError.configurationError("Listener was cancelled")
                    )

                default:
                    break
                }
            }

            newListener.start(
                queue: DispatchQueue(label: "sendbox.credential-proxy.listener")
            )
        }

        return actualPort
    }

    /// Clean up listener state after a failure.
    private func cleanUpListener() {
        listener?.cancel()
        listener = nil
    }

    /// Accept and process a single connection.
    private func acceptConnection(_ connection: NWConnection) {
        let connId = ObjectIdentifier(connection)

        guard activeConnections.count < proxyConfig.maxConnections else {
            logger.warning("Max connections reached, rejecting")
            connection.cancel()
            return
        }

        activeConnections[connId] = connection

        Task {
            defer {
                connection.cancel()
                activeConnections.removeValue(forKey: connId)
            }

            do {
                try await waitForConnectionReady(connection)
                let data = try await receiveRequestData(from: connection)
                guard !data.isEmpty else { return }

                let parsed = try Self.parseHTTPRequest(data: data)
                let response = try await handleRequest(
                    method: parsed.method,
                    url: parsed.url,
                    headers: parsed.headers,
                    body: parsed.body
                )
                let responseData = Self.serializeHTTPResponse(response)
                try await sendResponseData(responseData, on: connection)
            } catch {
                logger.error("Request error: \(error.localizedDescription)")
                let errorBody = "Bad Gateway: \(error.localizedDescription)"
                let errorResponse = Self.serializeHTTPResponse(
                    ProxiedResponse(
                        statusCode: 502,
                        headers: ["Content-Type": "text/plain; charset=utf-8"],
                        body: errorBody.data(using: .utf8)
                    )
                )
                try? await sendResponseData(errorResponse, on: connection)
            }
        }
    }

    /// Wait for an accepted NWConnection to reach the `.ready` state.
    private func waitForConnectionReady(_ connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            let flag = OnceFlag()
            connection.stateUpdateHandler = { state in
                guard !flag.fired else { return }
                switch state {
                case .ready:
                    flag.fired = true
                    continuation.resume()
                case .failed(let error):
                    flag.fired = true
                    continuation.resume(throwing: error)
                case .cancelled:
                    flag.fired = true
                    continuation.resume(
                        throwing: ProxyError.configurationError("Connection cancelled")
                    )
                default:
                    break
                }
            }
            connection.start(
                queue: DispatchQueue(label: "sendbox.credential-proxy.conn")
            )
        }
    }

    /// Read a complete HTTP request from the connection (up to 1 MB).
    private func receiveRequestData(from connection: NWConnection) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(
                minimumIncompleteLength: 1,
                maximumLength: 1_048_576
            ) { content, _, _, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: content ?? Data())
                }
            }
        }
    }

    /// Write response bytes to the connection.
    private func sendResponseData(_ data: Data, on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            connection.send(
                content: data,
                contentContext: .finalMessage,
                isComplete: true,
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                }
            )
        }
    }

    // MARK: - Internal — HTTP Parsing

    /// Parse a raw HTTP/1.1 request into components.
    ///
    /// Handles both forward-proxy style (`GET http://host/path HTTP/1.1`)
    /// and reverse-proxy style (`GET /path HTTP/1.1` with `Host:` header).
    private static func parseHTTPRequest(data: Data) throws -> ParsedRequest {
        guard let raw = String(data: data, encoding: .utf8) else {
            throw ProxyError.configurationError("Request is not valid UTF-8")
        }

        let headerBodySplit = raw.components(separatedBy: "\r\n\r\n")
        let headerSection = headerBodySplit[0]
        let bodyString: String? = headerBodySplit.count > 1
            ? headerBodySplit.dropFirst().joined(separator: "\r\n\r\n")
            : nil
        let body: Data? = bodyString.flatMap { $0.isEmpty ? nil : $0.data(using: .utf8) }

        let lines = headerSection.components(separatedBy: "\r\n")
        guard let requestLine = lines.first, !requestLine.isEmpty else {
            throw ProxyError.configurationError("Empty HTTP request")
        }

        let parts = requestLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else {
            throw ProxyError.configurationError("Malformed request line: \(requestLine)")
        }

        let method = String(parts[0])
        let rawURL = String(parts[1])

        // Parse headers before constructing the URL (we may need Host).
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colonIdx = line.firstIndex(of: ":") else { continue }
            let key = String(line[line.startIndex..<colonIdx])
                .trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colonIdx)...])
                .trimmingCharacters(in: .whitespaces)
            headers[key] = value
        }

        let url: URL
        if rawURL.hasPrefix("http://") || rawURL.hasPrefix("https://") {
            // Absolute URL — forward-proxy style.
            guard let parsed = URL(string: rawURL) else {
                throw ProxyError.configurationError("Invalid URL: \(rawURL)")
            }
            url = parsed
        } else {
            // Relative path — reconstruct from Host header.
            let host = headers["Host"] ?? headers["host"] ?? "localhost"
            guard let parsed = URL(string: "https://\(host)\(rawURL)") else {
                throw ProxyError.configurationError(
                    "Cannot construct URL from path \(rawURL) and host \(host)"
                )
            }
            url = parsed
        }

        return ParsedRequest(method: method, url: url, headers: headers, body: body)
    }

    /// Serialize an HTTP/1.1 response to raw bytes.
    private static func serializeHTTPResponse(_ response: ProxiedResponse) -> Data {
        var lines: [String] = [
            "HTTP/1.1 \(response.statusCode) \(httpStatusText(response.statusCode))",
        ]

        var headers = response.headers
        if let body = response.body {
            headers["Content-Length"] = "\(body.count)"
        } else {
            headers["Content-Length"] = "0"
        }
        headers["Connection"] = "close"

        for (key, value) in headers.sorted(by: { $0.key < $1.key }) {
            lines.append("\(key): \(value)")
        }
        lines.append("")  // blank line terminates headers
        lines.append("")

        var data = lines.joined(separator: "\r\n").data(using: .utf8) ?? Data()
        if let body = response.body {
            data.append(body)
        }
        return data
    }

    /// Map an HTTP status code to its standard reason phrase.
    private static func httpStatusText(_ code: Int) -> String {
        switch code {
        case 200: "OK"
        case 201: "Created"
        case 204: "No Content"
        case 301: "Moved Permanently"
        case 302: "Found"
        case 304: "Not Modified"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 429: "Too Many Requests"
        case 500: "Internal Server Error"
        case 502: "Bad Gateway"
        case 503: "Service Unavailable"
        case 504: "Gateway Timeout"
        default: "Unknown"
        }
    }
}
