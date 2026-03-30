import Foundation
import Logging

/// Generates and manages devcontainer configurations for sandboxed environments.
///
/// Uses the `copilot-bridge` TypeScript tool to analyze projects and produce
/// a `devcontainer.json`, then allows merging user overrides from the
/// `SandboxConfiguration`.
public struct DevContainerBuilder: Sendable {
    private let logger: Logger

    public struct DevContainerSpec: Codable, Sendable {
        public var name: String
        public var image: String
        public var features: [String: [String: String]]?
        public var customizations: Customizations?
        public var forwardPorts: [Int]?
        public var postCreateCommand: String?
        public var remoteUser: String?
        public var containerEnv: [String: String]?

        public struct Customizations: Codable, Sendable {
            public var vscode: VSCodeConfig?

            public struct VSCodeConfig: Codable, Sendable {
                public var extensions: [String]?
                public var settings: [String: AnyCodableValue]?
            }
        }

        public init(
            name: String,
            image: String = "mcr.microsoft.com/devcontainers/universal:2",
            features: [String: [String: String]]? = nil,
            customizations: Customizations? = nil,
            forwardPorts: [Int]? = nil,
            postCreateCommand: String? = nil,
            remoteUser: String? = "vscode",
            containerEnv: [String: String]? = nil
        ) {
            self.name = name
            self.image = image
            self.features = features
            self.customizations = customizations
            self.forwardPorts = forwardPorts
            self.postCreateCommand = postCreateCommand
            self.remoteUser = remoteUser
            self.containerEnv = containerEnv
        }
    }

    /// Type-erased Codable value for heterogeneous JSON settings.
    public enum AnyCodableValue: Codable, Sendable, Equatable {
        case string(String)
        case int(Int)
        case double(Double)
        case bool(Bool)
        case null

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()

            if container.decodeNil() {
                self = .null
            } else if let boolValue = try? container.decode(Bool.self) {
                self = .bool(boolValue)
            } else if let intValue = try? container.decode(Int.self) {
                self = .int(intValue)
            } else if let doubleValue = try? container.decode(Double.self) {
                self = .double(doubleValue)
            } else if let stringValue = try? container.decode(String.self) {
                self = .string(stringValue)
            } else {
                self = .null
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let value):
                try container.encode(value)
            case .int(let value):
                try container.encode(value)
            case .double(let value):
                try container.encode(value)
            case .bool(let value):
                try container.encode(value)
            case .null:
                try container.encodeNil()
            }
        }
    }

    public init(logger: Logger = Logger(label: "sendbox.devcontainer")) {
        self.logger = logger
    }

    // MARK: - Generation

    /// Generate a devcontainer.json by analyzing the project using the copilot-bridge.
    ///
    /// Shells out to the TypeScript bridge tool to inspect the project's files and
    /// produce a suitable devcontainer spec. Falls back to a sensible default if
    /// the bridge is unavailable or fails.
    public func generate(
        for projectPath: String,
        config: SandboxConfiguration
    ) async throws -> DevContainerSpec {
        logger.info("Generating devcontainer for project at \(projectPath)")

        do {
            let data = try await runCopilotBridge(
                action: "generate",
                projectPath: projectPath
            )

            let decoder = JSONDecoder()
            var spec = try decoder.decode(DevContainerSpec.self, from: data)

            // Ensure the spec name matches the sandbox name.
            spec.name = config.name

            return merge(spec, overrides: config.devcontainer)

        } catch {
            logger.warning(
                "Copilot bridge failed, generating default spec: \(error.localizedDescription)"
            )
            return defaultSpec(for: projectPath, config: config)
        }
    }

    // MARK: - Load / Save

    /// Load an existing devcontainer.json from disk.
    public func load(from path: String) throws -> DevContainerSpec {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)

        // devcontainer.json may contain JSON-with-comments (JSONC).
        // Strip single-line comments before parsing.
        let cleaned = stripJSONComments(data)

        let decoder = JSONDecoder()
        return try decoder.decode(DevContainerSpec.self, from: cleaned)
    }

    /// Save a devcontainer spec to the project's `.devcontainer` directory.
    ///
    /// Creates the `.devcontainer` directory if it doesn't exist and writes
    /// `devcontainer.json` with pretty-printed formatting.
    ///
    /// - Returns: The path to the written file.
    @discardableResult
    public func save(_ spec: DevContainerSpec, to projectPath: String) throws -> String {
        let dirURL = URL(fileURLWithPath: projectPath)
            .appendingPathComponent(".devcontainer")

        try FileManager.default.createDirectory(
            at: dirURL,
            withIntermediateDirectories: true
        )

        let fileURL = dirURL.appendingPathComponent("devcontainer.json")

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(spec)

        try data.write(to: fileURL, options: .atomic)

        logger.info("Saved devcontainer.json to \(fileURL.path)")
        return fileURL.path
    }

    // MARK: - Merging

    /// Merge user overrides from `SandboxConfiguration.DevContainerConfig` into a base spec.
    ///
    /// Overlays user-specified extensions and config path preferences onto the
    /// generated spec without discarding bridge-detected settings.
    public func merge(
        _ base: DevContainerSpec,
        overrides: SandboxConfiguration.DevContainerConfig?
    ) -> DevContainerSpec {
        guard let overrides else { return base }

        var result = base

        // Merge extensions: combine bridge-detected extensions with user-specified ones.
        if !overrides.extensions.isEmpty {
            var existingExtensions = result.customizations?.vscode?.extensions ?? []
            for ext in overrides.extensions where !existingExtensions.contains(ext) {
                existingExtensions.append(ext)
            }

            if result.customizations == nil {
                result.customizations = DevContainerSpec.Customizations()
            }
            if result.customizations?.vscode == nil {
                result.customizations?.vscode = DevContainerSpec.Customizations.VSCodeConfig()
            }
            result.customizations?.vscode?.extensions = existingExtensions
        }

        return result
    }

    // MARK: - Copilot Bridge Integration

    /// Run the copilot-bridge TypeScript tool to analyze the project.
    ///
    /// Tries `npx tsx` first (development mode), falls back to the compiled
    /// `node dist/index.js` if available.
    private func runCopilotBridge(
        action: String,
        projectPath: String
    ) async throws -> Data {
        // Locate the copilot-bridge relative to the package root.
        let bridgeDir = findBridgeDirectory(from: projectPath)

        // Try tsx (development) first, then compiled JS.
        let strategies: [(executable: String, args: [String])] = [
            ("npx", ["tsx", "\(bridgeDir)/src/index.ts", action, "--project", projectPath]),
            ("node", ["\(bridgeDir)/dist/index.js", action, "--project", projectPath]),
        ]

        var lastError: Error?

        for strategy in strategies {
            do {
                let data = try await runProcess(
                    executable: strategy.executable,
                    arguments: strategy.args,
                    workingDirectory: bridgeDir
                )
                return data
            } catch {
                lastError = error
                logger.debug(
                    "Bridge strategy \(strategy.executable) failed: \(error.localizedDescription)"
                )
            }
        }

        throw lastError ?? BridgeError.notFound
    }

    /// Execute a subprocess and capture its stdout.
    private func runProcess(
        executable: String,
        arguments: [String],
        workingDirectory: String
    ) async throws -> Data {
        let process = Process()

        // Resolve the executable using /usr/bin/env for PATH lookup.
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [executable] + arguments
        process.currentDirectoryURL = URL(fileURLWithPath: workingDirectory)

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        // Inherit a minimal environment with PATH for tool resolution.
        var environment = ProcessInfo.processInfo.environment
        environment["NODE_NO_WARNINGS"] = "1"
        process.environment = environment

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
                return
            }

            process.waitUntilExit()

            guard process.terminationStatus == 0 else {
                let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
                let stderrText = String(data: stderrData, encoding: .utf8) ?? "unknown error"
                continuation.resume(
                    throwing: BridgeError.executionFailed(
                        exitCode: process.terminationStatus,
                        stderr: stderrText
                    )
                )
                return
            }

            let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            continuation.resume(returning: data)
        }
    }

    // MARK: - Helpers

    /// Build a sensible default devcontainer spec when the bridge is unavailable.
    private func defaultSpec(
        for projectPath: String,
        config: SandboxConfiguration
    ) -> DevContainerSpec {
        let projectName = URL(fileURLWithPath: projectPath).lastPathComponent

        return DevContainerSpec(
            name: config.name.isEmpty ? projectName : config.name,
            image: "mcr.microsoft.com/devcontainers/universal:2",
            customizations: DevContainerSpec.Customizations(
                vscode: DevContainerSpec.Customizations.VSCodeConfig(
                    extensions: config.devcontainer?.extensions ?? [
                        "github.copilot",
                        "github.copilot-chat",
                    ]
                )
            ),
            remoteUser: "vscode",
            containerEnv: [
                "SENDBOX_PROJECT": projectName,
            ]
        )
    }

    /// Locate the copilot-bridge directory by walking up from the project path.
    private func findBridgeDirectory(from projectPath: String) -> String {
        // The bridge lives at the repository root under `copilot-bridge/`.
        // Walk up from the project path to find it.
        var current = URL(fileURLWithPath: projectPath)
        for _ in 0..<10 {
            let candidate = current.appendingPathComponent("copilot-bridge")
            if FileManager.default.fileExists(atPath: candidate.appendingPathComponent("package.json").path) {
                return candidate.path
            }
            let parent = current.deletingLastPathComponent()
            if parent.path == current.path { break }
            current = parent
        }

        // Fallback: assume it's relative to the project.
        return URL(fileURLWithPath: projectPath)
            .appendingPathComponent("copilot-bridge")
            .path
    }

    /// Strip single-line comments (`//`) from JSON data to handle JSONC format.
    private func stripJSONComments(_ data: Data) -> Data {
        guard let text = String(data: data, encoding: .utf8) else {
            return data
        }

        let lines = text.components(separatedBy: .newlines)
        let cleaned = lines.map { line -> String in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("//") {
                return ""
            }
            return line
        }.joined(separator: "\n")

        return Data(cleaned.utf8)
    }
}

// MARK: - Errors

extension DevContainerBuilder {
    public enum BridgeError: Error, LocalizedError {
        case notFound
        case executionFailed(exitCode: Int32, stderr: String)

        public var errorDescription: String? {
            switch self {
            case .notFound:
                return "copilot-bridge tool not found"
            case .executionFailed(let code, let stderr):
                return "copilot-bridge exited with code \(code): \(stderr)"
            }
        }
    }
}
