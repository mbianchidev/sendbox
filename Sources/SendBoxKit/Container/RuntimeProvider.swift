import Foundation
import Logging

/// Cross-runtime lifecycle state for a sandbox container.
public enum RuntimeContainerStatus: String, Sendable {
    case creating
    case running
    case stopped
    case failed
    case unknown
}

/// The result of executing a command inside a runtime-managed container.
public struct ExecResult: Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public init(exitCode: Int32, stdout: String, stderr: String) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

/// Runtime-neutral container lifecycle used by the agent runner.
public protocol RuntimeProvider: Sendable {
    func initialize() async throws
    func createContainer(_ config: ContainerConfig) async throws -> String
    func stopContainer(id: String) async throws
    func containerStatus(id: String) async -> RuntimeContainerStatus
    func exec(
        containerId: String,
        command: [String],
        policy: CommandPolicy
    ) async throws -> ExecResult
    func attachOutput(containerId: String) async throws -> AsyncStream<String>
    func cleanup() async throws
}

public enum RuntimeProviderError: Error, LocalizedError {
    case unavailable(RuntimeConfiguration.Provider, String)

    public var errorDescription: String? {
        switch self {
        case .unavailable(let provider, let reason):
            return "Runtime provider '\(provider.rawValue)' is unavailable: \(reason)"
        }
    }
}

/// Selects the configured runtime while keeping host-specific implementations isolated.
public enum RuntimeProviderFactory {
    public static func make(
        configuration: RuntimeConfiguration = .default,
        logger: Logger = Logger(label: "sendbox.runtime")
    ) -> any RuntimeProvider {
        switch resolvedProvider(for: configuration.provider) {
        case .automatic:
            return UnavailableRuntimeProvider(
                provider: .automatic,
                reason: "automatic runtime resolution failed"
            )
        case .apple:
            #if canImport(Containerization)
            return ContainerRuntime(logger: logger)
            #else
            return UnavailableRuntimeProvider(
                provider: .apple,
                reason: "Apple Containerization is only available on supported macOS hosts"
            )
            #endif
        case .kata:
            return KataContainerRuntime(configuration: configuration.kata, logger: logger)
        }
    }

    public static func resolvedProvider(
        for provider: RuntimeConfiguration.Provider
    ) -> RuntimeConfiguration.Provider {
        guard provider == .automatic else {
            return provider
        }

        #if canImport(Containerization)
        return .apple
        #else
        return .kata
        #endif
    }
}

private struct UnavailableRuntimeProvider: RuntimeProvider {
    let provider: RuntimeConfiguration.Provider
    let reason: String

    func initialize() async throws {
        throw RuntimeProviderError.unavailable(provider, reason)
    }

    func createContainer(_ config: ContainerConfig) async throws -> String {
        throw RuntimeProviderError.unavailable(provider, reason)
    }

    func stopContainer(id: String) async throws {
        throw RuntimeProviderError.unavailable(provider, reason)
    }

    func containerStatus(id: String) async -> RuntimeContainerStatus {
        .unknown
    }

    func exec(
        containerId: String,
        command: [String],
        policy: CommandPolicy
    ) async throws -> ExecResult {
        throw RuntimeProviderError.unavailable(provider, reason)
    }

    func attachOutput(containerId: String) async throws -> AsyncStream<String> {
        throw RuntimeProviderError.unavailable(provider, reason)
    }

    func cleanup() async throws {
        throw RuntimeProviderError.unavailable(provider, reason)
    }
}
