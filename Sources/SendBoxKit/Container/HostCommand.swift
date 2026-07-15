import Foundation

struct HostCommandResult: Sendable, Equatable {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

enum HostCommand {
    static func run(
        executable: String,
        arguments: [String],
        environment: [String: String] = [:]
    ) async throws -> HostCommandResult {
        try await Task.detached {
            try runSynchronously(
                executable: executable,
                arguments: arguments,
                environment: environment
            )
        }.value
    }

    private static func runSynchronously(
        executable: String,
        arguments: [String],
        environment: [String: String]
    ) throws -> HostCommandResult {
        let fileManager = FileManager.default
        let captureDirectory = fileManager.temporaryDirectory
            .appendingPathComponent("sendbox-command-\(UUID().uuidString)", isDirectory: true)

        try SecureFile.ensureDirectory(at: captureDirectory)
        defer {
            try? fileManager.removeItem(at: captureDirectory)
        }

        let stdoutURL = captureDirectory.appendingPathComponent("stdout")
        let stderrURL = captureDirectory.appendingPathComponent("stderr")

        try SecureFile.create(at: stdoutURL, data: Data())
        try SecureFile.create(at: stderrURL, data: Data())

        let stdoutHandle = try FileHandle(forWritingTo: stdoutURL)
        let stderrHandle = try FileHandle(forWritingTo: stderrURL)
        defer {
            try? stdoutHandle.close()
            try? stderrHandle.close()
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [executable] + arguments
        process.standardOutput = stdoutHandle
        process.standardError = stderrHandle
        if !environment.isEmpty {
            process.environment = ProcessInfo.processInfo.environment.merging(
                environment,
                uniquingKeysWith: { _, override in override }
            )
        }

        try process.run()
        process.waitUntilExit()
        try stdoutHandle.close()
        try stderrHandle.close()

        let stdout = String(data: try Data(contentsOf: stdoutURL), encoding: .utf8) ?? ""
        let stderr = String(data: try Data(contentsOf: stderrURL), encoding: .utf8) ?? ""

        return HostCommandResult(
            exitCode: process.terminationStatus,
            stdout: stdout,
            stderr: stderr
        )
    }
}
