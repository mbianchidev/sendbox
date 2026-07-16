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
        environment: [String: String] = [:],
        inheritEnvironment: Bool = true
    ) async throws -> HostCommandResult {
        let cancellation = ProcessCancellation()
        return try await withTaskCancellationHandler {
            try await Task.detached {
                try runSynchronously(
                    executable: executable,
                    arguments: arguments,
                    environment: environment,
                    inheritEnvironment: inheritEnvironment,
                    cancellation: cancellation
                )
            }.value
        } onCancel: {
            cancellation.cancel()
        }
    }

    private static func runSynchronously(
        executable: String,
        arguments: [String],
        environment: [String: String],
        inheritEnvironment: Bool,
        cancellation: ProcessCancellation
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
        if inheritEnvironment {
            process.environment = ProcessInfo.processInfo.environment.merging(
                environment,
                uniquingKeysWith: { _, override in override }
            )
        } else {
            process.environment = environment
        }

        try process.run()
        cancellation.install(process)
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

private final class ProcessCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var isCancelled = false

    func install(_ process: Process) {
        lock.lock()
        self.process = process
        let shouldTerminate = isCancelled
        lock.unlock()

        if shouldTerminate && process.isRunning {
            process.terminate()
        }
    }

    func cancel() {
        lock.lock()
        isCancelled = true
        let process = process
        lock.unlock()

        if process?.isRunning == true {
            process?.terminate()
        }
    }
}
