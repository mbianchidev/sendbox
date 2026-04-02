import Foundation
import Crypto
import Logging

/// Content-addressed filesystem snapshots for undo & rollback.
///
/// Captures the state of the workspace directory before each agent session
/// using SHA-256 hashing. Each snapshot is a manifest of file paths → content hashes,
/// stored as a JSON file. Rollback restores files to a previous snapshot state.
public final class SnapshotManager: Sendable {

    private let snapshotDir: String
    private let logger: Logger

    // MARK: - Types

    /// A point-in-time snapshot of the workspace.
    public struct Snapshot: Codable, Sendable {
        public let id: String
        public let timestamp: Date
        public let sessionName: String
        public let workspacePath: String
        public let files: [FileEntry]
        public let totalSize: UInt64

        public struct FileEntry: Codable, Sendable {
            public let relativePath: String
            public let contentHash: String
            public let size: UInt64
            public let permissions: UInt16
            public let modifiedAt: Date

            private enum CodingKeys: String, CodingKey {
                case relativePath = "relative_path"
                case contentHash = "content_hash"
                case size
                case permissions
                case modifiedAt = "modified_at"
            }
        }

        private enum CodingKeys: String, CodingKey {
            case id
            case timestamp
            case sessionName = "session_name"
            case workspacePath = "workspace_path"
            case files
            case totalSize = "total_size"
        }
    }

    /// Result of restoring a workspace to a previous snapshot.
    public struct RestoreResult: Sendable {
        public let filesRestored: Int
        public let filesDeleted: Int
        public let filesUnchanged: Int
        public let changedPaths: [String]
    }

    /// Diff between two snapshots.
    public struct SnapshotDiff: Sendable {
        public let added: [String]
        public let modified: [String]
        public let deleted: [String]
        public let unchanged: [String]
    }

    public enum SnapshotError: Error, LocalizedError {
        case workspaceNotFound(String)
        case snapshotNotFound(String)
        case corruptedSnapshot(String)
        case restoreFailed(String)
        case hashMismatch(file: String, expected: String, actual: String)

        public var errorDescription: String? {
            switch self {
            case .workspaceNotFound(let path):
                return "Workspace not found: \(path)"
            case .snapshotNotFound(let id):
                return "Snapshot not found: \(id)"
            case .corruptedSnapshot(let reason):
                return "Corrupted snapshot: \(reason)"
            case .restoreFailed(let reason):
                return "Restore failed: \(reason)"
            case .hashMismatch(let file, let expected, let actual):
                return "Hash mismatch for \(file): expected \(expected), got \(actual)"
            }
        }
    }

    private static let ignoredNames: Set<String> = [
        ".git", ".build", "node_modules", ".DS_Store",
        ".swiftpm", "__pycache__", ".tox", ".venv",
    ]

    // MARK: - Init

    public init(
        snapshotDir: String = "~/.sendbox/snapshots",
        logger: Logger = Logger(label: "sendbox.snapshots")
    ) {
        self.snapshotDir = (snapshotDir as NSString).expandingTildeInPath
        self.logger = logger
    }

    // MARK: - Public API

    /// Create a snapshot of the workspace before a session starts.
    /// Returns the snapshot ID (content-addressed hash of the manifest).
    public func capture(workspace: String, sessionName: String) throws -> Snapshot {
        let expandedPath = (workspace as NSString).expandingTildeInPath
        let fm = FileManager.default

        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: expandedPath, isDirectory: &isDir), isDir.boolValue else {
            throw SnapshotError.workspaceNotFound(expandedPath)
        }

        logger.info("Capturing snapshot", metadata: [
            "workspace": "\(expandedPath)",
            "session": "\(sessionName)",
        ])

        let entries = try scanWorkspace(at: expandedPath)
        let totalSize = entries.reduce(UInt64(0)) { $0 + $1.size }
        let now = Date()

        // Hash the manifest content (excluding the ID) to produce a content-addressed ID.
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]

        let hashableContent = Snapshot(
            id: "",
            timestamp: now,
            sessionName: sessionName,
            workspacePath: expandedPath,
            files: entries,
            totalSize: totalSize
        )
        let manifestData = try encoder.encode(hashableContent)
        let snapshotId = sha256Hex(manifestData)

        let snapshot = Snapshot(
            id: snapshotId,
            timestamp: now,
            sessionName: sessionName,
            workspacePath: expandedPath,
            files: entries,
            totalSize: totalSize
        )

        try fm.createDirectory(atPath: snapshotDir, withIntermediateDirectories: true)

        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        let finalData = try encoder.encode(snapshot)
        try finalData.write(to: URL(fileURLWithPath: manifestFilePath(for: snapshotId)))

        // Store a compressed tarball alongside the manifest for restore.
        try createTarball(for: snapshotId, workspace: expandedPath)

        logger.info("Snapshot captured", metadata: [
            "id": "\(snapshotId)",
            "files": "\(entries.count)",
            "size": "\(totalSize)",
        ])

        return snapshot
    }

    /// List all snapshots for a workspace, newest first.
    public func list(workspace: String? = nil) throws -> [Snapshot] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: snapshotDir) else { return [] }

        let contents = try fm.contentsOfDirectory(atPath: snapshotDir)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let expandedWorkspace = workspace.map { ($0 as NSString).expandingTildeInPath }

        var snapshots: [Snapshot] = []
        for file in contents where file.hasSuffix(".json") {
            let path = (snapshotDir as NSString).appendingPathComponent(file)
            guard let data = fm.contents(atPath: path),
                  let snapshot = try? decoder.decode(Snapshot.self, from: data) else { continue }

            if let ws = expandedWorkspace, snapshot.workspacePath != ws { continue }
            snapshots.append(snapshot)
        }

        return snapshots.sorted { $0.timestamp > $1.timestamp }
    }

    /// Get a specific snapshot by ID.
    public func get(id: String) throws -> Snapshot {
        let path = manifestFilePath(for: id)
        guard let data = FileManager.default.contents(atPath: path) else {
            throw SnapshotError.snapshotNotFound(id)
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        do {
            return try decoder.decode(Snapshot.self, from: data)
        } catch {
            throw SnapshotError.corruptedSnapshot(
                "Failed to decode snapshot \(id): \(error.localizedDescription)"
            )
        }
    }

    /// Restore a workspace to a previous snapshot state.
    /// Files added after the snapshot are deleted. Modified files are restored.
    /// Returns a list of changes made during restore.
    public func restore(snapshotId: String) throws -> RestoreResult {
        let snapshot = try get(id: snapshotId)
        let tarball = tarballFilePath(for: snapshotId)
        let fm = FileManager.default

        guard fm.fileExists(atPath: tarball) else {
            throw SnapshotError.restoreFailed("Tarball not found for snapshot \(snapshotId)")
        }

        let workspace = snapshot.workspacePath
        logger.info("Restoring snapshot", metadata: [
            "id": "\(snapshotId)",
            "workspace": "\(workspace)",
        ])

        let currentFiles = try scanWorkspace(at: workspace)
        let snapshotPaths = Set(snapshot.files.map(\.relativePath))
        let currentPaths = Set(currentFiles.map(\.relativePath))
        let currentByPath = Dictionary(
            currentFiles.map { ($0.relativePath, $0) },
            uniquingKeysWith: { first, _ in first }
        )

        var changedPaths: [String] = []
        var filesDeleted = 0

        // Delete files that were added after the snapshot.
        for path in currentPaths.subtracting(snapshotPaths).sorted() {
            let fullPath = (workspace as NSString).appendingPathComponent(path)
            try fm.removeItem(atPath: fullPath)
            filesDeleted += 1
            changedPaths.append(path)
        }

        // Extract tarball to restore original files.
        try extractTarball(tarballPath: tarball, to: workspace)

        var filesRestored = 0
        var filesUnchanged = 0
        for entry in snapshot.files {
            if let current = currentByPath[entry.relativePath],
               current.contentHash == entry.contentHash {
                filesUnchanged += 1
            } else {
                filesRestored += 1
                changedPaths.append(entry.relativePath)
            }
        }

        logger.info("Snapshot restored", metadata: [
            "restored": "\(filesRestored)",
            "deleted": "\(filesDeleted)",
            "unchanged": "\(filesUnchanged)",
        ])

        return RestoreResult(
            filesRestored: filesRestored,
            filesDeleted: filesDeleted,
            filesUnchanged: filesUnchanged,
            changedPaths: changedPaths.sorted()
        )
    }

    /// Compare two snapshots and return the diff.
    public func diff(from fromId: String, to toId: String) throws -> SnapshotDiff {
        let fromSnapshot = try get(id: fromId)
        let toSnapshot = try get(id: toId)

        let fromByPath = Dictionary(
            fromSnapshot.files.map { ($0.relativePath, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let toByPath = Dictionary(
            toSnapshot.files.map { ($0.relativePath, $0) },
            uniquingKeysWith: { first, _ in first }
        )

        let fromPaths = Set(fromByPath.keys)
        let toPaths = Set(toByPath.keys)

        let added = toPaths.subtracting(fromPaths).sorted()
        let deleted = fromPaths.subtracting(toPaths).sorted()

        var modified: [String] = []
        var unchanged: [String] = []
        for path in fromPaths.intersection(toPaths).sorted() {
            if fromByPath[path]!.contentHash != toByPath[path]!.contentHash {
                modified.append(path)
            } else {
                unchanged.append(path)
            }
        }

        return SnapshotDiff(
            added: added,
            modified: modified,
            deleted: deleted,
            unchanged: unchanged
        )
    }

    /// Delete old snapshots, keeping the N most recent per workspace.
    public func prune(keep: Int = 10) throws -> Int {
        let allSnapshots = try list(workspace: nil)
        let fm = FileManager.default

        // Group by workspace path.
        var byWorkspace: [String: [Snapshot]] = [:]
        for snapshot in allSnapshots {
            byWorkspace[snapshot.workspacePath, default: []].append(snapshot)
        }

        var deletedCount = 0
        for (_, snapshots) in byWorkspace {
            // Already sorted newest-first from list().
            for snapshot in snapshots.dropFirst(keep) {
                try? fm.removeItem(atPath: manifestFilePath(for: snapshot.id))
                try? fm.removeItem(atPath: tarballFilePath(for: snapshot.id))
                deletedCount += 1
                logger.debug("Pruned snapshot", metadata: ["id": "\(snapshot.id)"])
            }
        }

        logger.info("Pruned snapshots", metadata: ["deleted": "\(deletedCount)"])
        return deletedCount
    }

    /// Verify a snapshot's integrity (re-hash files and compare).
    public func verify(snapshotId: String) throws -> Bool {
        let snapshot = try get(id: snapshotId)
        let fm = FileManager.default

        for entry in snapshot.files {
            let fullPath = (snapshot.workspacePath as NSString)
                .appendingPathComponent(entry.relativePath)
            guard let data = fm.contents(atPath: fullPath) else {
                logger.warning("File missing during verify", metadata: [
                    "path": "\(entry.relativePath)",
                ])
                return false
            }
            let actual = sha256Hex(data)
            guard actual == entry.contentHash else {
                throw SnapshotError.hashMismatch(
                    file: entry.relativePath,
                    expected: entry.contentHash,
                    actual: actual
                )
            }
        }

        logger.info("Snapshot verified", metadata: ["id": "\(snapshotId)"])
        return true
    }

    // MARK: - Private helpers

    private func manifestFilePath(for id: String) -> String {
        (snapshotDir as NSString).appendingPathComponent("\(id).json")
    }

    private func tarballFilePath(for id: String) -> String {
        (snapshotDir as NSString).appendingPathComponent("\(id).tar.gz")
    }

    /// Recursively scan the workspace and build a sorted list of file entries.
    private func scanWorkspace(at path: String) throws -> [Snapshot.FileEntry] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: URL(fileURLWithPath: path),
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey]
        ) else {
            throw SnapshotError.workspaceNotFound(path)
        }

        let basePath = URL(fileURLWithPath: path).standardized.path
        let prefix = basePath + "/"
        var entries: [Snapshot.FileEntry] = []

        while let fileURL = enumerator.nextObject() as? URL {
            if Self.ignoredNames.contains(fileURL.lastPathComponent) {
                enumerator.skipDescendants()
                continue
            }

            let values = try fileURL.resourceValues(forKeys: [
                .isRegularFileKey, .fileSizeKey, .contentModificationDateKey,
            ])
            guard values.isRegularFile == true else { continue }
            guard fileURL.path.hasPrefix(prefix) else { continue }

            let relativePath = String(fileURL.path.dropFirst(prefix.count))
            guard let data = fm.contents(atPath: fileURL.path) else { continue }

            let attrs = try fm.attributesOfItem(atPath: fileURL.path)
            let permissions = UInt16((attrs[.posixPermissions] as? Int) ?? 0o644)

            entries.append(Snapshot.FileEntry(
                relativePath: relativePath,
                contentHash: sha256Hex(data),
                size: UInt64(values.fileSize ?? 0),
                permissions: permissions,
                modifiedAt: values.contentModificationDate ?? Date()
            ))
        }

        // Sort by path for deterministic hashing.
        return entries.sorted { $0.relativePath < $1.relativePath }
    }

    private func createTarball(for snapshotId: String, workspace: String) throws {
        let tarball = tarballFilePath(for: snapshotId)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")

        var args = ["czf", tarball]
        for name in Self.ignoredNames.sorted() {
            args.append(contentsOf: ["--exclude", name])
        }
        args.append(contentsOf: ["-C", workspace, "."])

        process.arguments = args
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            throw SnapshotError.restoreFailed(
                "Failed to create tarball (exit \(process.terminationStatus))"
            )
        }
    }

    private func extractTarball(tarballPath: String, to workspace: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.arguments = ["xzf", tarballPath, "-C", workspace]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            throw SnapshotError.restoreFailed(
                "Failed to extract tarball (exit \(process.terminationStatus))"
            )
        }
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
