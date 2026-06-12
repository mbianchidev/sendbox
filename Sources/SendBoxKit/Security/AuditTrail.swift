import Foundation
import Crypto
import Logging

/// Cryptographically-verified audit trail using Merkle trees.
///
/// Every action taken by an agent (command execution, file access, network request,
/// permission change) is logged as an AuditEntry. Entries are organized into a
/// Merkle tree so that:
/// 1. Any tampering with the log is detectable
/// 2. Individual entries can be verified against the root hash
/// 3. The full log can be exported for compliance/review
public actor AuditTrail {

    private let logDir: String
    private let logger: Logger
    private var entries: [AuditEntry]
    private var tree: MerkleTree?
    private let sessionId: String

    private static let genesisHash = "sendbox-genesis-v1"

    // MARK: - Types

    /// A single auditable action.
    public struct AuditEntry: Codable, Sendable {
        public let id: String
        public let timestamp: Date
        public let sessionId: String
        public let category: Category
        public let action: String
        public let subject: String
        public let outcome: Outcome
        public let details: [String: String]?
        public let hash: String

        public enum Category: String, Codable, Sendable {
            case command
            case fileAccess = "file_access"
            case network
            case permission
            case secret
            case lifecycle
            case policy
            case mcp
        }

        public enum Outcome: String, Codable, Sendable {
            case allowed
            case denied
            case error
        }

        private enum CodingKeys: String, CodingKey {
            case id
            case timestamp
            case sessionId = "session_id"
            case category
            case action
            case subject
            case outcome
            case details
            case hash
        }
    }

    /// Merkle tree for log integrity verification.
    public struct MerkleTree: Codable, Sendable {
        public let rootHash: String
        public let leafCount: Int
        public let nodes: [String]

        public struct ProofNode: Codable, Sendable {
            public let hash: String
            public let position: Position

            public enum Position: String, Codable, Sendable {
                case left, right
            }
        }

        private enum CodingKeys: String, CodingKey {
            case rootHash = "root_hash"
            case leafCount = "leaf_count"
            case nodes
        }

        /// Build a Merkle tree from leaf hashes.
        public init(leaves: [String]) {
            leafCount = leaves.count

            guard !leaves.isEmpty else {
                rootHash = ""
                nodes = []
                return
            }

            // Pad leaves to the next power of two by duplicating the last leaf.
            var padded = leaves
            let target = Self.nextPowerOf2(leaves.count)
            while padded.count < target {
                padded.append(padded.last!)
            }

            // Build the tree in a flat array (root at index 0).
            let total = 2 * target - 1
            var nodeArray = Array(repeating: "", count: total)
            let leafStart = target - 1

            for (i, hash) in padded.enumerated() {
                nodeArray[leafStart + i] = hash
            }

            // Compute internal nodes bottom-up.
            for i in stride(from: leafStart - 1, through: 0, by: -1) {
                nodeArray[i] = Self.hashPair(nodeArray[2 * i + 1], nodeArray[2 * i + 2])
            }

            rootHash = nodeArray[0]
            nodes = nodeArray
        }

        /// Verify that a specific entry is part of this tree.
        public func verify(entryHash: String, index: Int) -> Bool {
            guard index >= 0, index < leafCount, !nodes.isEmpty else { return false }

            let proof = proofPath(for: index)
            var current = entryHash

            for node in proof {
                switch node.position {
                case .left:
                    current = Self.hashPair(node.hash, current)
                case .right:
                    current = Self.hashPair(current, node.hash)
                }
            }

            return current == rootHash
        }

        /// Get the proof path for an entry at a given index.
        public func proofPath(for index: Int) -> [ProofNode] {
            guard !nodes.isEmpty, index >= 0, index < leafCount else { return [] }

            let paddedCount = Self.nextPowerOf2(leafCount)
            let leafStart = paddedCount - 1
            var nodeIndex = leafStart + index
            var proof: [ProofNode] = []

            while nodeIndex > 0 {
                let isLeftChild = (nodeIndex % 2 == 1)
                let sibling = isLeftChild ? nodeIndex + 1 : nodeIndex - 1

                guard sibling < nodes.count else { break }

                proof.append(ProofNode(
                    hash: nodes[sibling],
                    position: isLeftChild ? .right : .left
                ))

                nodeIndex = (nodeIndex - 1) / 2
            }

            return proof
        }

        private static func hashPair(_ left: String, _ right: String) -> String {
            let data = Data((left + right).utf8)
            return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }

        private static func nextPowerOf2(_ n: Int) -> Int {
            guard n > 1 else { return 1 }
            var v = n - 1
            v |= v >> 1
            v |= v >> 2
            v |= v >> 4
            v |= v >> 8
            v |= v >> 16
            return v + 1
        }
    }

    /// Result of an integrity verification.
    public struct IntegrityResult: Sendable {
        public let isValid: Bool
        public let entriesVerified: Int
        public let firstCorruptedIndex: Int?
        public let rootHash: String
    }

    /// Summary statistics of the audit trail.
    public struct AuditSummary: Sendable {
        public let totalEntries: Int
        public let commandsExecuted: Int
        public let commandsBlocked: Int
        public let filesAccessed: Int
        public let networkConnections: Int
        public let duration: TimeInterval?
    }

    public enum AuditError: Error, LocalizedError {
        case sessionNotFound(String)
        case corruptedEntry(index: Int, reason: String)
        case saveFailed(String)

        public var errorDescription: String? {
            switch self {
            case .sessionNotFound(let id):
                return "Audit session not found: \(id)"
            case .corruptedEntry(let index, let reason):
                return "Corrupted entry at index \(index): \(reason)"
            case .saveFailed(let reason):
                return "Failed to save audit trail: \(reason)"
            }
        }
    }

    // MARK: - Init

    public init(
        sessionId: String,
        logDir: String = "~/.sendbox/audit",
        logger: Logger = Logger(label: "sendbox.audit")
    ) {
        self.sessionId = sessionId
        self.logDir = (logDir as NSString).expandingTildeInPath
        self.logger = logger
        self.entries = []
        self.tree = nil
    }

    private init(
        sessionId: String,
        logDir: String,
        logger: Logger,
        entries: [AuditEntry],
        tree: MerkleTree?
    ) {
        self.sessionId = sessionId
        self.logDir = logDir
        self.logger = logger
        self.entries = entries
        self.tree = tree
    }

    // MARK: - Public API

    /// Log a new audit entry. Returns the entry's hash.
    public func log(
        category: AuditEntry.Category,
        action: String,
        subject: String,
        outcome: AuditEntry.Outcome,
        details: [String: String]? = nil
    ) -> String {
        let previousHash = entries.last?.hash ?? Self.genesisHash
        let id = UUID().uuidString
        let timestamp = Date()

        let hash = computeEntryHash(
            previousHash: previousHash,
            id: id,
            timestamp: timestamp,
            category: category,
            action: action,
            subject: subject,
            outcome: outcome,
            details: details
        )

        let entry = AuditEntry(
            id: id,
            timestamp: timestamp,
            sessionId: sessionId,
            category: category,
            action: action,
            subject: subject,
            outcome: outcome,
            details: details,
            hash: hash
        )

        entries.append(entry)
        tree = nil

        logger.info("Audit entry", metadata: [
            "category": "\(category.rawValue)",
            "action": "\(action)",
            "outcome": "\(outcome.rawValue)",
        ])

        return hash
    }

    /// Build/rebuild the Merkle tree from current entries.
    @discardableResult
    public func buildTree() -> MerkleTree {
        let leaves = entries.map(\.hash)
        let newTree = MerkleTree(leaves: leaves)
        tree = newTree
        return newTree
    }

    /// Verify the entire audit trail's integrity.
    public func verifyIntegrity() -> IntegrityResult {
        // Re-compute every hash in the chain.
        var previousHash = Self.genesisHash

        for (index, entry) in entries.enumerated() {
            let expected = computeEntryHash(
                previousHash: previousHash,
                id: entry.id,
                timestamp: entry.timestamp,
                category: entry.category,
                action: entry.action,
                subject: entry.subject,
                outcome: entry.outcome,
                details: entry.details
            )

            if expected != entry.hash {
                logger.warning("Integrity check failed", metadata: [
                    "index": "\(index)",
                    "expected": "\(expected)",
                    "actual": "\(entry.hash)",
                ])
                return IntegrityResult(
                    isValid: false,
                    entriesVerified: index,
                    firstCorruptedIndex: index,
                    rootHash: tree?.rootHash ?? ""
                )
            }
            previousHash = entry.hash
        }

        let currentTree = tree ?? buildTree()
        return IntegrityResult(
            isValid: true,
            entriesVerified: entries.count,
            firstCorruptedIndex: nil,
            rootHash: currentTree.rootHash
        )
    }

    /// Export the full audit trail as JSON.
    public func export() throws -> Data {
        let payload = ExportPayload(
            sessionId: sessionId,
            entries: entries,
            tree: tree ?? buildTree()
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        return try encoder.encode(payload)
    }

    /// Export as human-readable text report.
    public func exportReport() -> String {
        let formatter = ISO8601DateFormatter()
        var lines: [String] = [
            "=== SendBox Audit Report ===",
            "Session: \(sessionId)",
            "Entries: \(entries.count)",
            "",
        ]

        for (index, entry) in entries.enumerated() {
            lines.append(
                "[\(index)] \(formatter.string(from: entry.timestamp)) "
                    + "[\(entry.category.rawValue)] \(entry.action) → \(entry.subject) "
                    + "(\(entry.outcome.rawValue))"
            )
            if let details = entry.details, !details.isEmpty {
                for (key, value) in details.sorted(by: { $0.key < $1.key }) {
                    lines.append("       \(key): \(value)")
                }
            }
        }

        if let tree {
            lines.append("")
            lines.append("Merkle root: \(tree.rootHash)")
        }

        lines.append("")
        return lines.joined(separator: "\n")
    }

    /// Get entries filtered by category, time range, or outcome.
    public func query(
        category: AuditEntry.Category? = nil,
        from: Date? = nil,
        to: Date? = nil,
        outcome: AuditEntry.Outcome? = nil
    ) -> [AuditEntry] {
        entries.filter { entry in
            if let category, entry.category != category { return false }
            if let from, entry.timestamp < from { return false }
            if let to, entry.timestamp > to { return false }
            if let outcome, entry.outcome != outcome { return false }
            return true
        }
    }

    /// Save the current state (entries + tree) to disk.
    public func save() throws {
        let fm = FileManager.default
        let sessionDir = (logDir as NSString).appendingPathComponent(sessionId)
        try fm.createDirectory(atPath: sessionDir, withIntermediateDirectories: true)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]

        let entriesData = try encoder.encode(entries)
        let entriesPath = (sessionDir as NSString).appendingPathComponent("entries.json")
        try entriesData.write(to: URL(fileURLWithPath: entriesPath))

        let currentTree = tree ?? buildTree()
        let treeData = try encoder.encode(currentTree)
        let treePath = (sessionDir as NSString).appendingPathComponent("tree.json")
        try treeData.write(to: URL(fileURLWithPath: treePath))

        logger.info("Audit trail saved", metadata: [
            "session": "\(sessionId)",
            "entries": "\(entries.count)",
        ])
    }

    /// Load a previous session's audit trail.
    public static func load(
        sessionId: String,
        logDir: String = "~/.sendbox/audit"
    ) throws -> AuditTrail {
        let expandedDir = (logDir as NSString).expandingTildeInPath
        let sessionDir = (expandedDir as NSString).appendingPathComponent(sessionId)
        let entriesPath = (sessionDir as NSString).appendingPathComponent("entries.json")
        let treePath = (sessionDir as NSString).appendingPathComponent("tree.json")

        let fm = FileManager.default
        guard let entriesData = fm.contents(atPath: entriesPath) else {
            throw AuditError.sessionNotFound(sessionId)
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let loadedEntries = try decoder.decode([AuditEntry].self, from: entriesData)

        var loadedTree: MerkleTree?
        if let treeData = fm.contents(atPath: treePath) {
            loadedTree = try? decoder.decode(MerkleTree.self, from: treeData)
        }

        return AuditTrail(
            sessionId: sessionId,
            logDir: expandedDir,
            logger: Logger(label: "sendbox.audit"),
            entries: loadedEntries,
            tree: loadedTree
        )
    }

    /// Get summary statistics.
    public func summary() -> AuditSummary {
        let commands = entries.filter { $0.category == .command }
        let duration: TimeInterval?
        if let first = entries.first?.timestamp, let last = entries.last?.timestamp {
            duration = last.timeIntervalSince(first)
        } else {
            duration = nil
        }

        return AuditSummary(
            totalEntries: entries.count,
            commandsExecuted: commands.filter { $0.outcome == .allowed }.count,
            commandsBlocked: commands.filter { $0.outcome == .denied }.count,
            filesAccessed: entries.filter { $0.category == .fileAccess }.count,
            networkConnections: entries.filter { $0.category == .network }.count,
            duration: duration
        )
    }

    // MARK: - Private helpers

    private func computeEntryHash(
        previousHash: String,
        id: String,
        timestamp: Date,
        category: AuditEntry.Category,
        action: String,
        subject: String,
        outcome: AuditEntry.Outcome,
        details: [String: String]?
    ) -> String {
        let formatter = ISO8601DateFormatter()
        let detailsStr = details?
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: ",") ?? ""

        let content = [
            id,
            formatter.string(from: timestamp),
            sessionId,
            category.rawValue,
            action,
            subject,
            outcome.rawValue,
            detailsStr,
        ].joined(separator: "|")

        let hashInput = previousHash + content
        return sha256Hex(Data(hashInput.utf8))
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Private Codable Helpers

private struct ExportPayload: Codable, Sendable {
    let sessionId: String
    let entries: [AuditTrail.AuditEntry]
    let tree: AuditTrail.MerkleTree

    private enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case entries
        case tree
    }
}
