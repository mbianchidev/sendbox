import Foundation
import Logging
import Security

/// Manages secrets via the macOS Keychain, providing safe injection into containers.
public final class SecretsVault: Sendable {

    private let serviceName: String
    private let logger: Logger

    // MARK: - Types

    public struct Secret: Sendable {
        public let key: String
        public let createdAt: Date
        public let updatedAt: Date
    }

    public enum VaultError: Error, LocalizedError {
        case secretNotFound(String)
        case keychainError(OSStatus)
        case encodingError
        case accessDenied

        public var errorDescription: String? {
            switch self {
            case .secretNotFound(let key):
                return "Secret not found: \(key)"
            case .keychainError(let status):
                return "Keychain error: \(status) (\(SecCopyErrorMessageString(status, nil) as String? ?? "unknown"))"
            case .encodingError:
                return "Failed to encode/decode secret value"
            case .accessDenied:
                return "Access denied to the Keychain"
            }
        }
    }

    // MARK: - Init

    public init(
        serviceName: String = "com.sendbox.secrets",
        logger: Logger = Logger(label: "sendbox.secrets")
    ) {
        self.serviceName = serviceName
        self.logger = logger
    }

    // MARK: - Public API

    /// Store a secret in the Keychain. Updates in-place if it already exists.
    public func store(key: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw VaultError.encodingError
        }

        // Try to update first.
        if (try? exists(key: key)) == true {
            let query = baseQuery(for: key)
            let attributes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrComment as String: ISO8601DateFormatter().string(from: Date()),
            ]
            let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            guard status == errSecSuccess else {
                throw mapStatus(status)
            }
            logger.info("Updated secret", metadata: ["key": "\(key)"])
            return
        }

        var query = baseQuery(for: key)
        query[kSecValueData as String] = data
        let now = ISO8601DateFormatter().string(from: Date())
        query[kSecAttrComment as String] = now
        query[kSecAttrDescription as String] = "sendbox-secret"

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw mapStatus(status)
        }
        logger.info("Stored secret", metadata: ["key": "\(key)"])
    }

    /// Retrieve the value of a secret.
    public func retrieve(key: String) throws -> String {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            throw mapStatus(status, key: key)
        }
        guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
            throw VaultError.encodingError
        }
        // Intentionally never log the value.
        logger.debug("Retrieved secret", metadata: ["key": "\(key)"])
        return value
    }

    /// Delete a secret from the Keychain.
    public func delete(key: String) throws {
        let query = baseQuery(for: key)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapStatus(status, key: key)
        }
        logger.info("Deleted secret", metadata: ["key": "\(key)"])
    }

    /// List all secret keys stored under this service (values are never returned).
    public func list() throws -> [Secret] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        // Not requesting kSecReturnData — values stay in the Keychain.
        _ = query  // silence unused-var warning in some toolchains

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw mapStatus(status)
        }

        guard let items = result as? [[String: Any]] else {
            return []
        }

        let formatter = ISO8601DateFormatter()
        return items.compactMap { attrs in
            guard let account = attrs[kSecAttrAccount as String] as? String else { return nil }
            let commentStr = attrs[kSecAttrComment as String] as? String
            let timestamp = commentStr.flatMap { formatter.date(from: $0) } ?? Date()
            let creation = attrs[kSecAttrCreationDate as String] as? Date ?? timestamp
            return Secret(key: account, createdAt: creation, updatedAt: timestamp)
        }
    }

    /// Check whether a secret with the given key exists.
    public func exists(key: String) throws -> Bool {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = false

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        default:
            throw mapStatus(status, key: key)
        }
    }

    /// Generate a shell snippet that exports secrets as environment variables.
    public func generateEnvScript(keys: [String]) throws -> String {
        var lines: [String] = [
            "#!/usr/bin/env bash",
            "# Generated by SendBox SecretsVault",
            "# WARNING: contains sensitive values — do not persist to disk.",
            "",
        ]
        for key in keys {
            let value = try retrieve(key: key)
            let escaped = value
                .replacingOccurrences(of: "'", with: "'\\''")
            lines.append("export \(key)='\(escaped)'")
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }

    /// Write each secret to `outputDir/<key>` (like Docker /run/secrets) and return paths.
    public func generateSecretFiles(keys: [String], outputDir: String) throws -> [String] {
        let fm = FileManager.default
        if !fm.fileExists(atPath: outputDir) {
            try fm.createDirectory(atPath: outputDir, withIntermediateDirectories: true)
        }

        var paths: [String] = []
        for key in keys {
            let value = try retrieve(key: key)
            let filePath = (outputDir as NSString).appendingPathComponent(key)
            guard let data = value.data(using: .utf8) else {
                throw VaultError.encodingError
            }
            try data.write(to: URL(fileURLWithPath: filePath))

            // Restrict permissions: owner read-only.
            try fm.setAttributes(
                [.posixPermissions: 0o400],
                ofItemAtPath: filePath
            )
            paths.append(filePath)
            logger.info("Wrote secret file", metadata: ["path": "\(filePath)"])
        }
        return paths
    }

    // MARK: - Private helpers

    private func baseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
        ]
    }

    private func mapStatus(_ status: OSStatus, key: String? = nil) -> VaultError {
        switch status {
        case errSecItemNotFound:
            return .secretNotFound(key ?? "<unknown>")
        case errSecAuthFailed, errSecInteractionNotAllowed:
            return .accessDenied
        default:
            return .keychainError(status)
        }
    }
}
