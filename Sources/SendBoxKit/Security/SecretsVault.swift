import Foundation
import Logging

#if canImport(Security)
import Security
#endif

/// Manages secrets via macOS Keychain or a protected Linux file store.
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
        case keychainError(Int32)
        case storageError(String)
        case encodingError
        case accessDenied

        public var errorDescription: String? {
            switch self {
            case .secretNotFound(let key):
                return "Secret not found: \(key)"
            case .keychainError(let status):
                #if canImport(Security)
                let message =
                    SecCopyErrorMessageString(OSStatus(status), nil) as String? ?? "unknown"
                return "Keychain error: \(status) (\(message))"
                #else
                return "Keychain error: \(status)"
                #endif
            case .storageError(let reason):
                return "Secret storage error: \(reason)"
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

    /// Store a secret in the host secret store. Updates in-place if it already exists.
    public func store(key: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw VaultError.encodingError
        }

        #if canImport(Security)
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
        #else
        let fileURL = try secretFileURL(for: key, createDirectory: true)
        do {
            try SecureFile.replaceAtomically(at: fileURL, data: data)
        } catch {
            throw VaultError.storageError(error.localizedDescription)
        }
        #endif
        logger.info("Stored secret", metadata: ["key": "\(key)"])
    }

    /// Retrieve the value of a secret.
    public func retrieve(key: String) throws -> String {
        #if canImport(Security)
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
        #else
        let fileURL = try secretFileURL(for: key)
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            throw VaultError.secretNotFound(key)
        }
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch {
            throw VaultError.storageError(error.localizedDescription)
        }
        guard let value = String(data: data, encoding: .utf8) else {
            throw VaultError.encodingError
        }
        #endif
        // Intentionally never log the value.
        logger.debug("Retrieved secret", metadata: ["key": "\(key)"])
        return value
    }

    /// Delete a secret from the host secret store.
    public func delete(key: String) throws {
        #if canImport(Security)
        let query = baseQuery(for: key)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapStatus(status, key: key)
        }
        #else
        let fileURL = try secretFileURL(for: key)
        if FileManager.default.fileExists(atPath: fileURL.path) {
            do {
                try FileManager.default.removeItem(at: fileURL)
            } catch {
                throw VaultError.storageError(error.localizedDescription)
            }
        }
        #endif
        logger.info("Deleted secret", metadata: ["key": "\(key)"])
    }

    /// List all secret keys stored under this service (values are never returned).
    public func list() throws -> [Secret] {
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
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
        #else
        let directory = try storageDirectory(create: true)
        let urls: [URL]
        do {
            urls = try FileManager.default.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )
        } catch {
            throw VaultError.storageError(error.localizedDescription)
        }

        return try urls.compactMap { url in
            guard let key = decodeFilename(url.lastPathComponent) else {
                return nil
            }
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let createdAt =
                attributes[.creationDate] as? Date
                ?? attributes[.modificationDate] as? Date
                ?? Date()
            let updatedAt = attributes[.modificationDate] as? Date ?? createdAt
            return Secret(key: key, createdAt: createdAt, updatedAt: updatedAt)
        }.sorted { $0.key < $1.key }
        #endif
    }

    /// Check whether a secret with the given key exists.
    public func exists(key: String) throws -> Bool {
        #if canImport(Security)
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
        #else
        let fileURL = try secretFileURL(for: key)
        return FileManager.default.fileExists(atPath: fileURL.path)
        #endif
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

    #if canImport(Security)
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
    #else
    private func storageDirectory(create: Bool) throws -> URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let sendboxDirectory = home.appendingPathComponent(".sendbox", isDirectory: true)
        let secretsDirectory = sendboxDirectory
            .appendingPathComponent("secrets", isDirectory: true)
        let directory = secretsDirectory
            .appendingPathComponent(encodeFilename(serviceName), isDirectory: true)

        if create {
            do {
                try SecureFile.ensureDirectory(at: sendboxDirectory)
                try SecureFile.ensureDirectory(at: secretsDirectory)
                try SecureFile.ensureDirectory(at: directory)
            } catch {
                throw VaultError.storageError(error.localizedDescription)
            }
        }
        return directory
    }

    private func secretFileURL(
        for key: String,
        createDirectory: Bool = false
    ) throws -> URL {
        guard !key.isEmpty else {
            throw VaultError.storageError("secret key cannot be empty")
        }
        return try storageDirectory(create: createDirectory)
            .appendingPathComponent(encodeFilename(key), isDirectory: false)
    }

    private func encodeFilename(_ value: String) -> String {
        value.utf8.map { String(format: "%02x", $0) }.joined()
    }

    private func decodeFilename(_ value: String) -> String? {
        guard value.count.isMultiple(of: 2) else {
            return nil
        }

        var bytes: [UInt8] = []
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else {
                return nil
            }
            bytes.append(byte)
            index = next
        }
        return String(data: Data(bytes), encoding: .utf8)
    }
    #endif
}
