import Foundation
import Crypto
import Logging

/// Supply-chain provenance verification using cryptographic signatures.
///
/// Ensures that sandbox configuration files, policy files, and agent instruction files
/// are authored by trusted identities. Uses a Sigstore-compatible signing model:
/// - Files are signed with Ed25519 keys
/// - Signatures are stored as detached .sig files or inline in YAML
/// - A trust store maps key fingerprints to identities
/// - Verification checks signature + identity before applying config
public struct SupplyChainProvenance: Sendable {

    private var trustStore: TrustStore
    private let logger: Logger

    // MARK: - Types

    /// A cryptographic identity that can sign files.
    public struct Identity: Codable, Sendable, Equatable {
        public let fingerprint: String
        public let name: String
        public let email: String?
        public let publicKey: String
        public let addedAt: Date
        public let expiresAt: Date?

        public init(
            fingerprint: String,
            name: String,
            email: String?,
            publicKey: String,
            addedAt: Date = Date(),
            expiresAt: Date? = nil
        ) {
            self.fingerprint = fingerprint
            self.name = name
            self.email = email
            self.publicKey = publicKey
            self.addedAt = addedAt
            self.expiresAt = expiresAt
        }
    }

    /// A detached signature for a file.
    public struct Signature: Codable, Sendable {
        public let fileHash: String
        public let signature: String
        public let signerFingerprint: String
        public let timestamp: Date
        public let metadata: SignatureMetadata?

        public struct SignatureMetadata: Codable, Sendable {
            public let toolVersion: String
            public let purpose: String

            public init(toolVersion: String, purpose: String) {
                self.toolVersion = toolVersion
                self.purpose = purpose
            }
        }

        public init(
            fileHash: String,
            signature: String,
            signerFingerprint: String,
            timestamp: Date = Date(),
            metadata: SignatureMetadata? = nil
        ) {
            self.fileHash = fileHash
            self.signature = signature
            self.signerFingerprint = signerFingerprint
            self.timestamp = timestamp
            self.metadata = metadata
        }
    }

    /// Trust store managing known identities.
    public struct TrustStore: Codable, Sendable {
        public var identities: [Identity]
        public var requireSignature: Bool
        public var minimumSigners: Int

        public init(
            identities: [Identity] = [],
            requireSignature: Bool = false,
            minimumSigners: Int = 0
        ) {
            self.identities = identities
            self.requireSignature = requireSignature
            self.minimumSigners = minimumSigners
        }

        /// Empty store, signatures optional.
        public static let `default` = TrustStore(
            identities: [],
            requireSignature: false,
            minimumSigners: 0
        )

        /// Requires at least one valid signature.
        public static let strict = TrustStore(
            identities: [],
            requireSignature: true,
            minimumSigners: 1
        )
    }

    // MARK: - Errors

    public enum ProvenanceError: Error, LocalizedError {
        case untrustedSigner(String)
        case signatureInvalid(String)
        case signatureMissing(String)
        case keyExpired(String)
        case insufficientSigners(required: Int, found: Int)
        case keyGenerationFailed
        case encodingError

        public var errorDescription: String? {
            switch self {
            case .untrustedSigner(let fp):
                return "Signer '\(fp)' is not in the trust store"
            case .signatureInvalid(let detail):
                return "Invalid signature: \(detail)"
            case .signatureMissing(let path):
                return "No signature found for '\(path)'"
            case .keyExpired(let fp):
                return "Key '\(fp)' has expired"
            case .insufficientSigners(let required, let found):
                return "Insufficient signers: required \(required), found \(found)"
            case .keyGenerationFailed:
                return "Failed to generate Ed25519 keypair"
            case .encodingError:
                return "Failed to encode or decode signature data"
            }
        }
    }

    // MARK: - Verification Result

    /// Verification result.
    public struct VerificationResult: Sendable {
        public let isValid: Bool
        public let fileHash: String
        public let signers: [Identity]
        public let warnings: [String]

        public init(
            isValid: Bool,
            fileHash: String,
            signers: [Identity] = [],
            warnings: [String] = []
        ) {
            self.isValid = isValid
            self.fileHash = fileHash
            self.signers = signers
            self.warnings = warnings
        }
    }

    // MARK: - Init

    public init(
        trustStore: TrustStore = .default,
        logger: Logger = Logger(label: "sendbox.supply-chain")
    ) {
        self.trustStore = trustStore
        self.logger = logger
    }

    // MARK: - Key Management

    /// Generate a new Ed25519 keypair. Returns (privateKeyBase64, Identity).
    public static func generateKeypair(
        name: String,
        email: String? = nil,
        expiresIn: TimeInterval? = nil
    ) throws -> (privateKey: String, identity: Identity) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let privateKeyBase64 = privateKey.rawRepresentation.base64EncodedString()
        let publicKeyBase64 = publicKey.rawRepresentation.base64EncodedString()
        let fingerprint = Self.computeFingerprint(publicKey: publicKey)

        let now = Date()
        let expiresAt: Date? = expiresIn.map { now.addingTimeInterval($0) }

        let identity = Identity(
            fingerprint: fingerprint,
            name: name,
            email: email,
            publicKey: publicKeyBase64,
            addedAt: now,
            expiresAt: expiresAt
        )

        return (privateKey: privateKeyBase64, identity: identity)
    }

    // MARK: - Signing

    /// Sign content with a private key. Returns a detached Signature.
    public static func sign(
        content: Data,
        privateKey: String,
        purpose: String
    ) throws -> Signature {
        guard let keyData = Data(base64Encoded: privateKey) else {
            throw ProvenanceError.encodingError
        }

        let signingKey: Curve25519.Signing.PrivateKey
        do {
            signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
        } catch {
            throw ProvenanceError.keyGenerationFailed
        }

        let fileHash = Self.sha256Hex(content)
        let signatureData = try signingKey.signature(for: content)
        let signatureBase64 = signatureData.base64EncodedString()
        let fingerprint = Self.computeFingerprint(publicKey: signingKey.publicKey)

        let metadata = Signature.SignatureMetadata(
            toolVersion: "sendbox-1.0",
            purpose: purpose
        )

        return Signature(
            fileHash: fileHash,
            signature: signatureBase64,
            signerFingerprint: fingerprint,
            timestamp: Date(),
            metadata: metadata
        )
    }

    /// Sign a file at a path, writing the .sig file alongside it.
    /// Returns the path of the .sig file.
    public static func signFile(
        at path: String,
        privateKey: String,
        purpose: String
    ) throws -> String {
        let url = URL(fileURLWithPath: path)
        let content = try Data(contentsOf: url)
        let signature = try sign(content: content, privateKey: privateKey, purpose: purpose)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let sigData = try encoder.encode(signature)

        let sigPath = path + ".sig"
        try sigData.write(to: URL(fileURLWithPath: sigPath))

        return sigPath
    }

    // MARK: - Verification

    /// Verify signatures against the trust store.
    public func verify(content: Data, signatures: [Signature]) -> VerificationResult {
        let fileHash = Self.sha256Hex(content)
        var verifiedSigners: [Identity] = []
        var warnings: [String] = []

        if signatures.isEmpty {
            if trustStore.requireSignature {
                return VerificationResult(
                    isValid: false,
                    fileHash: fileHash,
                    warnings: ["No signatures provided but trust store requires signatures"]
                )
            }
            return VerificationResult(
                isValid: true,
                fileHash: fileHash,
                warnings: ["No signatures provided; verification skipped"]
            )
        }

        for sig in signatures {
            // Check file hash matches.
            guard sig.fileHash == fileHash else {
                warnings.append(
                    "Signature from \(sig.signerFingerprint) has mismatched file hash"
                )
                continue
            }

            // Look up identity in trust store.
            guard let identity = trustStore.identities.first(
                where: { $0.fingerprint == sig.signerFingerprint }
            ) else {
                warnings.append("Signer \(sig.signerFingerprint) not in trust store")
                continue
            }

            // Check key expiry.
            if let expiresAt = identity.expiresAt, expiresAt < Date() {
                warnings.append("Key for '\(identity.name)' expired at \(expiresAt)")
                continue
            }

            // Decode public key and signature.
            guard let pubKeyData = Data(base64Encoded: identity.publicKey),
                  let sigData = Data(base64Encoded: sig.signature)
            else {
                warnings.append("Failed to decode key or signature for \(identity.name)")
                continue
            }

            do {
                let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: pubKeyData)
                if publicKey.isValidSignature(sigData, for: content) {
                    verifiedSigners.append(identity)
                    logger.debug("Verified signature from \(identity.name)")
                } else {
                    warnings.append(
                        "Signature from \(identity.name) failed cryptographic verification"
                    )
                }
            } catch {
                warnings.append(
                    "Failed to verify signature from \(identity.name): \(error.localizedDescription)"
                )
            }
        }

        // Check minimum signers.
        let meetsMinimum = verifiedSigners.count >= trustStore.minimumSigners
        let isValid: Bool
        if trustStore.requireSignature {
            isValid = !verifiedSigners.isEmpty && meetsMinimum
        } else {
            isValid = verifiedSigners.isEmpty || meetsMinimum
        }

        if !meetsMinimum && trustStore.minimumSigners > 0 {
            warnings.append(
                "Required \(trustStore.minimumSigners) signers, found \(verifiedSigners.count)"
            )
        }

        return VerificationResult(
            isValid: isValid,
            fileHash: fileHash,
            signers: verifiedSigners,
            warnings: warnings
        )
    }

    /// Verify a file and its companion .sig file(s).
    public func verifyFile(at path: String) throws -> VerificationResult {
        let url = URL(fileURLWithPath: path)
        let content = try Data(contentsOf: url)

        let signatures = try Self.loadSignatures(forFileAt: path)
        return verify(content: content, signatures: signatures)
    }

    /// Verify a sandbox config file before loading it.
    public func verifySandboxConfig(at path: String) throws -> VerificationResult {
        logger.info("Verifying sandbox config provenance: \(path)")
        let result = try verifyFile(at: path)

        if result.isValid {
            let signerNames = result.signers.map(\.name).joined(separator: ", ")
            if result.signers.isEmpty {
                logger.info("Config '\(path)' has no signatures (not required)")
            } else {
                logger.info("Config '\(path)' verified, signed by: \(signerNames)")
            }
        } else {
            logger.warning(
                "Config '\(path)' FAILED provenance check: \(result.warnings.joined(separator: "; "))"
            )
        }

        return result
    }

    // MARK: - Trust Store Management

    /// Add a trusted identity to the store.
    public mutating func addTrustedIdentity(_ identity: Identity) {
        if trustStore.identities.contains(where: { $0.fingerprint == identity.fingerprint }) {
            logger.debug("Identity \(identity.name) already in trust store")
            return
        }
        trustStore.identities.append(identity)
        logger.info("Added trusted identity: \(identity.name) (\(identity.fingerprint))")
    }

    /// Remove a trusted identity.
    public mutating func removeTrustedIdentity(fingerprint: String) {
        trustStore.identities.removeAll { $0.fingerprint == fingerprint }
        logger.info("Removed trusted identity: \(fingerprint)")
    }

    /// Save the trust store to disk as JSON.
    public func saveTrustStore(to path: String) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(trustStore)
        try data.write(to: URL(fileURLWithPath: path))
        logger.info("Trust store saved to \(path)")
    }

    /// Load a trust store from disk.
    public static func loadTrustStore(from path: String) throws -> TrustStore {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(TrustStore.self, from: data)
    }

    // MARK: - Private Helpers

    /// Compute SHA-256 fingerprint of a public key.
    private static func computeFingerprint(
        publicKey: Curve25519.Signing.PublicKey
    ) -> String {
        sha256Hex(publicKey.rawRepresentation)
    }

    /// Hex-encoded SHA-256 digest.
    private static func sha256Hex(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Load all .sig files for a given file path.
    ///
    /// Checks for `<path>.sig` and numbered variants `<path>.sig.2`, `<path>.sig.3`, etc.
    private static func loadSignatures(forFileAt path: String) throws -> [Signature] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var signatures: [Signature] = []

        let primarySigPath = path + ".sig"
        if FileManager.default.fileExists(atPath: primarySigPath) {
            let data = try Data(contentsOf: URL(fileURLWithPath: primarySigPath))

            // Try decoding as an array first, then as a single signature.
            if let array = try? decoder.decode([Signature].self, from: data) {
                signatures.append(contentsOf: array)
            } else {
                let single = try decoder.decode(Signature.self, from: data)
                signatures.append(single)
            }
        }

        // Check for numbered .sig files: .sig.2, .sig.3, ...
        var index = 2
        while true {
            let numberedPath = "\(path).sig.\(index)"
            guard FileManager.default.fileExists(atPath: numberedPath) else { break }

            let data = try Data(contentsOf: URL(fileURLWithPath: numberedPath))
            let sig = try decoder.decode(Signature.self, from: data)
            signatures.append(sig)
            index += 1
        }

        return signatures
    }
}
