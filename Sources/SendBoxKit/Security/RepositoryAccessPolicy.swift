import Foundation

/// Decides whether data may flow between two GitHub repositories.
public struct RepositoryAccessPolicy: Sendable {
    public enum Visibility: String, Codable, Sendable {
        case `public`
        case `private`
    }

    public struct Repository: Sendable {
        public let owner: String
        public let name: String
        public let visibility: Visibility
        public let organization: String?

        public init(
            owner: String,
            name: String,
            visibility: Visibility,
            organization: String? = nil
        ) {
            self.owner = owner
            self.name = name
            self.visibility = visibility
            self.organization = organization
        }
    }

    public enum Decision: Equatable, Sendable {
        case allow
        case warn(String)
        case deny(String)
    }

    public init() {}

    public func evaluate(
        source: Repository,
        target: Repository,
        privateAccessOverride: Bool = false
    ) -> Decision {
        guard target.visibility == .private else {
            return .allow
        }

        guard source.visibility == .private else {
            return .deny(
                "Public repository \(source.owner)/\(source.name) cannot access private repository "
                    + "\(target.owner)/\(target.name)"
            )
        }

        guard let sourceOrganization = source.organization,
              let targetOrganization = target.organization,
              sourceOrganization.caseInsensitiveCompare(targetOrganization) == .orderedSame else {
            return .deny("Private repository access is restricted to repositories in the same organization")
        }

        guard privateAccessOverride else {
            return .warn(
                "Accessing another private repository can expose its data to "
                    + "\(source.owner)/\(source.name); explicit approval is required"
            )
        }

        return .allow
    }

    public func isCredentialScopeAllowed(
        privateRepositoryOwners: [String],
        organization: String
    ) -> Bool {
        !privateRepositoryOwners.isEmpty
            && privateRepositoryOwners.allSatisfy {
                $0.caseInsensitiveCompare(organization) == .orderedSame
            }
    }
}
