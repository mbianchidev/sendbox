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
        if isSameRepository(source, target), source.visibility == target.visibility {
            return .allow
        }

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
            return .deny(
                "Additional private repository \(target.owner)/\(target.name) is outside "
                    + "the selected repository organization"
            )
        }

        guard privateAccessOverride else {
            return .warn(
                "Accessing additional private repository \(target.owner)/\(target.name) "
                    + "can expose its data to "
                    + "\(source.owner)/\(source.name); explicit approval is required"
            )
        }

        return .allow
    }

    public func evaluateCredentialScope(
        source: Repository,
        accessiblePrivateRepositories: [Repository],
        privateAccessOverride: Bool = false
    ) -> Decision {
        if source.visibility == .private,
           !accessiblePrivateRepositories.contains(where: {
               isSameRepository(source, $0) && $0.visibility == .private
           }) {
            return .deny(
                "GitHub credentials cannot access selected private repository "
                    + "\(source.owner)/\(source.name)"
            )
        }

        for repository in accessiblePrivateRepositories {
            let decision = evaluate(
                source: source,
                target: repository,
                privateAccessOverride: privateAccessOverride
            )
            switch decision {
            case .allow:
                continue
            case .warn, .deny:
                return decision
            }
        }

        return .allow
    }

    private func isSameRepository(_ lhs: Repository, _ rhs: Repository) -> Bool {
        lhs.owner.caseInsensitiveCompare(rhs.owner) == .orderedSame
            && lhs.name.caseInsensitiveCompare(rhs.name) == .orderedSame
    }
}
