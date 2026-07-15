import Testing
@testable import SendBoxKit

struct RepositoryAccessPolicyTests {
    private let policy = RepositoryAccessPolicy()

    @Test func publicRepositoryCannotAccessPrivateRepository() {
        let decision = policy.evaluate(
            source: repository("public-source", visibility: .public),
            target: repository("private-target", visibility: .private, organization: "acme"),
            privateAccessOverride: true
        )

        guard case .deny = decision else {
            Issue.record("Expected public-to-private access to be denied")
            return
        }
    }

    @Test func privateRepositoryCanAccessPublicRepository() {
        let decision = policy.evaluate(
            source: repository("private-source", visibility: .private, organization: "acme"),
            target: repository("public-target", visibility: .public)
        )

        #expect(decision == .allow)
    }

    @Test func publicRepositoryCanAccessPublicRepository() {
        let decision = policy.evaluate(
            source: repository("public-source", visibility: .public),
            target: repository("public-target", visibility: .public)
        )

        #expect(decision == .allow)
    }

    @Test func sameOrganizationPrivateAccessRequiresOverride() {
        let source = repository("source", visibility: .private, organization: "acme")
        let target = repository("target", visibility: .private, organization: "ACME")

        guard case .warn = policy.evaluate(source: source, target: target) else {
            Issue.record("Expected private-to-private access to require explicit approval")
            return
        }
        #expect(
            policy.evaluate(
                source: source,
                target: target,
                privateAccessOverride: true
            ) == .allow
        )
    }

    @Test func differentOrganizationPrivateAccessCannotBeOverridden() {
        let decision = policy.evaluate(
            source: repository("source", visibility: .private, organization: "acme"),
            target: repository("target", visibility: .private, organization: "other"),
            privateAccessOverride: true
        )

        guard case .deny = decision else {
            Issue.record("Expected cross-organization private access to be denied")
            return
        }
    }

    @Test func credentialsMustBeScopedToSourceOrganization() {
        #expect(
            policy.isCredentialScopeAllowed(
                privateRepositoryOwners: ["acme", "ACME"],
                organization: "acme"
            )
        )
        #expect(
            !policy.isCredentialScopeAllowed(
                privateRepositoryOwners: ["acme", "other"],
                organization: "acme"
            )
        )
        #expect(
            !policy.isCredentialScopeAllowed(
                privateRepositoryOwners: [],
                organization: "acme"
            )
        )
    }

    private func repository(
        _ name: String,
        visibility: RepositoryAccessPolicy.Visibility,
        organization: String? = nil
    ) -> RepositoryAccessPolicy.Repository {
        RepositoryAccessPolicy.Repository(
            owner: organization ?? "owner",
            name: name,
            visibility: visibility,
            organization: organization
        )
    }
}
