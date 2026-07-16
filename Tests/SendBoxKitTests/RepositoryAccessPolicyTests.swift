import Testing
@testable import SendBoxKit

struct RepositoryAccessPolicyTests {
    private let policy = RepositoryAccessPolicy()

    @Test func selectedPrivateRepositoryIsAllowedByDefault() {
        let source = repository(
            "source",
            owner: "person",
            visibility: .private
        )
        let selectedRepository = repository(
            "SOURCE",
            owner: "PERSON",
            visibility: .private
        )

        #expect(policy.evaluate(source: source, target: selectedRepository) == .allow)
    }

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

    @Test func additionalSameOrganizationPrivateAccessRequiresOverride() {
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

    @Test func credentialScopeAllowsOnlySelectedPrivateRepositoryByDefault() {
        let source = repository(
            "source",
            owner: "person",
            visibility: .private
        )

        #expect(
            policy.evaluateCredentialScope(
                source: source,
                accessiblePrivateRepositories: [source]
            ) == .allow
        )
    }

    @Test func credentialScopeRequiresAccessToSelectedPrivateRepository() {
        let source = repository("source", visibility: .private, organization: "acme")
        let other = repository("other", visibility: .private, organization: "acme")

        guard case .deny = policy.evaluateCredentialScope(
            source: source,
            accessiblePrivateRepositories: [other],
            privateAccessOverride: true
        ) else {
            Issue.record("Expected credentials without selected-repository access to be denied")
            return
        }
    }

    @Test func credentialScopeGatesAdditionalPrivateRepositories() {
        let source = repository("source", visibility: .private, organization: "acme")
        let additional = repository("additional", visibility: .private, organization: "acme")

        guard case .warn = policy.evaluateCredentialScope(
            source: source,
            accessiblePrivateRepositories: [source, additional]
        ) else {
            Issue.record("Expected additional private repository access to require an override")
            return
        }

        #expect(
            policy.evaluateCredentialScope(
                source: source,
                accessiblePrivateRepositories: [source, additional],
                privateAccessOverride: true
            ) == .allow
        )
    }

    @Test func credentialScopeRejectsCrossOrganizationPrivateRepositories() {
        let source = repository("source", visibility: .private, organization: "acme")
        let additional = repository("additional", visibility: .private, organization: "other")

        guard case .deny = policy.evaluateCredentialScope(
            source: source,
            accessiblePrivateRepositories: [source, additional],
            privateAccessOverride: true
        ) else {
            Issue.record("Expected cross-organization credential scope to be denied")
            return
        }
    }

    @Test func publicSourceCredentialScopeAllowsNoPrivateRepositories() {
        let source = repository("source", visibility: .public)

        #expect(
            policy.evaluateCredentialScope(
                source: source,
                accessiblePrivateRepositories: []
            ) == .allow
        )

        guard case .deny = policy.evaluateCredentialScope(
            source: source,
            accessiblePrivateRepositories: [
                repository("private", visibility: .private, organization: "acme")
            ]
        ) else {
            Issue.record("Expected public-source credentials with private access to be denied")
            return
        }
    }

    private func repository(
        _ name: String,
        owner: String = "owner",
        visibility: RepositoryAccessPolicy.Visibility,
        organization: String? = nil
    ) -> RepositoryAccessPolicy.Repository {
        RepositoryAccessPolicy.Repository(
            owner: organization ?? owner,
            name: name,
            visibility: visibility,
            organization: organization
        )
    }
}

struct AgentAuthenticationEnvironmentTests {
    @Test func copilotAuthDoesNotDependOnGitHubRepositoryCredentials() {
        let environment = AgentAuthenticationEnvironment.make(
            githubToken: "github-token",
            forwardGitHubToken: false,
            copilotToken: "copilot-token",
            forwardCopilotToken: true
        )

        #expect(environment["GITHUB_TOKEN"] == nil)
        #expect(environment["GITHUB_COPILOT_TOKEN"] == "copilot-token")
    }

    @Test func forwardsApprovedGitHubRepositoryCredentials() {
        let environment = AgentAuthenticationEnvironment.make(
            githubToken: "github-token",
            forwardGitHubToken: true,
            copilotToken: nil,
            forwardCopilotToken: false
        )

        #expect(environment["GITHUB_TOKEN"] == "github-token")
        #expect(environment["GITHUB_COPILOT_TOKEN"] == nil)
    }
}
