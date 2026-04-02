import Testing
@testable import SendBoxKit

struct CommandPolicyTests {

    // MARK: - Helpers

    private func makePolicy(
        defaultAction: PolicyConfiguration.CommandPolicyConfig.Action = .deny,
        allowlist: [String] = [],
        denylist: [String] = [],
        logBlocked: Bool = false
    ) -> CommandPolicy {
        let config = PolicyConfiguration.CommandPolicyConfig(
            defaultAction: defaultAction,
            allowlist: allowlist,
            denylist: denylist,
            logBlocked: logBlocked
        )
        return CommandPolicy(config: config)
    }

    // MARK: - Basic allow / deny

    @Test func testAllowedCommand() async {
        let policy = makePolicy(allowlist: ["ls", "cat"])
        let decision = await policy.evaluate("ls")
        #expect(decision.isAllowed)
    }

    @Test func testDeniedCommand() async {
        let policy = makePolicy(denylist: ["rm"])
        let decision = await policy.evaluate("rm")
        #expect(!decision.isAllowed)
    }

    // MARK: - Default action

    @Test func testDefaultDenyBlocksUnknown() async {
        let policy = makePolicy(defaultAction: .deny, allowlist: ["ls"])
        let decision = await policy.evaluate("whoami")
        #expect(!decision.isAllowed)
    }

    @Test func testDefaultAllowPassesUnknown() async {
        let policy = makePolicy(defaultAction: .allow)
        let decision = await policy.evaluate("whoami")
        #expect(decision.isAllowed)
    }

    // MARK: - Denylist priority over allowlist

    @Test func testDenylistTakesPriority() async {
        let policy = makePolicy(
            defaultAction: .allow,
            allowlist: ["rm"],
            denylist: ["rm"]
        )
        let decision = await policy.evaluate("rm")
        #expect(!decision.isAllowed)
    }

    // MARK: - Glob pattern matching

    @Test func testGlobWildcard() async {
        let policy = makePolicy(allowlist: ["git *"])
        let decision = await policy.evaluate("git status")
        #expect(decision.isAllowed)
    }

    @Test func testExactMatch() async {
        let policy = makePolicy(allowlist: ["git status"])
        let allowed = await policy.evaluate("git status")
        #expect(allowed.isAllowed)
        let denied = await policy.evaluate("git push")
        #expect(!denied.isAllowed)
    }

    // MARK: - Pipeline evaluation

    @Test func testPipelineAllSegmentsAllowed() async {
        let policy = makePolicy(allowlist: ["ls", "grep *"])
        let decision = await policy.evaluatePipeline("ls | grep foo")
        #expect(decision.isAllowed)
    }

    @Test func testPipelineOneDenied() async {
        let policy = makePolicy(allowlist: ["ls"], denylist: ["rm"])
        let decision = await policy.evaluatePipeline("ls | rm -rf /")
        #expect(!decision.isAllowed)
    }

    @Test func testChainedCommands() async {
        let policy = makePolicy(allowlist: ["echo *", "cat *"])
        let decision = await policy.evaluatePipeline("echo hello && cat file.txt")
        #expect(decision.isAllowed)
    }

    // MARK: - Dangerous command patterns

    @Test func testSudoBlocked() async {
        let policy = makePolicy(denylist: ["sudo *", "sudo"])
        let decision = await policy.evaluate("sudo rm -rf /")
        #expect(!decision.isAllowed)
    }

    @Test func testRmRfSlashBlocked() async {
        let policy = makePolicy(denylist: ["rm -rf /"])
        let decision = await policy.evaluate("rm -rf /")
        #expect(!decision.isAllowed)
    }

    // MARK: - Default policy preset

    @Test func testDefaultPolicyAllowsGit() async {
        let policy = CommandPolicy(config: PolicyConfiguration.default.commands)
        let decision = await policy.evaluate("git")
        #expect(decision.isAllowed)
    }

    @Test func testDefaultPolicyBlocksSudo() async {
        let policy = CommandPolicy(config: PolicyConfiguration.default.commands)
        let decision = await policy.evaluate("sudo")
        // Default preset has default-deny with no sudo in allowlist
        #expect(!decision.isAllowed)
    }

    // MARK: - Strict policy preset

    @Test func testStrictPolicyBlocksNetworkTools() async {
        let policy = CommandPolicy(config: PolicyConfiguration.strict.commands)
        let curlDecision = await policy.evaluate("curl https://example.com")
        #expect(!curlDecision.isAllowed)
        let npmDecision = await policy.evaluate("npm install")
        #expect(!npmDecision.isAllowed)
    }

    // MARK: - Edge cases

    @Test func testEmptyCommand() async {
        let policy = makePolicy(defaultAction: .allow)
        let decision = await policy.evaluate("")
        #expect(!decision.isAllowed)
        if case .denied(let reason) = decision {
            #expect(reason == "Empty command")
        }
    }

    @Test func testCommandWithQuotes() async {
        let policy = makePolicy(allowlist: ["echo *"])
        let decision = await policy.evaluate("echo 'hello world'")
        #expect(decision.isAllowed)
    }
}
