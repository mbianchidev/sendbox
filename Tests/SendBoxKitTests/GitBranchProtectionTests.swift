import Foundation
import Testing
@testable import SendBoxKit

struct GitBranchProtectionTests {
    private let selectedRepository = GitBranchProtection.RepositoryIdentity(
        host: "github.com",
        owner: "acme",
        name: "project"
    )

    @Test func protectedBranchesOverrideAllowedPatterns() {
        let policy = makePolicy(
            protectedBranches: ["main", "master"],
            allowedBranchPatterns: ["*"]
        )

        #expect(!policy.evaluate(branch: "main", operation: .push).isAllowed)
        #expect(!policy.evaluate(branch: "refs/heads/master", operation: .pull).isAllowed)
    }

    @Test func defaultPatternsAllowFeatureBranches() {
        let policy = makePolicy()

        #expect(policy.evaluate(branch: "mbianchidev/topic", operation: .push).isAllowed)
        #expect(policy.evaluate(branch: "copilot/fix", operation: .push).isAllowed)
        #expect(policy.evaluate(branch: "feature/auth", operation: .pull).isAllowed)
        #expect(!policy.evaluate(branch: "release/1.0", operation: .push).isAllowed)
    }

    @Test func unresolvedUsernamePatternDoesNotMatch() {
        let policy = makePolicy(username: nil)

        #expect(!policy.evaluate(branch: "mbianchidev/topic", operation: .push).isAllowed)
        #expect(policy.evaluate(branch: "feature/topic", operation: .push).isAllowed)
    }

    @Test func disabledProtectionAllowsProtectedBranches() {
        let policy = makePolicy(enabled: false)

        #expect(policy.evaluate(branch: "main", operation: .push).isAllowed)
        #expect(policy.evaluate(branch: "master", operation: .pull).isAllowed)
    }

    @Test func parsesCommonGitHubRemoteURLs() {
        #expect(
            GitBranchProtection.RepositoryIdentity.parse(
                remoteURL: "https://github.com/Acme/Project.git"
            ) == selectedRepository
        )
        #expect(
            GitBranchProtection.RepositoryIdentity.parse(
                remoteURL: "git@github.com:acme/project.git"
            ) == selectedRepository
        )
        #expect(
            GitBranchProtection.RepositoryIdentity.parse(
                remoteURL: "ssh://git@github.com/acme/project.git"
            ) == selectedRepository
        )
    }

    @Test func generatedPolicyNormalizesDestinationRefspecs() {
        let script = makePolicy().generatePolicyScript()

        #expect(script.contains("refs/heads/"))
        #expect(script.contains("push.default=matching"))
        #expect(script.contains("protected branch"))
        #expect(script.contains("remote.pushDefault"))
    }

    @Test func generatedPolicyRejectsProtectedDestinationRefspec() throws {
        let fixture = try makeScriptFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let result = try runPolicy(
            fixture: fixture,
            arguments: ["push", "origin", "feature/topic:refs/heads/main"],
            branch: "feature/topic",
            remoteURL: "https://github.com/acme/project.git",
            repositoryRoot: fixture.selectedWorkspace.path
        )

        #expect(result.exitCode == 128)
        #expect(result.stderr.contains("protected branch 'main'"))
        #expect((try? String(contentsOf: fixture.log, encoding: .utf8)) == nil)
    }

    @Test func generatedPolicyAllowsFeaturePush() throws {
        let fixture = try makeScriptFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let result = try runPolicy(
            fixture: fixture,
            arguments: ["push", "origin", "feature/topic"],
            branch: "feature/topic",
            remoteURL: "https://github.com/acme/project.git",
            repositoryRoot: fixture.selectedWorkspace.path
        )

        #expect(result.exitCode == 0)
        let log = try String(contentsOf: fixture.log, encoding: .utf8)
        #expect(log.contains("push origin feature/topic"))
    }

    @Test func generatedPolicyAllowsOtherRepositoryPulls() throws {
        let fixture = try makeScriptFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let otherRepository = fixture.root.appendingPathComponent("other-repository")
        try FileManager.default.createDirectory(
            at: otherRepository,
            withIntermediateDirectories: true
        )
        let result = try runPolicy(
            fixture: fixture,
            arguments: ["pull", "origin", "main"],
            branch: "main",
            remoteURL: "https://github.com/open-source/library.git",
            repositoryRoot: otherRepository.path,
            currentDirectory: otherRepository
        )

        #expect(result.exitCode == 0, "stderr: \(result.stderr)")
        let log = try String(contentsOf: fixture.log, encoding: .utf8)
        #expect(log.contains("pull origin main"))
    }

    @Test func generatedPolicyAllowsExplicitOtherRemoteFromSelectedWorkspace() throws {
        let fixture = try makeScriptFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let result = try runPolicy(
            fixture: fixture,
            arguments: [
                "push",
                "https://github.com/open-source/library.git",
                "release/1.0",
            ],
            branch: "release/1.0",
            remoteURL: "https://github.com/acme/project.git",
            repositoryRoot: fixture.selectedWorkspace.path
        )

        #expect(result.exitCode == 0)
        let log = try String(contentsOf: fixture.log, encoding: .utf8)
        #expect(log.contains("push https://github.com/open-source/library.git release/1.0"))
    }

    @Test func generatedPolicyRejectsSelectedRepositoryCloneElsewhere() throws {
        let fixture = try makeScriptFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let clone = fixture.root.appendingPathComponent("selected-clone")
        try FileManager.default.createDirectory(at: clone, withIntermediateDirectories: true)
        let result = try runPolicy(
            fixture: fixture,
            arguments: ["push", "origin", "main"],
            branch: "feature/topic",
            remoteURL: "git@github.com:acme/project.git",
            repositoryRoot: clone.path,
            currentDirectory: clone
        )

        #expect(result.exitCode == 128)
        #expect(result.stderr.contains("protected branch 'main'"))
    }

    @Test func generatedPolicyRejectsPullFromProtectedBranch() throws {
        let fixture = try makeScriptFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let result = try runPolicy(
            fixture: fixture,
            arguments: ["pull", "origin", "main"],
            branch: "feature/topic",
            remoteURL: "https://github.com/acme/project.git",
            repositoryRoot: fixture.selectedWorkspace.path
        )

        #expect(result.exitCode == 128)
        #expect(result.stderr.contains("protected branch 'main'"))
    }

    @Test func generatedPolicyRejectsPushFromProtectedCurrentBranch() throws {
        let fixture = try makeScriptFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let result = try runPolicy(
            fixture: fixture,
            arguments: ["push", "origin", "feature/topic"],
            branch: "main",
            remoteURL: "https://github.com/acme/project.git",
            repositoryRoot: fixture.selectedWorkspace.path
        )

        #expect(result.exitCode == 128)
        #expect(result.stderr.contains("protected branch 'main'"))
    }

    @Test func generatedPolicyRejectsMatchingPushDefault() throws {
        let fixture = try makeScriptFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let result = try runPolicy(
            fixture: fixture,
            arguments: ["push"],
            branch: "feature/topic",
            remoteURL: "https://github.com/acme/project.git",
            repositoryRoot: fixture.selectedWorkspace.path,
            pushDefault: "matching"
        )

        #expect(result.exitCode == 128)
        #expect(result.stderr.contains("push.default=matching"))
    }

    private func makePolicy(
        enabled: Bool = true,
        username: String? = "mbianchidev",
        protectedBranches: [String] = ["main", "master"],
        allowedBranchPatterns: [String] = [
            "{username}/*",
            "copilot/*",
            "feature/*",
        ]
    ) -> GitBranchProtection {
        GitBranchProtection(
            config: .init(
                enabled: enabled,
                username: nil,
                protectedBranches: protectedBranches,
                allowedBranchPatterns: allowedBranchPatterns
            ),
            username: username,
            selectedRepository: selectedRepository
        )
    }

    private struct ScriptFixture {
        let root: URL
        let selectedWorkspace: URL
        let policyScript: URL
        let log: URL
    }

    private struct ScriptResult {
        let exitCode: Int32
        let stderr: String
    }

    private func makeScriptFixture() throws -> ScriptFixture {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("sendbox-git-policy-\(UUID().uuidString)")
        let selectedWorkspace = root.appendingPathComponent("selected-repository")
        try FileManager.default.createDirectory(
            at: selectedWorkspace,
            withIntermediateDirectories: true
        )

        let fakeGit = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/fake-git.sh")

        let policy = GitBranchProtection(
            config: .default,
            username: "mbianchidev",
            selectedRepository: selectedRepository,
            selectedWorkspace: selectedWorkspace.path
        )
        let policyScript = root.appendingPathComponent("git-policy.py")
        try Data(
            policy.generatePolicyScript(realGitPath: fakeGit.path).utf8
        ).write(to: policyScript)

        return ScriptFixture(
            root: root,
            selectedWorkspace: selectedWorkspace,
            policyScript: policyScript,
            log: root.appendingPathComponent("git.log")
        )
    }

    private func runPolicy(
        fixture: ScriptFixture,
        arguments: [String],
        branch: String,
        remoteURL: String,
        repositoryRoot: String,
        currentDirectory: URL? = nil,
        pushDefault: String? = nil
    ) throws -> ScriptResult {
        let process = Process()
        let stderr = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "python3",
            "-I",
            "-B",
            fixture.policyScript.path,
        ] + arguments
        process.currentDirectoryURL = currentDirectory ?? fixture.selectedWorkspace
        var environment = ProcessInfo.processInfo.environment
        environment["FAKE_GIT_BRANCH"] = branch
        environment["FAKE_GIT_REMOTE_URL"] = remoteURL
        environment["FAKE_GIT_ROOT"] = repositoryRoot
        environment["FAKE_GIT_LOG"] = fixture.log.path
        environment["FAKE_GIT_UPSTREAM"] = "origin/\(branch)"
        if let pushDefault {
            environment["FAKE_GIT_PUSH_DEFAULT"] = pushDefault
        } else {
            environment.removeValue(forKey: "FAKE_GIT_PUSH_DEFAULT")
        }
        process.environment = environment
        process.standardOutput = Pipe()
        process.standardError = stderr

        try process.run()
        process.waitUntilExit()
        let data = stderr.fileHandleForReading.readDataToEndOfFile()
        return ScriptResult(
            exitCode: process.terminationStatus,
            stderr: String(data: data, encoding: .utf8) ?? ""
        )
    }
}
