import Foundation

/// Guards push and pull operations for the repository selected when SendBox starts.
public struct GitBranchProtection: Sendable {
    public typealias Configuration =
        SandboxConfiguration.GitHubConfig.BranchProtectionConfig

    public static let rootPath = "/run/sendbox-branch-protection"
    public static let realGitPath = rootPath + "/git-real"
    public static let policyScriptPath = rootPath + "/git-policy.py"
    public static let wrapperPath = "/usr/local/bin/git"

    public struct RepositoryIdentity: Equatable, Sendable {
        public let host: String
        public let owner: String
        public let name: String

        public init(host: String, owner: String, name: String) {
            self.host = host.lowercased()
            self.owner = owner.lowercased()
            self.name = Self.trimGitSuffix(name).lowercased()
        }

        public static func parse(remoteURL: String) -> RepositoryIdentity? {
            let trimmed = remoteURL.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                return nil
            }

            if let components = URLComponents(string: trimmed),
               let host = components.host {
                return identity(host: host, path: components.path)
            }

            guard let colon = trimmed.firstIndex(of: ":") else {
                return nil
            }
            let prefix = String(trimmed[..<colon])
            guard !prefix.contains("/") else {
                return nil
            }
            let host = prefix.split(separator: "@").last.map(String.init) ?? prefix
            let path = String(trimmed[trimmed.index(after: colon)...])
            return identity(host: host, path: path)
        }

        private static func identity(host: String, path: String) -> RepositoryIdentity? {
            let decodedPath = path.removingPercentEncoding ?? path
            let components = decodedPath.split(separator: "/").map(String.init)
            guard components.count >= 2 else {
                return nil
            }
            return RepositoryIdentity(
                host: host,
                owner: components[0],
                name: components[1]
            )
        }

        private static func trimGitSuffix(_ value: String) -> String {
            value.lowercased().hasSuffix(".git")
                ? String(value.dropLast(4))
                : value
        }
    }

    public enum Operation: String, Sendable {
        case push
        case pull
    }

    public enum Decision: Equatable, Sendable {
        case allow
        case deny(String)

        public var isAllowed: Bool {
            if case .allow = self {
                return true
            }
            return false
        }
    }

    public enum ValidationError: Error, LocalizedError, Equatable {
        case selectedRepositoryInvalid
        case selectedWorkspaceInvalid
        case protectedBranchInvalid(String)
        case allowedPatternInvalid(String)
        case gitRemoteUnavailable
        case gitRemoteUnsupported

        public var errorDescription: String? {
            switch self {
            case .selectedRepositoryInvalid:
                return "Git branch protection requires a valid selected Git repository"
            case .selectedWorkspaceInvalid:
                return "Git branch protection requires an absolute guest workspace path"
            case .protectedBranchInvalid(let branch):
                return "Git branch protection contains an invalid protected branch: \(branch)"
            case .allowedPatternInvalid(let pattern):
                return "Git branch protection contains an invalid allowed pattern: \(pattern)"
            case .gitRemoteUnavailable:
                return "Git branch protection could not determine the selected repository remote"
            case .gitRemoteUnsupported:
                return "Git branch protection requires a supported Git remote URL"
            }
        }
    }

    private let config: Configuration
    private let username: String?
    private let selectedRepository: RepositoryIdentity
    private let selectedWorkspace: String

    public init(
        config: Configuration,
        username: String?,
        selectedRepository: RepositoryIdentity,
        selectedWorkspace: String = "/workspaces/project"
    ) {
        self.config = config
        self.username = username?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.selectedRepository = selectedRepository
        self.selectedWorkspace = selectedWorkspace
    }

    public static func resolveRepositoryIdentity(
        projectPath: String
    ) throws -> RepositoryIdentity {
        let remoteNames = try runProcess(
            "git",
            arguments: ["remote"],
            currentDirectory: projectPath
        ).split(whereSeparator: \.isNewline).map(String.init)
        guard let remote = remoteNames.contains("origin")
            ? "origin"
            : remoteNames.first else {
            throw ValidationError.gitRemoteUnavailable
        }

        let remoteURL = try runProcess(
            "git",
            arguments: ["remote", "get-url", remote],
            currentDirectory: projectPath
        )
        guard let repository = RepositoryIdentity.parse(remoteURL: remoteURL) else {
            throw ValidationError.gitRemoteUnsupported
        }
        return repository
    }

    public static func resolveGitHubUsername(host: String) -> String? {
        guard let username = try? runProcess(
            "gh",
            arguments: ["api", "--hostname", host, "user", "--jq", ".login"]
        ), !username.isEmpty else {
            return nil
        }
        return username
    }

    public func validate() throws {
        guard !selectedRepository.host.isEmpty,
              !selectedRepository.owner.isEmpty,
              !selectedRepository.name.isEmpty else {
            throw ValidationError.selectedRepositoryInvalid
        }
        guard selectedWorkspace.hasPrefix("/") else {
            throw ValidationError.selectedWorkspaceInvalid
        }

        for branch in config.protectedBranches {
            guard normalizedBranch(branch) != nil else {
                throw ValidationError.protectedBranchInvalid(branch)
            }
        }
        for pattern in config.allowedBranchPatterns {
            guard !pattern.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ValidationError.allowedPatternInvalid(pattern)
            }
        }
    }

    public func evaluate(branch: String, operation: Operation) -> Decision {
        guard config.enabled else {
            return .allow
        }
        guard let normalized = normalizedBranch(branch) else {
            return .deny(
                "Git \(operation.rawValue) denied because branch '\(branch)' is invalid"
            )
        }

        let protected = Set(
            config.protectedBranches.compactMap(normalizedBranch).map {
                $0.lowercased()
            }
        )
        if protected.contains(normalized.lowercased()) {
            return .deny(
                "Git \(operation.rawValue) denied for protected branch '\(normalized)'"
            )
        }

        if expandedAllowedPatterns.contains(where: {
            GlobPattern.matches(normalized, pattern: $0)
        }) {
            return .allow
        }

        return .deny(
            "Git \(operation.rawValue) denied because branch '\(normalized)' "
                + "does not match an allowed branch pattern"
        )
    }

    public func generateInstallationScript() -> String {
        let policyScript = generatePolicyScript()
        return #"""
            #!/usr/bin/env bash
            set -euo pipefail

            GIT_COMMAND="$(command -v git || true)"
            [ -n "$GIT_COMMAND" ] || {
              echo '[sendbox-branch-protection] git is unavailable' >&2
              exit 126
            }
            GIT_RESOLVED="$(readlink -f "$GIT_COMMAND")"
            PYTHON_BIN="$(command -v python3 || true)"
            [ -n "$PYTHON_BIN" ] || {
              echo '[sendbox-branch-protection] python3 is unavailable' >&2
              exit 126
            }

            install -d -m 0711 \#(ShellEscaping.quote(Self.rootPath))
            install -d -m 0755 "$(dirname \#(ShellEscaping.quote(Self.wrapperPath)))"
            cp -- "$GIT_RESOLVED" \#(ShellEscaping.quote(Self.realGitPath))
            chmod 0111 \#(ShellEscaping.quote(Self.realGitPath))

            cat > \#(ShellEscaping.quote(Self.policyScriptPath)) << 'SENDBOX_GIT_POLICY'
            \#(policyScript)
            SENDBOX_GIT_POLICY
            chmod 0444 \#(ShellEscaping.quote(Self.policyScriptPath))

            cat > \#(ShellEscaping.quote(Self.wrapperPath)) << SENDBOX_GIT_WRAPPER
            #!/bin/sh
            exec "$PYTHON_BIN" -I -B \#(ShellEscaping.quote(Self.policyScriptPath)) "\$@"
            SENDBOX_GIT_WRAPPER
            chmod 0555 \#(ShellEscaping.quote(Self.wrapperPath))

            for git_path in "$GIT_COMMAND" "$GIT_RESOLVED" /usr/bin/git /bin/git; do
              [ "$git_path" = \#(ShellEscaping.quote(Self.wrapperPath)) ] && continue
              if [ -e "$git_path" ] || [ -L "$git_path" ]; then
                rm -f -- "$git_path"
                ln -s \#(ShellEscaping.quote(Self.wrapperPath)) "$git_path"
              fi
            done

            hash -r
            \#(ShellEscaping.quote(Self.wrapperPath)) --version >/dev/null
            echo '[sendbox-branch-protection] selected repository git guard enabled' >&2
            """#
    }

    public func generatePolicyScript(
        realGitPath: String = GitBranchProtection.realGitPath
    ) -> String {
        let protectedBranches = jsonLiteral(
            config.protectedBranches.compactMap(normalizedBranch)
        )
        let allowedPatterns = jsonLiteral(expandedAllowedPatterns)
        let selectedRepository = jsonLiteral([
            self.selectedRepository.host,
            self.selectedRepository.owner,
            self.selectedRepository.name,
        ])

        return #"""
            import fnmatch
            import os
            import re
            import shlex
            import subprocess
            import sys
            import urllib.parse

            REAL_GIT = \#(jsonLiteral(realGitPath))
            SELECTED_REPOSITORY = tuple(\#(selectedRepository))
            SELECTED_WORKSPACE = os.path.realpath(\#(jsonLiteral(selectedWorkspace)))
            PROTECTED_BRANCHES = {branch.lower() for branch in \#(protectedBranches)}
            ALLOWED_BRANCH_PATTERNS = \#(allowedPatterns)

            GLOBAL_OPTIONS_WITH_VALUE = {
                "-C",
                "-c",
                "--config-env",
                "--exec-path",
                "--git-dir",
                "--namespace",
                "--super-prefix",
                "--work-tree",
            }
            GLOBAL_OPTION_PREFIXES = (
                "--config-env=",
                "--exec-path=",
                "--git-dir=",
                "--namespace=",
                "--super-prefix=",
                "--work-tree=",
            )
            PUSH_OPTIONS_WITH_VALUE = {
                "--exec",
                "--push-option",
                "--receive-pack",
                "--repo",
                "-o",
            }
            PULL_OPTIONS_WITH_VALUE = {
                "--deepen",
                "--depth",
                "--jobs",
                "--negotiation-tip",
                "--recurse-submodules",
                "--server-option",
                "--shallow-exclude",
                "--shallow-since",
                "--strategy",
                "--strategy-option",
                "--upload-pack",
                "-X",
                "-j",
                "-o",
                "-s",
                "-u",
            }
            PUSH_BROAD_OPTIONS = {"--all", "--branches", "--mirror", "--tags"}
            PULL_BROAD_OPTIONS = {"--all"}


            def fail(message):
                sys.stderr.write(f"[sendbox-branch-protection] {message}\n")
                sys.stderr.flush()
                raise SystemExit(128)


            def execute_real():
                os.execve(REAL_GIT, [REAL_GIT] + sys.argv[1:], os.environ.copy())


            def run_git(arguments):
                return subprocess.run(
                    [REAL_GIT] + arguments,
                    cwd=os.getcwd(),
                    env=os.environ.copy(),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    check=False,
                )


            def git_values(arguments):
                result = run_git(arguments)
                if result.returncode != 0:
                    return []
                return [line.strip() for line in result.stdout.splitlines() if line.strip()]


            def git_value(arguments):
                values = git_values(arguments)
                return values[0] if values else None


            def split_invocation(arguments):
                global_arguments = []
                index = 0
                while index < len(arguments):
                    argument = arguments[index]
                    if argument == "--":
                        index += 1
                        break
                    if argument in GLOBAL_OPTIONS_WITH_VALUE:
                        if index + 1 >= len(arguments):
                            fail(f"git option {argument} is missing its value")
                        global_arguments.extend(arguments[index:index + 2])
                        index += 2
                        continue
                    if argument.startswith(GLOBAL_OPTION_PREFIXES):
                        global_arguments.append(argument)
                        index += 1
                        continue
                    if argument.startswith("-"):
                        global_arguments.append(argument)
                        index += 1
                        continue
                    return global_arguments, argument, arguments[index + 1:]

                if index < len(arguments):
                    return global_arguments, arguments[index], arguments[index + 1:]
                return global_arguments, None, []


            def resolve_alias(global_arguments, command, command_arguments):
                for _ in range(8):
                    if command in ("push", "pull") or command is None:
                        return global_arguments, command, command_arguments
                    alias = git_value(
                        global_arguments + ["config", "--get", f"alias.{command}"]
                    )
                    if alias is None:
                        return global_arguments, command, command_arguments
                    if alias.startswith("!"):
                        fail(f"shell git alias '{command}' is disabled by branch protection")
                    try:
                        expansion = shlex.split(alias)
                    except ValueError as error:
                        fail(f"git alias '{command}' is invalid: {error}")
                    if not expansion:
                        fail(f"git alias '{command}' is empty")
                    alias_globals, command, alias_arguments = split_invocation(
                        expansion + command_arguments
                    )
                    global_arguments += alias_globals
                    command_arguments = alias_arguments
                fail("git alias expansion exceeded the safety limit")


            def parse_operation_arguments(operation, arguments):
                value_options = (
                    PUSH_OPTIONS_WITH_VALUE if operation == "push"
                    else PULL_OPTIONS_WITH_VALUE
                )
                broad_options = (
                    PUSH_BROAD_OPTIONS if operation == "push"
                    else PULL_BROAD_OPTIONS
                )
                broad = None
                repository_option = None
                positionals = []
                index = 0

                while index < len(arguments):
                    argument = arguments[index]
                    if argument in ("-h", "--help"):
                        return None, [], None, True
                    if argument == "--":
                        positionals.extend(arguments[index + 1:])
                        break
                    if argument in broad_options:
                        broad = argument
                        index += 1
                        continue
                    if argument == "--repo":
                        if index + 1 >= len(arguments):
                            fail("git --repo is missing its value")
                        repository_option = arguments[index + 1]
                        index += 2
                        continue
                    if argument.startswith("--repo="):
                        repository_option = argument.split("=", 1)[1]
                        index += 1
                        continue
                    if argument in value_options:
                        if index + 1 >= len(arguments):
                            fail(f"git {operation} option {argument} is missing its value")
                        index += 2
                        continue
                    if any(
                        argument.startswith(option + "=")
                        for option in value_options if option.startswith("--")
                    ):
                        index += 1
                        continue
                    if argument.startswith(("-X", "-j", "-o")) and len(argument) > 2:
                        index += 1
                        continue
                    if argument.startswith("-"):
                        index += 1
                        continue
                    positionals.append(argument)
                    index += 1

                repository = repository_option
                if repository is None and positionals:
                    repository = positionals.pop(0)
                return repository, positionals, broad, False


            def current_branch(global_arguments):
                branch = git_value(global_arguments + ["branch", "--show-current"])
                if not branch:
                    fail("git push and pull require an allowed non-detached local branch")
                return branch


            def config_value(global_arguments, key):
                return git_value(global_arguments + ["config", "--get", key])


            def config_values(global_arguments, key):
                return git_values(global_arguments + ["config", "--get-all", key])


            def default_remote(global_arguments, operation, branch):
                if operation == "push":
                    candidates = [
                        f"branch.{branch}.pushRemote",
                        "remote.pushDefault",
                        f"branch.{branch}.remote",
                    ]
                else:
                    candidates = [f"branch.{branch}.remote"]
                for key in candidates:
                    value = config_value(global_arguments, key)
                    if value:
                        return value
                return "origin"


            def normalize_remote_url(remote_url):
                value = remote_url.strip()
                if not value:
                    return None

                match = re.match(r"^(?:[^@]+@)?([^:\/]+):(.+)$", value)
                if match and "://" not in value:
                    host = match.group(1)
                    path = match.group(2)
                elif "://" in value:
                    parsed = urllib.parse.urlparse(value)
                    if not parsed.hostname:
                        return None
                    host = parsed.hostname
                    path = parsed.path
                else:
                    parts = [part for part in value.strip("/").split("/") if part]
                    if len(parts) == 2:
                        host = SELECTED_REPOSITORY[0]
                        path = value
                    else:
                        return None

                parts = [
                    urllib.parse.unquote(part)
                    for part in path.strip("/").split("/")
                    if part
                ]
                if len(parts) < 2:
                    return None
                name = parts[1][:-4] if parts[1].lower().endswith(".git") else parts[1]
                return (host.lower(), parts[0].lower(), name.lower())


            def remote_identity(global_arguments, operation, repository):
                if repository is None:
                    return None
                direct = normalize_remote_url(repository)
                if direct is not None:
                    return direct

                arguments = global_arguments + ["remote", "get-url"]
                if operation == "push":
                    arguments.append("--push")
                arguments.append(repository)
                remote_url = git_value(arguments)
                return normalize_remote_url(remote_url) if remote_url else None


            def repository_root(global_arguments):
                root = git_value(global_arguments + ["rev-parse", "--show-toplevel"])
                return os.path.realpath(root) if root else None


            def targets_selected_repository(
                global_arguments,
                operation,
                repository,
            ):
                identity = remote_identity(global_arguments, operation, repository)
                if identity is not None:
                    return identity == SELECTED_REPOSITORY
                return repository_root(global_arguments) == SELECTED_WORKSPACE


            def normalize_branch(branch):
                value = branch.strip()
                while value.startswith("+"):
                    value = value[1:]
                if value in ("HEAD", "@"):
                    return None
                if value.startswith("refs/heads/"):
                    value = value[len("refs/heads/"):]
                elif value.startswith("refs/remotes/"):
                    remainder = value[len("refs/remotes/"):]
                    value = remainder.split("/", 1)[1] if "/" in remainder else ""
                elif value.startswith("refs/"):
                    return None
                if not value or "*" in value or "?" in value:
                    return None
                return value


            def check_branch(branch, operation, label):
                normalized = normalize_branch(branch)
                if normalized is None:
                    fail(f"git {operation} cannot safely resolve {label} branch '{branch}'")
                if normalized.lower() in PROTECTED_BRANCHES:
                    fail(f"git {operation} denied for protected branch '{normalized}'")
                if not any(
                    fnmatch.fnmatchcase(normalized, pattern)
                    for pattern in ALLOWED_BRANCH_PATTERNS
                ):
                    fail(
                        f"git {operation} denied because {label} branch '{normalized}' "
                        "does not match an allowed branch pattern"
                    )
                return normalized


            def upstream_branch(global_arguments):
                upstream = git_value(
                    global_arguments
                    + ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"]
                )
                if not upstream:
                    return None
                if upstream.startswith("refs/remotes/"):
                    upstream = upstream[len("refs/remotes/"):]
                return upstream.split("/", 1)[1] if "/" in upstream else upstream


            def local_branch_from_source(global_arguments, source, current):
                value = source.strip()
                while value.startswith("+"):
                    value = value[1:]
                if not value:
                    return None
                if value in ("HEAD", "@"):
                    return current
                if value.startswith("refs/heads/"):
                    return value[len("refs/heads/"):]
                if value.startswith("refs/"):
                    return None
                result = run_git(
                    global_arguments
                    + ["show-ref", "--verify", "--quiet", f"refs/heads/{value}"]
                )
                return value if result.returncode == 0 else None


            def push_refspec_branches(global_arguments, refspec, current):
                value = refspec
                while value.startswith("+"):
                    value = value[1:]
                if ":" in value:
                    source, destination = value.split(":", 1)
                else:
                    source = value
                    destination = value

                source_branch = local_branch_from_source(
                    global_arguments,
                    source,
                    current,
                )
                if destination in ("HEAD", "@"):
                    destination = current
                elif destination == source and source_branch is not None:
                    destination = source_branch
                return source_branch, destination


            def evaluate_push(global_arguments, repository, refspecs, current):
                remote_name = repository or default_remote(
                    global_arguments,
                    "push",
                    current,
                )
                effective_refspecs = list(refspecs)
                if not effective_refspecs and remote_name and "/" not in remote_name:
                    effective_refspecs = config_values(
                        global_arguments,
                        f"remote.{remote_name}.push",
                    )

                if not effective_refspecs:
                    mode = config_value(global_arguments, "push.default") or "simple"
                    if mode == "matching":
                        fail("git push denied because push.default=matching may update multiple branches")
                    if mode == "nothing":
                        fail("git push denied because no destination branch can be resolved")
                    if mode in ("upstream", "tracking"):
                        destination = upstream_branch(global_arguments)
                        if destination is None:
                            fail("git push denied because the upstream branch cannot be resolved")
                    else:
                        destination = current
                    effective_refspecs = [f"HEAD:{destination}"]

                for refspec in effective_refspecs:
                    source, destination = push_refspec_branches(
                        global_arguments,
                        refspec,
                        current,
                    )
                    if source is not None:
                        check_branch(source, "push", "source")
                    check_branch(destination, "push", "destination")


            def evaluate_pull(global_arguments, refspecs, current):
                effective_refspecs = list(refspecs)
                if not effective_refspecs:
                    effective_refspecs = config_values(
                        global_arguments,
                        f"branch.{current}.merge",
                    )
                if not effective_refspecs:
                    upstream = upstream_branch(global_arguments)
                    if upstream is None:
                        fail("git pull denied because the upstream branch cannot be resolved")
                    effective_refspecs = [upstream]

                for refspec in effective_refspecs:
                    source = refspec.split(":", 1)[0]
                    check_branch(source, "pull", "source")


            def main():
                global_arguments, command, command_arguments = split_invocation(sys.argv[1:])
                global_arguments, command, command_arguments = resolve_alias(
                    global_arguments,
                    command,
                    command_arguments,
                )
                if command not in ("push", "pull"):
                    execute_real()

                repository, refspecs, broad, help_requested = parse_operation_arguments(
                    command,
                    command_arguments,
                )
                if help_requested:
                    execute_real()

                if repository is not None and not targets_selected_repository(
                    global_arguments,
                    command,
                    repository,
                ):
                    execute_real()

                current = current_branch(global_arguments)
                remote = repository or default_remote(
                    global_arguments,
                    command,
                    current,
                )
                if repository is None and not targets_selected_repository(
                    global_arguments,
                    command,
                    remote,
                ):
                    execute_real()

                check_branch(current, command, "current")
                if broad is not None:
                    fail(f"git {command} option {broad} is too broad for branch protection")

                if command == "push":
                    evaluate_push(global_arguments, remote, refspecs, current)
                else:
                    evaluate_pull(global_arguments, refspecs, current)
                execute_real()


            main()
            """#
    }

    private var expandedAllowedPatterns: [String] {
        config.allowedBranchPatterns.compactMap { pattern in
            let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                return nil
            }
            guard trimmed.contains("{username}") else {
                return trimmed
            }
            guard let username, !username.isEmpty else {
                return nil
            }
            return trimmed.replacingOccurrences(of: "{username}", with: username)
        }
    }

    private func normalizedBranch(_ branch: String) -> String? {
        var value = branch.trimmingCharacters(in: .whitespacesAndNewlines)
        while value.hasPrefix("+") {
            value.removeFirst()
        }
        if value.hasPrefix("refs/heads/") {
            value.removeFirst("refs/heads/".count)
        } else if value.hasPrefix("refs/remotes/") {
            value.removeFirst("refs/remotes/".count)
            guard let slash = value.firstIndex(of: "/") else {
                return nil
            }
            value = String(value[value.index(after: slash)...])
        } else if value.hasPrefix("refs/") {
            return nil
        }
        guard !value.isEmpty, !value.contains("*"), !value.contains("?") else {
            return nil
        }
        return value
    }

    private func jsonLiteral<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        let data = (try? encoder.encode(value)) ?? Data("null".utf8)
        return String(data: data, encoding: .utf8) ?? "null"
    }

    private static func runProcess(
        _ executable: String,
        arguments: [String],
        currentDirectory: String? = nil
    ) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [executable] + arguments
        if let currentDirectory {
            process.currentDirectoryURL = URL(fileURLWithPath: currentDirectory)
        }

        let output = Pipe()
        process.standardOutput = output
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw ValidationError.gitRemoteUnavailable
        }
        return String(
            data: output.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        )?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }
}
