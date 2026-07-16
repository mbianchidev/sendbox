import Foundation
import Logging

/// Evaluates commands against allowlist / denylist rules using glob-style patterns.
public actor CommandPolicy {

    private struct CommandInvocation: Hashable, Sendable {
        let arguments: [String]
    }

    private enum Rules: Sendable {
        case configured(PolicyConfiguration.CommandPolicyConfig)
        case exact(Set<CommandInvocation>)
    }

    private let rules: Rules
    private let logger: Logger

    // MARK: - Types

    public enum CommandDecision: Sendable, Equatable {
        case allowed
        case denied(reason: String)

        public var isAllowed: Bool {
            switch self {
            case .allowed: return true
            case .denied: return false
            }
        }
    }

    // MARK: - Init

    public init(
        config: PolicyConfiguration.CommandPolicyConfig,
        logger: Logger = Logger(label: "sendbox.command-policy")
    ) {
        self.rules = .configured(config)
        self.logger = logger
    }

    static func exactlyAllowing(
        _ commands: [[String]],
        logger: Logger = Logger(label: "sendbox.command-policy.bootstrap")
    ) -> CommandPolicy {
        CommandPolicy(
            rules: .exact(Set(commands.map { CommandInvocation(arguments: $0) })),
            logger: logger
        )
    }

    private init(rules: Rules, logger: Logger) {
        self.rules = rules
        self.logger = logger
    }

    // MARK: - Public API

    /// Evaluate a single command against the policy.
    public func evaluate(_ command: String) -> CommandDecision {
        let trimmed = command.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else {
            return .denied(reason: "Empty command")
        }

        let parsed = parseCommand(trimmed)
        return evaluate(
            arguments: [parsed.binary] + parsed.arguments,
            matchText: trimmed,
            diagnosticText: trimmed
        )
    }

    /// Evaluate one argv vector without interpreting shell metacharacters.
    public func evaluate(_ arguments: [String]) -> CommandDecision {
        guard let executable = arguments.first,
            !executable.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            return .denied(reason: "Empty command")
        }

        return evaluate(
            arguments: arguments,
            matchText: arguments.joined(separator: " "),
            diagnosticText: diagnosticCommand(arguments)
        )
    }

    private func evaluate(
        arguments: [String],
        matchText: String,
        diagnosticText: String
    ) -> CommandDecision {
        switch rules {
        case .exact(let allowedCommands):
            if allowedCommands.contains(CommandInvocation(arguments: arguments)) {
                logger.debug("Allowed exact command: \(diagnosticText)")
                return .allowed
            }
            let binary = arguments.first ?? ""
            return .denied(
                reason: "Command '\(binary)' is not an approved runtime bootstrap invocation"
            )

        case .configured(let config):
            return evaluateConfigured(
                arguments: arguments,
                matchText: matchText,
                diagnosticText: diagnosticText,
                config: config
            )
        }
    }

    private func evaluateConfigured(
        arguments: [String],
        matchText: String,
        diagnosticText: String,
        config: PolicyConfiguration.CommandPolicyConfig
    ) -> CommandDecision {
        for pattern in config.denylist {
            if matches(arguments, matchText: matchText, pattern: pattern) {
                let decision = CommandDecision.denied(
                    reason: "Command '\(arguments[0])' matches deny pattern '\(pattern)'"
                )
                if config.logBlocked {
                    logger.warning(
                        "Blocked command: \(diagnosticText) (deny pattern: \(pattern))"
                    )
                }
                return decision
            }
        }

        for pattern in config.allowlist {
            if matches(arguments, matchText: matchText, pattern: pattern) {
                logger.debug("Allowed command: \(diagnosticText) (pattern: \(pattern))")
                return .allowed
            }
        }

        switch config.defaultAction {
        case .allow:
            logger.debug("Allowed command by default: \(diagnosticText)")
            return .allowed
        case .deny:
            let decision = CommandDecision.denied(
                reason: "Command '\(arguments[0])' not in allowlist"
            )
            if config.logBlocked {
                logger.warning("Blocked command (default deny): \(diagnosticText)")
            }
            return decision
        }
    }

    /// Evaluate a pipeline or chained command (e.g. `cmd1 | cmd2 && cmd3`).
    /// Every segment must pass evaluation independently.
    public func evaluatePipeline(_ command: String) -> CommandDecision {
        let segments = splitPipeline(command)

        for segment in segments {
            let decision = evaluate(segment)
            if !decision.isAllowed {
                return decision
            }
        }
        return .allowed
    }

    // MARK: - Private helpers

    /// Check whether `command` matches a glob-style `pattern`.
    ///
    /// Matching rules:
    /// - A bare name (no `*`) matches the binary name exactly.
    /// - A pattern ending with ` *` (e.g. `git *`) matches any command whose
    ///   binary equals the prefix.
    /// - A pattern containing `*` elsewhere is matched character-by-character
    ///   against the full command string.
    private func matches(
        _ arguments: [String],
        matchText: String,
        pattern: String
    ) -> Bool {
        let hasWildcard = pattern.contains("*") || pattern.contains("?")
        if !hasWildcard {
            let parsedPattern = parseCommand(pattern)
            let patternArguments = [parsedPattern.binary] + parsedPattern.arguments
            guard !patternArguments[0].isEmpty else {
                return false
            }
            if patternArguments.count == 1 {
                return arguments.first == patternArguments[0]
            }
            return arguments.starts(with: patternArguments)
        }

        if pattern.hasSuffix(" *") {
            let prefix = String(pattern.dropLast(2))
            if !prefix.contains("*") && !prefix.contains("?") {
                let parsedPrefix = parseCommand(prefix)
                let prefixArguments = [parsedPrefix.binary] + parsedPrefix.arguments
                return arguments.starts(with: prefixArguments)
            }
        }

        return GlobPattern.matches(matchText, pattern: pattern)
    }

    private func diagnosticCommand(_ arguments: [String]) -> String {
        arguments.map { argument in
            "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }.joined(separator: " ")
    }

    /// Parse a raw command string into its binary name and argument list.
    private func parseCommand(_ command: String) -> (binary: String, arguments: [String]) {
        let trimmed = command.trimmingCharacters(in: .whitespaces)
        var parts: [String] = []
        var current = ""
        var inSingleQuote = false
        var inDoubleQuote = false
        var escaped = false

        for char in trimmed {
            if escaped {
                current.append(char)
                escaped = false
                continue
            }

            if char == "\\" && !inSingleQuote {
                escaped = true
                continue
            }

            if char == "'" && !inDoubleQuote {
                inSingleQuote.toggle()
                continue
            }

            if char == "\"" && !inSingleQuote {
                inDoubleQuote.toggle()
                continue
            }

            if char == " " && !inSingleQuote && !inDoubleQuote {
                if !current.isEmpty {
                    parts.append(current)
                    current = ""
                }
                continue
            }

            current.append(char)
        }
        if !current.isEmpty {
            parts.append(current)
        }

        guard let binary = parts.first else {
            return (binary: "", arguments: [])
        }
        return (binary: binary, arguments: Array(parts.dropFirst()))
    }

    /// Split a pipeline / chain into individual command strings.
    /// Handles `|`, `&&`, `||`, and `;`.
    private func splitPipeline(_ command: String) -> [String] {
        var segments: [String] = []
        var current = ""
        var inSingleQuote = false
        var inDoubleQuote = false
        var escaped = false
        let chars = Array(command)
        var i = 0

        while i < chars.count {
            let char = chars[i]

            if escaped {
                current.append(char)
                escaped = false
                i += 1
                continue
            }

            if char == "\\" && !inSingleQuote {
                escaped = true
                current.append(char)
                i += 1
                continue
            }

            if char == "'" && !inDoubleQuote {
                inSingleQuote.toggle()
                current.append(char)
                i += 1
                continue
            }

            if char == "\"" && !inSingleQuote {
                inDoubleQuote.toggle()
                current.append(char)
                i += 1
                continue
            }

            if !inSingleQuote && !inDoubleQuote {
                // Check for && or ||
                if i + 1 < chars.count
                    && ((char == "&" && chars[i + 1] == "&")
                        || (char == "|" && chars[i + 1] == "|"))
                {
                    let trimmed = current.trimmingCharacters(in: .whitespaces)
                    if !trimmed.isEmpty { segments.append(trimmed) }
                    current = ""
                    i += 2
                    continue
                }

                // Check for | (pipe) or ; (semicolon)
                if char == "|" || char == ";" {
                    let trimmed = current.trimmingCharacters(in: .whitespaces)
                    if !trimmed.isEmpty { segments.append(trimmed) }
                    current = ""
                    i += 1
                    continue
                }
            }

            current.append(char)
            i += 1
        }

        let trimmed = current.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty { segments.append(trimmed) }
        return segments
    }
}
