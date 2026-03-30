import Foundation
import Logging

/// Evaluates commands against allowlist / denylist rules using glob-style patterns.
public actor CommandPolicy {

    private let config: PolicyConfiguration.CommandPolicyConfig
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
        self.config = config
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

        // Denylist always takes priority.
        for pattern in config.denylist {
            if matches(trimmed, pattern: pattern) {
                let decision = CommandDecision.denied(
                    reason: "Command '\(parsed.binary)' matches deny pattern '\(pattern)'"
                )
                if config.logBlocked {
                    logger.warning("Blocked command: \(trimmed) (deny pattern: \(pattern))")
                }
                return decision
            }
        }

        // Check allowlist.
        for pattern in config.allowlist {
            if matches(trimmed, pattern: pattern) {
                logger.debug("Allowed command: \(trimmed) (pattern: \(pattern))")
                return .allowed
            }
        }

        // Fall through to default action.
        switch config.defaultAction {
        case .allow:
            logger.debug("Allowed command by default: \(trimmed)")
            return .allowed
        case .deny:
            let decision = CommandDecision.denied(
                reason: "Command '\(parsed.binary)' not in allowlist"
            )
            if config.logBlocked {
                logger.warning("Blocked command (default deny): \(trimmed)")
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
    private func matches(_ command: String, pattern: String) -> Bool {
        let parsed = parseCommand(command)

        // Exact binary-only match (pattern has no wildcard).
        if !pattern.contains("*") {
            // Match full command or just binary.
            if command == pattern || parsed.binary == pattern {
                return true
            }
            // Support multi-word exact patterns like "git status".
            return command.hasPrefix(pattern)
                && (command.count == pattern.count
                    || command[command.index(command.startIndex, offsetBy: pattern.count)] == " ")
        }

        // Pattern like "git *" — binary match + allow any arguments.
        if pattern.hasSuffix(" *") {
            let prefix = String(pattern.dropLast(2))
            return parsed.binary == prefix
        }

        // General glob match against full command string.
        return globMatch(command, pattern: pattern)
    }

    /// Simple glob matching: `*` matches zero or more of any character.
    private func globMatch(_ string: String, pattern: String) -> Bool {
        var si = string.startIndex
        var pi = pattern.startIndex

        var starMatchSI = string.endIndex
        var starPI = pattern.endIndex

        while si < string.endIndex {
            if pi < pattern.endIndex && (pattern[pi] == "?" || pattern[pi] == string[si]) {
                si = string.index(after: si)
                pi = pattern.index(after: pi)
            } else if pi < pattern.endIndex && pattern[pi] == "*" {
                starPI = pi
                starMatchSI = si
                pi = pattern.index(after: pi)
            } else if starPI != pattern.endIndex {
                pi = pattern.index(after: starPI)
                starMatchSI = string.index(after: starMatchSI)
                si = starMatchSI
            } else {
                return false
            }
        }

        while pi < pattern.endIndex && pattern[pi] == "*" {
            pi = pattern.index(after: pi)
        }
        return pi == pattern.endIndex
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
