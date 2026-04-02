import Foundation
import Logging

/// Runtime supervisor for dynamic permission expansion with user approval.
///
/// When an agent attempts an action that is outside its current policy (e.g., a
/// command not in the allowlist, or a network domain not allowed), instead of
/// immediately blocking it, the supervisor can:
/// 1. Prompt the user for one-time or session-wide approval
/// 2. Auto-approve based on escalation rules
/// 3. Log the decision for audit
///
/// This enables a "progressive trust" model where agents start restricted
/// and earn broader permissions through supervised interaction.
public actor RuntimeSupervisor {

    private let config: SupervisorConfig
    private let logger: Logger
    private var sessionGrants: [PermissionGrant]
    private var pendingRequests: [PermissionRequest]
    private var decisionHistory: [PermissionDecision]
    private var onApprovalRequest: (@Sendable (PermissionRequest) async -> ApprovalResponse)?

    // MARK: - Types

    /// Supervisor configuration.
    public struct SupervisorConfig: Codable, Sendable {
        /// Whether to prompt user for blocked actions.
        public var interactiveMode: Bool
        /// Auto-approve patterns (actions that are always allowed after first approval).
        public var autoApprovePatterns: [AutoApproveRule]
        /// Maximum times to prompt per session before auto-denying.
        public var maxPromptsPerSession: Int
        /// Whether to allow session-wide grants.
        public var allowSessionGrants: Bool
        /// Timeout for user response (seconds).
        public var approvalTimeout: TimeInterval

        public init(
            interactiveMode: Bool = true,
            autoApprovePatterns: [AutoApproveRule] = [],
            maxPromptsPerSession: Int = 50,
            allowSessionGrants: Bool = true,
            approvalTimeout: TimeInterval = 30
        ) {
            self.interactiveMode = interactiveMode
            self.autoApprovePatterns = autoApprovePatterns
            self.maxPromptsPerSession = maxPromptsPerSession
            self.allowSessionGrants = allowSessionGrants
            self.approvalTimeout = approvalTimeout
        }

        /// Balanced defaults: interactive, session grants allowed, 30s timeout.
        public static let `default` = SupervisorConfig()

        /// No auto-approve, always prompt, short timeout.
        public static let strict = SupervisorConfig(
            interactiveMode: true,
            autoApprovePatterns: [],
            maxPromptsPerSession: 100,
            allowSessionGrants: false,
            approvalTimeout: 15
        )

        /// Auto-approve most things, generous limits.
        public static let autonomous = SupervisorConfig(
            interactiveMode: false,
            autoApprovePatterns: [
                AutoApproveRule(pattern: "*", category: .command, maxUses: nil),
                AutoApproveRule(pattern: "*", category: .fileWrite, maxUses: nil),
                AutoApproveRule(pattern: "*", category: .network, maxUses: nil),
            ],
            maxPromptsPerSession: 0,
            allowSessionGrants: true,
            approvalTimeout: 0
        )
    }

    /// A rule for auto-approving certain patterns after initial approval.
    public struct AutoApproveRule: Codable, Sendable {
        public let pattern: String
        public let category: PermissionCategory
        public let maxUses: Int?

        public init(pattern: String, category: PermissionCategory, maxUses: Int? = nil) {
            self.pattern = pattern
            self.category = category
            self.maxUses = maxUses
        }
    }

    public enum PermissionCategory: String, Codable, Sendable {
        case command
        case network
        case fileWrite
        case secretAccess
        case systemCall
    }

    /// A request for elevated permission.
    public struct PermissionRequest: Sendable {
        public let id: String
        public let timestamp: Date
        public let category: PermissionCategory
        public let action: String
        public let context: String
        public let riskLevel: RiskLevel

        public enum RiskLevel: String, Sendable, Codable {
            case low
            case medium
            case high
            case critical
        }

        public init(
            id: String = UUID().uuidString,
            timestamp: Date = Date(),
            category: PermissionCategory,
            action: String,
            context: String,
            riskLevel: RiskLevel
        ) {
            self.id = id
            self.timestamp = timestamp
            self.category = category
            self.action = action
            self.context = context
            self.riskLevel = riskLevel
        }
    }

    /// User's response to a permission request.
    public enum ApprovalResponse: Sendable {
        case approveOnce
        case approveForSession
        case approvePattern(String)
        case deny
        case denyAlways
    }

    /// A granted permission.
    public struct PermissionGrant: Codable, Sendable {
        public let id: String
        public let category: PermissionCategory
        public let pattern: String
        public let grantedAt: Date
        public let expiresAt: Date?
        public let usesRemaining: Int?
        public let grantType: GrantType

        public enum GrantType: String, Codable, Sendable {
            case once
            case session
            case pattern
        }

        public init(
            id: String = UUID().uuidString,
            category: PermissionCategory,
            pattern: String,
            grantedAt: Date = Date(),
            expiresAt: Date? = nil,
            usesRemaining: Int? = nil,
            grantType: GrantType
        ) {
            self.id = id
            self.category = category
            self.pattern = pattern
            self.grantedAt = grantedAt
            self.expiresAt = expiresAt
            self.usesRemaining = usesRemaining
            self.grantType = grantType
        }
    }

    /// A recorded decision for audit.
    public struct PermissionDecision: Codable, Sendable {
        public let requestId: String
        public let timestamp: Date
        public let category: PermissionCategory
        public let action: String
        public let response: String
        public let automated: Bool

        public init(
            requestId: String,
            timestamp: Date = Date(),
            category: PermissionCategory,
            action: String,
            response: String,
            automated: Bool
        ) {
            self.requestId = requestId
            self.timestamp = timestamp
            self.category = category
            self.action = action
            self.response = response
            self.automated = automated
        }
    }

    /// Summary of supervisor activity.
    public struct SupervisorSummary: Sendable {
        public let totalRequests: Int
        public let approved: Int
        public let denied: Int
        public let autoApproved: Int
        public let activeGrantCount: Int
        public let categoryCounts: [PermissionCategory: Int]
    }

    // MARK: - Init

    public init(
        config: SupervisorConfig = .default,
        logger: Logger = Logger(label: "sendbox.runtime-supervisor")
    ) {
        self.config = config
        self.logger = logger
        self.sessionGrants = []
        self.pendingRequests = []
        self.decisionHistory = []
        self.onApprovalRequest = nil
    }

    // MARK: - Approval Handler

    /// Set the callback for requesting user approval.
    /// This is typically wired to the CLI's interactive prompt.
    public func setApprovalHandler(
        _ handler: @escaping @Sendable (PermissionRequest) async -> ApprovalResponse
    ) {
        onApprovalRequest = handler
    }

    // MARK: - Permission Checks

    /// Check if an action is permitted. May prompt the user.
    /// Returns true if allowed (by grant, auto-approve, or fresh approval).
    public func checkPermission(
        category: PermissionCategory,
        action: String,
        context: String
    ) async -> Bool {
        // 1. Check existing grants.
        if let grant = matchesGrant(category: category, action: action) {
            logger.debug("Action '\(action)' allowed by grant \(grant.id)")
            recordDecision(
                requestId: "grant-\(grant.id)",
                category: category,
                action: action,
                response: "approved (existing grant)",
                automated: true
            )
            consumeGrantUse(grantId: grant.id)
            return true
        }

        // 2. Check auto-approve rules.
        if matchesAutoApprove(category: category, action: action) {
            logger.debug("Action '\(action)' auto-approved by rule")
            recordDecision(
                requestId: UUID().uuidString,
                category: category,
                action: action,
                response: "approved (auto-approve rule)",
                automated: true
            )
            return true
        }

        // 3. If not interactive, deny.
        guard config.interactiveMode else {
            logger.info("Action '\(action)' denied (non-interactive mode)")
            recordDecision(
                requestId: UUID().uuidString,
                category: category,
                action: action,
                response: "denied (non-interactive)",
                automated: true
            )
            return false
        }

        // 4. Check prompt budget.
        let promptCount = decisionHistory.filter { !$0.automated }.count
        guard promptCount < config.maxPromptsPerSession else {
            logger.warning("Prompt budget exhausted (\(config.maxPromptsPerSession)), auto-denying")
            recordDecision(
                requestId: UUID().uuidString,
                category: category,
                action: action,
                response: "denied (prompt budget exhausted)",
                automated: true
            )
            return false
        }

        // 5. Prompt the user.
        guard let handler = onApprovalRequest else {
            logger.info("No approval handler set, denying '\(action)'")
            recordDecision(
                requestId: UUID().uuidString,
                category: category,
                action: action,
                response: "denied (no handler)",
                automated: true
            )
            return false
        }

        let riskLevel = assessRisk(category: category, action: action)
        let request = PermissionRequest(
            category: category,
            action: action,
            context: context,
            riskLevel: riskLevel
        )

        pendingRequests.append(request)
        logger.info(
            "Requesting approval for '\(action)' (category: \(category.rawValue), risk: \(riskLevel.rawValue))"
        )

        let response = await withTimeout(seconds: config.approvalTimeout) {
            await handler(request)
        }

        pendingRequests.removeAll { $0.id == request.id }
        return processApproval(response: response, request: request)
    }

    /// Evaluate an action against current grants (no prompting).
    public func hasGrant(category: PermissionCategory, action: String) -> Bool {
        matchesGrant(category: category, action: action) != nil
    }

    // MARK: - Grant Management

    /// Manually grant a permission.
    public func grant(_ grant: PermissionGrant) {
        sessionGrants.append(grant)
        logger.info(
            "Granted \(grant.grantType.rawValue) permission for '\(grant.pattern)' (category: \(grant.category.rawValue))"
        )
    }

    /// Revoke a specific grant.
    public func revoke(grantId: String) {
        sessionGrants.removeAll { $0.id == grantId }
        logger.info("Revoked grant \(grantId)")
    }

    /// Revoke all session grants.
    public func revokeAll() {
        let count = sessionGrants.count
        sessionGrants.removeAll()
        logger.info("Revoked all \(count) session grants")
    }

    /// Get all active (non-expired, uses remaining) grants.
    public func activeGrants() -> [PermissionGrant] {
        let now = Date()
        return sessionGrants.filter { grant in
            if let expiresAt = grant.expiresAt, expiresAt < now {
                return false
            }
            if let uses = grant.usesRemaining, uses <= 0 {
                return false
            }
            return true
        }
    }

    /// Get decision history for audit.
    public func history() -> [PermissionDecision] {
        decisionHistory
    }

    /// Get a summary of supervisor activity.
    public func summary() -> SupervisorSummary {
        let approved = decisionHistory.filter { $0.response.hasPrefix("approved") }.count
        let denied = decisionHistory.filter { $0.response.hasPrefix("denied") }.count
        let autoApproved = decisionHistory.filter {
            $0.automated && $0.response.hasPrefix("approved")
        }.count

        var categoryCounts: [PermissionCategory: Int] = [:]
        for decision in decisionHistory {
            categoryCounts[decision.category, default: 0] += 1
        }

        return SupervisorSummary(
            totalRequests: decisionHistory.count,
            approved: approved,
            denied: denied,
            autoApproved: autoApproved,
            activeGrantCount: activeGrants().count,
            categoryCounts: categoryCounts
        )
    }

    // MARK: - Private Helpers

    /// Classify the risk level of an action.
    private func assessRisk(
        category: PermissionCategory,
        action: String
    ) -> PermissionRequest.RiskLevel {
        switch category {
        case .systemCall:
            let criticalPatterns = ["mount", "umount", "reboot", "shutdown", "kexec", "insmod"]
            if criticalPatterns.contains(where: { action.contains($0) }) {
                return .critical
            }
            return .high

        case .secretAccess:
            return .high

        case .network:
            // Known registries are medium, everything else is high.
            let knownDomains = [
                "github.com", "npmjs.org", "pypi.org", "crates.io",
                "docker.io", "docker.com",
            ]
            if knownDomains.contains(where: { action.contains($0) }) {
                return .medium
            }
            return .high

        case .command:
            let dangerousCommands = [
                "sudo", "su", "chmod", "chown", "dd", "mkfs",
                "fdisk", "iptables", "systemctl",
            ]
            if dangerousCommands.contains(where: { action.hasPrefix($0) }) {
                return .high
            }
            return .medium

        case .fileWrite:
            // Writes outside the working directory are riskier.
            if action.hasPrefix("/etc") || action.hasPrefix("/usr")
                || action.hasPrefix("/sys") || action.hasPrefix("/proc")
            {
                return .high
            }
            return .low
        }
    }

    /// Check if an action matches any auto-approve rule.
    private func matchesAutoApprove(
        category: PermissionCategory,
        action: String
    ) -> Bool {
        for rule in config.autoApprovePatterns {
            guard rule.category == category else { continue }
            if globMatch(action, pattern: rule.pattern) {
                if let maxUses = rule.maxUses {
                    let usedCount = decisionHistory.filter {
                        $0.automated && $0.category == category
                            && $0.response.contains("auto-approve")
                    }.count
                    if usedCount >= maxUses { continue }
                }
                return true
            }
        }
        return false
    }

    /// Check if action matches any existing active grant.
    private func matchesGrant(
        category: PermissionCategory,
        action: String
    ) -> PermissionGrant? {
        let now = Date()
        return activeGrants().first { grant in
            guard grant.category == category else { return false }
            if let expiresAt = grant.expiresAt, expiresAt < now { return false }
            if let uses = grant.usesRemaining, uses <= 0 { return false }
            return globMatch(action, pattern: grant.pattern)
        }
    }

    /// Consume one use of a use-limited grant.
    private func consumeGrantUse(grantId: String) {
        guard let index = sessionGrants.firstIndex(where: { $0.id == grantId }),
              let remaining = sessionGrants[index].usesRemaining
        else { return }

        let grant = sessionGrants[index]
        sessionGrants[index] = PermissionGrant(
            id: grant.id,
            category: grant.category,
            pattern: grant.pattern,
            grantedAt: grant.grantedAt,
            expiresAt: grant.expiresAt,
            usesRemaining: remaining - 1,
            grantType: grant.grantType
        )
    }

    /// Process an approval response and create grants as needed.
    private func processApproval(
        response: ApprovalResponse,
        request: PermissionRequest
    ) -> Bool {
        switch response {
        case .approveOnce:
            let grant = PermissionGrant(
                category: request.category,
                pattern: request.action,
                usesRemaining: 1,
                grantType: .once
            )
            sessionGrants.append(grant)
            recordDecision(
                requestId: request.id,
                category: request.category,
                action: request.action,
                response: "approved (once)",
                automated: false
            )
            logger.info("User approved '\(request.action)' once")
            return true

        case .approveForSession:
            guard config.allowSessionGrants else {
                logger.warning("Session grants not allowed by config, treating as approve-once")
                return processApproval(response: .approveOnce, request: request)
            }
            let grant = PermissionGrant(
                category: request.category,
                pattern: request.action,
                grantType: .session
            )
            sessionGrants.append(grant)
            recordDecision(
                requestId: request.id,
                category: request.category,
                action: request.action,
                response: "approved (session)",
                automated: false
            )
            logger.info("User approved '\(request.action)' for session")
            return true

        case .approvePattern(let pattern):
            let grant = PermissionGrant(
                category: request.category,
                pattern: pattern,
                grantType: .pattern
            )
            sessionGrants.append(grant)
            recordDecision(
                requestId: request.id,
                category: request.category,
                action: request.action,
                response: "approved (pattern: \(pattern))",
                automated: false
            )
            logger.info("User approved pattern '\(pattern)' for \(request.category.rawValue)")
            return true

        case .deny:
            recordDecision(
                requestId: request.id,
                category: request.category,
                action: request.action,
                response: "denied",
                automated: false
            )
            logger.info("User denied '\(request.action)'")
            return false

        case .denyAlways:
            recordDecision(
                requestId: request.id,
                category: request.category,
                action: request.action,
                response: "denied (always)",
                automated: false
            )
            logger.info("User permanently denied '\(request.action)'")
            return false
        }
    }

    /// Record a permission decision for the audit trail.
    private func recordDecision(
        requestId: String,
        category: PermissionCategory,
        action: String,
        response: String,
        automated: Bool
    ) {
        let decision = PermissionDecision(
            requestId: requestId,
            category: category,
            action: action,
            response: response,
            automated: automated
        )
        decisionHistory.append(decision)
    }

    /// Simple glob matching: `*` matches zero or more of any character.
    private func globMatch(_ string: String, pattern: String) -> Bool {
        if pattern == "*" { return true }

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

    /// Run an async closure with a timeout. Returns `.deny` on timeout.
    private func withTimeout(
        seconds: TimeInterval,
        operation: @escaping @Sendable () async -> ApprovalResponse
    ) async -> ApprovalResponse {
        guard seconds > 0 else {
            return await operation()
        }

        return await withTaskGroup(of: ApprovalResponse.self) { group in
            group.addTask {
                await operation()
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return .deny
            }

            // Return whichever finishes first.
            let result = await group.next() ?? .deny
            group.cancelAll()
            return result
        }
    }
}
