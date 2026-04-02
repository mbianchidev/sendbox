import Foundation
import Logging

/// Generates iptables rules and DNS configuration for container network isolation.
public struct NetworkFirewall: Sendable {

    private let config: PolicyConfiguration.NetworkPolicyConfig
    private let logger: Logger

    // MARK: - Init

    public init(
        config: PolicyConfiguration.NetworkPolicyConfig,
        logger: Logger = Logger(label: "sendbox.firewall")
    ) {
        self.config = config
        self.logger = logger
    }

    // MARK: - Domain checks

    /// Check whether `domain` is permitted by the current policy.
    public func isDomainAllowed(_ domain: String) -> Bool {
        let lowered = domain.lowercased()

        // Blocked domains always win.
        for pattern in config.blockedDomains {
            if matchesDomain(lowered, pattern: pattern.lowercased()) {
                logger.debug("Domain blocked: \(domain) (pattern: \(pattern))")
                return false
            }
        }

        // Allowed domains.
        for pattern in config.allowedDomains {
            if matchesDomain(lowered, pattern: pattern.lowercased()) {
                logger.debug("Domain allowed: \(domain) (pattern: \(pattern))")
                return true
            }
        }

        // Fall through to default action.
        switch config.defaultAction {
        case .allow:
            return true
        case .deny:
            logger.debug("Domain denied by default: \(domain)")
            return false
        }
    }

    // MARK: - Rule generation

    /// Generate a complete iptables rule script for the container.
    public func generateFirewallRules() -> String {
        var lines: [String] = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            "# --- SendBox firewall rules ---",
            "",
            "# Flush existing rules",
            "iptables -F",
            "iptables -X",
            "iptables -t nat -F",
            "iptables -t nat -X",
            "",
            "# Allow loopback",
            "iptables -A INPUT  -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            "",
            "# Allow established / related connections",
            "iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "",
        ]

        // DNS
        if config.allowDNS {
            lines.append("# Allow DNS (UDP + TCP port 53)")
            lines.append("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT")
            lines.append("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT")
            lines.append("iptables -A INPUT  -p udp --sport 53 -j ACCEPT")
            lines.append("iptables -A INPUT  -p tcp --sport 53 -j ACCEPT")
            lines.append("")
        }

        // Rate limiting
        if let max = config.maxConnections {
            lines.append("# Rate-limit new outbound connections (\(max)/min)")
            lines.append(
                "iptables -A OUTPUT -m conntrack --ctstate NEW "
                + "-m limit --limit \(max)/minute --limit-burst \(max) -j ACCEPT"
            )
            lines.append(
                "iptables -A OUTPUT -m conntrack --ctstate NEW -j DROP"
            )
            lines.append("")
        }

        switch config.defaultAction {
        case .deny:
            // Add ACCEPT rules for allowed domains.
            if !config.allowedDomains.isEmpty {
                lines.append("# Allowed domains (resolved at apply-time)")
                for domain in config.allowedDomains {
                    let clean = domain.replacingOccurrences(of: "*.", with: "")
                    lines.append("# \(domain)")
                    lines.append(
                        "for ip in $(dig +short \(clean) A 2>/dev/null); do"
                    )
                    lines.append(
                        "  iptables -A OUTPUT -d \"$ip\" -j ACCEPT"
                    )
                    lines.append("done")
                }
                lines.append("")
            }

            // Log + drop everything else.
            lines.append("# Log dropped packets")
            lines.append(
                "iptables -A OUTPUT -j LOG --log-prefix \"[SENDBOX DROP] \" --log-level 4"
            )
            lines.append("")
            lines.append("# Default policy: DROP")
            lines.append("iptables -P INPUT   DROP")
            lines.append("iptables -P FORWARD DROP")
            lines.append("iptables -P OUTPUT  DROP")

        case .allow:
            // Add DROP rules for blocked domains.
            if !config.blockedDomains.isEmpty {
                lines.append("# Blocked domains (resolved at apply-time)")
                for domain in config.blockedDomains {
                    let clean = domain.replacingOccurrences(of: "*.", with: "")
                    lines.append("# \(domain)")
                    lines.append(
                        "for ip in $(dig +short \(clean) A 2>/dev/null); do"
                    )
                    lines.append(
                        "  iptables -A OUTPUT -d \"$ip\" -j DROP"
                    )
                    lines.append("done")
                }
                lines.append("")
            }

            // Log dropped packets (if any explicit blocks exist).
            if !config.blockedDomains.isEmpty {
                lines.append("# Log explicitly dropped packets")
                lines.append(
                    "iptables -A OUTPUT -m mark --mark 0x1 -j LOG "
                    + "--log-prefix \"[SENDBOX DROP] \" --log-level 4"
                )
                lines.append("")
            }

            lines.append("# Default policy: ACCEPT")
            lines.append("iptables -P INPUT   ACCEPT")
            lines.append("iptables -P FORWARD DROP")
            lines.append("iptables -P OUTPUT  ACCEPT")
        }

        lines.append("")
        return lines.joined(separator: "\n")
    }

    /// Generate resolv.conf content for the container.
    public func generateDNSConfig() -> String {
        var lines: [String] = [
            "# Generated by SendBox",
        ]

        if config.allowDNS {
            // Use well-known public resolvers.
            lines.append("nameserver 1.1.1.1")
            lines.append("nameserver 8.8.8.8")
            lines.append("options edns0 trust-ad ndots:0")
        } else {
            // Point at localhost so resolution silently fails inside the container.
            lines.append("# DNS disabled by policy")
            lines.append("nameserver 127.0.0.1")
        }

        lines.append("")
        return lines.joined(separator: "\n")
    }

    /// Generate a complete startup script that applies firewall rules and DNS config.
    public func generateStartupScript() -> String {
        let firewall = generateFirewallRules()
        let dns = generateDNSConfig()

        var script: [String] = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            "# ============================================",
            "# SendBox container network setup",
            "# ============================================",
            "",
            "echo '[sendbox] Configuring DNS...'",
            "cat > /etc/resolv.conf << 'SENDBOX_DNS'",
            dns.trimmingCharacters(in: .newlines),
            "SENDBOX_DNS",
            "",
            "echo '[sendbox] Applying firewall rules...'",
            "",
        ]

        // Embed the firewall script inline (skip the shebang / set lines
        // since the outer script already has them).
        let firewallBody = firewall
            .split(separator: "\n", omittingEmptySubsequences: false)
            .dropFirst(2)  // drop #!/usr/bin/env bash and set -euo pipefail
            .joined(separator: "\n")
        script.append(firewallBody)

        script.append("")
        script.append("echo '[sendbox] Network setup complete.'")
        script.append("")

        return script.joined(separator: "\n")
    }

    // MARK: - Private helpers

    /// Match a domain against a pattern.
    /// Supports wildcards: `*.github.com` matches `api.github.com`.
    private func matchesDomain(_ domain: String, pattern: String) -> Bool {
        if domain == pattern {
            return true
        }

        if pattern.hasPrefix("*.") {
            let suffix = String(pattern.dropFirst(1))  // ".github.com"
            return domain.hasSuffix(suffix) || domain == String(pattern.dropFirst(2))
        }

        return false
    }
}
