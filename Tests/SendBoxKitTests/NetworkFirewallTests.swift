import Testing
@testable import SendBoxKit

struct NetworkFirewallTests {

    // MARK: - Helpers

    private func makeFirewall(
        defaultAction: PolicyConfiguration.CommandPolicyConfig.Action = .deny,
        allowedDomains: [String] = [],
        blockedDomains: [String] = [],
        allowDNS: Bool = true,
        maxConnections: Int? = nil
    ) -> NetworkFirewall {
        let config = PolicyConfiguration.NetworkPolicyConfig(
            defaultAction: defaultAction,
            allowedDomains: allowedDomains,
            blockedDomains: blockedDomains,
            allowDNS: allowDNS,
            maxConnections: maxConnections
        )
        return NetworkFirewall(config: config)
    }

    // MARK: - Domain matching

    @Test func testExactDomainAllowed() {
        let firewall = makeFirewall(allowedDomains: ["github.com"])
        #expect(firewall.isDomainAllowed("github.com"))
    }

    @Test func testExactDomainBlocked() {
        let firewall = makeFirewall(
            defaultAction: .allow,
            blockedDomains: ["evil.com"]
        )
        #expect(!firewall.isDomainAllowed("evil.com"))
    }

    @Test func testWildcardDomainMatch() {
        let firewall = makeFirewall(allowedDomains: ["*.github.com"])
        #expect(firewall.isDomainAllowed("api.github.com"))
    }

    @Test func testWildcardNoMatch() {
        let firewall = makeFirewall(allowedDomains: ["*.github.com"])
        #expect(!firewall.isDomainAllowed("evil.com"))
    }

    // MARK: - Default action

    @Test func testDefaultDenyBlocksUnlisted() {
        let firewall = makeFirewall(
            defaultAction: .deny,
            allowedDomains: ["github.com"]
        )
        #expect(!firewall.isDomainAllowed("example.com"))
    }

    @Test func testDefaultAllowPassesUnlisted() {
        let firewall = makeFirewall(defaultAction: .allow)
        #expect(firewall.isDomainAllowed("anything.com"))
    }

    // MARK: - Blocked domains priority

    @Test func testBlockedTakesPriority() {
        let firewall = makeFirewall(
            defaultAction: .allow,
            allowedDomains: ["evil.com"],
            blockedDomains: ["evil.com"]
        )
        #expect(!firewall.isDomainAllowed("evil.com"))
    }

    // MARK: - Firewall rule generation

    @Test func testGeneratesValidIptables() {
        let firewall = makeFirewall(
            defaultAction: .deny,
            allowedDomains: ["github.com"]
        )
        let rules = firewall.generateFirewallRules()
        #expect(rules.contains("iptables -F"))
        #expect(rules.contains("iptables -P OUTPUT  DROP"))
        #expect(rules.contains("github.com"))
    }

    @Test func testDNSRulesIncluded() {
        let firewall = makeFirewall(allowDNS: true)
        let rules = firewall.generateFirewallRules()
        #expect(rules.contains("--dport 53"))
        #expect(rules.contains("--sport 53"))
    }

    @Test func testRateLimitingRules() {
        let firewall = makeFirewall(maxConnections: 20)
        let rules = firewall.generateFirewallRules()
        #expect(rules.contains("--limit 20/minute"))
        #expect(rules.contains("--limit-burst 20"))
    }

    // MARK: - DNS config generation

    @Test func testDNSConfigFormat() {
        let firewall = makeFirewall(allowDNS: true)
        let dns = firewall.generateDNSConfig()
        #expect(dns.contains("nameserver 1.1.1.1"))
        #expect(dns.contains("nameserver 8.8.8.8"))

        let noDNS = makeFirewall(allowDNS: false)
        let dnsDisabled = noDNS.generateDNSConfig()
        #expect(dnsDisabled.contains("nameserver 127.0.0.1"))
        #expect(dnsDisabled.contains("DNS disabled by policy"))
    }

    // MARK: - Startup script

    @Test func testStartupScriptComplete() {
        let firewall = makeFirewall(
            defaultAction: .deny,
            allowedDomains: ["github.com"],
            allowDNS: true
        )
        let script = firewall.generateStartupScript()
        #expect(script.contains("#!/usr/bin/env bash"))
        #expect(script.contains("Configuring DNS"))
        #expect(script.contains("Applying firewall rules"))
        #expect(script.contains("Network setup complete"))
        #expect(script.contains("resolv.conf"))
    }

    // MARK: - Default policy preset

    @Test func testDefaultPolicyAllowsGitHub() {
        let firewall = NetworkFirewall(config: PolicyConfiguration.default.network)
        #expect(firewall.isDomainAllowed("github.com"))
        #expect(firewall.isDomainAllowed("api.github.com"))
    }

    @Test func testDefaultPolicyAllowsNpm() {
        let firewall = NetworkFirewall(config: PolicyConfiguration.default.network)
        #expect(firewall.isDomainAllowed("registry.npmjs.org"))
    }

    // MARK: - Edge cases

    @Test func testSubdomainMatching() {
        let firewall = makeFirewall(allowedDomains: ["*.github.com"])
        #expect(firewall.isDomainAllowed("api.github.com"))
        #expect(firewall.isDomainAllowed("raw.github.com"))
        // The bare domain should also match wildcard *.github.com
        #expect(firewall.isDomainAllowed("github.com"))
    }

    @Test func testCaseInsensitivity() {
        let firewall = makeFirewall(allowedDomains: ["GitHub.com"])
        #expect(firewall.isDomainAllowed("github.com"))
        #expect(firewall.isDomainAllowed("GITHUB.COM"))
    }
}
