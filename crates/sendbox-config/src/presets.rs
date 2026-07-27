use sendbox_policy::{
    Action, BoundaryPolicy, CommandPolicy, NetworkPolicy, PolicyConfiguration, SyscallPolicy,
    ToolCallPolicy,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyPreset {
    Default,
    Permissive,
    Strict,
}

impl PolicyPreset {
    #[must_use]
    pub fn configuration(self) -> PolicyConfiguration {
        match self {
            Self::Default => default_policy(),
            Self::Permissive => permissive_policy(),
            Self::Strict => strict_policy(),
        }
    }
}

fn default_policy() -> PolicyConfiguration {
    PolicyConfiguration {
        commands: CommandPolicy {
            default_action: Action::Deny,
            allowlist: strings(&[
                "git",
                "npm",
                "npx",
                "yarn",
                "pnpm",
                "pip",
                "pip3",
                "python",
                "python3",
                "node",
                "make",
                "cmake",
                "cargo",
                "go",
                "rustc",
                "gcc",
                "g++",
                "curl",
                "cat",
                "ls",
                "find",
                "grep",
                "sed",
                "awk",
                "head",
                "tail",
                "echo",
                "env",
                "which",
                "whoami",
                "mkdir",
                "cp",
                "mv",
                "touch",
                "rm",
                "swift",
                "swiftc",
                "xcodebuild",
            ]),
            denylist: Vec::new(),
            log_blocked: true,
        },
        network: network(
            Action::Deny,
            &[
                "github.com",
                "*.github.com",
                "*.githubusercontent.com",
                "registry.npmjs.org",
                "pypi.org",
                "*.pypi.org",
                "rubygems.org",
                "crates.io",
                "proxy.golang.org",
                "*.docker.io",
                "*.docker.com",
            ],
            None,
        ),
        boundaries: BoundaryPolicy::default(),
    }
}

fn permissive_policy() -> PolicyConfiguration {
    PolicyConfiguration {
        commands: CommandPolicy {
            default_action: Action::Allow,
            allowlist: Vec::new(),
            denylist: strings(&[
                "sudo",
                "su",
                "mount",
                "umount",
                "fdisk",
                "mkfs",
                "dd",
                "shutdown",
                "reboot",
                "halt",
                "poweroff",
                "systemctl",
                "service",
                "iptables",
                "ip6tables",
                "nft",
                "passwd",
                "useradd",
                "userdel",
                "usermod",
                "groupadd",
                "groupdel",
                "chown",
                "chmod 777",
            ]),
            log_blocked: true,
        },
        network: network(Action::Allow, &[], None),
        boundaries: BoundaryPolicy {
            tool_calls: ToolCallPolicy {
                default_action: Action::Allow,
                ..ToolCallPolicy::default()
            },
            ..BoundaryPolicy::default()
        },
    }
}

fn strict_policy() -> PolicyConfiguration {
    PolicyConfiguration {
        commands: CommandPolicy {
            default_action: Action::Deny,
            allowlist: strings(&[
                "cat",
                "ls",
                "find",
                "grep",
                "head",
                "tail",
                "echo",
                "env",
                "which",
                "whoami",
                "wc",
                "sort",
                "uniq",
                "diff",
                "git status",
                "git log",
                "git diff",
                "git show",
            ]),
            denylist: Vec::new(),
            log_blocked: true,
        },
        network: network(Action::Deny, &["github.com", "*.github.com"], Some(10)),
        boundaries: BoundaryPolicy {
            tool_calls: ToolCallPolicy {
                max_frame_bytes: 262_144,
                ..ToolCallPolicy::default()
            },
            syscalls: SyscallPolicy::default(),
            ..BoundaryPolicy::default()
        },
    }
}

fn network(
    default_action: Action,
    allowed_domains: &[&str],
    max_connections: Option<i64>,
) -> NetworkPolicy {
    NetworkPolicy {
        default_action,
        allowed_domains: strings(allowed_domains),
        blocked_domains: Vec::new(),
        allow_dns: true,
        max_connections,
        allowed_networks: Vec::new(),
        blocked_networks: Vec::new(),
        allowed_ports: Vec::new(),
        dns: sendbox_policy::DnsPolicy::default(),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
