//! Authenticated production runtime policy for guest egress enforcement.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sendbox_core::SessionId;
use sendbox_policy::{
    Action, DEFAULT_MCP_HTTP_GATEWAY_PORT, DnsPolicy, McpHttpOrigin, NetworkPolicy, ToolCallPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::policy::{PolicyEngine, PolicyError};

pub const RUNTIME_POLICY_SCHEMA_VERSION: u32 = 3;
pub const DEFAULT_CONNECT_PORT: u16 = 15_080;
pub const DEFAULT_DNS_PORT: u16 = 53;
pub const DEFAULT_REGISTRY_PROXY_PORT: u16 = 14_873;
pub const DEFAULT_TRUSTED_REGISTRY_PORT: u16 = 15_081;
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
const INSTANCE_ID_HEX_BYTES: usize = 12;
const TABLE_PREFIX: &str = "sbxeg_";
const NO_PROXY_VALUE: &str = "localhost,127.0.0.1,::1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicyDocument {
    pub schema_version: u32,
    pub instance_id: String,
    pub table_name: String,
    pub broker_mark: u32,
    pub connect_port: u16,
    pub dns_port: Option<u16>,
    pub mcp_gateway_port: Option<u16>,
    pub reserved_mcp_origins: Vec<McpHttpOrigin>,
    pub deny_direct_ip: bool,
    pub network_policy: NetworkPolicy,
    #[serde(default)]
    pub registry: Option<RegistryEgressPolicy>,
    pub proxy_environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEgressPolicy {
    pub proxy_port: u16,
    pub trusted_upstream_port: u16,
    pub upstream_network_policy: NetworkPolicy,
}

#[derive(Debug, Error)]
pub enum RuntimePolicyError {
    #[error("unsupported egress runtime policy schema version {0}")]
    UnsupportedSchema(u32),
    #[error("egress instance ID must be exactly 24 lowercase hexadecimal characters")]
    InvalidInstanceId,
    #[error("egress table name must be exactly sbxeg_<instance-id>")]
    InvalidTableName,
    #[error("egress broker mark must be non-zero")]
    ZeroMark,
    #[error("egress CONNECT port must be non-zero and distinct from the DNS port")]
    InvalidConnectPort,
    #[error("DNS-enabled egress requires port 53; DNS-disabled egress must omit the DNS port")]
    InvalidDnsPort,
    #[error("remote MCP egress state does not match the signed reserved origins")]
    InvalidRemoteMcp,
    #[error("egress loopback service ports must be non-zero and pairwise distinct")]
    InvalidLoopbackPorts,
    #[error("egress proxy environment does not match the signed endpoints")]
    InvalidProxyEnvironment,
    #[error("invalid network policy: {0}")]
    InvalidNetworkPolicy(#[from] PolicyError),
}

impl RuntimePolicyDocument {
    #[must_use]
    pub fn for_session(session_id: SessionId, network_policy: NetworkPolicy) -> Self {
        Self::for_session_with_mcp(session_id, network_policy, None)
            .expect("an absent MCP policy is always valid")
    }

    pub fn for_session_with_mcp(
        session_id: SessionId,
        network_policy: NetworkPolicy,
        tool_policy: Option<&ToolCallPolicy>,
    ) -> Result<Self, RuntimePolicyError> {
        let digest = Sha256::digest(session_id.as_bytes());
        let instance_id = digest[..INSTANCE_ID_HEX_BYTES]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let table_name = format!("{TABLE_PREFIX}{instance_id}");
        let broker_mark = u32::from_be_bytes(
            digest[INSTANCE_ID_HEX_BYTES..INSTANCE_ID_HEX_BYTES + 4]
                .try_into()
                .expect("fixed SHA-256 slice"),
        ) | 1;
        let connect_port = DEFAULT_CONNECT_PORT;
        let dns_port = network_policy.allow_dns.then_some(DEFAULT_DNS_PORT);
        let reserved_mcp_origins = tool_policy
            .map(ToolCallPolicy::remote_origins)
            .transpose()
            .map_err(|_| RuntimePolicyError::InvalidRemoteMcp)?
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        let remote_mcp_active = !reserved_mcp_origins.is_empty();
        Ok(Self {
            schema_version: RUNTIME_POLICY_SCHEMA_VERSION,
            instance_id,
            table_name,
            broker_mark,
            connect_port,
            dns_port,
            mcp_gateway_port: remote_mcp_active.then_some(DEFAULT_MCP_HTTP_GATEWAY_PORT),
            reserved_mcp_origins,
            deny_direct_ip: remote_mcp_active,
            network_policy,
            registry: None,
            proxy_environment: proxy_environment(connect_port, None),
        })
    }

    #[must_use]
    pub fn with_registry(
        mut self,
        proxy_port: u16,
        trusted_upstream_port: u16,
        upstream_network_policy: NetworkPolicy,
    ) -> Self {
        self.registry = Some(RegistryEgressPolicy {
            proxy_port,
            trusted_upstream_port,
            upstream_network_policy,
        });
        self.proxy_environment = proxy_environment(self.connect_port, Some(proxy_port));
        self
    }

    pub fn validate(&self) -> Result<(), RuntimePolicyError> {
        if self.schema_version != RUNTIME_POLICY_SCHEMA_VERSION {
            return Err(RuntimePolicyError::UnsupportedSchema(self.schema_version));
        }
        if self.instance_id.len() != INSTANCE_ID_HEX_BYTES * 2
            || !self
                .instance_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RuntimePolicyError::InvalidInstanceId);
        }
        if self.table_name != format!("{TABLE_PREFIX}{}", self.instance_id) {
            return Err(RuntimePolicyError::InvalidTableName);
        }
        if self.broker_mark == 0 {
            return Err(RuntimePolicyError::ZeroMark);
        }
        if self.connect_port == 0 || self.dns_port == Some(self.connect_port) {
            return Err(RuntimePolicyError::InvalidConnectPort);
        }
        if self.dns_port != self.network_policy.allow_dns.then_some(DEFAULT_DNS_PORT) {
            return Err(RuntimePolicyError::InvalidDnsPort);
        }
        let remote_mcp_active = !self.reserved_mcp_origins.is_empty();
        if self.mcp_gateway_port != remote_mcp_active.then_some(DEFAULT_MCP_HTTP_GATEWAY_PORT)
            || self.deny_direct_ip != remote_mcp_active
        {
            return Err(RuntimePolicyError::InvalidRemoteMcp);
        }
        let origins = self
            .reserved_mcp_origins
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if origins.len() != self.reserved_mcp_origins.len()
            || origins.iter().any(|origin| {
                origin.port == 0
                    || McpHttpOrigin::from_endpoint(&format!(
                        "https://{}:{}/",
                        if origin.host.contains(':') {
                            format!("[{}]", origin.host)
                        } else {
                            origin.host.clone()
                        },
                        origin.port
                    ))
                    .map(|parsed| parsed != *origin)
                    .unwrap_or(true)
            })
        {
            return Err(RuntimePolicyError::InvalidRemoteMcp);
        }

        let mut loopback_ports = vec![self.connect_port];
        loopback_ports.extend(self.dns_port);
        loopback_ports.extend(self.mcp_gateway_port);
        if let Some(registry) = &self.registry {
            loopback_ports.extend([registry.proxy_port, registry.trusted_upstream_port]);
            PolicyEngine::compile(&registry.upstream_network_policy)?;
        }
        loopback_ports.sort_unstable();
        if loopback_ports.first() == Some(&0)
            || loopback_ports.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(RuntimePolicyError::InvalidLoopbackPorts);
        }

        if self.proxy_environment
            != proxy_environment(
                self.connect_port,
                self.registry.as_ref().map(|registry| registry.proxy_port),
            )
        {
            return Err(RuntimePolicyError::InvalidProxyEnvironment);
        }
        PolicyEngine::compile(&self.network_policy)?;
        Ok(())
    }

    #[must_use]
    pub fn execution_cgroup_parent(&self, cgroup_root: &Path) -> PathBuf {
        cgroup_root
            .join("sendbox")
            .join(&self.instance_id)
            .join("agent")
    }
}

#[must_use]
pub fn requires_enforcement(network: &NetworkPolicy) -> bool {
    network.default_action != Action::Allow
        || !network.allowed_domains.is_empty()
        || !network.blocked_domains.is_empty()
        || !network.allowed_networks.is_empty()
        || !network.blocked_networks.is_empty()
        || !network.allowed_ports.is_empty()
        || !network.allow_dns
        || network.max_connections.is_some()
        || network.dns != DnsPolicy::default()
}

#[must_use]
pub fn proxy_environment(
    connect_port: u16,
    registry_proxy_port: Option<u16>,
) -> BTreeMap<String, String> {
    let proxy = format!("socks5h://127.0.0.1:{connect_port}");
    let mut environment = BTreeMap::from([
        ("ALL_PROXY".to_owned(), proxy.clone()),
        ("NO_PROXY".to_owned(), NO_PROXY_VALUE.to_owned()),
        ("all_proxy".to_owned(), proxy),
        ("no_proxy".to_owned(), NO_PROXY_VALUE.to_owned()),
    ]);
    if let Some(port) = registry_proxy_port {
        let registry = format!("http://127.0.0.1:{port}/");
        environment.extend([
            ("NPM_CONFIG_IGNORE_SCRIPTS".to_owned(), "true".to_owned()),
            ("NPM_CONFIG_REGISTRY".to_owned(), registry.clone()),
            ("npm_config_ignore_scripts".to_owned(), "true".to_owned()),
            ("npm_config_registry".to_owned(), registry),
        ]);
    }
    environment
}

#[cfg(test)]
mod tests {
    use sendbox_policy::{
        Action, McpHttpPolicy, McpServerPolicy, NetworkPolicy, ServerToolPolicy, ToolCallPolicy,
    };

    use super::*;

    fn network_policy() -> NetworkPolicy {
        NetworkPolicy {
            default_action: Action::Deny,
            allowed_domains: vec!["example.com".to_owned()],
            blocked_domains: Vec::new(),
            allow_dns: true,
            max_connections: Some(10),
            allowed_networks: Vec::new(),
            blocked_networks: Vec::new(),
            allowed_ports: Vec::new(),
            dns: DnsPolicy::default(),
        }
    }

    #[test]
    fn session_policy_is_short_stable_and_valid() {
        let first =
            RuntimePolicyDocument::for_session(SessionId::from_bytes([7; 16]), network_policy());
        let second =
            RuntimePolicyDocument::for_session(SessionId::from_bytes([7; 16]), network_policy());
        assert_eq!(first, second);
        assert_eq!(first.instance_id.len(), 24);
        assert_eq!(first.table_name.len(), 30);
        assert_ne!(first.broker_mark, 0);
        assert!(first.registry.is_none());
        assert_eq!(
            first.execution_cgroup_parent(Path::new(DEFAULT_CGROUP_ROOT)),
            Path::new(DEFAULT_CGROUP_ROOT)
                .join("sendbox")
                .join(&first.instance_id)
                .join("agent")
        );
        first.validate().expect("valid policy");
    }

    #[test]
    fn registry_policy_adds_only_local_npm_environment() {
        let original = network_policy();
        let policy =
            RuntimePolicyDocument::for_session(SessionId::from_bytes([9; 16]), original.clone())
                .with_registry(
                    DEFAULT_REGISTRY_PROXY_PORT,
                    DEFAULT_TRUSTED_REGISTRY_PORT,
                    original,
                );
        policy.validate().unwrap();
        assert_eq!(
            policy.proxy_environment["npm_config_registry"],
            "http://127.0.0.1:14873/"
        );
        assert_eq!(
            policy.proxy_environment["NPM_CONFIG_IGNORE_SCRIPTS"],
            "true"
        );
    }

    #[test]
    fn remote_mcp_and_registry_use_distinct_fail_closed_ports() {
        let tool_policy = ToolCallPolicy {
            servers: BTreeMap::from([(
                "remote".to_owned(),
                McpServerPolicy::StreamableHttp {
                    url: "https://mcp.example.com/mcp".to_owned(),
                    tools: ServerToolPolicy::default(),
                    http: McpHttpPolicy::default(),
                },
            )]),
            ..ToolCallPolicy::default()
        };
        let original = network_policy();
        let policy = RuntimePolicyDocument::for_session_with_mcp(
            SessionId::from_bytes([10; 16]),
            original.clone(),
            Some(&tool_policy),
        )
        .unwrap()
        .with_registry(
            DEFAULT_REGISTRY_PROXY_PORT,
            DEFAULT_TRUSTED_REGISTRY_PORT,
            original,
        );

        policy.validate().unwrap();
        assert_eq!(policy.mcp_gateway_port, Some(DEFAULT_MCP_HTTP_GATEWAY_PORT));
        assert_eq!(
            policy.registry.as_ref().map(|registry| registry.proxy_port),
            Some(DEFAULT_REGISTRY_PROXY_PORT)
        );
        assert_eq!(
            policy
                .registry
                .as_ref()
                .map(|registry| registry.trusted_upstream_port),
            Some(DEFAULT_TRUSTED_REGISTRY_PORT)
        );

        let mut colliding = policy;
        colliding
            .registry
            .as_mut()
            .expect("registry policy")
            .trusted_upstream_port = DEFAULT_MCP_HTTP_GATEWAY_PORT;
        assert!(matches!(
            colliding.validate(),
            Err(RuntimePolicyError::InvalidLoopbackPorts)
        ));
    }

    #[test]
    fn policy_rejects_proxy_and_dns_drift() {
        let mut policy =
            RuntimePolicyDocument::for_session(SessionId::from_bytes([8; 16]), network_policy());
        policy
            .proxy_environment
            .insert("ALL_PROXY".to_owned(), "socks5h://127.0.0.1:1".to_owned());
        assert!(matches!(
            policy.validate(),
            Err(RuntimePolicyError::InvalidProxyEnvironment)
        ));

        let mut policy =
            RuntimePolicyDocument::for_session(SessionId::from_bytes([8; 16]), network_policy());
        policy.dns_port = None;
        assert!(matches!(
            policy.validate(),
            Err(RuntimePolicyError::InvalidDnsPort)
        ));
    }

    #[test]
    fn enforcement_detection_matches_permissive_networks() {
        let mut network = network_policy();
        assert!(requires_enforcement(&network));
        network.default_action = Action::Allow;
        network.allowed_domains.clear();
        network.max_connections = None;
        assert!(!requires_enforcement(&network));
    }
}
