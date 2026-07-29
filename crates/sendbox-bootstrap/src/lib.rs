#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use sendbox_core::{BoundaryPlanDigest, SessionId};
use sendbox_egress::runtime::{
    DEFAULT_CGROUP_ROOT, RuntimePolicyDocument as EgressRuntimePolicyDocument,
};
use sendbox_git::GuardPolicyDocument;
use sendbox_mcp::runtime::RuntimePolicyDocument;
use sendbox_policy::{CommandPolicy, PackageSupplyChainPolicy};
use sendbox_protocol::BootstrapSecret;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const BOOTSTRAP_SCHEMA_VERSION: u32 = 4;
pub const MAX_BOOTSTRAP_BYTES: usize = 2 * 1024 * 1024;
const MAX_GATEWAY_CREDENTIALS: usize = 64;
const MAX_GATEWAY_CREDENTIAL_BYTES: usize = 64 * 1024;
pub const MAX_REGISTRY_CREDENTIALS: usize = 16;
pub const MAX_REGISTRY_CREDENTIAL_BYTES: usize = 16 * 1024;
pub const MAX_REGISTRY_CREDENTIAL_TOTAL_BYTES: usize = 32 * 1024;
pub const DEFAULT_REGISTRY_UID: u32 = 65_532;
pub const DEFAULT_REGISTRY_GID: u32 = 65_532;
pub const DEFAULT_REGISTRY_CACHE_ROOT: &str = "/var/lib/sendbox/package-cache";
pub const REQUIRED_RUNTIME_CONTROLS: [ControlKind; 3] = [
    ControlKind::PrivilegeDrop,
    ControlKind::Capabilities,
    ControlKind::Seccomp,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    PrivilegeDrop,
    Capabilities,
    Seccomp,
}

impl ControlKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PrivilegeDrop => "privilege_drop",
            Self::Capabilities => "capabilities",
            Self::Seccomp => "seccomp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceId {
    Exec,
    Mcp,
    Dns,
    Egress,
    Audit,
    Bpf,
    SafeOutputs,
}

impl ServiceId {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Mcp => "mcp",
            Self::Dns => "dns",
            Self::Egress => "egress",
            Self::Audit => "audit",
            Self::Bpf => "bpf",
            Self::SafeOutputs => "safe_outputs",
        }
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPolicy {
    #[serde(default)]
    pub max_restarts: u32,
    #[serde(default = "default_backoff_ms")]
    pub backoff_ms: u64,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 0,
            backoff_ms: default_backoff_ms(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HealthCheck {
    ProcessAlive {
        #[serde(default = "default_health_delay_ms")]
        delay_ms: u64,
    },
    UnixSocket {
        path: PathBuf,
        #[serde(default = "default_health_timeout_ms")]
        timeout_ms: u64,
    },
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::ProcessAlive {
            delay_ms: default_health_delay_ms(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    pub id: ServiceId,
    #[serde(default)]
    pub dependencies: Vec<ServiceId>,
    pub executable: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_true")]
    pub mandatory: bool,
    #[serde(default)]
    pub restart: RestartPolicy,
    #[serde(default)]
    pub health: HealthCheck,
    #[serde(default = "default_grace_ms")]
    pub graceful_shutdown_ms: u64,
    #[serde(default = "default_kill_ms")]
    pub forced_shutdown_ms: u64,
    #[serde(default = "default_log_bytes")]
    pub max_log_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBrokerConfiguration {
    pub runtime_parent: PathBuf,
    pub socket_path: PathBuf,
    pub launcher_path: PathBuf,
    pub cgroup_parent: PathBuf,
    pub workspace_root: PathBuf,
    pub system_root: PathBuf,
    pub workload_uid: u32,
    pub workload_gid: u32,
    pub command_policy: CommandPolicy,
    pub git_guard_policy: Option<GuardPolicyDocument>,
    pub mcp_policy: Option<RuntimePolicyDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBrokerBootstrap {
    pub authentication: [u8; 32],
    pub runtime_parent: PathBuf,
    pub socket_path: PathBuf,
    pub launcher_path: PathBuf,
    pub cgroup_parent: PathBuf,
    pub workspace_root: PathBuf,
    pub system_root: PathBuf,
    pub workload_uid: u32,
    pub workload_gid: u32,
    pub command_policy: CommandPolicy,
    #[serde(default)]
    pub git_guard_policy: Option<GuardPolicyDocument>,
    #[serde(default)]
    pub mcp_policy: Option<RuntimePolicyDocument>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayCredential {
    pub name: String,
    value: Vec<u8>,
}

impl GatewayCredential {
    pub fn new(name: impl Into<String>, value: Vec<u8>) -> Result<Self, BootstrapError> {
        let credential = Self {
            name: name.into(),
            value,
        };
        validate_gateway_credential(&credential)?;
        Ok(credential)
    }

    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for GatewayCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayCredential")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for GatewayCredential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RegistryCredential {
    pub secret_reference: String,
    token: Zeroizing<Vec<u8>>,
}

impl RegistryCredential {
    pub fn new(
        secret_reference: impl Into<String>,
        token: Vec<u8>,
    ) -> Result<Self, BootstrapError> {
        let credential = Self {
            secret_reference: secret_reference.into(),
            token: Zeroizing::new(token),
        };
        validate_registry_credential(&credential)?;
        Ok(credential)
    }

    #[must_use]
    pub fn expose_to_registry_proxy(&self) -> &[u8] {
        self.token.as_slice()
    }
}

impl fmt::Debug for RegistryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryCredential")
            .field("secret_reference", &self.secret_reference)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl Serialize for RegistryCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RegistryCredential", 2)?;
        state.serialize_field("secret_reference", &self.secret_reference)?;
        state.serialize_field("token", self.token.as_slice())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RegistryCredential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            secret_reference: String,
            token: Vec<u8>,
        }

        let wire = Wire::deserialize(deserializer)?;
        RegistryCredential::new(wire.secret_reference, wire.token).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryProxyConfiguration {
    pub policy: PackageSupplyChainPolicy,
    pub proxy_port: u16,
    pub trusted_upstream_port: u16,
    pub cache_root: PathBuf,
    pub report_path: PathBuf,
    pub proxy_uid: u32,
    pub proxy_gid: u32,
    #[serde(default)]
    pub credentials: Vec<RegistryCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapDocumentConfiguration {
    pub session_id: SessionId,
    pub boundary_plan_digest: BoundaryPlanDigest,
    pub host_version: String,
    pub trust_root_id: String,
    pub manifest_path: PathBuf,
    pub minimum_release_sequence: u64,
    pub required_controls: Vec<ControlKind>,
    pub required_services: Vec<ServiceId>,
    pub services: Vec<ServiceSpec>,
    pub execution_broker: Option<ExecutionBrokerConfiguration>,
    pub egress_policy: Option<EgressRuntimePolicyDocument>,
    pub gateway_credentials: Vec<GatewayCredential>,
    pub registry_proxy: Option<RegistryProxyConfiguration>,
}

pub struct BootstrapDocument {
    pub session_id: SessionId,
    pub boundary_plan_digest: BoundaryPlanDigest,
    pub bootstrap_nonce: [u8; 32],
    pub bootstrap_secret: BootstrapSecret,
    pub host_version: String,
    pub trust_root_id: String,
    pub manifest_path: PathBuf,
    pub minimum_release_sequence: u64,
    pub required_controls: Vec<ControlKind>,
    pub required_services: Vec<ServiceId>,
    pub services: Vec<ServiceSpec>,
    pub execution_broker: Option<ExecutionBrokerBootstrap>,
    pub egress_policy: Option<EgressRuntimePolicyDocument>,
    pub gateway_credentials: Vec<GatewayCredential>,
    pub registry_proxy: Option<RegistryProxyConfiguration>,
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("invalid guest bootstrap: {0}")]
    Invalid(String),
    #[error("failed to generate guest bootstrap entropy: {0}")]
    Entropy(String),
    #[error("failed to encode guest bootstrap: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("failed to decode guest bootstrap: {0}")]
    Decode(#[source] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapWire {
    schema_version: u32,
    session_id: SessionId,
    boundary_plan_digest: BoundaryPlanDigest,
    bootstrap_nonce: [u8; 32],
    bootstrap_secret: SecretBytes,
    host_version: String,
    trust_root_id: String,
    manifest_path: PathBuf,
    minimum_release_sequence: u64,
    #[serde(default)]
    required_controls: Vec<ControlKind>,
    #[serde(default)]
    required_services: Vec<ServiceId>,
    #[serde(default)]
    services: Vec<ServiceSpec>,
    #[serde(default)]
    execution_broker: Option<ExecutionBrokerBootstrap>,
    #[serde(default)]
    egress_policy: Option<EgressRuntimePolicyDocument>,
    #[serde(default)]
    gateway_credentials: Vec<GatewayCredential>,
    #[serde(default)]
    registry_proxy: Option<RegistryProxyConfiguration>,
}

struct SecretBytes(Zeroizing<[u8; 32]>);

impl SecretBytes {
    fn from_slice(bytes: &[u8]) -> Result<Self, BootstrapError> {
        let secret = <[u8; 32]>::try_from(bytes).map_err(|_| {
            BootstrapError::Invalid("bootstrap secret must contain exactly 32 bytes".to_owned())
        })?;
        Ok(Self(Zeroizing::new(secret)))
    }
}

impl Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretVisitor;

        impl<'de> Visitor<'de> for SecretVisitor {
            type Value = SecretBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 32 bootstrap-secret bytes")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Zeroizing::new([0_u8; 32]);
                for index in 0..32 {
                    bytes[index] = sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                if sequence.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(33, &self));
                }
                Ok(SecretBytes(bytes))
            }
        }

        deserializer.deserialize_seq(SecretVisitor)
    }
}

pub fn encode_bootstrap_document(
    configuration: BootstrapDocumentConfiguration,
    bootstrap_secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BootstrapError> {
    validate_configuration(&configuration)?;
    let mut bootstrap_nonce = [0_u8; 32];
    fill_entropy(&mut bootstrap_nonce)?;
    let execution_broker = configuration
        .execution_broker
        .map(|configuration| {
            let mut authentication = [0_u8; 32];
            fill_entropy(&mut authentication)?;
            Ok(ExecutionBrokerBootstrap {
                authentication,
                runtime_parent: configuration.runtime_parent,
                socket_path: configuration.socket_path,
                launcher_path: configuration.launcher_path,
                cgroup_parent: configuration.cgroup_parent,
                workspace_root: configuration.workspace_root,
                system_root: configuration.system_root,
                workload_uid: configuration.workload_uid,
                workload_gid: configuration.workload_gid,
                command_policy: configuration.command_policy,
                git_guard_policy: configuration.git_guard_policy,
                mcp_policy: configuration.mcp_policy,
            })
        })
        .transpose()?;
    let wire = BootstrapWire {
        schema_version: BOOTSTRAP_SCHEMA_VERSION,
        session_id: configuration.session_id,
        boundary_plan_digest: configuration.boundary_plan_digest,
        bootstrap_nonce,
        bootstrap_secret: SecretBytes::from_slice(bootstrap_secret)?,
        host_version: configuration.host_version,
        trust_root_id: configuration.trust_root_id,
        manifest_path: configuration.manifest_path,
        minimum_release_sequence: configuration.minimum_release_sequence,
        required_controls: configuration.required_controls,
        required_services: configuration.required_services,
        services: configuration.services,
        execution_broker,
        egress_policy: configuration.egress_policy,
        gateway_credentials: configuration.gateway_credentials,
        registry_proxy: configuration.registry_proxy,
    };
    let encoded = serde_json::to_vec(&wire).map_err(BootstrapError::Encode)?;
    if encoded.len() > MAX_BOOTSTRAP_BYTES {
        return Err(BootstrapError::Invalid(format!(
            "encoded bootstrap exceeds {MAX_BOOTSTRAP_BYTES} bytes"
        )));
    }
    Ok(Zeroizing::new(encoded))
}

pub fn decode_bootstrap_document(bytes: &[u8]) -> Result<BootstrapDocument, BootstrapError> {
    if bytes.len() > MAX_BOOTSTRAP_BYTES {
        return Err(BootstrapError::Invalid(format!(
            "bootstrap exceeds {MAX_BOOTSTRAP_BYTES} bytes"
        )));
    }
    let wire: BootstrapWire = serde_json::from_slice(bytes).map_err(BootstrapError::Decode)?;
    validate_wire(wire)
}

fn validate_configuration(
    configuration: &BootstrapDocumentConfiguration,
) -> Result<(), BootstrapError> {
    validate_common(
        &configuration.host_version,
        &configuration.trust_root_id,
        &configuration.manifest_path,
        configuration.minimum_release_sequence,
    )?;
    if let Some(broker) = &configuration.execution_broker {
        validate_broker(
            broker.workload_uid,
            broker.workload_gid,
            &broker.runtime_parent,
            &broker.socket_path,
            &broker.launcher_path,
            &broker.cgroup_parent,
            &broker.workspace_root,
            &broker.system_root,
            broker.git_guard_policy.as_ref(),
            broker.mcp_policy.as_ref(),
        )?;
    }
    validate_egress(
        configuration.session_id,
        configuration.egress_policy.as_ref(),
        configuration
            .execution_broker
            .as_ref()
            .and_then(|broker| broker.mcp_policy.as_ref()),
        configuration
            .execution_broker
            .as_ref()
            .map(|broker| &broker.cgroup_parent),
    )?;
    validate_gateway_credentials(
        &configuration.gateway_credentials,
        configuration
            .execution_broker
            .as_ref()
            .and_then(|broker| broker.mcp_policy.as_ref()),
    )?;
    if configuration
        .execution_broker
        .as_ref()
        .and_then(|broker| broker.mcp_policy.as_ref())
        .is_some_and(|policy| policy.tool_policy.has_remote_servers())
        && configuration.egress_policy.is_none()
    {
        return Err(BootstrapError::Invalid(
            "remote MCP requires authenticated egress enforcement".to_owned(),
        ));
    }
    validate_registry_proxy(
        configuration.registry_proxy.as_ref(),
        configuration.egress_policy.as_ref(),
        configuration
            .execution_broker
            .as_ref()
            .map(|broker| (broker.workload_uid, broker.workload_gid)),
    )?;
    Ok(())
}

fn validate_wire(wire: BootstrapWire) -> Result<BootstrapDocument, BootstrapError> {
    if wire.schema_version != BOOTSTRAP_SCHEMA_VERSION {
        return Err(BootstrapError::Invalid(format!(
            "unsupported schema version {}",
            wire.schema_version
        )));
    }
    if wire.bootstrap_nonce.iter().all(|byte| *byte == 0) {
        return Err(BootstrapError::Invalid(
            "bootstrap nonce must not be all zero".to_owned(),
        ));
    }
    validate_common(
        &wire.host_version,
        &wire.trust_root_id,
        &wire.manifest_path,
        wire.minimum_release_sequence,
    )?;
    if let Some(broker) = &wire.execution_broker {
        validate_broker(
            broker.workload_uid,
            broker.workload_gid,
            &broker.runtime_parent,
            &broker.socket_path,
            &broker.launcher_path,
            &broker.cgroup_parent,
            &broker.workspace_root,
            &broker.system_root,
            broker.git_guard_policy.as_ref(),
            broker.mcp_policy.as_ref(),
        )?;
    }
    validate_egress(
        wire.session_id,
        wire.egress_policy.as_ref(),
        wire.execution_broker
            .as_ref()
            .and_then(|broker| broker.mcp_policy.as_ref()),
        wire.execution_broker
            .as_ref()
            .map(|broker| &broker.cgroup_parent),
    )?;
    validate_gateway_credentials(
        &wire.gateway_credentials,
        wire.execution_broker
            .as_ref()
            .and_then(|broker| broker.mcp_policy.as_ref()),
    )?;
    if wire
        .execution_broker
        .as_ref()
        .and_then(|broker| broker.mcp_policy.as_ref())
        .is_some_and(|policy| policy.tool_policy.has_remote_servers())
        && wire.egress_policy.is_none()
    {
        return Err(BootstrapError::Invalid(
            "remote MCP requires authenticated egress enforcement".to_owned(),
        ));
    }
    validate_registry_proxy(
        wire.registry_proxy.as_ref(),
        wire.egress_policy.as_ref(),
        wire.execution_broker
            .as_ref()
            .map(|broker| (broker.workload_uid, broker.workload_gid)),
    )?;
    let bootstrap_secret = BootstrapSecret::new(wire.bootstrap_secret.0.as_ref().to_vec())
        .map_err(|_| BootstrapError::Invalid("bootstrap secret is invalid".to_owned()))?;
    Ok(BootstrapDocument {
        session_id: wire.session_id,
        boundary_plan_digest: wire.boundary_plan_digest,
        bootstrap_nonce: wire.bootstrap_nonce,
        bootstrap_secret,
        host_version: wire.host_version,
        trust_root_id: wire.trust_root_id,
        manifest_path: wire.manifest_path,
        minimum_release_sequence: wire.minimum_release_sequence,
        required_controls: wire.required_controls,
        required_services: wire.required_services,
        services: wire.services,
        execution_broker: wire.execution_broker,
        egress_policy: wire.egress_policy,
        gateway_credentials: wire.gateway_credentials,
        registry_proxy: wire.registry_proxy,
    })
}

fn validate_registry_proxy(
    registry: Option<&RegistryProxyConfiguration>,
    egress: Option<&EgressRuntimePolicyDocument>,
    workload: Option<(u32, u32)>,
) -> Result<(), BootstrapError> {
    let Some(registry) = registry else {
        return Ok(());
    };
    if !registry.policy.enabled {
        return Err(BootstrapError::Invalid(
            "registry proxy bootstrap requires enabled package policy".to_owned(),
        ));
    }
    registry
        .policy
        .validate()
        .map_err(|error| BootstrapError::Invalid(error.to_string()))?;
    let egress = egress.ok_or_else(|| {
        BootstrapError::Invalid("registry proxy requires authenticated egress policy".to_owned())
    })?;
    let registry_egress = egress.registry.as_ref().ok_or_else(|| {
        BootstrapError::Invalid("registry proxy requires registry egress isolation".to_owned())
    })?;
    if registry.proxy_port == 0
        || registry.trusted_upstream_port == 0
        || registry.proxy_port == registry.trusted_upstream_port
        || registry.proxy_port == egress.connect_port
        || registry.trusted_upstream_port == egress.connect_port
        || egress.dns_port.is_some_and(|port| {
            port == registry.proxy_port || port == registry.trusted_upstream_port
        })
    {
        return Err(BootstrapError::Invalid(
            "registry proxy ports must be non-zero and distinct from egress ports".to_owned(),
        ));
    }
    if registry.proxy_port != registry_egress.proxy_port
        || registry.trusted_upstream_port != registry_egress.trusted_upstream_port
    {
        return Err(BootstrapError::Invalid(
            "registry proxy ports do not match authenticated egress policy".to_owned(),
        ));
    }
    if registry.proxy_uid == 0
        || registry.proxy_gid == 0
        || workload.is_some_and(|workload| workload == (registry.proxy_uid, registry.proxy_gid))
    {
        return Err(BootstrapError::Invalid(
            "registry proxy requires a dedicated non-root identity".to_owned(),
        ));
    }
    for (name, path) in [
        ("cache root", &registry.cache_root),
        ("report", &registry.report_path),
    ] {
        if !path.is_absolute() {
            return Err(BootstrapError::Invalid(format!(
                "registry proxy {name} path must be absolute"
            )));
        }
    }
    if registry.cache_root == registry.report_path
        || registry.report_path.starts_with(&registry.cache_root)
    {
        return Err(BootstrapError::Invalid(
            "registry proxy report must be outside the package cache".to_owned(),
        ));
    }
    if registry.credentials.len() > MAX_REGISTRY_CREDENTIALS {
        return Err(BootstrapError::Invalid(
            "registry proxy has too many credentials".to_owned(),
        ));
    }
    let mut total = 0_usize;
    let mut references = std::collections::BTreeSet::new();
    for credential in &registry.credentials {
        validate_registry_credential(credential)?;
        total = total.checked_add(credential.token.len()).ok_or_else(|| {
            BootstrapError::Invalid("registry credential byte count overflowed".to_owned())
        })?;
        if !references.insert(credential.secret_reference.as_str()) {
            return Err(BootstrapError::Invalid(
                "registry proxy credentials contain a duplicate reference".to_owned(),
            ));
        }
    }
    if total > MAX_REGISTRY_CREDENTIAL_TOTAL_BYTES {
        return Err(BootstrapError::Invalid(
            "registry proxy credentials exceed the total byte limit".to_owned(),
        ));
    }
    let expected = registry
        .policy
        .registries
        .iter()
        .filter_map(|entry| entry.credential_secret.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    if references != expected {
        return Err(BootstrapError::Invalid(
            "registry proxy credentials do not exactly match package policy references".to_owned(),
        ));
    }
    Ok(())
}

fn validate_registry_credential(credential: &RegistryCredential) -> Result<(), BootstrapError> {
    if credential.secret_reference.is_empty()
        || credential.secret_reference.len() > 128
        || !credential
            .secret_reference
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                byte == b'_'
                    || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
            })
    {
        return Err(BootstrapError::Invalid(
            "registry credential reference is invalid".to_owned(),
        ));
    }
    if credential.token.is_empty() || credential.token.len() > MAX_REGISTRY_CREDENTIAL_BYTES {
        return Err(BootstrapError::Invalid(format!(
            "registry credential must contain 1-{MAX_REGISTRY_CREDENTIAL_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_egress(
    session_id: SessionId,
    policy: Option<&EgressRuntimePolicyDocument>,
    mcp_policy: Option<&RuntimePolicyDocument>,
    cgroup_parent: Option<&PathBuf>,
) -> Result<(), BootstrapError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    policy
        .validate()
        .map_err(|error| BootstrapError::Invalid(error.to_string()))?;
    let mut expected = EgressRuntimePolicyDocument::for_session_with_mcp(
        session_id,
        policy.network_policy.clone(),
        mcp_policy.map(|policy| &policy.tool_policy),
    )
    .map_err(|error| BootstrapError::Invalid(error.to_string()))?;
    if let Some(registry) = &policy.registry {
        expected = expected.with_registry(
            registry.proxy_port,
            registry.trusted_upstream_port,
            registry.upstream_network_policy.clone(),
        );
    }
    if &expected != policy {
        return Err(BootstrapError::Invalid(
            "egress runtime policy does not match the authenticated session".to_owned(),
        ));
    }

    let expected_parent = policy.execution_cgroup_parent(Path::new(DEFAULT_CGROUP_ROOT));
    if cgroup_parent.map(PathBuf::as_path) != Some(expected_parent.as_path()) {
        return Err(BootstrapError::Invalid(
            "execution broker cgroup parent does not match the egress agent hierarchy".to_owned(),
        ));
    }
    Ok(())
}

fn validate_gateway_credentials(
    credentials: &[GatewayCredential],
    mcp_policy: Option<&RuntimePolicyDocument>,
) -> Result<(), BootstrapError> {
    if credentials.len() > MAX_GATEWAY_CREDENTIALS {
        return Err(BootstrapError::Invalid(format!(
            "gateway credentials may contain at most {MAX_GATEWAY_CREDENTIALS} entries"
        )));
    }
    let mut actual = BTreeSet::new();
    for credential in credentials {
        validate_gateway_credential(credential)?;
        if !actual.insert(credential.name.clone()) {
            return Err(BootstrapError::Invalid(
                "gateway credential names must be unique".to_owned(),
            ));
        }
    }
    let expected = mcp_policy
        .map(|policy| policy.tool_policy.gateway_secret_names())
        .unwrap_or_default();
    if actual != expected {
        return Err(BootstrapError::Invalid(
            "gateway credential names do not exactly match the authenticated MCP policy".to_owned(),
        ));
    }
    Ok(())
}

fn validate_gateway_credential(credential: &GatewayCredential) -> Result<(), BootstrapError> {
    if credential.name.is_empty()
        || credential.name.len() > 128
        || credential.name.chars().any(char::is_control)
    {
        return Err(BootstrapError::Invalid(
            "gateway credential names must be printable and between 1 and 128 UTF-8 bytes"
                .to_owned(),
        ));
    }
    if credential.value.is_empty() || credential.value.len() > MAX_GATEWAY_CREDENTIAL_BYTES {
        return Err(BootstrapError::Invalid(format!(
            "gateway credential '{}' must contain between 1 and {MAX_GATEWAY_CREDENTIAL_BYTES} bytes",
            credential.name
        )));
    }
    let value = std::str::from_utf8(&credential.value).map_err(|_| {
        BootstrapError::Invalid(format!(
            "gateway credential '{}' must be UTF-8",
            credential.name
        ))
    })?;
    if value.chars().any(char::is_control) {
        return Err(BootstrapError::Invalid(format!(
            "gateway credential '{}' cannot contain control characters",
            credential.name
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_broker(
    workload_uid: u32,
    workload_gid: u32,
    runtime_parent: &Path,
    socket_path: &Path,
    launcher_path: &Path,
    cgroup_parent: &Path,
    workspace_root: &Path,
    system_root: &Path,
    git_guard_policy: Option<&GuardPolicyDocument>,
    mcp_policy: Option<&RuntimePolicyDocument>,
) -> Result<(), BootstrapError> {
    if workload_uid == 0 || workload_gid == 0 {
        return Err(BootstrapError::Invalid(
            "execution broker workload identity must be non-root".to_owned(),
        ));
    }
    for (name, path) in [
        ("runtime parent", runtime_parent),
        ("socket", socket_path),
        ("launcher", launcher_path),
        ("cgroup parent", cgroup_parent),
        ("workspace root", workspace_root),
        ("system root", system_root),
    ] {
        if !path.is_absolute() {
            return Err(BootstrapError::Invalid(format!(
                "execution broker {name} path must be absolute"
            )));
        }
    }
    if let Some(policy) = git_guard_policy {
        policy
            .validate()
            .map_err(|error| BootstrapError::Invalid(error.to_string()))?;
        if policy.selected_workspace != workspace_root {
            return Err(BootstrapError::Invalid(
                "Git guard workspace must match the execution broker workspace".to_owned(),
            ));
        }
    }
    if let Some(policy) = mcp_policy {
        policy.validate().map_err(BootstrapError::Invalid)?;
        if policy.workspace_root != workspace_root
            || policy.workload_uid != workload_uid
            || policy.workload_gid != workload_gid
        {
            return Err(BootstrapError::Invalid(
                "MCP policy workspace and workload identity must match the execution broker"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_common(
    host_version: &str,
    trust_root_id: &str,
    manifest_path: &Path,
    minimum_release_sequence: u64,
) -> Result<(), BootstrapError> {
    if host_version.is_empty()
        || host_version.len() > 128
        || trust_root_id.is_empty()
        || trust_root_id.len() > 128
    {
        return Err(BootstrapError::Invalid(
            "host version and trust-root ID must be 1-128 bytes".to_owned(),
        ));
    }
    if minimum_release_sequence == 0 {
        return Err(BootstrapError::Invalid(
            "minimum release sequence must be greater than zero".to_owned(),
        ));
    }
    if manifest_path.as_os_str().is_empty()
        || manifest_path.is_absolute()
        || manifest_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BootstrapError::Invalid(
            "manifest path must be a normalized relative path".to_owned(),
        ));
    }
    Ok(())
}

fn fill_entropy(bytes: &mut [u8; 32]) -> Result<(), BootstrapError> {
    getrandom::fill(bytes).map_err(|error| BootstrapError::Entropy(error.to_string()))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(BootstrapError::Entropy(
            "random source returned an all-zero value".to_owned(),
        ));
    }
    Ok(())
}

const fn default_backoff_ms() -> u64 {
    25
}

const fn default_health_delay_ms() -> u64 {
    50
}

const fn default_health_timeout_ms() -> u64 {
    1_000
}

const fn default_true() -> bool {
    true
}

const fn default_grace_ms() -> u64 {
    500
}

const fn default_kill_ms() -> u64 {
    500
}

const fn default_log_bytes() -> usize {
    64 * 1024
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use sendbox_mcp::runtime::RUNTIME_POLICY_SCHEMA_VERSION;
    use sendbox_policy::{
        Action, McpHttpPolicy, McpServerPolicy, ServerToolPolicy, ToolCallPolicy, ToolTransport,
    };

    use super::*;

    fn configuration() -> BootstrapDocumentConfiguration {
        BootstrapDocumentConfiguration {
            session_id: SessionId::from_bytes([7; 16]),
            boundary_plan_digest: BoundaryPlanDigest::from_bytes([8; 32]),
            host_version: "0.1.0".to_owned(),
            trust_root_id: "root-v1".to_owned(),
            manifest_path: PathBuf::from("manifest.json"),
            minimum_release_sequence: 4,
            required_controls: REQUIRED_RUNTIME_CONTROLS.to_vec(),
            required_services: Vec::new(),
            services: Vec::new(),
            execution_broker: Some(ExecutionBrokerConfiguration {
                runtime_parent: PathBuf::from("/run/sendbox-broker"),
                socket_path: PathBuf::from(
                    "/run/sendbox-broker/07070707-0707-0707-0707-070707070707/s",
                ),
                launcher_path: PathBuf::from("/opt/sendbox/bin/sendbox-exec-launcher"),
                cgroup_parent: PathBuf::from("/sys/fs/cgroup/sendbox"),
                workspace_root: PathBuf::from("/workspace"),
                system_root: PathBuf::from("/"),
                workload_uid: 65_534,
                workload_gid: 65_534,
                command_policy: CommandPolicy {
                    default_action: Action::Deny,
                    allowlist: vec!["git".to_owned()],
                    denylist: Vec::new(),
                    log_blocked: true,
                },
                git_guard_policy: None,
                mcp_policy: None,
            }),
            egress_policy: None,
            gateway_credentials: Vec::new(),
            registry_proxy: None,
        }
    }

    fn mcp_policy() -> RuntimePolicyDocument {
        RuntimePolicyDocument {
            schema_version: RUNTIME_POLICY_SCHEMA_VERSION,
            workspace_root: PathBuf::from("/workspace"),
            workload_uid: 65_534,
            workload_gid: 65_534,
            tool_policy: ToolCallPolicy {
                transport: ToolTransport::Stdio,
                default_action: Action::Deny,
                allowlist: vec!["read_*".to_owned()],
                denylist: Vec::new(),
                max_frame_bytes: 4096,
                server_command_patterns: Vec::new(),
                allowed_server_commands: vec![vec!["/usr/bin/mcp-server".to_owned()]],
                servers: BTreeMap::new(),
            },
            audit_log_path: PathBuf::from("/var/log/sendbox/boundary.log"),
            fixed_environment: BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]),
            inherited_environment_keys: BTreeSet::from(["TOKEN".to_owned()]),
            observation: None,
            safe_outputs: None,
        }
    }

    fn remote_mcp_policy() -> RuntimePolicyDocument {
        RuntimePolicyDocument {
            tool_policy: ToolCallPolicy {
                servers: BTreeMap::from([(
                    "remote".to_owned(),
                    McpServerPolicy::StreamableHttp {
                        url: "https://mcp.example.com/mcp".to_owned(),
                        tools: ServerToolPolicy::default(),
                        http: McpHttpPolicy::default(),
                    },
                )]),
                ..ToolCallPolicy::default()
            },
            inherited_environment_keys: BTreeSet::new(),
            ..mcp_policy()
        }
    }

    #[test]
    fn typed_document_round_trips_without_secret_drift() {
        let encoded =
            encode_bootstrap_document(configuration(), &[9; 32]).expect("encode bootstrap");
        let decoded = decode_bootstrap_document(&encoded).expect("decode bootstrap");

        assert_eq!(decoded.session_id, SessionId::from_bytes([7; 16]));
        assert_eq!(
            decoded.boundary_plan_digest,
            BoundaryPlanDigest::from_bytes([8; 32])
        );
        assert_eq!(
            decoded.bootstrap_secret.expose_for_key_derivation(),
            &[9; 32]
        );
        assert_eq!(decoded.required_controls, REQUIRED_RUNTIME_CONTROLS);
        let broker = decoded.execution_broker.expect("execution broker");
        assert!(broker.authentication.iter().any(|byte| *byte != 0));
        assert_eq!(broker.workspace_root, Path::new("/workspace"));
    }

    #[test]
    fn encoding_rejects_invalid_secret_and_manifest() {
        assert!(encode_bootstrap_document(configuration(), &[1; 31]).is_err());
        let mut invalid = configuration();
        invalid.manifest_path = PathBuf::from("../manifest.json");
        assert!(encode_bootstrap_document(invalid, &[1; 32]).is_err());
    }

    #[test]
    fn decoder_rejects_unknown_fields() {
        let encoded =
            encode_bootstrap_document(configuration(), &[3; 32]).expect("encode bootstrap");
        let mut value: serde_json::Value =
            serde_json::from_slice(&encoded).expect("bootstrap JSON");
        value
            .as_object_mut()
            .expect("bootstrap object")
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        let bytes = serde_json::to_vec(&value).expect("mutated bootstrap");
        assert!(decode_bootstrap_document(&bytes).is_err());
    }

    #[test]
    fn authenticated_bootstrap_round_trips_mcp_policy() {
        let mut configuration = configuration();
        configuration
            .execution_broker
            .as_mut()
            .expect("execution broker")
            .mcp_policy = Some(mcp_policy());
        let encoded = encode_bootstrap_document(configuration, &[4; 32]).expect("encode bootstrap");
        let decoded = decode_bootstrap_document(&encoded).expect("decode bootstrap");
        assert_eq!(
            decoded
                .execution_broker
                .expect("execution broker")
                .mcp_policy,
            Some(mcp_policy())
        );
    }

    #[test]
    fn authenticated_bootstrap_rejects_mcp_identity_drift() {
        let mut configuration = configuration();
        let mut policy = mcp_policy();
        policy.workload_uid = 1000;
        configuration
            .execution_broker
            .as_mut()
            .expect("execution broker")
            .mcp_policy = Some(policy);
        assert!(encode_bootstrap_document(configuration, &[4; 32]).is_err());
    }

    #[test]
    fn authenticated_bootstrap_binds_egress_policy_and_exec_parent() {
        let mut config = configuration();
        let network = sendbox_policy::NetworkPolicy {
            default_action: Action::Deny,
            allowed_domains: vec!["example.com".to_owned()],
            blocked_domains: Vec::new(),
            allow_dns: true,
            max_connections: None,
            allowed_networks: Vec::new(),
            blocked_networks: Vec::new(),
            allowed_ports: Vec::new(),
            dns: sendbox_policy::DnsPolicy::default(),
        };
        let policy = EgressRuntimePolicyDocument::for_session(config.session_id, network.clone());
        config
            .execution_broker
            .as_mut()
            .expect("execution broker")
            .cgroup_parent = policy.execution_cgroup_parent(Path::new(DEFAULT_CGROUP_ROOT));
        config.egress_policy = Some(policy.clone());
        let encoded = encode_bootstrap_document(config, &[5; 32]).expect("encode bootstrap");
        let decoded = decode_bootstrap_document(&encoded).expect("decode bootstrap");
        assert_eq!(decoded.egress_policy, Some(policy));

        let mut config = configuration();
        let drifted =
            EgressRuntimePolicyDocument::for_session(SessionId::from_bytes([9; 16]), network);
        config
            .execution_broker
            .as_mut()
            .expect("execution broker")
            .cgroup_parent = drifted.execution_cgroup_parent(Path::new(DEFAULT_CGROUP_ROOT));
        config.egress_policy = Some(drifted);
        assert!(encode_bootstrap_document(config, &[5; 32]).is_err());
    }

    #[test]
    fn remote_mcp_bootstrap_requires_authenticated_egress() {
        let mut config = configuration();
        let mcp = remote_mcp_policy();
        config
            .execution_broker
            .as_mut()
            .expect("execution broker")
            .mcp_policy = Some(mcp.clone());
        assert!(encode_bootstrap_document(config.clone(), &[6; 32]).is_err());

        let network = sendbox_policy::NetworkPolicy {
            default_action: Action::Allow,
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
            allow_dns: true,
            max_connections: None,
            allowed_networks: Vec::new(),
            blocked_networks: Vec::new(),
            allowed_ports: Vec::new(),
            dns: sendbox_policy::DnsPolicy::default(),
        };
        let egress = EgressRuntimePolicyDocument::for_session_with_mcp(
            config.session_id,
            network,
            Some(&mcp.tool_policy),
        )
        .unwrap();
        config
            .execution_broker
            .as_mut()
            .expect("execution broker")
            .cgroup_parent = egress.execution_cgroup_parent(Path::new(DEFAULT_CGROUP_ROOT));
        config.egress_policy = Some(egress);
        assert!(encode_bootstrap_document(config, &[6; 32]).is_ok());
    }

    #[test]
    fn authenticated_bootstrap_round_trips_redacted_registry_credentials() {
        let mut config = configuration();
        let network = sendbox_policy::NetworkPolicy {
            default_action: Action::Deny,
            allowed_domains: vec!["registry.example.com".to_owned()],
            blocked_domains: Vec::new(),
            allow_dns: true,
            max_connections: None,
            allowed_networks: Vec::new(),
            blocked_networks: Vec::new(),
            allowed_ports: Vec::new(),
            dns: sendbox_policy::DnsPolicy::default(),
        };
        let egress = EgressRuntimePolicyDocument::for_session(config.session_id, network.clone())
            .with_registry(14_873, 15_081, network);
        config
            .execution_broker
            .as_mut()
            .expect("execution broker")
            .cgroup_parent = egress.execution_cgroup_parent(Path::new(DEFAULT_CGROUP_ROOT));
        config.egress_policy = Some(egress);
        let policy = sendbox_policy::PackageSupplyChainPolicy {
            enabled: true,
            registries: vec![sendbox_policy::PackageRegistryPolicy {
                url: "https://registry.example.com/".to_owned(),
                credential_secret: Some("PRIVATE_NPM_TOKEN".to_owned()),
                ..sendbox_policy::PackageRegistryPolicy::default()
            }],
            ..sendbox_policy::PackageSupplyChainPolicy::default()
        };
        config.registry_proxy = Some(RegistryProxyConfiguration {
            policy,
            proxy_port: 14_873,
            trusted_upstream_port: 15_081,
            cache_root: PathBuf::from("/var/cache/sendbox/packages"),
            report_path: PathBuf::from("/run/sendbox/package-report.json"),
            proxy_uid: DEFAULT_REGISTRY_UID,
            proxy_gid: DEFAULT_REGISTRY_GID,
            credentials: vec![
                RegistryCredential::new("PRIVATE_NPM_TOKEN", b"top-secret".to_vec()).unwrap(),
            ],
        });

        let encoded = encode_bootstrap_document(config, &[6; 32]).expect("encode bootstrap");
        assert!(!String::from_utf8_lossy(&encoded).contains("top-secret"));
        let decoded = decode_bootstrap_document(&encoded).expect("decode bootstrap");
        let registry = decoded.registry_proxy.expect("registry proxy");
        assert_eq!(
            registry.credentials[0].expose_to_registry_proxy(),
            b"top-secret"
        );
        assert_eq!(
            format!("{:?}", registry.credentials[0]),
            "RegistryCredential { secret_reference: \"PRIVATE_NPM_TOKEN\", token: \"[REDACTED]\" }"
        );
    }

    #[test]
    fn authenticated_bootstrap_rejects_missing_or_oversized_registry_credentials() {
        let mut config = configuration();
        let network = sendbox_policy::NetworkPolicy {
            default_action: Action::Deny,
            allowed_domains: vec!["registry.example.com".to_owned()],
            blocked_domains: Vec::new(),
            allow_dns: true,
            max_connections: None,
            allowed_networks: Vec::new(),
            blocked_networks: Vec::new(),
            allowed_ports: Vec::new(),
            dns: sendbox_policy::DnsPolicy::default(),
        };
        let egress = EgressRuntimePolicyDocument::for_session(config.session_id, network.clone())
            .with_registry(14_873, 15_081, network);
        config
            .execution_broker
            .as_mut()
            .expect("execution broker")
            .cgroup_parent = egress.execution_cgroup_parent(Path::new(DEFAULT_CGROUP_ROOT));
        config.egress_policy = Some(egress);
        config.registry_proxy = Some(RegistryProxyConfiguration {
            policy: sendbox_policy::PackageSupplyChainPolicy {
                enabled: true,
                registries: vec![sendbox_policy::PackageRegistryPolicy {
                    credential_secret: Some("PRIVATE_NPM_TOKEN".to_owned()),
                    ..sendbox_policy::PackageRegistryPolicy::default()
                }],
                ..sendbox_policy::PackageSupplyChainPolicy::default()
            },
            proxy_port: 14_873,
            trusted_upstream_port: 15_081,
            cache_root: PathBuf::from("/var/cache/sendbox/packages"),
            report_path: PathBuf::from("/run/sendbox/package-report.json"),
            proxy_uid: DEFAULT_REGISTRY_UID,
            proxy_gid: DEFAULT_REGISTRY_GID,
            credentials: Vec::new(),
        });
        assert!(encode_bootstrap_document(config, &[6; 32]).is_err());
        assert!(
            RegistryCredential::new(
                "PRIVATE_NPM_TOKEN",
                vec![7; MAX_REGISTRY_CREDENTIAL_BYTES + 1]
            )
            .is_err()
        );
    }
}
