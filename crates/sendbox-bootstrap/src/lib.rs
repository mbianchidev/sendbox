#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Component, Path, PathBuf};

use sendbox_core::{BoundaryPlanDigest, SessionId};
use sendbox_git::GuardPolicyDocument;
use sendbox_policy::CommandPolicy;
use sendbox_protocol::BootstrapSecret;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use zeroize::Zeroizing;

pub const BOOTSTRAP_SCHEMA_VERSION: u32 = 2;
pub const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;
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
        )?;
    }
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
        )?;
    }
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
    })
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
    use sendbox_policy::Action;

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
            }),
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
}
