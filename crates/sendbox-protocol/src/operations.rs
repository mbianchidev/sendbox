use serde::{Deserialize, Serialize};

pub const OPERATION_SCHEMA_VERSION: u32 = 1;
pub const AGENT_LAUNCH_OPERATION: &str = "agent.launch";
pub const HEALTH_OPERATION: &str = "health";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEntryV1 {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequestV1 {
    pub schema_version: u32,
    pub program: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub environment: Vec<EnvironmentEntryV1>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalStateV1 {
    Exited {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    Cancelled,
    TimedOut,
    OutputSaturated,
    ClientDisconnected,
    BrokerShutdown,
    SupervisorDied,
    Rejected {
        reason: String,
    },
    LaunchFailed {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalResultV1 {
    pub schema_version: u32,
    pub terminal: TerminalStateV1,
    pub cleanup_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponseV1 {
    pub schema_version: u32,
    pub ready: bool,
    pub broker_live: bool,
    pub release_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_schema_preserves_exact_argv_boundaries() {
        let request = LaunchRequestV1 {
            schema_version: OPERATION_SCHEMA_VERSION,
            program: "/usr/bin/tool".to_owned(),
            arguments: vec!["one value".to_owned(), "two".to_owned()],
            working_directory: "/workspace".to_owned(),
            environment: vec![EnvironmentEntryV1 {
                name: "SAFE".to_owned(),
                value: "value".to_owned(),
            }],
            timeout_ms: 1_000,
        };
        let encoded = serde_json::to_vec(&request).expect("encode");
        let decoded: LaunchRequestV1 = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, request);
        assert_eq!(decoded.arguments, ["one value", "two"]);
    }
}
