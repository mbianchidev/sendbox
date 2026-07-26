use sendbox_config::{InspectionTransport, McpInspectionConfiguration};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeObserverArtifact {
    pub schema_version: u32,
    pub artifact_kind: &'static str,
    pub observer: &'static str,
    pub authorization_boundary: &'static str,
    pub runtime_integration: &'static str,
    pub enabled: bool,
    pub transports: Vec<&'static str>,
    pub capture_payloads: bool,
    pub max_payload_bytes: i64,
    pub log_path: String,
    pub server_command_patterns: Vec<String>,
}

impl NativeObserverArtifact {
    #[must_use]
    pub fn from_config(config: &McpInspectionConfiguration) -> Self {
        Self {
            schema_version: 1,
            artifact_kind: "sendbox.native-mcp-observer-description",
            observer: "future C/libbpf ring-buffer metadata producer",
            authorization_boundary: "local stdio broker only; HTTP/SSE is observation-only",
            runtime_integration: "not included",
            enabled: config.enabled,
            transports: config
                .transports
                .iter()
                .map(|transport| match transport {
                    InspectionTransport::Stdio => "stdio",
                    InspectionTransport::Http => "http",
                })
                .collect(),
            capture_payloads: config.capture_payloads,
            max_payload_bytes: config.max_payload_bytes,
            log_path: config.log_path.display().to_string(),
            server_command_patterns: config.server_command_patterns.clone(),
        }
    }

    pub fn to_pretty_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self).map(|mut json| {
            json.push('\n');
            json
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_is_deterministic_and_not_an_executable_script() {
        let artifact = NativeObserverArtifact::from_config(&McpInspectionConfiguration::default())
            .to_pretty_json()
            .unwrap();
        assert_eq!(
            artifact,
            NativeObserverArtifact::from_config(&McpInspectionConfiguration::default())
                .to_pretty_json()
                .unwrap()
        );
        assert!(artifact.contains("observation-only"));
        assert!(artifact.contains("\"runtime_integration\": \"not included\""));
        assert!(!artifact.contains("#!/"));
        assert!(!artifact.contains("bpftrace"));
    }
}
