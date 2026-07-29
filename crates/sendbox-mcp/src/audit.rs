use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::AuditError;
use crate::policy::{AuditDecision, AuditOutcome};

pub const MAX_AUDIT_EVENT_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryAuditEvent {
    pub schema_version: u32,
    pub timestamp_unix_ms: u128,
    pub server_policy_id: String,
    pub server_fingerprint: String,
    pub transport: sendbox_policy::ToolTransport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id_hash: Option<String>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl BoundaryAuditEvent {
    #[must_use]
    pub fn from_decision(decision: &AuditDecision) -> Self {
        Self {
            schema_version: 1,
            timestamp_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            server_policy_id: decision.server_id.clone(),
            server_fingerprint: decision.server_fingerprint.clone(),
            transport: decision.transport,
            normalized_endpoint: decision.endpoint.clone(),
            session_id_hash: None,
            method: decision.method.clone(),
            tool: decision.tool.clone(),
            outcome: match decision.outcome {
                AuditOutcome::Allowed => "allowed",
                AuditOutcome::Denied => "denied",
                AuditOutcome::Dropped => "dropped",
            }
            .to_owned(),
            matched_rule: decision.matched_rule.clone(),
            denial_reason: decision.reason.clone(),
            status: None,
            request_bytes: None,
            response_bytes: None,
            duration_ms: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnixAuditSink {
    path: std::path::PathBuf,
    timeout: std::time::Duration,
}

impl UnixAuditSink {
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            timeout: std::time::Duration::from_secs(2),
        }
    }
}

impl BoundaryAuditSink for UnixAuditSink {
    fn record(&self, event: &BoundaryAuditEvent) -> Result<(), AuditError> {
        let encoded = serde_json::to_vec(event).map_err(AuditError::Encode)?;
        if encoded.len() > MAX_AUDIT_EVENT_BYTES {
            return Err(AuditError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "MCP audit event exceeds the socket protocol limit",
            )));
        }
        let length = u32::try_from(encoded.len()).map_err(|_| {
            AuditError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "MCP audit event length is invalid",
            ))
        })?;
        let mut stream = UnixStream::connect(&self.path).map_err(AuditError::Io)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(AuditError::Io)?;
        stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| stream.write_all(&encoded))
            .map_err(AuditError::Io)?;
        let mut ack = [0_u8; 1];
        stream.read_exact(&mut ack).map_err(AuditError::Io)?;
        if ack != [1] {
            return Err(AuditError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "MCP audit service rejected the event",
            )));
        }
        Ok(())
    }
}

pub trait BoundaryAuditSink: Send + Sync {
    fn record(&self, event: &BoundaryAuditEvent) -> Result<(), AuditError>;
}

#[derive(Debug)]
pub struct FileAuditSink {
    file: Mutex<File>,
}

impl FileAuditSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(AuditError::Io)?;
        let metadata = file.metadata().map_err(AuditError::Io)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(AuditError::UntrustedPath(path.display().to_string()));
        }
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl BoundaryAuditSink for FileAuditSink {
    fn record(&self, event: &BoundaryAuditEvent) -> Result<(), AuditError> {
        let mut encoded = serde_json::to_vec(event).map_err(AuditError::Encode)?;
        encoded.push(b'\n');
        let mut file = self.file.lock().map_err(|_| AuditError::Poisoned)?;
        file.write_all(&encoded)
            .and_then(|()| file.flush())
            .map_err(AuditError::Io)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sendbox_policy::ToolTransport;

    use super::*;

    #[test]
    fn file_audit_is_redacted_json_lines() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("boundary.log");
        File::create(&path).unwrap();
        let sink = Arc::new(FileAuditSink::open(&path).unwrap());
        sink.record(&BoundaryAuditEvent::from_decision(&AuditDecision {
            server_id: "github".to_owned(),
            server_fingerprint: "abc".to_owned(),
            transport: ToolTransport::Stdio,
            endpoint: None,
            method: "tools/call".to_owned(),
            tool: Some("search_code".to_owned()),
            outcome: AuditOutcome::Allowed,
            matched_rule: Some("search_*".to_owned()),
            reason: None,
        }))
        .unwrap();
        let encoded = std::fs::read_to_string(path).unwrap();
        assert!(encoded.contains("\"server_policy_id\":\"github\""));
        assert!(encoded.contains("\"tool\":\"search_code\""));
        assert!(!encoded.contains("arguments"));
        assert_eq!(encoded.lines().count(), 1);
    }
}
