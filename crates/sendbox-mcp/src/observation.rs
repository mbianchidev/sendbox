use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ObservationError;
use crate::jsonrpc::{MessageKind as RpcMessageKind, validate_message};

pub const LEGACY_EVENT_MARKER: &str = "SENDBOX_MCP";
pub const EVENT_V1_MARKER: &str = "SENDBOX_MCP_EVENT";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Stdio,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Spawn,
    ToServer,
    FromServer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationMetadata {
    pub timestamp_nanos: Option<u64>,
    pub process_id: Option<u32>,
    pub command: Option<String>,
    pub transport: Transport,
    pub direction: Direction,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEventV1 {
    pub schema_version: u32,
    pub timestamp_nanos: Option<u64>,
    pub process_id: Option<u32>,
    pub command: Option<String>,
    pub transport: Transport,
    pub direction: Direction,
    pub payload: String,
}

impl ObservationEventV1 {
    pub fn from_metadata(metadata: ObservationMetadata) -> Result<Self, ObservationError> {
        let payload = String::from_utf8(metadata.payload)
            .map_err(|_| ObservationError::InvalidEvent("payload is not UTF-8".into()))?;
        Ok(Self {
            schema_version: 1,
            timestamp_nanos: metadata.timestamp_nanos,
            process_id: metadata.process_id,
            command: metadata.command,
            transport: metadata.transport,
            direction: metadata.direction,
            payload,
        })
    }

    pub fn encode_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self).map(|json| format!("{EVENT_V1_MARKER}\t{json}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Request,
    Response,
    Notification,
    Error,
    Spawn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodCategory {
    Lifecycle,
    Tools,
    Resources,
    Prompts,
    Sampling,
    Roots,
    Completion,
    Logging,
    Notification,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedCall {
    pub timestamp_nanos: Option<u64>,
    pub process_id: Option<u32>,
    pub command: Option<String>,
    pub transport: Transport,
    pub kind: MessageKind,
    pub method: Option<String>,
    pub category: MethodCategory,
    pub id: Option<String>,
    pub subject: Option<String>,
    pub error_code: Option<i64>,
    pub error_message: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionSummary {
    pub total_calls: usize,
    pub by_category: BTreeMap<MethodCategory, usize>,
    pub by_kind: BTreeMap<MessageKind, usize>,
    pub by_transport: BTreeMap<Transport, usize>,
    pub tool_call_count: usize,
    pub tool_invocations: BTreeMap<String, usize>,
    pub error_count: usize,
    pub distinct_methods: Vec<String>,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ObservationParser {
    capture_payloads: bool,
}

impl ObservationParser {
    #[must_use]
    pub fn new(capture_payloads: bool) -> Self {
        Self { capture_payloads }
    }

    pub fn parse_log(&self, log: &str) -> Vec<ObservedCall> {
        let mut calls = Vec::new();
        let mut pending = HashMap::<
            (Option<u32>, Option<String>, String, Direction),
            (String, MethodCategory),
        >::new();
        for line in log.lines() {
            let Ok(event) = parse_event_line(line) else {
                continue;
            };
            if event.direction == Direction::Spawn {
                let subject = event.payload.trim().to_owned();
                calls.push(ObservedCall {
                    timestamp_nanos: event.timestamp_nanos,
                    process_id: event.process_id,
                    command: event.command,
                    transport: event.transport,
                    kind: MessageKind::Spawn,
                    method: None,
                    category: MethodCategory::Lifecycle,
                    id: None,
                    subject: Some(subject.clone()),
                    error_code: None,
                    error_message: None,
                    raw: subject,
                });
                continue;
            }
            for object in extract_json_objects(&event.payload) {
                let Ok((mut call, raw_id)) = self.parse_message_internal(
                    &object,
                    event.transport,
                    event.process_id,
                    event.command.clone(),
                    event.timestamp_nanos,
                ) else {
                    continue;
                };
                if let Some(id) = raw_id {
                    match call.kind {
                        MessageKind::Request => {
                            if let Some(method) = call.method.clone() {
                                pending.insert(
                                    (call.process_id, call.command.clone(), id, event.direction),
                                    (method, call.category),
                                );
                            }
                        }
                        MessageKind::Response | MessageKind::Error => {
                            let request_direction = match event.direction {
                                Direction::FromServer => Direction::ToServer,
                                Direction::ToServer => Direction::FromServer,
                                Direction::Spawn => continue,
                            };
                            let key =
                                (call.process_id, call.command.clone(), id, request_direction);
                            if call.method.is_none()
                                && let Some((method, category)) = pending.remove(&key)
                            {
                                call.method = Some(method);
                                call.category = category;
                            }
                        }
                        MessageKind::Notification | MessageKind::Spawn => {}
                    }
                }
                calls.push(call);
            }
        }
        calls
    }

    pub fn parse_message(
        &self,
        json: &str,
        transport: Transport,
        process_id: Option<u32>,
        command: Option<String>,
        timestamp_nanos: Option<u64>,
    ) -> Result<ObservedCall, ObservationError> {
        self.parse_message_internal(json, transport, process_id, command, timestamp_nanos)
            .map(|(call, _)| call)
    }

    fn parse_message_internal(
        &self,
        json: &str,
        transport: Transport,
        process_id: Option<u32>,
        command: Option<String>,
        timestamp_nanos: Option<u64>,
    ) -> Result<(ObservedCall, Option<String>), ObservationError> {
        let message = validate_message(json.as_bytes())?;
        let category = classify(message.method.as_deref());
        let kind = match message.kind {
            RpcMessageKind::Request => MessageKind::Request,
            RpcMessageKind::Notification => MessageKind::Notification,
            RpcMessageKind::Response => MessageKind::Response,
            RpcMessageKind::Error => MessageKind::Error,
        };
        let raw_id = message.id.raw().map(str::to_owned);
        let id = raw_id.as_deref().map(display_id);
        let subject = if self.capture_payloads || message.method.as_deref() == Some("tools/call") {
            message.subject
        } else {
            None
        };
        let raw = if self.capture_payloads {
            json.trim().to_owned()
        } else {
            redacted_envelope(
                message.method.as_deref(),
                id.as_deref(),
                subject.as_deref(),
                kind,
            )
        };
        Ok((
            ObservedCall {
                timestamp_nanos,
                process_id,
                command,
                transport,
                kind,
                method: message.method,
                category,
                id,
                subject,
                error_code: message.error_code,
                error_message: self
                    .capture_payloads
                    .then_some(message.error_message)
                    .flatten(),
                raw,
            },
            raw_id,
        ))
    }
}

#[must_use]
pub fn summarize(calls: &[ObservedCall]) -> InspectionSummary {
    let mut by_category = BTreeMap::new();
    let mut by_kind = BTreeMap::new();
    let mut by_transport = BTreeMap::new();
    let mut tool_invocations = BTreeMap::new();
    let mut methods = BTreeSet::new();
    let mut servers = BTreeSet::new();
    let mut tool_call_count = 0;
    let mut error_count = 0;
    for call in calls {
        *by_category.entry(call.category).or_insert(0) += 1;
        *by_kind.entry(call.kind).or_insert(0) += 1;
        *by_transport.entry(call.transport).or_insert(0) += 1;
        if let Some(method) = &call.method {
            methods.insert(method.clone());
        }
        if call.kind == MessageKind::Error {
            error_count += 1;
        }
        if call.kind == MessageKind::Spawn {
            servers.insert(call.subject.clone().unwrap_or_else(|| "unknown".into()));
        }
        if call.kind == MessageKind::Request && call.method.as_deref() == Some("tools/call") {
            tool_call_count += 1;
            if let Some(tool) = &call.subject {
                *tool_invocations.entry(tool.clone()).or_insert(0) += 1;
            }
        }
    }
    InspectionSummary {
        total_calls: calls.len(),
        by_category,
        by_kind,
        by_transport,
        tool_call_count,
        tool_invocations,
        error_count,
        distinct_methods: methods.into_iter().collect(),
        servers: servers.into_iter().collect(),
    }
}

#[must_use]
pub fn render_report(summary: &InspectionSummary) -> String {
    let mut lines = vec![
        format!("MCP calls: {}", summary.total_calls),
        format!("Tool calls: {}", summary.tool_call_count),
        format!("Errors: {}", summary.error_count),
    ];
    for (tool, count) in &summary.tool_invocations {
        lines.push(format!("tool {tool}: {count}"));
    }
    for server in &summary.servers {
        lines.push(format!("server: {server}"));
    }
    lines.join("\n") + "\n"
}

#[must_use]
pub fn classify(method: Option<&str>) -> MethodCategory {
    let Some(method) = method.filter(|method| !method.is_empty()) else {
        return MethodCategory::Other;
    };
    if method.starts_with("notifications/") {
        MethodCategory::Notification
    } else if method.starts_with("tools/") {
        MethodCategory::Tools
    } else if method.starts_with("resources/") {
        MethodCategory::Resources
    } else if method.starts_with("prompts/") {
        MethodCategory::Prompts
    } else if method.starts_with("sampling/") {
        MethodCategory::Sampling
    } else if method.starts_with("roots/") {
        MethodCategory::Roots
    } else if method.starts_with("completion/") {
        MethodCategory::Completion
    } else if method.starts_with("logging/") {
        MethodCategory::Logging
    } else if ["initialize", "initialized", "ping", "shutdown", "exit"].contains(&method) {
        MethodCategory::Lifecycle
    } else {
        MethodCategory::Other
    }
}

fn parse_event_line(line: &str) -> Result<ObservationEventV1, ObservationError> {
    if let Some(json) = line.strip_prefix(&format!("{EVENT_V1_MARKER}\t")) {
        let event: ObservationEventV1 = serde_json::from_str(json)
            .map_err(|error| ObservationError::InvalidEvent(error.to_string()))?;
        if event.schema_version != 1 {
            return Err(ObservationError::InvalidEvent(
                "unsupported schema version".into(),
            ));
        }
        return Ok(event);
    }
    let fields = line.splitn(7, '\t').collect::<Vec<_>>();
    if fields.len() != 7 || fields[0] != LEGACY_EVENT_MARKER {
        return Err(ObservationError::InvalidEvent(
            "not a recognized MCP event".into(),
        ));
    }
    let transport = match fields[4] {
        "stdio" => Transport::Stdio,
        "http" => Transport::Http,
        value => {
            return Err(ObservationError::InvalidEvent(format!(
                "unknown transport {value}"
            )));
        }
    };
    let direction = match fields[5] {
        "spawn" => Direction::Spawn,
        "to_server" => Direction::ToServer,
        "from_server" => Direction::FromServer,
        value => {
            return Err(ObservationError::InvalidEvent(format!(
                "unknown direction {value}"
            )));
        }
    };
    Ok(ObservationEventV1 {
        schema_version: 1,
        timestamp_nanos: fields[1].parse().ok(),
        process_id: fields[2].parse().ok(),
        command: (!fields[3].is_empty()).then(|| fields[3].to_owned()),
        transport,
        direction,
        payload: fields[6].to_owned(),
    })
}

fn display_id(raw: &str) -> String {
    if raw.starts_with('"') {
        serde_json::from_str::<String>(raw).unwrap_or_else(|_| raw.to_owned())
    } else {
        raw.to_owned()
    }
}

fn redacted_envelope(
    method: Option<&str>,
    id: Option<&str>,
    subject: Option<&str>,
    kind: MessageKind,
) -> String {
    let mut object = serde_json::Map::new();
    object.insert("jsonrpc".into(), Value::String("2.0".into()));
    object.insert("_redacted".into(), Value::Bool(true));
    if let Some(id) = id {
        object.insert("id".into(), Value::String(id.into()));
    }
    if let Some(method) = method {
        object.insert("method".into(), Value::String(method.into()));
    }
    if let Some(subject) = subject {
        object.insert("name".into(), Value::String(subject.into()));
    }
    object.insert(
        "kind".into(),
        Value::String(
            serde_json::to_value(kind)
                .expect("enum serialization")
                .as_str()
                .expect("string enum")
                .into(),
        ),
    );
    serde_json::to_string(&object).expect("map serialization")
}

fn extract_json_objects(payload: &str) -> Vec<String> {
    let chars = payload.char_indices().collect::<Vec<_>>();
    let mut results = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        if chars[index].1 != '{' {
            index += 1;
            continue;
        }
        let start = chars[index].0;
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        let mut closed = None;
        for &(byte_index, character) in &chars[index..] {
            if in_string {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
            } else {
                match character {
                    '"' => in_string = true,
                    '{' => depth += 1,
                    '}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            closed = Some(byte_index + character.len_utf8());
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        let Some(end) = closed else {
            break;
        };
        let candidate = &payload[start..end];
        if candidate.contains("jsonrpc") {
            results.push(candidate.to_owned());
        }
        while index < chars.len() && chars[index].0 < end {
            index += 1;
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_and_versioned_events_with_correlation() {
        let legacy = concat!(
            "SENDBOX_MCP\t100\t42\tnode\tstdio\tto_server\t",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\"}}\n",
            "SENDBOX_MCP\t200\t42\tnode\tstdio\tfrom_server\t",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}"
        );
        let calls = ObservationParser::new(true).parse_log(legacy);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].method.as_deref(), Some("tools/call"));

        let event = ObservationEventV1 {
            schema_version: 1,
            timestamp_nanos: Some(1),
            process_id: Some(7),
            command: Some("server".into()),
            transport: Transport::Stdio,
            direction: Direction::ToServer,
            payload: r#"{"jsonrpc":"2.0","method":"ping"}"#.into(),
        };
        let calls = ObservationParser::new(true).parse_log(&event.encode_line().unwrap());
        assert_eq!(calls[0].category, MethodCategory::Lifecycle);
    }

    #[test]
    fn redaction_removes_arguments_and_error_messages() {
        let parser = ObservationParser::new(false);
        let call = parser
            .parse_message(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"cmd":"secret"}}}"#,
                Transport::Stdio,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(call.raw.contains("_redacted"));
        assert!(!call.raw.contains("secret"));
    }

    #[test]
    fn redaction_drops_resource_uris() {
        let call = ObservationParser::new(false)
            .parse_message(
                r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///private/token?secret=x"}}"#,
                Transport::Stdio,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(call.subject, None);
        assert!(!call.raw.contains("private"));
        assert!(!call.raw.contains("secret"));
    }

    #[test]
    fn correlation_distinguishes_string_numeric_and_request_direction() {
        let log = concat!(
            "SENDBOX_MCP\t1\t1\tnode\tstdio\tto_server\t",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n",
            "SENDBOX_MCP\t2\t1\tnode\tstdio\tfrom_server\t",
            "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"resources/list\"}\n",
            "SENDBOX_MCP\t3\t1\tnode\tstdio\tfrom_server\t",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[]}\n",
            "SENDBOX_MCP\t4\t1\tnode\tstdio\tto_server\t",
            "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":[]}"
        );
        let calls = ObservationParser::new(true).parse_log(log);
        assert_eq!(calls[2].method.as_deref(), Some("tools/list"));
        assert_eq!(calls[3].method.as_deref(), Some("resources/list"));
    }

    #[test]
    fn summary_and_report_are_deterministic() {
        let calls = ObservationParser::new(true).parse_log(concat!(
            "SENDBOX_MCP\t1\t1\tnode\tstdio\tspawn\tnode mcp-server\n",
            "SENDBOX_MCP\t2\t1\tnode\tstdio\tto_server\t",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\"}}"
        ));
        let summary = summarize(&calls);
        assert_eq!(summary.tool_call_count, 1);
        assert_eq!(
            render_report(&summary),
            "MCP calls: 2\nTool calls: 1\nErrors: 0\ntool ls: 1\nserver: node mcp-server\n"
        );
    }

    #[test]
    fn metadata_ingestion_rejects_non_utf8() {
        let metadata = ObservationMetadata {
            timestamp_nanos: None,
            process_id: None,
            command: None,
            transport: Transport::Stdio,
            direction: Direction::ToServer,
            payload: vec![0xff],
        };
        assert!(ObservationEventV1::from_metadata(metadata).is_err());
    }
}
