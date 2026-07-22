use serde::Serialize;

use crate::{BpfError, DiagnosticKind};

pub const EVENT_SCHEMA_VERSION: u8 = 1;
pub const EVENT_HEADER_SIZE: usize = 8;
pub const COMM_LEN: usize = 16;
pub const FILENAME_LEN: usize = 128;
pub const MCP_CAPTURE_LEN: usize = 256;
pub const EXEC_EVENT_SIZE: usize = 176;
pub const SYSCALL_EVENT_SIZE: usize = 88;
pub const MCP_EVENT_SIZE: usize = 296;
pub const MAX_EVENT_SIZE: usize = MCP_EVENT_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Exec = 1,
    Syscall = 2,
    Mcp = 3,
}

impl TryFrom<u8> for EventKind {
    type Error = BpfError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Exec),
            2 => Ok(Self::Syscall),
            3 => Ok(Self::Mcp),
            _ => Err(decode_error(format!("unknown event kind {value}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct EventHeader {
    pub size: u16,
    pub version: u8,
    pub kind: EventKind,
    pub flags: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    ProcessExec(ExecEvent),
    SyscallEnter(SyscallEvent),
    McpObservation(McpEvent),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecEvent {
    pub header: EventHeader,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub filename: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyscallEvent {
    pub header: EventHeader,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub syscall_id: u32,
    pub arguments: [u64; 6],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum McpDirection {
    Request = 1,
    Response = 2,
}

impl TryFrom<u8> for McpDirection {
    type Error = BpfError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            _ => Err(decode_error(format!("unknown MCP direction {value}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    Stdio = 1,
    StreamableHttp = 2,
}

impl TryFrom<u8> for McpTransport {
    type Error = BpfError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Stdio),
            2 => Ok(Self::StreamableHttp),
            _ => Err(decode_error(format!("unknown MCP transport {value}"))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct McpEvent {
    pub header: EventHeader,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub direction: McpDirection,
    pub transport: McpTransport,
    pub payload_len: u32,
    pub captured_payload: Vec<u8>,
}

impl Event {
    pub fn decode(data: &[u8]) -> Result<Self, BpfError> {
        if data.len() > MAX_EVENT_SIZE {
            return Err(decode_error(format!(
                "oversized event: received {} bytes, maximum is {MAX_EVENT_SIZE}",
                data.len()
            )));
        }
        if data.len() < EVENT_HEADER_SIZE {
            return Err(decode_error(format!(
                "malformed event: received {} bytes, minimum header is {EVENT_HEADER_SIZE}",
                data.len()
            )));
        }

        let header = EventHeader {
            size: read_u16(data, 0)?,
            version: data[2],
            kind: EventKind::try_from(data[3])?,
            flags: read_u32(data, 4)?,
        };
        if header.version != EVENT_SCHEMA_VERSION {
            return Err(decode_error(format!(
                "unsupported event schema version {}",
                header.version
            )));
        }
        if usize::from(header.size) != data.len() {
            return Err(decode_error(format!(
                "event size field is {}, received {} bytes",
                header.size,
                data.len()
            )));
        }

        match header.kind {
            EventKind::Exec => decode_exec(data, header).map(Self::ProcessExec),
            EventKind::Syscall => decode_syscall(data, header).map(Self::SyscallEnter),
            EventKind::Mcp => decode_mcp(data, header).map(Self::McpObservation),
        }
    }
}

fn decode_exec(data: &[u8], header: EventHeader) -> Result<ExecEvent, BpfError> {
    require_exact_size(data, EXEC_EVENT_SIZE, "exec")?;
    Ok(ExecEvent {
        header,
        timestamp_ns: read_u64(data, 8)?,
        pid: read_u32(data, 16)?,
        tgid: read_u32(data, 20)?,
        uid: read_u32(data, 24)?,
        gid: read_u32(data, 28)?,
        comm: read_c_string(&data[32..32 + COMM_LEN], "comm")?,
        filename: read_c_string(&data[32 + COMM_LEN..EXEC_EVENT_SIZE], "filename")?,
    })
}

fn decode_syscall(data: &[u8], header: EventHeader) -> Result<SyscallEvent, BpfError> {
    require_exact_size(data, SYSCALL_EVENT_SIZE, "syscall")?;
    let mut arguments = [0_u64; 6];
    for (index, argument) in arguments.iter_mut().enumerate() {
        *argument = read_u64(data, 40 + index * 8)?;
    }
    Ok(SyscallEvent {
        header,
        timestamp_ns: read_u64(data, 8)?,
        pid: read_u32(data, 16)?,
        tgid: read_u32(data, 20)?,
        uid: read_u32(data, 24)?,
        gid: read_u32(data, 28)?,
        syscall_id: read_u32(data, 32)?,
        arguments,
    })
}

fn decode_mcp(data: &[u8], header: EventHeader) -> Result<McpEvent, BpfError> {
    require_exact_size(data, MCP_EVENT_SIZE, "MCP")?;
    let payload_len = read_u32(data, 28)?;
    let captured_len = usize::try_from(read_u32(data, 32)?)
        .map_err(|_| decode_error("MCP captured length does not fit usize"))?;
    if captured_len > MCP_CAPTURE_LEN {
        return Err(decode_error(format!(
            "MCP captured length {captured_len} exceeds {MCP_CAPTURE_LEN}"
        )));
    }
    if u64::from(payload_len) < u64::try_from(captured_len).expect("bounded length fits u64") {
        return Err(decode_error(
            "MCP captured length exceeds declared payload length",
        ));
    }
    Ok(McpEvent {
        header,
        timestamp_ns: read_u64(data, 8)?,
        pid: read_u32(data, 16)?,
        tgid: read_u32(data, 20)?,
        direction: McpDirection::try_from(data[24])?,
        transport: McpTransport::try_from(data[25])?,
        payload_len,
        captured_payload: data[36..36 + captured_len].to_vec(),
    })
}

fn require_exact_size(data: &[u8], expected: usize, event: &str) -> Result<(), BpfError> {
    if data.len() == expected {
        Ok(())
    } else {
        Err(decode_error(format!(
            "malformed {event} event: received {} bytes, expected {expected}",
            data.len()
        )))
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, BpfError> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| decode_error("event ended before a u16 field"))?;
    Ok(u16::from_ne_bytes(
        bytes
            .try_into()
            .map_err(|_| decode_error("invalid u16 field width"))?,
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, BpfError> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| decode_error("event ended before a u32 field"))?;
    Ok(u32::from_ne_bytes(
        bytes
            .try_into()
            .map_err(|_| decode_error("invalid u32 field width"))?,
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, BpfError> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| decode_error("event ended before a u64 field"))?;
    Ok(u64::from_ne_bytes(
        bytes
            .try_into()
            .map_err(|_| decode_error("invalid u64 field width"))?,
    ))
}

fn read_c_string(bytes: &[u8], field: &str) -> Result<String, BpfError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| decode_error(format!("{field} is not NUL-terminated")))?;
    let value = std::str::from_utf8(&bytes[..end])
        .map_err(|error| decode_error(format!("{field} is not valid UTF-8: {error}")))?;
    Ok(value.to_owned())
}

fn decode_error(message: impl Into<String>) -> BpfError {
    BpfError::new(
        DiagnosticKind::DecodeFailure,
        "event_decode",
        message,
        "reject the event and verify the BPF object and Rust decoder use the same ABI",
    )
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn header(size: usize, kind: EventKind) -> Vec<u8> {
        let mut bytes = vec![0_u8; size];
        bytes[0..2].copy_from_slice(
            &u16::try_from(size)
                .expect("fixture size fits u16")
                .to_ne_bytes(),
        );
        bytes[2] = EVENT_SCHEMA_VERSION;
        bytes[3] = kind as u8;
        bytes
    }

    fn exec_fixture() -> Vec<u8> {
        let mut bytes = header(EXEC_EVENT_SIZE, EventKind::Exec);
        bytes[8..16].copy_from_slice(&42_u64.to_ne_bytes());
        bytes[16..20].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[24..28].copy_from_slice(&1000_u32.to_ne_bytes());
        bytes[28..32].copy_from_slice(&1001_u32.to_ne_bytes());
        bytes[32..36].copy_from_slice(b"true");
        bytes[48..57].copy_from_slice(b"/bin/true");
        bytes
    }

    #[test]
    fn decodes_exec_fixture_with_stable_json() {
        let event = Event::decode(&exec_fixture()).expect("valid event");
        let json = serde_json::to_string(&event).expect("JSON");
        assert!(json.contains(r#""event":"process_exec""#));
        assert!(json.contains(r#""filename":"/bin/true""#));
    }

    #[test]
    fn decodes_syscall_fixture() {
        let mut bytes = header(SYSCALL_EVENT_SIZE, EventKind::Syscall);
        bytes[32..36].copy_from_slice(&60_u32.to_ne_bytes());
        for index in 0..6 {
            let offset = 40 + index * 8;
            bytes[offset..offset + 8]
                .copy_from_slice(&u64::try_from(index).expect("index fits").to_ne_bytes());
        }
        let Event::SyscallEnter(event) = Event::decode(&bytes).expect("valid event") else {
            panic!("wrong event");
        };
        assert_eq!(event.syscall_id, 60);
        assert_eq!(event.arguments, [0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn decodes_bounded_mcp_fixture() {
        let mut bytes = header(MCP_EVENT_SIZE, EventKind::Mcp);
        bytes[24] = McpDirection::Request as u8;
        bytes[25] = McpTransport::Stdio as u8;
        bytes[28..32].copy_from_slice(&100_u32.to_ne_bytes());
        bytes[32..36].copy_from_slice(&4_u32.to_ne_bytes());
        bytes[36..40].copy_from_slice(b"ping");
        let Event::McpObservation(event) = Event::decode(&bytes).expect("valid event") else {
            panic!("wrong event");
        };
        assert_eq!(event.payload_len, 100);
        assert_eq!(event.captured_payload, b"ping");
    }

    #[test]
    fn rejects_loss_and_malformed_cases() {
        let mut oversized = exec_fixture();
        oversized.resize(MAX_EVENT_SIZE + 1, 0);
        assert!(Event::decode(&oversized).is_err());

        let mut wrong_size = exec_fixture();
        wrong_size[0..2].copy_from_slice(&1_u16.to_ne_bytes());
        assert!(Event::decode(&wrong_size).is_err());

        let mut unterminated = exec_fixture();
        unterminated[32..48].fill(b'x');
        assert!(Event::decode(&unterminated).is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = Event::decode(&bytes);
        }
    }
}
