use serde::Serialize;

use crate::diagnostic::{DiagnosticKind, SpikeError};

pub const COMM_LEN: usize = 16;
pub const FILENAME_LEN: usize = 128;
pub const EVENT_SIZE: usize = 8 + (4 * 4) + COMM_LEN + FILENAME_LEN;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecEvent {
    pub schema_version: u8,
    pub event: &'static str,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub filename: String,
}

impl ExecEvent {
    pub fn decode(data: &[u8]) -> Result<Self, SpikeError> {
        if data.len() > EVENT_SIZE {
            return Err(SpikeError::new(
                DiagnosticKind::DecodeFailure,
                "event_decode",
                format!(
                    "oversized exec event: received {} bytes, maximum is {EVENT_SIZE}",
                    data.len()
                ),
                "reject the producer and verify the BPF/Rust event schema versions match",
            ));
        }
        if data.len() < EVENT_SIZE {
            return Err(SpikeError::new(
                DiagnosticKind::DecodeFailure,
                "event_decode",
                format!(
                    "malformed exec event: received {} bytes, expected {EVENT_SIZE}",
                    data.len()
                ),
                "verify the BPF object and guest binary were built from the same source",
            ));
        }

        let timestamp_ns = read_u64(data, 0)?;
        let pid = read_u32(data, 8)?;
        let tgid = read_u32(data, 12)?;
        let uid = read_u32(data, 16)?;
        let gid = read_u32(data, 20)?;
        let comm = read_c_string(&data[24..24 + COMM_LEN], "comm")?;
        let filename = read_c_string(&data[24 + COMM_LEN..EVENT_SIZE], "filename")?;

        Ok(Self {
            schema_version: 1,
            event: "process_exec",
            timestamp_ns,
            pid,
            tgid,
            uid,
            gid,
            comm,
            filename,
        })
    }
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, SpikeError> {
    let bytes = data.get(offset..offset + 8).ok_or_else(|| {
        SpikeError::new(
            DiagnosticKind::DecodeFailure,
            "event_decode",
            "event ended before a u64 field",
            "verify the BPF/Rust event schema versions match",
        )
    })?;
    let array: [u8; 8] = bytes.try_into().map_err(|_| {
        SpikeError::new(
            DiagnosticKind::DecodeFailure,
            "event_decode",
            "invalid u64 field width",
            "verify the BPF/Rust event schema versions match",
        )
    })?;
    Ok(u64::from_ne_bytes(array))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, SpikeError> {
    let bytes = data.get(offset..offset + 4).ok_or_else(|| {
        SpikeError::new(
            DiagnosticKind::DecodeFailure,
            "event_decode",
            "event ended before a u32 field",
            "verify the BPF/Rust event schema versions match",
        )
    })?;
    let array: [u8; 4] = bytes.try_into().map_err(|_| {
        SpikeError::new(
            DiagnosticKind::DecodeFailure,
            "event_decode",
            "invalid u32 field width",
            "verify the BPF/Rust event schema versions match",
        )
    })?;
    Ok(u32::from_ne_bytes(array))
}

fn read_c_string(bytes: &[u8], field: &'static str) -> Result<String, SpikeError> {
    let end = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        SpikeError::new(
            DiagnosticKind::DecodeFailure,
            "event_decode",
            format!("{field} is not NUL-terminated"),
            "reject the event and verify the BPF producer bounded the string",
        )
    })?;
    let value = std::str::from_utf8(&bytes[..end]).map_err(|error| {
        SpikeError::new(
            DiagnosticKind::DecodeFailure,
            "event_decode",
            format!("{field} is not valid UTF-8: {error}"),
            "reject the malformed event",
        )
    })?;
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic_json;

    fn sample_bytes() -> Vec<u8> {
        let mut bytes = vec![0_u8; EVENT_SIZE];
        bytes[0..8].copy_from_slice(&42_u64.to_ne_bytes());
        bytes[8..12].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[16..20].copy_from_slice(&1000_u32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&1001_u32.to_ne_bytes());
        bytes[24..28].copy_from_slice(b"true");
        let filename_offset = 24 + COMM_LEN;
        bytes[filename_offset..filename_offset + 9].copy_from_slice(b"/bin/true");
        bytes
    }

    #[test]
    fn decodes_event_and_emits_stable_json() {
        let event = ExecEvent::decode(&sample_bytes()).expect("valid event");
        assert_eq!(
            deterministic_json(&event).expect("JSON"),
            r#"{"schema_version":1,"event":"process_exec","timestamp_ns":42,"pid":7,"tgid":7,"uid":1000,"gid":1001,"comm":"true","filename":"/bin/true"}"#
        );
    }

    #[test]
    fn rejects_malformed_event() {
        let error = ExecEvent::decode(&sample_bytes()[..EVENT_SIZE - 1]).expect_err("must reject");
        assert_eq!(error.kind, DiagnosticKind::DecodeFailure);
        assert!(error.message.contains("malformed"));
    }

    #[test]
    fn rejects_oversized_event() {
        let mut bytes = sample_bytes();
        bytes.push(0);
        let error = ExecEvent::decode(&bytes).expect_err("must reject");
        assert_eq!(error.kind, DiagnosticKind::DecodeFailure);
        assert!(error.message.contains("oversized"));
    }

    #[test]
    fn rejects_unterminated_string() {
        let mut bytes = sample_bytes();
        bytes[24..24 + COMM_LEN].fill(b'x');
        let error = ExecEvent::decode(&bytes).expect_err("must reject");
        assert!(error.message.contains("NUL-terminated"));
    }
}
