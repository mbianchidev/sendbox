use std::collections::BTreeMap;

use sendbox_core::SessionId;
use serde::{Deserialize, Serialize};

use crate::{Event, LossSnapshot};

pub const TRACE_REPORT_SCHEMA_VERSION: u32 = 1;
pub const MAX_TRACE_REPORT_BYTES: usize = 96 * 1024;
pub const MAX_TRACE_SAMPLES: usize = 256;
const MAX_SYSCALL_COUNTERS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceArchitecture {
    X86_64,
    Aarch64,
}

impl TraceArchitecture {
    pub fn current() -> Result<Self, String> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            _ => Err("syscall observation requires x86_64 or aarch64".to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceSampleKind {
    Exec,
    Syscall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceSample {
    pub kind: TraceSampleKind,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceReport {
    pub schema_version: u32,
    pub session_id: SessionId,
    pub architecture: TraceArchitecture,
    pub observed_events: u64,
    pub sampled_out: u64,
    pub uncounted_syscalls: u64,
    pub log_limit_reached: bool,
    pub losses: LossSnapshot,
    pub syscall_counts: BTreeMap<u32, u64>,
    pub samples: Vec<TraceSample>,
}

impl TraceReport {
    #[must_use]
    pub fn new(session_id: SessionId, architecture: TraceArchitecture) -> Self {
        Self {
            schema_version: TRACE_REPORT_SCHEMA_VERSION,
            session_id,
            architecture,
            observed_events: 0,
            sampled_out: 0,
            uncounted_syscalls: 0,
            log_limit_reached: false,
            losses: LossSnapshot::default(),
            syscall_counts: BTreeMap::new(),
            samples: Vec::new(),
        }
    }

    pub fn record(&mut self, event: &Event) -> Result<TraceSample, String> {
        let sample = match event {
            Event::ProcessExec(event) => TraceSample {
                kind: TraceSampleKind::Exec,
                timestamp_ns: event.timestamp_ns,
                pid: event.pid,
                tgid: event.tgid,
                syscall_id: None,
            },
            Event::SyscallEnter(event) => TraceSample {
                kind: TraceSampleKind::Syscall,
                timestamp_ns: event.timestamp_ns,
                pid: event.pid,
                tgid: event.tgid,
                syscall_id: Some(event.syscall_id),
            },
            Event::McpObservation(_) => {
                return Err("MCP payloads do not belong in syscall reports".to_owned());
            }
        };
        self.observed_events = increment(self.observed_events)?;
        if let Some(id) = sample.syscall_id {
            if self.syscall_counts.len() < MAX_SYSCALL_COUNTERS
                || self.syscall_counts.contains_key(&id)
            {
                let count = self.syscall_counts.entry(id).or_default();
                *count = increment(*count)?;
            } else {
                self.uncounted_syscalls = increment(self.uncounted_syscalls)?;
            }
        }
        if self.samples.len() < MAX_TRACE_SAMPLES {
            self.samples.push(sample.clone());
        } else {
            self.sampled_out = increment(self.sampled_out)?;
        }
        Ok(sample)
    }

    pub fn validate(&self, expected_session: SessionId) -> Result<(), String> {
        if self.schema_version != TRACE_REPORT_SCHEMA_VERSION || self.session_id != expected_session
        {
            return Err("syscall report schema or session does not match".to_owned());
        }
        if self.samples.len() > MAX_TRACE_SAMPLES
            || self.syscall_counts.len() > MAX_SYSCALL_COUNTERS
        {
            return Err("syscall report exceeds its collection bounds".to_owned());
        }
        if self.observed_events.checked_sub(self.samples.len() as u64) != Some(self.sampled_out) {
            return Err("syscall report sample accounting is inconsistent".to_owned());
        }
        let counted = self
            .syscall_counts
            .values()
            .try_fold(0_u64, |total, count| {
                total
                    .checked_add(*count)
                    .ok_or_else(|| "syscall report counters overflowed".to_owned())
            })?;
        if counted
            .checked_add(self.uncounted_syscalls)
            .is_none_or(|count| count > self.observed_events)
        {
            return Err("syscall report counters exceed observed events".to_owned());
        }
        if self.samples.iter().any(|sample| {
            sample.pid == 0
                || sample.tgid == 0
                || (sample.kind == TraceSampleKind::Syscall) != sample.syscall_id.is_some()
        }) {
            return Err("syscall report contains an invalid sample".to_owned());
        }
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_TRACE_REPORT_BYTES {
            return Err("syscall report exceeds the protocol byte limit".to_owned());
        }
        Ok(())
    }
}

fn increment(value: u64) -> Result<u64, String> {
    value
        .checked_add(1)
        .ok_or_else(|| "syscall observation counter overflowed".to_owned())
}
