use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libbpf_rs::{
    ErrorKind, Link, MapCore, Object, ObjectBuilder, PrintCallback, PrintLevel, RingBuffer,
    RingBufferBuilder, set_print,
};
use serde::Serialize;

use crate::diagnostic::{DiagnosticKind, SpikeError};
use crate::event::ExecEvent;
use crate::preflight::{inspect_host, require_live_ready};

const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/exec_observe.bpf.o"));
const PROGRAM_NAME: &str = "observe_exec";
const EVENTS_MAP_NAME: &str = "events";
const MAX_EVENTS_LIMIT: usize = 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(60);

static LIBBPF_LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static LIBBPF_CAPTURE: Mutex<()> = Mutex::new(());

#[derive(Debug, Serialize)]
pub struct AttachReport {
    pub schema_version: u8,
    pub status: &'static str,
    pub operation: &'static str,
    pub program: &'static str,
    pub map: &'static str,
    pub link_lifetime: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SelfTestReport {
    pub schema_version: u8,
    pub status: &'static str,
    pub operation: &'static str,
    pub spawned_pid: u32,
    pub observed_pid: u32,
    pub pid_namespace_match: bool,
    pub executed_path: String,
    pub observed_event: ExecEvent,
}

struct Attached {
    object: Object,
    _link: Link,
}

pub struct EventStream {
    _attached: Attached,
    ring_buffer: RingBuffer<'static>,
    events: Arc<Mutex<VecDeque<Result<ExecEvent, SpikeError>>>>,
}

impl EventStream {
    pub fn attach() -> Result<Self, SpikeError> {
        let report = inspect_host()?;
        require_live_ready(&report)?;
        let mut attached = load_and_attach()?;
        let events = Arc::new(Mutex::new(VecDeque::new()));
        let callback_events = Arc::clone(&events);
        let map = attached
            .object
            .maps_mut()
            .find(|map| map.name() == EVENTS_MAP_NAME)
            .ok_or_else(|| {
                SpikeError::new(
                    DiagnosticKind::LoadFailure,
                    "ring_buffer",
                    format!("BPF object does not contain map {EVENTS_MAP_NAME}"),
                    "rebuild the BPF object and guest binary together",
                )
            })?;
        let mut builder = RingBufferBuilder::new();
        builder
            .add(&map, move |data| {
                let decoded = ExecEvent::decode(data);
                match callback_events.lock() {
                    Ok(mut queue) => {
                        queue.push_back(decoded);
                        0
                    }
                    Err(_) => -5,
                }
            })
            .map_err(|error| classify_libbpf("ring_buffer", error, DiagnosticKind::LoadFailure))?;
        let ring_buffer = builder
            .build()
            .map_err(|error| classify_libbpf("ring_buffer", error, DiagnosticKind::LoadFailure))?;

        Ok(Self {
            _attached: attached,
            ring_buffer,
            events,
        })
    }

    pub fn collect(
        &self,
        max_events: usize,
        timeout: Duration,
    ) -> Result<Vec<ExecEvent>, SpikeError> {
        validate_bounds(max_events, timeout)?;
        let deadline = Instant::now() + timeout;
        let mut collected = Vec::new();

        while collected.len() < max_events {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            self.ring_buffer
                .poll(remaining.min(Duration::from_millis(100)))
                .map_err(|error| {
                    classify_libbpf("ring_buffer_poll", error, DiagnosticKind::LoadFailure)
                })?;
            let mut queue = self.events.lock().map_err(|_| {
                SpikeError::new(
                    DiagnosticKind::Internal,
                    "ring_buffer",
                    "event queue lock was poisoned",
                    "restart the guest helper and report the failure",
                )
            })?;
            while collected.len() < max_events {
                match queue.pop_front() {
                    Some(Ok(event)) => collected.push(event),
                    Some(Err(error)) => return Err(error),
                    None => break,
                }
            }
        }

        if collected.is_empty() {
            Err(SpikeError::new(
                DiagnosticKind::Timeout,
                "ring_buffer_poll",
                format!(
                    "no process-exec events arrived within {} ms",
                    timeout.as_millis()
                ),
                "run an executable while the events command is polling",
            ))
        } else {
            Ok(collected)
        }
    }
}

pub fn attach_once() -> Result<AttachReport, SpikeError> {
    let report = inspect_host()?;
    require_live_ready(&report)?;
    let _attached = load_and_attach()?;
    Ok(AttachReport {
        schema_version: 1,
        status: "passed",
        operation: "load_attach_probe",
        program: PROGRAM_NAME,
        map: EVENTS_MAP_NAME,
        link_lifetime: "command_scope",
    })
}

pub fn live_self_test() -> Result<SelfTestReport, SpikeError> {
    if std::env::var("SENDBOX_GUEST_BPF_LIVE").as_deref() != Ok("1") {
        return Err(SpikeError::new(
            DiagnosticKind::Unavailable,
            "self_test",
            "live BPF self-test is disabled",
            "set SENDBOX_GUEST_BPF_LIVE=1 only on a native privileged Linux test host",
        ));
    }

    let stream = EventStream::attach()?;
    let executable = SelfTestExecutable::create()?;
    let executed_path = executable.path().to_string_lossy().into_owned();
    let mut child = Command::new(executable.path())
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            SpikeError::new(
                DiagnosticKind::Unavailable,
                "self_test",
                format!("failed to spawn {executed_path}: {error}"),
                "provide an executable guest helper and a writable /tmp",
            )
        })?;
    let child_pid = child.id();
    let status = child.wait().map_err(|error| {
        SpikeError::new(
            DiagnosticKind::Unavailable,
            "self_test",
            format!("failed to wait for {executed_path}: {error}"),
            "verify process creation works in the guest",
        )
    })?;
    if !status.success() {
        return Err(SpikeError::new(
            DiagnosticKind::Unavailable,
            "self_test",
            format!("{executed_path} exited with {status}"),
            "repair the guest image before testing BPF",
        ));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SpikeError::new(
                DiagnosticKind::Timeout,
                "self_test",
                format!("attached successfully but did not observe {executed_path}"),
                "verify tracepoint availability and ring-buffer event delivery",
            ));
        }
        let events =
            match stream.collect(MAX_EVENTS_LIMIT, remaining.min(Duration::from_millis(250))) {
                Ok(events) => events,
                Err(error) if error.kind == DiagnosticKind::Timeout => continue,
                Err(error) => return Err(error),
            };
        for event in events {
            if event.filename == executed_path {
                return Ok(SelfTestReport {
                    schema_version: 1,
                    status: "passed",
                    operation: "native_attach_and_event_delivery",
                    spawned_pid: child_pid,
                    observed_pid: event.pid,
                    pid_namespace_match: event.pid == child_pid,
                    executed_path,
                    observed_event: event,
                });
            }
        }
    }
}

fn load_and_attach() -> Result<Attached, SpikeError> {
    let mut builder = ObjectBuilder::default();
    let open_object = capture_libbpf_logs(|| builder.open_memory(BPF_OBJECT))
        .map_err(|error| classify_libbpf("object_open", error, DiagnosticKind::LoadFailure))?;
    let object = capture_libbpf_logs(|| open_object.load())
        .map_err(|error| classify_libbpf("object_load", error, DiagnosticKind::LoadFailure))?;
    let program = object
        .progs_mut()
        .find(|program| program.name() == PROGRAM_NAME)
        .ok_or_else(|| {
            SpikeError::new(
                DiagnosticKind::LoadFailure,
                "object_load",
                format!("BPF object does not contain program {PROGRAM_NAME}"),
                "rebuild the BPF object and guest binary together",
            )
        })?;
    let link = capture_libbpf_logs(|| program.attach())
        .map_err(|error| classify_libbpf("program_attach", error, DiagnosticKind::AttachFailure))?;
    Ok(Attached {
        object,
        _link: link,
    })
}

fn validate_bounds(max_events: usize, timeout: Duration) -> Result<(), SpikeError> {
    if !(1..=MAX_EVENTS_LIMIT).contains(&max_events) {
        return Err(SpikeError::new(
            DiagnosticKind::InvalidInput,
            "events",
            format!("max-events must be between 1 and {MAX_EVENTS_LIMIT}"),
            "choose a bounded event count",
        ));
    }
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(SpikeError::new(
            DiagnosticKind::InvalidInput,
            "events",
            "timeout must be between 1 ms and 60000 ms",
            "choose a bounded polling timeout",
        ));
    }
    Ok(())
}

fn capture_libbpf_logs<T>(
    operation: impl FnOnce() -> Result<T, libbpf_rs::Error>,
) -> Result<T, libbpf_rs::Error> {
    let _capture = LIBBPF_CAPTURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    LIBBPF_LOGS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    let previous = set_print(Some((PrintLevel::Debug, record_libbpf_log)));
    let _restore = PrintRestore { previous };
    operation()
}

fn record_libbpf_log(_level: PrintLevel, message: String) {
    LIBBPF_LOGS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(message);
}

fn classify_libbpf(
    stage: &'static str,
    error: libbpf_rs::Error,
    default_kind: DiagnosticKind,
) -> SpikeError {
    let logs = LIBBPF_LOGS
        .lock()
        .map(|messages| messages.join(""))
        .unwrap_or_default();
    let detail = format!("{error:#}; {logs}");
    let lower = detail.to_ascii_lowercase();
    let kind = classify_kind(error.kind(), &lower, default_kind);
    let action = match kind {
        DiagnosticKind::PermissionDenied => {
            "grant the required BPF/perf capabilities and permit the bpf syscall"
        }
        DiagnosticKind::RelocationFailure => {
            "verify host BTF compatibility and rebuild from the pinned architecture-specific BTF"
        }
        DiagnosticKind::AttachFailure => {
            "verify the sched_process_exec tracepoint exists and attachment is permitted"
        }
        _ => "inspect the libbpf diagnostic and kernel verifier log",
    };
    SpikeError::new(kind, stage, detail.trim().to_owned(), action)
}

fn classify_kind(
    error_kind: ErrorKind,
    detail: &str,
    default_kind: DiagnosticKind,
) -> DiagnosticKind {
    if error_kind == ErrorKind::PermissionDenied {
        DiagnosticKind::PermissionDenied
    } else if [
        "relocation failed",
        "failed to relocate",
        "failed co-re relocation",
        "co-re relocation failed",
        "failed to perform co-re",
    ]
    .iter()
    .any(|message| detail.contains(message))
    {
        DiagnosticKind::RelocationFailure
    } else {
        default_kind
    }
}

struct PrintRestore {
    previous: Option<(PrintLevel, PrintCallback)>,
}

impl Drop for PrintRestore {
    fn drop(&mut self) {
        set_print(self.previous.take());
    }
}

struct SelfTestExecutable {
    path: PathBuf,
}

impl SelfTestExecutable {
    fn create() -> Result<Self, SpikeError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                SpikeError::new(
                    DiagnosticKind::Unavailable,
                    "self_test",
                    format!("system clock is before the Unix epoch: {error}"),
                    "repair the guest clock before running the live self-test",
                )
            })?
            .as_nanos();
        let path = PathBuf::from(format!(
            "/tmp/sendbox-bpf-selftest-{}-{nonce}",
            std::process::id()
        ));
        let source = std::env::current_exe().map_err(|error| {
            SpikeError::new(
                DiagnosticKind::Unavailable,
                "self_test",
                format!("failed to locate the guest helper executable: {error}"),
                "run the self-test from an executable guest helper",
            )
        })?;
        std::fs::copy(&source, &path).map_err(|error| {
            SpikeError::new(
                DiagnosticKind::Unavailable,
                "self_test",
                format!(
                    "failed to copy {} to {}: {error}",
                    source.display(),
                    path.display()
                ),
                "provide a writable /tmp in the guest image",
            )
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SelfTestExecutable {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unbounded_event_count() {
        let error = validate_bounds(0, Duration::from_secs(1)).expect_err("must reject");
        assert_eq!(error.kind, DiagnosticKind::InvalidInput);
        let error =
            validate_bounds(MAX_EVENTS_LIMIT + 1, Duration::from_secs(1)).expect_err("must reject");
        assert_eq!(error.kind, DiagnosticKind::InvalidInput);
    }

    #[test]
    fn rejects_unbounded_timeout() {
        let error = validate_bounds(1, Duration::ZERO).expect_err("must reject");
        assert_eq!(error.kind, DiagnosticKind::InvalidInput);
        let error =
            validate_bounds(1, MAX_TIMEOUT + Duration::from_millis(1)).expect_err("must reject");
        assert_eq!(error.kind, DiagnosticKind::InvalidInput);
    }

    #[test]
    fn distinguishes_permission_relocation_load_and_attach_failures() {
        assert_eq!(
            classify_kind(
                ErrorKind::PermissionDenied,
                "operation not permitted",
                DiagnosticKind::LoadFailure
            ),
            DiagnosticKind::PermissionDenied
        );
        assert_eq!(
            classify_kind(
                ErrorKind::InvalidData,
                "co-re relocation failed",
                DiagnosticKind::LoadFailure
            ),
            DiagnosticKind::RelocationFailure
        );
        assert_eq!(
            classify_kind(
                ErrorKind::InvalidData,
                "verifier rejected program",
                DiagnosticKind::LoadFailure
            ),
            DiagnosticKind::LoadFailure
        );
        assert_eq!(
            classify_kind(
                ErrorKind::InvalidData,
                "tracepoint missing",
                DiagnosticKind::AttachFailure
            ),
            DiagnosticKind::AttachFailure
        );
    }

    #[test]
    fn embedded_core_object_is_compiled_elf() {
        assert!(BPF_OBJECT.len() > 1024);
        assert_eq!(&BPF_OBJECT[..4], b"\x7fELF");
    }
}
