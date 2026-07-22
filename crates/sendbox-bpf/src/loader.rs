use std::time::Duration;

use serde::Serialize;

use crate::{BpfError, DiagnosticKind, Event};

pub const MAX_EVENTS_PER_COLLECTION: usize = 4096;
pub const MAX_POLL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachConfig {
    pub target_cgroup_id: u64,
}

impl AttachConfig {
    pub fn validate(self) -> Result<Self, BpfError> {
        if self.target_cgroup_id == 0 {
            return Err(BpfError::new(
                DiagnosticKind::InvalidInput,
                "attach",
                "target cgroup id must be non-zero",
                "resolve the sandbox cgroup id before attaching observation programs",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct LossSnapshot {
    pub kernel_ring_reserve_failures: u64,
    pub userspace_queue_drops: u64,
    pub decode_failures: u64,
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use libbpf_rs::{
        ErrorKind, Link, MapCore, MapFlags, Object, ObjectBuilder, PrintCallback, PrintLevel,
        RingBuffer, RingBufferBuilder, set_print,
    };

    use super::{
        AttachConfig, BpfError, DiagnosticKind, Event, LossSnapshot, MAX_EVENTS_PER_COLLECTION,
        MAX_POLL_TIMEOUT,
    };
    use crate::preflight::{inspect_host, require_live_ready};

    const EVENTS_MAP: &str = "events";
    const LOSSES_MAP: &str = "losses";
    const SCOPE_MAP: &str = "scope";
    const PROGRAMS: [&str; 2] = ["observe_exec", "observe_sys_enter"];
    const MAX_QUEUED_EVENTS: usize = 4096;

    static LIBBPF_LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static LIBBPF_CAPTURE: Mutex<()> = Mutex::new(());

    struct Attached {
        object: Object,
        _links: Vec<Link>,
    }

    pub struct EventStream {
        attached: Attached,
        ring_buffer: RingBuffer<'static>,
        events: Arc<Mutex<VecDeque<Result<Event, BpfError>>>>,
        userspace_queue_drops: Arc<AtomicU64>,
        decode_failures: Arc<AtomicU64>,
    }

    impl EventStream {
        pub fn attach(object_bytes: &[u8], config: AttachConfig) -> Result<Self, BpfError> {
            let config = config.validate()?;
            let report = inspect_host()?;
            require_live_ready(&report)?;
            let mut attached = load_and_attach(object_bytes, config)?;
            let events = Arc::new(Mutex::new(VecDeque::new()));
            let userspace_queue_drops = Arc::new(AtomicU64::new(0));
            let decode_failures = Arc::new(AtomicU64::new(0));
            let callback_events = Arc::clone(&events);
            let callback_drops = Arc::clone(&userspace_queue_drops);
            let callback_decode_failures = Arc::clone(&decode_failures);
            let map = attached
                .object
                .maps_mut()
                .find(|map| map.name() == EVENTS_MAP)
                .ok_or_else(|| missing_object_member("map", EVENTS_MAP))?;
            let mut builder = RingBufferBuilder::new();
            builder
                .add(&map, move |data| {
                    let decoded = Event::decode(data);
                    if decoded.is_err() {
                        callback_decode_failures.fetch_add(1, Ordering::Relaxed);
                    }
                    match callback_events.lock() {
                        Ok(mut queue) if queue.len() < MAX_QUEUED_EVENTS => {
                            queue.push_back(decoded);
                            0
                        }
                        Ok(_) => {
                            callback_drops.fetch_add(1, Ordering::Relaxed);
                            0
                        }
                        Err(_) => -5,
                    }
                })
                .map_err(|error| {
                    classify_libbpf("ring_buffer", error, DiagnosticKind::LoadFailure)
                })?;
            let ring_buffer = builder.build().map_err(|error| {
                classify_libbpf("ring_buffer", error, DiagnosticKind::LoadFailure)
            })?;
            Ok(Self {
                attached,
                ring_buffer,
                events,
                userspace_queue_drops,
                decode_failures,
            })
        }

        pub fn collect(
            &self,
            max_events: usize,
            timeout: Duration,
        ) -> Result<Vec<Event>, BpfError> {
            validate_collection_bounds(max_events, timeout)?;
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
                    BpfError::new(
                        DiagnosticKind::Internal,
                        "ring_buffer",
                        "event queue lock was poisoned",
                        "restart the observation consumer and report the failure",
                    )
                })?;
                drain_events(&mut queue, &mut collected, max_events)?;
            }
            Ok(collected)
        }

        pub fn losses(&self) -> Result<LossSnapshot, BpfError> {
            let map = self
                .attached
                .object
                .maps()
                .find(|map| map.name() == LOSSES_MAP)
                .ok_or_else(|| missing_object_member("map", LOSSES_MAP))?;
            let value = map
                .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)
                .map_err(|error| {
                    classify_libbpf("loss_lookup", error, DiagnosticKind::LoadFailure)
                })?
                .ok_or_else(|| {
                    BpfError::new(
                        DiagnosticKind::LoadFailure,
                        "loss_lookup",
                        "loss counter map did not contain key zero",
                        "rebuild the BPF object from the production source",
                    )
                })?;
            let kernel_ring_reserve_failures = value
                .get(..8)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map(u64::from_ne_bytes)
                .ok_or_else(|| {
                    BpfError::new(
                        DiagnosticKind::DecodeFailure,
                        "loss_lookup",
                        "loss counter value has an invalid width",
                        "rebuild the BPF object and Rust facade from the same ABI",
                    )
                })?;
            Ok(LossSnapshot {
                kernel_ring_reserve_failures,
                userspace_queue_drops: self.userspace_queue_drops.load(Ordering::Relaxed),
                decode_failures: self.decode_failures.load(Ordering::Relaxed),
            })
        }
    }

    fn load_and_attach(object_bytes: &[u8], config: AttachConfig) -> Result<Attached, BpfError> {
        let mut builder = ObjectBuilder::default();
        let open = capture_libbpf_logs(|| builder.open_memory(object_bytes))
            .map_err(|error| classify_libbpf("object_open", error, DiagnosticKind::LoadFailure))?;
        let mut object = capture_libbpf_logs(|| open.load())
            .map_err(|error| classify_libbpf("object_load", error, DiagnosticKind::LoadFailure))?;
        let scope = object
            .maps_mut()
            .find(|map| map.name() == SCOPE_MAP)
            .ok_or_else(|| missing_object_member("map", SCOPE_MAP))?;
        scope
            .update(
                &0_u32.to_ne_bytes(),
                &config.target_cgroup_id.to_ne_bytes(),
                MapFlags::ANY,
            )
            .map_err(|error| classify_libbpf("scope_update", error, DiagnosticKind::LoadFailure))?;

        let mut links = Vec::with_capacity(PROGRAMS.len());
        for name in PROGRAMS {
            let program = object
                .progs_mut()
                .find(|program| program.name() == name)
                .ok_or_else(|| missing_object_member("program", name))?;
            let link = capture_libbpf_logs(|| program.attach()).map_err(|error| {
                classify_libbpf("program_attach", error, DiagnosticKind::AttachFailure)
            })?;
            links.push(link);
        }
        Ok(Attached {
            object,
            _links: links,
        })
    }

    fn validate_collection_bounds(max_events: usize, timeout: Duration) -> Result<(), BpfError> {
        if !(1..=MAX_EVENTS_PER_COLLECTION).contains(&max_events) {
            return Err(BpfError::new(
                DiagnosticKind::InvalidInput,
                "collect",
                format!("max events must be between 1 and {MAX_EVENTS_PER_COLLECTION}"),
                "choose a bounded event count",
            ));
        }
        if timeout.is_zero() || timeout > MAX_POLL_TIMEOUT {
            return Err(BpfError::new(
                DiagnosticKind::InvalidInput,
                "collect",
                "timeout must be between 1 ms and 60000 ms",
                "choose a bounded polling timeout",
            ));
        }
        Ok(())
    }

    fn drain_events(
        queue: &mut VecDeque<Result<Event, BpfError>>,
        collected: &mut Vec<Event>,
        max_events: usize,
    ) -> Result<(), BpfError> {
        while collected.len() < max_events {
            match queue.pop_front() {
                Some(Ok(event)) => collected.push(event),
                Some(Err(error)) if collected.is_empty() => return Err(error),
                Some(Err(error)) => {
                    queue.push_front(Err(error));
                    break;
                }
                None => break,
            }
        }
        Ok(())
    }

    fn missing_object_member(kind: &str, name: &str) -> BpfError {
        BpfError::new(
            DiagnosticKind::LoadFailure,
            "object_load",
            format!("BPF object does not contain {kind} {name}"),
            "rebuild the BPF object from the production source",
        )
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
    ) -> BpfError {
        let logs = LIBBPF_LOGS
            .lock()
            .map(|messages| messages.join(""))
            .unwrap_or_default();
        let detail = format!("{error:#}; {logs}");
        let lower = detail.to_ascii_lowercase();
        let kind = if error.kind() == ErrorKind::PermissionDenied {
            DiagnosticKind::PermissionDenied
        } else if [
            "relocation failed",
            "failed to relocate",
            "failed co-re relocation",
            "co-re relocation failed",
            "failed to perform co-re",
        ]
        .iter()
        .any(|message| lower.contains(message))
        {
            DiagnosticKind::RelocationFailure
        } else {
            default_kind
        };
        let action = match kind {
            DiagnosticKind::PermissionDenied => {
                "grant required BPF/perf capabilities and permit the bpf syscall"
            }
            DiagnosticKind::RelocationFailure => {
                "verify host BTF compatibility and the pinned CO-RE build inputs"
            }
            DiagnosticKind::AttachFailure => {
                "verify required tracepoints exist and attachment is permitted"
            }
            _ => "inspect the libbpf diagnostic and kernel verifier log",
        };
        BpfError::new(kind, stage, detail.trim(), action)
    }

    struct PrintRestore {
        previous: Option<(PrintLevel, PrintCallback)>,
    }

    impl Drop for PrintRestore {
        fn drop(&mut self) {
            set_print(self.previous.take());
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{EventHeader, EventKind, ExecEvent};

        #[test]
        fn rejects_unbounded_collection() {
            assert!(validate_collection_bounds(0, Duration::from_secs(1)).is_err());
            assert!(
                validate_collection_bounds(MAX_EVENTS_PER_COLLECTION + 1, Duration::from_secs(1))
                    .is_err()
            );
            assert!(validate_collection_bounds(1, Duration::ZERO).is_err());
            assert!(
                validate_collection_bounds(1, MAX_POLL_TIMEOUT + Duration::from_millis(1)).is_err()
            );
        }

        #[test]
        fn preserves_decode_error_after_returning_valid_batch() {
            let event = Event::ProcessExec(ExecEvent {
                header: EventHeader {
                    size: 176,
                    version: 1,
                    kind: EventKind::Exec,
                    flags: 0,
                },
                timestamp_ns: 1,
                pid: 2,
                tgid: 2,
                uid: 3,
                gid: 4,
                comm: "true".to_owned(),
                filename: "/bin/true".to_owned(),
            });
            let error = BpfError::new(
                DiagnosticKind::DecodeFailure,
                "event_decode",
                "malformed event",
                "reject it",
            );
            let mut queue = VecDeque::from([Ok(event), Err(error)]);
            let mut collected = Vec::new();
            drain_events(&mut queue, &mut collected, 2).expect("valid batch returned");
            assert_eq!(collected.len(), 1);
            assert_eq!(queue.len(), 1);

            let error = drain_events(&mut queue, &mut Vec::new(), 1)
                .expect_err("preserved decode error surfaced");
            assert_eq!(error.kind, DiagnosticKind::DecodeFailure);
            assert!(queue.is_empty());
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::EventStream;

#[cfg(not(target_os = "linux"))]
pub struct EventStream;

#[cfg(not(target_os = "linux"))]
impl EventStream {
    pub fn attach(_object_bytes: &[u8], config: AttachConfig) -> Result<Self, BpfError> {
        config.validate()?;
        Err(BpfError::new(
            DiagnosticKind::UnsupportedHost,
            "attach",
            format!("BPF loading is unsupported on {}", std::env::consts::OS),
            "load the production BPF object on Linux",
        ))
    }

    pub fn collect(&self, _max_events: usize, _timeout: Duration) -> Result<Vec<Event>, BpfError> {
        Err(BpfError::new(
            DiagnosticKind::UnsupportedHost,
            "collect",
            "BPF event collection is unsupported on this host",
            "collect events on Linux",
        ))
    }

    pub fn losses(&self) -> Result<LossSnapshot, BpfError> {
        Err(BpfError::new(
            DiagnosticKind::UnsupportedHost,
            "loss_lookup",
            "BPF loss accounting is unsupported on this host",
            "query BPF losses on Linux",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_cgroup_scope_is_rejected() {
        let error = AttachConfig {
            target_cgroup_id: 0,
        }
        .validate()
        .expect_err("zero scope must fail");
        assert_eq!(error.kind, DiagnosticKind::InvalidInput);
    }
}
