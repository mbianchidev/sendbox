use sendbox_bpf::{
    EVENT_SCHEMA_VERSION, Event, EventHeader, EventKind, EventStream, SyscallEvent,
    report::{MAX_TRACE_SAMPLES, TraceArchitecture, TraceReport},
};
use sendbox_core::SessionId;
use std::path::Path;

#[test]
fn tree_attachment_cannot_succeed_without_a_supported_delegated_cgroup() {
    assert!(
        EventStream::attach_cgroup_tree(
            b"invalid-object",
            Path::new("/nonexistent-sendbox-cgroup")
        )
        .is_err()
    );
}

#[test]
fn syscall_reports_are_session_bound_bounded_and_argument_free() {
    let session = SessionId::from_bytes([9; 16]);
    let mut report = TraceReport::new(session, TraceArchitecture::Aarch64);
    for timestamp in 0..MAX_TRACE_SAMPLES + 4 {
        report
            .record(&Event::SyscallEnter(SyscallEvent {
                header: EventHeader {
                    size: 88,
                    version: EVENT_SCHEMA_VERSION,
                    kind: EventKind::Syscall,
                    flags: 0,
                },
                timestamp_ns: timestamp as u64,
                pid: 77,
                tgid: 77,
                uid: 1000,
                gid: 1000,
                syscall_id: 42,
                arguments: [0xdead_beef; 6],
            }))
            .expect("record observation");
    }
    report.validate(session).expect("valid report");
    assert_eq!(report.samples.len(), MAX_TRACE_SAMPLES);
    assert_eq!(report.sampled_out, 4);
    assert_eq!(report.syscall_counts[&42], (MAX_TRACE_SAMPLES + 4) as u64);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("arguments"));
    assert!(!json.contains("3735928559"));
    assert!(report.validate(SessionId::from_bytes([8; 16])).is_err());
    let mut tampered = serde_json::to_value(report).unwrap();
    tampered["samples"][0]["arguments"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<TraceReport>(tampered).is_err());
}
