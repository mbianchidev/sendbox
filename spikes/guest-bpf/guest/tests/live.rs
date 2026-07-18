#![forbid(unsafe_code)]

use sendbox_guest_bpf::loader::live_self_test;

#[test]
fn native_live_attach_and_event_delivery() {
    if std::env::var("SENDBOX_GUEST_BPF_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set SENDBOX_GUEST_BPF_LIVE=1 on a privileged native Linux host");
        return;
    }

    let report = live_self_test().expect("live BPF self-test");
    assert_eq!(report.status, "passed");
    assert_eq!(report.observed_event.filename, report.executed_path);
}
