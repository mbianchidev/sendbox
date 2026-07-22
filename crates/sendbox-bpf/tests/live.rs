#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use sendbox_bpf::{AttachConfig, Event, EventStream};

#[test]
fn observes_exec_and_syscall_events_when_explicitly_enabled() {
    if std::env::var("SENDBOX_BPF_LIVE").as_deref() != Ok("1") {
        return;
    }
    let object = PathBuf::from(
        std::env::var_os("SENDBOX_BPF_OBJECT").expect("SENDBOX_BPF_OBJECT must name observe.bpf.o"),
    );
    let bytes = fs::read(&object).expect("read BPF object");
    let stream = EventStream::attach(
        &bytes,
        AttachConfig {
            target_cgroup_id: current_cgroup_id(),
        },
    )
    .expect("attach observation programs");
    let status = Command::new("/bin/true").status().expect("spawn /bin/true");
    assert!(status.success());
    let events = stream
        .collect(1024, Duration::from_secs(5))
        .expect("collect events");
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ProcessExec(exec) if exec.filename == "/bin/true"))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::SyscallEnter(_)))
    );
}

fn current_cgroup_id() -> u64 {
    let cgroup = fs::read_to_string("/proc/self/cgroup").expect("read cgroup membership");
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("unified cgroup v2 membership");
    let path = PathBuf::from("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    fs::metadata(path).expect("stat current cgroup").ino()
}
