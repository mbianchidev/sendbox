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
    fs::metadata(current_cgroup_path())
        .expect("stat current cgroup")
        .ino()
}

fn current_cgroup_path() -> PathBuf {
    let cgroup = fs::read_to_string("/proc/self/cgroup").expect("read cgroup membership");
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("unified cgroup v2 membership");
    PathBuf::from("/sys/fs/cgroup").join(relative.trim_start_matches('/'))
}

#[test]
fn observes_descendants_of_the_execution_cgroup_when_explicitly_enabled() {
    if std::env::var("SENDBOX_BPF_LIVE").as_deref() != Ok("1") {
        return;
    }
    struct OwnedCgroup(PathBuf);
    impl Drop for OwnedCgroup {
        fn drop(&mut self) {
            if let Err(error) = fs::remove_dir(&self.0) {
                eprintln!(
                    "could not remove owned trace cgroup {}: {error}",
                    self.0.display()
                );
            }
        }
    }
    let parent = current_cgroup_path().join(format!("sendbox-bpf-test-{}", std::process::id()));
    fs::create_dir(&parent).expect("owned trace cgroup");
    let parent = OwnedCgroup(parent);
    let leaf = parent.0.join("command");
    fs::create_dir(&leaf).expect("descendant execution cgroup");
    let leaf = OwnedCgroup(leaf);
    let object = fs::read(std::env::var_os("SENDBOX_BPF_OBJECT").expect("BPF object")).unwrap();
    let stream = EventStream::attach_cgroup_tree(&object, &parent.0).expect("attach cgroup tree");
    assert!(
        Command::new("/bin/sh")
            .args([
                "-c",
                "printf '%s' $$ > \"$1/cgroup.procs\"; exec /bin/true",
                "sendbox-bpf-test"
            ])
            .arg(&leaf.0)
            .env_clear()
            .status()
            .expect("synthetic descendant")
            .success()
    );
    let events = stream
        .collect(4096, Duration::from_secs(2))
        .expect("descendant events");
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ProcessExec(exec) if exec.filename == "/bin/true"))
    );
}
