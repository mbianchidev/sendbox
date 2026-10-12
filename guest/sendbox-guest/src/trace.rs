use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sendbox_bpf::report::MAX_TRACE_REPORT_BYTES;
use sendbox_config::{AtomicWriteMode, atomic_write_file};
use sendbox_core::SessionId;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Duration, timeout};

use crate::GuestError;
use crate::manifest::{ArtifactKind, VerifiedManifest};
use crate::secure_fs::{open_directory_no_symlinks, read_bounded_named};
use crate::service::{HealthCheck, RestartPolicy, ServiceId, ServiceSpec};

const BPF_ARTIFACT: &str = "lib/sendbox/observe.bpf.o";
const CONFIG_FILE: &str = "bpf-trace.json";
const SOCKET_FILE: &str = "bpf-report.sock";
const OBJECT_FILE: &str = "observe.bpf.o";
pub const TRACE_LOG_PATH: &str = "/var/log/sendbox/syscalls.jsonl";
const MAX_OBJECT_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_LOG_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TraceConfiguration {
    session_id: SessionId,
    cgroup_parent: PathBuf,
}

#[must_use]
pub fn service_spec(session_dir: &Path, egress: bool) -> ServiceSpec {
    ServiceSpec {
        id: ServiceId::Bpf,
        dependencies: if egress {
            vec![ServiceId::Egress]
        } else {
            Vec::new()
        },
        executable: PathBuf::from("bin/sendbox-guest"),
        args: vec![
            "bpf-trace".to_owned(),
            "--config".to_owned(),
            session_dir.join(CONFIG_FILE).display().to_string(),
        ],
        mandatory: true,
        restart: RestartPolicy::default(),
        health: HealthCheck::UnixSocket {
            path: session_dir.join(SOCKET_FILE),
            timeout_ms: 30_000,
        },
        graceful_shutdown_ms: 5_000,
        forced_shutdown_ms: 2_000,
        max_log_bytes: 64 * 1024,
    }
}

pub fn prepare(
    session_dir: &Path,
    session_id: SessionId,
    cgroup_parent: &Path,
    manifest: &VerifiedManifest,
    egress: bool,
) -> Result<ServiceSpec, GuestError> {
    open_directory_no_symlinks(session_dir)?;
    if !cgroup_parent.starts_with("/sys/fs/cgroup/sendbox")
        || cgroup_parent
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(GuestError::Runtime(
            "tracing must select the owned execution cgroup".to_owned(),
        ));
    }
    let descriptor =
        manifest.artifact_descriptor(Path::new(BPF_ARTIFACT), ArtifactKind::BpfObject)?;
    let mut artifact = File::from(descriptor);
    artifact
        .seek(SeekFrom::Start(0))
        .map_err(|error| GuestError::io("seeking verified BPF object", error))?;
    let bytes = read_bounded_named(&mut artifact, MAX_OBJECT_BYTES, "BPF object")?;
    atomic_write_file(
        &session_dir.join(OBJECT_FILE),
        &bytes,
        0o400,
        AtomicWriteMode::CreateNew,
    )
    .map_err(|error| GuestError::io("staging verified BPF object", error))?;
    let config = serde_json::to_vec(&TraceConfiguration {
        session_id,
        cgroup_parent: cgroup_parent.to_path_buf(),
    })
    .map_err(|error| GuestError::Runtime(format!("encoding tracing configuration: {error}")))?;
    atomic_write_file(
        &session_dir.join(CONFIG_FILE),
        &config,
        0o400,
        AtomicWriteMode::CreateNew,
    )
    .map_err(|error| GuestError::io("staging tracing configuration", error))?;
    Ok(service_spec(session_dir, egress))
}

pub async fn fetch_report(session_dir: &Path) -> Result<Vec<u8>, GuestError> {
    timeout(Duration::from_secs(5), async {
        let mut stream = UnixStream::connect(session_dir.join(SOCKET_FILE))
            .await
            .map_err(|error| GuestError::io("connecting to syscall report service", error))?;
        if stream
            .peer_cred()
            .map_err(|error| GuestError::io("checking trace service identity", error))?
            .uid()
            != 0
        {
            return Err(GuestError::Runtime(
                "syscall report service must be root-owned".to_owned(),
            ));
        }
        stream
            .write_all(&[1])
            .await
            .map_err(|error| GuestError::io("requesting syscall report", error))?;
        let mut bytes = Vec::new();
        stream
            .take((MAX_TRACE_REPORT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| GuestError::io("reading bounded syscall report", error))?;
        if bytes.len() > MAX_TRACE_REPORT_BYTES {
            return Err(GuestError::Runtime(
                "syscall report exceeds its byte limit".to_owned(),
            ));
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| GuestError::Runtime("syscall report service timed out".to_owned()))?
}

#[cfg(target_os = "linux")]
pub async fn run(config_path: PathBuf) -> Result<(), GuestError> {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    use rustix::mount::{MountFlags, mount};
    use sendbox_bpf::{
        EventStream,
        loader::MAX_EVENTS_PER_COLLECTION,
        report::{TraceArchitecture, TraceReport},
    };
    use tokio::net::UnixListener;

    if rustix::process::getuid().as_raw() != 0 || rustix::process::getgid().as_raw() != 0 {
        return Err(GuestError::Runtime(
            "syscall tracing must run in the trusted guest supervisor identity".to_owned(),
        ));
    }
    let session_dir = config_path.parent().ok_or_else(|| {
        GuestError::Runtime("tracing configuration has no session directory".to_owned())
    })?;
    let root = open_directory_no_symlinks(session_dir)?;
    let mut config = crate::secure_fs::open_relative_regular(
        &root,
        Path::new(CONFIG_FILE),
        "tracing configuration",
    )?;
    crate::secure_fs::validate_regular_metadata(
        &config.stat,
        0o400,
        0,
        0,
        true,
        "tracing configuration",
    )?;
    let bytes = read_bounded_named(&mut config.file, 4096, "tracing configuration")?;
    let config: TraceConfiguration = serde_json::from_slice(&bytes)
        .map_err(|error| GuestError::Runtime(format!("decoding tracing configuration: {error}")))?;
    let expected_name = config.session_id.to_string();
    if config_path != session_dir.join(CONFIG_FILE)
        || session_dir.file_name().and_then(|value| value.to_str()) != Some(expected_name.as_str())
        || !config.cgroup_parent.starts_with("/sys/fs/cgroup/sendbox")
    {
        return Err(GuestError::Runtime(
            "tracing configuration does not match its session".to_owned(),
        ));
    }
    fs::remove_file(&config_path)
        .map_err(|error| GuestError::io("consuming tracing configuration", error))?;
    open_directory_no_symlinks(&config.cgroup_parent)?;
    if !Path::new("/sys/kernel/tracing/events/raw_syscalls/sys_enter/id").is_file()
        && !Path::new("/sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/id").is_file()
    {
        mount(
            "tracefs",
            "/sys/kernel/tracing",
            "tracefs",
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            None::<&std::ffi::CStr>,
        )
        .map_err(|error| GuestError::io("mounting guest tracefs", error.into()))?;
    }
    let mut object = crate::secure_fs::open_relative_regular(
        &root,
        Path::new(OBJECT_FILE),
        "verified BPF object",
    )?;
    crate::secure_fs::validate_regular_metadata(
        &object.stat,
        0o400,
        0,
        0,
        true,
        "verified BPF object",
    )?;
    let object = read_bounded_named(&mut object.file, MAX_OBJECT_BYTES, "BPF object")?;
    let stream =
        EventStream::attach_cgroup_tree(&object, &config.cgroup_parent).map_err(|error| {
            GuestError::Runtime(format!("attaching guest syscall observation: {error}"))
        })?;
    sendbox_config::ensure_directory(Path::new("/var/log/sendbox"), 0o755)
        .map_err(|error| GuestError::io("preparing syscall log directory", error))?;
    let metadata = fs::metadata("/var/log/sendbox")
        .map_err(|error| GuestError::io("checking syscall log directory", error))?;
    if metadata.uid() != 0 || metadata.gid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(GuestError::Runtime(
            "syscall log directory must be root-owned and not writable by the workload".to_owned(),
        ));
    }
    let mut log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(TRACE_LOG_PATH)
        .map_err(|error| GuestError::io("creating private syscall log", error))?;
    let socket = session_dir.join(SOCKET_FILE);
    let listener = UnixListener::bind(&socket)
        .map_err(|error| GuestError::io("binding private syscall report socket", error))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|error| GuestError::io("protecting syscall report socket", error))?;
    let mut report = TraceReport::new(
        config.session_id,
        TraceArchitecture::current().map_err(GuestError::Runtime)?,
    );
    let mut log_bytes = 0_usize;
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| GuestError::io("installing syscall tracer shutdown handler", error))?;
    loop {
        tokio::select! {
            _ = terminate.recv() => {
                log.sync_all().map_err(|error| GuestError::io("syncing syscall observations", error))?;
                fs::remove_file(&socket).map_err(|error| GuestError::io("removing syscall report socket", error))?;
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                collect(&stream, &mut report, &mut log, &mut log_bytes)?;
            }
            accepted = listener.accept() => {
                let (mut client, _) = accepted.map_err(|error| GuestError::io("accepting syscall report client", error))?;
                if client.peer_cred().map_err(|error| GuestError::io("checking syscall report client", error))?.uid() != 0 {
                    return Err(GuestError::Runtime("untrusted process reached the private syscall report service".to_owned()));
                }
                let mut request = [0; 1];
                match timeout(Duration::from_secs(1), client.read(&mut request)).await {
                    Ok(Ok(0)) => continue,
                    Ok(Ok(1)) if request == [1] => {}
                    _ => {
                        eprintln!("[sendbox-bpf] invalid or timed-out report request");
                        continue;
                    }
                }
                for _ in 0..4 {
                    if collect(&stream, &mut report, &mut log, &mut log_bytes)? < MAX_EVENTS_PER_COLLECTION {
                        break;
                    }
                }
                report.losses = stream.losses().map_err(|error| GuestError::Runtime(error.to_string()))?;
                report.validate(config.session_id).map_err(GuestError::Runtime)?;
                let bytes = serde_json::to_vec(&report)
                    .map_err(|error| GuestError::Runtime(format!("encoding syscall report: {error}")))?;
                timeout(Duration::from_secs(2), client.write_all(&bytes)).await
                    .map_err(|_| GuestError::Runtime("syscall report writer timed out".to_owned()))?
                    .map_err(|error| GuestError::io("writing syscall report", error))?;
                client.shutdown().await.map_err(|error| GuestError::io("closing syscall report", error))?;
            }
        }
    }

    fn collect(
        stream: &EventStream,
        report: &mut TraceReport,
        log: &mut File,
        log_bytes: &mut usize,
    ) -> Result<usize, GuestError> {
        let events = stream
            .collect(MAX_EVENTS_PER_COLLECTION, Duration::from_millis(1))
            .map_err(|error| {
                GuestError::Runtime(format!("collecting syscall observations: {error}"))
            })?;
        let count = events.len();
        for event in events {
            let sample = report.record(&event).map_err(GuestError::Runtime)?;
            let mut bytes = serde_json::to_vec(&sample).map_err(|error| {
                GuestError::Runtime(format!("encoding syscall observation: {error}"))
            })?;
            bytes.push(b'\n');
            if !report.log_limit_reached && bytes.len() <= MAX_LOG_BYTES.saturating_sub(*log_bytes)
            {
                log.write_all(&bytes)
                    .map_err(|error| GuestError::io("writing syscall observation", error))?;
                *log_bytes += bytes.len();
            } else if !report.log_limit_reached {
                report.log_limit_reached = true;
                eprintln!(
                    "[sendbox-bpf] syscall log byte limit reached; continuing bounded sampling and counters"
                );
            }
        }
        Ok(count)
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run(_config_path: PathBuf) -> Result<(), GuestError> {
    Err(GuestError::Runtime(
        "syscall tracing requires a Linux guest; it never runs on the host".to_owned(),
    ))
}
