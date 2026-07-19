use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::diagnostic::{DiagnosticKind, SpikeError};

const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeInput {
    pub os: String,
    pub architecture: String,
    pub kernel_release: String,
    pub btf_present: bool,
    pub btf_readable: bool,
    pub bpffs_mounted: bool,
    pub bpffs_writable: bool,
    pub effective_capabilities: u64,
    pub lsm_available: bool,
    pub lsm_entries: Vec<String>,
    pub tracepoint_id_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PreflightReport {
    pub schema_version: u8,
    pub status: &'static str,
    pub operating_system: String,
    pub architecture: String,
    pub kernel_release: String,
    pub ring_buffer_supported: bool,
    pub tracepoint: TracepointReport,
    pub btf: BtfReport,
    pub bpffs: BpffsReport,
    pub capabilities: CapabilityReport,
    pub bpf_lsm: LsmReport,
    pub live_ready: bool,
    pub issues: Vec<PreflightIssue>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BtfReport {
    pub path: &'static str,
    pub present: bool,
    pub readable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BpffsReport {
    pub path: &'static str,
    pub mounted: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityReport {
    pub effective_hex: String,
    pub names: Vec<&'static str>,
    pub has_cap_bpf: bool,
    pub has_cap_perfmon: bool,
    pub has_cap_sys_admin: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LsmReport {
    pub source_available: bool,
    pub entries: Vec<String>,
    pub bpf_present: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TracepointReport {
    pub name: &'static str,
    pub available: bool,
    pub id_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PreflightIssue {
    pub kind: DiagnosticKind,
    pub message: String,
    pub action: String,
}

pub fn inspect_host() -> Result<PreflightReport, SpikeError> {
    ensure_supported_os(std::env::consts::OS)?;

    let btf_path = Path::new("/sys/kernel/btf/vmlinux");
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        SpikeError::new(
            DiagnosticKind::Unavailable,
            "preflight",
            format!("cannot read /proc/self/mountinfo: {error}"),
            "mount procfs inside the guest",
        )
    })?;
    let status = fs::read_to_string("/proc/self/status").map_err(|error| {
        SpikeError::new(
            DiagnosticKind::Unavailable,
            "preflight",
            format!("cannot read /proc/self/status: {error}"),
            "mount procfs inside the guest",
        )
    })?;
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    let lsm = fs::read_to_string("/sys/kernel/security/lsm").ok();
    let capabilities = parse_effective_capabilities(&status)?;
    let tracepoint_id_path = [
        "/sys/kernel/tracing/events/sched/sched_process_exec/id",
        "/sys/kernel/debug/tracing/events/sched/sched_process_exec/id",
    ]
    .into_iter()
    .find(|path| fs::read_to_string(path).is_ok())
    .map(str::to_owned);

    Ok(build_report(ProbeInput {
        os: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        kernel_release,
        btf_present: btf_path.exists(),
        btf_readable: fs::File::open(btf_path).is_ok(),
        bpffs_mounted: bpffs_is_mounted(&mountinfo),
        bpffs_writable: is_writable_directory(Path::new("/sys/fs/bpf")),
        effective_capabilities: capabilities,
        lsm_available: lsm.is_some(),
        lsm_entries: lsm.as_deref().map(parse_lsm).unwrap_or_default(),
        tracepoint_id_path,
    }))
}

pub fn build_report(mut input: ProbeInput) -> PreflightReport {
    input.lsm_entries.sort();
    input.lsm_entries.dedup();

    let names = capability_names(input.effective_capabilities);
    let has_cap_bpf = has_capability(input.effective_capabilities, CAP_BPF);
    let has_cap_perfmon = has_capability(input.effective_capabilities, CAP_PERFMON);
    let has_cap_sys_admin = has_capability(input.effective_capabilities, CAP_SYS_ADMIN);
    let privilege_ready = has_cap_sys_admin || (has_cap_bpf && has_cap_perfmon);
    let ring_buffer_supported = kernel_at_least_5_8(&input.kernel_release);
    let mut issues = Vec::new();

    if input.os != "linux" {
        issues.push(PreflightIssue {
            kind: DiagnosticKind::UnsupportedHost,
            message: format!("unsupported operating system: {}", input.os),
            action: "run the guest helper on Linux".to_owned(),
        });
    }
    if !input.btf_present || !input.btf_readable {
        issues.push(PreflightIssue {
            kind: DiagnosticKind::Unavailable,
            message: "/sys/kernel/btf/vmlinux is absent or unreadable".to_owned(),
            action: "use a kernel built with CONFIG_DEBUG_INFO_BTF=y".to_owned(),
        });
    }
    if !ring_buffer_supported {
        issues.push(PreflightIssue {
            kind: DiagnosticKind::Unavailable,
            message: format!(
                "kernel {} predates BPF ring-buffer support",
                input.kernel_release
            ),
            action: "use Linux 5.8 or newer".to_owned(),
        });
    }
    if input.tracepoint_id_path.is_none() {
        issues.push(PreflightIssue {
            kind: DiagnosticKind::Unavailable,
            message: "sched:sched_process_exec tracepoint is unavailable".to_owned(),
            action: "mount tracefs and use a kernel exposing sched_process_exec".to_owned(),
        });
    }
    if !privilege_ready {
        issues.push(PreflightIssue {
            kind: DiagnosticKind::PermissionDenied,
            message: "effective capabilities cannot load and attach this BPF program".to_owned(),
            action:
                "grant CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN on kernels using the legacy model"
                    .to_owned(),
        });
    }

    let bpf_present = input.lsm_entries.iter().any(|entry| entry == "bpf");
    let live_ready = issues.is_empty();
    PreflightReport {
        schema_version: 1,
        status: if live_ready { "ready" } else { "unavailable" },
        operating_system: input.os,
        architecture: input.architecture,
        kernel_release: input.kernel_release,
        ring_buffer_supported,
        tracepoint: TracepointReport {
            name: "sched:sched_process_exec",
            available: input.tracepoint_id_path.is_some(),
            id_path: input.tracepoint_id_path,
        },
        btf: BtfReport {
            path: "/sys/kernel/btf/vmlinux",
            present: input.btf_present,
            readable: input.btf_readable,
        },
        bpffs: BpffsReport {
            path: "/sys/fs/bpf",
            mounted: input.bpffs_mounted,
            writable: input.bpffs_writable,
        },
        capabilities: CapabilityReport {
            effective_hex: format!("0x{:016x}", input.effective_capabilities),
            names,
            has_cap_bpf,
            has_cap_perfmon,
            has_cap_sys_admin,
        },
        bpf_lsm: LsmReport {
            source_available: input.lsm_available,
            entries: input.lsm_entries,
            bpf_present,
        },
        live_ready,
        issues,
    }
}

pub fn require_live_ready(report: &PreflightReport) -> Result<(), SpikeError> {
    if report.live_ready {
        return Ok(());
    }

    let issue = report.issues.first().ok_or_else(|| {
        SpikeError::new(
            DiagnosticKind::Internal,
            "preflight",
            "preflight was unavailable without a diagnostic",
            "report this inconsistent preflight result",
        )
    })?;
    Err(SpikeError::new(
        issue.kind,
        "preflight",
        &issue.message,
        &issue.action,
    ))
}

pub fn ensure_supported_os(os: &str) -> Result<(), SpikeError> {
    if os == "linux" {
        Ok(())
    } else {
        Err(SpikeError::new(
            DiagnosticKind::UnsupportedHost,
            "preflight",
            format!("unsupported operating system: {os}"),
            "run the guest helper on Linux",
        ))
    }
}

fn parse_effective_capabilities(status: &str) -> Result<u64, SpikeError> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim)
        .ok_or_else(|| {
            SpikeError::new(
                DiagnosticKind::Unavailable,
                "preflight",
                "CapEff is missing from /proc/self/status",
                "use a Linux procfs exposing effective capabilities",
            )
        })?;
    u64::from_str_radix(value, 16).map_err(|error| {
        SpikeError::new(
            DiagnosticKind::Unavailable,
            "preflight",
            format!("invalid CapEff value {value:?}: {error}"),
            "use a valid Linux procfs",
        )
    })
}

fn bpffs_is_mounted(mountinfo: &str) -> bool {
    mountinfo.lines().any(|line| {
        let Some((before_separator, after_separator)) = line.split_once(" - ") else {
            return false;
        };
        let mount_point = before_separator.split_whitespace().nth(4);
        let filesystem = after_separator.split_whitespace().next();
        mount_point == Some("/sys/fs/bpf") && filesystem == Some("bpf")
    })
}

fn is_writable_directory(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_dir() && !metadata.permissions().readonly())
        .unwrap_or(false)
}

fn parse_lsm(value: &str) -> Vec<String> {
    value
        .trim()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

fn has_capability(mask: u64, capability: u32) -> bool {
    mask & (1_u64 << capability) != 0
}

fn kernel_at_least_5_8(release: &str) -> bool {
    let mut parts = release.split(['.', '-']);
    let major = parts.next().and_then(|value| value.parse::<u32>().ok());
    let minor = parts.next().and_then(|value| value.parse::<u32>().ok());
    matches!((major, minor), (Some(major), Some(minor)) if major > 5 || (major == 5 && minor >= 8))
}

fn capability_names(mask: u64) -> Vec<&'static str> {
    const NAMES: &[(u32, &str)] = &[
        (0, "CAP_CHOWN"),
        (1, "CAP_DAC_OVERRIDE"),
        (2, "CAP_DAC_READ_SEARCH"),
        (3, "CAP_FOWNER"),
        (4, "CAP_FSETID"),
        (5, "CAP_KILL"),
        (6, "CAP_SETGID"),
        (7, "CAP_SETUID"),
        (8, "CAP_SETPCAP"),
        (9, "CAP_LINUX_IMMUTABLE"),
        (10, "CAP_NET_BIND_SERVICE"),
        (11, "CAP_NET_BROADCAST"),
        (12, "CAP_NET_ADMIN"),
        (13, "CAP_NET_RAW"),
        (14, "CAP_IPC_LOCK"),
        (15, "CAP_IPC_OWNER"),
        (16, "CAP_SYS_MODULE"),
        (17, "CAP_SYS_RAWIO"),
        (18, "CAP_SYS_CHROOT"),
        (19, "CAP_SYS_PTRACE"),
        (20, "CAP_SYS_PACCT"),
        (21, "CAP_SYS_ADMIN"),
        (22, "CAP_SYS_BOOT"),
        (23, "CAP_SYS_NICE"),
        (24, "CAP_SYS_RESOURCE"),
        (25, "CAP_SYS_TIME"),
        (26, "CAP_SYS_TTY_CONFIG"),
        (27, "CAP_MKNOD"),
        (28, "CAP_LEASE"),
        (29, "CAP_AUDIT_WRITE"),
        (30, "CAP_AUDIT_CONTROL"),
        (31, "CAP_SETFCAP"),
        (32, "CAP_MAC_OVERRIDE"),
        (33, "CAP_MAC_ADMIN"),
        (34, "CAP_SYSLOG"),
        (35, "CAP_WAKE_ALARM"),
        (36, "CAP_BLOCK_SUSPEND"),
        (37, "CAP_AUDIT_READ"),
        (38, "CAP_PERFMON"),
        (39, "CAP_BPF"),
        (40, "CAP_CHECKPOINT_RESTORE"),
    ];
    NAMES
        .iter()
        .filter_map(|(number, name)| has_capability(mask, *number).then_some(*name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic_json;

    fn ready_input() -> ProbeInput {
        ProbeInput {
            os: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            kernel_release: "6.8.0-test".to_owned(),
            btf_present: true,
            btf_readable: true,
            bpffs_mounted: true,
            bpffs_writable: false,
            effective_capabilities: (1_u64 << CAP_BPF) | (1_u64 << CAP_PERFMON),
            lsm_available: true,
            lsm_entries: vec!["landlock".to_owned(), "bpf".to_owned()],
            tracepoint_id_path: Some(
                "/sys/kernel/tracing/events/sched/sched_process_exec/id".to_owned(),
            ),
        }
    }

    #[test]
    fn detects_modern_bpf_capabilities() {
        let report = build_report(ready_input());
        assert!(report.live_ready);
        assert_eq!(report.capabilities.names, vec!["CAP_PERFMON", "CAP_BPF"]);
        assert!(report.bpf_lsm.bpf_present);
    }

    #[test]
    fn detects_legacy_sys_admin_capability() {
        let mut input = ready_input();
        input.effective_capabilities = 1_u64 << CAP_SYS_ADMIN;
        assert!(build_report(input).live_ready);
    }

    #[test]
    fn missing_capabilities_are_permission_denied() {
        let mut input = ready_input();
        input.effective_capabilities = 0;
        let report = build_report(input);
        assert!(!report.live_ready);
        assert_eq!(report.issues[0].kind, DiagnosticKind::PermissionDenied);
    }

    #[test]
    fn unsupported_host_is_typed() {
        let error = ensure_supported_os("macos").expect_err("must reject");
        assert_eq!(error.kind, DiagnosticKind::UnsupportedHost);
    }

    #[test]
    fn old_kernel_is_unavailable() {
        let mut input = ready_input();
        input.kernel_release = "5.4.0-test".to_owned();
        let report = build_report(input);
        assert!(!report.live_ready);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.message.contains("ring-buffer"))
        );
    }

    #[test]
    fn preflight_json_order_is_stable() {
        let json = deterministic_json(&build_report(ready_input())).expect("JSON");
        assert!(json.starts_with(
            r#"{"schema_version":1,"status":"ready","operating_system":"linux","architecture":"x86_64","kernel_release":"6.8.0-test","ring_buffer_supported":true,"tracepoint":{"name":"sched:sched_process_exec","available":true"#
        ));
    }

    #[test]
    fn parses_mountinfo_and_cap_eff() {
        let mountinfo = "29 23 0:26 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw";
        assert!(bpffs_is_mounted(mountinfo));
        assert_eq!(
            parse_effective_capabilities("Name:\ttest\nCapEff:\t0000000000200000\n")
                .expect("capabilities"),
            1_u64 << CAP_SYS_ADMIN
        );
    }
}
