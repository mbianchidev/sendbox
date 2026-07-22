use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::{BpfError, DiagnosticKind};

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
    pub effective_capabilities: u64,
    pub exec_tracepoint_available: bool,
    pub syscall_tracepoint_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PreflightReport {
    pub schema_version: u8,
    pub status: &'static str,
    pub operating_system: String,
    pub architecture: String,
    pub kernel_release: String,
    pub ring_buffer_supported: bool,
    pub btf_present: bool,
    pub btf_readable: bool,
    pub exec_tracepoint_available: bool,
    pub syscall_tracepoint_available: bool,
    pub effective_capabilities_hex: String,
    pub privilege_ready: bool,
    pub live_ready: bool,
    pub issues: Vec<PreflightIssue>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PreflightIssue {
    pub kind: DiagnosticKind,
    pub message: String,
    pub action: String,
}

pub fn inspect_host() -> Result<PreflightReport, BpfError> {
    if std::env::consts::OS != "linux" {
        return Err(BpfError::new(
            DiagnosticKind::UnsupportedHost,
            "preflight",
            format!("unsupported operating system: {}", std::env::consts::OS),
            "run BPF observation on Linux",
        ));
    }

    let status = fs::read_to_string("/proc/self/status").map_err(|error| {
        BpfError::new(
            DiagnosticKind::Unavailable,
            "preflight",
            format!("cannot read /proc/self/status: {error}"),
            "mount procfs inside the guest",
        )
    })?;
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    let btf = Path::new("/sys/kernel/btf/vmlinux");
    Ok(build_report(ProbeInput {
        os: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        kernel_release,
        btf_present: btf.exists(),
        btf_readable: fs::File::open(btf).is_ok(),
        effective_capabilities: parse_effective_capabilities(&status)?,
        exec_tracepoint_available: tracepoint_available("sched/sched_process_exec"),
        syscall_tracepoint_available: tracepoint_available("raw_syscalls/sys_enter"),
    }))
}

pub fn build_report(input: ProbeInput) -> PreflightReport {
    let ring_buffer_supported = kernel_at_least_5_8(&input.kernel_release);
    let privilege_ready = has_capability(input.effective_capabilities, CAP_SYS_ADMIN)
        || (has_capability(input.effective_capabilities, CAP_BPF)
            && has_capability(input.effective_capabilities, CAP_PERFMON));
    let mut issues = Vec::new();
    if input.os != "linux" {
        issues.push(issue(
            DiagnosticKind::UnsupportedHost,
            format!("unsupported operating system: {}", input.os),
            "run BPF observation on Linux",
        ));
    }
    if !input.btf_present || !input.btf_readable {
        issues.push(issue(
            DiagnosticKind::Unavailable,
            "/sys/kernel/btf/vmlinux is absent or unreadable",
            "use a kernel built with CONFIG_DEBUG_INFO_BTF=y",
        ));
    }
    if !ring_buffer_supported {
        issues.push(issue(
            DiagnosticKind::Unavailable,
            format!(
                "kernel {} predates BPF ring-buffer support",
                input.kernel_release
            ),
            "use Linux 5.8 or newer",
        ));
    }
    if !input.exec_tracepoint_available || !input.syscall_tracepoint_available {
        issues.push(issue(
            DiagnosticKind::Unavailable,
            "required exec or syscall tracepoint is unavailable",
            "mount tracefs and expose sched_process_exec and raw_syscalls/sys_enter",
        ));
    }
    if !privilege_ready {
        issues.push(issue(
            DiagnosticKind::PermissionDenied,
            "effective capabilities cannot load and attach the BPF programs",
            "grant CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN on legacy kernels",
        ));
    }
    let live_ready = issues.is_empty();
    PreflightReport {
        schema_version: 1,
        status: if live_ready { "ready" } else { "unavailable" },
        operating_system: input.os,
        architecture: input.architecture,
        kernel_release: input.kernel_release,
        ring_buffer_supported,
        btf_present: input.btf_present,
        btf_readable: input.btf_readable,
        exec_tracepoint_available: input.exec_tracepoint_available,
        syscall_tracepoint_available: input.syscall_tracepoint_available,
        effective_capabilities_hex: format!("0x{:016x}", input.effective_capabilities),
        privilege_ready,
        live_ready,
        issues,
    }
}

pub fn require_live_ready(report: &PreflightReport) -> Result<(), BpfError> {
    if report.live_ready {
        return Ok(());
    }
    let issue = report.issues.first().ok_or_else(|| {
        BpfError::new(
            DiagnosticKind::Internal,
            "preflight",
            "unavailable preflight did not contain a diagnostic",
            "report the inconsistent preflight result",
        )
    })?;
    Err(BpfError::new(
        issue.kind,
        "preflight",
        &issue.message,
        &issue.action,
    ))
}

fn issue(
    kind: DiagnosticKind,
    message: impl Into<String>,
    action: impl Into<String>,
) -> PreflightIssue {
    PreflightIssue {
        kind,
        message: message.into(),
        action: action.into(),
    }
}

fn tracepoint_available(name: &str) -> bool {
    [
        format!("/sys/kernel/tracing/events/{name}/id"),
        format!("/sys/kernel/debug/tracing/events/{name}/id"),
    ]
    .iter()
    .any(|path| fs::read_to_string(path).is_ok())
}

fn parse_effective_capabilities(status: &str) -> Result<u64, BpfError> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim)
        .ok_or_else(|| {
            BpfError::new(
                DiagnosticKind::Unavailable,
                "preflight",
                "CapEff is missing from /proc/self/status",
                "use a Linux procfs exposing effective capabilities",
            )
        })?;
    u64::from_str_radix(value, 16).map_err(|error| {
        BpfError::new(
            DiagnosticKind::Unavailable,
            "preflight",
            format!("invalid CapEff value {value:?}: {error}"),
            "use a valid Linux procfs",
        )
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_input() -> ProbeInput {
        ProbeInput {
            os: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            kernel_release: "6.8.0".to_owned(),
            btf_present: true,
            btf_readable: true,
            effective_capabilities: (1_u64 << CAP_BPF) | (1_u64 << CAP_PERFMON),
            exec_tracepoint_available: true,
            syscall_tracepoint_available: true,
        }
    }

    #[test]
    fn modern_linux_is_ready() {
        assert!(build_report(ready_input()).live_ready);
    }

    #[test]
    fn missing_privilege_is_permission_denied() {
        let mut input = ready_input();
        input.effective_capabilities = 0;
        let report = build_report(input);
        assert_eq!(report.issues[0].kind, DiagnosticKind::PermissionDenied);
    }

    #[test]
    fn old_kernel_is_unavailable() {
        let mut input = ready_input();
        input.kernel_release = "5.4.0".to_owned();
        assert!(!build_report(input).live_ready);
    }
}
