//! Seccomp filter construction using the safe `libseccomp` crate. No
//! `unsafe` is written in this module: every FFI/unsafe detail is
//! encapsulated inside the `libseccomp` crate itself.

#![forbid(unsafe_code)]

use crate::error::PlatformError;
use crate::platform::SeccompProfile;
use libc::EPERM;
use libseccomp::{
    ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};

/// `clone(2)`/`unshare(2)`/`setns(2)` namespace-creation flags. `clone` is
/// still needed for ordinary thread/process creation, so it is only
/// conditionally denied when one of these bits is set in its flags
/// argument; `clone3` cannot be filtered this way (its flags live inside a
/// `struct clone_args` in memory, not in a register), so it is denied
/// outright.
const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;

/// Syscalls denied unconditionally in every profile: ptrace/process
/// introspection, io_uring, bpf, userfaultfd, mount-family, keyring,
/// kernel modules, kexec, reboot, and a handful of other raw high-risk
/// primitives.
const ALWAYS_DENIED: &[&str] = &[
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "bpf",
    "userfaultfd",
    "mount",
    "umount",
    "umount2",
    "pivot_root",
    "fsopen",
    "fsconfig",
    "fsmount",
    "move_mount",
    "open_tree",
    "fspick",
    "mount_setattr",
    "unshare",
    "setns",
    "keyctl",
    "add_key",
    "request_key",
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    // Additional defense-in-depth denials beyond the explicitly enumerated
    // list, for other raw high-risk primitives in the same spirit.
    "acct",
    "swapon",
    "swapoff",
    "quotactl",
    "syslog",
    "personality",
];

/// `memfd_create` is denied in every profile: nothing this crate spawns
/// legitimately needs to create anonymous, in-memory, executable-backing
/// files.
const MEMFD_CREATE: &str = "memfd_create";

/// Denied only in [`SeccompProfile::AgentBootstrap`].
const EXEC_SYSCALLS: &[&str] = &["execve", "execveat"];

/// `clone3` carries its flags through a pointer, so libseccomp cannot safely
/// distinguish ordinary process creation from namespace-creating variants.
/// The trusted broker and realistic development-command descendants retain it
/// because current runtimes use it for ordinary process/thread creation. The
/// agent does not need it after bootstrap and denies it outright. ADR-001 must
/// record the descendant-profile limitation rather than claim clone3 flag
/// filtering that seccomp cannot safely express.
const CLONE3: &str = "clone3";

/// Denied only in [`SeccompProfile::Launcher`], so neither the target nor
/// its descendants can leave the process group the broker placed them in.
const PROCESS_GROUP_SYSCALLS: &[&str] = &["setsid", "setpgid"];

/// Builds and loads (with `TSYNC`) the seccomp filter for `profile`.
pub fn install(profile: SeccompProfile) -> Result<(), PlatformError> {
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)
        .map_err(|e| PlatformError::Seccomp(format!("failed to create filter context: {e}")))?;

    install_explicit_architectures(&mut ctx)?;

    for name in ALWAYS_DENIED {
        deny_syscall(&mut ctx, name)?;
    }
    deny_syscall(&mut ctx, MEMFD_CREATE)?;
    deny_namespace_creating_clone(&mut ctx)?;

    match profile {
        SeccompProfile::AgentBootstrap => {
            deny_syscall(&mut ctx, CLONE3)?;
            for name in EXEC_SYSCALLS {
                deny_syscall(&mut ctx, name)?;
            }
        }
        SeccompProfile::Broker => {
            // `execve`/`execveat`/`clone` remain at the default `Allow`
            // action: the broker must retain the ability to fork+exec a
            // fresh `contained-launcher` per accepted request.
        }
        SeccompProfile::Launcher => {
            // Exec remains allowed (the launcher must exec the target),
            // but the target and its descendants may never change process
            // group once placed into one by the broker.
            for name in PROCESS_GROUP_SYSCALLS {
                deny_syscall(&mut ctx, name)?;
            }
        }
    }

    ctx.set_ctl_nnp(false)
        .map_err(|e| PlatformError::Seccomp(format!("failed to disable libseccomp's automatic NNP handling (this crate sets it explicitly itself): {e}")))?;
    ctx.set_ctl_tsync(true)
        .map_err(|e| PlatformError::Seccomp(format!("failed to request TSYNC: {e}")))?;

    ctx.load()
        .map_err(|e| PlatformError::Seccomp(format!("failed to load filter: {e}")))?;

    Ok(())
}

/// Explicitly adds the native architecture and any well-known compatible
/// "confused deputy" architectures (e.g. 32-bit x86/x32 on a 64-bit x86_64
/// process, or 32-bit ARM on aarch64) to `ctx`, rather than relying on
/// whatever `ScmpFilterContext::new` happens to add by default. Without
/// this, a process could potentially issue syscalls through a secondary
/// ABI that the filter's rules do not cover.
fn install_explicit_architectures(ctx: &mut ScmpFilterContext) -> Result<(), PlatformError> {
    let native = ScmpArch::native();
    ensure_arch_present(ctx, native)?;

    let compatible = match native {
        ScmpArch::X8664 => vec![ScmpArch::X86, ScmpArch::X32],
        ScmpArch::Aarch64 => vec![ScmpArch::Arm],
        _ => Vec::new(),
    };
    for arch in compatible {
        ensure_arch_present(ctx, arch)?;
    }
    Ok(())
}

fn ensure_arch_present(ctx: &mut ScmpFilterContext, arch: ScmpArch) -> Result<(), PlatformError> {
    let present = ctx
        .is_arch_present(arch)
        .map_err(|e| PlatformError::Seccomp(format!("failed to check arch {arch:?}: {e}")))?;
    if !present {
        ctx.add_arch(arch)
            .map_err(|e| PlatformError::Seccomp(format!("failed to add arch {arch:?}: {e}")))?;
    }
    Ok(())
}

fn deny_syscall(ctx: &mut ScmpFilterContext, name: &str) -> Result<(), PlatformError> {
    match ScmpSyscall::from_name(name) {
        Ok(syscall) => {
            ctx.add_rule(ScmpAction::Errno(EPERM), syscall)
                .map_err(|e| {
                    PlatformError::Seccomp(format!("failed to add deny rule for {name}: {e}"))
                })?;
            Ok(())
        }
        // Some syscalls (e.g. the legacy `umount`) do not exist on every
        // architecture/libc combination. Skipping a syscall that is not
        // resolvable on this platform is safe: it cannot be invoked at all
        // if it does not exist.
        Err(_) => Ok(()),
    }
}

fn deny_namespace_creating_clone(ctx: &mut ScmpFilterContext) -> Result<(), PlatformError> {
    let Ok(syscall) = ScmpSyscall::from_name("clone") else {
        return Ok(());
    };
    // `MaskedEqual(mask)` compares `(actual_arg & mask) == datum`. We want
    // to deny `clone` whenever *any* namespace-creation bit is set in its
    // flags argument (arg index 0), i.e. `(flags & MASK) != 0`. libseccomp's
    // conditional rules only express equality-style comparisons, so "any
    // bit in the mask is set" is expressed as one rule per individual
    // namespace flag, each independently sufficient to deny the call.
    for flag in [
        CLONE_NEWNS,
        CLONE_NEWCGROUP,
        CLONE_NEWUTS,
        CLONE_NEWIPC,
        CLONE_NEWUSER,
        CLONE_NEWPID,
        CLONE_NEWNET,
    ] {
        let compare = ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(flag), flag);
        ctx.add_rule_conditional(ScmpAction::Errno(EPERM), syscall, &[compare])
            .map_err(|e| {
                PlatformError::Seccomp(format!(
                    "failed to add conditional deny rule for clone namespace flag {flag:#x}: {e}"
                ))
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_syscall_silently_skips_unknown_names() {
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow).expect("new filter context");
        // "not_a_real_syscall_name" cannot resolve on any architecture; this
        // must not error.
        deny_syscall(&mut ctx, "not_a_real_syscall_name").expect("must not error");
    }

    #[test]
    fn install_explicit_architectures_adds_native_arch() {
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow).expect("new filter context");
        install_explicit_architectures(&mut ctx).expect("install arches");
        assert!(
            ctx.is_arch_present(ScmpArch::native())
                .expect("check native arch")
        );
    }
}
