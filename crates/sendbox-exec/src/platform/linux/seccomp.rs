//! TSYNC seccomp profiles for agent bootstrap and command descendants.

#![forbid(unsafe_code)]

use libseccomp::{
    ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};

use crate::error::{KernelPrimitive, PlatformError, UnsupportedKernel};

const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;

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
    "acct",
    "swapon",
    "swapoff",
    "quotactl",
    "syslog",
    "personality",
    "memfd_create",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile<'a> {
    AgentBootstrap,
    Command {
        additional_denied_syscalls: &'a [String],
    },
}

pub fn install(profile: Profile<'_>) -> Result<(), PlatformError> {
    let mut context = ScmpFilterContext::new(ScmpAction::Allow)
        .map_err(|error| PlatformError::SecuritySetup(format!("create seccomp filter: {error}")))?;
    install_architectures(&mut context)?;
    for syscall in ALWAYS_DENIED {
        deny_optional(&mut context, syscall)?;
    }
    deny_namespace_clone(&mut context)?;
    match profile {
        Profile::AgentBootstrap => {
            for syscall in ["execve", "execveat", "clone3"] {
                deny_required(&mut context, syscall)?;
            }
        }
        Profile::Command {
            additional_denied_syscalls,
        } => {
            for syscall in additional_denied_syscalls {
                deny_required(&mut context, syscall)?;
            }
        }
    }
    context.set_ctl_nnp(false).map_err(|error| {
        PlatformError::SecuritySetup(format!("disable implicit seccomp NNP: {error}"))
    })?;
    context.set_ctl_tsync(true).map_err(|error| {
        UnsupportedKernel::new(
            KernelPrimitive::SeccompTsync,
            None,
            format!("libseccomp rejected TSYNC: {error}"),
        )
    })?;
    context.load().map_err(|error| {
        let detail = format!("load TSYNC seccomp filter: {error}");
        if detail.contains("Operation not supported") || detail.contains("Invalid argument") {
            PlatformError::UnsupportedKernel(UnsupportedKernel::new(
                KernelPrimitive::SeccompTsync,
                None,
                detail,
            ))
        } else {
            PlatformError::SecuritySetup(detail)
        }
    })
}

fn install_architectures(context: &mut ScmpFilterContext) -> Result<(), PlatformError> {
    let native = ScmpArch::native();
    ensure_architecture(context, native)?;
    let compatible = match native {
        ScmpArch::X8664 => &[ScmpArch::X86, ScmpArch::X32][..],
        ScmpArch::Aarch64 => &[ScmpArch::Arm][..],
        _ => &[],
    };
    for architecture in compatible {
        ensure_architecture(context, *architecture)?;
    }
    Ok(())
}

fn ensure_architecture(
    context: &mut ScmpFilterContext,
    architecture: ScmpArch,
) -> Result<(), PlatformError> {
    if !context.is_arch_present(architecture).map_err(|error| {
        PlatformError::SecuritySetup(format!("query seccomp architecture: {error}"))
    })? {
        context.add_arch(architecture).map_err(|error| {
            PlatformError::SecuritySetup(format!("add seccomp architecture: {error}"))
        })?;
    }
    Ok(())
}

fn deny_optional(context: &mut ScmpFilterContext, name: &str) -> Result<(), PlatformError> {
    let Ok(syscall) = ScmpSyscall::from_name(name) else {
        return Ok(());
    };
    add_deny_rule(context, syscall, name)
}

fn deny_required(context: &mut ScmpFilterContext, name: &str) -> Result<(), PlatformError> {
    let syscall = ScmpSyscall::from_name(name).map_err(|error| {
        PlatformError::SecuritySetup(format!("unknown required syscall {name:?}: {error}"))
    })?;
    add_deny_rule(context, syscall, name)
}

fn add_deny_rule(
    context: &mut ScmpFilterContext,
    syscall: ScmpSyscall,
    name: &str,
) -> Result<(), PlatformError> {
    context
        .add_rule(ScmpAction::Errno(libc::EPERM), syscall)
        .map(|_| ())
        .map_err(|error| PlatformError::SecuritySetup(format!("deny syscall {name:?}: {error}")))
}

fn deny_namespace_clone(context: &mut ScmpFilterContext) -> Result<(), PlatformError> {
    let Ok(clone) = ScmpSyscall::from_name("clone") else {
        return Ok(());
    };
    for flag in [
        CLONE_NEWNS,
        CLONE_NEWCGROUP,
        CLONE_NEWUTS,
        CLONE_NEWIPC,
        CLONE_NEWUSER,
        CLONE_NEWPID,
        CLONE_NEWNET,
    ] {
        let comparison = ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(flag), flag);
        context
            .add_rule_conditional(ScmpAction::Errno(libc::EPERM), clone, &[comparison])
            .map_err(|error| {
                PlatformError::SecuritySetup(format!(
                    "deny clone namespace flag {flag:#x}: {error}"
                ))
            })?;
    }
    Ok(())
}
