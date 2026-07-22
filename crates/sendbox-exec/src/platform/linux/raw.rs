//! Audited raw Linux syscall adapter.
//!
//! # Safety boundary
//!
//! This is the only module in the crate allowed to use unsafe code. It owns
//! every descriptor returned by a raw syscall, validates all C strings before
//! crossing the ABI, and prebuilds every argv/env pointer before `clone3`.
//! The post-clone child branch performs only raw syscalls over pre-existing
//! stack/heap data and terminates with `_exit` on failure; it does not allocate,
//! lock, unwind, or invoke Tokio/runtime code.

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::api::{ExitStatus, FileIdentity};
use crate::error::{KernelPrimitive, PlatformError, UnsupportedKernel};

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const REQUIRED_RESOLVE_FLAGS: u64 =
    RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;
const CLONE_PIDFD: u64 = 0x0000_1000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
const P_PIDFD: libc::idtype_t = 3;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const CLONE3_SYSCALL_NUMBER: u32 = 435;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const CHILD_STAGE_SETUP: u8 = 1;
const CHILD_STAGE_SECCOMP: u8 = 2;
const CHILD_STAGE_EXEC: u8 = 3;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

struct ChildExec<'a> {
    executable_fd: RawFd,
    cwd_fd: RawFd,
    argv: &'a [*mut libc::c_char],
    environment: &'a [*mut libc::c_char],
    child_filter: &'a [libc::sock_filter],
    close_fds: &'a [RawFd],
    null_fd: RawFd,
    stdout_pipe: [RawFd; 2],
    stderr_pipe: [RawFd; 2],
    error_pipe: [RawFd; 2],
}

/// Parent-owned descriptors created atomically with the cgroup-placed child.
#[derive(Debug)]
pub(crate) struct SpawnedProcess {
    pub(crate) pidfd: OwnedFd,
    pub(crate) stdout: OwnedFd,
    pub(crate) stderr: OwnedFd,
    pub(crate) exec_error: OwnedFd,
}

pub(crate) fn open_root(path: &Path) -> Result<OwnedFd, PlatformError> {
    let path = cstring_from_os(path.as_os_str(), "root path")?;
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: `path` is a live NUL-terminated C string and flags do not
    // request a variadic mode argument.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    owned_fd(fd, "open trusted root")
}

pub(crate) fn open_beneath(
    root_fd: RawFd,
    relative: &str,
    directory: bool,
) -> Result<OwnedFd, PlatformError> {
    let path = CString::new(relative).map_err(|_| {
        PlatformError::io(
            "validate openat2 path",
            io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"),
        )
    })?;
    let mut flags = libc::O_CLOEXEC;
    if directory {
        flags |= libc::O_PATH | libc::O_DIRECTORY;
    } else {
        flags |= libc::O_RDONLY;
    }
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: REQUIRED_RESOLVE_FLAGS,
    };
    // SAFETY: all pointers refer to live values of the documented ABI sizes.
    let result = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd,
            path.as_ptr(),
            &raw const how,
            size_of::<OpenHow>(),
        )
    };
    if result < 0 {
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::ENOSYS) {
            return Err(unsupported(
                KernelPrimitive::OpenAt2,
                source,
                "openat2 syscall is absent",
            ));
        }
        return Err(PlatformError::io("openat2 beneath root", source));
    }
    // SAFETY: a non-negative openat2 result is a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) })
}

pub(crate) fn identity(fd: RawFd) -> Result<FileIdentity, PlatformError> {
    // SAFETY: zero is a valid initial bit pattern for `stat`, and `fd` is
    // borrowed for the duration of the call.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `&mut stat` is writable and correctly sized.
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        return Err(PlatformError::io(
            "fstat descriptor identity",
            io::Error::last_os_error(),
        ));
    }
    Ok(FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
    })
}

/// Creates a child directly in `cgroup_fd` and returns its pidfd and output
/// descriptors. No fork/spawn fallback exists.
pub(crate) fn clone3_exec(
    cgroup_fd: RawFd,
    executable_fd: RawFd,
    cwd_fd: RawFd,
    argv: &[CString],
    environment: &[CString],
) -> Result<SpawnedProcess, PlatformError> {
    if argv.is_empty() {
        return Err(PlatformError::io(
            "prepare execveat argv",
            io::Error::new(io::ErrorKind::InvalidInput, "argv is empty"),
        ));
    }

    let mut argv_pointers: Vec<*mut libc::c_char> =
        argv.iter().map(|value| value.as_ptr().cast_mut()).collect();
    argv_pointers.push(std::ptr::null_mut());
    let mut environment_pointers: Vec<*mut libc::c_char> = environment
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect();
    environment_pointers.push(std::ptr::null_mut());
    let child_filter = child_clone3_filter()?;

    let stdout_pipe = create_pipe()?;
    let stderr_pipe = create_pipe()?;
    let error_pipe = create_pipe()?;
    let null_fd = match open_dev_null() {
        Ok(fd) => fd,
        Err(error) => {
            close_pipe(stdout_pipe);
            close_pipe(stderr_pipe);
            close_pipe(error_pipe);
            return Err(error);
        }
    };
    let close_fds = match collect_child_close_fds(&[
        executable_fd,
        cwd_fd,
        stdout_pipe[1],
        stderr_pipe[1],
        error_pipe[1],
        null_fd,
    ]) {
        Ok(fds) => fds,
        Err(error) => {
            close_pipe(stdout_pipe);
            close_pipe(stderr_pipe);
            close_pipe(error_pipe);
            close_raw(null_fd);
            return Err(error);
        }
    };
    let mut pidfd = -1;
    let arguments = CloneArgs {
        flags: CLONE_PIDFD | CLONE_INTO_CGROUP,
        pidfd: (&raw mut pidfd) as u64,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: cgroup_fd as u64,
    };

    // SAFETY: `arguments` is the full current clone3 ABI struct, all pointer
    // fields are either zero or point to live stack storage, and this function
    // is called only by the single-thread guard in `launcher`.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw const arguments,
            size_of::<CloneArgs>(),
        )
    };
    if result < 0 {
        close_pipe(stdout_pipe);
        close_pipe(stderr_pipe);
        close_pipe(error_pipe);
        close_raw(null_fd);
        let source = io::Error::last_os_error();
        if matches!(
            source.raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
        ) {
            return Err(unsupported(
                KernelPrimitive::Clone3IntoCgroup,
                source,
                "clone3 with CLONE_INTO_CGROUP|CLONE_PIDFD is unavailable",
            ));
        }
        return Err(PlatformError::io("clone3 into cgroup", source));
    }

    if result == 0 {
        child_exec(ChildExec {
            executable_fd,
            cwd_fd,
            argv: &argv_pointers,
            environment: &environment_pointers,
            child_filter: &child_filter,
            close_fds: &close_fds,
            null_fd,
            stdout_pipe,
            stderr_pipe,
            error_pipe,
        });
    }

    // Parent branch. Close child-owned pipe ends before wrapping parent ends.
    close_raw(stdout_pipe[1]);
    close_raw(stderr_pipe[1]);
    close_raw(error_pipe[1]);
    close_raw(null_fd);
    if pidfd < 0 {
        close_raw(stdout_pipe[0]);
        close_raw(stderr_pipe[0]);
        close_raw(error_pipe[0]);
        return Err(UnsupportedKernel::new(
            KernelPrimitive::Pidfd,
            None,
            "clone3 succeeded without returning a pidfd",
        )
        .into());
    }
    // SAFETY: these descriptors are unique and owned by this parent branch.
    Ok(SpawnedProcess {
        pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
        stdout: unsafe { OwnedFd::from_raw_fd(stdout_pipe[0]) },
        stderr: unsafe { OwnedFd::from_raw_fd(stderr_pipe[0]) },
        exec_error: unsafe { OwnedFd::from_raw_fd(error_pipe[0]) },
    })
}

pub(crate) fn pidfd_send_signal(pidfd: RawFd, signal: i32) -> Result<(), PlatformError> {
    // SAFETY: pidfd is borrowed, siginfo is null by contract, flags are zero.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::ENOSYS) {
            return Err(unsupported(
                KernelPrimitive::PidfdSendSignal,
                source,
                "pidfd_send_signal syscall is absent",
            ));
        }
        return Err(PlatformError::io("pidfd_send_signal", source));
    }
    Ok(())
}

pub(crate) fn pidfd_has_exited(pidfd: RawFd) -> Result<bool, PlatformError> {
    let mut information = zeroed_siginfo();
    // SAFETY: information is valid writable storage; WNOWAIT preserves the
    // zombie for the mandatory cleanup reap.
    let result = unsafe {
        libc::waitid(
            P_PIDFD,
            pidfd as libc::id_t,
            &raw mut information,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(waitid_error());
    }
    Ok(information.si_signo != 0)
}

pub(crate) fn pidfd_reap(pidfd: RawFd) -> Result<ExitStatus, PlatformError> {
    let mut information = zeroed_siginfo();
    // SAFETY: information is valid writable storage and this consumes the
    // waitable child associated with the pidfd.
    let result = unsafe {
        libc::waitid(
            P_PIDFD,
            pidfd as libc::id_t,
            &raw mut information,
            libc::WEXITED,
        )
    };
    if result != 0 {
        return Err(waitid_error());
    }
    // SAFETY: after successful waitid for SIGCHLD, the libc accessor reads
    // the active child-status union field.
    let status = unsafe { information.si_status() };
    if information.si_code == libc::CLD_EXITED {
        Ok(ExitStatus {
            exit_code: Some(status),
            signal: None,
        })
    } else {
        Ok(ExitStatus {
            exit_code: None,
            signal: Some(status),
        })
    }
}

pub(crate) fn set_no_new_privs() -> Result<(), PlatformError> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes only scalar arguments.
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(PlatformError::io(
            "prctl(PR_SET_NO_NEW_PRIVS)",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

pub(crate) fn set_child_subreaper() -> Result<(), PlatformError> {
    // SAFETY: PR_SET_CHILD_SUBREAPER takes only scalar arguments.
    let result = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if result != 0 {
        return Err(PlatformError::io(
            "prctl(PR_SET_CHILD_SUBREAPER)",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

pub(crate) fn open_exec_probe(path: &Path) -> Result<OwnedFd, PlatformError> {
    let path = cstring_from_os(path.as_os_str(), "execveat probe path")?;
    // SAFETY: path is a live C string and flags require no mode argument.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    owned_fd(fd, "open execveat probe descriptor")
}

pub(crate) fn verify_direct_exec_denied(path: &CStr) -> Result<(), PlatformError> {
    let argv = [path.as_ptr(), std::ptr::null()];
    let environment = [std::ptr::null()];
    // SAFETY: the seccomp installer calls this only after loading an
    // execve-denying TSYNC filter. If that invariant holds, this returns
    // EPERM; a successful call cannot return.
    let result = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), environment.as_ptr()) };
    require_eperm(result as libc::c_long, "libc execve")?;
    // SAFETY: same live pointers; the loaded filter must deny the raw number.
    let result = unsafe {
        libc::syscall(
            libc::SYS_execve,
            path.as_ptr(),
            argv.as_ptr(),
            environment.as_ptr(),
        )
    };
    require_eperm(result, "raw execve")
}

pub(crate) fn verify_direct_execveat_denied(fd: RawFd) -> Result<(), PlatformError> {
    let empty = c"";
    let argv = [empty.as_ptr().cast_mut(), std::ptr::null_mut()];
    let environment = [std::ptr::null_mut()];
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: fd is a live executable descriptor and pointers are valid.
        let result = unsafe {
            libc::execveat(
                fd,
                empty.as_ptr(),
                argv.as_ptr(),
                environment.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        require_eperm(result as libc::c_long, "libc execveat")?;
    }
    // SAFETY: same valid ABI data through the raw syscall entry point.
    let result = unsafe {
        raw_execveat(
            fd,
            empty.as_ptr(),
            argv.as_ptr(),
            environment.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    require_eperm(result, "raw execveat")
}

pub(crate) fn verify_memfd_denied() -> Result<(), PlatformError> {
    // SAFETY: the static name is valid and flags are zero.
    let result = unsafe { libc::memfd_create(c"sendbox-agent-probe".as_ptr(), 0) };
    require_eperm(result as libc::c_long, "memfd_create")
}

fn require_eperm(result: libc::c_long, operation: &'static str) -> Result<(), PlatformError> {
    if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        return Ok(());
    }
    Err(PlatformError::SecuritySetup(format!(
        "{operation} verification did not return EPERM"
    )))
}

pub(crate) fn peer_uid(socket_fd: RawFd) -> Result<u32, PlatformError> {
    // SAFETY: zero is a valid initial credential buffer.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials and length are correctly sized writable buffers.
    let result = unsafe {
        libc::getsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        let source = io::Error::last_os_error();
        if matches!(
            source.raw_os_error(),
            Some(libc::ENOPROTOOPT | libc::EINVAL)
        ) {
            return Err(unsupported(
                KernelPrimitive::PeerCredentials,
                source,
                "SO_PEERCRED is unavailable",
            ));
        }
        return Err(PlatformError::io("getsockopt(SO_PEERCRED)", source));
    }
    Ok(credentials.uid)
}

fn open_dev_null() -> Result<RawFd, PlatformError> {
    // SAFETY: the static C string is valid and no mode argument is required.
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(PlatformError::io(
            "open /dev/null for child stdin",
            io::Error::last_os_error(),
        ));
    }
    Ok(fd)
}

fn collect_child_close_fds(preserved: &[RawFd]) -> Result<Vec<RawFd>, PlatformError> {
    let mut descriptors = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")
        .map_err(|source| PlatformError::io("enumerate inherited descriptors", source))?
    {
        let entry =
            entry.map_err(|source| PlatformError::io("read inherited descriptor", source))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(fd) = name.parse::<RawFd>() else {
            continue;
        };
        if fd > libc::STDERR_FILENO && !preserved.contains(&fd) {
            descriptors.push(fd);
        }
    }
    descriptors.sort_unstable();
    descriptors.dedup();
    Ok(descriptors)
}

fn child_clone3_filter() -> Result<Vec<libc::sock_filter>, PlatformError> {
    #[cfg(target_arch = "x86_64")]
    let architectures = [0xc000_003e, 0x4000_0003];
    #[cfg(target_arch = "aarch64")]
    let architectures = [0xc000_00b7, 0x4000_0028];
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return Err(UnsupportedKernel::new(
            KernelPrimitive::Seccomp,
            None,
            format!(
                "child clone3 deny filter is unsupported on {}",
                std::env::consts::ARCH
            ),
        )
        .into());
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        Ok(vec![
            bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
            bpf_jump(BPF_JMP_JEQ_K, architectures[0], 2, 0),
            bpf_jump(BPF_JMP_JEQ_K, architectures[1], 1, 0),
            bpf_statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
            bpf_jump(BPF_JMP_JEQ_K, CLONE3_SYSCALL_NUMBER, 1, 0),
            bpf_jump(BPF_JMP_JEQ_K, X32_SYSCALL_BIT | CLONE3_SYSCALL_NUMBER, 0, 1),
            bpf_statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
            bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW),
        ])
    }
}

const fn bpf_statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn bpf_jump(code: u16, value: u32, jump_true: u8, jump_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

unsafe fn install_child_seccomp(filter: &[libc::sock_filter]) -> libc::c_long {
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: program points to prebuilt immutable BPF storage inherited
    // across clone3 and live for the duration of this raw syscall.
    unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &raw const program,
        )
    }
}

fn child_exec(context: ChildExec<'_>) -> ! {
    // SAFETY: only async-signal-safe syscalls are used in this post-clone
    // branch. All pointers and descriptors were prepared before clone3.
    unsafe {
        libc::close(context.stdout_pipe[0]);
        libc::close(context.stderr_pipe[0]);
        libc::close(context.error_pipe[0]);
        if libc::dup2(context.null_fd, libc::STDIN_FILENO) < 0
            || libc::dup2(context.stdout_pipe[1], libc::STDOUT_FILENO) < 0
            || libc::dup2(context.stderr_pipe[1], libc::STDERR_FILENO) < 0
            || libc::fchdir(context.cwd_fd) < 0
        {
            child_fail(context.error_pipe[1], CHILD_STAGE_SETUP);
        }
        if install_child_seccomp(context.child_filter) != 0 {
            child_fail(context.error_pipe[1], CHILD_STAGE_SECCOMP);
        }
        libc::close(context.stdout_pipe[1]);
        libc::close(context.stderr_pipe[1]);
        libc::close(context.null_fd);
        libc::close(context.cwd_fd);
        for fd in context.close_fds {
            libc::close(*fd);
        }
        raw_execveat(
            context.executable_fd,
            c"".as_ptr(),
            context.argv.as_ptr(),
            context.environment.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
        child_fail(context.error_pipe[1], CHILD_STAGE_EXEC);
    }
}

unsafe fn raw_execveat(
    fd: RawFd,
    path: *const libc::c_char,
    argv: *const *mut libc::c_char,
    environment: *const *mut libc::c_char,
    flags: libc::c_int,
) -> libc::c_long {
    // SAFETY: callers provide the exact execveat ABI and keep all pointed-to
    // values live for the duration of the syscall.
    unsafe { libc::syscall(libc::SYS_execveat, fd, path, argv, environment, flags) }
}

unsafe fn child_fail(error_fd: RawFd, stage: u8) -> ! {
    // SAFETY: called only immediately after a failed libc syscall in the
    // post-clone child, so the thread-local errno slot contains that failure.
    let errno = unsafe { *libc::__errno_location() };
    let errno_bytes = errno.to_ne_bytes();
    let bytes = [
        stage,
        errno_bytes[0],
        errno_bytes[1],
        errno_bytes[2],
        errno_bytes[3],
    ];
    // SAFETY: error_fd is the dedicated pipe and bytes is valid stack data.
    unsafe {
        libc::write(error_fd, bytes.as_ptr().cast(), bytes.len());
        libc::_exit(127);
    }
}

fn create_pipe() -> Result<[RawFd; 2], PlatformError> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors is a writable two-element fd array.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(PlatformError::io(
            "pipe2 launcher channel",
            io::Error::last_os_error(),
        ));
    }
    Ok(descriptors)
}

fn close_pipe(descriptors: [RawFd; 2]) {
    close_raw(descriptors[0]);
    close_raw(descriptors[1]);
}

fn close_raw(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: close tolerates any live descriptor; errors are irrelevant
        // while unwinding a failed setup path.
        unsafe {
            libc::close(fd);
        }
    }
}

fn owned_fd(fd: RawFd, operation: &'static str) -> Result<OwnedFd, PlatformError> {
    if fd < 0 {
        return Err(PlatformError::io(operation, io::Error::last_os_error()));
    }
    // SAFETY: a successful open returns a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn cstring_from_os(value: &OsStr, operation: &'static str) -> Result<CString, PlatformError> {
    CString::new(value.as_bytes()).map_err(|_| {
        PlatformError::io(
            operation,
            io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"),
        )
    })
}

fn unsupported(
    primitive: KernelPrimitive,
    source: io::Error,
    detail: &'static str,
) -> PlatformError {
    UnsupportedKernel::new(primitive, source.raw_os_error(), detail).into()
}

fn zeroed_siginfo() -> libc::siginfo_t {
    // SAFETY: all-zero is a valid empty siginfo buffer for waitid.
    unsafe { std::mem::zeroed() }
}

fn waitid_error() -> PlatformError {
    let source = io::Error::last_os_error();
    if matches!(source.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) {
        unsupported(
            KernelPrimitive::WaitidPidfd,
            source,
            "waitid(P_PIDFD) is unavailable",
        )
    } else {
        PlatformError::io("waitid(P_PIDFD)", source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn openat2_rejects_symlinks_beneath_root() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::write(directory.path().join("real"), b"x").expect("write");
        std::os::unix::fs::symlink("real", directory.path().join("link")).expect("symlink");
        let root = open_root(directory.path()).expect("root");
        let error = open_beneath(root.as_raw_fd(), "link", false).expect_err("must reject link");
        assert!(matches!(error, PlatformError::Io { .. }));
    }
}
