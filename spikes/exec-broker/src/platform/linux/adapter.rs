//! The single, tiny, isolated home for every `unsafe` operation in this
//! crate.
//!
//! # Why this module needs `unsafe` at all
//!
//! Three things here have no safe wrapper available anywhere in the
//! dependency graph used by this crate:
//!
//! 1. `prctl(PR_SET_NO_NEW_PRIVS, ...)` — required before an unprivileged
//!    process may install a seccomp filter, and neither `nix` nor `rustix`
//!    expose a safe wrapper for this specific `prctl` operation.
//! 2. `memfd_create(2)` — used only by the syscall probe to prove that
//!    executing straight out of an anonymous, in-memory file is denied.
//! 3. Direct libc/raw-syscall invocations of `execve`/`execveat` — used
//!    only by the syscall probe to prove the installed seccomp filter
//!    actually denies them, bypassing any higher-level wrapper that might
//!    otherwise mask the raw syscall boundary being tested.
//! 4. `setsid`/`setpgid`/`ptrace(PTRACE_TRACEME)`/the raw
//!    `io_uring_setup` syscall — used only by the `exec-broker-test-helper`
//!    binary's `highrisk` mode to prove a launcher's descendant cannot
//!    leave its process group or perform other representative high-risk
//!    operations; same "isolated adapter" rationale as (3).
//!
//! # Invariants callers must uphold
//!
//! * Every `attempt_*` function in this module **must** be called only
//!   after [`set_no_new_privs`] and a seccomp filter denying
//!   `execve`/`execveat`/`memfd_create` has already been installed and
//!   loaded in the *calling thread* (and, thanks to `TSYNC`, therefore in
//!   every thread of the process). Calling these functions beforehand
//!   would, on success, replace the calling process's image and never
//!   return — there is no way to safely "undo" a successful `exec`. This is
//!   precisely why these functions exist only to be driven from a
//!   dedicated, disposable probe binary/mode (see
//!   `bin/agent.rs`), never from the crate's own test harness process.
//! * [`create_memfd`]/[`write_fd`]/[`open_executable_fd`], by contrast,
//!   **must** be called *before* the filter is installed: `memfd_create`
//!   itself is in the same denylist as `execve`/`execveat` (every profile
//!   denies it unconditionally, see `platform::linux::seccomp`), so a
//!   filter installed first would make `create_memfd`/`open_executable_fd`
//!   themselves fail with `EPERM` before an `execveat`-by-fd attempt could
//!   even be constructed — proving only that `memfd_create`/`open` is
//!   denied, never that `execveat` against an fd that legitimately already
//!   exists is *also* independently denied. `bin/agent.rs`'s `run`
//!   therefore creates/populates the memfd and opens the `/bin/true` fd
//!   during trusted bootstrap, strictly before installing the filter and
//!   before parsing any untrusted input (argv), then threads those
//!   already-open fds into the post-filter probe attempts.
//! * All C strings passed to the FFI/raw-syscall attempts here are
//!   constructed from Rust string literals or already-validated paths
//!   local to this module; none of it is influenced by untrusted network
//!   input.

#![allow(unsafe_code)]

use crate::error::PlatformError;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::io::RawFd;

/// Sets `PR_SET_NO_NEW_PRIVS` on the calling thread. Note that this
/// attribute is genuinely **per-thread**, not per-process, despite being
/// inherited across `fork`/`exec`: a multi-threaded process must ensure
/// every thread that could execute untrusted code has it set (in this
/// crate's design, it is set on the single bootstrap thread before any
/// other thread is created, and TSYNC extends the accompanying seccomp
/// filter to any threads created later).
pub fn set_no_new_privs() -> Result<(), PlatformError> {
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` takes no pointer
    // arguments that could be misinterpreted; the three trailing zero
    // arguments are the documented "unused" arguments for this operation
    // (see prctl(2)). The return value is checked below.
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
    if result != 0 {
        return Err(PlatformError::Prctl {
            operation: "PR_SET_NO_NEW_PRIVS",
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// Reads back whether `no_new_privs` is currently set *for the calling
/// thread*, by parsing `/proc/thread-self/status`. Used only by tests to
/// confirm [`set_no_new_privs`] took effect; involves no `unsafe` itself.
///
/// Deliberately reads `/proc/thread-self/status`, not `/proc/self/status`:
/// `NoNewPrivs` is a per-thread attribute, and `/proc/self` resolves to the
/// thread-group leader's entry rather than the calling thread's own entry.
/// Since Rust's test harness (and `tokio`'s worker pool) run on OS threads
/// that are not the process's main/leader thread, reading `/proc/self`
/// here would spuriously report `false` even immediately after a
/// successful `set_no_new_privs()` call on that same (non-leader) thread.
pub fn no_new_privs_is_set() -> io::Result<bool> {
    let status = fs::read_to_string("/proc/thread-self/status")?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("NoNewPrivs:") {
            return Ok(value.trim() == "1");
        }
    }
    Ok(false)
}

/// The outcome of one attempted `exec`-family call or syscall, always
/// expected to be [`ExecAttemptOutcome::Denied`] once a filter is loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecAttemptOutcome {
    /// The kernel denied the syscall with the given `errno`. This is the
    /// expected, successful-test outcome once the seccomp filter is
    /// active.
    Denied { errno: i32 },
    /// The syscall was **not** denied and would have replaced the process
    /// image. This function only returns this value in the (should never
    /// happen once a filter is loaded) case where the kernel reported
    /// success without actually replacing the calling process — which does
    /// not occur in practice for `execve`/`execveat`, so observing this
    /// variant at all is itself a sandboxing failure worth flagging loudly.
    UnexpectedSuccess,
    /// Setting up the attempt itself failed (e.g. could not open a helper
    /// file), distinct from the syscall under test being denied.
    SetupFailed { message: String },
}

/// Attempts `execve` of `path` via the libc wrapper, with an empty argv/
/// envp. Used to prove the seccomp filter denies `execve` regardless of
/// what target path is requested — a script, the dynamic linker,
/// `/proc/self/exe`, an alternate interpreter, or an ordinary ELF binary
/// all hit the same denied syscall.
#[must_use]
pub fn attempt_libc_execve(path: &str) -> ExecAttemptOutcome {
    let Ok(path) = CString::new(path) else {
        return ExecAttemptOutcome::SetupFailed {
            message: "failed to build CString".to_string(),
        };
    };
    let argv: [*const libc::c_char; 2] = [path.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: `path`, `argv`, and `envp` are all valid, NUL-terminated
    // arrays kept alive for the duration of this call. Per the module
    // invariant, this is only reachable after a seccomp filter denying
    // `execve` has been loaded, so this call cannot actually replace the
    // process image; it can only return -1/EPERM.
    let result = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    exec_result_to_outcome(result)
}

/// Attempts the raw `execve` syscall (bypassing the libc wrapper) on
/// `path`.
#[must_use]
pub fn attempt_raw_syscall_execve(path: &str) -> ExecAttemptOutcome {
    let Ok(path) = CString::new(path) else {
        return ExecAttemptOutcome::SetupFailed {
            message: "failed to build CString".to_string(),
        };
    };
    let argv: [*const libc::c_char; 2] = [path.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: see `attempt_libc_execve`; this issues the same logical call
    // through `libc::syscall` to prove the seccomp filter denies the
    // syscall number directly, not merely the libc entry point.
    let result = unsafe {
        libc::syscall(
            libc::SYS_execve,
            path.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    exec_result_to_outcome(result as i32)
}

/// Attempts `execveat` via the libc wrapper on an already-open file
/// descriptor, using `AT_EMPTY_PATH` (the memfd/"exec this fd" idiom).
#[must_use]
pub fn attempt_libc_execveat_fd(fd: RawFd) -> ExecAttemptOutcome {
    let empty = CString::new("").expect("empty CString is always valid");
    // `execveat`'s libc binding declares `argv`/`envp` as `*const *mut
    // c_char` (matching the C prototype's non-`const`-qualified `char
    // *const argv[]` idiom) even though the kernel never mutates through
    // them; `.cast_mut()` reflects that without any real mutation ever
    // occurring.
    let argv: [*mut libc::c_char; 2] = [empty.as_ptr().cast_mut(), std::ptr::null_mut()];
    let envp: [*mut libc::c_char; 1] = [std::ptr::null_mut()];
    // SAFETY: `fd` is a valid, caller-owned file descriptor; `empty`/`argv`
    // /`envp` are valid NUL-terminated data kept alive for this call. Only
    // reachable post-filter-install per the module invariant.
    let result = unsafe {
        libc::execveat(
            fd,
            empty.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    exec_result_to_outcome(result)
}

/// Attempts the raw `execveat` syscall (bypassing the libc wrapper).
#[must_use]
pub fn attempt_raw_syscall_execveat_fd(fd: RawFd) -> ExecAttemptOutcome {
    let empty = CString::new("").expect("empty CString is always valid");
    let argv: [*mut libc::c_char; 2] = [empty.as_ptr().cast_mut(), std::ptr::null_mut()];
    let envp: [*mut libc::c_char; 1] = [std::ptr::null_mut()];
    // SAFETY: see `attempt_libc_execveat_fd`.
    let result = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            empty.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    exec_result_to_outcome(result as i32)
}

/// Creates an anonymous, sealed-less `memfd`, returning its file
/// descriptor. Used only to set up the memfd-execution probe attempt; does
/// not itself attempt to execute anything.
pub fn create_memfd(name: &str) -> Result<RawFd, PlatformError> {
    let name = CString::new(name)
        .map_err(|e| PlatformError::ProbeSetup(format!("bad memfd name: {e}")))?;
    // SAFETY: `name` is a valid NUL-terminated string kept alive for the
    // duration of the call; `flags` is `0`, a valid, documented value.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        return Err(PlatformError::ProbeSetup(format!(
            "memfd_create failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(fd)
}

/// Writes `data` to the file descriptor `fd` using the raw `write(2)`
/// syscall via libc. Used only to populate the memfd probe fixture.
pub fn write_fd(fd: RawFd, data: &[u8]) -> Result<(), PlatformError> {
    // SAFETY: `fd` is caller-owned and `data` is a valid slice for
    // `data.len()` bytes for the duration of the call.
    let written = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if written < 0 || written as usize != data.len() {
        return Err(PlatformError::ProbeSetup(format!(
            "write to memfd failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Opens `path` read-only, returning its file descriptor. Used only to set
/// up the "already-open executable fd" fixture for the `execveat`-by-fd
/// probe (see the module doc comment's invariant: this must be called
/// *before* any filter denying `open`/`execveat` is installed, so the
/// probe attempt afterward exercises a real, pre-existing fd rather than
/// failing during its own setup).
pub fn open_executable_fd(path: &str) -> Result<RawFd, PlatformError> {
    let cpath =
        CString::new(path).map_err(|e| PlatformError::ProbeSetup(format!("bad path: {e}")))?;
    // SAFETY: `cpath` is a valid NUL-terminated string kept alive for the
    // duration of the call; `O_RDONLY` is a valid, documented flag value
    // and takes no further arguments.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(PlatformError::ProbeSetup(format!(
            "open({path}) failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(fd)
}

/// Closes a file descriptor previously obtained from [`create_memfd`] or
/// [`open_executable_fd`]. Provided so callers outside this module (which
/// otherwise deny `unsafe_code` crate-wide) can clean up probe fixtures
/// without needing their own `unsafe` block.
pub fn close_fd(fd: RawFd) {
    // SAFETY: the caller is required to pass an `fd` it owns (obtained
    // from `create_memfd`/`open_executable_fd`) that has not already been
    // closed; `close` on an fd is always safe to call and its result is
    // deliberately not inspected here since this is purely best-effort
    // probe-fixture cleanup, not a resource whose leak would be
    // security-relevant beyond an ordinary fd leak in this short-lived
    // probe binary.
    unsafe {
        libc::close(fd);
    }
}

fn exec_result_to_outcome(result: i32) -> ExecAttemptOutcome {
    if result == -1 {
        ExecAttemptOutcome::Denied {
            errno: io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default(),
        }
    } else {
        ExecAttemptOutcome::UnexpectedSuccess
    }
}

/// The outcome of one attempted non-exec high-risk syscall (`setsid`,
/// `setpgid`, `memfd_create`, `ptrace`, `io_uring_setup`, ...), used by
/// the `exec-broker-test-helper` binary's `highrisk` mode to prove a
/// launcher's descendants cannot perform any of these operations. Distinct from
/// [`ExecAttemptOutcome`] only in naming (these calls do not "replace the
/// process image" on success, they instead have some other observable
/// side effect), kept as a separate type so callers cannot mix up which
/// probe family produced a given result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallAttemptOutcome {
    /// The kernel denied the syscall with the given `errno` — the
    /// expected outcome for every one of these probes once the
    /// `Launcher` seccomp profile (or the unconditional
    /// `ALWAYS_DENIED`/`memfd_create` rules) is active.
    Denied { errno: i32 },
    /// The syscall succeeded. For every syscall this module's `attempt_*`
    /// functions probe, this is a containment failure worth flagging
    /// loudly, never a "the descendant did something legitimate" result.
    UnexpectedSuccess,
    /// Setting up the attempt itself failed, distinct from the syscall
    /// under test being denied.
    SetupFailed { message: String },
}

fn syscall_result_to_outcome(result: i64) -> SyscallAttemptOutcome {
    if result < 0 {
        SyscallAttemptOutcome::Denied {
            errno: io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default(),
        }
    } else {
        SyscallAttemptOutcome::UnexpectedSuccess
    }
}

/// Attempts `setsid(2)` via the libc wrapper. A launcher's target (and any
/// descendant it spawns) is expected to have this denied by the
/// `Launcher` seccomp profile, so it can never leave the process group
/// the broker placed it in.
#[must_use]
pub fn attempt_setsid() -> SyscallAttemptOutcome {
    // SAFETY: `setsid` takes no arguments; its return value (new session
    // id on success, -1/errno on failure) is checked below. If this
    // unexpectedly succeeds it only changes this (short-lived, disposable
    // probe) process's own session — no other resource is at stake.
    let result = unsafe { libc::setsid() };
    syscall_result_to_outcome(result as i64)
}

/// Attempts `setpgid(0, 0)` via the libc wrapper (move the calling
/// process into a new process group led by itself). Also expected to be
/// denied by the `Launcher` profile.
#[must_use]
pub fn attempt_setpgid() -> SyscallAttemptOutcome {
    // SAFETY: `setpgid(0, 0)` operates only on the calling process; its
    // return value is checked below.
    let result = unsafe { libc::setpgid(0, 0) };
    syscall_result_to_outcome(result as i64)
}

/// Attempts `memfd_create(2)` via the libc wrapper, used by the
/// `highrisk` probe (unlike [`create_memfd`], which is a trusted-bootstrap
/// fixture helper meant to be called *before* a filter is installed, this
/// function is meant to be called *after* one, to prove `memfd_create`
/// itself is denied to a launcher's descendants). Closes the fd
/// immediately if the call unexpectedly succeeds, so this probe never
/// leaks an fd even in the failure-to-contain case.
#[must_use]
pub fn attempt_memfd_create(name: &str) -> SyscallAttemptOutcome {
    let Ok(name) = CString::new(name) else {
        return SyscallAttemptOutcome::SetupFailed {
            message: "failed to build CString".to_string(),
        };
    };
    // SAFETY: `name` is a valid NUL-terminated string kept alive for the
    // call; `flags` is `0`, a documented valid value.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd >= 0 {
        close_fd(fd);
    }
    syscall_result_to_outcome(fd as i64)
}

/// Attempts `ptrace(PTRACE_TRACEME, ...)` via the libc wrapper, used by
/// the `highrisk` probe. `PTRACE_TRACEME` is chosen because it requires
/// no target pid/permissions of its own to attempt (unlike
/// `PTRACE_ATTACH`, which could otherwise fail for permission reasons
/// unrelated to the seccomp filter under test) — any denial observed here
/// is therefore attributable to the filter, not to an unrelated
/// permission check.
#[must_use]
pub fn attempt_ptrace_traceme() -> SyscallAttemptOutcome {
    // SAFETY: `PTRACE_TRACEME` takes no further meaningful arguments; the
    // trailing three are ignored by the kernel for this request. Return
    // value is checked below.
    let result = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
    syscall_result_to_outcome(result)
}

/// Attempts the raw `io_uring_setup(2)` syscall (no libc wrapper exists
/// in the `libc` crate for this one), used by the `highrisk` probe.
/// Passes a valid, zeroed `struct io_uring_params` on the stack so any
/// denial observed is attributable to the seccomp filter itself, not to
/// an invalid-argument failure that would occur even without a filter.
#[must_use]
pub fn attempt_raw_io_uring_setup() -> SyscallAttemptOutcome {
    // 120 bytes is `size_of::<io_uring_params>()` on every architecture
    // this crate targets (the struct is a fixed layout defined by the
    // stable io_uring ABI); zeroed is a valid "no flags requested" value.
    let mut params = [0u8; 120];
    // SAFETY: `params.as_mut_ptr()` points to a valid, writable 120-byte
    // stack buffer for the duration of this call, matching
    // `io_uring_setup`'s documented `struct io_uring_params *` argument;
    // `entries = 1` is a minimal, valid value. If this unexpectedly
    // succeeds the kernel returns an owned fd, which the caller does not
    // currently close (this only happens in the containment-failure case
    // this probe exists to detect, and the probe process is short-lived).
    let result = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
    syscall_result_to_outcome(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_no_new_privs_takes_effect() {
        // NNP is a one-way ratchet and harmless to other tests in this
        // process (unlike installing a seccomp filter, which would be),
        // so it is safe to exercise directly in the shared test binary.
        set_no_new_privs().expect("set_no_new_privs should succeed");
        assert!(no_new_privs_is_set().expect("read /proc/self/status"));
    }

    #[test]
    fn memfd_create_and_write_succeed_without_a_filter_installed() {
        // This test intentionally does NOT install a seccomp filter, so it
        // is safe to run in the shared cargo-test process: it only proves
        // the *setup* half of the memfd probe attempt works, not the
        // (filter-dependent) exec-denial half, which is exercised from the
        // isolated `agent probe` binary instead.
        let fd = create_memfd("exec-broker-adapter-test").expect("create_memfd");
        write_fd(fd, b"not a real ELF, just probe fixture bytes").expect("write_fd");
        close_fd(fd);
    }

    #[test]
    fn open_executable_fd_and_close_fd_succeed_without_a_filter_installed() {
        // Same rationale as above: only proves the setup half (opening a
        // real executable fd ahead of any filter) works; the
        // filter-dependent execveat-denial half is exercised from the
        // isolated `agent probe` binary.
        let fd = open_executable_fd("/bin/true").expect("open_executable_fd");
        assert!(fd >= 0);
        close_fd(fd);
    }

    // The following tests intentionally do NOT install a seccomp filter
    // (this is the shared cargo-test process), so every one of these
    // high-risk probes is expected to *succeed* here — that is precisely
    // what makes them meaningful probes when run instead from
    // `exec-broker-test-helper`'s `highrisk` mode inside a launcher's
    // `Launcher`-profile-filtered descendant, where they must instead be
    // `Denied`. These tests only prove the setup/dispatch machinery
    // itself (correct syscall numbers/argument shapes, no panics), not
    // the filter-dependent denial, matching this module's established
    // convention for its other "no filter installed" tests above.

    #[test]
    fn attempt_setsid_setup_succeeds_without_a_filter_installed() {
        // Forking is required because a real `setsid()` call changes the
        // calling process's session, which would be disruptive to the
        // shared test-harness process otherwise.
        run_in_forked_child(|| {
            let outcome = attempt_setsid();
            assert_eq!(outcome, SyscallAttemptOutcome::UnexpectedSuccess);
        });
    }

    #[test]
    fn attempt_setpgid_setup_succeeds_without_a_filter_installed() {
        run_in_forked_child(|| {
            let outcome = attempt_setpgid();
            assert_eq!(outcome, SyscallAttemptOutcome::UnexpectedSuccess);
        });
    }

    #[test]
    fn attempt_memfd_create_setup_succeeds_without_a_filter_installed() {
        let outcome = attempt_memfd_create("exec-broker-adapter-highrisk-test");
        assert_eq!(outcome, SyscallAttemptOutcome::UnexpectedSuccess);
    }

    #[test]
    fn attempt_ptrace_traceme_setup_succeeds_without_a_filter_installed() {
        run_in_forked_child(|| {
            let outcome = attempt_ptrace_traceme();
            assert_eq!(outcome, SyscallAttemptOutcome::UnexpectedSuccess);
        });
    }

    #[test]
    fn attempt_raw_io_uring_setup_succeeds_or_is_unsupported_without_a_filter_installed() {
        // io_uring can be disabled at the kernel level (sysctl
        // `kernel.io_uring_disabled`) independent of seccomp, so a
        // filter-free environment may still legitimately report `Denied`
        // with `EPERM`/`ENOSYS` here; this test only asserts the call
        // dispatches correctly and never panics, not a specific outcome.
        let outcome = attempt_raw_io_uring_setup();
        match outcome {
            SyscallAttemptOutcome::UnexpectedSuccess | SyscallAttemptOutcome::Denied { .. } => {}
            SyscallAttemptOutcome::SetupFailed { message } => {
                panic!("attempt_raw_io_uring_setup should not fail to set up: {message}")
            }
        }
    }

    /// Runs `body` in a forked child process and asserts the child
    /// observed no panic, without letting `body`'s own process/session
    /// mutations (e.g. `setsid`) leak into the shared test-harness
    /// process. Used only by tests in this module for syscalls whose
    /// success would otherwise mutate calling-process-global state.
    fn run_in_forked_child(body: impl FnOnce()) {
        // SAFETY: `fork()` itself is always safe to call; the child only
        // calls the provided closure and then `_exit`s immediately without
        // returning through any unwinding path, so there is no risk of
        // running destructors twice or otherwise corrupting parent state
        // shared via copy-on-write pages.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            body();
            // SAFETY: `_exit` never returns; skips atexit/Drop handlers,
            // which is exactly what is wanted here (the parent's harness
            // state must not be touched by this disposable child).
            unsafe { libc::_exit(0) };
        }
        let mut status: i32 = 0;
        // SAFETY: `&mut status` is a valid pointer to a local for the
        // duration of the call.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(
            waited,
            pid,
            "waitpid failed: {}",
            io::Error::last_os_error()
        );
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "forked child did not exit cleanly (status={status}); its assertion likely failed"
        );
    }
}
