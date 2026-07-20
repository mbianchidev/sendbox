//! Trusted agent bootstrap installed before any untrusted callback runs.

#![forbid(unsafe_code)]

use std::ffi::CString;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::error::PlatformError;

use super::{raw, seccomp};

/// Proof object constructible only after NNP, TSYNC seccomp, and direct-exec
/// verification have succeeded.
#[derive(Debug)]
pub struct AgentBootstrap {
    _private: (),
}

impl AgentBootstrap {
    pub fn install() -> Result<Self, PlatformError> {
        let execveat_probe = raw::open_exec_probe(Path::new("/proc/self/exe"))?;
        let mut execve_probes = vec![
            CString::new("/proc/self/exe").expect("static path"),
            CString::new("/bin/sh").expect("static path"),
        ];
        for linker in [
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/ld-linux-aarch64.so.1",
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        ] {
            if Path::new(linker).exists() {
                execve_probes.push(CString::new(linker).expect("static path"));
            }
        }
        raw::set_no_new_privs()?;
        seccomp::install(seccomp::Profile::AgentBootstrap)?;
        if !no_new_privs_is_set()? {
            return Err(PlatformError::SecuritySetup(
                "NoNewPrivs was not visible on the calling thread".into(),
            ));
        }
        for path in &execve_probes {
            raw::verify_direct_exec_denied(path)?;
        }
        raw::verify_direct_execveat_denied(execveat_probe.as_raw_fd())?;
        raw::verify_memfd_denied()?;
        Ok(Self { _private: () })
    }

    /// Runs the callback only after all bootstrap verification is complete.
    pub fn run_untrusted<T>(self, callback: impl FnOnce() -> T) -> T {
        callback()
    }

    /// Verifies an additional pre-existing executable path (including a
    /// shebang script) is denied by both libc and raw execve entry points.
    pub fn verify_exec_path_denied(&self, path: &Path) -> Result<(), PlatformError> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            PlatformError::SecuritySetup("exec probe path contains a NUL byte".into())
        })?;
        raw::verify_direct_exec_denied(&path)
    }
}

fn no_new_privs_is_set() -> Result<bool, PlatformError> {
    let status = fs::read_to_string("/proc/thread-self/status")
        .map_err(|source| PlatformError::io("read /proc/thread-self/status", source))?;
    Ok(status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .is_some_and(|value| value.trim() == "1"))
}
