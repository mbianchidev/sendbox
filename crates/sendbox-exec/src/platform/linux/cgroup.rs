//! Cgroup v2 subtree, atomic-placement leaf, and ordered cleanup lifecycle.

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sendbox_core::SessionId;

use crate::api::{CleanupFailure, CleanupReport, CleanupStep, ContainmentProfile, ExitStatus};
use crate::error::{KernelPrimitive, PlatformError, UnsupportedKernel};

use super::raw;

/// Supervisor-owned cgroup subtree. It is always created fresh.
#[derive(Debug)]
pub struct CgroupManager {
    root: PathBuf,
    next_leaf: AtomicU64,
}

impl CgroupManager {
    /// Creates a fresh subtree below a delegated cgroup-v2 parent.
    pub fn create(parent: &Path, session_id: SessionId) -> Result<Self, PlatformError> {
        require_cgroup_v2(parent)?;
        enable_controllers(parent)?;
        let root = parent.join(format!("sendbox-{session_id}"));
        fs::create_dir(&root).map_err(|source| {
            if matches!(
                source.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
            ) {
                unsupported(
                    KernelPrimitive::CgroupDelegation,
                    &source,
                    "cannot create supervisor-owned cgroup subtree",
                )
            } else {
                PlatformError::io("create cgroup subtree", source)
            }
        })?;
        if let Err(error) = enable_controllers(&root) {
            let _ = fs::remove_dir(&root);
            return Err(error);
        }
        Ok(Self {
            root,
            next_leaf: AtomicU64::new(1),
        })
    }

    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// Configures a fresh leaf fully before any child can be created.
    pub fn create_leaf(&self, profile: &ContainmentProfile) -> Result<CgroupLeaf, PlatformError> {
        let id = self.next_leaf.fetch_add(1, Ordering::Relaxed);
        let path = self.root.join(format!("command-{id:016x}"));
        fs::create_dir(&path).map_err(|source| PlatformError::io("create cgroup leaf", source))?;
        let result = configure_leaf(&path, profile).and_then(|()| {
            if !path.join("cgroup.kill").is_file() {
                return Err(UnsupportedKernel::new(
                    KernelPrimitive::CgroupKill,
                    None,
                    "cgroup.kill is absent from the command leaf",
                )
                .into());
            }
            let descriptor = File::open(&path)
                .map_err(|source| PlatformError::io("open cgroup leaf", source))?;
            Ok(CgroupLeaf {
                path: path.clone(),
                descriptor,
            })
        });
        if result.is_err() {
            let _ = fs::remove_dir(&path);
        }
        result
    }

    /// Removes the empty supervisor subtree after every leaf is gone.
    pub fn remove(self) -> Result<(), PlatformError> {
        fs::remove_dir(&self.root)
            .map_err(|source| PlatformError::io("remove cgroup subtree", source))
    }
}

/// One fully configured command leaf.
#[derive(Debug)]
pub struct CgroupLeaf {
    path: PathBuf,
    descriptor: File,
}

impl CgroupLeaf {
    #[must_use]
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.descriptor.as_raw_fd()
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Removes an unpopulated leaf when launch failed before clone3.
    pub fn remove_unlaunched(self) -> CleanupReport {
        let mut report = CleanupReport {
            status: crate::api::CleanupStatus::NoChild,
            attempted: vec![CleanupStep::RemoveLeaf],
            failures: Vec::new(),
        };
        if let Err(error) = fs::remove_dir(&self.path) {
            report.status = crate::api::CleanupStatus::Incomplete;
            report.failures.push(CleanupFailure {
                step: CleanupStep::RemoveLeaf,
                message: error.to_string(),
            });
        }
        report
    }

    /// Mandatory cleanup order: cgroup.kill, pidfd reap, bounded populated=0
    /// observation, and leaf removal.
    pub fn cleanup(
        self,
        pidfd: RawFd,
        wait_bound: Duration,
    ) -> (CleanupReport, Option<ExitStatus>) {
        let attempted = vec![
            CleanupStep::CgroupKill,
            CleanupStep::PidfdReap,
            CleanupStep::ObserveUnpopulated,
            CleanupStep::RemoveLeaf,
        ];
        let mut failures = Vec::new();

        if let Err(error) = fs::write(self.path.join("cgroup.kill"), b"1\n") {
            failures.push(CleanupFailure {
                step: CleanupStep::CgroupKill,
                message: error.to_string(),
            });
            if let Err(signal_error) = raw::pidfd_send_signal(pidfd, libc::SIGKILL) {
                failures.push(CleanupFailure {
                    step: CleanupStep::CgroupKill,
                    message: format!(
                        "cgroup.kill failed and defensive pidfd SIGKILL also failed: {signal_error}"
                    ),
                });
            }
        }

        let exit_status = match wait_pidfd_exit(pidfd, wait_bound) {
            Ok(()) => match raw::pidfd_reap(pidfd) {
                Ok(status) => Some(status),
                Err(error) => {
                    failures.push(CleanupFailure {
                        step: CleanupStep::PidfdReap,
                        message: error.to_string(),
                    });
                    None
                }
            },
            Err(error) => {
                failures.push(CleanupFailure {
                    step: CleanupStep::PidfdReap,
                    message: error.to_string(),
                });
                None
            }
        };

        if let Err(error) = wait_unpopulated(&self.path, wait_bound) {
            failures.push(CleanupFailure {
                step: CleanupStep::ObserveUnpopulated,
                message: error.to_string(),
            });
        }

        if let Err(error) = fs::remove_dir(&self.path) {
            failures.push(CleanupFailure {
                step: CleanupStep::RemoveLeaf,
                message: error.to_string(),
            });
        }

        (
            CleanupReport::from_attempts(attempted, failures),
            exit_status,
        )
    }
}

fn require_cgroup_v2(parent: &Path) -> Result<(), PlatformError> {
    let controllers = parent.join("cgroup.controllers");
    if !controllers.is_file() {
        return Err(UnsupportedKernel::new(
            KernelPrimitive::CgroupV2,
            None,
            format!("{} does not expose cgroup.controllers", parent.display()),
        )
        .into());
    }
    Ok(())
}

fn enable_controllers(path: &Path) -> Result<(), PlatformError> {
    let available = fs::read_to_string(path.join("cgroup.controllers"))
        .map_err(|source| PlatformError::io("read cgroup.controllers", source))?;
    for required in ["pids", "memory"] {
        if !available
            .split_ascii_whitespace()
            .any(|value| value == required)
        {
            return Err(UnsupportedKernel::new(
                KernelPrimitive::CgroupDelegation,
                None,
                format!("required {required} controller is not delegated"),
            )
            .into());
        }
    }
    let mut enable = "+pids +memory".to_owned();
    if available
        .split_ascii_whitespace()
        .any(|value| value == "cpu")
    {
        enable.push_str(" +cpu");
    }
    enable.push('\n');
    fs::write(path.join("cgroup.subtree_control"), enable).map_err(|source| {
        unsupported(
            KernelPrimitive::CgroupDelegation,
            &source,
            "cannot enable pids and memory controllers",
        )
    })
}

fn configure_leaf(path: &Path, profile: &ContainmentProfile) -> Result<(), PlatformError> {
    fs::write(path.join("pids.max"), format!("{}\n", profile.pids_max))
        .map_err(|source| PlatformError::io("write pids.max", source))?;
    write_optional_limit(
        path.join("memory.max"),
        profile.memory_max_bytes,
        "write memory.max",
    )?;
    write_optional_limit(
        path.join("memory.swap.max"),
        profile.memory_swap_max_bytes,
        "write memory.swap.max",
    )?;
    if let Some(cpu_max) = &profile.cpu_max {
        let cpu_path = path.join("cpu.max");
        if !cpu_path.is_file() {
            return Err(UnsupportedKernel::new(
                KernelPrimitive::CgroupDelegation,
                None,
                "cpu controller is not delegated for configured cpu.max",
            )
            .into());
        }
        fs::write(cpu_path, format!("{cpu_max}\n"))
            .map_err(|source| PlatformError::io("write cpu.max", source))?;
    }
    Ok(())
}

fn write_optional_limit(
    path: PathBuf,
    value: Option<u64>,
    operation: &'static str,
) -> Result<(), PlatformError> {
    let value = value.map_or_else(|| "max\n".to_owned(), |limit| format!("{limit}\n"));
    fs::write(path, value).map_err(|source| PlatformError::io(operation, source))
}

fn wait_unpopulated(path: &Path, bound: Duration) -> Result<(), io::Error> {
    let deadline = Instant::now() + bound;
    loop {
        let events = fs::read_to_string(path.join("cgroup.events"))?;
        if events
            .lines()
            .any(|line| line.split_once(' ') == Some(("populated", "0")))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "cgroup remained populated past cleanup bound",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_pidfd_exit(pidfd: RawFd, bound: Duration) -> Result<(), io::Error> {
    let deadline = Instant::now() + bound;
    loop {
        match raw::pidfd_has_exited(pidfd) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => return Err(io::Error::other(error.to_string())),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pidfd leader did not become waitable before cleanup bound",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn unsupported(
    primitive: KernelPrimitive,
    source: &io::Error,
    detail: &'static str,
) -> PlatformError {
    UnsupportedKernel::new(primitive, source.raw_os_error(), detail).into()
}
