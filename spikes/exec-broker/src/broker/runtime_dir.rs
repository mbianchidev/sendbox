//! The broker's private runtime directory: created fresh with `0700`
//! permissions at startup, holding only the broker's Unix socket, and
//! removed in full on clean shutdown.
//!
//! # Restart is unsupported
//!
//! This module deliberately refuses to reuse or replace anything already
//! present at the configured runtime directory path — a leftover directory
//! from a previous run, a symlink, or any other pre-existing filesystem
//! object there is treated as unsafe and rejected outright. In practice
//! this means restarting a broker with the same runtime directory path
//! requires the operator (or, in production, the supervisor) to first
//! remove the stale path; there is no in-place "restart" operation. This is
//! an intentional simplification for this Phase 1 spike rather than an
//! oversight.

#![forbid(unsafe_code)]

use crate::error::BrokerError;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Filename of the broker's Unix socket inside the runtime directory.
pub const SOCKET_FILE_NAME: &str = "broker.sock";

/// Permission bits required on the runtime directory: owner-only
/// read/write/execute.
const RUNTIME_DIR_MODE: u32 = 0o700;

/// The broker's private runtime directory.
#[derive(Debug)]
pub struct RuntimeDir {
    path: PathBuf,
}

impl RuntimeDir {
    /// Creates a fresh runtime directory at `path`. Fails if anything
    /// already exists at `path` (of any type — directory, file, or
    /// symlink), since reusing or silently replacing a stale path could
    /// mean inheriting an attacker-planted or leftover artifact.
    pub fn create_fresh(path: impl Into<PathBuf>) -> Result<Self, BrokerError> {
        let path = path.into();

        // `symlink_metadata` (lstat) rather than `metadata` (stat), so a
        // symlink left at this path is detected rather than silently
        // followed.
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(BrokerError::RestartUnsupported(
                    "runtime directory path already exists; restart is unsupported by this \
                     spike — remove the stale path and start a fresh broker instance",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(BrokerError::Io(e)),
        }

        fs::DirBuilder::new().mode(RUNTIME_DIR_MODE).create(&path)?;

        // Re-check immediately after creation: confirm it is a real
        // directory, owned by this process's effective UID, with exactly
        // the expected mode bits, rather than trusting `DirBuilder` alone.
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_dir() {
            return Err(BrokerError::UnsafeRuntimeDir(format!(
                "{} is not a directory immediately after creation",
                path.display()
            )));
        }
        let expected_uid = current_uid();
        if metadata.uid() != expected_uid {
            return Err(BrokerError::UnsafeRuntimeDir(format!(
                "{} is owned by uid {} but this process is uid {}",
                path.display(),
                metadata.uid(),
                expected_uid
            )));
        }
        if metadata.permissions().mode() & 0o777 != RUNTIME_DIR_MODE {
            return Err(BrokerError::UnsafeRuntimeDir(format!(
                "{} has mode {:o}, expected {:o}",
                path.display(),
                metadata.permissions().mode() & 0o777,
                RUNTIME_DIR_MODE
            )));
        }

        Ok(Self { path })
    }

    /// Validates that a runtime directory already exists at `path` and
    /// still satisfies every safety invariant `create_fresh` established
    /// (real directory via `lstat`, owned by this process's UID, mode
    /// exactly `0700`) — without creating or modifying anything. Used by
    /// the supervisor to attach to a runtime directory the broker created,
    /// for death-triggered cleanup, without re-deriving the broker's own
    /// creation logic.
    pub fn open_existing(path: impl Into<PathBuf>) -> Result<Self, BrokerError> {
        let path = path.into();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_dir() {
            return Err(BrokerError::UnsafeRuntimeDir(format!(
                "{} is not a directory",
                path.display()
            )));
        }
        let expected_uid = current_uid();
        if metadata.uid() != expected_uid {
            return Err(BrokerError::UnsafeRuntimeDir(format!(
                "{} is owned by uid {} but this process is uid {}",
                path.display(),
                metadata.uid(),
                expected_uid
            )));
        }
        if metadata.permissions().mode() & 0o777 != RUNTIME_DIR_MODE {
            return Err(BrokerError::UnsafeRuntimeDir(format!(
                "{} has mode {:o}, expected {:o}",
                path.display(),
                metadata.permissions().mode() & 0o777,
                RUNTIME_DIR_MODE
            )));
        }
        Ok(Self { path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.path.join(SOCKET_FILE_NAME)
    }

    /// Removes the runtime directory and everything in it (the socket
    /// file). Called on clean shutdown.
    pub fn remove(self) -> io::Result<()> {
        fs::remove_dir_all(&self.path)
    }
}

fn current_uid() -> u32 {
    // This is intentionally *not* in the platform adapter module:
    // `getuid()` takes no arguments, can never fail, and returns a plain
    // integer with no pointer/lifetime/ownership invariants to uphold, so
    // the safe `nix` wrapper is used directly rather than treating it as a
    // hardening primitive that needs isolation. (This whole module is only
    // ever compiled for `target_os = "linux"`, via the `#[cfg]` on its
    // declaration in `lib.rs`.)
    nix::unistd::getuid().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_directory_with_expected_mode_and_owner() {
        let base = tempfile::tempdir().expect("tempdir");
        let runtime_path = base.path().join("runtime");
        let runtime = RuntimeDir::create_fresh(&runtime_path).expect("create_fresh");
        let metadata = fs::symlink_metadata(runtime.path()).expect("stat");
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), current_uid());
    }

    #[test]
    fn refuses_to_reuse_a_stale_path() {
        let base = tempfile::tempdir().expect("tempdir");
        let runtime_path = base.path().join("runtime");
        fs::create_dir_all(&runtime_path).expect("pre-create stale dir");
        let err = RuntimeDir::create_fresh(&runtime_path).expect_err("must reject stale path");
        assert!(matches!(err, BrokerError::RestartUnsupported(_)));
    }

    #[test]
    fn refuses_to_reuse_a_symlink_at_the_path() {
        let base = tempfile::tempdir().expect("tempdir");
        let target = base.path().join("elsewhere");
        fs::create_dir_all(&target).expect("mkdir target");
        let runtime_path = base.path().join("runtime");
        std::os::unix::fs::symlink(&target, &runtime_path).expect("symlink");
        let err = RuntimeDir::create_fresh(&runtime_path).expect_err("must reject symlink");
        assert!(matches!(err, BrokerError::RestartUnsupported(_)));
    }

    #[test]
    fn remove_deletes_the_directory_and_its_contents() {
        let base = tempfile::tempdir().expect("tempdir");
        let runtime_path = base.path().join("runtime");
        let runtime = RuntimeDir::create_fresh(&runtime_path).expect("create_fresh");
        fs::write(runtime.socket_path(), b"placeholder").expect("write placeholder");
        runtime.remove().expect("remove");
        assert!(fs::symlink_metadata(&runtime_path).is_err());
    }

    #[test]
    fn open_existing_attaches_to_an_already_created_directory() {
        let base = tempfile::tempdir().expect("tempdir");
        let runtime_path = base.path().join("runtime");
        let created = RuntimeDir::create_fresh(&runtime_path).expect("create_fresh");
        drop(created);
        let attached = RuntimeDir::open_existing(&runtime_path).expect("open_existing");
        assert_eq!(attached.path(), runtime_path);
    }

    #[test]
    fn open_existing_rejects_missing_path() {
        let base = tempfile::tempdir().expect("tempdir");
        let runtime_path = base.path().join("does-not-exist");
        let err = RuntimeDir::open_existing(&runtime_path).expect_err("must reject missing path");
        assert!(matches!(err, BrokerError::Io(_)));
    }
}
