//! A small, file-backed registry of process-group IDs (PGIDs) that the
//! broker has spawned and the supervisor is responsible for cleaning up if
//! the broker itself dies unexpectedly.
//!
//! The registry is a single JSON array of `i32` PGIDs stored at a path
//! inside the broker's runtime directory, guarded by an advisory
//! (`flock`) exclusive lock around every read-modify-write cycle so that
//! the broker (writer, on every spawn/reap) and the supervisor (reader, on
//! broker death) never observe a partially written file. The lock is
//! obtained through `nix::fcntl::Flock`, a safe RAII wrapper around
//! `flock(2)` — no `unsafe` is needed anywhere in this module.
//!
//! # The narrow spawn-before-registration race
//!
//! Registration happens *after* `fork`/`exec` has already placed a new
//! process group on the system (a plain `tokio::process::Command::spawn`
//! cannot atomically fork-and-register in one step without OS-level
//! primitives such as `clone3` with `CLONE_INTO_CGROUP` or an equivalent
//! cgroup/namespace-based sandbox that contains the child from the moment
//! it exists). If the broker is killed in the narrow window between a
//! successful `spawn()` and the corresponding [`PgidRegistry::register`]
//! call completing, that process group is never recorded and the
//! supervisor's death-triggered cleanup sweep cannot find or kill it: it
//! will be leaked (until it exits on its own, e.g. via its own requested
//! timeout, if any).
//!
//! This is a known, explicitly accepted limitation of this Phase 1 spike.
//! Closing it fully in production requires one of: (a) an atomic
//! `clone3(CLONE_INTO_CGROUP)`-based spawn that places the child into a
//! pre-created, supervisor-owned cgroup *before* it can run any code, so
//! cgroup-kill (rather than this registry) becomes the sole source of
//! truth for teardown, or (b) launching every command inside a
//! pre-provisioned sandbox/namespace whose teardown does not depend on the
//! broker being alive to have registered anything.

#![forbid(unsafe_code)]

use nix::fcntl::{Flock, FlockArg};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Mode the registry file is created with, and re-asserted on every open:
/// owner read/write only. Neither the supervisor nor the broker ever needs
/// group/other access, and this file's contents (a list of live PGIDs the
/// broker is actively managing) are operationally sensitive enough that a
/// stricter default than umask alone is warranted.
const REGISTRY_FILE_MODE: u32 = 0o600;

/// A registry file at a fixed path, opened fresh for every operation (so
/// no long-lived file handle needs to be shared across tasks/threads).
#[derive(Debug, Clone)]
pub struct PgidRegistry {
    path: PathBuf,
}

impl PgidRegistry {
    /// Points at (but does not yet create) a registry file at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Adds `pgid` to the registry, if not already present.
    pub fn register(&self, pgid: i32) -> std::io::Result<()> {
        self.with_locked_file(|entries| {
            if !entries.contains(&pgid) {
                entries.push(pgid);
            }
        })
    }

    /// Removes `pgid` from the registry, if present.
    pub fn unregister(&self, pgid: i32) -> std::io::Result<()> {
        self.with_locked_file(|entries| entries.retain(|&p| p != pgid))
    }

    /// Returns every currently registered PGID.
    pub fn read_all(&self) -> std::io::Result<Vec<i32>> {
        let mut result = Vec::new();
        self.with_locked_file(|entries| result = entries.clone())?;
        Ok(result)
    }

    /// Truncates the registry to empty.
    pub fn clear(&self) -> std::io::Result<()> {
        self.with_locked_file(|entries| entries.clear())
    }

    fn with_locked_file(&self, mutate: impl FnOnce(&mut Vec<i32>)) -> std::io::Result<()> {
        let file = open_or_create(&self.path)?;
        let mut file = Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_file, errno)| std::io::Error::from_raw_os_error(errno as i32))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let mut entries: Vec<i32> = if contents.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&contents).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "pgid registry at {} contains invalid JSON: {err}",
                        self.path.display()
                    ),
                )
            })?
        };

        mutate(&mut entries);

        let serialized = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string());
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(serialized.as_bytes())?;
        file.flush()?;

        // Dropping `file` (a `Flock<File>`) at the end of this function
        // releases the flock automatically via `Flock`'s `Drop` impl.
        Ok(())
    }
}

/// Opens the registry file, creating it if absent. Symlink-safe: `O_NOFOLLOW`
/// means a symlink planted at this path (by another, potentially
/// lower-privileged, local user in a shared/world-writable directory) is
/// rejected outright rather than silently followed and read/written
/// through. The file is created with (and, defensively, re-set to)
/// exactly [`REGISTRY_FILE_MODE`] rather than relying solely on umask,
/// which may be more permissive than desired in some deployment
/// environments.
fn open_or_create(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // Explicitly not truncating on open: the existing contents (if
        // any) are read into memory first, mutated, and then the file is
        // truncated-and-rewritten manually (see `with_locked_file`) only
        // after the exclusive flock is held, to avoid a window where a
        // concurrent reader could observe a truncated-but-not-yet-rewritten
        // file.
        .truncate(false)
        .mode(REGISTRY_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    // `.mode(..)` above only takes effect when this call actually creates
    // the file; if it already existed (e.g. left over with a different
    // mode from an earlier, differently-configured run), re-assert the
    // expected mode explicitly rather than trusting whatever was already
    // on disk.
    let mut permissions = file.metadata()?.permissions();
    if permissions.mode() & 0o777 != REGISTRY_FILE_MODE {
        permissions.set_mode(REGISTRY_FILE_MODE);
        file.set_permissions(permissions)?;
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_read_all_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = PgidRegistry::new(dir.path().join("pgids.json"));
        registry.register(1234).expect("register");
        registry.register(5678).expect("register");
        let mut all = registry.read_all().expect("read_all");
        all.sort_unstable();
        assert_eq!(all, vec![1234, 5678]);
    }

    #[test]
    fn register_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = PgidRegistry::new(dir.path().join("pgids.json"));
        registry.register(1234).expect("register");
        registry.register(1234).expect("register again");
        assert_eq!(registry.read_all().expect("read_all"), vec![1234]);
    }

    #[test]
    fn unregister_removes_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = PgidRegistry::new(dir.path().join("pgids.json"));
        registry.register(1234).expect("register");
        registry.register(5678).expect("register");
        registry.unregister(1234).expect("unregister");
        assert_eq!(registry.read_all().expect("read_all"), vec![5678]);
    }

    #[test]
    fn clear_empties_the_registry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = PgidRegistry::new(dir.path().join("pgids.json"));
        registry.register(1234).expect("register");
        registry.clear().expect("clear");
        assert!(registry.read_all().expect("read_all").is_empty());
    }

    #[test]
    fn invalid_json_is_surfaced_as_an_error_not_silently_treated_as_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pgids.json");
        std::fs::write(&path, b"not valid json{{{").expect("write corrupt file");
        let registry = PgidRegistry::new(path);

        let err = registry
            .read_all()
            .expect_err("corrupt JSON must be an error, not []");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        // A subsequent register() must also fail loudly rather than
        // silently overwriting the corrupt data with a fresh, empty
        // registry.
        let err = registry
            .register(999)
            .expect_err("register must also refuse to proceed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn open_or_create_creates_file_with_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pgids.json");
        let registry = PgidRegistry::new(path.clone());
        registry.register(1).expect("register");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn open_or_create_refuses_to_follow_a_symlink_at_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real_target = dir.path().join("elsewhere.json");
        std::fs::write(&real_target, b"[]").expect("write target");
        let link_path = dir.path().join("pgids.json");
        std::os::unix::fs::symlink(&real_target, &link_path).expect("symlink");

        let registry = PgidRegistry::new(link_path);
        let err = registry
            .register(1)
            .expect_err("must refuse to follow the symlink");
        // ELOOP is the errno O_NOFOLLOW produces when the final path
        // component is a symlink.
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }
}
