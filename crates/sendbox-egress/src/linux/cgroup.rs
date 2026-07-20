//! Supervisor-owned stable cgroup v2 hierarchy.
//!
//! The supervisor creates a stable hierarchy `<root>/sendbox/<instance>/agent`
//! and `<root>/sendbox/<instance>/broker`. These directories give the agent and
//! broker **kernel-stable identities** that nftables matches on with
//! `socket cgroupv2` — an identity no unrelated process can assume merely by
//! sharing a UID.
//!
//! All filesystem operations are **descriptor-relative** and symlink-race
//! resistant: the crate opens the cgroup v2 root once as a capability
//! [`cap_std::fs::Dir`] and performs every create/write/remove relative to that
//! directory descriptor. `cap-std` confines resolution beneath the opened root
//! (Linux `openat2`/`RESOLVE_BENEATH`), so a symlink planted under the root can
//! never redirect a hierarchy operation outside it.
//!
//! The cgroup hierarchy is created **directly under the mounted cgroup v2 root**
//! (`<root>/sendbox/<instance>/…`), so the [`CgroupIdentity`] nftables matches on
//! is exactly that mount-relative path: nftables userspace stats
//! `/sys/fs/cgroup/<identifier>` to resolve the rule, and the kernel adds the
//! current cgroup-namespace subtree level internally. The mount-relative path is
//! also reused for the descriptor-relative filesystem operations and for the
//! `cgroup.procs` accessors a self-placing helper writes to.
//!
//! The broker cgroup directory is *stable across broker process restarts*: the
//! supervisor never removes/recreates it when the broker process dies, so the
//! cgroup id baked into the loaded nftables rules stays valid. A restarted
//! broker is simply re-placed into the same existing cgroup.
//!
//! No controllers are enabled in the subtree, so processes can be placed
//! directly into the leaf cgroups (the cgroup v2 "no internal processes" rule
//! only constrains cgroups whose controllers are enabled).

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use thiserror::Error;

use crate::linux::nft::{CgroupIdentity, NftError};

/// The conventional cgroup v2 unified-hierarchy mount point.
pub const DEFAULT_CGROUP2_ROOT: &str = "/sys/fs/cgroup";
/// Top-level directory the crate owns under the cgroup v2 root.
pub const SENDBOX_CGROUP_PREFIX: &str = "sendbox";

#[derive(Debug, Error)]
pub enum CgroupError {
    #[error("cgroup v2 is not mounted at any known location")]
    NotMounted,
    #[error("invalid instance id '{0}': must be 1-32 chars of [a-z0-9_]")]
    InvalidInstanceId(String),
    #[error(transparent)]
    Identity(#[from] NftError),
    #[error("failed to open cgroup root '{path}': {source}")]
    OpenRoot {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("descriptor-relative operation on '{root}/{rel}' failed: {source}")]
    Io {
        root: String,
        rel: String,
        #[source]
        source: io::Error,
    },
}

/// Parses the mount point of a `cgroup2` filesystem from `/proc/mounts`-style
/// content. Pure, so it is unit tested without a real mount table.
#[must_use]
pub fn parse_cgroup2_mount(mounts: &str) -> Option<PathBuf> {
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let _device = parts.next();
        let mount_point = parts.next();
        let fstype = parts.next();
        if fstype == Some("cgroup2")
            && let Some(point) = mount_point
        {
            return Some(PathBuf::from(point));
        }
    }
    None
}

/// Detects the cgroup v2 unified-hierarchy mount root: the default location if
/// it exposes `cgroup.controllers`, otherwise the first `cgroup2` mount in
/// `/proc/mounts`.
pub fn detect_cgroup2_root() -> Result<PathBuf, CgroupError> {
    let default = Path::new(DEFAULT_CGROUP2_ROOT);
    if default.join("cgroup.controllers").exists() {
        return Ok(default.to_path_buf());
    }
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts")
        && let Some(point) = parse_cgroup2_mount(&mounts)
    {
        return Ok(point);
    }
    Err(CgroupError::NotMounted)
}

/// A created, supervisor-owned cgroup hierarchy for one sandbox instance. Holds
/// an opened capability directory for the cgroup v2 root; all operations are
/// relative to it.
pub struct CgroupHierarchy {
    root_dir: Dir,
    root_path: PathBuf,
    /// Mount-relative base path `sendbox/<instance>` (filesystem operations).
    base_rel: String,
    /// Mount-relative agent leaf `sendbox/<instance>/agent` (filesystem ops).
    agent_rel: String,
    /// Mount-relative broker leaf `sendbox/<instance>/broker` (filesystem ops).
    broker_rel: String,
    /// Whether this instance's base cgroup directory already existed when the
    /// hierarchy was (re)created. Used by the supervisor to avoid tearing down a
    /// live instance's cgroups on a failed re-arm.
    preexisting: bool,
    /// nft `socket cgroupv2` identity for the agent — the mount-relative path
    /// `sendbox/<instance>/agent` (equal to `agent_rel`).
    agent: CgroupIdentity,
    /// nft `socket cgroupv2` identity for the broker.
    broker: CgroupIdentity,
}

impl CgroupHierarchy {
    /// Creates the hierarchy under the detected cgroup v2 root.
    pub fn create(instance_id: &str) -> Result<Self, CgroupError> {
        let root = detect_cgroup2_root()?;
        Self::create_under(&root, instance_id)
    }

    /// Creates the hierarchy under an explicit root (a real cgroup v2 mount, or
    /// a tempdir in tests). Opens the root as a capability directory and does
    /// every filesystem operation relative to it. The nft [`CgroupIdentity`] is
    /// the mount-relative path (`sendbox/<instance>/…`), exactly what nftables
    /// userspace stats under `/sys/fs/cgroup`. Idempotent: existing directories
    /// are reused, which keeps the broker cgroup stable across process restarts.
    pub fn create_under(root: &Path, instance_id: &str) -> Result<Self, CgroupError> {
        if !is_valid_instance_id(instance_id) {
            return Err(CgroupError::InvalidInstanceId(instance_id.to_owned()));
        }
        let root_dir = Dir::open_ambient_dir(root, ambient_authority()).map_err(|source| {
            CgroupError::OpenRoot {
                path: root.display().to_string(),
                source,
            }
        })?;

        // Mount-relative paths: used both for the descriptor-relative filesystem
        // operations and, verbatim, as the nft `socket cgroupv2` identity.
        let base_rel = format!("{SENDBOX_CGROUP_PREFIX}/{instance_id}");
        let agent_rel = format!("{base_rel}/agent");
        let broker_rel = format!("{base_rel}/broker");

        // Record whether this instance's base cgroup already existed *before* we
        // (idempotently) create it. A re-arm of a live instance must not tear
        // down these cgroups on failure.
        let preexisting = root_dir.exists(&base_rel);

        let hierarchy = Self {
            root_dir,
            root_path: root.to_path_buf(),
            base_rel,
            preexisting,
            agent: CgroupIdentity::new(agent_rel.clone())?,
            broker: CgroupIdentity::new(broker_rel.clone())?,
            agent_rel,
            broker_rel,
        };

        for rel in [
            &hierarchy.base_rel,
            &hierarchy.agent_rel,
            &hierarchy.broker_rel,
        ] {
            hierarchy.create_dir_relative(rel)?;
        }
        Ok(hierarchy)
    }

    fn create_dir_relative(&self, rel: &str) -> Result<(), CgroupError> {
        match self.root_dir.create_dir_all(rel) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(source) => Err(self.io_error(rel, source)),
        }
    }

    fn io_error(&self, rel: &str, source: io::Error) -> CgroupError {
        CgroupError::Io {
            root: self.root_path.display().to_string(),
            rel: rel.to_owned(),
            source,
        }
    }

    #[must_use]
    pub fn agent_identity(&self) -> &CgroupIdentity {
        &self.agent
    }

    #[must_use]
    pub fn broker_identity(&self) -> &CgroupIdentity {
        &self.broker
    }

    /// Whether this instance's base cgroup directory already existed when the
    /// hierarchy was created (i.e. this is a re-arm of a possibly-live
    /// instance), rather than being freshly created by this call.
    #[must_use]
    pub fn preexisting(&self) -> bool {
        self.preexisting
    }

    /// Deterministic reporting path for the agent cgroup directory on the local
    /// mounted filesystem (mount root + mount-relative path). Reporting/probing
    /// only; hierarchy operations use the descriptor.
    #[must_use]
    pub fn agent_dir(&self) -> PathBuf {
        self.root_path.join(&self.agent_rel)
    }

    /// Deterministic reporting path for the broker cgroup directory on the local
    /// mounted filesystem.
    #[must_use]
    pub fn broker_dir(&self) -> PathBuf {
        self.root_path.join(&self.broker_rel)
    }

    /// Local filesystem path of the agent cgroup's `cgroup.procs`, for a helper
    /// (e.g. the live harness) that self-places by writing its pid. This is the
    /// *mount-relative* path, never the global nft identity.
    #[must_use]
    pub fn agent_procs_path(&self) -> PathBuf {
        self.agent_dir().join("cgroup.procs")
    }

    /// Local filesystem path of the broker cgroup's `cgroup.procs`.
    #[must_use]
    pub fn broker_procs_path(&self) -> PathBuf {
        self.broker_dir().join("cgroup.procs")
    }

    /// Moves `pid` into the agent cgroup via a descriptor-relative write.
    pub fn place_agent(&self, pid: u32) -> Result<(), CgroupError> {
        self.place(&self.agent_rel, pid)
    }

    /// Moves `pid` into the broker cgroup. Safe to call again with a new pid
    /// after a broker restart; the cgroup directory is never recreated.
    pub fn place_broker(&self, pid: u32) -> Result<(), CgroupError> {
        self.place(&self.broker_rel, pid)
    }

    fn place(&self, leaf_rel: &str, pid: u32) -> Result<(), CgroupError> {
        let procs_rel = format!("{leaf_rel}/cgroup.procs");
        // Descriptor-relative open with write+create (no truncate): the kernel
        // ignores truncation on the cgroup control file, and create makes the
        // same code path work against a tempdir in tests.
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(false);
        let mut file = self
            .root_dir
            .open_with(&procs_rel, &options)
            .map_err(|source| self.io_error(&procs_rel, source))?;
        file.write_all(format!("{pid}\n").as_bytes())
            .map_err(|source| self.io_error(&procs_rel, source))
    }

    /// Removes the leaf and base cgroup directories (leaf-first), then the
    /// top-level owned `sendbox` directory if it is empty. Every removal is
    /// descriptor-relative. Absent-safe: a directory already gone is not an
    /// error. A leaf or base directory that still exists but cannot be removed
    /// (e.g. it still holds processes) surfaces as an error rather than being
    /// swallowed — the supervisor uses that to keep enforcement in place. The
    /// top-level `sendbox` directory being non-empty is tolerated (a sibling
    /// instance still owns it).
    pub fn teardown(&self) -> Vec<CgroupError> {
        let mut errors = Vec::new();
        for rel in [
            self.broker_rel.clone(),
            self.agent_rel.clone(),
            self.base_rel.clone(),
        ] {
            if let Err(err) = self.remove_owned_dir(&rel) {
                errors.push(err);
            }
        }
        if let Err(err) = self.remove_top_level_if_empty() {
            errors.push(err);
        }
        errors
    }

    fn remove_owned_dir(&self, rel: &str) -> Result<(), CgroupError> {
        match self.root_dir.remove_dir(rel) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(self.io_error(rel, source)),
        }
    }

    fn remove_top_level_if_empty(&self) -> Result<(), CgroupError> {
        match self.root_dir.remove_dir(SENDBOX_CGROUP_PREFIX) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            // A sibling sandbox instance still owns the shared top-level dir.
            Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(()),
            Err(source) => Err(self.io_error(SENDBOX_CGROUP_PREFIX, source)),
        }
    }
}

fn is_valid_instance_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cgroup2_mount_point() {
        let mounts = "\
proc /proc proc rw 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nsdelegate 0 0
tmpfs /run tmpfs rw 0 0
";
        assert_eq!(
            parse_cgroup2_mount(mounts),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
    }

    #[test]
    fn parses_none_when_no_cgroup2_present() {
        let mounts = "proc /proc proc rw 0 0\ntmpfs /run tmpfs rw 0 0\n";
        assert_eq!(parse_cgroup2_mount(mounts), None);
    }

    #[test]
    fn rejects_invalid_instance_ids() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            CgroupHierarchy::create_under(root.path(), ""),
            Err(CgroupError::InvalidInstanceId(_))
        ));
        assert!(matches!(
            CgroupHierarchy::create_under(root.path(), "Bad-Id"),
            Err(CgroupError::InvalidInstanceId(_))
        ));
        assert!(matches!(
            CgroupHierarchy::create_under(root.path(), "a/b"),
            Err(CgroupError::InvalidInstanceId(_))
        ));
    }

    #[test]
    fn creates_hierarchy_with_correct_identities_and_levels() {
        let root = tempfile::tempdir().unwrap();
        let hierarchy = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        // The nft identity is the mount-relative path (what nftables stats under
        // `/sys/fs/cgroup`); the kernel adds the cgroup-namespace subtree level.
        assert_eq!(
            hierarchy.agent_identity().relative_path(),
            "sendbox/inst01/agent"
        );
        assert_eq!(hierarchy.agent_identity().level(), 3);
        assert_eq!(
            hierarchy.broker_identity().relative_path(),
            "sendbox/inst01/broker"
        );
        assert!(hierarchy.agent_dir().is_dir());
        assert!(hierarchy.broker_dir().is_dir());
    }

    #[test]
    fn procs_paths_are_mount_relative_and_placement_writes_there() {
        let root = tempfile::tempdir().unwrap();
        let hierarchy = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        assert!(
            hierarchy
                .agent_procs_path()
                .ends_with("sendbox/inst01/agent/cgroup.procs")
        );
        assert!(
            hierarchy
                .broker_procs_path()
                .ends_with("sendbox/inst01/broker/cgroup.procs")
        );
        hierarchy.place_agent(4242).unwrap();
        let contents = std::fs::read_to_string(hierarchy.agent_procs_path()).unwrap();
        assert_eq!(contents, "4242\n");
    }

    #[test]
    fn create_under_is_idempotent_for_restart_stability() {
        let root = tempfile::tempdir().unwrap();
        let first = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        let second = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        assert_eq!(
            first.broker_identity().relative_path(),
            second.broker_identity().relative_path()
        );
    }

    #[test]
    fn preexisting_reflects_prior_base_directory() {
        let root = tempfile::tempdir().unwrap();
        let first = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        assert!(!first.preexisting(), "a first creation is fresh");
        let second = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        assert!(
            second.preexisting(),
            "a re-creation must see the existing base directory"
        );
    }

    #[test]
    fn place_writes_pid_to_cgroup_procs() {
        let root = tempfile::tempdir().unwrap();
        let hierarchy = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        hierarchy.place_agent(4242).unwrap();
        let contents = std::fs::read_to_string(hierarchy.agent_dir().join("cgroup.procs")).unwrap();
        assert_eq!(contents, "4242\n");
        hierarchy.place_broker(4243).unwrap();
        let broker = std::fs::read_to_string(hierarchy.broker_dir().join("cgroup.procs")).unwrap();
        assert_eq!(broker, "4243\n");
    }

    #[test]
    fn teardown_removes_empty_dirs_and_is_absent_safe() {
        let root = tempfile::tempdir().unwrap();
        let hierarchy = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        let errors = hierarchy.teardown();
        assert!(errors.is_empty(), "teardown errors: {errors:?}");
        assert!(!hierarchy.agent_dir().exists());
        // The owned top-level directory is removed when empty.
        assert!(!root.path().join("sendbox").exists());
        let again = hierarchy.teardown();
        assert!(again.is_empty());
    }

    #[test]
    fn teardown_tolerates_shared_top_level_with_sibling_instances() {
        let root = tempfile::tempdir().unwrap();
        let one = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        let _two = CgroupHierarchy::create_under(root.path(), "inst02").unwrap();
        // Tearing down inst01 must not fail just because inst02 still owns the
        // shared top-level `sendbox` directory.
        let errors = one.teardown();
        assert!(errors.is_empty(), "teardown errors: {errors:?}");
        assert!(root.path().join("sendbox/inst02").is_dir());
    }

    #[test]
    fn teardown_reports_error_when_a_leaf_cannot_be_removed() {
        let root = tempfile::tempdir().unwrap();
        let hierarchy = CgroupHierarchy::create_under(root.path(), "inst01").unwrap();
        // Simulate a lingering process: a cgroup.procs entry makes the leaf
        // non-empty, so rmdir fails. The error must be surfaced.
        hierarchy.place_agent(4242).unwrap();
        let errors = hierarchy.teardown();
        assert!(
            errors.iter().any(|e| matches!(e, CgroupError::Io { .. })),
            "expected a surfaced removal error, got {errors:?}"
        );
    }

    #[test]
    fn symlink_under_root_cannot_redirect_operations_outside_root() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        // Plant a symlink `root/sendbox` -> outside, so a naive path join would
        // create the hierarchy in `outside`. cap-std must refuse to traverse it.
        symlink(outside.path(), root.path().join("sendbox")).unwrap();
        let result = CgroupHierarchy::create_under(root.path(), "inst01");
        assert!(
            result.is_err(),
            "creating through an escaping symlink must fail"
        );
        assert!(
            !outside.path().join("inst01").exists(),
            "operations must not escape the opened root descriptor"
        );
    }
}
