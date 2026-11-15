use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::error::io_error;
use crate::{SecurityError, SecurityResult};

pub const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const PRIVATE_FILE_MODE: u32 = 0o600;
pub const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryType {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryMetadata {
    pub entry_type: EntryType,
    pub mode: u32,
    pub owner: u32,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub allocated_bytes: u64,
    pub modified_unix_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_unix_seconds: i64,
    pub changed_nanoseconds: i64,
    pub hardlink_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: OsString,
    pub metadata: EntryMetadata,
}

pub struct OpenedFile {
    pub file: File,
    pub metadata: EntryMetadata,
}

pub struct ExclusiveLock {
    _file: File,
}

#[cfg(unix)]
mod platform {
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    use rustix::fs::{
        AtFlags, Dir, FileType, Mode, OFlags, fchmod, fstat, fsync, linkat, mkdirat, openat,
        readlinkat, renameat, statat, symlinkat, unlinkat,
    };
    use rustix::io::dup;
    use rustix::process::getuid;

    use super::*;

    pub struct SecureRoot {
        fd: OwnedFd,
        expected_owner: u32,
        device: u64,
    }

    impl SecureRoot {
        pub fn open(path: impl AsRef<Path>) -> SecurityResult<Self> {
            let path = path.as_ref();
            let fd = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| io_error("open root directory", path, error.into()))?;
            let stat = fstat(&fd)
                .map_err(|error| io_error("inspect root directory", path, error.into()))?;
            let owner = stat.st_uid;
            let expected_owner = getuid().as_raw();
            if owner != expected_owner {
                return Err(SecurityError::OwnerMismatch {
                    path: path.to_path_buf(),
                    expected: expected_owner,
                    actual: owner,
                });
            }
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
                return Err(SecurityError::UnsupportedFileType(path.to_path_buf()));
            }
            Ok(Self {
                fd,
                expected_owner,
                device: normalize_u64(stat.st_dev),
            })
        }

        pub fn root_device(&self) -> u64 {
            self.device
        }

        pub fn metadata(&self, path: impl AsRef<Path>) -> SecurityResult<EntryMetadata> {
            let path = validated(path.as_ref())?;
            let (parent, name) = self.open_parent(&path)?;
            let stat = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| io_error("inspect entry", &path, error.into()))?;
            let metadata = metadata_from_stat(&stat);
            self.validate_owner(&path, &metadata)?;
            Ok(metadata)
        }

        pub fn open_regular(
            &self,
            path: impl AsRef<Path>,
            max_bytes: u64,
        ) -> SecurityResult<OpenedFile> {
            let path = validated(path.as_ref())?;
            let (parent, name) = self.open_parent(&path)?;
            let fd = openat(
                &parent,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| io_error("open regular file", &path, error.into()))?;
            let stat = fstat(&fd)
                .map_err(|error| io_error("inspect regular file", &path, error.into()))?;
            let metadata = metadata_from_stat(&stat);
            self.validate_owner(&path, &metadata)?;
            if metadata.entry_type != EntryType::Regular {
                return Err(SecurityError::UnsupportedFileType(path.to_path_buf()));
            }
            if metadata.size > max_bytes {
                return Err(SecurityError::SizeLimit {
                    path,
                    limit: max_bytes,
                });
            }
            Ok(OpenedFile {
                file: File::from(fd),
                metadata,
            })
        }

        pub fn read_bounded(
            &self,
            path: impl AsRef<Path>,
            max_bytes: u64,
        ) -> SecurityResult<Vec<u8>> {
            let path = path.as_ref();
            let opened = self.open_regular(path, max_bytes)?;
            let capacity =
                usize::try_from(opened.metadata.size).map_err(|_| SecurityError::SizeLimit {
                    path: path.to_path_buf(),
                    limit: max_bytes,
                })?;
            let mut bytes = Vec::with_capacity(capacity);
            opened
                .file
                .take(max_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|error| io_error("read file", path, error))?;
            if bytes.len() as u64 > max_bytes {
                return Err(SecurityError::SizeLimit {
                    path: path.to_path_buf(),
                    limit: max_bytes,
                });
            }
            Ok(bytes)
        }

        pub fn read_link(&self, path: impl AsRef<Path>) -> SecurityResult<PathBuf> {
            let path = validated(path.as_ref())?;
            let (parent, name) = self.open_parent(&path)?;
            let target = readlinkat(&parent, name, Vec::new())
                .map_err(|error| io_error("read symbolic link", &path, error.into()))?;
            Ok(PathBuf::from(OsString::from_vec(target.into_bytes())))
        }

        pub fn list_dir(&self, path: impl AsRef<Path>) -> SecurityResult<Vec<DirectoryEntry>> {
            let path = validated_allow_empty(path.as_ref())?;
            let fd = self.open_dir(&path)?;
            let mut dir = Dir::read_from(&fd)
                .map_err(|error| io_error("read directory", &path, error.into()))?;
            let mut entries = Vec::new();
            for item in &mut dir {
                let item =
                    item.map_err(|error| io_error("read directory entry", &path, error.into()))?;
                let name = item.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                let os_name = OsString::from_vec(name.to_vec());
                let child = path.join(&os_name);
                let stat = statat(&fd, OsStr::from_bytes(name), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|error| io_error("inspect directory entry", &child, error.into()))?;
                let metadata = metadata_from_stat(&stat);
                self.validate_owner(&child, &metadata)?;
                entries.push(DirectoryEntry {
                    name: os_name,
                    metadata,
                });
            }
            entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
            Ok(entries)
        }

        pub fn create_dir_all(&self, path: impl AsRef<Path>, mode: u32) -> SecurityResult<()> {
            let path = validated(path.as_ref())?;
            let mut current = dup(&self.fd)
                .map_err(|error| io_error("duplicate root descriptor", "", error.into()))?;
            let mut traversed = PathBuf::new();
            let mut components = path.components().peekable();
            while let Some(component) = components.next() {
                let Component::Normal(name) = component else {
                    return Err(SecurityError::InvalidPath(path));
                };
                let is_leaf = components.peek().is_none();
                traversed.push(name);
                let component_mode = if is_leaf {
                    mode
                } else {
                    PRIVATE_DIRECTORY_MODE
                };
                let created = match mkdirat(&current, name, mode_from(component_mode)) {
                    Ok(()) => true,
                    Err(error) if error == rustix::io::Errno::EXIST => false,
                    Err(error) => {
                        return Err(io_error("create directory", &traversed, error.into()));
                    }
                };
                current = openat(
                    &current,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| io_error("open directory", &traversed, error.into()))?;
                let stat = fstat(&current)
                    .map_err(|error| io_error("inspect directory", &traversed, error.into()))?;
                let metadata = metadata_from_stat(&stat);
                self.validate_owner(&traversed, &metadata)?;
                if created || is_leaf {
                    fchmod(&current, mode_from(component_mode)).map_err(|error| {
                        io_error("set directory mode", &traversed, error.into())
                    })?;
                }
            }
            sync_fd(&current).map_err(|error| io_error("sync directory", &path, error))?;
            Ok(())
        }

        pub fn write_atomic(
            &self,
            path: impl AsRef<Path>,
            bytes: &[u8],
            max_bytes: u64,
            mode: u32,
        ) -> SecurityResult<()> {
            self.write_atomic_inner(path.as_ref(), bytes, max_bytes, mode, |_| Ok(()))
        }

        pub fn lock_exclusive(&self, path: impl AsRef<Path>) -> SecurityResult<ExclusiveLock> {
            let path = validated(path.as_ref())?;
            let fd = self.open_lock_file(&path)?;
            rustix::fs::flock(&fd, rustix::fs::FlockOperation::LockExclusive)
                .map_err(|error| io_error("lock file", path, error.into()))?;
            Ok(ExclusiveLock {
                _file: File::from(fd),
            })
        }

        pub fn try_lock_exclusive(
            &self,
            path: impl AsRef<Path>,
        ) -> SecurityResult<Option<ExclusiveLock>> {
            let path = validated(path.as_ref())?;
            let fd = self.open_lock_file(&path)?;
            match rustix::fs::flock(&fd, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => Ok(Some(ExclusiveLock {
                    _file: File::from(fd),
                })),
                Err(error) if error == rustix::io::Errno::WOULDBLOCK => Ok(None),
                Err(error) => Err(io_error("lock file", path, error.into())),
            }
        }

        fn open_lock_file(&self, path: &Path) -> SecurityResult<OwnedFd> {
            let (parent, name) = self.open_parent(path)?;
            let fd = openat(
                &parent,
                name,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                mode_from(PRIVATE_FILE_MODE),
            )
            .map_err(|error| io_error("open lock file", path, error.into()))?;
            let stat =
                fstat(&fd).map_err(|error| io_error("inspect lock file", path, error.into()))?;
            let metadata = metadata_from_stat(&stat);
            self.validate_owner(path, &metadata)?;
            if metadata.entry_type != EntryType::Regular {
                return Err(SecurityError::UnsupportedFileType(path.to_path_buf()));
            }
            fchmod(&fd, mode_from(PRIVATE_FILE_MODE))
                .map_err(|error| io_error("set lock file mode", path, error.into()))?;
            Ok(fd)
        }

        fn write_atomic_inner<F>(
            &self,
            path: &Path,
            bytes: &[u8],
            max_bytes: u64,
            mode: u32,
            before_commit: F,
        ) -> SecurityResult<()>
        where
            F: FnOnce(&mut File) -> std::io::Result<()>,
        {
            let path = validated(path)?;
            if bytes.len() as u64 > max_bytes {
                return Err(SecurityError::SizeLimit {
                    path,
                    limit: max_bytes,
                });
            }
            let (parent, name) = self.open_parent(&path)?;
            let temp_name = temporary_name(&name)?;
            let temp_fd = openat(
                &parent,
                &temp_name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                mode_from(mode),
            )
            .map_err(|error| io_error("create temporary file", &path, error.into()))?;
            let mut temp = File::from(temp_fd);
            let primary = (|| -> std::io::Result<()> {
                fchmod(&temp, mode_from(mode)).map_err(std::io::Error::from)?;
                temp.write_all(bytes)?;
                before_commit(&mut temp)?;
                sync_file(&temp)?;
                renameat(&parent, &temp_name, &parent, name).map_err(std::io::Error::from)?;
                sync_fd(&parent)?;
                Ok(())
            })();
            if let Err(primary) = primary {
                match unlinkat(&parent, &temp_name, AtFlags::empty()) {
                    Ok(()) => return Err(io_error("atomically replace file", path, primary)),
                    Err(cleanup) if cleanup == rustix::io::Errno::NOENT => {
                        return Err(io_error("atomically replace file", path, primary));
                    }
                    Err(cleanup) => {
                        return Err(SecurityError::Cleanup {
                            operation: "atomically replace file",
                            path,
                            primary: primary.to_string(),
                            cleanup: cleanup.to_string(),
                        });
                    }
                }
            }
            Ok(())
        }

        pub fn create_symlink(
            &self,
            path: impl AsRef<Path>,
            target: impl AsRef<Path>,
        ) -> SecurityResult<()> {
            let path = validated(path.as_ref())?;
            let (parent, name) = self.open_parent(&path)?;
            symlinkat(target.as_ref(), &parent, name)
                .map_err(|error| io_error("create symbolic link", &path, error.into()))?;
            sync_fd(&parent).map_err(|error| io_error("sync parent directory", path, error))
        }

        pub fn create_hardlink(
            &self,
            source: impl AsRef<Path>,
            destination: impl AsRef<Path>,
        ) -> SecurityResult<()> {
            let source = validated(source.as_ref())?;
            let destination = validated(destination.as_ref())?;
            let (source_parent, source_name) = self.open_parent(&source)?;
            let (destination_parent, destination_name) = self.open_parent(&destination)?;
            linkat(
                &source_parent,
                source_name,
                &destination_parent,
                destination_name,
                AtFlags::empty(),
            )
            .map_err(|error| io_error("create hard link", &destination, error.into()))?;
            sync_fd(&destination_parent)
                .map_err(|error| io_error("sync parent directory", destination, error))
        }

        pub fn rename(
            &self,
            source: impl AsRef<Path>,
            destination: impl AsRef<Path>,
        ) -> SecurityResult<()> {
            let source = validated(source.as_ref())?;
            let destination = validated(destination.as_ref())?;
            let (source_parent, source_name) = self.open_parent(&source)?;
            let (destination_parent, destination_name) = self.open_parent(&destination)?;
            renameat(
                &source_parent,
                source_name,
                &destination_parent,
                destination_name,
            )
            .map_err(|error| io_error("rename entry", &source, error.into()))?;
            sync_fd(&source_parent)
                .map_err(|error| io_error("sync source directory", &source, error))?;
            sync_fd(&destination_parent)
                .map_err(|error| io_error("sync destination directory", destination, error))
        }

        pub fn remove_tree(&self, path: impl AsRef<Path>) -> SecurityResult<()> {
            let path = validated(path.as_ref())?;
            let metadata = self.metadata(&path)?;
            match metadata.entry_type {
                EntryType::Directory => {
                    for entry in self.list_dir(&path)? {
                        self.remove_tree(path.join(entry.name))?;
                    }
                    let (parent, name) = self.open_parent(&path)?;
                    unlinkat(&parent, name, AtFlags::REMOVEDIR)
                        .map_err(|error| io_error("remove directory", &path, error.into()))?;
                    sync_fd(&parent).map_err(|error| io_error("sync parent directory", path, error))
                }
                _ => {
                    let (parent, name) = self.open_parent(&path)?;
                    unlinkat(&parent, name, AtFlags::empty())
                        .map_err(|error| io_error("remove entry", &path, error.into()))?;
                    sync_fd(&parent).map_err(|error| io_error("sync parent directory", path, error))
                }
            }
        }

        fn open_parent(&self, path: &Path) -> SecurityResult<(OwnedFd, OsString)> {
            let name = path
                .file_name()
                .ok_or_else(|| SecurityError::InvalidPath(path.to_path_buf()))?
                .to_owned();
            let parent = path.parent().unwrap_or_else(|| Path::new(""));
            Ok((self.open_dir(parent)?, name))
        }

        fn open_dir(&self, path: &Path) -> SecurityResult<OwnedFd> {
            let mut current = dup(&self.fd)
                .map_err(|error| io_error("duplicate root descriptor", "", error.into()))?;
            let mut traversed = PathBuf::new();
            for component in path.components() {
                let Component::Normal(name) = component else {
                    return Err(SecurityError::InvalidPath(path.to_path_buf()));
                };
                traversed.push(name);
                current = openat(
                    &current,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| io_error("open directory", &traversed, error.into()))?;
                let stat = fstat(&current)
                    .map_err(|error| io_error("inspect directory", &traversed, error.into()))?;
                let metadata = metadata_from_stat(&stat);
                self.validate_owner(&traversed, &metadata)?;
                if metadata.entry_type != EntryType::Directory {
                    return Err(SecurityError::UnsupportedFileType(traversed));
                }
            }
            Ok(current)
        }

        fn validate_owner(&self, path: &Path, metadata: &EntryMetadata) -> SecurityResult<()> {
            if metadata.owner != self.expected_owner {
                return Err(SecurityError::OwnerMismatch {
                    path: path.to_path_buf(),
                    expected: self.expected_owner,
                    actual: metadata.owner,
                });
            }
            Ok(())
        }
    }

    fn metadata_from_stat(stat: &rustix::fs::Stat) -> EntryMetadata {
        let entry_type = match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => EntryType::Regular,
            FileType::Directory => EntryType::Directory,
            FileType::Symlink => EntryType::Symlink,
            _ => EntryType::Other,
        };
        EntryMetadata {
            entry_type,
            mode: normalize_u32(Mode::from_raw_mode(stat.st_mode).bits()),
            owner: stat.st_uid,
            device: normalize_u64(stat.st_dev),
            inode: stat.st_ino,
            size: u64::try_from(stat.st_size).unwrap_or(0),
            allocated_bytes: u64::try_from(stat.st_blocks)
                .unwrap_or(0)
                .saturating_mul(512),
            modified_unix_seconds: stat.st_mtime,
            modified_nanoseconds: normalize_nanoseconds(stat.st_mtime_nsec),
            changed_unix_seconds: stat.st_ctime,
            changed_nanoseconds: normalize_nanoseconds(stat.st_ctime_nsec),
            hardlink_count: normalize_u64(stat.st_nlink),
        }
    }

    fn mode_from(mode: u32) -> Mode {
        Mode::from_raw_mode((mode & 0o777) as rustix::fs::RawMode)
    }

    fn normalize_nanoseconds<T: TryInto<i64>>(value: T) -> i64 {
        value.try_into().unwrap_or_default()
    }

    fn normalize_u32<T: TryInto<u32>>(value: T) -> u32 {
        value.try_into().unwrap_or_default()
    }

    fn normalize_u64<T: TryInto<u64>>(value: T) -> u64 {
        value.try_into().unwrap_or_default()
    }

    fn temporary_name(name: &OsStr) -> SecurityResult<OsString> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| SecurityError::Malformed {
            format: "temporary filename",
            detail: error.to_string(),
        })?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut bytes = b".".to_vec();
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b".");
        bytes.extend_from_slice(suffix.as_bytes());
        bytes.extend_from_slice(b".tmp");
        Ok(OsString::from_vec(bytes))
    }

    fn sync_file(file: &File) -> std::io::Result<()> {
        fsync(file).map_err(std::io::Error::from)?;
        #[cfg(target_vendor = "apple")]
        rustix::fs::fcntl_fullfsync(file).map_err(std::io::Error::from)?;
        Ok(())
    }

    fn sync_fd(fd: impl AsFd) -> std::io::Result<()> {
        fsync(fd).map_err(std::io::Error::from)
    }

    fn validated(path: &Path) -> SecurityResult<PathBuf> {
        let path = validated_allow_empty(path)?;
        if path.as_os_str().is_empty() {
            return Err(SecurityError::InvalidPath(path));
        }
        Ok(path)
    }

    fn validated_allow_empty(path: &Path) -> SecurityResult<PathBuf> {
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            if path.as_os_str().is_empty() {
                return Ok(PathBuf::new());
            }
            return Err(SecurityError::InvalidPath(path.to_path_buf()));
        }
        Ok(path.to_path_buf())
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::symlink;

        use tempfile::TempDir;

        use super::*;

        #[test]
        fn rejects_symlink_for_read_and_parent_traversal() {
            let temp = TempDir::new().expect("temp dir");
            std::fs::write(temp.path().join("target"), b"secret").expect("write target");
            symlink("target", temp.path().join("link")).expect("create link");
            let root = SecureRoot::open(temp.path()).expect("open root");

            assert!(root.read_bounded("link", 32).is_err());

            std::fs::create_dir(temp.path().join("real")).expect("create real");
            symlink("real", temp.path().join("dir-link")).expect("create dir link");
            assert!(root.write_atomic("dir-link/file", b"x", 32, 0o600).is_err());
        }

        #[test]
        fn atomic_failure_preserves_destination_and_cleans_temp() {
            let temp = TempDir::new().expect("temp dir");
            std::fs::write(temp.path().join("state"), b"old").expect("write state");
            let root = SecureRoot::open(temp.path()).expect("open root");
            let error = root
                .write_atomic_inner("state".as_ref(), b"new", 32, 0o600, |_| {
                    Err(std::io::Error::other("injected failure"))
                })
                .expect_err("write must fail");
            assert!(error.to_string().contains("injected failure"));
            assert_eq!(
                std::fs::read(temp.path().join("state")).expect("read state"),
                b"old"
            );
            assert_eq!(
                std::fs::read_dir(temp.path())
                    .expect("list root")
                    .filter_map(Result::ok)
                    .count(),
                1
            );
        }

        #[test]
        fn bounded_io_and_atomic_replace_work() {
            let temp = TempDir::new().expect("temp dir");
            let root = SecureRoot::open(temp.path()).expect("open root");
            root.create_dir_all("private/nested", 0o700)
                .expect("create dirs");
            root.write_atomic("private/nested/state", b"value", 5, 0o600)
                .expect("write state");
            assert_eq!(
                root.read_bounded("private/nested/state", 5)
                    .expect("read state"),
                b"value"
            );
            assert!(matches!(
                root.read_bounded("private/nested/state", 4),
                Err(SecurityError::SizeLimit { .. })
            ));
        }

        #[test]
        fn nonblocking_lock_reports_contention() {
            let temp = TempDir::new().expect("temp dir");
            let root = SecureRoot::open(temp.path()).expect("open root");
            let held = root.lock_exclusive("lease.lock").expect("hold lock");

            assert!(
                root.try_lock_exclusive("lease.lock")
                    .expect("try contended lock")
                    .is_none()
            );
            drop(held);
            assert!(
                root.try_lock_exclusive("lease.lock")
                    .expect("try released lock")
                    .is_some()
            );
        }

        #[test]
        fn create_dir_all_does_not_chmod_existing_ancestors() {
            use std::os::unix::fs::PermissionsExt;

            let temp = TempDir::new().expect("temp dir");
            std::fs::create_dir(temp.path().join("ancestor")).expect("create ancestor");
            std::fs::set_permissions(
                temp.path().join("ancestor"),
                std::fs::Permissions::from_mode(0o700),
            )
            .expect("set ancestor mode");
            let root = SecureRoot::open(temp.path()).expect("open root");
            root.create_dir_all("ancestor/leaf", 0o755)
                .expect("create leaf");
            assert_eq!(
                std::fs::metadata(temp.path().join("ancestor"))
                    .expect("ancestor metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(temp.path().join("ancestor/leaf"))
                    .expect("leaf metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
    }
}

#[cfg(unix)]
pub use platform::SecureRoot;

/// Who may own a trusted configuration file and every directory above it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedOwnership {
    /// The file and every ancestor are root-owned. Use for operator-managed
    /// configuration that an unprivileged user must not be able to change.
    Root,
    /// The file and every ancestor are owned by root or the given user. Use for
    /// configuration a user opts into for their own sessions.
    RootOrUser(u32),
}

impl TrustedOwnership {
    const fn permits(self, owner: u32) -> bool {
        match self {
            Self::Root => owner == 0,
            Self::RootOrUser(user) => owner == 0 || owner == user,
        }
    }
}

/// Reads a bounded regular file whose path cannot be changed by anyone other
/// than the permitted owners.
///
/// The file must be a single-link regular file. The file and every ancestor
/// of its canonical location must be owned according to `ownership` and must
/// not be writable by group or other users. The file is opened without
/// following symlinks and its identity is rechecked after opening.
#[cfg(unix)]
pub fn read_trusted_file(
    path: &Path,
    ownership: TrustedOwnership,
    max_bytes: u64,
) -> SecurityResult<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let invalid = |detail: String| SecurityError::Policy(format!("{}: {detail}", path.display()));
    if !path.is_absolute() {
        return Err(invalid(
            "trusted configuration paths must be absolute".to_owned(),
        ));
    }
    let name = path
        .file_name()
        .ok_or_else(|| invalid("path has no file name".to_owned()))?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("path has no parent directory".to_owned()))?;
    let parent = std::fs::canonicalize(parent)
        .map_err(|source| io_error("canonicalize trusted directory", parent, source))?;
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|source| io_error("inspect trusted directory", ancestor, source))?;
        if !metadata.is_dir() || !ownership.permits(metadata.uid()) || metadata.mode() & 0o022 != 0
        {
            return Err(invalid(format!(
                "directory {} must be a non-symlink directory owned by a permitted owner and not writable by group or other users",
                ancestor.display()
            )));
        }
    }
    let canonical = parent.join(name);
    let expected = std::fs::symlink_metadata(&canonical)
        .map_err(|source| io_error("inspect trusted file", &canonical, source))?;
    let validate = |metadata: &std::fs::Metadata| {
        metadata.file_type().is_file()
            && metadata.nlink() == 1
            && ownership.permits(metadata.uid())
            && metadata.mode() & 0o022 == 0
    };
    if !validate(&expected) {
        return Err(invalid(
            "file must be a single-link regular file owned by a permitted owner and not writable by group or other users".to_owned(),
        ));
    }
    if expected.size() > max_bytes {
        return Err(SecurityError::SizeLimit {
            path: canonical,
            limit: max_bytes,
        });
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&canonical)
        .map_err(|source| io_error("open trusted file", &canonical, source))?;
    let opened = file
        .metadata()
        .map_err(|source| io_error("inspect opened trusted file", &canonical, source))?;
    if opened.dev() != expected.dev() || opened.ino() != expected.ino() || !validate(&opened) {
        return Err(invalid("file changed while it was being opened".to_owned()));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read trusted file", &canonical, source))?;
    if bytes.len() as u64 > max_bytes {
        return Err(SecurityError::SizeLimit {
            path: canonical,
            limit: max_bytes,
        });
    }
    Ok(bytes)
}

#[cfg(not(unix))]
pub fn read_trusted_file(
    _path: &Path,
    _ownership: TrustedOwnership,
    _max_bytes: u64,
) -> SecurityResult<Vec<u8>> {
    Err(SecurityError::UnsupportedPlatform)
}

#[cfg(not(unix))]
pub struct SecureRoot;

#[cfg(not(unix))]
impl SecureRoot {
    pub fn open(_path: impl AsRef<Path>) -> SecurityResult<Self> {
        Err(SecurityError::UnsupportedPlatform)
    }
}

#[cfg(all(test, unix))]
mod trusted_file_tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::Builder::new()
            .prefix(".trusted-file-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        directory
    }

    fn write(path: &Path, mode: u32) {
        std::fs::write(path, b"trusted").expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
    }

    #[test]
    fn trusted_files_require_permitted_owners_and_protected_paths() {
        let directory = private_directory();
        let uid = rustix::process::getuid().as_raw();
        let file = directory.path().join("governance.yaml");
        write(&file, 0o644);
        if ancestors_are_protected(directory.path(), uid) {
            assert_eq!(
                read_trusted_file(&file, TrustedOwnership::RootOrUser(uid), 64).expect("read"),
                b"trusted"
            );
            assert!(matches!(
                read_trusted_file(&file, TrustedOwnership::RootOrUser(uid), 3),
                Err(SecurityError::SizeLimit { .. })
            ));
        }
        if uid != 0 {
            assert!(read_trusted_file(&file, TrustedOwnership::Root, 64).is_err());
        }

        let writable = directory.path().join("writable.yaml");
        write(&writable, 0o664);
        assert!(read_trusted_file(&writable, TrustedOwnership::RootOrUser(uid), 64).is_err());

        let link = directory.path().join("link.yaml");
        symlink(&file, &link).expect("symlink");
        assert!(read_trusted_file(&link, TrustedOwnership::RootOrUser(uid), 64).is_err());
        assert!(read_trusted_file(Path::new("relative.yaml"), TrustedOwnership::Root, 64).is_err());
    }

    fn ancestors_are_protected(path: &Path, uid: u32) -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::canonicalize(path)
            .expect("canonical")
            .ancestors()
            .all(|ancestor| {
                std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                    (metadata.uid() == 0 || metadata.uid() == uid) && metadata.mode() & 0o022 == 0
                })
            })
    }
}
