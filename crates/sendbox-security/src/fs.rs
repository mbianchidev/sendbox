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
                device: u64::try_from(stat.st_dev).unwrap_or(0),
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
                return Err(SecurityError::UnsupportedFileType(path));
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
            let (parent, name) = self.open_parent(&path)?;
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
            .map_err(|error| io_error("open lock file", &path, error.into()))?;
            let stat =
                fstat(&fd).map_err(|error| io_error("inspect lock file", &path, error.into()))?;
            let metadata = metadata_from_stat(&stat);
            self.validate_owner(&path, &metadata)?;
            if metadata.entry_type != EntryType::Regular {
                return Err(SecurityError::UnsupportedFileType(path));
            }
            fchmod(&fd, mode_from(PRIVATE_FILE_MODE))
                .map_err(|error| io_error("set lock file mode", &path, error.into()))?;
            rustix::fs::flock(&fd, rustix::fs::FlockOperation::LockExclusive)
                .map_err(|error| io_error("lock file", path, error.into()))?;
            Ok(ExclusiveLock {
                _file: File::from(fd),
            })
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
            mode: u32::from(Mode::from_raw_mode(stat.st_mode).bits()),
            owner: stat.st_uid,
            device: u64::try_from(stat.st_dev).unwrap_or(0),
            inode: stat.st_ino,
            size: u64::try_from(stat.st_size).unwrap_or(0),
            allocated_bytes: u64::try_from(stat.st_blocks)
                .unwrap_or(0)
                .saturating_mul(512),
            modified_unix_seconds: stat.st_mtime,
            modified_nanoseconds: normalize_nanoseconds(stat.st_mtime_nsec),
            hardlink_count: u64::from(stat.st_nlink),
        }
    }

    fn mode_from(mode: u32) -> Mode {
        Mode::from_raw_mode((mode & 0o777) as rustix::fs::RawMode)
    }

    fn normalize_nanoseconds<T: TryInto<i64>>(value: T) -> i64 {
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

#[cfg(not(unix))]
pub struct SecureRoot;

#[cfg(not(unix))]
impl SecureRoot {
    pub fn open(_path: impl AsRef<Path>) -> SecurityResult<Self> {
        Err(SecurityError::UnsupportedPlatform)
    }
}
