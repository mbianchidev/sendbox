use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, fchmod, fsync, mkdirat, open, openat, renameat,
    renameat_with, unlinkat,
};
use sendbox_core::CONFIG_SCHEMA_VERSION;
use serde::Serialize;
use serde::de::Error as _;
use serde_yaml_ng::{Mapping, Value};

use crate::{ConfigurationError, SandboxConfiguration};

pub const CONFIG_FILE_MODE: u32 = 0o600;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicWriteMode {
    CreateNew,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationReport {
    pub source_version: u32,
    pub target_version: u32,
    pub explicit_source_version: bool,
    pub schema_changed: bool,
    pub canonicalized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfiguration {
    pub configuration: SandboxConfiguration,
    pub migration: MigrationReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationResult {
    pub configuration: SandboxConfiguration,
    pub yaml: String,
    pub migration: MigrationReport,
}

pub(crate) fn parse_with_migration(
    yaml: &str,
    path: &Path,
) -> Result<LoadedConfiguration, ConfigurationError> {
    let (configuration, explicit_source_version) = decode_v1(yaml, path)?;
    let canonical = serialize(&configuration)?;
    Ok(LoadedConfiguration {
        configuration,
        migration: MigrationReport {
            source_version: CONFIG_SCHEMA_VERSION,
            target_version: CONFIG_SCHEMA_VERSION,
            explicit_source_version,
            schema_changed: false,
            canonicalized: normalize_yaml(yaml) != normalize_yaml(&canonical),
        },
    })
}

pub(crate) fn migrate(yaml: &str, path: &Path) -> Result<MigrationResult, ConfigurationError> {
    let loaded = parse_with_migration(yaml, path)?;
    loaded
        .configuration
        .validate()
        .map_err(ConfigurationError::Validation)?;
    let canonical = serialize(&loaded.configuration)?;
    Ok(MigrationResult {
        configuration: loaded.configuration,
        yaml: canonical,
        migration: loaded.migration,
    })
}

fn decode_v1(yaml: &str, path: &Path) -> Result<(SandboxConfiguration, bool), ConfigurationError> {
    let mut document: Value =
        serde_yaml_ng::from_str(yaml).map_err(|source| ConfigurationError::Decode {
            path: path.to_path_buf(),
            source,
        })?;
    let Some(mapping) = document.as_mapping_mut() else {
        return serde_yaml_ng::from_str::<SandboxConfiguration>(yaml)
            .map(|configuration| (configuration, false))
            .map_err(|source| ConfigurationError::Decode {
                path: path.to_path_buf(),
                source,
            });
    };
    let version = take_schema_version(mapping, path)?;
    if version.is_none() {
        return serde_yaml_ng::from_str(yaml)
            .map(|configuration| (configuration, false))
            .map_err(|source| ConfigurationError::Decode {
                path: path.to_path_buf(),
                source,
            });
    }
    serde_yaml_ng::from_value(document)
        .map(|configuration| (configuration, true))
        .map_err(|source| ConfigurationError::Decode {
            path: path.to_path_buf(),
            source,
        })
}

fn take_schema_version(
    mapping: &mut Mapping,
    path: &Path,
) -> Result<Option<u32>, ConfigurationError> {
    let key = Value::String("schema_version".to_owned());
    let Some(value) = mapping.remove(&key) else {
        return Ok(None);
    };
    let Some(version) = value.as_u64() else {
        return Err(ConfigurationError::Decode {
            path: path.to_path_buf(),
            source: serde_yaml_ng::Error::custom("schema_version must be a positive integer"),
        });
    };
    if version != u64::from(CONFIG_SCHEMA_VERSION) {
        return Err(ConfigurationError::UnsupportedVersion {
            found: version,
            current: CONFIG_SCHEMA_VERSION,
        });
    }
    Ok(Some(CONFIG_SCHEMA_VERSION))
}

pub(crate) fn serialize(
    configuration: &SandboxConfiguration,
) -> Result<String, ConfigurationError> {
    let yaml = serde_yaml_ng::to_string(configuration)
        .map_err(|source| ConfigurationError::Encode { source })?;
    Ok(yaml
        .strip_prefix("---\n")
        .unwrap_or(yaml.as_str())
        .to_owned())
}

pub fn atomic_write_file(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    write_mode: AtomicWriteMode,
) -> io::Result<()> {
    atomic_write_file_inner(path, bytes, mode, write_mode, || Ok(()))
}

pub fn ensure_directory(path: &Path, mode: u32) -> io::Result<()> {
    let directory = open_directory_no_symlinks(path, Some(mode))?;
    fchmod(&directory, mode_from(mode)).map_err(io::Error::from)?;
    fsync(&directory).map_err(io::Error::from)
}

fn atomic_write_file_inner<F>(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    write_mode: AtomicWriteMode,
    before_commit: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination has no file name")
    })?;
    let parent = open_directory_no_symlinks(parent, None)?;
    let (temporary_name, mut temporary) = create_temporary(&parent, mode)?;
    let prepare = (|| {
        temporary.write_all(bytes)?;
        temporary.flush()?;
        fsync(&temporary).map_err(io::Error::from)?;
        before_commit()
    })();
    if let Err(error) = prepare {
        let _ = unlinkat(&parent, &temporary_name, AtFlags::empty());
        return Err(error);
    }

    let commit = match write_mode {
        AtomicWriteMode::CreateNew => renameat_with(
            &parent,
            &temporary_name,
            &parent,
            file_name,
            RenameFlags::NOREPLACE,
        ),
        AtomicWriteMode::Replace => renameat(&parent, &temporary_name, &parent, file_name),
    };
    if let Err(error) = commit {
        let _ = unlinkat(&parent, &temporary_name, AtFlags::empty());
        return Err(io::Error::from(error));
    }

    // The file is fully synced before the atomic commit. Directory fsync is a
    // durability enhancement; it cannot be reported as a failed write after
    // the destination has already become visible.
    let _ = fsync(&parent);
    Ok(())
}

fn open_directory_no_symlinks(path: &Path, create_mode: Option<u32>) -> io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current = if path.is_absolute() {
        open("/", flags, Mode::empty()).map_err(io::Error::from)?
    } else {
        open(".", flags, Mode::empty()).map_err(io::Error::from)?
    };
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path must not contain parent or platform-prefix components",
                ));
            }
        };
        let is_leaf = components.peek().is_none();
        let next = match openat(&current, name, flags, Mode::empty()) {
            Ok(next) => next,
            Err(error) if error == rustix::io::Errno::NOENT && create_mode.is_some() => {
                let Some(mode) = create_mode else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "directory does not exist",
                    ));
                };
                mkdirat(&current, name, mode_from(mode)).map_err(io::Error::from)?;
                openat(&current, name, flags, Mode::empty()).map_err(io::Error::from)?
            }
            Err(error) => return Err(io::Error::from(error)),
        };
        if is_leaf && let Some(mode) = create_mode {
            fchmod(&next, mode_from(mode)).map_err(io::Error::from)?;
        }
        current = next;
    }
    Ok(current)
}

fn create_temporary(parent: &OwnedFd, mode: u32) -> io::Result<(OsString, File)> {
    for _ in 0..128 {
        let name = temporary_name();
        match openat(
            parent,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode_from(mode),
        ) {
            Ok(file) => {
                fchmod(&file, mode_from(mode)).map_err(io::Error::from)?;
                return Ok((name, File::from(file)));
            }
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary file",
    ))
}

fn temporary_name() -> OsString {
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    OsString::from(format!(
        ".sendbox-write-{}-{sequence}.tmp",
        std::process::id()
    ))
}

fn mode_from(mode: u32) -> Mode {
    Mode::from_raw_mode((mode & 0o777) as rustix::fs::RawMode)
}

fn normalize_yaml(yaml: &str) -> String {
    yaml.replace("\r\n", "\n").trim().to_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_components() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        let linked = root.join("linked");
        symlink(&real, &linked).unwrap();

        let error = atomic_write_file(
            &linked.join("config.yaml"),
            b"content",
            0o600,
            AtomicWriteMode::CreateNew,
        )
        .unwrap_err();
        assert!(
            matches!(
                error.raw_os_error(),
                Some(code) if code == rustix::io::Errno::LOOP.raw_os_error()
                    || code == rustix::io::Errno::NOTDIR.raw_os_error()
            ),
            "{error}"
        );
        assert!(!real.join("config.yaml").exists());
    }

    #[test]
    fn no_clobber_commit_loses_a_destination_creation_race() {
        let root = tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let path = root.join("config.yaml");
        let result =
            atomic_write_file_inner(&path, b"sendbox", 0o600, AtomicWriteMode::CreateNew, || {
                fs::write(&path, b"attacker")
            });

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"attacker");
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("sendbox-write")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn creates_directories_without_following_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let external = tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let external = external.path().canonicalize().unwrap();
        symlink(&external, root.join("linked")).unwrap();

        assert!(ensure_directory(&root.join("linked/child"), 0o755).is_err());
        assert!(!external.join("child").exists());
    }
}
