use std::{
    env,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::GuardError;

#[derive(Debug, Clone)]
pub struct TrustedGitBinary {
    path: PathBuf,
    identity: FileIdentity,
    _descriptor: Arc<File>,
}

impl TrustedGitBinary {
    pub fn verify(path: impl AsRef<Path>) -> Result<Self, GuardError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(invalid(path, "path is not absolute"));
        }
        let symlink_metadata = fs::symlink_metadata(path).map_err(|error| invalid(path, error))?;
        if symlink_metadata.file_type().is_symlink() {
            return Err(invalid(path, "symlinks are not trusted"));
        }
        if !symlink_metadata.is_file() {
            return Err(invalid(path, "path is not a regular file"));
        }
        validate_mode(path, &symlink_metadata)?;
        let canonical = fs::canonicalize(path).map_err(|error| invalid(path, error))?;
        if canonical != path {
            return Err(invalid(path, "path is not canonical"));
        }
        let descriptor = File::open(path).map_err(|error| invalid(path, error))?;
        let identity = FileIdentity::from_metadata(
            &descriptor
                .metadata()
                .map_err(|error| invalid(path, error))?,
        );
        let current = env::current_exe().map_err(|error| invalid(path, error))?;
        if let Ok(current_metadata) = fs::metadata(current)
            && identity == FileIdentity::from_metadata(&current_metadata)
        {
            return Err(invalid(path, "guard recursion is not allowed"));
        }
        Ok(Self {
            path: path.to_owned(),
            identity,
            _descriptor: Arc::new(descriptor),
        })
    }

    pub fn verify_unchanged(&self) -> Result<(), GuardError> {
        let metadata =
            fs::symlink_metadata(&self.path).map_err(|error| invalid(&self.path, error))?;
        validate_mode(&self.path, &metadata)?;
        if metadata.file_type().is_symlink()
            || self.identity != FileIdentity::from_metadata(&metadata)
        {
            return Err(invalid(
                &self.path,
                "binary identity changed after verification",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn invalid(path: &Path, reason: impl ToString) -> GuardError {
    GuardError::InvalidGitBinary {
        path: path.to_owned(),
        reason: reason.to_string(),
    }
}

#[cfg(unix)]
fn validate_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), GuardError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(invalid(path, "binary is not executable"));
    }
    if mode & 0o022 != 0 {
        return Err(invalid(path, "binary is group- or world-writable"));
    }
    let owner = metadata.uid();
    if owner != 0 && owner != rustix::process::geteuid().as_raw() {
        return Err(invalid(path, "binary owner is not trusted"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_mode(_path: &Path, _metadata: &fs::Metadata) -> Result<(), GuardError> {
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    #[cfg(unix)]
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    #[cfg(not(unix))]
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: 0,
            inode: 0,
            length: metadata.len(),
            changed_seconds: 0,
            changed_nanoseconds: 0,
        }
    }
}
