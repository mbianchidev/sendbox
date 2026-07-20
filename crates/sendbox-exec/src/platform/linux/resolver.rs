//! Descriptor-relative executable and working-directory resolution.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use crate::api::{DescriptorPath, FileIdentity, RootId};
use crate::error::PlatformError;

use super::raw;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const DENIED_EXECUTABLE_BASENAMES: &[&str] = &[
    "env",
    "ld.so",
    "ld-linux.so.2",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
    "ld-linux-armhf.so.3",
    "ld-musl-x86_64.so.1",
    "ld-musl-aarch64.so.1",
    "ld64.so.1",
    "ld64.so.2",
];

/// One trusted root descriptor opened before untrusted requests are handled.
#[derive(Debug)]
pub struct RootDirectory {
    path: PathBuf,
    fd: OwnedFd,
}

impl RootDirectory {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PlatformError> {
        let path = path.as_ref().to_path_buf();
        let fd = raw::open_root(&path)?;
        Ok(Self { path, fd })
    }

    #[must_use]
    pub fn configured_path(&self) -> &Path {
        &self.path
    }
}

/// Immutable set of trusted root descriptors.
#[derive(Debug, Default)]
pub struct RootSet {
    roots: BTreeMap<RootId, RootDirectory>,
}

impl RootSet {
    #[must_use]
    pub fn new(roots: BTreeMap<RootId, RootDirectory>) -> Self {
        Self { roots }
    }

    pub fn insert(&mut self, id: RootId, root: RootDirectory) -> Option<RootDirectory> {
        self.roots.insert(id, root)
    }

    pub fn resolve(
        &self,
        executable: &DescriptorPath,
        cwd: &DescriptorPath,
    ) -> Result<ResolvedCommand, PlatformError> {
        let executable_root = self.root(&executable.root)?;
        let cwd_root = self.root(&cwd.root)?;
        let executable_fd = raw::open_beneath(
            executable_root.fd.as_raw_fd(),
            executable.relative.as_str(),
            false,
        )?;
        let cwd_fd = raw::open_beneath(cwd_root.fd.as_raw_fd(), cwd.relative.as_str(), true)?;
        let executable_identity = raw::identity(executable_fd.as_raw_fd())?;
        let cwd_identity = raw::identity(cwd_fd.as_raw_fd())?;
        validate_executable(
            &executable_fd,
            executable.relative.as_str(),
            executable_identity,
        )?;
        validate_directory(cwd_identity)?;
        Ok(ResolvedCommand {
            executable_fd,
            cwd_fd,
            executable_identity,
            cwd_identity,
        })
    }

    fn root(&self, id: &RootId) -> Result<&RootDirectory, PlatformError> {
        self.roots.get(id).ok_or_else(|| {
            PlatformError::io(
                "select trusted root",
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("trusted root {id:?} is not configured"),
                ),
            )
        })
    }
}

/// Retained descriptors and identities approved for one launch.
#[derive(Debug)]
pub struct ResolvedCommand {
    pub(crate) executable_fd: OwnedFd,
    pub(crate) cwd_fd: OwnedFd,
    pub executable_identity: FileIdentity,
    pub cwd_identity: FileIdentity,
}

fn validate_executable(
    descriptor: &OwnedFd,
    relative: &str,
    identity: FileIdentity,
) -> Result<(), PlatformError> {
    if identity.mode & libc::S_IFMT != libc::S_IFREG {
        return Err(PlatformError::io(
            "validate executable type",
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "executable is not a regular file",
            ),
        ));
    }
    let basename = Path::new(relative)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if DENIED_EXECUTABLE_BASENAMES.contains(&basename) {
        return Err(PlatformError::io(
            "validate executable basename",
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "generic environment launcher or dynamic linker is denied",
            ),
        ));
    }
    let mut file = File::from(
        descriptor
            .try_clone()
            .map_err(|source| PlatformError::io("clone executable fd", source))?,
    );
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .map_err(|source| PlatformError::io("read executable ELF magic", source))?;
    if magic != ELF_MAGIC {
        return Err(PlatformError::io(
            "validate executable ELF magic",
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "scripts and non-ELF executables are denied",
            ),
        ));
    }
    let after = raw::identity(descriptor.as_raw_fd())?;
    if after != identity {
        return Err(PlatformError::io(
            "revalidate executable descriptor",
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "executable descriptor identity changed during validation",
            ),
        ));
    }
    Ok(())
}

fn validate_directory(identity: FileIdentity) -> Result<(), PlatformError> {
    if identity.mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(PlatformError::io(
            "validate cwd type",
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "working directory is not a directory",
            ),
        ));
    }
    Ok(())
}
