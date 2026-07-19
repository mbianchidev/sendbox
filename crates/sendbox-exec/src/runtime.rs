//! Fresh owner-only Unix runtime directories, sockets, and peer checks.

#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use sendbox_core::SessionId;
use thiserror::Error;

use crate::platform;
use crate::session::{BrokerSession, CREDENTIALS_FILE_NAME, SessionError};

const RUNTIME_MODE: u32 = 0o700;
const SOCKET_MODE: u32 = 0o600;
pub const SOCKET_FILE_NAME: &str = "s";

/// Strict runtime path errors.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime path {0} already exists; stale paths are never reused")]
    StalePath(PathBuf),
    #[error("runtime path {path} has wrong type")]
    WrongType { path: PathBuf },
    #[error("runtime path {path} is owned by uid {actual}, expected {expected}")]
    WrongOwner {
        path: PathBuf,
        actual: u32,
        expected: u32,
    },
    #[error("runtime path {path} has mode {actual:o}, expected {expected:o}")]
    WrongMode {
        path: PathBuf,
        actual: u32,
        expected: u32,
    },
    #[error("runtime io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("peer uid {actual} does not match expected uid {expected}")]
    PeerUid { actual: u32, expected: u32 },
    #[error(transparent)]
    Platform(#[from] crate::error::PlatformError),
    #[error(transparent)]
    Session(#[from] SessionError),
}

/// A fresh session-scoped runtime directory.
#[derive(Debug)]
pub struct RuntimeDirectory {
    path: PathBuf,
    expected_uid: u32,
}

impl RuntimeDirectory {
    /// Creates `<parent>/<lowercase session hex>` with mode 0700. The short
    /// name preserves headroom for Unix-domain socket path limits.
    pub fn create(
        parent: &Path,
        session_id: SessionId,
        expected_uid: u32,
    ) -> Result<Self, RuntimeError> {
        let path = parent.join(session_id.to_string());
        if fs::symlink_metadata(&path).is_ok() {
            return Err(RuntimeError::StalePath(path));
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(RUNTIME_MODE);
        builder.create(&path).map_err(|source| RuntimeError::Io {
            path: path.clone(),
            source,
        })?;
        validate_directory(&path, expected_uid, RUNTIME_MODE)?;
        Ok(Self { path, expected_uid })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.path.join(SOCKET_FILE_NAME)
    }

    #[must_use]
    pub fn credentials_path(&self) -> PathBuf {
        self.path.join(CREDENTIALS_FILE_NAME)
    }

    /// Writes fresh credentials and binds a fresh socket without unlinking.
    pub fn initialize(
        &self,
        session: &BrokerSession,
    ) -> Result<AuthenticatedUnixListener, RuntimeError> {
        validate_directory(&self.path, self.expected_uid, RUNTIME_MODE)?;
        let credentials_path = self.credentials_path();
        session.write_credentials(&credentials_path)?;
        let credentials_identity = artifact_identity(&credentials_path)?;
        match self.bind() {
            Ok(listener) => Ok(listener),
            Err(error) => {
                rollback_owned_artifact(&credentials_path, credentials_identity);
                Err(error)
            }
        }
    }

    /// Binds a fresh owner-only Unix socket. Existing paths are fatal.
    pub fn bind(&self) -> Result<AuthenticatedUnixListener, RuntimeError> {
        validate_directory(&self.path, self.expected_uid, RUNTIME_MODE)?;
        let path = self.socket_path();
        if fs::symlink_metadata(&path).is_ok() {
            return Err(RuntimeError::StalePath(path));
        }
        let listener = UnixListener::bind(&path).map_err(|source| RuntimeError::Io {
            path: path.clone(),
            source,
        })?;
        let identity = match path_identity(&path) {
            Ok(identity) => identity,
            Err(error) => {
                drop(listener);
                return Err(error);
            }
        };
        let setup = (|| {
            let mut permissions = fs::symlink_metadata(&path)
                .map_err(|source| RuntimeError::Io {
                    path: path.clone(),
                    source,
                })?
                .permissions();
            permissions.set_mode(SOCKET_MODE);
            fs::set_permissions(&path, permissions).map_err(|source| RuntimeError::Io {
                path: path.clone(),
                source,
            })?;
            validate_socket(&path, self.expected_uid)?;
            if path_identity(&path)? != identity {
                return Err(RuntimeError::StalePath(path.clone()));
            }
            Ok(())
        })();
        if let Err(error) = setup {
            rollback_owned_socket(&path, identity);
            drop(listener);
            return Err(error);
        }
        Ok(AuthenticatedUnixListener {
            listener,
            path,
            expected_uid: self.expected_uid,
        })
    }

    /// Removes only an empty runtime directory after its socket and
    /// credential files have already been explicitly removed.
    pub fn remove(self) -> Result<(), RuntimeError> {
        fs::remove_dir(&self.path).map_err(|source| RuntimeError::Io {
            path: self.path,
            source,
        })
    }
}

/// Listener that authenticates every accepted connection with `SO_PEERCRED`.
#[derive(Debug)]
pub struct AuthenticatedUnixListener {
    listener: UnixListener,
    path: PathBuf,
    expected_uid: u32,
}

impl AuthenticatedUnixListener {
    pub fn accept(&self) -> Result<UnixStream, RuntimeError> {
        validate_socket(&self.path, self.expected_uid)?;
        let (stream, _) = self.listener.accept().map_err(|source| RuntimeError::Io {
            path: self.path.clone(),
            source,
        })?;
        validate_socket(&self.path, self.expected_uid)?;
        authenticate_peer(&stream, self.expected_uid)?;
        Ok(stream)
    }

    #[must_use]
    pub fn local_path(&self) -> &Path {
        &self.path
    }
}

/// Validates the socket before connecting and never follows a stale symlink.
pub fn connect(path: &Path, expected_uid: u32) -> Result<UnixStream, RuntimeError> {
    let identity = path_identity(path)?;
    validate_socket(path, expected_uid)?;
    let stream = UnixStream::connect(path).map_err(|source| RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_socket(path, expected_uid)?;
    if path_identity(path)? != identity {
        return Err(RuntimeError::StalePath(path.to_path_buf()));
    }
    authenticate_peer(&stream, expected_uid)?;
    Ok(stream)
}

pub fn authenticate_peer(stream: &UnixStream, expected_uid: u32) -> Result<(), RuntimeError> {
    validate_peer_uid(platform::peer_uid(stream)?, expected_uid)
}

fn validate_peer_uid(actual: u32, expected: u32) -> Result<(), RuntimeError> {
    if actual != expected {
        return Err(RuntimeError::PeerUid { actual, expected });
    }
    Ok(())
}

fn validate_directory(path: &Path, expected_uid: u32, mode: u32) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::WrongType {
            path: path.to_path_buf(),
        });
    }
    validate_owner_mode(path, &metadata, expected_uid, mode)
}

fn validate_socket(path: &Path, expected_uid: u32) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(RuntimeError::WrongType {
            path: path.to_path_buf(),
        });
    }
    validate_owner_mode(path, &metadata, expected_uid, SOCKET_MODE)
}

fn validate_owner_mode(
    path: &Path,
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_mode: u32,
) -> Result<(), RuntimeError> {
    if metadata.uid() != expected_uid {
        return Err(RuntimeError::WrongOwner {
            path: path.to_path_buf(),
            actual: metadata.uid(),
            expected: expected_uid,
        });
    }

    let actual = metadata.permissions().mode() & 0o777;
    if actual != expected_mode {
        return Err(RuntimeError::WrongMode {
            path: path.to_path_buf(),
            actual,
            expected: expected_mode,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArtifactIdentity {
    path: PathIdentity,
    size: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn path_identity(path: &Path) -> Result<PathIdentity, RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(PathIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
    })
}

fn artifact_identity(path: &Path) -> Result<ArtifactIdentity, RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(ArtifactIdentity {
        path: PathIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        },
        size: metadata.size(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn rollback_owned_artifact(path: &Path, expected: ArtifactIdentity) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    let type_matches = metadata.is_file() && !metadata.file_type().is_symlink();
    let identity = ArtifactIdentity {
        path: PathIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        },
        size: metadata.size(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    };
    if type_matches && identity == expected {
        let _ = fs::remove_file(path);
    }
}

fn rollback_owned_socket(path: &Path, expected: PathIdentity) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_socket()
        && (PathIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        }) == expected
    {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_directory_and_socket_refuse_stale_reuse() {
        let parent = tempfile::tempdir().expect("tempdir");
        let uid = fs::metadata(parent.path()).expect("metadata").uid();
        let id = SessionId::from_bytes([7; 16]);
        let runtime = RuntimeDirectory::create(parent.path(), id, uid).expect("runtime");
        assert!(matches!(
            RuntimeDirectory::create(parent.path(), id, uid),
            Err(RuntimeError::StalePath(_))
        ));
        let listener = runtime.bind().expect("bind");
        assert!(matches!(runtime.bind(), Err(RuntimeError::StalePath(_))));
        drop(listener);
        fs::remove_file(runtime.socket_path()).expect("remove socket");
        runtime.remove().expect("remove runtime");
    }

    #[test]
    fn socket_validation_rejects_wrong_expected_uid() {
        let parent = tempfile::tempdir().expect("tempdir");
        let uid = fs::metadata(parent.path()).expect("metadata").uid();
        let runtime = RuntimeDirectory::create(parent.path(), SessionId::from_bytes([8; 16]), uid)
            .expect("runtime");
        let listener = runtime.bind().expect("bind");
        let wrong_uid = uid.wrapping_add(1);
        assert!(matches!(
            connect(listener.local_path(), wrong_uid),
            Err(RuntimeError::WrongOwner { .. })
        ));
        drop(listener);
        fs::remove_file(runtime.socket_path()).expect("remove socket");
        runtime.remove().expect("remove runtime");
    }

    #[test]
    fn initialization_rolls_back_only_its_credential_file() {
        let parent = tempfile::tempdir().expect("tempdir");
        let uid = fs::metadata(parent.path()).expect("metadata").uid();
        let runtime = RuntimeDirectory::create(parent.path(), SessionId::from_bytes([9; 16]), uid)
            .expect("runtime");
        fs::write(runtime.socket_path(), b"stale").expect("stale socket path");
        let session = BrokerSession::generate().expect("session");
        assert!(matches!(
            runtime.initialize(&session),
            Err(RuntimeError::StalePath(_))
        ));
        assert!(!runtime.credentials_path().exists());
        assert_eq!(
            fs::read(runtime.socket_path()).expect("stale file remains"),
            b"stale"
        );
        fs::remove_file(runtime.socket_path()).expect("remove stale");
        runtime.remove().expect("remove runtime");
    }

    #[test]
    fn peer_uid_mismatch_is_typed() {
        assert!(matches!(
            validate_peer_uid(1001, 1000),
            Err(RuntimeError::PeerUid {
                actual: 1001,
                expected: 1000
            })
        ));
    }

    #[test]
    fn rollback_refuses_to_remove_a_replaced_artifact() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("artifact");
        fs::write(&path, b"original").expect("write original");
        let identity = artifact_identity(&path).expect("identity");
        fs::remove_file(&path).expect("remove original");
        fs::write(&path, b"replacement").expect("write replacement");
        rollback_owned_artifact(&path, identity);
        assert_eq!(
            fs::read(&path).expect("replacement remains"),
            b"replacement"
        );
    }
}
