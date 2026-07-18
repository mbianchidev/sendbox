use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

const MAX_SOCKET_PATH_BYTES: usize = 103;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SocketPublication {
    pub host_path: PathBuf,
    pub guest_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum SocketPublicationError {
    #[error("{side} socket path must be absolute")]
    RelativePath { side: &'static str },
    #[error("{side} socket path must not contain `..`")]
    ParentTraversal { side: &'static str },
    #[error("{side} socket path must be valid UTF-8")]
    NonUtf8 { side: &'static str },
    #[error("{side} socket path must not contain `:` or NUL")]
    InvalidCharacter { side: &'static str },
    #[error("{side} socket path exceeds {MAX_SOCKET_PATH_BYTES} UTF-8 bytes")]
    TooLong { side: &'static str },
    #[error("host socket path already exists: {0}")]
    HostPathExists(PathBuf),
    #[error("could not inspect host socket path `{path}`: {source}")]
    HostPathInspection {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl SocketPublication {
    pub fn new(
        host_path: impl Into<PathBuf>,
        guest_path: impl Into<PathBuf>,
    ) -> Result<Self, SocketPublicationError> {
        let host_path = host_path.into();
        let guest_path = guest_path.into();
        validate_path(&host_path, "host")?;
        validate_path(&guest_path, "guest")?;
        match host_path.try_exists() {
            Ok(false) => {}
            Ok(true) => return Err(SocketPublicationError::HostPathExists(host_path)),
            Err(source) => {
                return Err(SocketPublicationError::HostPathInspection {
                    path: host_path,
                    source,
                });
            }
        }
        Ok(Self {
            host_path,
            guest_path,
        })
    }

    #[must_use]
    pub fn specification(&self) -> String {
        format!("{}:{}", self.host_path.display(), self.guest_path.display())
    }
}

fn validate_path(path: &Path, side: &'static str) -> Result<(), SocketPublicationError> {
    if !path.is_absolute() {
        return Err(SocketPublicationError::RelativePath { side });
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(SocketPublicationError::ParentTraversal { side });
    }
    let Some(path) = path.to_str() else {
        return Err(SocketPublicationError::NonUtf8 { side });
    };
    if path.contains(':') || path.contains('\0') {
        return Err(SocketPublicationError::InvalidCharacter { side });
    }
    if path.len() > MAX_SOCKET_PATH_BYTES {
        return Err(SocketPublicationError::TooLong { side });
    }
    Ok(())
}
