//! Broker session identity, authentication, and fresh credential files.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sendbox_core::SessionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::api::{CorrelationId, SESSION_AUTHENTICATION_BYTES, SessionAuthentication};

pub const CREDENTIALS_FILE_NAME: &str = "session.credentials";
const CREDENTIALS_MODE: u32 = 0o600;
const CREDENTIALS_LOCKED_MODE: u32 = 0o400;

/// Safe representation written to the private runtime directory.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCredentials {
    pub session_id_hex: String,
    pub token_hex: String,
}

impl fmt::Debug for SessionCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCredentials")
            .field("session_id_hex", &self.session_id_hex)
            .field("token_hex", &"<redacted>")
            .finish()
    }
}

impl SessionCredentials {
    /// Converts filesystem-boundary hex back to binary protocol material.
    pub fn decode(&self, path: &Path) -> Result<(SessionId, SessionAuthentication), SessionError> {
        let session_bytes = decode_fixed_hex::<16>(&self.session_id_hex)
            .ok_or_else(|| SessionError::MalformedSessionId(path.to_path_buf()))?;
        let token = decode_fixed_hex::<SESSION_AUTHENTICATION_BYTES>(&self.token_hex)
            .ok_or_else(|| SessionError::MalformedToken(path.to_path_buf()))?;
        Ok((
            SessionId::from_bytes(session_bytes),
            SessionAuthentication::from_bytes(token),
        ))
    }
}

/// Session persistence and validation failures.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("failed to source random session material: {0}")]
    Random(#[from] getrandom::Error),
    #[error("session credential file {0} already exists or cannot be created")]
    Create(PathBuf, #[source] io::Error),
    #[error("session credential file {0} cannot be read or written")]
    Io(PathBuf, #[source] io::Error),
    #[error("session credential file {0} is not a regular non-symlink file")]
    WrongType(PathBuf),
    #[error("session credential file {path} is owned by uid {actual}, expected {expected}")]
    WrongOwner {
        path: PathBuf,
        actual: u32,
        expected: u32,
    },
    #[error("session credential file {path} has unsafe mode {actual:o}")]
    WrongMode { path: PathBuf, actual: u32 },
    #[error("session credential file {0} contains malformed JSON")]
    Decode(PathBuf, #[source] serde_json::Error),
    #[error("session credential file {0} contains a malformed session id")]
    MalformedSessionId(PathBuf),
    #[error("session credential file {0} contains a malformed token")]
    MalformedToken(PathBuf),
    #[error("failed to serialize session credentials: {0}")]
    Encode(#[source] serde_json::Error),
}

/// One live broker session. Correlation identifiers are globally single-use.
pub struct BrokerSession {
    id: SessionId,
    token: Zeroizing<[u8; SESSION_AUTHENTICATION_BYTES]>,
    correlations: Mutex<BTreeSet<CorrelationId>>,
}

impl fmt::Debug for BrokerSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerSession")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BrokerSession {
    /// Generates fresh binary session identity and authentication material.
    pub fn generate() -> Result<Self, SessionError> {
        let mut id = [0u8; 16];
        let mut token = [0u8; SESSION_AUTHENTICATION_BYTES];
        getrandom::fill(&mut id)?;
        getrandom::fill(&mut token)?;
        Ok(Self {
            id: SessionId::from_bytes(id),
            token: Zeroizing::new(token),
            correlations: Mutex::new(BTreeSet::new()),
        })
    }

    #[must_use]
    pub fn from_material(id: SessionId, authentication: SessionAuthentication) -> Self {
        Self {
            id,
            token: Zeroizing::new(*authentication.as_bytes()),
            correlations: Mutex::new(BTreeSet::new()),
        }
    }

    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    #[must_use]
    pub fn authentication(&self) -> SessionAuthentication {
        SessionAuthentication::from_bytes(*self.token)
    }

    #[must_use]
    pub fn authenticate(
        &self,
        session_id: SessionId,
        authentication: &SessionAuthentication,
    ) -> bool {
        if session_id != self.id {
            return false;
        }
        let mut difference = 0u8;
        for (expected, supplied) in self.token.iter().zip(authentication.as_bytes()) {
            difference |= expected ^ supplied;
        }
        difference == 0
    }

    /// Registers a correlation id exactly once across all connections.
    #[must_use]
    pub fn register(&self, correlation_id: CorrelationId) -> bool {
        self.correlations
            .lock()
            .expect("broker session correlation mutex poisoned")
            .insert(correlation_id)
    }

    #[must_use]
    pub fn credentials(&self) -> SessionCredentials {
        SessionCredentials {
            session_id_hex: self.id.to_string(),
            token_hex: encode_hex(self.token.as_ref()),
        }
    }

    /// Creates a new credentials file atomically and refuses stale reuse.
    pub fn write_credentials(&self, path: &Path) -> Result<(), SessionError> {
        let bytes = serde_json::to_vec(&self.credentials()).map_err(SessionError::Encode)?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(CREDENTIALS_MODE)
            .open(path)
            .map_err(|source| SessionError::Create(path.to_path_buf(), source))?;
        let metadata = file
            .metadata()
            .map_err(|source| SessionError::Io(path.to_path_buf(), source))?;
        let identity = FileIdentity::from_metadata(&metadata);
        let result = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| SessionError::Io(path.to_path_buf(), source))
            .and_then(|()| validate_credentials_metadata(path, metadata.uid()));
        if result.is_err() {
            rollback_regular_file(path, identity);
        }
        result
    }
}

/// Loads credentials only after lstat owner/mode/type validation.
pub fn load_credentials(
    path: &Path,
    expected_uid: u32,
) -> Result<(SessionId, SessionAuthentication), SessionError> {
    validate_credentials_metadata(path, expected_uid)?;
    let contents = fs::read(path).map_err(|source| SessionError::Io(path.to_path_buf(), source))?;
    let credentials: SessionCredentials = serde_json::from_slice(&contents)
        .map_err(|source| SessionError::Decode(path.to_path_buf(), source))?;
    credentials.decode(path)
}

fn validate_credentials_metadata(path: &Path, expected_uid: u32) -> Result<(), SessionError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| SessionError::Io(path.to_path_buf(), source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SessionError::WrongType(path.to_path_buf()));
    }

    if metadata.uid() != expected_uid {
        return Err(SessionError::WrongOwner {
            path: path.to_path_buf(),
            actual: metadata.uid(),
            expected: expected_uid,
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if !matches!(mode, CREDENTIALS_MODE | CREDENTIALS_LOCKED_MODE) {
        return Err(SessionError::WrongMode {
            path: path.to_path_buf(),
            actual: mode,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        }
    }
}

fn rollback_regular_file(path: &Path, expected: FileIdentity) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || FileIdentity::from_metadata(&metadata) != expected
    {
        return;
    }
    let _ = fs::remove_file(path);
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut result = [0u8; N];
    for (index, output) in result.iter_mut().enumerate() {
        let offset = index * 2;
        *output = (decode_nibble(value.as_bytes()[offset])? << 4)
            | decode_nibble(value.as_bytes()[offset + 1])?;
    }
    Some(result)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_round_trip_and_debug_redacts_token() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join(CREDENTIALS_FILE_NAME);
        let session = BrokerSession::generate().expect("session");
        session.write_credentials(&path).expect("write");
        let uid = fs::metadata(&path).expect("metadata").uid();
        let (id, authentication) = load_credentials(&path, uid).expect("load");
        assert!(session.authenticate(id, &authentication));
        let debug = format!("{:?}", session.credentials());
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&session.credentials().token_hex));
    }

    #[test]
    fn credentials_refuse_stale_reuse_and_permissive_modes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join(CREDENTIALS_FILE_NAME);
        let session = BrokerSession::generate().expect("session");
        session.write_credentials(&path).expect("write");
        assert!(matches!(
            session.write_credentials(&path),
            Err(SessionError::Create(_, _))
        ));
        let uid = fs::metadata(&path).expect("metadata").uid();
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&path, permissions).expect("chmod");
        assert!(matches!(
            load_credentials(&path, uid),
            Err(SessionError::WrongMode { .. })
        ));
    }

    #[test]
    fn credentials_reject_symlinks_and_wrong_owners() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join(CREDENTIALS_FILE_NAME);
        let link = directory.path().join("credentials.link");
        let session = BrokerSession::generate().expect("session");
        session.write_credentials(&path).expect("write");
        let uid = fs::metadata(&path).expect("metadata").uid();
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(matches!(
            load_credentials(&link, uid),
            Err(SessionError::WrongType(_))
        ));
        assert!(matches!(
            load_credentials(&path, uid.wrapping_add(1)),
            Err(SessionError::WrongOwner { .. })
        ));
    }
}
