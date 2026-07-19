//! Session identity: a single, broker-instance-wide session id plus a
//! 32-byte token, generated once at broker startup and shared by every
//! connection for the lifetime of that broker instance.
//!
//! This is the credential every `Execute`/`Cancel` request must carry on
//! the wire (see [`crate::protocol::ClientMessage`]) in addition to the
//! kernel-level `SO_PEERCRED` check performed when a connection is
//! accepted: `SO_PEERCRED` proves *which user* is connected, while the
//! session id/token proves the caller actually holds the credential the
//! broker wrote to its private, owner-only credential file at startup
//! (see [`Session::write_credentials_file`] / [`load_credentials_file`]).
//! Because the session is shared broker-wide (not re-issued per
//! connection), a correlation id already used on *any* connection is a
//! duplicate on *every* connection, for as long as the broker runs.
//!
//! This module is pure aside from the credential-file read/write helpers,
//! which use only safe standard-library filesystem APIs (`std::fs`,
//! `std::os::unix::fs`) — no `unsafe` anywhere.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Length, in bytes, of a session token.
pub const TOKEN_BYTES: usize = 32;

/// Length, in bytes, of the random component of a session id.
const SESSION_ID_RANDOM_BYTES: usize = 16;

/// Filename of the session credential file inside the broker's runtime
/// directory.
pub const CREDENTIALS_FILE_NAME: &str = "session.credentials";

/// Permission bits the broker writes the credential file with. A client
/// reading it back accepts either this or [`CREDENTIALS_FILE_MODE_LOCKED`]
/// (an operator may harden an already-written file to read-only).
const CREDENTIALS_FILE_MODE: u32 = 0o600;

/// An alternate, stricter permission an operator may apply to the
/// credential file after creation (owner read-only). Accepted by
/// [`load_credentials_file`] as equally valid to [`CREDENTIALS_FILE_MODE`].
const CREDENTIALS_FILE_MODE_LOCKED: u32 = 0o400;

/// Errors generating, persisting, or loading session material.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("failed to source random bytes for session material: {0}")]
    Random(#[from] getrandom::Error),
    #[error("failed to serialize session credentials: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("failed to parse session credential file {path}: {source}")]
    Decode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("io error on session credential file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("session credential file {0} is a symlink, not a regular file")]
    Symlink(PathBuf),
    #[error("session credential file {path} is owned by uid {actual}, expected {expected}")]
    WrongOwner {
        path: PathBuf,
        actual: u32,
        expected: u32,
    },
    #[error(
        "session credential file {path} has mode {actual:o}, expected {:o} or {:o}",
        CREDENTIALS_FILE_MODE,
        CREDENTIALS_FILE_MODE_LOCKED
    )]
    WrongMode { path: PathBuf, actual: u32 },
    #[error("token in session credential file {0} is not valid hex")]
    MalformedToken(PathBuf),
}

/// An opaque, hex-encoded session identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Generates a new random session id.
    pub fn generate() -> Result<Self, SessionError> {
        let mut bytes = [0u8; SESSION_ID_RANDOM_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(hex_encode(&bytes)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A 32-byte, cryptographically random per-session token.
#[derive(Clone)]
pub struct SessionToken([u8; TOKEN_BYTES]);

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the token value itself.
        f.write_str("SessionToken(..)")
    }
}

impl SessionToken {
    /// Generates a new random token.
    pub fn generate() -> Result<Self, SessionError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }

    /// Hex-encodes the token for wire/file transport.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Constant-time equality check against a byte slice supplied by a
    /// peer, to avoid leaking timing information about how many leading
    /// bytes matched.
    #[must_use]
    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        if other.len() != TOKEN_BYTES {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// A safe, serializable representation of a session's credentials — what
/// gets written to (and read back from) the on-disk credential file, and
/// what a client places into the `session_id`/`token` fields of every
/// `Execute`/`Cancel` request.
///
/// The custom [`fmt::Debug`] impl below deliberately never prints
/// `token_hex`, mirroring [`SessionToken`]'s own `Debug` impl, so this
/// value is safe to include in a log line by accident — the token is only
/// ever exposed through [`SessionCredentials::token_hex`] or by
/// serializing to JSON (used solely for the credential file/wire
/// protocol, never logged by this crate).
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionCredentials {
    pub session_id: String,
    pub token_hex: String,
}

impl fmt::Debug for SessionCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCredentials")
            .field("session_id", &self.session_id)
            .field("token_hex", &"<redacted>")
            .finish()
    }
}

/// A live, broker-instance-wide session: a single id/token pair generated
/// once at broker startup and shared, via `Arc`, by every accepted
/// connection for the lifetime of that broker instance. Also tracks every
/// correlation id used so far, across all connections, so a duplicate is
/// detected regardless of which connection first used it.
#[derive(Debug)]
pub struct Session {
    id: SessionId,
    token: SessionToken,
    known_correlation_ids: Mutex<BTreeSet<String>>,
}

impl Session {
    /// Generates a fresh session, intended to be called exactly once at
    /// broker startup.
    pub fn generate() -> Result<Self, SessionError> {
        Ok(Self {
            id: SessionId::generate()?,
            token: SessionToken::generate()?,
            known_correlation_ids: Mutex::new(BTreeSet::new()),
        })
    }

    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    #[must_use]
    pub fn token(&self) -> &SessionToken {
        &self.token
    }

    /// The safe, serializable credential representation for this session.
    #[must_use]
    pub fn credentials(&self) -> SessionCredentials {
        SessionCredentials {
            session_id: self.id.as_str().to_string(),
            token_hex: self.token.to_hex(),
        }
    }

    /// Verifies that `session_id` and `token` (raw bytes) match this
    /// session, in constant time with respect to the token comparison.
    #[must_use]
    pub fn authenticate(&self, session_id: &str, token: &[u8]) -> bool {
        self.id.as_str() == session_id && self.token.constant_time_eq(token)
    }

    /// Verifies that `session_id` and `token_hex` (as carried on the wire)
    /// match this session. Returns `false` (rather than erroring) if
    /// `token_hex` is not valid hex, since a malformed token is simply a
    /// failed authentication attempt, not a distinct error case a caller
    /// needs to handle differently.
    #[must_use]
    pub fn authenticate_hex(&self, session_id: &str, token_hex: &str) -> bool {
        match hex_decode(token_hex) {
            Some(bytes) => self.authenticate(session_id, &bytes),
            None => false,
        }
    }

    /// Registers a correlation id as in-use for this session (across every
    /// connection), returning `false` if it was already registered (a
    /// duplicate).
    #[must_use]
    pub fn register_correlation_id(&self, correlation_id: &str) -> bool {
        self.known_correlation_ids
            .lock()
            .expect("session correlation id mutex poisoned")
            .insert(correlation_id.to_string())
    }

    /// Returns whether `correlation_id` has already been used on this
    /// session (on any connection).
    #[must_use]
    pub fn is_known_correlation_id(&self, correlation_id: &str) -> bool {
        self.known_correlation_ids
            .lock()
            .expect("session correlation id mutex poisoned")
            .contains(correlation_id)
    }

    /// Writes this session's credentials to `path` as a fresh file (never
    /// overwriting an existing one), with exactly [`CREDENTIALS_FILE_MODE`]
    /// permissions applied atomically at creation time via `mode()` (not a
    /// separate `chmod` afterward, which would leave a window where the
    /// file briefly has the process umask's permissions instead).
    /// Intended to be called once, by the broker, immediately after
    /// creating its private `0700` runtime directory.
    pub fn write_credentials_file(&self, path: &Path) -> Result<(), SessionError> {
        let json = serde_json::to_vec(&self.credentials()).map_err(SessionError::Encode)?;

        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(CREDENTIALS_FILE_MODE)
            .open(path)
            .map_err(|source| SessionError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        file.write_all(&json).map_err(|source| SessionError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        file.flush().map_err(|source| SessionError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        // Re-check immediately after creation, the same defense-in-depth
        // pattern used by `broker::runtime_dir`/`broker::socket`: confirm
        // the mode actually took effect rather than trusting `mode()`
        // alone (a restrictive umask cannot loosen it, but a permissive
        // umask combined with a platform quirk should still be caught).
        let metadata = fs::symlink_metadata(path).map_err(|source| SessionError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.permissions().mode() & 0o777 != CREDENTIALS_FILE_MODE {
            return Err(SessionError::WrongMode {
                path: path.to_path_buf(),
                actual: metadata.permissions().mode() & 0o777,
            });
        }

        Ok(())
    }
}

/// Loads and strictly validates a session credential file before trusting
/// its contents: rejects a symlink at `path` (via `lstat`, never
/// following it), requires the file be owned by `expected_uid`, requires
/// its mode be exactly [`CREDENTIALS_FILE_MODE`] or
/// [`CREDENTIALS_FILE_MODE_LOCKED`], and only then parses it as JSON.
///
/// Used by a connecting client (never by the broker itself, which holds
/// the session in memory) to obtain the `session_id`/`token` it must send
/// with every `Execute`/`Cancel` request.
pub fn load_credentials_file(
    path: &Path,
    expected_uid: u32,
) -> Result<SessionCredentials, SessionError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SessionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(SessionError::Symlink(path.to_path_buf()));
    }
    if metadata.uid() != expected_uid {
        return Err(SessionError::WrongOwner {
            path: path.to_path_buf(),
            actual: metadata.uid(),
            expected: expected_uid,
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != CREDENTIALS_FILE_MODE && mode != CREDENTIALS_FILE_MODE_LOCKED {
        return Err(SessionError::WrongMode {
            path: path.to_path_buf(),
            actual: mode,
        });
    }

    let contents = fs::read_to_string(path).map_err(|source| SessionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let credentials: SessionCredentials =
        serde_json::from_str(&contents).map_err(|source| SessionError::Decode {
            path: path.to_path_buf(),
            source,
        })?;
    if hex_decode(&credentials.token_hex).is_none() {
        return Err(SessionError::MalformedToken(path.to_path_buf()));
    }
    Ok(credentials)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes a lowercase- or uppercase-hex string into bytes, returning
/// `None` on any malformed input (odd length, non-hex characters) rather
/// than panicking — this is invoked on peer-supplied wire data.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_hex_and_expected_length() {
        let id = SessionId::generate().expect("generate");
        assert_eq!(id.as_str().len(), SESSION_ID_RANDOM_BYTES * 2);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn two_generated_session_ids_and_tokens_differ() {
        let a = SessionId::generate().expect("generate");
        let b = SessionId::generate().expect("generate");
        assert_ne!(a, b);

        let ta = SessionToken::generate().expect("generate");
        let tb = SessionToken::generate().expect("generate");
        assert!(!ta.constant_time_eq(tb.as_bytes()));
    }

    #[test]
    fn token_constant_time_eq_matches_self() {
        let token = SessionToken::generate().expect("generate");
        assert!(token.constant_time_eq(token.as_bytes()));
    }

    #[test]
    fn token_constant_time_eq_rejects_wrong_length() {
        let token = SessionToken::generate().expect("generate");
        assert!(!token.constant_time_eq(&[0u8; 4]));
    }

    #[test]
    fn session_authenticate_requires_both_id_and_token() {
        let session = Session::generate().expect("generate session");
        assert!(session.authenticate(session.id().as_str(), session.token().as_bytes()));
        assert!(!session.authenticate("wrong-id", session.token().as_bytes()));
        assert!(!session.authenticate(session.id().as_str(), &[0u8; TOKEN_BYTES]));
    }

    #[test]
    fn session_authenticate_hex_round_trips_through_credentials() {
        let session = Session::generate().expect("generate session");
        let creds = session.credentials();
        assert!(session.authenticate_hex(&creds.session_id, &creds.token_hex));
        assert!(!session.authenticate_hex(&creds.session_id, "not-hex!!"));
        assert!(!session.authenticate_hex("wrong-id", &creds.token_hex));
    }

    #[test]
    fn session_detects_duplicate_correlation_ids() {
        let session = Session::generate().expect("generate session");
        assert!(session.register_correlation_id("corr-1"));
        assert!(!session.register_correlation_id("corr-1"));
        assert!(session.is_known_correlation_id("corr-1"));
        assert!(!session.is_known_correlation_id("corr-2"));
    }

    #[test]
    fn duplicate_correlation_ids_are_shared_across_uses_of_the_same_session() {
        // A single `Session` is shared (via `Arc`) across every connection
        // in the real broker; this exercises the same underlying
        // dedup-by-session-not-by-connection behavior without needing a
        // live socket.
        let session = std::sync::Arc::new(Session::generate().expect("generate session"));
        let a = std::sync::Arc::clone(&session);
        let b = std::sync::Arc::clone(&session);
        assert!(a.register_correlation_id("corr-shared"));
        assert!(!b.register_correlation_id("corr-shared"));
    }

    #[test]
    fn debug_impl_does_not_print_token_bytes() {
        let token = SessionToken::generate().expect("generate");
        let debug = format!("{token:?}");
        assert_eq!(debug, "SessionToken(..)");
    }

    #[test]
    fn credentials_debug_impl_redacts_token() {
        let session = Session::generate().expect("generate session");
        let creds = session.credentials();
        let debug = format!("{creds:?}");
        assert!(!debug.contains(&creds.token_hex));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn hex_round_trips() {
        let token = SessionToken::generate().expect("generate");
        let hex = token.to_hex();
        let decoded = hex_decode(&hex).expect("decode");
        assert_eq!(decoded, token.as_bytes());
    }

    #[test]
    fn hex_decode_rejects_malformed_input() {
        assert!(hex_decode("xyz").is_none());
        assert!(hex_decode("abc").is_none()); // odd length
    }

    #[test]
    fn write_and_load_credentials_file_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.credentials");
        let session = Session::generate().expect("generate session");
        session
            .write_credentials_file(&path)
            .expect("write_credentials_file");

        let metadata = fs::symlink_metadata(&path).expect("stat");
        assert_eq!(metadata.permissions().mode() & 0o777, CREDENTIALS_FILE_MODE);

        let expected_uid = current_uid(&path);
        let loaded = load_credentials_file(&path, expected_uid).expect("load_credentials_file");
        assert_eq!(loaded.session_id, session.id().as_str());
        assert_eq!(loaded.token_hex, session.token().to_hex());
    }

    #[test]
    fn load_credentials_file_rejects_wrong_owner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.credentials");
        let session = Session::generate().expect("generate session");
        session
            .write_credentials_file(&path)
            .expect("write_credentials_file");

        let wrong_uid = current_uid(&path).wrapping_add(1);
        let err = load_credentials_file(&path, wrong_uid).expect_err("must reject wrong owner");
        assert!(matches!(err, SessionError::WrongOwner { .. }));
    }

    #[test]
    fn load_credentials_file_rejects_permissive_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.credentials");
        let session = Session::generate().expect("generate session");
        session
            .write_credentials_file(&path)
            .expect("write_credentials_file");

        let mut perms = fs::metadata(&path).expect("stat").permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).expect("chmod");

        let uid = current_uid(&path);
        let err = load_credentials_file(&path, uid).expect_err("must reject permissive mode");
        assert!(matches!(err, SessionError::WrongMode { .. }));
    }

    #[test]
    fn load_credentials_file_accepts_locked_read_only_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.credentials");
        let session = Session::generate().expect("generate session");
        session
            .write_credentials_file(&path)
            .expect("write_credentials_file");

        let uid = current_uid(&path);
        let mut perms = fs::metadata(&path).expect("stat").permissions();
        perms.set_mode(CREDENTIALS_FILE_MODE_LOCKED);
        fs::set_permissions(&path, perms).expect("chmod");

        load_credentials_file(&path, uid).expect("mode 0400 must be accepted as equally valid");
    }

    #[test]
    fn load_credentials_file_rejects_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real_path = dir.path().join("real.credentials");
        let session = Session::generate().expect("generate session");
        session
            .write_credentials_file(&real_path)
            .expect("write_credentials_file");

        let uid = current_uid(&real_path);
        let link_path = dir.path().join("link.credentials");
        std::os::unix::fs::symlink(&real_path, &link_path).expect("symlink");

        let err = load_credentials_file(&link_path, uid).expect_err("must reject symlink");
        assert!(matches!(err, SessionError::Symlink(_)));
    }

    #[test]
    fn write_credentials_file_refuses_to_overwrite_an_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.credentials");
        let first = Session::generate().expect("generate session");
        first
            .write_credentials_file(&path)
            .expect("first write must succeed");

        let second = Session::generate().expect("generate session");
        let err = second
            .write_credentials_file(&path)
            .expect_err("must refuse to clobber an existing credentials file");
        assert!(matches!(err, SessionError::Io { .. }));
    }

    /// A portable (works on macOS too) way to obtain the uid that owns a
    /// just-created file, without depending on the Linux-only `nix` crate
    /// from this cross-platform module.
    fn current_uid(existing_path: &Path) -> u32 {
        fs::metadata(existing_path).expect("stat").uid()
    }
}
