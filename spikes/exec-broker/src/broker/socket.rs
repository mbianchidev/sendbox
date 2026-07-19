//! The broker's Unix socket: bound at `0600` inside the private `0700`
//! runtime directory, with `SO_PEERCRED` validation of every accepted
//! connection's UID and an `lstat`-based check that the socket path itself
//! still looks like the genuine broker socket before a client connects to
//! it.

#![forbid(unsafe_code)]

use crate::broker::runtime_dir::RuntimeDir;
use crate::error::BrokerError;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};

/// Permission bits required on the socket file: owner-only read/write.
const SOCKET_MODE: u32 = 0o600;

/// The credentials of a connected peer, obtained via `SO_PEERCRED`
/// (kernel-verified, not spoofable by the peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

/// Binds a fresh Unix socket at `runtime_dir.socket_path()`, then chmods it
/// to `0600` explicitly (rather than relying on the process umask at bind
/// time to happen to produce that result).
pub fn bind(runtime_dir: &RuntimeDir) -> Result<UnixListener, BrokerError> {
    let socket_path = runtime_dir.socket_path();
    let listener = UnixListener::bind(&socket_path)?;

    let mut permissions = fs::metadata(&socket_path)?.permissions();
    permissions.set_mode(SOCKET_MODE);
    fs::set_permissions(&socket_path, permissions)?;

    Ok(listener)
}

/// Reads the connecting peer's credentials via `SO_PEERCRED` and returns an
/// error unless its UID equals `expected_uid`.
pub fn authenticate_peer(
    stream: &UnixStream,
    expected_uid: u32,
) -> Result<ClientCredentials, BrokerError> {
    let raw_credentials = getsockopt(stream, PeerCredentials)
        .map_err(|e| BrokerError::UnsafeRuntimeDir(format!("SO_PEERCRED failed: {e}")))?;
    let credentials = ClientCredentials {
        uid: raw_credentials.uid(),
        gid: raw_credentials.gid(),
        pid: raw_credentials.pid(),
    };
    if credentials.uid != expected_uid {
        return Err(BrokerError::UnsafeRuntimeDir(format!(
            "peer uid {} does not match expected uid {}",
            credentials.uid, expected_uid
        )));
    }
    Ok(credentials)
}

/// Validates, via `lstat` (never following a symlink), that `socket_path`
/// is actually a Unix domain socket, owned by `expected_uid`, with exactly
/// `0600` permissions — a client-side (or defense-in-depth broker-side)
/// check that the well-known path has not been swapped for something else
/// (a symlink, a regular file, a different socket owned by another user)
/// between when it was expected to exist and when it is used.
///
/// This narrows, but as with every path-based check in this crate, cannot
/// fully eliminate every TOCTOU race against the moment `connect(2)` itself
/// resolves the path: see [`crate::error::BrokerError::ResidualToctou`].
pub fn validate_socket_path_for_connect(
    socket_path: &Path,
    expected_uid: u32,
) -> Result<(), BrokerError> {
    let metadata = fs::symlink_metadata(socket_path)?;
    if metadata.file_type().is_symlink() {
        return Err(BrokerError::UnsafeRuntimeDir(format!(
            "{} is a symlink, not a socket",
            socket_path.display()
        )));
    }
    if !is_socket(&metadata) {
        return Err(BrokerError::UnsafeRuntimeDir(format!(
            "{} is not a Unix domain socket",
            socket_path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(BrokerError::UnsafeRuntimeDir(format!(
            "{} is owned by uid {}, expected {}",
            socket_path.display(),
            metadata.uid(),
            expected_uid
        )));
    }
    if metadata.permissions().mode() & 0o777 != SOCKET_MODE {
        return Err(BrokerError::UnsafeRuntimeDir(format!(
            "{} has mode {:o}, expected {:o}",
            socket_path.display(),
            metadata.permissions().mode() & 0o777,
            SOCKET_MODE
        )));
    }
    Ok(())
}

fn is_socket(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_socket()
}

/// Connects to `socket_path` as a client, after first performing
/// [`validate_socket_path_for_connect`].
pub fn connect(socket_path: &Path, expected_uid: u32) -> Result<StdUnixStream, BrokerError> {
    validate_socket_path_for_connect(socket_path, expected_uid)?;
    Ok(StdUnixStream::connect(socket_path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[tokio::test]
    async fn accepted_connection_reports_own_process_uid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = RuntimeDir::create_fresh(dir.path().join("runtime")).expect("runtime dir");
        let listener = bind(&runtime).expect("bind");
        let socket_path = runtime.socket_path();

        let client_task = {
            let socket_path = socket_path.clone();
            tokio::spawn(async move { UnixStream::connect(&socket_path).await })
        };

        let (server_stream, _addr) = listener.accept().await.expect("accept");
        let _client_stream = client_task.await.expect("join").expect("connect");

        let expected_uid = nix::unistd::getuid().as_raw();
        let credentials =
            authenticate_peer(&server_stream, expected_uid).expect("authenticate_peer");
        assert_eq!(credentials.uid, expected_uid);
    }

    #[tokio::test]
    async fn authenticate_peer_rejects_unexpected_uid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = RuntimeDir::create_fresh(dir.path().join("runtime")).expect("runtime dir");
        let listener = bind(&runtime).expect("bind");
        let socket_path = runtime.socket_path();

        let client_task = {
            let socket_path = socket_path.clone();
            tokio::spawn(async move { UnixStream::connect(&socket_path).await })
        };
        let (server_stream, _addr) = listener.accept().await.expect("accept");
        let _client_stream = client_task.await.expect("join").expect("connect");

        let wrong_uid = nix::unistd::getuid().as_raw().wrapping_add(1);
        let err = authenticate_peer(&server_stream, wrong_uid).expect_err("must reject");
        assert!(matches!(err, BrokerError::UnsafeRuntimeDir(_)));
    }

    #[tokio::test]
    async fn socket_is_created_with_expected_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = RuntimeDir::create_fresh(dir.path().join("runtime")).expect("runtime dir");
        let _listener = bind(&runtime).expect("bind");
        let metadata = fs::symlink_metadata(runtime.socket_path()).expect("stat socket");
        assert_eq!(metadata.permissions().mode() & 0o777, SOCKET_MODE);
        assert!(is_socket(&metadata));
    }

    #[tokio::test]
    async fn validate_socket_path_rejects_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = RuntimeDir::create_fresh(dir.path().join("runtime")).expect("runtime dir");
        let _listener = bind(&runtime).expect("bind");
        let link_path = dir.path().join("link-to-socket");
        symlink(runtime.socket_path(), &link_path).expect("symlink");
        let err = validate_socket_path_for_connect(&link_path, nix::unistd::getuid().as_raw())
            .expect_err("must reject symlink");
        assert!(matches!(err, BrokerError::UnsafeRuntimeDir(_)));
    }

    #[test]
    fn validate_socket_path_rejects_regular_file_at_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake_socket = dir.path().join("not-a-socket");
        fs::write(&fake_socket, b"not a socket").expect("write");
        let mut perms = fs::metadata(&fake_socket).expect("stat").permissions();
        perms.set_mode(SOCKET_MODE);
        fs::set_permissions(&fake_socket, perms).expect("chmod");
        let err = validate_socket_path_for_connect(&fake_socket, nix::unistd::getuid().as_raw())
            .expect_err("must reject regular file");
        assert!(matches!(err, BrokerError::UnsafeRuntimeDir(_)));
    }
}
