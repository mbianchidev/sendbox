use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sendbox_core::SessionId;
use serde::Serialize;

use crate::GuestError;
use crate::audit::AuditEvent;
use crate::platform::ControlStatus;
use crate::service::ServiceHealth;
use crate::state::StartupState;

#[derive(Debug, Clone, Copy)]
pub struct RuntimeIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl RuntimeIdentity {
    #[must_use]
    pub const fn root() -> Self {
        Self { uid: 0, gid: 0 }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessSnapshot {
    pub session_id: SessionId,
    pub state: StartupState,
    pub release_sequence: u64,
    pub controls: Vec<ControlStatus>,
    pub services: Vec<ServiceHealth>,
    pub audit_events: Vec<AuditEvent>,
}

pub struct RuntimeSession {
    root: PathBuf,
    session_dir: PathBuf,
    state_path: PathBuf,
    readiness_path: PathBuf,
    socket_path: PathBuf,
}

impl Drop for RuntimeSession {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl RuntimeSession {
    pub fn prepare(
        root: &Path,
        session_id: SessionId,
        identity: RuntimeIdentity,
    ) -> Result<Self, GuestError> {
        prepare_root(root, identity)?;
        let session_dir = root.join(session_id.to_string());
        DirBuilder::new()
            .mode(0o700)
            .create(&session_dir)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    GuestError::Runtime(format!(
                        "stale session state exists at {}",
                        session_dir.display()
                    ))
                } else {
                    GuestError::io("creating session runtime directory", error)
                }
            })?;
        validate_directory(&session_dir, 0o700, identity)?;
        Ok(Self {
            root: root.to_path_buf(),
            state_path: session_dir.join("state.json"),
            readiness_path: session_dir.join("ready.json"),
            socket_path: session_dir.join("control.sock"),
            session_dir,
        })
    }

    #[must_use]
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn readiness_path(&self) -> &Path {
        &self.readiness_path
    }

    pub fn write_state(&self, state: StartupState) -> Result<(), GuestError> {
        atomic_json(&self.state_path, &state)
    }

    pub fn publish_readiness(&self, readiness: &ReadinessSnapshot) -> Result<(), GuestError> {
        if readiness.state != StartupState::Ready {
            return Err(GuestError::Runtime(
                "readiness marker can only describe the ready state".to_owned(),
            ));
        }
        atomic_json(&self.readiness_path, readiness)
    }

    pub fn revoke_readiness(&self) -> Result<(), GuestError> {
        match fs::remove_file(&self.readiness_path) {
            Ok(()) => sync_directory(&self.session_dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(GuestError::io("revoking readiness marker", error)),
        }
    }

    pub fn cleanup(&self) -> Result<(), GuestError> {
        self.revoke_readiness()?;
        match fs::remove_dir_all(&self.session_dir) {
            Ok(()) => sync_directory(&self.root),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(GuestError::io("cleaning session runtime directory", error)),
        }
    }
}

fn prepare_root(root: &Path, identity: RuntimeIdentity) -> Result<(), GuestError> {
    if !root.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(root)
            .map_err(|error| GuestError::io("creating runtime root", error))?;
    }
    validate_directory(root, 0o700, identity)
}

fn validate_directory(
    path: &Path,
    expected_mode: u32,
    identity: RuntimeIdentity,
) -> Result<(), GuestError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| GuestError::io("inspecting runtime directory", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GuestError::Runtime(format!(
            "{} is not a real directory",
            path.display()
        )));
    }
    let actual_mode = metadata.mode() & 0o7777;
    if actual_mode != expected_mode
        || metadata.uid() != identity.uid
        || metadata.gid() != identity.gid
    {
        return Err(GuestError::Runtime(format!(
            "{} has mode/owner {actual_mode:#o} {}:{}, expected {expected_mode:#o} {}:{}",
            path.display(),
            metadata.uid(),
            metadata.gid(),
            identity.uid,
            identity.gid
        )));
    }
    Ok(())
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<(), GuestError> {
    let parent = path
        .parent()
        .ok_or_else(|| GuestError::Runtime("state path has no parent".to_owned()))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        std::process::id()
    ));
    let bytes = serde_json::to_vec(value)
        .map_err(|error| GuestError::Runtime(format!("serializing runtime state: {error}")))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|error| GuestError::io("creating atomic runtime state", error))?;
    file.write_all(&bytes)
        .map_err(|error| GuestError::io("writing atomic runtime state", error))?;
    file.sync_all()
        .map_err(|error| GuestError::io("syncing atomic runtime state", error))?;
    fs::rename(&temp, path).map_err(|error| GuestError::io("publishing runtime state", error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| GuestError::io("setting runtime state mode", error))?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<(), GuestError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| GuestError::io("syncing runtime directory", error))
}

#[cfg(test)]
mod tests {
    use rustix::process::{getgid, getuid};
    use tempfile::tempdir;

    use super::*;

    fn identity() -> RuntimeIdentity {
        RuntimeIdentity {
            uid: getuid().as_raw(),
            gid: getgid().as_raw(),
        }
    }

    #[test]
    fn stale_session_is_rejected_and_cleanup_is_idempotent() {
        let temporary = tempdir().expect("temporary directory");
        let root = temporary.path().join("run");
        let session_id = SessionId::from_bytes([7; 16]);
        let runtime = RuntimeSession::prepare(&root, session_id, identity()).expect("runtime");
        assert!(RuntimeSession::prepare(&root, session_id, identity()).is_err());
        runtime.cleanup().expect("cleanup");
        runtime.cleanup().expect("idempotent cleanup");
        assert!(!runtime.session_dir().exists());
    }

    #[test]
    fn readiness_requires_ready_state_and_is_revocable() {
        let temporary = tempdir().expect("temporary directory");
        let root = temporary.path().join("run");
        let session_id = SessionId::from_bytes([8; 16]);
        let runtime = RuntimeSession::prepare(&root, session_id, identity()).expect("runtime");
        let mut snapshot = ReadinessSnapshot {
            session_id,
            state: StartupState::SelfTesting,
            release_sequence: 1,
            controls: Vec::new(),
            services: Vec::new(),
            audit_events: Vec::new(),
        };
        assert!(runtime.publish_readiness(&snapshot).is_err());
        snapshot.state = StartupState::Ready;
        runtime.publish_readiness(&snapshot).expect("readiness");
        assert!(runtime.readiness_path().exists());
        runtime.revoke_readiness().expect("revoke");
        assert!(!runtime.readiness_path().exists());
    }
}
