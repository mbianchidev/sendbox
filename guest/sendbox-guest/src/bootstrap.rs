use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, fstat, openat, renameat};
use sendbox_bootstrap::decode_bootstrap_document;
pub use sendbox_bootstrap::{
    BOOTSTRAP_SCHEMA_VERSION, BootstrapDocument as BootstrapMaterial, MAX_BOOTSTRAP_BYTES,
};
use sendbox_core::SessionId;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::GuestError;
use crate::manifest::encode_hex;
use crate::secure_fs::{
    leaf_name, open_directory_no_symlinks, read_bounded, unlink_relative, validate_regular_metadata,
};

pub struct ImmutableBootstrapSource {
    path: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
}

impl ImmutableBootstrapSource {
    #[must_use]
    pub fn new(path: PathBuf, expected_uid: u32, expected_gid: u32) -> Self {
        Self {
            path,
            expected_uid,
            expected_gid,
        }
    }

    pub fn consume(self, replay_root: &Path) -> Result<BootstrapMaterial, GuestError> {
        if !self.path.is_absolute() {
            return Err(GuestError::Bootstrap(
                "immutable bootstrap path must be absolute".to_owned(),
            ));
        }
        let (parent_path, name) = leaf_name(&self.path)?;
        let parent = open_directory_no_symlinks(parent_path)?;
        let consumed_name = format!(".{}.consumed", name.to_string_lossy());
        let descriptor = openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            if io::Error::from(error).kind() == io::ErrorKind::NotFound {
                GuestError::BootstrapConsumed
            } else {
                GuestError::io("opening immutable bootstrap", io::Error::from(error))
            }
        })?;
        let stat = fstat(&descriptor).map_err(|error| {
            GuestError::io("inspecting immutable bootstrap", io::Error::from(error))
        })?;
        validate_regular_metadata(
            &stat,
            0o400,
            self.expected_uid,
            self.expected_gid,
            true,
            "bootstrap file",
        )?;
        renameat(&parent, name, &parent, consumed_name.as_str()).map_err(|error| {
            GuestError::io("consuming immutable bootstrap", io::Error::from(error))
        })?;
        let mut consumed = ConsumedBootstrap {
            directory: parent,
            name: consumed_name.into(),
            removed: false,
        };

        let mut file = File::from(descriptor);
        let mut bytes = read_bounded(&mut file, MAX_BOOTSTRAP_BYTES)?;
        let material = decode_bootstrap_document(&bytes);
        bytes.zeroize();
        let material = material.map_err(|error| GuestError::Bootstrap(error.to_string()))?;
        register_replay(
            replay_root,
            &replay_key(material.session_id, &material.bootstrap_nonce),
            self.expected_uid,
            self.expected_gid,
        )?;
        consumed.remove()?;
        Ok(material)
    }
}

struct ConsumedBootstrap {
    directory: OwnedFd,
    name: OsString,
    removed: bool,
}

impl ConsumedBootstrap {
    fn remove(&mut self) -> Result<(), GuestError> {
        unlink_relative(&self.directory, &self.name, "removing consumed bootstrap")?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for ConsumedBootstrap {
    fn drop(&mut self) {
        if !self.removed {
            let _ = unlink_relative(
                &self.directory,
                &self.name,
                "removing failed bootstrap input",
            );
        }
    }
}

pub fn replay_key(session_id: SessionId, nonce: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sendbox guest bootstrap replay v2");
    hasher.update(session_id.as_bytes());
    hasher.update(nonce);
    encode_hex(&hasher.finalize())
}

pub fn register_replay(
    replay_root: &Path,
    key: &str,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), GuestError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let metadata = replay_root
        .symlink_metadata()
        .map_err(|error| GuestError::io("inspecting bootstrap replay ledger", error))?;
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(GuestError::Runtime(
            "bootstrap replay ledger ownership or mode is invalid".to_owned(),
        ));
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(replay_root.join(key))
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                GuestError::Bootstrap("replayed bootstrap material".to_owned())
            } else {
                GuestError::io("recording bootstrap replay key", error)
            }
        })?
        .sync_all()
        .map_err(|error| GuestError::io("syncing bootstrap replay key", error))?;
    File::open(replay_root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| GuestError::io("syncing bootstrap replay ledger", error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    use super::*;
    use crate::secure_fs::secure_tempdir;
    use rustix::process::{getgid, getuid};
    use sendbox_bootstrap::{BootstrapDocumentConfiguration, encode_bootstrap_document};
    use sendbox_core::BoundaryPlanDigest;

    fn identity() -> (u32, u32) {
        (getuid().as_raw(), getgid().as_raw())
    }

    fn write_bootstrap(path: &Path, secret: [u8; 32]) {
        let encoded = encode_bootstrap_document(
            BootstrapDocumentConfiguration {
                session_id: SessionId::from_bytes([1; 16]),
                boundary_plan_digest: BoundaryPlanDigest::from_bytes([2; 32]),
                host_version: "0.1.0".to_owned(),
                trust_root_id: "root-v1".to_owned(),
                manifest_path: PathBuf::from("manifest.json"),
                minimum_release_sequence: 1,
                required_controls: Vec::new(),
                required_services: Vec::new(),
                services: Vec::new(),
                execution_broker: None,
                egress_policy: None,
                registry_proxy: None,
            },
            &secret,
        )
        .expect("bootstrap JSON");
        fs::write(path, &encoded[..]).expect("write bootstrap");
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).expect("bootstrap mode");
    }

    fn create_replay_root(temporary: &tempfile::TempDir) -> PathBuf {
        let replay = temporary.path().join("replay");
        DirBuilder::new()
            .mode(0o700)
            .create(&replay)
            .expect("replay root");
        replay
    }

    #[test]
    fn immutable_bootstrap_is_consumed_once() {
        let temporary = secure_tempdir();
        let path = temporary.path().join("bootstrap.json");
        let replay = create_replay_root(&temporary);
        write_bootstrap(&path, [9; 32]);
        let (uid, gid) = identity();
        let material = ImmutableBootstrapSource::new(path.clone(), uid, gid)
            .consume(&replay)
            .expect("first consume");
        assert_eq!(material.session_id, SessionId::from_bytes([1; 16]));
        assert!(
            ImmutableBootstrapSource::new(path, uid, gid)
                .consume(&replay)
                .is_err()
        );
    }

    #[test]
    fn replay_ledger_rejects_duplicate_nonce() {
        let temporary = secure_tempdir();
        let root = temporary.path().join("replay");
        DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("runtime root");
        let (uid, gid) = identity();
        let key = replay_key(SessionId::from_bytes([3; 16]), &[4; 32]);
        register_replay(&root, &key, uid, gid).expect("first registration");
        assert!(register_replay(&root, &key, uid, gid).is_err());
    }

    #[test]
    fn wrong_mode_and_oversized_input_fail_closed() {
        let temporary = secure_tempdir();
        let path = temporary.path().join("bootstrap.json");
        let replay = create_replay_root(&temporary);
        write_bootstrap(&path, [9; 32]);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("wrong mode");
        let (uid, gid) = identity();
        assert!(
            ImmutableBootstrapSource::new(path.clone(), uid, gid)
                .consume(&replay)
                .is_err()
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("correct mode");
        assert!(
            ImmutableBootstrapSource::new(path.clone(), uid.saturating_add(1), gid)
                .consume(&replay)
                .is_err()
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("writable mode");
        fs::write(&path, vec![b'x'; MAX_BOOTSTRAP_BYTES + 1]).expect("oversized");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("mode");
        assert!(matches!(
            ImmutableBootstrapSource::new(path, uid, gid).consume(&replay),
            Err(GuestError::BootstrapTooLarge(MAX_BOOTSTRAP_BYTES))
        ));
        assert!(!temporary.path().join(".bootstrap.json.consumed").exists());
    }
}
