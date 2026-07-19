use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, fstat, openat, renameat};
use sendbox_core::SessionId;
use sendbox_protocol::BootstrapSecret;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::GuestError;
use crate::manifest::encode_hex;
use crate::platform::ControlKind;
use crate::secure_fs::{
    leaf_name, open_directory_no_symlinks, read_bounded, unlink_relative, validate_regular_metadata,
};
use crate::service::{ServiceId, ServiceSpec};

pub const BOOTSTRAP_SCHEMA_VERSION: u32 = 1;
pub const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;

pub struct BootstrapMaterial {
    pub session_id: SessionId,
    pub bootstrap_nonce: [u8; 32],
    pub bootstrap_secret: BootstrapSecret,
    pub host_version: String,
    pub trust_root_id: String,
    pub manifest_path: PathBuf,
    pub minimum_release_sequence: u64,
    pub required_controls: Vec<ControlKind>,
    pub required_services: Vec<ServiceId>,
    pub services: Vec<ServiceSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapWire {
    schema_version: u32,
    session_id: SessionId,
    bootstrap_nonce: [u8; 32],
    bootstrap_secret: SecretBytes,
    host_version: String,
    trust_root_id: String,
    manifest_path: PathBuf,
    minimum_release_sequence: u64,
    #[serde(default)]
    required_controls: Vec<ControlKind>,
    #[serde(default)]
    required_services: Vec<ServiceId>,
    #[serde(default)]
    services: Vec<ServiceSpec>,
}

struct SecretBytes(Zeroizing<[u8; 32]>);

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretVisitor;

        impl<'de> Visitor<'de> for SecretVisitor {
            type Value = SecretBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 32 bootstrap-secret bytes")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Zeroizing::new([0_u8; 32]);
                for index in 0..32 {
                    bytes[index] = sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                if sequence.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(33, &self));
                }
                Ok(SecretBytes(bytes))
            }
        }

        deserializer.deserialize_seq(SecretVisitor)
    }
}

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
        let wire: BootstrapWire = serde_json::from_slice(&bytes)
            .map_err(|error| GuestError::Bootstrap(error.to_string()))?;
        bytes.zeroize();
        let material = validate_wire(wire)?;
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

fn validate_wire(wire: BootstrapWire) -> Result<BootstrapMaterial, GuestError> {
    if wire.schema_version != BOOTSTRAP_SCHEMA_VERSION {
        return Err(GuestError::Bootstrap(format!(
            "unsupported schema version {}",
            wire.schema_version
        )));
    }
    if wire.bootstrap_nonce.iter().all(|byte| *byte == 0) {
        return Err(GuestError::Bootstrap(
            "bootstrap nonce must not be all zero".to_owned(),
        ));
    }
    if wire.host_version.is_empty()
        || wire.host_version.len() > 128
        || wire.trust_root_id.is_empty()
        || wire.trust_root_id.len() > 128
    {
        return Err(GuestError::Bootstrap(
            "host version and trust-root ID must be 1-128 bytes".to_owned(),
        ));
    }
    let secret = BootstrapSecret::new(wire.bootstrap_secret.0.as_ref().to_vec())?;
    Ok(BootstrapMaterial {
        session_id: wire.session_id,
        bootstrap_nonce: wire.bootstrap_nonce,
        bootstrap_secret: secret,
        host_version: wire.host_version,
        trust_root_id: wire.trust_root_id,
        manifest_path: wire.manifest_path,
        minimum_release_sequence: wire.minimum_release_sequence,
        required_controls: wire.required_controls,
        required_services: wire.required_services,
        services: wire.services,
    })
}

pub fn replay_key(session_id: SessionId, nonce: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sendbox guest bootstrap replay v1");
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
    use serde_json::json;

    fn identity() -> (u32, u32) {
        (getuid().as_raw(), getgid().as_raw())
    }

    fn write_bootstrap(path: &Path, secret: [u8; 32]) {
        fs::write(
            path,
            serde_json::to_vec(&json!({
                "schema_version": BOOTSTRAP_SCHEMA_VERSION,
                "session_id": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                "bootstrap_nonce": [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
                "bootstrap_secret": secret,
                "host_version": "0.1.0",
                "trust_root_id": "root-v1",
                "manifest_path": "manifest.json",
                "minimum_release_sequence": 1,
                "required_controls": [],
                "required_services": [],
                "services": []
            }))
            .expect("bootstrap JSON"),
        )
        .expect("write bootstrap");
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
