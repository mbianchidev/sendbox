use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::sync::Mutex;

use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt as _, MetadataExt as _, OpenOptions, OpenOptionsExt as _,
};
use fs2::FileExt as _;
use rustix::process::geteuid;

use crate::record::{decode_for_name, encode_record};
use crate::types::unix_time_ms;
use crate::{
    MAX_SECRET_VALUE_BYTES, RecordVersion, Secret, SecretMetadata, SecretName, SecretStore,
    SecretStoreError, SecretValue,
};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const LOCK_NAME: &str = ".store.lock";
const MAX_RECORD_BYTES: u64 = (MAX_SECRET_VALUE_BYTES + 2048) as u64;

pub struct LinuxFileStore {
    directory: Dir,
    owner_uid: u32,
    in_process_lock: Mutex<()>,
}

impl LinuxFileStore {
    pub fn open(root: &Path, service: &str) -> Result<Self, SecretStoreError> {
        let root = open_ambient_directory(root)?;
        validate_directory(&root, DIRECTORY_MODE, "secret root")?;
        Self::open_under(root, service)
    }

    pub fn open_default(service: &str) -> Result<Self, SecretStoreError> {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| SecretStoreError::InsecureStore("HOME is not configured".to_owned()))?;
        let home = open_ambient_directory(Path::new(&home))?;
        validate_anchor_directory(&home, "home directory")?;
        let sendbox = open_or_create_directory(&home, ".sendbox")?;
        let secrets = open_or_create_directory(&sendbox, "secrets")?;
        Self::open_under(secrets, service)
    }

    fn open_under(parent: Dir, service: &str) -> Result<Self, SecretStoreError> {
        if service.is_empty() || service.len() > 128 || service.chars().any(char::is_control) {
            return Err(SecretStoreError::InvalidName(
                "service name is invalid".to_owned(),
            ));
        }
        let directory = open_or_create_directory(&parent, &encode_filename(service.as_bytes()))?;
        let store = Self {
            directory,
            owner_uid: geteuid().as_raw(),
            in_process_lock: Mutex::new(()),
        };
        store.with_store_lock(|_| Ok(()))?;
        Ok(store)
    }

    fn with_store_lock<T>(
        &self,
        operation: impl FnOnce(&Self) -> Result<T, SecretStoreError>,
    ) -> Result<T, SecretStoreError> {
        let _thread_guard = self
            .in_process_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        validate_directory(&self.directory, DIRECTORY_MODE, "service directory")?;
        let lock = open_lock_file(&self.directory)?;
        validate_std_file_metadata(
            &lock
                .metadata()
                .map_err(|error| SecretStoreError::io("read lock metadata", error))?,
            self.owner_uid,
            LOCK_NAME,
        )?;
        lock.lock_exclusive()
            .map_err(|error| SecretStoreError::io("lock secret store", error))?;
        operation(self)
    }

    fn read_unlocked(&self, name: &SecretName) -> Result<Secret, SecretStoreError> {
        let filename = encode_filename(name.as_str().as_bytes());
        let mut file = open_existing_file(&self.directory, &filename, self.owner_uid, name)?;
        let metadata = file
            .metadata()
            .map_err(|error| SecretStoreError::io("read secret metadata", error))?;
        if metadata.len() > MAX_RECORD_BYTES {
            return Err(SecretStoreError::Corrupt(
                "persisted record exceeds maximum size".to_owned(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| SecretStoreError::io("read secret", error))?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(SecretStoreError::Corrupt(
                "persisted record exceeds maximum size".to_owned(),
            ));
        }
        let timestamp = metadata_time_ms(&metadata);
        decode_for_name(name, &bytes, timestamp, timestamp)
    }

    fn write_unlocked(
        &self,
        name: &SecretName,
        secret: &Secret,
        existing_required: Option<bool>,
    ) -> Result<(), SecretStoreError> {
        let filename = encode_filename(name.as_str().as_bytes());
        let existing = inspect_entry(&self.directory, &filename)?;
        match (existing_required, existing) {
            (Some(true), None) => return Err(SecretStoreError::NotFound(name.clone())),
            (Some(false), Some(_)) => return Err(SecretStoreError::AlreadyExists(name.clone())),
            (_, Some(metadata)) => {
                validate_metadata(&metadata, self.owner_uid, &filename)?;
            }
            (_, None) => {}
        }

        let encoded = encode_record(secret)?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|error| SecretStoreError::Corrupt(error.to_string()))?;
        let temporary = format!(".tmp-{}", encode_filename(&random));
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = self
            .directory
            .open_with(&temporary, &options)
            .map_err(|error| SecretStoreError::io("create temporary secret", error))?;
        let write_result = (|| {
            file.write_all(&encoded)
                .map_err(|error| SecretStoreError::io("write temporary secret", error))?;
            file.sync_all()
                .map_err(|error| SecretStoreError::io("sync temporary secret", error))?;
            validate_file_metadata(
                &file
                    .metadata()
                    .map_err(|error| SecretStoreError::io("validate temporary secret", error))?,
                self.owner_uid,
                &temporary,
            )?;
            self.directory
                .rename(&temporary, &self.directory, &filename)
                .map_err(|error| SecretStoreError::io("replace secret atomically", error))?;
            sync_directory(&self.directory)
        })();
        if write_result.is_err() {
            let _ = self.directory.remove_file(&temporary);
        }
        write_result
    }
}

impl SecretStore for LinuxFileStore {
    fn store(
        &self,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError> {
        self.with_store_lock(|store| {
            let now = unix_time_ms();
            let secret = Secret {
                metadata: SecretMetadata {
                    name: name.clone(),
                    created_at_unix_ms: now,
                    updated_at_unix_ms: now,
                    version: RecordVersion::V1,
                },
                value,
            };
            store.write_unlocked(name, &secret, Some(false))?;
            Ok(secret.metadata)
        })
    }

    fn update(
        &self,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError> {
        self.with_store_lock(|store| {
            let previous = store.read_unlocked(name)?;
            let secret = Secret {
                metadata: SecretMetadata {
                    name: name.clone(),
                    created_at_unix_ms: previous.metadata.created_at_unix_ms,
                    updated_at_unix_ms: unix_time_ms(),
                    version: RecordVersion::V1,
                },
                value,
            };
            store.write_unlocked(name, &secret, Some(true))?;
            Ok(secret.metadata)
        })
    }

    fn retrieve(&self, name: &SecretName) -> Result<Secret, SecretStoreError> {
        self.with_store_lock(|store| store.read_unlocked(name))
    }

    fn delete(&self, name: &SecretName) -> Result<(), SecretStoreError> {
        self.with_store_lock(|store| {
            let filename = encode_filename(name.as_str().as_bytes());
            let metadata = inspect_entry(&store.directory, &filename)?
                .ok_or_else(|| SecretStoreError::NotFound(name.clone()))?;
            validate_metadata(&metadata, store.owner_uid, &filename)?;
            store
                .directory
                .remove_file(&filename)
                .map_err(|error| SecretStoreError::io("delete secret", error))?;
            sync_directory(&store.directory)
        })
    }

    fn list(&self) -> Result<Vec<SecretMetadata>, SecretStoreError> {
        self.with_store_lock(|store| {
            let entries = store
                .directory
                .entries()
                .map_err(|error| SecretStoreError::io("list secrets", error))?;
            let mut metadata = Vec::new();
            for entry in entries {
                let entry =
                    entry.map_err(|error| SecretStoreError::io("read secret entry", error))?;
                let filename = entry.file_name();
                let filename = filename.to_str().ok_or_else(|| {
                    SecretStoreError::Corrupt("secret filename is not UTF-8".to_owned())
                })?;
                if filename == LOCK_NAME || filename.starts_with(".tmp-") {
                    continue;
                }
                let decoded = decode_filename(filename)?;
                let name = SecretName::new(decoded)?;
                metadata.push(store.read_unlocked(&name)?.metadata);
            }
            metadata.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(metadata)
        })
    }

    fn exists(&self, name: &SecretName) -> Result<bool, SecretStoreError> {
        self.with_store_lock(|store| {
            let filename = encode_filename(name.as_str().as_bytes());
            match inspect_entry(&store.directory, &filename)? {
                Some(metadata) => {
                    validate_metadata(&metadata, store.owner_uid, &filename)?;
                    Ok(true)
                }
                None => Ok(false),
            }
        })
    }

    fn migrate(&self, name: &SecretName) -> Result<SecretMetadata, SecretStoreError> {
        self.with_store_lock(|store| {
            let mut secret = store.read_unlocked(name)?;
            if secret.metadata.version == RecordVersion::V1 {
                return Ok(secret.metadata);
            }
            secret.metadata.version = RecordVersion::V1;
            store.write_unlocked(name, &secret, Some(true))?;
            Ok(secret.metadata)
        })
    }
}

fn open_ambient_directory(path: &Path) -> Result<Dir, SecretStoreError> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|error| SecretStoreError::io("open secure directory", error))?;
    Ok(Dir::from_std_file(file))
}

fn open_or_create_directory(parent: &Dir, name: &str) -> Result<Dir, SecretStoreError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) => validate_directory_metadata(&metadata, geteuid().as_raw(), name)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(DIRECTORY_MODE);
            if let Err(error) = parent.create_dir_with(name, &builder)
                && error.kind() != io::ErrorKind::AlreadyExists
            {
                return Err(SecretStoreError::io("create secure directory", error));
            }
        }
        Err(error) => return Err(SecretStoreError::io("inspect secure directory", error)),
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let file = parent
        .open_with(name, &options)
        .map_err(|error| SecretStoreError::io("open secure child directory", error))?;
    let directory = Dir::from_std_file(file.into_std());
    validate_directory(&directory, DIRECTORY_MODE, name)?;
    Ok(directory)
}

fn open_lock_file(directory: &Dir) -> Result<fs::File, SecretStoreError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    directory
        .open_with(LOCK_NAME, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|error| SecretStoreError::io("open secret store lock", error))
}

fn open_existing_file(
    directory: &Dir,
    filename: &str,
    owner_uid: u32,
    name: &SecretName,
) -> Result<cap_std::fs::File, SecretStoreError> {
    let metadata = inspect_entry(directory, filename)?
        .ok_or_else(|| SecretStoreError::NotFound(name.clone()))?;
    validate_metadata(&metadata, owner_uid, filename)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = directory.open_with(filename, &options).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            SecretStoreError::NotFound(name.clone())
        } else {
            SecretStoreError::io("open secret", error)
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| SecretStoreError::io("validate secret", error))?;
    validate_file_metadata(&metadata, owner_uid, filename)?;
    Ok(file)
}

fn inspect_entry(
    directory: &Dir,
    filename: &str,
) -> Result<Option<cap_std::fs::Metadata>, SecretStoreError> {
    match directory.symlink_metadata(filename) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SecretStoreError::io("inspect secret", error)),
    }
}

fn validate_anchor_directory(directory: &Dir, label: &str) -> Result<(), SecretStoreError> {
    let metadata = directory
        .try_clone()
        .and_then(|clone| clone.into_std_file().metadata())
        .map_err(|error| SecretStoreError::io("validate directory", error))?;
    if !metadata.is_dir() || metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
        return Err(SecretStoreError::InsecureStore(format!(
            "{label} must be an owner-controlled directory without group/world write access"
        )));
    }
    Ok(())
}

fn validate_directory(
    directory: &Dir,
    expected_mode: u32,
    label: &str,
) -> Result<(), SecretStoreError> {
    let metadata = directory
        .try_clone()
        .and_then(|clone| clone.into_std_file().metadata())
        .map_err(|error| SecretStoreError::io("validate directory", error))?;
    if !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != expected_mode
    {
        return Err(SecretStoreError::InsecureStore(format!(
            "{label} must be owned by the effective user with mode {expected_mode:o}"
        )));
    }
    Ok(())
}

fn validate_file_metadata(
    metadata: &cap_std::fs::Metadata,
    owner_uid: u32,
    label: &str,
) -> Result<(), SecretStoreError> {
    validate_metadata(metadata, owner_uid, label)
}

fn validate_directory_metadata(
    metadata: &cap_std::fs::Metadata,
    owner_uid: u32,
    label: &str,
) -> Result<(), SecretStoreError> {
    if !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != DIRECTORY_MODE
    {
        return Err(SecretStoreError::InsecureStore(format!(
            "{label} must be a directory owned by the effective user with mode {DIRECTORY_MODE:o}"
        )));
    }
    Ok(())
}

fn validate_std_file_metadata(
    metadata: &fs::Metadata,
    owner_uid: u32,
    label: &str,
) -> Result<(), SecretStoreError> {
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(SecretStoreError::InsecureStore(format!(
            "{label} must be a regular file owned by the effective user with mode {FILE_MODE:o}"
        )));
    }
    Ok(())
}

fn validate_metadata(
    metadata: &cap_std::fs::Metadata,
    owner_uid: u32,
    label: &str,
) -> Result<(), SecretStoreError> {
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(SecretStoreError::InsecureStore(format!(
            "{label} must be a regular file owned by the effective user with mode {FILE_MODE:o}"
        )));
    }
    Ok(())
}

fn sync_directory(directory: &Dir) -> Result<(), SecretStoreError> {
    directory
        .try_clone()
        .and_then(|clone| clone.into_std_file().sync_all())
        .map_err(|error| SecretStoreError::io("sync secret directory", error))
}

fn metadata_time_ms(metadata: &cap_std::fs::Metadata) -> u64 {
    let seconds = metadata.mtime().max(0) as u64;
    let nanoseconds = metadata.mtime_nsec().max(0) as u64;
    seconds
        .saturating_mul(1000)
        .saturating_add(nanoseconds / 1_000_000)
}

fn encode_filename(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_filename(filename: &str) -> Result<String, SecretStoreError> {
    if filename.is_empty() || !filename.len().is_multiple_of(2) {
        return Err(SecretStoreError::Corrupt(
            "secret filename has invalid hex length".to_owned(),
        ));
    }
    let bytes = filename
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let text = std::str::from_utf8(chunk)
                .map_err(|_| SecretStoreError::Corrupt("filename is not hex".to_owned()))?;
            u8::from_str_radix(text, 16)
                .map_err(|_| SecretStoreError::Corrupt("filename is not hex".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes)
        .map_err(|_| SecretStoreError::Corrupt("filename is not valid UTF-8".to_owned()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::thread;

    use serde::Deserialize;
    use tempfile::TempDir;

    use super::*;

    fn root() -> TempDir {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("permissions");
        root
    }

    fn store(root: &TempDir) -> LinuxFileStore {
        LinuxFileStore::open(root.path(), "com.sendbox.secrets").expect("store")
    }

    #[test]
    fn round_trip_update_list_delete_and_unicode() {
        let root = root();
        let store = store(&root);
        let name = SecretName::new("TOKEN_日本語").expect("name");
        let created = store
            .store(&name, SecretValue::try_from("first").expect("value"))
            .expect("store");
        assert!(store.exists(&name).expect("exists"));
        assert_eq!(
            store
                .retrieve(&name)
                .expect("retrieve")
                .value
                .expose_secret(),
            b"first"
        );
        let updated = store
            .update(&name, SecretValue::try_from("second").expect("value"))
            .expect("update");
        assert_eq!(created.created_at_unix_ms, updated.created_at_unix_ms);
        assert_eq!(store.list().expect("list"), vec![updated]);
        store.delete(&name).expect("delete");
        assert!(!store.exists(&name).expect("exists"));
        assert!(matches!(
            store.retrieve(&name),
            Err(SecretStoreError::NotFound(_))
        ));
    }

    #[test]
    fn reads_and_explicitly_migrates_swift_linux_fixture() {
        #[derive(Deserialize)]
        struct Fixture {
            service: String,
            encoded_service: String,
            name: String,
            encoded_name: String,
            value_utf8: String,
        }
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../test-fixtures/secrets/swift-linux-v0.json"
        ))
        .expect("fixture");
        let root = root();
        let store = LinuxFileStore::open(root.path(), &fixture.service).expect("store");
        let name = SecretName::new(&fixture.name).expect("name");
        assert_eq!(
            encode_filename(fixture.service.as_bytes()),
            fixture.encoded_service
        );
        assert_eq!(
            encode_filename(name.as_str().as_bytes()),
            fixture.encoded_name
        );
        let service_dir = root.path().join(&fixture.encoded_service);
        let path = service_dir.join(encode_filename(name.as_str().as_bytes()));
        fs::write(&path, fixture.value_utf8.as_bytes()).expect("fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE)).expect("mode");

        let legacy = store.retrieve(&name).expect("legacy");
        assert_eq!(legacy.metadata.version, RecordVersion::SwiftLegacy);
        assert_eq!(legacy.value.expose_secret(), b"swift-legacy-value");
        let migrated = store.migrate(&name).expect("migrate");
        assert_eq!(migrated.version, RecordVersion::V1);
        assert_eq!(
            store
                .retrieve(&name)
                .expect("migrated")
                .value
                .expose_secret(),
            b"swift-legacy-value"
        );
    }

    #[test]
    fn rejects_symlinks_and_insecure_modes_without_repairing_them() {
        let root = root();
        let service_dir = root.path().join(encode_filename(b"com.sendbox.secrets"));
        fs::create_dir(&service_dir).expect("service");
        fs::set_permissions(&service_dir, fs::Permissions::from_mode(0o755)).expect("mode");
        assert!(matches!(
            LinuxFileStore::open(root.path(), "com.sendbox.secrets"),
            Err(SecretStoreError::InsecureStore(_))
        ));
        assert_eq!(
            fs::metadata(&service_dir)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        fs::remove_dir(&service_dir).expect("remove");
        let target = root.path().join("target");
        fs::create_dir(&target).expect("target");
        symlink(&target, &service_dir).expect("symlink");
        assert!(LinuxFileStore::open(root.path(), "com.sendbox.secrets").is_err());
    }

    #[test]
    fn concurrent_updates_never_corrupt_records() {
        let root = root();
        let store = store(&root);
        let name = SecretName::new("TOKEN").expect("name");
        store
            .store(&name, SecretValue::try_from("initial").expect("value"))
            .expect("store");
        let handles = (0..16)
            .map(|index| {
                let root = root.path().to_path_buf();
                let name = name.clone();
                thread::spawn(move || {
                    let store = LinuxFileStore::open(&root, "com.sendbox.secrets").expect("store");
                    store
                        .update(
                            &name,
                            SecretValue::new(format!("value-{index}").into_bytes()).expect("value"),
                        )
                        .expect("update");
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("thread");
        }
        let value = store.retrieve(&name).expect("retrieve");
        assert!(
            std::str::from_utf8(value.value.expose_secret())
                .expect("UTF-8")
                .starts_with("value-")
        );
    }

    #[test]
    fn partial_temporary_writes_are_ignored() {
        let root = root();
        let store = store(&root);
        let service_dir = root.path().join(encode_filename(b"com.sendbox.secrets"));
        let partial = service_dir.join(".tmp-interrupted");
        fs::write(&partial, b"partial").expect("partial");
        fs::set_permissions(&partial, fs::Permissions::from_mode(FILE_MODE)).expect("mode");
        assert!(store.list().expect("list").is_empty());
    }

    #[test]
    fn rejects_corrupt_records_secret_symlinks_and_oversized_values() {
        let root = root();
        let store = store(&root);
        let name = SecretName::new("TOKEN").expect("name");
        let service_dir = root.path().join(encode_filename(b"com.sendbox.secrets"));
        let path = service_dir.join(encode_filename(name.as_str().as_bytes()));
        fs::write(&path, b"\xffSBXSECRET\x01\x81").expect("corrupt");
        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE)).expect("mode");
        assert!(matches!(
            store.retrieve(&name),
            Err(SecretStoreError::Corrupt(_))
        ));

        fs::remove_file(&path).expect("remove");
        let target = service_dir.join("target");
        fs::write(&target, b"value").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(FILE_MODE)).expect("mode");
        symlink(&target, &path).expect("symlink");
        assert!(matches!(
            store.retrieve(&name),
            Err(SecretStoreError::InsecureStore(_))
        ));

        assert!(matches!(
            SecretValue::new(vec![0_u8; MAX_SECRET_VALUE_BYTES + 1]),
            Err(SecretStoreError::ValueTooLarge { .. })
        ));
    }
}
