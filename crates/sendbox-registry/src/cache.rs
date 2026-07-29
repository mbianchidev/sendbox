use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use fs2::FileExt as _;
use rustix::process::geteuid;
use sendbox_config::{AtomicWriteMode, atomic_write_file, ensure_directory};
use sendbox_policy::{PackageCachePolicy, PackageEcosystem};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512};

use crate::{ArtifactDigest, PackageVerdictRecord, RegistryError, RegistryResult, Verdict};

const CACHE_RECORD_SCHEMA_VERSION: u32 = 1;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheKey {
    pub ecosystem: PackageEcosystem,
    pub artifact_digest: ArtifactDigest,
    pub scanner_version: String,
    pub policy_digest: String,
    pub trust_metadata_digest: String,
}

impl CacheKey {
    pub fn digest(&self) -> RegistryResult<String> {
        let encoded = serde_json::to_vec(self)
            .map_err(|error| RegistryError::Cache(format!("encode cache key: {error}")))?;
        let mut digest = Sha256::new();
        digest.update(b"sendbox-package-cache-key-v1\0");
        digest.update(encoded);
        Ok(encode_hex(&digest.finalize()))
    }
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub record: PackageVerdictRecord,
    pub artifact_path: Option<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct CacheLock {
    _file: File,
    pub shared: bool,
}

#[derive(Debug)]
pub(crate) struct CacheStore {
    pub artifact_path: Option<PathBuf>,
    pub cleanup_artifact: bool,
}

#[derive(Debug, Clone)]
pub struct PackageCache {
    root: PathBuf,
    policy: PackageCachePolicy,
    owner_uid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedCacheEntry {
    schema_version: u32,
    key: CacheKey,
    record: PackageVerdictRecord,
}

impl PackageCache {
    pub fn open(root: impl Into<PathBuf>, policy: PackageCachePolicy) -> RegistryResult<Self> {
        if policy.enabled && (policy.max_bytes == 0 || policy.max_entries == 0) {
            return Err(RegistryError::Invalid(
                "package cache limits must be greater than zero".to_owned(),
            ));
        }
        let root = root.into();
        ensure_directory(&root, DIRECTORY_MODE)
            .map_err(|error| cache_io("prepare package cache root", &root, error))?;
        validate_directory(&root)?;
        for name in ["blobs", "records", "locks", "quarantine", "rejected"] {
            let path = root.join(name);
            ensure_directory(&path, DIRECTORY_MODE)
                .map_err(|error| cache_io("prepare package cache directory", &path, error))?;
            validate_directory(&path)?;
        }
        let cache = Self {
            root,
            policy,
            owner_uid: geteuid().as_raw(),
        };
        Ok(cache)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.policy.enabled
    }

    pub(crate) async fn acquire_route_lock(&self, route_id: &str) -> RegistryResult<CacheLock> {
        validate_identifier(route_id)?;
        let path = self.root.join("locks").join(format!("{route_id}.lock"));
        let owner_uid = self.owner_uid;
        tokio::task::spawn_blocking(move || {
            let file = open_lock_file(&path, owner_uid)?;
            let shared = match file.try_lock_exclusive() {
                Ok(()) => false,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    file.lock_exclusive()
                        .map_err(|error| cache_io("lock package analysis", &path, error))?;
                    true
                }
                Err(error) => return Err(cache_io("lock package analysis", &path, error)),
            };
            Ok(CacheLock {
                _file: file,
                shared,
            })
        })
        .await
        .map_err(|error| RegistryError::Cache(format!("join package cache lock task: {error}")))?
    }

    pub fn quarantine_path(&self) -> RegistryResult<PathBuf> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|error| RegistryError::Cache(format!("generate quarantine name: {error}")))?;
        Ok(self
            .root
            .join("quarantine")
            .join(format!("{}.part", encode_hex(&random))))
    }

    pub fn lookup(&self, key: &CacheKey) -> RegistryResult<Option<CacheEntry>> {
        if !self.policy.enabled {
            return Ok(None);
        }
        let record_path = self.record_path(key)?;
        let Some(bytes) = read_optional_file(&record_path, self.owner_uid, MAX_RECORD_BYTES)?
        else {
            return Ok(None);
        };
        let persisted: PersistedCacheEntry = serde_json::from_slice(&bytes)
            .map_err(|error| RegistryError::Cache(format!("decode cache record: {error}")))?;
        if persisted.schema_version != CACHE_RECORD_SCHEMA_VERSION || persisted.key != *key {
            return Err(RegistryError::Cache(
                "package cache record does not match its key".to_owned(),
            ));
        }
        if persisted.record.artifact_digest.as_ref() != Some(&key.artifact_digest) {
            return Err(RegistryError::Cache(
                "package cache record artifact digest is inconsistent".to_owned(),
            ));
        }
        let artifact_path = if persisted.record.verdict == Verdict::Allow {
            let path = self.blob_path(&key.artifact_digest)?;
            validate_regular_file(&path, self.owner_uid)?;
            verify_sha512(&path, &key.artifact_digest)?;
            Some(path)
        } else {
            None
        };
        Ok(Some(CacheEntry {
            record: persisted.record,
            artifact_path,
        }))
    }

    pub(crate) fn store(
        &self,
        key: &CacheKey,
        record: &PackageVerdictRecord,
        quarantine: &Path,
    ) -> RegistryResult<CacheStore> {
        if record.artifact_digest.as_ref() != Some(&key.artifact_digest) {
            return Err(RegistryError::Cache(
                "cannot store a verdict under a different artifact digest".to_owned(),
            ));
        }
        if !self.policy.enabled {
            return self.store_without_cache(record.verdict, quarantine);
        }
        let lock_path = self.root.join("locks").join(".cache.lock");
        let lock = open_lock_file(&lock_path, self.owner_uid)?;
        lock.lock_exclusive()
            .map_err(|error| cache_io("lock package cache", &lock_path, error))?;

        let record_path = self.record_path(key)?;
        let record_exists = record_path
            .symlink_metadata()
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
        if !record_exists
            && count_regular_files(&self.root.join("records"))?
                >= u64::from(self.policy.max_entries)
        {
            return self.store_without_cache(record.verdict, quarantine);
        }

        let artifact_path = match record.verdict {
            Verdict::Allow => {
                let blob_path = self.blob_path(&key.artifact_digest)?;
                if !blob_path.exists() {
                    let artifact_bytes = validate_regular_file(quarantine, self.owner_uid)?.len();
                    let cached_bytes = sum_regular_file_bytes(&self.root.join("blobs"))?
                        .checked_add(sum_regular_file_bytes(&self.root.join("rejected"))?)
                        .ok_or_else(|| {
                            RegistryError::Cache("cache byte count overflowed".to_owned())
                        })?;
                    if artifact_bytes > self.policy.max_bytes
                        || cached_bytes > self.policy.max_bytes.saturating_sub(artifact_bytes)
                    {
                        return Ok(CacheStore {
                            artifact_path: Some(quarantine.to_path_buf()),
                            cleanup_artifact: true,
                        });
                    }
                    fs::rename(quarantine, &blob_path)
                        .map_err(|error| cache_io("promote approved package", &blob_path, error))?;
                    sync_parent(&blob_path)?;
                } else {
                    validate_regular_file(&blob_path, self.owner_uid)?;
                    remove_regular_file(quarantine)?;
                }
                verify_sha512(&blob_path, &key.artifact_digest)?;
                Some(blob_path)
            }
            Verdict::Deny | Verdict::Quarantine => {
                if self.policy.retain_quarantined {
                    let rejected = self.rejected_path(key)?;
                    if rejected.exists() {
                        validate_regular_file(&rejected, self.owner_uid)?;
                        remove_regular_file(quarantine)?;
                    } else {
                        let artifact_bytes =
                            validate_regular_file(quarantine, self.owner_uid)?.len();
                        let cached_bytes = sum_regular_file_bytes(&self.root.join("blobs"))?
                            .checked_add(sum_regular_file_bytes(&self.root.join("rejected"))?)
                            .ok_or_else(|| {
                                RegistryError::Cache("cache byte count overflowed".to_owned())
                            })?;
                        if artifact_bytes > self.policy.max_bytes
                            || cached_bytes > self.policy.max_bytes.saturating_sub(artifact_bytes)
                        {
                            remove_regular_file(quarantine)?;
                        } else {
                            fs::rename(quarantine, &rejected).map_err(|error| {
                                cache_io("retain rejected package", &rejected, error)
                            })?;
                            sync_parent(&rejected)?;
                        }
                    }
                } else {
                    remove_regular_file(quarantine)?;
                }
                None
            }
        };

        let persisted = PersistedCacheEntry {
            schema_version: CACHE_RECORD_SCHEMA_VERSION,
            key: key.clone(),
            record: record.clone(),
        };
        let encoded = serde_json::to_vec(&persisted)
            .map_err(|error| RegistryError::Cache(format!("encode cache record: {error}")))?;
        atomic_write_file(&record_path, &encoded, FILE_MODE, AtomicWriteMode::Replace)
            .map_err(|error| cache_io("write package cache record", &record_path, error))?;
        Ok(CacheStore {
            artifact_path,
            cleanup_artifact: false,
        })
    }

    pub fn invalidate_all(&self) -> RegistryResult<()> {
        let lock_path = self.root.join("locks").join(".cache.lock");
        let lock = open_lock_file(&lock_path, self.owner_uid)?;
        lock.lock_exclusive()
            .map_err(|error| cache_io("lock package cache", &lock_path, error))?;
        for name in ["blobs", "records", "rejected"] {
            remove_directory_files(&self.root.join(name))?;
        }
        Ok(())
    }

    fn store_without_cache(
        &self,
        verdict: Verdict,
        quarantine: &Path,
    ) -> RegistryResult<CacheStore> {
        if verdict == Verdict::Allow {
            Ok(CacheStore {
                artifact_path: Some(quarantine.to_path_buf()),
                cleanup_artifact: true,
            })
        } else {
            remove_regular_file(quarantine)?;
            Ok(CacheStore {
                artifact_path: None,
                cleanup_artifact: false,
            })
        }
    }

    fn record_path(&self, key: &CacheKey) -> RegistryResult<PathBuf> {
        Ok(self
            .root
            .join("records")
            .join(format!("{}.json", key.digest()?)))
    }

    fn rejected_path(&self, key: &CacheKey) -> RegistryResult<PathBuf> {
        Ok(self
            .root
            .join("rejected")
            .join(format!("{}.artifact", key.digest()?)))
    }

    fn blob_path(&self, digest: &ArtifactDigest) -> RegistryResult<PathBuf> {
        validate_sha512_digest(digest)?;
        Ok(self.root.join("blobs").join(format!("{}.tgz", digest.hex)))
    }
}

fn validate_identifier(value: &str) -> RegistryResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RegistryError::Invalid(
            "package artifact route identifier is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sha512_digest(digest: &ArtifactDigest) -> RegistryResult<()> {
    if digest.algorithm != "sha512"
        || digest.hex.len() != 128
        || !digest
            .hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RegistryError::Cache(
            "package cache requires a lowercase SHA-512 artifact digest".to_owned(),
        ));
    }
    Ok(())
}

fn validate_directory(path: &Path) -> RegistryResult<()> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| cache_io("inspect package cache directory", path, error))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(RegistryError::Cache(format!(
            "package cache directory {} must be owner-controlled with mode 0700",
            path.display()
        )));
    }
    Ok(())
}

fn validate_regular_file(path: &Path, owner_uid: u32) -> RegistryResult<fs::Metadata> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| cache_io("inspect package cache file", path, error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(RegistryError::Cache(format!(
            "package cache file {} is not a private owner-controlled regular file",
            path.display()
        )));
    }
    Ok(metadata)
}

fn open_lock_file(path: &Path, owner_uid: u32) -> RegistryResult<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| cache_io("open package cache lock", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| cache_io("inspect package cache lock", path, error))?;
    if !metadata.is_file() || metadata.uid() != owner_uid || metadata.mode() & 0o077 != 0 {
        return Err(RegistryError::Cache(format!(
            "package cache lock {} is not owner-controlled",
            path.display()
        )));
    }
    Ok(file)
}

fn read_optional_file(
    path: &Path,
    owner_uid: u32,
    maximum_bytes: u64,
) -> RegistryResult<Option<Vec<u8>>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(cache_io("open package cache record", path, error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| cache_io("inspect package cache record", path, error))?;
    if !metadata.is_file() || metadata.uid() != owner_uid || metadata.mode() & 0o077 != 0 {
        return Err(RegistryError::Cache(format!(
            "package cache record {} is not owner-controlled",
            path.display()
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(RegistryError::Cache(
            "package cache record exceeds its size limit".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| cache_io("read package cache record", path, error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
        return Err(RegistryError::Cache(
            "package cache record exceeds its size limit".to_owned(),
        ));
    }
    Ok(Some(bytes))
}

fn verify_sha512(path: &Path, expected: &ArtifactDigest) -> RegistryResult<()> {
    validate_sha512_digest(expected)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| cache_io("open cached package", path, error))?;
    let mut digest = Sha512::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| cache_io("read cached package", path, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if encode_hex(&digest.finalize()) != expected.hex {
        return Err(RegistryError::Cache(format!(
            "cached package {} failed digest verification",
            path.display()
        )));
    }
    Ok(())
}

fn remove_regular_file(path: &Path) -> RegistryResult<()> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)
                .map_err(|error| cache_io("remove package cache file", path, error))
        }
        Ok(_) => Err(RegistryError::Cache(format!(
            "refusing to remove non-regular cache path {}",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(cache_io("inspect package cache file", path, error)),
    }
}

fn remove_directory_files(directory: &Path) -> RegistryResult<()> {
    for entry in fs::read_dir(directory)
        .map_err(|error| cache_io("read package cache directory", directory, error))?
    {
        let entry = entry
            .map_err(|error| cache_io("read package cache directory entry", directory, error))?;
        remove_regular_file(&entry.path())?;
    }
    Ok(())
}

fn count_regular_files(directory: &Path) -> RegistryResult<u64> {
    let mut count = 0_u64;
    for entry in fs::read_dir(directory)
        .map_err(|error| cache_io("read package cache directory", directory, error))?
    {
        let path = entry
            .map_err(|error| cache_io("read package cache directory entry", directory, error))?
            .path();
        let metadata = path
            .symlink_metadata()
            .map_err(|error| cache_io("inspect package cache entry", &path, error))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(RegistryError::Cache(format!(
                "package cache contains unsupported entry {}",
                path.display()
            )));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| RegistryError::Cache("cache entry count overflowed".to_owned()))?;
    }
    Ok(count)
}

fn sum_regular_file_bytes(directory: &Path) -> RegistryResult<u64> {
    let mut total = 0_u64;
    for entry in fs::read_dir(directory)
        .map_err(|error| cache_io("read package cache directory", directory, error))?
    {
        let path = entry
            .map_err(|error| cache_io("read package cache directory entry", directory, error))?
            .path();
        let metadata = path
            .symlink_metadata()
            .map_err(|error| cache_io("inspect package cache entry", &path, error))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(RegistryError::Cache(format!(
                "package cache contains unsupported entry {}",
                path.display()
            )));
        }
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| RegistryError::Cache("cache byte count overflowed".to_owned()))?;
    }
    Ok(total)
}

fn sync_parent(path: &Path) -> RegistryResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| RegistryError::Cache("cache path has no parent".to_owned()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| cache_io("sync package cache directory", parent, error))
}

fn cache_io(action: &str, path: &Path, error: io::Error) -> RegistryError {
    RegistryError::Cache(format!("{action} {}: {error}", path.display()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use sendbox_policy::{PackageAction, PackageFindingKind};
    use tempfile::tempdir;

    use super::*;
    use crate::{
        CacheOutcome, PackageFinding, PackageIdentity, REGISTRY_SCANNER_VERSION,
        VerificationEvidence,
    };

    fn digest(byte: char) -> ArtifactDigest {
        ArtifactDigest {
            algorithm: "sha512".to_owned(),
            hex: byte.to_string().repeat(128),
        }
    }

    fn key(policy: &str, trust: &str, artifact_digest: ArtifactDigest) -> CacheKey {
        CacheKey {
            ecosystem: PackageEcosystem::Npm,
            artifact_digest,
            scanner_version: REGISTRY_SCANNER_VERSION.to_owned(),
            policy_digest: policy.to_owned(),
            trust_metadata_digest: trust.to_owned(),
        }
    }

    fn record(artifact_digest: ArtifactDigest, verdict: Verdict) -> PackageVerdictRecord {
        PackageVerdictRecord {
            identity: PackageIdentity {
                ecosystem: PackageEcosystem::Npm,
                name: "fixture".to_owned(),
                version: "1.0.0".to_owned(),
            },
            upstream: "https://registry.npmjs.org/fixture".to_owned(),
            artifact_digest: Some(artifact_digest.clone()),
            policy_digest: "policy".to_owned(),
            scanner_version: REGISTRY_SCANNER_VERSION.to_owned(),
            verification: Some(VerificationEvidence {
                artifact_digest,
                verified_integrity: vec!["sha512".to_owned()],
                signature_key_ids: Vec::new(),
                provenance_subjects: Vec::new(),
                trust_metadata_digest: "trust".to_owned(),
            }),
            findings: vec![PackageFinding {
                kind: PackageFindingKind::LifecycleScript,
                action: PackageAction::Deny,
                path: Some("package.json".to_owned()),
                detail: "install script".to_owned(),
            }],
            verdict,
            cache: CacheOutcome::Miss,
            requested_by_session: "session".to_owned(),
        }
    }

    fn write_artifact(path: &Path, bytes: &[u8]) -> ArtifactDigest {
        fs::write(path, bytes).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(FILE_MODE);
        fs::set_permissions(path, permissions).unwrap();
        let mut digest = Sha512::new();
        digest.update(bytes);
        ArtifactDigest {
            algorithm: "sha512".to_owned(),
            hex: encode_hex(&digest.finalize()),
        }
    }

    #[test]
    fn cache_key_changes_with_policy_and_trust() {
        let artifact = digest('a');
        assert_ne!(
            key("policy-a", "trust", artifact.clone()).digest().unwrap(),
            key("policy-b", "trust", artifact.clone()).digest().unwrap()
        );
        assert_ne!(
            key("policy", "trust-a", artifact.clone()).digest().unwrap(),
            key("policy", "trust-b", artifact).digest().unwrap()
        );
    }

    #[test]
    fn approved_artifact_round_trips_and_is_digest_checked() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let cache = PackageCache::open(root.join("cache"), PackageCachePolicy::default()).unwrap();
        let quarantine = cache.quarantine_path().unwrap();
        let artifact_digest = write_artifact(&quarantine, b"approved");
        let key = key("policy", "trust", artifact_digest.clone());
        let record = record(artifact_digest, Verdict::Allow);
        let stored = cache.store(&key, &record, &quarantine).unwrap();
        assert!(!stored.cleanup_artifact);
        assert!(stored.artifact_path.as_ref().unwrap().exists());
        let hit = cache.lookup(&key).unwrap().unwrap();
        assert_eq!(hit.record.verdict, Verdict::Allow);
        assert!(hit.artifact_path.unwrap().exists());
    }

    #[test]
    fn rejected_artifact_is_deleted_by_default() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let cache = PackageCache::open(root.join("cache"), PackageCachePolicy::default()).unwrap();
        let quarantine = cache.quarantine_path().unwrap();
        let artifact_digest = write_artifact(&quarantine, b"rejected");
        let key = key("policy", "trust", artifact_digest.clone());
        cache
            .store(&key, &record(artifact_digest, Verdict::Deny), &quarantine)
            .unwrap();
        assert!(!quarantine.exists());
        let hit = cache.lookup(&key).unwrap().unwrap();
        assert_eq!(hit.record.verdict, Verdict::Deny);
        assert!(hit.artifact_path.is_none());
    }
}
