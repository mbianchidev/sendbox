//! Content-addressed workspace snapshot persistence.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{decode_hash, encode_hash};
use crate::canonical::{decode_canonical, encode};
use crate::fs::{
    DEFAULT_MAX_FILE_BYTES, EntryMetadata, EntryType, PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE,
    SecureRoot,
};
use crate::{SecurityError, SecurityResult};

pub const SNAPSHOT_FORMAT_VERSION: u16 = 1;
pub const DEFAULT_MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_MAX_SNAPSHOT_ENTRIES: usize = 100_000;
pub const DEFAULT_MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_LINK_TARGET_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_LEGACY_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

const SNAPSHOT_FORMAT: &str = "sendbox-snapshot";
const LEGACY_SNAPSHOT_FORMAT: &str = "swift-snapshot-v1";
const OBJECTS_DIRECTORY: &str = "objects";
const MANIFESTS_DIRECTORY: &str = "manifests";
const LOCK_FILE: &str = ".snapshot.lock";
const DEFAULT_EXCLUDED_NAMES: [&str; 8] = [
    ".DS_Store",
    ".build",
    ".git",
    ".swiftpm",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotLimits {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_entries: usize,
    pub max_manifest_bytes: u64,
    pub max_link_target_bytes: usize,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
            max_entries: DEFAULT_MAX_SNAPSHOT_ENTRIES,
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            max_link_target_bytes: DEFAULT_MAX_LINK_TARGET_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExclusionPolicy {
    excluded_components: BTreeSet<String>,
}

impl ExclusionPolicy {
    pub fn new<I, S>(components: I) -> SecurityResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut excluded_components = BTreeSet::new();
        for component in components {
            let component = component.into();
            validate_component(&component)?;
            excluded_components.insert(component);
        }
        Ok(Self {
            excluded_components,
        })
    }

    pub fn excludes(&self, component: &str) -> bool {
        self.excluded_components.contains(component)
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.excluded_components.iter().map(String::as_str)
    }
}

impl Default for ExclusionPolicy {
    fn default() -> Self {
        Self {
            excluded_components: DEFAULT_EXCLUDED_NAMES
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub format: String,
    pub version: u16,
    pub id: String,
    pub entries: Vec<SnapshotEntry>,
    pub total_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEntry {
    pub path: String,
    pub mode: u32,
    pub kind: SnapshotEntryKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SnapshotEntryKind {
    Directory,
    Regular { content_hash: String, size: u64 },
    Symlink { target: String },
    Hardlink { source: String, size: u64 },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnapshotDiff {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    pub unchanged: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PruneResult {
    pub manifests_removed: usize,
    pub objects_removed: usize,
}

pub trait RestoreHooks {
    fn after_workspace_backup(&self) -> SecurityResult<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoRestoreHooks;

impl RestoreHooks for NoRestoreHooks {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LegacySwiftSnapshot {
    pub id: String,
    pub timestamp: String,
    pub session_name: String,
    pub workspace_path: String,
    pub files: Vec<LegacySwiftSnapshotFile>,
    pub total_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LegacySwiftSnapshotFile {
    pub relative_path: String,
    pub content_hash: String,
    pub size: u64,
    pub permissions: u16,
    pub modified_at: String,
}

pub fn decode_legacy_swift_manifest(
    bytes: &[u8],
    max_bytes: u64,
    max_entries: usize,
) -> SecurityResult<LegacySwiftSnapshot> {
    if bytes.len() as u64 > max_bytes {
        return Err(SecurityError::SizeLimit {
            path: PathBuf::from("legacy snapshot manifest"),
            limit: max_bytes,
        });
    }
    let manifest: LegacySwiftSnapshot =
        serde_json::from_slice(bytes).map_err(|error| SecurityError::Malformed {
            format: LEGACY_SNAPSHOT_FORMAT,
            detail: error.to_string(),
        })?;
    validate_hash(&manifest.id)?;
    validate_iso_timestamp(&manifest.timestamp)?;
    if manifest.session_name.is_empty()
        || manifest.session_name.contains('\0')
        || manifest.workspace_path.is_empty()
        || manifest.workspace_path.contains('\0')
    {
        return malformed_legacy("invalid session name or workspace path");
    }
    if manifest.files.len() > max_entries {
        return malformed_legacy("file count exceeds limit");
    }
    let mut previous = None;
    let mut total_size = 0_u64;
    for file in &manifest.files {
        validate_relative_path(&file.relative_path)?;
        if previous
            .as_ref()
            .is_some_and(|path| path >= &file.relative_path)
        {
            return malformed_legacy("file paths are not strictly sorted");
        }
        previous = Some(file.relative_path.clone());
        validate_hash(&file.content_hash)?;
        validate_iso_timestamp(&file.modified_at)?;
        if u32::from(file.permissions) & !0o7777 != 0 {
            return malformed_legacy("invalid file permissions");
        }
        total_size = total_size
            .checked_add(file.size)
            .ok_or_else(|| legacy_error("total size overflows"))?;
    }
    if total_size != manifest.total_size {
        return Err(SecurityError::Integrity(
            "legacy snapshot total size mismatch".to_owned(),
        ));
    }
    Ok(manifest)
}

pub fn decode_legacy_swift_manifest_default(bytes: &[u8]) -> SecurityResult<LegacySwiftSnapshot> {
    decode_legacy_swift_manifest(
        bytes,
        DEFAULT_MAX_LEGACY_MANIFEST_BYTES,
        DEFAULT_MAX_SNAPSHOT_ENTRIES,
    )
}

pub struct SnapshotManager<'a> {
    root: &'a SecureRoot,
    directory: PathBuf,
    limits: SnapshotLimits,
    exclusions: ExclusionPolicy,
}

pub type SnapshotStore<'a> = SnapshotManager<'a>;

impl<'a> SnapshotManager<'a> {
    pub fn new(root: &'a SecureRoot, directory: impl Into<PathBuf>) -> Self {
        Self {
            root,
            directory: directory.into(),
            limits: SnapshotLimits::default(),
            exclusions: ExclusionPolicy::default(),
        }
    }

    pub fn with_limits(mut self, limits: SnapshotLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_exclusion_policy(mut self, exclusions: ExclusionPolicy) -> Self {
        self.exclusions = exclusions;
        self
    }

    #[cfg(unix)]
    pub fn capture(&self, workspace: &SecureRoot) -> SecurityResult<SnapshotManifest> {
        self.ensure_layout()?;
        let _lock = self.root.lock_exclusive(self.directory.join(LOCK_FILE))?;
        let mut state = CaptureState::default();
        self.capture_directory(workspace, Path::new(""), &mut state)?;
        state
            .entries
            .sort_by(|left, right| left.path.cmp(&right.path));
        let content = ManifestHashContent {
            format: SNAPSHOT_FORMAT,
            version: SNAPSHOT_FORMAT_VERSION,
            entries: &state.entries,
            total_size: state.total_size,
        };
        let id = hash_bytes(&encode(&content, SNAPSHOT_FORMAT)?);
        let manifest = SnapshotManifest {
            format: SNAPSHOT_FORMAT.to_owned(),
            version: SNAPSHOT_FORMAT_VERSION,
            id,
            entries: state.entries,
            total_size: state.total_size,
        };
        self.validate_manifest(&manifest)?;
        let bytes = encode(&manifest, SNAPSHOT_FORMAT)?;
        let path = self.manifest_path(&manifest.id);
        match self.read_store_file(&path, self.limits.max_manifest_bytes) {
            Ok(existing) if existing == bytes => {}
            Ok(_) => {
                return Err(SecurityError::Integrity(
                    "existing snapshot manifest content does not match its ID".to_owned(),
                ));
            }
            Err(error) if is_not_found(&error) => {
                self.root.write_atomic(
                    path,
                    &bytes,
                    self.limits.max_manifest_bytes,
                    PRIVATE_FILE_MODE,
                )?;
            }
            Err(error) => return Err(error),
        }
        Ok(manifest)
    }

    #[cfg(unix)]
    pub fn get(&self, id: &str) -> SecurityResult<SnapshotManifest> {
        validate_hash(id)?;
        if encode_hash(&decode_hash(id)?) != id {
            return Err(SecurityError::Malformed {
                format: SNAPSHOT_FORMAT,
                detail: "snapshot ID must use lowercase hexadecimal".to_owned(),
            });
        }
        let bytes =
            self.read_store_file(&self.manifest_path(id), self.limits.max_manifest_bytes)?;
        let manifest: SnapshotManifest = decode_canonical(&bytes, SNAPSHOT_FORMAT)?;
        self.validate_manifest(&manifest)?;
        if manifest.id != id {
            return Err(SecurityError::Integrity(
                "snapshot filename does not match manifest ID".to_owned(),
            ));
        }
        Ok(manifest)
    }

    #[cfg(unix)]
    pub fn list(&self) -> SecurityResult<Vec<SnapshotManifest>> {
        let directory = self.directory.join(MANIFESTS_DIRECTORY);
        let entries = match self.root.list_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if is_not_found(&error) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut manifests = Vec::new();
        for entry in entries {
            if entry.metadata.entry_type != EntryType::Regular {
                return Err(SecurityError::UnsupportedFileType(
                    directory.join(entry.name),
                ));
            }
            let name = entry
                .name
                .into_string()
                .map_err(|name| SecurityError::InvalidPath(PathBuf::from(name)))?;
            let Some(id) = name.strip_suffix(".json") else {
                return Err(SecurityError::Malformed {
                    format: SNAPSHOT_FORMAT,
                    detail: format!("unexpected manifest filename {name}"),
                });
            };
            manifests.push(self.get(id)?);
        }
        manifests.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(manifests)
    }

    #[cfg(unix)]
    pub fn verify(&self, id: &str) -> SecurityResult<()> {
        let manifest = self.get(id)?;
        let mut verified = BTreeSet::new();
        for entry in &manifest.entries {
            if let SnapshotEntryKind::Regular { content_hash, size } = &entry.kind
                && verified.insert(content_hash)
            {
                let bytes = self.read_object(content_hash)?;
                if bytes.len() as u64 != *size {
                    return Err(SecurityError::Integrity(format!(
                        "object size mismatch for {}",
                        entry.path
                    )));
                }
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    pub fn diff(&self, from_id: &str, to_id: &str) -> SecurityResult<SnapshotDiff> {
        let from = self.get(from_id)?;
        let to = self.get(to_id)?;
        Ok(diff_manifests(&from, &to))
    }

    #[cfg(unix)]
    pub fn prune(&self, keep: usize) -> SecurityResult<PruneResult> {
        self.ensure_layout()?;
        let _lock = self.root.lock_exclusive(self.directory.join(LOCK_FILE))?;
        let manifest_directory = self.directory.join(MANIFESTS_DIRECTORY);
        let mut manifests = Vec::new();
        for entry in self.root.list_dir(&manifest_directory)? {
            if entry.metadata.entry_type != EntryType::Regular {
                return Err(SecurityError::UnsupportedFileType(
                    manifest_directory.join(entry.name),
                ));
            }
            let name = entry
                .name
                .into_string()
                .map_err(|name| SecurityError::InvalidPath(PathBuf::from(name)))?;
            let id = name
                .strip_suffix(".json")
                .ok_or_else(|| SecurityError::Malformed {
                    format: SNAPSHOT_FORMAT,
                    detail: format!("unexpected manifest filename {name}"),
                })?;
            let manifest = self.get(id)?;
            manifests.push((entry.metadata, manifest));
        }
        manifests.sort_by(|(left_meta, left), (right_meta, right)| {
            (
                right_meta.modified_unix_seconds,
                right_meta.modified_nanoseconds,
                &right.id,
            )
                .cmp(&(
                    left_meta.modified_unix_seconds,
                    left_meta.modified_nanoseconds,
                    &left.id,
                ))
        });
        let mut result = PruneResult::default();
        for (_, manifest) in manifests.iter().skip(keep) {
            self.root.remove_tree(self.manifest_path(&manifest.id))?;
            result.manifests_removed += 1;
        }
        let retained_hashes = manifests
            .iter()
            .take(keep)
            .flat_map(|(_, manifest)| manifest.entries.iter())
            .filter_map(|entry| match &entry.kind {
                SnapshotEntryKind::Regular { content_hash, .. } => Some(content_hash.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        result.objects_removed = self.prune_objects(&retained_hashes)?;
        Ok(result)
    }

    #[cfg(unix)]
    pub fn restore(
        &self,
        id: &str,
        parent: &SecureRoot,
        workspace_name: impl AsRef<Path>,
    ) -> SecurityResult<()> {
        self.restore_with_hooks(id, parent, workspace_name, &NoRestoreHooks)
    }

    #[cfg(unix)]
    pub fn restore_with_hooks<H: RestoreHooks>(
        &self,
        id: &str,
        parent: &SecureRoot,
        workspace_name: impl AsRef<Path>,
        hooks: &H,
    ) -> SecurityResult<()> {
        let manifest = self.get(id)?;
        self.verify(id)?;
        let workspace_name = validate_workspace_name(workspace_name.as_ref())?;
        let _lock = parent.lock_exclusive(".snapshot-restore.lock")?;
        let workspace_metadata = parent.metadata(&workspace_name)?;
        check_device(parent, &workspace_name, &workspace_metadata)?;
        if workspace_metadata.entry_type != EntryType::Directory {
            return Err(SecurityError::UnsupportedFileType(workspace_name));
        }
        let nonce = random_hex()?;
        let display_name = workspace_name.to_string_lossy();
        let stage = PathBuf::from(format!(".{display_name}.{nonce}.snapshot-stage"));
        let backup = PathBuf::from(format!(".{display_name}.{nonce}.snapshot-backup"));
        ensure_absent(parent, &stage)?;
        ensure_absent(parent, &backup)?;
        parent.create_dir_all(&stage, PRIVATE_DIRECTORY_MODE)?;
        if let Err(error) = self.populate_stage(&manifest, parent, &stage) {
            return cleanup_after_error(
                parent,
                &stage,
                "populate snapshot staging directory",
                error,
            );
        }
        if let Err(error) = parent.rename(&workspace_name, &backup) {
            return cleanup_after_error(parent, &stage, "stage snapshot restore", error);
        }
        if let Err(primary) = hooks.after_workspace_backup() {
            let rollback = parent.rename(&backup, &workspace_name);
            let cleanup = parent.remove_tree(&stage);
            return match (rollback, cleanup) {
                (Ok(()), Ok(())) => Err(primary),
                (rollback, cleanup) => Err(SecurityError::Cleanup {
                    operation: "interrupt snapshot restore",
                    path: workspace_name,
                    primary: primary.to_string(),
                    cleanup: format!(
                        "rollback: {}; staging cleanup: {}",
                        result_detail(&rollback),
                        result_detail(&cleanup)
                    ),
                }),
            };
        }
        if let Err(primary) = parent.rename(&stage, &workspace_name) {
            let rollback = parent.rename(&backup, &workspace_name);
            let cleanup = parent.remove_tree(&stage);
            return match (rollback, cleanup) {
                (Ok(()), Ok(())) => Err(primary),
                (rollback, cleanup) => Err(SecurityError::Cleanup {
                    operation: "commit snapshot restore",
                    path: workspace_name,
                    primary: primary.to_string(),
                    cleanup: format!(
                        "rollback: {}; staging cleanup: {}",
                        result_detail(&rollback),
                        result_detail(&cleanup)
                    ),
                }),
            };
        }
        parent.remove_tree(backup)
    }

    #[cfg(unix)]
    fn capture_directory(
        &self,
        workspace: &SecureRoot,
        directory: &Path,
        state: &mut CaptureState,
    ) -> SecurityResult<()> {
        for entry in workspace.list_dir(directory)? {
            let component = entry
                .name
                .to_str()
                .ok_or_else(|| SecurityError::InvalidPath(directory.join(&entry.name)))?;
            if self.exclusions.excludes(component) {
                continue;
            }
            validate_component(component)?;
            let path = directory.join(component);
            check_device(workspace, &path, &entry.metadata)?;
            match entry.metadata.entry_type {
                EntryType::Directory => {
                    state.push_entry(
                        SnapshotEntry {
                            path: path_to_string(&path)?,
                            mode: safe_mode(entry.metadata.mode),
                            kind: SnapshotEntryKind::Directory,
                        },
                        &self.limits,
                    )?;
                    self.capture_directory(workspace, &path, state)?;
                }
                EntryType::Regular => self.capture_regular(workspace, &path, state)?,
                EntryType::Symlink => {
                    let target = workspace.read_link(&path)?;
                    let target = target.to_str().ok_or_else(|| {
                        SecurityError::InvalidPath(PathBuf::from("non-UTF-8 symbolic link target"))
                    })?;
                    if target.is_empty()
                        || target.contains('\0')
                        || target.len() > self.limits.max_link_target_bytes
                    {
                        return Err(SecurityError::Malformed {
                            format: SNAPSHOT_FORMAT,
                            detail: format!("invalid symbolic link target at {}", path.display()),
                        });
                    }
                    state.push_entry(
                        SnapshotEntry {
                            path: path_to_string(&path)?,
                            mode: safe_mode(entry.metadata.mode),
                            kind: SnapshotEntryKind::Symlink {
                                target: target.to_owned(),
                            },
                        },
                        &self.limits,
                    )?;
                }
                EntryType::Other => return Err(SecurityError::UnsupportedFileType(path)),
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn capture_regular(
        &self,
        workspace: &SecureRoot,
        path: &Path,
        state: &mut CaptureState,
    ) -> SecurityResult<()> {
        let opened = workspace.open_regular(path, self.limits.max_file_bytes)?;
        check_device(workspace, path, &opened.metadata)?;
        reject_sparse(path, &opened.metadata)?;
        let metadata = opened.metadata;
        state.add_size(metadata.size, path, &self.limits)?;
        let capacity = usize::try_from(metadata.size).map_err(|_| SecurityError::SizeLimit {
            path: path.to_path_buf(),
            limit: self.limits.max_file_bytes,
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        opened
            .file
            .take(self.limits.max_file_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| SecurityError::Io {
                operation: "read snapshot file",
                path: path.to_path_buf(),
                source,
            })?;
        if bytes.len() as u64 != metadata.size {
            return Err(SecurityError::Integrity(format!(
                "file changed while capturing {}",
                path.display()
            )));
        }
        let content_hash = hash_bytes(&bytes);
        let key = (metadata.device, metadata.inode);
        let path_string = path_to_string(path)?;
        let kind = if let Some((source, source_hash, source_size)) = state.hardlinks.get(&key) {
            if source_hash != &content_hash || *source_size != metadata.size {
                return Err(SecurityError::Integrity(format!(
                    "hard link changed while capturing {}",
                    path.display()
                )));
            }
            SnapshotEntryKind::Hardlink {
                source: source.clone(),
                size: metadata.size,
            }
        } else {
            self.store_object(&content_hash, &bytes)?;
            state.hardlinks.insert(
                key,
                (path_string.clone(), content_hash.clone(), metadata.size),
            );
            SnapshotEntryKind::Regular {
                content_hash,
                size: metadata.size,
            }
        };
        state.push_entry(
            SnapshotEntry {
                path: path_string,
                mode: safe_mode(metadata.mode),
                kind,
            },
            &self.limits,
        )
    }

    #[cfg(unix)]
    fn store_object(&self, hash: &str, bytes: &[u8]) -> SecurityResult<()> {
        let path = self.object_path(hash)?;
        let parent = path
            .parent()
            .ok_or_else(|| SecurityError::InvalidPath(path.clone()))?;
        self.root.create_dir_all(parent, PRIVATE_DIRECTORY_MODE)?;
        match self.read_store_file(&path, self.limits.max_file_bytes) {
            Ok(existing) => {
                if existing != bytes || hash_bytes(&existing) != hash {
                    return Err(SecurityError::Integrity(format!(
                        "existing object {hash} is corrupt"
                    )));
                }
                Ok(())
            }
            Err(error) if is_not_found(&error) => {
                self.root
                    .write_atomic(path, bytes, self.limits.max_file_bytes, PRIVATE_FILE_MODE)
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(unix)]
    fn read_object(&self, hash: &str) -> SecurityResult<Vec<u8>> {
        let bytes = self.read_store_file(&self.object_path(hash)?, self.limits.max_file_bytes)?;
        let actual = hash_bytes(&bytes);
        if actual != hash {
            return Err(SecurityError::Integrity(format!(
                "object hash mismatch: expected {hash}, found {actual}"
            )));
        }
        Ok(bytes)
    }

    #[cfg(unix)]
    fn read_store_file(&self, path: &Path, max_bytes: u64) -> SecurityResult<Vec<u8>> {
        let opened = self.root.open_regular(path, max_bytes)?;
        check_device(self.root, path, &opened.metadata)?;
        reject_sparse(path, &opened.metadata)?;
        let expected_size = opened.metadata.size;
        let mut bytes = Vec::with_capacity(usize::try_from(expected_size).map_err(|_| {
            SecurityError::SizeLimit {
                path: path.to_path_buf(),
                limit: max_bytes,
            }
        })?);
        opened
            .file
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| SecurityError::Io {
                operation: "read snapshot store file",
                path: path.to_path_buf(),
                source,
            })?;
        if bytes.len() as u64 != expected_size {
            return Err(SecurityError::Integrity(format!(
                "snapshot store file changed while reading {}",
                path.display()
            )));
        }
        Ok(bytes)
    }

    #[cfg(unix)]
    fn validate_manifest(&self, manifest: &SnapshotManifest) -> SecurityResult<()> {
        if manifest.format != SNAPSHOT_FORMAT || manifest.version != SNAPSHOT_FORMAT_VERSION {
            return Err(SecurityError::UnsupportedVersion {
                format: SNAPSHOT_FORMAT,
                version: manifest.version,
            });
        }
        validate_hash(&manifest.id)?;
        if manifest.entries.len() > self.limits.max_entries {
            return malformed("entry count exceeds limit");
        }
        let mut previous = None;
        let mut entries_by_path = BTreeMap::new();
        let mut total_size = 0_u64;
        for entry in &manifest.entries {
            validate_relative_path(&entry.path)?;
            if entry
                .path
                .split('/')
                .any(|component| self.exclusions.excludes(component))
            {
                return malformed("manifest contains an excluded path component");
            }
            if previous.as_ref().is_some_and(|path| path >= &entry.path) {
                return malformed("entry paths are not strictly sorted");
            }
            previous = Some(entry.path.clone());
            if entry.mode & !0o777 != 0 {
                return malformed("entry contains unsafe mode bits");
            }
            if let Some(parent) = Path::new(&entry.path).parent()
                && !parent.as_os_str().is_empty()
            {
                let parent = path_to_string(parent)?;
                if !matches!(
                    entries_by_path.get(&parent),
                    Some(SnapshotEntryKind::Directory)
                ) {
                    return malformed("entry parent is not an explicit directory");
                }
            }
            match &entry.kind {
                SnapshotEntryKind::Directory => {}
                SnapshotEntryKind::Regular { content_hash, size } => {
                    validate_hash(content_hash)?;
                    if *size > self.limits.max_file_bytes {
                        return Err(SecurityError::SizeLimit {
                            path: PathBuf::from(&entry.path),
                            limit: self.limits.max_file_bytes,
                        });
                    }
                    total_size = checked_total(total_size, *size, &entry.path, &self.limits)?;
                }
                SnapshotEntryKind::Symlink { target } => {
                    if target.is_empty()
                        || target.contains('\0')
                        || target.len() > self.limits.max_link_target_bytes
                    {
                        return malformed("invalid symbolic link target");
                    }
                }
                SnapshotEntryKind::Hardlink { source, size } => {
                    validate_relative_path(source)?;
                    let Some(SnapshotEntryKind::Regular {
                        size: source_size, ..
                    }) = entries_by_path.get(source)
                    else {
                        return malformed("hard link source is not an earlier regular file");
                    };
                    if source_size != size {
                        return malformed("hard link size differs from its source");
                    }
                    total_size = checked_total(total_size, *size, &entry.path, &self.limits)?;
                }
            }
            entries_by_path.insert(entry.path.clone(), entry.kind.clone());
        }
        if total_size != manifest.total_size {
            return Err(SecurityError::Integrity(
                "snapshot total size mismatch".to_owned(),
            ));
        }
        let content = ManifestHashContent {
            format: &manifest.format,
            version: manifest.version,
            entries: &manifest.entries,
            total_size: manifest.total_size,
        };
        let expected = hash_bytes(&encode(&content, SNAPSHOT_FORMAT)?);
        if manifest.id != expected {
            return Err(SecurityError::Integrity(
                "snapshot manifest ID mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn populate_stage(
        &self,
        manifest: &SnapshotManifest,
        parent: &SecureRoot,
        stage: &Path,
    ) -> SecurityResult<()> {
        let mut directories = manifest
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, SnapshotEntryKind::Directory))
            .collect::<Vec<_>>();
        directories.sort_by(|left, right| {
            path_depth(&right.path)
                .cmp(&path_depth(&left.path))
                .then_with(|| right.path.cmp(&left.path))
        });
        for entry in &directories {
            parent.create_dir_all(stage.join(&entry.path), entry.mode | 0o700)?;
        }
        for entry in &manifest.entries {
            match &entry.kind {
                SnapshotEntryKind::Directory | SnapshotEntryKind::Hardlink { .. } => {}
                SnapshotEntryKind::Regular { content_hash, size } => {
                    let bytes = self.read_object(content_hash)?;
                    if bytes.len() as u64 != *size {
                        return Err(SecurityError::Integrity(format!(
                            "object size mismatch for {}",
                            entry.path
                        )));
                    }
                    parent.write_atomic(
                        stage.join(&entry.path),
                        &bytes,
                        self.limits.max_file_bytes,
                        entry.mode,
                    )?;
                }
                SnapshotEntryKind::Symlink { target } => {
                    parent.create_symlink(stage.join(&entry.path), target)?;
                }
            }
        }
        for entry in &manifest.entries {
            if let SnapshotEntryKind::Hardlink { source, .. } = &entry.kind {
                parent.create_hardlink(stage.join(source), stage.join(&entry.path))?;
            }
        }
        for entry in directories {
            parent.create_dir_all(stage.join(&entry.path), entry.mode)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn prune_objects(&self, retained: &BTreeSet<String>) -> SecurityResult<usize> {
        let objects = self.directory.join(OBJECTS_DIRECTORY);
        let mut removed = 0;
        for shard in self.root.list_dir(&objects)? {
            let shard_name = shard
                .name
                .into_string()
                .map_err(|name| SecurityError::InvalidPath(PathBuf::from(name)))?;
            if shard.metadata.entry_type != EntryType::Directory
                || shard_name.len() != 2
                || !shard_name.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return malformed("invalid object shard");
            }
            let shard_path = objects.join(&shard_name);
            for object in self.root.list_dir(&shard_path)? {
                if object.metadata.entry_type != EntryType::Regular {
                    return Err(SecurityError::UnsupportedFileType(
                        shard_path.join(object.name),
                    ));
                }
                let object_name = object
                    .name
                    .into_string()
                    .map_err(|name| SecurityError::InvalidPath(PathBuf::from(name)))?;
                let hash = format!("{shard_name}{object_name}");
                validate_hash(&hash)?;
                if !retained.contains(&hash) {
                    self.root.remove_tree(shard_path.join(object_name))?;
                    removed += 1;
                }
            }
            if self.root.list_dir(&shard_path)?.is_empty() {
                self.root.remove_tree(shard_path)?;
            }
        }
        Ok(removed)
    }

    #[cfg(unix)]
    fn ensure_layout(&self) -> SecurityResult<()> {
        self.root.create_dir_all(
            self.directory.join(OBJECTS_DIRECTORY),
            PRIVATE_DIRECTORY_MODE,
        )?;
        self.root.create_dir_all(
            self.directory.join(MANIFESTS_DIRECTORY),
            PRIVATE_DIRECTORY_MODE,
        )
    }

    fn manifest_path(&self, id: &str) -> PathBuf {
        self.directory
            .join(MANIFESTS_DIRECTORY)
            .join(format!("{id}.json"))
    }

    fn object_path(&self, hash: &str) -> SecurityResult<PathBuf> {
        validate_hash(hash)?;
        Ok(self
            .directory
            .join(OBJECTS_DIRECTORY)
            .join(&hash[..2])
            .join(&hash[2..]))
    }
}

#[derive(Serialize)]
struct ManifestHashContent<'a> {
    format: &'a str,
    version: u16,
    entries: &'a [SnapshotEntry],
    total_size: u64,
}

#[derive(Default)]
struct CaptureState {
    entries: Vec<SnapshotEntry>,
    hardlinks: BTreeMap<(u64, u64), (String, String, u64)>,
    total_size: u64,
}

impl CaptureState {
    fn push_entry(&mut self, entry: SnapshotEntry, limits: &SnapshotLimits) -> SecurityResult<()> {
        if self.entries.len() >= limits.max_entries {
            return malformed("entry count exceeds limit");
        }
        self.entries.push(entry);
        Ok(())
    }

    fn add_size(&mut self, size: u64, path: &Path, limits: &SnapshotLimits) -> SecurityResult<()> {
        self.total_size =
            self.total_size
                .checked_add(size)
                .ok_or_else(|| SecurityError::SizeLimit {
                    path: path.to_path_buf(),
                    limit: limits.max_total_bytes,
                })?;
        if self.total_size > limits.max_total_bytes {
            return Err(SecurityError::SizeLimit {
                path: path.to_path_buf(),
                limit: limits.max_total_bytes,
            });
        }
        Ok(())
    }
}

pub fn diff_manifests(from: &SnapshotManifest, to: &SnapshotManifest) -> SnapshotDiff {
    let from_entries = from
        .entries
        .iter()
        .map(|entry| (&entry.path, entry))
        .collect::<BTreeMap<_, _>>();
    let to_entries = to
        .entries
        .iter()
        .map(|entry| (&entry.path, entry))
        .collect::<BTreeMap<_, _>>();
    let mut diff = SnapshotDiff::default();
    for (path, entry) in &to_entries {
        match from_entries.get(path) {
            None => diff.added.push((*path).clone()),
            Some(previous) if *previous == *entry => diff.unchanged.push((*path).clone()),
            Some(_) => diff.modified.push((*path).clone()),
        }
    }
    for path in from_entries.keys() {
        if !to_entries.contains_key(path) {
            diff.deleted.push((*path).clone());
        }
    }
    diff
}

fn checked_total(
    total: u64,
    size: u64,
    path: &str,
    limits: &SnapshotLimits,
) -> SecurityResult<u64> {
    let total = total
        .checked_add(size)
        .ok_or_else(|| SecurityError::SizeLimit {
            path: PathBuf::from(path),
            limit: limits.max_total_bytes,
        })?;
    if total > limits.max_total_bytes {
        return Err(SecurityError::SizeLimit {
            path: PathBuf::from(path),
            limit: limits.max_total_bytes,
        });
    }
    Ok(total)
}

fn validate_hash(value: &str) -> SecurityResult<()> {
    let decoded = decode_hash(value)?;
    if encode_hash(&decoded) != value {
        return Err(SecurityError::Malformed {
            format: "sha256",
            detail: "hash must use lowercase hexadecimal".to_owned(),
        });
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    encode_hash(&Sha256::digest(bytes).into())
}

fn safe_mode(mode: u32) -> u32 {
    mode & 0o777
}

fn validate_component(component: &str) -> SecurityResult<()> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\0')
    {
        return Err(SecurityError::InvalidPath(PathBuf::from(component)));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> SecurityResult<()> {
    let path_ref = Path::new(path);
    if path.is_empty()
        || path.contains('\0')
        || path_ref.is_absolute()
        || path_ref
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path_ref
            .components()
            .any(|component| component.as_os_str().to_str().is_none())
    {
        return Err(SecurityError::InvalidPath(path_ref.to_path_buf()));
    }
    Ok(())
}

fn validate_workspace_name(path: &Path) -> SecurityResult<PathBuf> {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next() else {
        return Err(SecurityError::InvalidPath(path.to_path_buf()));
    };
    if components.next().is_some() || name.to_str().is_none() {
        return Err(SecurityError::InvalidPath(path.to_path_buf()));
    }
    validate_component(name.to_str().unwrap_or_default())?;
    Ok(PathBuf::from(name))
}

fn path_to_string(path: &Path) -> SecurityResult<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| SecurityError::InvalidPath(path.to_path_buf()))
}

fn path_depth(path: &str) -> usize {
    path.bytes().filter(|byte| *byte == b'/').count()
}

fn validate_iso_timestamp(value: &str) -> SecurityResult<()> {
    time::OffsetDateTime::parse(
        value,
        &time::format_description::well_known::Iso8601::DEFAULT,
    )
    .map(|_| ())
    .map_err(|error| SecurityError::Malformed {
        format: LEGACY_SNAPSHOT_FORMAT,
        detail: format!("invalid ISO timestamp: {error}"),
    })
}

fn malformed<T>(detail: impl Into<String>) -> SecurityResult<T> {
    Err(SecurityError::Malformed {
        format: SNAPSHOT_FORMAT,
        detail: detail.into(),
    })
}

fn malformed_legacy<T>(detail: impl Into<String>) -> SecurityResult<T> {
    Err(legacy_error(detail))
}

fn legacy_error(detail: impl Into<String>) -> SecurityError {
    SecurityError::Malformed {
        format: LEGACY_SNAPSHOT_FORMAT,
        detail: detail.into(),
    }
}

#[cfg(unix)]
fn check_device(root: &SecureRoot, path: &Path, metadata: &EntryMetadata) -> SecurityResult<()> {
    if metadata.device != root.root_device() {
        return Err(SecurityError::Integrity(format!(
            "cross-device entry rejected at {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn reject_sparse(path: &Path, metadata: &EntryMetadata) -> SecurityResult<()> {
    if metadata.size != 0 && metadata.allocated_bytes < metadata.size {
        return Err(SecurityError::Integrity(format!(
            "sparse file rejected at {}",
            path.display()
        )));
    }
    Ok(())
}

fn is_not_found(error: &SecurityError) -> bool {
    matches!(
        error,
        SecurityError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound
    )
}

#[cfg(unix)]
fn random_hex() -> SecurityResult<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|error| SecurityError::Malformed {
        format: SNAPSHOT_FORMAT,
        detail: error.to_string(),
    })?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(unix)]
fn ensure_absent(root: &SecureRoot, path: &Path) -> SecurityResult<()> {
    match root.metadata(path) {
        Err(error) if is_not_found(&error) => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(SecurityError::Integrity(format!(
            "restore staging path already exists: {}",
            path.display()
        ))),
    }
}

#[cfg(unix)]
fn cleanup_after_error<T>(
    root: &SecureRoot,
    path: &Path,
    operation: &'static str,
    primary: SecurityError,
) -> SecurityResult<T> {
    match root.remove_tree(path) {
        Ok(()) => Err(primary),
        Err(cleanup) => Err(SecurityError::Cleanup {
            operation,
            path: path.to_path_buf(),
            primary: primary.to_string(),
            cleanup: cleanup.to_string(),
        }),
    }
}

#[cfg(unix)]
fn result_detail(result: &SecurityResult<()>) -> String {
    match result {
        Ok(()) => "ok".to_owned(),
        Err(error) => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;

    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        _temp: TempDir,
        store: SecureRoot,
        workspace: SecureRoot,
        parent: SecureRoot,
        workspace_path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = TempDir::new().expect("temp dir");
            let store_path = temp.path().join("store");
            let parent_path = temp.path().join("parent");
            let workspace_path = parent_path.join("workspace");
            fs::create_dir(&store_path).expect("store dir");
            fs::create_dir(&parent_path).expect("parent dir");
            fs::create_dir(&workspace_path).expect("workspace dir");
            Self {
                store: SecureRoot::open(&store_path).expect("open store"),
                workspace: SecureRoot::open(&workspace_path).expect("open workspace"),
                parent: SecureRoot::open(&parent_path).expect("open parent"),
                workspace_path,
                _temp: temp,
            }
        }

        fn manager(&self) -> SnapshotManager<'_> {
            SnapshotManager::new(&self.store, "snapshots")
        }
    }

    #[test]
    fn deterministic_capture_list_diff_verify_and_prune() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.workspace_path.join("dir")).expect("create dir");
        fs::write(fixture.workspace_path.join("dir/a"), b"alpha").expect("write a");
        fs::write(fixture.workspace_path.join(".DS_Store"), b"ignored").expect("write ignored");
        let first = fixture
            .manager()
            .capture(&fixture.workspace)
            .expect("capture first");
        let repeated = fixture
            .manager()
            .capture(&fixture.workspace)
            .expect("repeat capture");
        assert_eq!(first, repeated);
        assert_eq!(fixture.manager().list().expect("list"), vec![first.clone()]);
        fixture.manager().verify(&first.id).expect("verify");

        fs::write(fixture.workspace_path.join("dir/a"), b"beta").expect("modify a");
        fs::write(fixture.workspace_path.join("b"), b"bravo").expect("write b");
        let second = fixture
            .manager()
            .capture(&fixture.workspace)
            .expect("capture second");
        let diff = fixture.manager().diff(&first.id, &second.id).expect("diff");
        assert_eq!(diff.added, vec!["b"]);
        assert_eq!(diff.modified, vec!["dir/a"]);
        assert_eq!(diff.unchanged, vec!["dir"]);

        let pruned = fixture.manager().prune(1).expect("prune");
        assert_eq!(pruned.manifests_removed, 1);
        let retained = fixture.manager().list().expect("list");
        assert_eq!(retained.len(), 1);
        fixture
            .manager()
            .verify(&retained[0].id)
            .expect("retained snapshot remains valid");
    }

    #[test]
    fn captures_and_restores_symlinks_hardlinks_and_modes() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.workspace_path.join("nested")).expect("create nested");
        let original = fixture.workspace_path.join("nested/original");
        fs::write(&original, b"linked").expect("write original");
        fs::set_permissions(&original, fs::Permissions::from_mode(0o640)).expect("set mode");
        fs::hard_link(&original, fixture.workspace_path.join("nested/alias")).expect("hard link");
        symlink("original", fixture.workspace_path.join("nested/symlink")).expect("symlink");

        let manifest = fixture
            .manager()
            .capture(&fixture.workspace)
            .expect("capture");
        fs::write(&original, b"changed").expect("change original");
        fixture
            .manager()
            .restore(&manifest.id, &fixture.parent, "workspace")
            .expect("restore");

        assert_eq!(fs::read(&original).expect("read restored"), b"linked");
        assert_eq!(
            fs::read_link(fixture.workspace_path.join("nested/symlink")).expect("read link"),
            PathBuf::from("original")
        );
        let first = fs::metadata(&original).expect("original metadata");
        let second =
            fs::metadata(fixture.workspace_path.join("nested/alias")).expect("alias metadata");
        assert_eq!(first.ino(), second.ino());
        assert_eq!(first.permissions().mode() & 0o777, 0o640);
        assert_eq!(
            fs::metadata(&fixture.workspace_path)
                .expect("workspace metadata")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_DIRECTORY_MODE
        );
    }

    #[test]
    fn rejects_special_sparse_and_non_utf8_entries() {
        use std::os::unix::ffi::OsStringExt;

        let fixture = Fixture::new();
        let socket = fixture.workspace_path.join("socket");
        let _listener = UnixListener::bind(&socket).expect("bind socket");
        assert!(matches!(
            fixture.manager().capture(&fixture.workspace),
            Err(SecurityError::UnsupportedFileType(_))
        ));
        fs::remove_file(socket).expect("remove socket");

        let sparse_path = fixture.workspace_path.join("sparse");
        let mut sparse = File::create(&sparse_path).expect("create sparse");
        sparse.seek(SeekFrom::Start(1024 * 1024)).expect("seek");
        sparse.write_all(b"x").expect("write tail");
        sparse.sync_all().expect("sync sparse");
        if fs::metadata(&sparse_path)
            .expect("sparse metadata")
            .blocks()
            * 512
            < fs::metadata(&sparse_path).expect("sparse metadata").len()
        {
            assert!(matches!(
                fixture.manager().capture(&fixture.workspace),
                Err(SecurityError::Integrity(_))
            ));
        }
        fs::remove_file(sparse_path).expect("remove sparse");

        let non_utf8_result = fs::write(
            fixture
                .workspace_path
                .join(std::ffi::OsString::from_vec(vec![0xff])),
            b"x",
        );
        if non_utf8_result.is_ok() {
            assert!(matches!(
                fixture.manager().capture(&fixture.workspace),
                Err(SecurityError::InvalidPath(_))
            ));
        }
    }

    #[test]
    fn detects_object_corruption() {
        let fixture = Fixture::new();
        fs::write(fixture.workspace_path.join("file"), b"content").expect("write file");
        let manifest = fixture
            .manager()
            .capture(&fixture.workspace)
            .expect("capture");
        let hash = manifest
            .entries
            .iter()
            .find_map(|entry| match &entry.kind {
                SnapshotEntryKind::Regular { content_hash, .. } => Some(content_hash),
                _ => None,
            })
            .expect("object hash");
        let object = fixture
            ._temp
            .path()
            .join("store/snapshots/objects")
            .join(&hash[..2])
            .join(&hash[2..]);
        fs::write(object, b"corrupt").expect("corrupt object");
        assert!(matches!(
            fixture.manager().verify(&manifest.id),
            Err(SecurityError::Integrity(_))
        ));
    }

    #[test]
    fn interrupted_restore_rolls_back_workspace() {
        struct Interrupt;
        impl RestoreHooks for Interrupt {
            fn after_workspace_backup(&self) -> SecurityResult<()> {
                Err(SecurityError::Integrity("injected interruption".to_owned()))
            }
        }

        let fixture = Fixture::new();
        fs::write(fixture.workspace_path.join("file"), b"before").expect("write before");
        let manifest = fixture
            .manager()
            .capture(&fixture.workspace)
            .expect("capture");
        fs::write(fixture.workspace_path.join("file"), b"current").expect("write current");

        assert!(
            fixture
                .manager()
                .restore_with_hooks(&manifest.id, &fixture.parent, "workspace", &Interrupt)
                .is_err()
        );
        assert_eq!(
            fs::read(fixture.workspace_path.join("file")).expect("read rolled back workspace"),
            b"current"
        );
        let leftovers = fs::read_dir(fixture.workspace_path.parent().expect("workspace parent"))
            .expect("list parent")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_name() != "workspace" && entry.file_name() != ".snapshot-restore.lock"
            })
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn rejects_manifest_path_traversal() {
        let fixture = Fixture::new();
        let manifest = SnapshotManifest {
            format: SNAPSHOT_FORMAT.to_owned(),
            version: SNAPSHOT_FORMAT_VERSION,
            id: "00".repeat(32),
            entries: vec![SnapshotEntry {
                path: "../escape".to_owned(),
                mode: 0o600,
                kind: SnapshotEntryKind::Regular {
                    content_hash: "00".repeat(32),
                    size: 0,
                },
            }],
            total_size: 0,
        };
        assert!(matches!(
            fixture.manager().validate_manifest(&manifest),
            Err(SecurityError::InvalidPath(_))
        ));
    }

    #[test]
    fn validates_bounded_legacy_swift_manifest() {
        let hash = "00".repeat(32);
        let bytes = format!(
            concat!(
                "{{\"id\":\"{hash}\",\"timestamp\":\"2025-01-01T00:00:00Z\",",
                "\"session_name\":\"s\",\"workspace_path\":\"/work\",",
                "\"files\":[{{\"relative_path\":\"a\",\"content_hash\":\"{hash}\",",
                "\"size\":1,\"permissions\":420,",
                "\"modified_at\":\"2025-01-01T00:00:00Z\"}}],\"total_size\":1}}"
            ),
            hash = hash
        );
        let legacy = decode_legacy_swift_manifest_default(bytes.as_bytes()).expect("decode legacy");
        assert_eq!(legacy.files[0].relative_path, "a");
        assert!(decode_legacy_swift_manifest(bytes.as_bytes(), 4, 1).is_err());
    }
}
