use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use sendbox_core::CONFIG_SCHEMA_VERSION;
use serde::Serialize;
use serde::de::Error as _;
use serde_yaml_ng::{Mapping, Value};
use tempfile::NamedTempFile;

use crate::{ConfigurationError, SandboxConfiguration};

pub const CONFIG_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicWriteMode {
    CreateNew,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationReport {
    pub source_version: u32,
    pub target_version: u32,
    pub explicit_source_version: bool,
    pub schema_changed: bool,
    pub canonicalized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfiguration {
    pub configuration: SandboxConfiguration,
    pub migration: MigrationReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationResult {
    pub configuration: SandboxConfiguration,
    pub yaml: String,
    pub migration: MigrationReport,
}

pub(crate) fn parse_with_migration(
    yaml: &str,
    path: &Path,
) -> Result<LoadedConfiguration, ConfigurationError> {
    let (configuration, explicit_source_version) = decode_v1(yaml, path)?;
    let canonical = serialize(&configuration)?;
    Ok(LoadedConfiguration {
        configuration,
        migration: MigrationReport {
            source_version: CONFIG_SCHEMA_VERSION,
            target_version: CONFIG_SCHEMA_VERSION,
            explicit_source_version,
            schema_changed: false,
            canonicalized: normalize_yaml(yaml) != normalize_yaml(&canonical),
        },
    })
}

pub(crate) fn migrate(yaml: &str, path: &Path) -> Result<MigrationResult, ConfigurationError> {
    let loaded = parse_with_migration(yaml, path)?;
    loaded
        .configuration
        .validate()
        .map_err(ConfigurationError::Validation)?;
    let canonical = serialize(&loaded.configuration)?;
    Ok(MigrationResult {
        configuration: loaded.configuration,
        yaml: canonical,
        migration: loaded.migration,
    })
}

fn decode_v1(yaml: &str, path: &Path) -> Result<(SandboxConfiguration, bool), ConfigurationError> {
    let mut document: Value =
        serde_yaml_ng::from_str(yaml).map_err(|source| ConfigurationError::Decode {
            path: path.to_path_buf(),
            source,
        })?;
    let Some(mapping) = document.as_mapping_mut() else {
        return serde_yaml_ng::from_str::<SandboxConfiguration>(yaml)
            .map(|configuration| (configuration, false))
            .map_err(|source| ConfigurationError::Decode {
                path: path.to_path_buf(),
                source,
            });
    };
    let version = take_schema_version(mapping, path)?;
    if version.is_none() {
        return serde_yaml_ng::from_str(yaml)
            .map(|configuration| (configuration, false))
            .map_err(|source| ConfigurationError::Decode {
                path: path.to_path_buf(),
                source,
            });
    }
    serde_yaml_ng::from_value(document)
        .map(|configuration| (configuration, true))
        .map_err(|source| ConfigurationError::Decode {
            path: path.to_path_buf(),
            source,
        })
}

fn take_schema_version(
    mapping: &mut Mapping,
    path: &Path,
) -> Result<Option<u32>, ConfigurationError> {
    let key = Value::String("schema_version".to_owned());
    let Some(value) = mapping.remove(&key) else {
        return Ok(None);
    };
    let Some(version) = value.as_u64() else {
        return Err(ConfigurationError::Decode {
            path: path.to_path_buf(),
            source: serde_yaml_ng::Error::custom("schema_version must be a positive integer"),
        });
    };
    if version != u64::from(CONFIG_SCHEMA_VERSION) {
        return Err(ConfigurationError::UnsupportedVersion {
            found: version,
            current: CONFIG_SCHEMA_VERSION,
        });
    }
    Ok(Some(CONFIG_SCHEMA_VERSION))
}

pub(crate) fn serialize(
    configuration: &SandboxConfiguration,
) -> Result<String, ConfigurationError> {
    let yaml = serde_yaml_ng::to_string(configuration)
        .map_err(|source| ConfigurationError::Encode { source })?;
    Ok(yaml
        .strip_prefix("---\n")
        .unwrap_or(yaml.as_str())
        .to_owned())
}

pub fn atomic_write_file(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    write_mode: AtomicWriteMode,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination has no file name",
        ));
    }
    let mut temporary = NamedTempFile::new_in(parent)?;
    set_mode(temporary.as_file(), mode)?;
    temporary.write_all(bytes)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;

    match write_mode {
        AtomicWriteMode::CreateNew => {
            temporary
                .persist_noclobber(path)
                .map_err(|error| error.error)?;
        }
        AtomicWriteMode::Replace => {
            temporary.persist(path).map_err(|error| error.error)?;
        }
    }
    sync_directory(parent)
}

#[cfg(unix)]
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_file: &File, _mode: u32) -> io::Result<()> {
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn normalize_yaml(yaml: &str) -> String {
    yaml.replace("\r\n", "\n").trim().to_owned()
}
