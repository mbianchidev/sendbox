use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::GuardError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryIdentity {
    host: String,
    owner: String,
    name: String,
}

impl RepositoryIdentity {
    pub fn new(
        host: impl Into<String>,
        owner: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, GuardError> {
        let host = normalize_host(&host.into())?;
        let owner = normalize_component(&owner.into(), "owner")?;
        let name = normalize_component(trim_git_suffix(&name.into()), "repository")?;
        Ok(Self { host, owner, name })
    }

    pub fn parse(remote: &str, shorthand_host: Option<&str>) -> Result<Self, GuardError> {
        let value = remote.trim();
        if value.is_empty() {
            return Err(GuardError::AmbiguousRepository);
        }
        if let Ok(url) = Url::parse(value) {
            return parse_url(&url);
        }
        if let Some((host, path)) = parse_scp_like(value) {
            return from_host_path(host, path);
        }
        if let Some(host) = shorthand_host {
            return from_host_path(host, value);
        }
        Err(GuardError::AmbiguousRepository)
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for RepositoryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}/{}", self.host, self.owner, self.name)
    }
}

fn parse_url(url: &Url) -> Result<RepositoryIdentity, GuardError> {
    if !matches!(url.scheme(), "https" | "http" | "ssh" | "git") {
        return Err(GuardError::AmbiguousRepository);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(GuardError::AmbiguousRepository);
    }
    let host = url.host_str().ok_or(GuardError::AmbiguousRepository)?;
    let explicit_port = url.port();
    let default_port = match url.scheme() {
        "https" => Some(443),
        "http" => Some(80),
        "ssh" => Some(22),
        "git" => Some(9418),
        _ => None,
    };
    let host = match explicit_port {
        Some(explicit) if Some(explicit) != default_port => format!("{host}:{explicit}"),
        _ => host.to_owned(),
    };
    from_host_path(&host, url.path())
}

fn parse_scp_like(value: &str) -> Option<(&str, &str)> {
    if value.contains("://") || value.starts_with('/') {
        return None;
    }
    let (prefix, path) = value.split_once(':')?;
    if prefix.is_empty() || path.is_empty() || prefix.contains(['/', '\\']) {
        return None;
    }
    let host = prefix.rsplit_once('@').map_or(prefix, |(_, host)| host);
    (!host.is_empty()).then_some((host, path))
}

fn from_host_path(host: &str, path: &str) -> Result<RepositoryIdentity, GuardError> {
    let components = path
        .trim_matches('/')
        .split('/')
        .map(decode_component)
        .collect::<Result<Vec<_>, _>>()?;
    if components.len() != 2 {
        return Err(GuardError::AmbiguousRepository);
    }
    RepositoryIdentity::new(host, &components[0], &components[1])
}

fn decode_component(value: &str) -> Result<String, GuardError> {
    if value.is_empty() {
        return Err(GuardError::AmbiguousRepository);
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(GuardError::AmbiguousRepository);
            }
            let high = hex(bytes[index + 1]).ok_or(GuardError::AmbiguousRepository)?;
            let low = hex(bytes[index + 2]).ok_or(GuardError::AmbiguousRepository)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded).map_err(|_| GuardError::AmbiguousRepository)?;
    if decoded.contains(['/', '\\']) || decoded == "." || decoded == ".." {
        return Err(GuardError::AmbiguousRepository);
    }
    Ok(decoded)
}

const fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn normalize_host(value: &str) -> Result<String, GuardError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.contains(['/', '\\', '@'])
        || value.chars().any(char::is_whitespace)
    {
        return Err(GuardError::InvalidPolicy(
            "selected repository host is invalid".to_owned(),
        ));
    }
    Ok(value)
}

fn normalize_component(value: &str, label: &str) -> Result<String, GuardError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains(['/', '\\', ':'])
        || value.chars().any(char::is_whitespace)
    {
        return Err(GuardError::InvalidPolicy(format!(
            "selected repository {label} is invalid"
        )));
    }
    Ok(value)
}

fn trim_git_suffix(value: &str) -> &str {
    value
        .get(..value.len().saturating_sub(4))
        .filter(|_| value.to_ascii_lowercase().ends_with(".git"))
        .unwrap_or(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIdentity {
    canonical_path: PathBuf,
    file_identity: FileIdentity,
}

impl WorkspaceIdentity {
    pub fn capture(path: impl AsRef<Path>) -> Result<Self, GuardError> {
        let canonical_path = fs::canonicalize(path.as_ref()).map_err(|error| {
            GuardError::InvalidPolicy(format!(
                "selected workspace `{}` cannot be resolved: {error}",
                path.as_ref().display()
            ))
        })?;
        let metadata = fs::metadata(&canonical_path)?;
        if !metadata.is_dir() {
            return Err(GuardError::InvalidPolicy(
                "selected workspace must be a directory".to_owned(),
            ));
        }
        Ok(Self {
            canonical_path,
            file_identity: FileIdentity::from_metadata(&metadata),
        })
    }

    pub fn matches_path(&self, path: impl AsRef<Path>) -> Result<bool, GuardError> {
        let canonical = fs::canonicalize(path.as_ref())?;
        let metadata = fs::metadata(&canonical)?;
        Ok(self.canonical_path == canonical
            && self.file_identity == FileIdentity::from_metadata(&metadata))
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.canonical_path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    #[cfg(unix)]
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(not(unix))]
    fn from_metadata(_metadata: &fs::Metadata) -> Self {
        Self {
            device: 0,
            inode: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::RepositoryIdentity;

    #[test]
    fn parses_supported_remote_forms() {
        let expected = RepositoryIdentity::new("github.com", "Acme", "Project.git").unwrap();
        for remote in [
            "https://github.com/Acme/Project.git",
            "git@github.com:acme/project.git",
            "ssh://git@github.com/acme/project.git",
            "acme/project.git",
        ] {
            assert_eq!(
                RepositoryIdentity::parse(remote, Some("github.com")).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn rejects_ambiguous_or_encoded_paths() {
        for remote in [
            "https://github.com/acme/project/extra",
            "https://github.com/acme%2fother/project",
            "file:///tmp/project",
            "ext::sh -c evil",
            "../acme/project",
        ] {
            assert!(RepositoryIdentity::parse(remote, Some("github.com")).is_err());
        }
    }

    proptest! {
        #[test]
        fn remote_parser_never_panics(value in any::<String>()) {
            let _ = RepositoryIdentity::parse(&value, Some("github.com"));
        }
    }
}
