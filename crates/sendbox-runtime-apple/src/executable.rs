use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const SEARCH_DIRECTORIES: [&str; 4] = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableReport {
    pub requested_path: Option<PathBuf>,
    pub resolved_path: Option<PathBuf>,
    pub symlink_chain: Vec<PathBuf>,
    pub owner_uid: Option<u32>,
    pub mode: Option<u32>,
    pub trusted: bool,
    pub reasons: Vec<String>,
}

#[must_use]
pub fn resolve_container_executable(requested: Option<&Path>) -> ExecutableReport {
    let requested_path = requested.map(Path::to_path_buf);
    let candidate = match requested {
        Some(path) if !path.is_absolute() => {
            return missing(
                requested_path,
                "configured container executable must be absolute",
            );
        }
        Some(path) => path.to_path_buf(),
        None => {
            let Some(path) = SEARCH_DIRECTORIES
                .iter()
                .map(|directory| Path::new(directory).join("container"))
                .find(|path| path.exists())
            else {
                return missing(
                    None,
                    "container executable was not found in trusted search directories",
                );
            };
            path
        }
    };
    inspect(requested_path, candidate)
}

fn inspect(requested_path: Option<PathBuf>, candidate: PathBuf) -> ExecutableReport {
    let original = candidate.clone();
    let mut current = candidate;
    let mut visited = BTreeSet::new();
    let mut symlink_chain = Vec::new();
    let mut reasons = Vec::new();

    for _ in 0..16 {
        if !visited.insert(current.clone()) {
            return missing_with_chain(
                requested_path,
                symlink_chain,
                "container executable symlink chain contains a loop",
            );
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) => {
                return missing_with_chain(
                    requested_path,
                    symlink_chain,
                    format!("cannot inspect container executable: {error}"),
                );
            }
        };
        if !metadata.file_type().is_symlink() {
            break;
        }
        symlink_chain.push(current.clone());
        let target = match fs::read_link(&current) {
            Ok(target) => target,
            Err(error) => {
                return missing_with_chain(
                    requested_path,
                    symlink_chain,
                    format!("cannot read container executable symlink: {error}"),
                );
            }
        };
        current = if target.is_absolute() {
            target
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .join(target)
        };
    }

    let resolved_path = match fs::canonicalize(&current) {
        Ok(path) => path,
        Err(error) => {
            return missing_with_chain(
                requested_path,
                symlink_chain,
                format!("cannot canonicalize container executable: {error}"),
            );
        }
    };
    let metadata = match fs::metadata(&resolved_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return missing_with_chain(
                requested_path,
                symlink_chain,
                format!("cannot inspect resolved container executable: {error}"),
            );
        }
    };
    if !metadata.is_file() {
        reasons.push("resolved container executable is not a regular file".to_owned());
    }

    #[cfg(unix)]
    let (owner_uid, mode) = {
        use std::os::unix::fs::MetadataExt;
        let owner_uid = metadata.uid();
        let mode = metadata.mode() & 0o7777;
        if owner_uid != 0 {
            reasons.push(format!(
                "resolved container executable is owned by uid {owner_uid}, not root"
            ));
        }
        if mode & 0o022 != 0 {
            reasons.push(
                "resolved container executable is writable by group or other users".to_owned(),
            );
        }
        inspect_ancestors(&original, &mut reasons);
        inspect_ancestors(&resolved_path, &mut reasons);
        (Some(owner_uid), Some(mode))
    };
    #[cfg(not(unix))]
    let (owner_uid, mode) = {
        reasons.push("container executable trust validation requires Unix metadata".to_owned());
        (None, None)
    };

    reasons.sort();
    reasons.dedup();
    ExecutableReport {
        requested_path,
        resolved_path: Some(resolved_path),
        symlink_chain,
        owner_uid,
        mode,
        trusted: reasons.is_empty(),
        reasons,
    }
}

#[cfg(unix)]
fn inspect_ancestors(path: &Path, reasons: &mut Vec<String>) {
    use std::os::unix::fs::MetadataExt;

    for ancestor in path.ancestors().skip(1) {
        let Ok(metadata) = fs::metadata(ancestor) else {
            reasons.push(format!(
                "cannot inspect executable ancestor {}",
                ancestor.display()
            ));
            continue;
        };
        let mode = metadata.mode() & 0o7777;
        if metadata.uid() != 0 {
            reasons.push(format!(
                "executable ancestor {} is not root-owned",
                ancestor.display()
            ));
        }
        if mode & 0o022 != 0 {
            reasons.push(format!(
                "executable ancestor {} is writable by group or other users",
                ancestor.display()
            ));
        }
    }
}

fn missing(requested_path: Option<PathBuf>, reason: impl Into<String>) -> ExecutableReport {
    missing_with_chain(requested_path, Vec::new(), reason)
}

fn missing_with_chain(
    requested_path: Option<PathBuf>,
    symlink_chain: Vec<PathBuf>,
    reason: impl Into<String>,
) -> ExecutableReport {
    ExecutableReport {
        requested_path,
        resolved_path: None,
        symlink_chain,
        owner_uid: None,
        mode: None,
        trusted: false,
        reasons: vec![reason.into()],
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn rejects_relative_and_user_owned_executables() {
        assert!(!resolve_container_executable(Some(Path::new("container"))).trusted);
        let directory = tempdir().expect("directory");
        let executable = directory.path().join("container");
        fs::write(&executable, b"fixture").expect("write");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("mode");
        let report = resolve_container_executable(Some(&executable));
        assert!(!report.trusted);
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.contains("not root"))
        );
    }
}
