use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_SEARCH_DIRECTORIES: &[&str] =
    &["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutableReport {
    pub requested_path: Option<PathBuf>,
    pub resolved_path: Option<PathBuf>,
    pub symlink_chain: Vec<PathBuf>,
    pub regular_file: bool,
    pub owner_uid: Option<u32>,
    pub mode_octal: Option<String>,
    pub writable_by_group_or_other: bool,
    pub trusted: bool,
    pub reasons: Vec<String>,
}

impl ExecutableReport {
    #[must_use]
    pub fn missing(requested_path: Option<PathBuf>, reason: impl Into<String>) -> Self {
        Self {
            requested_path,
            resolved_path: None,
            symlink_chain: Vec::new(),
            regular_file: false,
            owner_uid: None,
            mode_octal: None,
            writable_by_group_or_other: false,
            trusted: false,
            reasons: vec![reason.into()],
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExecutableResolver {
    search_directories: Vec<PathBuf>,
}

impl Default for ExecutableResolver {
    fn default() -> Self {
        Self {
            search_directories: DEFAULT_SEARCH_DIRECTORIES
                .iter()
                .map(PathBuf::from)
                .collect(),
        }
    }
}

impl ExecutableResolver {
    #[must_use]
    pub fn with_search_directories(search_directories: Vec<PathBuf>) -> Self {
        Self { search_directories }
    }

    #[must_use]
    pub fn resolve(&self, requested: Option<&Path>) -> ExecutableReport {
        let requested_path = requested.map(Path::to_path_buf);
        let candidate = match requested {
            Some(path) if !path.is_absolute() => {
                return ExecutableReport::missing(
                    requested_path,
                    "configured executable path must be absolute",
                );
            }
            Some(path) => path.to_path_buf(),
            None => {
                let Some(path) = self
                    .search_directories
                    .iter()
                    .map(|directory| directory.join("container"))
                    .find(|path| path.exists())
                else {
                    return ExecutableReport::missing(
                        None,
                        "container executable was not found in trusted search directories",
                    );
                };
                path
            }
        };

        inspect_candidate(requested_path, candidate)
    }
}

fn inspect_candidate(requested_path: Option<PathBuf>, candidate: PathBuf) -> ExecutableReport {
    let candidate_for_trust = candidate.clone();
    let mut current = candidate;
    let mut symlink_chain = Vec::new();
    let mut visited = BTreeSet::new();
    let mut reasons = Vec::new();

    for _ in 0..16 {
        if !visited.insert(current.clone()) {
            reasons.push("executable symlink chain contains a loop".to_owned());
            return untrusted(requested_path, symlink_chain, reasons);
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) => {
                reasons.push(format!("cannot inspect executable: {error}"));
                return untrusted(requested_path, symlink_chain, reasons);
            }
        };
        if !metadata.file_type().is_symlink() {
            break;
        }
        symlink_chain.push(current.clone());
        let target = match fs::read_link(&current) {
            Ok(target) => target,
            Err(error) => {
                reasons.push(format!("cannot read executable symlink: {error}"));
                return untrusted(requested_path, symlink_chain, reasons);
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
            reasons.push(format!("cannot resolve executable path: {error}"));
            return untrusted(requested_path, symlink_chain, reasons);
        }
    };
    let metadata = match fs::metadata(&resolved_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            reasons.push(format!("cannot inspect resolved executable: {error}"));
            return untrusted(requested_path, symlink_chain, reasons);
        }
    };
    let regular_file = metadata.is_file();
    if !regular_file {
        reasons.push("resolved executable is not a regular file".to_owned());
    }

    #[cfg(unix)]
    let (owner_uid, mode, writable) = {
        use std::os::unix::fs::MetadataExt;
        let owner_uid = metadata.uid();
        let mode = metadata.mode() & 0o7777;
        let writable = mode & 0o022 != 0;
        if owner_uid != 0 {
            reasons.push(format!(
                "resolved executable is owned by uid {owner_uid}, not root"
            ));
        }
        if writable {
            reasons.push("resolved executable is writable by group or others".to_owned());
        }
        (Some(owner_uid), Some(format!("{mode:04o}")), writable)
    };
    #[cfg(unix)]
    {
        inspect_ancestor_trust(&candidate_for_trust, &mut reasons);
        inspect_ancestor_trust(&resolved_path, &mut reasons);
        reasons.sort();
        reasons.dedup();
    }

    #[cfg(not(unix))]
    let (owner_uid, mode, writable) = {
        reasons.push("executable ownership checks require a Unix host".to_owned());
        (None, None, false)
    };

    ExecutableReport {
        requested_path,
        resolved_path: Some(resolved_path),
        symlink_chain,
        regular_file,
        owner_uid,
        mode_octal: mode,
        writable_by_group_or_other: writable,
        trusted: reasons.is_empty(),
        reasons,
    }
}

#[cfg(unix)]
fn inspect_ancestor_trust(path: &Path, reasons: &mut Vec<String>) {
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
                "executable ancestor {} is writable by group or others",
                ancestor.display()
            ));
        }
    }
}

fn untrusted(
    requested_path: Option<PathBuf>,
    symlink_chain: Vec<PathBuf>,
    reasons: Vec<String>,
) -> ExecutableReport {
    ExecutableReport {
        requested_path,
        resolved_path: None,
        symlink_chain,
        regular_file: false,
        owner_uid: None,
        mode_octal: None,
        writable_by_group_or_other: false,
        trusted: false,
        reasons,
    }
}
