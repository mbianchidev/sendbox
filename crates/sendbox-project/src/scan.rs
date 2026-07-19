use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{ProjectError, Result};

const RELEVANT_FILES: &[&str] = &[
    ".dockerignore",
    ".python-version",
    "Cargo.toml",
    "CMakeLists.txt",
    "Dockerfile",
    "Gemfile",
    "Makefile",
    "Package.swift",
    "Pipfile",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "go.mod",
    "mix.exs",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "tsconfig.json",
    "yarn.lock",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanLimits {
    pub max_depth: usize,
    pub max_files: usize,
    pub max_bytes: u64,
    pub max_file_bytes: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_depth: 12,
            max_files: 4096,
            max_bytes: 8 * 1024 * 1024,
            max_file_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanIssueKind {
    Symlink,
    DepthLimit,
    FileLimit,
    ByteLimit,
    FileTooLarge,
    PermissionDenied,
    Io,
    ChangedDuringScan,
    ManifestParse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanIssue {
    pub path: String,
    pub kind: ScanIssueKind,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub limits: ScanLimits,
    pub files_seen: usize,
    pub bytes_read: u64,
    pub skipped: Vec<ScanIssue>,
    pub errors: Vec<ScanIssue>,
}

#[derive(Debug)]
pub(crate) struct ProjectSnapshot {
    pub files: Vec<String>,
    pub contents: BTreeMap<String, String>,
    pub report: ScanReport,
}

pub(crate) fn scan(root: &Path, limits: ScanLimits) -> Result<ProjectSnapshot> {
    let root = fs::canonicalize(root)
        .map_err(|source| ProjectError::io(root, source))
        .and_then(|canonical| {
            if canonical.is_dir() {
                Ok(canonical)
            } else {
                Err(ProjectError::InvalidProjectRoot(canonical))
            }
        })?;

    let mut report = ScanReport {
        limits,
        files_seen: 0,
        bytes_read: 0,
        skipped: Vec::new(),
        errors: Vec::new(),
    };
    let mut files = Vec::new();
    let mut contents = BTreeMap::new();
    let mut directories = vec![(root.clone(), PathBuf::new(), 0_usize)];
    let mut file_limit_reached = false;

    while let Some((directory, relative_directory, depth)) = directories.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                report.errors.push(io_issue(&relative_directory, error));
                continue;
            }
        };
        let mut entries = match entries.collect::<std::result::Result<Vec<_>, _>>() {
            Ok(entries) => entries,
            Err(error) => {
                report.errors.push(io_issue(&relative_directory, error));
                continue;
            }
        };
        entries.sort_by_key(|entry| entry.file_name());

        let mut child_directories = Vec::new();
        for entry in entries {
            let relative = relative_directory.join(entry.file_name());
            let relative_text = path_text(&relative);
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) => {
                    report.errors.push(io_issue(&relative, error));
                    continue;
                }
            };

            if metadata.file_type().is_symlink() {
                report.skipped.push(ScanIssue {
                    path: relative_text,
                    kind: ScanIssueKind::Symlink,
                    message: "symbolic links are never followed".to_owned(),
                });
                continue;
            }

            if metadata.is_dir() {
                if depth >= limits.max_depth {
                    report.skipped.push(ScanIssue {
                        path: relative_text,
                        kind: ScanIssueKind::DepthLimit,
                        message: format!("maximum scan depth {} reached", limits.max_depth),
                    });
                } else {
                    child_directories.push((entry.path(), relative, depth + 1));
                }
                continue;
            }

            if !metadata.is_file() {
                continue;
            }
            if report.files_seen >= limits.max_files {
                report.skipped.push(ScanIssue {
                    path: relative_text,
                    kind: ScanIssueKind::FileLimit,
                    message: format!("maximum file count {} reached", limits.max_files),
                });
                file_limit_reached = true;
                break;
            }

            report.files_seen += 1;
            files.push(relative_text.clone());
            if !is_relevant(&relative) {
                continue;
            }
            if metadata.len() > limits.max_file_bytes {
                report.skipped.push(ScanIssue {
                    path: relative_text,
                    kind: ScanIssueKind::FileTooLarge,
                    message: format!(
                        "file is {} bytes; per-file limit is {}",
                        metadata.len(),
                        limits.max_file_bytes
                    ),
                });
                continue;
            }
            if report.bytes_read.saturating_add(metadata.len()) > limits.max_bytes {
                report.skipped.push(ScanIssue {
                    path: relative_text,
                    kind: ScanIssueKind::ByteLimit,
                    message: format!("total byte limit {} reached", limits.max_bytes),
                });
                continue;
            }

            match read_stable_file(&entry.path(), &metadata, limits.max_file_bytes) {
                Ok(content) => {
                    report.bytes_read += content.len() as u64;
                    contents.insert(relative_text, content);
                }
                Err(issue) => report.errors.push(ScanIssue {
                    path: relative_text,
                    ..issue
                }),
            }
        }

        if file_limit_reached {
            break;
        }
        child_directories.reverse();
        directories.extend(child_directories);
    }

    files.sort();
    report
        .skipped
        .sort_by(|left, right| left.path.cmp(&right.path));
    report
        .errors
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(ProjectSnapshot {
        files,
        contents,
        report,
    })
}

fn is_relevant(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    RELEVANT_FILES.contains(&name) || name.ends_with(".csproj") || name.ends_with(".fsproj")
}

fn read_stable_file(
    path: &Path,
    before: &fs::Metadata,
    limit: u64,
) -> std::result::Result<String, ScanIssue> {
    let mut file = File::open(path).map_err(file_issue)?;
    let after = file.metadata().map_err(file_issue)?;
    if !same_file(before, &after) {
        return Err(ScanIssue {
            path: String::new(),
            kind: ScanIssueKind::ChangedDuringScan,
            message: "file identity changed while it was being opened".to_owned(),
        });
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(file_issue)?;
    if bytes.len() as u64 > limit {
        return Err(ScanIssue {
            path: String::new(),
            kind: ScanIssueKind::FileTooLarge,
            message: format!("file exceeded the per-file limit of {limit} bytes while reading"),
        });
    }
    String::from_utf8(bytes).map_err(|error| ScanIssue {
        path: String::new(),
        kind: ScanIssueKind::ManifestParse,
        message: format!("manifest is not valid UTF-8: {error}"),
    })
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.file_type() == right.file_type()
}

fn file_issue(error: std::io::Error) -> ScanIssue {
    let kind = if error.kind() == std::io::ErrorKind::PermissionDenied {
        ScanIssueKind::PermissionDenied
    } else {
        ScanIssueKind::Io
    };
    ScanIssue {
        path: String::new(),
        kind,
        message: error.to_string(),
    }
}

fn io_issue(path: &Path, error: std::io::Error) -> ScanIssue {
    let mut issue = file_issue(error);
    issue.path = path_text(path);
    issue
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
