use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use sendbox_policy::{PackageAnalysisLimits, PackageFindingKind};
use serde::Deserialize;
use tar::Archive;

use crate::{
    ArchiveEntry, ArchiveEntryKind, ArtifactDescriptor, NormalizedManifest, RawFinding,
    RegistryError, RegistryResult,
};

const PACKAGE_JSON_PATHS: [&str; 2] = ["package/package.json", "package.json"];
const LIFECYCLE_SCRIPTS: [&str; 8] = [
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishonly",
    "publish",
    "postpublish",
];

pub(crate) fn normalize_npm_manifest(
    artifact: &Path,
    descriptor: &ArtifactDescriptor,
    limits: &PackageAnalysisLimits,
) -> RegistryResult<NormalizedManifest> {
    let deadline = deadline(limits.scan_timeout_secs);
    let mut manifest = None;
    visit_archive(artifact, limits, deadline, |entry, reader| {
        if PACKAGE_JSON_PATHS.contains(&entry.path.as_str()) {
            if manifest.is_some() {
                return Err(RegistryError::Inspection(
                    "npm archive contains multiple package manifests".to_owned(),
                ));
            }
            if entry.size > limits.max_entry_bytes {
                return Err(RegistryError::Finding {
                    kind: PackageFindingKind::OversizedEntry,
                    message: "npm package manifest exceeds the entry limit".to_owned(),
                });
            }
            let capacity = usize::try_from(entry.size).map_err(|_| {
                RegistryError::Inspection("npm package manifest is too large".to_owned())
            })?;
            let mut bytes = Vec::with_capacity(capacity);
            reader
                .take(limits.max_entry_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    RegistryError::Inspection(format!("read package.json: {error}"))
                })?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limits.max_entry_bytes {
                return Err(RegistryError::Finding {
                    kind: PackageFindingKind::OversizedEntry,
                    message: "npm package manifest exceeds the entry limit".to_owned(),
                });
            }
            manifest = Some(parse_manifest(&bytes, descriptor)?);
        }
        Ok(())
    })?;
    manifest.ok_or_else(|| RegistryError::Inspection("npm archive omitted package.json".to_owned()))
}

pub fn enumerate_npm_archive(
    artifact: &Path,
    limits: &PackageAnalysisLimits,
) -> RegistryResult<Vec<ArchiveEntry>> {
    let deadline = deadline(limits.scan_timeout_secs);
    let mut entries = Vec::new();
    visit_archive(artifact, limits, deadline, |entry, _| {
        entries.push(entry);
        Ok(())
    })?;
    Ok(entries)
}

pub fn inspect_npm_archive(
    artifact: &Path,
    _descriptor: &ArtifactDescriptor,
    manifest: &NormalizedManifest,
    entries: &[ArchiveEntry],
    limits: &PackageAnalysisLimits,
) -> RegistryResult<Vec<RawFinding>> {
    let mut findings = structural_findings(manifest, entries, limits);
    let deadline = deadline(limits.scan_timeout_secs);
    let executable_paths = manifest
        .executable_paths
        .iter()
        .flat_map(|path| [path.clone(), format!("package/{path}")])
        .collect::<BTreeSet<_>>();
    let mut source_bytes = 0_u64;
    visit_archive(artifact, limits, deadline, |entry, reader| {
        if entry.kind != ArchiveEntryKind::File || entry.size > limits.max_entry_bytes {
            return Ok(());
        }
        let path = entry.path.to_ascii_lowercase();
        let should_read = executable_extension(&path)
            || source_extension(&path)
            || entry.mode & 0o111 != 0
            || path.ends_with("/package.json");
        if !should_read {
            return Ok(());
        }
        let remaining = limits.max_source_scan_bytes.saturating_sub(source_bytes);
        if entry.size > remaining {
            return Err(RegistryError::Finding {
                kind: PackageFindingKind::UnsupportedContent,
                message: "npm source scan exceeds the configured byte limit".to_owned(),
            });
        }
        let maximum = entry.size;
        let capacity = usize::try_from(maximum).map_err(|_| {
            RegistryError::Inspection("source scan byte limit is too large".to_owned())
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        reader
            .take(maximum)
            .read_to_end(&mut bytes)
            .map_err(|error| RegistryError::Inspection(format!("read {}: {error}", entry.path)))?;
        source_bytes = source_bytes
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| RegistryError::Inspection("source scan size overflowed".to_owned()))?;
        if entry.mode & 0o111 != 0 && !executable_paths.contains(&entry.path) {
            findings.push(finding(
                PackageFindingKind::UnexpectedExecutable,
                &entry.path,
                "regular file has executable mode bits but is not declared in package.json bin",
            ));
        }
        if path.ends_with(".node") {
            findings.push(finding(
                PackageFindingKind::NativeAddon,
                &entry.path,
                "native Node.js addon is present",
            ));
        } else if prebuilt_extension(&path) {
            findings.push(finding(
                PackageFindingKind::PrebuiltBinary,
                &entry.path,
                "prebuilt binary payload is present",
            ));
        }
        if executable_magic(&bytes) {
            findings.push(finding(
                PackageFindingKind::EmbeddedExecutable,
                &entry.path,
                "file content has a native executable or WebAssembly header",
            ));
        }
        if source_extension(&path)
            && let Ok(source) = std::str::from_utf8(&bytes)
        {
            inspect_source(source, &entry.path, &mut findings);
        }
        Ok(())
    })?;
    findings.sort();
    findings.dedup();
    let maximum = usize::try_from(limits.max_report_findings).unwrap_or(usize::MAX);
    if findings.len() > maximum {
        return Err(RegistryError::Finding {
            kind: PackageFindingKind::ScannerFailure,
            message: "npm findings exceed the report limit".to_owned(),
        });
    }
    Ok(findings)
}

fn structural_findings(
    manifest: &NormalizedManifest,
    entries: &[ArchiveEntry],
    limits: &PackageAnalysisLimits,
) -> Vec<RawFinding> {
    let mut findings = Vec::new();
    for (script, command) in &manifest.scripts {
        if LIFECYCLE_SCRIPTS.contains(&script.to_ascii_lowercase().as_str()) {
            findings.push(finding(
                PackageFindingKind::LifecycleScript,
                "package.json",
                &format!("lifecycle script `{script}` is declared: {command}"),
            ));
        }
    }
    let mut total = 0_u64;
    for entry in entries {
        total = total.saturating_add(entry.size);
        if entry.path.len() > usize::try_from(limits.max_path_bytes).unwrap_or(usize::MAX) {
            findings.push(finding(
                PackageFindingKind::UnsupportedContent,
                &entry.path,
                "archive path exceeds the configured limit",
            ));
        }
        if archive_path_unsafe(&entry.path) {
            let kind = if Path::new(&entry.path).is_absolute() || entry.path.starts_with('\\') {
                PackageFindingKind::AbsoluteArchivePath
            } else {
                PackageFindingKind::ArchiveTraversal
            };
            findings.push(finding(kind, &entry.path, "archive path escapes its root"));
        }
        if path_depth(&entry.path) > limits.max_depth {
            findings.push(finding(
                PackageFindingKind::UnsupportedContent,
                &entry.path,
                "archive path exceeds the configured depth",
            ));
        }
        if entry.size > limits.max_entry_bytes {
            findings.push(finding(
                PackageFindingKind::OversizedEntry,
                &entry.path,
                "archive entry exceeds the configured size",
            ));
        }
        match entry.kind {
            ArchiveEntryKind::Symlink => {
                if entry
                    .link_target
                    .as_deref()
                    .is_none_or(|target| link_escapes(&entry.path, target))
                {
                    findings.push(finding(
                        PackageFindingKind::UnsafeSymlink,
                        &entry.path,
                        "symbolic link target escapes the archive root",
                    ));
                }
            }
            ArchiveEntryKind::Hardlink => {
                if entry.link_target.as_deref().is_none_or(archive_path_unsafe) {
                    findings.push(finding(
                        PackageFindingKind::UnsafeHardlink,
                        &entry.path,
                        "hard-link target escapes the archive root",
                    ));
                }
            }
            ArchiveEntryKind::CharacterDevice | ArchiveEntryKind::BlockDevice => {
                findings.push(finding(
                    PackageFindingKind::DeviceEntry,
                    &entry.path,
                    "archive contains a device entry",
                ))
            }
            ArchiveEntryKind::Fifo => findings.push(finding(
                PackageFindingKind::FifoEntry,
                &entry.path,
                "archive contains a FIFO entry",
            )),
            ArchiveEntryKind::Sparse => findings.push(finding(
                PackageFindingKind::SparseEntry,
                &entry.path,
                "archive contains a sparse entry",
            )),
            ArchiveEntryKind::Other => findings.push(finding(
                PackageFindingKind::UnsupportedArchiveEntry,
                &entry.path,
                "archive contains an unsupported entry type",
            )),
            ArchiveEntryKind::File | ArchiveEntryKind::Directory => {}
        }
    }
    if total > limits.max_unpacked_bytes {
        findings.push(RawFinding {
            kind: PackageFindingKind::DecompressionLimit,
            path: None,
            detail: "declared archive size exceeds the unpacked byte limit".to_owned(),
        });
    }
    findings
}

fn visit_archive<F>(
    artifact: &Path,
    limits: &PackageAnalysisLimits,
    deadline: Instant,
    mut visitor: F,
) -> RegistryResult<()>
where
    F: FnMut(ArchiveEntry, &mut dyn Read) -> RegistryResult<()>,
{
    let metadata = std::fs::metadata(artifact).map_err(|error| {
        RegistryError::Inspection(format!("inspect archive {}: {error}", artifact.display()))
    })?;
    if metadata.len() > limits.max_download_bytes {
        return Err(RegistryError::Finding {
            kind: PackageFindingKind::OversizedEntry,
            message: "compressed archive exceeds the download limit".to_owned(),
        });
    }
    let file = File::open(artifact).map_err(|error| {
        RegistryError::Inspection(format!("open archive {}: {error}", artifact.display()))
    })?;
    let decoder = GzDecoder::new(BufReader::new(file));
    let bounded = BoundedReader::new(decoder, limits.max_unpacked_bytes);
    let mut archive = Archive::new(bounded);
    let entries = archive
        .entries()
        .map_err(|error| archive_error("read tar archive", error))?;
    let mut count = 0_u32;
    for entry in entries {
        check_deadline(deadline)?;
        count = count.checked_add(1).ok_or_else(|| {
            RegistryError::Inspection("archive entry count overflowed".to_owned())
        })?;
        if count > limits.max_entries {
            return Err(RegistryError::Finding {
                kind: PackageFindingKind::UnsupportedContent,
                message: "archive exceeds the configured entry count".to_owned(),
            });
        }
        let mut entry = entry.map_err(|error| archive_error("read tar entry", error))?;
        let path_bytes = entry.path_bytes();
        if path_bytes.len() > usize::try_from(limits.max_path_bytes).unwrap_or(usize::MAX) {
            return Err(RegistryError::Finding {
                kind: PackageFindingKind::UnsupportedContent,
                message: "archive path exceeds the configured byte limit".to_owned(),
            });
        }
        let path = std::str::from_utf8(path_bytes.as_ref())
            .map_err(|_| RegistryError::Unsupported("archive path is not UTF-8".to_owned()))?
            .to_owned();
        let size = entry
            .header()
            .size()
            .map_err(|error| RegistryError::Inspection(format!("read tar entry size: {error}")))?;
        let mode = entry
            .header()
            .mode()
            .map_err(|error| RegistryError::Inspection(format!("read tar entry mode: {error}")))?;
        let kind = entry_kind(entry.header().entry_type().as_byte());
        let link_target = if matches!(kind, ArchiveEntryKind::Symlink | ArchiveEntryKind::Hardlink)
        {
            entry
                .link_name()
                .map_err(|error| {
                    RegistryError::Inspection(format!("read tar link target: {error}"))
                })?
                .map(|path| {
                    path.to_str().map(str::to_owned).ok_or_else(|| {
                        RegistryError::Unsupported("archive link target is not UTF-8".to_owned())
                    })
                })
                .transpose()?
        } else {
            None
        };
        visitor(
            ArchiveEntry {
                path,
                kind,
                size,
                mode,
                link_target,
            },
            &mut entry,
        )?;
    }
    Ok(())
}

fn parse_manifest(
    bytes: &[u8],
    descriptor: &ArtifactDescriptor,
) -> RegistryResult<NormalizedManifest> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        name: String,
        version: String,
        #[serde(default)]
        scripts: BTreeMap<String, String>,
        #[serde(default)]
        bin: Option<Bin>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Bin {
        Path(String),
        Map(BTreeMap<String, String>),
    }

    let manifest: Manifest = serde_json::from_slice(bytes)
        .map_err(|error| RegistryError::Inspection(format!("decode package.json: {error}")))?;
    if manifest.name != descriptor.identity.name || manifest.version != descriptor.identity.version
    {
        return Err(RegistryError::Finding {
            kind: PackageFindingKind::IdentityMismatch,
            message: format!(
                "package.json identity {}@{} does not match requested {}@{}",
                manifest.name,
                manifest.version,
                descriptor.identity.name,
                descriptor.identity.version
            ),
        });
    }
    let executable_paths = match manifest.bin {
        None => Vec::new(),
        Some(Bin::Path(path)) => vec![normalize_manifest_path(&path)?],
        Some(Bin::Map(paths)) => paths
            .values()
            .map(|path| normalize_manifest_path(path))
            .collect::<RegistryResult<Vec<_>>>()?,
    };
    Ok(NormalizedManifest {
        identity: descriptor.identity.clone(),
        scripts: manifest.scripts,
        executable_paths,
        metadata: BTreeMap::new(),
    })
}

fn normalize_manifest_path(path: &str) -> RegistryResult<String> {
    let path = path.strip_prefix("./").unwrap_or(path);
    if archive_path_unsafe(path) {
        return Err(RegistryError::Inspection(
            "package.json bin path escapes the package root".to_owned(),
        ));
    }
    Ok(path.to_owned())
}

fn inspect_source(source: &str, path: &str, findings: &mut Vec<RawFinding>) {
    let mut normalized = source.to_ascii_lowercase();
    normalized.retain(|character| !character.is_ascii_whitespace());
    for concatenation in ["'+'", "\"+\"", "`+`"] {
        normalized = normalized.replace(concatenation, "");
    }
    let child_process = normalized.contains("child_process")
        || normalized.contains("node:child_process")
        || normalized.contains("['child','process'].join('_')")
        || normalized.contains("[\"child\",\"process\"].join(\"_\")");
    let subprocess = [".spawn(", ".spawnsync(", ".exec(", ".execfile(", ".fork("]
        .iter()
        .any(|needle| normalized.contains(needle))
        || ["['spawn'](", "[\"spawn\"](", "['exec'](", "[\"exec\"]("]
            .iter()
            .any(|needle| normalized.contains(needle));
    if child_process && subprocess {
        findings.push(finding(
            PackageFindingKind::SubprocessApi,
            path,
            "source invokes a Node.js child_process API",
        ));
    }
    if normalized.contains("shelljs")
        || normalized.contains("cross-spawn")
        || normalized.contains("execa(")
        || normalized.contains("shell:true")
        || normalized.contains("/bin/sh")
        || normalized.contains("bash-c")
        || normalized.contains("sh-c")
    {
        findings.push(finding(
            PackageFindingKind::ShellApi,
            path,
            "source invokes or enables a shell wrapper",
        ));
    }
}

fn finding(kind: PackageFindingKind, path: &str, detail: &str) -> RawFinding {
    RawFinding {
        kind,
        path: Some(path.to_owned()),
        detail: detail.to_owned(),
    }
}

fn archive_path_unsafe(path: &str) -> bool {
    path.is_empty()
        || path.contains('\\')
        || Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
}

fn path_depth(path: &str) -> u32 {
    u32::try_from(Path::new(path).components().count()).unwrap_or(u32::MAX)
}

fn link_escapes(entry: &str, target: &str) -> bool {
    if target.contains('\\') || Path::new(target).is_absolute() {
        return true;
    }
    let mut depth = Path::new(entry)
        .parent()
        .map(|parent| {
            parent
                .components()
                .filter(|component| matches!(component, Component::Normal(_)))
                .count()
        })
        .unwrap_or(0);
    for component in Path::new(target).components() {
        match component {
            Component::Normal(_) => depth = depth.saturating_add(1),
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return true,
        }
    }
    false
}

fn entry_kind(value: u8) -> ArchiveEntryKind {
    match value {
        0 | b'0' => ArchiveEntryKind::File,
        b'1' => ArchiveEntryKind::Hardlink,
        b'2' => ArchiveEntryKind::Symlink,
        b'3' => ArchiveEntryKind::CharacterDevice,
        b'4' => ArchiveEntryKind::BlockDevice,
        b'5' => ArchiveEntryKind::Directory,
        b'6' => ArchiveEntryKind::Fifo,
        b'S' => ArchiveEntryKind::Sparse,
        _ => ArchiveEntryKind::Other,
    }
}

fn source_extension(path: &str) -> bool {
    [".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx"]
        .iter()
        .any(|extension| path.ends_with(extension))
}

fn executable_extension(path: &str) -> bool {
    prebuilt_extension(path) || path.ends_with(".node")
}

fn prebuilt_extension(path: &str) -> bool {
    [".exe", ".dll", ".so", ".dylib", ".wasm"]
        .iter()
        .any(|extension| path.ends_with(extension))
}

fn executable_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\0asm")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

fn deadline(timeout_secs: u32) -> Instant {
    Instant::now() + Duration::from_secs(u64::from(timeout_secs))
}

fn check_deadline(deadline: Instant) -> RegistryResult<()> {
    if Instant::now() > deadline {
        Err(RegistryError::Timeout(
            "npm archive scan exceeded its deadline".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn archive_error(action: &str, error: io::Error) -> RegistryError {
    if error
        .to_string()
        .contains("decompressed archive exceeds byte limit")
    {
        RegistryError::Finding {
            kind: PackageFindingKind::DecompressionLimit,
            message: "decompressed archive exceeds the configured byte limit".to_owned(),
        }
    } else {
        RegistryError::Inspection(format!("{action}: {error}"))
    }
}

struct BoundedReader<R> {
    inner: R,
    consumed: u64,
    maximum: u64,
}

impl<R> BoundedReader<R> {
    const fn new(inner: R, maximum: u64) -> Self {
        Self {
            inner,
            consumed: 0,
            maximum,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.maximum.saturating_sub(self.consumed);
        if remaining == 0 {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other("decompressed archive exceeds byte limit")),
            };
        }
        let maximum = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = self.inner.read(&mut buffer[..maximum])?;
        self.consumed = self
            .consumed
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| io::Error::other("decompressed byte count overflowed"))?;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use sendbox_policy::PackageEcosystem;
    use tar::{Builder, EntryType, Header};
    use tempfile::tempdir;

    use super::*;
    use crate::{IntegrityClaim, IntegritySource, PackageIdentity};

    fn descriptor() -> ArtifactDescriptor {
        ArtifactDescriptor {
            identity: PackageIdentity {
                ecosystem: PackageEcosystem::Npm,
                name: "fixture".to_owned(),
                version: "1.0.0".to_owned(),
            },
            source_url: "https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz".to_owned(),
            integrity: vec![IntegrityClaim {
                algorithm: crate::IntegrityAlgorithm::Sha512,
                digest: vec![0; 64],
                source: IntegritySource::Sri,
            }],
            signature_integrity: "sha512-placeholder".to_owned(),
            metadata_revision: "1-a".to_owned(),
            published_at: None,
            signatures: Vec::new(),
            provenance: None,
        }
    }

    fn archive(entries: &[(&str, u32, &[u8])]) -> (tempfile::TempDir, PathBuf) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("fixture.tgz");
        let file = File::create(&path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        for (path, mode, bytes) in entries {
            let mut header = Header::new_gnu();
            header.set_size(u64::try_from(bytes.len()).unwrap());
            header.set_mode(*mode);
            header.set_entry_type(EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
        (directory, path)
    }

    #[test]
    fn benign_package_has_no_findings() {
        let manifest = br#"{"name":"fixture","version":"1.0.0","bin":{"fixture":"cli.js"}}"#;
        let (_directory, path) = archive(&[
            ("package/package.json", 0o644, manifest),
            ("package/index.js", 0o644, b"module.exports = 1"),
            ("package/cli.js", 0o755, b"console.log('ok')"),
        ]);
        let limits = PackageAnalysisLimits::default();
        let normalized = normalize_npm_manifest(&path, &descriptor(), &limits).unwrap();
        let entries = enumerate_npm_archive(&path, &limits).unwrap();
        let findings =
            inspect_npm_archive(&path, &descriptor(), &normalized, &entries, &limits).unwrap();
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn lifecycle_subprocess_native_and_executable_payloads_are_found() {
        let manifest = br#"{
            "name":"fixture",
            "version":"1.0.0",
            "scripts":{"install":"node install.js"}
        }"#;
        let source = b"const cp = require('child' + '_process'); cp['exec']('id')";
        let (_directory, path) = archive(&[
            ("package/package.json", 0o644, manifest),
            ("package/install.js", 0o755, source),
            ("package/addon.node", 0o644, b"\x7fELFpayload"),
        ]);
        let limits = PackageAnalysisLimits::default();
        let normalized = normalize_npm_manifest(&path, &descriptor(), &limits).unwrap();
        let entries = enumerate_npm_archive(&path, &limits).unwrap();
        let findings =
            inspect_npm_archive(&path, &descriptor(), &normalized, &entries, &limits).unwrap();
        let kinds = findings
            .iter()
            .map(|finding| finding.kind)
            .collect::<BTreeSet<_>>();
        for expected in [
            PackageFindingKind::LifecycleScript,
            PackageFindingKind::SubprocessApi,
            PackageFindingKind::UnexpectedExecutable,
            PackageFindingKind::NativeAddon,
            PackageFindingKind::EmbeddedExecutable,
        ] {
            assert!(
                kinds.contains(&expected),
                "missing {expected:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn unsafe_links_and_special_entries_are_found() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("fixture.tgz");
        let file = File::create(&path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        let manifest = br#"{"name":"fixture","version":"1.0.0"}"#;
        let mut header = Header::new_gnu();
        header.set_size(u64::try_from(manifest.len()).unwrap());
        header.set_mode(0o644);
        header.set_entry_type(EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", manifest.as_slice())
            .unwrap();

        let mut link = Header::new_gnu();
        link.set_size(0);
        link.set_mode(0o777);
        link.set_entry_type(EntryType::Symlink);
        link.set_link_name("../../outside").unwrap();
        link.set_cksum();
        builder
            .append_data(&mut link, "package/link", io::empty())
            .unwrap();

        let mut fifo = Header::new_gnu();
        fifo.set_size(0);
        fifo.set_mode(0o644);
        fifo.set_entry_type(EntryType::Fifo);
        fifo.set_cksum();
        builder
            .append_data(&mut fifo, "package/pipe", io::empty())
            .unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();

        let limits = PackageAnalysisLimits::default();
        let normalized = normalize_npm_manifest(&path, &descriptor(), &limits).unwrap();
        let entries = enumerate_npm_archive(&path, &limits).unwrap();
        let findings =
            inspect_npm_archive(&path, &descriptor(), &normalized, &entries, &limits).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == PackageFindingKind::UnsafeSymlink)
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == PackageFindingKind::FifoEntry)
        );
    }

    #[test]
    fn decompression_limit_fails_closed() {
        let manifest = br#"{"name":"fixture","version":"1.0.0"}"#;
        let (_directory, path) = archive(&[("package/package.json", 0o644, manifest)]);
        let limits = PackageAnalysisLimits {
            max_unpacked_bytes: 16,
            ..PackageAnalysisLimits::default()
        };
        assert!(enumerate_npm_archive(&path, &limits).is_err());
    }
}
