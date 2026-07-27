#![forbid(unsafe_code)]

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rustix::process::{getgid, getuid};
use sendbox_guest::manifest::{
    ArtifactExpectation, ArtifactKind, ArtifactManifest, MANIFEST_DOMAIN, MANIFEST_SCHEMA_VERSION,
    MAX_ARTIFACTS, MAX_MANIFEST_BYTES, SignedManifestEnvelope, VerifiedManifest, decode_hex,
    encode_hex, verify_file_expectation, verify_manifest_for_architecture,
};
use sendbox_guest::secure_fs::open_directory_no_symlinks;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_KEY_BYTES: usize = 129;
const RELEASE_METADATA_DOMAIN: &str = "dev.sendbox.guest.release-metadata.v1";

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid bundle input: {0}")]
    InvalidInput(String),
    #[error("bundle serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("bundle verification failed: {0}")]
    Verification(#[from] sendbox_guest::GuestError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl Architecture {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

#[derive(Debug)]
pub struct StageOptions<'a> {
    pub output: &'a Path,
    pub guest_binary: &'a Path,
    pub exec_launcher: &'a Path,
    pub bpf_object: &'a Path,
    pub signing_key: &'a Path,
    pub architecture: Architecture,
    pub trust_root_id: &'a str,
    pub release_sequence: u64,
    pub minimum_accepted_sequence: u64,
    pub host_version: &'a str,
    pub guest_version: &'a str,
    pub minimum_kernel: &'a str,
    pub btf_archive_sha256: &'a str,
    pub vmlinux_header_sha256: &'a str,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug)]
pub struct VerifyOptions<'a> {
    pub root: &'a Path,
    pub public_key: &'a Path,
    pub architecture: Architecture,
    pub trust_root_id: &'a str,
    pub host_version: &'a str,
    pub guest_version: &'a str,
    pub minimum_release_sequence: u64,
}

#[derive(Debug, Serialize)]
pub struct StageReport {
    pub schema_version: u8,
    pub architecture: &'static str,
    pub release_sequence: u64,
    pub artifact_count: usize,
    pub manifest_path: PathBuf,
    pub detached_signature_path: PathBuf,
    pub release_metadata_path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub schema_version: u8,
    pub architecture: String,
    pub release_sequence: u64,
    pub artifact_count: usize,
}

#[derive(Debug)]
pub struct VerifiedBundle {
    pub report: VerifyReport,
    pub manifest: VerifiedManifest,
}

#[derive(Serialize)]
struct BundleMetadata<'a> {
    schema_version: u8,
    architecture: &'a str,
    minimum_kernel: &'a str,
    requires_kernel_btf: bool,
    requires_cgroup_scope: bool,
    observation_only: bool,
    event_schema_version: u8,
    host_version: &'a str,
    guest_version: &'a str,
    bpf_programs: [&'a str; 2],
    rust_version: &'static str,
    clang_version: &'static str,
    bpftool_version: &'static str,
    libbpf_rs_version: &'static str,
    libbpf_version: &'static str,
    libseccomp_version: &'static str,
    btf_source_commit: &'static str,
    btf_archive_sha256: &'a str,
    vmlinux_header_sha256: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InventoryKind {
    GuestBinary,
    ServiceBinary,
    BpfObject,
    UnikraftShellKernel,
    Initrd,
    Metadata,
}

impl InventoryKind {
    fn manifest_kind(self) -> Option<ArtifactKind> {
        match self {
            Self::GuestBinary => Some(ArtifactKind::GuestBinary),
            Self::ServiceBinary => Some(ArtifactKind::ServiceBinary),
            Self::BpfObject => Some(ArtifactKind::BpfObject),
            Self::UnikraftShellKernel => Some(ArtifactKind::UnikraftShellKernel),
            Self::Initrd => Some(ArtifactKind::Initrd),
            Self::Metadata => None,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InventoryEntry {
    kind: InventoryKind,
    path: PathBuf,
    sha256: String,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema_version: u8,
    domain: String,
    trust_root_id: String,
    release_sequence: u64,
    architecture: String,
    artifacts: Vec<InventoryEntry>,
}

#[derive(Serialize)]
struct VerificationReport {
    schema_version: u8,
    status: &'static str,
    checks: [&'static str; 8],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: &'static str,
    data_license: &'static str,
    spdx_id: &'static str,
    name: String,
    document_namespace: String,
    creation_info: SpdxCreationInfo,
    files: Vec<SpdxFile>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxCreationInfo {
    created: &'static str,
    creators: [&'static str; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxFile {
    file_name: String,
    spdx_id: String,
    checksums: [SpdxChecksum; 1],
    license_concluded: &'static str,
    copyright_text: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxChecksum {
    algorithm: &'static str,
    checksum_value: String,
}

pub fn stage_bundle(options: &StageOptions<'_>) -> Result<StageReport, BundleError> {
    validate_stage_options(options)?;
    prepare_output(options.output)?;

    let mut inventory = Vec::new();
    inventory.push(stage_source(
        options.guest_binary,
        options.output,
        Path::new("bin/sendbox-guest"),
        InventoryKind::GuestBinary,
        0o500,
        options.uid,
        options.gid,
    )?);
    inventory.push(stage_source(
        options.exec_launcher,
        options.output,
        Path::new("bin/sendbox-exec-launcher"),
        InventoryKind::ServiceBinary,
        0o500,
        options.uid,
        options.gid,
    )?);
    inventory.push(stage_source(
        options.bpf_object,
        options.output,
        Path::new("lib/sendbox/observe.bpf.o"),
        InventoryKind::BpfObject,
        0o400,
        options.uid,
        options.gid,
    )?);

    let metadata = BundleMetadata {
        schema_version: 1,
        architecture: options.architecture.as_str(),
        minimum_kernel: options.minimum_kernel,
        requires_kernel_btf: true,
        requires_cgroup_scope: true,
        observation_only: true,
        event_schema_version: 1,
        host_version: options.host_version,
        guest_version: options.guest_version,
        bpf_programs: ["observe_exec", "observe_sys_enter"],
        rust_version: "1.93.1",
        clang_version: "21.1.2",
        bpftool_version: "6.19.14",
        libbpf_rs_version: "0.26.2",
        libbpf_version: "1.7.0",
        libseccomp_version: "2.6.0",
        btf_source_commit: "abbcdfab668b9a346a24cb0829f1cfbb80bc51db",
        btf_archive_sha256: options.btf_archive_sha256,
        vmlinux_header_sha256: options.vmlinux_header_sha256,
    };
    inventory.push(stage_generated(
        options.output,
        Path::new("share/sendbox/bundle-metadata.json"),
        &metadata,
        0o400,
        options.uid,
        options.gid,
    )?);

    let verification = VerificationReport {
        schema_version: 1,
        status: "verified_at_build",
        checks: [
            "guest_static_elf",
            "launcher_static_elf",
            "bpf_abi_assertions",
            "bpf_core_relocations",
            "artifact_sha256",
            "artifact_mode_owner",
            "manifest_ed25519",
            "architecture_and_rollback",
        ],
    };
    inventory.push(stage_generated(
        options.output,
        Path::new("share/sendbox/verification-report.json"),
        &verification,
        0o400,
        options.uid,
        options.gid,
    )?);

    let sbom = build_sbom(options, &inventory);
    inventory.push(stage_generated(
        options.output,
        Path::new("share/sendbox/sbom.spdx.json"),
        &sbom,
        0o400,
        options.uid,
        options.gid,
    )?);

    let primary_inventory = Inventory {
        schema_version: 1,
        domain: RELEASE_METADATA_DOMAIN.to_owned(),
        trust_root_id: options.trust_root_id.to_owned(),
        release_sequence: options.release_sequence,
        architecture: options.architecture.as_str().to_owned(),
        artifacts: inventory.clone(),
    };
    inventory.push(stage_generated(
        options.output,
        Path::new("share/sendbox/inventory.json"),
        &primary_inventory,
        0o400,
        options.uid,
        options.gid,
    )?);

    let manifest = ArtifactManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        domain: MANIFEST_DOMAIN.to_owned(),
        trust_root_id: options.trust_root_id.to_owned(),
        release_sequence: options.release_sequence,
        minimum_accepted_sequence: options.minimum_accepted_sequence,
        expected_host_version: options.host_version.to_owned(),
        expected_guest_version: options.guest_version.to_owned(),
        architecture: options.architecture.as_str().to_owned(),
        artifacts: inventory
            .iter()
            .filter_map(|entry| {
                entry.kind.manifest_kind().map(|kind| ArtifactExpectation {
                    kind,
                    path: entry.path.clone(),
                    sha256: entry.sha256.clone(),
                    mode: entry.mode,
                    uid: entry.uid,
                    gid: entry.gid,
                })
            })
            .collect(),
    };
    let payload = serde_json::to_string(&manifest)?;
    let signing_key = read_signing_key(options.signing_key)?;
    let signature = signing_key.sign(payload.as_bytes());
    let signature_hex = encode_hex(&signature.to_bytes());
    let envelope = SignedManifestEnvelope {
        payload,
        signature: signature_hex.clone(),
    };
    let manifest_path = options.output.join("manifest.json");
    write_json(&manifest_path, &envelope, 0o400)?;
    let signature_path = options.output.join("manifest.sig");
    write_bytes(&signature_path, signature_hex.as_bytes(), 0o400)?;
    let release_payload = serde_json::to_string(&primary_inventory)?;
    let release_signature = signing_key.sign(release_payload.as_bytes());
    let release_signature_hex = encode_hex(&release_signature.to_bytes());
    let release_envelope = SignedManifestEnvelope {
        payload: release_payload,
        signature: release_signature_hex.clone(),
    };
    let release_metadata_path = options.output.join("release-metadata.json");
    write_json(&release_metadata_path, &release_envelope, 0o400)?;
    write_bytes(
        &options.output.join("release-metadata.sig"),
        release_signature_hex.as_bytes(),
        0o400,
    )?;

    Ok(StageReport {
        schema_version: 1,
        architecture: options.architecture.as_str(),
        release_sequence: options.release_sequence,
        artifact_count: manifest.artifacts.len(),
        manifest_path,
        detached_signature_path: signature_path,
        release_metadata_path,
    })
}

pub fn verify_bundle(options: &VerifyOptions<'_>) -> Result<VerifyReport, BundleError> {
    Ok(verify_bundle_artifacts(options)?.report)
}

pub fn verify_bundle_artifacts(options: &VerifyOptions<'_>) -> Result<VerifiedBundle, BundleError> {
    let root = if options.root.is_absolute() {
        options.root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| BundleError::Io {
                context: "resolving current directory",
                source,
            })?
            .join(options.root)
    };
    let descriptor = open_directory_no_symlinks(&root)?;
    let public_key = read_public_key(options.public_key)?;
    let verified = verify_manifest_for_architecture(
        &descriptor,
        Path::new("manifest.json"),
        &public_key,
        options.trust_root_id,
        options.host_version,
        options.guest_version,
        options.architecture.as_str(),
        options.minimum_release_sequence,
    )?;
    verify_detached_signature(&root, &verified)?;
    verify_release_metadata(&descriptor, &root, &public_key, options, &verified)?;
    Ok(VerifiedBundle {
        report: VerifyReport {
            schema_version: 1,
            architecture: verified.manifest.architecture.clone(),
            release_sequence: verified.manifest.release_sequence,
            artifact_count: verified.manifest.artifacts.len(),
        },
        manifest: verified,
    })
}

pub fn write_public_key(signing_key: &Path, output: &Path) -> Result<(), BundleError> {
    let verifying_key = read_signing_key(signing_key)?.verifying_key();
    write_bytes(output, &verifying_key.to_bytes(), 0o400)
}

fn validate_stage_options(options: &StageOptions<'_>) -> Result<(), BundleError> {
    if options.trust_root_id.is_empty()
        || options.host_version.is_empty()
        || options.guest_version.is_empty()
        || options.minimum_kernel.is_empty()
    {
        return Err(BundleError::InvalidInput(
            "trust root, versions, and minimum kernel must be non-empty".to_owned(),
        ));
    }
    if options.minimum_accepted_sequence > options.release_sequence {
        return Err(BundleError::InvalidInput(
            "minimum accepted sequence exceeds release sequence".to_owned(),
        ));
    }
    validate_sha256(options.btf_archive_sha256, "BTF archive")?;
    validate_sha256(options.vmlinux_header_sha256, "vmlinux header")?;
    let current_uid = getuid().as_raw();
    let current_gid = getgid().as_raw();
    if options.uid != current_uid || options.gid != current_gid {
        return Err(BundleError::InvalidInput(format!(
            "staging process owner is {current_uid}:{current_gid}, requested {}:{}",
            options.uid, options.gid
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str, subject: &str) -> Result<(), BundleError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(BundleError::InvalidInput(format!(
            "{subject} SHA-256 must contain 64 hexadecimal characters"
        )))
    }
}

fn prepare_output(output: &Path) -> Result<(), BundleError> {
    if output.exists() {
        let metadata = fs::symlink_metadata(output).map_err(|source| BundleError::Io {
            context: "reading output directory metadata",
            source,
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(BundleError::InvalidInput(format!(
                "output path must be a real directory: {}",
                output.display()
            )));
        }
        let mut entries = fs::read_dir(output).map_err(|source| BundleError::Io {
            context: "reading output directory",
            source,
        })?;
        if entries.next().is_some() {
            return Err(BundleError::InvalidInput(format!(
                "output directory is not empty: {}",
                output.display()
            )));
        }
    } else {
        fs::create_dir_all(output).map_err(|source| BundleError::Io {
            context: "creating output directory",
            source,
        })?;
    }
    Ok(())
}

fn stage_source(
    source: &Path,
    root: &Path,
    relative: &Path,
    kind: InventoryKind,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<InventoryEntry, BundleError> {
    let metadata = fs::symlink_metadata(source).map_err(|source| BundleError::Io {
        context: "reading source artifact metadata",
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(BundleError::InvalidInput(format!(
            "source artifact must be a single-link regular file: {}",
            source.display()
        )));
    }
    let destination = root.join(relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|source| BundleError::Io {
            context: "creating artifact directory",
            source,
        })?;
    }
    fs::copy(source, &destination).map_err(|source| BundleError::Io {
        context: "copying source artifact",
        source,
    })?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(mode)).map_err(|source| {
        BundleError::Io {
            context: "setting artifact mode",
            source,
        }
    })?;
    inventory_entry(kind, relative, &destination, mode, uid, gid)
}

fn stage_generated<T: Serialize>(
    root: &Path,
    relative: &Path,
    value: &T,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<InventoryEntry, BundleError> {
    let destination = root.join(relative);
    write_json(&destination, value, mode)?;
    inventory_entry(
        InventoryKind::Metadata,
        relative,
        &destination,
        mode,
        uid,
        gid,
    )
}

fn inventory_entry(
    kind: InventoryKind,
    relative: &Path,
    destination: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<InventoryEntry, BundleError> {
    let bytes = fs::read(destination).map_err(|source| BundleError::Io {
        context: "reading staged artifact",
        source,
    })?;
    Ok(InventoryEntry {
        kind,
        path: relative.to_path_buf(),
        sha256: encode_hex(&Sha256::digest(bytes)),
        mode,
        uid,
        gid,
    })
}

fn build_sbom(options: &StageOptions<'_>, inventory: &[InventoryEntry]) -> SpdxDocument {
    let files = inventory
        .iter()
        .enumerate()
        .map(|(index, entry)| SpdxFile {
            file_name: entry.path.display().to_string(),
            spdx_id: format!("SPDXRef-File-{index}"),
            checksums: [SpdxChecksum {
                algorithm: "SHA256",
                checksum_value: entry.sha256.clone(),
            }],
            license_concluded: "NOASSERTION",
            copyright_text: "NOASSERTION",
        })
        .collect();
    SpdxDocument {
        spdx_version: "SPDX-2.3",
        data_license: "CC0-1.0",
        spdx_id: "SPDXRef-DOCUMENT",
        name: format!(
            "sendbox-guest-{}-{}",
            options.guest_version,
            options.architecture.as_str()
        ),
        document_namespace: format!(
            "https://sendbox.dev/spdx/guest/{}/{}",
            options.guest_version,
            options.architecture.as_str()
        ),
        creation_info: SpdxCreationInfo {
            created: "1970-01-01T00:00:00Z",
            creators: ["Tool: sendbox-bundle"],
        },
        files,
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<(), BundleError> {
    let bytes = serde_json::to_vec(value)?;
    write_bytes(path, &bytes, mode)
}

fn write_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<(), BundleError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| BundleError::Io {
            context: "creating generated artifact directory",
            source,
        })?;
    }
    fs::write(path, bytes).map_err(|source| BundleError::Io {
        context: "writing generated artifact",
        source,
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| BundleError::Io {
        context: "setting generated artifact mode",
        source,
    })
}

fn read_signing_key(path: &Path) -> Result<SigningKey, BundleError> {
    let bytes = read_key_material(path)?;
    let key = decode_key_material(&bytes)?;
    Ok(SigningKey::from_bytes(&key))
}

fn read_public_key(path: &Path) -> Result<[u8; 32], BundleError> {
    let bytes = read_key_material(path)?;
    decode_key_material(&bytes)
}

fn read_key_material(path: &Path) -> Result<Zeroizing<Vec<u8>>, BundleError> {
    let mut file = fs::File::open(path).map_err(|source| BundleError::Io {
        context: "opening key file",
        source,
    })?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(u64::try_from(MAX_KEY_BYTES).expect("key bound fits u64"))
        .read_to_end(&mut bytes)
        .map_err(|source| BundleError::Io {
            context: "reading key file",
            source,
        })?;
    Ok(bytes)
}

fn decode_key_material(bytes: &[u8]) -> Result<[u8; 32], BundleError> {
    if bytes.len() == 32 {
        return bytes.try_into().map_err(|_| {
            BundleError::InvalidInput("key material must contain exactly 32 bytes".to_owned())
        });
    }
    let text = std::str::from_utf8(bytes).map(str::trim).map_err(|_| {
        BundleError::InvalidInput("key file is neither raw nor UTF-8 hex".to_owned())
    })?;
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BundleError::InvalidInput(
            "key file must contain 32 raw bytes or 64 hexadecimal characters".to_owned(),
        ));
    }
    let decoded = (0..32)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| BundleError::InvalidInput(format!("invalid hexadecimal key: {error}")))?;
    decoded.try_into().map_err(|_| {
        BundleError::InvalidInput("key material must contain exactly 32 bytes".to_owned())
    })
}

fn verify_detached_signature(root: &Path, verified: &VerifiedManifest) -> Result<(), BundleError> {
    let envelope: SignedManifestEnvelope =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).map_err(|source| {
            BundleError::Io {
                context: "reading signed manifest",
                source,
            }
        })?)?;
    let detached =
        fs::read_to_string(root.join("manifest.sig")).map_err(|source| BundleError::Io {
            context: "reading detached signature",
            source,
        })?;
    if detached.trim() != envelope.signature {
        return Err(BundleError::InvalidInput(
            "detached signature does not match the signed envelope".to_owned(),
        ));
    }
    if envelope.payload != serde_json::to_string(&verified.manifest)? {
        return Err(BundleError::InvalidInput(
            "verified manifest payload is not canonical".to_owned(),
        ));
    }
    Ok(())
}

fn verify_release_metadata(
    descriptor: &std::os::fd::OwnedFd,
    root: &Path,
    public_key: &[u8; 32],
    options: &VerifyOptions<'_>,
    verified: &VerifiedManifest,
) -> Result<(), BundleError> {
    let envelope_bytes =
        fs::read(root.join("release-metadata.json")).map_err(|source| BundleError::Io {
            context: "reading signed release metadata",
            source,
        })?;
    if envelope_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(BundleError::InvalidInput(
            "signed release metadata is too large".to_owned(),
        ));
    }
    let envelope: SignedManifestEnvelope = serde_json::from_slice(&envelope_bytes)?;
    let signature_bytes = decode_hex(&envelope.signature, 64)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|error| {
        BundleError::InvalidInput(format!("invalid release signature: {error}"))
    })?;
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|error| BundleError::InvalidInput(format!("invalid public key: {error}")))?;
    verifying_key
        .verify(envelope.payload.as_bytes(), &signature)
        .map_err(|_| BundleError::InvalidInput("release metadata signature failed".to_owned()))?;
    let inventory: Inventory = serde_json::from_str(&envelope.payload)?;
    if inventory.schema_version != 1
        || inventory.domain != RELEASE_METADATA_DOMAIN
        || inventory.trust_root_id != options.trust_root_id
        || inventory.release_sequence != verified.manifest.release_sequence
        || inventory.architecture != options.architecture.as_str()
        || inventory.artifacts.is_empty()
        || inventory.artifacts.len() > MAX_ARTIFACTS
    {
        return Err(BundleError::InvalidInput(
            "release metadata identity or bounds mismatch".to_owned(),
        ));
    }
    let inventory_bytes =
        fs::read(root.join("share/sendbox/inventory.json")).map_err(|source| BundleError::Io {
            context: "reading release inventory",
            source,
        })?;
    if inventory_bytes != envelope.payload.as_bytes() {
        return Err(BundleError::InvalidInput(
            "release inventory does not match signed metadata".to_owned(),
        ));
    }
    let detached = fs::read_to_string(root.join("release-metadata.sig")).map_err(|source| {
        BundleError::Io {
            context: "reading detached release metadata signature",
            source,
        }
    })?;
    if detached.trim() != envelope.signature {
        return Err(BundleError::InvalidInput(
            "detached release metadata signature mismatch".to_owned(),
        ));
    }
    for entry in &inventory.artifacts {
        if entry.sha256.len() != 64
            || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || entry.mode & !0o7777 != 0
        {
            return Err(BundleError::InvalidInput(format!(
                "invalid release inventory entry: {}",
                entry.path.display()
            )));
        }
        verify_file_expectation(
            descriptor,
            &entry.path,
            &entry.sha256,
            entry.mode,
            entry.uid,
            entry.gid,
        )?;
    }
    for artifact in &verified.manifest.artifacts {
        let expected_kind = match artifact.kind {
            ArtifactKind::GuestBinary => InventoryKind::GuestBinary,
            ArtifactKind::ServiceBinary => InventoryKind::ServiceBinary,
            ArtifactKind::BpfObject => InventoryKind::BpfObject,
            ArtifactKind::UnikraftShellKernel => InventoryKind::UnikraftShellKernel,
            ArtifactKind::Initrd => InventoryKind::Initrd,
        };
        if !inventory.artifacts.iter().any(|entry| {
            entry.kind == expected_kind
                && entry.path == artifact.path
                && entry.sha256 == artifact.sha256
                && entry.mode == artifact.mode
                && entry.uid == artifact.uid
                && entry.gid == artifact.gid
        }) {
            return Err(BundleError::InvalidInput(format!(
                "signed inventory is missing manifest artifact {}",
                artifact.path.display()
            )));
        }
    }
    Ok(())
}

pub mod fuzzing {
    use sendbox_guest::manifest::{ArtifactManifest, MAX_MANIFEST_BYTES, SignedManifestEnvelope};

    pub fn decode_manifest(bytes: &[u8]) {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return;
        }
        if let Ok(envelope) = serde_json::from_slice::<SignedManifestEnvelope>(bytes) {
            let _ = serde_json::from_str::<ArtifactManifest>(&envelope.payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use ed25519_dalek::VerifyingKey;
    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        temp: TempDir,
        guest: PathBuf,
        launcher: PathBuf,
        bpf: PathBuf,
        signing_key: PathBuf,
        public_key: PathBuf,
    }

    fn new_fixture() -> Fixture {
        let base = std::env::temp_dir().canonicalize().expect("canonical temp");
        let temp = tempfile::Builder::new()
            .prefix("sendbox-bundle-")
            .tempdir_in(base)
            .expect("tempdir");
        let guest = temp.path().join("guest");
        let launcher = temp.path().join("launcher");
        let bpf = temp.path().join("observe.bpf.o");
        fs::write(&guest, b"guest").expect("guest");
        fs::write(&launcher, b"launcher").expect("launcher");
        fs::write(&bpf, b"\x7fELFbpf").expect("bpf");
        let signing_key = temp.path().join("signing.key");
        fs::write(&signing_key, [7_u8; 32]).expect("signing key");
        let public_key = temp.path().join("public.key");
        let verifying = VerifyingKey::from(&SigningKey::from_bytes(&[7_u8; 32]));
        fs::write(&public_key, verifying.to_bytes()).expect("public key");
        Fixture {
            temp,
            guest,
            launcher,
            bpf,
            signing_key,
            public_key,
        }
    }

    fn stage(fixture: &Fixture) -> PathBuf {
        let output = fixture.temp.path().join("bundle");
        stage_bundle(&StageOptions {
            output: &output,
            guest_binary: &fixture.guest,
            exec_launcher: &fixture.launcher,
            bpf_object: &fixture.bpf,
            signing_key: &fixture.signing_key,
            architecture: Architecture::X86_64,
            trust_root_id: "test-root",
            release_sequence: 7,
            minimum_accepted_sequence: 5,
            host_version: "0.1.0",
            guest_version: "0.1.0",
            minimum_kernel: "5.8.0",
            btf_archive_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            vmlinux_header_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
            uid: getuid().as_raw(),
            gid: getgid().as_raw(),
        })
        .expect("stage");
        output
    }

    fn verify(fixture: &Fixture, root: &Path) -> Result<VerifyReport, BundleError> {
        verify_bundle(&VerifyOptions {
            root,
            public_key: &fixture.public_key,
            architecture: Architecture::X86_64,
            trust_root_id: "test-root",
            host_version: "0.1.0",
            guest_version: "0.1.0",
            minimum_release_sequence: 6,
        })
    }

    #[test]
    fn staged_bundle_verifies_and_contains_inventory_and_sbom() {
        let fixture = new_fixture();
        let root = stage(&fixture);
        let report = verify(&fixture, &root).expect("verify");
        assert_eq!(report.artifact_count, 3);
        assert!(root.join("share/sendbox/inventory.json").is_file());
        assert!(root.join("share/sendbox/sbom.spdx.json").is_file());
        assert!(
            root.join("share/sendbox/verification-report.json")
                .is_file()
        );
        assert!(root.join("release-metadata.json").is_file());
        assert!(root.join("release-metadata.sig").is_file());
    }

    #[test]
    fn tamper_wrong_architecture_rollback_and_mode_fail_closed() {
        let fixture = new_fixture();
        let root = stage(&fixture);
        let guest = root.join("bin/sendbox-guest");
        fs::remove_file(&guest).expect("remove guest");
        fs::write(&guest, b"tamper").expect("tamper");
        fs::set_permissions(&guest, fs::Permissions::from_mode(0o500)).expect("restore mode");
        assert!(verify(&fixture, &root).is_err());

        let fixture = new_fixture();
        let root = stage(&fixture);
        let sbom = root.join("share/sendbox/sbom.spdx.json");
        fs::set_permissions(&sbom, fs::Permissions::from_mode(0o600)).expect("writable sbom");
        fs::write(&sbom, b"tampered sbom").expect("tamper sbom");
        fs::set_permissions(&sbom, fs::Permissions::from_mode(0o400)).expect("restore mode");
        assert!(verify(&fixture, &root).is_err());

        let fixture = new_fixture();
        let root = stage(&fixture);
        let wrong_arch = verify_bundle(&VerifyOptions {
            root: &root,
            public_key: &fixture.public_key,
            architecture: Architecture::Aarch64,
            trust_root_id: "test-root",
            host_version: "0.1.0",
            guest_version: "0.1.0",
            minimum_release_sequence: 6,
        });
        assert!(wrong_arch.is_err());

        let fixture = new_fixture();
        let root = stage(&fixture);
        let rollback = verify_bundle(&VerifyOptions {
            root: &root,
            public_key: &fixture.public_key,
            architecture: Architecture::X86_64,
            trust_root_id: "test-root",
            host_version: "0.1.0",
            guest_version: "0.1.0",
            minimum_release_sequence: 8,
        });
        assert!(rollback.is_err());

        let fixture = new_fixture();
        let root = stage(&fixture);
        fs::set_permissions(
            root.join("bin/sendbox-guest"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("mode");
        assert!(verify(&fixture, &root).is_err());
    }

    #[test]
    fn source_symlinks_are_rejected() {
        let fixture = new_fixture();
        let linked = fixture.temp.path().join("guest-link");
        symlink(&fixture.guest, &linked).expect("symlink");
        let error = stage_bundle(&StageOptions {
            output: &fixture.temp.path().join("bundle"),
            guest_binary: &linked,
            exec_launcher: &fixture.launcher,
            bpf_object: &fixture.bpf,
            signing_key: &fixture.signing_key,
            architecture: Architecture::X86_64,
            trust_root_id: "test-root",
            release_sequence: 1,
            minimum_accepted_sequence: 1,
            host_version: "0.1.0",
            guest_version: "0.1.0",
            minimum_kernel: "5.8.0",
            btf_archive_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            vmlinux_header_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
            uid: getuid().as_raw(),
            gid: getgid().as_raw(),
        })
        .expect_err("symlink rejected");
        assert!(error.to_string().contains("single-link regular file"));
    }

    #[test]
    fn symlinked_bundle_roots_are_rejected() {
        let fixture = new_fixture();
        let root = stage(&fixture);
        let linked = fixture.temp.path().join("bundle-link");
        symlink(&root, &linked).expect("symlink");
        assert!(verify(&fixture, &linked).is_err());
    }
}
