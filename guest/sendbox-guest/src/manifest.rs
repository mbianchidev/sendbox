use std::collections::BTreeMap;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::GuestError;
use crate::secure_fs::{open_relative_regular, validate_relative_path};

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_DOMAIN: &str = "dev.sendbox.guest.artifact-manifest.v1";
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_ARTIFACTS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    GuestBinary,
    ServiceBinary,
    BpfObject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactExpectation {
    pub kind: ArtifactKind,
    pub path: PathBuf,
    pub sha256: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub schema_version: u32,
    pub domain: String,
    pub trust_root_id: String,
    pub release_sequence: u64,
    pub minimum_accepted_sequence: u64,
    pub expected_host_version: String,
    pub expected_guest_version: String,
    pub architecture: String,
    pub artifacts: Vec<ArtifactExpectation>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifestEnvelope {
    pub payload: String,
    pub signature: String,
}

#[derive(Debug)]
pub struct VerifiedManifest {
    pub manifest: ArtifactManifest,
    verified_artifacts: BTreeMap<PathBuf, VerifiedArtifact>,
}

#[derive(Debug)]
struct VerifiedArtifact {
    kind: ArtifactKind,
    descriptor: OwnedFd,
}

impl VerifiedManifest {
    pub fn executable_descriptor(&self, path: &Path) -> Result<OwnedFd, GuestError> {
        let artifact = self
            .verified_artifacts
            .get(path)
            .ok_or_else(|| GuestError::Artifact {
                path: path.display().to_string(),
                detail: "service executable is not a verified artifact".to_owned(),
            })?;
        if !matches!(
            artifact.kind,
            ArtifactKind::GuestBinary | ArtifactKind::ServiceBinary
        ) {
            return Err(GuestError::Artifact {
                path: path.display().to_string(),
                detail: "artifact is not executable service material".to_owned(),
            });
        }
        artifact
            .descriptor
            .try_clone()
            .map_err(|error| GuestError::io("duplicating verified executable", error))
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let executable = std::env::current_exe().expect("current test executable");
        let verified_artifacts = paths
            .into_iter()
            .map(|path| {
                let descriptor = OwnedFd::from(
                    std::fs::File::open(&executable).expect("open current test executable"),
                );
                (
                    path,
                    VerifiedArtifact {
                        kind: ArtifactKind::ServiceBinary,
                        descriptor,
                    },
                )
            })
            .collect();
        Self {
            manifest: ArtifactManifest {
                schema_version: MANIFEST_SCHEMA_VERSION,
                domain: MANIFEST_DOMAIN.to_owned(),
                trust_root_id: "test".to_owned(),
                release_sequence: 1,
                minimum_accepted_sequence: 1,
                expected_host_version: "test".to_owned(),
                expected_guest_version: "test".to_owned(),
                architecture: std::env::consts::ARCH.to_owned(),
                artifacts: Vec::new(),
            },
            verified_artifacts,
        }
    }
}

pub fn verify_manifest(
    root: &OwnedFd,
    envelope_path: &Path,
    trust_root: &[u8; 32],
    expected_trust_root_id: &str,
    expected_host_version: &str,
    expected_guest_version: &str,
    minimum_release_sequence: u64,
) -> Result<VerifiedManifest, GuestError> {
    verify_manifest_for_architecture(
        root,
        envelope_path,
        trust_root,
        expected_trust_root_id,
        expected_host_version,
        expected_guest_version,
        std::env::consts::ARCH,
        minimum_release_sequence,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_manifest_for_architecture(
    root: &OwnedFd,
    envelope_path: &Path,
    trust_root: &[u8; 32],
    expected_trust_root_id: &str,
    expected_host_version: &str,
    expected_guest_version: &str,
    expected_architecture: &str,
    minimum_release_sequence: u64,
) -> Result<VerifiedManifest, GuestError> {
    let mut envelope_file =
        open_relative_regular(root, envelope_path, "opening signed manifest")?.file;
    let mut envelope_bytes = Zeroizing::new(Vec::new());
    envelope_file
        .by_ref()
        .take(u64::try_from(MAX_MANIFEST_BYTES + 1).expect("manifest limit fits u64"))
        .read_to_end(&mut envelope_bytes)
        .map_err(|error| GuestError::io("reading signed manifest", error))?;
    if envelope_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(GuestError::Manifest(
            "signed envelope is too large".to_owned(),
        ));
    }
    let envelope: SignedManifestEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|error| GuestError::Manifest(error.to_string()))?;
    let signature_bytes = decode_hex(&envelope.signature, 64)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| GuestError::Manifest(format!("invalid signature: {error}")))?;
    let verifying_key = VerifyingKey::from_bytes(trust_root)
        .map_err(|error| GuestError::Manifest(format!("invalid trust root: {error}")))?;
    verifying_key
        .verify(envelope.payload.as_bytes(), &signature)
        .map_err(|_| GuestError::Manifest("release signature verification failed".to_owned()))?;

    let manifest: ArtifactManifest = serde_json::from_str(&envelope.payload)
        .map_err(|error| GuestError::Manifest(error.to_string()))?;
    validate_manifest(
        &manifest,
        expected_trust_root_id,
        expected_host_version,
        expected_guest_version,
        expected_architecture,
        minimum_release_sequence,
    )?;

    let mut verified_artifacts = BTreeMap::new();
    for artifact in &manifest.artifacts {
        let descriptor = verify_artifact(root, artifact)?;
        if verified_artifacts
            .insert(
                artifact.path.clone(),
                VerifiedArtifact {
                    kind: artifact.kind,
                    descriptor,
                },
            )
            .is_some()
        {
            return Err(GuestError::Manifest(format!(
                "duplicate artifact path: {}",
                artifact.path.display()
            )));
        }
    }

    Ok(VerifiedManifest {
        manifest,
        verified_artifacts,
    })
}

fn validate_manifest(
    manifest: &ArtifactManifest,
    expected_trust_root_id: &str,
    expected_host_version: &str,
    expected_guest_version: &str,
    expected_architecture: &str,
    minimum_release_sequence: u64,
) -> Result<(), GuestError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(GuestError::Manifest(format!(
            "unsupported schema version {}",
            manifest.schema_version
        )));
    }
    if manifest.domain != MANIFEST_DOMAIN {
        return Err(GuestError::Manifest("signature domain mismatch".to_owned()));
    }
    if manifest.trust_root_id != expected_trust_root_id {
        return Err(GuestError::Manifest(
            "trust-root identity mismatch".to_owned(),
        ));
    }
    if manifest.expected_host_version != expected_host_version {
        return Err(GuestError::Manifest("host version mismatch".to_owned()));
    }
    if manifest.expected_guest_version != expected_guest_version {
        return Err(GuestError::Manifest("guest version mismatch".to_owned()));
    }
    if manifest.architecture != expected_architecture {
        return Err(GuestError::Manifest(format!(
            "architecture mismatch: expected {}, got {}",
            expected_architecture, manifest.architecture
        )));
    }
    if manifest.minimum_accepted_sequence > manifest.release_sequence
        || manifest.release_sequence < minimum_release_sequence
    {
        return Err(GuestError::Manifest(
            "release sequence violates rollback policy".to_owned(),
        ));
    }
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > MAX_ARTIFACTS {
        return Err(GuestError::Manifest(format!(
            "artifact count must be between 1 and {MAX_ARTIFACTS}"
        )));
    }
    for artifact in &manifest.artifacts {
        validate_relative_path(&artifact.path)?;
        if artifact.sha256.len() != 64
            || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(GuestError::Manifest(format!(
                "invalid SHA-256 digest for {}",
                artifact.path.display()
            )));
        }
        if artifact.mode & !0o7777 != 0 {
            return Err(GuestError::Manifest(format!(
                "invalid mode for {}",
                artifact.path.display()
            )));
        }
    }
    Ok(())
}

fn verify_artifact(root: &OwnedFd, artifact: &ArtifactExpectation) -> Result<OwnedFd, GuestError> {
    verify_file_expectation(
        root,
        &artifact.path,
        &artifact.sha256,
        artifact.mode,
        artifact.uid,
        artifact.gid,
    )
}

pub fn verify_file_expectation(
    root: &OwnedFd,
    path: &Path,
    sha256: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<OwnedFd, GuestError> {
    validate_relative_path(path)?;
    let mut opened = open_relative_regular(root, path, "opening artifact")?;
    #[allow(clippy::useless_conversion)] // st_mode is u16 on macOS and u32 on Linux.
    let actual_mode = u32::from(opened.stat.st_mode & 0o7777);
    if actual_mode != mode {
        return Err(file_error(path, "mode mismatch"));
    }
    if opened.stat.st_uid != uid || opened.stat.st_gid != gid {
        return Err(file_error(path, "owner mismatch"));
    }
    if opened.stat.st_nlink != 1 {
        return Err(file_error(path, "hard-linked artifact rejected"));
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = opened
            .file
            .read(&mut buffer)
            .map_err(|error| GuestError::io("hashing artifact", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = encode_hex(&hasher.finalize());
    if actual != sha256.to_ascii_lowercase() {
        return Err(file_error(path, "digest mismatch"));
    }
    Ok(OwnedFd::from(opened.file))
}

fn file_error(path: &Path, detail: &str) -> GuestError {
    GuestError::Artifact {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}

pub fn decode_hex(value: &str, expected_bytes: usize) -> Result<Vec<u8>, GuestError> {
    if value.len() != expected_bytes * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GuestError::Manifest("invalid hexadecimal value".to_owned()));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)
                .map_err(|error| GuestError::Manifest(error.to_string()))?;
            u8::from_str_radix(pair, 16).map_err(|error| GuestError::Manifest(error.to_string()))
        })
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;
    use crate::secure_fs::{open_directory_no_symlinks, secure_tempdir};
    use ed25519_dalek::{Signer, SigningKey};
    use rustix::process::{getgid, getuid};

    fn fixture() -> (tempfile::TempDir, SigningKey, ArtifactManifest, PathBuf) {
        let temporary = secure_tempdir();
        let artifact_path = temporary.path().join("guest");
        fs::write(&artifact_path, b"trusted guest").expect("artifact");
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o500))
            .expect("artifact mode");
        let digest = encode_hex(&Sha256::digest(b"trusted guest"));
        let manifest = ArtifactManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            domain: MANIFEST_DOMAIN.to_owned(),
            trust_root_id: "root-v1".to_owned(),
            release_sequence: 7,
            minimum_accepted_sequence: 5,
            expected_host_version: "0.1.0".to_owned(),
            expected_guest_version: env!("CARGO_PKG_VERSION").to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            artifacts: vec![ArtifactExpectation {
                kind: ArtifactKind::GuestBinary,
                path: PathBuf::from("guest"),
                sha256: digest,
                mode: 0o500,
                uid: getuid().as_raw(),
                gid: getgid().as_raw(),
            }],
        };
        (
            temporary,
            SigningKey::from_bytes(&[7; 32]),
            manifest,
            artifact_path,
        )
    }

    fn write_envelope(root: &Path, signing_key: &SigningKey, manifest: &ArtifactManifest) {
        let payload = serde_json::to_string(manifest).expect("payload");
        let signature = signing_key.sign(payload.as_bytes());
        let envelope = SignedManifestEnvelope {
            payload,
            signature: encode_hex(&signature.to_bytes()),
        };
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&envelope).expect("envelope"),
        )
        .expect("manifest");
    }

    fn verify(
        temporary: &tempfile::TempDir,
        signing_key: &SigningKey,
        manifest: &ArtifactManifest,
        minimum: u64,
    ) -> Result<VerifiedManifest, GuestError> {
        write_envelope(temporary.path(), signing_key, manifest);
        let root = open_directory_no_symlinks(temporary.path()).expect("root descriptor");
        verify_manifest(
            &root,
            Path::new("manifest.json"),
            &signing_key.verifying_key().to_bytes(),
            "root-v1",
            "0.1.0",
            env!("CARGO_PKG_VERSION"),
            minimum,
        )
    }

    #[test]
    fn signed_manifest_verifies_digest_mode_owner_and_version() {
        let (temporary, signing_key, manifest, _) = fixture();
        let verified = verify(&temporary, &signing_key, &manifest, 6).expect("verified");
        assert!(verified.executable_descriptor(Path::new("guest")).is_ok());
    }

    #[test]
    fn signature_digest_mode_owner_and_rollback_fail_closed() {
        let (temporary, signing_key, mut manifest, artifact) = fixture();
        manifest.artifacts[0].sha256 = "00".repeat(32);
        assert!(verify(&temporary, &signing_key, &manifest, 6).is_err());

        manifest.artifacts[0].sha256 = encode_hex(&Sha256::digest(b"trusted guest"));
        manifest.artifacts[0].mode = 0o400;
        assert!(verify(&temporary, &signing_key, &manifest, 6).is_err());

        manifest.artifacts[0].mode = 0o500;
        manifest.artifacts[0].uid = artifact.metadata().expect("metadata").uid() + 1;
        assert!(verify(&temporary, &signing_key, &manifest, 6).is_err());

        manifest.artifacts[0].uid = getuid().as_raw();
        assert!(verify(&temporary, &signing_key, &manifest, 8).is_err());

        write_envelope(temporary.path(), &signing_key, &manifest);
        let mut envelope: SignedManifestEnvelope = serde_json::from_slice(
            &fs::read(temporary.path().join("manifest.json")).expect("read envelope"),
        )
        .expect("decode envelope");
        envelope.signature.replace_range(0..2, "ff");
        fs::write(
            temporary.path().join("manifest.json"),
            serde_json::to_vec(&envelope).expect("encode envelope"),
        )
        .expect("tamper envelope");
        let root = open_directory_no_symlinks(temporary.path()).expect("root");
        assert!(
            verify_manifest(
                &root,
                Path::new("manifest.json"),
                &signing_key.verifying_key().to_bytes(),
                "root-v1",
                "0.1.0",
                env!("CARGO_PKG_VERSION"),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn symlinks_and_hardlinks_are_rejected() {
        let (temporary, signing_key, manifest, artifact) = fixture();
        let target = temporary.path().join("target");
        fs::rename(&artifact, &target).expect("move artifact");
        symlink(&target, &artifact).expect("symlink");
        assert!(verify(&temporary, &signing_key, &manifest, 1).is_err());

        fs::remove_file(&artifact).expect("remove symlink");
        fs::hard_link(&target, &artifact).expect("hard link");
        assert!(verify(&temporary, &signing_key, &manifest, 1).is_err());
    }

    #[test]
    fn manifest_v1_rejects_unversioned_artifact_kinds() {
        assert!(serde_json::from_str::<ArtifactKind>(r#""metadata""#).is_err());
    }
}
