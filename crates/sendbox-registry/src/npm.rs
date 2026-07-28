use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use sendbox_policy::{
    EvidenceRequirement, PackageAnalysisLimits, PackageEcosystem, PackageRegistryPolicy,
    PackageSupplyChainPolicy,
};
use serde::Deserialize;
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    AdapterCapabilities, ArchiveEntry, ArtifactDescriptor, ArtifactDigest, IntegrityAlgorithm,
    IntegrityClaim, IntegritySource, NormalizedManifest, PackageProvenanceVerifier,
    ProvenanceClaim, RawFinding, RegistryAdapter, RegistryError, RegistryResult, ResolvedMetadata,
    SignatureClaim, TrustMetadata, UpstreamClient, UpstreamRequest, VerificationEvidence,
};

const FULL_METADATA_ACCEPT: &str = "application/json";
const MISSING_TIME_CUTOFF: &str = "2015-01-01T00:00:00.000Z";
const NPM_KEYS_PATH: &str = "/-/npm/v1/keys";

#[derive(Clone)]
pub struct NpmAdapter {
    registry: Url,
    registry_policy: PackageRegistryPolicy,
    package_policy: PackageSupplyChainPolicy,
    authorization: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for NpmAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NpmAdapter")
            .field("registry", &self.registry)
            .field("registry_policy", &self.registry_policy)
            .field("package_policy", &self.package_policy)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl NpmAdapter {
    pub fn new(
        registry_policy: PackageRegistryPolicy,
        package_policy: PackageSupplyChainPolicy,
        token: Option<Vec<u8>>,
    ) -> RegistryResult<Self> {
        if registry_policy.ecosystem != PackageEcosystem::Npm {
            return Err(RegistryError::Invalid(
                "npm adapter requires an npm registry policy".to_owned(),
            ));
        }
        package_policy
            .validate()
            .map_err(|error| RegistryError::Invalid(error.to_string()))?;
        let registry = Url::parse(&registry_policy.url)
            .map_err(|error| RegistryError::Invalid(format!("parse npm registry URL: {error}")))?;
        let authorization = token
            .map(|token| {
                if token.is_empty() {
                    return Err(RegistryError::Invalid(
                        "npm registry token must not be empty".to_owned(),
                    ));
                }
                let mut header = Zeroizing::new(Vec::with_capacity(7 + token.len()));
                header.extend_from_slice(b"Bearer ");
                header.extend_from_slice(&token);
                Ok(header)
            })
            .transpose()?;
        if registry_policy.credential_secret.is_some() != authorization.is_some() {
            return Err(RegistryError::Invalid(
                "npm registry credential does not match its policy reference".to_owned(),
            ));
        }
        Ok(Self {
            registry,
            registry_policy,
            package_policy,
            authorization,
        })
    }

    #[must_use]
    pub fn registry(&self) -> &Url {
        &self.registry
    }

    #[must_use]
    pub fn registry_policy(&self) -> &PackageRegistryPolicy {
        &self.registry_policy
    }

    #[must_use]
    pub fn limits(&self) -> &PackageAnalysisLimits {
        &self.package_policy.limits
    }

    pub async fn fetch_trust_metadata(
        &self,
        descriptor: &ArtifactDescriptor,
        upstream: &dyn UpstreamClient,
    ) -> RegistryResult<TrustMetadata> {
        let registry_keys = if descriptor.signatures.is_empty() {
            Vec::new()
        } else {
            let mut url = self.registry.clone();
            url.set_path(NPM_KEYS_PATH);
            url.set_query(None);
            url.set_fragment(None);
            let response = upstream
                .fetch(UpstreamRequest {
                    url: url.to_string(),
                    accept: Some("application/json".to_owned()),
                    authorization: self.authorization_header(),
                    maximum_bytes: self.package_policy.limits.max_metadata_bytes,
                })
                .await?;
            require_success("npm registry keys", response.status)?;
            response.body
        };
        let provenance_bundle = match descriptor.provenance.as_ref() {
            None => None,
            Some(claim) => {
                let url = self.registry_relative_url(&claim.url)?;
                let response = upstream
                    .fetch(UpstreamRequest {
                        url: url.to_string(),
                        accept: Some("application/json".to_owned()),
                        authorization: self.authorization_header(),
                        maximum_bytes: self.package_policy.limits.max_metadata_bytes,
                    })
                    .await?;
                require_success("npm attestation bundle", response.status)?;
                Some(response.body)
            }
        };
        let mut digest = Sha256::new();
        digest.update(b"sendbox-npm-trust-metadata-v1\0");
        digest.update(&registry_keys);
        if let Some(bundle) = provenance_bundle.as_deref() {
            digest.update(bundle);
        }
        Ok(TrustMetadata {
            registry_keys,
            package_trust_root: Vec::new(),
            provenance_bundle,
            digest: format!("sha256:{}", encode_hex(&digest.finalize())),
        })
    }

    fn authorization_header(&self) -> Option<Vec<u8>> {
        self.authorization
            .as_ref()
            .map(|authorization| authorization.as_slice().to_vec())
    }

    fn metadata_url(&self, package: &str) -> RegistryResult<Url> {
        validate_package_name(package)?;
        let mut url = self.registry.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|()| {
                RegistryError::Invalid("npm registry URL cannot accept path segments".to_owned())
            })?;
            segments.pop_if_empty();
            segments.push(package);
        }
        Ok(url)
    }

    fn registry_relative_url(&self, candidate: &str) -> RegistryResult<Url> {
        let candidate = Url::parse(candidate)
            .map_err(|error| RegistryError::Invalid(format!("parse npm upstream URL: {error}")))?;
        if candidate.scheme() != self.registry.scheme()
            || candidate.host_str() != self.registry.host_str()
            || candidate.port_or_known_default() != self.registry.port_or_known_default()
        {
            return Err(RegistryError::Verification(
                "npm metadata referenced an artifact outside the configured registry origin"
                    .to_owned(),
            ));
        }
        let mut result = self.registry.clone();
        result.set_path(candidate.path());
        result.set_query(candidate.query());
        result.set_fragment(None);
        Ok(result)
    }

    fn parse_metadata(&self, body: &[u8], requested: &str) -> RegistryResult<ResolvedMetadata> {
        let document: Value = serde_json::from_slice(body)
            .map_err(|error| RegistryError::Invalid(format!("decode npm metadata: {error}")))?;
        let object = document
            .as_object()
            .ok_or_else(|| RegistryError::Invalid("npm metadata must be an object".to_owned()))?;
        let name = object.get("name").and_then(Value::as_str).ok_or_else(|| {
            RegistryError::Invalid("npm metadata omitted package name".to_owned())
        })?;
        if name != requested {
            return Err(RegistryError::Verification(format!(
                "npm metadata identity mismatch: requested {requested}, received {name}"
            )));
        }
        let revision = object
            .get("_rev")
            .or_else(|| object.get("modified"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                let mut digest = Sha256::new();
                digest.update(body);
                format!("sha256:{}", encode_hex(&digest.finalize()))
            });
        let versions = object
            .get("versions")
            .and_then(Value::as_object)
            .ok_or_else(|| RegistryError::Invalid("npm metadata omitted versions".to_owned()))?;
        let times = object.get("time").and_then(Value::as_object);
        let mut artifacts = Vec::with_capacity(versions.len());
        for (version, value) in versions {
            let version_object = value.as_object().ok_or_else(|| {
                RegistryError::Invalid(format!("npm version {version} metadata must be an object"))
            })?;
            if version_object
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|value| value != name)
                || version_object
                    .get("version")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value != version)
            {
                return Err(RegistryError::Verification(format!(
                    "npm version identity mismatch for {name}@{version}"
                )));
            }
            let dist = version_object
                .get("dist")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    RegistryError::Invalid(format!("npm {name}@{version} omitted dist metadata"))
                })?;
            let source_url = dist
                .get("tarball")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    RegistryError::Invalid(format!("npm {name}@{version} omitted dist.tarball"))
                })?
                .to_owned();
            self.registry_relative_url(&source_url)?;
            let mut integrity = Vec::new();
            let signature_integrity =
                if let Some(sri) = dist.get("integrity").and_then(Value::as_str) {
                    integrity.extend(parse_sri(sri)?);
                    sri.to_owned()
                } else if let Some(shasum) = dist.get("shasum").and_then(Value::as_str) {
                    if !self.package_policy.allow_legacy_sha1 {
                        return Err(RegistryError::Verification(format!(
                            "npm {name}@{version} only declares legacy SHA-1"
                        )));
                    }
                    let digest = decode_hex(shasum, 20)?;
                    integrity.push(IntegrityClaim {
                        algorithm: IntegrityAlgorithm::Sha1,
                        digest: digest.clone(),
                        source: IntegritySource::Shasum,
                    });
                    format!("sha1-{}", STANDARD.encode(digest))
                } else {
                    return Err(RegistryError::Verification(format!(
                        "npm {name}@{version} omitted integrity and shasum"
                    )));
                };
            if let Some(shasum) = dist.get("shasum").and_then(Value::as_str)
                && !integrity
                    .iter()
                    .any(|claim| claim.source == IntegritySource::Shasum)
            {
                integrity.push(IntegrityClaim {
                    algorithm: IntegrityAlgorithm::Sha1,
                    digest: decode_hex(shasum, 20)?,
                    source: IntegritySource::Shasum,
                });
            }
            let signatures = dist
                .get("signatures")
                .map(parse_signatures)
                .transpose()?
                .unwrap_or_default();
            let provenance = dist.get("attestations").map(parse_provenance).transpose()?;
            artifacts.push(ArtifactDescriptor {
                identity: crate::PackageIdentity {
                    ecosystem: PackageEcosystem::Npm,
                    name: name.to_owned(),
                    version: version.to_owned(),
                },
                source_url,
                integrity,
                signature_integrity,
                metadata_revision: revision.clone(),
                published_at: times
                    .and_then(|times| times.get(version))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                signatures,
                provenance,
            });
        }
        Ok(ResolvedMetadata {
            content_type: "application/json".to_owned(),
            body: body.to_vec(),
            artifacts,
            revision,
        })
    }
}

#[async_trait]
impl RegistryAdapter for NpmAdapter {
    fn ecosystem(&self) -> PackageEcosystem {
        PackageEcosystem::Npm
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            metadata_rewrite: true,
            signatures: true,
            provenance: true,
            layered_artifacts: false,
        }
    }

    async fn resolve(
        &self,
        package: &str,
        upstream: &dyn UpstreamClient,
    ) -> RegistryResult<ResolvedMetadata> {
        let response = upstream
            .fetch(UpstreamRequest {
                url: self.metadata_url(package)?.to_string(),
                accept: Some(FULL_METADATA_ACCEPT.to_owned()),
                authorization: self.authorization_header(),
                maximum_bytes: self.package_policy.limits.max_metadata_bytes,
            })
            .await?;
        require_success("npm package metadata", response.status)?;
        self.parse_metadata(&response.body, package)
    }

    fn rewrite_metadata(
        &self,
        metadata: &ResolvedMetadata,
        proxy_base_url: &str,
    ) -> RegistryResult<Vec<u8>> {
        let mut document: Value = serde_json::from_slice(&metadata.body)
            .map_err(|error| RegistryError::Invalid(format!("decode npm metadata: {error}")))?;
        let versions = document
            .get_mut("versions")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| RegistryError::Invalid("npm metadata omitted versions".to_owned()))?;
        let proxy = Url::parse(proxy_base_url)
            .map_err(|error| RegistryError::Invalid(format!("parse proxy base URL: {error}")))?;
        for descriptor in &metadata.artifacts {
            let version = versions
                .get_mut(&descriptor.identity.version)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    RegistryError::Invalid(format!(
                        "npm metadata omitted resolved version {}",
                        descriptor.identity.version
                    ))
                })?;
            let dist = version
                .get_mut("dist")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| RegistryError::Invalid("npm version omitted dist".to_owned()))?;
            let mut artifact = proxy.clone();
            artifact.set_path(&format!("/-/sendbox/artifacts/{}", descriptor.opaque_id()?));
            artifact.set_query(None);
            artifact.set_fragment(None);
            dist.insert("tarball".to_owned(), Value::String(artifact.to_string()));
        }
        serde_json::to_vec(&document)
            .map_err(|error| RegistryError::Invalid(format!("encode npm metadata: {error}")))
    }

    async fn fetch_artifact(
        &self,
        descriptor: &ArtifactDescriptor,
        destination: &Path,
        upstream: &dyn UpstreamClient,
    ) -> RegistryResult<u64> {
        let source = self.registry_relative_url(&descriptor.source_url)?;
        upstream
            .download(
                UpstreamRequest {
                    url: source.to_string(),
                    accept: Some("application/octet-stream".to_owned()),
                    authorization: self.authorization_header(),
                    maximum_bytes: self.package_policy.limits.max_download_bytes,
                },
                destination,
            )
            .await
    }

    async fn verify_artifact(
        &self,
        descriptor: &ArtifactDescriptor,
        artifact: &Path,
        trust: &TrustMetadata,
        provenance: &dyn PackageProvenanceVerifier,
    ) -> RegistryResult<VerificationEvidence> {
        let computed = compute_digests(artifact)?;
        let verified_integrity = verify_integrity(descriptor, &computed)?;
        let signature_key_ids = verify_registry_signatures(descriptor, &trust.registry_keys)?;
        if self.registry_policy.signature == EvidenceRequirement::Required
            && signature_key_ids.is_empty()
        {
            return Err(RegistryError::Verification(format!(
                "{}@{} has no required registry signature",
                descriptor.identity.name, descriptor.identity.version
            )));
        }
        let provenance_subjects = match descriptor.provenance.as_ref() {
            None if self.registry_policy.provenance == EvidenceRequirement::Required => {
                return Err(RegistryError::Verification(format!(
                    "{}@{} has no required provenance",
                    descriptor.identity.name, descriptor.identity.version
                )));
            }
            None => Vec::new(),
            Some(_) => {
                let bundle = trust.provenance_bundle.as_deref().ok_or_else(|| {
                    RegistryError::Verification("npm provenance bundle is unavailable".to_owned())
                })?;
                provenance
                    .verify(
                        &descriptor.identity,
                        &computed.sha512_hex,
                        bundle,
                        &trust.package_trust_root,
                    )
                    .await?
            }
        };
        Ok(VerificationEvidence {
            artifact_digest: ArtifactDigest {
                algorithm: "sha512".to_owned(),
                hex: computed.sha512_hex,
            },
            verified_integrity,
            signature_key_ids,
            provenance_subjects,
            trust_metadata_digest: trust.digest.clone(),
        })
    }

    fn normalize_manifest(
        &self,
        descriptor: &ArtifactDescriptor,
        artifact: &Path,
    ) -> RegistryResult<NormalizedManifest> {
        crate::scanner::normalize_npm_manifest(artifact, descriptor, &self.package_policy.limits)
    }

    fn enumerate_artifact(
        &self,
        _descriptor: &ArtifactDescriptor,
        artifact: &Path,
    ) -> RegistryResult<Vec<ArchiveEntry>> {
        crate::scanner::enumerate_npm_archive(artifact, &self.package_policy.limits)
    }

    fn inspect_risks(
        &self,
        descriptor: &ArtifactDescriptor,
        manifest: &NormalizedManifest,
        entries: &[ArchiveEntry],
        artifact: &Path,
    ) -> RegistryResult<Vec<RawFinding>> {
        crate::scanner::inspect_npm_archive(
            artifact,
            descriptor,
            manifest,
            entries,
            &self.package_policy.limits,
        )
    }
}

#[derive(Debug, Default)]
pub struct FailClosedPackageProvenanceVerifier;

#[async_trait]
impl PackageProvenanceVerifier for FailClosedPackageProvenanceVerifier {
    async fn verify(
        &self,
        _identity: &crate::PackageIdentity,
        _artifact_digest: &str,
        _bundle: &[u8],
        _trust_root: &[u8],
    ) -> RegistryResult<Vec<String>> {
        Err(RegistryError::Unsupported(
            "npm provenance bundle verification is unavailable because the Rust verifier does not validate every required transparency-log proof"
                .to_owned(),
        ))
    }
}

impl ArtifactDescriptor {
    pub fn opaque_id(&self) -> RegistryResult<String> {
        let encoded = serde_json::to_vec(self)
            .map_err(|error| RegistryError::Invalid(format!("encode artifact route: {error}")))?;
        let mut digest = Sha256::new();
        digest.update(b"sendbox-artifact-route-v1\0");
        digest.update(encoded);
        Ok(encode_hex(&digest.finalize()))
    }
}

#[derive(Default)]
struct ComputedDigests {
    sha1: Vec<u8>,
    sha256: Vec<u8>,
    sha384: Vec<u8>,
    sha512: Vec<u8>,
    sha512_hex: String,
}

fn compute_digests(path: &Path) -> RegistryResult<ComputedDigests> {
    let file = File::open(path).map_err(|error| {
        RegistryError::Verification(format!("open artifact {}: {error}", path.display()))
    })?;
    let mut reader = BufReader::new(file);
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut sha384 = Sha384::new();
    let mut sha512 = Sha512::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            RegistryError::Verification(format!("read artifact {}: {error}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        let bytes = &buffer[..read];
        sha1.update(bytes);
        sha256.update(bytes);
        sha384.update(bytes);
        sha512.update(bytes);
    }
    let sha512 = sha512.finalize().to_vec();
    Ok(ComputedDigests {
        sha1: sha1.finalize().to_vec(),
        sha256: sha256.finalize().to_vec(),
        sha384: sha384.finalize().to_vec(),
        sha512_hex: encode_hex(&sha512),
        sha512,
    })
}

fn verify_integrity(
    descriptor: &ArtifactDescriptor,
    computed: &ComputedDigests,
) -> RegistryResult<Vec<String>> {
    let mut verified = Vec::with_capacity(descriptor.integrity.len());
    for claim in &descriptor.integrity {
        let actual = match claim.algorithm {
            IntegrityAlgorithm::Sha1 => &computed.sha1,
            IntegrityAlgorithm::Sha256 => &computed.sha256,
            IntegrityAlgorithm::Sha384 => &computed.sha384,
            IntegrityAlgorithm::Sha512 => &computed.sha512,
        };
        if actual != &claim.digest {
            return Err(RegistryError::Verification(format!(
                "{}@{} failed {:?} integrity verification",
                descriptor.identity.name, descriptor.identity.version, claim.algorithm
            )));
        }
        verified.push(format!(
            "{:?}:{}",
            claim.algorithm,
            STANDARD.encode(&claim.digest)
        ));
    }
    Ok(verified)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryKeySet {
    keys: Vec<RegistryKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryKey {
    expires: Option<String>,
    keyid: String,
    keytype: String,
    scheme: String,
    key: String,
}

fn verify_registry_signatures(
    descriptor: &ArtifactDescriptor,
    registry_keys: &[u8],
) -> RegistryResult<Vec<String>> {
    if descriptor.signatures.is_empty() {
        return Ok(Vec::new());
    }
    let keys: RegistryKeySet = serde_json::from_slice(registry_keys).map_err(|error| {
        RegistryError::Verification(format!("decode npm registry keys: {error}"))
    })?;
    let published_at = OffsetDateTime::parse(
        descriptor
            .published_at
            .as_deref()
            .unwrap_or(MISSING_TIME_CUTOFF),
        &Rfc3339,
    )
    .map_err(|error| RegistryError::Verification(format!("parse npm publish time: {error}")))?;
    let message = format!(
        "{}@{}:{}",
        descriptor.identity.name, descriptor.identity.version, descriptor.signature_integrity
    );
    let mut verified = Vec::with_capacity(descriptor.signatures.len());
    for signature in &descriptor.signatures {
        let key = keys
            .keys
            .iter()
            .find(|key| key.keyid == signature.key_id)
            .ok_or_else(|| {
                RegistryError::Verification(format!(
                    "npm signature key {} is unavailable",
                    signature.key_id
                ))
            })?;
        if key.keytype != "ecdsa-sha2-nistp256" || key.scheme != "ecdsa-sha2-nistp256" {
            return Err(RegistryError::Unsupported(format!(
                "npm signature key {} uses unsupported type or scheme",
                key.keyid
            )));
        }
        if let Some(expires) = key.expires.as_deref() {
            let expires = OffsetDateTime::parse(expires, &Rfc3339).map_err(|error| {
                RegistryError::Verification(format!("parse npm key expiry: {error}"))
            })?;
            if published_at >= expires {
                return Err(RegistryError::Verification(format!(
                    "npm signature key {} expired before package publication",
                    key.keyid
                )));
            }
        }
        let key_der = decode_base64(&key.key)?;
        let verifying_key = VerifyingKey::from_public_key_der(&key_der).map_err(|error| {
            RegistryError::Verification(format!("decode npm signature key {}: {error}", key.keyid))
        })?;
        let signature_der = decode_base64(&signature.signature)?;
        let parsed_signature = Signature::from_der(&signature_der).map_err(|error| {
            RegistryError::Verification(format!(
                "decode npm registry signature {}: {error}",
                signature.key_id
            ))
        })?;
        verifying_key
            .verify(message.as_bytes(), &parsed_signature)
            .map_err(|_| {
                RegistryError::Verification(format!(
                    "npm registry signature {} is invalid",
                    signature.key_id
                ))
            })?;
        verified.push(signature.key_id.clone());
    }
    Ok(verified)
}

fn parse_sri(value: &str) -> RegistryResult<Vec<IntegrityClaim>> {
    let mut claims = Vec::new();
    for token in value.split_ascii_whitespace() {
        let token = token.split_once('?').map_or(token, |(value, _)| value);
        let (algorithm, digest) = token.split_once('-').ok_or_else(|| {
            RegistryError::Invalid("npm integrity token omitted an algorithm".to_owned())
        })?;
        let algorithm = match algorithm {
            "sha256" => IntegrityAlgorithm::Sha256,
            "sha384" => IntegrityAlgorithm::Sha384,
            "sha512" => IntegrityAlgorithm::Sha512,
            other => {
                return Err(RegistryError::Unsupported(format!(
                    "npm integrity uses unsupported algorithm {other}"
                )));
            }
        };
        claims.push(IntegrityClaim {
            algorithm,
            digest: decode_base64(digest)?,
            source: IntegritySource::Sri,
        });
    }
    if claims.is_empty() {
        return Err(RegistryError::Invalid(
            "npm integrity did not contain a digest".to_owned(),
        ));
    }
    Ok(claims)
}

fn parse_signatures(value: &Value) -> RegistryResult<Vec<SignatureClaim>> {
    let signatures = value
        .as_array()
        .ok_or_else(|| RegistryError::Invalid("npm dist.signatures must be an array".to_owned()))?;
    signatures
        .iter()
        .map(|signature| {
            let object = signature.as_object().ok_or_else(|| {
                RegistryError::Invalid("npm signature must be an object".to_owned())
            })?;
            Ok(SignatureClaim {
                key_id: required_string(object, "keyid", "npm signature")?.to_owned(),
                signature: required_string(object, "sig", "npm signature")?.to_owned(),
            })
        })
        .collect()
}

fn parse_provenance(value: &Value) -> RegistryResult<ProvenanceClaim> {
    let object = value.as_object().ok_or_else(|| {
        RegistryError::Invalid("npm dist.attestations must be an object".to_owned())
    })?;
    Ok(ProvenanceClaim {
        url: required_string(object, "url", "npm attestations")?.to_owned(),
    })
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    subject: &str,
) -> RegistryResult<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| RegistryError::Invalid(format!("{subject} omitted string field {field}")))
}

fn validate_package_name(package: &str) -> RegistryResult<()> {
    if package.is_empty()
        || package.len() > 256
        || package.contains('\\')
        || package.contains('\0')
        || package.starts_with('/')
        || package.ends_with('/')
        || package
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || package.starts_with('@') && package.matches('/').count() != 1
        || !package.starts_with('@') && package.contains('/')
    {
        return Err(RegistryError::Invalid(
            "invalid npm package name".to_owned(),
        ));
    }
    Ok(())
}

fn require_success(subject: &str, status: u16) -> RegistryResult<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(RegistryError::Upstream(format!(
            "{subject} returned HTTP {status}"
        )))
    }
}

fn decode_base64(value: &str) -> RegistryResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .map_err(|error| RegistryError::Invalid(format!("decode base64 value: {error}")))
}

fn decode_hex(value: &str, expected_bytes: usize) -> RegistryResult<Vec<u8>> {
    if value.len() != expected_bytes * 2 {
        return Err(RegistryError::Invalid(
            "hex digest has an invalid length".to_owned(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(value: u8) -> RegistryResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(RegistryError::Invalid(
            "hex digest contains a non-hex character".to_owned(),
        )),
    }
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
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey as _;
    use tempfile::tempdir;

    use super::*;
    use crate::UpstreamResponse;

    struct StaticUpstream {
        responses: Mutex<BTreeMap<String, UpstreamResponse>>,
    }

    #[async_trait]
    impl UpstreamClient for StaticUpstream {
        async fn fetch(&self, request: UpstreamRequest) -> RegistryResult<UpstreamResponse> {
            self.responses
                .lock()
                .expect("responses")
                .remove(&request.url)
                .ok_or_else(|| RegistryError::Upstream(format!("unexpected URL {}", request.url)))
        }

        async fn download(
            &self,
            _request: UpstreamRequest,
            _destination: &Path,
        ) -> RegistryResult<u64> {
            Err(RegistryError::Upstream("unexpected download".to_owned()))
        }
    }

    fn policy() -> PackageSupplyChainPolicy {
        PackageSupplyChainPolicy {
            enabled: true,
            registries: vec![PackageRegistryPolicy::default()],
            ..PackageSupplyChainPolicy::default()
        }
    }

    #[tokio::test]
    async fn rewrites_packument_tarballs_to_opaque_local_routes() {
        let bytes = b"artifact";
        let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(bytes)));
        let metadata = serde_json::json!({
            "name": "@acme/pkg",
            "_rev": "1-a",
            "time": {"1.0.0": "2024-01-01T00:00:00.000Z"},
            "versions": {
                "1.0.0": {
                    "name": "@acme/pkg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@acme/pkg/-/pkg-1.0.0.tgz",
                        "integrity": integrity
                    }
                }
            }
        });
        let metadata_url = "https://registry.npmjs.org/@acme%2Fpkg".to_owned();
        let upstream = StaticUpstream {
            responses: Mutex::new(BTreeMap::from([(
                metadata_url,
                UpstreamResponse {
                    status: 200,
                    content_type: Some("application/json".to_owned()),
                    body: serde_json::to_vec(&metadata).unwrap(),
                },
            )])),
        };
        let adapter = NpmAdapter::new(PackageRegistryPolicy::default(), policy(), None).unwrap();
        let resolved = adapter.resolve("@acme/pkg", &upstream).await.unwrap();
        let rewritten = adapter
            .rewrite_metadata(&resolved, "http://127.0.0.1:15081/")
            .unwrap();
        let rewritten: Value = serde_json::from_slice(&rewritten).unwrap();
        let tarball = rewritten["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert!(tarball.starts_with("http://127.0.0.1:15081/-/sendbox/artifacts/"));
        assert!(!tarball.contains("pkg-1.0.0.tgz"));
        assert_eq!(resolved.artifacts[0].identity.name, "@acme/pkg");
    }

    #[tokio::test]
    async fn verifies_integrity_and_registry_signature() {
        let directory = tempdir().unwrap();
        let artifact = directory.path().join("artifact.tgz");
        let bytes = b"signed artifact";
        std::fs::write(&artifact, bytes).unwrap();
        let digest = Sha512::digest(bytes).to_vec();
        let integrity = format!("sha512-{}", STANDARD.encode(&digest));
        let signing_key = SigningKey::from_slice(&[7_u8; 32]).unwrap();
        let verifying_der = signing_key.verifying_key().to_public_key_der().unwrap();
        let message = format!("example@1.0.0:{integrity}");
        let signature: Signature = signing_key.sign(message.as_bytes());
        let descriptor = ArtifactDescriptor {
            identity: crate::PackageIdentity {
                ecosystem: PackageEcosystem::Npm,
                name: "example".to_owned(),
                version: "1.0.0".to_owned(),
            },
            source_url: "https://registry.npmjs.org/example/-/example-1.0.0.tgz".to_owned(),
            integrity: vec![IntegrityClaim {
                algorithm: IntegrityAlgorithm::Sha512,
                digest,
                source: IntegritySource::Sri,
            }],
            signature_integrity: integrity,
            metadata_revision: "1-a".to_owned(),
            published_at: Some("2024-01-01T00:00:00.000Z".to_owned()),
            signatures: vec![SignatureClaim {
                key_id: "test-key".to_owned(),
                signature: STANDARD.encode(signature.to_der().as_bytes()),
            }],
            provenance: None,
        };
        let trust = TrustMetadata {
            registry_keys: serde_json::to_vec(&serde_json::json!({
                "keys": [{
                    "expires": null,
                    "keyid": "test-key",
                    "keytype": "ecdsa-sha2-nistp256",
                    "scheme": "ecdsa-sha2-nistp256",
                    "key": STANDARD.encode(verifying_der.as_bytes())
                }]
            }))
            .unwrap(),
            package_trust_root: Vec::new(),
            provenance_bundle: None,
            digest: "sha256:test".to_owned(),
        };
        let adapter = NpmAdapter::new(PackageRegistryPolicy::default(), policy(), None).unwrap();
        let evidence = adapter
            .verify_artifact(
                &descriptor,
                &artifact,
                &trust,
                &FailClosedPackageProvenanceVerifier,
            )
            .await
            .unwrap();
        assert_eq!(evidence.signature_key_ids, ["test-key"]);
        assert_eq!(evidence.artifact_digest.algorithm, "sha512");
    }

    #[tokio::test]
    async fn rejects_integrity_mismatch_and_advertised_provenance() {
        let directory = tempdir().unwrap();
        let artifact = directory.path().join("artifact.tgz");
        std::fs::write(&artifact, b"tampered").unwrap();
        let mut descriptor = ArtifactDescriptor {
            identity: crate::PackageIdentity {
                ecosystem: PackageEcosystem::Npm,
                name: "example".to_owned(),
                version: "1.0.0".to_owned(),
            },
            source_url: "https://registry.npmjs.org/example/-/example-1.0.0.tgz".to_owned(),
            integrity: vec![IntegrityClaim {
                algorithm: IntegrityAlgorithm::Sha512,
                digest: vec![0; 64],
                source: IntegritySource::Sri,
            }],
            signature_integrity: format!("sha512-{}", STANDARD.encode([0_u8; 64])),
            metadata_revision: "1-a".to_owned(),
            published_at: None,
            signatures: Vec::new(),
            provenance: None,
        };
        let trust = TrustMetadata {
            registry_keys: Vec::new(),
            package_trust_root: Vec::new(),
            provenance_bundle: None,
            digest: "sha256:test".to_owned(),
        };
        let adapter = NpmAdapter::new(PackageRegistryPolicy::default(), policy(), None).unwrap();
        assert!(
            adapter
                .verify_artifact(
                    &descriptor,
                    &artifact,
                    &trust,
                    &FailClosedPackageProvenanceVerifier,
                )
                .await
                .is_err()
        );

        let digest = Sha512::digest(b"tampered").to_vec();
        descriptor.integrity[0].digest = digest.clone();
        descriptor.signature_integrity = format!("sha512-{}", STANDARD.encode(digest));
        descriptor.provenance = Some(ProvenanceClaim {
            url: "https://registry.npmjs.org/-/npm/v1/attestations/example@1.0.0".to_owned(),
        });
        let trust = TrustMetadata {
            provenance_bundle: Some(br#"{"attestations":[]}"#.to_vec()),
            ..trust
        };
        assert!(
            adapter
                .verify_artifact(
                    &descriptor,
                    &artifact,
                    &trust,
                    &FailClosedPackageProvenanceVerifier,
                )
                .await
                .is_err()
        );
    }
}
