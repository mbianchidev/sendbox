use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, BufReader, Read as _};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, Path as AxumPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::Stream;
use sendbox_config::{AtomicWriteMode, atomic_write_file, ensure_directory};
use sendbox_policy::{PackageFindingKind, PackageSupplyChainPolicy};
use serde::Serialize;
use sha2::{Digest as _, Sha512};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::cache::CacheStore;
use crate::{
    ArtifactDescriptor, ArtifactDigest, CacheKey, CacheOutcome, PackageCache,
    PackageProvenanceVerifier, PackageSecurityReport, PackageVerdictRecord,
    REGISTRY_SCANNER_VERSION, RawFinding, RegistryAdapter, RegistryError, RegistryResult,
    UpstreamClient, Verdict, evaluate_findings, package_policy_digest,
};

const REPORT_FILE_MODE: u32 = 0o600;
const REPORT_DIRECTORY_MODE: u32 = 0o700;

#[derive(Debug, Clone)]
pub struct RegistryProxyConfiguration {
    pub base_url: String,
    pub cache_root: PathBuf,
    pub report_path: PathBuf,
    pub session_id: String,
    pub policy: PackageSupplyChainPolicy,
}

#[derive(Debug, Clone)]
pub enum ArtifactAnalysis {
    Allowed {
        path: PathBuf,
        record: PackageVerdictRecord,
        cleanup: bool,
    },
    Rejected {
        record: PackageVerdictRecord,
    },
}

#[derive(Clone)]
pub struct RegistryProxy {
    inner: Arc<RegistryProxyInner>,
}

struct RegistryProxyInner {
    base_url: String,
    cache: PackageCache,
    report_path: PathBuf,
    session_id: String,
    policy: PackageSupplyChainPolicy,
    policy_digest: String,
    adapter: Arc<dyn RegistryAdapter>,
    upstream: Arc<dyn UpstreamClient>,
    provenance: Arc<dyn PackageProvenanceVerifier>,
    descriptors: RwLock<BTreeMap<String, ArtifactDescriptor>>,
    report: Mutex<PackageSecurityReport>,
}

impl RegistryProxy {
    pub fn new(
        configuration: RegistryProxyConfiguration,
        adapter: Arc<dyn RegistryAdapter>,
        upstream: Arc<dyn UpstreamClient>,
        provenance: Arc<dyn PackageProvenanceVerifier>,
    ) -> RegistryResult<Self> {
        configuration
            .policy
            .validate()
            .map_err(|error| RegistryError::Invalid(error.to_string()))?;
        if !configuration.policy.enabled {
            return Err(RegistryError::Invalid(
                "registry proxy requires enabled package policy".to_owned(),
            ));
        }
        validate_base_url(&configuration.base_url)?;
        if configuration.session_id.is_empty() || configuration.session_id.len() > 128 {
            return Err(RegistryError::Invalid(
                "registry proxy session identifier is invalid".to_owned(),
            ));
        }
        if !configuration
            .policy
            .registries
            .iter()
            .any(|registry| registry.ecosystem == adapter.ecosystem())
        {
            return Err(RegistryError::Invalid(
                "registry adapter has no matching package policy registry".to_owned(),
            ));
        }
        let report_parent = configuration
            .report_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| {
                RegistryError::Invalid("package report path has no parent".to_owned())
            })?;
        ensure_directory(report_parent, REPORT_DIRECTORY_MODE).map_err(|error| {
            RegistryError::Cache(format!(
                "prepare package report directory {}: {error}",
                report_parent.display()
            ))
        })?;
        let cache = PackageCache::open(
            &configuration.cache_root,
            configuration.policy.cache.clone(),
        )?;
        let report = PackageSecurityReport::enabled();
        persist_report(
            &configuration.report_path,
            &report,
            configuration.policy.limits.max_report_bytes,
        )?;
        Ok(Self {
            inner: Arc::new(RegistryProxyInner {
                base_url: configuration.base_url,
                cache,
                report_path: configuration.report_path,
                session_id: configuration.session_id,
                policy_digest: package_policy_digest(&configuration.policy)?,
                policy: configuration.policy,
                adapter,
                upstream,
                provenance,
                descriptors: RwLock::new(BTreeMap::new()),
                report: Mutex::new(report),
            }),
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/-/ping", get(ping))
            .route("/-/sendbox/status", get(status))
            .route("/-/sendbox/artifacts/{artifact_id}", get(artifact))
            .fallback(get(metadata))
            .with_state(self.clone())
    }

    pub async fn serve(
        self,
        listener: TcpListener,
        cancellation: CancellationToken,
    ) -> RegistryResult<()> {
        axum::serve(listener, self.router())
            .with_graceful_shutdown(cancellation.cancelled_owned())
            .await
            .map_err(|error| RegistryError::Upstream(format!("serve registry proxy: {error}")))
    }

    pub async fn resolve_metadata(&self, package: &str) -> RegistryResult<Vec<u8>> {
        let metadata = self
            .inner
            .adapter
            .resolve(package, self.inner.upstream.as_ref())
            .await?;
        if metadata.artifacts.len()
            > usize::try_from(self.inner.policy.limits.max_entries).unwrap_or(usize::MAX)
        {
            return Err(RegistryError::Invalid(
                "npm metadata exceeds the configured version count".to_owned(),
            ));
        }
        let mut descriptors = self.inner.descriptors.write().await;
        for descriptor in &metadata.artifacts {
            let identifier = descriptor.opaque_id()?;
            if let Some(existing) = descriptors.get(&identifier)
                && existing != descriptor
            {
                return Err(RegistryError::Verification(
                    "opaque package route collision detected".to_owned(),
                ));
            }
            if !descriptors.contains_key(&identifier)
                && descriptors.len()
                    >= usize::try_from(self.inner.policy.cache.max_entries).unwrap_or(usize::MAX)
            {
                return Err(RegistryError::Invalid(
                    "registry proxy descriptor table is full".to_owned(),
                ));
            }
            descriptors.insert(identifier, descriptor.clone());
        }
        drop(descriptors);
        self.inner
            .adapter
            .rewrite_metadata(&metadata, &self.inner.base_url)
    }

    pub async fn analyze_artifact(&self, artifact_id: &str) -> RegistryResult<ArtifactAnalysis> {
        let descriptor = self
            .inner
            .descriptors
            .read()
            .await
            .get(artifact_id)
            .cloned()
            .ok_or_else(|| RegistryError::Invalid("unknown package artifact route".to_owned()))?;
        let route_lock = self.inner.cache.acquire_route_lock(artifact_id).await?;

        let trust = match self
            .inner
            .adapter
            .fetch_trust_metadata(&descriptor, self.inner.upstream.as_ref())
            .await
        {
            Ok(trust) => trust,
            Err(error) => {
                let record = self.failure_record(
                    &descriptor,
                    expected_sha512(&descriptor),
                    None,
                    error_finding(error, trust_failure_kind(&descriptor)),
                    self.initial_cache_outcome(),
                );
                self.append_report(record.clone()).await?;
                return Ok(ArtifactAnalysis::Rejected { record });
            }
        };

        if let Some(digest) = expected_sha512(&descriptor) {
            let key = self.cache_key(&descriptor, digest, &trust.digest);
            match self.lookup_cache(key.clone()).await {
                Ok(Some(hit)) => {
                    let mut record = hit.record;
                    record.cache = if route_lock.shared {
                        CacheOutcome::SharedAnalysis
                    } else {
                        CacheOutcome::Hit
                    };
                    record.requested_by_session = self.inner.session_id.clone();
                    self.append_report(record.clone()).await?;
                    return if record.verdict == Verdict::Allow {
                        Ok(ArtifactAnalysis::Allowed {
                            path: hit.artifact_path.ok_or_else(|| {
                                RegistryError::Cache(
                                    "approved cache record omitted its artifact".to_owned(),
                                )
                            })?,
                            record,
                            cleanup: false,
                        })
                    } else {
                        Ok(ArtifactAnalysis::Rejected { record })
                    };
                }
                Ok(None) => {}
                Err(error) => {
                    let record = self.failure_record(
                        &descriptor,
                        expected_sha512(&descriptor),
                        None,
                        error_finding(error, PackageFindingKind::ScannerFailure),
                        self.initial_cache_outcome(),
                    );
                    self.append_report(record.clone()).await?;
                    return Ok(ArtifactAnalysis::Rejected { record });
                }
            }
        }

        let quarantine = self.inner.cache.quarantine_path()?;
        if let Err(error) = self
            .inner
            .adapter
            .fetch_artifact(&descriptor, &quarantine, self.inner.upstream.as_ref())
            .await
        {
            let _ = remove_transient(&quarantine);
            let record = self.failure_record(
                &descriptor,
                expected_sha512(&descriptor),
                None,
                error_finding(error, PackageFindingKind::ScannerFailure),
                self.initial_cache_outcome(),
            );
            self.append_report(record.clone()).await?;
            return Ok(ArtifactAnalysis::Rejected { record });
        }

        let digest_path = quarantine.clone();
        let artifact_digest =
            match tokio::task::spawn_blocking(move || sha512_digest(&digest_path)).await {
                Ok(Ok(digest)) => digest,
                Ok(Err(error)) => {
                    let _ = remove_transient(&quarantine);
                    let record = self.failure_record(
                        &descriptor,
                        expected_sha512(&descriptor),
                        None,
                        error_finding(error, PackageFindingKind::ScannerFailure),
                        self.initial_cache_outcome(),
                    );
                    self.append_report(record.clone()).await?;
                    return Ok(ArtifactAnalysis::Rejected { record });
                }
                Err(error) => {
                    let _ = remove_transient(&quarantine);
                    let record = self.failure_record(
                        &descriptor,
                        expected_sha512(&descriptor),
                        None,
                        RawFinding {
                            kind: PackageFindingKind::ScannerFailure,
                            path: None,
                            detail: format!("join package digest task: {error}"),
                        },
                        self.initial_cache_outcome(),
                    );
                    self.append_report(record.clone()).await?;
                    return Ok(ArtifactAnalysis::Rejected { record });
                }
            };
        let key = self.cache_key(&descriptor, artifact_digest.clone(), &trust.digest);
        match self.lookup_cache(key.clone()).await {
            Ok(Some(hit)) => {
                remove_transient(&quarantine)?;
                let mut record = hit.record;
                record.cache = CacheOutcome::SharedAnalysis;
                record.requested_by_session = self.inner.session_id.clone();
                self.append_report(record.clone()).await?;
                return if record.verdict == Verdict::Allow {
                    Ok(ArtifactAnalysis::Allowed {
                        path: hit.artifact_path.ok_or_else(|| {
                            RegistryError::Cache(
                                "approved cache record omitted its artifact".to_owned(),
                            )
                        })?,
                        record,
                        cleanup: false,
                    })
                } else {
                    Ok(ArtifactAnalysis::Rejected { record })
                };
            }
            Ok(None) => {}
            Err(error) => {
                let _ = remove_transient(&quarantine);
                let record = self.failure_record(
                    &descriptor,
                    Some(artifact_digest),
                    None,
                    error_finding(error, PackageFindingKind::ScannerFailure),
                    self.initial_cache_outcome(),
                );
                self.append_report(record.clone()).await?;
                return Ok(ArtifactAnalysis::Rejected { record });
            }
        }

        let verification = match self
            .inner
            .adapter
            .verify_artifact(
                &descriptor,
                &quarantine,
                &trust,
                self.inner.provenance.as_ref(),
            )
            .await
        {
            Ok(verification) => Some(verification),
            Err(error) => {
                let finding = error_finding(error, PackageFindingKind::IntegrityFailure);
                return self
                    .finalize_analysis(
                        descriptor,
                        artifact_digest,
                        trust.digest,
                        None,
                        vec![finding],
                        quarantine,
                    )
                    .await;
            }
        };

        let manifest = match self
            .inner
            .adapter
            .normalize_manifest(&descriptor, &quarantine)
        {
            Ok(manifest) => manifest,
            Err(error) => {
                let finding = error_finding(error, PackageFindingKind::ScannerFailure);
                return self
                    .finalize_analysis(
                        descriptor,
                        artifact_digest,
                        trust.digest,
                        verification,
                        vec![finding],
                        quarantine,
                    )
                    .await;
            }
        };
        let entries = match self
            .inner
            .adapter
            .enumerate_artifact(&descriptor, &quarantine)
        {
            Ok(entries) => entries,
            Err(error) => {
                let finding = error_finding(error, PackageFindingKind::ScannerFailure);
                return self
                    .finalize_analysis(
                        descriptor,
                        artifact_digest,
                        trust.digest,
                        verification,
                        vec![finding],
                        quarantine,
                    )
                    .await;
            }
        };
        let findings =
            match self
                .inner
                .adapter
                .inspect_risks(&descriptor, &manifest, &entries, &quarantine)
            {
                Ok(findings) => findings,
                Err(error) => vec![error_finding(error, PackageFindingKind::ScannerFailure)],
            };
        self.finalize_analysis(
            descriptor,
            artifact_digest,
            trust.digest,
            verification,
            findings,
            quarantine,
        )
        .await
    }

    pub async fn report(&self) -> PackageSecurityReport {
        self.inner.report.lock().await.clone()
    }

    async fn finalize_analysis(
        &self,
        descriptor: ArtifactDescriptor,
        artifact_digest: ArtifactDigest,
        trust_digest: String,
        verification: Option<crate::VerificationEvidence>,
        findings: Vec<RawFinding>,
        quarantine: PathBuf,
    ) -> RegistryResult<ArtifactAnalysis> {
        let digest_label = format!("{}:{}", artifact_digest.algorithm, artifact_digest.hex);
        let decision = evaluate_findings(
            &self.inner.policy,
            &descriptor.identity,
            &digest_label,
            findings,
        );
        let record = PackageVerdictRecord {
            identity: descriptor.identity.clone(),
            upstream: descriptor.source_url.clone(),
            artifact_digest: Some(artifact_digest.clone()),
            policy_digest: self.inner.policy_digest.clone(),
            scanner_version: REGISTRY_SCANNER_VERSION.to_owned(),
            verification,
            findings: decision.findings,
            verdict: decision.verdict,
            cache: self.initial_cache_outcome(),
            requested_by_session: self.inner.session_id.clone(),
        };
        let key = self.cache_key(&descriptor, artifact_digest, &trust_digest);
        let cache = self.inner.cache.clone();
        let stored_record = record.clone();
        let stored_quarantine = quarantine.clone();
        let store = tokio::task::spawn_blocking(move || {
            cache.store(&key, &stored_record, &stored_quarantine)
        })
        .await
        .map_err(|error| RegistryError::Cache(format!("join package cache task: {error}")))?;
        let store = match store {
            Ok(store) => store,
            Err(error) => {
                let _ = remove_transient(&quarantine);
                let failed = self.failure_record(
                    &descriptor,
                    record.artifact_digest.clone(),
                    record.verification.clone(),
                    error_finding(error, PackageFindingKind::ScannerFailure),
                    self.initial_cache_outcome(),
                );
                self.append_report(failed.clone()).await?;
                return Ok(ArtifactAnalysis::Rejected { record: failed });
            }
        };
        if let Err(error) = self.append_report(record.clone()).await {
            if store.cleanup_artifact
                && let Some(path) = store.artifact_path.as_deref()
            {
                let _ = remove_transient(path);
            }
            return Err(error);
        }
        delivery_from_store(record, store)
    }

    fn cache_key(
        &self,
        descriptor: &ArtifactDescriptor,
        artifact_digest: ArtifactDigest,
        trust_digest: &str,
    ) -> CacheKey {
        CacheKey {
            ecosystem: descriptor.identity.ecosystem,
            artifact_digest,
            scanner_version: REGISTRY_SCANNER_VERSION.to_owned(),
            policy_digest: self.inner.policy_digest.clone(),
            trust_metadata_digest: trust_digest.to_owned(),
        }
    }

    async fn lookup_cache(&self, key: CacheKey) -> RegistryResult<Option<crate::CacheEntry>> {
        let cache = self.inner.cache.clone();
        tokio::task::spawn_blocking(move || cache.lookup(&key))
            .await
            .map_err(|error| RegistryError::Cache(format!("join package cache task: {error}")))?
    }

    fn failure_record(
        &self,
        descriptor: &ArtifactDescriptor,
        artifact_digest: Option<ArtifactDigest>,
        verification: Option<crate::VerificationEvidence>,
        finding: RawFinding,
        cache: CacheOutcome,
    ) -> PackageVerdictRecord {
        let digest_label = artifact_digest
            .as_ref()
            .map(|digest| format!("{}:{}", digest.algorithm, digest.hex))
            .unwrap_or_default();
        let decision = evaluate_findings(
            &self.inner.policy,
            &descriptor.identity,
            &digest_label,
            vec![finding],
        );
        PackageVerdictRecord {
            identity: descriptor.identity.clone(),
            upstream: descriptor.source_url.clone(),
            artifact_digest,
            policy_digest: self.inner.policy_digest.clone(),
            scanner_version: REGISTRY_SCANNER_VERSION.to_owned(),
            verification,
            findings: decision.findings,
            verdict: decision.verdict,
            cache,
            requested_by_session: self.inner.session_id.clone(),
        }
    }

    async fn append_report(&self, record: PackageVerdictRecord) -> RegistryResult<()> {
        let mut report = self.inner.report.lock().await;
        let mut next = report.clone();
        next.push(record);
        let report_limit =
            usize::try_from(self.inner.policy.limits.max_report_findings).unwrap_or(usize::MAX);
        next.validate(report_limit, report_limit)
            .map_err(RegistryError::Inspection)?;
        let report_path = self.inner.report_path.clone();
        let persisted = next.clone();
        let maximum_bytes = self.inner.policy.limits.max_report_bytes;
        tokio::task::spawn_blocking(move || {
            persist_report(&report_path, &persisted, maximum_bytes)
        })
        .await
        .map_err(|error| {
            RegistryError::Cache(format!("join report persistence task: {error}"))
        })??;
        *report = next;
        Ok(())
    }

    fn initial_cache_outcome(&self) -> CacheOutcome {
        if self.inner.cache.enabled() {
            CacheOutcome::Miss
        } else {
            CacheOutcome::Disabled
        }
    }
}

async fn ping() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true}))
}

async fn status(State(proxy): State<RegistryProxy>) -> impl IntoResponse {
    Json(proxy.report().await)
}

async fn metadata(State(proxy): State<RegistryProxy>, OriginalUri(uri): OriginalUri) -> Response {
    let package = match decode_package_path(uri.path()) {
        Ok(package) => package,
        Err(error) => return error_response(error),
    };
    match proxy.resolve_metadata(&package).await {
        Ok(body) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(error) => error_response(error),
    }
}

async fn artifact(
    State(proxy): State<RegistryProxy>,
    AxumPath(artifact_id): AxumPath<String>,
) -> Response {
    match proxy.analyze_artifact(&artifact_id).await {
        Ok(ArtifactAnalysis::Rejected { record }) => {
            (StatusCode::UNPROCESSABLE_ENTITY, Json(record)).into_response()
        }
        Ok(ArtifactAnalysis::Allowed {
            path,
            cleanup,
            record: _,
        }) => match artifact_body(&path, cleanup).await {
            Ok(response) => response,
            Err(error) => error_response(error),
        },
        Err(error) => error_response(error),
    }
}

async fn artifact_body(path: &Path, cleanup: bool) -> RegistryResult<Response> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| RegistryError::Cache(format!("open approved artifact: {error}")))?;
    let length = file
        .metadata()
        .map_err(|error| RegistryError::Cache(format!("inspect approved artifact: {error}")))?
        .len();
    let stream = CleanupStream {
        inner: ReaderStream::new(tokio::fs::File::from_std(file)),
        cleanup: cleanup.then(|| path.to_path_buf()),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, length)
        .header(
            header::CACHE_CONTROL,
            "private, max-age=31536000, immutable",
        )
        .body(Body::from_stream(stream))
        .map_err(|error| RegistryError::Cache(format!("build artifact response: {error}")))
}

fn delivery_from_store(
    record: PackageVerdictRecord,
    store: CacheStore,
) -> RegistryResult<ArtifactAnalysis> {
    if record.verdict == Verdict::Allow {
        Ok(ArtifactAnalysis::Allowed {
            path: store.artifact_path.ok_or_else(|| {
                RegistryError::Cache("approved analysis omitted its artifact".to_owned())
            })?,
            record,
            cleanup: store.cleanup_artifact,
        })
    } else {
        Ok(ArtifactAnalysis::Rejected { record })
    }
}

fn expected_sha512(descriptor: &ArtifactDescriptor) -> Option<ArtifactDigest> {
    descriptor
        .integrity
        .iter()
        .find(|claim| claim.algorithm == crate::IntegrityAlgorithm::Sha512)
        .map(|claim| ArtifactDigest {
            algorithm: "sha512".to_owned(),
            hex: encode_hex(&claim.digest),
        })
}

fn trust_failure_kind(descriptor: &ArtifactDescriptor) -> PackageFindingKind {
    if descriptor.provenance.is_some() && descriptor.signatures.is_empty() {
        PackageFindingKind::ProvenanceFailure
    } else {
        PackageFindingKind::SignatureFailure
    }
}

fn sha512_digest(path: &Path) -> RegistryResult<ArtifactDigest> {
    let file = std::fs::File::open(path)
        .map_err(|error| RegistryError::Inspection(format!("open package artifact: {error}")))?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha512::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            RegistryError::Inspection(format!("read package artifact: {error}"))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(ArtifactDigest {
        algorithm: "sha512".to_owned(),
        hex: encode_hex(&digest.finalize()),
    })
}

fn error_finding(error: RegistryError, fallback: PackageFindingKind) -> RawFinding {
    let kind = error.finding_kind().unwrap_or(match &error {
        RegistryError::Timeout(_) => PackageFindingKind::Timeout,
        RegistryError::Unsupported(_) => PackageFindingKind::UnsupportedContent,
        _ => fallback,
    });
    RawFinding {
        kind,
        path: None,
        detail: error.to_string(),
    }
}

fn validate_base_url(value: &str) -> RegistryResult<()> {
    let url = Url::parse(value)
        .map_err(|error| RegistryError::Invalid(format!("parse registry proxy URL: {error}")))?;
    if url.scheme() != "http"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_none()
    {
        return Err(RegistryError::Invalid(
            "registry proxy URL must be an unauthenticated loopback HTTP origin with a port"
                .to_owned(),
        ));
    }
    match url.host() {
        Some(Host::Ipv4(address)) if IpAddr::V4(address).is_loopback() => Ok(()),
        Some(Host::Ipv6(address)) if IpAddr::V6(address).is_loopback() => Ok(()),
        _ => Err(RegistryError::Invalid(
            "registry proxy URL must use a loopback IP address".to_owned(),
        )),
    }
}

fn decode_package_path(path: &str) -> RegistryResult<String> {
    let encoded = path.strip_prefix('/').unwrap_or(path);
    if encoded.is_empty() || encoded.starts_with("-/") {
        return Err(RegistryError::Invalid(
            "npm package metadata path is invalid".to_owned(),
        ));
    }
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(RegistryError::Invalid(
                    "npm package path has invalid percent encoding".to_owned(),
                ));
            }
            let high = decode_hex_digit(bytes[index + 1])?;
            let low = decode_hex_digit(bytes[index + 2])?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let package = String::from_utf8(decoded)
        .map_err(|_| RegistryError::Invalid("npm package path is not UTF-8".to_owned()))?;
    if package.chars().any(char::is_control) {
        return Err(RegistryError::Invalid(
            "npm package path contains control characters".to_owned(),
        ));
    }
    Ok(package)
}

fn decode_hex_digit(byte: u8) -> RegistryResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RegistryError::Invalid(
            "npm package path has invalid percent encoding".to_owned(),
        )),
    }
}

fn persist_report(
    path: &Path,
    report: &PackageSecurityReport,
    maximum_bytes: u64,
) -> RegistryResult<()> {
    let encoded = serde_json::to_vec(report)
        .map_err(|error| RegistryError::Cache(format!("encode package report: {error}")))?;
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > maximum_bytes {
        return Err(RegistryError::Inspection(format!(
            "package report exceeds the configured {maximum_bytes}-byte limit"
        )));
    }
    atomic_write_file(path, &encoded, REPORT_FILE_MODE, AtomicWriteMode::Replace)
        .map_err(|error| RegistryError::Cache(format!("write package report: {error}")))
}

fn remove_transient(path: &Path) -> RegistryResult<()> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            std::fs::remove_file(path).map_err(|error| {
                RegistryError::Cache(format!("remove transient artifact: {error}"))
            })
        }
        Ok(_) => Err(RegistryError::Cache(
            "refusing to remove non-regular transient artifact".to_owned(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RegistryError::Cache(format!(
            "inspect transient artifact: {error}"
        ))),
    }
}

fn error_response(error: RegistryError) -> Response {
    let status = match error {
        RegistryError::Invalid(_) => StatusCode::BAD_REQUEST,
        RegistryError::Upstream(_) => StatusCode::BAD_GATEWAY,
        RegistryError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        RegistryError::Verification(_)
        | RegistryError::Inspection(_)
        | RegistryError::Unsupported(_)
        | RegistryError::Finding { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        RegistryError::Cache(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(ProxyError {
            error: error.to_string(),
        }),
    )
        .into_response()
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

#[derive(Serialize)]
struct ProxyError {
    error: String,
}

struct CleanupStream {
    inner: ReaderStream<tokio::fs::File>,
    cleanup: Option<PathBuf>,
}

impl Stream for CleanupStream {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(context)
    }
}

impl Drop for CleanupStream {
    fn drop(&mut self) {
        if let Some(path) = self.cleanup.take() {
            let _ = remove_transient(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::net::SocketAddr;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use sendbox_policy::{
        PackageAction, PackageEcosystem, PackageRegistryPolicy, PackageSupplyChainPolicy,
    };
    use serde_json::Value;
    use tar::{Builder, EntryType, Header};
    use tempfile::tempdir;

    use super::*;
    use crate::{
        NpmAdapter, NpmPackageProvenanceVerifier, PackageFinding, UpstreamRequest, UpstreamResponse,
    };

    #[derive(Debug)]
    struct FixtureUpstream {
        metadata: Vec<u8>,
        artifact: Vec<u8>,
        downloads: AtomicUsize,
    }

    #[async_trait]
    impl UpstreamClient for FixtureUpstream {
        async fn fetch(&self, _request: UpstreamRequest) -> RegistryResult<UpstreamResponse> {
            Ok(UpstreamResponse {
                status: 200,
                content_type: Some("application/json".to_owned()),
                body: self.metadata.clone(),
            })
        }

        async fn download(
            &self,
            _request: UpstreamRequest,
            destination: &Path,
        ) -> RegistryResult<u64> {
            self.downloads.fetch_add(1, Ordering::SeqCst);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(destination)
                .map_err(|error| RegistryError::Cache(error.to_string()))?;
            use std::io::Write as _;
            file.write_all(&self.artifact)
                .map_err(|error| RegistryError::Cache(error.to_string()))?;
            Ok(u64::try_from(self.artifact.len()).unwrap())
        }
    }

    fn artifact(script: Option<&str>) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);
        let manifest = match script {
            Some(script) => format!(
                r#"{{"name":"fixture","version":"1.0.0","scripts":{{"install":"{script}"}}}}"#
            ),
            None => r#"{"name":"fixture","version":"1.0.0"}"#.to_owned(),
        };
        let mut header = Header::new_gnu();
        header.set_size(u64::try_from(manifest.len()).unwrap());
        header.set_mode(0o644);
        header.set_entry_type(EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", manifest.as_bytes())
            .unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    fn metadata(artifact: &[u8]) -> Vec<u8> {
        let mut digest = Sha512::new();
        digest.update(artifact);
        serde_json::to_vec(&serde_json::json!({
            "name": "fixture",
            "_rev": "1-a",
            "versions": {
                "1.0.0": {
                    "name": "fixture",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz",
                        "integrity": format!("sha512-{}", STANDARD.encode(digest.finalize()))
                    }
                }
            }
        }))
        .unwrap()
    }

    fn policy() -> PackageSupplyChainPolicy {
        PackageSupplyChainPolicy {
            enabled: true,
            registries: vec![PackageRegistryPolicy::default()],
            default_finding_action: PackageAction::Deny,
            ..PackageSupplyChainPolicy::default()
        }
    }

    fn proxy(
        root: &Path,
        policy: PackageSupplyChainPolicy,
        upstream: Arc<FixtureUpstream>,
    ) -> RegistryProxy {
        let adapter = NpmAdapter::new(policy.registries[0].clone(), policy.clone(), None).unwrap();
        RegistryProxy::new(
            RegistryProxyConfiguration {
                base_url: "http://127.0.0.1:4873/".to_owned(),
                cache_root: root.join("cache"),
                report_path: root.join("run/report.json"),
                session_id: "fixture-session".to_owned(),
                policy,
            },
            Arc::new(adapter),
            upstream,
            Arc::new(NpmPackageProvenanceVerifier),
        )
        .unwrap()
    }

    async fn artifact_id(proxy: &RegistryProxy) -> String {
        let rewritten = proxy.resolve_metadata("fixture").await.unwrap();
        let document: Value = serde_json::from_slice(&rewritten).unwrap();
        let tarball = document["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        Url::parse(tarball)
            .unwrap()
            .path_segments()
            .unwrap()
            .next_back()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_analysis_and_cache_hit() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let bytes = artifact(None);
        let upstream = Arc::new(FixtureUpstream {
            metadata: metadata(&bytes),
            artifact: bytes,
            downloads: AtomicUsize::new(0),
        });
        let proxy = proxy(&root, policy(), upstream.clone());
        let identifier = artifact_id(&proxy).await;
        let (first, second) = tokio::join!(
            proxy.analyze_artifact(&identifier),
            proxy.analyze_artifact(&identifier)
        );
        assert!(matches!(first.unwrap(), ArtifactAnalysis::Allowed { .. }));
        assert!(matches!(second.unwrap(), ArtifactAnalysis::Allowed { .. }));
        assert_eq!(upstream.downloads.load(Ordering::SeqCst), 1);
        let third = proxy.analyze_artifact(&identifier).await.unwrap();
        assert!(matches!(third, ArtifactAnalysis::Allowed { .. }));
        assert_eq!(upstream.downloads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn policy_change_forces_reanalysis() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let bytes = artifact(None);
        let upstream = Arc::new(FixtureUpstream {
            metadata: metadata(&bytes),
            artifact: bytes,
            downloads: AtomicUsize::new(0),
        });
        let first = proxy(&root, policy(), upstream.clone());
        let identifier = artifact_id(&first).await;
        assert!(matches!(
            first.analyze_artifact(&identifier).await.unwrap(),
            ArtifactAnalysis::Allowed { .. }
        ));

        let mut changed = policy();
        changed.allow_legacy_sha1 = false;
        let second = proxy(&root, changed, upstream.clone());
        let identifier = artifact_id(&second).await;
        assert!(matches!(
            second.analyze_artifact(&identifier).await.unwrap(),
            ArtifactAnalysis::Allowed { .. }
        ));
        assert_eq!(upstream.downloads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rejected_artifact_is_not_delivered_or_retained() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let bytes = artifact(Some("node install.js"));
        let upstream = Arc::new(FixtureUpstream {
            metadata: metadata(&bytes),
            artifact: bytes,
            downloads: AtomicUsize::new(0),
        });
        let proxy = proxy(&root, policy(), upstream);
        let identifier = artifact_id(&proxy).await;
        let analysis = proxy.analyze_artifact(&identifier).await.unwrap();
        assert!(matches!(analysis, ArtifactAnalysis::Rejected { .. }));
        assert_eq!(
            std::fs::read_dir(root.join("cache/quarantine"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(root.join("cache/blobs")).unwrap().count(),
            0
        );
    }

    #[test]
    fn metadata_path_decodes_scoped_names_without_form_semantics() {
        assert_eq!(
            decode_package_path("/@scope%2Fpackage").unwrap(),
            "@scope/package"
        );
        assert_eq!(decode_package_path("/left-pad").unwrap(), "left-pad");
        assert!(decode_package_path("/bad%2").is_err());
    }

    #[test]
    fn base_url_must_be_loopback_http() {
        assert!(validate_base_url("http://127.0.0.1:4873/").is_ok());
        assert!(validate_base_url("https://127.0.0.1:4873/").is_err());
        assert!(validate_base_url("http://registry.npmjs.org:4873/").is_err());
    }

    #[test]
    fn cache_hit_report_is_bounded() {
        let mut report = PackageSecurityReport::enabled();
        assert!(report.validate(0, 0).is_ok());
        report.push(PackageVerdictRecord {
            identity: crate::PackageIdentity {
                ecosystem: PackageEcosystem::Npm,
                name: "fixture".to_owned(),
                version: "1.0.0".to_owned(),
            },
            upstream: "https://registry.npmjs.org/fixture".to_owned(),
            artifact_digest: None,
            policy_digest: "policy".to_owned(),
            scanner_version: REGISTRY_SCANNER_VERSION.to_owned(),
            verification: None,
            findings: vec![PackageFinding {
                kind: PackageFindingKind::Timeout,
                action: PackageAction::Deny,
                path: None,
                detail: "timeout".to_owned(),
            }],
            verdict: Verdict::Deny,
            cache: CacheOutcome::Disabled,
            requested_by_session: "session".to_owned(),
        });
        assert!(report.validate(1, 0).is_err());
        assert!(report.validate(1, 1).is_ok());
    }

    #[test]
    fn report_persistence_enforces_the_byte_limit_before_installing() {
        let temporary = tempdir().expect("temporary directory");
        let root = temporary.path().canonicalize().expect("canonical temp dir");
        let path = root.join("report.json");
        let report = PackageSecurityReport::enabled();
        let encoded = serde_json::to_vec(&report).expect("encode report");
        assert!(
            persist_report(
                &path,
                &report,
                u64::try_from(encoded.len()).expect("report length"),
            )
            .is_ok()
        );
        assert_eq!(std::fs::read(&path).expect("read report"), encoded);
        assert!(persist_report(&path, &report, 1).is_err());
        assert_eq!(
            std::fs::read(&path).expect("previous report remains"),
            serde_json::to_vec(&report).expect("encode report")
        );
    }

    #[tokio::test]
    async fn cancellation_stops_loopback_server() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let bytes = artifact(None);
        let upstream = Arc::new(FixtureUpstream {
            metadata: metadata(&bytes),
            artifact: bytes,
            downloads: AtomicUsize::new(0),
        });
        let proxy = proxy(&root, policy(), upstream);
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(proxy.clone().serve(listener, cancellation.child_token()));
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
