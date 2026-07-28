use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigstore_verify::crypto::{Checkpoint, parse_certificate_info, verify_signature_auto};
use sigstore_verify::trust_root::TrustedRoot;
use sigstore_verify::types::{
    Bundle, DerCertificate, DigestBytes, HashAlgorithm, MessageDigest, MessageSignature,
    SignatureBytes, SignatureContent,
};
use sigstore_verify::{
    DEFAULT_CLOCK_SKEW_SECONDS, VerificationPolicy, VerificationResult, Verifier,
};

use crate::{PackageIdentity, PackageProvenanceVerifier, RegistryError, RegistryResult};

const IN_TOTO_STATEMENT_V01: &str = "https://in-toto.io/Statement/v0.1";
const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
const SLSA_PROVENANCE_V02: &str = "https://slsa.dev/provenance/v0.2";
const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";
const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITLAB_ISSUER: &str = "https://gitlab.com";

#[derive(Debug, Default)]
pub struct NpmPackageProvenanceVerifier;

#[async_trait]
impl PackageProvenanceVerifier for NpmPackageProvenanceVerifier {
    async fn verify(
        &self,
        identity: &PackageIdentity,
        artifact_digest: &str,
        attestations: &[u8],
        trust_root: &[u8],
    ) -> RegistryResult<Vec<String>> {
        verify_npm_provenance(identity, artifact_digest, attestations, trust_root)
    }
}

fn verify_npm_provenance(
    identity: &PackageIdentity,
    artifact_digest: &str,
    attestations: &[u8],
    trust_root: &[u8],
) -> RegistryResult<Vec<String>> {
    let document: NpmAttestationDocument = serde_json::from_slice(attestations)
        .map_err(|error| verification(format!("decode npm attestations: {error}")))?;
    let supported = document
        .attestations
        .iter()
        .filter(|attestation| {
            matches!(
                attestation.predicate_type.as_str(),
                SLSA_PROVENANCE_V02 | SLSA_PROVENANCE_V1
            )
        })
        .collect::<Vec<_>>();
    let [attestation] = supported.as_slice() else {
        return Err(verification(format!(
            "npm attestations must contain exactly one supported SLSA provenance entry, found {}",
            supported.len()
        )));
    };

    let envelope = match &attestation.bundle.content {
        SignatureContent::DsseEnvelope(envelope) => envelope,
        SignatureContent::MessageSignature(_) => {
            return Err(verification(
                "npm provenance must use a DSSE envelope".to_owned(),
            ));
        }
    };
    if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err(verification(format!(
            "npm provenance uses unsupported DSSE payload type {}",
            envelope.payload_type
        )));
    }
    if envelope.signatures.len() != 1 {
        return Err(verification(format!(
            "npm provenance must contain exactly one DSSE signature, found {}",
            envelope.signatures.len()
        )));
    }

    let statement: ProvenanceStatement = serde_json::from_slice(envelope.payload.as_bytes())
        .map_err(|error| verification(format!("decode npm provenance statement: {error}")))?;
    verify_statement(identity, artifact_digest, attestation, &statement)?;

    let trust_root = std::str::from_utf8(trust_root).map_err(|error| {
        verification(format!("npm provenance trust root is not UTF-8: {error}"))
    })?;
    let trust_root = TrustedRoot::from_json(trust_root)
        .map_err(|error| verification(format!("decode npm provenance trust root: {error}")))?;
    let certificate = attestation.bundle.signing_certificate().ok_or_else(|| {
        verification("npm provenance bundle omitted a signing certificate".to_owned())
    })?;
    verify_transparency_log(&attestation.bundle, envelope, certificate, &trust_root)?;
    let signing = verify_signing_material(&attestation.bundle, &trust_root)?;

    let issuer = signing.issuer.ok_or_else(|| {
        verification("npm provenance certificate omitted its OIDC issuer".to_owned())
    })?;
    if !matches!(issuer.as_str(), GITHUB_ACTIONS_ISSUER | GITLAB_ISSUER) {
        return Err(verification(format!(
            "npm provenance certificate uses unsupported issuer {issuer}"
        )));
    }
    let certificate_identity = signing.identity.ok_or_else(|| {
        verification("npm provenance certificate omitted its workflow identity".to_owned())
    })?;

    Ok(vec![
        expected_npm_purl(identity),
        format!("predicate:{}", attestation.predicate_type),
        format!("issuer:{issuer}"),
        format!("identity:{certificate_identity}"),
    ])
}

fn verify_statement(
    identity: &PackageIdentity,
    artifact_digest: &str,
    attestation: &NpmAttestation,
    statement: &ProvenanceStatement,
) -> RegistryResult<()> {
    if !matches!(
        statement.statement_type.as_str(),
        IN_TOTO_STATEMENT_V01 | IN_TOTO_STATEMENT_V1
    ) {
        return Err(verification(format!(
            "npm provenance uses unsupported statement type {}",
            statement.statement_type
        )));
    }
    if statement.predicate_type != attestation.predicate_type {
        return Err(verification(
            "npm attestation predicate type does not match its signed statement".to_owned(),
        ));
    }
    if !statement.predicate.is_object() {
        return Err(verification(
            "npm provenance predicate must be an object".to_owned(),
        ));
    }
    let [subject] = statement.subject.as_slice() else {
        return Err(verification(format!(
            "npm provenance must contain exactly one subject, found {}",
            statement.subject.len()
        )));
    };
    let expected_purl = expected_npm_purl(identity);
    if subject.name != expected_purl {
        return Err(verification(format!(
            "npm provenance subject mismatch: expected {expected_purl}, received {}",
            subject.name
        )));
    }
    let Some(subject_digest) = subject.digest.get("sha512") else {
        return Err(verification(
            "npm provenance subject omitted its SHA-512 digest".to_owned(),
        ));
    };
    if subject.digest.len() != 1 {
        return Err(verification(
            "npm provenance subject must contain only its SHA-512 digest".to_owned(),
        ));
    }
    require_hex(subject_digest, 64, "npm provenance SHA-512 digest")?;
    require_hex(artifact_digest, 64, "artifact SHA-512 digest")?;
    if !subject_digest.eq_ignore_ascii_case(artifact_digest) {
        return Err(verification(
            "npm provenance subject digest does not match the package artifact".to_owned(),
        ));
    }
    let builder = match statement.predicate_type.as_str() {
        SLSA_PROVENANCE_V1 => statement
            .predicate
            .pointer("/runDetails/builder/id")
            .and_then(serde_json::Value::as_str),
        SLSA_PROVENANCE_V02 => statement
            .predicate
            .pointer("/builder/id")
            .and_then(serde_json::Value::as_str),
        _ => None,
    };
    if builder.is_none_or(str::is_empty) {
        return Err(verification(
            "npm provenance omitted its SLSA builder identity".to_owned(),
        ));
    }
    Ok(())
}

fn verify_signing_material(
    bundle: &Bundle,
    trust_root: &TrustedRoot,
) -> RegistryResult<VerificationResult> {
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(verification(
            "npm provenance must use a DSSE envelope".to_owned(),
        ));
    };
    let signature = envelope
        .signatures
        .first()
        .ok_or_else(|| verification("npm provenance omitted its DSSE signature".to_owned()))?;
    let pae = envelope.pae();
    let pae_digest = Sha256::digest(&pae);
    let mut verification_material = bundle.verification_material.clone();
    let [entry] = verification_material.tlog_entries.as_mut_slice() else {
        return Err(verification(
            "npm provenance must contain exactly one transparency-log entry".to_owned(),
        ));
    };
    // sigstore-verify only accepts integrated time from legacy entries; the v0.0.2
    // Rekor entry was verified above, so adapt only its shape to supply that trusted time.
    entry.kind_version.kind = "dsse".to_owned();
    entry.kind_version.version = "0.0.1".to_owned();
    let synthetic = Bundle {
        media_type: bundle.media_type.clone(),
        verification_material,
        content: SignatureContent::MessageSignature(MessageSignature {
            message_digest: Some(MessageDigest {
                algorithm: HashAlgorithm::Sha2256,
                digest: DigestBytes::from_bytes(pae_digest.to_vec()),
            }),
            signature: signature.sig.clone(),
        }),
    };
    Verifier::new(trust_root)
        .verify(
            pae.as_slice(),
            &synthetic,
            &VerificationPolicy::default().skip_tlog(),
        )
        .map_err(|error| verification(format!("verify npm provenance signature: {error}")))
}

fn verify_transparency_log(
    bundle: &Bundle,
    envelope: &sigstore_verify::types::DsseEnvelope,
    certificate: &DerCertificate,
    trust_root: &TrustedRoot,
) -> RegistryResult<()> {
    let [entry] = bundle.verification_material.tlog_entries.as_slice() else {
        return Err(verification(format!(
            "npm provenance must contain exactly one transparency-log entry, found {}",
            bundle.verification_material.tlog_entries.len()
        )));
    };
    if entry.kind_version.kind != "intoto" || entry.kind_version.version != "0.0.2" {
        return Err(verification(format!(
            "npm provenance uses unsupported Rekor entry {}/{}",
            entry.kind_version.kind, entry.kind_version.version
        )));
    }
    let proof = entry.inclusion_proof.as_ref().ok_or_else(|| {
        verification("npm provenance omitted its Rekor inclusion proof".to_owned())
    })?;
    if entry.inclusion_promise.is_none() {
        return Err(verification(
            "npm provenance omitted its Rekor inclusion promise".to_owned(),
        ));
    }

    let proof_index = proof
        .log_index
        .as_u64()
        .ok_or_else(|| verification("npm provenance proof has an invalid log index".to_owned()))?;
    // npm can return a SET and an inclusion proof from duplicate Rekor entries at
    // different indices. Both are verified independently against the same body.
    let tree_size = u64::try_from(proof.tree_size)
        .map_err(|_| verification("npm provenance has an invalid Rekor tree size".to_owned()))?;
    let leaf_hash = sigstore_merkle::hash_leaf(entry.canonicalized_body.as_bytes());
    sigstore_merkle::verify_inclusion_proof(
        &leaf_hash,
        proof_index,
        tree_size,
        &proof.hashes,
        &proof.root_hash,
    )
    .map_err(|error| verification(format!("verify npm Rekor inclusion proof: {error}")))?;

    let checkpoint = Checkpoint::from_text(&proof.checkpoint.envelope)
        .map_err(|error| verification(format!("parse npm Rekor checkpoint: {error}")))?;
    if checkpoint.root_hash.as_bytes() != proof.root_hash.as_bytes()
        || checkpoint.tree_size != tree_size
    {
        return Err(verification(
            "npm Rekor checkpoint does not match its inclusion proof".to_owned(),
        ));
    }
    let checkpoint_verified = trust_root
        .rekor_keys_with_hints()
        .map_err(|error| verification(format!("load npm Rekor checkpoint keys: {error}")))?
        .iter()
        .any(|(key_hint, public_key)| {
            checkpoint.signatures.iter().any(|signature| {
                signature.key_id == *key_hint
                    && verify_signature_auto(
                        public_key,
                        &signature.signature,
                        checkpoint.signed_data(),
                    )
                    .is_ok()
            })
        });
    if !checkpoint_verified {
        return Err(verification(
            "npm Rekor checkpoint signature is invalid".to_owned(),
        ));
    }

    let certificate_info = parse_certificate_info(certificate.as_bytes())
        .map_err(|error| verification(format!("parse npm provenance certificate: {error}")))?;
    let integrated_time = entry.integrated_time;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if integrated_time <= 0
        || integrated_time > now + DEFAULT_CLOCK_SKEW_SECONDS
        || integrated_time < certificate_info.not_before
        || integrated_time > certificate_info.not_after
    {
        return Err(verification(
            "npm Rekor integrated time is outside the signing certificate validity window"
                .to_owned(),
        ));
    }
    verify_signed_entry_timestamp(entry, trust_root, integrated_time)?;
    verify_rekor_body(entry, envelope, certificate)?;
    Ok(())
}

fn verify_signed_entry_timestamp(
    entry: &sigstore_verify::types::TransparencyLogEntry,
    trust_root: &TrustedRoot,
    integrated_time: i64,
) -> RegistryResult<()> {
    let promise = entry.inclusion_promise.as_ref().ok_or_else(|| {
        verification("npm provenance omitted its Rekor inclusion promise".to_owned())
    })?;
    let timestamp = Timestamp::from_second(integrated_time)
        .map_err(|error| verification(format!("parse npm Rekor integrated time: {error}")))?;
    let log_key = trust_root
        .rekor_key_for_log_at(&entry.log_id.key_id, timestamp)
        .map_err(|error| verification(format!("load npm Rekor log key: {error}")))?;
    let log_index = entry
        .log_index
        .as_u64()
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| verification("npm provenance has an invalid log index".to_owned()))?;
    let log_id = entry
        .log_id
        .key_id
        .decode()
        .map_err(|error| verification(format!("decode npm Rekor log ID: {error}")))?;
    let payload = RekorSignedEntryPayload {
        body: entry.canonicalized_body.to_base64(),
        integrated_time,
        log_index,
        log_id: encode_hex(&log_id),
    };
    let canonical = serde_json_canonicalizer::to_vec(&payload)
        .map_err(|error| verification(format!("canonicalize npm Rekor SET payload: {error}")))?;
    let signature = SignatureBytes::new(promise.signed_entry_timestamp.as_bytes().to_vec());
    verify_signature_auto(&log_key, &signature, &canonical)
        .map_err(|error| verification(format!("verify npm Rekor SET: {error}")))
}

fn verify_rekor_body(
    entry: &sigstore_verify::types::TransparencyLogEntry,
    envelope: &sigstore_verify::types::DsseEnvelope,
    certificate: &DerCertificate,
) -> RegistryResult<()> {
    let body: RekorIntotoEntry = serde_json::from_slice(entry.canonicalized_body.as_bytes())
        .map_err(|error| verification(format!("decode npm Rekor body: {error}")))?;
    if body.api_version != "0.0.2" || body.kind != "intoto" {
        return Err(verification(
            "npm Rekor body kind or version does not match the bundle".to_owned(),
        ));
    }
    let content = body.spec.content;
    if content.envelope.payload_type != envelope.payload_type
        || content.envelope.signatures.len() != envelope.signatures.len()
    {
        return Err(verification(
            "npm Rekor envelope metadata does not match the DSSE envelope".to_owned(),
        ));
    }
    if content.payload_hash.algorithm != "sha256"
        || content.payload_hash.value != encode_hex(&Sha256::digest(envelope.payload.as_bytes()))
    {
        return Err(verification(
            "npm Rekor payload hash does not match the DSSE payload".to_owned(),
        ));
    }
    if content.envelope_hash.algorithm != "sha256" {
        return Err(verification(
            "npm Rekor envelope hash uses an unsupported algorithm".to_owned(),
        ));
    }
    require_hex(&content.envelope_hash.value, 32, "npm Rekor envelope hash")?;

    for (rekor_signature, bundle_signature) in
        content.envelope.signatures.iter().zip(&envelope.signatures)
    {
        let encoded_signature = STANDARD
            .decode(&rekor_signature.signature)
            .map_err(|error| verification(format!("decode npm Rekor signature: {error}")))?;
        if encoded_signature != bundle_signature.sig.to_base64().as_bytes() {
            return Err(verification(
                "npm Rekor signature does not match the DSSE signature".to_owned(),
            ));
        }
        if let Some(key_id) = rekor_signature.key_id.as_deref()
            && !key_id.is_empty()
            && key_id != bundle_signature.keyid.as_str()
        {
            return Err(verification(
                "npm Rekor signature key ID does not match the DSSE signature".to_owned(),
            ));
        }
        let certificate_pem = STANDARD
            .decode(&rekor_signature.public_key)
            .map_err(|error| verification(format!("decode npm Rekor certificate: {error}")))?;
        let certificate_pem = std::str::from_utf8(&certificate_pem).map_err(|error| {
            verification(format!("npm Rekor certificate is not UTF-8: {error}"))
        })?;
        let rekor_certificate = DerCertificate::from_pem(certificate_pem)
            .map_err(|error| verification(format!("parse npm Rekor certificate: {error}")))?;
        if rekor_certificate.as_bytes() != certificate.as_bytes() {
            return Err(verification(
                "npm Rekor certificate does not match the DSSE signing certificate".to_owned(),
            ));
        }
    }
    Ok(())
}

fn expected_npm_purl(identity: &PackageIdentity) -> String {
    let encoded = identity
        .name
        .split('/')
        .map(percent_encode_purl_segment)
        .collect::<Vec<_>>()
        .join("/");
    format!(
        "pkg:npm/{encoded}@{}",
        percent_encode_purl_segment(&identity.version)
    )
}

fn percent_encode_purl_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(HEX[usize::from(byte >> 4)] as char);
            encoded.push(HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    encoded
}

fn require_hex(value: &str, expected_bytes: usize, subject: &str) -> RegistryResult<()> {
    if value.len() != expected_bytes * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(verification(format!("{subject} is not valid hexadecimal")));
    }
    Ok(())
}

fn verification(message: String) -> RegistryError {
    RegistryError::Verification(message)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NpmAttestationDocument {
    attestations: Vec<NpmAttestation>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NpmAttestation {
    predicate_type: String,
    bundle: Bundle,
    #[serde(rename = "signedAccessSignatureUrl", default)]
    _signed_access_signature_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvenanceStatement {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<ProvenanceSubject>,
    predicate_type: String,
    predicate: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceSubject {
    name: String,
    digest: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct RekorSignedEntryPayload {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logIndex")]
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RekorIntotoEntry {
    api_version: String,
    kind: String,
    spec: RekorIntotoSpec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorIntotoSpec {
    content: RekorIntotoContent,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RekorIntotoContent {
    envelope: RekorEnvelope,
    #[serde(rename = "hash")]
    envelope_hash: RekorHash,
    payload_hash: RekorHash,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RekorEnvelope {
    payload_type: String,
    signatures: Vec<RekorEnvelopeSignature>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RekorEnvelopeSignature {
    #[serde(default)]
    key_id: Option<String>,
    #[serde(rename = "sig")]
    signature: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorHash {
    algorithm: String,
    value: String,
}

#[cfg(test)]
mod tests {
    use sigstore_verify::trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT;

    use super::*;
    use sendbox_policy::PackageEcosystem;

    const REAL_ATTESTATIONS: &[u8] =
        include_bytes!("../test-data/npm-sigstore-bundle-2.3.0-attestations.json");
    const REAL_DIGEST: &str = "314dd760790ebca1059ee52d700b55874b384537a64728b534df3bfaff5f00bd2a47d259b8afe7176ed827bf708cfbef8b55bdb33dea73b71382c847e6d8e2e9";

    fn identity() -> PackageIdentity {
        PackageIdentity {
            ecosystem: PackageEcosystem::Npm,
            name: "@sigstore/bundle".to_owned(),
            version: "2.3.0".to_owned(),
        }
    }

    #[test]
    fn verifies_real_npm_slsa_provenance_offline() {
        let evidence = verify_npm_provenance(
            &identity(),
            REAL_DIGEST,
            REAL_ATTESTATIONS,
            SIGSTORE_PRODUCTION_TRUSTED_ROOT.as_bytes(),
        )
        .expect("real npm provenance");
        assert!(evidence.contains(&"pkg:npm/%40sigstore/bundle@2.3.0".to_owned()));
        assert!(
            evidence
                .iter()
                .any(|value| value == "issuer:https://token.actions.githubusercontent.com")
        );
    }

    #[test]
    fn rejects_tampered_subject_digest() {
        let error = verify_npm_provenance(
            &identity(),
            &format!("0{}", &REAL_DIGEST[1..]),
            REAL_ATTESTATIONS,
            SIGSTORE_PRODUCTION_TRUSTED_ROOT.as_bytes(),
        )
        .expect_err("tampered digest");
        assert!(error.to_string().contains("subject digest"));
    }

    #[test]
    fn rejects_tampered_rekor_body() {
        let mut document: serde_json::Value =
            serde_json::from_slice(REAL_ATTESTATIONS).expect("fixture");
        let attestation = document["attestations"]
            .as_array_mut()
            .expect("attestations")
            .iter_mut()
            .find(|value| value["predicateType"] == SLSA_PROVENANCE_V1)
            .expect("SLSA attestation");
        attestation["bundle"]["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"] =
            serde_json::Value::String(STANDARD.encode(b"{}"));
        let bytes = serde_json::to_vec(&document).expect("tampered fixture");
        assert!(
            verify_npm_provenance(
                &identity(),
                REAL_DIGEST,
                &bytes,
                SIGSTORE_PRODUCTION_TRUSTED_ROOT.as_bytes(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_duplicate_slsa_provenance() {
        let mut document: serde_json::Value =
            serde_json::from_slice(REAL_ATTESTATIONS).expect("fixture");
        let attestations = document["attestations"]
            .as_array_mut()
            .expect("attestations");
        let duplicate = attestations
            .iter()
            .find(|value| value["predicateType"] == SLSA_PROVENANCE_V1)
            .expect("SLSA attestation")
            .clone();
        attestations.push(duplicate);
        let bytes = serde_json::to_vec(&document).expect("duplicate fixture");
        let error = verify_npm_provenance(
            &identity(),
            REAL_DIGEST,
            &bytes,
            SIGSTORE_PRODUCTION_TRUSTED_ROOT.as_bytes(),
        )
        .expect_err("duplicate SLSA provenance");
        assert!(error.to_string().contains("exactly one"));
    }
}
