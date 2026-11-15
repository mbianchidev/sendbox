use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand, ValueEnum};
use sendbox_config::SandboxConfiguration;
use sendbox_governance::{GovernanceProfile, RuntimeKind};
use sendbox_host::governance::{
    GovernanceCheckRequest, MANAGED_CONFIGURATION_PATH, SIGNATURES_FORMAT, check,
    encode_signatures, verify_active,
};
use sendbox_security::provenance::{
    DetachedSignature, SignedSubject, SigningKeyMaterial, SubjectKind,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{GOVERNANCE_EXIT, INVALID_CONFIGURATION_EXIT, print_json};

#[derive(Debug, Args)]
pub(crate) struct GovernanceArgs {
    #[command(subcommand)]
    command: GovernanceCommand,
}

#[derive(Debug, Subcommand)]
enum GovernanceCommand {
    /// Create an Ed25519 profile-signing key and print its public identity.
    Keygen(KeygenArgs),
    /// Sign the exact bytes of a governance profile.
    Sign(SignArgs),
    /// Verify the active governance profile and its signatures.
    Verify(VerifyArgs),
    /// Explain whether a project configuration fits the active profile.
    Check(CheckArgs),
}

#[derive(Debug, Args)]
struct KeygenArgs {
    /// New private key file; created with mode 0600 and never overwritten.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    #[arg(long, default_value = "SendBox governance operator")]
    name: String,
    #[arg(long)]
    email: Option<String>,
    #[arg(long, value_name = "UNIX_SECONDS")]
    expires_at_unix: Option<u64>,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
}

#[derive(Debug, Args)]
struct SignArgs {
    #[arg(value_name = "PROFILE")]
    profile: PathBuf,
    #[arg(long, value_name = "PATH")]
    key: PathBuf,
    /// Signature bundle path. Defaults to PROFILE.sig.json.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Add this signature to an existing bundle for threshold signing.
    #[arg(long)]
    append: bool,
    #[arg(long, value_name = "UNIX_SECONDS")]
    expires_at_unix: Option<u64>,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Opt-in operator configuration. Ignored in favor of the managed
    /// configuration when one exists.
    #[arg(long, value_name = "PATH")]
    governance_config: Option<PathBuf>,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CheckRuntime {
    Apple,
    Kata,
}

#[derive(Debug, Args)]
struct CheckArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_name = "PATH")]
    governance_config: Option<PathBuf>,
    #[arg(long, value_enum)]
    runtime: Option<CheckRuntime>,
    #[arg(long, value_name = "IMAGE@sha256:DIGEST")]
    image: Option<String>,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
}

#[derive(Debug, Serialize)]
struct KeygenResult {
    schema_version: u32,
    ok: bool,
    key: String,
    identity: sendbox_security::provenance::Identity,
}

#[derive(Debug, Serialize)]
struct SignResult {
    schema_version: u32,
    ok: bool,
    profile: String,
    revision: u64,
    sha256: String,
    signatures: String,
    signer: String,
    signature_count: usize,
}

#[derive(Debug, Serialize)]
struct VerifyResult {
    schema_version: u32,
    ok: bool,
    governed: bool,
    mode: Option<String>,
    authority: Option<String>,
    profile: Option<String>,
    revision: Option<u64>,
    sha256: Option<String>,
    expires_at_unix: Option<u64>,
    signers: Vec<String>,
    credential_services: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SignatureBundle {
    signatures: Vec<DetachedSignature>,
}

pub(crate) fn execute(arguments: GovernanceArgs) -> ExitCode {
    let (json, result) = match arguments.command {
        GovernanceCommand::Keygen(arguments) => (arguments.json, keygen(&arguments)),
        GovernanceCommand::Sign(arguments) => (arguments.json, sign(&arguments)),
        GovernanceCommand::Verify(arguments) => (arguments.json, verify(&arguments)),
        GovernanceCommand::Check(arguments) => (arguments.json, check_configuration(&arguments)),
    };
    match result {
        Ok(code) => code,
        Err((code, message)) => {
            if json {
                print_json(&serde_json::json!({
                    "schema_version": sendbox_core::CONFIG_SCHEMA_VERSION,
                    "ok": false,
                    "exit_code": code,
                    "message": message,
                }));
            } else {
                eprintln!("sendbox governance: {message}");
            }
            ExitCode::from(code)
        }
    }
}

type CommandResult = Result<ExitCode, (u8, String)>;

fn invalid(message: impl ToString) -> (u8, String) {
    (INVALID_CONFIGURATION_EXIT, message.to_string())
}

fn governance(message: impl ToString) -> (u8, String) {
    (GOVERNANCE_EXIT, message.to_string())
}

fn now_unix() -> Result<u64, (u8, String)> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| invalid(format!("system clock is before the Unix epoch: {error}")))
}

fn keygen(arguments: &KeygenArgs) -> CommandResult {
    let now = now_unix()?;
    let key = SigningKeyMaterial::generate().map_err(invalid)?;
    let exported = key.export();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&arguments.output)
        .map_err(|error| {
            invalid(format!(
                "create private key {}: {error}",
                arguments.output.display()
            ))
        })?;
    file.write_all(exported.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| invalid(format!("write private key: {error}")))?;
    let identity = key.identity(
        arguments.name.clone(),
        arguments.email.clone(),
        now,
        arguments.expires_at_unix,
    );
    if arguments.json {
        print_json(&KeygenResult {
            schema_version: sendbox_core::CONFIG_SCHEMA_VERSION,
            ok: true,
            key: arguments.output.display().to_string(),
            identity,
        });
    } else {
        eprintln!(
            "private key written to {}; keep it offline. Add this identity to trust.signers:",
            arguments.output.display()
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&identity).map_err(invalid)?
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn read_private_key(path: &Path) -> Result<SigningKeyMaterial, (u8, String)> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("inspect private key {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix_uid()
    {
        return Err(invalid(
            "private key must be a regular file owned by you with mode 0600",
        ));
    }
    let text = Zeroizing::new(
        fs::read_to_string(path).map_err(|error| invalid(format!("read private key: {error}")))?,
    );
    SigningKeyMaterial::import(text.trim()).map_err(invalid)
}

fn rustix_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn sign(arguments: &SignArgs) -> CommandResult {
    let bytes = fs::read(&arguments.profile)
        .map_err(|error| invalid(format!("read {}: {error}", arguments.profile.display())))?;
    let profile = GovernanceProfile::parse(&bytes).map_err(invalid)?;
    let key = read_private_key(&arguments.key)?;
    let now = now_unix()?;
    let signature = DetachedSignature::sign(
        SignedSubject::from_bytes(SubjectKind::Configuration, None, &bytes),
        &key,
        now,
        arguments.expires_at_unix,
        BTreeMap::new(),
    )
    .map_err(invalid)?;
    let signer = signature.signer_fingerprint.clone();
    let output = arguments.output.clone().unwrap_or_else(|| {
        let mut path = arguments.profile.clone().into_os_string();
        path.push(".sig.json");
        PathBuf::from(path)
    });
    let mut signatures = Vec::new();
    if arguments.append {
        let existing = fs::read(&output)
            .map_err(|error| invalid(format!("read {}: {error}", output.display())))?;
        let bundle: SignatureBundle = serde_json::from_slice(&existing)
            .map_err(|error| invalid(format!("{SIGNATURES_FORMAT}: {error}")))?;
        let reference = profile.reference(&bytes);
        for existing in bundle.signatures {
            if existing.subject.sha256 != reference.sha256.to_string() {
                return Err(invalid(
                    "existing signatures cover different profile bytes; re-sign every signer",
                ));
            }
            if existing.signer_fingerprint != signer {
                signatures.push(existing);
            }
        }
    } else if output.exists() {
        return Err(invalid(format!(
            "{} exists; pass --append to add a signature",
            output.display()
        )));
    }
    signatures.push(signature);
    let encoded = encode_signatures(&signatures).map_err(invalid)?;
    let temporary = output.with_extension("json.tmp");
    let write = || -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temporary)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(&temporary, &output)
    };
    if let Err(error) = write() {
        let _ = fs::remove_file(&temporary);
        return Err(invalid(format!("write {}: {error}", output.display())));
    }
    let reference = profile.reference(&bytes);
    if arguments.json {
        print_json(&SignResult {
            schema_version: sendbox_core::CONFIG_SCHEMA_VERSION,
            ok: true,
            profile: reference.id.to_string(),
            revision: reference.revision,
            sha256: reference.sha256.to_string(),
            signatures: output.display().to_string(),
            signer,
            signature_count: signatures.len(),
        });
    } else {
        println!(
            "signed {} revision {} ({}) -> {} [{} signature(s)]",
            reference.id,
            reference.revision,
            reference.sha256,
            output.display(),
            signatures.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn verify(arguments: &VerifyArgs) -> CommandResult {
    let active = verify_active(
        Path::new(MANAGED_CONFIGURATION_PATH),
        arguments.governance_config.as_deref(),
    )
    .map_err(governance)?;
    let result = match &active {
        None => VerifyResult {
            schema_version: sendbox_core::CONFIG_SCHEMA_VERSION,
            ok: true,
            governed: false,
            mode: None,
            authority: None,
            profile: None,
            revision: None,
            sha256: None,
            expires_at_unix: None,
            signers: Vec::new(),
            credential_services: Vec::new(),
        },
        Some(active) => VerifyResult {
            schema_version: sendbox_core::CONFIG_SCHEMA_VERSION,
            ok: true,
            governed: true,
            mode: serde_json::to_value(active.source.mode)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned)),
            authority: Some(active.verified.authority.id.clone()),
            profile: Some(active.verified.reference.id.to_string()),
            revision: Some(active.verified.reference.revision),
            sha256: Some(active.verified.reference.sha256.to_string()),
            expires_at_unix: Some(active.verified.profile.expires_at_unix),
            signers: active.verified.signers.iter().cloned().collect(),
            credential_services: active
                .verified
                .profile
                .credential_services
                .iter()
                .map(|service| service.id.to_string())
                .collect(),
        },
    };
    if arguments.json {
        print_json(&result);
    } else if !result.governed {
        println!(
            "no governance configured ({MANAGED_CONFIGURATION_PATH} is absent and no --governance-config was given)"
        );
    } else {
        println!(
            "verified {} profile {} revision {} ({}) signed by {} trusted signer(s); expires at {}",
            result.mode.as_deref().unwrap_or_default(),
            result.profile.as_deref().unwrap_or_default(),
            result.revision.unwrap_or_default(),
            result.sha256.as_deref().unwrap_or_default(),
            result.signers.len(),
            result.expires_at_unix.unwrap_or_default(),
        );
        if !result.credential_services.is_empty() {
            println!(
                "brokered credential services: {}",
                result.credential_services.join(", ")
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn check_configuration(arguments: &CheckArgs) -> CommandResult {
    let configuration = SandboxConfiguration::load(&arguments.config).map_err(invalid)?;
    let report = check(GovernanceCheckRequest {
        configuration,
        managed_path: PathBuf::from(MANAGED_CONFIGURATION_PATH),
        governance_config: arguments.governance_config.clone(),
        runtime: arguments.runtime.map(|runtime| match runtime {
            CheckRuntime::Apple => RuntimeKind::Apple,
            CheckRuntime::Kata => RuntimeKind::Kata,
        }),
        image: arguments.image.clone(),
    })
    .map_err(governance)?;
    if arguments.json {
        print_json(&serde_json::json!({
            "schema_version": sendbox_core::CONFIG_SCHEMA_VERSION,
            "ok": report.admitted,
            "report": report,
        }));
    } else {
        match &report.profile {
            None => println!("no governance configured"),
            Some(profile) => println!(
                "profile {profile} revision {} ({})",
                report.profile_revision.unwrap_or_default(),
                report.profile_sha256.as_deref().unwrap_or_default()
            ),
        }
        for (label, entries) in [
            ("denied commands", &report.applied_denials.commands),
            ("blocked domains", &report.applied_denials.domains),
            ("blocked networks", &report.applied_denials.networks),
        ] {
            if !entries.is_empty() {
                println!("adds {label}: {}", entries.join(", "));
            }
        }
        if report.admitted {
            println!("admitted");
        } else {
            println!("rejected:");
            for violation in &report.violations {
                println!("  - {violation}");
            }
        }
    }
    Ok(if report.admitted {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(GOVERNANCE_EXIT)
    })
}
