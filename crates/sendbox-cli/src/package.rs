use std::cmp::Ordering;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use clap::{Args, Subcommand};
use sendbox_policy::MAX_PACKAGE_REPORT_BYTES;
use sendbox_registry::PackageSecurityReport;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::RUNTIME_EXIT;

const PACKAGE_COMMAND_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Args)]
pub(crate) struct PackageArgs {
    #[command(subcommand)]
    command: PackageCommand,
}

#[derive(Debug, Subcommand)]
enum PackageCommand {
    /// Show the latest or selected session's package verdict summary.
    Status(SessionArgs),
    /// Print the latest or selected session's complete package security report.
    Report(SessionArgs),
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[arg(long, value_name = "SESSION_ID")]
    session: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct PackageStatus<'a> {
    schema_version: u32,
    session_id: &'a str,
    report_path: String,
    sha256: &'a str,
    verdict: &'static str,
    proxy_enabled: bool,
    records: usize,
    allowed: u32,
    denied: u32,
    quarantined: u32,
}

struct LoadedReport {
    session_id: String,
    path: PathBuf,
    sha256: String,
    report: PackageSecurityReport,
}

pub(crate) fn execute(arguments: PackageArgs, state_root: &Path) -> ExitCode {
    let (arguments, show_report) = match arguments.command {
        PackageCommand::Status(arguments) => (arguments, false),
        PackageCommand::Report(arguments) => (arguments, true),
    };
    let loaded = match load_report(state_root, arguments.session.as_deref()) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("sendbox package: {error}");
            return ExitCode::from(RUNTIME_EXIT);
        }
    };
    if show_report {
        let encoded = if arguments.json {
            serde_json::to_string(&loaded.report)
        } else {
            serde_json::to_string_pretty(&loaded.report)
        };
        match encoded {
            Ok(encoded) => println!("{encoded}"),
            Err(error) => {
                eprintln!("sendbox package: encode package report: {error}");
                return ExitCode::from(RUNTIME_EXIT);
            }
        }
        return ExitCode::SUCCESS;
    }

    let status = PackageStatus {
        schema_version: PACKAGE_COMMAND_SCHEMA_VERSION,
        session_id: &loaded.session_id,
        report_path: loaded.path.display().to_string(),
        sha256: &loaded.sha256,
        verdict: report_verdict(&loaded.report),
        proxy_enabled: loaded.report.proxy_enabled,
        records: loaded.report.records.len(),
        allowed: loaded.report.allowed,
        denied: loaded.report.denied,
        quarantined: loaded.report.quarantined,
    };
    if arguments.json {
        println!(
            "{}",
            serde_json::to_string(&status).expect("package status is serializable")
        );
    } else {
        println!("session: {}", status.session_id);
        println!("verdict: {}", status.verdict);
        println!(
            "packages: {} allowed, {} denied, {} quarantined",
            status.allowed, status.denied, status.quarantined
        );
        println!("report: {}", status.report_path);
        println!("sha256: {}", status.sha256);
    }
    ExitCode::SUCCESS
}

fn load_report(state_root: &Path, requested_session: Option<&str>) -> Result<LoadedReport, String> {
    let sessions_root = state_root.join("sessions");
    require_directory(&sessions_root, "session state directory")?;
    let session_id = match requested_session {
        Some(session_id) => {
            validate_session_id(session_id)?;
            session_id.to_owned()
        }
        None => latest_report_session(&sessions_root)?,
    };
    let session_directory = sessions_root.join(&session_id);
    require_directory(&session_directory, "session directory")?;
    let path = session_directory.join(sendbox_host::PACKAGE_SECURITY_REPORT_FILE);
    let bytes = read_secure_report(&path)?;
    let report: PackageSecurityReport = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode {}: {error}", path.display()))?;
    report
        .validate(usize::MAX, usize::MAX)
        .map_err(|error| format!("validate {}: {error}", path.display()))?;
    if report
        .records
        .iter()
        .any(|record| record.requested_by_session != session_id)
    {
        return Err(format!(
            "{} contains records for a different session",
            path.display()
        ));
    }
    Ok(LoadedReport {
        session_id,
        path,
        sha256: sha256_label(&bytes),
        report,
    })
}

fn latest_report_session(sessions_root: &Path) -> Result<String, String> {
    let mut candidates = Vec::new();
    let entries = fs::read_dir(sessions_root)
        .map_err(|error| format!("read {}: {error}", sessions_root.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("read {} entry: {error}", sessions_root.display()))?;
        let session_id = match entry.file_name().into_string() {
            Ok(session_id) if validate_session_id(&session_id).is_ok() => session_id,
            _ => continue,
        };
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect session {session_id}: {error}"))?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let report_path = entry
            .path()
            .join(sendbox_host::PACKAGE_SECURITY_REPORT_FILE);
        let metadata = match report_path.symlink_metadata() {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!("inspect {}: {error}", report_path.display()));
            }
        };
        let modified = metadata
            .modified()
            .map_err(|error| format!("read {} timestamp: {error}", report_path.display()))?;
        candidates.push((modified, session_id));
    }
    select_latest(candidates).ok_or_else(|| {
        format!(
            "no package security reports found in {}",
            sessions_root.display()
        )
    })
}

fn select_latest(candidates: Vec<(SystemTime, String)>) -> Option<String> {
    candidates
        .into_iter()
        .max_by(|left, right| match left.0.cmp(&right.0) {
            Ordering::Equal => left.1.cmp(&right.1),
            ordering => ordering,
        })
        .map(|(_, session_id)| session_id)
}

fn require_directory(path: &Path, subject: &str) -> Result<(), String> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{subject} {} is not a real directory",
            path.display()
        ));
    }
    Ok(())
}

fn read_secure_report(path: &Path) -> Result<Vec<u8>, String> {
    let file = open_secure_report(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect open {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular report file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.gid() != rustix::process::getgid().as_raw()
        {
            return Err(format!(
                "{} must be a single-link 0600 file owned by the current user",
                path.display()
            ));
        }
    }
    let limit = usize::try_from(MAX_PACKAGE_REPORT_BYTES)
        .map_err(|_| "package report byte limit is out of range".to_owned())?;
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| "package report byte limit is out of range".to_owned())?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!(
            "{} exceeds the {limit}-byte package report limit",
            path.display()
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_secure_report(path: &Path) -> Result<File, String> {
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("open {}: {}", path.display(), std::io::Error::from(error)))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_secure_report(path: &Path) -> Result<File, String> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{} is not a regular report file", path.display()));
    }
    File::open(path).map_err(|error| format!("open {}: {error}", path.display()))
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("session ID must be 32 lowercase hexadecimal characters".to_owned());
    }
    Ok(())
}

fn report_verdict(report: &PackageSecurityReport) -> &'static str {
    if report.denied > 0 {
        "deny"
    } else if report.quarantined > 0 {
        "quarantine"
    } else {
        "allow"
    }
}

fn sha256_label(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut label = String::with_capacity("sha256:".len() + digest.len() * 2);
    label.push_str("sha256:");
    for byte in digest {
        write!(&mut label, "{byte:02x}").expect("writing to a string cannot fail");
    }
    label
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, UNIX_EPOCH};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn latest_session_uses_timestamp_then_session_id() {
        let earlier = "1".repeat(32);
        let lower = "2".repeat(32);
        let higher = "f".repeat(32);
        assert_eq!(
            select_latest(vec![
                (UNIX_EPOCH, earlier),
                (UNIX_EPOCH + Duration::from_secs(1), lower),
                (UNIX_EPOCH + Duration::from_secs(1), higher.clone()),
            ]),
            Some(higher)
        );
    }

    #[test]
    fn report_loading_is_bounded_strict_and_session_scoped() {
        let temporary = tempdir().expect("temporary directory");
        let sessions = temporary.path().join("sessions");
        let session_id = "a".repeat(32);
        let session = sessions.join(&session_id);
        fs::create_dir_all(&session).expect("session directory");
        let report_path = session.join(sendbox_host::PACKAGE_SECURITY_REPORT_FILE);
        let report = PackageSecurityReport::enabled();
        fs::write(
            &report_path,
            serde_json::to_vec(&report).expect("encode report"),
        )
        .expect("write report");
        fs::set_permissions(&report_path, fs::Permissions::from_mode(0o600)).expect("report mode");

        let loaded = load_report(temporary.path(), Some(&session_id)).expect("load report");
        assert_eq!(loaded.session_id, session_id);
        assert!(loaded.report.proxy_enabled);
        assert!(loaded.sha256.starts_with("sha256:"));

        fs::write(&report_path, b"{\"schema_version\":1,\"unknown\":true}")
            .expect("replace report");
        assert!(load_report(temporary.path(), Some(&session_id)).is_err());
        assert!(load_report(temporary.path(), Some("../escape")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secure_report_open_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().expect("temporary directory");
        let target = temporary.path().join("report.json");
        let link = temporary.path().join("report-link.json");
        fs::write(&target, b"{}").expect("write target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
        symlink(&target, &link).expect("create symlink");

        assert!(read_secure_report(&link).is_err());
    }
}
