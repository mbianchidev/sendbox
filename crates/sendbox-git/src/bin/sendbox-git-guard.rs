use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
};

use sendbox_git::{
    GuardError, GuardPolicyDocument, GuardService, SystemGitProcessRunner, TrustedGitBinary,
};

const EXIT_DENIED: i32 = 128;

fn main() {
    if let Err(error) = run() {
        eprintln!("[sendbox-git-guard] {error}");
        std::process::exit(EXIT_DENIED);
    }
}

fn run() -> Result<(), GuardError> {
    let mut arguments = env::args().skip(1);
    let policy_path = required_flag(&mut arguments, "--policy")?;
    let git_path = required_flag(&mut arguments, "--git")?;
    if arguments.next().as_deref() != Some("--") {
        return Err(GuardError::InvalidInvocation(
            "expected `--` before Git arguments".to_owned(),
        ));
    }
    let git_arguments = arguments.collect::<Vec<_>>();
    let policy = read_policy(Path::new(&policy_path))?;
    let executable = TrustedGitBinary::verify(git_path)?;
    let service = GuardService::new(
        policy,
        executable,
        SystemGitProcessRunner,
        env::current_dir()?,
        env::vars(),
    )?;
    service.execute(&git_arguments)
}

fn required_flag(
    arguments: &mut impl Iterator<Item = String>,
    expected: &str,
) -> Result<String, GuardError> {
    let flag = arguments.next().ok_or_else(|| {
        GuardError::InvalidInvocation(format!("required option `{expected}` is missing"))
    })?;
    if flag != expected {
        return Err(GuardError::InvalidInvocation(format!(
            "expected option `{expected}`"
        )));
    }
    arguments.next().ok_or_else(|| {
        GuardError::InvalidInvocation(format!("option `{expected}` is missing its value"))
    })
}

fn read_policy(path: &Path) -> Result<GuardPolicyDocument, GuardError> {
    if !path.is_absolute() {
        return Err(invalid_policy_file(path, "path is not absolute"));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| invalid_policy_file(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid_policy_file(
            path,
            "policy must be a regular non-symlink file",
        ));
    }
    validate_policy_mode(path, &metadata)?;
    let mut file = fs::File::open(path).map_err(|error| invalid_policy_file(path, error))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((1024 * 1024 + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| invalid_policy_file(path, error))?;
    if bytes.len() > 1024 * 1024 {
        return Err(invalid_policy_file(path, "policy exceeds 1 MiB"));
    }
    let policy: GuardPolicyDocument =
        serde_json::from_slice(&bytes).map_err(|error| invalid_policy_file(path, error))?;
    if bytes.len() > policy.limits.policy_bytes {
        return Err(invalid_policy_file(
            path,
            "policy exceeds its configured byte limit",
        ));
    }
    Ok(policy)
}

fn invalid_policy_file(path: &Path, reason: impl ToString) -> GuardError {
    GuardError::InvalidPolicyFile {
        path: PathBuf::from(path),
        reason: reason.to_string(),
    }
}

#[cfg(unix)]
fn validate_policy_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), GuardError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(invalid_policy_file(
            path,
            "policy is group- or world-writable",
        ));
    }
    if metadata.uid() != 0 && metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(invalid_policy_file(path, "policy owner is not trusted"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_policy_mode(_path: &Path, _metadata: &fs::Metadata) -> Result<(), GuardError> {
    Ok(())
}
