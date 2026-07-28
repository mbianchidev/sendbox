use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use sendbox_git::{
    GIT_ASKPASS_PATH, GIT_SSH_PATH, GITHUB_TOKEN_ENVIRONMENT, GuardPolicyDocument,
    SSH_KEY_ENVIRONMENT, TrustedExecutable, TrustedGitBinary, execute_guarded_git,
};

use crate::GuestError;

const ROOT_PATH: &str = "/run/sendbox-branch-protection";
const POLICY_PATH: &str = "/run/sendbox-branch-protection/policy.json";
const REAL_GIT_PATH: &str = "/run/sendbox-branch-protection/git-real";
const SSH_WORK_ROOT: &str = "/run/sendbox-branch-protection/ssh-work";
const GIT_CANDIDATES: [&str; 3] = ["/usr/bin/git", "/bin/git", "/usr/local/bin/git"];
const EXIT_DENIED: u8 = 128;

pub fn install(
    policy: &GuardPolicyDocument,
    artifact_root: &Path,
    workload_uid: u32,
    workload_gid: u32,
) -> Result<(), GuestError> {
    let guest_binary = artifact_root.join("bin/sendbox-guest");
    install_with_paths(
        policy,
        &InstallPaths {
            root: PathBuf::from(ROOT_PATH),
            policy: PathBuf::from(POLICY_PATH),
            real_git: PathBuf::from(REAL_GIT_PATH),
            askpass: PathBuf::from(GIT_ASKPASS_PATH),
            ssh_wrapper: PathBuf::from(GIT_SSH_PATH),
            ssh_work_root: PathBuf::from(SSH_WORK_ROOT),
            guest_binary,
            git_candidates: GIT_CANDIDATES.iter().map(PathBuf::from).collect(),
        },
        0,
        workload_uid,
        workload_gid,
    )
}

pub fn execute_current(arguments: &[String]) -> Result<(), GuestError> {
    execute_guarded_git(Path::new(POLICY_PATH), Path::new(REAL_GIT_PATH), arguments)
        .map_err(|error| GuestError::Runtime(error.to_string()))
}

pub fn askpass_response(arguments: &[String]) -> Result<String, GuestError> {
    let prompt = arguments
        .first()
        .map_or("", String::as_str)
        .to_ascii_lowercase();
    if prompt.contains("username") {
        return Ok("x-access-token".to_owned());
    }
    if !prompt.contains("password") && !prompt.contains("token") {
        return Err(GuestError::Runtime(
            "Git askpass received an unsupported prompt".to_owned(),
        ));
    }
    let token = std::env::var(GITHUB_TOKEN_ENVIRONMENT)
        .map_err(|_| GuestError::Runtime("GitHub token is unavailable".to_owned()))?;
    if token.is_empty() || token.contains(['\r', '\n']) {
        return Err(GuestError::Runtime(
            "GitHub token is invalid for askpass".to_owned(),
        ));
    }
    Ok(token)
}

pub fn execute_ssh(arguments: &[String]) -> Result<i32, GuestError> {
    validate_ssh_arguments(arguments)?;
    let key = std::env::var(SSH_KEY_ENVIRONMENT)
        .map_err(|_| GuestError::Runtime("Git SSH key is unavailable".to_owned()))?;
    if key.is_empty() || !key.contains("PRIVATE KEY") {
        return Err(GuestError::Runtime(
            "Git SSH key is not a supported private key".to_owned(),
        ));
    }
    let mut temporary = TemporarySshKey::create(key.as_bytes())?;
    let ssh = trusted_ssh()?;
    let status = Command::new(ssh.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .args([
            "-F",
            "/dev/null",
            "-i",
            temporary
                .key
                .to_str()
                .ok_or_else(|| GuestError::Runtime("Git SSH key path is not UTF-8".to_owned()))?,
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
        ])
        .args(arguments)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| GuestError::io("running trusted SSH", error))?;
    temporary.cleanup()?;
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |signal| 128 + signal)))
}

#[must_use]
pub const fn denied_exit_code() -> u8 {
    EXIT_DENIED
}

struct InstallPaths {
    root: PathBuf,
    policy: PathBuf,
    real_git: PathBuf,
    askpass: PathBuf,
    ssh_wrapper: PathBuf,
    ssh_work_root: PathBuf,
    guest_binary: PathBuf,
    git_candidates: Vec<PathBuf>,
}

fn install_with_paths(
    policy: &GuardPolicyDocument,
    paths: &InstallPaths,
    expected_owner: u32,
    workload_uid: u32,
    workload_gid: u32,
) -> Result<(), GuestError> {
    policy
        .validate()
        .map_err(|error| GuestError::Runtime(error.to_string()))?;
    validate_layout(paths)?;
    let guest_binary = TrustedExecutable::verify(&paths.guest_binary)
        .map_err(|error| GuestError::Runtime(error.to_string()))?;
    validate_executable_owner(guest_binary.path(), expected_owner, "guest binary")?;
    let (source_path, replacement_paths) =
        find_git_and_replacement_paths(&paths.git_candidates, expected_owner)?;
    let source = TrustedGitBinary::verify(&source_path)
        .map_err(|error| GuestError::Runtime(error.to_string()))?;

    fs::DirBuilder::new()
        .mode(0o755)
        .create(&paths.root)
        .map_err(|error| GuestError::io("creating Git guard root", error))?;
    fs::set_permissions(&paths.root, fs::Permissions::from_mode(0o755))
        .map_err(|error| GuestError::io("setting Git guard root mode", error))?;
    validate_directory(&paths.root, expected_owner, "Git guard root")?;
    write_policy(&paths.policy, policy)?;
    source
        .copy_to(&paths.real_git, 0o555)
        .map_err(|error| GuestError::Runtime(error.to_string()))?;
    fs::set_permissions(&paths.real_git, fs::Permissions::from_mode(0o555))
        .map_err(|error| GuestError::io("setting guarded Git mode", error))?;
    if policy.github_https_auth {
        copy_wrapper(&guest_binary, &paths.askpass)?;
    }
    if policy.git_ssh_auth {
        copy_wrapper(&guest_binary, &paths.ssh_wrapper)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&paths.ssh_work_root)
            .map_err(|error| GuestError::io("creating Git SSH work root", error))?;
        std::os::unix::fs::chown(&paths.ssh_work_root, Some(workload_uid), Some(workload_gid))
            .map_err(|error| GuestError::io("assigning Git SSH work root", error))?;
        fs::set_permissions(&paths.ssh_work_root, fs::Permissions::from_mode(0o700))
            .map_err(|error| GuestError::io("setting Git SSH work root mode", error))?;
        validate_directory(&paths.ssh_work_root, workload_uid, "Git SSH work root")?;
    }

    for replacement in replacement_paths {
        if replacement.symlink_metadata().is_ok() {
            let metadata = replacement
                .symlink_metadata()
                .map_err(|error| GuestError::io("inspecting Git replacement path", error))?;
            if metadata.is_dir() {
                return Err(GuestError::Runtime(format!(
                    "Git replacement path `{}` is a directory",
                    replacement.display()
                )));
            }
            fs::remove_file(&replacement)
                .map_err(|error| GuestError::io("removing original Git path", error))?;
        }
        copy_wrapper(&guest_binary, &replacement)?;
    }
    fs::File::open(&paths.root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| GuestError::io("syncing Git guard root", error))
}

fn validate_layout(paths: &InstallPaths) -> Result<(), GuestError> {
    if !paths.root.is_absolute()
        || paths.policy.parent() != Some(paths.root.as_path())
        || paths.real_git.parent() != Some(paths.root.as_path())
        || paths.askpass.parent() != Some(paths.root.as_path())
        || paths.ssh_wrapper.parent() != Some(paths.root.as_path())
        || paths.ssh_work_root.parent() != Some(paths.root.as_path())
        || BTreeSet::from([
            &paths.policy,
            &paths.real_git,
            &paths.askpass,
            &paths.ssh_wrapper,
            &paths.ssh_work_root,
        ])
        .len()
            != 5
        || !paths.guest_binary.is_absolute()
    {
        return Err(GuestError::Runtime(
            "Git guard installation paths are invalid".to_owned(),
        ));
    }
    if paths.root.symlink_metadata().is_ok() {
        return Err(GuestError::Runtime(
            "Git guard root already exists".to_owned(),
        ));
    }
    Ok(())
}

fn copy_wrapper(guest_binary: &TrustedExecutable, destination: &Path) -> Result<(), GuestError> {
    guest_binary
        .copy_to(destination, 0o555)
        .map_err(|error| GuestError::Runtime(error.to_string()))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o555))
        .map_err(|error| GuestError::io("setting Git helper mode", error))
}

struct TemporarySshKey {
    directory: PathBuf,
    key: PathBuf,
    active: bool,
}

impl TemporarySshKey {
    fn create(bytes: &[u8]) -> Result<Self, GuestError> {
        let work_root = Path::new(SSH_WORK_ROOT);
        validate_directory(
            work_root,
            rustix::process::geteuid().as_raw(),
            "Git SSH work root",
        )?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|error| GuestError::Runtime(format!("generate Git SSH key path: {error}")))?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let directory = work_root.join(suffix);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|error| GuestError::io("creating private Git SSH directory", error))?;
        let key = directory.join("identity");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&key)
            .map_err(|error| GuestError::io("creating temporary Git SSH key", error))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| GuestError::io("writing temporary Git SSH key", error))?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
            .map_err(|error| GuestError::io("setting temporary Git SSH key mode", error))?;
        Ok(Self {
            directory,
            key,
            active: true,
        })
    }

    fn cleanup(&mut self) -> Result<(), GuestError> {
        fs::remove_file(&self.key)
            .map_err(|error| GuestError::io("removing temporary Git SSH key", error))?;
        fs::remove_dir(&self.directory)
            .map_err(|error| GuestError::io("removing private Git SSH directory", error))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for TemporarySshKey {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.key);
            let _ = fs::remove_dir(&self.directory);
        }
    }
}

fn trusted_ssh() -> Result<TrustedExecutable, GuestError> {
    ["/usr/bin/ssh", "/bin/ssh"]
        .into_iter()
        .filter_map(|candidate| Path::new(candidate).canonicalize().ok())
        .find_map(|candidate| TrustedExecutable::verify(candidate).ok())
        .ok_or_else(|| GuestError::Runtime("trusted SSH is unavailable in the guest".to_owned()))
}

fn validate_ssh_arguments(arguments: &[String]) -> Result<(), GuestError> {
    let mut index = 0;
    let mut host_seen = false;
    while index < arguments.len() {
        let argument = &arguments[index];
        if host_seen {
            index += 1;
            continue;
        }
        if !argument.starts_with('-') || argument == "-" {
            host_seen = true;
            index += 1;
            continue;
        }
        match argument.as_str() {
            "-4" | "-6" | "-q" | "-T" | "-v" => index += 1,
            "-l" | "-p" => {
                index += 2;
                if index > arguments.len() {
                    return Err(GuestError::Runtime(
                        "Git SSH option is missing its value".to_owned(),
                    ));
                }
            }
            "-o" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    GuestError::Runtime("Git SSH -o option is missing its value".to_owned())
                })?;
                if value != "SendEnv=GIT_PROTOCOL" {
                    return Err(GuestError::Runtime(format!(
                        "Git SSH option `{value}` is not allowed"
                    )));
                }
                index += 2;
            }
            _ => {
                return Err(GuestError::Runtime(format!(
                    "Git SSH option `{argument}` is not allowed"
                )));
            }
        }
    }
    if host_seen {
        Ok(())
    } else {
        Err(GuestError::Runtime(
            "Git SSH invocation does not include a host".to_owned(),
        ))
    }
}

fn find_git_and_replacement_paths(
    candidates: &[PathBuf],
    expected_owner: u32,
) -> Result<(PathBuf, BTreeSet<PathBuf>), GuestError> {
    let mut source = None;
    let mut replacements = BTreeSet::new();
    for candidate in candidates {
        if !candidate.is_absolute() {
            return Err(GuestError::Runtime(
                "Git candidate paths must be absolute".to_owned(),
            ));
        }
        let Some(parent) = candidate.parent() else {
            continue;
        };
        let Ok(parent) = parent.canonicalize() else {
            continue;
        };
        validate_directory(&parent, expected_owner, "Git binary directory")?;
        let effective = parent.join(
            candidate
                .file_name()
                .ok_or_else(|| GuestError::Runtime("Git candidate has no file name".to_owned()))?,
        );
        if effective.symlink_metadata().is_err() {
            continue;
        }
        if source.is_none() {
            source = Some(
                effective
                    .canonicalize()
                    .map_err(|error| GuestError::io("resolving original Git binary", error))?,
            );
        }
        replacements.insert(effective);
    }
    source
        .map(|source| (source, replacements))
        .ok_or_else(|| GuestError::Runtime("Git is unavailable in the guest".to_owned()))
}

fn validate_directory(path: &Path, expected_owner: u32, label: &str) -> Result<(), GuestError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| GuestError::io("inspecting Git guard directory", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_owner
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(GuestError::Runtime(format!(
            "{label} `{}` must be owned by the trusted guest identity and not writable by group or world",
            path.display()
        )));
    }
    Ok(())
}

fn validate_executable_owner(
    path: &Path,
    expected_owner: u32,
    label: &str,
) -> Result<(), GuestError> {
    let canonical = path
        .canonicalize()
        .map_err(|error| GuestError::io("resolving Git guard executable", error))?;
    if canonical != path {
        return Err(GuestError::Runtime(format!(
            "{label} `{}` must be canonical",
            path.display()
        )));
    }
    let metadata = path
        .symlink_metadata()
        .map_err(|error| GuestError::io("inspecting Git guard executable", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != expected_owner
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(GuestError::Runtime(format!(
            "{label} `{}` is not a trusted executable",
            path.display()
        )));
    }
    Ok(())
}

fn write_policy(path: &Path, policy: &GuardPolicyDocument) -> Result<(), GuestError> {
    let bytes = serde_json::to_vec(policy)
        .map_err(|error| GuestError::Runtime(format!("encode Git guard policy: {error}")))?;
    if bytes.len() > policy.limits.policy_bytes {
        return Err(GuestError::Runtime(
            "Git guard policy exceeds its configured byte limit".to_owned(),
        ));
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o444)
        .open(path)
        .map_err(|error| GuestError::io("creating Git guard policy", error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| GuestError::io("writing Git guard policy", error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o444))
        .map_err(|error| GuestError::io("setting Git guard policy mode", error))
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    use sendbox_git::{
        BranchPolicyConfiguration, EnvironmentPolicy, GuardLimits, PolicySchemaVersion,
        RepositoryIdentity, read_policy_file,
    };

    use super::*;

    fn executable(path: &Path) {
        fs::write(path, "#!/bin/sh\nexit 0\n").expect("write executable");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("mode");
    }

    fn policy(workspace: PathBuf) -> GuardPolicyDocument {
        GuardPolicyDocument {
            schema_version: PolicySchemaVersion::V1,
            selected_repository: RepositoryIdentity::new("github.com", "owner", "repo")
                .expect("repository"),
            selected_workspace: workspace,
            branch_protection: BranchPolicyConfiguration::default(),
            environment: EnvironmentPolicy::default(),
            github_https_auth: false,
            git_ssh_auth: false,
            limits: GuardLimits::default(),
        }
    }

    #[test]
    fn installs_root_owned_policy_and_replaces_every_git_alias() {
        let temporary = tempfile::tempdir().expect("temporary");
        let temporary_root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary");
        let owner = rustix::process::geteuid().as_raw();
        let root = temporary_root.join("guard");
        let bin = temporary_root.join("bin");
        fs::create_dir(&bin).expect("bin");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("bin mode");
        let guest = temporary_root.join("sendbox-guest");
        fs::write(&guest, "#!/bin/sh\nexit 64\n").expect("write guest");
        fs::set_permissions(&guest, fs::Permissions::from_mode(0o755)).expect("guest mode");
        let git = bin.join("git");
        executable(&git);
        let paths = InstallPaths {
            policy: root.join("policy.json"),
            real_git: root.join("git-real"),
            askpass: root.join("sendbox-git-askpass"),
            ssh_wrapper: root.join("sendbox-git-ssh"),
            ssh_work_root: root.join("ssh-work"),
            root: root.clone(),
            guest_binary: guest.clone(),
            git_candidates: vec![git.clone()],
        };
        let mut configured = policy(PathBuf::from("/workspace"));
        configured.github_https_auth = true;
        configured.git_ssh_auth = true;
        configured
            .environment
            .inherited_keys
            .insert(GITHUB_TOKEN_ENVIRONMENT.to_owned());
        configured
            .environment
            .inherited_keys
            .insert(SSH_KEY_ENVIRONMENT.to_owned());
        install_with_paths(
            &configured,
            &paths,
            owner,
            owner,
            rustix::process::getegid().as_raw(),
        )
        .expect("install");

        assert!(
            !git.symlink_metadata()
                .expect("guard metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(&git).expect("guard wrapper"),
            "#!/bin/sh\nexit 64\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("git-real")).expect("real git"),
            "#!/bin/sh\nexit 0\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("sendbox-git-askpass")).expect("askpass"),
            "#!/bin/sh\nexit 64\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("sendbox-git-ssh")).expect("SSH wrapper"),
            "#!/bin/sh\nexit 64\n"
        );
        assert_eq!(
            root.join("ssh-work")
                .symlink_metadata()
                .expect("SSH work root")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let installed = read_policy_file(&root.join("policy.json")).expect("policy");
        assert_eq!(installed.selected_workspace, Path::new("/workspace"));
    }

    #[test]
    fn rejects_preexisting_guard_root() {
        let temporary = tempfile::tempdir().expect("temporary");
        let temporary_root = temporary
            .path()
            .canonicalize()
            .expect("canonical temporary");
        let owner = rustix::process::geteuid().as_raw();
        let root = temporary_root.join("guard");
        fs::create_dir(&root).expect("root");
        let guest = temporary_root.join("sendbox-guest");
        executable(&guest);
        let git = temporary_root.join("git");
        executable(&git);
        let paths = InstallPaths {
            policy: root.join("policy.json"),
            real_git: root.join("git-real"),
            askpass: root.join("sendbox-git-askpass"),
            ssh_wrapper: root.join("sendbox-git-ssh"),
            ssh_work_root: root.join("ssh-work"),
            root,
            guest_binary: guest,
            git_candidates: vec![git],
        };
        assert!(
            install_with_paths(
                &policy(PathBuf::from("/workspace")),
                &paths,
                owner,
                owner,
                rustix::process::getegid().as_raw(),
            )
            .is_err()
        );
    }

    #[test]
    fn askpass_and_ssh_argument_filters_fail_closed() {
        assert_eq!(
            askpass_response(&["Username for 'https://github.com':".to_owned()]).expect("username"),
            "x-access-token"
        );
        assert!(
            validate_ssh_arguments(&[
                "-o".to_owned(),
                "ProxyCommand=attacker".to_owned(),
                "git@github.com".to_owned(),
            ])
            .is_err()
        );
        validate_ssh_arguments(&[
            "-o".to_owned(),
            "SendEnv=GIT_PROTOCOL".to_owned(),
            "-p".to_owned(),
            "22".to_owned(),
            "git@github.com".to_owned(),
            "git-upload-pack 'owner/repo.git'".to_owned(),
        ])
        .expect("Git SSH arguments");
    }
}
