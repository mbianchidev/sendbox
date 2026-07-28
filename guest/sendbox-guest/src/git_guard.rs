use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use sendbox_git::{GuardPolicyDocument, TrustedExecutable, TrustedGitBinary, execute_guarded_git};

use crate::GuestError;

const ROOT_PATH: &str = "/run/sendbox-branch-protection";
const POLICY_PATH: &str = "/run/sendbox-branch-protection/policy.json";
const REAL_GIT_PATH: &str = "/run/sendbox-branch-protection/git-real";
const GIT_CANDIDATES: [&str; 3] = ["/usr/bin/git", "/bin/git", "/usr/local/bin/git"];
const EXIT_DENIED: u8 = 128;

pub fn install(policy: &GuardPolicyDocument, artifact_root: &Path) -> Result<(), GuestError> {
    let guest_binary = artifact_root.join("bin/sendbox-guest");
    install_with_paths(
        policy,
        &InstallPaths {
            root: PathBuf::from(ROOT_PATH),
            policy: PathBuf::from(POLICY_PATH),
            real_git: PathBuf::from(REAL_GIT_PATH),
            guest_binary,
            git_candidates: GIT_CANDIDATES.iter().map(PathBuf::from).collect(),
        },
        0,
    )
}

pub fn execute_current(arguments: &[String]) -> Result<(), GuestError> {
    execute_guarded_git(Path::new(POLICY_PATH), Path::new(REAL_GIT_PATH), arguments)
        .map_err(|error| GuestError::Runtime(error.to_string()))
}

#[must_use]
pub const fn denied_exit_code() -> u8 {
    EXIT_DENIED
}

struct InstallPaths {
    root: PathBuf,
    policy: PathBuf,
    real_git: PathBuf,
    guest_binary: PathBuf,
    git_candidates: Vec<PathBuf>,
}

fn install_with_paths(
    policy: &GuardPolicyDocument,
    paths: &InstallPaths,
    expected_owner: u32,
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
        guest_binary
            .copy_to(&replacement, 0o555)
            .map_err(|error| GuestError::Runtime(error.to_string()))?;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o555))
            .map_err(|error| GuestError::io("setting Git guard wrapper mode", error))?;
    }
    fs::File::open(&paths.root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| GuestError::io("syncing Git guard root", error))
}

fn validate_layout(paths: &InstallPaths) -> Result<(), GuestError> {
    if !paths.root.is_absolute()
        || paths.policy.parent() != Some(paths.root.as_path())
        || paths.real_git.parent() != Some(paths.root.as_path())
        || paths.policy == paths.real_git
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
            root: root.clone(),
            guest_binary: guest.clone(),
            git_candidates: vec![git.clone()],
        };
        install_with_paths(&policy(PathBuf::from("/workspace")), &paths, owner).expect("install");

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
            root,
            guest_binary: guest,
            git_candidates: vec![git],
        };
        assert!(install_with_paths(&policy(PathBuf::from("/workspace")), &paths, owner).is_err());
    }
}
