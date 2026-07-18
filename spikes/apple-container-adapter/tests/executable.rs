use apple_container_adapter_spike::executable::ExecutableResolver;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn reports_missing_executable() {
    let report = ExecutableResolver::default().resolve(Some(
        PathBuf::from("/definitely/missing/container").as_path(),
    ));
    assert!(!report.trusted);
    assert!(report.resolved_path.is_none());
    assert!(report.reasons[0].contains("cannot inspect executable"));
}

#[test]
fn rejects_non_root_owned_executable() {
    let directory = tempdir().expect("temporary directory");
    let executable = directory.path().join("container");
    fs::write(&executable, b"fixture").expect("write fixture");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
        .expect("set executable mode");

    let report = ExecutableResolver::default().resolve(Some(&executable));
    assert!(!report.trusted);
    assert_eq!(
        report.resolved_path,
        Some(fs::canonicalize(&executable).expect("canonical fixture"))
    );
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.contains("not root"))
    );
}

#[test]
fn records_symlink_chain_before_rejecting_untrusted_target() {
    let directory = tempdir().expect("temporary directory");
    let target = directory.path().join("container-real");
    let link = directory.path().join("container");
    fs::write(&target, b"fixture").expect("write fixture");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("set executable mode");
    symlink(&target, &link).expect("create symlink");

    let report = ExecutableResolver::default().resolve(Some(&link));
    assert_eq!(report.symlink_chain, vec![link]);
    assert_eq!(
        report.resolved_path,
        Some(fs::canonicalize(&target).expect("canonical target"))
    );
    assert!(!report.trusted);
}
