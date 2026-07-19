use std::collections::BTreeMap;
use std::fs;

use proptest::prelude::*;
use sendbox_project::{
    Analyzer, DevContainerOverrides, ProjectError, generate_devcontainer, parse_jsonc,
    write_devcontainer,
};
use serde_json::{Value, json};
use tempfile::tempdir;

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn jsonc_comments_strings_and_trailing_commas_parse_correctly() {
    let source =
        fs::read_to_string(fixture("jsonc").join(".devcontainer/devcontainer.json")).unwrap();
    let parsed = parse_jsonc(&source).unwrap();
    assert_eq!(parsed["image"], "registry.example/dev//image:latest");
    assert_eq!(
        parsed["customizations"]["vscode"]["settings"]["example.url"],
        "https://example.test/a//b"
    );
}

#[test]
fn existing_jsonc_and_rust_overrides_merge_deterministically() {
    let analysis = Analyzer::default().analyze(fixture("jsonc")).unwrap();
    let existing = parse_jsonc(
        &fs::read_to_string(fixture("jsonc").join(".devcontainer/devcontainer.json")).unwrap(),
    )
    .unwrap();
    let overrides = DevContainerOverrides {
        image: Some("mcr.microsoft.com/devcontainers/javascript-node:1-22-bookworm".to_owned()),
        extensions: vec!["example.override".to_owned(), "example.existing".to_owned()],
        container_env: BTreeMap::from([("OVERRIDE".to_owned(), "true".to_owned())]),
        forward_ports: vec![3000, 5173],
        ..DevContainerOverrides::default()
    };
    let first = generate_devcontainer(&analysis, Some(existing.clone()), &overrides).unwrap();
    let second = generate_devcontainer(&analysis, Some(existing), &overrides).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first["image"],
        "mcr.microsoft.com/devcontainers/javascript-node:1-22-bookworm"
    );
    assert_eq!(first["containerEnv"]["EXISTING"], "true");
    assert_eq!(first["containerEnv"]["OVERRIDE"], "true");
    assert_eq!(first["forwardPorts"], json!([3000, 5173]));
    assert_eq!(
        first["customizations"]["vscode"]["extensions"],
        json!([
            "EditorConfig.EditorConfig",
            "GitHub.copilot",
            "GitHub.copilot-chat",
            "dbaeumer.vscode-eslint",
            "esbenp.prettier-vscode",
            "example.existing",
            "example.override"
        ])
    );
}

#[test]
fn atomic_output_is_private_and_reports_comment_loss() {
    let project = tempdir().unwrap();
    fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname='x'\nversion='0.1.0'\n",
    )
    .unwrap();
    let analysis = Analyzer::default().analyze(project.path()).unwrap();
    let generated = write_devcontainer(
        project.path(),
        None,
        &analysis,
        &DevContainerOverrides::default(),
    )
    .unwrap();
    assert!(generated.path.exists());
    assert!(!generated.comments_preserved);
    let written: Value = serde_json::from_slice(&fs::read(&generated.path).unwrap()).unwrap();
    assert_eq!(written, generated.spec);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&generated.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn refuses_symlink_output() {
    use std::os::unix::fs::symlink;

    let project = tempdir().unwrap();
    fs::write(
        project.path().join("go.mod"),
        "module example.test/x\ngo 1.24\n",
    )
    .unwrap();
    fs::create_dir(project.path().join(".devcontainer")).unwrap();
    let target = project.path().join("target.json");
    fs::write(&target, "{}").unwrap();
    symlink(
        &target,
        project.path().join(".devcontainer/devcontainer.json"),
    )
    .unwrap();
    let analysis = Analyzer::default().analyze(project.path()).unwrap();
    let error = write_devcontainer(
        project.path(),
        None,
        &analysis,
        &DevContainerOverrides::default(),
    )
    .unwrap_err();
    assert!(matches!(error, ProjectError::SymlinkOutput(_)));
}

proptest! {
    #[test]
    fn jsonc_parser_preserves_comment_tokens_inside_strings(
        left in "[a-zA-Z0-9]{0,20}",
        right in "[a-zA-Z0-9]{0,20}",
        number in any::<u32>(),
    ) {
        let string = format!("{left}//{right}/*literal*/");
        let encoded = serde_json::to_string(&string).unwrap();
        let source = format!(
            "{{/*before*/\"value\":{encoded},//line\n\"number\":{number},}}"
        );
        let parsed = parse_jsonc(&source).unwrap();
        prop_assert_eq!(parsed["value"].as_str(), Some(string.as_str()));
        prop_assert_eq!(parsed["number"].as_u64(), Some(u64::from(number)));
    }
}
