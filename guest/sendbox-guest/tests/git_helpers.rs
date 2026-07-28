#![forbid(unsafe_code)]

use std::{os::unix::process::CommandExt, process::Command};

fn guest() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sendbox-guest"))
}

#[test]
fn askpass_returns_only_the_requested_credential_value() {
    let output = guest()
        .arg0("sendbox-git-askpass")
        .arg("Password for 'https://github.com':")
        .env("GITHUB_TOKEN", "secret-token")
        .output()
        .expect("run askpass");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"secret-token\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn ssh_wrapper_rejects_caller_configuration_without_leaking_the_key() {
    let key = "-----BEGIN PRIVATE KEY-----\nsecret-key\n-----END PRIVATE KEY-----";
    let output = guest()
        .arg0("sendbox-git-ssh")
        .args(["-F", "/tmp/attacker", "git@github.com"])
        .env("SENDBOX_GIT_SSH_KEY", key)
        .output()
        .expect("run SSH wrapper");
    assert_eq!(output.status.code(), Some(128));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-key"));
}
