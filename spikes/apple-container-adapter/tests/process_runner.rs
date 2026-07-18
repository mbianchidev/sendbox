use apple_container_adapter_spike::process::{
    CommandSpec, ProcessControls, ProcessRunner, ProcessTermination, TokioProcessRunner,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn controls() -> ProcessControls {
    ProcessControls {
        timeout: Duration::from_secs(2),
        stdout_limit: 1024,
        stderr_limit: 1024,
        cancellation: CancellationToken::new(),
    }
}

#[tokio::test]
async fn preserves_exit_status() {
    let output = TokioProcessRunner
        .run(&CommandSpec::new("/usr/bin/false", Vec::new()), controls())
        .await
        .expect("false should execute");

    assert_eq!(output.termination, ProcessTermination::Exited);
    assert!(!output.status.success);
    assert_eq!(output.status.code, Some(1));
}

#[tokio::test]
async fn times_out_and_reaps_the_child() {
    let mut controls = controls();
    controls.timeout = Duration::from_millis(50);
    let output = TokioProcessRunner
        .run(
            &CommandSpec::new("/bin/sleep", vec!["5".to_owned()]),
            controls,
        )
        .await
        .expect("sleep should be terminated");

    assert_eq!(output.termination, ProcessTermination::TimedOut);
    assert!(!output.status.success);
}

#[tokio::test]
async fn cancellation_terminates_and_reaps_the_child() {
    let token = CancellationToken::new();
    let mut controls = controls();
    controls.cancellation = token.clone();
    let task = tokio::spawn(async move {
        TokioProcessRunner
            .run(
                &CommandSpec::new("/bin/sleep", vec!["5".to_owned()]),
                controls,
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    token.cancel();
    let output = task
        .await
        .expect("runner task should not panic")
        .expect("sleep should be cancelled");

    assert_eq!(output.termination, ProcessTermination::Cancelled);
    assert!(!output.status.success);
}

#[tokio::test]
async fn caps_output_without_deadlocking() {
    let payload = "x".repeat(256 * 1024);
    let mut controls = controls();
    controls.stdout_limit = 128;
    let output = TokioProcessRunner
        .run(
            &CommandSpec::new("/usr/bin/printf", vec!["%s".to_owned(), payload]),
            controls,
        )
        .await
        .expect("printf should execute");

    assert!(output.status.success);
    assert_eq!(output.stdout.text.len(), 128);
    assert!(output.stdout.truncated);
}

#[tokio::test]
async fn clears_inherited_environment_and_redacts_secrets() {
    let environment_specification = CommandSpec::new("/usr/bin/env", Vec::new());
    let allowed_keys = environment_specification
        .environment
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let environment_output = TokioProcessRunner
        .run(&environment_specification, controls())
        .await
        .expect("env should execute");
    for line in environment_output.stdout.text.lines() {
        let key = line.split_once('=').map_or(line, |(key, _)| key);
        assert!(allowed_keys.iter().any(|allowed| allowed == key));
    }

    let mut specification = CommandSpec::new(
        "/usr/bin/printf",
        vec!["%s".to_owned(), "super-secret".to_owned()],
    );
    specification.add_secret("super-secret");
    let output = TokioProcessRunner
        .run(&specification, controls())
        .await
        .expect("printf should execute");
    assert_eq!(output.stdout.text, "<redacted>");
    assert!(!specification.diagnostic().contains("super-secret"));
}
