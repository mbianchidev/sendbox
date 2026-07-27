#![forbid(unsafe_code)]

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use sendbox_runtime::{
    CancellationToken, Clock, CommandArgument, CommandSpec, EnvironmentVariable, OutputEvent,
    OutputStream, ProcessOptions, ProcessRunner, ProcessSignal, Program, ProgramResolver,
    RuntimeError, SearchPathResolver, TerminationReason,
};
use sendbox_testkit::{ManualClock, TempResource};

fn fixture_command(mode: &str, arguments: impl IntoIterator<Item = String>) -> CommandSpec {
    let mut command = CommandSpec::new(Program::Absolute(PathBuf::from(env!(
        "CARGO_BIN_EXE_sendbox-process-fixture"
    ))));
    command.arguments.push(CommandArgument::plain(mode));
    command
        .arguments
        .extend(arguments.into_iter().map(CommandArgument::plain));
    command
}

fn runner() -> ProcessRunner {
    ProcessRunner::new(Arc::new(
        SearchPathResolver::new(Vec::<PathBuf>::new()).expect("empty resolver"),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drains_saturated_stdout_and_stderr_concurrently() {
    let command = fixture_command("saturate", ["256".to_owned(), "4096".to_owned()]);
    let options = ProcessOptions {
        stdout_capture_bytes: 2 * 1024 * 1024,
        stderr_capture_bytes: 2 * 1024 * 1024,
        output_channel_capacity: 1,
        timeout: Some(Duration::from_secs(10)),
        ..ProcessOptions::default()
    };

    let outcome = runner()
        .run(command, options, &CancellationToken::new())
        .await
        .expect("saturated process");

    assert!(outcome.status.success);
    assert_eq!(outcome.stdout.total_bytes, 1024 * 1024);
    assert_eq!(outcome.stderr.total_bytes, 1024 * 1024);
    assert_eq!(outcome.stdout.truncated_bytes, 0);
    assert_eq!(outcome.stderr.truncated_bytes, 0);
    assert!(outcome.output.dropped.dropped_events > 0);
}

#[tokio::test]
async fn timeout_terminates_and_reaps_process() {
    let command = fixture_command("sleep", ["5000".to_owned()]);
    let options = ProcessOptions {
        timeout: Some(Duration::from_millis(50)),
        termination_grace: Duration::from_millis(25),
        ..ProcessOptions::default()
    };
    let started = Instant::now();

    let outcome = runner()
        .run(command, options, &CancellationToken::new())
        .await
        .expect("timed process");

    assert_eq!(outcome.termination, TerminationReason::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn explicit_cancellation_terminates_and_reaps_process() {
    let command = fixture_command("sleep", ["5000".to_owned()]);
    let mut process = runner()
        .spawn(
            command,
            ProcessOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("spawn");
    drop(process.take_output_subscription());
    let cancellation = CancellationToken::new();
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        trigger.cancel();
    });

    let outcome = process
        .wait(&cancellation)
        .await
        .expect("cancelled process");
    assert_eq!(outcome.termination, TerminationReason::Cancelled);
}

#[cfg(unix)]
#[tokio::test]
async fn signals_target_the_process_group_and_report_signal_exit() {
    let command = fixture_command("sleep", ["5000".to_owned()]);
    let process = runner()
        .spawn(
            command,
            ProcessOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("spawn");
    process
        .send_signal(ProcessSignal::Terminate)
        .expect("send terminate");

    let outcome = process.wait(&CancellationToken::new()).await.expect("wait");
    assert_eq!(outcome.termination, TerminationReason::Exited);
    assert_eq!(outcome.status.signal, Some(libc_signal_term()));
}

#[cfg(unix)]
const fn libc_signal_term() -> i32 {
    15
}

#[tokio::test]
async fn nonzero_exit_is_an_outcome_not_a_runner_error() {
    let outcome = runner()
        .run(
            fixture_command("exit", ["23".to_owned()]),
            ProcessOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("nonzero process outcome");

    assert!(!outcome.status.success);
    assert_eq!(outcome.status.code, Some(23));
    assert_eq!(outcome.termination, TerminationReason::Exited);
}

#[tokio::test]
async fn missing_executable_is_a_redacted_spawn_error() {
    let secret_argument = "argument-secret-2d8d";
    let secret_environment = "environment-secret-90c1";
    let mut command = CommandSpec::new(Program::Absolute(PathBuf::from(
        "/definitely/missing/sendbox-fixture",
    )));
    command
        .arguments
        .push(CommandArgument::sensitive(secret_argument));
    command.environment.push(EnvironmentVariable::sensitive(
        "SENDBOX_SECRET",
        secret_environment,
    ));

    let error = runner()
        .run(
            command,
            ProcessOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .expect_err("missing executable");
    let display = error.to_string();
    assert!(matches!(error, RuntimeError::Spawn { .. }));
    assert!(!display.contains(secret_argument));
    assert!(!display.contains(secret_environment));
    assert!(display.contains("<redacted>"));
}

#[tokio::test]
async fn invalid_environment_and_working_directories_fail_before_spawn() {
    let mut invalid_key = fixture_command("sleep", ["1".to_owned()]);
    invalid_key
        .environment
        .push(EnvironmentVariable::plain("BAD=KEY", "value"));
    assert!(matches!(
        runner()
            .run(
                invalid_key,
                ProcessOptions::default(),
                &CancellationToken::new()
            )
            .await,
        Err(RuntimeError::InvalidCommand { .. })
    ));

    let mut invalid_value = fixture_command("sleep", ["1".to_owned()]);
    invalid_value
        .environment
        .push(EnvironmentVariable::plain("KEY", "bad\0value"));
    assert!(matches!(
        runner()
            .run(
                invalid_value,
                ProcessOptions::default(),
                &CancellationToken::new()
            )
            .await,
        Err(RuntimeError::InvalidCommand { .. })
    ));

    let resources = TempResource::new().expect("temp");
    let file = resources
        .create_file("not-a-directory", b"data")
        .expect("file");
    let mut invalid_cwd = fixture_command("sleep", ["1".to_owned()]);
    invalid_cwd.current_directory = Some(file);
    assert!(matches!(
        runner()
            .run(
                invalid_cwd,
                ProcessOptions::default(),
                &CancellationToken::new()
            )
            .await,
        Err(RuntimeError::InvalidWorkingDirectory { .. })
    ));
}

#[tokio::test]
async fn capture_caps_report_exact_truncation_while_still_draining() {
    let options = ProcessOptions {
        stdout_capture_bytes: 97,
        stderr_capture_bytes: 113,
        output_channel_capacity: 1,
        ..ProcessOptions::default()
    };
    let outcome = runner()
        .run(
            fixture_command("saturate", ["8".to_owned(), "1024".to_owned()]),
            options,
            &CancellationToken::new(),
        )
        .await
        .expect("bounded capture");

    assert_eq!(outcome.stdout.bytes.len(), 97);
    assert_eq!(outcome.stderr.bytes.len(), 113);
    assert_eq!(outcome.stdout.total_bytes, 8192);
    assert_eq!(outcome.stderr.total_bytes, 8192);
    assert_eq!(outcome.stdout.truncated_bytes, 8192 - 97);
    assert_eq!(outcome.stderr.truncated_bytes, 8192 - 113);
}

#[tokio::test]
async fn capture_only_process_does_not_publish_output_events() {
    let mut process = runner()
        .spawn(
            fixture_command("saturate", ["1".to_owned(), "64".to_owned()]),
            ProcessOptions {
                publish_output: false,
                ..ProcessOptions::default()
            },
            &CancellationToken::new(),
        )
        .await
        .expect("spawn");
    assert!(process.take_output_subscription().is_none());
    let outcome = process
        .wait(&CancellationToken::new())
        .await
        .expect("capture-only process");
    assert_eq!(outcome.stdout.total_bytes, 64);
    assert_eq!(outcome.stderr.total_bytes, 64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_client_observes_monotonic_events_and_explicit_loss() {
    let mut process = runner()
        .spawn(
            fixture_command("saturate", ["128".to_owned(), "1024".to_owned()]),
            ProcessOptions {
                output_channel_capacity: 2,
                ..ProcessOptions::default()
            },
            &CancellationToken::new(),
        )
        .await
        .expect("spawn");
    let mut subscription = process
        .take_output_subscription()
        .expect("output subscription");
    let outcome = process.wait(&CancellationToken::new()).await.expect("wait");

    let mut previous = 0;
    let mut previous_stdout = 0;
    let mut previous_stderr = 0;
    let mut reported_loss = 0;
    while let Some(event) = subscription
        .next(&CancellationToken::new())
        .await
        .expect("stream event")
    {
        assert!(event.global_sequence() > previous);
        previous = event.global_sequence();
        match event {
            OutputEvent::Data {
                stream,
                stream_sequence,
                dropped_before,
                ..
            } => {
                let previous_stream = match stream {
                    OutputStream::Stdout => &mut previous_stdout,
                    OutputStream::Stderr => &mut previous_stderr,
                };
                assert!(stream_sequence > *previous_stream);
                *previous_stream = stream_sequence;
                reported_loss += dropped_before.map_or(0, |loss| loss.dropped_events);
            }
            OutputEvent::Loss { dropped, .. } => {
                reported_loss += dropped.dropped_events;
            }
        }
    }
    assert_eq!(reported_loss, outcome.output.dropped.dropped_events);
    assert!(reported_loss > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_output_client_never_blocks_pipe_drain() {
    let mut process = runner()
        .spawn(
            fixture_command("saturate", ["128".to_owned(), "2048".to_owned()]),
            ProcessOptions {
                output_channel_capacity: 1,
                timeout: Some(Duration::from_secs(5)),
                ..ProcessOptions::default()
            },
            &CancellationToken::new(),
        )
        .await
        .expect("spawn");
    drop(process.take_output_subscription());

    let outcome = process
        .wait(&CancellationToken::new())
        .await
        .expect("wait after client drop");
    assert!(outcome.status.success);
    assert_eq!(outcome.stdout.total_bytes, 128 * 2048);
    assert_eq!(outcome.stderr.total_bytes, 128 * 2048);
    assert!(outcome.output.dropped.dropped_events > 0);
}

#[tokio::test]
async fn cancelling_only_the_output_subscription_does_not_cancel_the_process() {
    let process_cancellation = CancellationToken::new();
    let mut process = runner()
        .spawn(
            fixture_command("sleep", ["5000".to_owned()]),
            ProcessOptions::default(),
            &process_cancellation,
        )
        .await
        .expect("spawn");
    let mut subscription = process
        .take_output_subscription()
        .expect("output subscription");
    let client_cancellation = CancellationToken::new();
    client_cancellation.cancel();
    assert!(matches!(
        subscription.next(&client_cancellation).await,
        Err(RuntimeError::Cancelled)
    ));

    process_cancellation.cancel();
    let outcome = process
        .wait(&process_cancellation)
        .await
        .expect("cancel process");
    assert_eq!(outcome.termination, TerminationReason::Cancelled);
}

#[tokio::test]
async fn environment_is_cleared_by_default_and_cwd_creates_no_files() {
    let resources = TempResource::new().expect("temp");
    let mut environment_command = fixture_command("echo-env", ["PATH".to_owned()]);
    environment_command.current_directory = Some(resources.path().to_path_buf());
    let outcome = runner()
        .run(
            environment_command,
            ProcessOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("environment check");
    assert_eq!(outcome.stdout.bytes, b"<missing>\n");

    let entries = std::fs::read_dir(resources.path())
        .expect("read temporary directory")
        .count();
    assert_eq!(entries, 0);
}

#[tokio::test]
async fn process_elapsed_time_uses_the_injected_clock() {
    let clock = Arc::new(ManualClock::new());
    let resolver =
        Arc::new(SearchPathResolver::new(Vec::<PathBuf>::new()).expect("empty resolver"));
    let runner = ProcessRunner::with_clock(resolver, clock.clone());
    let process = runner
        .spawn(
            fixture_command("sleep", ["25".to_owned()]),
            ProcessOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("spawn");
    clock.advance(Duration::from_secs(7));
    let outcome = process.wait(&CancellationToken::new()).await.expect("wait");

    assert_eq!(outcome.elapsed, Duration::from_secs(7));
    assert_eq!(clock.now(), outcome.finished_at);
}

#[derive(Debug)]
struct RelativeResolver;

impl ProgramResolver for RelativeResolver {
    fn resolve(&self, _name: &str) -> Result<PathBuf, RuntimeError> {
        Ok(PathBuf::from("relative-program"))
    }
}

#[tokio::test]
async fn named_program_resolver_must_return_an_absolute_path() {
    let runner = ProcessRunner::new(Arc::new(RelativeResolver));
    let error = runner
        .run(
            CommandSpec::new(Program::Named("fixture".to_owned())),
            ProcessOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .expect_err("relative resolution");
    assert!(matches!(
        error,
        RuntimeError::ResolverReturnedRelative { .. }
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn cancellation_kills_child_processes_in_the_same_group() {
    use nix::{errno::Errno, sys::signal::kill, unistd::Pid};

    let cancellation = CancellationToken::new();
    let mut process = runner()
        .spawn(
            fixture_command("spawn-child", ["5000".to_owned()]),
            ProcessOptions {
                termination_grace: Duration::from_millis(25),
                output_channel_capacity: 4,
                ..ProcessOptions::default()
            },
            &cancellation,
        )
        .await
        .expect("spawn process group");
    let mut subscription = process
        .take_output_subscription()
        .expect("output subscription");
    let mut child_pid_bytes = Vec::new();
    while !child_pid_bytes.contains(&b'\n') {
        let event = tokio::time::timeout(Duration::from_secs(5), subscription.next(&cancellation))
            .await
            .expect("child pid output timeout")
            .expect("child pid output")
            .expect("child pid event");
        if let OutputEvent::Data {
            stream: OutputStream::Stdout,
            bytes,
            ..
        } = event
        {
            child_pid_bytes.extend(bytes);
        }
    }
    let child_pid = String::from_utf8(child_pid_bytes)
        .expect("child pid UTF-8")
        .trim()
        .parse::<i32>()
        .expect("child pid");
    cancellation.cancel();
    let outcome = process
        .wait(&cancellation)
        .await
        .expect("cancel process group");
    assert_eq!(outcome.termination, TerminationReason::Cancelled);

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match kill(Pid::from_raw(child_pid), None) {
            Err(Errno::ESRCH) => break,
            Ok(()) | Err(Errno::EPERM) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            result => panic!("child process {child_pid} survived group cleanup: {result:?}"),
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_running_process_synchronously_kills_its_process_group() {
    use nix::{errno::Errno, sys::signal::kill, unistd::Pid};

    let cancellation = CancellationToken::new();
    let mut process = runner()
        .spawn(
            fixture_command("spawn-child", ["5000".to_owned()]),
            ProcessOptions {
                output_channel_capacity: 4,
                ..ProcessOptions::default()
            },
            &cancellation,
        )
        .await
        .expect("spawn process group");
    let parent_pid = i32::try_from(process.pid()).expect("parent pid");
    let mut subscription = process
        .take_output_subscription()
        .expect("output subscription");
    let mut child_pid_bytes = Vec::new();
    while !child_pid_bytes.contains(&b'\n') {
        let event = tokio::time::timeout(Duration::from_secs(5), subscription.next(&cancellation))
            .await
            .expect("child pid output timeout")
            .expect("child pid output")
            .expect("child pid event");
        if let OutputEvent::Data {
            stream: OutputStream::Stdout,
            bytes,
            ..
        } = event
        {
            child_pid_bytes.extend(bytes);
        }
    }
    let child_pid = String::from_utf8(child_pid_bytes)
        .expect("child pid UTF-8")
        .trim()
        .parse::<i32>()
        .expect("child pid");

    drop(process);

    for pid in [parent_pid, child_pid] {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match kill(Pid::from_raw(pid), None) {
                Err(Errno::ESRCH) => break,
                Ok(()) | Err(Errno::EPERM) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                result => panic!("process {pid} survived RunningProcess drop: {result:?}"),
            }
        }
    }
}
