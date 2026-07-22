#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use sendbox_guest::GuestError;
use sendbox_guest::platform::UnavailablePlatformControls;
use sendbox_guest::runtime::RuntimeIdentity;
use sendbox_guest::supervisor::{SupervisorOptions, run};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::sleep;

#[derive(Debug, Parser)]
#[command(
    name = "sendbox-guest",
    version,
    about = "Trusted SendBox guest supervisor"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Consume bootstrap material and remain as the session supervisor.
    Bootstrap(LifecycleArgs),
    /// Run the complete bootstrap, readiness, supervision, and control lifecycle.
    Supervisor(LifecycleArgs),
    /// Print an authenticated session's local readiness marker.
    Health(HealthArgs),
    #[command(hide = true)]
    ServiceRun(ServiceRunArgs),
}

#[derive(Debug, Clone, Args)]
struct LifecycleArgs {
    #[arg(long)]
    bootstrap_file: PathBuf,
    #[arg(long)]
    trust_root_file: PathBuf,
    #[arg(long)]
    artifact_root: PathBuf,
    #[arg(long, default_value = "/run/sendbox")]
    runtime_root: PathBuf,
    #[arg(long, default_value = "/var/lib/sendbox/replay")]
    replay_root: PathBuf,
}

#[derive(Debug, Args)]
struct HealthArgs {
    #[arg(long)]
    readiness_file: PathBuf,
}

#[derive(Debug, Args)]
struct ServiceRunArgs {
    #[arg(long, value_enum, default_value_t = FixtureMode::Healthy)]
    mode: FixtureMode,
    #[arg(long, default_value_t = 0)]
    log_lines: usize,
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long)]
    pid_file: Option<PathBuf>,
    #[arg(long)]
    child_pid_file: Option<PathBuf>,
    #[arg(long, default_value_t = 25)]
    crash_after_ms: u64,
    #[arg(long)]
    crash_trigger_file: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    spawn_child: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FixtureMode {
    Healthy,
    Crash,
    IgnoreTerm,
}

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sendbox-guest: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<(), GuestError> {
    match cli.command {
        Commands::Bootstrap(args) | Commands::Supervisor(args) => {
            run(
                SupervisorOptions {
                    bootstrap_file: args.bootstrap_file,
                    trust_root_file: args.trust_root_file,
                    artifact_root: args.artifact_root,
                    runtime_root: args.runtime_root,
                    replay_root: args.replay_root,
                },
                &UnavailablePlatformControls,
                RuntimeIdentity::root(),
            )
            .await
        }
        Commands::Health(args) => {
            let readiness = tokio::fs::read_to_string(args.readiness_file)
                .await
                .map_err(|error| GuestError::io("reading readiness marker", error))?;
            println!("{readiness}");
            Ok(())
        }
        Commands::ServiceRun(args) => service_run(args).await,
    }
}

async fn service_run(args: ServiceRunArgs) -> Result<(), GuestError> {
    if let Some(path) = &args.pid_file {
        tokio::fs::write(path, std::process::id().to_string())
            .await
            .map_err(|error| GuestError::io("writing fixture PID", error))?;
    }
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    for index in 0..args.log_lines {
        stdout
            .write_all(format!("stdout-{index}\n").as_bytes())
            .await
            .map_err(|error| GuestError::io("writing fixture stdout", error))?;
        stderr
            .write_all(format!("stderr-{index}\n").as_bytes())
            .await
            .map_err(|error| GuestError::io("writing fixture stderr", error))?;
    }
    stdout
        .flush()
        .await
        .map_err(|error| GuestError::io("flushing fixture stdout", error))?;
    stderr
        .flush()
        .await
        .map_err(|error| GuestError::io("flushing fixture stderr", error))?;

    let listener = if let Some(path) = &args.socket {
        Some(
            UnixListener::bind(path)
                .map_err(|error| GuestError::io("binding fixture socket", error))?,
        )
    } else {
        None
    };
    if let Some(listener) = listener {
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    }

    let mut child = if args.spawn_child {
        let child = Command::new("sleep")
            .arg("300")
            .spawn()
            .map_err(|error| GuestError::io("spawning fixture child", error))?;
        if let (Some(path), Some(pid)) = (&args.child_pid_file, child.id()) {
            tokio::fs::write(path, pid.to_string())
                .await
                .map_err(|error| GuestError::io("writing fixture child PID", error))?;
        }
        Some(child)
    } else {
        None
    };

    match args.mode {
        FixtureMode::Crash => {
            if let Some(path) = args.crash_trigger_file {
                while tokio::fs::metadata(&path).await.is_err() {
                    sleep(Duration::from_millis(10)).await;
                }
            } else {
                sleep(Duration::from_millis(args.crash_after_ms)).await;
            }
            Err(GuestError::Service {
                service: "fixture".to_owned(),
                detail: "intentional crash".to_owned(),
            })
        }
        FixtureMode::Healthy => {
            let mut terminate = signal(SignalKind::terminate())
                .map_err(|error| GuestError::io("installing fixture SIGTERM handler", error))?;
            terminate.recv().await;
            if let Some(child) = &mut child {
                let _ = child.wait().await;
            }
            Ok(())
        }
        FixtureMode::IgnoreTerm => {
            let mut terminate = signal(SignalKind::terminate())
                .map_err(|error| GuestError::io("installing fixture SIGTERM handler", error))?;
            loop {
                terminate.recv().await;
            }
        }
    }
}
