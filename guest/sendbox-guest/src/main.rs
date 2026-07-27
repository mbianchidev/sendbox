#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use sendbox_guest::GuestError;
use sendbox_guest::platform::LinuxPlatformControls;
use sendbox_guest::runtime::RuntimeIdentity;
use sendbox_guest::supervisor::{SupervisorOptions, run};
use tokio::io::AsyncReadExt;
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
    #[command(hide = true)]
    ExecBroker(ExecBrokerArgs),
    #[command(hide = true)]
    Tunnel(TunnelArgs),
    #[command(hide = true)]
    InjectBootstrap(InjectBootstrapArgs),
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

#[derive(Debug, Args)]
struct ExecBrokerArgs {
    #[arg(long)]
    config: PathBuf,
}

#[derive(Debug, Args)]
struct TunnelArgs {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long, default_value_t = 30_000)]
    connect_timeout_ms: u64,
}

#[derive(Debug, Args)]
struct InjectBootstrapArgs {
    #[arg(long)]
    bootstrap_target: PathBuf,
    #[arg(long)]
    trust_root_target: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FixtureMode {
    Healthy,
    Crash,
    IgnoreTerm,
}

#[tokio::main(flavor = "current_thread")]
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
    return match cli.command {
        Commands::Bootstrap(args) | Commands::Supervisor(args) => {
            run(
                SupervisorOptions {
                    bootstrap_file: args.bootstrap_file,
                    trust_root_file: args.trust_root_file,
                    artifact_root: args.artifact_root,
                    runtime_root: args.runtime_root,
                    replay_root: args.replay_root,
                },
                &LinuxPlatformControls::new(PathBuf::from("/sys/fs/cgroup/sendbox")),
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
        Commands::ExecBroker(args) => sendbox_guest::broker::run(args.config).await,
        Commands::Tunnel(args) => tunnel(args).await,
        Commands::InjectBootstrap(args) => inject_bootstrap(args).await,
    };

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct InjectionEnvelope {
        bootstrap: Vec<u8>,
        trust_root: Vec<u8>,
    }

    async fn inject_bootstrap(args: InjectBootstrapArgs) -> Result<(), GuestError> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        use zeroize::Zeroize;

        if args.bootstrap_target.parent() != args.trust_root_target.parent()
            || !args.bootstrap_target.is_absolute()
        {
            return Err(GuestError::Bootstrap(
                "injected bootstrap paths must share one absolute parent".to_owned(),
            ));
        }
        let parent = args
            .bootstrap_target
            .parent()
            .expect("absolute injection path has a parent");
        if !parent.exists() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(parent)
                .map_err(|error| GuestError::io("creating bootstrap injection directory", error))?;
        }
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| GuestError::io("setting bootstrap injection directory mode", error))?;
        let mut encoded = Vec::new();
        tokio::io::stdin()
            .take(128 * 1024)
            .read_to_end(&mut encoded)
            .await
            .map_err(|error| GuestError::io("reading injected bootstrap", error))?;
        let mut envelope: InjectionEnvelope =
            serde_json::from_slice(&encoded).map_err(|error| {
                GuestError::Bootstrap(format!("decode injection envelope: {error}"))
            })?;
        encoded.zeroize();
        if envelope.trust_root.len() != 32 {
            envelope.bootstrap.zeroize();
            envelope.trust_root.zeroize();
            return Err(GuestError::Bootstrap(
                "injected trust root must contain exactly 32 bytes".to_owned(),
            ));
        }
        write_injected(&args.bootstrap_target, &envelope.bootstrap, 0o400)?;
        write_injected(&args.trust_root_target, &envelope.trust_root, 0o444)?;
        envelope.bootstrap.zeroize();
        envelope.trust_root.zeroize();
        Ok(())
    }

    fn write_injected(path: &std::path::Path, bytes: &[u8], mode: u32) -> Result<(), GuestError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(path)
            .map_err(|error| GuestError::io("creating injected file", error))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| GuestError::io("writing injected file", error))
    }

    async fn tunnel(args: TunnelArgs) -> Result<(), GuestError> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(args.connect_timeout_ms);
        let stream = loop {
            match tokio::net::UnixStream::connect(&args.socket).await {
                Ok(stream) => break stream,
                Err(error) if tokio::time::Instant::now() < deadline => {
                    let _ = error;
                    sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(GuestError::io("connecting guest control socket", error)),
            }
        };
        let (mut guest_read, mut guest_write) = stream.into_split();
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        tokio::select! {
            result = tokio::io::copy(&mut stdin, &mut guest_write) => {
                result.map_err(|error| GuestError::io("tunneling host input", error))?;
            }
            result = tokio::io::copy(&mut guest_read, &mut stdout) => {
                result.map_err(|error| GuestError::io("tunneling guest output", error))?;
            }
        }
        Ok(())
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
