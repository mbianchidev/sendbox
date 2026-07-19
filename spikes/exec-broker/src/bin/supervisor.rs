//! `exec-broker-supervisor`: starts the broker, and on broker death kills
//! every process group it had registered, then removes the runtime
//! directory. See [`exec_broker_spike::supervisor`] for the full
//! semantics, including the documented narrow spawn-before-registration
//! race.
//!
//! This binary is deliberately started directly (not as a descendant of
//! the conceptually seccomp-filtered agent process), and does not itself
//! install any seccomp filter: it must retain the ability to signal other
//! process groups, which is exactly the kind of operation the broker's and
//! launcher's own filters intentionally restrict for *them*.
//!
//! On any non-Linux target this binary immediately reports the
//! "unsupported platform" error and exits non-zero.

#[cfg(target_os = "linux")]
fn main() {
    linux_main::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "error: {}",
        exec_broker_spike::platform::unsupported_platform_error()
    );
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux_main {
    use clap::Parser;
    use exec_broker_spike::pgid_registry::PgidRegistry;
    use exec_broker_spike::supervisor::supervise_once;
    use std::path::PathBuf;

    /// Runtime directory *path* handed to the broker on the command line;
    /// the supervisor does not create it — the broker creates its own
    /// runtime directory on startup (see
    /// `exec_broker_spike::broker::runtime_dir::RuntimeDir::create_fresh`)
    /// and the supervisor only attaches to it afterward, for cleanup, once
    /// the broker has exited.
    #[derive(Parser, Debug)]
    #[command(name = "exec-broker-supervisor")]
    struct Cli {
        /// Path to the `exec-broker` binary to supervise.
        #[arg(long)]
        broker_binary: PathBuf,

        /// Runtime directory path the broker will create fresh on its own
        /// startup (passed through via `--runtime-dir`, appended to
        /// `broker_args`); the supervisor attaches to it for cleanup only
        /// after the broker exits.
        #[arg(long)]
        runtime_dir: PathBuf,

        /// Every other argument is forwarded verbatim to the broker
        /// binary (allowlist entries, approved root, etc.).
        #[arg(trailing_var_arg = true)]
        broker_args: Vec<String>,
    }

    pub fn run() {
        let cli = Cli::parse();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        if let Err(err) = runtime.block_on(async_main(cli)) {
            eprintln!("fatal: {err}");
            std::process::exit(1);
        }
    }

    async fn async_main(cli: Cli) -> Result<(), exec_broker_spike::error::BrokerError> {
        let registry = PgidRegistry::new(cli.runtime_dir.join("pgids.json"));

        let mut broker_args = vec![
            "--runtime-dir".to_string(),
            cli.runtime_dir.to_string_lossy().into_owned(),
        ];
        broker_args.extend(cli.broker_args);

        let status =
            supervise_once(&cli.broker_binary, &broker_args, &cli.runtime_dir, registry).await?;
        std::process::exit(status.code().unwrap_or(1));
    }
}
