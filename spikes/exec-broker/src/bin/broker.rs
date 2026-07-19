//! `exec-broker`: the control-plane binary. Applies `PR_SET_NO_NEW_PRIVS`
//! and the [`SeccompProfile::Broker`] filter to itself, creates a fresh
//! runtime directory and Unix socket, then serves accepted connections
//! until asked to shut down (`SIGINT`/`SIGTERM`).
//!
//! This binary is never started as a descendant of the (conceptually)
//! seccomp-filtered agent process — it is a separate, directly-launched
//! trusted component, matching the architecture documented in
//! [`exec_broker_spike::platform`].
//!
//! On any non-Linux target this binary immediately reports the
//! "unsupported platform" error and exits non-zero.

use exec_broker_spike::platform;

#[cfg(target_os = "linux")]
fn main() {
    linux_main::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("error: {}", platform::unsupported_platform_error());
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux_main {
    use super::platform;
    use clap::Parser;
    use exec_broker_spike::broker::runtime_dir::RuntimeDir;
    use exec_broker_spike::broker::server::{BrokerConfig, serve};
    use exec_broker_spike::broker::socket;
    use exec_broker_spike::pgid_registry::PgidRegistry;
    use exec_broker_spike::platform::SeccompProfile;
    use exec_broker_spike::policy::Policy;
    use exec_broker_spike::protocol::Limits;
    use exec_broker_spike::session::Session;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// Command-line configuration for one broker instance. Parsed only
    /// after this process has already applied its own `NO_NEW_PRIVS` +
    /// `Broker` seccomp filter (defense-in-depth; unlike the agent binary,
    /// the broker's own CLI arguments are operator-supplied trusted
    /// configuration, not adversarial input, but there is no reason not to
    /// harden first regardless).
    #[derive(Parser, Debug)]
    #[command(name = "exec-broker")]
    struct Cli {
        /// Directory to create fresh (0700) as this broker instance's
        /// runtime directory; must not already exist (see
        /// `RuntimeDir::create_fresh` — restart is unsupported by design).
        #[arg(long)]
        runtime_dir: PathBuf,

        /// Absolute path under which every approved `cwd` must fall.
        #[arg(long)]
        allowed_root: PathBuf,

        /// Canonical absolute path of an executable to allow. May be
        /// repeated.
        #[arg(long = "allow-exec")]
        allowed_executables: Vec<PathBuf>,

        /// Absolute path to the `exec-broker-launcher` binary.
        #[arg(long)]
        launcher_binary: PathBuf,

        /// Fixed `PATH` supplied to every spawned command.
        #[arg(long, default_value = "/usr/bin:/bin")]
        fixed_path: String,

        /// Fixed `LANG` supplied to every spawned command.
        #[arg(long, default_value = "C.UTF-8")]
        fixed_lang: String,
    }

    pub fn run() {
        if let Err(err) = platform::set_no_new_privs() {
            eprintln!("fatal: set_no_new_privs failed: {err}");
            std::process::exit(1);
        }
        if let Err(err) = platform::install_seccomp_filter(SeccompProfile::Broker) {
            eprintln!("fatal: install_seccomp_filter failed: {err}");
            std::process::exit(1);
        }

        let cli = Cli::parse();

        // The broker installs its seccomp profile before constructing the
        // runtime. That profile deliberately denies clone3 because its flags
        // are pointer-based and cannot be filtered safely. A current-thread
        // runtime preserves fully asynchronous socket/process handling
        // without needing to create worker threads after the filter is armed.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        if let Err(err) = runtime.block_on(async_main(cli)) {
            eprintln!("fatal: {err}");
            std::process::exit(1);
        }
    }

    async fn async_main(cli: Cli) -> Result<(), exec_broker_spike::error::BrokerError> {
        let runtime_dir = RuntimeDir::create_fresh(&cli.runtime_dir)?;
        let listener = socket::bind(&runtime_dir)?;
        let expected_uid = nix::unistd::getuid().as_raw();

        // Generate the single session credential for this broker instance
        // once, at startup, and persist it as an owner-only file inside
        // the already-0700 runtime directory. Every connection
        // authenticates every `Execute`/`Cancel` request against this same
        // shared session (see `exec_broker_spike::session`); there is no
        // per-connection session issuance.
        let session = Session::generate()
            .map_err(|err| exec_broker_spike::error::BrokerError::SessionSetup(err.to_string()))?;
        session
            .write_credentials_file(
                &runtime_dir
                    .path()
                    .join(exec_broker_spike::session::CREDENTIALS_FILE_NAME),
            )
            .map_err(|err| exec_broker_spike::error::BrokerError::SessionSetup(err.to_string()))?;
        let session = Arc::new(session);

        let registry = PgidRegistry::new(runtime_dir.path().join("pgids.json"));

        let policy = Policy::new(
            &cli.allowed_root,
            cli.allowed_executables.clone(),
            cli.fixed_path.clone(),
            cli.fixed_lang.clone(),
            Limits::default(),
        )?;

        let config = Arc::new(BrokerConfig {
            policy,
            launcher_binary: cli.launcher_binary.clone(),
            process_limits: Default::default(),
            pgid_registry: Some(registry),
            session,
        });

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("failed to install SIGINT handler");

        // `serve` runs as its own task so that, when a signal arrives, we
        // can flip the shutdown watch and then still *await* `serve`
        // draining its in-flight connections (rather than racing the
        // signal against `serve` directly, which would simply cancel it
        // immediately instead of giving it a chance to shut down
        // gracefully).
        let mut serve_task = tokio::spawn(serve(listener, expected_uid, config, shutdown_rx));

        tokio::select! {
            result = &mut serve_task => {
                result.expect("serve task panicked")?;
            }
            _ = sigterm.recv() => {
                let _ = shutdown_tx.send(true);
                serve_task.await.expect("serve task panicked")?;
            }
            _ = sigint.recv() => {
                let _ = shutdown_tx.send(true);
                serve_task.await.expect("serve task panicked")?;
            }
        }

        runtime_dir.remove()?;
        Ok(())
    }
}
