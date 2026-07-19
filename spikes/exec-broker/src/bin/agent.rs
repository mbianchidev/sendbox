//! `exec-broker-agent`: the trusted-bootstrap entry point for the
//! (conceptual, in this spike) sandboxed workload role, plus a `probe`
//! subcommand implementing the static syscall test helper and a
//! `broker-client` subcommand implementing a real, working IPC client.
//!
//! # Trusted bootstrap semantics
//!
//! `main` installs `PR_SET_NO_NEW_PRIVS` and the
//! [`exec_broker_spike::platform::SeccompProfile::AgentBootstrap`] filter
//! (with `TSYNC`) **before** parsing any command-line argument or reading
//! any other untrusted input, satisfying "before any untrusted input" by
//! construction: nothing about argv/env is inspected until after the
//! filter is already loaded. This holds for every subcommand, including
//! `broker-client` below: the mode string itself is the first byte of
//! argv this process ever looks at, and that lookup happens strictly
//! after `install_seccomp_filter` returns.
//!
//! # The `probe` mode
//!
//! `exec-broker-agent probe` runs only after the bootstrap filter is
//! installed, attempts a fixed battery of exec-family primitives (libc
//! `execve`, the raw `execve` syscall, libc/raw `execveat` against an
//! already-open `memfd` *and* an already-open fd for `/bin/true`, a
//! shebang script, the dynamic linker, `argv[0]` pointed at
//! `/proc/self/exe`, and an alternate interpreter path), and prints one
//! JSON object per line describing the typed, structured outcome of each
//! attempt — deliberately never actually replacing this process's image.
//! It also spawns a second thread *before* installing the filter, to
//! prove `TSYNC` synchronizes the filter to that thread too (not just the
//! thread that called `seccomp()`).
//!
//! Crucially, the memfd and the `/bin/true` fd used by the `execveat`
//! attempts are both created *during trusted bootstrap* — before the
//! filter is installed and before argv is ever parsed — not inside
//! `probe` itself. `memfd_create` is unconditionally denied by every
//! seccomp profile this crate installs (including `AgentBootstrap`), so
//! creating the memfd only *after* the filter would make `create_memfd`
//! itself fail with `EPERM` and the `execveat`-by-fd attempts would never
//! run against a real fd at all — proving only that `memfd_create` is
//! denied, not that `execveat` against an fd that already exists is also
//! independently denied. See `platform::linux::adapter`'s module doc
//! comment for the precise invariant.
//!
//! # The `broker-client` mode
//!
//! `exec-broker-agent broker-client --runtime-dir <dir> -- <argv...>` is
//! the real agent role this spike's architecture describes: after the
//! seccomp filter denying every exec-family syscall is already installed
//! and active on this process, it reads the broker's session credential
//! file and connects to the broker's Unix socket (both re-validated for
//! owner/mode — see [`exec_broker_spike::session::load_credentials_file`]
//! and [`exec_broker_spike::broker::socket::validate_socket_path_for_connect`]),
//! sends exactly one authenticated `Execute` request, optionally follows
//! it with a `Cancel`, drains every typed [`ServerEvent`] until a terminal
//! `Completed`/`Rejected`, and exits with a status code reflecting that
//! terminal result. Successfully completing this round trip demonstrates
//! that ordinary socket I/O still works after this process's own
//! exec-family syscalls have been unconditionally denied — the filter
//! narrows what this process can *become*, not what it can communicate
//! over an already-open file descriptor.
//!
//! # The `fail-closed-probe` mode
//!
//! `exec-broker-agent fail-closed-probe --runtime-dir <dir> --cwd <dir>`
//! proves that killing the broker never reopens *this* process's own
//! local sandbox: after the same bootstrap filter is installed, it
//! authenticates a real `Execute` request against the real broker
//! session (proving normal socket I/O still works), signals readiness,
//! then waits for the broker's socket to disappear (the observable sign
//! that it was killed and cleaned up — see
//! [`exec_broker_spike::supervisor`]), and only then repeats the same
//! direct libc/raw `execve`/`execveat` battery `probe` mode runs,
//! against the same trusted-bootstrap fds. Every attempt is still
//! expected to be `Denied`: the seccomp filter is a property of this
//! process, entirely independent of whether any particular broker
//! instance is alive. Intended to be driven by an external integration
//! test that also owns starting the supervisor/broker and killing the
//! broker at the right moment.
//!
//! On any non-Linux target, `main` immediately prints the
//! "unsupported platform" error and exits non-zero without attempting any
//! of the above.

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
    use exec_broker_spike::broker::framing::{read_message, write_message};
    use exec_broker_spike::broker::runtime_dir::{RuntimeDir, SOCKET_FILE_NAME};
    use exec_broker_spike::broker::socket;
    use exec_broker_spike::error::PlatformError;
    use exec_broker_spike::platform::SeccompProfile;
    use exec_broker_spike::platform::linux::adapter::{
        self, ExecAttemptOutcome, attempt_libc_execve, attempt_libc_execveat_fd,
        attempt_raw_syscall_execve, attempt_raw_syscall_execveat_fd,
    };
    use exec_broker_spike::protocol::{ClientMessage, Outcome, ServerEvent};
    use exec_broker_spike::session;
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::os::unix::io::RawFd;
    use std::path::PathBuf;

    pub fn run() {
        // Bootstrap: before touching argv, env, stdin, or the network,
        // install NNP + the AgentBootstrap filter (with TSYNC).
        if let Err(err) = platform::set_no_new_privs() {
            eprintln!("fatal: set_no_new_privs failed: {err}");
            std::process::exit(1);
        }

        // The second-thread TSYNC proof needs a thread parked *before* the
        // filter is installed, so it is set up here, ahead of installing
        // the filter, and only proceeds with its own probe attempt once
        // told to (after the filter is loaded on the main thread).
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let (result_tx, result_rx) = std::sync::mpsc::channel::<ExecAttemptOutcome>();
        let second_thread = std::thread::spawn(move || {
            // Signal we exist and are about to block, then wait to be told
            // the filter has been installed (with TSYNC) on the main
            // thread before attempting anything.
            let _ = ready_tx.send(());
            let _ = go_rx.recv();
            let outcome = attempt_libc_execve("/bin/true");
            let _ = result_tx.send(outcome);
        });
        let _ = ready_rx.recv();

        // Trusted-bootstrap fixture setup: create/populate the memfd and
        // open an executable fd for `/bin/true` *before* installing the
        // filter and before parsing any untrusted input (argv). This is
        // load-bearing, not merely early for tidiness: `memfd_create` is
        // itself unconditionally denied by every seccomp profile (see
        // `platform::linux::seccomp::MEMFD_CREATE`), so if these fds were
        // created *after* the filter, `create_memfd`/`open_executable_fd`
        // would fail during their own setup and the subsequent
        // `execveat`-by-fd attempts could never actually exercise the
        // kernel's denial of `execveat` itself — only of `memfd_create`.
        // Creating them now means the post-filter probe attempts run
        // against fds that already, genuinely exist, so a `Denied` result
        // from them proves `execveat` is denied, not merely that creating
        // the fd was denied.
        let memfd = adapter::create_memfd("exec-broker-agent-probe").and_then(|fd| {
            adapter::write_fd(fd, b"\x7fELF-not-a-real-binary-just-probe-fixture")?;
            Ok(fd)
        });
        let bin_true_fd = adapter::open_executable_fd("/bin/true");

        if let Err(err) = platform::install_seccomp_filter(SeccompProfile::AgentBootstrap) {
            eprintln!("fatal: install_seccomp_filter failed: {err}");
            std::process::exit(1);
        }

        // Only now, after the bootstrap filter is loaded, is it safe to
        // parse argv (untrusted input) and dispatch subcommands.
        let args: Vec<String> = std::env::args().collect();
        let mode = args.get(1).map(String::as_str).unwrap_or("bootstrap");

        match mode {
            "probe" => run_probe(go_tx, result_rx, second_thread, memfd, bin_true_fd),
            "broker-client" => {
                // The parked probe thread and its channels are only used
                // by `probe` mode; tear them down cleanly here too so this
                // mode does not hang waiting on a thread it will never
                // signal. The memfd/bin_true fixture fds are likewise only
                // used by `probe` mode; close them here so this mode never
                // leaks them.
                let _ = go_tx.send(());
                let _ = second_thread.join();
                close_probe_fds(memfd, bin_true_fd);
                let exit_code = run_broker_client(&args[2..]);
                std::process::exit(exit_code);
            }
            "fail-closed-probe" => {
                // Same cleanup rationale as `broker-client` above: this
                // mode does not use the parked TSYNC-proof thread, but it
                // does reuse the memfd/`/bin/true` fixture fds created
                // during trusted bootstrap for its own post-broker-death
                // `execveat`-by-fd attempts, so they are threaded through
                // rather than closed here.
                let _ = go_tx.send(());
                let _ = second_thread.join();
                let exit_code = run_fail_closed_probe(&args[2..], memfd, bin_true_fd);
                std::process::exit(exit_code);
            }
            _ => {
                // Plain bootstrap mode: prove the filter is active and
                // exit. A real agent would proceed to connect to the
                // broker's Unix socket and request every command
                // execution from here on, never calling exec* itself.
                println!(
                    "exec-broker-agent: bootstrap complete (no_new_privs={}, filter=AgentBootstrap)",
                    adapter::no_new_privs_is_set().unwrap_or(false)
                );
                // Tear down the parked probe thread and the unused
                // probe fixture fds cleanly even in bootstrap mode, so
                // `main` does not hang or leak fds.
                let _ = go_tx.send(());
                let _ = second_thread.join();
                close_probe_fds(memfd, bin_true_fd);
            }
        }
    }

    /// Closes whichever of the memfd/`/bin/true` probe fixture fds were
    /// successfully created, for any mode that does not go on to use them
    /// (`bootstrap`, `broker-client`). A `SetupFailed` (never obtained a
    /// valid fd) is a no-op here, not a double-free: there is nothing to
    /// close.
    fn close_probe_fds(
        memfd: Result<RawFd, PlatformError>,
        bin_true_fd: Result<RawFd, PlatformError>,
    ) {
        if let Ok(fd) = memfd {
            adapter::close_fd(fd);
        }
        if let Ok(fd) = bin_true_fd {
            adapter::close_fd(fd);
        }
    }

    #[derive(Serialize)]
    struct ProbeResult {
        name: &'static str,
        outcome: OutcomeJson,
    }

    #[derive(Serialize)]
    #[serde(tag = "kind")]
    enum OutcomeJson {
        Denied { errno: i32 },
        UnexpectedSuccess,
        SetupFailed { message: String },
    }

    impl From<ExecAttemptOutcome> for OutcomeJson {
        fn from(outcome: ExecAttemptOutcome) -> Self {
            match outcome {
                ExecAttemptOutcome::Denied { errno } => OutcomeJson::Denied { errno },
                ExecAttemptOutcome::UnexpectedSuccess => OutcomeJson::UnexpectedSuccess,
                ExecAttemptOutcome::SetupFailed { message } => OutcomeJson::SetupFailed { message },
            }
        }
    }

    fn emit(name: &'static str, outcome: ExecAttemptOutcome) {
        let result = ProbeResult {
            name,
            outcome: outcome.into(),
        };
        let line = serde_json::to_string(&result).unwrap_or_else(|e| {
            format!("{{\"name\":\"{name}\",\"outcome\":{{\"kind\":\"SetupFailed\",\"message\":\"failed to encode result: {e}\"}}}}")
        });
        println!("{line}");
        let _ = std::io::stdout().flush();
    }

    /// Runs every static syscall-probe attempt, after the bootstrap filter
    /// (denying `execve`/`execveat`/`memfd_create`) is already installed
    /// and loaded. Every attempt is expected to end in
    /// `ExecAttemptOutcome::Denied`, printed as one JSON line each; this
    /// function deliberately never lets any attempt actually replace the
    /// process image.
    fn run_probe(
        go_tx: std::sync::mpsc::Sender<()>,
        result_rx: std::sync::mpsc::Receiver<ExecAttemptOutcome>,
        second_thread: std::thread::JoinHandle<()>,
        memfd: Result<RawFd, PlatformError>,
        bin_true_fd: Result<RawFd, PlatformError>,
    ) {
        emit("libc_execve_bin_true", attempt_libc_execve("/bin/true"));
        emit(
            "raw_syscall_execve_bin_true",
            attempt_raw_syscall_execve("/bin/true"),
        );

        // Both fds below were created and populated during trusted
        // bootstrap, strictly before the filter denying
        // `execve`/`execveat`/`memfd_create` was installed (see `run`).
        // Reaching this point with `Ok(fd)` therefore means the fd
        // genuinely, already exists; a `Denied` outcome from the
        // `execveat` attempt against it proves the kernel denies
        // `execveat` itself, not merely that creating the fd was denied.
        match memfd {
            Ok(fd) => {
                emit("libc_execveat_memfd", attempt_libc_execveat_fd(fd));
                emit(
                    "raw_syscall_execveat_memfd",
                    attempt_raw_syscall_execveat_fd(fd),
                );
                adapter::close_fd(fd);
            }
            Err(err) => {
                emit(
                    "libc_execveat_memfd",
                    ExecAttemptOutcome::SetupFailed {
                        message: err.to_string(),
                    },
                );
                emit(
                    "raw_syscall_execveat_memfd",
                    ExecAttemptOutcome::SetupFailed {
                        message: err.to_string(),
                    },
                );
            }
        }

        match bin_true_fd {
            Ok(fd) => {
                emit("libc_execveat_bin_true_fd", attempt_libc_execveat_fd(fd));
                emit(
                    "raw_syscall_execveat_bin_true_fd",
                    attempt_raw_syscall_execveat_fd(fd),
                );
                adapter::close_fd(fd);
            }
            Err(err) => {
                emit(
                    "libc_execveat_bin_true_fd",
                    ExecAttemptOutcome::SetupFailed {
                        message: err.to_string(),
                    },
                );
                emit(
                    "raw_syscall_execveat_bin_true_fd",
                    ExecAttemptOutcome::SetupFailed {
                        message: err.to_string(),
                    },
                );
            }
        }

        match write_temp_shebang_script() {
            Ok(path) => {
                emit("libc_execve_shebang_script", attempt_libc_execve(&path));
                if let Err(err) = std::fs::remove_file(&path) {
                    eprintln!(
                        "exec-broker-agent: warning: failed to clean up probe script {path}: {err}"
                    );
                }
            }
            Err(message) => emit(
                "libc_execve_shebang_script",
                ExecAttemptOutcome::SetupFailed { message },
            ),
        }

        match find_existing_path(&[
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/ld-linux-aarch64.so.1",
            "/lib/ld-musl-x86_64.so.1",
            "/lib/ld-musl-aarch64.so.1",
        ]) {
            Some(path) => emit("libc_execve_dynamic_linker", attempt_libc_execve(&path)),
            None => emit(
                "libc_execve_dynamic_linker",
                ExecAttemptOutcome::SetupFailed {
                    message: "no known dynamic linker path found on this system".to_string(),
                },
            ),
        }

        emit(
            "libc_execve_proc_self_exe",
            attempt_libc_execve("/proc/self/exe"),
        );

        match find_existing_path(&["/bin/sh", "/usr/bin/sh"]) {
            Some(path) => emit(
                "libc_execve_alternate_interpreter",
                attempt_libc_execve(&path),
            ),
            None => emit(
                "libc_execve_alternate_interpreter",
                ExecAttemptOutcome::SetupFailed {
                    message: "no known shell interpreter path found on this system".to_string(),
                },
            ),
        }

        // Second-thread TSYNC proof: the filter was installed on the main
        // thread only; this parked thread never called `seccomp()`
        // itself. If its attempt is also `Denied`, TSYNC actually
        // propagated the filter to it.
        let _ = go_tx.send(());
        match result_rx.recv() {
            Ok(outcome) => emit("second_thread_tsync_execve_bin_true", outcome),
            Err(_) => emit(
                "second_thread_tsync_execve_bin_true",
                ExecAttemptOutcome::SetupFailed {
                    message: "second thread did not report a result".to_string(),
                },
            ),
        }
        let _ = second_thread.join();
    }

    fn write_temp_shebang_script() -> Result<String, String> {
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("exec-broker-agent-probe-{pid}.sh"));
        std::fs::write(&path, b"#!/bin/sh\necho probe\n")
            .map_err(|e| format!("failed to write probe script: {e}"))?;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| format!("failed to stat probe script: {e}"))?
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| format!("failed to chmod probe script: {e}"))?;
        Ok(path.to_string_lossy().into_owned())
    }

    fn find_existing_path(candidates: &[&str]) -> Option<String> {
        candidates
            .iter()
            .find(|candidate| std::path::Path::new(candidate).exists())
            .map(|s| (*s).to_string())
    }

    /// CLI surface for `broker-client`, parsed only after the
    /// `AgentBootstrap` seccomp filter is already active (see the module
    /// doc comment). Every field here is treated as untrusted input from
    /// the process's own invoker: it influences only the *contents* of
    /// the `Execute` request sent to the broker, never which credential
    /// file or socket is trusted (those are derived solely from
    /// `--runtime-dir`, validated by owner/mode before use, matching the
    /// broker's own trust model).
    #[derive(Parser, Debug)]
    #[command(name = "exec-broker-agent broker-client")]
    struct BrokerClientCli {
        /// The broker's runtime directory (created 0700 by `exec-broker`
        /// at startup). The session credential file and the Unix socket
        /// are both located, and validated, relative to this path.
        #[arg(long)]
        runtime_dir: PathBuf,

        /// `cwd` sent in the `Execute` request. Must fall under the
        /// broker's configured `allowed_root` or the broker rejects the
        /// request.
        #[arg(long)]
        cwd: PathBuf,

        /// Timeout, in milliseconds, sent in the `Execute` request.
        #[arg(long, default_value_t = 5_000)]
        timeout_ms: u64,

        /// `KEY=VALUE` environment entries sent in the `Execute` request.
        /// May be repeated. The broker's policy independently sanitizes
        /// and may reject/override entries here regardless of what is
        /// passed.
        #[arg(long = "env", value_parser = parse_env_kv)]
        env: Vec<(String, String)>,

        /// If set, a `Cancel` for this same correlation id is sent this
        /// many milliseconds after `Execute`, exercising the broker's
        /// cancellation path end-to-end from a real client.
        #[arg(long)]
        cancel_after_ms: Option<u64>,

        /// The command to execute: `argv[0]` is both the executable path
        /// and the first argument, matching POSIX `exec*` semantics
        /// (no separate "executable" field), consistent with
        /// `exec_broker_spike::protocol::ClientMessage::Execute`.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    }

    fn parse_env_kv(raw: &str) -> Result<(String, String), String> {
        match raw.split_once('=') {
            Some((key, value)) => Ok((key.to_string(), value.to_string())),
            None => Err(format!("expected KEY=VALUE, got {raw:?}")),
        }
    }

    /// Runs the `broker-client` subcommand: connects to the broker over
    /// its Unix socket, sends one authenticated `Execute` (and optionally
    /// a `Cancel`), drains every `ServerEvent` until a terminal result,
    /// and returns a process exit code reflecting that result. `raw_args`
    /// excludes both the program name and the `broker-client` mode word
    /// itself.
    fn run_broker_client(raw_args: &[String]) -> i32 {
        let cli = match BrokerClientCli::try_parse_from(
            std::iter::once("exec-broker-agent broker-client".to_string())
                .chain(raw_args.iter().cloned()),
        ) {
            Ok(cli) => cli,
            Err(err) => {
                eprintln!("{err}");
                return 2;
            }
        };

        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("fatal: failed to build tokio runtime: {err}");
                return 1;
            }
        };

        runtime.block_on(async_broker_client(cli))
    }

    async fn async_broker_client(cli: BrokerClientCli) -> i32 {
        let expected_uid = nix::unistd::getuid().as_raw();

        // Validates the runtime directory itself (real directory, owned
        // by this process's uid, mode exactly 0700) before trusting
        // anything inside it.
        let runtime_dir = match RuntimeDir::open_existing(&cli.runtime_dir) {
            Ok(dir) => dir,
            Err(err) => {
                eprintln!("fatal: runtime directory is not safe to use: {err}");
                return 1;
            }
        };

        // Reads and validates the session credential file: rejects
        // symlinks, wrong owner, and any mode other than the two
        // documented owner-only bits, only then parses it as JSON. See
        // `exec_broker_spike::session::load_credentials_file`.
        let credentials = match session::load_credentials_file(
            &runtime_dir.path().join(session::CREDENTIALS_FILE_NAME),
            expected_uid,
        ) {
            Ok(credentials) => credentials,
            Err(err) => {
                eprintln!("fatal: failed to load session credentials: {err}");
                return 1;
            }
        };

        // Validates the socket path (real socket, owned by this
        // process's uid, mode exactly 0600) before connecting.
        let std_stream = match socket::connect(&runtime_dir.socket_path(), expected_uid) {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("fatal: failed to connect to broker socket: {err}");
                return 1;
            }
        };
        if let Err(err) = std_stream.set_nonblocking(true) {
            eprintln!("fatal: failed to set socket non-blocking: {err}");
            return 1;
        }
        let stream = match tokio::net::UnixStream::from_std(std_stream) {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("fatal: failed to hand socket to async runtime: {err}");
                return 1;
            }
        };

        let correlation_id = generate_correlation_id();
        let env: BTreeMap<String, String> = cli.env.into_iter().collect();

        let (mut read_half, mut write_half) = stream.into_split();

        let execute = ClientMessage::Execute {
            correlation_id: correlation_id.clone(),
            session_id: credentials.session_id.clone(),
            token: credentials.token_hex.clone(),
            argv: cli.argv,
            cwd: cli.cwd.to_string_lossy().into_owned(),
            env,
            timeout_ms: cli.timeout_ms,
        };
        if let Err(err) = write_message(&mut write_half, &execute).await {
            eprintln!("fatal: failed to send Execute request: {err}");
            return 1;
        }
        // `execute` (and its credentials) must not be logged verbatim:
        // drop the owned copy holding the token now that it has been
        // sent, so nothing later in this function can accidentally print
        // it.
        drop(execute);

        // NOTE: deliberately *not* `Option::map(move |...| ...)` here: a
        // `move` closure captures `write_half` at construction time
        // regardless of whether `Option::map` ever actually calls it, so
        // when `cancel_after_ms` is `None` the closure (and the
        // `write_half` it captured) would be constructed and immediately
        // dropped — which sends `SHUT_WR` on the socket and makes the
        // broker observe a premature disconnect before the execution can
        // even complete. An explicit `if`/`else` only moves `write_half`
        // into the spawned task in the `Some` case; in the `None` case it
        // simply stays owned by this function until the read loop below
        // finishes and this function returns.
        let mut cancel_task = if let Some(delay_ms) = cli.cancel_after_ms {
            let session_id = credentials.session_id.clone();
            let token = credentials.token_hex.clone();
            let correlation_id = correlation_id.clone();
            Some(tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                let cancel = ClientMessage::Cancel {
                    correlation_id,
                    session_id,
                    token,
                };
                let _ = write_message(&mut write_half, &cancel).await;
            }))
        } else {
            None
        };

        loop {
            match read_message::<ServerEvent, _>(&mut read_half).await {
                Ok(Some(ServerEvent::Started { pid, pgid, .. })) => {
                    eprintln!("started: pid={pid} pgid={pgid}");
                }
                Ok(Some(ServerEvent::Stdout {
                    data, truncated, ..
                })) => {
                    print_decoded(&data, truncated, false);
                }
                Ok(Some(ServerEvent::Stderr {
                    data, truncated, ..
                })) => {
                    print_decoded(&data, truncated, true);
                }
                Ok(Some(ServerEvent::Rejected { code, message, .. })) => {
                    eprintln!("rejected: {code:?}: {message}");
                    if let Some(task) = cancel_task.take() {
                        task.abort();
                    }
                    return 3;
                }
                Ok(Some(ServerEvent::Completed { outcome, .. })) => {
                    if let Some(task) = cancel_task.take() {
                        task.abort();
                    }
                    if !matches!(outcome, Outcome::Exited { .. }) {
                        eprintln!("completed: {outcome:?}");
                    }
                    return exit_code_for_outcome(&outcome);
                }
                Ok(None) => {
                    eprintln!("fatal: broker closed the connection before completion");
                    return 1;
                }
                Err(err) => {
                    eprintln!("fatal: failed to read server event: {err}");
                    return 1;
                }
            }
        }
    }

    fn print_decoded(data_b64: &str, truncated: bool, is_stderr: bool) {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .unwrap_or_default();
        if is_stderr {
            let _ = std::io::stderr().write_all(&bytes);
        } else {
            let _ = std::io::stdout().write_all(&bytes);
        }
        if truncated {
            eprintln!("(stream truncated by broker-side cap)");
        }
    }

    fn exit_code_for_outcome(outcome: &Outcome) -> i32 {
        match outcome {
            Outcome::Exited { exit_code, .. } => exit_code.unwrap_or(128),
            Outcome::TimedOut => 124,
            Outcome::Cancelled => 130,
            Outcome::ClientDisconnected => 1,
            Outcome::BrokerShutdown => 1,
            Outcome::SpawnFailed { .. } => 1,
            Outcome::StreamStalled => 1,
        }
    }

    /// CLI for `fail-closed-probe`: see its module-level and function-level
    /// documentation for the full scenario this proves.
    #[derive(Parser, Debug)]
    #[command(name = "exec-broker-agent fail-closed-probe")]
    struct FailClosedProbeCli {
        /// The broker's runtime directory, exactly as for `broker-client`.
        #[arg(long)]
        runtime_dir: PathBuf,

        /// `cwd` sent in the one-shot `Execute` request used only to
        /// prove this process authenticated and observed a real broker
        /// session before the broker was killed. Must fall under the
        /// broker's configured `allowed_root`.
        #[arg(long)]
        cwd: PathBuf,

        /// How long to wait, after authenticating, for the broker's own
        /// socket to disappear (the observable signal that the broker has
        /// died and been cleaned up) before giving up and failing loudly
        /// rather than silently skipping the post-death probes.
        #[arg(long, default_value_t = 30)]
        death_timeout_secs: u64,

        /// The command sent in the one-shot `Execute` request used only
        /// to prove this process authenticated and observed a real
        /// broker session before the broker was killed. Must already be
        /// in the broker's allowlist and be the fully canonical path
        /// (broker policy rejects non-canonical/symlink executable
        /// paths), e.g. `/usr/bin/true` rather than `/bin/true` on
        /// distributions where the latter is a symlink.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        exec_argv: Vec<String>,
    }

    /// Runs the "fail-closed after broker death" scenario end to end from
    /// inside a single agent process, for an external integration harness
    /// to orchestrate (see `tests/fail_closed_after_broker_death.rs`):
    ///
    /// 1. The `AgentBootstrap` seccomp filter (denying every exec-family
    ///    syscall) is already installed by the time this function is ever
    ///    called — `main`/`run` install it before argv is even parsed, for
    ///    every mode including this one.
    /// 2. This process connects to the broker's real Unix socket,
    ///    authenticates with the real session credentials, and sends one
    ///    real `Execute` request for the allowlisted command given on the
    ///    command line, reading events until it
    ///    sees proof of a genuine, authenticated broker session (a
    ///    `Started` or `Completed` event) — demonstrating that ordinary
    ///    socket I/O and the broker protocol both still work fully after
    ///    this process's own exec-family syscalls are already denied.
    /// 3. It prints a readiness line to stdout and flushes, so a harness
    ///    knows it is safe to now kill the broker.
    /// 4. It polls (bounded by `--death-timeout-secs`) for the broker's
    ///    socket file to disappear — the supervisor's post-broker-death
    ///    cleanup (see `exec_broker_spike::supervisor`) removes the whole
    ///    runtime directory, including the socket, so this is a reliable,
    ///    externally-observable "the broker is gone and has been cleaned
    ///    up" signal that does not require this process to have any other
    ///    channel to the harness. If the timeout elapses first, this is
    ///    treated as a harness/environment failure and reported loudly
    ///    (non-zero exit, explicit message), never silently skipped.
    /// 5. Only then, with the broker fully gone, does it attempt the same
    ///    direct libc/raw `execve`/`execveat` primitives `probe` mode
    ///    does, against the same fixtures created during trusted
    ///    bootstrap (the memfd and the `/bin/true` fd), emitting one JSON
    ///    line per attempt via the same typed [`OutcomeJson`] used by
    ///    `probe`. The seccomp filter is a per-process kernel-held
    ///    attribute of *this* process; it is never installed, refreshed,
    ///    or in any way dependent on the broker's continued existence, so
    ///    every attempt here is expected to still end in `Denied` with
    ///    `EPERM` — proving the broker's death does not reopen this
    ///    process's own local sandbox.
    fn run_fail_closed_probe(
        raw_args: &[String],
        memfd: Result<RawFd, PlatformError>,
        bin_true_fd: Result<RawFd, PlatformError>,
    ) -> i32 {
        let cli = match FailClosedProbeCli::try_parse_from(
            std::iter::once("exec-broker-agent fail-closed-probe".to_string())
                .chain(raw_args.iter().cloned()),
        ) {
            Ok(cli) => cli,
            Err(err) => {
                eprintln!("{err}");
                close_probe_fds(memfd, bin_true_fd);
                return 2;
            }
        };

        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("fatal: failed to build tokio runtime: {err}");
                close_probe_fds(memfd, bin_true_fd);
                return 1;
            }
        };

        let socket_path = cli.runtime_dir.join(SOCKET_FILE_NAME);

        if let Err(exit_code) = runtime.block_on(authenticate_and_observe_session(&cli)) {
            close_probe_fds(memfd, bin_true_fd);
            return exit_code;
        }

        println!("fail-closed-probe: authenticated and observed a real broker session");
        println!("fail-closed-probe: ready, waiting for the broker to be killed and cleaned up");
        let _ = std::io::stdout().flush();

        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(cli.death_timeout_secs);
        while socket_path.exists() {
            if std::time::Instant::now() >= deadline {
                eprintln!(
                    "fatal: broker socket {} still exists after {}s; the harness never killed \
                     the broker (or the supervisor never cleaned it up) within the deadline — \
                     refusing to silently skip the post-death probes",
                    socket_path.display(),
                    cli.death_timeout_secs
                );
                close_probe_fds(memfd, bin_true_fd);
                return 1;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        println!("fail-closed-probe: broker socket is gone; running post-death exec attempts");
        let _ = std::io::stdout().flush();

        // Identical primitives, and the identical trusted-bootstrap fds,
        // to `probe` mode's exec-family battery — see that function's
        // documentation for why the fds must have been created before
        // the filter was installed.
        emit("libc_execve_bin_true", attempt_libc_execve("/bin/true"));
        emit(
            "raw_syscall_execve_bin_true",
            attempt_raw_syscall_execve("/bin/true"),
        );
        let memfd_outcome = match memfd.as_ref() {
            Ok(fd) => attempt_libc_execveat_fd(*fd),
            Err(err) => ExecAttemptOutcome::SetupFailed {
                message: err.to_string(),
            },
        };
        emit("libc_execveat_memfd", memfd_outcome);
        let memfd_raw_outcome = match memfd.as_ref() {
            Ok(fd) => attempt_raw_syscall_execveat_fd(*fd),
            Err(err) => ExecAttemptOutcome::SetupFailed {
                message: err.to_string(),
            },
        };
        emit("raw_syscall_execveat_memfd", memfd_raw_outcome);
        let bin_true_outcome = match bin_true_fd.as_ref() {
            Ok(fd) => attempt_libc_execveat_fd(*fd),
            Err(err) => ExecAttemptOutcome::SetupFailed {
                message: err.to_string(),
            },
        };
        emit("libc_execveat_bin_true_fd", bin_true_outcome);
        let bin_true_raw_outcome = match bin_true_fd.as_ref() {
            Ok(fd) => attempt_raw_syscall_execveat_fd(*fd),
            Err(err) => ExecAttemptOutcome::SetupFailed {
                message: err.to_string(),
            },
        };
        emit("raw_syscall_execveat_bin_true_fd", bin_true_raw_outcome);

        close_probe_fds(memfd, bin_true_fd);
        0
    }

    /// Connects to the broker, authenticates, and sends one `Execute`
    /// request for the caller-provided allowlisted command, reading events until either a `Started`
    /// or a terminal `Completed`/`Rejected` is observed — any of which is
    /// sufficient proof that this process really did authenticate and
    /// exchange messages with a live broker session, which is all
    /// `run_fail_closed_probe` needs before it starts waiting for that
    /// broker to die. Returns `Err(exit_code)` on any setup/connection
    /// failure.
    async fn authenticate_and_observe_session(cli: &FailClosedProbeCli) -> Result<(), i32> {
        let expected_uid = nix::unistd::getuid().as_raw();

        let runtime_dir = RuntimeDir::open_existing(&cli.runtime_dir).map_err(|err| {
            eprintln!("fatal: runtime directory is not safe to use: {err}");
            1
        })?;

        let credentials = session::load_credentials_file(
            &runtime_dir.path().join(session::CREDENTIALS_FILE_NAME),
            expected_uid,
        )
        .map_err(|err| {
            eprintln!("fatal: failed to load session credentials: {err}");
            1
        })?;

        let std_stream =
            socket::connect(&runtime_dir.socket_path(), expected_uid).map_err(|err| {
                eprintln!("fatal: failed to connect to broker socket: {err}");
                1
            })?;
        std_stream.set_nonblocking(true).map_err(|err| {
            eprintln!("fatal: failed to set socket non-blocking: {err}");
            1
        })?;
        let stream = tokio::net::UnixStream::from_std(std_stream).map_err(|err| {
            eprintln!("fatal: failed to hand socket to async runtime: {err}");
            1
        })?;

        let (mut read_half, mut write_half) = stream.into_split();
        let execute = ClientMessage::Execute {
            correlation_id: generate_correlation_id(),
            session_id: credentials.session_id.clone(),
            token: credentials.token_hex.clone(),
            argv: cli.exec_argv.clone(),
            cwd: cli.cwd.to_string_lossy().into_owned(),
            env: BTreeMap::new(),
            timeout_ms: 5_000,
        };
        write_message(&mut write_half, &execute)
            .await
            .map_err(|err| {
                eprintln!("fatal: failed to send Execute request: {err}");
                1
            })?;
        drop(execute);

        loop {
            match read_message::<ServerEvent, _>(&mut read_half).await {
                Ok(Some(ServerEvent::Started { .. })) | Ok(Some(ServerEvent::Completed { .. })) => {
                    return Ok(());
                }
                Ok(Some(ServerEvent::Rejected { code, message, .. })) => {
                    eprintln!(
                        "fatal: the one-shot authentication Execute was rejected ({code:?}: \
                         {message}); this scenario requires a genuinely authenticated session"
                    );
                    return Err(1);
                }
                Ok(Some(_)) => continue,
                Ok(None) => {
                    eprintln!(
                        "fatal: broker closed the connection before authentication completed"
                    );
                    return Err(1);
                }
                Err(err) => {
                    eprintln!("fatal: failed to read server event during authentication: {err}");
                    return Err(1);
                }
            }
        }
    }

    /// A correlation id unique enough for one client invocation:
    /// process id plus a random suffix, so two concurrent
    /// `broker-client` invocations from the same or different processes
    /// cannot collide.
    fn generate_correlation_id() -> String {
        let mut random_bytes = [0u8; 8];
        let _ = getrandom::fill(&mut random_bytes);
        let mut suffix = String::with_capacity(random_bytes.len() * 2);
        for byte in random_bytes {
            suffix.push_str(&format!("{byte:02x}"));
        }
        format!("agent-client-{}-{suffix}", std::process::id())
    }
}
