//! `exec-broker-test-helper`: an ELF test-fixture binary that exists only
//! to prove descendant-containment properties of a launched process, from
//! *inside* a real launched process — never invoked by anything other
//! than this crate's own test suite, and never allowlisted by a
//! production broker configuration.
//!
//! This binary is ordinary, safe Rust (`unsafe_code = "deny"` from the
//! workspace `Cargo.toml` applies here exactly as it does to every other
//! binary in this crate); every raw syscall probe it performs is
//! delegated to [`exec_broker_spike::platform::linux::adapter`], the sole
//! isolated home for this crate's `unsafe` code, never reimplemented here.
//!
//! # Modes
//!
//! * `flood` — concurrently writes a large, deterministic, distinguishable
//!   byte stream to both stdout and stderr, to prove a broker/launcher
//!   draining both streams cannot deadlock and that both are
//!   bounded/truncated rather than allowed to grow unbounded.
//! * `highrisk` — attempts `setsid`, `setpgid`, `memfd_create`,
//!   `ptrace(PTRACE_TRACEME)`, and the raw `io_uring_setup` syscall (a
//!   representative sample of the high-risk primitives this crate's
//!   seccomp profiles deny), printing one typed JSON result per attempt.
//! * `recurse` — recursively spawns copies of itself (one child per
//!   level, always waited-for before the parent exits) until process
//!   creation itself fails (the expected outcome once `RLIMIT_NPROC` is
//!   hit) or a strict depth/wall-clock bound is reached first (the
//!   fallback outcome when the limit cannot be observed within the
//!   bounds, e.g. running as `root` in an environment where `RLIMIT_NPROC`
//!   is not enforced) — never actually unbounded, and every level fully
//!   waits for (and thus reaps) its own child before exiting, so no
//!   descendant is ever left behind regardless of which way the
//!   recursion terminates.
//! * `longlived` — prints a single readiness line and then sleeps
//!   indefinitely, for tests that need a long-lived descendant to
//!   observe/kill from outside (e.g. the supervisor-crash-cleanup test).
//!
//! On any non-Linux target, `main` immediately prints the "unsupported
//! platform" error and exits non-zero, matching every other binary in
//! this crate.

#[cfg(not(target_os = "linux"))]
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
    use clap::{Parser, Subcommand};
    use exec_broker_spike::platform::linux::adapter::{
        SyscallAttemptOutcome, attempt_memfd_create, attempt_ptrace_traceme,
        attempt_raw_io_uring_setup, attempt_setpgid, attempt_setsid,
    };
    use serde::Serialize;
    use std::io::Write;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[derive(Parser, Debug)]
    #[command(name = "exec-broker-test-helper")]
    struct Cli {
        #[command(subcommand)]
        mode: Mode,
    }

    #[derive(Subcommand, Debug)]
    enum Mode {
        /// Concurrently flood stdout and stderr with a large, bounded
        /// amount of distinguishable data.
        Flood {
            /// Bytes to write to *each* stream (default: 4 MiB, well
            /// above this crate's default 1 MiB per-stream cap, so
            /// truncation is actually exercised).
            #[arg(long, default_value_t = 4 * 1024 * 1024)]
            bytes: usize,
        },
        /// Attempt a representative battery of high-risk syscalls and
        /// report typed, structured results, one JSON line each.
        Highrisk,
        /// Recursively self-spawn until process creation fails or a
        /// strict depth/time bound is hit.
        Recurse {
            /// Current recursion depth (internal; always `0` when a human
            /// or test harness invokes this directly).
            #[arg(long, default_value_t = 0)]
            depth: u32,
            /// Hard depth ceiling, independent of any observed failure,
            /// so a misconfigured/unenforced environment (e.g. `RLIMIT_NPROC`
            /// not applying to `root`) can never cause unbounded recursion.
            #[arg(long, default_value_t = 100_000)]
            max_depth: u32,
            /// Absolute deadline (Unix milliseconds) shared by every
            /// level of the recursion. Computed once by the depth-`0`
            /// invocation and threaded through every subsequent level's
            /// argv, so the *overall* recursion has a fixed wall-clock
            /// budget regardless of depth.
            #[arg(long)]
            deadline_unix_ms: Option<u64>,
            /// Wall-clock budget, in seconds, used only by the depth-`0`
            /// invocation to compute `deadline_unix_ms`.
            #[arg(long, default_value_t = 20)]
            time_budget_secs: u64,
        },
        /// Print a readiness line, then sleep indefinitely.
        Longlived,
        /// Drop this process's own uid to `uid` via `setuid` (requires
        /// starting as root, or `CAP_SETUID`), then connect to
        /// `socket_path` and prove whether the connection is honored or
        /// dropped: used by the unauthorized-peer-UID live test
        /// (`tests/raw_frame_boundary.rs`) to actually exercise a real
        /// second UID connecting to the broker's `SO_PEERCRED`-gated
        /// socket, from a genuinely separate process rather than a raw
        /// (and, in this crate, forbidden-by-lint) in-test `fork()`.
        /// `setuid`/`connect`/socket I/O are all ordinary safe Rust —
        /// this mode performs no seccomp-relevant syscall probing and so
        /// has no need of the isolated adapter module.
        ConnectAsUid {
            #[arg(long)]
            uid: u32,
            #[arg(long)]
            socket_path: std::path::PathBuf,
        },
    }

    pub fn run() {
        let cli = Cli::parse();
        match cli.mode {
            Mode::Flood { bytes } => run_flood(bytes),
            Mode::Highrisk => run_highrisk(),
            Mode::Recurse {
                depth,
                max_depth,
                deadline_unix_ms,
                time_budget_secs,
            } => run_recurse(depth, max_depth, deadline_unix_ms, time_budget_secs),
            Mode::Longlived => run_longlived(),
            Mode::ConnectAsUid { uid, socket_path } => run_connect_as_uid(uid, &socket_path),
        }
    }

    /// Writes `bytes` distinguishable bytes to stdout and, concurrently
    /// (on a second thread), `bytes` distinguishable bytes to stderr, in
    /// fixed-size chunks. If either stream's writer returns an error
    /// (e.g. `BrokenPipe`, should whatever is reading it close early),
    /// that thread simply stops writing rather than panicking — a flood
    /// probe proving the *reader* side never deadlocks must not itself
    /// crash just because the reader stopped reading.
    fn run_flood(bytes: usize) {
        const CHUNK: usize = 64 * 1024;
        let stdout_chunk = vec![b'O'; CHUNK];
        let stderr_chunk = vec![b'E'; CHUNK];

        let stderr_thread = std::thread::spawn(move || {
            let mut written = 0usize;
            let mut stderr = std::io::stderr();
            while written < bytes {
                let take = CHUNK.min(bytes - written);
                if stderr.write_all(&stderr_chunk[..take]).is_err() {
                    break;
                }
                written += take;
            }
            let _ = stderr.flush();
        });

        let mut written = 0usize;
        let mut stdout = std::io::stdout();
        while written < bytes {
            let take = CHUNK.min(bytes - written);
            if stdout.write_all(&stdout_chunk[..take]).is_err() {
                break;
            }
            written += take;
        }
        let _ = stdout.flush();

        let _ = stderr_thread.join();
    }

    #[derive(Serialize)]
    struct HighRiskResult {
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

    impl From<SyscallAttemptOutcome> for OutcomeJson {
        fn from(outcome: SyscallAttemptOutcome) -> Self {
            match outcome {
                SyscallAttemptOutcome::Denied { errno } => OutcomeJson::Denied { errno },
                SyscallAttemptOutcome::UnexpectedSuccess => OutcomeJson::UnexpectedSuccess,
                SyscallAttemptOutcome::SetupFailed { message } => {
                    OutcomeJson::SetupFailed { message }
                }
            }
        }
    }

    fn emit(name: &'static str, outcome: SyscallAttemptOutcome) {
        let result = HighRiskResult {
            name,
            outcome: outcome.into(),
        };
        let line = serde_json::to_string(&result).unwrap_or_else(|e| {
            format!(
                "{{\"name\":\"{name}\",\"outcome\":{{\"kind\":\"SetupFailed\",\"message\":\"failed to encode result: {e}\"}}}}"
            )
        });
        println!("{line}");
        let _ = std::io::stdout().flush();
    }

    /// Runs every high-risk syscall attempt and prints one JSON line each.
    /// Every attempt is expected to end in `Denied` when this process is a
    /// launched descendant under this crate's `Launcher` seccomp profile
    /// (or, for `memfd_create`/the always-denied syscalls, under any of
    /// this crate's profiles); `UnexpectedSuccess` here is a containment
    /// failure, not a probe-only artifact, since this mode's whole purpose
    /// is to run *inside* a real launched descendant.
    fn run_highrisk() {
        emit("setsid", attempt_setsid());
        emit("setpgid", attempt_setpgid());
        emit(
            "memfd_create",
            attempt_memfd_create("exec-broker-test-helper-highrisk"),
        );
        emit("ptrace_traceme", attempt_ptrace_traceme());
        emit("raw_io_uring_setup", attempt_raw_io_uring_setup());
    }

    #[derive(Serialize)]
    #[serde(tag = "stopped_reason")]
    enum RecurseResult {
        /// Process creation itself failed — the expected, desired outcome
        /// once `RLIMIT_NPROC` (or another process-creation limit) is
        /// actually enforced.
        ForkFailed { depth: u32, message: String },
        /// The depth ceiling was reached without ever observing a
        /// process-creation failure. In an environment where the
        /// process-creation limit is genuinely not enforced for the
        /// calling uid (e.g. `root` in many container configurations),
        /// this is an expected, typed "environment limitation" result,
        /// not a crash — callers (the integration test) are responsible
        /// for deciding whether this is acceptable for the uid under
        /// test.
        DepthBoundReached { depth: u32 },
        /// The wall-clock deadline was reached without ever observing a
        /// process-creation failure. Same rationale as
        /// `DepthBoundReached`.
        TimeBoundReached { depth: u32 },
    }

    fn run_recurse(
        depth: u32,
        max_depth: u32,
        deadline_unix_ms: Option<u64>,
        time_budget_secs: u64,
    ) {
        let deadline_unix_ms = deadline_unix_ms
            .unwrap_or_else(|| now_unix_ms().saturating_add(time_budget_secs.saturating_mul(1000)));

        if depth >= max_depth {
            print_recurse_result(&RecurseResult::DepthBoundReached { depth });
            return;
        }
        if now_unix_ms() >= deadline_unix_ms {
            print_recurse_result(&RecurseResult::TimeBoundReached { depth });
            return;
        }

        let current_exe = match std::env::current_exe() {
            Ok(path) => path,
            Err(err) => {
                print_recurse_result(&RecurseResult::ForkFailed {
                    depth,
                    message: format!("current_exe failed: {err}"),
                });
                return;
            }
        };

        let spawn_result = std::process::Command::new(current_exe)
            .arg("recurse")
            .arg(format!("--depth={}", depth + 1))
            .arg(format!("--max-depth={max_depth}"))
            .arg(format!("--deadline-unix-ms={deadline_unix_ms}"))
            .spawn();

        match spawn_result {
            Ok(mut child) => {
                // Always wait for (and thus reap) the child before this
                // level exits, regardless of how deep the recursion goes
                // or how it eventually terminates: this is what guarantees
                // no descendant is ever left behind by this mode.
                let _ = child.wait();
            }
            Err(err) => {
                let errno = err.raw_os_error().unwrap_or_default();
                print_recurse_result(&RecurseResult::ForkFailed {
                    depth,
                    message: format!("spawn failed (errno={errno}): {err}"),
                });
            }
        }
    }

    fn print_recurse_result(result: &RecurseResult) {
        let line = serde_json::to_string(result).unwrap_or_else(|e| {
            format!("{{\"stopped_reason\":\"SerializeFailed\",\"error\":\"{e}\"}}")
        });
        println!("{line}");
        let _ = std::io::stdout().flush();
    }

    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Prints one readiness line, then sleeps indefinitely (in bounded
    /// chunks, so a `SIGTERM`/`SIGKILL` sent from outside this process at
    /// any point takes effect promptly rather than only between long sleep
    /// calls). Exists purely to give supervisor/broker-crash tests and
    /// descendant-containment tests a genuinely long-lived descendant to
    /// observe, signal, and confirm the eventual absence of.
    fn run_longlived() {
        println!(
            "exec-broker-test-helper: longlived ready pid={}",
            std::process::id()
        );
        let _ = std::io::stdout().flush();
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    /// Drops to `uid`, connects to `socket_path`, writes a harmless
    /// (all-zero, deliberately-never-a-valid-length-prefix-of-anything-
    /// meaningful) probe frame, then attempts to read a reply within a
    /// bounded timeout.
    ///
    /// Exit code `0` means the connection was **rejected**: the read
    /// observed a clean EOF (0 bytes) or any I/O error, proving the
    /// broker dropped this peer's connection at (or immediately after)
    /// `accept()` without ever spawning a `handle_connection` task for
    /// it. Exit code `1` means the connection was **not** rejected
    /// (bytes were read back, or the read never resolved within the
    /// timeout) — a containment failure this mode exists to catch.
    /// Exit code `2` means a setup step itself failed unexpectedly
    /// (`setuid`, `connect`), which is reported distinctly on stderr so a
    /// test can tell "the probe ran and proved rejection" apart from
    /// "the probe could not even run".
    fn run_connect_as_uid(uid: u32, socket_path: &std::path::Path) {
        if let Err(err) = nix::unistd::setuid(nix::unistd::Uid::from_raw(uid)) {
            eprintln!("exec-broker-test-helper: setuid({uid}) failed: {err}");
            std::process::exit(2);
        }
        let mut stream = match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(stream) => stream,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                // The broker's socket file is `0600`, owned by the
                // broker's own uid: a different uid cannot even open(2)
                // it, independent of (and before ever reaching) the
                // application-level `SO_PEERCRED` check performed once a
                // connection is accepted. This is itself a valid, load-
                // bearing proof that a cross-UID peer is rejected — a
                // defense-in-depth layer *in front of* `SO_PEERCRED`,
                // not a replacement for it (a socket with looser
                // filesystem permissions, or a different-uid peer in the
                // same group with read/write on the socket inode, would
                // still need `SO_PEERCRED` to catch it).
                println!(
                    "exec-broker-test-helper: connect-as-uid rejected \
                     (permission denied opening the socket file)"
                );
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!(
                    "exec-broker-test-helper: connect to {} failed: {err}",
                    socket_path.display()
                );
                std::process::exit(2);
            }
        };
        if let Err(err) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
            eprintln!("exec-broker-test-helper: set_read_timeout failed: {err}");
            std::process::exit(2);
        }
        // Best-effort: the broker may already have dropped its end
        // before this write is attempted, in which case a `BrokenPipe`
        // here is itself further evidence of rejection, not a setup
        // failure.
        let _ = stream.write_all(&0u32.to_be_bytes());

        let mut buf = [0u8; 16];
        match std::io::Read::read(&mut stream, &mut buf) {
            Ok(0) => {
                println!("exec-broker-test-helper: connect-as-uid rejected (eof)");
                std::process::exit(0);
            }
            Ok(n) => {
                eprintln!(
                    "exec-broker-test-helper: connect-as-uid unexpectedly read {n} reply byte(s)"
                );
                std::process::exit(1);
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                eprintln!(
                    "exec-broker-test-helper: connect-as-uid saw neither EOF nor a reply \
                     within the timeout; inconclusive, treated as NOT proving rejection"
                );
                std::process::exit(1);
            }
            Err(err) => {
                // Any other I/O error (e.g. `ConnectionReset`) is itself
                // further evidence the broker tore the connection down.
                println!("exec-broker-test-helper: connect-as-uid rejected (io error: {err})");
                std::process::exit(0);
            }
        }
    }
}
