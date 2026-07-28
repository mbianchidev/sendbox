//! Host terminal plumbing for `sendbox run --interactive`.
//!
//! Puts the controlling terminal into raw mode, forwards keystrokes and window
//! size changes to the sandboxed workload, and guarantees the terminal is
//! restored on every exit path the process can still observe.

use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sendbox_agent::{BoxFuture, GuestTerminalSize, HostTerminalCommand, TerminalSource};

/// Bound on queued host keystrokes. Deeper than a human types and deep enough
/// for a paste; beyond that the operator is better served by back pressure on
/// the reader than by unbounded memory growth.
const INPUT_QUEUE_DEPTH: usize = 256;

/// Largest keystroke batch read from the host terminal in one go.
const INPUT_CHUNK: usize = 4096;

/// Default terminal type when the host environment does not set `TERM`.
const DEFAULT_TERM: &str = "xterm-256color";

/// Longest accepted `TERM` value; terminfo names are far shorter.
const MAX_TERM_LENGTH: usize = 64;

#[derive(Debug)]
pub enum TerminalError {
    NotATerminal(&'static str),
    NotForeground,
    Query(String),
    RawMode(String),
    Term(String),
}

impl std::fmt::Display for TerminalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotATerminal(stream) => write!(
                formatter,
                "--interactive requires a terminal but {stream} is not one; \
                 drop --interactive to run without a terminal"
            ),
            Self::NotForeground => formatter.write_str(
                "--interactive requires the foreground process group of the terminal; \
                 run sendbox in the foreground instead of with & or under a job-control shell",
            ),
            Self::Query(message) => write!(formatter, "read terminal state: {message}"),
            Self::RawMode(message) => write!(formatter, "enter raw terminal mode: {message}"),
            Self::Term(message) => write!(formatter, "invalid TERM: {message}"),
        }
    }
}

impl std::error::Error for TerminalError {}

#[cfg(unix)]
mod imp {
    use super::{
        Arc, AtomicBool, BoxFuture, DEFAULT_TERM, GuestTerminalSize, HostTerminalCommand,
        INPUT_CHUNK, INPUT_QUEUE_DEPTH, MAX_TERM_LENGTH, Ordering, Read, TerminalError,
        TerminalSource, io,
    };
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

    use rustix::termios::{OptionalActions, Termios};

    fn stdin_fd() -> BorrowedFd<'static> {
        rustix::stdio::stdin()
    }

    fn stdout_fd() -> BorrowedFd<'static> {
        rustix::stdio::stdout()
    }

    /// Restores the terminal attributes captured before raw mode was entered.
    ///
    /// Restoration is idempotent so the caller can restore explicitly before
    /// printing a diagnostic and still rely on `Drop` for panic paths.
    pub struct RawModeGuard {
        original: Termios,
        restored: AtomicBool,
    }

    impl RawModeGuard {
        pub fn enter() -> Result<Self, TerminalError> {
            let original = rustix::termios::tcgetattr(stdin_fd())
                .map_err(|error| TerminalError::Query(error.to_string()))?;
            let mut raw = original.clone();
            raw.make_raw();
            // `Now` rather than `Flush`: bytes already typed ahead belong to the
            // workload, not to the terminal driver's discard pile.
            rustix::termios::tcsetattr(stdin_fd(), OptionalActions::Now, &raw)
                .map_err(|error| TerminalError::RawMode(error.to_string()))?;
            Ok(Self {
                original,
                restored: AtomicBool::new(false),
            })
        }

        pub fn restore(&self) {
            if self.restored.swap(true, Ordering::SeqCst) {
                return;
            }
            if let Err(error) =
                rustix::termios::tcsetattr(stdin_fd(), OptionalActions::Now, &self.original)
            {
                eprintln!("sendbox run: restoring terminal mode failed: {error}");
            }
        }
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            self.restore();
        }
    }

    /// Confirms the process owns the terminal and reports its current size.
    pub fn require_controlling_terminal() -> Result<GuestTerminalSize, TerminalError> {
        if !rustix::termios::isatty(stdin_fd()) {
            return Err(TerminalError::NotATerminal("stdin"));
        }
        if !rustix::termios::isatty(stdout_fd()) {
            return Err(TerminalError::NotATerminal("stdout"));
        }
        let foreground = rustix::termios::tcgetpgrp(stdin_fd())
            .map_err(|error| TerminalError::Query(error.to_string()))?;
        if foreground != rustix::process::getpgrp() {
            return Err(TerminalError::NotForeground);
        }
        let size = window_size()?.ok_or_else(|| {
            TerminalError::Query("terminal reported a zero-sized window".to_owned())
        })?;
        Ok(GuestTerminalSize {
            columns: size.0,
            rows: size.1,
            term: host_term()?,
        })
    }

    /// Reads the current window size, treating a zero dimension as "unknown"
    /// rather than an error: terminals transiently report zeros while resizing.
    fn window_size() -> Result<Option<(u16, u16)>, TerminalError> {
        let size = rustix::termios::tcgetwinsize(stdout_fd())
            .map_err(|error| TerminalError::Query(error.to_string()))?;
        if size.ws_col == 0 || size.ws_row == 0 {
            return Ok(None);
        }
        Ok(Some((size.ws_col, size.ws_row)))
    }

    fn host_term() -> Result<String, TerminalError> {
        let term = std::env::var("TERM").unwrap_or_else(|_| DEFAULT_TERM.to_owned());
        if term.is_empty() {
            return Ok(DEFAULT_TERM.to_owned());
        }
        if term.len() > MAX_TERM_LENGTH {
            return Err(TerminalError::Term(format!(
                "TERM is longer than {MAX_TERM_LENGTH} bytes"
            )));
        }
        if !term
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
        {
            return Err(TerminalError::Term(
                "TERM may only contain ASCII letters, digits and -_.+".to_owned(),
            ));
        }
        Ok(term)
    }

    /// Host keystroke and resize stream handed to the agent orchestrator.
    pub struct CliTerminal {
        commands: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<HostTerminalCommand>>,
    }

    impl TerminalSource for CliTerminal {
        fn next_command<'a>(&'a self) -> BoxFuture<'a, Option<HostTerminalCommand>> {
            Box::pin(async move { self.commands.lock().await.recv().await })
        }
    }

    /// Owns the terminal-facing tasks for one interactive run.
    pub struct TerminalSession {
        guard: Arc<RawModeGuard>,
        source: Arc<CliTerminal>,
        reader: Option<StdinPump>,
        resizes: tokio::task::JoinHandle<()>,
    }

    impl TerminalSession {
        pub fn start() -> Result<(Self, GuestTerminalSize), TerminalError> {
            // Register for resizes before sampling the size, so a resize racing
            // startup is reported rather than lost.
            let mut winch =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                    .map_err(|error| {
                        TerminalError::Query(format!("watch terminal resizes: {error}"))
                    })?;
            let size = require_controlling_terminal()?;
            let guard = Arc::new(RawModeGuard::enter()?);
            let (sender, receiver) = tokio::sync::mpsc::channel(INPUT_QUEUE_DEPTH);
            let reader = StdinPump::start(sender.clone())?;
            let resizes = tokio::spawn(async move {
                while winch.recv().await.is_some() {
                    match window_size() {
                        Ok(Some((columns, rows))) => {
                            if sender
                                .send(HostTerminalCommand::Resize { columns, rows })
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            eprintln!("sendbox run: reading terminal size failed: {error}");
                            return;
                        }
                    }
                }
            });
            Ok((
                Self {
                    guard,
                    source: Arc::new(CliTerminal {
                        commands: tokio::sync::Mutex::new(receiver),
                    }),
                    reader: Some(reader),
                    resizes,
                },
                size,
            ))
        }

        #[must_use]
        pub fn source(&self) -> Arc<dyn TerminalSource> {
            Arc::clone(&self.source) as Arc<dyn TerminalSource>
        }

        /// Stops the terminal tasks and puts the terminal back into the mode it
        /// was in before the run. Joining the reader first guarantees it cannot
        /// steal a keystroke from the shell that resumes after `sendbox` exits.
        pub fn finish(mut self) {
            self.resizes.abort();
            if let Some(reader) = self.reader.take() {
                reader.stop();
            }
            self.guard.restore();
        }
    }

    impl Drop for TerminalSession {
        fn drop(&mut self) {
            self.resizes.abort();
            if let Some(reader) = self.reader.take() {
                reader.stop();
            }
            self.guard.restore();
        }
    }

    /// Blocking stdin reader that can be woken and joined.
    ///
    /// `poll` waits on the terminal and on a self-pipe so shutting down never
    /// depends on the operator pressing another key.
    struct StdinPump {
        wake: OwnedFd,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl StdinPump {
        fn start(
            sender: tokio::sync::mpsc::Sender<HostTerminalCommand>,
        ) -> Result<Self, TerminalError> {
            let (wake_reader, wake_writer) = rustix::pipe::pipe()
                .map_err(|error| TerminalError::Query(format!("create wake pipe: {error}")))?;
            let handle = std::thread::Builder::new()
                .name("sendbox-stdin".to_owned())
                .spawn(move || pump_stdin(&wake_reader, &sender))
                .map_err(|error| TerminalError::Query(format!("start stdin reader: {error}")))?;
            Ok(Self {
                wake: wake_writer,
                handle: Some(handle),
            })
        }

        fn stop(mut self) {
            self.shutdown();
        }

        fn shutdown(&mut self) {
            let _ = rustix::io::write(&self.wake, b"\0");
            if let Some(handle) = self.handle.take()
                && handle.join().is_err()
            {
                eprintln!("sendbox run: the terminal input reader panicked");
            }
        }
    }

    impl Drop for StdinPump {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    fn pump_stdin(wake: &OwnedFd, sender: &tokio::sync::mpsc::Sender<HostTerminalCommand>) {
        let stdin = io::stdin();
        let input = stdin_fd();
        let wake = wake.as_fd();
        let mut buffer = [0_u8; INPUT_CHUNK];
        loop {
            let mut fds = [
                rustix::event::PollFd::new(&input, rustix::event::PollFlags::IN),
                rustix::event::PollFd::new(&wake, rustix::event::PollFlags::IN),
            ];
            match rustix::event::poll(&mut fds, None) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => {
                    eprintln!("sendbox run: waiting for terminal input failed: {error}");
                    return;
                }
            }
            if !fds[1].revents().is_empty() {
                return;
            }
            if fds[0].revents().is_empty() {
                continue;
            }
            match stdin.lock().read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.blocking_send(HostTerminalCommand::InputEof);
                    return;
                }
                Ok(read) => {
                    if sender
                        .blocking_send(HostTerminalCommand::Input(buffer[..read].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    eprintln!("sendbox run: reading terminal input failed: {error}");
                    return;
                }
            }
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::{Arc, GuestTerminalSize, TerminalError, TerminalSource};

    pub struct TerminalSession;

    impl TerminalSession {
        pub fn start() -> Result<(Self, GuestTerminalSize), TerminalError> {
            Err(TerminalError::NotATerminal("this platform"))
        }

        #[must_use]
        pub fn source(&self) -> Arc<dyn TerminalSource> {
            unreachable!("interactive sessions are unavailable on this platform")
        }

        pub fn finish(self) {}
    }
}

pub use imp::TerminalSession;

#[cfg(test)]
mod tests {
    use super::TerminalError;

    #[test]
    fn errors_name_the_offending_stream_and_the_way_out() {
        let message = TerminalError::NotATerminal("stdin").to_string();
        assert!(message.contains("stdin"), "unexpected message: {message}");
        assert!(
            message.contains("drop --interactive"),
            "unexpected message: {message}"
        );
    }

    #[test]
    fn foreground_error_explains_job_control() {
        let message = TerminalError::NotForeground.to_string();
        assert!(
            message.contains("foreground process group"),
            "unexpected message: {message}"
        );
    }
}
