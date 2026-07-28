//! Host terminal plumbing for `sendbox run --interactive`.
//!
//! Puts the controlling terminal into raw mode, forwards keystrokes and window
//! size changes to the sandboxed workload, and guarantees the terminal is
//! restored on every exit path the process can still observe.

use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use sendbox_agent::{
    AgentError, BoxFuture, GuestTerminalSize, HostTerminalCommand, TerminalSource,
};

/// Bound on queued host keystrokes. Deeper than a human types and deep enough
/// for a paste; beyond that the operator is better served by back pressure on
/// the reader than by unbounded memory growth.
const INPUT_QUEUE_DEPTH: usize = 256;

/// Largest keystroke batch read from the host terminal in one go.
const INPUT_CHUNK: usize = sendbox_core::TERMINAL_INPUT_CHUNK_BYTES;

/// How long the reader thread waits before retrying a full input queue. Short
/// enough that shutdown is prompt, long enough not to spin a core.
const OFFER_RETRY: std::time::Duration = std::time::Duration::from_millis(2);

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
        AgentError, Arc, AtomicBool, AtomicU16, BoxFuture, DEFAULT_TERM, GuestTerminalSize,
        HostTerminalCommand, INPUT_CHUNK, INPUT_QUEUE_DEPTH, MAX_TERM_LENGTH, OFFER_RETRY,
        Ordering, Read, TerminalError, TerminalSource, io,
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
    pub fn require_controlling_terminal(
        separate_stderr: bool,
    ) -> Result<GuestTerminalSize, TerminalError> {
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
            separate_stderr,
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
        credits: Arc<InputCreditGate>,
    }

    impl TerminalSource for CliTerminal {
        fn next_command<'a>(&'a self) -> BoxFuture<'a, Option<HostTerminalCommand>> {
            Box::pin(async move { self.commands.lock().await.recv().await })
        }

        fn grant_input_credit(&self, credits: u16) -> Result<(), AgentError> {
            self.credits.grant(credits)
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
        pub fn start(separate_stderr: bool) -> Result<(Self, GuestTerminalSize), TerminalError> {
            // Register for resizes before sampling the size, so a resize racing
            // startup is reported rather than lost.
            let mut winch =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                    .map_err(|error| {
                        TerminalError::Query(format!("watch terminal resizes: {error}"))
                    })?;
            let size = require_controlling_terminal(separate_stderr)?;
            let guard = Arc::new(RawModeGuard::enter()?);
            let (sender, receiver) = tokio::sync::mpsc::channel(INPUT_QUEUE_DEPTH);
            let (reader, credits) = StdinPump::start(sender.clone())?;
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
                        credits,
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
        credits: Arc<InputCreditGate>,
        stopping: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    struct InputCreditGate {
        available: AtomicU16,
        wake: OwnedFd,
    }

    impl InputCreditGate {
        fn grant(&self, credits: u16) -> Result<(), AgentError> {
            if credits == 0 {
                return Err(AgentError::TerminalInput(
                    "terminal input credit must be non-zero".to_owned(),
                ));
            }
            let mut current = self.available.load(Ordering::Acquire);
            loop {
                let next = current
                    .checked_add(credits)
                    .filter(|next| *next <= sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS)
                    .ok_or_else(|| {
                        AgentError::TerminalInput(
                            "terminal input credit exceeds the negotiated window".to_owned(),
                        )
                    })?;
                match self.available.compare_exchange_weak(
                    current,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        if current == 0 {
                            self.notify().map_err(|error| {
                                AgentError::TerminalInput(format!(
                                    "wake terminal input reader: {error}"
                                ))
                            })?;
                        }
                        return Ok(());
                    }
                    Err(observed) => current = observed,
                }
            }
        }

        fn available(&self) -> u16 {
            self.available.load(Ordering::Acquire)
        }

        fn consume(&self) -> bool {
            let mut current = self.available.load(Ordering::Acquire);
            loop {
                if current == 0 {
                    return false;
                }
                match self.available.compare_exchange_weak(
                    current,
                    current - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return true,
                    Err(observed) => current = observed,
                }
            }
        }

        fn notify(&self) -> io::Result<()> {
            rustix::io::write(&self.wake, b"\0")
                .map(|_| ())
                .map_err(io::Error::from)
        }
    }

    impl StdinPump {
        fn start(
            sender: tokio::sync::mpsc::Sender<HostTerminalCommand>,
        ) -> Result<(Self, Arc<InputCreditGate>), TerminalError> {
            let (wake_reader, wake_writer) = rustix::pipe::pipe()
                .map_err(|error| TerminalError::Query(format!("create wake pipe: {error}")))?;
            let credits = Arc::new(InputCreditGate {
                available: AtomicU16::new(0),
                wake: wake_writer,
            });
            let stopping = Arc::new(AtomicBool::new(false));
            let thread_stopping = Arc::clone(&stopping);
            let thread_credits = Arc::clone(&credits);
            let handle = std::thread::Builder::new()
                .name("sendbox-stdin".to_owned())
                .spawn(move || {
                    pump_stdin(&wake_reader, &sender, &thread_stopping, &thread_credits);
                })
                .map_err(|error| TerminalError::Query(format!("start stdin reader: {error}")))?;
            Ok((
                Self {
                    credits: Arc::clone(&credits),
                    stopping,
                    handle: Some(handle),
                },
                credits,
            ))
        }

        fn stop(mut self) {
            self.shutdown();
        }

        /// Raising the flag before waking is what makes the join below bounded:
        /// the reader may be parked in `poll` or waiting for room in the input
        /// queue, and nothing drains that queue once the run is tearing down.
        fn shutdown(&mut self) {
            self.stopping.store(true, Ordering::Release);
            let _ = self.credits.notify();
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

    /// Hands one command to the async side, giving up as soon as the session
    /// starts shutting down. Returns `false` when the reader should stop.
    fn offer(
        sender: &tokio::sync::mpsc::Sender<HostTerminalCommand>,
        stopping: &AtomicBool,
        command: HostTerminalCommand,
    ) -> bool {
        let mut pending = command;
        loop {
            if stopping.load(Ordering::Acquire) {
                return false;
            }
            match sender.try_send(pending) {
                Ok(()) => return true,
                Err(tokio::sync::mpsc::error::TrySendError::Full(returned)) => {
                    pending = returned;
                    std::thread::sleep(OFFER_RETRY);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
            }
        }
    }

    fn pump_stdin(
        wake: &OwnedFd,
        sender: &tokio::sync::mpsc::Sender<HostTerminalCommand>,
        stopping: &AtomicBool,
        credits: &InputCreditGate,
    ) {
        let stdin = io::stdin();
        let input = stdin_fd();
        let wake = wake.as_fd();
        let mut buffer = [0_u8; INPUT_CHUNK];
        loop {
            let has_credit = credits.available() > 0;
            let mut fds = vec![rustix::event::PollFd::new(
                &wake,
                rustix::event::PollFlags::IN,
            )];
            if has_credit {
                fds.push(rustix::event::PollFd::new(
                    &input,
                    rustix::event::PollFlags::IN,
                ));
            }
            match rustix::event::poll(&mut fds, None) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => {
                    eprintln!("sendbox run: waiting for terminal input failed: {error}");
                    return;
                }
            }
            if !fds[0].revents().is_empty() {
                let mut notification = [0_u8; 8];
                let _ = rustix::io::read(wake, &mut notification);
                if stopping.load(Ordering::Acquire) {
                    return;
                }
                continue;
            }
            if !has_credit || fds[1].revents().is_empty() {
                continue;
            }
            match stdin.lock().read(&mut buffer) {
                Ok(0) => {
                    offer(sender, stopping, HostTerminalCommand::InputEof);
                    return;
                }
                Ok(read) => {
                    if !credits.consume() {
                        eprintln!(
                            "sendbox run: terminal input became readable without launcher credit"
                        );
                        return;
                    }
                    if !offer(
                        sender,
                        stopping,
                        HostTerminalCommand::Input(buffer[..read].to_vec()),
                    ) {
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

    #[cfg(test)]
    mod tests {
        use super::{AtomicBool, AtomicU16, HostTerminalCommand, InputCreditGate, Ordering, offer};
        use std::sync::Arc;

        #[test]
        fn a_full_queue_never_pins_the_reader_past_shutdown() {
            // The receiver stops draining while the run tears down, so a reader
            // parked on a full queue would hang the join that restores the
            // terminal.
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            sender
                .try_send(HostTerminalCommand::Input(vec![b'a']))
                .expect("queue starts empty");
            let stopping = Arc::new(AtomicBool::new(false));
            let reader_stopping = Arc::clone(&stopping);
            let reader = std::thread::spawn(move || {
                offer(
                    &sender,
                    &reader_stopping,
                    HostTerminalCommand::Input(vec![b'b']),
                )
            });
            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(!reader.is_finished(), "offer returned before shutdown");
            stopping.store(true, Ordering::Release);
            assert!(
                !reader.join().expect("reader thread panicked"),
                "offer should report that the reader must stop"
            );
        }

        #[test]
        fn input_credit_gate_starts_closed_and_enforces_the_window() {
            let (_reader, writer) = rustix::pipe::pipe().expect("wake pipe");
            let gate = InputCreditGate {
                available: AtomicU16::new(0),
                wake: writer,
            };
            assert_eq!(gate.available(), 0);
            gate.grant(sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS)
                .expect("initial credit");
            assert_eq!(
                gate.available(),
                sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS
            );
            assert!(gate.grant(1).is_err(), "overgrant must fail");
            for _ in 0..sendbox_core::TERMINAL_INPUT_WINDOW_CREDITS {
                assert!(gate.consume());
            }
            assert!(!gate.consume(), "zero-credit input must be refused");
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::{Arc, GuestTerminalSize, TerminalError, TerminalSource};

    pub struct TerminalSession;

    impl TerminalSession {
        pub fn start(_separate_stderr: bool) -> Result<(Self, GuestTerminalSize), TerminalError> {
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
