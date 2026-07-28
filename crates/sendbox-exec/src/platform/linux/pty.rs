//! Safe pseudoterminal allocation for interactive workloads.
//!
//! Every operation here goes through `rustix`, so the crate's audited unsafe
//! surface stays confined to [`super::raw`]. The pair is always allocated in
//! the launcher *before* the seccomp filter is installed and before `clone3`,
//! so the child only has to perform async-signal-safe `setsid`/`ioctl`/`dup2`.

#![forbid(unsafe_code)]

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};
use rustix::termios::{SpecialCodeIndex, Winsize, tcgetattr, tcsetwinsize};

use crate::api::ExecutionUser;
use crate::error::PlatformError;

/// Fallback end-of-transmission byte used when the secondary terminal reports
/// a disabled `VEOF`. Matches the kernel default (`Ctrl-D`).
const DEFAULT_VEOF: u8 = 0x04;

/// An allocated pseudoterminal pair.
///
/// The primary stays in the launcher and is pumped as merged workload output;
/// the secondary is handed to the child as its controlling terminal and is
/// closed in the launcher immediately after `clone3` returns.
#[derive(Debug)]
pub(crate) struct PseudoTerminal {
    primary: OwnedFd,
    secondary: Option<OwnedFd>,
}

impl PseudoTerminal {
    /// Allocates a pair sized to `columns` x `rows`.
    ///
    /// Both dimensions must be non-zero: a zero winsize is what an unset
    /// terminal looks like, and forwarding it would leave full-screen agents
    /// rendering into a degenerate viewport instead of failing loudly.
    pub(crate) fn open(columns: u16, rows: u16) -> Result<Self, PlatformError> {
        if columns == 0 || rows == 0 {
            return Err(PlatformError::io(
                "allocate pseudoterminal",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "terminal dimensions must be non-zero",
                ),
            ));
        }
        let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let primary =
            openpt(flags).map_err(|error| pty_error("open pseudoterminal primary", error))?;
        // A no-op on Linux devpts, but keeps the sequence correct if this ever
        // runs against a legacy pty implementation.
        grantpt(&primary).map_err(|error| pty_error("grant pseudoterminal secondary", error))?;
        unlockpt(&primary).map_err(|error| pty_error("unlock pseudoterminal secondary", error))?;
        // TIOCGPTPEER avoids the ptsname()-then-open() race, where the resolved
        // path could be replaced between resolution and open.
        let secondary = ioctl_tiocgptpeer(&primary, flags)
            .map_err(|error| pty_error("open pseudoterminal secondary", error))?;
        let terminal = Self {
            primary,
            secondary: Some(secondary),
        };
        terminal.resize(columns, rows)?;
        Ok(terminal)
    }

    /// Applies a new window size, which makes the kernel deliver `SIGWINCH` to
    /// the workload's foreground process group.
    pub(crate) fn resize(&self, columns: u16, rows: u16) -> Result<(), PlatformError> {
        if columns == 0 || rows == 0 {
            return Err(PlatformError::io(
                "resize pseudoterminal",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "terminal dimensions must be non-zero",
                ),
            ));
        }
        let winsize = Winsize {
            ws_row: rows,
            ws_col: columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        tcsetwinsize(&self.primary, winsize)
            .map_err(|error| pty_error("resize pseudoterminal", error))
    }

    /// Returns the terminal's *configured* end-of-file byte.
    ///
    /// The workload may have reprogrammed `VEOF`, so a hardcoded `0x04` would
    /// be delivered as ordinary input instead of ending the read.
    pub(crate) fn end_of_file_byte(&self) -> Result<u8, PlatformError> {
        let termios = tcgetattr(&self.primary)
            .map_err(|error| pty_error("read pseudoterminal attributes", error))?;
        let configured = termios.special_codes[SpecialCodeIndex::VEOF];
        Ok(if configured == 0 {
            DEFAULT_VEOF
        } else {
            configured
        })
    }

    /// Transfers ownership of the secondary to a workload running as another
    /// user, so it can still open and reconfigure its own terminal.
    pub(crate) fn transfer_secondary_to(&self, user: ExecutionUser) -> Result<(), PlatformError> {
        let secondary = self.secondary_fd()?;
        rustix::fs::fchown(
            secondary,
            Some(rustix::fs::Uid::from_raw(user.uid)),
            Some(rustix::fs::Gid::from_raw(user.gid)),
        )
        .map_err(|error| pty_error("assign pseudoterminal secondary owner", error))
    }

    /// Detaches the primary so it can be moved into an output pump thread.
    pub(crate) fn primary(&self) -> &OwnedFd {
        &self.primary
    }

    /// Raw secondary descriptor for the post-`clone3` child branch.
    pub(crate) fn secondary_raw_fd(&self) -> Result<RawFd, PlatformError> {
        Ok(self.secondary_fd()?.as_raw_fd())
    }

    /// Closes the launcher's copy of the secondary.
    ///
    /// This must happen right after `clone3`, otherwise the primary never
    /// reports EOF when the workload exits because the launcher still holds a
    /// writer open.
    pub(crate) fn release_secondary(&mut self) {
        self.secondary = None;
    }

    fn secondary_fd(&self) -> Result<&OwnedFd, PlatformError> {
        self.secondary.as_ref().ok_or_else(|| {
            PlatformError::io(
                "use pseudoterminal secondary",
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "pseudoterminal secondary was already released",
                ),
            )
        })
    }
}

impl AsFd for PseudoTerminal {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.primary.as_fd()
    }
}

fn pty_error(operation: &'static str, error: rustix::io::Errno) -> PlatformError {
    PlatformError::io(
        operation,
        io::Error::from_raw_os_error(error.raw_os_error()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn allocates_a_pair_with_the_requested_size() {
        let terminal = PseudoTerminal::open(120, 40).expect("allocate pty");
        let size = rustix::termios::tcgetwinsize(terminal.primary()).expect("read size");
        assert_eq!(size.ws_col, 120);
        assert_eq!(size.ws_row, 40);
    }

    #[test]
    fn rejects_zero_dimensions() {
        for (columns, rows) in [(0_u16, 24_u16), (80, 0), (0, 0)] {
            let error = PseudoTerminal::open(columns, rows).expect_err("zero size must fail");
            assert!(
                error.to_string().contains("non-zero"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn resize_updates_the_window_size() {
        let terminal = PseudoTerminal::open(80, 24).expect("allocate pty");
        terminal.resize(132, 50).expect("resize");
        let size = rustix::termios::tcgetwinsize(terminal.primary()).expect("read size");
        assert_eq!((size.ws_col, size.ws_row), (132, 50));
        let error = terminal.resize(0, 10).expect_err("zero resize must fail");
        assert!(error.to_string().contains("non-zero"));
    }

    #[test]
    fn reports_the_configured_end_of_file_byte() {
        let terminal = PseudoTerminal::open(80, 24).expect("allocate pty");
        assert_eq!(
            terminal.end_of_file_byte().expect("read VEOF"),
            DEFAULT_VEOF
        );
    }

    #[test]
    fn secondary_is_unavailable_after_release() {
        let mut terminal = PseudoTerminal::open(80, 24).expect("allocate pty");
        terminal.secondary_raw_fd().expect("secondary is live");
        terminal.release_secondary();
        let error = terminal
            .secondary_raw_fd()
            .expect_err("released secondary must fail");
        assert!(error.to_string().contains("already released"));
    }

    #[test]
    fn bytes_written_to_the_secondary_surface_on_the_primary() {
        let terminal = PseudoTerminal::open(80, 24).expect("allocate pty");
        let secondary = terminal.secondary_fd().expect("secondary").try_clone();
        let mut writer = std::fs::File::from(secondary.expect("clone secondary"));
        writer.write_all(b"hi\n").expect("write");
        writer.flush().expect("flush");
        let primary = terminal
            .primary()
            .try_clone()
            .map(std::fs::File::from)
            .expect("clone primary");
        let mut reader = primary;
        let mut buffer = [0u8; 16];
        let length = reader.read(&mut buffer).expect("read");
        // The line discipline echoes CR for LF on the primary side.
        assert!(
            buffer[..length].starts_with(b"hi"),
            "{:?}",
            &buffer[..length]
        );
    }
}
