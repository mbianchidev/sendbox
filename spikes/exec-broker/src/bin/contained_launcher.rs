//! `exec-broker-launcher`: the trusted helper the broker forks for every
//! approved `Execute` request. See [`exec_broker_spike::launcher`] for the
//! full hardening sequence this binary drives.
//!
//! This binary takes **no** policy-related CLI arguments at all: the
//! broker hands it a [`exec_broker_spike::launcher::LauncherEnvelope`]
//! (the validated request plus an immutable policy snapshot) over stdin,
//! after this process has already applied `NO_NEW_PRIVS` + the
//! `Launcher` seccomp filter + dropped capabilities + applied rlimits.
//! Accepting policy configuration via argv would mean trusting whatever
//! spawned this process to have passed the right flags — including
//! (defense-in-depth aside) exposing that configuration in
//! `/proc/<pid>/cmdline`; instead, the launcher reconstructs and
//! independently re-validates from the broker-authored snapshot alone.
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
    pub fn run() {
        match exec_broker_spike::launcher::run() {
            Ok(never) => match never {},
            Err(err) => {
                eprintln!("fatal: {err}");
                std::process::exit(1);
            }
        }
    }
}
