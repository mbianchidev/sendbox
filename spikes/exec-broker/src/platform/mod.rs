//! Platform abstraction: Linux-specific hardening primitives (the only
//! platform this crate supports at runtime) behind a small, explicit
//! surface, plus a stub for every other OS so the crate still compiles —
//! and its pure unit tests still run — on macOS.
//!
//! This lint is `deny`, not `forbid`: lint levels are inherited by
//! descendant modules, and `forbid` would be non-overridable by the one
//! submodule ([`linux::adapter`]) that legitimately needs
//! `#![allow(unsafe_code)]`.

#![deny(unsafe_code)]

use crate::error::PlatformError;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(not(target_os = "linux"))]
pub mod unsupported;

/// Seccomp filter profiles used at different points in the process
/// hierarchy. See [`linux::seccomp`] for the concrete syscall lists.
///
/// # Why three profiles instead of one
///
/// A single seccomp filter cannot both deny `execve` unconditionally *and*
/// be usable by a process that legitimately needs to fork+exec, because a
/// seccomp filter is inherited across `fork`/`clone` and can only ever be
/// tightened (never loosened) by a descendant. Given that hard constraint,
/// the roles in this system need genuinely different filters:
///
/// * The (conceptual, in this spike represented by the `agent` binary's
///   bootstrap/probe mode) *sandboxed workload* never needs to call
///   `exec*` itself at all — every command it wants to run must be
///   requested from the broker over the Unix socket protocol. Its filter
///   can therefore deny `execve`/`execveat` unconditionally.
/// * The *broker* is the control-plane process accepting requests and must
///   retain the ability to fork+exec a fresh `contained-launcher` per
///   accepted request, so its filter permits `execve`/`clone` while still
///   denying the other high-risk primitives.
/// * `contained-launcher` is forked fresh per request *before* it has
///   applied any filter, applies its own [`SeccompProfile::Launcher`]
///   filter (which still permits exec, since it must become the target),
///   then execs the target. Because the filter denies `setsid`/`setpgid`,
///   neither the target nor its descendants can leave the process group
///   the broker placed them in, which is what makes the broker's
///   process-group-based cleanup sound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompProfile {
    /// Denies `execve`/`execveat`/`memfd_create` and the other high-risk
    /// primitives outright, with no exceptions.
    AgentBootstrap,
    /// Denies the same high-risk primitives as `AgentBootstrap` but
    /// permits `execve`/`execveat`/`clone`.
    Broker,
    /// Permits exec (for itself, once, and for the target's own
    /// descendants), still denies the other high-risk primitives, and
    /// additionally denies `setsid`/`setpgid`.
    Launcher,
}

/// Returns a [`PlatformError::UnsupportedPlatform`] describing the current
/// (non-Linux) `target_os`.
#[must_use]
pub fn unsupported_platform_error() -> PlatformError {
    PlatformError::UnsupportedPlatform(std::env::consts::OS)
}

/// Installs `PR_SET_NO_NEW_PRIVS` (Linux) or fails with
/// [`PlatformError::UnsupportedPlatform`] (every other target).
pub fn set_no_new_privs() -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::set_no_new_privs()
    }
    #[cfg(not(target_os = "linux"))]
    {
        unsupported::set_no_new_privs()
    }
}

/// Builds and loads the seccomp filter for `profile` (Linux) or fails with
/// [`PlatformError::UnsupportedPlatform`] (every other target).
pub fn install_seccomp_filter(profile: SeccompProfile) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::install_seccomp_filter(profile)
    }
    #[cfg(not(target_os = "linux"))]
    {
        unsupported::install_seccomp_filter(profile)
    }
}

/// Drops every capability (Linux) or fails with
/// [`PlatformError::UnsupportedPlatform`] (every other target).
pub fn drop_all_capabilities() -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::drop_all_capabilities()
    }
    #[cfg(not(target_os = "linux"))]
    {
        unsupported::drop_all_capabilities()
    }
}

/// Applies the contained-launcher's default rlimits (Linux) or fails with
/// [`PlatformError::UnsupportedPlatform`] (every other target).
pub fn apply_default_rlimits() -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        linux::apply_default_rlimits()
    }
    #[cfg(not(target_os = "linux"))]
    {
        unsupported::apply_default_rlimits()
    }
}
