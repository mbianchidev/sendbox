//! Linux platform support: the trusted-bootstrap adapter, seccomp filter
//! construction, capability dropping, and resource limits.
//!
//! Only [`adapter`] is permitted to contain `unsafe` code; every other
//! submodule here is built entirely on safe wrapper crates (`libseccomp`,
//! `caps`, `rlimit`) and denies `unsafe` itself.
//!
//! This module-level lint is deliberately `deny`, not `forbid`: `forbid` is
//! a stronger, non-overridable lint level that would also apply to (and
//! break) the [`adapter`] submodule's own `#![allow(unsafe_code)]`, since
//! lint levels are inherited by descendant modules. `caps`, `rlimits`, and
//! `seccomp` additionally each redeclare `#![forbid(unsafe_code)]` locally
//! for an unambiguous, per-file guarantee that has no submodules to
//! conflict with.

#![deny(unsafe_code)]

pub mod adapter;
pub mod caps;
pub mod rlimits;
pub mod seccomp;

use crate::error::PlatformError;
use crate::platform::SeccompProfile;

/// Installs `PR_SET_NO_NEW_PRIVS` and the requested seccomp filter (with
/// `TSYNC`, so the filter applies to every thread of the current process
/// atomically) before any untrusted input is processed. This is the
/// trusted-bootstrap entry point every binary in this crate calls exactly
/// once, as early as possible in `main`.
pub fn set_no_new_privs() -> Result<(), PlatformError> {
    adapter::set_no_new_privs()
}

/// Builds and loads the seccomp filter for `profile` with `TSYNC` set.
pub fn install_seccomp_filter(profile: SeccompProfile) -> Result<(), PlatformError> {
    seccomp::install(profile)
}

/// Drops every capability from the permitted/effective/inheritable/bounding
/// sets, where supported.
pub fn drop_all_capabilities() -> Result<(), PlatformError> {
    caps::drop_all()
}

/// Applies the contained-launcher's default resource limits
/// (`NOFILE`/`NPROC`/`CORE`/`FSIZE`/`AS`).
pub fn apply_default_rlimits() -> Result<(), PlatformError> {
    rlimits::apply_defaults()
}
