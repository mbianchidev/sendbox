//! `exec-broker-spike`: a standalone Phase 1 execution-mediation spike.
//!
//! An untrusted "agent" process is locked down (via `PR_SET_NO_NEW_PRIVS`
//! plus a `TSYNC`-synchronized seccomp filter, installed before any
//! untrusted input is processed) and must request every command execution
//! from a privileged "broker" over a private Unix socket. The broker
//! spawns approved commands through a hardened `contained-launcher`
//! helper, and a separate "supervisor" binary guarantees no process group
//! survives the broker's own death. See [`platform`] for the three
//! distinct seccomp profiles this design requires, and [`policy`] for the
//! executable-allowlist / environment-sanitization engine that decides
//! what the broker is willing to run at all.
//!
//! # Unsafe code
//!
//! This crate denies `unsafe_code` at the crate level; only
//! [`platform::linux::adapter`] carries an explicit, narrowly scoped
//! `#[allow(unsafe_code)]` for the handful of raw syscalls
//! (`PR_SET_NO_NEW_PRIVS`, the syscall-probe primitives) that have no safe
//! wrapper. Every other module — including every Linux-specific one — is
//! built entirely on safe wrapper crates (`libseccomp`, `caps`, `rlimit`,
//! `nix`) and additionally declares `#![forbid(unsafe_code)]` itself for
//! an unambiguous, file-local guarantee.
//!
//! # Platform support
//!
//! Every hardening primitive is Linux-only at runtime. This library still
//! *compiles* — and its pure protocol/policy/session unit tests still
//! run — on macOS and other non-Linux targets, via [`platform::unsupported`]
//! stubs that return a clear "unsupported platform" error instead of
//! attempting anything Linux-specific. The four binaries in `src/bin/`
//! each detect this at `main` and exit with that error rather than
//! attempting to run.

#![deny(unsafe_code)]

pub mod error;
pub mod policy;
pub mod protocol;
pub mod session;

pub mod platform;

#[cfg(target_os = "linux")]
pub mod broker;
#[cfg(target_os = "linux")]
pub mod launcher;
#[cfg(target_os = "linux")]
pub mod pgid_registry;
#[cfg(target_os = "linux")]
pub mod supervisor;
