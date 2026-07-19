//! Broker-side modules: runtime directory lifecycle, the authenticated
//! Unix socket, per-request process supervision, length-delimited framing,
//! and the accept loop / connection dispatch that ties them together.
//!
//! Everything under this module is Linux-only at the point of actual use
//! (it depends on `nix`/`libc` process-group and credential primitives),
//! but each submodule itself forbids `unsafe` — the only unsafe in this
//! crate lives in [`crate::platform::linux::adapter`].

#![forbid(unsafe_code)]

pub mod framing;
pub mod process;
pub mod runtime_dir;
pub mod server;
pub mod socket;
