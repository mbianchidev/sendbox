//! Linux execution implementation.
//!
//! Only `raw` may contain unsafe code. Policy, cgroup lifecycle, descriptor
//! resolution, launcher preparation, and security profiles remain safe Rust.

#![deny(unsafe_code)]

pub mod agent;
pub mod capabilities;
pub mod cgroup;
pub mod launcher;
pub mod resolver;
pub mod rlimits;
pub mod seccomp;

#[allow(unsafe_code)]
pub(crate) mod raw;
