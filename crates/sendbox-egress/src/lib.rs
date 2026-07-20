#![forbid(unsafe_code)]
//! Production network egress enforcement for SendBox.
//!
//! This crate promotes the proven `spikes/egress-enforcement` architecture
//! into a production workspace crate. It is split into two clearly separated
//! layers:
//!
//! * A **portable policy core** (`address`, `domain`, `policy`,
//!   `authorization`, `resolver`, `forwarding_resolver`, `dns_budget`,
//!   `connect_proto`, `dns_broker`, `connect_broker`, `gateway`, `audit`,
//!   `dialer`). It performs no privileged operations, compiles on macOS and
//!   Linux alike, and is exercised by ordinary unit/integration tests.
//! * A **Linux enforcement layer** ([`linux`], compiled only on
//!   `target_os = "linux"`). It owns a stable cgroup v2 hierarchy, renders and
//!   atomically applies versioned nftables rules that key on
//!   `socket cgroupv2` identity plus a fixed `SO_MARK`, and exposes a
//!   supervisor whose armed guard refuses to let an agent start until every
//!   control is verified.
//!
//! Existing `sendbox_policy::NetworkPolicy` fields remain the single source of
//! truth. [`policy::PolicyEngine`] compiles that type into deterministic,
//! side-effect-free egress decisions; nothing here mutates policy.
//!
//! The whole crate forbids `unsafe` Rust.

pub mod address;
pub mod audit;
pub mod authorization;
pub mod connect_broker;
pub mod connect_proto;
pub mod dialer;
pub mod dns_broker;
pub mod dns_budget;
pub mod domain;
pub mod fixture_resolver;
pub mod forwarding_resolver;
pub mod gateway;
pub mod policy;
pub mod resolver;
pub mod socks5;

#[cfg(target_os = "linux")]
pub mod linux;
