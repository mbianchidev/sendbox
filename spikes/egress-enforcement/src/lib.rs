#![forbid(unsafe_code)]
//! Phase 1 network-enforcement spike: a typed, canonical egress policy, a
//! DNS-decoding/validating broker, a small versioned CONNECT egress broker,
//! deterministic nftables ruleset generation, and an opt-in Linux network
//! namespace harness that proves the enforcement mechanism end to end.
//!
//! This crate is a standalone spike. It is not wired into any production
//! runtime path and makes no claim about Kata, Apple `container`,
//! Hyperlight, or any other SendBox provider beyond proving the underlying
//! Linux kernel enforcement mechanism (network namespaces + nftables) works
//! as designed.

pub mod address;
pub mod authorization;
pub mod connect_broker;
pub mod connect_proto;
pub mod dns_broker;
pub mod domain;
pub mod fixture_file;
pub mod fixture_resolver;
pub mod netns_harness;
pub mod nft;
pub mod policy;
pub mod resolver;
