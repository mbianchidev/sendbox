#![forbid(unsafe_code)]
//! Production-safe MCP framing, policy, stdio brokering, configuration
//! validation, and observation processing.
//!
//! Authorization in this crate applies only to local stdio MCP servers launched
//! through the broker. HTTP and SSE data can be represented as observations,
//! but are never treated as an authorization boundary.

pub mod artifact;
pub mod broker;
pub mod config;
pub mod error;
pub mod framing;
pub mod jsonrpc;
pub mod observation;
pub mod policy;

pub use error::{BrokerError, ConfigError, FrameError, JsonRpcError, ObservationError};
