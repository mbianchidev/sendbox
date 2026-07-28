#![forbid(unsafe_code)]
//! Production-safe MCP framing, policy, stdio brokering, trusted Streamable
//! HTTP gateway enforcement, configuration validation, and observation
//! processing.

pub mod artifact;
pub mod audit;
pub mod broker;
pub mod config;
pub mod error;
pub mod framing;
pub mod http_gateway;
pub mod jsonrpc;
pub mod observation;
pub mod policy;
pub mod runtime;

pub use error::{AuditError, BrokerError, ConfigError, FrameError, JsonRpcError, ObservationError};
