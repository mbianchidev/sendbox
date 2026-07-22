#![forbid(unsafe_code)]

pub mod error;
pub mod event;
pub mod loader;
pub mod preflight;

pub use error::{BpfError, DiagnosticKind};
pub use event::{
    EVENT_SCHEMA_VERSION, Event, EventHeader, EventKind, ExecEvent, McpDirection, McpEvent,
    McpTransport, SyscallEvent,
};
pub use loader::{AttachConfig, EventStream, LossSnapshot};
pub use preflight::{PreflightReport, inspect_host};
