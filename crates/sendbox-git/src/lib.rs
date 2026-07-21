//! Native Git push/pull admission for a selected repository.
//!
//! This crate is a policy component for later execution-broker integration. It
//! does not prevent direct use of alternate Git binaries, remote helpers,
//! hosting-provider APIs, or other clients. Server-side repository rules remain
//! mandatory.

#![forbid(unsafe_code)]

mod argv;
mod error;
mod identity;
mod pattern;
mod process;
mod service;
mod trusted;

pub use argv::{
    GlobalInvocation, Operation, OperationArguments, parse_alias_words, parse_invocation,
    parse_operation_arguments,
};
pub use error::GuardError;
pub use identity::{RepositoryIdentity, WorkspaceIdentity};
pub use pattern::{BranchPolicy, BranchPolicyConfiguration, normalize_branch};
pub use process::{
    EnvironmentPolicy, GitProcessRunner, ProcessOutput, ProcessRequest, SystemGitProcessRunner,
};
pub use service::{
    Admission, GuardLimits, GuardPolicyDocument, GuardService, PolicySchemaVersion,
    parse_push_refspec,
};
pub use trusted::TrustedGitBinary;
