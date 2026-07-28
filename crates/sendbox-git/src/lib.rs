//! Native Git push/pull admission for a selected repository.
//!
//! This crate is a policy component for later execution-broker integration. It
//! does not prevent direct use of alternate Git binaries, remote helpers,
//! hosting-provider APIs, or other clients. Server-side repository rules remain
//! mandatory.

#![forbid(unsafe_code)]

mod argv;
mod discovery;
mod error;
mod identity;
mod pattern;
mod process;
mod service;
mod standalone;
mod trusted;

pub use argv::{
    GlobalInvocation, Operation, OperationArguments, parse_alias_words, parse_invocation,
    parse_operation_arguments,
};
pub use discovery::discover_repository_identity;
pub use error::GuardError;
pub use identity::{RepositoryIdentity, WorkspaceIdentity};
pub use pattern::{BranchPolicy, BranchPolicyConfiguration, normalize_branch};
pub use process::{
    EnvironmentPolicy, GitProcessRunner, ProcessOutput, ProcessRequest, SystemGitProcessRunner,
};
pub use service::{
    Admission, GIT_ASKPASS_PATH, GIT_SSH_PATH, GITHUB_TOKEN_ENVIRONMENT, GuardLimits,
    GuardPolicyDocument, GuardService, PolicySchemaVersion, SSH_KEY_ENVIRONMENT,
    parse_push_refspec,
};
pub use standalone::{execute_guarded_git, read_policy_file};
pub use trusted::{TrustedExecutable, TrustedGitBinary};
