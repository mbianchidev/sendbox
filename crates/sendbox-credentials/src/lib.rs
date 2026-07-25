#![forbid(unsafe_code)]

mod broker;
mod config;
mod error;
mod github;
mod http1;
mod session;
mod upstream;

pub use broker::{
    AuditSink, BrokerAuditEvent, BrokerHandle, CredentialBroker, NoopAuditSink, SecretResolver,
};
pub use config::{
    BrokerBind, BrokerConfiguration, BrokerLimits, CredentialRule, UpstreamAddressPolicy,
};
pub use error::CredentialBrokerError;
pub use github::{
    GhMetadataClient, GhProcessConfiguration, GitHubAuthorization, GitHubMetadataClient,
    GitHubRepository, OwnerKind, RepositoryAccessDecision, RepositoryAccessPolicy,
    RepositoryIdentity, RepositoryVisibility, authorize_github,
};
pub use session::{
    AgentCredentialEndpoint, BrokerAgentConfiguration, GitHubSessionCredentials,
    SessionCredentialConfiguration,
};
pub use upstream::{
    PinnedHttpsTransport, SystemResolver, UpstreamRequest, UpstreamResolver, UpstreamResponse,
    UpstreamTransport,
};

#[doc(hidden)]
pub mod fuzzing {
    pub fn parse_http1_request(bytes: &[u8]) -> Result<(), String> {
        crate::http1::parse_complete_request(bytes, &crate::config::BrokerLimits::default())
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}
