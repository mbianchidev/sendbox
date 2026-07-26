use std::{fmt, net::SocketAddr};

use sendbox_secrets::SecretValue;
use url::Url;

use crate::{CredentialBrokerError, CredentialRule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCredentialEndpoint {
    pub rule_id: String,
    pub base_url: Url,
    pub upstream_host: String,
    pub upstream_path_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerAgentConfiguration {
    pub listener_url: Url,
    pub endpoints: Vec<AgentCredentialEndpoint>,
    pub supports_connect: bool,
    pub requires_explicit_base_url: bool,
}

impl BrokerAgentConfiguration {
    pub(crate) fn new(
        local_addr: SocketAddr,
        rules: &[CredentialRule],
    ) -> Result<Self, CredentialBrokerError> {
        let listener_url = Url::parse(&format!("http://{local_addr}/")).map_err(|error| {
            CredentialBrokerError::InvalidConfiguration(format!(
                "could not construct broker listener URL: {error}"
            ))
        })?;
        let endpoints = rules
            .iter()
            .map(|rule| {
                let base_url = listener_url
                    .join(&format!(
                        "credentials/{}/{}",
                        rule.id(),
                        rule.policy().path_prefix().trim_start_matches('/')
                    ))
                    .map_err(|error| {
                        CredentialBrokerError::InvalidConfiguration(format!(
                            "could not construct agent credential endpoint: {error}"
                        ))
                    })?;
                Ok(AgentCredentialEndpoint {
                    rule_id: rule.id().to_owned(),
                    base_url,
                    upstream_host: rule.policy().target_host().to_owned(),
                    upstream_path_prefix: rule.policy().path_prefix().to_owned(),
                })
            })
            .collect::<Result<Vec<_>, CredentialBrokerError>>()?;
        Ok(Self {
            listener_url,
            endpoints,
            supports_connect: false,
            requires_explicit_base_url: true,
        })
    }
}

pub struct GitHubSessionCredentials {
    pub github_token: Option<SecretValue>,
    pub copilot_token: Option<SecretValue>,
}

impl fmt::Debug for GitHubSessionCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubSessionCredentials")
            .field(
                "github_token",
                &self.github_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "copilot_token",
                &self.copilot_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

pub struct SessionCredentialConfiguration {
    pub session_id: String,
    pub broker: BrokerAgentConfiguration,
    pub github: GitHubSessionCredentials,
}

impl SessionCredentialConfiguration {
    pub fn new(
        session_id: impl Into<String>,
        broker: BrokerAgentConfiguration,
        github: GitHubSessionCredentials,
    ) -> Result<Self, CredentialBrokerError> {
        let session_id = session_id.into();
        if session_id.is_empty()
            || session_id.len() > 128
            || session_id.chars().any(char::is_control)
        {
            return Err(CredentialBrokerError::InvalidConfiguration(
                "session ID must be 1-128 bytes without control characters".to_owned(),
            ));
        }
        Ok(Self {
            session_id,
            broker,
            github,
        })
    }
}

impl fmt::Debug for SessionCredentialConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCredentialConfiguration")
            .field("session_id", &self.session_id)
            .field("broker", &self.broker)
            .field("github", &self.github)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use http::Method;
    use sendbox_secrets::{
        CredentialInjection, CredentialPolicy, RedirectPolicy, SecretName, SecretValue,
    };

    use super::*;

    #[test]
    fn agent_configuration_uses_explicit_rule_base_urls_and_redacts_tokens() {
        let name = SecretName::new("TOKEN").expect("name");
        let policy = CredentialPolicy::new(
            "api.example.com",
            "/v1/",
            CredentialInjection::Bearer,
            [Method::GET],
            0,
            1024,
            RedirectPolicy::Deny,
            name.clone(),
        )
        .expect("policy");
        let rule = CredentialRule::new("api", name, policy).expect("rule");
        let broker =
            BrokerAgentConfiguration::new(SocketAddr::from(([127, 0, 0, 1], 9000)), &[rule])
                .expect("agent configuration");
        assert_eq!(
            broker.endpoints[0].base_url.as_str(),
            "http://127.0.0.1:9000/credentials/api/v1/"
        );
        assert!(broker.requires_explicit_base_url);
        assert!(!broker.supports_connect);

        let session = SessionCredentialConfiguration::new(
            "session-1",
            broker,
            GitHubSessionCredentials {
                github_token: Some(SecretValue::try_from("github-secret").expect("token")),
                copilot_token: Some(SecretValue::try_from("copilot-secret").expect("token")),
            },
        )
        .expect("session");
        let debug = format!("{session:?}");
        assert!(!debug.contains("github-secret"));
        assert!(!debug.contains("copilot-secret"));
    }
}
