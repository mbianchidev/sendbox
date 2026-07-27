use std::collections::HashSet;
use std::fmt;

use http::{HeaderName, HeaderValue, Method};
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::{SecretName, SecretValue};

const MAX_BROKER_BODY_BYTES: usize = 16 * 1024 * 1024;

pub const GUARDED_GITHUB_CREDENTIALS: &[&str] = &[
    "GH_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "GITHUB_PAT",
    "GITHUB_OAUTH_TOKEN",
    "GITHUB_APP_PRIVATE_KEY",
    "GIT_ASKPASS",
    "GIT_ASKPASS_REQUIRE",
    "SSH_ASKPASS",
    "SSH_ASKPASS_REQUIRE",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_AUTH_SOCK",
];

#[must_use]
pub fn requires_guarded_github_forwarding(name: &SecretName) -> bool {
    GUARDED_GITHUB_CREDENTIALS
        .iter()
        .any(|candidate| name.as_str().eq_ignore_ascii_case(candidate))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialInjection {
    Bearer,
    Header { name: HeaderName },
    Query { parameter: String },
    Path { placeholder: String },
}

impl CredentialInjection {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Header { .. } => "header",
            Self::Query { .. } => "query",
            Self::Path { .. } => "path",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectPolicy {
    Deny,
    SameTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVerification {
    Required,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialPolicyError {
    #[error("target host is invalid")]
    InvalidTargetHost,
    #[error("path prefix must be an absolute path without control characters")]
    InvalidPathPrefix,
    #[error("credential injection field is invalid")]
    InvalidInjection,
    #[error("request/response limit is invalid")]
    InvalidLimit,
    #[error("repository credential requires guarded GitHub forwarding")]
    GuardedRepositoryCredential,
    #[error("request target does not exactly match the credential policy")]
    TargetMismatch,
    #[error("request method is not allowed")]
    MethodDenied,
    #[error("request body exceeds the configured limit")]
    RequestTooLarge,
    #[error("response body exceeds the configured limit")]
    ResponseTooLarge,
    #[error("TLS verification is required")]
    TlsRequired,
    #[error("request userinfo is forbidden")]
    UserInfoForbidden,
    #[error("redirect is forbidden by credential policy")]
    RedirectDenied,
    #[error("secret is not valid for the configured injection type")]
    InvalidSecretEncoding,
    #[error("credential header value is invalid")]
    InvalidHeaderValue,
    #[error("credential query parameter already exists")]
    DuplicateQueryParameter,
    #[error("path placeholder must occur exactly once as a complete segment")]
    PathPlaceholderMismatch,
}

#[derive(Debug, Clone)]
pub struct CredentialPolicy {
    target_host: String,
    path_prefix: String,
    injection: CredentialInjection,
    allowed_methods: HashSet<Method>,
    max_request_body_bytes: usize,
    max_response_body_bytes: usize,
    redirect_policy: RedirectPolicy,
    tls_verification: TlsVerification,
    secret_name: SecretName,
}

impl CredentialPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_host: &str,
        path_prefix: &str,
        injection: CredentialInjection,
        allowed_methods: impl IntoIterator<Item = Method>,
        max_request_body_bytes: usize,
        max_response_body_bytes: usize,
        redirect_policy: RedirectPolicy,
        secret_name: SecretName,
    ) -> Result<Self, CredentialPolicyError> {
        let target_host = canonical_host(target_host)?;
        if !path_prefix.starts_with('/')
            || path_prefix.chars().any(char::is_control)
            || path_prefix.contains(['?', '#'])
        {
            return Err(CredentialPolicyError::InvalidPathPrefix);
        }
        validate_injection(&injection)?;
        let allowed_methods = allowed_methods.into_iter().collect::<HashSet<_>>();
        if allowed_methods.is_empty()
            || max_request_body_bytes > MAX_BROKER_BODY_BYTES
            || max_response_body_bytes == 0
            || max_response_body_bytes > MAX_BROKER_BODY_BYTES
        {
            return Err(CredentialPolicyError::InvalidLimit);
        }
        if requires_guarded_github_forwarding(&secret_name) {
            return Err(CredentialPolicyError::GuardedRepositoryCredential);
        }
        Ok(Self {
            target_host,
            path_prefix: path_prefix.to_owned(),
            injection,
            allowed_methods,
            max_request_body_bytes,
            max_response_body_bytes,
            redirect_policy,
            tls_verification: TlsVerification::Required,
            secret_name,
        })
    }

    pub fn transform(
        &self,
        request: BrokerRequest,
        secret: &SecretValue,
    ) -> Result<TransformedRequest, CredentialPolicyError> {
        self.validate_request(&request)?;
        let audit = AuditSafeRequestMetadata {
            method: request.method.clone(),
            target_host: self.target_host.clone(),
            path: request.url.path().to_owned(),
            injection_kind: self.injection.kind(),
            secret_name: self.secret_name.clone(),
            request_body_bytes: request.body.len(),
        };
        let mut url = request.url;
        let mut headers = request
            .headers
            .into_iter()
            .map(|(name, value)| {
                HeaderValue::from_bytes(&value)
                    .map(|_| (name, SensitiveBytes::new(value)))
                    .map_err(|_| CredentialPolicyError::InvalidHeaderValue)
            })
            .collect::<Result<Vec<_>, _>>()?;

        match &self.injection {
            CredentialInjection::Bearer => {
                let mut value =
                    Zeroizing::new(Vec::with_capacity(7 + secret.expose_secret().len()));
                value.extend_from_slice(b"Bearer ");
                value.extend_from_slice(secret.expose_secret());
                HeaderValue::from_bytes(&value)
                    .map_err(|_| CredentialPolicyError::InvalidHeaderValue)?;
                replace_header(
                    &mut headers,
                    http::header::AUTHORIZATION,
                    SensitiveBytes::new(value.to_vec()),
                );
            }
            CredentialInjection::Header { name } => {
                HeaderValue::from_bytes(secret.expose_secret())
                    .map_err(|_| CredentialPolicyError::InvalidHeaderValue)?;
                replace_header(
                    &mut headers,
                    name.clone(),
                    SensitiveBytes::new(secret.expose_secret().to_vec()),
                );
            }
            CredentialInjection::Query { parameter } => {
                if url
                    .query_pairs()
                    .any(|(name, _)| name == parameter.as_str())
                {
                    return Err(CredentialPolicyError::DuplicateQueryParameter);
                }
                let value = std::str::from_utf8(secret.expose_secret())
                    .map_err(|_| CredentialPolicyError::InvalidSecretEncoding)?;
                url.query_pairs_mut().append_pair(parameter, value);
            }
            CredentialInjection::Path { placeholder } => {
                let value = std::str::from_utf8(secret.expose_secret())
                    .map_err(|_| CredentialPolicyError::InvalidSecretEncoding)?;
                let segments = url
                    .path_segments()
                    .ok_or(CredentialPolicyError::PathPlaceholderMismatch)?
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                if segments
                    .iter()
                    .filter(|segment| segment.as_str() == placeholder)
                    .count()
                    != 1
                {
                    return Err(CredentialPolicyError::PathPlaceholderMismatch);
                }
                let replacement = segments
                    .iter()
                    .map(|segment| {
                        if segment == placeholder {
                            value
                        } else {
                            segment.as_str()
                        }
                    })
                    .collect::<Vec<_>>();
                let mut path = url
                    .path_segments_mut()
                    .map_err(|_| CredentialPolicyError::PathPlaceholderMismatch)?;
                path.clear();
                path.extend(replacement);
            }
        }

        Ok(TransformedRequest {
            method: request.method,
            url: SensitiveUrl::new(url.to_string()),
            headers,
            body: SensitiveBytes::new(request.body),
            audit,
        })
    }

    pub fn validate_response_size(&self, bytes: usize) -> Result<(), CredentialPolicyError> {
        if bytes > self.max_response_body_bytes {
            Err(CredentialPolicyError::ResponseTooLarge)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    #[must_use]
    pub fn path_prefix(&self) -> &str {
        &self.path_prefix
    }

    #[must_use]
    pub const fn max_request_body_bytes(&self) -> usize {
        self.max_request_body_bytes
    }

    #[must_use]
    pub const fn max_response_body_bytes(&self) -> usize {
        self.max_response_body_bytes
    }

    pub fn authorize_redirect(&self, from: &Url, to: &Url) -> Result<(), CredentialPolicyError> {
        match self.redirect_policy {
            RedirectPolicy::Deny => Err(CredentialPolicyError::RedirectDenied),
            RedirectPolicy::SameTarget => {
                self.validate_url(to)?;
                if from.scheme() != to.scheme()
                    || from.host_str() != to.host_str()
                    || from.port_or_known_default() != to.port_or_known_default()
                {
                    return Err(CredentialPolicyError::RedirectDenied);
                }
                Ok(())
            }
        }
    }

    fn validate_request(&self, request: &BrokerRequest) -> Result<(), CredentialPolicyError> {
        self.validate_url(&request.url)?;
        if !self.allowed_methods.contains(&request.method) {
            return Err(CredentialPolicyError::MethodDenied);
        }
        if request.body.len() > self.max_request_body_bytes {
            return Err(CredentialPolicyError::RequestTooLarge);
        }
        Ok(())
    }

    fn validate_url(&self, url: &Url) -> Result<(), CredentialPolicyError> {
        if self.tls_verification != TlsVerification::Required || url.scheme() != "https" {
            return Err(CredentialPolicyError::TlsRequired);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(CredentialPolicyError::UserInfoForbidden);
        }
        if url.host_str() != Some(self.target_host.as_str())
            || url.port_or_known_default() != Some(443)
            || !url.path().starts_with(&self.path_prefix)
        {
            return Err(CredentialPolicyError::TargetMismatch);
        }
        Ok(())
    }
}

pub struct BrokerRequest {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(HeaderName, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for BrokerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub struct SensitiveBytes(Zeroizing<Vec<u8>>);

impl SensitiveBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveBytes([REDACTED])")
    }
}

impl fmt::Display for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

pub struct SensitiveUrl(Zeroizing<String>);

impl SensitiveUrl {
    fn new(url: String) -> Self {
        Self(Zeroizing::new(url))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SensitiveUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveUrl([REDACTED])")
    }
}

impl fmt::Display for SensitiveUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

pub struct TransformedRequest {
    pub method: Method,
    pub url: SensitiveUrl,
    pub headers: Vec<(HeaderName, SensitiveBytes)>,
    pub body: SensitiveBytes,
    pub audit: AuditSafeRequestMetadata,
}

impl fmt::Debug for TransformedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransformedRequest")
            .field("method", &self.method)
            .field("url", &"[REDACTED]")
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .field("audit", &self.audit)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSafeRequestMetadata {
    pub method: Method,
    pub target_host: String,
    pub path: String,
    pub injection_kind: &'static str,
    pub secret_name: SecretName,
    pub request_body_bytes: usize,
}

fn canonical_host(host: &str) -> Result<String, CredentialPolicyError> {
    if host.is_empty()
        || host.ends_with('.')
        || host.chars().any(char::is_control)
        || host.contains(['/', '@', ':'])
    {
        return Err(CredentialPolicyError::InvalidTargetHost);
    }
    match Host::parse(host).map_err(|_| CredentialPolicyError::InvalidTargetHost)? {
        Host::Domain(domain) => Ok(domain.to_ascii_lowercase()),
        Host::Ipv4(address) => Ok(address.to_string()),
        Host::Ipv6(_) => Err(CredentialPolicyError::InvalidTargetHost),
    }
}

fn validate_injection(injection: &CredentialInjection) -> Result<(), CredentialPolicyError> {
    let field = match injection {
        CredentialInjection::Bearer => return Ok(()),
        CredentialInjection::Header { name } => name.as_str(),
        CredentialInjection::Query { parameter } => parameter,
        CredentialInjection::Path { placeholder } => placeholder,
    };
    if field.is_empty()
        || field.chars().any(char::is_control)
        || field.contains(['/', '?', '#', '&', '='])
        || matches!(injection, CredentialInjection::Path { .. })
            && !field.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
    {
        return Err(CredentialPolicyError::InvalidInjection);
    }
    Ok(())
}

fn replace_header(
    headers: &mut Vec<(HeaderName, SensitiveBytes)>,
    name: HeaderName,
    value: SensitiveBytes,
) {
    headers.retain(|(candidate, _)| candidate != name);
    headers.push((name, value));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(injection: CredentialInjection) -> CredentialPolicy {
        CredentialPolicy::new(
            "api.example.com",
            "/v1/",
            injection,
            [Method::GET, Method::POST],
            1024,
            2048,
            RedirectPolicy::SameTarget,
            SecretName::new("EXAMPLE_TOKEN").expect("name"),
        )
        .expect("policy")
    }

    fn request(url: &str) -> BrokerRequest {
        BrokerRequest {
            method: Method::POST,
            url: Url::parse(url).expect("url"),
            headers: vec![(
                HeaderName::from_static("content-type"),
                b"application/json".to_vec(),
            )],
            body: b"{}".to_vec(),
        }
    }

    #[test]
    fn bearer_injection_uses_the_real_secret_and_redacts_formatting() {
        let transformed = policy(CredentialInjection::Bearer)
            .transform(
                request("https://api.example.com/v1/messages"),
                &SecretValue::try_from("actual-token").expect("secret"),
            )
            .expect("transform");
        let authorization = transformed
            .headers
            .iter()
            .find(|(name, _)| name == http::header::AUTHORIZATION)
            .expect("authorization");
        assert_eq!(authorization.1.expose(), b"Bearer actual-token");
        assert_ne!(authorization.1.expose(), b"******");
        assert!(!format!("{transformed:?}").contains("actual-token"));
        assert!(!format!("{}", transformed.url).contains("actual-token"));
    }

    #[test]
    fn target_method_tls_body_response_and_redirect_rules_fail_closed() {
        let policy = policy(CredentialInjection::Bearer);
        for url in [
            "http://api.example.com/v1/messages",
            "https://api.example.com.evil.test/v1/messages",
            "https://api.example.com./v1/messages",
            "https://user@api.example.com/v1/messages",
            "https://api.example.com/other",
            "https://api.example.com:444/v1/messages",
        ] {
            assert!(
                policy
                    .transform(
                        request(url),
                        &SecretValue::try_from("token").expect("secret")
                    )
                    .is_err()
            );
        }

        let mut denied_method = request("https://api.example.com/v1/messages");
        denied_method.method = Method::DELETE;
        assert!(matches!(
            policy.transform(
                denied_method,
                &SecretValue::try_from("token").expect("secret")
            ),
            Err(CredentialPolicyError::MethodDenied)
        ));
        let mut oversized = request("https://api.example.com/v1/messages");
        oversized.body = vec![0_u8; 1025];
        assert!(matches!(
            policy.transform(oversized, &SecretValue::try_from("token").expect("secret")),
            Err(CredentialPolicyError::RequestTooLarge)
        ));
        assert!(matches!(
            policy.validate_response_size(2049),
            Err(CredentialPolicyError::ResponseTooLarge)
        ));
        assert!(
            policy
                .authorize_redirect(
                    &Url::parse("https://api.example.com/v1/a").expect("from"),
                    &Url::parse("https://api.example.com/v1/b").expect("to")
                )
                .is_ok()
        );
        assert!(matches!(
            policy.authorize_redirect(
                &Url::parse("https://api.example.com/v1/a").expect("from"),
                &Url::parse("https://evil.test/v1/b").expect("to")
            ),
            Err(CredentialPolicyError::TargetMismatch | CredentialPolicyError::RedirectDenied)
        ));
    }

    #[test]
    fn query_and_path_injection_are_exact_and_encoded() {
        let query = policy(CredentialInjection::Query {
            parameter: "api_key".to_owned(),
        })
        .transform(
            request("https://api.example.com/v1/messages?mode=fast"),
            &SecretValue::try_from("a+b&c").expect("secret"),
        )
        .expect("query");
        assert!(query.url.expose().contains("api_key=a%2Bb%26c"));

        let path_policy = CredentialPolicy::new(
            "api.example.com",
            "/v1/",
            CredentialInjection::Path {
                placeholder: "credential".to_owned(),
            },
            [Method::POST],
            1024,
            2048,
            RedirectPolicy::Deny,
            SecretName::new("EXAMPLE_TOKEN").expect("name"),
        )
        .expect("policy");
        let path = path_policy
            .transform(
                request("https://api.example.com/v1/credential/messages"),
                &SecretValue::try_from("a/b").expect("secret"),
            )
            .expect("path");
        assert!(path.url.expose().contains("/v1/a%2Fb/messages"));
    }

    #[test]
    fn repository_credentials_are_explicitly_denied() {
        for name in GUARDED_GITHUB_CREDENTIALS {
            let name = SecretName::new(*name).expect("name");
            assert!(requires_guarded_github_forwarding(&name));
            assert!(matches!(
                CredentialPolicy::new(
                    "api.github.com",
                    "/",
                    CredentialInjection::Bearer,
                    [Method::GET],
                    0,
                    1024,
                    RedirectPolicy::Deny,
                    name
                ),
                Err(CredentialPolicyError::GuardedRepositoryCredential)
            ));
        }
    }
}
