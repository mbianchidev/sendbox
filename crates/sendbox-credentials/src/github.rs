use std::{fmt, path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use sendbox_config::GitHubConfiguration;
use sendbox_runtime::{
    CancellationToken, CommandArgument, CommandSpec, EnvironmentVariable, ProcessOptions,
    ProcessRunner, Program, SearchPathResolver, TerminationReason,
};
use sendbox_secrets::SecretValue;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::{CredentialBrokerError, GitHubSessionCredentials};

const MAX_GITHUB_PAGES: usize = 100;
const MAX_GITHUB_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const GITHUB_HOST: &str = "github.com";
const SELECTED_REPOSITORY_QUERY: &str = r#"query($owner:String!,$name:String!){repository(owner:$owner,name:$name){nameWithOwner visibility owner{login __typename}}}"#;
const ACCESSIBLE_REPOSITORIES_QUERY: &str = r#"query($cursor:String){viewer{repositories(first:100,after:$cursor,affiliations:[OWNER,COLLABORATOR,ORGANIZATION_MEMBER]){nodes{nameWithOwner visibility owner{login __typename}} pageInfo{hasNextPage endCursor}}}}"#;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepositoryIdentity {
    pub owner: String,
    pub name: String,
}

impl RepositoryIdentity {
    pub fn parse(value: &str) -> Result<Self, CredentialBrokerError> {
        let mut parts = value.split('/');
        let owner = parts.next().unwrap_or_default();
        let name = parts.next().unwrap_or_default();
        if parts.next().is_some()
            || !valid_repository_component(owner)
            || !valid_repository_component(name)
        {
            return Err(CredentialBrokerError::InvalidConfiguration(
                "repository identity must be OWNER/NAME using GitHub-safe characters".to_owned(),
            ));
        }
        Ok(Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
        })
    }

    #[must_use]
    pub fn name_with_owner(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    fn same_repository(&self, other: &Self) -> bool {
        self.owner.eq_ignore_ascii_case(&other.owner) && self.name.eq_ignore_ascii_case(&other.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RepositoryVisibility {
    Public,
    Private,
    Internal,
}

impl RepositoryVisibility {
    const fn is_non_public(self) -> bool {
        !matches!(self, Self::Public)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKind {
    User,
    Organization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubRepository {
    pub identity: RepositoryIdentity,
    pub visibility: RepositoryVisibility,
    pub owner_kind: OwnerKind,
}

impl GitHubRepository {
    fn organization(&self) -> Option<&str> {
        matches!(self.owner_kind, OwnerKind::Organization).then_some(self.identity.owner.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryAccessDecision {
    Allow,
    Warn(String),
    Deny(String),
}

#[derive(Debug, Default)]
pub struct RepositoryAccessPolicy;

impl RepositoryAccessPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn evaluate(
        &self,
        source: &GitHubRepository,
        target: &GitHubRepository,
        private_access_override: bool,
    ) -> RepositoryAccessDecision {
        if source.identity.same_repository(&target.identity)
            && source.visibility == target.visibility
        {
            return RepositoryAccessDecision::Allow;
        }
        if !target.visibility.is_non_public() {
            return RepositoryAccessDecision::Allow;
        }
        if !source.visibility.is_non_public() {
            return RepositoryAccessDecision::Deny(format!(
                "public repository {} cannot access non-public repository {}",
                source.identity.name_with_owner(),
                target.identity.name_with_owner()
            ));
        }
        let same_organization = source
            .organization()
            .zip(target.organization())
            .is_some_and(|(source, target)| source.eq_ignore_ascii_case(target));
        if !same_organization {
            return RepositoryAccessDecision::Deny(format!(
                "additional non-public repository {} is outside the selected repository organization",
                target.identity.name_with_owner()
            ));
        }
        if !private_access_override {
            return RepositoryAccessDecision::Warn(format!(
                "additional non-public repository {} requires explicit approval",
                target.identity.name_with_owner()
            ));
        }
        RepositoryAccessDecision::Allow
    }

    #[must_use]
    pub fn evaluate_credential_scope(
        &self,
        source: &GitHubRepository,
        accessible_non_public: &[GitHubRepository],
        private_access_override: bool,
    ) -> RepositoryAccessDecision {
        if source.visibility.is_non_public()
            && !accessible_non_public.iter().any(|repository| {
                source.identity.same_repository(&repository.identity)
                    && repository.visibility.is_non_public()
            })
        {
            return RepositoryAccessDecision::Deny(format!(
                "GitHub credentials cannot access selected non-public repository {}",
                source.identity.name_with_owner()
            ));
        }
        for repository in accessible_non_public {
            match self.evaluate(source, repository, private_access_override) {
                RepositoryAccessDecision::Allow => {}
                decision => return decision,
            }
        }
        RepositoryAccessDecision::Allow
    }
}

#[async_trait]
pub trait GitHubMetadataClient: Send + Sync {
    async fn repository(
        &self,
        identity: &RepositoryIdentity,
        cancellation: &CancellationToken,
    ) -> Result<GitHubRepository, CredentialBrokerError>;

    async fn accessible_non_public_repositories(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Vec<GitHubRepository>, CredentialBrokerError>;

    async fn auth_token(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<SecretValue, CredentialBrokerError>;
}

pub struct GitHubAuthorization {
    pub selected_repository: Option<GitHubRepository>,
    pub accessible_non_public_repositories: Vec<GitHubRepository>,
    pub credentials: GitHubSessionCredentials,
}

impl fmt::Debug for GitHubAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubAuthorization")
            .field("selected_repository", &self.selected_repository)
            .field(
                "accessible_non_public_repositories",
                &self.accessible_non_public_repositories,
            )
            .field("credentials", &self.credentials)
            .finish()
    }
}

pub async fn authorize_github(
    client: &dyn GitHubMetadataClient,
    selected_identity: &RepositoryIdentity,
    configuration: &GitHubConfiguration,
    copilot_token: Option<SecretValue>,
    cancellation: &CancellationToken,
) -> Result<GitHubAuthorization, CredentialBrokerError> {
    let copilot_token = configuration
        .forward_copilot_auth
        .then_some(copilot_token)
        .flatten();
    if !configuration.forward_auth {
        return Ok(GitHubAuthorization {
            selected_repository: None,
            accessible_non_public_repositories: Vec::new(),
            credentials: GitHubSessionCredentials {
                github_token: None,
                copilot_token,
            },
        });
    }

    let selected = client.repository(selected_identity, cancellation).await?;
    let accessible = client
        .accessible_non_public_repositories(cancellation)
        .await?;
    let decision = RepositoryAccessPolicy::new().evaluate_credential_scope(
        &selected,
        &accessible,
        configuration.allow_private_repository_access,
    );
    match decision {
        RepositoryAccessDecision::Allow => {}
        RepositoryAccessDecision::Warn(message) | RepositoryAccessDecision::Deny(message) => {
            return Err(CredentialBrokerError::GitHubAuthorization(message));
        }
    }
    let github_token = client.auth_token(cancellation).await?;
    Ok(GitHubAuthorization {
        selected_repository: Some(selected),
        accessible_non_public_repositories: accessible,
        credentials: GitHubSessionCredentials {
            github_token: Some(github_token),
            copilot_token,
        },
    })
}

#[derive(Debug, Clone)]
pub struct GhProcessConfiguration {
    pub executable: PathBuf,
    pub config_dir: PathBuf,
    pub home: PathBuf,
    pub timeout: Duration,
}

impl GhProcessConfiguration {
    pub fn new(
        executable: PathBuf,
        config_dir: PathBuf,
        home: PathBuf,
    ) -> Result<Self, CredentialBrokerError> {
        if !executable.is_absolute() || !config_dir.is_absolute() || !home.is_absolute() {
            return Err(CredentialBrokerError::InvalidConfiguration(
                "gh executable, config directory, and home must be absolute paths".to_owned(),
            ));
        }
        Ok(Self {
            executable,
            config_dir,
            home,
            timeout: Duration::from_secs(15),
        })
    }
}

#[async_trait]
trait GhExecutor: Send + Sync {
    async fn execute(
        &self,
        arguments: Vec<String>,
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialBrokerError>;
}

struct ProcessGhExecutor {
    runner: ProcessRunner,
    configuration: GhProcessConfiguration,
}

#[async_trait]
impl GhExecutor for ProcessGhExecutor {
    async fn execute(
        &self,
        arguments: Vec<String>,
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialBrokerError> {
        let mut command =
            CommandSpec::new(Program::Absolute(self.configuration.executable.clone()));
        command.arguments = arguments.into_iter().map(CommandArgument::plain).collect();
        command.environment = vec![
            EnvironmentVariable::plain(
                "GH_CONFIG_DIR",
                self.configuration.config_dir.to_string_lossy(),
            ),
            EnvironmentVariable::plain("HOME", self.configuration.home.to_string_lossy()),
            EnvironmentVariable::plain("GH_HOST", GITHUB_HOST),
            EnvironmentVariable::plain("GH_PROMPT_DISABLED", "1"),
            EnvironmentVariable::plain("GH_NO_UPDATE_NOTIFIER", "1"),
            EnvironmentVariable::plain("GH_PAGER", "cat"),
            EnvironmentVariable::plain("NO_COLOR", "1"),
        ];
        command.clear_environment = true;
        let mut outcome = self
            .runner
            .run(
                command,
                ProcessOptions {
                    stdout_capture_bytes: MAX_GITHUB_OUTPUT_BYTES,
                    stderr_capture_bytes: 64 * 1024,
                    output_channel_capacity: 1,
                    timeout: Some(self.configuration.timeout),
                    publish_output: false,
                    ..ProcessOptions::default()
                },
                cancellation,
            )
            .await?;
        let stderr = Zeroizing::new(std::mem::take(&mut outcome.stderr.bytes));
        if outcome.termination != TerminationReason::Exited {
            return Err(CredentialBrokerError::GitHubCommand(format!(
                "gh did not exit normally ({:?})",
                outcome.termination
            )));
        }
        if !outcome.status.success {
            return Err(CredentialBrokerError::GitHubCommand(format!(
                "gh exited unsuccessfully with code {:?}",
                outcome.status.code
            )));
        }
        if outcome.stdout.truncated_bytes != 0 || outcome.stderr.truncated_bytes != 0 {
            return Err(CredentialBrokerError::GitHubCommand(
                "gh output exceeded the configured capture limit".to_owned(),
            ));
        }
        drop(stderr);
        Ok(Zeroizing::new(std::mem::take(&mut outcome.stdout.bytes)))
    }
}

pub struct GhMetadataClient {
    executor: Arc<dyn GhExecutor>,
}

impl fmt::Debug for GhMetadataClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GhMetadataClient")
            .finish_non_exhaustive()
    }
}

impl GhMetadataClient {
    pub fn new(configuration: GhProcessConfiguration) -> Result<Self, CredentialBrokerError> {
        let resolver = SearchPathResolver::new(Vec::<PathBuf>::new())?;
        Ok(Self {
            executor: Arc::new(ProcessGhExecutor {
                runner: ProcessRunner::new(Arc::new(resolver)),
                configuration,
            }),
        })
    }

    #[cfg(test)]
    fn with_executor(executor: Arc<dyn GhExecutor>) -> Self {
        Self { executor }
    }

    async fn execute_json<T: for<'de> Deserialize<'de>>(
        &self,
        arguments: Vec<String>,
        cancellation: &CancellationToken,
    ) -> Result<T, CredentialBrokerError> {
        let mut bytes = self.executor.execute(arguments, cancellation).await?;
        let parsed = serde_json::from_slice(&bytes).map_err(|error| {
            CredentialBrokerError::InvalidGitHubMetadata(format!(
                "gh returned malformed JSON: {error}"
            ))
        });
        bytes.zeroize();
        parsed
    }
}

#[async_trait]
impl GitHubMetadataClient for GhMetadataClient {
    async fn repository(
        &self,
        identity: &RepositoryIdentity,
        cancellation: &CancellationToken,
    ) -> Result<GitHubRepository, CredentialBrokerError> {
        let response: SelectedResponse = self
            .execute_json(
                vec![
                    "api".to_owned(),
                    "graphql".to_owned(),
                    "-f".to_owned(),
                    format!("query={SELECTED_REPOSITORY_QUERY}"),
                    "-F".to_owned(),
                    format!("owner={}", identity.owner),
                    "-F".to_owned(),
                    format!("name={}", identity.name),
                ],
                cancellation,
            )
            .await?;
        let node = response
            .data
            .and_then(|data| data.repository)
            .ok_or_else(|| {
                CredentialBrokerError::InvalidGitHubMetadata(
                    "selected repository was not returned by GitHub".to_owned(),
                )
            })?;
        let repository = node.into_repository()?;
        if !repository.identity.same_repository(identity) {
            return Err(CredentialBrokerError::InvalidGitHubMetadata(
                "GitHub returned a different selected repository".to_owned(),
            ));
        }
        Ok(repository)
    }

    async fn accessible_non_public_repositories(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Vec<GitHubRepository>, CredentialBrokerError> {
        let mut repositories = Vec::new();
        let mut cursor = None::<String>;
        for _ in 0..MAX_GITHUB_PAGES {
            let mut arguments = vec![
                "api".to_owned(),
                "graphql".to_owned(),
                "-f".to_owned(),
                format!("query={ACCESSIBLE_REPOSITORIES_QUERY}"),
            ];
            if let Some(cursor) = &cursor {
                arguments.extend(["-f".to_owned(), format!("cursor={cursor}")]);
            }
            let response: AccessibleResponse = self.execute_json(arguments, cancellation).await?;
            let connection = response
                .data
                .map(|data| data.viewer.repositories)
                .ok_or_else(|| {
                    CredentialBrokerError::InvalidGitHubMetadata(
                        "GitHub repository pagination data is missing".to_owned(),
                    )
                })?;
            for node in connection.nodes {
                let repository = node.into_repository()?;
                if repository.visibility.is_non_public() {
                    repositories.push(repository);
                }
            }
            if !connection.page_info.has_next_page {
                repositories.sort_by(|left, right| left.identity.cmp(&right.identity));
                repositories.dedup_by(|left, right| {
                    left.identity.same_repository(&right.identity)
                        && left.visibility == right.visibility
                });
                return Ok(repositories);
            }
            let next = connection.page_info.end_cursor.ok_or_else(|| {
                CredentialBrokerError::InvalidGitHubMetadata(
                    "GitHub pagination requires a non-empty end cursor".to_owned(),
                )
            })?;
            if next.is_empty() || cursor.as_ref() == Some(&next) {
                return Err(CredentialBrokerError::InvalidGitHubMetadata(
                    "GitHub pagination cursor did not advance".to_owned(),
                ));
            }
            cursor = Some(next);
        }
        Err(CredentialBrokerError::InvalidGitHubMetadata(
            "GitHub repository pagination exceeded the hard page limit".to_owned(),
        ))
    }

    async fn auth_token(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<SecretValue, CredentialBrokerError> {
        let mut bytes = self
            .executor
            .execute(
                vec![
                    "auth".to_owned(),
                    "token".to_owned(),
                    "--hostname".to_owned(),
                    GITHUB_HOST.to_owned(),
                ],
                cancellation,
            )
            .await?;
        let token = trim_ascii_whitespace(&bytes);
        if token.is_empty() {
            return Err(CredentialBrokerError::GitHubCommand(
                "gh returned an empty authentication token".to_owned(),
            ));
        }
        let secret = SecretValue::new(token.to_vec())?;
        bytes.zeroize();
        Ok(secret)
    }
}

#[derive(Debug, Deserialize)]
struct SelectedResponse {
    data: Option<SelectedData>,
}

#[derive(Debug, Deserialize)]
struct SelectedData {
    repository: Option<RepositoryNode>,
}

#[derive(Debug, Deserialize)]
struct AccessibleResponse {
    data: Option<AccessibleData>,
}

#[derive(Debug, Deserialize)]
struct AccessibleData {
    viewer: Viewer,
}

#[derive(Debug, Deserialize)]
struct Viewer {
    repositories: RepositoryConnection,
}

#[derive(Debug, Deserialize)]
struct RepositoryConnection {
    nodes: Vec<RepositoryNode>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RepositoryNode {
    #[serde(rename = "nameWithOwner")]
    name_with_owner: String,
    visibility: RepositoryVisibility,
    owner: RepositoryOwner,
}

impl RepositoryNode {
    fn into_repository(self) -> Result<GitHubRepository, CredentialBrokerError> {
        let identity = RepositoryIdentity::parse(&self.name_with_owner)?;
        if !identity.owner.eq_ignore_ascii_case(&self.owner.login) {
            return Err(CredentialBrokerError::InvalidGitHubMetadata(
                "repository owner metadata is inconsistent".to_owned(),
            ));
        }
        let owner_kind = match self.owner.kind.as_str() {
            "Organization" => OwnerKind::Organization,
            "User" => OwnerKind::User,
            _ => {
                return Err(CredentialBrokerError::InvalidGitHubMetadata(
                    "repository owner type is unsupported".to_owned(),
                ));
            }
        };
        Ok(GitHubRepository {
            identity,
            visibility: self.visibility,
            owner_kind,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RepositoryOwner {
    login: String,
    #[serde(rename = "__typename")]
    kind: String,
}

fn valid_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;

    fn repository(
        owner: &str,
        name: &str,
        visibility: RepositoryVisibility,
        owner_kind: OwnerKind,
    ) -> GitHubRepository {
        GitHubRepository {
            identity: RepositoryIdentity {
                owner: owner.to_owned(),
                name: name.to_owned(),
            },
            visibility,
            owner_kind,
        }
    }

    struct FakeMetadata {
        selected: GitHubRepository,
        accessible: Vec<GitHubRepository>,
        token_calls: AtomicUsize,
    }

    #[async_trait]
    impl GitHubMetadataClient for FakeMetadata {
        async fn repository(
            &self,
            _identity: &RepositoryIdentity,
            _cancellation: &CancellationToken,
        ) -> Result<GitHubRepository, CredentialBrokerError> {
            Ok(self.selected.clone())
        }

        async fn accessible_non_public_repositories(
            &self,
            _cancellation: &CancellationToken,
        ) -> Result<Vec<GitHubRepository>, CredentialBrokerError> {
            Ok(self.accessible.clone())
        }

        async fn auth_token(
            &self,
            _cancellation: &CancellationToken,
        ) -> Result<SecretValue, CredentialBrokerError> {
            self.token_calls.fetch_add(1, Ordering::Relaxed);
            SecretValue::try_from("github-token").map_err(Into::into)
        }
    }

    fn github_configuration(
        forward_auth: bool,
        forward_copilot_auth: bool,
        allow_private_repository_access: bool,
    ) -> GitHubConfiguration {
        GitHubConfiguration {
            forward_auth,
            forward_copilot_auth,
            allow_private_repository_access,
            branch_protection: sendbox_config::BranchProtectionConfiguration::default(),
            ssh_key_path: None,
        }
    }

    #[test]
    fn repository_scope_matches_swift_policy() {
        let policy = RepositoryAccessPolicy::new();
        let source = repository(
            "acme",
            "source",
            RepositoryVisibility::Private,
            OwnerKind::Organization,
        );
        let same = repository(
            "ACME",
            "SOURCE",
            RepositoryVisibility::Private,
            OwnerKind::Organization,
        );
        assert_eq!(
            policy.evaluate_credential_scope(&source, &[same], false),
            RepositoryAccessDecision::Allow
        );

        let additional = repository(
            "ACME",
            "other",
            RepositoryVisibility::Private,
            OwnerKind::Organization,
        );
        assert!(matches!(
            policy.evaluate_credential_scope(&source, &[source.clone(), additional.clone()], false),
            RepositoryAccessDecision::Warn(_)
        ));
        assert_eq!(
            policy.evaluate_credential_scope(&source, &[source.clone(), additional], true),
            RepositoryAccessDecision::Allow
        );

        let cross_org = repository(
            "other",
            "private",
            RepositoryVisibility::Private,
            OwnerKind::Organization,
        );
        assert!(matches!(
            policy.evaluate_credential_scope(&source, &[source.clone(), cross_org], true),
            RepositoryAccessDecision::Deny(_)
        ));
    }

    #[test]
    fn user_owned_private_repositories_are_not_treated_as_an_organization() {
        let source = repository(
            "person",
            "source",
            RepositoryVisibility::Private,
            OwnerKind::User,
        );
        let additional = repository(
            "person",
            "other",
            RepositoryVisibility::Private,
            OwnerKind::User,
        );
        assert!(matches!(
            RepositoryAccessPolicy::new().evaluate(&source, &additional, true),
            RepositoryAccessDecision::Deny(_)
        ));
    }

    #[test]
    fn public_selected_repository_rejects_private_token_scope() {
        let source = repository(
            "person",
            "source",
            RepositoryVisibility::Public,
            OwnerKind::User,
        );
        let private = repository(
            "acme",
            "private",
            RepositoryVisibility::Private,
            OwnerKind::Organization,
        );
        assert!(matches!(
            RepositoryAccessPolicy::new().evaluate_credential_scope(&source, &[private], true),
            RepositoryAccessDecision::Deny(_)
        ));
    }

    #[tokio::test]
    async fn authorization_checks_scope_before_requesting_token() {
        let selected = repository(
            "acme",
            "source",
            RepositoryVisibility::Private,
            OwnerKind::Organization,
        );
        let client = FakeMetadata {
            selected: selected.clone(),
            accessible: vec![
                selected,
                repository(
                    "other",
                    "private",
                    RepositoryVisibility::Private,
                    OwnerKind::Organization,
                ),
            ],
            token_calls: AtomicUsize::new(0),
        };
        let error = authorize_github(
            &client,
            &RepositoryIdentity::parse("acme/source").expect("identity"),
            &github_configuration(true, false, true),
            None,
            &CancellationToken::new(),
        )
        .await
        .expect_err("cross-org scope");
        assert!(matches!(
            error,
            CredentialBrokerError::GitHubAuthorization(_)
        ));
        assert_eq!(client.token_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn copilot_credentials_are_independent_from_repository_auth() {
        let client = FakeMetadata {
            selected: repository(
                "person",
                "source",
                RepositoryVisibility::Public,
                OwnerKind::User,
            ),
            accessible: vec![],
            token_calls: AtomicUsize::new(0),
        };
        let authorization = authorize_github(
            &client,
            &RepositoryIdentity::parse("person/source").expect("identity"),
            &github_configuration(false, true, false),
            Some(SecretValue::try_from("copilot-token").expect("token")),
            &CancellationToken::new(),
        )
        .await
        .expect("authorization");
        assert!(authorization.credentials.github_token.is_none());
        assert_eq!(
            authorization
                .credentials
                .copilot_token
                .as_ref()
                .expect("copilot token")
                .expose_secret(),
            b"copilot-token"
        );
        assert_eq!(client.token_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn repository_identity_rejects_graphql_metacharacters() {
        assert!(RepositoryIdentity::parse("owner/repo\") { viewer { login } }").is_err());
    }

    struct FakeExecutor {
        outputs: Mutex<VecDeque<Result<Vec<u8>, CredentialBrokerError>>>,
        arguments: Mutex<Vec<Vec<String>>>,
    }

    #[async_trait]
    impl GhExecutor for FakeExecutor {
        async fn execute(
            &self,
            arguments: Vec<String>,
            _cancellation: &CancellationToken,
        ) -> Result<Zeroizing<Vec<u8>>, CredentialBrokerError> {
            self.arguments
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(arguments);
            self.outputs
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .pop_front()
                .expect("fake output")
                .map(Zeroizing::new)
        }
    }

    #[tokio::test]
    async fn gh_adapter_paginates_and_filters_non_public_repositories() {
        let executor = Arc::new(FakeExecutor {
            outputs: Mutex::new(VecDeque::from([
                Ok(br#"{"data":{"viewer":{"repositories":{"nodes":[{"nameWithOwner":"acme/private","visibility":"PRIVATE","owner":{"login":"acme","__typename":"Organization"}},{"nameWithOwner":"acme/public","visibility":"PUBLIC","owner":{"login":"acme","__typename":"Organization"}}],"pageInfo":{"hasNextPage":true,"endCursor":"cursor-1"}}}}}"#.to_vec()),
                Ok(br#"{"data":{"viewer":{"repositories":{"nodes":[{"nameWithOwner":"acme/internal","visibility":"INTERNAL","owner":{"login":"acme","__typename":"Organization"}}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}"#.to_vec()),
            ])),
            arguments: Mutex::new(Vec::new()),
        });
        let client = GhMetadataClient::with_executor(executor.clone());
        let repositories = client
            .accessible_non_public_repositories(&CancellationToken::new())
            .await
            .expect("repositories");
        assert_eq!(repositories.len(), 2);
        let arguments = executor
            .arguments
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(arguments.len(), 2);
        assert!(
            !arguments[0]
                .iter()
                .any(|argument| argument.contains("cursor="))
        );
        assert!(
            arguments[1]
                .iter()
                .any(|argument| argument == "cursor=cursor-1")
        );
    }

    #[tokio::test]
    async fn gh_adapter_rejects_malformed_and_stalled_pagination() {
        let malformed = Arc::new(FakeExecutor {
            outputs: Mutex::new(VecDeque::from([Ok(b"not-json".to_vec())])),
            arguments: Mutex::new(Vec::new()),
        });
        let error = GhMetadataClient::with_executor(malformed)
            .accessible_non_public_repositories(&CancellationToken::new())
            .await
            .expect_err("malformed");
        assert!(matches!(
            error,
            CredentialBrokerError::InvalidGitHubMetadata(_)
        ));

        let stalled = Arc::new(FakeExecutor {
            outputs: Mutex::new(VecDeque::from([
                Ok(br#"{"data":{"viewer":{"repositories":{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"same"}}}}}"#.to_vec()),
                Ok(br#"{"data":{"viewer":{"repositories":{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"same"}}}}}"#.to_vec()),
            ])),
            arguments: Mutex::new(Vec::new()),
        });
        let error = GhMetadataClient::with_executor(stalled)
            .accessible_non_public_repositories(&CancellationToken::new())
            .await
            .expect_err("stalled");
        assert!(matches!(
            error,
            CredentialBrokerError::InvalidGitHubMetadata(_)
        ));
    }

    #[tokio::test]
    async fn selected_repository_uses_graphql_variables_not_query_interpolation() {
        let executor = Arc::new(FakeExecutor {
            outputs: Mutex::new(VecDeque::from([Ok(
                br#"{"data":{"repository":{"nameWithOwner":"owner/repo","visibility":"PUBLIC","owner":{"login":"owner","__typename":"User"}}}}"#.to_vec(),
            )])),
            arguments: Mutex::new(Vec::new()),
        });
        let client = GhMetadataClient::with_executor(executor.clone());
        client
            .repository(
                &RepositoryIdentity::parse("owner/repo").expect("identity"),
                &CancellationToken::new(),
            )
            .await
            .expect("repository");
        let arguments = executor
            .arguments
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        assert!(
            arguments[0]
                .iter()
                .any(|argument| argument == "owner=owner")
        );
        assert!(arguments[0].iter().any(|argument| argument == "name=repo"));
        assert!(!SELECTED_REPOSITORY_QUERY.contains("owner/repo"));
    }

    #[tokio::test]
    async fn token_is_independent_and_redacted() {
        let executor = Arc::new(FakeExecutor {
            outputs: Mutex::new(VecDeque::from([Ok(b"raw-token\n".to_vec())])),
            arguments: Mutex::new(Vec::new()),
        });
        let token = GhMetadataClient::with_executor(executor)
            .auth_token(&CancellationToken::new())
            .await
            .expect("token");
        assert_eq!(token.expose_secret(), b"raw-token");
        assert!(!format!("{token:?}").contains("raw-token"));
    }
}
