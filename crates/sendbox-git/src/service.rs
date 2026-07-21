use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    BranchPolicy, BranchPolicyConfiguration, EnvironmentPolicy, GitProcessRunner, GlobalInvocation,
    GuardError, Operation, OperationArguments, ProcessRequest, RepositoryIdentity,
    TrustedGitBinary, WorkspaceIdentity, parse_alias_words, parse_invocation,
    parse_operation_arguments,
};

const MAX_ALIAS_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicySchemaVersion(u32);

impl PolicySchemaVersion {
    pub const V1: Self = Self(1);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardLimits {
    pub probe_timeout_ms: u64,
    pub probe_output_bytes: usize,
    pub policy_bytes: usize,
}

impl Default for GuardLimits {
    fn default() -> Self {
        Self {
            probe_timeout_ms: 2_000,
            probe_output_bytes: 256 * 1024,
            policy_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardPolicyDocument {
    pub schema_version: PolicySchemaVersion,
    pub selected_repository: RepositoryIdentity,
    pub selected_workspace: PathBuf,
    #[serde(default)]
    pub branch_protection: BranchPolicyConfiguration,
    #[serde(default)]
    pub environment: EnvironmentPolicy,
    #[serde(default)]
    pub limits: GuardLimits,
}

impl GuardPolicyDocument {
    pub fn validate(&self) -> Result<(), GuardError> {
        if self.schema_version != PolicySchemaVersion::V1 {
            return Err(GuardError::InvalidPolicy(
                "unsupported Git guard policy schema version".to_owned(),
            ));
        }
        if !self.selected_workspace.is_absolute() {
            return Err(GuardError::InvalidPolicy(
                "selected workspace must be absolute".to_owned(),
            ));
        }
        if self.limits.probe_timeout_ms == 0
            || self.limits.probe_output_bytes == 0
            || self.limits.policy_bytes == 0
        {
            return Err(GuardError::InvalidPolicy(
                "Git guard limits must be greater than zero".to_owned(),
            ));
        }
        BranchPolicy::compile(&self.branch_protection)?;
        self.environment.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    PassThrough { reason: &'static str },
    Guarded,
}

pub struct GuardService<R> {
    policy: GuardPolicyDocument,
    branches: BranchPolicy,
    workspace: WorkspaceIdentity,
    executable: TrustedGitBinary,
    runner: R,
    current_directory: PathBuf,
    environment: BTreeMap<String, String>,
}

impl<R: GitProcessRunner> GuardService<R> {
    pub fn new<I, K, V>(
        policy: GuardPolicyDocument,
        executable: TrustedGitBinary,
        runner: R,
        current_directory: impl Into<PathBuf>,
        environment: I,
    ) -> Result<Self, GuardError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        policy.validate()?;
        let branches = BranchPolicy::compile(&policy.branch_protection)?;
        let workspace = WorkspaceIdentity::capture(&policy.selected_workspace)?;
        let environment = policy.environment.sanitize(environment)?;
        let service = Self {
            policy,
            branches,
            workspace,
            executable,
            runner,
            current_directory: current_directory.into(),
            environment,
        };
        let version = service.required_value(&[], &["--version"], "Git version")?;
        if !version.starts_with("git version ") {
            return Err(GuardError::InvalidGitBinary {
                path: service.executable.path().to_owned(),
                reason: "binary did not identify itself as Git".to_owned(),
            });
        }
        Ok(service)
    }

    pub fn admit(&self, arguments: &[String]) -> Result<Admission, GuardError> {
        if !self.branches.enabled() {
            return Ok(Admission::PassThrough {
                reason: "branch protection disabled",
            });
        }
        let invocation = self.resolve_aliases(parse_invocation(arguments)?)?;
        let operation = match invocation.command.as_deref() {
            Some("push") => Operation::Push,
            Some("pull") => Operation::Pull,
            _ => {
                return Ok(Admission::PassThrough {
                    reason: "not a guarded Git operation",
                });
            }
        };
        let parsed = parse_operation_arguments(operation, &invocation.command_arguments)?;
        if parsed.help_requested {
            return Ok(Admission::PassThrough {
                reason: "Git help requested",
            });
        }
        if let Some(repository) = parsed.repository.as_deref()
            && self.resolve_remote_identity(&invocation.global_arguments, operation, repository)?
                != self.policy.selected_repository
        {
            return Ok(Admission::PassThrough {
                reason: "operation targets another repository",
            });
        }
        let current = self.required_value(
            &invocation.global_arguments,
            &["branch", "--show-current"],
            "allowed non-detached current branch",
        )?;
        let remote = parsed.repository.clone().unwrap_or(self.default_remote(
            &invocation.global_arguments,
            operation,
            &current,
        )?);
        let target = self.resolve_remote_identity(&invocation.global_arguments, operation, &remote);
        let root = self.optional_value(
            &invocation.global_arguments,
            &["rev-parse", "--show-toplevel"],
        )?;
        let selected_workspace = match root {
            Some(root) => self.workspace.matches_path(root)?,
            None => false,
        };
        match target {
            Ok(identity) if identity != self.policy.selected_repository => {
                return Ok(Admission::PassThrough {
                    reason: "operation targets another repository",
                });
            }
            Ok(_) => {}
            Err(_) if !selected_workspace => {
                return Err(GuardError::AmbiguousRepository);
            }
            Err(error) => return Err(error),
        }
        if invocation
            .global_arguments
            .iter()
            .any(|argument| argument == "--config-env" || argument.starts_with("--config-env="))
        {
            return Err(GuardError::denied(
                operation,
                "--config-env is unsupported because it can diverge probe configuration",
            ));
        }
        self.validate_global_configuration(&invocation.global_arguments, operation)?;
        if !invocation.unsupported_options.is_empty() {
            return Err(GuardError::denied(
                operation,
                "unsupported global Git option",
            ));
        }
        self.reject_external_configuration(&invocation.global_arguments, operation)?;
        self.branches.check(&current, operation, "current")?;
        if let Some(broad) = parsed.broad_option.as_deref() {
            return Err(GuardError::denied(
                operation,
                format!("option `{broad}` may update an unbounded set of refs"),
            ));
        }
        if !parsed.unsupported_options.is_empty() {
            return Err(GuardError::denied(
                operation,
                "unsupported Git operation option",
            ));
        }
        match operation {
            Operation::Push => {
                self.evaluate_push(&invocation.global_arguments, &remote, &parsed, &current)?;
            }
            Operation::Pull => {
                self.evaluate_pull(&invocation.global_arguments, &parsed, &current)?;
            }
        }
        Ok(Admission::Guarded)
    }

    pub fn execute(&self, arguments: &[String]) -> Result<(), GuardError> {
        self.admit(arguments)?;
        self.runner.execute(&self.request(arguments))
    }

    fn resolve_aliases(
        &self,
        mut invocation: GlobalInvocation,
    ) -> Result<GlobalInvocation, GuardError> {
        for _ in 0..MAX_ALIAS_DEPTH {
            let Some(command) = invocation.command.as_deref() else {
                return Ok(invocation);
            };
            if matches!(command, "push" | "pull") {
                return Ok(invocation);
            }
            let alias =
                self.config_value(&invocation.global_arguments, &format!("alias.{command}"))?;
            let Some(alias) = alias else {
                return Ok(invocation);
            };
            if alias.trim_start().starts_with('!') {
                return Err(GuardError::InvalidInvocation(format!(
                    "shell Git alias `{command}` is disabled"
                )));
            }
            let mut expansion = parse_alias_words(&alias)?;
            if expansion.is_empty() {
                return Err(GuardError::InvalidInvocation(format!(
                    "Git alias `{command}` is empty"
                )));
            }
            expansion.extend(invocation.command_arguments);
            let expanded = parse_invocation(&expansion)?;
            invocation
                .global_arguments
                .extend(expanded.global_arguments);
            invocation.command = expanded.command;
            invocation.command_arguments = expanded.command_arguments;
            invocation
                .unsupported_options
                .extend(expanded.unsupported_options);
        }
        Err(GuardError::InvalidInvocation(
            "Git alias expansion exceeded the safety limit".to_owned(),
        ))
    }

    fn evaluate_push(
        &self,
        globals: &[String],
        remote: &str,
        parsed: &OperationArguments,
        current: &str,
    ) -> Result<(), GuardError> {
        if self
            .config_value(globals, &format!("remote.{remote}.mirror"))?
            .as_deref()
            == Some("true")
        {
            return Err(GuardError::denied(
                Operation::Push,
                "mirror remote configuration is unsupported",
            ));
        }
        let mut refspecs = parsed.refspecs.clone();
        if parsed.delete {
            refspecs = refspecs
                .into_iter()
                .map(|destination| format!(":{destination}"))
                .collect();
        }
        if refspecs.is_empty() && remote_name(remote) {
            refspecs = self.config_values(globals, &format!("remote.{remote}.push"))?;
        }
        if refspecs.is_empty() {
            let mode = self
                .config_value(globals, "push.default")?
                .unwrap_or_else(|| "simple".to_owned());
            let destination = match mode.as_str() {
                "current" => current.to_owned(),
                "simple" => {
                    let upstream = self.upstream_branch(globals)?.ok_or_else(|| {
                        GuardError::denied(
                            Operation::Push,
                            "push.default=simple requires a resolvable upstream branch",
                        )
                    })?;
                    if upstream != current {
                        return Err(GuardError::denied(
                            Operation::Push,
                            "push.default=simple upstream branch differs from current branch",
                        ));
                    }
                    upstream
                }
                "upstream" | "tracking" => self.upstream_branch(globals)?.ok_or_else(|| {
                    GuardError::denied(Operation::Push, "the upstream branch cannot be resolved")
                })?,
                "matching" => {
                    return Err(GuardError::denied(
                        Operation::Push,
                        "push.default=matching may update multiple branches",
                    ));
                }
                "nothing" => {
                    return Err(GuardError::denied(
                        Operation::Push,
                        "push.default=nothing has no resolvable destination",
                    ));
                }
                _ => {
                    return Err(GuardError::denied(
                        Operation::Push,
                        "unsupported push.default mode",
                    ));
                }
            };
            refspecs.push(format!("HEAD:{destination}"));
        }
        for refspec in refspecs {
            let (source, destination) = parse_push_refspec(&refspec, current)?;
            if let Some(source) = source {
                if !self.branch_exists(globals, &source)? {
                    return Err(GuardError::denied(
                        Operation::Push,
                        format!("source branch `{source}` does not exist locally"),
                    ));
                }
                self.branches.check(&source, Operation::Push, "source")?;
            }
            self.branches
                .check(&destination, Operation::Push, "destination")?;
        }
        Ok(())
    }

    fn evaluate_pull(
        &self,
        globals: &[String],
        parsed: &OperationArguments,
        current: &str,
    ) -> Result<(), GuardError> {
        let mut refspecs = parsed.refspecs.clone();
        if refspecs.is_empty() {
            refspecs = self.config_values(globals, &format!("branch.{current}.merge"))?;
        }
        if refspecs.is_empty() {
            refspecs.push(self.upstream_branch(globals)?.ok_or_else(|| {
                GuardError::denied(Operation::Pull, "the upstream branch cannot be resolved")
            })?);
        }
        for refspec in refspecs {
            let source = refspec
                .trim_start_matches('+')
                .split_once(':')
                .map_or(refspec.as_str(), |(source, _)| source);
            self.branches.check(source, Operation::Pull, "source")?;
        }
        Ok(())
    }

    fn default_remote(
        &self,
        globals: &[String],
        operation: Operation,
        branch: &str,
    ) -> Result<String, GuardError> {
        let keys = match operation {
            Operation::Push => vec![
                format!("branch.{branch}.pushRemote"),
                "remote.pushDefault".to_owned(),
                format!("branch.{branch}.remote"),
            ],
            Operation::Pull => vec![format!("branch.{branch}.remote")],
        };
        for key in keys {
            if let Some(value) = self.config_value(globals, &key)? {
                return Ok(value);
            }
        }
        Ok("origin".to_owned())
    }

    fn upstream_branch(&self, globals: &[String]) -> Result<Option<String>, GuardError> {
        let upstream = self.optional_value(
            globals,
            &[
                "rev-parse",
                "--abbrev-ref",
                "--symbolic-full-name",
                "@{upstream}",
            ],
        )?;
        Ok(upstream.and_then(|value| {
            let value = value.strip_prefix("refs/remotes/").unwrap_or(&value);
            value.split_once('/').map_or_else(
                || Some(value.to_owned()),
                |(_, branch)| Some(branch.to_owned()),
            )
        }))
    }

    fn branch_exists(&self, globals: &[String], branch: &str) -> Result<bool, GuardError> {
        let mut complete = globals.to_vec();
        complete.extend([
            "show-ref".to_owned(),
            "--verify".to_owned(),
            "--quiet".to_owned(),
            format!("refs/heads/{branch}"),
        ]);
        let output = self.runner.query(&self.request(&complete))?;
        Ok(output.exit_code == Some(0))
    }

    fn resolve_remote_identity(
        &self,
        globals: &[String],
        operation: Operation,
        repository: &str,
    ) -> Result<RepositoryIdentity, GuardError> {
        let urls = if remote_name(repository) {
            let mut arguments = vec!["remote", "get-url", "--all"];
            if operation == Operation::Push {
                arguments.push("--push");
            }
            arguments.push(repository);
            self.values(globals, &arguments)?
        } else {
            vec![self.required_value(
                globals,
                &["ls-remote", "--get-url", repository],
                "effective remote URL",
            )?]
        };
        if urls.len() != 1 {
            return Err(GuardError::AmbiguousRepository);
        }
        let identities = urls
            .iter()
            .map(|url| RepositoryIdentity::parse(url, Some(self.policy.selected_repository.host())))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if identities.len() != 1 {
            return Err(GuardError::AmbiguousRepository);
        }
        identities
            .into_iter()
            .next()
            .ok_or(GuardError::AmbiguousRepository)
    }

    fn optional_value(
        &self,
        globals: &[String],
        arguments: &[&str],
    ) -> Result<Option<String>, GuardError> {
        Ok(self.values(globals, arguments)?.into_iter().next())
    }

    fn config_value(&self, globals: &[String], key: &str) -> Result<Option<String>, GuardError> {
        Ok(self.config_values(globals, key)?.into_iter().next())
    }

    fn config_values(&self, globals: &[String], key: &str) -> Result<Vec<String>, GuardError> {
        let mut complete = globals.to_vec();
        complete.extend([
            "config".to_owned(),
            "--null".to_owned(),
            "--get-all".to_owned(),
            key.to_owned(),
        ]);
        let output = self.runner.query(&self.request(&complete))?;
        if output.exit_code != Some(0) {
            return Ok(Vec::new());
        }
        let stdout = String::from_utf8(output.stdout).map_err(|_| {
            GuardError::UnresolvedState("Git config output is not UTF-8".to_owned())
        })?;
        Ok(stdout.split_terminator('\0').map(str::to_owned).collect())
    }

    fn validate_global_configuration(
        &self,
        globals: &[String],
        operation: Operation,
    ) -> Result<(), GuardError> {
        let mut index = 0;
        while index < globals.len() {
            let argument = &globals[index];
            if argument == "--exec-path" || argument.starts_with("--exec-path=") {
                return Err(GuardError::denied(
                    operation,
                    "--exec-path can replace Git transport helpers",
                ));
            }
            let override_value = if argument == "-c" {
                index += 1;
                globals.get(index).map(String::as_str)
            } else {
                argument
                    .strip_prefix("-c")
                    .filter(|value| !value.is_empty())
            };
            if let Some(override_value) = override_value
                && !safe_config_override(override_value)
            {
                return Err(GuardError::denied(
                    operation,
                    "Git -c override is outside the modeled branch-protection configuration",
                ));
            }
            index += 1;
        }
        Ok(())
    }

    fn reject_external_configuration(
        &self,
        globals: &[String],
        operation: Operation,
    ) -> Result<(), GuardError> {
        let mut helpers = Vec::new();
        for helper in self.config_values(globals, "credential.helper")? {
            if helper.is_empty() {
                helpers.clear();
            } else {
                helpers.push(helper);
            }
        }
        if !helpers.is_empty() {
            return Err(GuardError::denied(
                operation,
                "configured credential helpers require later credential-broker integration",
            ));
        }
        Ok(())
    }

    fn required_value(
        &self,
        globals: &[String],
        arguments: &[&str],
        label: &str,
    ) -> Result<String, GuardError> {
        self.optional_value(globals, arguments)?
            .ok_or_else(|| GuardError::UnresolvedState(format!("{label} is unavailable")))
    }

    fn values(&self, globals: &[String], arguments: &[&str]) -> Result<Vec<String>, GuardError> {
        let mut complete = globals.to_vec();
        complete.extend(arguments.iter().map(|argument| (*argument).to_owned()));
        let output = self.runner.query(&self.request(&complete))?;
        if output.exit_code != Some(0) {
            return Ok(Vec::new());
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|_| GuardError::UnresolvedState("Git probe output is not UTF-8".to_owned()))?;
        Ok(stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect())
    }

    fn request<'a>(&'a self, arguments: &'a [String]) -> ProcessRequest<'a> {
        ProcessRequest {
            executable: &self.executable,
            arguments,
            environment: &self.environment,
            current_directory: &self.current_directory,
            timeout: Duration::from_millis(self.policy.limits.probe_timeout_ms),
            output_limit: self.policy.limits.probe_output_bytes,
        }
    }
}

fn remote_name(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['/', '\\', ':'])
        && !value.starts_with('.')
        && !value.chars().any(char::is_whitespace)
}

fn safe_config_override(value: &str) -> bool {
    let Some((key, configured_value)) = value.split_once('=') else {
        return false;
    };
    if key.eq_ignore_ascii_case("push.default") || key.eq_ignore_ascii_case("remote.pushDefault") {
        return true;
    }
    if key.eq_ignore_ascii_case("credential.helper") {
        return configured_value.is_empty();
    }
    let lowercase = key.to_ascii_lowercase();
    (lowercase.starts_with("alias.") && lowercase.len() > "alias.".len())
        || modeled_subsection_key(&lowercase, "branch.", &[".remote", ".pushremote", ".merge"])
        || modeled_subsection_key(
            &lowercase,
            "remote.",
            &[".url", ".pushurl", ".push", ".mirror"],
        )
        || modeled_subsection_key(&lowercase, "url.", &[".insteadof", ".pushinsteadof"])
}

fn modeled_subsection_key(value: &str, prefix: &str, suffixes: &[&str]) -> bool {
    value.starts_with(prefix)
        && suffixes.iter().any(|suffix| {
            value.ends_with(suffix) && value.len() > prefix.len().saturating_add(suffix.len())
        })
}

pub fn parse_push_refspec(
    refspec: &str,
    current: &str,
) -> Result<(Option<String>, String), GuardError> {
    let value = refspec.trim_start_matches('+');
    if value.is_empty() || value.starts_with('^') || value.contains(['*', '?']) {
        return Err(GuardError::denied(
            Operation::Push,
            "unsupported push refspec",
        ));
    }
    let (source, destination) = value.split_once(':').unwrap_or((value, value));
    let source = match source {
        "" => None,
        "HEAD" | "@" => Some(current.to_owned()),
        source => Some(normalize_push_source(source)?),
    };
    let destination = match destination {
        "HEAD" | "@" => current.to_owned(),
        destination if destination == value && source.is_some() => {
            source.clone().unwrap_or_default()
        }
        destination => destination.to_owned(),
    };
    if destination.starts_with("refs/") && !destination.starts_with("refs/heads/") {
        return Err(GuardError::denied(
            Operation::Push,
            "push destination is not a branch ref",
        ));
    }
    if destination.is_empty() {
        return Err(GuardError::denied(
            Operation::Push,
            "push destination is empty",
        ));
    }
    Ok((source, destination))
}

fn normalize_push_source(source: &str) -> Result<String, GuardError> {
    if let Some(branch) = source.strip_prefix("refs/heads/") {
        return Ok(branch.to_owned());
    }
    if source.starts_with("refs/") || source.contains(['~', '^']) {
        return Err(GuardError::denied(
            Operation::Push,
            "push source is not a local branch",
        ));
    }
    Ok(source.to_owned())
}

#[cfg(test)]
mod tests {
    use super::parse_push_refspec;

    #[test]
    fn parses_force_delete_and_head_refspecs() {
        assert_eq!(
            parse_push_refspec("+HEAD:refs/heads/feature/a", "feature/a").unwrap(),
            (
                Some("feature/a".to_owned()),
                "refs/heads/feature/a".to_owned()
            )
        );
        assert_eq!(
            parse_push_refspec(":refs/heads/main", "feature/a").unwrap(),
            (None, "refs/heads/main".to_owned())
        );
        assert!(parse_push_refspec("refs/heads/*:refs/heads/*", "feature/a").is_err());
    }
}
