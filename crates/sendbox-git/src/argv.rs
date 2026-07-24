use crate::GuardError;

const GLOBAL_VALUE_OPTIONS: &[&str] = &[
    "-C",
    "-c",
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
];
const GLOBAL_FLAG_OPTIONS: &[&str] = &[
    "--bare",
    "--glob-pathspecs",
    "--help",
    "--html-path",
    "--icase-pathspecs",
    "--info-path",
    "--literal-pathspecs",
    "--man-path",
    "--no-advice",
    "--no-optional-locks",
    "--no-pager",
    "--no-replace-objects",
    "--noglob-pathspecs",
    "--paginate",
    "--version",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Push,
    Pull,
}

impl Operation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Pull => "pull",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalInvocation {
    pub global_arguments: Vec<String>,
    pub command: Option<String>,
    pub command_arguments: Vec<String>,
    pub unsupported_options: Vec<String>,
}

pub fn parse_invocation(arguments: &[String]) -> Result<GlobalInvocation, GuardError> {
    let mut global_arguments = Vec::new();
    let mut unsupported_options = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            index += 1;
            break;
        }
        if GLOBAL_VALUE_OPTIONS.contains(&argument.as_str()) {
            let value = arguments.get(index + 1).ok_or_else(|| {
                GuardError::InvalidInvocation(format!(
                    "Git option `{argument}` is missing its value"
                ))
            })?;
            global_arguments.extend([argument.clone(), value.clone()]);
            index += 2;
            continue;
        }
        if global_value_prefix(argument).is_some() || compact_global_value(argument) {
            global_arguments.push(argument.clone());
            index += 1;
            continue;
        }
        if GLOBAL_FLAG_OPTIONS.contains(&argument.as_str()) {
            global_arguments.push(argument.clone());
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            unsupported_options.push(argument.clone());
            global_arguments.push(argument.clone());
            index += 1;
            continue;
        }
        return Ok(GlobalInvocation {
            global_arguments,
            command: Some(argument.clone()),
            command_arguments: arguments[index + 1..].to_vec(),
            unsupported_options,
        });
    }
    Ok(GlobalInvocation {
        global_arguments,
        command: arguments.get(index).cloned(),
        command_arguments: arguments.get(index + 1..).unwrap_or_default().to_vec(),
        unsupported_options,
    })
}

fn global_value_prefix(argument: &str) -> Option<&'static str> {
    GLOBAL_VALUE_OPTIONS
        .iter()
        .copied()
        .filter(|option| option.starts_with("--"))
        .find(|option| argument.starts_with(&format!("{option}=")))
}

fn compact_global_value(argument: &str) -> bool {
    (argument.starts_with("-C") || argument.starts_with("-c")) && argument.len() > 2
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationArguments {
    pub repository: Option<String>,
    pub refspecs: Vec<String>,
    pub broad_option: Option<String>,
    pub unsupported_options: Vec<String>,
    pub help_requested: bool,
    pub delete: bool,
}

pub fn parse_operation_arguments(
    operation: Operation,
    arguments: &[String],
) -> Result<OperationArguments, GuardError> {
    let mut repository_option = None;
    let mut positionals = Vec::new();
    let mut broad_option = None;
    let mut unsupported_options = Vec::new();
    let mut help_requested = false;
    let mut delete = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if matches!(argument.as_str(), "-h" | "--help") {
            help_requested = true;
            index += 1;
            continue;
        }
        if argument == "--" {
            positionals.extend_from_slice(&arguments[index + 1..]);
            break;
        }
        if broad_options(operation).contains(&argument.as_str()) {
            broad_option = Some(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--delete" {
            delete = true;
            index += 1;
            continue;
        }
        if argument == "--repo" {
            let value = arguments.get(index + 1).ok_or_else(|| {
                GuardError::InvalidInvocation("Git --repo is missing its value".to_owned())
            })?;
            repository_option = Some(value.clone());
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--repo=") {
            if value.is_empty() {
                return Err(GuardError::InvalidInvocation(
                    "Git --repo is missing its value".to_owned(),
                ));
            }
            repository_option = Some(value.to_owned());
            index += 1;
            continue;
        }
        if value_options(operation).contains(&argument.as_str()) {
            if arguments.get(index + 1).is_none() {
                return Err(GuardError::InvalidInvocation(format!(
                    "Git {} option `{argument}` is missing its value",
                    operation.as_str()
                )));
            }
            index += 2;
            continue;
        }
        if long_value_option(operation, argument) || compact_value_option(operation, argument) {
            index += 1;
            continue;
        }
        if flag_options(operation).contains(&argument.as_str())
            || optional_value_option(operation, argument)
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            unsupported_options.push(argument.clone());
            index += 1;
            continue;
        }
        positionals.push(argument.clone());
        index += 1;
    }
    let repository = repository_option.or_else(|| {
        if positionals.is_empty() {
            None
        } else {
            Some(positionals.remove(0))
        }
    });
    Ok(OperationArguments {
        repository,
        refspecs: positionals,
        broad_option,
        unsupported_options,
        help_requested,
        delete,
    })
}

fn value_options(operation: Operation) -> &'static [&'static str] {
    match operation {
        Operation::Push => &["--exec", "--push-option", "--receive-pack", "-o"],
        Operation::Pull => &[
            "--deepen",
            "--depth",
            "--jobs",
            "--negotiation-tip",
            "--recurse-submodules",
            "--server-option",
            "--shallow-exclude",
            "--shallow-since",
            "--strategy",
            "--strategy-option",
            "--upload-pack",
            "-X",
            "-j",
            "-s",
        ],
    }
}

fn flag_options(operation: Operation) -> &'static [&'static str] {
    match operation {
        Operation::Push => &[
            "--atomic",
            "--dry-run",
            "--force",
            "--force-if-includes",
            "--ipv4",
            "--ipv6",
            "--no-signed",
            "--no-thin",
            "--no-verify",
            "--porcelain",
            "--progress",
            "--quiet",
            "--set-upstream",
            "--thin",
            "--verbose",
            "-f",
            "-q",
            "-u",
            "-v",
        ],
        Operation::Pull => &[
            "--allow-unrelated-histories",
            "--autostash",
            "--commit",
            "--dry-run",
            "--edit",
            "--ff",
            "--ff-only",
            "--force",
            "--gpg-sign",
            "--ipv4",
            "--ipv6",
            "--log",
            "--no-autostash",
            "--no-commit",
            "--no-edit",
            "--no-ff",
            "--no-log",
            "--no-rebase",
            "--no-signoff",
            "--no-stat",
            "--no-tags",
            "--no-verify-signatures",
            "--progress",
            "--quiet",
            "--rebase",
            "--show-forced-updates",
            "--signoff",
            "--stat",
            "--tags",
            "--update-head-ok",
            "--verbose",
            "-f",
            "-n",
            "-q",
            "-r",
            "-v",
        ],
    }
}

fn broad_options(operation: Operation) -> &'static [&'static str] {
    match operation {
        Operation::Push => &[
            "--all",
            "--branches",
            "--follow-tags",
            "--mirror",
            "--prune",
            "--tags",
        ],
        Operation::Pull => &["--all"],
    }
}

fn long_value_option(operation: Operation, argument: &str) -> bool {
    value_options(operation)
        .iter()
        .filter(|option| option.starts_with("--"))
        .any(|option| argument.starts_with(&format!("{option}=")))
        || matches!(argument, value if value.starts_with("--force-with-lease="))
        || matches!(argument, value if value.starts_with("--signed="))
        || matches!(argument, value if value.starts_with("--gpg-sign="))
        || matches!(argument, value if value.starts_with("--log="))
        || matches!(argument, value if value.starts_with("--rebase="))
}

fn compact_value_option(operation: Operation, argument: &str) -> bool {
    match operation {
        Operation::Push => argument.starts_with("-o") && argument.len() > 2,
        Operation::Pull => ["-X", "-j", "-s"]
            .iter()
            .any(|option| argument.starts_with(option) && argument.len() > 2),
    }
}

fn optional_value_option(operation: Operation, argument: &str) -> bool {
    match operation {
        Operation::Push => {
            matches!(
                argument,
                "--force-with-lease" | "--recurse-submodules" | "--signed"
            ) || argument.starts_with("--recurse-submodules=")
        }
        Operation::Pull => false,
    }
}

pub fn parse_alias_words(value: &str) -> Result<Vec<String>, GuardError> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = value.chars().peekable();
    let mut quote = None;
    while let Some(character) = chars.next() {
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                } else {
                    current.push(character);
                }
            }
            Some('"') => match character {
                '"' => quote = None,
                '\\' => {
                    let escaped = chars.next().ok_or_else(|| {
                        GuardError::InvalidInvocation(
                            "Git alias ends with an incomplete escape".to_owned(),
                        )
                    })?;
                    current.push(escaped);
                }
                _ => current.push(character),
            },
            Some(_) => unreachable!("only supported quote states are stored"),
            None => match character {
                '\'' | '"' => quote = Some(character),
                '\\' => {
                    let escaped = chars.next().ok_or_else(|| {
                        GuardError::InvalidInvocation(
                            "Git alias ends with an incomplete escape".to_owned(),
                        )
                    })?;
                    current.push(escaped);
                }
                value if value.is_whitespace() => {
                    if !current.is_empty() {
                        words.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(character),
            },
        }
    }
    if quote.is_some() {
        return Err(GuardError::InvalidInvocation(
            "Git alias contains an unterminated quote".to_owned(),
        ));
    }
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{Operation, parse_alias_words, parse_invocation, parse_operation_arguments};

    #[test]
    fn parses_global_options_and_push_repository() {
        let invocation = parse_invocation(&[
            "-C".to_owned(),
            "/workspace".to_owned(),
            "-c".to_owned(),
            "push.default=current".to_owned(),
            "push".to_owned(),
            "--repo=origin".to_owned(),
            "HEAD:refs/heads/feature/a".to_owned(),
        ])
        .unwrap();
        assert_eq!(invocation.command.as_deref(), Some("push"));
        let operation =
            parse_operation_arguments(Operation::Push, &invocation.command_arguments).unwrap();
        assert_eq!(operation.repository.as_deref(), Some("origin"));
        assert_eq!(operation.refspecs, ["HEAD:refs/heads/feature/a"]);
    }

    #[test]
    fn parses_quoted_alias_without_shell_expansion() {
        assert_eq!(
            parse_alias_words(r#"push -c "value with spaces" 'literal*'"#).unwrap(),
            ["push", "-c", "value with spaces", "literal*"]
        );
        assert!(parse_alias_words("push 'unterminated").is_err());
    }

    proptest! {
        #[test]
        fn argv_and_alias_parsers_never_panic(arguments in proptest::collection::vec(any::<String>(), 0..32), alias in any::<String>()) {
            let _ = parse_invocation(&arguments);
            let _ = parse_alias_words(&alias);
            let _ = parse_operation_arguments(Operation::Push, &arguments);
            let _ = parse_operation_arguments(Operation::Pull, &arguments);
        }
    }
}
