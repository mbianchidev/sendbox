#![forbid(unsafe_code)]

mod completions;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use completions::CompletionShell;
use sendbox_config::{
    ConfigurationError, MigrationReport, PolicyPreset, RuntimeProvider, SandboxConfiguration,
};
use sendbox_core::{CONFIG_SCHEMA_VERSION, Diagnostic, DiagnosticCode, VERSION};
use sendbox_project::{
    Analyzer, DevContainerOverrides, ProjectError, ScanLimits, write_devcontainer,
};
use serde::Serialize;
use serde_json::Value;

const INVALID_CONFIGURATION_EXIT: u8 = 2;
const ANALYSIS_EXIT: u8 = 3;
const OUTPUT_EXIT: u8 = 4;

#[derive(Debug, Parser)]
#[command(
    name = "sendbox",
    bin_name = "sendbox",
    version = VERSION,
    about = "Secure hardware-isolated sandbox for AI agents"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Analyze(AnalyzeArgs),
    Completions(CompletionsArgs),
    Devcontainer(Box<DevContainerArgs>),
    Init(InitArgs),
    Policy(PolicyArgs),
}

#[derive(Debug, Args)]
struct AnalyzeArgs {
    #[command(flatten)]
    scan: ScanArgs,
    #[arg(long, help = "Emit the complete deterministic JSON analysis")]
    json: bool,
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(long, value_name = "PATH", default_value = ".")]
    project: PathBuf,
    #[arg(long, default_value_t = 12)]
    max_depth: usize,
    #[arg(long, default_value_t = 4096)]
    max_files: usize,
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    max_bytes: u64,
    #[arg(long, default_value_t = 1024 * 1024)]
    max_file_bytes: u64,
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long, value_name = "PATH", default_value = ".")]
    project: PathBuf,
    #[arg(long, value_enum, default_value_t = PolicyPresetArg::Default)]
    policy: PolicyPresetArg,
    #[arg(long, value_enum, default_value_t = RuntimeArg::Auto)]
    runtime: RuntimeArg,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PolicyPresetArg {
    Default,
    Permissive,
    Strict,
}

impl PolicyPresetArg {
    fn value(self) -> PolicyPreset {
        match self {
            Self::Default => PolicyPreset::Default,
            Self::Permissive => PolicyPreset::Permissive,
            Self::Strict => PolicyPreset::Strict,
        }
    }
}

impl std::fmt::Display for PolicyPresetArg {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Default => "default",
            Self::Permissive => "permissive",
            Self::Strict => "strict",
        })
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RuntimeArg {
    Auto,
    Apple,
    Kata,
    Hyperlight,
}

impl RuntimeArg {
    fn value(self) -> RuntimeProvider {
        match self {
            Self::Auto => RuntimeProvider::Auto,
            Self::Apple => RuntimeProvider::Apple,
            Self::Kata => RuntimeProvider::Kata,
            Self::Hyperlight => RuntimeProvider::Hyperlight,
        }
    }
}

impl std::fmt::Display for RuntimeArg {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Apple => "apple",
            Self::Kata => "kata",
            Self::Hyperlight => "hyperlight",
        })
    }
}

#[derive(Debug, Args)]
struct DevContainerArgs {
    #[command(subcommand)]
    command: DevContainerCommand,
}

#[derive(Debug, Subcommand)]
enum DevContainerCommand {
    Generate(GenerateArgs),
}

#[derive(Debug, Args)]
struct GenerateArgs {
    #[command(flatten)]
    scan: ScanArgs,
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    image: Option<String>,
    #[arg(long = "feature", value_parser = parse_json_entry, value_name = "ID[=JSON]")]
    features: Vec<(String, Value)>,
    #[arg(long = "extension", value_name = "ID")]
    extensions: Vec<String>,
    #[arg(long = "setting", value_parser = parse_json_entry, value_name = "KEY=JSON")]
    settings: Vec<(String, Value)>,
    #[arg(long = "forward-port", value_name = "PORT")]
    forward_ports: Vec<u16>,
    #[arg(long)]
    post_create_command: Option<String>,
    #[arg(long)]
    remote_user: Option<String>,
    #[arg(long = "container-env", value_parser = parse_string_entry, value_name = "KEY=VALUE")]
    container_env: Vec<(String, String)>,
    #[arg(long, help = "Emit the generated path and complete spec as JSON")]
    json: bool,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Show(ShowArgs),
    Validate(ValidateArgs),
}

#[derive(Debug, Args)]
struct ShowArgs {
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    #[arg(long, help = "Emit the effective policy as deterministic JSON")]
    json: bool,
}

#[derive(Debug, Args)]
struct ValidateArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
}

#[derive(Debug, Args)]
struct CompletionsArgs {
    #[command(subcommand)]
    command: Option<CompletionsCommand>,
}

#[derive(Debug, Subcommand)]
enum CompletionsCommand {
    Install(CompletionInstallArgs),
    Print(CompletionPrintArgs),
}

#[derive(Debug, Args)]
struct CompletionInstallArgs {
    #[arg(long, value_enum)]
    shell: Option<CompletionShell>,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
}

#[derive(Debug, Args)]
struct CompletionPrintArgs {
    #[arg(long, value_enum, default_value_t = CompletionShell::Bash)]
    shell: CompletionShell,
}

#[derive(Debug, Serialize)]
struct ValidationResult<'a> {
    schema_version: u32,
    valid: bool,
    config: String,
    sandbox: Option<&'a str>,
    runtime: Option<RuntimeProvider>,
    configuration: Option<&'a SandboxConfiguration>,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Serialize)]
struct CliFailure {
    schema_version: u32,
    ok: bool,
    exit_code: u8,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Serialize)]
struct InitResult<'a> {
    schema_version: u32,
    ok: bool,
    config: &'a str,
    project: &'a str,
    sandbox: &'a str,
    policy: &'a str,
    runtime: &'a str,
}

#[derive(Debug, Serialize)]
struct PolicyShowResult<'a> {
    schema_version: u32,
    source: &'a str,
    config: Option<&'a str>,
    migration: Option<&'a MigrationReport>,
    policy: &'a sendbox_policy::PolicyConfiguration,
}

#[derive(Debug, Serialize)]
struct CompletionInstallResult<'a> {
    schema_version: u32,
    ok: bool,
    shell: &'a str,
    path: &'a str,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Analyze(arguments) => analyze(arguments),
        Command::Completions(arguments) => completions(arguments),
        Command::Devcontainer(arguments) => match arguments.command {
            DevContainerCommand::Generate(arguments) => generate_devcontainer(arguments),
        },
        Command::Init(arguments) => init(arguments),
        Command::Policy(policy) => match policy.command {
            PolicyCommand::Show(arguments) => show_policy(arguments),
            PolicyCommand::Validate(arguments) => validate(arguments),
        },
    }
}

fn init(arguments: InitArgs) -> ExitCode {
    let project = match canonical_project(&arguments.project) {
        Ok(project) => project,
        Err(diagnostic) => {
            return emit_diagnostics(arguments.json, INVALID_CONFIGURATION_EXIT, vec![diagnostic]);
        }
    };
    let config_path = project.join(".sendbox.yaml");
    let configuration = SandboxConfiguration::for_project(
        project.clone(),
        arguments.policy.value(),
        arguments.runtime.value(),
    );

    if let Err(error) =
        configuration.write(&config_path, sendbox_config::AtomicWriteMode::CreateNew)
    {
        let diagnostics = if matches!(
            &error,
            ConfigurationError::Write { source, .. }
                if source.kind() == io::ErrorKind::AlreadyExists
        ) {
            vec![Diagnostic::new(
                DiagnosticCode::Io,
                config_path.display().to_string(),
                "configuration already exists; refusing to overwrite it",
            )]
        } else {
            configuration_error_diagnostics(error)
        };
        return emit_diagnostics(arguments.json, OUTPUT_EXIT, diagnostics);
    }

    let config = config_path.display().to_string();
    let project = project.display().to_string();
    if arguments.json {
        print_json(&InitResult {
            schema_version: CONFIG_SCHEMA_VERSION,
            ok: true,
            config: &config,
            project: &project,
            sandbox: &configuration.name,
            policy: &arguments.policy.to_string(),
            runtime: &arguments.runtime.to_string(),
        });
    } else {
        println!("created configuration: {config}");
        println!("project: {project}");
        println!("policy: {}", arguments.policy);
        println!("runtime: {}", arguments.runtime);
    }
    ExitCode::SUCCESS
}

fn canonical_project(path: &Path) -> Result<PathBuf, Diagnostic> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Diagnostic::new(
            DiagnosticCode::InvalidPath,
            path.display().to_string(),
            format!("could not resolve project directory: {error}"),
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        Diagnostic::new(
            DiagnosticCode::InvalidPath,
            canonical.display().to_string(),
            format!("could not inspect project directory: {error}"),
        )
    })?;
    if !metadata.is_dir() {
        return Err(Diagnostic::new(
            DiagnosticCode::InvalidPath,
            canonical.display().to_string(),
            "project path is not a directory",
        ));
    }
    Ok(canonical)
}

fn analyze(arguments: AnalyzeArgs) -> ExitCode {
    let project = arguments.scan.project.display().to_string();
    match analyzer(&arguments.scan).analyze(&arguments.scan.project) {
        Ok(analysis) => {
            if arguments.json {
                print_json(&analysis);
            } else {
                println!("language: {}", analysis.language);
                if let Some(framework) = analysis.framework {
                    println!("framework: {framework}");
                }
                if let Some(package_manager) = analysis.package_manager {
                    println!("package manager: {package_manager}");
                }
                println!(
                    "scan: {} files, {} bytes, {} skipped, {} errors",
                    analysis.scan.files_seen,
                    analysis.scan.bytes_read,
                    analysis.scan.skipped.len(),
                    analysis.scan.errors.len()
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_project_error(arguments.json, ANALYSIS_EXIT, &project, &error),
    }
}

fn generate_devcontainer(arguments: GenerateArgs) -> ExitCode {
    let project = arguments.scan.project.display().to_string();
    let analysis = match analyzer(&arguments.scan).analyze(&arguments.scan.project) {
        Ok(analysis) => analysis,
        Err(error) => {
            return emit_project_error(arguments.json, ANALYSIS_EXIT, &project, &error);
        }
    };
    let overrides = DevContainerOverrides {
        name: arguments.name,
        image: arguments.image,
        features: arguments.features.into_iter().collect(),
        extensions: arguments.extensions,
        settings: arguments.settings.into_iter().collect(),
        forward_ports: arguments.forward_ports,
        post_create_command: arguments.post_create_command,
        remote_user: arguments.remote_user,
        container_env: arguments.container_env.into_iter().collect(),
    };
    match write_devcontainer(
        &arguments.scan.project,
        arguments.output.as_deref(),
        &analysis,
        &overrides,
    ) {
        Ok(generated) => {
            if arguments.json {
                print_json(&generated);
            } else {
                println!("{}", generated.path.display());
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_project_error(arguments.json, OUTPUT_EXIT, &project, &error),
    }
}

fn analyzer(arguments: &ScanArgs) -> Analyzer {
    Analyzer::new(ScanLimits {
        max_depth: arguments.max_depth,
        max_files: arguments.max_files,
        max_bytes: arguments.max_bytes,
        max_file_bytes: arguments.max_file_bytes,
    })
}

#[derive(Debug, Serialize)]
struct ProjectFailure<'a> {
    ok: bool,
    exit_code: u8,
    project: &'a str,
    error: String,
}

fn emit_project_error(json: bool, exit_code: u8, project: &str, error: &ProjectError) -> ExitCode {
    if json {
        print_json(&ProjectFailure {
            ok: false,
            exit_code,
            project,
            error: error.to_string(),
        });
    } else {
        eprintln!("{error}");
    }
    ExitCode::from(exit_code)
}

fn show_policy(arguments: ShowArgs) -> ExitCode {
    let display_path = arguments
        .config
        .as_ref()
        .map(|path| path.display().to_string());
    let (policy, migration, source) = match &arguments.config {
        Some(path) => match SandboxConfiguration::load_with_migration(path) {
            Ok(loaded) => (
                loaded.configuration.policy,
                Some(loaded.migration),
                "config",
            ),
            Err(error) => {
                return emit_diagnostics(
                    arguments.json,
                    INVALID_CONFIGURATION_EXIT,
                    configuration_error_diagnostics(error),
                );
            }
        },
        None => (PolicyPreset::Default.configuration(), None, "default"),
    };
    if let Err(error) = policy.validate() {
        return emit_diagnostics(
            arguments.json,
            INVALID_CONFIGURATION_EXIT,
            error.into_diagnostics(),
        );
    }

    if arguments.json {
        print_json(&PolicyShowResult {
            schema_version: CONFIG_SCHEMA_VERSION,
            source,
            config: display_path.as_deref(),
            migration: migration.as_ref(),
            policy: &policy,
        });
    } else {
        if let Some(path) = display_path {
            println!("policy from: {path}");
        } else {
            println!("default policy");
        }
        print_policy(&policy);
    }
    ExitCode::SUCCESS
}

fn print_policy(policy: &sendbox_policy::PolicyConfiguration) {
    println!();
    println!("Command Policy:");
    println!(
        "  Default action: {}",
        action_name(policy.commands.default_action)
    );
    println!("  Log blocked:    {}", policy.commands.log_blocked);
    print_list("  Allowlist:", "+", &policy.commands.allowlist);
    print_list("  Denylist:", "-", &policy.commands.denylist);

    println!();
    println!("Network Policy:");
    println!(
        "  Default action: {}",
        action_name(policy.network.default_action)
    );
    println!("  Allow DNS:      {}", policy.network.allow_dns);
    if let Some(max_connections) = policy.network.max_connections {
        println!("  Max connections: {max_connections}");
    }
    print_list("  Allowed domains:", "+", &policy.network.allowed_domains);
    print_list("  Blocked domains:", "-", &policy.network.blocked_domains);

    println!();
    println!("Boundary Policy:");
    println!("  Enabled:        {}", policy.boundaries.enabled);
    println!(
        "  MCP transport:  {}",
        match policy.boundaries.tool_calls.transport {
            sendbox_policy::ToolTransport::Stdio => "stdio",
        }
    );
    println!(
        "  Tool default:    {}",
        action_name(policy.boundaries.tool_calls.default_action)
    );
    println!(
        "  Max frame bytes: {}",
        policy.boundaries.tool_calls.max_frame_bytes
    );
    println!("  Log path:       {}", policy.boundaries.log_path);
    print_list(
        "  Tool allowlist:",
        "+",
        &policy.boundaries.tool_calls.allowlist,
    );
    print_list(
        "  Tool denylist:",
        "-",
        &policy.boundaries.tool_calls.denylist,
    );
    print_list(
        "  Additional denied syscalls:",
        "-",
        &policy.boundaries.syscalls.additional_denylist,
    );
    if !policy
        .boundaries
        .tool_calls
        .allowed_server_commands
        .is_empty()
    {
        println!("  Allowed MCP server commands:");
        for command in &policy.boundaries.tool_calls.allowed_server_commands {
            println!("    + {}", command.join(" "));
        }
    }
}

fn print_list(heading: &str, marker: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    println!("{heading}");
    for value in values {
        println!("    {marker} {value}");
    }
}

fn action_name(action: sendbox_policy::Action) -> &'static str {
    match action {
        sendbox_policy::Action::Allow => "allow",
        sendbox_policy::Action::Deny => "deny",
    }
}

fn validate(arguments: ValidateArgs) -> ExitCode {
    let display_path = arguments.config.display().to_string();
    match SandboxConfiguration::load(&arguments.config) {
        Ok(configuration) => match configuration.validate() {
            Ok(()) => {
                if arguments.json {
                    print_json(&ValidationResult {
                        schema_version: CONFIG_SCHEMA_VERSION,
                        valid: true,
                        config: display_path,
                        sandbox: Some(&configuration.name),
                        runtime: configuration
                            .runtime
                            .as_ref()
                            .map(|runtime| runtime.provider),
                        configuration: Some(&configuration),
                        diagnostics: Vec::new(),
                    });
                } else {
                    println!(
                        "valid configuration: {} (sandbox: {})",
                        arguments.config.display(),
                        configuration.name
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                emit_validation_failure(
                    arguments.json,
                    display_path,
                    Some(&configuration),
                    error.into_diagnostics(),
                );
                ExitCode::from(INVALID_CONFIGURATION_EXIT)
            }
        },
        Err(error) => {
            emit_validation_failure(
                arguments.json,
                display_path,
                None,
                configuration_error_diagnostics(error),
            );
            ExitCode::from(INVALID_CONFIGURATION_EXIT)
        }
    }
}

fn emit_validation_failure(
    json: bool,
    config: String,
    configuration: Option<&SandboxConfiguration>,
    diagnostics: Vec<Diagnostic>,
) {
    if json {
        print_json(&ValidationResult {
            schema_version: CONFIG_SCHEMA_VERSION,
            valid: false,
            config,
            sandbox: configuration.map(|value| value.name.as_str()),
            runtime: configuration
                .and_then(|value| value.runtime.as_ref())
                .map(|runtime| runtime.provider),
            configuration,
            diagnostics,
        });
    } else {
        print_diagnostics(&diagnostics);
    }
}

fn completions(arguments: CompletionsArgs) -> ExitCode {
    match arguments
        .command
        .unwrap_or(CompletionsCommand::Install(CompletionInstallArgs {
            shell: None,
            json: false,
        })) {
        CompletionsCommand::Install(arguments) => install_completions(arguments),
        CompletionsCommand::Print(arguments) => print_completions(arguments),
    }
}

fn install_completions(arguments: CompletionInstallArgs) -> ExitCode {
    let shell = match arguments.shell {
        Some(shell) => shell,
        None => match CompletionShell::detect() {
            Ok(shell) => shell,
            Err(message) => {
                return emit_diagnostics(
                    arguments.json,
                    INVALID_CONFIGURATION_EXIT,
                    vec![Diagnostic::new(
                        DiagnosticCode::InvalidValue,
                        "shell",
                        message,
                    )],
                );
            }
        },
    };
    match shell.install() {
        Ok(path) => {
            let path = path.display().to_string();
            let shell_name = shell.to_string();
            if arguments.json {
                print_json(&CompletionInstallResult {
                    schema_version: CONFIG_SCHEMA_VERSION,
                    ok: true,
                    shell: &shell_name,
                    path: &path,
                });
            } else {
                println!("installed {shell} completions: {path}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_diagnostics(
            arguments.json,
            OUTPUT_EXIT,
            vec![Diagnostic::new(
                DiagnosticCode::Io,
                "completions",
                error.to_string(),
            )],
        ),
    }
}

fn print_completions(arguments: CompletionPrintArgs) -> ExitCode {
    let output = arguments.shell.generate();
    match io::stdout().write_all(&output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => emit_diagnostics(
            false,
            OUTPUT_EXIT,
            vec![Diagnostic::new(
                DiagnosticCode::Io,
                "stdout",
                error.to_string(),
            )],
        ),
    }
}

fn emit_diagnostics(json: bool, exit_code: u8, diagnostics: Vec<Diagnostic>) -> ExitCode {
    if json {
        print_json(&CliFailure {
            schema_version: CONFIG_SCHEMA_VERSION,
            ok: false,
            exit_code,
            diagnostics,
        });
    } else {
        print_diagnostics(&diagnostics);
    }
    ExitCode::from(exit_code)
}

fn print_diagnostics(diagnostics: &[Diagnostic]) {
    for diagnostic in diagnostics {
        eprintln!(
            "error[{}] {}: {}",
            diagnostic.code, diagnostic.path, diagnostic.message
        );
    }
}

fn configuration_error_diagnostics(error: ConfigurationError) -> Vec<Diagnostic> {
    match error {
        ConfigurationError::Validation(error) => error.into_diagnostics(),
        error => vec![error.diagnostic()],
    }
}

fn print_json(result: &impl Serialize) {
    let json = serde_json::to_string(result).expect("CLI results are serializable");
    println!("{json}");
}

fn parse_json_entry(value: &str) -> std::result::Result<(String, Value), String> {
    let Some((key, value)) = value.split_once('=') else {
        return Ok((value.to_owned(), serde_json::json!({})));
    };
    if key.is_empty() {
        return Err("key must not be empty".to_owned());
    }
    let value = serde_json::from_str(value).map_err(|error| error.to_string())?;
    Ok((key.to_owned(), value))
}

fn parse_string_entry(value: &str) -> std::result::Result<(String, String), String> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "expected KEY=VALUE".to_owned())?;
    if key.is_empty() {
        return Err("key must not be empty".to_owned());
    }
    Ok((key.to_owned(), value.to_owned()))
}
