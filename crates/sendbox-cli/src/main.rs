#![forbid(unsafe_code)]

mod boundary;
mod completions;
mod mcp;
mod package;
mod secrets;
mod terminal;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use completions::CompletionShell;
use sendbox_agent::{AgentError, AgentSignal, BoxFuture, NoSignals, OutputSink, SignalSource};
use sendbox_config::{
    ConfigurationError, MigrationReport, PolicyPreset, RuntimeProvider, SandboxConfiguration,
};
use sendbox_core::{CONFIG_SCHEMA_VERSION, Diagnostic, DiagnosticCode, VERSION};
use sendbox_host::{
    HostError, HostRunReport, HostRunRequest, RequestedRuntime, prepare as prepare_host_run,
};
use sendbox_project::{
    Analyzer, DevContainerOverrides, ProjectError, ScanLimits, write_devcontainer,
};
use sendbox_runtime::{CancellationToken, OutputStream};
use serde::Serialize;
use serde_json::Value;

const INVALID_CONFIGURATION_EXIT: u8 = 2;
const ANALYSIS_EXIT: u8 = 3;
const OUTPUT_EXIT: u8 = 4;
const RUNTIME_EXIT: u8 = 5;

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
    Boundary(boundary::BoundaryArgs),
    Completions(CompletionsArgs),
    Devcontainer(Box<DevContainerArgs>),
    Init(InitArgs),
    Mcp(mcp::McpArgs),
    Package(package::PackageArgs),
    Policy(PolicyArgs),
    /// Run one exact argv workload through an authenticated runtime boundary.
    Run(RunArgs),
    Secrets(secrets::SecretsArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RunRuntime {
    Auto,
    Apple,
    Kata,
    Hyperlight,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_enum, default_value_t = RunRuntime::Auto)]
    runtime: RunRuntime,
    #[arg(long, value_name = "IMAGE@sha256:DIGEST")]
    image: Option<String>,
    #[arg(long, value_name = "PATH")]
    bundle: PathBuf,
    #[arg(long, value_name = "PATH")]
    trust_root: PathBuf,
    #[arg(long, default_value = "external-release-root")]
    trust_root_id: String,
    #[arg(long, default_value_t = 1)]
    minimum_release_sequence: u64,
    #[arg(long)]
    json: bool,
    /// Run the workload on a pseudoterminal and forward this terminal's
    /// keystrokes and window size to it.
    #[arg(long, conflicts_with = "json")]
    interactive: bool,
    /// Give stderr its own non-controlling pseudoterminal. This loses strict
    /// ordering with stdout and is unsuitable for TUIs that draw through fd 2.
    #[arg(long, requires = "interactive")]
    separate_stderr: bool,
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct AnalyzeArgs {
    #[command(flatten)]
    scan: ScanArgs,
    #[arg(
        long,
        value_name = "PROJECT_ROOT",
        help = "Write PROJECT_ROOT/.devcontainer/devcontainer.json"
    )]
    output: Option<PathBuf>,
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Analyze(arguments) => analyze(arguments),
        Command::Boundary(arguments) => boundary::execute(arguments),
        Command::Completions(arguments) => completions(arguments),
        Command::Devcontainer(arguments) => match arguments.command {
            DevContainerCommand::Generate(arguments) => generate_devcontainer(arguments),
        },
        Command::Init(arguments) => init(arguments),
        Command::Mcp(arguments) => mcp::execute(arguments),
        Command::Package(arguments) => match runtime_state_directory() {
            Ok(state_root) => package::execute(arguments, &state_root),
            Err(error) => {
                eprintln!("sendbox package: {error}");
                ExitCode::from(RUNTIME_EXIT)
            }
        },
        Command::Policy(policy) => match policy.command {
            PolicyCommand::Show(arguments) => show_policy(arguments),
            PolicyCommand::Validate(arguments) => validate(arguments),
        },
        Command::Run(arguments) => run(arguments).await,
        Command::Secrets(arguments) => secrets::execute(arguments),
    }
}

async fn run(arguments: RunArgs) -> ExitCode {
    let configuration = match SandboxConfiguration::load(&arguments.config) {
        Ok(configuration) => configuration,
        Err(error) => {
            emit_run_error(
                arguments.json,
                INVALID_CONFIGURATION_EXIT,
                &error.to_string(),
            );
            return ExitCode::from(INVALID_CONFIGURATION_EXIT);
        }
    };
    if let Err(error) = configuration.validate() {
        emit_run_error(
            arguments.json,
            INVALID_CONFIGURATION_EXIT,
            &error.to_string(),
        );
        return ExitCode::from(INVALID_CONFIGURATION_EXIT);
    }
    if arguments
        .command
        .first()
        .is_none_or(|program| !Path::new(program).is_absolute())
    {
        emit_run_error(
            arguments.json,
            INVALID_CONFIGURATION_EXIT,
            "guest command must use an absolute executable path",
        );
        return ExitCode::from(INVALID_CONFIGURATION_EXIT);
    }
    let state_root = match runtime_state_directory() {
        Ok(path) => path,
        Err(error) => {
            emit_run_error(arguments.json, RUNTIME_EXIT, &error);
            return ExitCode::from(RUNTIME_EXIT);
        }
    };
    let session = if arguments.interactive {
        match terminal::TerminalSession::start(arguments.separate_stderr) {
            Ok(session) => Some(session),
            Err(error) => {
                emit_run_error(
                    arguments.json,
                    INVALID_CONFIGURATION_EXIT,
                    &error.to_string(),
                );
                return ExitCode::from(INVALID_CONFIGURATION_EXIT);
            }
        }
    } else {
        None
    };
    let terminal_size = session.as_ref().map(|(_, size)| size.clone());
    let prepared = match prepare_host_run(HostRunRequest {
        requested_runtime: match arguments.runtime {
            RunRuntime::Auto => RequestedRuntime::Auto,
            RunRuntime::Apple => RequestedRuntime::Apple,
            RunRuntime::Kata => RequestedRuntime::Kata,
            RunRuntime::Hyperlight => RequestedRuntime::Hyperlight,
        },
        configuration,
        image: arguments.image,
        bundle_root: arguments.bundle,
        trust_root: arguments.trust_root,
        trust_root_id: arguments.trust_root_id,
        minimum_release_sequence: arguments.minimum_release_sequence,
        command: arguments.command,
        state_root,
        readiness_timeout: Duration::from_secs(60),
        terminal: terminal_size,
    })
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            let code = host_error_exit_code(&error);
            if let Some((session, _)) = session {
                session.finish();
            }
            emit_run_error(arguments.json, code, &error.to_string());
            return ExitCode::from(code);
        }
    };
    let output = Arc::new(CliOutput {
        json: arguments.json,
    });
    let cancellation = CancellationToken::new();
    // Raw mode clears ISIG, so Ctrl-C reaches the workload's own terminal as a
    // byte. Intercepting it on the host as well would kill the sandbox instead
    // of the program the operator is looking at.
    let signals: Arc<dyn SignalSource> = match (session.is_some(), cfg!(unix)) {
        (true, _) => Arc::new(FatalSignals::new(cancellation.clone())),
        (false, true) => Arc::new(CtrlCSignals::new()),
        (false, false) => Arc::new(NoSignals),
    };
    let prepared = match session.as_ref() {
        Some((session, _)) => prepared.with_terminal_source(session.source()),
        None => prepared,
    };
    let result = prepared.execute(output, signals, &cancellation).await;
    if let Some((session, _)) = session {
        session.finish();
    }
    match result {
        Ok(report) => {
            let code = report.exit_code();
            if arguments.json {
                print_json(&serde_json::json!({
                    "event": "result",
                    "ok": code == 0,
                    "exit_code": code,
                    "execution": match &report {
                        HostRunReport::Persistent(_) => "persistent_guest",
                        HostRunReport::OneShot(_) => "authenticated_one_shot",
                    },
                    "session_id": report.session_id().map(|session_id| session_id.to_string()),
                    "package_report": report.package_report().map(|package| serde_json::json!({
                        "path": package.path(),
                        "sha256": package.sha256(),
                        "proxy_enabled": package.proxy_enabled(),
                        "records": package.records(),
                        "allowed": package.allowed(),
                        "denied": package.denied(),
                        "quarantined": package.quarantined(),
                    })),
                }));
            }
            exit_code(code)
        }
        Err(error) if host_error_cancelled(&error) => {
            if arguments.json {
                print_json(&serde_json::json!({
                    "event": "result",
                    "ok": false,
                    "exit_code": 130,
                    "terminal": "cancelled",
                }));
            } else {
                eprintln!("sendbox run: cancelled");
            }
            ExitCode::from(130)
        }
        Err(error) => {
            emit_run_error(arguments.json, RUNTIME_EXIT, &error.to_string());
            ExitCode::from(RUNTIME_EXIT)
        }
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
    fs::read_dir(&canonical).map_err(|error| {
        Diagnostic::new(
            DiagnosticCode::InvalidPath,
            canonical.display().to_string(),
            format!(
                "project directory must be readable and searchable for secure configuration writes: {error}"
            ),
        )
    })?;
    Ok(canonical)
}

fn analyze(arguments: AnalyzeArgs) -> ExitCode {
    let project = arguments.scan.project.display().to_string();
    match analyzer(&arguments.scan).analyze(&arguments.scan.project) {
        Ok(analysis) => {
            if let Some(output) = arguments.output.as_deref()
                && let Err(error) =
                    write_devcontainer(output, None, &analysis, &DevContainerOverrides::default())
            {
                return emit_project_error(arguments.json, OUTPUT_EXIT, &project, &error);
            }
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
        "  Max frame bytes: {}",
        policy.boundaries.tool_calls.max_frame_bytes
    );
    println!("  Log path:       {}", policy.boundaries.log_path);
    match sendbox_mcp::artifact::McpBoundaryInspection::from_policy(&policy.boundaries.tool_calls) {
        Ok(inspection) => {
            println!("  MCP policy mode: {}", inspection.mode);
            for server in inspection.servers {
                println!(
                    "  MCP server {}: {} ({})",
                    server.server_policy_id,
                    transport_name(server.transport),
                    server.fingerprint
                );
                if let Some(executable) = server.executable {
                    println!("    Executable: {executable}");
                }
                if let Some(endpoint) = server.normalized_endpoint {
                    println!("    Endpoint: {endpoint}");
                }
                if let Some(gateway) = server.local_gateway_url {
                    println!("    Local gateway: {gateway}");
                }
                if let Some(http) = server.http {
                    println!(
                        "    HTTP limits: request={} response={} concurrent={}",
                        http.max_request_bytes,
                        http.max_response_bytes,
                        http.max_concurrent_requests
                    );
                    println!(
                        "    Redirects: {} (max {})",
                        http.allow_redirects, http.max_redirects
                    );
                }
                println!(
                    "    Tool default: {}",
                    action_name(server.tools.default_action)
                );
                print_list("    Tool allowlist:", "+", &server.tools.allowlist);
                print_list("    Tool denylist:", "-", &server.tools.denylist);
            }
        }
        Err(error) => eprintln!("  MCP policy inspection failed: {error}"),
    }
    print_list(
        "  Additional denied syscalls:",
        "-",
        &policy.boundaries.syscalls.additional_denylist,
    );
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

fn transport_name(transport: sendbox_policy::ToolTransport) -> &'static str {
    match transport {
        sendbox_policy::ToolTransport::Stdio => "stdio",
        sendbox_policy::ToolTransport::StreamableHttp => "streamable-http",
        sendbox_policy::ToolTransport::StreamableHttp2025 => "streamable-http-2025",
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
                    println!("Validating {}...", arguments.config.display());
                    println!("✅ Configuration is valid");
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
        None => CompletionShell::detect(),
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

struct CliOutput {
    json: bool,
}

impl OutputSink for CliOutput {
    fn write<'a>(
        &'a self,
        stream: OutputStream,
        bytes: &'a [u8],
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), sendbox_agent::AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(sendbox_agent::AgentError::Cancelled);
            }
            if self.json {
                print_json(&serde_json::json!({
                    "event": "output",
                    "stream": match stream {
                        OutputStream::Stdout => "stdout",
                        OutputStream::Stderr => "stderr",
                    },
                    "encoding": "hex",
                    "data": encode_hex(bytes),
                }));
                return Ok(());
            }
            let result = match stream {
                OutputStream::Stdout => {
                    let mut output = io::stdout().lock();
                    output.write_all(bytes).and_then(|()| output.flush())
                }
                OutputStream::Stderr => {
                    let mut output = io::stderr().lock();
                    output.write_all(bytes).and_then(|()| output.flush())
                }
            };
            result.map_err(|error| sendbox_agent::AgentError::Output(error.to_string()))
        })
    }
}

/// Signal policy for interactive runs.
///
/// Ctrl-C belongs to the workload because raw mode forwards it as a byte, but a
/// terminal hang-up or an external `kill` must still unwind cleanly so the
/// terminal is put back the way it was found.
struct FatalSignals {
    receiver: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<AgentSignal>>,
}

impl FatalSignals {
    fn new(cancellation: CancellationToken) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        #[cfg(unix)]
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let Ok(mut terminate) = signal(SignalKind::terminate()) else {
                return;
            };
            let Ok(mut hangup) = signal(SignalKind::hangup()) else {
                return;
            };
            let Ok(mut quit) = signal(SignalKind::quit()) else {
                return;
            };
            tokio::select! {
                _ = terminate.recv() => {}
                _ = hangup.recv() => {}
                _ = quit.recv() => {}
            }
            cancellation.cancel();
            let _ = sender.send(AgentSignal::Interrupt).await;
        });
        #[cfg(not(unix))]
        {
            let _ = (cancellation, sender);
        }
        Self {
            receiver: tokio::sync::Mutex::new(receiver),
        }
    }
}

impl SignalSource for FatalSignals {
    fn next_signal<'a>(&'a self) -> BoxFuture<'a, Option<AgentSignal>> {
        Box::pin(async move { self.receiver.lock().await.recv().await })
    }
}

struct CtrlCSignals {
    receiver: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<AgentSignal>>,
}

impl CtrlCSignals {
    fn new() -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = sender.send(AgentSignal::Interrupt).await;
            }
        });
        Self {
            receiver: tokio::sync::Mutex::new(receiver),
        }
    }
}

impl SignalSource for CtrlCSignals {
    fn next_signal<'a>(&'a self) -> BoxFuture<'a, Option<AgentSignal>> {
        Box::pin(async move { self.receiver.lock().await.recv().await })
    }
}

fn runtime_state_directory() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set for the runtime state directory".to_owned())?;
    let path = home.join(".sendbox").join("run");
    fs::create_dir_all(&path).map_err(|error| format!("create {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("set {} permissions: {error}", path.display()))?;
    }
    Ok(path)
}

fn host_error_exit_code(error: &HostError) -> u8 {
    match error {
        HostError::Invalid(_)
        | HostError::Boundary(_)
        | HostError::Credentials(_)
        | HostError::GitGuard(_)
        | HostError::AgentPlan(_)
        | HostError::Bundle(_) => INVALID_CONFIGURATION_EXIT,
        _ => RUNTIME_EXIT,
    }
}

fn host_error_cancelled(error: &HostError) -> bool {
    match error {
        HostError::AgentRun(failure) => matches!(failure.primary, AgentError::Cancelled),
        HostError::Runtime(sendbox_runtime::RuntimeError::Cancelled) => true,
        HostError::RuntimeSecurity { runtime, .. } => host_error_cancelled(runtime),
        _ => false,
    }
}

fn emit_run_error(json: bool, exit_code: u8, message: &str) {
    if json {
        print_json(&serde_json::json!({
            "event": "error",
            "ok": false,
            "exit_code": exit_code,
            "message": message,
        }));
    } else {
        eprintln!("sendbox run: {message}");
    }
}

fn exit_code(code: i32) -> ExitCode {
    if (0..=255).contains(&code) {
        ExitCode::from(u8::try_from(code).expect("validated exit code"))
    } else {
        ExitCode::FAILURE
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
