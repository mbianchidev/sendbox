#![forbid(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use sendbox_agent::{
    AgentError, AgentOrchestrator, AgentRequest, AgentSignal, BoxFuture, EnvironmentIntent,
    GuestCommand, GuestTerminal, NoSignals, OutputSink, ProtocolGuestConnector, RunPlan,
    SecretEnvelope, SecretReference, SecretResolver, SignalSource,
};
use sendbox_config::{RuntimeProvider, SandboxConfiguration};
use sendbox_core::{CONFIG_SCHEMA_VERSION, Diagnostic, SessionId, VERSION};
use sendbox_project::{
    Analyzer, DevContainerOverrides, ProjectError, ScanLimits, write_devcontainer,
};
use sendbox_runtime::{CancellationToken, OutputStream, RuntimeProvider as RuntimeProviderTrait};
use sendbox_runtime_kata::{KataProviderConfiguration, KataRuntimeProvider};
use serde::Serialize;
use serde_json::Value;

const INVALID_CONFIGURATION_EXIT: u8 = 2;
const ANALYSIS_EXIT: u8 = 3;
const OUTPUT_EXIT: u8 = 4;
const RUNTIME_EXIT: u8 = 5;

#[derive(Debug, Parser)]
#[command(
    name = "sendbox-rs",
    version = VERSION,
    about = "Experimental native SendBox CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Analyze(AnalyzeArgs),
    Devcontainer(Box<DevContainerArgs>),
    Policy(PolicyArgs),
    /// Run one exact argv workload through the experimental Rust Kata runtime.
    Run(RunArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RunRuntime {
    Kata,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_enum, default_value_t = RunRuntime::Kata)]
    runtime: RunRuntime,
    #[arg(long, value_name = "IMAGE@sha256:DIGEST")]
    image: String,
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
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<String>,
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
    Validate(ValidateArgs),
}

#[derive(Debug, Args)]
struct ValidateArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Analyze(arguments) => analyze(arguments),
        Command::Devcontainer(arguments) => match arguments.command {
            DevContainerCommand::Generate(arguments) => generate_devcontainer(arguments),
        },
        Command::Policy(policy) => match policy.command {
            PolicyCommand::Validate(arguments) => validate(arguments),
        },
        Command::Run(arguments) => run(arguments).await,
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
    if !configuration.secrets.is_empty()
        || configuration
            .observability
            .as_ref()
            .is_some_and(|value| value.mcp_inspection.enabled)
    {
        emit_run_error(
            arguments.json,
            INVALID_CONFIGURATION_EXIT,
            "experimental Kata run does not provide secrets or MCP inspection",
        );
        return ExitCode::from(INVALID_CONFIGURATION_EXIT);
    }
    let Some(program) = arguments.command.first() else {
        emit_run_error(
            arguments.json,
            INVALID_CONFIGURATION_EXIT,
            "command is empty",
        );
        return ExitCode::from(INVALID_CONFIGURATION_EXIT);
    };
    if !Path::new(program).is_absolute() {
        emit_run_error(
            arguments.json,
            INVALID_CONFIGURATION_EXIT,
            "experimental Kata command must use an absolute guest executable path",
        );
        return ExitCode::from(INVALID_CONFIGURATION_EXIT);
    }
    let kata = configuration
        .runtime
        .as_ref()
        .map(|runtime| runtime.kata.clone())
        .unwrap_or_default();
    let (workload_uid, workload_gid) = match project_identity(&configuration.project_path) {
        Ok(identity) => identity,
        Err(error) => {
            emit_run_error(arguments.json, INVALID_CONFIGURATION_EXIT, &error);
            return ExitCode::from(INVALID_CONFIGURATION_EXIT);
        }
    };
    let provider = match KataRuntimeProvider::new(KataProviderConfiguration {
        executable: kata.executable,
        runtime_handler: kata.runtime_handler,
        namespace: kata.namespace,
        address: kata.address,
        snapshotter: kata.snapshotter,
        configuration_path: kata.configuration_path,
        bundle_root: arguments.bundle,
        trust_root_file: arguments.trust_root,
        trust_root_id: arguments.trust_root_id,
        minimum_release_sequence: arguments.minimum_release_sequence,
        command_policy: configuration.policy.commands.clone(),
        workload_uid,
        workload_gid,
    }) {
        Ok(provider) => Arc::new(provider),
        Err(error) => {
            emit_run_error(arguments.json, RUNTIME_EXIT, &error.to_string());
            return ExitCode::from(RUNTIME_EXIT);
        }
    };
    let session_id = match random_session_id() {
        Ok(session_id) => session_id,
        Err(error) => {
            emit_run_error(arguments.json, RUNTIME_EXIT, &error);
            return ExitCode::from(RUNTIME_EXIT);
        }
    };
    let bootstrap_reference =
        SecretReference::new(format!("bootstrap-{session_id}")).expect("generated reference");
    let state_directory = match runtime_state_directory() {
        Ok(path) => path,
        Err(error) => {
            emit_run_error(arguments.json, RUNTIME_EXIT, &error);
            return ExitCode::from(RUNTIME_EXIT);
        }
    };
    let request = AgentRequest {
        session_id,
        state_directory,
        image: arguments.image,
        guest_workspace: PathBuf::from("/workspace"),
        command: GuestCommand {
            program: program.clone(),
            arguments: arguments.command[1..].to_vec(),
            working_directory: "/workspace".to_owned(),
        },
        environment: Vec::<EnvironmentIntent>::new(),
        mounts: Vec::new(),
        bootstrap_reference: bootstrap_reference.clone(),
        readiness_timeout: Duration::from_secs(60),
    };
    let plan = match RunPlan::compile(&configuration, request, &provider.capabilities()) {
        Ok(plan) => plan,
        Err(error) => {
            emit_run_error(
                arguments.json,
                INVALID_CONFIGURATION_EXIT,
                &error.to_string(),
            );
            return ExitCode::from(INVALID_CONFIGURATION_EXIT);
        }
    };
    let mut secret = [0_u8; 32];
    if let Err(error) = getrandom::fill(&mut secret) {
        emit_run_error(
            arguments.json,
            RUNTIME_EXIT,
            &format!("generate bootstrap secret: {error}"),
        );
        return ExitCode::from(RUNTIME_EXIT);
    }
    let secrets = Arc::new(EphemeralSecrets {
        reference: bootstrap_reference,
        secret,
    });
    let output = Arc::new(CliOutput {
        json: arguments.json,
    });
    let signals: Arc<dyn SignalSource> = if cfg!(unix) {
        Arc::new(CtrlCSignals::new())
    } else {
        Arc::new(NoSignals)
    };
    let orchestrator = AgentOrchestrator::new(
        provider as Arc<dyn RuntimeProviderTrait>,
        secrets,
        Arc::new(ProtocolGuestConnector),
        output,
        signals,
    );
    let cancellation = CancellationToken::new();
    let result = orchestrator.run(&plan, &cancellation).await;
    match result {
        Ok(report) => {
            let code = match report.terminal {
                GuestTerminal::Exited { code } => code,
                GuestTerminal::Signaled { signal } => 128_i32.saturating_add(signal),
                GuestTerminal::Cancelled => 130,
                GuestTerminal::Failed { .. } => i32::from(RUNTIME_EXIT),
            };
            if arguments.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "result",
                        "ok": code == 0,
                        "exit_code": code,
                        "terminal": report.terminal,
                    })
                );
            }
            exit_code(code)
        }
        Err(error) if matches!(error.primary, AgentError::Cancelled) => {
            if arguments.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "result",
                        "ok": false,
                        "exit_code": 130,
                        "terminal": "cancelled",
                        "cleanup_failures": error.cleanup.len(),
                    })
                );
            } else {
                eprintln!("sendbox-rs run: cancelled");
            }
            ExitCode::from(130)
        }
        Err(error) => {
            emit_run_error(arguments.json, RUNTIME_EXIT, &error.to_string());
            ExitCode::from(RUNTIME_EXIT)
        }
    }
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
                emit_failure(
                    arguments.json,
                    display_path,
                    Some(&configuration),
                    error.into_diagnostics(),
                );
                ExitCode::from(INVALID_CONFIGURATION_EXIT)
            }
        },
        Err(error) => {
            emit_failure(arguments.json, display_path, None, vec![error.diagnostic()]);
            ExitCode::from(INVALID_CONFIGURATION_EXIT)
        }
    }
}

fn emit_failure(
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
        for diagnostic in diagnostics {
            eprintln!(
                "{:?} at {}: {}",
                diagnostic.code, diagnostic.path, diagnostic.message
            );
        }
    }
}

fn print_json(result: &impl Serialize) {
    let json = serde_json::to_string(result).expect("validation results are serializable");
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

struct EphemeralSecrets {
    reference: SecretReference,
    secret: [u8; 32],
}

impl SecretResolver for EphemeralSecrets {
    fn resolve<'a>(
        &'a self,
        reference: &'a SecretReference,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<SecretEnvelope, sendbox_agent::AgentError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(sendbox_agent::AgentError::Cancelled);
            }
            if reference != &self.reference {
                return Err(sendbox_agent::AgentError::Secret {
                    reference: reference.as_str().to_owned(),
                    message: "unknown ephemeral secret".to_owned(),
                });
            }
            Ok(SecretEnvelope::new(reference.clone(), self.secret))
        })
    }
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
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "output",
                        "stream": match stream {
                            OutputStream::Stdout => "stdout",
                            OutputStream::Stderr => "stderr",
                        },
                        "encoding": "hex",
                        "data": encode_hex(bytes),
                    })
                );
                return Ok(());
            }
            let result = match stream {
                OutputStream::Stdout => {
                    let mut output = std::io::stdout().lock();
                    output.write_all(bytes).and_then(|()| output.flush())
                }
                OutputStream::Stderr => {
                    let mut output = std::io::stderr().lock();
                    output.write_all(bytes).and_then(|()| output.flush())
                }
            };
            result.map_err(|error| sendbox_agent::AgentError::Output(error.to_string()))
        })
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

fn random_session_id() -> Result<SessionId, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    Ok(SessionId::from_bytes(bytes))
}

fn runtime_state_directory() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set for the Kata state directory".to_owned())?;
    let path = home.join(".sendbox").join("run");
    std::fs::create_dir_all(&path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("set {} permissions: {error}", path.display()))?;
    }

    Ok(path)
}

fn project_identity(path: &Path) -> Result<(u32, u32), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = path
            .metadata()
            .map_err(|error| format!("inspect project path {}: {error}", path.display()))?;
        if metadata.uid() == 0 || metadata.gid() == 0 {
            return Err(
                "experimental Kata workloads require a non-root project owner uid and gid"
                    .to_owned(),
            );
        }
        Ok((metadata.uid(), metadata.gid()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("experimental Kata workloads require a Unix host".to_owned())
    }
}

fn emit_run_error(json: bool, exit_code: u8, message: &str) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "event": "error",
                "ok": false,
                "exit_code": exit_code,
                "message": message,
            })
        );
    } else {
        eprintln!("sendbox-rs run: {message}");
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
