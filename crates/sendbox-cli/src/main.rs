#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use sendbox_config::{RuntimeProvider, SandboxConfiguration};
use sendbox_core::{CONFIG_SCHEMA_VERSION, Diagnostic, VERSION};
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

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Analyze(arguments) => analyze(arguments),
        Command::Devcontainer(arguments) => match arguments.command {
            DevContainerCommand::Generate(arguments) => generate_devcontainer(arguments),
        },
        Command::Policy(policy) => match policy.command {
            PolicyCommand::Validate(arguments) => validate(arguments),
        },
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
