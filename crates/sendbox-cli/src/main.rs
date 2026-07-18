#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use sendbox_config::{RuntimeProvider, SandboxConfiguration};
use sendbox_core::{CONFIG_SCHEMA_VERSION, Diagnostic, VERSION};
use serde::Serialize;

const INVALID_CONFIGURATION_EXIT: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "sendbox-rs",
    version = VERSION,
    about = "Experimental SendBox Rust configuration and policy validator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Policy(PolicyArgs),
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
        Command::Policy(policy) => match policy.command {
            PolicyCommand::Validate(arguments) => validate(arguments),
        },
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

fn print_json(result: &ValidationResult<'_>) {
    let json = serde_json::to_string(result).expect("validation results are serializable");
    println!("{json}");
}
