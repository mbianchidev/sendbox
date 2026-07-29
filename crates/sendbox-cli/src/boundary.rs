use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use sendbox_config::SandboxConfiguration;
use sendbox_core::CONFIG_SCHEMA_VERSION;
use sendbox_mcp::artifact::{McpBoundaryInspection, NativeObserverArtifact};
use serde::Serialize;

#[derive(Debug, Args)]
pub(crate) struct BoundaryArgs {
    #[command(subcommand)]
    command: BoundaryCommand,
}

#[derive(Debug, Subcommand)]
enum BoundaryCommand {
    /// Inspect the structured native boundary plan without generating scripts.
    Inspect(InspectArgs),
}

#[derive(Debug, Args)]
struct InspectArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, help = "Emit the complete deterministic inspection as JSON")]
    json: bool,
}

#[derive(Debug, Serialize)]
struct BoundaryInspection<'a> {
    schema_version: u32,
    artifact_kind: &'static str,
    generated_executables: bool,
    config_source: String,
    configuration: &'a SandboxConfiguration,
    mcp: McpBoundaryInspection,
    observer: NativeObserverArtifact,
}

pub(crate) fn execute(arguments: BoundaryArgs) -> ExitCode {
    match arguments.command {
        BoundaryCommand::Inspect(arguments) => inspect(arguments),
    }
}

fn inspect(arguments: InspectArgs) -> ExitCode {
    let configuration = match SandboxConfiguration::load(&arguments.config) {
        Ok(configuration) => configuration,
        Err(error) => return emit_error(arguments.json, &arguments.config, &error.to_string()),
    };
    if let Err(error) = configuration.validate() {
        return emit_error(arguments.json, &arguments.config, &error.to_string());
    }

    let mcp = match McpBoundaryInspection::from_policy(&configuration.policy.boundaries.tool_calls)
    {
        Ok(mcp) => mcp,
        Err(error) => return emit_error(arguments.json, &arguments.config, &error),
    };
    let inspection = BoundaryInspection {
        schema_version: CONFIG_SCHEMA_VERSION,
        artifact_kind: "sendbox.boundary-plan-inspection",
        generated_executables: false,
        config_source: arguments.config.display().to_string(),
        configuration: &configuration,
        mcp,
        observer: configuration.observability.as_ref().map_or_else(
            || {
                NativeObserverArtifact::from_config(
                    &sendbox_config::McpInspectionConfiguration::default(),
                )
            },
            |observability| NativeObserverArtifact::from_config(&observability.mcp_inspection),
        ),
    };
    if arguments.json {
        super::print_json(&inspection);
    } else {
        println!("sandbox: {}", configuration.name);
        println!(
            "runtime: {}",
            configuration.runtime.as_ref().map_or_else(
                || "auto".to_owned(),
                |runtime| { format!("{:?}", runtime.provider).to_ascii_lowercase() }
            )
        );
        println!("boundary artifact: {}", inspection.artifact_kind);
        println!("generated executables: no");
        println!("MCP policy mode: {}", inspection.mcp.mode);
        for server in &inspection.mcp.servers {
            println!(
                "MCP server: {} ({:?}, {})",
                server.server_policy_id, server.transport, server.fingerprint
            );
            if let Some(endpoint) = &server.normalized_endpoint {
                println!("  upstream endpoint: {endpoint}");
            }
            if let Some(gateway) = &server.local_gateway_url {
                println!("  local gateway: {gateway}");
            }
            if let Some(http) = &server.http {
                println!(
                    "  HTTP limits: request={} response={} concurrent={} redirects={}",
                    http.max_request_bytes,
                    http.max_response_bytes,
                    http.max_concurrent_requests,
                    if http.allow_redirects {
                        http.max_redirects
                    } else {
                        0
                    }
                );
            }
        }
        println!("observer artifact: {}", inspection.observer.artifact_kind);
    }
    ExitCode::SUCCESS
}

fn emit_error(json: bool, config: &std::path::Path, error: &str) -> ExitCode {
    if json {
        super::print_json(&serde_json::json!({
            "ok": false,
            "config": config,
            "error": error,
        }));
    } else {
        eprintln!("sendbox boundary inspect: {}: {error}", config.display());
    }
    ExitCode::from(super::INVALID_CONFIGURATION_EXIT)
}
