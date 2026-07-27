use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use sendbox_mcp::observation::{ObservationParser, ObservedCall, summarize};

const MAX_OBSERVATION_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Args)]
pub(crate) struct McpArgs {
    #[command(subcommand)]
    command: McpCommand,
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    /// Parse native or legacy MCP observations into normalized calls.
    Parse(ParseArgs),
    /// Summarize MCP observations without exposing request payloads.
    Report(ReportArgs),
}

#[derive(Debug, Args)]
struct ParseArgs {
    #[arg(value_name = "PATH")]
    input: PathBuf,
    #[arg(long, help = "Redact payloads, keeping only method/id/tool metadata")]
    redact: bool,
    #[arg(long, help = "Emit normalized calls as deterministic JSON")]
    json: bool,
}

#[derive(Debug, Args)]
struct ReportArgs {
    #[arg(value_name = "PATH")]
    input: PathBuf,
    #[arg(long, help = "Redact payloads before summarizing")]
    redact: bool,
    #[arg(long, help = "Emit the deterministic summary as JSON")]
    json: bool,
}

pub(crate) fn execute(arguments: McpArgs) -> ExitCode {
    match arguments.command {
        McpCommand::Parse(arguments) => parse(arguments),
        McpCommand::Report(arguments) => report(arguments),
    }
}

fn parse(arguments: ParseArgs) -> ExitCode {
    match parse_calls(&arguments.input, arguments.redact) {
        Ok(calls) => {
            if arguments.json {
                super::print_json(&calls);
            } else {
                for call in calls {
                    println!(
                        "{} {} {}",
                        call.timestamp_nanos.unwrap_or_default(),
                        call.method.as_deref().unwrap_or("-"),
                        call.subject.as_deref().unwrap_or("-")
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(arguments.json, "parse", &arguments.input, &error),
    }
}

fn report(arguments: ReportArgs) -> ExitCode {
    match parse_calls(&arguments.input, arguments.redact) {
        Ok(calls) => {
            let summary = summarize(&calls);
            if arguments.json {
                super::print_json(&serde_json::json!({
                    "total_calls": summary.total_calls,
                    "by_category": summary.by_category,
                    "by_kind": summary.by_kind,
                    "by_transport": summary.by_transport,
                    "tool_call_count": summary.tool_call_count,
                    "tool_invocations": summary.tool_invocations,
                    "error_count": summary.error_count,
                    "distinct_methods": summary.distinct_methods,
                    "servers": summary.servers,
                }));
            } else {
                println!("total calls: {}", summary.total_calls);
                println!("tool calls: {}", summary.tool_call_count);
                println!("errors: {}", summary.error_count);
                for (tool, count) in summary.tool_invocations {
                    println!("{tool}: {count}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(arguments.json, "report", &arguments.input, &error),
    }
}

fn parse_calls(input: &Path, redact: bool) -> Result<Vec<ObservedCall>, String> {
    let metadata = input
        .symlink_metadata()
        .map_err(|error| format!("could not inspect observation file: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("observation input must be a regular, non-symlink file".to_owned());
    }
    if metadata.len() > MAX_OBSERVATION_BYTES {
        return Err(format!(
            "observation input exceeds {MAX_OBSERVATION_BYTES} bytes"
        ));
    }
    let mut input_file =
        File::open(input).map_err(|error| format!("could not open observation file: {error}"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).expect("bounded observation length fits in usize"),
    );
    input_file
        .by_ref()
        .take(MAX_OBSERVATION_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read observation file: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_OBSERVATION_BYTES {
        return Err(format!(
            "observation input exceeds {MAX_OBSERVATION_BYTES} bytes"
        ));
    }
    let log = std::str::from_utf8(&bytes)
        .map_err(|error| format!("observation input is not valid UTF-8: {error}"))?;
    Ok(ObservationParser::new(!redact).parse_log(log))
}

fn emit_error(json: bool, action: &str, input: &Path, error: &str) -> ExitCode {
    if json {
        super::print_json(&serde_json::json!({
            "ok": false,
            "action": action,
            "input": input,
            "error": error,
        }));
    } else {
        eprintln!("sendbox mcp {action}: {}: {error}", input.display());
    }
    ExitCode::from(super::OUTPUT_EXIT)
}
