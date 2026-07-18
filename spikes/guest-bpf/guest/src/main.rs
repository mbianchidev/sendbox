#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use sendbox_guest_bpf::deterministic_json;
use sendbox_guest_bpf::diagnostic::SpikeError;
use sendbox_guest_bpf::loader::{EventStream, attach_once, live_self_test};
use sendbox_guest_bpf::preflight::inspect_host;

#[derive(Parser)]
#[command(
    name = "sendbox-guest-bpf",
    version,
    about = "Phase 1 guest/libbpf build spike"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report kernel, BTF, bpffs, capability, and BPF LSM availability.
    Preflight,
    /// Load and attach the embedded process-exec observation program.
    Attach,
    /// Consume a bounded number of process-exec ring-buffer events.
    Events {
        #[arg(long, default_value_t = 16)]
        max_events: usize,
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
    },
    /// Run an opt-in native attach and event-delivery self-test.
    SelfTest,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            emit_error(&error);
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<(), SpikeError> {
    match cli.command {
        Command::Preflight => emit(&inspect_host()?),
        Command::Attach => emit(&attach_once()?),
        Command::Events {
            max_events,
            timeout_ms,
        } => {
            let stream = EventStream::attach()?;
            for event in stream.collect(max_events, Duration::from_millis(timeout_ms))? {
                emit(&event)?;
            }
            Ok(())
        }
        Command::SelfTest => emit(&live_self_test()?),
    }
}

fn emit<T: serde::Serialize>(value: &T) -> Result<(), SpikeError> {
    println!("{}", deterministic_json(value)?);
    Ok(())
}

fn emit_error(error: &SpikeError) {
    match deterministic_json(&error.report()) {
        Ok(json) => eprintln!("{json}"),
        Err(serialization_error) => eprintln!(
            "{{\"schema_version\":1,\"status\":\"error\",\"kind\":\"internal\",\"stage\":\"json\",\"message\":\"{}\",\"action\":\"report this serialization failure\"}}",
            serialization_error
        ),
    }
}
