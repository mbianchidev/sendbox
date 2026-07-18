use apple_container_adapter_spike::capability::Probe;
use apple_container_adapter_spike::process::TokioProcessRunner;
use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "apple-container-probe",
    about = "Non-mutating capability probe for Apple's official container CLI"
)]
struct Arguments {
    #[arg(long)]
    executable: Option<PathBuf>,
    #[arg(long, default_value_t = 10)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 131_072)]
    output_limit_bytes: usize,
}

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse();
    let probe = Probe::new(
        TokioProcessRunner,
        Duration::from_secs(arguments.timeout_seconds),
        arguments.output_limit_bytes,
    );
    let report = probe.run(arguments.executable.as_deref()).await;
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to serialize probe report: {error}");
            std::process::exit(1);
        }
    }
}
