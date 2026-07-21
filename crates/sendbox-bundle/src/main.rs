#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use sendbox_bundle::{
    Architecture, StageOptions, VerifyOptions, stage_bundle, verify_bundle, write_public_key,
};

#[derive(Parser)]
#[command(name = "sendbox-bundle", version)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Stage {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        guest: PathBuf,
        #[arg(long)]
        launcher: PathBuf,
        #[arg(long)]
        bpf: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        architecture: CliArchitecture,
        #[arg(long)]
        trust_root_id: String,
        #[arg(long)]
        release_sequence: u64,
        #[arg(long)]
        minimum_accepted_sequence: u64,
        #[arg(long)]
        host_version: String,
        #[arg(long)]
        guest_version: String,
        #[arg(long, default_value = "5.8.0")]
        minimum_kernel: String,
        #[arg(long, default_value_t = 0)]
        uid: u32,
        #[arg(long, default_value_t = 0)]
        gid: u32,
    },
    Verify {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        architecture: CliArchitecture,
        #[arg(long)]
        trust_root_id: String,
        #[arg(long)]
        host_version: String,
        #[arg(long)]
        guest_version: String,
        #[arg(long)]
        minimum_release_sequence: u64,
    },
    PublicKey {
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliArchitecture {
    #[value(name = "x86_64")]
    X86_64,
    #[value(name = "aarch64")]
    Aarch64,
}

impl From<CliArchitecture> for Architecture {
    fn from(value: CliArchitecture) -> Self {
        match value {
            CliArchitecture::X86_64 => Self::X86_64,
            CliArchitecture::Aarch64 => Self::Aarch64,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("sendbox-bundle: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let json = match arguments.command {
        Command::Stage {
            output,
            guest,
            launcher,
            bpf,
            signing_key,
            architecture,
            trust_root_id,
            release_sequence,
            minimum_accepted_sequence,
            host_version,
            guest_version,
            minimum_kernel,
            uid,
            gid,
        } => serde_json::to_string(&stage_bundle(&StageOptions {
            output: &output,
            guest_binary: &guest,
            exec_launcher: &launcher,
            bpf_object: &bpf,
            signing_key: &signing_key,
            architecture: architecture.into(),
            trust_root_id: &trust_root_id,
            release_sequence,
            minimum_accepted_sequence,
            host_version: &host_version,
            guest_version: &guest_version,
            minimum_kernel: &minimum_kernel,
            uid,
            gid,
        })?)?,
        Command::Verify {
            root,
            public_key,
            architecture,
            trust_root_id,
            host_version,
            guest_version,
            minimum_release_sequence,
        } => serde_json::to_string(&verify_bundle(&VerifyOptions {
            root: &root,
            public_key: &public_key,
            architecture: architecture.into(),
            trust_root_id: &trust_root_id,
            host_version: &host_version,
            guest_version: &guest_version,
            minimum_release_sequence,
        })?)?,
        Command::PublicKey {
            signing_key,
            output,
        } => {
            write_public_key(&signing_key, &output)?;
            serde_json::json!({"schema_version": 1, "public_key": output}).to_string()
        }
    };
    println!("{json}");
    Ok(())
}
