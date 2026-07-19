use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use sendbox_qualification::{
    BenchmarkOptions, BenchmarkSpecification, CommandComparison, CommandSpec, ConformanceManifest,
    FeatureInventory, load_json, normalize_output, run_benchmarks, run_command, validate_all,
};

#[derive(Debug, Parser)]
#[command(name = "sendbox-qualification", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Validate(Paths),
    Compare(CompareArgs),
    Benchmark(BenchmarkArgs),
}

#[derive(Debug, Args)]
struct Paths {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long, default_value = "Tests/qualification/inventory.v1.json")]
    inventory: PathBuf,
    #[arg(long, default_value = "Tests/qualification/conformance.v1.json")]
    conformance: PathBuf,
    #[arg(long, default_value = "Tests/qualification/benchmark-spec.v1.json")]
    benchmark_spec: PathBuf,
}

#[derive(Debug, Args)]
struct CompareArgs {
    #[command(flatten)]
    paths: Paths,
    #[arg(long)]
    fixture: String,
    #[arg(long)]
    swift_binary: PathBuf,
    #[arg(long)]
    rust_binary: PathBuf,
}

#[derive(Debug, Args)]
struct BenchmarkArgs {
    #[command(flatten)]
    paths: Paths,
    #[arg(long, default_value = "config/example-sandbox.yaml")]
    config: PathBuf,
    #[arg(long)]
    rust_binary: Option<PathBuf>,
    #[arg(long, default_value = "smoke", value_parser = ["smoke", "qualification"])]
    profile: String,
    #[arg(long)]
    enforce_thresholds: bool,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Validate(paths) => validate(paths),
        Command::Compare(arguments) => compare(arguments),
        Command::Benchmark(arguments) => benchmark(arguments),
    }
}

fn validate(paths: Paths) -> ExitCode {
    let inventory = match load_json::<FeatureInventory>(&paths.inventory) {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let conformance = match load_json::<ConformanceManifest>(&paths.conformance) {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let benchmark = match load_json::<BenchmarkSpecification>(&paths.benchmark_spec) {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let report = validate_all(&paths.root, &inventory, &conformance, &benchmark);
    print_json(&report);
    if report.valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn compare(arguments: CompareArgs) -> ExitCode {
    let manifest = match load_json::<ConformanceManifest>(&arguments.paths.conformance) {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let Some(fixture) = manifest
        .fixtures
        .iter()
        .find(|fixture| fixture.id == arguments.fixture)
    else {
        eprintln!("unknown conformance fixture: {}", arguments.fixture);
        return ExitCode::from(2);
    };
    let Some(command) = &fixture.command else {
        eprintln!("fixture {} is not executable", fixture.id);
        return ExitCode::from(2);
    };
    let swift = comparable(
        run_command(&CommandSpec {
            executable: arguments.swift_binary,
            args: command.args.clone(),
            current_dir: arguments.paths.root.clone(),
            timeout: Duration::from_millis(command.timeout_ms),
            output_cap_bytes: command.output_cap_bytes,
        }),
        command,
    );
    let rust = comparable(
        run_command(&CommandSpec {
            executable: arguments.rust_binary,
            args: command.args.clone(),
            current_dir: arguments.paths.root,
            timeout: Duration::from_millis(command.timeout_ms),
            output_cap_bytes: command.output_cap_bytes,
        }),
        command,
    );
    let matched = swift.status == "completed"
        && rust.status == "completed"
        && swift.exit_code == rust.exit_code
        && swift.stdout == rust.stdout
        && swift.stderr == rust.stderr;
    print_json(&CommandComparison {
        schema_version: 1,
        fixture_id: fixture.id.clone(),
        matched,
        swift,
        rust,
    });
    if matched {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn benchmark(arguments: BenchmarkArgs) -> ExitCode {
    let specification = match load_json::<BenchmarkSpecification>(&arguments.paths.benchmark_spec) {
        Ok(value) => value,
        Err(error) => return fail(error),
    };
    let report = run_benchmarks(
        &specification,
        &BenchmarkOptions {
            root: &arguments.paths.root,
            config_path: &arguments.config,
            rust_binary: arguments.rust_binary.as_deref(),
            profile: &arguments.profile,
            enforce_thresholds: arguments.enforce_thresholds,
        },
    );
    let failed = report.workloads.iter().any(|result| {
        result.status == sendbox_qualification::WorkloadStatus::Failed
            || (arguments.profile == "qualification"
                && result.status == sendbox_qualification::WorkloadStatus::Unqualified
                && specification.workloads.iter().any(|workload| {
                    workload.id == result.id
                        && workload.availability
                            == sendbox_qualification::QualificationState::Qualified
                }))
            || result
                .threshold_results
                .iter()
                .any(|threshold| threshold.status == sendbox_qualification::ThresholdStatus::Fail)
    });
    print_json(&report);
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn comparable(
    outcome: sendbox_qualification::CommandOutcome,
    command: &sendbox_qualification::ComparisonCommand,
) -> sendbox_qualification::ComparableOutcome {
    sendbox_qualification::ComparableOutcome {
        status: serde_json::to_value(outcome.status)
            .expect("status serializes")
            .as_str()
            .expect("status is a string")
            .to_owned(),
        exit_code: outcome.exit_code,
        stdout: normalize_output(
            &outcome.stdout,
            &command.replacements,
            &command.redact_json_keys,
        ),
        stderr: normalize_output(
            &outcome.stderr,
            &command.replacements,
            &command.redact_json_keys,
        ),
        error: outcome.error,
    }
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("{error}");
    ExitCode::from(2)
}

fn print_json(value: &impl serde::Serialize) {
    println!(
        "{}",
        serde_json::to_string(value).expect("qualification output serializes")
    );
}
