use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sendbox_config::SandboxConfiguration;
use sendbox_core::SessionId;
use sendbox_protocol::{
    BootstrapSecret, Capability, FrameLimits, GuestHandshake, HandshakeConfig, HostHandshake,
    Message, Request, Response, ResponseStatus, VersionRange, decode_message, encode_message,
};

use crate::model::{
    BenchmarkReport, BenchmarkSpecification, Comparator, HostMetadata, QualificationState,
    ThresholdResult, ThresholdStatus, WorkloadResult, WorkloadStatus,
};
use crate::process::{CommandSpec, CommandStatus, run_command};
use crate::stats::summarize;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const SECRET: [u8; 32] = [0x6c; 32];

pub struct BenchmarkOptions<'a> {
    pub root: &'a Path,
    pub config_path: &'a Path,
    pub rust_binary: Option<&'a Path>,
    pub profile: &'a str,
    pub enforce_thresholds: bool,
}

pub fn run_benchmarks(
    specification: &BenchmarkSpecification,
    options: &BenchmarkOptions<'_>,
) -> BenchmarkReport {
    let (warmups, repetitions) = if options.profile == "smoke" {
        (1, 3)
    } else {
        (
            specification.methodology.warmups,
            specification.methodology.repetitions,
        )
    };
    let mut results = Vec::new();
    for workload in &specification.workloads {
        if workload.availability == QualificationState::Unqualified {
            results.push(unqualified(
                &workload.id,
                workload.unqualified_reason.clone().unwrap_or_default(),
            ));
            continue;
        }
        let result = match workload.id.as_str() {
            "cli.startup.help" => benchmark_cli(options, warmups, repetitions),
            "config.load_validate" => benchmark_config(options.config_path, warmups, repetitions),
            "policy.validate" => benchmark_policy(options.config_path, warmups, repetitions),
            "protocol.encode_decode" => benchmark_protocol_codec(warmups, repetitions),
            "protocol.authenticated_rtt" => benchmark_protocol_rtt(warmups, repetitions),
            other => unqualified(
                other,
                "no stable pure-path implementation is available".to_owned(),
            ),
        };
        results.push(result);
    }
    apply_thresholds(
        &mut results,
        specification,
        options.enforce_thresholds && options.profile != "smoke",
    );
    BenchmarkReport {
        schema_version: 1,
        specification_version: specification.specification_version.clone(),
        profile: options.profile.to_owned(),
        host: host_metadata(),
        workloads: results,
    }
}

fn benchmark_cli(options: &BenchmarkOptions<'_>, warmups: u32, repetitions: u32) -> WorkloadResult {
    let Some(binary) = options.rust_binary else {
        return unqualified(
            "cli.startup.help",
            "Rust binary path was not provided".to_owned(),
        );
    };
    let mut samples = Vec::new();
    for iteration in 0..warmups + repetitions {
        let started = Instant::now();
        let outcome = run_command(&CommandSpec {
            executable: binary.to_path_buf(),
            args: vec!["--help".to_owned()],
            current_dir: options.root.to_path_buf(),
            timeout: Duration::from_secs(5),
            output_cap_bytes: 1_048_576,
        });
        if outcome.status != CommandStatus::Completed || outcome.exit_code != Some(0) {
            return failed(
                "cli.startup.help",
                format!("CLI invocation failed: {:?}", outcome.status),
            );
        }
        if iteration >= warmups {
            samples.push(started.elapsed().as_secs_f64() * 1_000.0);
        }
    }
    measured("cli.startup.help", "milliseconds", samples)
}

fn benchmark_config(path: &Path, warmups: u32, repetitions: u32) -> WorkloadResult {
    measure(
        "config.load_validate",
        "milliseconds",
        warmups,
        repetitions,
        || {
            let configuration =
                SandboxConfiguration::load(path).map_err(|error| error.to_string())?;
            configuration.validate().map_err(|error| error.to_string())
        },
    )
}

fn benchmark_policy(path: &Path, warmups: u32, repetitions: u32) -> WorkloadResult {
    let configuration = match SandboxConfiguration::load(path) {
        Ok(configuration) => configuration,
        Err(error) => return failed("policy.validate", error.to_string()),
    };
    measure(
        "policy.validate",
        "microseconds",
        warmups,
        repetitions,
        || {
            configuration
                .policy
                .validate()
                .map_err(|error| error.to_string())
        },
    )
}

fn benchmark_protocol_codec(warmups: u32, repetitions: u32) -> WorkloadResult {
    let message = Message::Request(Request {
        request_id: 7,
        operation: "qualification".to_owned(),
        payload: vec![0x5a; 4096],
    });
    measure(
        "protocol.encode_decode",
        "microseconds",
        warmups,
        repetitions,
        || {
            let encoded = encode_message(&message).map_err(|error| error.to_string())?;
            let decoded = decode_message(&encoded).map_err(|error| error.to_string())?;
            (decoded == message)
                .then_some(())
                .ok_or_else(|| "protocol round trip changed the message".to_owned())
        },
    )
}

fn benchmark_protocol_rtt(warmups: u32, repetitions: u32) -> WorkloadResult {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => return failed("protocol.authenticated_rtt", error.to_string()),
    };
    let mut samples = Vec::new();
    for iteration in 0..warmups + repetitions {
        let result = runtime.block_on(authenticated_round_trip());
        let elapsed = match result {
            Ok(elapsed) => elapsed,
            Err(error) => return failed("protocol.authenticated_rtt", error),
        };
        if iteration >= warmups {
            samples.push(elapsed.as_secs_f64() * 1_000_000.0);
        }
    }
    measured("protocol.authenticated_rtt", "microseconds", samples)
}

async fn authenticated_round_trip() -> Result<Duration, String> {
    let session_id = SessionId::from_bytes([0x44; 16]);
    let config = || {
        HandshakeConfig::new(
            session_id,
            VersionRange::default(),
            [Capability::Lifecycle, Capability::Exec].into(),
            [Capability::Lifecycle].into(),
            FrameLimits::new(64 * 1024).map_err(|error| error.to_string())?,
            BootstrapSecret::new(SECRET).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())
    };
    let (host_stream, guest_stream) = tokio::io::duplex(64 * 1024);
    let mut host = HostHandshake::new(config()?);
    let mut guest = GuestHandshake::new(config()?);
    let (host_connection, guest_connection) =
        tokio::join!(host.establish(host_stream), guest.establish(guest_stream));
    let (mut host_reader, mut host_writer) = host_connection
        .map_err(|error| error.to_string())?
        .into_parts();
    let (mut guest_reader, mut guest_writer) = guest_connection
        .map_err(|error| error.to_string())?
        .into_parts();
    let guest_task = tokio::spawn(async move {
        let request = guest_reader
            .receive()
            .await
            .map_err(|error| error.to_string())?;
        let request_id = match request {
            Message::Request(request) => request.request_id,
            _ => return Err("expected request".to_owned()),
        };
        guest_writer
            .send(&Message::Response(Response {
                request_id,
                status: ResponseStatus::Ok,
                payload: vec![0x5a; 64],
            }))
            .await
            .map_err(|error| error.to_string())
    });
    let started = Instant::now();
    host_writer
        .send(&Message::Request(Request {
            request_id: 1,
            operation: "ping".to_owned(),
            payload: vec![0x5a; 64],
        }))
        .await
        .map_err(|error| error.to_string())?;
    let response = host_reader
        .receive()
        .await
        .map_err(|error| error.to_string())?;
    let elapsed = started.elapsed();
    guest_task
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    if !matches!(
        response,
        Message::Response(Response {
            status: ResponseStatus::Ok,
            ..
        })
    ) {
        return Err("unexpected protocol response".to_owned());
    }
    Ok(elapsed)
}

fn measure(
    id: &str,
    unit: &str,
    warmups: u32,
    repetitions: u32,
    mut operation: impl FnMut() -> Result<(), String>,
) -> WorkloadResult {
    let mut samples = Vec::new();
    for iteration in 0..warmups + repetitions {
        let started = Instant::now();
        if let Err(error) = operation() {
            return failed(id, error);
        }
        if iteration >= warmups {
            let elapsed = started.elapsed().as_secs_f64();
            samples.push(if unit == "milliseconds" {
                elapsed * 1_000.0
            } else {
                elapsed * 1_000_000.0
            });
        }
    }
    measured(id, unit, samples)
}

fn apply_thresholds(
    results: &mut [WorkloadResult],
    specification: &BenchmarkSpecification,
    enforce: bool,
) {
    for result in results {
        for threshold in specification
            .thresholds
            .iter()
            .filter(|threshold| threshold.workload_id == result.id)
        {
            let (status, observed, reason) = if threshold.relative_to.is_some() {
                (
                    ThresholdStatus::Unqualified,
                    None,
                    Some("relative baseline has not been captured".to_owned()),
                )
            } else if !enforce {
                (
                    ThresholdStatus::NotEnforced,
                    metric(result, &threshold.metric),
                    Some("shared-runner smoke does not enforce performance".to_owned()),
                )
            } else if let Some(observed) = metric(result, &threshold.metric) {
                let passes = match threshold.comparator {
                    Comparator::LessThanOrEqual => observed <= threshold.value,
                    Comparator::GreaterThanOrEqual => observed >= threshold.value,
                };
                (
                    if passes {
                        ThresholdStatus::Pass
                    } else {
                        ThresholdStatus::Fail
                    },
                    Some(observed),
                    None,
                )
            } else {
                (
                    ThresholdStatus::Unqualified,
                    None,
                    Some("workload was not measured".to_owned()),
                )
            };
            result.threshold_results.push(ThresholdResult {
                threshold_id: threshold.id.clone(),
                status,
                observed,
                reason,
            });
        }
    }
}

fn metric(result: &WorkloadResult, metric: &str) -> Option<f64> {
    let summary = result.summary.as_ref()?;
    match metric {
        "p50" => Some(summary.p50),
        "p95" => Some(summary.p95),
        "p99" => Some(summary.p99),
        "mean" => Some(summary.mean),
        _ => None,
    }
}

fn measured(id: &str, unit: &str, samples: Vec<f64>) -> WorkloadResult {
    WorkloadResult {
        id: id.to_owned(),
        status: WorkloadStatus::Measured,
        unit: unit.to_owned(),
        summary: summarize(&samples),
        raw_samples: samples,
        threshold_results: Vec::new(),
        reason: None,
    }
}

fn unqualified(id: &str, reason: String) -> WorkloadResult {
    WorkloadResult {
        id: id.to_owned(),
        status: WorkloadStatus::Unqualified,
        unit: "not_measured".to_owned(),
        raw_samples: Vec::new(),
        summary: None,
        threshold_results: Vec::new(),
        reason: Some(reason),
    }
}

fn failed(id: &str, reason: String) -> WorkloadResult {
    WorkloadResult {
        id: id.to_owned(),
        status: WorkloadStatus::Failed,
        unit: "not_measured".to_owned(),
        raw_samples: Vec::new(),
        summary: None,
        threshold_results: Vec::new(),
        reason: Some(reason),
    }
}

fn host_metadata() -> HostMetadata {
    HostMetadata {
        os: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        rustc: tool_version(PathBuf::from("rustc"), &["--version"]),
        swift: tool_version(PathBuf::from("/usr/bin/swift"), &["--version"]),
        qualification_tool: TOOL_VERSION.to_owned(),
    }
}

fn tool_version(executable: PathBuf, args: &[&str]) -> String {
    let outcome = run_command(&CommandSpec {
        executable,
        args: args.iter().map(|value| (*value).to_owned()).collect(),
        current_dir: PathBuf::from("."),
        timeout: Duration::from_secs(5),
        output_cap_bytes: 16 * 1024,
    });
    if outcome.status == CommandStatus::Completed {
        String::from_utf8_lossy(&outcome.stdout).trim().to_owned()
    } else {
        format!("unavailable:{:?}", outcome.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ThresholdStatus;

    #[test]
    fn threshold_pass_and_fail_are_explicit() {
        let mut results = vec![measured("w", "milliseconds", vec![1.0, 2.0, 3.0])];
        let mut specification: BenchmarkSpecification = serde_json::from_str(include_str!(
            "../../../Tests/qualification/benchmark-spec.v1.json"
        ))
        .expect("spec");
        specification.thresholds = vec![
            crate::model::Threshold {
                id: "pass".to_owned(),
                workload_id: "w".to_owned(),
                metric: "p50".to_owned(),
                comparator: Comparator::LessThanOrEqual,
                value: 2.0,
                unit: "milliseconds".to_owned(),
                relative_to: None,
                owner: "test".to_owned(),
            },
            crate::model::Threshold {
                id: "fail".to_owned(),
                workload_id: "w".to_owned(),
                metric: "p95".to_owned(),
                comparator: Comparator::LessThanOrEqual,
                value: 2.0,
                unit: "milliseconds".to_owned(),
                relative_to: None,
                owner: "test".to_owned(),
            },
        ];
        apply_thresholds(&mut results, &specification, true);
        assert_eq!(
            results[0].threshold_results[0].status,
            ThresholdStatus::Pass
        );
        assert_eq!(
            results[0].threshold_results[1].status,
            ThresholdStatus::Fail
        );
    }
}
