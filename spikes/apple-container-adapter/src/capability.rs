use crate::executable::{ExecutableReport, ExecutableResolver};
use crate::process::{
    CommandSpec, ProcessControls, ProcessOutput, ProcessRunner, ProcessTermination,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

const HELP_COMMANDS: &[(&str, &[&str])] = &[
    ("root_help", &["--help"]),
    ("create_help", &["create", "--help"]),
    ("run_help", &["run", "--help"]),
    ("start_help", &["start", "--help"]),
    ("exec_help", &["exec", "--help"]),
    ("logs_help", &["logs", "--help"]),
    ("kill_help", &["kill", "--help"]),
    ("stop_help", &["stop", "--help"]),
    ("delete_help", &["delete", "--help"]),
    ("inspect_help", &["inspect", "--help"]),
    ("list_help", &["list", "--help"]),
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostInfo {
    pub operating_system: String,
    pub architecture: String,
    pub version: String,
}

impl HostInfo {
    #[must_use]
    pub fn current() -> Self {
        Self {
            operating_system: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            version: host_version(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandEvidence {
    pub argv: Vec<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub termination: Option<ProcessTermination>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub error: Option<String>,
}

impl CommandEvidence {
    #[must_use]
    pub fn from_output(argv: Vec<String>, output: ProcessOutput) -> Self {
        Self {
            argv,
            exit_code: output.status.code,
            signal: output.status.signal,
            termination: Some(output.termination),
            stdout: output.stdout.text,
            stderr: output.stderr.text,
            stdout_truncated: output.stdout.truncated,
            stderr_truncated: output.stderr.truncated,
            error: None,
        }
    }

    #[must_use]
    pub fn failed(argv: Vec<String>, error: impl Into<String>) -> Self {
        Self {
            argv,
            exit_code: None,
            signal: None,
            termination: None,
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            error: Some(error.into()),
        }
    }

    #[must_use]
    pub fn complete_success(&self) -> bool {
        self.error.is_none()
            && self.exit_code == Some(0)
            && self.termination == Some(ProcessTermination::Exited)
            && !self.stdout_truncated
            && !self.stderr_truncated
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Running,
    Stopped,
    Unregistered,
    Unknown,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceReport {
    pub state: ServiceState,
    pub raw_status: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryStatus {
    Available,
    Missing,
    IncompleteEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeatureDiscovery {
    pub status: DiscoveryStatus,
    pub command: String,
    pub required_tokens: Vec<String>,
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Supported,
    Unsupported,
    Unverified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityVerdict {
    pub behavior: String,
    pub verdict: Verdict,
    pub evidence: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdrConsequence {
    CliAdapterViable,
    DirectRustVirtualizationFrameworkRequired,
    TemporarySwiftIpcBridgeStillNeeded,
    PlatformUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QualificationConclusion {
    pub overall_verdict: Verdict,
    pub adr_consequence: AdrConsequence,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProbeReport {
    pub schema_version: u32,
    pub host: HostInfo,
    pub executable: ExecutableReport,
    pub cli_version: Option<String>,
    pub service: ServiceReport,
    pub discoveries: BTreeMap<String, FeatureDiscovery>,
    pub capabilities: Vec<CapabilityVerdict>,
    pub evidence: BTreeMap<String, CommandEvidence>,
    pub conclusion: QualificationConclusion,
}

pub struct Probe<R> {
    runner: R,
    resolver: ExecutableResolver,
    timeout: Duration,
    output_limit: usize,
}

impl<R> Probe<R> {
    #[must_use]
    pub fn new(runner: R, timeout: Duration, output_limit: usize) -> Self {
        Self {
            runner,
            resolver: ExecutableResolver::default(),
            timeout,
            output_limit,
        }
    }

    #[must_use]
    pub fn with_resolver(mut self, resolver: ExecutableResolver) -> Self {
        self.resolver = resolver;
        self
    }
}

impl<R: ProcessRunner> Probe<R> {
    pub async fn run(&self, requested_executable: Option<&Path>) -> ProbeReport {
        let host = HostInfo::current();
        let executable = self.resolver.resolve(requested_executable);
        let mut evidence = BTreeMap::new();

        if let Some(path) = executable.resolved_path.as_deref()
            && executable.trusted
        {
            self.capture(path, "cli_version", &["--version"], &mut evidence)
                .await;
            self.capture(
                path,
                "service_status",
                &["system", "status", "--format", "json"],
                &mut evidence,
            )
            .await;
            for (name, arguments) in HELP_COMMANDS {
                self.capture(path, name, arguments, &mut evidence).await;
            }
        }

        analyze(host, executable, evidence)
    }

    async fn capture(
        &self,
        executable: &Path,
        name: &str,
        arguments: &[&str],
        evidence: &mut BTreeMap<String, CommandEvidence>,
    ) {
        let argv = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>();
        let specification = CommandSpec::new(executable, argv.clone());
        let controls = ProcessControls {
            timeout: self.timeout,
            stdout_limit: self.output_limit,
            stderr_limit: self.output_limit,
            ..ProcessControls::default()
        };
        let result = self.runner.run(&specification, controls).await;
        let observation = match result {
            Ok(output) => CommandEvidence::from_output(argv, output),
            Err(error) => CommandEvidence::failed(argv, error.to_string()),
        };
        evidence.insert(name.to_owned(), observation);
    }
}

#[must_use]
pub fn analyze(
    host: HostInfo,
    executable: ExecutableReport,
    evidence: BTreeMap<String, CommandEvidence>,
) -> ProbeReport {
    let cli_version = evidence
        .get("cli_version")
        .filter(|item| item.complete_success())
        .map(|item| item.stdout.trim().to_owned())
        .filter(|version| !version.is_empty());
    let service = service_report(evidence.get("service_status"));
    let discoveries = discoveries(&evidence);
    let capabilities = capability_verdicts(&host, &executable, &service, &discoveries);
    let conclusion = conclusion(&host, &executable, &service, &discoveries);

    ProbeReport {
        schema_version: 1,
        host,
        executable,
        cli_version,
        service,
        discoveries,
        capabilities,
        evidence,
        conclusion,
    }
}

fn service_report(evidence: Option<&CommandEvidence>) -> ServiceReport {
    let Some(evidence) = evidence else {
        return ServiceReport {
            state: ServiceState::Unavailable,
            raw_status: None,
            reason:
                "service status was not queried because the executable was unavailable or untrusted"
                    .to_owned(),
        };
    };
    if evidence.error.is_some()
        || evidence.stdout_truncated
        || evidence.termination != Some(ProcessTermination::Exited)
    {
        return ServiceReport {
            state: ServiceState::Unknown,
            raw_status: None,
            reason: "service status evidence was incomplete".to_owned(),
        };
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawStatus {
        status: String,
    }

    match serde_json::from_str::<RawStatus>(&evidence.stdout) {
        Ok(status) => {
            let normalized = status.status.to_ascii_lowercase();
            let state = match normalized.as_str() {
                "running" => ServiceState::Running,
                "stopped" => ServiceState::Stopped,
                "unregistered" => ServiceState::Unregistered,
                _ => ServiceState::Unknown,
            };
            ServiceReport {
                state,
                raw_status: Some(status.status),
                reason: format!(
                    "parsed `container system status --format json` with exit code {:?}",
                    evidence.exit_code
                ),
            }
        }
        Err(error) => ServiceReport {
            state: ServiceState::Unknown,
            raw_status: None,
            reason: format!("service status was not valid complete JSON: {error}"),
        },
    }
}

fn discoveries(evidence: &BTreeMap<String, CommandEvidence>) -> BTreeMap<String, FeatureDiscovery> {
    BTreeMap::from([
        (
            "run_create".to_owned(),
            discover(evidence, "create_help", &["USAGE:", "container create"]),
        ),
        (
            "detach".to_owned(),
            discover(evidence, "run_help", &["--detach"]),
        ),
        (
            "exec".to_owned(),
            discover(evidence, "exec_help", &["container exec"]),
        ),
        (
            "logs_attach".to_owned(),
            discover_multi(
                evidence,
                &[("logs_help", &["--follow"]), ("start_help", &["--attach"])],
            ),
        ),
        (
            "signal".to_owned(),
            discover(evidence, "kill_help", &["--signal"]),
        ),
        (
            "stop_delete".to_owned(),
            discover_multi(
                evidence,
                &[
                    ("stop_help", &["container stop", "--time"]),
                    ("delete_help", &["container delete"]),
                ],
            ),
        ),
        (
            "mounts".to_owned(),
            discover(evidence, "create_help", &["--mount", "--volume"]),
        ),
        (
            "environment".to_owned(),
            discover(evidence, "create_help", &["--env"]),
        ),
        (
            "dns_network".to_owned(),
            discover(evidence, "create_help", &["--dns", "--network"]),
        ),
        (
            "resource_limits".to_owned(),
            discover(evidence, "create_help", &["--cpus", "--memory", "--ulimit"]),
        ),
        (
            "kernel_selection".to_owned(),
            discover(evidence, "create_help", &["--kernel"]),
        ),
        (
            "structured_output".to_owned(),
            discover_multi(
                evidence,
                &[
                    ("list_help", &["--format"]),
                    ("inspect_help", &["container inspect"]),
                ],
            ),
        ),
        (
            "socket_publication".to_owned(),
            discover(evidence, "create_help", &["--publish-socket"]),
        ),
    ])
}

fn discover(
    evidence: &BTreeMap<String, CommandEvidence>,
    command: &str,
    required_tokens: &[&str],
) -> FeatureDiscovery {
    let Some(observation) = evidence.get(command) else {
        return FeatureDiscovery {
            status: DiscoveryStatus::IncompleteEvidence,
            command: command.to_owned(),
            required_tokens: strings(required_tokens),
            evidence: "help command was not captured".to_owned(),
        };
    };
    if !observation.complete_success() {
        return FeatureDiscovery {
            status: DiscoveryStatus::IncompleteEvidence,
            command: command.to_owned(),
            required_tokens: strings(required_tokens),
            evidence: "help output failed, timed out, was cancelled, or was truncated".to_owned(),
        };
    }
    let missing = required_tokens
        .iter()
        .filter(|token| !observation.stdout.contains(**token))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        FeatureDiscovery {
            status: DiscoveryStatus::Available,
            command: command.to_owned(),
            required_tokens: strings(required_tokens),
            evidence: format!(
                "complete help output contains {}",
                required_tokens.join(", ")
            ),
        }
    } else {
        FeatureDiscovery {
            status: DiscoveryStatus::Missing,
            command: command.to_owned(),
            required_tokens: strings(required_tokens),
            evidence: format!("complete help output is missing {}", missing.join(", ")),
        }
    }
}

fn discover_multi(
    evidence: &BTreeMap<String, CommandEvidence>,
    requirements: &[(&str, &[&str])],
) -> FeatureDiscovery {
    let results = requirements
        .iter()
        .map(|(command, tokens)| discover(evidence, command, tokens))
        .collect::<Vec<_>>();
    let status = if results
        .iter()
        .any(|result| result.status == DiscoveryStatus::Missing)
    {
        DiscoveryStatus::Missing
    } else if results
        .iter()
        .any(|result| result.status == DiscoveryStatus::IncompleteEvidence)
    {
        DiscoveryStatus::IncompleteEvidence
    } else {
        DiscoveryStatus::Available
    };
    FeatureDiscovery {
        status,
        command: results
            .iter()
            .map(|result| result.command.as_str())
            .collect::<Vec<_>>()
            .join(" + "),
        required_tokens: results
            .iter()
            .flat_map(|result| result.required_tokens.clone())
            .collect(),
        evidence: results
            .iter()
            .map(|result| result.evidence.as_str())
            .collect::<Vec<_>>()
            .join("; "),
    }
}

fn capability_verdicts(
    host: &HostInfo,
    executable: &ExecutableReport,
    service: &ServiceReport,
    discoveries: &BTreeMap<String, FeatureDiscovery>,
) -> Vec<CapabilityVerdict> {
    if host.operating_system != "macos" {
        return required_behaviors()
            .into_iter()
            .map(|(behavior, _)| CapabilityVerdict {
                behavior: behavior.to_owned(),
                verdict: Verdict::Unsupported,
                evidence: vec![format!("host operating system is {}", host.operating_system)],
                reason: "the official Apple container runtime is available only on supported macOS hosts"
                    .to_owned(),
            })
            .collect();
    }
    if !executable.trusted {
        return required_behaviors()
            .into_iter()
            .map(|(behavior, _)| CapabilityVerdict {
                behavior: behavior.to_owned(),
                verdict: Verdict::Unsupported,
                evidence: executable.reasons.clone(),
                reason: "no trusted executable is available".to_owned(),
            })
            .collect();
    }

    let mut verdicts = vec![CapabilityVerdict {
        behavior: "initialize_preflight".to_owned(),
        verdict: if service.state == ServiceState::Unknown
            || service.state == ServiceState::Unavailable
        {
            Verdict::Unverified
        } else {
            Verdict::Supported
        },
        evidence: vec![
            "trusted executable inspection completed".to_owned(),
            service.reason.clone(),
        ],
        reason: "version and service status are non-mutating and were executed directly".to_owned(),
    }];
    verdicts.extend(
        required_behaviors()
            .into_iter()
            .skip(1)
            .map(|(behavior, discovery)| verdict_from_discovery(behavior, discovery, discoveries)),
    );
    verdicts
}

fn verdict_from_discovery(
    behavior: &str,
    discovery_name: &str,
    discoveries: &BTreeMap<String, FeatureDiscovery>,
) -> CapabilityVerdict {
    let Some(discovery) = discoveries.get(discovery_name) else {
        return CapabilityVerdict {
            behavior: behavior.to_owned(),
            verdict: Verdict::Unverified,
            evidence: vec!["capability evidence was not collected".to_owned()],
            reason: "probe evidence is incomplete".to_owned(),
        };
    };
    let (verdict, reason) = match discovery.status {
        DiscoveryStatus::Available => (
            Verdict::Unverified,
            "the CLI advertises the surface, but the lifecycle operation was not exercised",
        ),
        DiscoveryStatus::Missing => (
            Verdict::Unsupported,
            "complete CLI help does not expose the required command or option",
        ),
        DiscoveryStatus::IncompleteEvidence => (
            Verdict::Unverified,
            "help evidence was incomplete and cannot prove absence",
        ),
    };
    CapabilityVerdict {
        behavior: behavior.to_owned(),
        verdict,
        evidence: vec![discovery.evidence.clone()],
        reason: reason.to_owned(),
    }
}

fn conclusion(
    host: &HostInfo,
    executable: &ExecutableReport,
    service: &ServiceReport,
    discoveries: &BTreeMap<String, FeatureDiscovery>,
) -> QualificationConclusion {
    if host.operating_system != "macos" {
        return QualificationConclusion {
            overall_verdict: Verdict::Unsupported,
            adr_consequence: AdrConsequence::PlatformUnavailable,
            reason: format!(
                "the official Apple container runtime cannot be qualified on {}",
                host.operating_system
            ),
        };
    }
    if !executable.trusted {
        return QualificationConclusion {
            overall_verdict: Verdict::Unsupported,
            adr_consequence: AdrConsequence::TemporarySwiftIpcBridgeStillNeeded,
            reason: "no trusted official container executable is available".to_owned(),
        };
    }
    if discoveries
        .get("socket_publication")
        .is_some_and(|item| item.status == DiscoveryStatus::Missing)
    {
        return QualificationConclusion {
            overall_verdict: Verdict::Unsupported,
            adr_consequence: AdrConsequence::DirectRustVirtualizationFrameworkRequired,
            reason: "the CLI lacks the required host/guest socket publication surface".to_owned(),
        };
    }
    if service.state == ServiceState::Running
        && discoveries
            .values()
            .all(|item| item.status == DiscoveryStatus::Available)
    {
        return QualificationConclusion {
            overall_verdict: Verdict::Unverified,
            adr_consequence: AdrConsequence::TemporarySwiftIpcBridgeStillNeeded,
            reason: "the advertised CLI surface is complete, but mutating lifecycle, streaming, cancellation, and socket behavior still require opt-in live qualification"
                .to_owned(),
        };
    }
    QualificationConclusion {
        overall_verdict: Verdict::Unverified,
        adr_consequence: AdrConsequence::TemporarySwiftIpcBridgeStillNeeded,
        reason: "the CLI surface is provisionally viable, but the stopped or unavailable service prevents lifecycle and control-channel qualification"
            .to_owned(),
    }
}

fn required_behaviors() -> Vec<(&'static str, &'static str)> {
    vec![
        ("initialize_preflight", ""),
        ("create", "run_create"),
        ("start_run", "run_create"),
        ("status", "structured_output"),
        ("exec", "exec"),
        ("attach_logs_output", "logs_attach"),
        ("signal", "signal"),
        ("stop", "stop_delete"),
        ("cleanup", "stop_delete"),
        ("mount_mapping", "mounts"),
        ("environment_mapping", "environment"),
        ("network_dns_mapping", "dns_network"),
        ("resource_mapping", "resource_limits"),
        ("kernel_selection", "kernel_selection"),
        ("structured_output", "structured_output"),
        ("transport_provisioning", "socket_publication"),
    ]
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn host_version() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .env_clear()
            .envs(crate::process::minimal_environment())
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .filter(|version| !version.is_empty())
            .unwrap_or_else(|| "unknown".to_owned())
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|contents| {
                contents.lines().find_map(|line| {
                    line.strip_prefix("PRETTY_NAME=")
                        .map(|value| value.trim_matches('"').to_owned())
                })
            })
            .unwrap_or_else(|| "unknown".to_owned())
    }
}

#[must_use]
pub fn trusted_fixture_executable(path: impl Into<PathBuf>) -> ExecutableReport {
    let path = path.into();
    ExecutableReport {
        requested_path: Some(path.clone()),
        resolved_path: Some(path),
        symlink_chain: Vec::new(),
        regular_file: true,
        owner_uid: Some(0),
        mode_octal: Some("0755".to_owned()),
        writable_by_group_or_other: false,
        trusted: true,
        reasons: Vec::new(),
    }
}
