use apple_container_adapter_spike::capability::{
    AdrConsequence, CommandEvidence, HostInfo, ProbeReport, ServiceState, Verdict, analyze,
    trusted_fixture_executable,
};
use apple_container_adapter_spike::process::ProcessTermination;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Fixture {
    host: HostInfo,
    version: String,
    status: StatusFixture,
    help: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct StatusFixture {
    exit_code: i32,
    stdout: String,
}

fn load_fixture(name: &str) -> (HostInfo, BTreeMap<String, CommandEvidence>) {
    let contents = match name {
        "0.10.0" => include_str!("fixtures/container-0.10.0.json"),
        "legacy" => include_str!("fixtures/container-legacy.json"),
        _ => panic!("unknown fixture"),
    };
    let fixture: Fixture = serde_json::from_str(contents).expect("valid fixture");
    let mut evidence = BTreeMap::new();
    evidence.insert(
        "cli_version".to_owned(),
        observation(vec!["--version"], 0, fixture.version),
    );
    evidence.insert(
        "service_status".to_owned(),
        observation(
            vec!["system", "status", "--format", "json"],
            fixture.status.exit_code,
            fixture.status.stdout,
        ),
    );
    for (name, stdout) in fixture.help {
        evidence.insert(name, observation(vec!["--help"], 0, stdout));
    }
    (fixture.host, evidence)
}

fn observation(argv: Vec<&str>, exit_code: i32, stdout: String) -> CommandEvidence {
    CommandEvidence {
        argv: argv.into_iter().map(str::to_owned).collect(),
        exit_code: Some(exit_code),
        signal: None,
        termination: Some(ProcessTermination::Exited),
        stdout,
        stderr: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        error: None,
    }
}

fn report(name: &str) -> ProbeReport {
    let (host, evidence) = load_fixture(name);
    analyze(
        host,
        trusted_fixture_executable("/usr/local/bin/container"),
        evidence,
    )
}

#[test]
fn stopped_service_report_is_deterministic_and_honest() {
    let report = report("0.10.0");
    assert_eq!(report.service.state, ServiceState::Unregistered);
    assert_eq!(
        report
            .capabilities
            .iter()
            .find(|item| item.behavior == "initialize_preflight")
            .expect("preflight verdict")
            .verdict,
        Verdict::Supported
    );
    assert_eq!(
        report
            .capabilities
            .iter()
            .find(|item| item.behavior == "transport_provisioning")
            .expect("transport verdict")
            .verdict,
        Verdict::Unverified
    );
    assert_eq!(
        report.conclusion.adr_consequence,
        AdrConsequence::TemporarySwiftIpcBridgeStillNeeded
    );
    let first = serde_json::to_string_pretty(&report).expect("serialize report");
    let second = serde_json::to_string_pretty(&report).expect("serialize report");
    assert_eq!(first, second);
}

#[test]
fn complete_help_without_socket_option_is_unsupported() {
    let report = report("legacy");
    assert_eq!(report.service.state, ServiceState::Stopped);
    assert_eq!(
        report
            .capabilities
            .iter()
            .find(|item| item.behavior == "transport_provisioning")
            .expect("transport verdict")
            .verdict,
        Verdict::Unsupported
    );
    assert_eq!(
        report.conclusion.adr_consequence,
        AdrConsequence::DirectRustVirtualizationFrameworkRequired
    );
}

#[test]
fn truncated_help_is_unverified_not_unsupported() {
    let (host, mut evidence) = load_fixture("legacy");
    evidence
        .get_mut("create_help")
        .expect("create help")
        .stdout_truncated = true;
    let report = analyze(
        host,
        trusted_fixture_executable("/usr/local/bin/container"),
        evidence,
    );
    assert_eq!(
        report
            .capabilities
            .iter()
            .find(|item| item.behavior == "transport_provisioning")
            .expect("transport verdict")
            .verdict,
        Verdict::Unverified
    );
}

#[test]
fn non_macos_host_reports_runtime_unavailable() {
    let (_, evidence) = load_fixture("0.10.0");
    let report = analyze(
        HostInfo {
            operating_system: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            version: "fixture".to_owned(),
        },
        trusted_fixture_executable("/usr/local/bin/container"),
        evidence,
    );
    assert!(
        report
            .capabilities
            .iter()
            .all(|item| item.verdict == Verdict::Unsupported)
    );
    assert_eq!(report.conclusion.overall_verdict, Verdict::Unsupported);
    assert_eq!(
        report.conclusion.adr_consequence,
        AdrConsequence::PlatformUnavailable
    );
}
