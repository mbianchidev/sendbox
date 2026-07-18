use apple_container_adapter_spike::adapter::{
    AppleContainerAdapter, AppleContainerCommands, ContainerId, ContainerRequest, ExecRequest,
    GuestEnvironmentVariable, MountMapping, NetworkMapping, ResourceMapping, RuntimeAdapter,
};
use apple_container_adapter_spike::process::{
    CapturedOutput, CommandSpec, ExitStatusRecord, ProcessControls, ProcessError, ProcessOutput,
    ProcessRunner, ProcessTermination,
};
use apple_container_adapter_spike::transport::SocketPublication;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

fn success(stdout: &str) -> ProcessOutput {
    ProcessOutput {
        termination: ProcessTermination::Exited,
        status: ExitStatusRecord {
            success: true,
            code: Some(0),
            signal: None,
        },
        stdout: CapturedOutput {
            text: stdout.to_owned(),
            truncated: false,
        },
        stderr: CapturedOutput {
            text: String::new(),
            truncated: false,
        },
    }
}

#[test]
fn constructs_exact_run_and_transport_argv_without_secret_values() {
    let directory = tempdir().expect("temporary directory");
    let request = ContainerRequest {
        id: ContainerId::parse("sendbox-spike-1").expect("valid ID"),
        image: "ghcr.io/example/sendbox:latest".to_owned(),
        arguments: vec!["/run/sendbox/bin/sendbox-guest".to_owned()],
        detached: true,
        environment: vec![
            GuestEnvironmentVariable {
                key: "PUBLIC_MODE".to_owned(),
                value: "probe".to_owned(),
                sensitive: false,
            },
            GuestEnvironmentVariable {
                key: "TOKEN".to_owned(),
                value: "top-secret".to_owned(),
                sensitive: true,
            },
        ],
        mounts: vec![MountMapping {
            source: "/Users/example/project".into(),
            target: "/workspace".into(),
            read_only: true,
        }],
        network: NetworkMapping {
            network: Some("sendbox-net".to_owned()),
            dns_servers: vec!["1.1.1.1".to_owned()],
            dns_search: vec!["example.test".to_owned()],
            no_dns: false,
        },
        resources: ResourceMapping {
            cpus: Some(4),
            memory_mib: Some(2048),
            ulimits: vec!["nofile=1024:2048".to_owned()],
        },
        kernel: Some("/opt/sendbox/kernel".into()),
        transport: Some(
            SocketPublication::new(
                directory.path().join("control.sock"),
                "/run/sendbox/control.sock",
            )
            .expect("valid socket publication"),
        ),
    };

    let specification = AppleContainerCommands::new("/usr/local/bin/container")
        .run(&request)
        .expect("valid run command");
    assert_eq!(
        specification.arguments,
        vec![
            "run",
            "--name",
            "sendbox-spike-1",
            "--detach",
            "--env",
            "PUBLIC_MODE=probe",
            "--env",
            "TOKEN",
            "--mount",
            "type=bind,source=/Users/example/project,target=/workspace,readonly",
            "--network",
            "sendbox-net",
            "--dns",
            "1.1.1.1",
            "--dns-search",
            "example.test",
            "--cpus",
            "4",
            "--memory",
            "2048M",
            "--ulimit",
            "nofile=1024:2048",
            "--kernel",
            "/opt/sendbox/kernel",
            "--publish-socket",
            &format!(
                "{}:/run/sendbox/control.sock",
                directory.path().join("control.sock").display()
            ),
            "ghcr.io/example/sendbox:latest",
            "/run/sendbox/bin/sendbox-guest"
        ]
    );
    assert_eq!(
        specification.environment.get("TOKEN").map(String::as_str),
        Some("top-secret")
    );
    assert!(!specification.arguments.join(" ").contains("top-secret"));
    assert!(!specification.diagnostic().contains("top-secret"));
}

#[test]
fn constructs_status_exec_logs_signal_stop_and_cleanup_argv() {
    let commands = AppleContainerCommands::new("/usr/local/bin/container");
    let id = ContainerId::parse("sandbox_1").expect("valid ID");
    assert_eq!(commands.status(&id).arguments, vec!["inspect", "sandbox_1"]);
    assert_eq!(
        commands.attach_logs(&id).arguments,
        vec!["logs", "--follow", "sandbox_1"]
    );
    assert_eq!(
        commands
            .signal(&id, "SIGUSR1")
            .expect("valid signal")
            .arguments,
        vec!["kill", "--signal", "SIGUSR1", "sandbox_1"]
    );
    assert_eq!(
        commands.stop(&id, 15).arguments,
        vec!["stop", "--time", "15", "sandbox_1"]
    );
    assert_eq!(commands.delete(&id).arguments, vec!["delete", "sandbox_1"]);
    let exec = commands
        .exec(&ExecRequest {
            id,
            arguments: vec!["/bin/echo".to_owned(), "hello".to_owned()],
            environment: Vec::new(),
            workdir: Some("/workspace".into()),
            detached: false,
        })
        .expect("valid exec");
    assert_eq!(
        exec.arguments,
        vec![
            "exec",
            "--workdir",
            "/workspace",
            "sandbox_1",
            "/bin/echo",
            "hello"
        ]
    );
}

#[test]
fn rejects_invalid_container_ids() {
    for invalid in ["", "-leading", "contains space", "bad/slash"] {
        assert!(ContainerId::parse(invalid).is_err(), "{invalid}");
    }
}

#[derive(Clone, Default)]
struct RecordingRunner {
    commands: Arc<Mutex<Vec<Vec<String>>>>,
}

#[async_trait]
impl ProcessRunner for RecordingRunner {
    async fn run(
        &self,
        specification: &CommandSpec,
        _controls: ProcessControls,
    ) -> Result<ProcessOutput, ProcessError> {
        self.commands
            .lock()
            .expect("recording mutex")
            .push(specification.arguments.clone());
        Ok(success("{}"))
    }
}

#[tokio::test]
async fn adapter_is_mockable_and_preflight_is_non_mutating() {
    let runner = RecordingRunner::default();
    let commands = runner.commands.clone();
    let adapter = AppleContainerAdapter::new(
        "/usr/local/bin/container",
        runner,
        ProcessControls::default(),
    );

    adapter.initialize().await.expect("mock preflight");
    assert_eq!(
        *commands.lock().expect("recording mutex"),
        vec![
            vec!["--version"],
            vec!["system", "status", "--format", "json"]
        ]
    );
}
