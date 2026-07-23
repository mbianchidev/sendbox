use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use ed25519_dalek::{Signer, SigningKey};
use sendbox_bundle::Architecture;
use sendbox_guest::manifest::{
    ArtifactExpectation, ArtifactKind, ArtifactManifest, MANIFEST_DOMAIN, MANIFEST_SCHEMA_VERSION,
    SignedManifestEnvelope, encode_hex,
};
use sendbox_runtime::{
    CancellationToken, CommandArgument, CommandSpec, ContainerId, CreateRequest, ExecPurpose,
    ExecRequest, InitializeRequest, LifecycleState, PreflightRequest, Program, RuntimeCapabilities,
    RuntimeCapability, RuntimeId, RuntimeProvider, StartRequest, StopRequest, TerminationReason,
};
use sendbox_testkit::{RuntimeConformanceScenario, run_runtime_conformance};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{
    AuthenticatedLaunchRequest, HyperlightConfiguration, HyperlightMount,
    HyperlightNetworkConfiguration, HyperlightNetworkMode, HyperlightRuntime, network_arguments,
    shell_command, validate_mount_staging_separation, validate_mounts, validate_trusted_file,
    verify_kvm_device,
};

struct Fixture {
    _temporary: TempDir,
    runtime: HyperlightRuntime,
    state: PathBuf,
    bundle: PathBuf,
    readonly_source: PathBuf,
}

impl Fixture {
    fn new(script: &str, network: HyperlightNetworkConfiguration) -> Self {
        Self::new_with_start(script, network, None)
    }

    fn new_with_start(
        script: &str,
        network: HyperlightNetworkConfiguration,
        start_command: Option<CommandSpec>,
    ) -> Self {
        let temporary = tempfile::tempdir_in(std::env::current_dir().expect("current directory"))
            .expect("temporary");
        let executable = temporary.path().join("hyperlight-unikraft");
        fs::write(&executable, script).expect("script");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("script mode");
        let bundle = temporary.path().join("bundle");
        fs::create_dir(&bundle).expect("bundle");
        let kernel = bundle.join("kernel");
        let initrd = bundle.join("rootfs.cpio");
        fs::write(&kernel, b"kernel").expect("kernel");
        fs::write(&initrd, b"initrd").expect("initrd");
        fs::set_permissions(&kernel, fs::Permissions::from_mode(0o500)).expect("kernel mode");
        fs::set_permissions(&initrd, fs::Permissions::from_mode(0o400)).expect("initrd mode");
        let key = SigningKey::from_bytes(&[7; 32]);
        let public_key = temporary.path().join("release-public.key");
        fs::write(&public_key, key.verifying_key().to_bytes()).expect("public key");
        fs::set_permissions(&public_key, fs::Permissions::from_mode(0o400))
            .expect("public key mode");
        write_bundle(&bundle, &key, &kernel, &initrd);

        let readonly_source = temporary.path().join("readonly");
        fs::create_dir(&readonly_source).expect("readonly source");
        fs::write(readonly_source.join("value.txt"), b"original").expect("readonly value");
        let state = temporary.path().join("state");
        fs::create_dir(&state).expect("state");
        let configuration = HyperlightConfiguration {
            executable,
            expected_cli_version: "0.test".to_owned(),
            bundle_root: bundle.clone(),
            public_key,
            trust_root_id: "test-root".to_owned(),
            expected_host_version: "0.1.0".to_owned(),
            expected_guest_version: "0.1.0".to_owned(),
            minimum_release_sequence: 1,
            kernel_path: kernel,
            initrd_path: Some(initrd),
            memory_mib: 64,
            stack_mib: 8,
            working_directory: PathBuf::from("/work"),
            start_command,
            mounts: vec![HyperlightMount {
                source: readonly_source.clone(),
                destination: PathBuf::from("/work/config"),
                read_only: true,
            }],
            network,
            listen_ports: Vec::new(),
            process_options: sendbox_runtime::ProcessOptions {
                timeout: Some(Duration::from_secs(10)),
                termination_grace: Duration::from_secs(5),
                ..sendbox_runtime::ProcessOptions::default()
            },
        };
        let runtime = HyperlightRuntime::new_inner(configuration, true).expect("runtime");
        Self {
            _temporary: temporary,
            runtime,
            state,
            bundle,
            readonly_source,
        }
    }

    async fn running(&self) -> ContainerId {
        let cancellation = CancellationToken::new();
        self.runtime
            .initialize(
                InitializeRequest {
                    state_directory: self.state.clone(),
                },
                &cancellation,
            )
            .await
            .expect("initialize");
        self.runtime
            .preflight(PreflightRequest::default(), &cancellation)
            .await
            .expect("preflight");
        let id = ContainerId::new("hyperlight-test").expect("ID");
        self.runtime
            .create(
                CreateRequest {
                    container_id: id.clone(),
                    image: self.bundle.display().to_string(),
                },
                &cancellation,
            )
            .await
            .expect("create");
        self.runtime
            .start(
                &id,
                StartRequest {
                    attach_standard_streams: false,
                },
                &cancellation,
            )
            .await
            .expect("start");
        id
    }

    fn temporary_path(&self) -> &Path {
        self._temporary.path()
    }
}

#[test]
fn exact_official_argv_and_minimal_host_environment() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nexit 0\n",
        HyperlightNetworkConfiguration {
            mode: HyperlightNetworkMode::AllowList,
            allowed_hosts: vec!["api.github.com".to_owned()],
            ..deny_network()
        },
    );
    let runtime = &fixture.runtime;
    let artifacts = runtime.load_artifacts().expect("artifacts");
    let directory = fixture.temporary_path().join("argv-container");
    fs::create_dir(&directory).expect("container directory");
    let container = std::sync::Arc::new(super::Container {
        lifecycle: sendbox_runtime::LifecycleStateMachine::new(LifecycleState::Running),
        operation: tokio::sync::Mutex::new(()),
        artifacts,
        directory: directory.clone(),
        directory_handle: test_directory_handle(&directory),
        start: tokio::sync::Mutex::new(None),
        output: tokio::sync::Mutex::new(None),
        last_result: tokio::sync::Mutex::new(None),
        pending_cleanup: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        active_invocations: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        active_notify: tokio::sync::Notify::new(),
    });
    let staging = runtime
        .prepare_invocation(&container, None)
        .expect("staging");
    let mut guest_command = command("printf", &["%s", "value'; rm -rf /"]);
    guest_command.arguments[1] = CommandArgument::sensitive("value'; rm -rf /");
    let host = runtime
        .launch_command(&staging, &guest_command, &[8080])
        .expect("launch command");
    assert!(host.arguments.last().expect("exec expression").sensitive);
    assert_eq!(
        host.environment
            .iter()
            .map(|variable| (variable.key.as_str(), variable.value.as_str()))
            .collect::<Vec<_>>(),
        [("LANG", "C"), ("PATH", "/usr/bin:/bin")]
    );
    let arguments = host
        .arguments
        .iter()
        .map(|argument| argument.value.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        arguments[1..7],
        [
            "--initrd",
            staging
                .initrd_path()
                .expect("initrd")
                .to_str()
                .expect("UTF-8"),
            "--memory",
            "64Mi",
            "--stack",
            "8Mi",
        ]
    );
    assert!(arguments.contains(&"--quiet"));
    assert!(arguments.contains(&"--mount"));
    assert!(arguments.contains(&"--net-allow"));
    assert!(arguments.windows(2).any(|pair| pair == ["--port", "8080"]));
    assert_eq!(arguments[arguments.len() - 2], "--exec");
    assert_eq!(
        arguments.last().copied(),
        Some("cd '/work' && exec 'printf' '%s' 'value'\\''; rm -rf /'")
    );
}

#[test]
fn every_read_only_mount_stage_is_fresh() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nexit 0\n",
        deny_network(),
    );
    let artifacts = fixture.runtime.load_artifacts().expect("artifacts");
    let directory = fixture.temporary_path().join("mount-container");
    fs::create_dir(&directory).expect("container directory");
    let container = std::sync::Arc::new(super::Container {
        lifecycle: sendbox_runtime::LifecycleStateMachine::new(LifecycleState::Running),
        operation: tokio::sync::Mutex::new(()),
        artifacts,
        directory: directory.clone(),
        directory_handle: test_directory_handle(&directory),
        start: tokio::sync::Mutex::new(None),
        output: tokio::sync::Mutex::new(None),
        last_result: tokio::sync::Mutex::new(None),
        pending_cleanup: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        active_invocations: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        active_notify: tokio::sync::Notify::new(),
    });
    let mut first = fixture
        .runtime
        .prepare_invocation(&container, None)
        .expect("first staging");
    let first_mount = first.mounts()[0].source.clone();
    fs::set_permissions(&first_mount, fs::Permissions::from_mode(0o700))
        .expect("unlock first mount");
    fs::set_permissions(
        first_mount.join("value.txt"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("unlock first value");
    fs::write(first_mount.join("value.txt"), b"mutated").expect("mutate first");

    let mut second = fixture
        .runtime
        .prepare_invocation(&container, None)
        .expect("second staging");
    let second_mount = second.mounts()[0].source.clone();
    assert_ne!(first_mount, second_mount);
    assert_eq!(
        fs::read(second_mount.join("value.txt")).expect("second value"),
        b"original"
    );
    first.cleanup().expect("first cleanup");
    second.cleanup().expect("second cleanup");
}

fn deny_network() -> HyperlightNetworkConfiguration {
    HyperlightNetworkConfiguration::default()
}

fn command(program: &str, arguments: &[&str]) -> CommandSpec {
    CommandSpec {
        arguments: arguments
            .iter()
            .map(|value| CommandArgument::plain(*value))
            .collect(),
        current_directory: Some(PathBuf::from("/work")),
        ..CommandSpec::new(Program::Named(program.to_owned()))
    }
}

fn test_directory_handle(path: &Path) -> std::sync::Arc<cap_std::fs::Dir> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
    let descriptor =
        sendbox_guest::secure_fs::open_directory_no_symlinks(path).expect("open directory");
    std::sync::Arc::new(cap_std::fs::Dir::from_std_file(std::fs::File::from(
        descriptor,
    )))
}

#[test]
fn command_quoting_blocks_shell_injection() {
    let rendered =
        shell_command(&command("printf", &["%s", "value'; touch /host/pwned"])).expect("command");
    assert_eq!(rendered, "'printf' '%s' 'value'\\''; touch /host/pwned'");
}

#[test]
fn network_precedence_and_ip_families_are_exact() {
    let precedence = HyperlightNetworkConfiguration {
        mode: HyperlightNetworkMode::AllowList,
        allowed_hosts: vec!["API.GITHUB.COM.".to_owned()],
        blocked_hosts: vec!["api.github.com".to_owned()],
        ..deny_network()
    };
    assert!(
        network_arguments(&precedence)
            .expect("precedence")
            .is_empty()
    );

    let addresses = HyperlightNetworkConfiguration {
        mode: HyperlightNetworkMode::AllowList,
        allowed_addresses: vec!["192.0.2.9/32".to_owned(), "2001:db8::9/128".to_owned()],
        ..deny_network()
    };
    let arguments = network_arguments(&addresses)
        .expect("network")
        .into_iter()
        .map(|argument| argument.value)
        .collect::<Vec<_>>();
    assert_eq!(
        arguments,
        ["--net-allow", "192.0.2.9", "--net-allow", "2001:db8::9"]
    );
}

#[test]
fn unsupported_network_controls_fail_closed() {
    for policy in [
        HyperlightNetworkConfiguration {
            mode: HyperlightNetworkMode::AllowList,
            allowed_hosts: vec!["*.github.com".to_owned()],
            ..deny_network()
        },
        HyperlightNetworkConfiguration {
            mode: HyperlightNetworkMode::AllowList,
            allowed_addresses: vec!["192.0.2.0/24".to_owned()],
            ..deny_network()
        },
        HyperlightNetworkConfiguration {
            mode: HyperlightNetworkMode::AllowList,
            allowed_hosts: vec!["api.github.com".to_owned()],
            allow_dns: false,
            ..deny_network()
        },
        HyperlightNetworkConfiguration {
            mode: HyperlightNetworkMode::AllowList,
            allowed_hosts: vec!["api.github.com".to_owned()],
            max_connections: Some(10),
            ..deny_network()
        },
        HyperlightNetworkConfiguration {
            mode: HyperlightNetworkMode::AllowList,
            allowed_hosts: vec!["api.github.com".to_owned()],
            blocked_addresses: vec!["192.0.2.9/32".to_owned()],
            ..deny_network()
        },
        HyperlightNetworkConfiguration {
            mode: HyperlightNetworkMode::AllowList,
            allowed_hosts: vec!["api.github.com".to_owned()],
            custom_dns_controls: true,
            ..deny_network()
        },
    ] {
        assert!(network_arguments(&policy).is_err());
    }
}

#[test]
fn trusted_executable_rejects_symlinks_and_untrusted_ownership() {
    let temporary = tempfile::tempdir_in(std::env::current_dir().expect("current directory"))
        .expect("temporary");
    let executable = temporary.path().join("hyperlight-unikraft");
    fs::write(&executable, b"binary").expect("binary");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("mode");
    assert!(validate_trusted_file(&executable, true).is_err());

    let link = temporary.path().join("link");
    std::os::unix::fs::symlink(&executable, &link).expect("symlink");
    assert!(validate_trusted_file(&link, true).is_err());
}

#[test]
fn writable_mounts_fail_closed() {
    let temporary =
        tempfile::tempdir_in(std::env::current_dir().expect("current directory")).expect("temp");
    assert!(
        validate_mounts(&[HyperlightMount {
            source: temporary.path().to_path_buf(),
            destination: PathBuf::from("/work"),
            read_only: false,
        }])
        .is_err()
    );
}

#[test]
fn mount_source_cannot_contain_staging_root() {
    let mounts = [HyperlightMount {
        source: PathBuf::from("/var/lib/sendbox"),
        destination: PathBuf::from("/work"),
        read_only: true,
    }];
    assert!(
        validate_mount_staging_separation(
            &mounts,
            Path::new("/var/lib/sendbox/hyperlight/container/invocation-1"),
        )
        .is_err()
    );
}

#[test]
fn kvm_open_errors_are_explicit() {
    let runtime = RuntimeId::new("hyperlight").expect("runtime");
    let error = verify_kvm_device(Path::new("/definitely/missing/sendbox-kvm"), &runtime)
        .expect_err("missing KVM");
    assert!(error.to_string().contains("readable and writable"));
}

#[tokio::test]
async fn writable_state_ancestor_is_rejected() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nexit 0\n",
        deny_network(),
    );
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o777)).expect("writable state");
    let error = fixture
        .runtime
        .initialize(
            InitializeRequest {
                state_directory: fixture.state.clone(),
            },
            &CancellationToken::new(),
        )
        .await
        .expect_err("writable ancestor rejected");
    assert!(error.to_string().contains("state path component"));
}

#[tokio::test]
async fn lifecycle_exec_output_exit_and_fresh_mount_cleanup() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nprintf 'hello'; printf 'problem' >&2; exit 7\n",
        deny_network(),
    );
    let id = fixture.running().await;
    let cancellation = CancellationToken::new();
    let outcome = fixture
        .runtime
        .exec(
            &id,
            ExecRequest {
                command: command("printf", &["hello"]),
                purpose: ExecPurpose::BootstrapControl,
            },
            &cancellation,
        )
        .await
        .expect("exec outcome");
    assert_eq!(outcome.status.code, Some(7));
    assert_eq!(outcome.stdout.bytes, b"hello");
    assert_eq!(outcome.stderr.bytes, b"problem");
    assert_eq!(
        fs::read(fixture.readonly_source.join("value.txt")).expect("source"),
        b"original"
    );
    let container_directory = fixture.state.join("hyperlight").join(id.as_str());
    assert!(
        fs::read_dir(&container_directory)
            .expect("container directory")
            .next()
            .is_none()
    );
    assert_eq!(
        fixture
            .runtime
            .status(&id, &cancellation)
            .await
            .expect("status")
            .lifecycle,
        LifecycleState::Running
    );
    fixture
        .runtime
        .stop(&id, StopRequest::default(), &cancellation)
        .await
        .expect("stop");
    assert!(
        fixture
            .runtime
            .active_start_cancellations
            .lock()
            .expect("active starts")
            .is_empty()
    );
    assert!(
        fixture
            .runtime
            .cleanup(&id, &cancellation)
            .await
            .expect("cleanup")
            .is_complete()
    );
}

#[tokio::test]
async fn cancellation_terminates_microvm_and_cleans_staging() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nsleep 30\n",
        deny_network(),
    );
    let id = fixture.running().await;
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    let future = fixture.runtime.exec(
        &id,
        ExecRequest {
            command: command("sleep", &["30"]),
            purpose: ExecPurpose::BootstrapControl,
        },
        &cancellation,
    );
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
    });
    let outcome = future.await.expect("cancelled outcome");
    canceller.await.expect("canceller");
    assert_eq!(outcome.termination, TerminationReason::Cancelled);
    let container_directory = fixture.state.join("hyperlight").join(id.as_str());
    assert!(
        fs::read_dir(container_directory)
            .expect("container directory")
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn stop_cancels_active_direct_exec() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nsleep 30\n",
        deny_network(),
    );
    let id = fixture.running().await;
    let exec_cancellation = CancellationToken::new();
    let stop_cancellation = CancellationToken::new();
    let exec = fixture.runtime.exec(
        &id,
        ExecRequest {
            command: command("sleep", &["30"]),
            purpose: ExecPurpose::BootstrapControl,
        },
        &exec_cancellation,
    );
    let stop = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        fixture
            .runtime
            .stop(&id, StopRequest::default(), &stop_cancellation)
            .await
    };
    let (outcome, stopped) = tokio::join!(exec, stop);
    assert_eq!(
        outcome.expect("exec cancellation").termination,
        TerminationReason::Cancelled
    );
    stopped.expect("stop active exec");
}

#[tokio::test]
async fn stop_cancels_start_microvm_and_cleanup_removes_session() {
    let fixture = Fixture::new_with_start(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nsleep 30\n",
        deny_network(),
        Some(command("sleep", &["30"])),
    );
    let id = fixture.running().await;
    let cancellation = CancellationToken::new();
    fixture
        .runtime
        .stop(&id, StopRequest::default(), &cancellation)
        .await
        .expect("stop");
    assert_eq!(
        fixture
            .runtime
            .status(&id, &cancellation)
            .await
            .expect("status")
            .lifecycle,
        LifecycleState::Stopped
    );
    assert!(
        fixture
            .runtime
            .cleanup(&id, &cancellation)
            .await
            .expect("cleanup")
            .is_complete()
    );
    assert!(!fixture.state.join("hyperlight").join(id.as_str()).exists());
}

#[tokio::test]
async fn authenticated_launch_stages_secret_without_environment_support() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nexit 0\n",
        deny_network(),
    );
    let id = fixture.running().await;
    let outcome = fixture
        .runtime
        .execute_authenticated_once(
            &id,
            AuthenticatedLaunchRequest {
                command: CommandSpec {
                    current_directory: Some(PathBuf::from("/work")),
                    ..CommandSpec::new(Program::Absolute(PathBuf::from("/sendbox-guest")))
                },
                bootstrap_material: sendbox_runtime::BootstrapMaterial::new([9; 32])
                    .expect("bootstrap"),
                listen_ports: Vec::new(),
            },
            &CancellationToken::new(),
        )
        .await
        .expect("authenticated launch");
    assert!(outcome.status.success);
}

#[tokio::test]
async fn authenticated_port_without_network_fails_closed() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nexit 0\n",
        deny_network(),
    );
    let id = fixture.running().await;
    let error = fixture
        .runtime
        .execute_authenticated_once(
            &id,
            AuthenticatedLaunchRequest {
                command: command("server", &[]),
                bootstrap_material: sendbox_runtime::BootstrapMaterial::new([9; 32])
                    .expect("bootstrap"),
                listen_ports: vec![8080],
            },
            &CancellationToken::new(),
        )
        .await
        .expect_err("port requires network");
    assert!(
        error
            .to_string()
            .contains("explicit Hyperlight network policy")
    );
}

#[tokio::test]
async fn provider_rejects_brokered_workloads_and_control_channels() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nexit 0\n",
        deny_network(),
    );
    let id = fixture.running().await;
    assert!(
        fixture
            .runtime
            .exec(
                &id,
                ExecRequest {
                    command: command("true", &[]),
                    purpose: ExecPurpose::Workload,
                },
                &CancellationToken::new(),
            )
            .await
            .is_err()
    );
    let capabilities = fixture.runtime.capabilities();
    assert!(!capabilities.contains(RuntimeCapability::BrokeredExec));
    assert!(!capabilities.contains(RuntimeCapability::TransportProvisioning));
}

#[tokio::test]
async fn shared_runtime_conformance_passes_for_one_shot_subset() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nprintf 'ok'; exit 0\n",
        deny_network(),
    );
    run_runtime_conformance(
        &fixture.runtime,
        RuntimeConformanceScenario {
            initialize: InitializeRequest {
                state_directory: fixture.state.clone(),
            },
            create: CreateRequest {
                container_id: ContainerId::new("conformance-hyperlight").expect("ID"),
                image: fixture.bundle.display().to_string(),
            },
            start: StartRequest {
                attach_standard_streams: false,
            },
            exec: ExecRequest {
                command: command("echo", &["ok"]),
                purpose: ExecPurpose::BootstrapControl,
            },
            signal: None,
        },
    )
    .await
    .expect("conformance");
}

#[tokio::test]
async fn preflight_reports_agent_capabilities_missing() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nexit 0\n",
        deny_network(),
    );
    fixture
        .runtime
        .initialize(
            InitializeRequest {
                state_directory: fixture.state.clone(),
            },
            &CancellationToken::new(),
        )
        .await
        .expect("initialize");
    let report = fixture
        .runtime
        .preflight(
            PreflightRequest {
                required_capabilities: RuntimeCapabilities::from([
                    RuntimeCapability::Lifecycle,
                    RuntimeCapability::BrokeredExec,
                    RuntimeCapability::TransportProvisioning,
                ]),
            },
            &CancellationToken::new(),
        )
        .await
        .expect("preflight");
    assert!(!report.is_compatible());
    assert!(
        report
            .missing_capabilities
            .contains(RuntimeCapability::BrokeredExec)
    );
}

#[tokio::test]
async fn signed_bundle_tampering_fails_preflight() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nexit 0\n",
        deny_network(),
    );
    let kernel = fixture.bundle.join("kernel");
    fs::set_permissions(&kernel, fs::Permissions::from_mode(0o700)).expect("unlock kernel");
    fs::write(&kernel, b"tampered").expect("tamper");
    fixture
        .runtime
        .initialize(
            InitializeRequest {
                state_directory: fixture.state.clone(),
            },
            &CancellationToken::new(),
        )
        .await
        .expect("initialize");
    let error = fixture
        .runtime
        .preflight(PreflightRequest::default(), &CancellationToken::new())
        .await
        .expect_err("tampering rejected");
    assert!(error.to_string().contains("bundle verification failed"));
}

#[tokio::test]
async fn artifact_mutation_after_create_is_rehashed_before_launch() {
    let fixture = Fixture::new(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'hyperlight-unikraft 0.test'; exit 0; fi\nexit 0\n",
        deny_network(),
    );
    let id = fixture.running().await;
    let kernel = fixture.bundle.join("kernel");
    fs::set_permissions(&kernel, fs::Permissions::from_mode(0o700)).expect("unlock kernel");
    fs::write(&kernel, b"tampered-after-create").expect("tamper");
    let error = fixture
        .runtime
        .exec(
            &id,
            ExecRequest {
                command: command("true", &[]),
                purpose: ExecPurpose::BootstrapControl,
            },
            &CancellationToken::new(),
        )
        .await
        .expect_err("mutation rejected");
    assert!(
        error
            .to_string()
            .contains("changed after signature verification")
    );
}

fn write_bundle(root: &Path, signing_key: &SigningKey, kernel: &Path, initrd: &Path) {
    let uid = fs::metadata(kernel).expect("kernel metadata").uid();
    let gid = fs::metadata(kernel).expect("kernel metadata").gid();
    let artifacts = vec![
        artifact(
            ArtifactKind::UnikraftShellKernel,
            "kernel",
            kernel,
            0o500,
            uid,
            gid,
        ),
        artifact(ArtifactKind::Initrd, "rootfs.cpio", initrd, 0o400, uid, gid),
    ];
    let manifest = ArtifactManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        domain: MANIFEST_DOMAIN.to_owned(),
        trust_root_id: "test-root".to_owned(),
        release_sequence: 1,
        minimum_accepted_sequence: 1,
        expected_host_version: "0.1.0".to_owned(),
        expected_guest_version: "0.1.0".to_owned(),
        architecture: match std::env::consts::ARCH {
            "aarch64" => Architecture::Aarch64.as_str(),
            _ => Architecture::X86_64.as_str(),
        }
        .to_owned(),
        artifacts: artifacts.clone(),
    };
    let payload = serde_json::to_string(&manifest).expect("manifest payload");
    let signature = encode_hex(&signing_key.sign(payload.as_bytes()).to_bytes());
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec(&SignedManifestEnvelope {
            payload,
            signature: signature.clone(),
        })
        .expect("manifest"),
    )
    .expect("manifest");
    fs::write(root.join("manifest.sig"), &signature).expect("manifest signature");

    let inventory_artifacts = artifacts
        .iter()
        .map(|artifact| {
            json!({
                "kind": match artifact.kind {
                    ArtifactKind::UnikraftShellKernel => "unikraft_shell_kernel",
                    ArtifactKind::Initrd => "initrd",
                    _ => unreachable!(),
                },
                "path": artifact.path,
                "sha256": artifact.sha256,
                "mode": artifact.mode,
                "uid": artifact.uid,
                "gid": artifact.gid,
            })
        })
        .collect::<Vec<_>>();
    let inventory = json!({
        "schema_version": 1,
        "domain": "dev.sendbox.guest.release-metadata.v1",
        "trust_root_id": "test-root",
        "release_sequence": 1,
        "architecture": manifest.architecture,
        "artifacts": inventory_artifacts,
    });
    let inventory_payload = serde_json::to_string(&inventory).expect("inventory");
    let inventory_signature =
        encode_hex(&signing_key.sign(inventory_payload.as_bytes()).to_bytes());
    fs::write(
        root.join("release-metadata.json"),
        serde_json::to_vec(&SignedManifestEnvelope {
            payload: inventory_payload.clone(),
            signature: inventory_signature.clone(),
        })
        .expect("release metadata"),
    )
    .expect("release metadata");
    fs::write(root.join("release-metadata.sig"), inventory_signature)
        .expect("release metadata signature");
    let share = root.join("share/sendbox");
    fs::create_dir_all(&share).expect("share");
    fs::write(share.join("inventory.json"), inventory_payload).expect("inventory file");
}

fn artifact(
    kind: ArtifactKind,
    relative: &str,
    path: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
) -> ArtifactExpectation {
    ArtifactExpectation {
        kind,
        path: PathBuf::from(relative),
        sha256: encode_hex(&Sha256::digest(fs::read(path).expect("artifact bytes"))),
        mode,
        uid,
        gid,
    }
}
