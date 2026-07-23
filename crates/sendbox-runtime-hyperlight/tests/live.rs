use std::{path::PathBuf, time::Duration};

use sendbox_runtime::{
    CancellationToken, CommandArgument, CommandSpec, ContainerId, CreateRequest, ExecPurpose,
    ExecRequest, InitializeRequest, PreflightRequest, Program, RuntimeProvider, StartRequest,
    StopRequest,
};
use sendbox_runtime_hyperlight::{
    HyperlightConfiguration, HyperlightNetworkConfiguration, HyperlightRuntime,
};

#[tokio::test]
async fn live_hyperlight_launch_when_designated() {
    if std::env::var_os("SENDBOX_HYPERLIGHT_LIVE").is_none() {
        return;
    }
    let required = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{name} is required when SENDBOX_HYPERLIGHT_LIVE is set"))
    };
    let bundle = required("SENDBOX_HYPERLIGHT_BUNDLE");
    let configuration = HyperlightConfiguration {
        executable: required("SENDBOX_HYPERLIGHT_EXECUTABLE"),
        expected_cli_version: std::env::var("SENDBOX_HYPERLIGHT_CLI_VERSION")
            .expect("SENDBOX_HYPERLIGHT_CLI_VERSION is required"),
        public_key: required("SENDBOX_HYPERLIGHT_PUBLIC_KEY"),
        kernel_path: required("SENDBOX_HYPERLIGHT_KERNEL"),
        initrd_path: Some(required("SENDBOX_HYPERLIGHT_INITRD")),
        bundle_root: bundle.clone(),
        trust_root_id: std::env::var("SENDBOX_HYPERLIGHT_TRUST_ROOT_ID")
            .expect("SENDBOX_HYPERLIGHT_TRUST_ROOT_ID is required"),
        expected_host_version: env!("CARGO_PKG_VERSION").to_owned(),
        expected_guest_version: std::env::var("SENDBOX_HYPERLIGHT_GUEST_VERSION")
            .expect("SENDBOX_HYPERLIGHT_GUEST_VERSION is required"),
        minimum_release_sequence: std::env::var("SENDBOX_HYPERLIGHT_MIN_RELEASE")
            .expect("SENDBOX_HYPERLIGHT_MIN_RELEASE is required")
            .parse()
            .expect("SENDBOX_HYPERLIGHT_MIN_RELEASE must be an integer"),
        memory_mib: 64,
        stack_mib: 8,
        working_directory: PathBuf::from("/"),
        start_command: None,
        mounts: Vec::new(),
        network: HyperlightNetworkConfiguration::default(),
        listen_ports: Vec::new(),
        process_options: sendbox_runtime::ProcessOptions {
            timeout: Some(Duration::from_secs(30)),
            termination_grace: Duration::from_secs(5),
            ..sendbox_runtime::ProcessOptions::default()
        },
    };
    let runtime = HyperlightRuntime::new(configuration).expect("configuration");
    let cancellation = CancellationToken::new();
    let state = required("SENDBOX_HYPERLIGHT_STATE");
    runtime
        .initialize(
            InitializeRequest {
                state_directory: state,
            },
            &cancellation,
        )
        .await
        .expect("initialize");
    runtime
        .preflight(PreflightRequest::default(), &cancellation)
        .await
        .expect("live preflight");
    let id = ContainerId::new("live-hyperlight").expect("container ID");
    runtime
        .create(
            CreateRequest {
                container_id: id.clone(),
                image: bundle.display().to_string(),
            },
            &cancellation,
        )
        .await
        .expect("create");
    runtime
        .start(
            &id,
            StartRequest {
                attach_standard_streams: false,
            },
            &cancellation,
        )
        .await
        .expect("start");
    let outcome = runtime
        .exec(
            &id,
            ExecRequest {
                command: CommandSpec {
                    arguments: vec![CommandArgument::plain("sendbox-hyperlight-live")],
                    ..CommandSpec::new(Program::Named("echo".to_owned()))
                },
                purpose: ExecPurpose::BootstrapControl,
            },
            &cancellation,
        )
        .await;
    let stopped = runtime
        .stop(&id, StopRequest::default(), &cancellation)
        .await;
    let cleaned = runtime.cleanup(&id, &cancellation).await;
    let outcome = outcome.expect("live exec");
    stopped.expect("live stop");
    assert!(cleaned.expect("live cleanup").is_complete());
    assert!(outcome.status.success, "{outcome:?}");
}
