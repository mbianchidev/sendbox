#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use sendbox_exec::environment::EnvironmentPolicy;
use sendbox_exec::platform::linux::agent::AgentBootstrap;
use sendbox_exec::platform::linux::cgroup::CgroupManager;
use sendbox_exec::platform::linux::launcher::{
    EnvironmentAuthority, LauncherControl, LauncherInvocation, LauncherProcessBackend,
    LauncherRoot, write_control_frame,
};
use sendbox_exec::platform::linux::resolver::{RootDirectory, RootSet};
use sendbox_exec::policy::CompiledCommandPolicy;
use sendbox_exec::runtime::{RuntimeDirectory, authenticate_peer, connect};
use sendbox_exec::service::read_frame;
use sendbox_exec::session::BrokerSession;
use sendbox_exec::{
    AdmissionDisposition, Broker, CancellationFlag, ContainmentProfile, CorrelationId,
    DescriptorPath, EnvironmentEntry, ExecutionBackend, ExecutionDecision, ExecutionEvent,
    ExecutionRequest, ExecutionTimeout, KernelPrimitive, LaunchFailure, RelativePath,
    RequestLimits, RootId, SemanticScope, SinkError, TerminalState,
};
use sendbox_policy::{Action, CommandPolicy};

#[test]
fn descriptor_identity_survives_path_swap_and_new_symlink_is_rejected() {
    let directory = tempfile::tempdir().expect("tempdir");
    let executable = directory.path().join("tool");
    write_fake_elf(&executable);
    fs::create_dir(directory.path().join("work")).expect("workdir");

    let mut roots = RootSet::default();
    roots.insert(
        RootId::System,
        RootDirectory::open(directory.path()).expect("system root"),
    );
    roots.insert(
        RootId::Workspace,
        RootDirectory::open(directory.path()).expect("workspace root"),
    );
    let executable_path = DescriptorPath {
        root: RootId::System,
        relative: RelativePath::new("tool").expect("path"),
    };
    let cwd = DescriptorPath {
        root: RootId::Workspace,
        relative: RelativePath::new("work").expect("cwd"),
    };
    let resolved = roots.resolve(&executable_path, &cwd).expect("resolve");
    let retained_identity = resolved.executable_identity;

    fs::rename(&executable, directory.path().join("original")).expect("rename");
    std::os::unix::fs::symlink("original", &executable).expect("swap symlink");
    assert_eq!(resolved.executable_identity, retained_identity);
    assert!(roots.resolve(&executable_path, &cwd).is_err());
}

#[test]
fn cgroup_v2_gate_reports_the_exact_unavailable_primitive() {
    let session = BrokerSession::generate().expect("session");
    let parent = match current_cgroup() {
        Ok(parent) => parent,
        Err(error) => {
            assert_eq!(error.primitive, KernelPrimitive::CgroupV2);
            eprintln!(
                "unsupported live gate: {}: {}",
                error.primitive, error.detail
            );
            return;
        }
    };
    match CgroupManager::create(&parent, session.id()) {
        Ok(manager) => manager.remove().expect("remove fresh cgroup"),
        Err(sendbox_exec::PlatformError::UnsupportedKernel(error)) => {
            assert!(matches!(
                error.primitive,
                KernelPrimitive::CgroupV2 | KernelPrimitive::CgroupDelegation
            ));
            eprintln!(
                "unsupported live gate: {}: {}",
                error.primitive, error.detail
            );
        }
        Err(error) => panic!("unexpected cgroup qualification failure: {error}"),
    }
}

#[test]
fn direct_exec_bypass_is_denied_before_untrusted_callback() {
    if std::env::var_os("SENDBOX_AGENT_BOOTSTRAP_CHILD").is_some() {
        let directory = tempfile::tempdir().expect("tempdir");
        let script = directory.path().join("probe.sh");
        fs::write(&script, b"#!/bin/sh\nexit 0\n").expect("write shebang probe");
        let mut permissions = fs::metadata(&script).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).expect("chmod shebang probe");
        let bootstrap = AgentBootstrap::install().expect("install and verify agent bootstrap");
        bootstrap
            .verify_exec_path_denied(&script)
            .expect("shebang execve probe denied");
        assert_eq!(bootstrap.run_untrusted(|| 41 + 1), 42);
        return;
    }
    let status = Command::new(std::env::current_exe().expect("current exe"))
        .args([
            "--exact",
            "direct_exec_bypass_is_denied_before_untrusted_callback",
        ])
        .env("SENDBOX_AGENT_BOOTSTRAP_CHILD", "1")
        .status()
        .expect("spawn isolated bootstrap probe");
    assert!(
        status.success(),
        "isolated bootstrap probe failed: {status}"
    );
}

#[test]
fn unix_socket_accepts_same_uid_peer_and_rejects_stale_rebind() {
    let parent = tempfile::tempdir().expect("tempdir");
    let uid = fs::metadata(parent.path()).expect("metadata").uid();
    let session = Arc::new(BrokerSession::generate().expect("session"));
    let runtime = RuntimeDirectory::create(parent.path(), session.id(), uid).expect("runtime");
    let listener = runtime.initialize(&session).expect("initialize");
    assert!(runtime.bind().is_err(), "stale socket must not be reused");
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let _stream = connect(listener.local_path(), uid).expect("connect");
        });
        let _stream = listener.accept().expect("authenticated accept");
    });
    drop(listener);
    fs::remove_file(runtime.socket_path()).expect("remove socket");
    fs::remove_file(runtime.credentials_path()).expect("remove credentials");
    runtime.remove().expect("remove runtime");
}

#[test]
fn unauthorized_second_uid_peer_is_rejected_when_available() {
    if let Some(socket_path) = std::env::var_os("SENDBOX_SECOND_UID_SOCKET") {
        UnixStream::connect(socket_path).expect("second uid connect");
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    let current_uid = fs::metadata(directory.path()).expect("metadata").uid();
    if current_uid != 0 {
        eprintln!("unsupported live gate: creating a conclusive second UID requires root");
        return;
    }
    let mut directory_permissions = fs::metadata(directory.path())
        .expect("metadata")
        .permissions();
    directory_permissions.set_mode(0o777);
    fs::set_permissions(directory.path(), directory_permissions).expect("chmod directory");
    let socket_path = directory.path().join("second-uid.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind second uid socket");
    let mut socket_permissions = fs::metadata(&socket_path).expect("metadata").permissions();
    socket_permissions.set_mode(0o777);
    fs::set_permissions(&socket_path, socket_permissions).expect("chmod socket");

    let child = Command::new(std::env::current_exe().expect("current exe"))
        .args([
            "--exact",
            "unauthorized_second_uid_peer_is_rejected_when_available",
        ])
        .env("SENDBOX_SECOND_UID_SOCKET", &socket_path)
        .uid(65_534)
        .gid(65_534)
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            eprintln!("unsupported live gate: could not create second UID process: {error}");
            return;
        }
    };
    let (stream, _) = listener.accept().expect("accept second uid");
    assert!(matches!(
        authenticate_peer(&stream, current_uid),
        Err(sendbox_exec::runtime::RuntimeError::PeerUid {
            actual: 65_534,
            expected: 0
        })
    ));
    assert!(child.wait().expect("wait second uid").success());
}

#[test]
fn atomic_clone_exec_and_output_saturation_are_live_gated() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-output",
            executable: "bin/yes",
            argv: vec!["/usr/bin/yes".into()],
            timeout: Duration::from_secs(2),
            containment: ContainmentProfile {
                pids_max: 16,
                memory_max_bytes: Some(128 * 1024 * 1024),
                ..ContainmentProfile::default()
            },
            output_event_limit: None,
        },
    );
    let (result, _) = invoke_launcher_with_sink_limit(&invocation, Some(0));
    match result.terminal {
        TerminalState::OutputSaturated => {
            assert!(
                result.cleanup.is_complete(),
                "{:?}",
                result.cleanup.failures
            );
        }

        TerminalState::LaunchFailed(LaunchFailure::UnsupportedKernel(error)) => {
            assert!(matches!(
                error.primitive,
                KernelPrimitive::Clone3IntoCgroup
                    | KernelPrimitive::Pidfd
                    | KernelPrimitive::WaitidPidfd
                    | KernelPrimitive::SeccompTsync
            ));
            eprintln!(
                "unsupported live gate: {}: {}",
                error.primitive, error.detail
            );
        }
        other => panic!("unexpected atomic execution result: {other:?}"),
    }
}

#[test]
fn production_backend_propagates_client_sink_disconnect() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-disconnect",
            executable: "bin/yes",
            argv: vec!["/usr/bin/yes".into()],
            timeout: Duration::from_secs(2),
            containment: ContainmentProfile::default(),
            output_event_limit: None,
        },
    );
    let backend = launcher_backend(&invocation);
    let mut sink = |event| {
        if matches!(event, ExecutionEvent::Output { .. }) {
            return Err(SinkError::Disconnected);
        }
        Ok(())
    };
    let result = backend.execute(
        &invocation.request,
        &invocation.decision,
        &mut sink,
        &CancellationFlag::default(),
    );
    assert_eq!(result.terminal, TerminalState::ClientDisconnected);
    assert!(
        result.cleanup.is_complete(),
        "{:?}",
        result.cleanup.failures
    );
}

#[test]
fn production_backend_propagates_explicit_cancellation() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-cancel",
            executable: "bin/sleep",
            argv: vec!["/usr/bin/sleep".into(), "5".into()],
            timeout: Duration::from_secs(10),
            containment: ContainmentProfile::default(),
            output_event_limit: None,
        },
    );
    let backend = launcher_backend(&invocation);
    let cancellation = CancellationFlag::default();
    let trigger = cancellation.clone();
    let cancellation_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        trigger.cancel();
    });
    let mut sink = |_event| Ok(());
    let result = backend.execute(
        &invocation.request,
        &invocation.decision,
        &mut sink,
        &cancellation,
    );
    cancellation_thread.join().expect("cancellation thread");
    assert_eq!(result.terminal, TerminalState::Cancelled);
    assert!(
        result.cleanup.is_complete(),
        "{:?}",
        result.cleanup.failures
    );
}

#[test]
fn production_backend_propagates_graceful_broker_shutdown() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-shutdown",
            executable: "bin/sleep",
            argv: vec!["/usr/bin/sleep".into(), "5".into()],
            timeout: Duration::from_secs(10),
            containment: ContainmentProfile::default(),
            output_event_limit: None,
        },
    );
    let backend = launcher_backend(&invocation);
    let cancellation = CancellationFlag::default();
    let trigger = cancellation.clone();
    let shutdown_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        trigger.shutdown();
    });
    let mut sink = |_event| Ok(());
    let result = backend.execute(
        &invocation.request,
        &invocation.decision,
        &mut sink,
        &cancellation,
    );
    shutdown_thread.join().expect("shutdown thread");
    assert_eq!(result.terminal, TerminalState::BrokerShutdown);
    assert!(
        result.cleanup.is_complete(),
        "{:?}",
        result.cleanup.failures
    );
}

#[test]
fn production_backend_propagates_supervisor_death() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-supervisor-death",
            executable: "bin/sleep",
            argv: vec!["/usr/bin/sleep".into(), "5".into()],
            timeout: Duration::from_secs(10),
            containment: ContainmentProfile::default(),
            output_event_limit: None,
        },
    );
    let backend = launcher_backend(&invocation);
    let cancellation = CancellationFlag::default();
    let trigger = cancellation.clone();
    let supervisor_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        trigger.supervisor_died();
    });
    let mut sink = |_event| Ok(());
    let result = backend.execute(
        &invocation.request,
        &invocation.decision,
        &mut sink,
        &cancellation,
    );
    supervisor_thread.join().expect("supervisor thread");
    assert_eq!(result.terminal, TerminalState::SupervisorDied);
    assert!(
        result.cleanup.is_complete(),
        "{:?}",
        result.cleanup.failures
    );
}

#[test]
fn control_pipe_eof_triggers_supervisor_death_cleanup() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let invocation = launcher_invocation(
        &session,
        parent.clone(),
        LaunchCase {
            correlation: "live-broker-crash",
            executable: "bin/sleep",
            argv: vec!["/usr/bin/sleep".into(), "5".into()],
            timeout: Duration::from_secs(10),
            containment: ContainmentProfile::default(),
            output_event_limit: None,
        },
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_sendbox-exec-launcher"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn launcher");
    let mut control = child.stdin.take().expect("control pipe");
    write_control_frame(
        &mut control,
        &LauncherControl::Start {
            invocation: Box::new(invocation.clone()),
        },
    )
    .expect("start frame");
    let mut events = BufReader::new(child.stdout.take().expect("event pipe"));
    let started: ExecutionEvent = read_frame(&mut events)
        .expect("read started")
        .expect("started frame");
    assert!(matches!(started, ExecutionEvent::Started { .. }));
    drop(control);
    let result = loop {
        let event: ExecutionEvent = read_frame(&mut events)
            .expect("read terminal after control EOF")
            .expect("terminal frame after control EOF");
        if let ExecutionEvent::Terminal { result, .. } = event {
            break result;
        }
    };
    let _ = child.wait();
    assert_eq!(result.terminal, TerminalState::SupervisorDied);
    assert!(
        result.cleanup.is_complete(),
        "{:?}",
        result.cleanup.failures
    );
    assert!(
        !parent.join(format!("sendbox-{}", session.id())).exists(),
        "launcher cgroup subtree survived control EOF"
    );
}

#[test]
fn broker_process_crash_removes_cgroup_subtree() {
    let session_id = sendbox_exec::SessionId::from_bytes([42; 16]);
    let authentication = sendbox_exec::SessionAuthentication::from_bytes([24; 32]);
    let parent = match current_cgroup() {
        Ok(parent) => parent,
        Err(error) => {
            eprintln!(
                "unsupported live gate: {}: {}",
                error.primitive, error.detail
            );
            return;
        }
    };
    if std::env::var_os("SENDBOX_CRASH_BROKER_CHILD").is_some() {
        let invocation =
            crash_invocation(session_id, authentication, parent, "crash-broker-command");
        let backend = launcher_backend(&invocation);
        let mut sink = |_event| Ok(());
        let _ = backend.execute(
            &invocation.request,
            &invocation.decision,
            &mut sink,
            &CancellationFlag::default(),
        );
        return;
    }

    let preflight = match CgroupManager::create(&parent, session_id) {
        Ok(manager) => manager,
        Err(sendbox_exec::PlatformError::UnsupportedKernel(error)) => {
            eprintln!(
                "unsupported live gate: {}: {}",
                error.primitive, error.detail
            );
            return;
        }
        Err(error) => panic!("unexpected cgroup setup failure: {error}"),
    };
    preflight.remove().expect("remove preflight cgroup root");
    let root = parent.join(format!("sendbox-{session_id}"));
    let mut broker = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--exact", "broker_process_crash_removes_cgroup_subtree"])
        .env("SENDBOX_CRASH_BROKER_CHILD", "1")
        .spawn()
        .expect("spawn broker helper");
    wait_for_path_state(&root, true, Duration::from_secs(3));
    broker.kill().expect("kill broker helper");
    let _ = broker.wait();
    wait_for_path_state(&root, false, Duration::from_secs(3));
}

#[test]
fn descendant_clone3_is_denied_by_child_only_filter() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let Some((python, executable)) = python_helper() else {
        return;
    };
    let script = concat!(
        "import ctypes\n",
        "libc=ctypes.CDLL(None, use_errno=True)\n",
        "result=libc.syscall(435, 0)\n",
        "print('clone3', result, ctypes.get_errno(), flush=True)\n",
    );
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-clone3-deny",
            executable: &executable,
            argv: vec![python, "-c".into(), script.into()],
            timeout: Duration::from_secs(3),
            containment: ContainmentProfile::default(),
            output_event_limit: None,
        },
    );
    let (result, output) = invoke_launcher(&invocation);
    assert!(matches!(result.terminal, TerminalState::Exited(_)));
    assert!(
        String::from_utf8_lossy(&output).contains("clone3 -1 1"),
        "clone3 did not return EPERM: {}",
        String::from_utf8_lossy(&output)
    );
}

#[test]
fn child_stdin_and_fd_inventory_are_hardened() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let Some((python, executable)) = python_helper() else {
        return;
    };
    let script = concat!(
        "import os\n",
        "print('stdin='+os.readlink('/proc/self/fd/0'), flush=True)\n",
        "extras=[]\n",
        "for name in os.listdir('/proc/self/fd'):\n",
        "  fd=int(name)\n",
        "  if fd > 2:\n",
        "    try:\n",
        "      extras.append((fd, os.readlink('/proc/self/fd/'+name)))\n",
        "    except FileNotFoundError:\n",
        "      pass\n",
        "print('extras='+repr(extras), flush=True)\n",
    );
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-fd-inventory",
            executable: &executable,
            argv: vec![python, "-c".into(), script.into()],
            timeout: Duration::from_secs(3),
            containment: ContainmentProfile::default(),
            output_event_limit: None,
        },
    );
    let (result, output) = invoke_launcher(&invocation);
    assert!(matches!(result.terminal, TerminalState::Exited(_)));
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("stdin=/dev/null"), "{output}");
    assert!(
        !output.contains("pipe:["),
        "inherited pipe leaked: {output}"
    );
    assert!(!output.contains("cgroup"), "cgroup fd leaked: {output}");
}

#[test]
fn broker_configured_environment_is_authoritative_in_launcher() {
    let session = Arc::new(BrokerSession::generate().expect("session"));
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let Some((python, executable)) = python_helper() else {
        return;
    };
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-environment",
            executable: &executable,
            argv: vec![
                python,
                "-c".into(),
                "import os; print(os.environ['CUSTOM_FIXED'], flush=True)".into(),
            ],
            timeout: Duration::from_secs(3),
            containment: ContainmentProfile::default(),
            output_event_limit: None,
        },
    );
    let broker = Broker::new(
        Arc::clone(&session),
        CompiledCommandPolicy::compile(&CommandPolicy {
            default_action: Action::Allow,
            allowlist: Vec::new(),
            denylist: Vec::new(),
            log_blocked: true,
        })
        .expect("policy"),
        EnvironmentPolicy::new([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("CUSTOM_FIXED".into(), "configured-value".into()),
        ]),
        RequestLimits::default(),
        launcher_backend(&invocation),
    );
    let mut output = Vec::new();
    let mut sink = |event| {
        if let ExecutionEvent::Output { data, .. } = event {
            output.extend(data);
        }
        Ok(())
    };
    let result = broker
        .execute(&invocation.request, &mut sink, &CancellationFlag::default())
        .expect("broker execution");
    assert!(matches!(result.terminal, TerminalState::Exited(_)));
    assert_eq!(String::from_utf8_lossy(&output).trim(), "configured-value");
}

#[test]
fn timeout_kills_and_reaps_the_entire_cgroup() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-timeout",
            executable: "bin/sleep",
            argv: vec!["/usr/bin/sleep".into(), "5".into()],
            timeout: Duration::from_millis(50),
            containment: ContainmentProfile::default(),
            output_event_limit: None,
        },
    );
    let (result, _) = invoke_launcher(&invocation);
    assert_eq!(result.terminal, TerminalState::TimedOut);
    assert!(
        result.cleanup.is_complete(),
        "{:?}",
        result.cleanup.failures
    );
}

#[test]
fn cgroup_process_limit_stops_fork_growth() {
    let session = BrokerSession::generate().expect("session");
    let Some(parent) = qualified_cgroup_parent(&session) else {
        return;
    };
    let python = match fs::canonicalize("/usr/bin/python3") {
        Ok(path) => path,
        Err(error) => {
            eprintln!("unsupported live gate: Python helper unavailable: {error}");
            return;
        }
    };
    let executable = python
        .strip_prefix("/usr")
        .expect("Python helper must be below /usr")
        .to_string_lossy()
        .trim_start_matches('/')
        .to_owned();
    let argv_zero = python.to_string_lossy().into_owned();
    let script = concat!(
        "import os,time\n",
        "children=[]\n",
        "for _ in range(64):\n",
        "  try:\n",
        "    pid=os.fork()\n",
        "  except OSError as error:\n",
        "    print('limited', error.errno, len(children), flush=True)\n",
        "    break\n",
        "  if pid == 0:\n",
        "    time.sleep(0.2)\n",
        "    os._exit(0)\n",
        "  children.append(pid)\n",
        "for pid in children:\n",
        "  os.waitpid(pid, 0)\n",
    );
    let invocation = launcher_invocation(
        &session,
        parent,
        LaunchCase {
            correlation: "live-pids",
            executable: &executable,
            argv: vec![argv_zero, "-c".into(), script.into()],
            timeout: Duration::from_secs(3),
            containment: ContainmentProfile {
                pids_max: 4,
                memory_max_bytes: Some(256 * 1024 * 1024),
                ..ContainmentProfile::default()
            },
            output_event_limit: None,
        },
    );
    let (result, output) = invoke_launcher(&invocation);
    assert_eq!(
        result.terminal,
        TerminalState::Exited(sendbox_exec::ExitStatus {
            exit_code: Some(0),
            signal: None,
        })
    );
    assert!(
        String::from_utf8_lossy(&output).contains("limited"),
        "process limit did not stop fork growth: {}",
        String::from_utf8_lossy(&output)
    );
    assert!(
        result.cleanup.is_complete(),
        "{:?}",
        result.cleanup.failures
    );
}

fn launcher_invocation(
    session: &BrokerSession,
    cgroup_parent: std::path::PathBuf,
    case: LaunchCase<'_>,
) -> LauncherInvocation {
    let request = ExecutionRequest {
        session_id: session.id(),
        authentication: session.authentication(),
        correlation_id: CorrelationId::new(case.correlation).expect("correlation"),
        cancellation_id: None,
        executable: DescriptorPath {
            root: RootId::System,
            relative: RelativePath::new(case.executable).expect("executable"),
        },
        argv: case.argv,
        cwd: DescriptorPath {
            root: RootId::Workspace,
            relative: RelativePath::new(".").expect("cwd"),
        },
        environment: vec![EnvironmentEntry {
            name: "LANG".into(),
            value: "C".into(),
        }],
        stdin: sendbox_exec::StandardInput::Null,
        timeout: ExecutionTimeout::new(case.timeout).expect("timeout"),
        containment: case.containment,
    };
    LauncherInvocation {
        decision: ExecutionDecision {
            session_id: request.session_id,
            correlation_id: request.correlation_id.clone(),
            disposition: AdmissionDisposition::Allow,
            matched_rule: Some("live qualification".into()),
            semantic_scope: SemanticScope::TopLevelOnly,
        },
        request,
        roots: vec![
            LauncherRoot {
                id: RootId::System,
                path: "/usr".into(),
            },
            LauncherRoot {
                id: RootId::Workspace,
                path: "/usr".into(),
            },
        ],
        cgroup_parent,
        cleanup_bound_ms: 2_000,
        output_event_limit: case.output_event_limit,
        environment_authority: EnvironmentAuthority::BrokerSanitizedV1,
    }
}

fn crash_invocation(
    session_id: sendbox_exec::SessionId,
    authentication: sendbox_exec::SessionAuthentication,
    cgroup_parent: std::path::PathBuf,
    correlation: &str,
) -> LauncherInvocation {
    let request = ExecutionRequest {
        session_id,
        authentication,
        correlation_id: CorrelationId::new(correlation).expect("correlation"),
        cancellation_id: None,
        executable: DescriptorPath {
            root: RootId::System,
            relative: RelativePath::new("bin/sleep").expect("sleep"),
        },
        argv: vec!["/usr/bin/sleep".into(), "10".into()],
        cwd: DescriptorPath {
            root: RootId::Workspace,
            relative: RelativePath::new(".").expect("cwd"),
        },
        environment: Vec::new(),
        stdin: sendbox_exec::StandardInput::Null,
        timeout: ExecutionTimeout::new(Duration::from_secs(15)).expect("timeout"),
        containment: ContainmentProfile::default(),
    };
    LauncherInvocation {
        decision: ExecutionDecision {
            session_id,
            correlation_id: request.correlation_id.clone(),
            disposition: AdmissionDisposition::Allow,
            matched_rule: Some("crash qualification".into()),
            semantic_scope: SemanticScope::TopLevelOnly,
        },
        request,
        roots: vec![
            LauncherRoot {
                id: RootId::System,
                path: "/usr".into(),
            },
            LauncherRoot {
                id: RootId::Workspace,
                path: "/usr".into(),
            },
        ],
        cgroup_parent,
        cleanup_bound_ms: 2_000,
        output_event_limit: None,
        environment_authority: EnvironmentAuthority::BrokerSanitizedV1,
    }
}

struct LaunchCase<'a> {
    correlation: &'a str,
    executable: &'a str,
    argv: Vec<String>,
    timeout: Duration,
    containment: ContainmentProfile,
    output_event_limit: Option<u64>,
}

fn invoke_launcher(invocation: &LauncherInvocation) -> (sendbox_exec::ExecutionResult, Vec<u8>) {
    invoke_launcher_with_sink_limit(invocation, None)
}

fn invoke_launcher_with_sink_limit(
    invocation: &LauncherInvocation,
    sink_limit: Option<u64>,
) -> (sendbox_exec::ExecutionResult, Vec<u8>) {
    let mut streamed_output = Vec::new();
    let backend = launcher_backend(invocation);
    let mut output_events = 0u64;
    let mut sink = |event| {
        if let ExecutionEvent::Output { data, .. } = event {
            if sink_limit.is_some_and(|limit| output_events >= limit) {
                return Err(SinkError::Saturated);
            }
            output_events = output_events.saturating_add(1);
            streamed_output.extend(data);
        }
        Ok(())
    };
    let result = backend.execute(
        &invocation.request,
        &invocation.decision,
        &mut sink,
        &CancellationFlag::default(),
    );
    (result, streamed_output)
}

fn launcher_backend(invocation: &LauncherInvocation) -> LauncherProcessBackend {
    LauncherProcessBackend::new(
        env!("CARGO_BIN_EXE_sendbox-exec-launcher"),
        invocation.roots.clone(),
        invocation.cgroup_parent.clone(),
        Duration::from_millis(invocation.cleanup_bound_ms),
    )
    .with_output_event_limit(invocation.output_event_limit)
}

fn python_helper() -> Option<(String, String)> {
    let python = match fs::canonicalize("/usr/bin/python3") {
        Ok(path) => path,
        Err(error) => {
            eprintln!("unsupported live gate: Python helper unavailable: {error}");
            return None;
        }
    };
    let executable = python
        .strip_prefix("/usr")
        .expect("Python helper must be below /usr")
        .to_string_lossy()
        .trim_start_matches('/')
        .to_owned();
    Some((python.to_string_lossy().into_owned(), executable))
}

fn wait_for_path_state(path: &std::path::Path, expected: bool, bound: Duration) {
    let deadline = std::time::Instant::now() + bound;
    while path.exists() != expected {
        assert!(
            std::time::Instant::now() < deadline,
            "path {} did not reach exists={expected}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn qualified_cgroup_parent(session: &BrokerSession) -> Option<std::path::PathBuf> {
    let parent = match current_cgroup() {
        Ok(parent) => parent,
        Err(error) => {
            eprintln!(
                "unsupported live gate: {}: {}",
                error.primitive, error.detail
            );
            return None;
        }
    };
    match CgroupManager::create(&parent, session.id()) {
        Ok(manager) => {
            manager.remove().expect("remove preflight cgroup root");
            Some(parent)
        }
        Err(sendbox_exec::PlatformError::UnsupportedKernel(error)) => {
            eprintln!(
                "unsupported live gate: {}: {}",
                error.primitive, error.detail
            );
            None
        }
        Err(error) => panic!("unexpected cgroup setup failure: {error}"),
    }
}

fn current_cgroup() -> Result<std::path::PathBuf, sendbox_exec::UnsupportedKernel> {
    if let Some(parent) = std::env::var_os("SENDBOX_CGROUP_PARENT") {
        return Ok(parent.into());
    }
    let membership = fs::read_to_string("/proc/self/cgroup").map_err(|error| {
        sendbox_exec::UnsupportedKernel::new(
            KernelPrimitive::CgroupV2,
            error.raw_os_error(),
            "cannot read cgroup membership",
        )
    })?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            sendbox_exec::UnsupportedKernel::new(
                KernelPrimitive::CgroupV2,
                None,
                "unified cgroup v2 membership is absent",
            )
        })?;
    Ok(std::path::Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')))
}

fn write_fake_elf(path: &std::path::Path) {
    let mut file = fs::File::create(path).expect("create ELF fixture");
    file.write_all(b"\x7fELF").expect("write magic");
    file.write_all(&[0; 64]).expect("write body");
    let mut permissions = file.metadata().expect("metadata").permissions();
    permissions.set_mode(0o755);
    file.set_permissions(permissions).expect("chmod");
}
