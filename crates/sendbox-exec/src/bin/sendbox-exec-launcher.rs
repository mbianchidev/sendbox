//! One-shot production launcher process.

#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux_main() {
        eprintln!("sendbox-exec-launcher: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sendbox-exec-launcher requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn linux_main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    use std::io::{self, BufReader};
    use std::time::Duration;

    use sendbox_exec::api::{AdmissionDisposition, ExecutionEvent, TerminalState};
    use sendbox_exec::broker::{CancellationFlag, RequestLimits, SinkError};
    use sendbox_exec::platform::linux::cgroup::CgroupManager;
    use sendbox_exec::platform::linux::launcher::{
        DedicatedLauncherBackend, EnvironmentAuthority, LauncherControl, read_control_frame,
        write_event_frame,
    };
    use sendbox_exec::platform::linux::resolver::{RootDirectory, RootSet};

    let mut control = BufReader::new(io::stdin());
    let Some(LauncherControl::Start { invocation }) = read_control_frame(&mut control)? else {
        return Err("first launcher control frame must be Start".into());
    };
    let invocation = *invocation;
    RequestLimits::default().validate(&invocation.request)?;
    if invocation.decision.disposition != AdmissionDisposition::Allow
        || invocation.decision.session_id != invocation.request.session_id
        || invocation.decision.correlation_id != invocation.request.correlation_id
    {
        return Err("launcher received a mismatched or denied admission decision".into());
    }
    if invocation.environment_authority != EnvironmentAuthority::BrokerSanitizedV1 {
        return Err("launcher environment is not broker-authoritative".into());
    }

    let roots = invocation
        .roots
        .into_iter()
        .map(|entry| RootDirectory::open(entry.path).map(|root| (entry.id, root)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let cgroups = CgroupManager::create(&invocation.cgroup_parent, invocation.request.session_id)?;
    let backend = DedicatedLauncherBackend::new(
        RootSet::new(roots),
        cgroups,
        Duration::from_millis(invocation.cleanup_bound_ms),
    );

    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut output_events = 0u64;
    let limit = invocation.output_event_limit;
    let mut sink = |event: ExecutionEvent| {
        if matches!(event, ExecutionEvent::Output { .. }) {
            if limit.is_some_and(|maximum| output_events >= maximum) {
                return Err(SinkError::Saturated);
            }
            output_events = output_events.saturating_add(1);
        }
        write_event_frame(&mut writer, &event).map_err(|_| SinkError::SupervisorDied)
    };
    let mut result = backend.execute_with_control(
        &invocation.request,
        &mut sink,
        &CancellationFlag::default(),
        control,
    );
    if let Err(error) = backend.remove_cgroup() {
        result.cleanup.status = sendbox_exec::CleanupStatus::Incomplete;
        result.cleanup.failures.push(sendbox_exec::CleanupFailure {
            step: sendbox_exec::CleanupStep::RemoveLeaf,
            message: format!("remove supervisor cgroup subtree: {error}"),
        });
    }
    let terminal = ExecutionEvent::Terminal {
        correlation_id: invocation.request.correlation_id,
        result,
    };
    write_event_frame(&mut writer, &terminal)?;

    if matches!(
        terminal,
        ExecutionEvent::Terminal {
            result: sendbox_exec::ExecutionResult {
                terminal: TerminalState::SupervisorDied,
                ..
            },
            ..
        }
    ) {
        return Err("supervisor died".into());
    }
    Ok(())
}
