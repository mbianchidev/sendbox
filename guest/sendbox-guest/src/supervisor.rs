use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rustix::fs::{Mode, OFlags, fstat, openat};
use tokio::net::UnixListener;

use crate::GuestError;
use crate::audit::AuditLog;
use crate::bootstrap::ImmutableBootstrapSource;
use crate::broker;
use crate::manifest::{VerifiedManifest, verify_manifest};
use crate::platform::PlatformControls;
use crate::protocol::{handshake_config, serve_authenticated};
use crate::runtime::{ReadinessSnapshot, RuntimeIdentity, RuntimeSession};
use crate::secure_fs::{leaf_name, open_directory_no_symlinks, validate_regular_metadata};
use crate::service::{ServiceId, ServiceManager};
use crate::state::{StartupState, StartupStateMachine};

#[derive(Debug, Clone)]
pub struct SupervisorOptions {
    pub bootstrap_file: PathBuf,
    pub trust_root_file: PathBuf,
    pub artifact_root: PathBuf,
    pub runtime_root: PathBuf,
    pub replay_root: PathBuf,
}

pub async fn run<P: PlatformControls>(
    options: SupervisorOptions,
    platform: &P,
    identity: RuntimeIdentity,
) -> Result<(), GuestError> {
    let audit = Arc::new(Mutex::new(AuditLog::default()));
    let state = Arc::new(Mutex::new(StartupStateMachine::default()));
    prepare_private_root(&options.replay_root, identity)?;
    wait_for_bootstrap(&options.bootstrap_file).await?;
    let mut bootstrap =
        ImmutableBootstrapSource::new(options.bootstrap_file, identity.uid, identity.gid)
            .consume(&options.replay_root)?;
    transition(&state, &audit, StartupState::BootstrapConsumed)?;

    let artifact_root = open_directory_no_symlinks(&options.artifact_root)?;
    let trust_root = read_trust_root(&options.trust_root_file, identity)?;
    let verified_manifest = verify_manifest(
        &artifact_root,
        &bootstrap.manifest_path,
        &trust_root,
        &bootstrap.trust_root_id,
        &bootstrap.host_version,
        env!("CARGO_PKG_VERSION"),
        bootstrap.minimum_release_sequence,
    )?;
    transition(&state, &audit, StartupState::ManifestVerified)?;

    let runtime = Arc::new(RuntimeSession::prepare(
        &options.runtime_root,
        bootstrap.session_id,
        identity,
    )?);
    runtime.write_state(StartupState::RuntimePrepared)?;
    transition(&state, &audit, StartupState::RuntimePrepared)?;

    let broker_client = bootstrap
        .execution_broker
        .take()
        .map(|configuration| {
            broker::prepare(bootstrap.session_id, runtime.session_dir(), configuration)
        })
        .transpose()?;
    if let Some((_, service)) = &broker_client {
        if bootstrap
            .services
            .iter()
            .any(|existing| existing.id == service.id)
        {
            return Err(GuestError::Runtime(
                "execution broker service was configured more than once".to_owned(),
            ));
        }

        bootstrap.services.push(service.clone());
        if !bootstrap.required_services.contains(&ServiceId::Exec) {
            bootstrap.required_services.push(ServiceId::Exec);
        }
    }
    let controls = platform.apply_and_verify(&bootstrap.required_controls)?;

    let mut services = ServiceManager::new(
        options.artifact_root,
        bootstrap.services,
        &bootstrap.required_services,
        &verified_manifest,
        Arc::clone(&audit),
    )?;
    transition_and_write(&state, &audit, &runtime, StartupState::ServicesStarting)?;
    if let Err(error) = services.start_all().await {
        fail_and_cleanup(&state, &audit, &runtime, &mut services).await?;
        return Err(error);
    }
    let controls = platform.lockdown_and_verify(controls)?;
    transition_and_write(&state, &audit, &runtime, StartupState::ControlsVerified)?;

    transition_and_write(&state, &audit, &runtime, StartupState::SelfTesting)?;
    platform.self_test(&controls)?;
    let service_health = services.health();
    if service_health
        .iter()
        .any(|service| service.mandatory && !service.healthy)
    {
        fail_and_cleanup(&state, &audit, &runtime, &mut services).await?;
        return Err(GuestError::Runtime(
            "mandatory service self-test failed".to_owned(),
        ));
    }

    fn prepare_private_root(path: &Path, identity: RuntimeIdentity) -> Result<(), GuestError> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        if !path.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(|error| GuestError::io("creating private guest root", error))?;
        }
        let metadata = path
            .symlink_metadata()
            .map_err(|error| GuestError::io("inspecting private guest root", error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != identity.uid
            || metadata.gid() != identity.gid
        {
            return Err(GuestError::Runtime(format!(
                "{} is not owned by the guest runtime identity",
                path.display()
            )));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| GuestError::io("setting private guest root mode", error))
    }

    let listener = UnixListener::bind(runtime.socket_path())
        .map_err(|error| GuestError::io("binding guest control socket", error))?;
    let service_readiness = services.readiness_gate();
    services.arm_readiness();
    transition_and_write(&state, &audit, &runtime, StartupState::Ready)?;
    let readiness = ReadinessSnapshot {
        session_id: bootstrap.session_id,
        state: StartupState::Ready,
        release_sequence: verified_manifest.manifest.release_sequence,
        controls,
        services: service_health,
        audit_events: audit.lock().expect("audit mutex").events().to_vec(),
    };
    runtime.publish_readiness(&readiness)?;

    let stream = tokio::select! {
        accepted = listener.accept() => {
            accepted
                .map(|(stream, _)| stream)
                .map_err(|error| GuestError::io("accepting guest control connection", error))
        }
        failure = services.wait_for_mandatory_failure() => Err(failure),
    };
    let result = match stream {
        Ok(stream) => {
            let config = handshake_config(bootstrap.session_id, bootstrap.bootstrap_secret)?;
            tokio::select! {
                protocol = serve_authenticated(
                    stream,
                    config,
                    Arc::clone(&state),
                    Arc::clone(&service_readiness),
                    Arc::clone(&runtime),
                    readiness,
                    broker_client.as_ref().map(|(client, _)| client.clone()),
                ) => protocol,
                failure = services.wait_for_mandatory_failure() => Err(failure),
            }
        }
        Err(error) => Err(error),
    };

    service_readiness.revoke();
    runtime.revoke_readiness()?;
    if result.is_err() {
        state.lock().expect("state mutex").fail();
        audit.lock().expect("audit mutex").record(
            "readiness_revoked",
            "session",
            "fail-closed shutdown",
        );
    }
    shutdown(&state, &audit, &runtime, &mut services).await?;
    result
}

async fn wait_for_bootstrap(path: &Path) -> Result<(), GuestError> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if tokio::fs::symlink_metadata(path).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(GuestError::Bootstrap(
                "timed out waiting for runtime-injected bootstrap".to_owned(),
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

fn read_trust_root(path: &Path, identity: RuntimeIdentity) -> Result<[u8; 32], GuestError> {
    if !path.is_absolute() {
        return Err(GuestError::Manifest(
            "trust-root path must be absolute".to_owned(),
        ));
    }
    let (parent_path, name) = leaf_name(path)?;
    let parent: OwnedFd = open_directory_no_symlinks(parent_path)?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| GuestError::io("opening injected trust root", io::Error::from(error)))?;
    let stat = fstat(&descriptor).map_err(|error| {
        GuestError::io("inspecting injected trust root", io::Error::from(error))
    })?;
    validate_regular_metadata(
        &stat,
        0o444,
        identity.uid,
        identity.gid,
        true,
        "trust-root file",
    )?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| GuestError::io("reading injected trust root", error))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        GuestError::Manifest(format!(
            "trust root must contain exactly 32 raw bytes, got {}",
            bytes.len()
        ))
    })
}

fn transition(
    state: &Arc<Mutex<StartupStateMachine>>,
    audit: &Arc<Mutex<AuditLog>>,
    next: StartupState,
) -> Result<(), GuestError> {
    state.lock().expect("state mutex").transition(next)?;
    audit
        .lock()
        .expect("audit mutex")
        .record("state_transition", "session", next.name());
    Ok(())
}

fn transition_and_write(
    state: &Arc<Mutex<StartupStateMachine>>,
    audit: &Arc<Mutex<AuditLog>>,
    runtime: &RuntimeSession,
    next: StartupState,
) -> Result<(), GuestError> {
    transition(state, audit, next)?;
    runtime.write_state(next)
}

async fn fail_and_cleanup(
    state: &Arc<Mutex<StartupStateMachine>>,
    audit: &Arc<Mutex<AuditLog>>,
    runtime: &RuntimeSession,
    services: &mut ServiceManager,
) -> Result<(), GuestError> {
    state.lock().expect("state mutex").fail();
    runtime.revoke_readiness()?;
    shutdown(state, audit, runtime, services).await
}

async fn shutdown(
    state: &Arc<Mutex<StartupStateMachine>>,
    audit: &Arc<Mutex<AuditLog>>,
    runtime: &RuntimeSession,
    services: &mut ServiceManager,
) -> Result<(), GuestError> {
    let current = state.lock().expect("state mutex").state();
    if current != StartupState::ShuttingDown {
        transition_and_write(state, audit, runtime, StartupState::ShuttingDown)?;
    }
    services.shutdown().await?;
    transition_and_write(state, audit, runtime, StartupState::Terminated)?;
    runtime.cleanup()
}

#[must_use]
pub fn verified_service_paths(manifest: &VerifiedManifest) -> usize {
    manifest.manifest.artifacts.len()
}
