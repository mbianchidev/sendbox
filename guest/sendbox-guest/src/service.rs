use std::collections::{BTreeMap, BTreeSet};
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::process::{Pid, Signal, kill_process_group, test_kill_process_group};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::GuestError;
use crate::audit::AuditLog;
use crate::manifest::VerifiedManifest;

const DEFAULT_LOG_BYTES: usize = 64 * 1024;
type ValidatedServices = (
    BTreeMap<ServiceId, ServiceSpec>,
    Vec<ServiceId>,
    BTreeMap<ServiceId, OwnedFd>,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceId {
    Exec,
    Mcp,
    Dns,
    Egress,
    Audit,
    Bpf,
}

impl ServiceId {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Mcp => "mcp",
            Self::Dns => "dns",
            Self::Egress => "egress",
            Self::Audit => "audit",
            Self::Bpf => "bpf",
        }
    }
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPolicy {
    #[serde(default)]
    pub max_restarts: u32,
    #[serde(default = "default_backoff_ms")]
    pub backoff_ms: u64,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 0,
            backoff_ms: default_backoff_ms(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HealthCheck {
    ProcessAlive {
        #[serde(default = "default_health_delay_ms")]
        delay_ms: u64,
    },
    UnixSocket {
        path: PathBuf,
        #[serde(default = "default_health_timeout_ms")]
        timeout_ms: u64,
    },
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::ProcessAlive {
            delay_ms: default_health_delay_ms(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    pub id: ServiceId,
    #[serde(default)]
    pub dependencies: Vec<ServiceId>,
    pub executable: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_true")]
    pub mandatory: bool,
    #[serde(default)]
    pub restart: RestartPolicy,
    #[serde(default)]
    pub health: HealthCheck,
    #[serde(default = "default_grace_ms")]
    pub graceful_shutdown_ms: u64,
    #[serde(default = "default_kill_ms")]
    pub forced_shutdown_ms: u64,
    #[serde(default = "default_log_bytes")]
    pub max_log_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceHealth {
    pub id: ServiceId,
    pub mandatory: bool,
    pub healthy: bool,
    pub restart_count: u32,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub output_truncated: bool,
}

struct RunningService {
    spec: ServiceSpec,
    child: Child,
    process_group: Pid,
    restart_count: u32,
    stdout: Arc<Mutex<BoundedLog>>,
    stderr: Arc<Mutex<BoundedLog>>,
    log_tasks: Vec<JoinHandle<()>>,
}

impl Drop for RunningService {
    fn drop(&mut self) {
        let _ = kill_process_group(self.process_group, Signal::KILL);
        let _ = self.child.start_kill();
        abort_log_tasks(self);
    }
}

#[derive(Debug)]
struct BoundedLog {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl BoundedLog {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            truncated: false,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        self.truncated |= chunk.len() > remaining;
    }
}

pub struct ServiceManager {
    artifact_root: PathBuf,
    specs: BTreeMap<ServiceId, ServiceSpec>,
    executables: BTreeMap<ServiceId, OwnedFd>,
    order: Vec<ServiceId>,
    running: BTreeMap<ServiceId, RunningService>,
    audit: Arc<Mutex<AuditLog>>,
    readiness: Arc<ReadinessGate>,
}

#[derive(Debug, Default)]
pub struct ReadinessGate {
    ready: AtomicBool,
    mandatory_groups: Mutex<BTreeMap<ServiceId, Pid>>,
}

impl ReadinessGate {
    fn arm(&self, services: &BTreeMap<ServiceId, RunningService>) {
        let groups = services
            .iter()
            .filter(|(_, service)| service.spec.mandatory)
            .map(|(id, service)| (*id, service.process_group))
            .collect();
        *self.mandatory_groups.lock().expect("mandatory group mutex") = groups;
        self.ready.store(true, Ordering::Release);
    }

    pub fn revoke(&self) {
        self.ready.store(false, Ordering::Release);
    }

    #[must_use]
    pub fn verified_live(&self) -> bool {
        if !self.ready.load(Ordering::Acquire) {
            return false;
        }
        let all_live = self
            .mandatory_groups
            .lock()
            .expect("mandatory group mutex")
            .values()
            .all(|group| process_group_is_live(*group));
        if !all_live {
            self.revoke();
        }

        fn process_group_is_live(group: Pid) -> bool {
            if test_kill_process_group(group).is_err() {
                return false;
            }
            #[cfg(target_os = "linux")]
            {
                let stat =
                    match std::fs::read_to_string(format!("/proc/{}/stat", group.as_raw_nonzero()))
                    {
                        Ok(stat) => stat,
                        Err(_) => return false,
                    };
                let state = stat
                    .rsplit_once(')')
                    .and_then(|(_, suffix)| suffix.trim_start().chars().next());
                !matches!(state, Some('Z' | 'X') | None)
            }
            #[cfg(not(target_os = "linux"))]
            {
                true
            }
        }
        all_live
    }

    #[cfg(test)]
    pub(crate) fn test_ready() -> Arc<Self> {
        let gate = Arc::new(Self::default());
        gate.ready.store(true, Ordering::Release);
        gate
    }
}

impl ServiceManager {
    pub fn new(
        artifact_root: PathBuf,
        specs: Vec<ServiceSpec>,
        required_services: &[ServiceId],
        manifest: &VerifiedManifest,
        audit: Arc<Mutex<AuditLog>>,
    ) -> Result<Self, GuestError> {
        let (specs, order, executables) = validate_specs(specs, required_services, manifest)?;
        Ok(Self {
            artifact_root,
            specs,
            executables,
            order,
            running: BTreeMap::new(),
            audit,
            readiness: Arc::new(ReadinessGate::default()),
        })
    }

    pub async fn start_all(&mut self) -> Result<(), GuestError> {
        for id in self.order.clone() {
            let spec = self.specs.get(&id).expect("validated service").clone();
            let executable = self.executables.get(&id).expect("verified executable");
            match spawn_service(&self.artifact_root, executable, spec.clone(), 0).await {
                Ok(service) => {
                    self.record("service_started", id, "health check passed");
                    self.running.insert(id, service);
                }
                Err(error) if !spec.mandatory => {
                    self.record("optional_service_failed", id, error.to_string());
                }
                Err(error) => {
                    self.shutdown().await?;
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub async fn wait_for_mandatory_failure(&mut self) -> GuestError {
        loop {
            let mut exited = None;
            for (id, service) in &mut self.running {
                match service.child.try_wait() {
                    Ok(Some(status)) => {
                        exited = Some((*id, status.to_string()));
                        break;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return GuestError::Service {
                            service: id.to_string(),
                            detail: format!("checking process status: {error}"),
                        };
                    }
                }
            }

            if let Some((id, status)) = exited {
                let mut service = self.running.remove(&id).expect("running service");
                abort_log_tasks(&mut service);
                self.record("service_exited", id, status.clone());
                let spec = service.spec.clone();
                let next_restart = service.restart_count + 1;
                drop(service);
                if spec.mandatory {
                    self.readiness.revoke();
                    return GuestError::Service {
                        service: id.to_string(),
                        detail: format!("mandatory service exited: {status}"),
                    };
                }
                if restart_allowed(&spec.restart, next_restart) {
                    sleep(Duration::from_millis(spec.restart.backoff_ms)).await;
                    let executable = self
                        .executables
                        .get(&id)
                        .expect("verified restart executable");
                    match spawn_service(&self.artifact_root, executable, spec.clone(), next_restart)
                        .await
                    {
                        Ok(restarted) => {
                            self.record("service_restarted", id, format!("restart {next_restart}"));
                            self.running.insert(id, restarted);
                            if let Err(error) = self.recheck_dependents(id).await {
                                return error;
                            }
                            continue;
                        }
                        Err(error) => return error,
                    }
                }
                self.record("optional_service_stopped", id, status);
            }
            sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn health(&self) -> Vec<ServiceHealth> {
        self.order
            .iter()
            .filter_map(|id| self.running.get(id))
            .map(|service| {
                let stdout = service.stdout.lock().expect("stdout log mutex");
                let stderr = service.stderr.lock().expect("stderr log mutex");
                ServiceHealth {
                    id: service.spec.id,
                    mandatory: service.spec.mandatory,
                    healthy: true,
                    restart_count: service.restart_count,
                    stdout_bytes: stdout.bytes.len(),
                    stderr_bytes: stderr.bytes.len(),
                    output_truncated: stdout.truncated || stderr.truncated,
                }
            })
            .collect()
    }

    pub fn arm_readiness(&self) {
        self.readiness.arm(&self.running);
    }

    #[must_use]
    pub fn readiness_gate(&self) -> Arc<ReadinessGate> {
        Arc::clone(&self.readiness)
    }

    pub async fn shutdown(&mut self) -> Result<(), GuestError> {
        self.readiness.revoke();
        for id in self.order.iter().rev() {
            if let Some(mut service) = self.running.remove(id) {
                terminate_service(&mut service).await?;
                self.record("service_stopped", *id, "process group reaped");
            }
        }
        Ok(())
    }

    async fn recheck_dependents(&mut self, dependency: ServiceId) -> Result<(), GuestError> {
        let dependents = self
            .specs
            .values()
            .filter(|spec| spec.dependencies.contains(&dependency))
            .map(|spec| spec.id)
            .collect::<Vec<_>>();
        for dependent in dependents {
            if let Some(service) = self.running.get_mut(&dependent) {
                check_health(service).await?;
            }
        }
        Ok(())
    }

    fn record(&self, code: &str, id: ServiceId, detail: impl Into<String>) {
        self.audit
            .lock()
            .expect("audit mutex")
            .record(code, id.name(), detail);
    }
}

fn validate_specs(
    specs: Vec<ServiceSpec>,
    required_services: &[ServiceId],
    manifest: &VerifiedManifest,
) -> Result<ValidatedServices, GuestError> {
    let mut by_id = BTreeMap::new();
    let mut executables = BTreeMap::new();
    for spec in specs {
        if spec.max_log_bytes == 0 || spec.max_log_bytes > 1024 * 1024 {
            return Err(GuestError::ServiceConfig(format!(
                "{} log limit must be between 1 and 1048576",
                spec.id
            )));
        }
        let descriptor = manifest
            .executable_descriptor(&spec.executable)
            .map_err(|error| GuestError::ServiceConfig(error.to_string()))?;
        executables.insert(spec.id, descriptor);
        if by_id.insert(spec.id, spec).is_some() {
            return Err(GuestError::ServiceConfig(
                "duplicate service identifier".to_owned(),
            ));
        }
    }
    for required in required_services {
        let spec = by_id.get(required).ok_or_else(|| {
            GuestError::ServiceConfig(format!("required service {required} is missing"))
        })?;
        if !spec.mandatory {
            return Err(GuestError::ServiceConfig(format!(
                "required service {required} must be mandatory"
            )));
        }
    }
    for spec in by_id.values() {
        for dependency in &spec.dependencies {
            let dependency_spec = by_id.get(dependency).ok_or_else(|| {
                GuestError::ServiceConfig(format!(
                    "{} depends on missing service {dependency}",
                    spec.id
                ))
            })?;
            if spec.mandatory && !dependency_spec.mandatory {
                return Err(GuestError::ServiceConfig(format!(
                    "mandatory service {} depends on optional service {dependency}",
                    spec.id
                )));
            }
        }
    }
    let order = topological_order(&by_id)?;
    Ok((by_id, order, executables))
}

fn topological_order(
    specs: &BTreeMap<ServiceId, ServiceSpec>,
) -> Result<Vec<ServiceId>, GuestError> {
    let mut remaining = specs
        .iter()
        .map(|(id, spec)| {
            (
                *id,
                spec.dependencies.iter().copied().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut order = Vec::with_capacity(specs.len());
    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .filter(|(_, dependencies)| dependencies.is_empty())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        if ready.is_empty() {
            return Err(GuestError::ServiceConfig(
                "service dependency cycle detected".to_owned(),
            ));
        }
        for id in ready {
            remaining.remove(&id);
            for dependencies in remaining.values_mut() {
                dependencies.remove(&id);
            }
            order.push(id);
        }
    }
    Ok(order)
}

async fn spawn_service(
    artifact_root: &Path,
    executable: &OwnedFd,
    spec: ServiceSpec,
    restart_count: u32,
) -> Result<RunningService, GuestError> {
    let executable_path = executable_path(artifact_root, &spec, executable);
    let mut command = Command::new(&executable_path);
    command
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().map_err(|error| GuestError::Service {
        service: spec.id.to_string(),
        detail: format!("spawning {}: {error}", executable_path.display()),
    })?;
    let raw_pid = child.id().ok_or_else(|| GuestError::Service {
        service: spec.id.to_string(),
        detail: "spawned process has no PID".to_owned(),
    })?;
    let process_group = Pid::from_raw(raw_pid as i32).ok_or_else(|| GuestError::Service {
        service: spec.id.to_string(),
        detail: "spawned process has an invalid PID".to_owned(),
    })?;
    let stdout = Arc::new(Mutex::new(BoundedLog::new(spec.max_log_bytes)));
    let stderr = Arc::new(Mutex::new(BoundedLog::new(spec.max_log_bytes)));
    let mut log_tasks = Vec::new();
    if let Some(pipe) = child.stdout.take() {
        log_tasks.push(tokio::spawn(drain_log(pipe, Arc::clone(&stdout))));
    }
    if let Some(pipe) = child.stderr.take() {
        log_tasks.push(tokio::spawn(drain_log(pipe, Arc::clone(&stderr))));
    }
    let mut service = RunningService {
        spec,
        child,
        process_group,
        restart_count,
        stdout,
        stderr,
        log_tasks,
    };
    check_health(&mut service).await?;
    Ok(service)
}

fn executable_path(artifact_root: &Path, spec: &ServiceSpec, executable: &OwnedFd) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let _ = artifact_root;
        let _ = spec;
        PathBuf::from(format!("/proc/self/fd/{}", executable.as_raw_fd()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = executable;
        artifact_root.join(&spec.executable)
    }
}

fn restart_allowed(policy: &RestartPolicy, next_restart: u32) -> bool {
    next_restart <= policy.max_restarts
}

async fn check_health(service: &mut RunningService) -> Result<(), GuestError> {
    match &service.spec.health {
        HealthCheck::ProcessAlive { delay_ms } => {
            sleep(Duration::from_millis(*delay_ms)).await;
            if let Some(status) = service
                .child
                .try_wait()
                .map_err(|error| GuestError::Service {
                    service: service.spec.id.to_string(),
                    detail: format!("checking startup health: {error}"),
                })?
            {
                return Err(GuestError::Service {
                    service: service.spec.id.to_string(),
                    detail: format!("exited during startup health check: {status}"),
                });
            }
        }
        HealthCheck::UnixSocket { path, timeout_ms } => {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(*timeout_ms);
            loop {
                if let Some(status) =
                    service
                        .child
                        .try_wait()
                        .map_err(|error| GuestError::Service {
                            service: service.spec.id.to_string(),
                            detail: format!("checking socket health: {error}"),
                        })?
                {
                    return Err(GuestError::Service {
                        service: service.spec.id.to_string(),
                        detail: format!("exited before socket health check: {status}"),
                    });
                }
                if tokio::net::UnixStream::connect(path).await.is_ok() {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(GuestError::Service {
                        service: service.spec.id.to_string(),
                        detail: format!("socket health check timed out: {}", path.display()),
                    });
                }
                sleep(Duration::from_millis(10)).await;
            }
        }
    }
    Ok(())
}

async fn terminate_service(service: &mut RunningService) -> Result<(), GuestError> {
    signal_group(service.process_group, Signal::TERM)?;
    if timeout(
        Duration::from_millis(service.spec.graceful_shutdown_ms),
        service.child.wait(),
    )
    .await
    .is_err()
    {
        signal_group(service.process_group, Signal::KILL)?;
        timeout(
            Duration::from_millis(service.spec.forced_shutdown_ms),
            service.child.wait(),
        )
        .await
        .map_err(|_| GuestError::Service {
            service: service.spec.id.to_string(),
            detail: "process group did not terminate after SIGKILL".to_owned(),
        })?
        .map_err(|error| GuestError::Service {
            service: service.spec.id.to_string(),
            detail: format!("reaping process: {error}"),
        })?;
    }
    abort_log_tasks(service);
    Ok(())
}

fn signal_group(group: Pid, signal: Signal) -> Result<(), GuestError> {
    match kill_process_group(group, signal) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
        Err(error) => Err(GuestError::io(
            "signalling service process group",
            io::Error::from(error),
        )),
    }
}

fn abort_log_tasks(service: &mut RunningService) {
    for task in service.log_tasks.drain(..) {
        task.abort();
    }
}

async fn drain_log(mut reader: impl AsyncRead + Unpin, output: Arc<Mutex<BoundedLog>>) {
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => output
                .lock()
                .expect("bounded log mutex")
                .push(&buffer[..read]),
        }
    }
}

const fn default_true() -> bool {
    true
}

const fn default_backoff_ms() -> u64 {
    25
}

const fn default_health_delay_ms() -> u64 {
    50
}

const fn default_health_timeout_ms() -> u64 {
    1_000
}

const fn default_grace_ms() -> u64 {
    500
}

const fn default_kill_ms() -> u64 {
    500
}

const fn default_log_bytes() -> usize {
    DEFAULT_LOG_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::VerifiedManifest;

    fn manifest(paths: &[&str]) -> VerifiedManifest {
        VerifiedManifest::test_fixture(paths.iter().map(PathBuf::from))
    }

    fn spec(id: ServiceId, dependencies: Vec<ServiceId>) -> ServiceSpec {
        ServiceSpec {
            id,
            dependencies,
            executable: PathBuf::from("guest"),
            args: Vec::new(),
            mandatory: true,
            restart: RestartPolicy::default(),
            health: HealthCheck::default(),
            graceful_shutdown_ms: 10,
            forced_shutdown_ms: 10,
            max_log_bytes: 1024,
        }
    }

    #[test]
    fn dependency_cycles_are_rejected() {
        let result = validate_specs(
            vec![
                spec(ServiceId::Exec, vec![ServiceId::Mcp]),
                spec(ServiceId::Mcp, vec![ServiceId::Exec]),
            ],
            &[ServiceId::Exec],
            &manifest(&["guest"]),
        );
        assert!(matches!(result, Err(GuestError::ServiceConfig(_))));
    }

    #[test]
    fn dependencies_are_ordered_before_dependents() {
        let (_, order, _) = validate_specs(
            vec![
                spec(ServiceId::Exec, vec![ServiceId::Audit]),
                spec(ServiceId::Audit, Vec::new()),
            ],
            &[ServiceId::Exec],
            &manifest(&["guest"]),
        )
        .expect("valid graph");
        assert_eq!(order, vec![ServiceId::Audit, ServiceId::Exec]);
    }

    #[test]
    fn restart_budget_exhaustion_is_deterministic() {
        let policy = RestartPolicy {
            max_restarts: 2,
            backoff_ms: 0,
        };
        assert!(restart_allowed(&policy, 1));
        assert!(restart_allowed(&policy, 2));
        assert!(!restart_allowed(&policy, 3));
    }

    #[test]
    fn mandatory_services_cannot_depend_on_optional_services() {
        let mut optional = spec(ServiceId::Audit, Vec::new());
        optional.mandatory = false;
        let result = validate_specs(
            vec![spec(ServiceId::Exec, vec![ServiceId::Audit]), optional],
            &[ServiceId::Exec],
            &manifest(&["guest"]),
        );
        assert!(matches!(result, Err(GuestError::ServiceConfig(_))));
    }
}
