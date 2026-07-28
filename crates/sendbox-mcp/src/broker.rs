use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::audit::{BoundaryAuditEvent, BoundaryAuditSink};
use crate::config::ApprovedCommand;
use crate::error::BrokerError;
use crate::framing::{FrameDecoder, FramingMode, encode_frame};
use crate::jsonrpc::validate_message;
use crate::policy::{AuditDecision, CompiledToolPolicy, PolicyAction};

pub type ChildReader = Box<dyn AsyncRead + Send + Unpin>;
pub type ChildWriter = Box<dyn AsyncWrite + Send + Unpin>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerDirection {
    ToServer,
    FromServer,
}

pub trait BrokerObserver: Send + Sync {
    fn observe(&self, direction: BrokerDirection, payload: &[u8]) -> Result<(), BrokerError>;
}

#[derive(Clone)]
struct BrokerIoContext {
    config: BrokerConfiguration,
    observer: Option<Arc<dyn BrokerObserver>>,
    policy: CompiledToolPolicy,
    audit: Arc<dyn BoundaryAuditSink>,
    requests: Arc<AsyncMutex<RequestTracker>>,
}

#[derive(Debug, Default)]
struct RequestTracker {
    client_requests: BTreeMap<String, String>,
    server_requests: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StderrPolicy {
    Inherit,
    Discard,
    Capture { max_bytes: usize },
}

#[derive(Debug, Clone)]
pub struct BrokerConfiguration {
    pub client_framing: FramingMode,
    pub server_framing: FramingMode,
    pub max_frame_bytes: usize,
    pub outbound_queue_capacity: usize,
    pub backpressure_timeout: Duration,
    pub graceful_shutdown_timeout: Duration,
    pub cleanup_timeout: Duration,
    pub stderr_policy: StderrPolicy,
}

impl Default for BrokerConfiguration {
    fn default() -> Self {
        Self {
            client_framing: FramingMode::Auto,
            server_framing: FramingMode::Auto,
            max_frame_bytes: 1_048_576,
            outbound_queue_capacity: 32,
            backpressure_timeout: Duration::from_secs(5),
            graceful_shutdown_timeout: Duration::from_secs(5),
            cleanup_timeout: Duration::from_secs(2),
            stderr_policy: StderrPolicy::Capture {
                max_bytes: 64 * 1024,
            },
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BrokerCancellation(CancellationToken);

impl BrokerCancellation {
    pub fn cancel(&self) {
        self.0.cancel();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
}

#[derive(Debug)]
pub struct BrokerReport {
    pub child_status: ExitStatus,
    pub stderr: Vec<u8>,
    pub decisions: Vec<AuditDecision>,
}

#[async_trait]
pub trait BrokerChild: Send {
    fn take_stdin(&mut self) -> Option<ChildWriter>;
    fn take_stdout(&mut self) -> Option<ChildReader>;
    fn take_stderr(&mut self) -> Option<ChildReader>;
    /// Waiting must be cancellation-safe: dropping the returned future before
    /// completion cannot consume the ability to wait again.
    async fn wait(&mut self) -> Result<ExitStatus, BrokerError>;
    fn start_kill(&mut self) -> Result<(), BrokerError>;
}

#[async_trait]
pub trait ProcessLauncher: Send + Sync {
    async fn spawn(
        &self,
        command: &ApprovedCommand,
        stderr_policy: &StderrPolicy,
    ) -> Result<Box<dyn BrokerChild>, BrokerError>;
}

#[derive(Debug, Clone, Default)]
pub struct TokioProcessLauncher {
    environment: BTreeMap<String, String>,
    working_directory: Option<PathBuf>,
}

impl TokioProcessLauncher {
    #[must_use]
    pub fn new(environment: BTreeMap<String, String>, working_directory: Option<PathBuf>) -> Self {
        Self {
            environment,
            working_directory,
        }
    }
}

#[async_trait]
impl ProcessLauncher for TokioProcessLauncher {
    async fn spawn(
        &self,
        approved: &ApprovedCommand,
        stderr_policy: &StderrPolicy,
    ) -> Result<Box<dyn BrokerChild>, BrokerError> {
        let mut command = Command::new(approved.executable());
        command
            .args(approved.arguments())
            .env_clear()
            .envs(&self.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true);
        if let Some(directory) = &self.working_directory {
            command.current_dir(directory);
        }
        match stderr_policy {
            StderrPolicy::Inherit => {
                command.stderr(Stdio::inherit());
            }
            StderrPolicy::Discard => {
                command.stderr(Stdio::null());
            }
            StderrPolicy::Capture { .. } => {
                command.stderr(Stdio::piped());
            }
        }
        let child = command
            .spawn()
            .map_err(|error| BrokerError::Launch(error.to_string()))?;
        Ok(Box::new(TokioBrokerChild(child)))
    }
}

struct TokioBrokerChild(Child);

#[async_trait]
impl BrokerChild for TokioBrokerChild {
    fn take_stdin(&mut self) -> Option<ChildWriter> {
        self.0
            .stdin
            .take()
            .map(|stdin| Box::new(stdin) as ChildWriter)
    }

    fn take_stdout(&mut self) -> Option<ChildReader> {
        self.0
            .stdout
            .take()
            .map(|stdout| Box::new(stdout) as ChildReader)
    }

    fn take_stderr(&mut self) -> Option<ChildReader> {
        self.0
            .stderr
            .take()
            .map(|stderr| Box::new(stderr) as ChildReader)
    }

    async fn wait(&mut self) -> Result<ExitStatus, BrokerError> {
        self.0.wait().await.map_err(BrokerError::Io)
    }

    fn start_kill(&mut self) -> Result<(), BrokerError> {
        self.0.start_kill().map_err(BrokerError::Io)
    }
}

pub struct StdioBroker<L> {
    launcher: L,
    approved_commands: BTreeSet<ApprovedCommand>,
    command: ApprovedCommand,
    policy: CompiledToolPolicy,
    audit: Arc<dyn BoundaryAuditSink>,
    config: BrokerConfiguration,
    observer: Option<Arc<dyn BrokerObserver>>,
}

impl<L: ProcessLauncher> StdioBroker<L> {
    #[must_use]
    pub fn new(
        launcher: L,
        approved_commands: impl IntoIterator<Item = ApprovedCommand>,
        command: ApprovedCommand,
        policy: CompiledToolPolicy,
        audit: Arc<dyn BoundaryAuditSink>,
        config: BrokerConfiguration,
    ) -> Self {
        Self {
            launcher,
            approved_commands: approved_commands.into_iter().collect(),
            command,
            policy,
            audit,
            config,
            observer: None,
        }
    }

    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn BrokerObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub async fn run<R, W>(
        &self,
        client_reader: R,
        client_writer: W,
        cancellation: BrokerCancellation,
    ) -> Result<BrokerReport, BrokerError>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        if !self.approved_commands.contains(&self.command) {
            return Err(BrokerError::CommandNotApproved);
        }
        let mut child = self
            .launcher
            .spawn(&self.command, &self.config.stderr_policy)
            .await?;
        let child_stdin = match child.take_stdin() {
            Some(stdin) => stdin,
            None => {
                cleanup_child(child.as_mut(), self.config.cleanup_timeout).await?;
                return Err(BrokerError::Launch("child stdin was not piped".into()));
            }
        };
        let child_stdout = match child.take_stdout() {
            Some(stdout) => stdout,
            None => {
                cleanup_child(child.as_mut(), self.config.cleanup_timeout).await?;
                return Err(BrokerError::Launch("child stdout was not piped".into()));
            }
        };
        let child_stderr = child.take_stderr();

        let internal = CancellationToken::new();
        let client_input_closed = Arc::new(AtomicBool::new(false));
        let (outbound_tx, outbound_rx) = mpsc::channel(self.config.outbound_queue_capacity.max(1));
        let requests = Arc::new(AsyncMutex::new(RequestTracker::default()));
        let io_context = BrokerIoContext {
            config: self.config.clone(),
            observer: self.observer.clone(),
            policy: self.policy.clone(),
            audit: Arc::clone(&self.audit),
            requests,
        };
        let mut tasks = JoinSet::new();
        tasks.spawn(client_to_server(
            client_reader,
            child_stdin,
            outbound_tx.clone(),
            io_context.clone(),
            internal.clone(),
            Arc::clone(&client_input_closed),
        ));
        tasks.spawn(server_to_client(
            child_stdout,
            outbound_tx,
            io_context,
            internal.clone(),
        ));
        tasks.spawn(write_client(
            client_writer,
            outbound_rx,
            self.config.backpressure_timeout,
            internal.clone(),
        ));
        if let Some(stderr) = child_stderr {
            tasks.spawn(drain_stderr(
                stderr,
                self.config.stderr_policy.clone(),
                internal.clone(),
            ));
        } else {
            tasks.spawn(async { Ok(TaskOutcome::Stderr(Vec::new())) });
        }

        let mut client_done = false;
        let mut server_done = false;
        let mut writer_done = false;
        let mut stderr_done = false;
        let mut decisions = Vec::new();
        let mut stderr = Vec::new();
        let mut child_status = None;
        let mut shutdown_deadline = None;

        let result = async {
            let mut child_wait = Box::pin(child.wait());
            loop {
                if let Some(status) = child_status
                    && client_done
                    && server_done
                    && writer_done
                    && stderr_done
                {
                    break Ok(BrokerReport {
                        child_status: status,
                        stderr,
                        decisions,
                    });
                }

                tokio::select! {
                    biased;
                    () = cancellation.0.cancelled() => {
                        break Err(BrokerError::Cancelled);
                    }
                    task = tasks.join_next(), if !tasks.is_empty() => {
                        let task = task
                            .ok_or_else(|| BrokerError::Task("task set ended unexpectedly".into()))?
                            .map_err(|error| BrokerError::Task(error.to_string()))??;
                        match task {
                            TaskOutcome::Client(mut task_decisions) => {
                                decisions.append(&mut task_decisions);
                                client_done = true;
                                shutdown_deadline = Some(Instant::now() + self.config.graceful_shutdown_timeout);
                            }
                            TaskOutcome::Server(mut task_decisions) => {
                                decisions.append(&mut task_decisions);
                                server_done = true;
                            }
                            TaskOutcome::Writer => writer_done = true,
                            TaskOutcome::Stderr(bytes) => {
                                stderr = bytes;
                                stderr_done = true;
                            }
                        }
                    }
                    status = &mut child_wait, if child_status.is_none() => {
                        let status = status?;
                        if !client_input_closed.load(Ordering::Acquire) {
                            break Err(BrokerError::ChildExited);
                        }
                        child_status = Some(status);
                    }
                    _ = async {
                        if let Some(deadline) = shutdown_deadline {
                            timeout_at(deadline, std::future::pending::<()>()).await.ok();
                        } else {
                            std::future::pending::<()>().await;
                        }
                    }, if shutdown_deadline.is_some() => {
                        break Err(BrokerError::Cleanup(
                            "broker tasks did not finish after client input closed".into(),
                        ));
                    }
                }
            }
        }
        .await;

        if result.is_err() {
            internal.cancel();
            tasks.abort_all();
            if let Err(cleanup) = cleanup_child(child.as_mut(), self.config.cleanup_timeout).await {
                return Err(BrokerError::Cleanup(format!(
                    "primary failure: {}; cleanup failure: {cleanup}",
                    result.as_ref().expect_err("result is an error")
                )));
            }
        }
        result
    }
}

#[derive(Debug)]
enum TaskOutcome {
    Client(Vec<AuditDecision>),
    Server(Vec<AuditDecision>),
    Writer,
    Stderr(Vec<u8>),
}

async fn client_to_server<R>(
    mut client: R,
    mut server: ChildWriter,
    outbound: mpsc::Sender<Vec<u8>>,
    context: BrokerIoContext,
    cancellation: CancellationToken,
    client_input_closed: Arc<AtomicBool>,
) -> Result<TaskOutcome, BrokerError>
where
    R: AsyncRead + Send + Unpin + 'static,
{
    let mut decoder = FrameDecoder::new(
        context.config.client_framing,
        context.config.max_frame_bytes,
    );
    let mut buffer = [0u8; 8192];
    let mut decisions = Vec::new();
    loop {
        let read = tokio::select! {
            () = cancellation.cancelled() => return Err(BrokerError::Cancelled),
            read = client.read(&mut buffer) => read?,
        };
        if read == 0 {
            decoder.finish()?;
            client_input_closed.store(true, Ordering::Release);
            server.shutdown().await?;
            return Ok(TaskOutcome::Client(decisions));
        }
        for frame in decoder.feed(&buffer[..read])? {
            let message = validate_message(&frame.payload)?;
            if let Some(observer) = &context.observer {
                observer.observe(BrokerDirection::ToServer, &frame.payload)?;
            }
            match context.policy.evaluate_message(&message) {
                PolicyAction::Forward(decision) => {
                    context
                        .audit
                        .record(&BoundaryAuditEvent::from_decision(&decision))?;
                    track_client_message(&context.requests, &message).await?;
                    decisions.push(decision);
                    server.write_all(&frame.raw).await?;
                    server.flush().await?;
                }
                PolicyAction::Respond { response, decision } => {
                    context
                        .audit
                        .record(&BoundaryAuditEvent::from_decision(&decision))?;
                    decisions.push(decision);
                    send_outbound(
                        &outbound,
                        encode_frame(&response, frame.mode),
                        context.config.backpressure_timeout,
                        &cancellation,
                    )
                    .await?;
                }
                PolicyAction::Drop(decision) => {
                    context
                        .audit
                        .record(&BoundaryAuditEvent::from_decision(&decision))?;
                    decisions.push(decision);
                }
                PolicyAction::Terminate(reason) => return Err(BrokerError::Policy(reason)),
            }
        }
    }
}

async fn server_to_client(
    mut server: ChildReader,
    outbound: mpsc::Sender<Vec<u8>>,
    context: BrokerIoContext,
    cancellation: CancellationToken,
) -> Result<TaskOutcome, BrokerError> {
    let mut decoder = FrameDecoder::new(
        context.config.server_framing,
        context.config.max_frame_bytes,
    );
    let mut buffer = [0u8; 8192];
    let mut decisions = Vec::new();
    loop {
        let read = tokio::select! {
            () = cancellation.cancelled() => return Err(BrokerError::Cancelled),
            read = server.read(&mut buffer) => read?,
        };
        if read == 0 {
            decoder.finish()?;
            return Ok(TaskOutcome::Server(decisions));
        }
        for frame in decoder.feed(&buffer[..read])? {
            let message = validate_message(&frame.payload)?;
            if let Some(observer) = &context.observer {
                observer.observe(BrokerDirection::FromServer, &frame.payload)?;
            }
            let request_method = track_server_message(&context.requests, &message).await?;
            let raw = if request_method.as_deref() == Some("tools/list") {
                let filtered = context.policy.filter_tools_list_response(&frame.payload)?;
                for decision in filtered.decisions {
                    context
                        .audit
                        .record(&BoundaryAuditEvent::from_decision(&decision))?;
                    decisions.push(decision);
                }
                encode_frame(&filtered.payload, frame.mode)
            } else {
                frame.raw
            };
            send_outbound(
                &outbound,
                raw,
                context.config.backpressure_timeout,
                &cancellation,
            )
            .await?;
        }
    }
}

async fn track_client_message(
    requests: &AsyncMutex<RequestTracker>,
    message: &crate::jsonrpc::ValidatedMessage,
) -> Result<(), BrokerError> {
    let mut requests = requests.lock().await;
    match message.kind {
        crate::jsonrpc::MessageKind::Request => {
            let id = message
                .id
                .raw()
                .ok_or_else(|| BrokerError::Policy("MCP request is missing an id".to_owned()))?;
            let method = message
                .method
                .as_deref()
                .ok_or_else(|| BrokerError::Policy("MCP request is missing a method".to_owned()))?;
            if requests
                .client_requests
                .insert(id.to_owned(), method.to_owned())
                .is_some()
            {
                return Err(BrokerError::Policy(format!(
                    "duplicate outstanding MCP client request id {id}"
                )));
            }
        }
        crate::jsonrpc::MessageKind::Response | crate::jsonrpc::MessageKind::Error => {
            let id = message
                .id
                .raw()
                .ok_or_else(|| BrokerError::Policy("MCP response is missing an id".to_owned()))?;
            if requests.server_requests.remove(id).is_none() {
                return Err(BrokerError::Policy(format!(
                    "MCP client response id {id} has no matching server request"
                )));
            }
        }
        crate::jsonrpc::MessageKind::Notification => {}
    }
    Ok(())
}

async fn track_server_message(
    requests: &AsyncMutex<RequestTracker>,
    message: &crate::jsonrpc::ValidatedMessage,
) -> Result<Option<String>, BrokerError> {
    let mut requests = requests.lock().await;
    match message.kind {
        crate::jsonrpc::MessageKind::Request => {
            let id = message
                .id
                .raw()
                .ok_or_else(|| BrokerError::Policy("MCP request is missing an id".to_owned()))?;
            let method = message
                .method
                .as_deref()
                .ok_or_else(|| BrokerError::Policy("MCP request is missing a method".to_owned()))?;
            if requests
                .server_requests
                .insert(id.to_owned(), method.to_owned())
                .is_some()
            {
                return Err(BrokerError::Policy(format!(
                    "duplicate outstanding MCP server request id {id}"
                )));
            }
            Ok(None)
        }
        crate::jsonrpc::MessageKind::Response | crate::jsonrpc::MessageKind::Error => {
            let id = message
                .id
                .raw()
                .ok_or_else(|| BrokerError::Policy("MCP response is missing an id".to_owned()))?;
            requests
                .client_requests
                .remove(id)
                .map(Some)
                .ok_or_else(|| {
                    BrokerError::Policy(format!(
                        "MCP server response id {id} has no matching client request"
                    ))
                })
        }
        crate::jsonrpc::MessageKind::Notification => Ok(None),
    }
}

async fn send_outbound(
    outbound: &mpsc::Sender<Vec<u8>>,
    frame: Vec<u8>,
    deadline: Duration,
    cancellation: &CancellationToken,
) -> Result<(), BrokerError> {
    tokio::select! {
        () = cancellation.cancelled() => Err(BrokerError::Cancelled),
        sent = timeout(deadline, outbound.send(frame)) => match sent {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(BrokerError::ClientDisconnected),
            Err(_) => Err(BrokerError::OutputSaturated),
        }
    }
}

async fn write_client<W>(
    mut client: W,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    write_timeout: Duration,
    cancellation: CancellationToken,
) -> Result<TaskOutcome, BrokerError>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    loop {
        let frame = tokio::select! {
            () = cancellation.cancelled() => return Err(BrokerError::Cancelled),
            frame = outbound.recv() => frame,
        };
        let Some(frame) = frame else {
            client.shutdown().await?;
            return Ok(TaskOutcome::Writer);
        };
        tokio::select! {
            () = cancellation.cancelled() => return Err(BrokerError::Cancelled),
            written = timeout(write_timeout, client.write_all(&frame)) => match written {
                Ok(result) => result?,
                Err(_) => return Err(BrokerError::OutputSaturated),
            }
        }
        tokio::select! {
            () = cancellation.cancelled() => return Err(BrokerError::Cancelled),
            flushed = timeout(write_timeout, client.flush()) => match flushed {
                Ok(result) => result?,
                Err(_) => return Err(BrokerError::OutputSaturated),
            }
        }
    }
}

async fn drain_stderr(
    mut stderr: ChildReader,
    policy: StderrPolicy,
    cancellation: CancellationToken,
) -> Result<TaskOutcome, BrokerError> {
    let maximum = match policy {
        StderrPolicy::Capture { max_bytes } => max_bytes,
        StderrPolicy::Inherit | StderrPolicy::Discard => 0,
    };
    let mut captured = Vec::with_capacity(maximum.min(8192));
    let mut buffer = [0u8; 8192];
    loop {
        let read = tokio::select! {
            () = cancellation.cancelled() => return Err(BrokerError::Cancelled),
            read = stderr.read(&mut buffer) => read?,
        };
        if read == 0 {
            return Ok(TaskOutcome::Stderr(captured));
        }
        let remaining = maximum.saturating_sub(captured.len());
        captured.extend_from_slice(&buffer[..read.min(remaining)]);
    }
}

async fn cleanup_child(
    child: &mut dyn BrokerChild,
    cleanup_timeout: Duration,
) -> Result<(), BrokerError> {
    child.start_kill()?;
    timeout(cleanup_timeout, child.wait())
        .await
        .map_err(|_| BrokerError::Cleanup("timed out waiting for killed child".into()))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use sendbox_policy::{Action, ToolCallPolicy, ToolTransport};
    use tokio::io::{AsyncWrite, DuplexStream, duplex};
    use tokio::sync::{Notify, oneshot};

    use super::*;
    use crate::error::AuditError;

    type RecordedEvents = Arc<Mutex<Vec<(BrokerDirection, Vec<u8>)>>>;

    #[derive(Clone)]
    struct FakeLauncher {
        behavior: FakeBehavior,
        killed: Arc<Mutex<bool>>,
    }

    #[derive(Clone, Copy)]
    enum FakeBehavior {
        Echo,
        ToolList,
        Flood,
        Die,
    }

    struct FakeChild {
        stdin: Option<DuplexStream>,
        stdout: Option<DuplexStream>,
        stderr: Option<DuplexStream>,
        status: Option<oneshot::Receiver<ExitStatus>>,
        cached_status: Option<ExitStatus>,
        killed: Arc<Mutex<bool>>,
        notify: Arc<Notify>,
    }

    struct RecordingObserver {
        events: RecordedEvents,
    }

    struct TestAudit;

    impl BoundaryAuditSink for TestAudit {
        fn record(&self, _event: &BoundaryAuditEvent) -> Result<(), AuditError> {
            Ok(())
        }
    }

    struct FailingAudit;

    impl BoundaryAuditSink for FailingAudit {
        fn record(&self, _event: &BoundaryAuditEvent) -> Result<(), AuditError> {
            Err(AuditError::UntrustedPath("test".to_owned()))
        }
    }

    impl BrokerObserver for RecordingObserver {
        fn observe(&self, direction: BrokerDirection, payload: &[u8]) -> Result<(), BrokerError> {
            self.events
                .lock()
                .expect("observer mutex")
                .push((direction, payload.to_vec()));
            Ok(())
        }
    }

    #[async_trait]
    impl ProcessLauncher for FakeLauncher {
        async fn spawn(
            &self,
            _command: &ApprovedCommand,
            _stderr_policy: &StderrPolicy,
        ) -> Result<Box<dyn BrokerChild>, BrokerError> {
            let (broker_stdin, mut server_stdin) = duplex(4096);
            let (mut server_stdout, broker_stdout) = duplex(4096);
            let (mut server_stderr, broker_stderr) = duplex(4096);
            let (status_tx, status_rx) = oneshot::channel();
            let notify = Arc::new(Notify::new());
            let notify_task = Arc::clone(&notify);
            let behavior = self.behavior;
            tokio::spawn(async move {
                match behavior {
                    FakeBehavior::Echo => {
                        let mut bytes = Vec::new();
                        server_stdin.read_to_end(&mut bytes).await.unwrap();
                        if !bytes.is_empty() {
                            let _ = server_stdout.write_all(&bytes).await;
                        }
                    }
                    FakeBehavior::ToolList => {
                        let mut bytes = Vec::new();
                        server_stdin.read_to_end(&mut bytes).await.unwrap();
                        if !bytes.is_empty() {
                            let _ = server_stdout
                                .write_all(
                                    b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"delete_file\"},{\"name\":\"other\"}],\"nextCursor\":\"next\"}}\n",
                                )
                                .await;
                        }
                    }
                    FakeBehavior::Flood => {
                        for index in 0..64 {
                            let _ = server_stdout
                                .write_all(
                                    format!(
                                        "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\",\"params\":{{\"i\":{index}}}}}\n"
                                    )
                                    .as_bytes(),
                                )
                                .await;
                        }
                    }
                    FakeBehavior::Die => {}
                }
                let _ = server_stderr.write_all(b"diagnostic").await;
                drop(server_stdout);
                drop(server_stderr);
                let _ = status_tx.send(success_status());
                notify_task.notify_waiters();
            });
            Ok(Box::new(FakeChild {
                stdin: Some(broker_stdin),
                stdout: Some(broker_stdout),
                stderr: Some(broker_stderr),
                status: Some(status_rx),
                cached_status: None,
                killed: Arc::clone(&self.killed),
                notify,
            }))
        }
    }

    #[async_trait]
    impl BrokerChild for FakeChild {
        fn take_stdin(&mut self) -> Option<ChildWriter> {
            self.stdin
                .take()
                .map(|stream| Box::new(stream) as ChildWriter)
        }

        fn take_stdout(&mut self) -> Option<ChildReader> {
            self.stdout
                .take()
                .map(|stream| Box::new(stream) as ChildReader)
        }

        fn take_stderr(&mut self) -> Option<ChildReader> {
            self.stderr
                .take()
                .map(|stream| Box::new(stream) as ChildReader)
        }

        async fn wait(&mut self) -> Result<ExitStatus, BrokerError> {
            if let Some(status) = self.cached_status {
                return Ok(status);
            }
            let receiver = self
                .status
                .as_mut()
                .ok_or_else(|| BrokerError::Task("wait called twice".into()))?;
            let status = receiver
                .await
                .map_err(|error| BrokerError::Task(error.to_string()))?;
            self.cached_status = Some(status);
            self.status = None;
            Ok(status)
        }

        fn start_kill(&mut self) -> Result<(), BrokerError> {
            *self.killed.lock().unwrap() = true;
            self.notify.notify_waiters();
            Ok(())
        }
    }

    struct NeverWriter;

    impl AsyncWrite for NeverWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Poll::Pending
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn success_status() -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(0)
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(0)
        }
    }

    fn broker_with_kill_flag(
        behavior: FakeBehavior,
        config: BrokerConfiguration,
    ) -> (StdioBroker<FakeLauncher>, Arc<Mutex<bool>>) {
        let command =
            ApprovedCommand::new("/usr/bin/node", ["/opt/mcp-server-filesystem.js".into()])
                .unwrap();
        let policy = CompiledToolPolicy::compile_legacy_unbound(&ToolCallPolicy {
            transport: ToolTransport::Stdio,
            default_action: Action::Deny,
            allowlist: vec!["read_*".into()],
            denylist: vec!["*delete*".into()],
            max_frame_bytes: 4096,
            server_command_patterns: Vec::new(),
            allowed_server_commands: Vec::new(),
            servers: BTreeMap::new(),
        });
        let killed = Arc::new(Mutex::new(false));
        let broker = StdioBroker::new(
            FakeLauncher {
                behavior,
                killed: Arc::clone(&killed),
            },
            [command.clone()],
            command,
            policy,
            Arc::new(TestAudit),
            config,
        );
        (broker, killed)
    }

    fn broker(behavior: FakeBehavior, config: BrokerConfiguration) -> StdioBroker<FakeLauncher> {
        broker_with_kill_flag(behavior, config).0
    }

    #[tokio::test]
    async fn forwards_allowed_frames_and_captures_stderr() {
        let (mut input_writer, input_reader) = duplex(4096);
        let (output_writer, mut output_reader) = duplex(4096);
        input_writer
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\"}}\n",
            )
            .await
            .unwrap();
        input_writer.shutdown().await.unwrap();
        let report = broker(FakeBehavior::Echo, BrokerConfiguration::default())
            .run(input_reader, output_writer, BrokerCancellation::default())
            .await
            .unwrap();
        let mut output = Vec::new();
        output_reader.read_to_end(&mut output).await.unwrap();
        assert!(String::from_utf8(output).unwrap().contains("read_file"));
        assert_eq!(report.stderr, b"diagnostic");
    }

    #[tokio::test]
    async fn tokio_launcher_clears_unapproved_environment() {
        let temp = tempfile::tempdir().expect("tempdir");
        let executable = temp.path().join("mcp-env-fixture");
        std::fs::write(
            &executable,
            b"#!/bin/sh\nprintf '%s|%s' \"$ALLOWED\" \"${SENDBOX_MCP_TEST_BLOCKED-unset}\"\n",
        )
        .expect("fixture");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("fixture mode");
        let command = ApprovedCommand::new(executable.display().to_string(), Vec::<String>::new())
            .expect("approved command");
        let launcher = TokioProcessLauncher::new(
            BTreeMap::from([("ALLOWED".to_owned(), "visible".to_owned())]),
            Some(temp.path().to_path_buf()),
        );
        let mut child = launcher
            .spawn(&command, &StderrPolicy::Discard)
            .await
            .expect("launch");
        let mut stdin = child.take_stdin().expect("stdin");
        stdin.shutdown().await.expect("shutdown stdin");
        let mut stdout = child.take_stdout().expect("stdout");
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.expect("read stdout");
        assert!(child.wait().await.expect("wait").success());
        assert_eq!(output, b"visible|unset");
    }

    #[tokio::test]
    async fn denied_content_length_request_gets_matching_error_frame() {
        let config = BrokerConfiguration {
            client_framing: FramingMode::ContentLength,
            server_framing: FramingMode::ContentLength,
            ..BrokerConfiguration::default()
        };
        let payload =
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_file"}}"#;
        let (mut input_writer, input_reader) = duplex(4096);
        let (output_writer, mut output_reader) = duplex(4096);
        input_writer
            .write_all(&encode_frame(payload, FramingMode::ContentLength))
            .await
            .unwrap();
        input_writer.shutdown().await.unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let _report = broker(FakeBehavior::Echo, config)
            .with_observer(Arc::new(RecordingObserver {
                events: Arc::clone(&events),
            }))
            .run(input_reader, output_writer, BrokerCancellation::default())
            .await
            .unwrap();
        let mut output = Vec::new();
        output_reader.read_to_end(&mut output).await.unwrap();
        let mut decoder = FrameDecoder::new(FramingMode::ContentLength, 4096);
        let frames = decoder.feed(&output).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(
            String::from_utf8(frames[0].payload.clone())
                .unwrap()
                .contains("-32001")
        );
        let events = events.lock().expect("observer mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, BrokerDirection::ToServer);
        assert!(String::from_utf8_lossy(&events[0].1).contains("delete_file"));
    }

    #[tokio::test]
    async fn filters_correlated_tools_list_responses() {
        let (mut input_writer, input_reader) = duplex(4096);
        let (output_writer, mut output_reader) = duplex(4096);
        input_writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
            .await
            .unwrap();
        input_writer.shutdown().await.unwrap();

        let report = broker(FakeBehavior::ToolList, BrokerConfiguration::default())
            .run(input_reader, output_writer, BrokerCancellation::default())
            .await
            .unwrap();
        let mut output = Vec::new();
        output_reader.read_to_end(&mut output).await.unwrap();
        let response = String::from_utf8(output).unwrap();
        assert!(response.contains("read_file"));
        assert!(!response.contains("delete_file"));
        assert!(!response.contains("\"other\""));
        assert!(response.contains("nextCursor"));
        assert_eq!(
            report
                .decisions
                .iter()
                .filter(|decision| decision.method == "tools/list" && decision.tool.is_some())
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn audit_failure_denies_before_forwarding_and_kills_child() {
        let command =
            ApprovedCommand::new("/usr/bin/node", ["/opt/mcp-server-filesystem.js".into()])
                .unwrap();
        let killed = Arc::new(Mutex::new(false));
        let broker = StdioBroker::new(
            FakeLauncher {
                behavior: FakeBehavior::Echo,
                killed: Arc::clone(&killed),
            },
            [command.clone()],
            command,
            CompiledToolPolicy::compile_legacy_unbound(&ToolCallPolicy {
                allowlist: vec!["read_*".to_owned()],
                ..ToolCallPolicy::default()
            }),
            Arc::new(FailingAudit),
            BrokerConfiguration::default(),
        );
        let (mut input_writer, input_reader) = duplex(4096);
        let (output_writer, _output_reader) = duplex(4096);
        input_writer
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\"}}\n",
            )
            .await
            .unwrap();
        input_writer.shutdown().await.unwrap();

        let error = broker
            .run(input_reader, output_writer, BrokerCancellation::default())
            .await
            .expect_err("audit failure must fail the broker");
        assert!(
            matches!(error, BrokerError::Audit(_)),
            "unexpected broker error: {error:?}"
        );
        assert!(*killed.lock().unwrap());
    }

    #[tokio::test]
    async fn child_death_is_fail_closed() {
        let (_input_writer, input_reader) = duplex(4096);
        let (output_writer, _output_reader) = duplex(4096);
        assert!(matches!(
            broker(FakeBehavior::Die, BrokerConfiguration::default())
                .run(input_reader, output_writer, BrokerCancellation::default())
                .await,
            Err(BrokerError::ChildExited)
        ));
    }

    #[tokio::test]
    async fn output_saturation_fails_closed() {
        let config = BrokerConfiguration {
            outbound_queue_capacity: 1,
            backpressure_timeout: Duration::from_millis(20),
            ..BrokerConfiguration::default()
        };
        let (mut input_writer, input_reader) = duplex(4096);
        input_writer.shutdown().await.unwrap();
        assert!(matches!(
            broker(FakeBehavior::Flood, config)
                .run(input_reader, NeverWriter, BrokerCancellation::default())
                .await,
            Err(BrokerError::OutputSaturated)
        ));
    }

    #[tokio::test]
    async fn cancellation_kills_and_reaps_child() {
        let (_input_writer, input_reader) = duplex(4096);
        let (output_writer, _output_reader) = duplex(4096);
        let cancellation = BrokerCancellation::default();
        cancellation.cancel();
        assert!(matches!(
            broker(FakeBehavior::Echo, BrokerConfiguration::default())
                .run(input_reader, output_writer, cancellation)
                .await,
            Err(BrokerError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn malformed_input_still_kills_child() {
        let (mut input_writer, input_reader) = duplex(4096);
        let (output_writer, _output_reader) = duplex(4096);
        input_writer.write_all(b"{not-json}\n").await.unwrap();
        input_writer.shutdown().await.unwrap();
        let (broker, killed) =
            broker_with_kill_flag(FakeBehavior::Echo, BrokerConfiguration::default());
        assert!(
            broker
                .run(input_reader, output_writer, BrokerCancellation::default())
                .await
                .is_err()
        );
        assert!(*killed.lock().unwrap());
    }
}
