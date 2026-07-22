use std::{
    io,
    pin::Pin,
    process::Stdio,
    sync::Arc,
    task::{Context, Poll},
};

use sendbox_runtime::{
    BoxFuture, CancellationToken, ChannelLifetime, ChannelOwnership, ControlStream, GuestAddress,
    HostAddress, ProvisionedControlChannel, ProvisionedControlChannelDescriptor, RuntimeError,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
    task::JoinHandle,
};

use crate::command::{AppleContainerCommands, minimal_environment};

pub(crate) struct AppleStdioChannel {
    descriptor: ProvisionedControlChannelDescriptor,
    commands: AppleContainerCommands,
    bridge_argv: Vec<String>,
    child: Arc<Mutex<Option<Child>>>,
    stderr_task: Option<JoinHandle<Result<(), RuntimeError>>>,
    accepted: bool,
    cleaned: bool,
}

impl AppleStdioChannel {
    pub(crate) fn new(commands: AppleContainerCommands, bridge_argv: Vec<String>) -> Self {
        Self {
            descriptor: ProvisionedControlChannelDescriptor {
                endpoint_kind: sendbox_runtime::ControlEndpointKind::InheritedStdio,
                host_address: HostAddress::Stdio,
                guest_address: GuestAddress::Stdio,
                ownership: ChannelOwnership::RuntimeLifecycle,
                lifetime: ChannelLifetime::UntilRuntimeCleanup,
            },
            commands,
            bridge_argv,
            child: Arc::new(Mutex::new(None)),
            stderr_task: None,
            accepted: false,
            cleaned: false,
        }
    }
}

impl ProvisionedControlChannel for AppleStdioChannel {
    fn descriptor(&self) -> &ProvisionedControlChannelDescriptor {
        &self.descriptor
    }

    fn accept<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ControlStream>, RuntimeError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(RuntimeError::Cancelled);
            }
            if self.accepted {
                return Err(RuntimeError::ControlChannelAlreadyAccepted);
            }
            self.accepted = true;

            let mut command = Command::new(self.commands.executable());
            command
                .args(&self.bridge_argv)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            for variable in minimal_environment() {
                command.env(variable.key, variable.value);
            }
            let mut child = command.spawn().map_err(|source| RuntimeError::Spawn {
                diagnostic: format!(
                    "{} {}",
                    self.commands.executable().display(),
                    self.bridge_argv.join(" ")
                ),
                source,
            })?;
            let stdin = child.stdin.take().ok_or_else(|| {
                RuntimeError::Provider("Apple control bridge stdin was not created".to_owned())
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                RuntimeError::Provider("Apple control bridge stdout was not created".to_owned())
            })?;
            let stderr = child.stderr.take().ok_or_else(|| {
                RuntimeError::Provider("Apple control bridge stderr was not created".to_owned())
            })?;
            self.stderr_task = Some(tokio::spawn(async move {
                drain_stderr(stderr, 64 * 1024).await
            }));
            *self.child.lock().await = Some(child);
            Ok(Box::new(BridgeStream { stdin, stdout }) as Box<dyn ControlStream>)
        })
    }

    fn cleanup<'a>(
        &'a mut self,
        _cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            if self.cleaned {
                return Ok(());
            }
            if let Some(mut child) = self.child.lock().await.take() {
                if child.try_wait().map_err(RuntimeError::Wait)?.is_none() {
                    child.start_kill().map_err(RuntimeError::Wait)?;
                }
                child.wait().await.map_err(RuntimeError::Wait)?;
            }
            if let Some(task) = self.stderr_task.take() {
                task.await
                    .map_err(|error| RuntimeError::ProcessTask(error.to_string()))??;
            }
            self.cleaned = true;
            Ok(())
        })
    }
}

struct BridgeStream {
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl AsyncRead for BridgeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(context, buffer)
    }
}

impl AsyncWrite for BridgeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stdin).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stdin).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stdin).poll_shutdown(context)
    }
}

async fn drain_stderr(
    mut stderr: tokio::process::ChildStderr,
    retained_limit: usize,
) -> Result<(), RuntimeError> {
    use tokio::io::AsyncReadExt;

    let mut retained = 0_usize;
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stderr
            .read(&mut buffer)
            .await
            .map_err(|source| RuntimeError::ProcessIo {
                stream: "Apple control bridge stderr",
                source,
            })?;
        if read == 0 {
            return Ok(());
        }
        retained = retained.saturating_add(read).min(retained_limit);
    }
}
