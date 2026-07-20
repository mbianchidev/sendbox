use std::sync::Arc;

use sendbox_protocol::{Capability, CapabilitySet};
use sendbox_runtime::{
    BootstrapDelivery, BootstrapMaterial, CancellationToken, ChannelLifetime, ChannelOwnership,
    CleanupReport, ControlChannelRequest, CreateRequest, InitializeRequest, PreflightRequest,
    ProvisionedControlChannel, RuntimeProvider, StartRequest, StopRequest,
};

use crate::{
    AgentError, CleanupFailure, GuestConnectionConfiguration, GuestConnector, GuestEvent,
    GuestExecution, GuestLaunchRequest, GuestSecretEnvelope, GuestSession, GuestTerminal,
    OutputSink, RunFailure, RunPlan, SecretResolver, SignalSource,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    Planned,
    Preflighted,
    Initialized,
    Created,
    Started,
    ChannelProvisioned,
    GuestReady,
    SecretsResolved,
    Running,
    Stopping,
    Cleaning,
    Completed,
    Failed,
}

impl AgentState {
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Planned, Self::Preflighted | Self::Failed)
                | (Self::Preflighted, Self::Initialized | Self::Failed)
                | (
                    Self::Initialized,
                    Self::Created | Self::Cleaning | Self::Failed
                )
                | (Self::Created, Self::Started | Self::Cleaning | Self::Failed)
                | (
                    Self::Started,
                    Self::ChannelProvisioned | Self::Stopping | Self::Cleaning | Self::Failed
                )
                | (
                    Self::ChannelProvisioned,
                    Self::GuestReady | Self::Stopping | Self::Cleaning | Self::Failed
                )
                | (
                    Self::GuestReady,
                    Self::SecretsResolved | Self::Stopping | Self::Cleaning | Self::Failed
                )
                | (
                    Self::SecretsResolved,
                    Self::Running | Self::Stopping | Self::Cleaning | Self::Failed
                )
                | (
                    Self::Running,
                    Self::Stopping | Self::Cleaning | Self::Failed
                )
                | (Self::Stopping, Self::Cleaning | Self::Failed)
                | (Self::Cleaning, Self::Completed | Self::Failed)
        )
    }
}

#[derive(Debug)]
pub struct AgentReport {
    pub terminal: GuestTerminal,
    pub states: Vec<AgentState>,
}

pub struct AgentOrchestrator {
    runtime: Arc<dyn RuntimeProvider>,
    secrets: Arc<dyn SecretResolver>,
    connector: Arc<dyn GuestConnector>,
    output: Arc<dyn OutputSink>,
    signals: Arc<dyn SignalSource>,
}

impl AgentOrchestrator {
    #[must_use]
    pub fn new(
        runtime: Arc<dyn RuntimeProvider>,
        secrets: Arc<dyn SecretResolver>,
        connector: Arc<dyn GuestConnector>,
        output: Arc<dyn OutputSink>,
        signals: Arc<dyn SignalSource>,
    ) -> Self {
        Self {
            runtime,
            secrets,
            connector,
            output,
            signals,
        }
    }

    pub async fn run(
        &self,
        plan: &RunPlan,
        cancellation: &CancellationToken,
    ) -> Result<AgentReport, RunFailure> {
        let mut context = RunContext::new(plan);
        let result = self.run_primary(plan, cancellation, &mut context).await;
        let cleanup = self.cleanup(cancellation, &mut context).await;
        match result {
            Ok(terminal) if cleanup.is_empty() => {
                if let Err(primary) = context.transition(AgentState::Completed) {
                    return Err(RunFailure {
                        primary,
                        cleanup: Vec::new(),
                    });
                }
                Ok(AgentReport {
                    terminal,
                    states: context.states,
                })
            }
            Ok(_) => Err(RunFailure {
                primary: AgentError::CleanupAfterSuccess,
                cleanup,
            }),
            Err(primary) => Err(RunFailure { primary, cleanup }),
        }
    }

    async fn run_primary(
        &self,
        plan: &RunPlan,
        cancellation: &CancellationToken,
        context: &mut RunContext<'_>,
    ) -> Result<GuestTerminal, AgentError> {
        check_cancelled(cancellation)?;
        let preflight = self
            .runtime
            .preflight(
                PreflightRequest {
                    required_capabilities: plan.required_runtime_capabilities().clone(),
                },
                cancellation,
            )
            .await?;
        if !preflight.is_compatible() {
            return Err(AgentError::RuntimeCapabilities(format!(
                "runtime `{}` is missing required capabilities",
                self.runtime.runtime_id()
            )));
        }
        context.transition(AgentState::Preflighted)?;

        self.runtime
            .initialize(
                InitializeRequest {
                    state_directory: plan.state_directory().to_path_buf(),
                },
                cancellation,
            )
            .await?;
        context.initialized = true;
        context.transition(AgentState::Initialized)?;

        let container = self
            .runtime
            .create(
                CreateRequest {
                    container_id: plan.container_id().clone(),
                    image: plan.image().to_owned(),
                },
                cancellation,
            )
            .await?;
        context.container_created = true;
        context.transition(AgentState::Created)?;

        self.runtime
            .start(
                &container,
                StartRequest {
                    attach_standard_streams: false,
                },
                cancellation,
            )
            .await?;
        context.started = true;
        context.transition(AgentState::Started)?;

        let bootstrap = self
            .secrets
            .resolve(plan.bootstrap_reference(), cancellation)
            .await?;
        let channel_request = ControlChannelRequest {
            session_id: plan.session_id(),
            container_id: container.clone(),
            endpoint_kind: plan.endpoint_kind(),
            ownership: ChannelOwnership::RuntimeLifecycle,
            lifetime: ChannelLifetime::UntilRuntimeCleanup,
            readiness_timeout: plan.readiness_timeout(),
            bootstrap_delivery: BootstrapDelivery::PreopenedFileDescriptor { descriptor: 3 },
            bootstrap_material: BootstrapMaterial::new(bootstrap.as_bytes().to_vec())?,
        };
        let channel = self
            .runtime
            .provision_control_channel(channel_request, cancellation)
            .await?;
        context.transition(AgentState::ChannelProvisioned)?;
        context.channel = Some(channel);
        let readiness_deadline = tokio::time::Instant::now() + plan.readiness_timeout();
        let stream = tokio::time::timeout(
            readiness_remaining(readiness_deadline)?,
            context
                .channel
                .as_mut()
                .expect("channel was stored")
                .accept(cancellation),
        )
        .await
        .map_err(|_| AgentError::ReadinessTimedOut)??;

        let guest = tokio::time::timeout(
            readiness_remaining(readiness_deadline)?,
            self.connector.connect(
                stream,
                GuestConnectionConfiguration {
                    session_id: plan.session_id(),
                    capabilities: CapabilitySet::from([
                        Capability::Exec,
                        Capability::StreamedIo,
                        Capability::Signals,
                        Capability::Health,
                    ]),
                    required_capabilities: plan.required_guest_capabilities().clone(),
                    bootstrap_secret: bootstrap.as_bytes().to_vec(),
                },
                cancellation,
            ),
        )
        .await
        .map_err(|_| AgentError::ReadinessTimedOut)??;
        if !plan
            .required_guest_capabilities()
            .is_subset(guest.negotiated_capabilities())
        {
            return Err(AgentError::Guest(
                "guest readiness omitted required capabilities".to_owned(),
            ));
        }
        context.guest = Some(guest);
        context.transition(AgentState::GuestReady)?;

        let mut secret_envelopes = Vec::new();
        for reference in plan.secret_references() {
            secret_envelopes.push(self.secrets.resolve(reference, cancellation).await?);
        }
        context.transition(AgentState::SecretsResolved)?;
        let guest_secrets = secret_envelopes
            .iter()
            .map(|envelope| GuestSecretEnvelope {
                reference: envelope.reference().as_str(),
                envelope: envelope.as_bytes(),
            })
            .collect();
        let execution = context
            .guest
            .as_mut()
            .expect("guest was stored")
            .start(
                GuestLaunchRequest {
                    command: plan.command(),
                    environment: plan.environment(),
                    secrets: guest_secrets,
                },
                cancellation,
            )
            .await?;
        context.execution = Some(execution);
        context.transition(AgentState::Running)?;
        self.monitor(cancellation, context).await
    }

    async fn monitor(
        &self,
        cancellation: &CancellationToken,
        context: &mut RunContext<'_>,
    ) -> Result<GuestTerminal, AgentError> {
        loop {
            let execution = context.execution.as_mut().expect("execution was stored");
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    execution.cancel(&CancellationToken::new()).await?;
                    return Err(AgentError::Cancelled);
                }
                signal = self.signals.next_signal() => {
                    if signal.is_some() {
                        cancellation.cancel();
                        execution.cancel(&CancellationToken::new()).await?;
                        return Err(AgentError::Cancelled);
                    }
                }
                event = execution.next_event(cancellation) => {
                    match event? {
                        GuestEvent::Output { stream, bytes } => {
                            if let Err(error) = self.output.write(stream, &bytes, cancellation).await {
                                execution.cancel(&CancellationToken::new()).await?;
                                return Err(error);
                            }
                        }
                        GuestEvent::Terminal(terminal) => return Ok(terminal),
                    }
                }
            }
        }
    }

    async fn cleanup(
        &self,
        cancellation: &CancellationToken,
        context: &mut RunContext<'_>,
    ) -> Vec<CleanupFailure> {
        let cleanup_cancellation = CancellationToken::new();
        let mut failures = Vec::new();
        if context.state != AgentState::Cleaning
            && context.state.can_transition_to(AgentState::Cleaning)
        {
            let _ = context.transition(AgentState::Cleaning);
        }
        if let Some(execution) = context.execution.as_mut()
            && let Err(error) = execution.cancel(&cleanup_cancellation).await
        {
            failures.push(CleanupFailure {
                step: "guest execution cancellation",
                error,
            });
        }
        if let Some(guest) = context.guest.as_mut()
            && let Err(error) = guest.cleanup(&cleanup_cancellation).await
        {
            failures.push(CleanupFailure {
                step: "guest session cleanup",
                error,
            });
        }
        if let Some(channel) = context.channel.as_mut()
            && let Err(error) = channel.cleanup(&cleanup_cancellation).await
        {
            failures.push(CleanupFailure {
                step: "control channel cleanup",
                error: AgentError::Runtime(error),
            });
        }
        if context.started
            && let Err(error) = self
                .runtime
                .stop(
                    context.plan.container_id(),
                    StopRequest::default(),
                    &cleanup_cancellation,
                )
                .await
        {
            failures.push(CleanupFailure {
                step: "runtime stop",
                error: AgentError::Runtime(error),
            });
        }
        if context.container_created {
            match self
                .runtime
                .cleanup(context.plan.container_id(), &cleanup_cancellation)
                .await
            {
                Ok(report) => append_runtime_cleanup_failures(report, &mut failures),
                Err(error) => failures.push(CleanupFailure {
                    step: "runtime cleanup",
                    error: AgentError::Runtime(error),
                }),
            }
        }
        let _ = cancellation;
        failures
    }
}

struct RunContext<'a> {
    plan: &'a RunPlan,
    state: AgentState,
    states: Vec<AgentState>,
    initialized: bool,
    container_created: bool,
    started: bool,
    channel: Option<Box<dyn ProvisionedControlChannel>>,
    guest: Option<Box<dyn GuestSession>>,
    execution: Option<Box<dyn GuestExecution>>,
}

impl<'a> RunContext<'a> {
    fn new(plan: &'a RunPlan) -> Self {
        Self {
            plan,
            state: AgentState::Planned,
            states: vec![AgentState::Planned],
            initialized: false,
            container_created: false,
            started: false,
            channel: None,
            guest: None,
            execution: None,
        }
    }

    fn transition(&mut self, next: AgentState) -> Result<(), AgentError> {
        if !self.state.can_transition_to(next) {
            return Err(AgentError::Guest(format!(
                "invalid agent transition from {:?} to {next:?}",
                self.state
            )));
        }
        self.state = next;
        self.states.push(next);
        Ok(())
    }
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), AgentError> {
    if cancellation.is_cancelled() {
        Err(AgentError::Cancelled)
    } else {
        Ok(())
    }
}

fn readiness_remaining(deadline: tokio::time::Instant) -> Result<std::time::Duration, AgentError> {
    deadline
        .checked_duration_since(tokio::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(AgentError::ReadinessTimedOut)
}

fn append_runtime_cleanup_failures(report: CleanupReport, failures: &mut Vec<CleanupFailure>) {
    let had_failures = !report.failures.is_empty();
    for failure in report.failures {
        failures.push(CleanupFailure {
            step: "runtime cleanup step",
            error: AgentError::Runtime(failure.error),
        });
    }
    if report.remaining > 0 && !had_failures {
        failures.push(CleanupFailure {
            step: "runtime cleanup completion",
            error: AgentError::Guest(format!(
                "{} runtime cleanup step(s) remain",
                report.remaining
            )),
        });
    }
}
