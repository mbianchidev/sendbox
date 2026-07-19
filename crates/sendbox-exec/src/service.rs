//! Bounded one-session Unix broker service framing.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use serde::{Deserialize, Serialize};

use crate::api::{CorrelationId, ExecutionEvent, ExecutionRequest, ExecutionResult};
use crate::broker::{Broker, CancellationFlag, EventSink, ExecutionBackend, SinkError};
use crate::error::ExecError;
use crate::runtime::{AuthenticatedUnixListener, RuntimeError};

pub const MAX_SERVICE_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientFrame {
    Execute { request: Box<ExecutionRequest> },
    Cancel { correlation_id: CorrelationId },
    GracefulShutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerFrame {
    Event { event: ExecutionEvent },
    ProtocolError { message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("service io failed: {0}")]
    Io(#[from] io::Error),
    #[error("service protocol failed: {0}")]
    Protocol(String),
    #[error(transparent)]
    Broker(#[from] ExecError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
}

pub struct BrokerService<B> {
    broker: Arc<Broker<B>>,
}

impl<B: ExecutionBackend + 'static> BrokerService<B> {
    #[must_use]
    pub fn new(broker: Arc<Broker<B>>) -> Self {
        Self { broker }
    }

    pub fn serve_once(
        &self,
        listener: &AuthenticatedUnixListener,
    ) -> Result<ExecutionResult, ServiceError> {
        self.serve_connection(listener.accept()?)
    }

    pub fn serve_connection(
        &self,
        mut stream: UnixStream,
    ) -> Result<ExecutionResult, ServiceError> {
        let read_stream = stream.try_clone()?;
        let shutdown_stream = stream.try_clone()?;
        let mut reader = BufReader::new(read_stream);
        let Some(ClientFrame::Execute { request }) = read_frame(&mut reader)? else {
            write_frame(
                &mut stream,
                &ServerFrame::ProtocolError {
                    message: "first frame must be Execute".into(),
                },
            )?;
            return Err(ServiceError::Protocol("first frame must be Execute".into()));
        };

        let cancellation = CancellationFlag::default();
        let done = Arc::new(AtomicBool::new(false));
        spawn_client_control_reader(
            reader,
            cancellation.clone(),
            request.correlation_id.clone(),
            Arc::clone(&done),
        );
        let mut sink = ServiceEventSink {
            stream: &mut stream,
        };
        let result = self.broker.execute(&request, &mut sink, &cancellation)?;
        done.store(true, Ordering::Release);
        let _ = shutdown_stream.shutdown(Shutdown::Both);
        Ok(result)
    }
}

struct ServiceEventSink<'a> {
    stream: &'a mut UnixStream,
}

impl EventSink for ServiceEventSink<'_> {
    fn emit(&mut self, event: ExecutionEvent) -> Result<(), SinkError> {
        write_frame(self.stream, &ServerFrame::Event { event }).map_err(|_| SinkError::Disconnected)
    }
}

fn spawn_client_control_reader(
    mut reader: BufReader<UnixStream>,
    cancellation: CancellationFlag,
    correlation_id: CorrelationId,
    done: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        if !done.load(Ordering::Acquire) {
            match read_frame(&mut reader) {
                Ok(Some(ClientFrame::Cancel {
                    correlation_id: requested,
                })) if requested == correlation_id => {
                    cancellation.cancel();
                }
                Ok(Some(ClientFrame::GracefulShutdown)) => {
                    cancellation.shutdown();
                }
                Ok(Some(ClientFrame::Execute { .. } | ClientFrame::Cancel { .. })) | Err(_) => {
                    cancellation.disconnect();
                }
                Ok(None) => {
                    cancellation.disconnect();
                }
            }
        }
    });
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let encoded = serde_json::to_vec(value).map_err(io::Error::other)?;
    if encoded.len() > MAX_SERVICE_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service frame exceeds limit",
        ));
    }
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

pub fn read_frame<T: for<'de> Deserialize<'de>>(
    reader: &mut impl BufRead,
) -> io::Result<Option<T>> {
    let Some(line) = read_bounded_line(reader)? else {
        return Ok(None);
    };
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(io::Error::other)
}

fn read_bounded_line(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "service frame ended without newline",
                ))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(consumed) > MAX_SERVICE_FRAME_BYTES + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "service frame exceeds limit",
            ));
        }
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sendbox_policy::{Action, CommandPolicy};

    use super::*;
    use crate::api::{
        CleanupReport, CleanupStep, ContainmentProfile, DescriptorPath, EnvironmentEntry,
        ExecutionDecision, ExecutionTimeout, ExitStatus, RelativePath, RootId, StandardInput,
        TerminalState,
    };
    use crate::broker::RequestLimits;
    use crate::environment::EnvironmentPolicy;
    use crate::policy::CompiledCommandPolicy;
    use crate::session::BrokerSession;

    struct CancellableBackend;

    impl ExecutionBackend for CancellableBackend {
        fn execute(
            &self,
            request: &ExecutionRequest,
            _decision: &ExecutionDecision,
            sink: &mut dyn EventSink,
            cancellation: &CancellationFlag,
        ) -> ExecutionResult {
            let _ = sink.emit(ExecutionEvent::Started {
                correlation_id: request.correlation_id.clone(),
                executable_identity: crate::api::FileIdentity {
                    device: 1,
                    inode: 2,
                    mode: 0,
                },
                cwd_identity: crate::api::FileIdentity {
                    device: 1,
                    inode: 3,
                    mode: 0,
                },
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !cancellation.is_cancelled() && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            let terminal = if cancellation.is_cancelled() {
                TerminalState::Cancelled
            } else {
                TerminalState::Exited(ExitStatus {
                    exit_code: Some(0),
                    signal: None,
                })
            };
            ExecutionResult {
                terminal,
                cleanup: complete_cleanup(),
            }
        }
    }

    #[test]
    fn service_streams_typed_events_and_propagates_cancel() {
        let session = Arc::new(BrokerSession::generate().expect("session"));
        let broker = Arc::new(Broker::new(
            Arc::clone(&session),
            CompiledCommandPolicy::compile(&CommandPolicy {
                default_action: Action::Allow,
                allowlist: Vec::new(),
                denylist: Vec::new(),
                log_blocked: true,
            })
            .expect("policy"),
            EnvironmentPolicy::default(),
            RequestLimits::default(),
            CancellableBackend,
        ));
        let service = BrokerService::new(broker);
        let (server, mut client) = UnixStream::pair().expect("pair");
        let service_thread =
            thread::spawn(move || service.serve_connection(server).expect("serve connection"));
        let request = request(&session);
        write_frame(
            &mut client,
            &ClientFrame::Execute {
                request: Box::new(request.clone()),
            },
        )
        .expect("execute frame");
        write_frame(
            &mut client,
            &ClientFrame::Cancel {
                correlation_id: request.correlation_id.clone(),
            },
        )
        .expect("cancel frame");
        let mut reader = BufReader::new(client);
        let mut terminal = None;
        while let Some(frame) = read_frame::<ServerFrame>(&mut reader).expect("server frame") {
            if let ServerFrame::Event {
                event: ExecutionEvent::Terminal { result, .. },
            } = frame
            {
                terminal = Some(result.terminal);
                break;
            }
        }
        assert_eq!(terminal, Some(TerminalState::Cancelled));
        assert_eq!(
            service_thread.join().expect("service thread").terminal,
            TerminalState::Cancelled
        );
    }

    #[test]
    fn service_frame_limit_is_enforced_before_decode() {
        let oversized = vec![b'a'; MAX_SERVICE_FRAME_BYTES + 2];
        let mut reader = BufReader::new(oversized.as_slice());
        assert_eq!(
            read_frame::<ClientFrame>(&mut reader)
                .expect_err("oversized frame")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    fn request(session: &BrokerSession) -> ExecutionRequest {
        ExecutionRequest {
            session_id: session.id(),
            authentication: session.authentication(),
            correlation_id: CorrelationId::new("service-request").expect("correlation"),
            cancellation_id: None,
            executable: DescriptorPath {
                root: RootId::System,
                relative: RelativePath::new("usr/bin/tool").expect("path"),
            },
            argv: vec!["tool".into()],
            cwd: DescriptorPath {
                root: RootId::Workspace,
                relative: RelativePath::new(".").expect("cwd"),
            },
            environment: vec![EnvironmentEntry {
                name: "SAFE".into(),
                value: "yes".into(),
            }],
            stdin: StandardInput::Null,
            timeout: ExecutionTimeout::new(Duration::from_secs(1)).expect("timeout"),
            containment: ContainmentProfile::default(),
        }
    }

    fn complete_cleanup() -> CleanupReport {
        CleanupReport::complete(vec![
            CleanupStep::CgroupKill,
            CleanupStep::PidfdReap,
            CleanupStep::ObserveUnpopulated,
            CleanupStep::RemoveLeaf,
        ])
    }
}
