use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sendbox_core::BoundaryPlanDigest;
use sendbox_mcp::framing::{FrameDecoder, FramingMode, encode_frame};
use sendbox_mcp::safe_outputs::{
    AcceptedIntentV1, IntentAccumulator, MAX_SAFE_OUTPUTS_FRAME_BYTES, McpGateway,
    SafeOutputTool, SafeOutputsError, SafeOutputsRuntimePolicy, SafeOutputsSealV1,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::GuestError;

const ARTIFACT_NAME: &str = "accepted.ndjson";
const ROOT_MODE: u32 = 0o755;
const SESSION_MODE: u32 = 0o710;
const ARTIFACT_MODE: u32 = 0o600;
const WRITER_SOCKET_MODE: u32 = 0o660;
const CONTROL_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedSafeOutputs {
    pub artifact: Vec<u8>,
    pub seal: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecorderState {
    Open,
    Sealed,
    Collected,
}

enum Control {
    Seal {
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    Collect {
        reply: tokio::sync::oneshot::Sender<Result<CollectedSafeOutputs, String>>,
    },
    Shutdown {
        reply: tokio::sync::oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub struct SafeOutputsHandle {
    control: tokio::sync::mpsc::Sender<Control>,
    live: Arc<AtomicBool>,
}

impl SafeOutputsHandle {
    #[must_use]
    pub fn verified_live(&self) -> bool {
        self.live.load(Ordering::Acquire) && !self.control.is_closed()
    }

    pub async fn seal(&self) -> Result<(), GuestError> {
        let (reply, receive) = tokio::sync::oneshot::channel();
        self.control
            .send(Control::Seal { reply })
            .await
            .map_err(|_| GuestError::Runtime("Safe Outputs recorder stopped".to_owned()))?;
        receive
            .await
            .map_err(|_| GuestError::Runtime("Safe Outputs recorder stopped".to_owned()))?
            .map_err(GuestError::Runtime)
    }

    pub async fn collect(&self) -> Result<CollectedSafeOutputs, GuestError> {
        let (reply, receive) = tokio::sync::oneshot::channel();
        self.control
            .send(Control::Collect { reply })
            .await
            .map_err(|_| GuestError::Runtime("Safe Outputs recorder stopped".to_owned()))?;
        receive
            .await
            .map_err(|_| GuestError::Runtime("Safe Outputs recorder stopped".to_owned()))?
            .map_err(GuestError::Runtime)
    }

    pub async fn shutdown(&self) {
        let (reply, receive) = tokio::sync::oneshot::channel();
        if self.control.send(Control::Shutdown { reply }).await.is_ok() {
            let _ = receive.await;
        }
    }
}

pub fn start(
    policy: SafeOutputsRuntimePolicy,
    boundary_plan_digest: BoundaryPlanDigest,
    seal_key: [u8; 32],
    owner_uid: u32,
    owner_gid: u32,
    workload_gid: u32,
) -> Result<(SafeOutputsHandle, tokio::task::JoinHandle<Result<(), GuestError>>), GuestError> {
    policy
        .validate()
        .map_err(|error| GuestError::Runtime(format!("invalid Safe Outputs policy: {error}")))?;
    prepare_parent(
        policy
            .writer_socket
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| {
                GuestError::Runtime("Safe Outputs writer socket has no runtime root".to_owned())
            })?,
        owner_uid,
        owner_gid,
    )?;
    let session_root = policy
        .writer_socket
        .parent()
        .ok_or_else(|| GuestError::Runtime("Safe Outputs writer socket has no parent".to_owned()))?;
    prepare_session_root(session_root, owner_uid, workload_gid)?;
    let artifact_path = session_root.join(ARTIFACT_NAME);
    write_artifact(&artifact_path, &[], owner_uid, owner_gid)?;
    let listener = UnixListener::bind(&policy.writer_socket)
        .map_err(|error| GuestError::io("binding Safe Outputs writer socket", error))?;
    fs::set_permissions(
        &policy.writer_socket,
        fs::Permissions::from_mode(WRITER_SOCKET_MODE),
    )
    .map_err(|error| GuestError::io("setting Safe Outputs writer socket mode", error))?;
    std::os::unix::fs::chown(&policy.writer_socket, Some(owner_uid), Some(workload_gid))
        .map_err(|error| GuestError::io("assigning Safe Outputs writer socket", error))?;

    let accumulator = IntentAccumulator::new(policy.clone(), boundary_plan_digest)
        .map_err(safe_outputs_error)?;
    let gateway = McpGateway::new(policy.clone()).map_err(safe_outputs_error)?;
    let (control, receiver) = tokio::sync::mpsc::channel(CONTROL_DEPTH);
    let actor = RecorderActor {
        listener,
        policy,
        gateway,
        accumulator,
        artifact_path,
        artifact: Vec::new(),
        seal_key,
        state: RecorderState::Open,
        sealed: None,
        active: None,
        control: receiver,
        owner_uid,
        owner_gid,
        workload_gid,
    };
    let live = Arc::new(AtomicBool::new(true));
    let actor_live = Arc::clone(&live);
    let task = tokio::spawn(async move {
        let result = actor.run().await;
        actor_live.store(false, Ordering::Release);
        result
    });
    Ok((SafeOutputsHandle { control, live }, task))
}

struct ActiveWriter {
    stream: UnixStream,
    decoder: FrameDecoder,
    buffer: [u8; 8192],
}

struct RecorderActor {
    listener: UnixListener,
    policy: SafeOutputsRuntimePolicy,
    gateway: McpGateway,
    accumulator: IntentAccumulator,
    artifact_path: PathBuf,
    artifact: Vec<u8>,
    seal_key: [u8; 32],
    state: RecorderState,
    sealed: Option<CollectedSafeOutputs>,
    active: Option<ActiveWriter>,
    control: tokio::sync::mpsc::Receiver<Control>,
    owner_uid: u32,
    owner_gid: u32,
    workload_gid: u32,
}

impl RecorderActor {
    async fn run(mut self) -> Result<(), GuestError> {
        loop {
            tokio::select! {
                biased;
                command = self.control.recv() => {
                    let Some(command) = command else {
                        return Ok(());
                    };
                    if self.handle_control(command)? {
                        return Ok(());
                    }
                }
                read = read_active(&mut self.active), if self.active.is_some() => {
                    match read {
                        Ok(0) => {
                            if let Some(active) = self.active.take() {
                                active.decoder.finish().map_err(|error| {
                                    GuestError::Runtime(format!("incomplete Safe Outputs MCP frame: {error}"))
                                })?;
                            }
                        }
                        Ok(read) => self.process_active(read).await?,
                        Err(error) => {
                            self.active = None;
                            return Err(GuestError::io("reading Safe Outputs writer socket", error));
                        }
                    }
                }
                accepted = self.listener.accept(), if self.active.is_none() && self.state == RecorderState::Open => {
                    let (stream, _) = accepted
                        .map_err(|error| GuestError::io("accepting Safe Outputs writer", error))?;
                    let credentials = stream.peer_cred()
                        .map_err(|error| GuestError::io("authenticating Safe Outputs writer", error))?;
                    if credentials.gid() != self.workload_gid {
                        eprintln!(
                            "sendbox-guest: rejected Safe Outputs writer with uid {} gid {}",
                            credentials.uid(),
                            credentials.gid()
                        );
                        continue;
                    }
                    self.active = Some(ActiveWriter {
                        stream,
                        decoder: FrameDecoder::new(FramingMode::Auto, MAX_SAFE_OUTPUTS_FRAME_BYTES),
                        buffer: [0; 8192],
                    });
                }
            }
        }
    }

    fn handle_control(&mut self, command: Control) -> Result<bool, GuestError> {
        match command {
            Control::Seal { reply } => {
                let result = self.seal().map_err(|error| error.to_string());
                let _ = reply.send(result);
                Ok(false)
            }
            Control::Collect { reply } => {
                let result = self.collect().map_err(|error| error.to_string());
                let _ = reply.send(result);
                Ok(false)
            }
            Control::Shutdown { reply } => {
                self.active = None;
                let _ = fs::remove_file(&self.policy.writer_socket);
                let _ = reply.send(());
                Ok(true)
            }
        }
    }

    async fn process_active(&mut self, read: usize) -> Result<(), GuestError> {
        let frames = {
            let active = self.active.as_mut().expect("active writer");
            active
                .decoder
                .feed(&active.buffer[..read])
                .map_err(|error| GuestError::Runtime(format!("invalid Safe Outputs MCP frame: {error}")))?
        };
        for frame in frames {
            let response = match self.accept_frame(&frame.payload) {
                Ok(response) => response,
                Err(error) => Some(
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": {
                            "code": -32000,
                            "message": error.to_string()
                        }
                    }))
                    .map_err(|encode| GuestError::Runtime(format!(
                        "encoding Safe Outputs MCP error: {encode}"
                    )))?,
                ),
            };
            if let Some(response) = response {
                let encoded = encode_frame(&response, frame.mode);
                self.active
                    .as_mut()
                    .expect("active writer")
                    .stream
                    .write_all(&encoded)
                    .await
                    .map_err(|error| GuestError::io("writing Safe Outputs MCP response", error))?;
            }
        }
        Ok(())
    }

    fn accept_frame(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SafeOutputsError> {
        if self.state != RecorderState::Open {
            return Err(SafeOutputsError::Artifact(
                "Safe Outputs recorder is sealed".to_owned(),
            ));
        }
        let gateway = &self.gateway;
        let accumulator = &mut self.accumulator;
        let artifact = &mut self.artifact;
        let artifact_path = &self.artifact_path;
        let owner_uid = self.owner_uid;
        let owner_gid = self.owner_gid;
        gateway.handle(payload, |tool, arguments| {
            accept_intent(
                accumulator,
                artifact,
                artifact_path,
                owner_uid,
                owner_gid,
                tool,
                arguments,
            )
        })
    }

    fn seal(&mut self) -> Result<(), GuestError> {
        if self.state != RecorderState::Open {
            return Err(GuestError::Runtime(
                "Safe Outputs recorder may only be sealed once".to_owned(),
            ));
        }
        self.active = None;
        let seal = SafeOutputsSealV1::create(&self.accumulator, &self.artifact, &self.seal_key)
            .map_err(safe_outputs_error)?;
        let seal = serde_json::to_vec(&seal)
            .map_err(|error| GuestError::Runtime(format!("encoding Safe Outputs seal: {error}")))?;
        self.sealed = Some(CollectedSafeOutputs {
            artifact: self.artifact.clone(),
            seal,
        });
        self.state = RecorderState::Sealed;
        Ok(())
    }

    fn collect(&mut self) -> Result<CollectedSafeOutputs, GuestError> {
        if self.state != RecorderState::Sealed {
            return Err(GuestError::Runtime(
                "Safe Outputs collection requires a sealed, uncollected artifact".to_owned(),
            ));
        }
        let collected = self
            .sealed
            .take()
            .ok_or_else(|| GuestError::Runtime("Safe Outputs seal is unavailable".to_owned()))?;
        self.state = RecorderState::Collected;
        Ok(collected)
    }
}

async fn read_active(active: &mut Option<ActiveWriter>) -> std::io::Result<usize> {
    let active = active.as_mut().expect("guarded by select condition");
    active.stream.read(&mut active.buffer).await
}

fn accept_intent(
    accumulator: &mut IntentAccumulator,
    artifact: &mut Vec<u8>,
    artifact_path: &Path,
    owner_uid: u32,
    owner_gid: u32,
    tool: SafeOutputTool,
    arguments: Value,
) -> Result<AcceptedIntentV1, SafeOutputsError> {
    let accepted_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| SafeOutputsError::Encoding(format!("read system time: {error}")))?
        .as_millis()
        .try_into()
        .map_err(|_| SafeOutputsError::Encoding("system time is out of range".to_owned()))?;
    let prepared = accumulator.prepare(tool, arguments, accepted_at_unix_ms)?;
    let mut next_accumulator = accumulator.clone();
    next_accumulator.commit(&prepared)?;
    let mut next_artifact = artifact.clone();
    next_artifact.extend_from_slice(&prepared.line);
    write_artifact(artifact_path, &next_artifact, owner_uid, owner_gid)
        .map_err(|error| SafeOutputsError::Artifact(error.to_string()))?;
    *accumulator = next_accumulator;
    *artifact = next_artifact;
    Ok(prepared.record)
}

fn prepare_parent(path: &Path, owner_uid: u32, owner_gid: u32) -> Result<(), GuestError> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(ROOT_MODE)
            .create(path)
            .map_err(|error| GuestError::io("creating Safe Outputs runtime root", error))?;
    }
    std::os::unix::fs::chown(path, Some(owner_uid), Some(owner_gid))
        .map_err(|error| GuestError::io("assigning Safe Outputs runtime root", error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(ROOT_MODE))
        .map_err(|error| GuestError::io("setting Safe Outputs runtime root mode", error))?;
    validate_directory(path, owner_uid, owner_gid, ROOT_MODE, "Safe Outputs runtime root")
}

fn prepare_session_root(path: &Path, owner_uid: u32, workload_gid: u32) -> Result<(), GuestError> {
    fs::DirBuilder::new()
        .mode(SESSION_MODE)
        .create(path)
        .map_err(|error| GuestError::io("creating Safe Outputs session root", error))?;
    std::os::unix::fs::chown(path, Some(owner_uid), Some(workload_gid))
        .map_err(|error| GuestError::io("assigning Safe Outputs session root", error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(SESSION_MODE))
        .map_err(|error| GuestError::io("setting Safe Outputs session root mode", error))?;
    validate_directory(
        path,
        owner_uid,
        workload_gid,
        SESSION_MODE,
        "Safe Outputs session root",
    )
}

fn validate_directory(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    subject: &str,
) -> Result<(), GuestError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| GuestError::io("inspecting Safe Outputs directory", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != mode
    {
        return Err(GuestError::Runtime(format!(
            "{subject} ownership or mode is invalid"
        )));
    }
    Ok(())
}

fn write_artifact(
    path: &Path,
    bytes: &[u8],
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), GuestError> {
    let temporary = path.with_extension("ndjson.tmp");
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ARTIFACT_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| GuestError::io("creating Safe Outputs artifact", error))?;
    std::os::unix::fs::chown(&temporary, Some(owner_uid), Some(owner_gid))
        .map_err(|error| GuestError::io("assigning Safe Outputs artifact", error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| GuestError::io("writing Safe Outputs artifact", error))?;
    fs::rename(&temporary, path)
        .map_err(|error| GuestError::io("publishing Safe Outputs artifact", error))?;
    File::open(
        path.parent()
            .ok_or_else(|| GuestError::Runtime("Safe Outputs artifact has no parent".to_owned()))?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|error| GuestError::io("syncing Safe Outputs artifact directory", error))
}

fn safe_outputs_error(error: SafeOutputsError) -> GuestError {
    GuestError::Runtime(format!("Safe Outputs: {error}"))
}
