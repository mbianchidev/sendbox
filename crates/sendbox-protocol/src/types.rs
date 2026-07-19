use std::collections::BTreeSet;

use sendbox_core::SessionId;

pub const PROTOCOL_MAGIC: [u8; 8] = *b"SENDBOX\0";
pub const PROTOCOL_VERSION: u16 = 1;
pub const NONCE_BYTES: usize = 32;
pub const MAC_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    pub minimum: u16,
    pub maximum: u16,
}

impl VersionRange {
    #[must_use]
    pub const fn new(minimum: u16, maximum: u16) -> Self {
        Self { minimum, maximum }
    }

    #[must_use]
    pub fn negotiate(self, other: Self) -> Option<u16> {
        let minimum = self.minimum.max(other.minimum);
        let maximum = self.maximum.min(other.maximum);
        (minimum <= maximum).then_some(maximum)
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.minimum > 0 && self.minimum <= self.maximum
    }
}

impl Default for VersionRange {
    fn default() -> Self {
        Self::new(PROTOCOL_VERSION, PROTOCOL_VERSION)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerRole {
    HostClient = 1,
    GuestServer = 2,
}

impl PeerRole {
    #[must_use]
    pub const fn direction(self) -> MessageDirection {
        match self {
            Self::HostClient => MessageDirection::HostToGuest,
            Self::GuestServer => MessageDirection::GuestToHost,
        }
    }

    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::HostClient => Self::GuestServer,
            Self::GuestServer => Self::HostClient,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageDirection {
    HostToGuest = 1,
    GuestToHost = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum Capability {
    Lifecycle = 1,
    Exec = 2,
    StreamedIo = 3,
    Signals = 4,
    Mounts = 5,
    Network = 6,
    Mcp = 7,
    Audit = 8,
    Health = 9,
}

impl Capability {
    pub(crate) const COUNT: u64 = 9;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl CapabilitySet {
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self(capabilities.into_iter().collect())
    }

    #[must_use]
    pub fn contains(&self, capability: Capability) -> bool {
        self.0.contains(&capability)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }

    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self(self.0.intersection(&other.0).copied().collect())
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Capability> + '_ {
        self.0.iter().copied()
    }
}

impl<const N: usize> From<[Capability; N]> for CapabilitySet {
    fn from(value: [Capability; N]) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageKind {
    Hello = 1,
    CapabilityNegotiation = 2,
    Readiness = 3,
    Request = 4,
    Response = 5,
    Event = 6,
    Cancellation = 7,
    GracefulClose = 8,
    ProtocolError = 9,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub magic: [u8; 8],
    pub versions: VersionRange,
    pub session_id: SessionId,
    pub role: PeerRole,
    pub nonce: [u8; NONCE_BYTES],
    pub capabilities: CapabilitySet,
    pub required_capabilities: CapabilitySet,
    pub max_frame_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiation {
    pub magic: [u8; 8],
    pub versions: VersionRange,
    pub selected_version: u16,
    pub session_id: SessionId,
    pub role: PeerRole,
    pub client_nonce: [u8; NONCE_BYTES],
    pub server_nonce: [u8; NONCE_BYTES],
    pub capabilities: CapabilitySet,
    pub required_capabilities: CapabilitySet,
    pub negotiated_capabilities: CapabilitySet,
    pub max_frame_bytes: u32,
    pub proof: [u8; MAC_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    pub role: PeerRole,
    pub session_id: SessionId,
    pub selected_version: u16,
    pub negotiated_capabilities: CapabilitySet,
    pub max_frame_bytes: u32,
    pub proof: [u8; MAC_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub request_id: u64,
    pub operation: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    Ok = 1,
    Rejected = 2,
    Failed = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub request_id: u64,
    pub status: ResponseStatus,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    StandardOutput = 1,
    StandardError = 2,
    Audit = 3,
    Health = 4,
    Lifecycle = 5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub stream_id: u64,
    pub kind: EventKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancellation {
    pub request_id: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseCode {
    Normal = 1,
    Shutdown = 2,
    ProtocolFailure = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GracefulClose {
    pub code: CloseCode,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProtocolErrorCode {
    MalformedFrame = 1,
    Authentication = 2,
    UnsupportedVersion = 3,
    UnsupportedCapability = 4,
    InvalidState = 5,
    Internal = 6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolErrorMessage {
    pub code: ProtocolErrorCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    CapabilityNegotiation(Negotiation),
    Readiness(Readiness),
    Request(Request),
    Response(Response),
    Event(Event),
    Cancellation(Cancellation),
    GracefulClose(GracefulClose),
    ProtocolError(ProtocolErrorMessage),
}

impl Message {
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::Hello(_) => MessageKind::Hello,
            Self::CapabilityNegotiation(_) => MessageKind::CapabilityNegotiation,
            Self::Readiness(_) => MessageKind::Readiness,
            Self::Request(_) => MessageKind::Request,
            Self::Response(_) => MessageKind::Response,
            Self::Event(_) => MessageKind::Event,
            Self::Cancellation(_) => MessageKind::Cancellation,
            Self::GracefulClose(_) => MessageKind::GracefulClose,
            Self::ProtocolError(_) => MessageKind::ProtocolError,
        }
    }

    #[must_use]
    pub const fn is_handshake(&self) -> bool {
        matches!(
            self,
            Self::Hello(_) | Self::CapabilityNegotiation(_) | Self::Readiness(_)
        )
    }
}
