use std::io;

use sendbox_core::SessionId;
use thiserror::Error;

use crate::{MessageDirection, PeerRole};

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame limit {requested} is invalid; expected 1..={hard_max}")]
    InvalidFrameLimit { requested: usize, hard_max: usize },
    #[error("bootstrap secret must contain at least 32 bytes")]
    BootstrapSecretTooShort,
    #[error("operating-system randomness failed: {0}")]
    Randomness(String),
    #[error("declared frame size {declared} exceeds configured limit {max}")]
    FrameTooLarge { declared: usize, max: usize },
    #[error("zero-length frames are invalid")]
    EmptyFrame,
    #[error("stream ended before the next frame")]
    EndOfStream,
    #[error("stream ended with an incomplete frame: received {received} of {expected} bytes")]
    IncompleteFrame { expected: usize, received: usize },
    #[error("malformed canonical CBOR: {0}")]
    MalformedEncoding(String),
    #[error("encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("unsupported message kind {0}")]
    UnsupportedMessageKind(u8),
    #[error("invalid protocol magic")]
    InvalidMagic,
    #[error("unsupported protocol version range {minimum}..={maximum}")]
    UnsupportedVersion { minimum: u16, maximum: u16 },
    #[error("protocol version {0} does not match the negotiated version")]
    VersionMismatch(u16),
    #[error("session {actual} does not match expected session {expected}")]
    SessionMismatch {
        expected: SessionId,
        actual: SessionId,
    },
    #[error("peer role {actual:?} does not match expected role {expected:?}")]
    RoleMismatch {
        expected: PeerRole,
        actual: PeerRole,
    },
    #[error("message direction {actual:?} does not match expected direction {expected:?}")]
    DirectionMismatch {
        expected: MessageDirection,
        actual: MessageDirection,
    },
    #[error("required capabilities are not available")]
    MissingRequiredCapabilities,
    #[error("capability negotiation did not produce any shared capabilities")]
    EmptyCapabilityIntersection,
    #[error("negotiated frame limit is invalid")]
    InvalidNegotiatedFrameLimit,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("replayed frame sequence {actual}; expected {expected}")]
    Replay { expected: u64, actual: u64 },
    #[error("out-of-order frame sequence {actual}; expected {expected}")]
    OutOfOrder { expected: u64, actual: u64 },
    #[error("frame sequence is exhausted")]
    SequenceOverflow,
    #[error("handshake cannot run from state {0}")]
    RepeatedHandshake(&'static str),
    #[error("expected {expected} during handshake, received {actual}")]
    UnexpectedHandshakeMessage { expected: &'static str, actual: u8 },
    #[error("handshake messages cannot be sent after readiness")]
    HandshakeMessageAfterReady,
    #[error("authenticated reader is terminally poisoned")]
    ReaderPoisoned,
    #[error("authenticated writer is terminally poisoned")]
    WriterPoisoned,
    #[error("I/O failed: {0}")]
    Io(#[from] io::Error),
}
