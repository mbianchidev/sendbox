#![forbid(unsafe_code)]

mod codec;
mod crypto;
mod error;
mod frame;
mod handshake;
mod limits;
mod types;

pub use codec::{decode_message, encode_message};
pub use error::ProtocolError;
pub use frame::{AuthenticatedConnection, FramedReader, FramedWriter, NegotiatedSession};
pub use handshake::{BootstrapSecret, GuestHandshake, HandshakeConfig, HostHandshake};
pub use limits::{DEFAULT_MAX_FRAME_BYTES, FrameLimits, HARD_MAX_FRAME_BYTES};
pub use types::{
    Cancellation, Capability, CapabilitySet, CloseCode, Event, EventKind, GracefulClose, Hello,
    Message, MessageDirection, MessageKind, Negotiation, PROTOCOL_MAGIC, PROTOCOL_VERSION,
    PeerRole, ProtocolErrorCode, ProtocolErrorMessage, Readiness, Request, Response,
    ResponseStatus, VersionRange,
};

#[doc(hidden)]
pub mod fuzzing {
    use crate::{ProtocolError, frame};

    pub fn decode_authenticated_frame(bytes: &[u8]) -> Result<(), ProtocolError> {
        frame::validate_signed_frame_encoding(bytes)
    }

    pub fn decode_handshake_message(bytes: &[u8]) -> Result<(), ProtocolError> {
        crate::decode_message(bytes).map(|_| ())
    }
}
