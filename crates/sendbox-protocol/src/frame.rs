use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use minicbor::decode;
use minicbor::encode;
use minicbor::{Decoder, Encoder};
use sendbox_core::SessionId;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::codec::{decode_message_from, encode_message_to};
use crate::crypto::{frame_mac, verify_frame_mac};
use crate::types::{MAC_BYTES, PROTOCOL_MAGIC};
use crate::{FrameLimits, Message, MessageDirection, ProtocolError};

#[derive(Debug, Clone)]
struct FrameMetadata {
    version: u16,
    session_id: SessionId,
    direction: MessageDirection,
}

struct WireFrame {
    magic: [u8; 8],
    version: u16,
    session_id: SessionId,
    direction: MessageDirection,
    sequence: u64,
    message: Message,
    proof: [u8; MAC_BYTES],
}

pub struct AuthenticatedConnection<R, W> {
    negotiated: NegotiatedSession,
    reader: FramedReader<R>,
    writer: FramedWriter<W>,
}

pub(crate) struct ConnectionParameters {
    pub negotiated: NegotiatedSession,
    pub local_direction: MessageDirection,
    pub send_key: Zeroizing<[u8; MAC_BYTES]>,
    pub receive_key: Zeroizing<[u8; MAC_BYTES]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedSession {
    pub version: u16,
    pub session_id: SessionId,
    pub capabilities: crate::CapabilitySet,
    pub limits: FrameLimits,
}

impl<R, W> AuthenticatedConnection<R, W> {
    pub(crate) fn new(reader: R, writer: W, parameters: ConnectionParameters) -> Self {
        let ConnectionParameters {
            negotiated,
            local_direction,
            send_key,
            receive_key,
        } = parameters;
        let terminal = Arc::new(AtomicBool::new(false));
        let version = negotiated.version;
        let session_id = negotiated.session_id;
        let limits = negotiated.limits;
        Self {
            negotiated,
            reader: FramedReader::new(
                reader,
                FrameMetadata {
                    version,
                    session_id,
                    direction: match local_direction {
                        MessageDirection::HostToGuest => MessageDirection::GuestToHost,
                        MessageDirection::GuestToHost => MessageDirection::HostToGuest,
                    },
                },
                limits,
                receive_key,
                Arc::clone(&terminal),
            ),
            writer: FramedWriter::new(
                writer,
                FrameMetadata {
                    version,
                    session_id,
                    direction: local_direction,
                },
                limits,
                send_key,
                terminal,
            ),
        }
    }

    #[must_use]
    pub fn into_parts(self) -> (FramedReader<R>, FramedWriter<W>) {
        (self.reader, self.writer)
    }

    #[must_use]
    pub const fn negotiated(&self) -> &NegotiatedSession {
        &self.negotiated
    }
}

pub struct FramedWriter<W> {
    writer: W,
    metadata: FrameMetadata,
    limits: FrameLimits,
    key: Zeroizing<[u8; MAC_BYTES]>,
    next_sequence: u64,
    sending: bool,
    terminal: Arc<AtomicBool>,
}

impl<W> FramedWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub async fn send(&mut self, message: &Message) -> Result<(), ProtocolError> {
        if self.sending || self.terminal.load(Ordering::Acquire) {
            return Err(ProtocolError::WriterPoisoned);
        }
        if message.is_handshake() {
            return Err(ProtocolError::HandshakeMessageAfterReady);
        }
        if self.next_sequence == u64::MAX {
            self.poison();
            return Err(ProtocolError::SequenceOverflow);
        }

        let unsigned =
            encode_unsigned_frame(PROTOCOL_MAGIC, &self.metadata, self.next_sequence, message)?;
        let proof = frame_mac(self.key.as_ref(), &unsigned)?;
        let payload = encode_signed_frame(&self.metadata, self.next_sequence, message, proof)?;
        if payload.len() > self.limits.max_frame_bytes() {
            return Err(ProtocolError::FrameTooLarge {
                declared: payload.len(),
                max: self.limits.max_frame_bytes(),
            });
        }
        let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
            declared: payload.len(),
            max: self.limits.max_frame_bytes(),
        })?;
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);

        self.sending = true;
        let mut cancellation_guard = SendCancellationGuard::new(Arc::clone(&self.terminal));
        if let Err(error) = self.writer.write_all(&frame).await {
            self.sending = false;
            self.poison();
            cancellation_guard.disarm();
            return Err(ProtocolError::Io(error));
        }
        if let Err(error) = self.writer.flush().await {
            self.sending = false;
            self.poison();
            cancellation_guard.disarm();
            return Err(ProtocolError::Io(error));
        }
        cancellation_guard.disarm();
        self.sending = false;
        self.next_sequence += 1;
        Ok(())
    }

    fn poison(&self) {
        self.terminal.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn set_next_sequence(&mut self, sequence: u64) {
        self.next_sequence = sequence;
    }
}

impl<W> FramedWriter<W> {
    fn new(
        writer: W,
        metadata: FrameMetadata,
        limits: FrameLimits,
        key: Zeroizing<[u8; MAC_BYTES]>,
        terminal: Arc<AtomicBool>,
    ) -> Self {
        Self {
            writer,
            metadata,
            limits,
            key,
            next_sequence: 0,
            sending: false,
            terminal,
        }
    }
}

pub struct FramedReader<R> {
    reader: R,
    metadata: FrameMetadata,
    limits: FrameLimits,
    key: Zeroizing<[u8; MAC_BYTES]>,
    next_sequence: u64,
    buffer: Vec<u8>,
    declared_length: Option<usize>,
    terminal: Arc<AtomicBool>,
}

impl<R> FramedReader<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn receive(&mut self) -> Result<Message, ProtocolError> {
        if self.terminal.load(Ordering::Acquire) {
            return Err(ProtocolError::ReaderPoisoned);
        }
        if self.next_sequence == u64::MAX {
            return self.fail(ProtocolError::SequenceOverflow);
        }

        loop {
            if self.declared_length.is_none() && self.buffer.len() >= 4 {
                let declared = u32::from_be_bytes(
                    self.buffer[..4]
                        .try_into()
                        .expect("four-byte prefix was length checked"),
                ) as usize;
                if declared == 0 {
                    return self.fail(ProtocolError::EmptyFrame);
                }
                if declared > self.limits.max_frame_bytes() {
                    return self.fail(ProtocolError::FrameTooLarge {
                        declared,
                        max: self.limits.max_frame_bytes(),
                    });
                }
                self.declared_length = Some(declared);
                self.buffer.reserve(declared);
            }

            if let Some(declared) = self.declared_length {
                let total = 4 + declared;
                if self.buffer.len() >= total {
                    let payload = self.buffer[4..total].to_vec();
                    let frame = match decode_signed_frame(&payload) {
                        Ok(frame) => frame,
                        Err(error) => return self.fail(error),
                    };
                    let unsigned = match encode_unsigned_frame(
                        frame.magic,
                        &FrameMetadata {
                            version: frame.version,
                            session_id: frame.session_id,
                            direction: frame.direction,
                        },
                        frame.sequence,
                        &frame.message,
                    ) {
                        Ok(unsigned) => unsigned,
                        Err(error) => return self.fail(error),
                    };
                    if let Err(error) = verify_frame_mac(self.key.as_ref(), &unsigned, &frame.proof)
                    {
                        return self.fail(error);
                    }
                    if frame.magic != PROTOCOL_MAGIC {
                        return self.fail(ProtocolError::InvalidMagic);
                    }
                    if frame.version != self.metadata.version {
                        return self.fail(ProtocolError::VersionMismatch(frame.version));
                    }
                    if frame.session_id != self.metadata.session_id {
                        return self.fail(ProtocolError::SessionMismatch {
                            expected: self.metadata.session_id,
                            actual: frame.session_id,
                        });
                    }
                    if frame.direction != self.metadata.direction {
                        return self.fail(ProtocolError::DirectionMismatch {
                            expected: self.metadata.direction,
                            actual: frame.direction,
                        });
                    }
                    if frame.sequence < self.next_sequence {
                        return self.fail(ProtocolError::Replay {
                            expected: self.next_sequence,
                            actual: frame.sequence,
                        });
                    }
                    if frame.sequence > self.next_sequence {
                        return self.fail(ProtocolError::OutOfOrder {
                            expected: self.next_sequence,
                            actual: frame.sequence,
                        });
                    }
                    self.buffer.drain(..total);
                    self.declared_length = None;
                    self.next_sequence += 1;
                    return Ok(frame.message);
                }
            }

            let target = self.declared_length.map_or(4, |declared| 4 + declared);
            let remaining = target.saturating_sub(self.buffer.len());
            let mut chunk = [0_u8; 8192];
            let read_length = remaining.min(chunk.len());
            let count = match self.reader.read(&mut chunk[..read_length]).await {
                Ok(count) => count,
                Err(error) => return self.fail(ProtocolError::Io(error)),
            };
            if count == 0 {
                if self.buffer.is_empty() {
                    return Err(ProtocolError::EndOfStream);
                }
                return self.fail(ProtocolError::IncompleteFrame {
                    expected: target,
                    received: self.buffer.len(),
                });
            }
            self.buffer.extend_from_slice(&chunk[..count]);
        }
    }

    fn fail<T>(&mut self, error: ProtocolError) -> Result<T, ProtocolError> {
        self.terminal.store(true, Ordering::Release);
        Err(error)
    }
}

impl<R> FramedReader<R> {
    fn new(
        reader: R,
        metadata: FrameMetadata,
        limits: FrameLimits,
        key: Zeroizing<[u8; MAC_BYTES]>,
        terminal: Arc<AtomicBool>,
    ) -> Self {
        Self {
            reader,
            metadata,
            limits,
            key,
            next_sequence: 0,
            buffer: Vec::with_capacity(4),
            declared_length: None,
            terminal,
        }
    }
}

struct SendCancellationGuard {
    terminal: Arc<AtomicBool>,
    armed: bool,
}

impl SendCancellationGuard {
    fn new(terminal: Arc<AtomicBool>) -> Self {
        Self {
            terminal,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SendCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.terminal.store(true, Ordering::Release);
        }
    }
}

pub(crate) async fn write_bounded_message<W>(
    writer: &mut W,
    message: &Message,
    limits: FrameLimits,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let payload = crate::encode_message(message)?;
    if payload.len() > limits.max_frame_bytes() {
        return Err(ProtocolError::FrameTooLarge {
            declared: payload.len(),
            max: limits.max_frame_bytes(),
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
        declared: payload.len(),
        max: limits.max_frame_bytes(),
    })?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_bounded_message<R>(
    reader: &mut R,
    limits: FrameLimits,
) -> Result<(Message, Vec<u8>), ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 4];
    let prefix_bytes = read_counted(reader, &mut prefix).await?;
    if prefix_bytes == 0 {
        return Err(ProtocolError::EndOfStream);
    }
    if prefix_bytes != prefix.len() {
        return Err(ProtocolError::IncompleteFrame {
            expected: prefix.len(),
            received: prefix_bytes,
        });
    }
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if declared > limits.max_frame_bytes() {
        return Err(ProtocolError::FrameTooLarge {
            declared,
            max: limits.max_frame_bytes(),
        });
    }
    let mut payload = vec![0_u8; declared];
    let payload_bytes = read_counted(reader, &mut payload).await?;
    if payload_bytes != declared {
        return Err(ProtocolError::IncompleteFrame {
            expected: declared + prefix.len(),
            received: payload_bytes + prefix.len(),
        });
    }
    let message = crate::decode_message(&payload)?;
    Ok((message, payload))
}

async fn read_counted<R>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut received = 0;
    while received < buffer.len() {
        let count = reader.read(&mut buffer[received..]).await?;
        if count == 0 {
            break;
        }
        received += count;
    }
    Ok(received)
}

fn encode_unsigned_frame(
    magic: [u8; 8],
    metadata: &FrameMetadata,
    sequence: u64,
    message: &Message,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(6).map_err(encode_error)?;
    encoder.bytes(&magic).map_err(encode_error)?;
    encoder.u16(metadata.version).map_err(encode_error)?;
    encoder
        .bytes(metadata.session_id.as_bytes())
        .map_err(encode_error)?;
    encoder.u8(metadata.direction as u8).map_err(encode_error)?;
    encoder.u64(sequence).map_err(encode_error)?;
    encode_message_to(&mut encoder, message)?;
    Ok(encoder.into_writer())
}

fn encode_signed_frame(
    metadata: &FrameMetadata,
    sequence: u64,
    message: &Message,
    proof: [u8; MAC_BYTES],
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(7).map_err(encode_error)?;
    encoder.bytes(&PROTOCOL_MAGIC).map_err(encode_error)?;
    encoder.u16(metadata.version).map_err(encode_error)?;
    encoder
        .bytes(metadata.session_id.as_bytes())
        .map_err(encode_error)?;
    encoder.u8(metadata.direction as u8).map_err(encode_error)?;
    encoder.u64(sequence).map_err(encode_error)?;
    encode_message_to(&mut encoder, message)?;
    encoder.bytes(&proof).map_err(encode_error)?;
    Ok(encoder.into_writer())
}

pub(crate) fn validate_signed_frame_encoding(bytes: &[u8]) -> Result<(), ProtocolError> {
    decode_signed_frame(bytes).map(|_| ())
}

fn decode_signed_frame(bytes: &[u8]) -> Result<WireFrame, ProtocolError> {
    let mut decoder = Decoder::new(bytes);
    let length = decoder
        .array()
        .map_err(decode_error)?
        .ok_or_else(|| ProtocolError::MalformedEncoding("indefinite frame array".to_owned()))?;
    if length != 7 {
        return Err(ProtocolError::MalformedEncoding(format!(
            "expected frame array length 7, received {length}"
        )));
    }
    let frame = WireFrame {
        magic: decode_fixed_bytes(&mut decoder)?,
        version: decoder.u16().map_err(decode_error)?,
        session_id: SessionId::from_bytes(decode_fixed_bytes(&mut decoder)?),
        direction: match decoder.u8().map_err(decode_error)? {
            1 => MessageDirection::HostToGuest,
            2 => MessageDirection::GuestToHost,
            value => {
                return Err(ProtocolError::MalformedEncoding(format!(
                    "unsupported message direction {value}"
                )));
            }
        },
        sequence: decoder.u64().map_err(decode_error)?,
        message: decode_message_from(&mut decoder)?,
        proof: decode_fixed_bytes(&mut decoder)?,
    };
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::MalformedEncoding(
            "trailing bytes after frame".to_owned(),
        ));
    }
    let canonical = encode_signed_frame(
        &FrameMetadata {
            version: frame.version,
            session_id: frame.session_id,
            direction: frame.direction,
        },
        frame.sequence,
        &frame.message,
        frame.proof,
    )?;
    if canonical != bytes {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    Ok(frame)
}

fn decode_fixed_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], ProtocolError> {
    decoder
        .bytes()
        .map_err(decode_error)?
        .try_into()
        .map_err(|_| ProtocolError::MalformedEncoding(format!("expected {N} bytes")))
}

fn encode_error(error: encode::Error<Infallible>) -> ProtocolError {
    ProtocolError::MalformedEncoding(error.to_string())
}

fn decode_error(error: decode::Error) -> ProtocolError {
    ProtocolError::MalformedEncoding(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{HARD_MAX_FRAME_BYTES, PROTOCOL_VERSION, Request};
    use serde::Deserialize;
    use tokio::time::{sleep, timeout};

    const KEY: [u8; MAC_BYTES] = [0x42; MAC_BYTES];

    fn metadata() -> FrameMetadata {
        FrameMetadata {
            version: PROTOCOL_VERSION,
            session_id: SessionId::from_bytes([1; 16]),
            direction: MessageDirection::HostToGuest,
        }
    }

    fn request(payload_size: usize) -> Message {
        Message::Request(Request {
            request_id: 7,
            operation: "exec".to_owned(),
            payload: vec![0x5a; payload_size],
        })
    }

    fn wire_frame(
        metadata: &FrameMetadata,
        sequence: u64,
        message: &Message,
        key: &[u8],
    ) -> Vec<u8> {
        let unsigned =
            encode_unsigned_frame(PROTOCOL_MAGIC, metadata, sequence, message).expect("encode");
        let proof = frame_mac(key, &unsigned).expect("mac");
        let payload =
            encode_signed_frame(metadata, sequence, message, proof).expect("signed frame");
        let mut wire = Vec::with_capacity(payload.len() + 4);
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(&payload);
        wire
    }

    fn reader_for<R>(reader: R, metadata: FrameMetadata) -> FramedReader<R> {
        FramedReader::new(
            reader,
            metadata,
            FrameLimits::default(),
            Zeroizing::new(KEY),
            Arc::new(AtomicBool::new(false)),
        )
    }

    #[tokio::test]
    async fn sequence_overflow_poisoned_writer() {
        let (_, writer) = tokio::io::duplex(64);
        let terminal = Arc::new(AtomicBool::new(false));
        let mut framed = FramedWriter::new(
            writer,
            FrameMetadata {
                version: PROTOCOL_VERSION,
                session_id: SessionId::from_bytes([1; 16]),
                direction: MessageDirection::HostToGuest,
            },
            FrameLimits::default(),
            Zeroizing::new([2; MAC_BYTES]),
            terminal,
        );
        framed.set_next_sequence(u64::MAX);
        let error = framed
            .send(&request(0))
            .await
            .expect_err("sequence overflow must fail");
        assert!(matches!(error, ProtocolError::SequenceOverflow));
    }

    #[tokio::test]
    async fn tampering_is_fatal_and_does_not_advance() {
        let (mut peer, stream) = tokio::io::duplex(4096);
        let mut wire = wire_frame(&metadata(), 0, &request(0), &KEY);
        let last = wire.last_mut().expect("frame has proof");
        *last ^= 1;
        peer.write_all(&wire).await.expect("write tampered frame");
        let mut reader = reader_for(stream, metadata());
        let error = reader.receive().await.expect_err("tampering must fail");
        assert!(matches!(error, ProtocolError::AuthenticationFailed));
        assert_eq!(reader.next_sequence, 0);
        assert!(matches!(
            reader.receive().await,
            Err(ProtocolError::ReaderPoisoned)
        ));
    }

    #[tokio::test]
    async fn replay_and_out_of_order_frames_are_rejected() {
        let first = wire_frame(&metadata(), 0, &request(0), &KEY);
        let replay = first.clone();
        let (mut peer, stream) = tokio::io::duplex(first.len() + replay.len());
        peer.write_all(&first).await.expect("write first");
        peer.write_all(&replay).await.expect("write replay");
        let mut reader = reader_for(stream, metadata());
        assert_eq!(reader.receive().await.expect("first frame"), request(0));
        let error = reader.receive().await.expect_err("replay must fail");
        assert!(matches!(
            error,
            ProtocolError::Replay {
                expected: 1,
                actual: 0
            }
        ));

        let out_of_order = wire_frame(&metadata(), 1, &request(0), &KEY);
        let (mut peer, stream) = tokio::io::duplex(out_of_order.len());
        peer.write_all(&out_of_order)
            .await
            .expect("write out of order");
        let mut reader = reader_for(stream, metadata());
        let error = reader.receive().await.expect_err("out of order must fail");
        assert!(matches!(
            error,
            ProtocolError::OutOfOrder {
                expected: 0,
                actual: 1
            }
        ));
    }

    #[tokio::test]
    async fn wrong_session_and_direction_are_rejected() {
        let mut wrong_session = metadata();
        wrong_session.session_id = SessionId::from_bytes([9; 16]);
        let wire = wire_frame(&wrong_session, 0, &request(0), &KEY);
        let (mut peer, stream) = tokio::io::duplex(wire.len());
        peer.write_all(&wire).await.expect("write wrong session");
        let mut reader = reader_for(stream, metadata());
        assert!(matches!(
            reader.receive().await,
            Err(ProtocolError::SessionMismatch { .. })
        ));

        let mut reflected = metadata();
        reflected.direction = MessageDirection::GuestToHost;
        let wire = wire_frame(&reflected, 0, &request(0), &KEY);
        let (mut peer, stream) = tokio::io::duplex(wire.len());
        peer.write_all(&wire).await.expect("write reflected frame");
        let mut reader = reader_for(stream, metadata());
        assert!(matches!(
            reader.receive().await,
            Err(ProtocolError::DirectionMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn oversized_length_is_rejected_before_payload_allocation() {
        let (mut peer, stream) = tokio::io::duplex(4);
        peer.write_all(&((HARD_MAX_FRAME_BYTES + 1) as u32).to_be_bytes())
            .await
            .expect("write prefix");
        let mut reader = reader_for(stream, metadata());
        let initial_capacity = reader.buffer.capacity();
        let error = reader.receive().await.expect_err("oversize must fail");
        assert!(matches!(error, ProtocolError::FrameTooLarge { .. }));
        assert_eq!(reader.buffer.capacity(), initial_capacity);
        assert!(reader.declared_length.is_none());
    }

    #[tokio::test]
    async fn eof_and_truncation_are_explicit() {
        let (peer, stream) = tokio::io::duplex(4);
        drop(peer);
        let mut reader = reader_for(stream, metadata());
        assert!(matches!(
            reader.receive().await,
            Err(ProtocolError::EndOfStream)
        ));

        let (mut peer, stream) = tokio::io::duplex(8);
        peer.write_all(&10_u32.to_be_bytes())
            .await
            .expect("write prefix");
        peer.write_all(&[1, 2, 3]).await.expect("write partial");
        drop(peer);
        let mut reader = reader_for(stream, metadata());
        assert!(matches!(
            reader.receive().await,
            Err(ProtocolError::IncompleteFrame {
                expected: 14,
                received: 7
            })
        ));
    }

    #[tokio::test]
    async fn read_cancellation_preserves_buffered_state() {
        let wire = wire_frame(&metadata(), 0, &request(0), &KEY);
        let (mut peer, stream) = tokio::io::duplex(wire.len());
        let split = wire.len() / 2;
        let first = wire[..split].to_vec();
        let second = wire[split..].to_vec();
        let writer = tokio::spawn(async move {
            peer.write_all(&first).await.expect("write first half");
            sleep(Duration::from_millis(40)).await;
            peer.write_all(&second).await.expect("write second half");
        });
        let mut reader = reader_for(stream, metadata());
        assert!(
            timeout(Duration::from_millis(10), reader.receive())
                .await
                .is_err()
        );
        assert_eq!(
            timeout(Duration::from_secs(1), reader.receive())
                .await
                .expect("receive timeout")
                .expect("receive after cancellation"),
            request(0)
        );
        writer.await.expect("writer task");
    }

    #[tokio::test]
    async fn write_cancellation_poisoned_connection() {
        let (_peer, stream) = tokio::io::duplex(1);
        let terminal = Arc::new(AtomicBool::new(false));
        let mut writer = FramedWriter::new(
            stream,
            metadata(),
            FrameLimits::default(),
            Zeroizing::new(KEY),
            Arc::clone(&terminal),
        );
        assert!(
            timeout(Duration::from_millis(10), writer.send(&request(4096)))
                .await
                .is_err()
        );
        assert!(terminal.load(Ordering::Acquire));
        assert!(matches!(
            writer.send(&request(0)).await,
            Err(ProtocolError::WriterPoisoned)
        ));
    }

    #[tokio::test]
    async fn bounded_writer_applies_backpressure() {
        let (mut peer, stream) = tokio::io::duplex(8);
        let terminal = Arc::new(AtomicBool::new(false));
        let mut writer = FramedWriter::new(
            stream,
            metadata(),
            FrameLimits::default(),
            Zeroizing::new(KEY),
            terminal,
        );
        let drain;
        {
            let message = request(4096);
            let send = writer.send(&message);
            tokio::pin!(send);
            assert!(timeout(Duration::from_millis(10), &mut send).await.is_err());
            drain = tokio::spawn(async move {
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await.expect("drain peer");
            });
            timeout(Duration::from_secs(1), &mut send)
                .await
                .expect("send timeout")
                .expect("send after drain");
        }
        drop(writer);
        drain.await.expect("drain task");
    }

    #[derive(Deserialize)]
    struct FrameVector {
        session_id: String,
        host_to_guest_key: String,
        frame_mac: String,
        frame_hex: String,
    }

    #[test]
    fn deterministic_authenticated_frame_vector_is_stable() {
        let vector: FrameVector = serde_json::from_str(include_str!(
            "../../../test-fixtures/protocol/v1-authenticated-session.json"
        ))
        .expect("fixture");
        let metadata = FrameMetadata {
            version: 2,
            session_id: SessionId::from_bytes(decode_hex_array(&vector.session_id)),
            direction: MessageDirection::HostToGuest,
        };
        let key = decode_hex(&vector.host_to_guest_key);
        let message = Message::Request(Request {
            request_id: 42,
            operation: "health.check".to_owned(),
            payload: vec![1, 2, 3, 4],
        });
        let unsigned =
            encode_unsigned_frame(PROTOCOL_MAGIC, &metadata, 0, &message).expect("unsigned");
        let proof = frame_mac(&key, &unsigned).expect("proof");
        let payload = encode_signed_frame(&metadata, 0, &message, proof).expect("signed payload");
        let mut wire = Vec::with_capacity(payload.len() + 4);
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(&payload);
        let actual_mac = hex(&proof);
        let actual_frame = hex(&wire);
        if actual_mac != vector.frame_mac || actual_frame != vector.frame_hex {
            panic!("frame_mac={actual_mac}\nframe_hex={actual_frame}");
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hex utf8");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }

    fn decode_hex_array<const N: usize>(value: &str) -> [u8; N] {
        decode_hex(value).try_into().expect("fixed-size hex")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
