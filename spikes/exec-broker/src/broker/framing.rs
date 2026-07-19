//! Async length-delimited framing over any `AsyncRead`/`AsyncWrite`
//! (in practice, a Unix socket connection): a 4-byte big-endian length
//! prefix followed by exactly that many bytes of JSON, matching
//! [`crate::protocol::MAX_FRAME_BYTES`] in both directions.
//!
//! This is deliberately a thin, manual implementation using
//! [`tokio::io::AsyncReadExt`]/[`tokio::io::AsyncWriteExt`] directly (rather
//! than `tokio_util::codec::Framed` + `futures::{Sink, Stream}`) so the
//! crate does not need to add a `futures` dependency just for `.send()`/
//! `.next()` sugar; [`crate::protocol::framed_codec`] remains available as
//! the pure codec configuration for anything that does want to build a
//! `Framed` transport directly.

#![forbid(unsafe_code)]

use crate::error::{BrokerError, ProtocolError};
use crate::protocol::{LENGTH_PREFIX_BYTES, MAX_FRAME_BYTES, decode_message, encode_message};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Reads one length-delimited JSON message from `stream`. Returns `Ok(None)`
/// on a clean EOF at a message boundary (the peer closed the connection
/// without sending a partial frame), which callers treat as a disconnect
/// rather than an error.
pub async fn read_message<T, R>(stream: &mut R) -> Result<Option<T>, BrokerError>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0u8; LENGTH_PREFIX_BYTES];
    let mut prefix_read = 0usize;
    while prefix_read < LENGTH_PREFIX_BYTES {
        match stream.read(&mut length_bytes[prefix_read..]).await {
            Ok(0) if prefix_read == 0 => return Ok(None),
            Ok(0) => {
                return Err(BrokerError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "truncated frame length prefix: received {prefix_read} of \
                         {LENGTH_PREFIX_BYTES} bytes"
                    ),
                )));
            }
            Ok(read) => prefix_read += read,
            Err(err) => return Err(BrokerError::Io(err)),
        }
    }
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(BrokerError::Protocol(ProtocolError::FrameTooLarge(length)));
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(BrokerError::Io)?;
    let value = decode_message(&payload)?;
    Ok(Some(value))
}

/// Encodes `value` and writes it to `stream` as one length-delimited frame.
pub async fn write_message<T, W>(stream: &mut W, value: &T) -> Result<(), BrokerError>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let payload = encode_message(value)?;
    let length = (payload.len() as u32).to_be_bytes();
    stream.write_all(&length).await.map_err(BrokerError::Io)?;
    stream.write_all(&payload).await.map_err(BrokerError::Io)?;
    stream.flush().await.map_err(BrokerError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ClientMessage;
    use std::collections::BTreeMap;
    use tokio::io::duplex;

    #[tokio::test]
    async fn round_trips_a_message_over_an_in_memory_duplex_stream() {
        let (mut a, mut b) = duplex(4096);
        let msg = ClientMessage::Execute {
            correlation_id: "corr-1".into(),
            session_id: "session-1".into(),
            token: "aa".into(),
            argv: vec!["/bin/echo".into()],
            cwd: "/tmp".into(),
            env: BTreeMap::new(),
            timeout_ms: 1000,
        };
        write_message(&mut a, &msg).await.expect("write");
        let decoded: ClientMessage = read_message(&mut b).await.expect("read").expect("not eof");
        assert_eq!(decoded, msg);
    }

    #[tokio::test]
    async fn clean_close_at_boundary_reads_as_none() {
        let (a, mut b) = duplex(4096);
        drop(a);
        let decoded: Option<ClientMessage> = read_message(&mut b).await.expect("read");
        assert!(decoded.is_none());
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_rejected_before_reading_payload() {
        let (mut a, mut b) = duplex(4096);
        let huge_length = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
        a.write_all(&huge_length).await.expect("write length");
        let err = read_message::<ClientMessage, _>(&mut b)
            .await
            .expect_err("must reject");
        assert!(matches!(
            err,
            BrokerError::Protocol(ProtocolError::FrameTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn truncated_length_prefix_is_an_error_not_a_clean_close() {
        let (mut a, mut b) = duplex(4096);
        a.write_all(&[0, 0]).await.expect("write partial prefix");
        drop(a);

        let err = read_message::<ClientMessage, _>(&mut b)
            .await
            .expect_err("partial prefix must be malformed");
        assert!(matches!(
            err,
            BrokerError::Io(ref source)
                if source.kind() == std::io::ErrorKind::UnexpectedEof
        ));
    }
}
