//! A small, explicitly versioned, bounded CONNECT-style framing protocol
//! used between the sandboxed agent process and the egress broker, in place
//! of SOCKS5.
//!
//! Wire format (all multi-byte integers are big-endian):
//!
//! Request:
//! ```text
//! u8  version            (must equal PROTOCOL_VERSION)
//! u8  protocol           (1 = TCP, 2 = UDP; UDP is always denied)
//! u16 port
//! u8  target_kind        (1 = hostname, 2 = literal IP)
//! ..target..
//!   hostname: u8 length (1..=253), then that many ASCII bytes
//!   ip:       u8 ip_version (4 or 6), then 4 or 16 address bytes
//! u8  has_expected_ip    (0 or 1)
//! ..expected_ip.. (only present if has_expected_ip == 1, same encoding as an
//!                  ip target)
//! ```
//!
//! The optional `expected_ip` is supplied by the client purely as a
//! consistency check against the broker's own resolution; it is never
//! treated as proof of where a hostname resolves and a mismatch is always
//! rejected rather than silently corrected.
//!
//! Response:
//! ```text
//! u8 version
//! u8 status
//! ```
//! On `Ok`, the byte stream immediately becomes a raw bidirectional copy of
//! the upstream connection; there is no further framing.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_HOSTNAME_LEN: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectProtocol {
    Tcp = 1,
    Udp = 2,
}

impl ConnectProtocol {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTarget {
    Hostname(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub protocol: ConnectProtocol,
    pub port: u16,
    pub target: ConnectTarget,
    /// Client-supplied consistency check only; never trusted as resolution
    /// proof.
    pub expected_ip: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectStatus {
    Ok = 0,
    PolicyDenied = 1,
    ResolutionFailed = 2,
    ConnectFailed = 3,
    LimitExceeded = 4,
    Malformed = 5,
    UnsupportedProtocol = 6,
    ExpectedIpMismatch = 7,
    Timeout = 8,
}

#[derive(Debug, Error)]
pub enum ConnectProtoError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("malformed frame: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn encode_request(request: &ConnectRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.push(PROTOCOL_VERSION);
    buf.push(request.protocol as u8);
    buf.extend_from_slice(&request.port.to_be_bytes());
    match &request.target {
        ConnectTarget::Hostname(host) => {
            buf.push(1);
            let bytes = host.as_bytes();
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
        ConnectTarget::Ip(ip) => {
            buf.push(2);
            encode_ip(&mut buf, *ip);
        }
    }
    match request.expected_ip {
        Some(ip) => {
            buf.push(1);
            encode_ip(&mut buf, ip);
        }
        None => buf.push(0),
    }
    buf
}

fn encode_ip(buf: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.octets());
        }
    }
}

/// Reads a wire-encoded IP address and canonicalizes it immediately (see
/// [`crate::address::canonicalize`]), so an IPv4-mapped IPv6 literal
/// supplied by a client is collapsed to its plain IPv4 form before it is
/// ever compared against policy, used as an authorization-cache key, or
/// dialed. This is the wire boundary for every client-supplied IP in the
/// CONNECT protocol (a direct-IP target and the optional `expected_ip`
/// consistency check).
async fn read_ip<R: AsyncRead + Unpin>(reader: &mut R) -> Result<IpAddr, ConnectProtoError> {
    let mut version_byte = [0u8; 1];
    reader.read_exact(&mut version_byte).await?;
    let ip = match version_byte[0] {
        4 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        6 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(ConnectProtoError::Malformed("invalid ip version byte")),
    };
    Ok(crate::address::canonicalize(ip))
}

/// Decodes exactly one request frame. Every read is bounded: the hostname
/// length byte is capped at [`MAX_HOSTNAME_LEN`], and the caller is expected
/// to wrap this call in an overall timeout to defend against a peer that
/// trickles bytes one at a time (slowloris).
pub async fn decode_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ConnectRequest, ConnectProtoError> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let version = header[0];
    if version != PROTOCOL_VERSION {
        return Err(ConnectProtoError::UnsupportedVersion(version));
    }
    let protocol = ConnectProtocol::from_u8(header[1])
        .ok_or(ConnectProtoError::Malformed("unknown protocol"))?;
    let port = u16::from_be_bytes([header[2], header[3]]);

    let mut target_kind = [0u8; 1];
    reader.read_exact(&mut target_kind).await?;
    let target = match target_kind[0] {
        1 => {
            let mut len_byte = [0u8; 1];
            reader.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            if len == 0 || len > MAX_HOSTNAME_LEN {
                return Err(ConnectProtoError::Malformed(
                    "hostname length out of bounds",
                ));
            }
            let mut host_bytes = vec![0u8; len];
            reader.read_exact(&mut host_bytes).await?;
            let host = String::from_utf8(host_bytes)
                .map_err(|_| ConnectProtoError::Malformed("hostname not utf8"))?;
            ConnectTarget::Hostname(host)
        }
        2 => ConnectTarget::Ip(read_ip(reader).await?),
        _ => return Err(ConnectProtoError::Malformed("unknown target kind")),
    };

    let mut has_expected = [0u8; 1];
    reader.read_exact(&mut has_expected).await?;
    let expected_ip = match has_expected[0] {
        0 => None,
        1 => Some(read_ip(reader).await?),
        _ => return Err(ConnectProtoError::Malformed("invalid has_expected_ip flag")),
    };

    Ok(ConnectRequest {
        protocol,
        port,
        target,
        expected_ip,
    })
}

pub async fn write_status<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: ConnectStatus,
) -> io::Result<()> {
    let frame = [PROTOCOL_VERSION, status as u8];
    writer.write_all(&frame).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn round_trips_hostname_request() {
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Hostname("example.com".to_owned()),
            expected_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        };
        let bytes = encode_request(&request);
        let mut cursor = Cursor::new(bytes);
        let decoded = decode_request(&mut cursor).await.unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn round_trips_ip_request_v6() {
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 22,
            target: ConnectTarget::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            expected_ip: None,
        };
        let bytes = encode_request(&request);
        let mut cursor = Cursor::new(bytes);
        let decoded = decode_request(&mut cursor).await.unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn decoding_an_ipv4_mapped_ipv6_target_canonicalizes_to_ipv4() {
        let v4 = Ipv4Addr::new(203, 0, 113, 9);
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Ip(IpAddr::V6(v4.to_ipv6_mapped())),
            expected_ip: None,
        };
        let bytes = encode_request(&request);
        let mut cursor = Cursor::new(bytes);
        let decoded = decode_request(&mut cursor).await.unwrap();
        assert_eq!(decoded.target, ConnectTarget::Ip(IpAddr::V4(v4)));
    }

    #[tokio::test]
    async fn decoding_an_ipv4_mapped_ipv6_expected_ip_canonicalizes_to_ipv4() {
        let v4 = Ipv4Addr::new(198, 51, 100, 2);
        let request = ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 443,
            target: ConnectTarget::Hostname("example.com".to_owned()),
            expected_ip: Some(IpAddr::V6(v4.to_ipv6_mapped())),
        };
        let bytes = encode_request(&request);
        let mut cursor = Cursor::new(bytes);
        let decoded = decode_request(&mut cursor).await.unwrap();
        assert_eq!(decoded.expected_ip, Some(IpAddr::V4(v4)));
    }

    #[tokio::test]
    async fn rejects_bad_version() {
        let mut bytes = encode_request(&ConnectRequest {
            protocol: ConnectProtocol::Tcp,
            port: 1,
            target: ConnectTarget::Hostname("a".to_owned()),
            expected_ip: None,
        });
        bytes[0] = 9;
        let mut cursor = Cursor::new(bytes);
        assert!(matches!(
            decode_request(&mut cursor).await,
            Err(ConnectProtoError::UnsupportedVersion(9))
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_hostname_length_byte() {
        let mut bytes = vec![PROTOCOL_VERSION, ConnectProtocol::Tcp as u8, 0, 80, 1, 255];
        bytes.extend_from_slice(&[b'a'; 255]);
        let mut cursor = Cursor::new(bytes);
        assert!(matches!(
            decode_request(&mut cursor).await,
            Err(ConnectProtoError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn truncated_frame_is_io_error_not_panic() {
        let bytes = vec![PROTOCOL_VERSION, ConnectProtocol::Tcp as u8, 0];
        let mut cursor = Cursor::new(bytes);
        assert!(decode_request(&mut cursor).await.is_err());
    }
}
