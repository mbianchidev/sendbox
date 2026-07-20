//! Bounded SOCKS5 (RFC 1928) front end for the CONNECT broker.
//!
//! This parses the SOCKS5 no-authentication handshake and a single request,
//! then hands the target/port to the *same* policy, pinning, and dial path the
//! native CONNECT protocol uses. Only `CONNECT` is honored; `BIND` and
//! `UDP ASSOCIATE` are explicitly refused with `Command not supported`, which
//! is how UDP/QUIC is rejected at the SOCKS layer. Every read is bounded and
//! the caller wraps the handshake in a timeout, so a slow/oversized peer cannot
//! stall or exhaust the broker.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::connect_proto::ConnectTarget;

pub const SOCKS_VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xff;

/// The SOCKS5 command in a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Command {
    Connect,
    Bind,
    UdpAssociate,
}

/// SOCKS5 reply codes (RFC 1928 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Socks5Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// A decoded SOCKS5 request. `target` reuses [`ConnectTarget`] so the broker's
/// shared authorize/dial path handles both front ends identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    pub command: Socks5Command,
    pub target: ConnectTarget,
    pub port: u16,
}

#[derive(Debug, Error)]
pub enum Socks5Error {
    #[error("unsupported SOCKS version {0}")]
    UnsupportedVersion(u8),
    #[error("no acceptable authentication methods")]
    NoAcceptableMethods,
    #[error("unsupported SOCKS address type {0}")]
    UnsupportedAddressType(u8),
    #[error("malformed SOCKS message: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Performs the SOCKS5 method-negotiation handshake, accepting only the
/// no-authentication method. On no acceptable method it writes the SOCKS
/// rejection (`0x05 0xff`) before returning the error.
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<(), Socks5Error> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err(Socks5Error::UnsupportedVersion(header[0]));
    }
    let nmethods = header[1] as usize;
    if nmethods == 0 {
        return Err(Socks5Error::Malformed("no methods offered"));
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        let _ = stream
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await;
        return Err(Socks5Error::NoAcceptableMethods);
    }
    stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
    Ok(())
}

/// Reads exactly one SOCKS5 request. Every field is bounded (the domain length
/// is a single length byte). Literal IP targets are canonicalized immediately
/// (see [`crate::address::canonicalize`]) so an IPv4-mapped IPv6 literal cannot
/// slip past policy.
pub async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Socks5Request, Socks5Error> {
    let mut header = [0u8; 4]; // VER, CMD, RSV, ATYP
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err(Socks5Error::UnsupportedVersion(header[0]));
    }
    let command = match header[1] {
        0x01 => Socks5Command::Connect,
        0x02 => Socks5Command::Bind,
        0x03 => Socks5Command::UdpAssociate,
        _ => return Err(Socks5Error::Malformed("unknown command")),
    };
    // header[2] is RSV; RFC requires 0x00 but real clients occasionally send
    // other values, so it is not enforced.
    let target = match header[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            ConnectTarget::Ip(crate::address::canonicalize(IpAddr::V4(Ipv4Addr::from(
                octets,
            ))))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            ConnectTarget::Ip(crate::address::canonicalize(IpAddr::V6(Ipv6Addr::from(
                octets,
            ))))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let n = len[0] as usize;
            if n == 0 {
                return Err(Socks5Error::Malformed("empty domain"));
            }
            let mut buf = vec![0u8; n];
            stream.read_exact(&mut buf).await?;
            let host =
                String::from_utf8(buf).map_err(|_| Socks5Error::Malformed("domain not utf8"))?;
            ConnectTarget::Hostname(host)
        }
        other => return Err(Socks5Error::UnsupportedAddressType(other)),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Socks5Request {
        command,
        target,
        port: u16::from_be_bytes(port),
    })
}

/// Writes a SOCKS5 reply with the given bound address.
pub async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    reply: Socks5Reply,
    bound: SocketAddr,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(22);
    buf.push(SOCKS_VERSION);
    buf.push(reply as u8);
    buf.push(0x00); // RSV
    match bound {
        SocketAddr::V4(addr) => {
            buf.push(0x01);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            buf.push(0x04);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    stream.write_all(&buf).await
}

/// A failure reply with an all-zero IPv4 bound address (RFC allows an unset
/// address for failures).
pub async fn write_failure<S: AsyncWrite + Unpin>(
    stream: &mut S,
    reply: Socks5Reply,
) -> io::Result<()> {
    write_reply(
        stream,
        reply,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn concat(parts: &[&[u8]]) -> Vec<u8> {
        parts.iter().flat_map(|p| p.iter().copied()).collect()
    }

    #[tokio::test]
    async fn negotiate_accepts_no_auth() {
        let input = concat(&[&[SOCKS_VERSION, 1, METHOD_NO_AUTH]]);
        let mut buf = Vec::new();
        let mut stream = tokio::io::join(Cursor::new(input), &mut buf);
        negotiate(&mut stream).await.unwrap();
        assert_eq!(buf, vec![SOCKS_VERSION, METHOD_NO_AUTH]);
    }

    #[tokio::test]
    async fn negotiate_rejects_when_no_no_auth_method() {
        let input = concat(&[&[SOCKS_VERSION, 1, 0x02]]); // only user/pass
        let mut out = Vec::new();
        let mut stream = tokio::io::join(Cursor::new(input), &mut out);
        let result = negotiate(&mut stream).await;
        assert!(matches!(result, Err(Socks5Error::NoAcceptableMethods)));
        assert_eq!(out, vec![SOCKS_VERSION, METHOD_NONE_ACCEPTABLE]);
    }

    #[tokio::test]
    async fn negotiate_rejects_wrong_version() {
        let input = vec![0x04, 1, METHOD_NO_AUTH];
        let mut cursor = Cursor::new(input);
        let mut out = Vec::new();
        let mut stream = tokio::io::join(&mut cursor, &mut out);
        assert!(matches!(
            negotiate(&mut stream).await,
            Err(Socks5Error::UnsupportedVersion(0x04))
        ));
    }

    #[tokio::test]
    async fn reads_connect_domain_request() {
        let host = b"example.com";
        let input = concat(&[
            &[SOCKS_VERSION, 0x01, 0x00, 0x03],
            &[host.len() as u8],
            host,
            &[0x01, 0xbb], // port 443
        ]);
        let mut cursor = Cursor::new(input);
        let request = read_request(&mut cursor).await.unwrap();
        assert_eq!(request.command, Socks5Command::Connect);
        assert_eq!(
            request.target,
            ConnectTarget::Hostname("example.com".into())
        );
        assert_eq!(request.port, 443);
    }

    #[tokio::test]
    async fn reads_udp_associate_command() {
        let input = concat(&[&[SOCKS_VERSION, 0x03, 0x00, 0x01], &[10, 0, 0, 1], &[0, 53]]);
        let mut cursor = Cursor::new(input);
        let request = read_request(&mut cursor).await.unwrap();
        assert_eq!(request.command, Socks5Command::UdpAssociate);
    }

    #[tokio::test]
    async fn canonicalizes_ipv4_mapped_ipv6_target() {
        let v4 = Ipv4Addr::new(203, 0, 113, 9);
        let mapped = v4.to_ipv6_mapped().octets();
        let input = concat(&[&[SOCKS_VERSION, 0x01, 0x00, 0x04], &mapped, &[0x01, 0xbb]]);
        let mut cursor = Cursor::new(input);
        let request = read_request(&mut cursor).await.unwrap();
        assert_eq!(request.target, ConnectTarget::Ip(IpAddr::V4(v4)));
    }

    #[tokio::test]
    async fn rejects_unsupported_address_type() {
        let input = vec![SOCKS_VERSION, 0x01, 0x00, 0x07];
        let mut cursor = Cursor::new(input);
        assert!(matches!(
            read_request(&mut cursor).await,
            Err(Socks5Error::UnsupportedAddressType(0x07))
        ));
    }

    #[tokio::test]
    async fn rejects_empty_domain() {
        let input = vec![SOCKS_VERSION, 0x01, 0x00, 0x03, 0x00];
        let mut cursor = Cursor::new(input);
        assert!(matches!(
            read_request(&mut cursor).await,
            Err(Socks5Error::Malformed(_))
        ));
    }
}
