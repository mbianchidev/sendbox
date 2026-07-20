//! `SO_MARK` socket helpers for the Linux enforcement layer.
//!
//! nftables permits the broker's external egress only when the socket carries
//! both the broker cgroup identity *and* a fixed `SO_MARK`. These helpers set
//! that mark through the safe [`socket2`] API before the socket is connected or
//! bound; the crate never touches a raw file descriptor unsafely.
//!
//! Setting `SO_MARK` requires `CAP_NET_ADMIN` in the socket's network
//! namespace. [`probe_can_set_mark`] surfaces the absence of that capability as
//! a preflight failure rather than letting an unmarked socket be silently
//! dropped by nftables at runtime.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::dialer::Dialer;

fn domain_for(addr: &SocketAddr) -> Domain {
    match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    }
}

/// Probes whether this process can set `SO_MARK` (i.e. holds `CAP_NET_ADMIN`
/// in the current network namespace). Returns the underlying error so a
/// preflight can report a precise reason.
pub fn probe_can_set_mark() -> io::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_mark(1)
}

/// Connects a TCP stream to `addr` with `SO_MARK` set to `mark`. The mark must
/// be set before `connect`, so the connection is created through `socket2`
/// and handed to Tokio. Inability to set the mark is surfaced, never ignored.
pub async fn connect_tcp_with_mark(addr: SocketAddr, mark: u32) -> io::Result<TcpStream> {
    let socket = Socket::new(domain_for(&addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_mark(mark)?;
    socket.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = socket.into();
    let tcp_socket = TcpSocket::from_std_stream(std_stream);
    tcp_socket.connect(addr).await
}

/// Binds a UDP socket at `bind` with `SO_MARK` set to `mark`.
pub async fn bind_udp_with_mark(bind: SocketAddr, mark: u32) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain_for(&bind), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_mark(mark)?;
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// A [`Dialer`] that sets a fixed `SO_MARK` on every external socket, so the
/// CONNECT broker's upstream dials satisfy the `socket cgroupv2 + meta mark`
/// nftables rule.
#[derive(Debug, Clone, Copy)]
pub struct MarkDialer {
    mark: u32,
}

impl MarkDialer {
    #[must_use]
    pub fn new(mark: u32) -> Self {
        Self { mark }
    }
}

#[async_trait]
impl Dialer for MarkDialer {
    async fn dial(&self, addr: SocketAddr, connect_timeout: Duration) -> io::Result<TcpStream> {
        crate::dialer::connect_tcp(addr, connect_timeout, Some(self.mark)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn mark_dialer_connects_when_mark_is_settable() {
        // Only meaningful where SO_MARK can be set (root/CAP_NET_ADMIN).
        // Otherwise this proves the failure is surfaced, not swallowed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let dialer = MarkDialer::new(0x5b0e);
        let result = dialer.dial(addr, Duration::from_secs(2)).await;
        match probe_can_set_mark() {
            Ok(()) => assert!(result.is_ok(), "mark settable but dial failed: {result:?}"),
            Err(_) => assert!(
                result.is_err(),
                "mark not settable yet dial unexpectedly succeeded"
            ),
        }
    }
}
