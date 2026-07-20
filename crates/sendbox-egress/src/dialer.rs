//! Upstream dial abstraction and `SO_MARK`-aware socket helpers.
//!
//! The CONNECT broker dials the exact validated destination through a
//! [`Dialer`]. The portable [`DirectDialer`] performs a plain connect; the
//! Linux enforcement layer injects [`crate::linux::mark::MarkDialer`], which
//! sets a fixed `SO_MARK` on the socket before connecting so the broker's
//! external sockets carry both a cgroup identity *and* the mark that nftables
//! requires.
//!
//! The [`connect_tcp`] / [`bind_udp`] helpers are the single place where a
//! mark is applied. On non-Linux hosts a requested mark is an error (fail
//! closed) rather than a silently unmarked socket, because the only reason to
//! request one is to satisfy a Linux nftables rule that cannot exist here.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// Dials a TCP destination, bounded by `connect_timeout`.
#[async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(&self, addr: SocketAddr, connect_timeout: Duration) -> io::Result<TcpStream>;
}

/// Plain connect, used wherever the `SO_MARK` identity is not required
/// (portable tests, non-Linux hosts, brokers outside a Linux topology).
#[derive(Debug, Default, Clone, Copy)]
pub struct DirectDialer;

#[async_trait]
impl Dialer for DirectDialer {
    async fn dial(&self, addr: SocketAddr, connect_timeout: Duration) -> io::Result<TcpStream> {
        connect_tcp(addr, connect_timeout, None).await
    }
}

/// Connects a TCP stream to `addr`, optionally setting `SO_MARK` first, bounded
/// by `connect_timeout`.
pub(crate) async fn connect_tcp(
    addr: SocketAddr,
    connect_timeout: Duration,
    mark: Option<u32>,
) -> io::Result<TcpStream> {
    let connect = async {
        match mark {
            None => TcpStream::connect(addr).await,
            Some(mark) => connect_tcp_marked(addr, mark).await,
        }
    };
    match timeout(connect_timeout, connect).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "upstream connect timed out",
        )),
    }
}

/// Binds a UDP socket at `bind`, optionally setting `SO_MARK` first.
pub(crate) async fn bind_udp(bind: SocketAddr, mark: Option<u32>) -> io::Result<UdpSocket> {
    match mark {
        None => UdpSocket::bind(bind).await,
        Some(mark) => bind_udp_marked(bind, mark).await,
    }
}

#[cfg(target_os = "linux")]
async fn connect_tcp_marked(addr: SocketAddr, mark: u32) -> io::Result<TcpStream> {
    crate::linux::mark::connect_tcp_with_mark(addr, mark).await
}

#[cfg(not(target_os = "linux"))]
async fn connect_tcp_marked(_addr: SocketAddr, _mark: u32) -> io::Result<TcpStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_MARK is only supported on Linux",
    ))
}

#[cfg(target_os = "linux")]
async fn bind_udp_marked(bind: SocketAddr, mark: u32) -> io::Result<UdpSocket> {
    crate::linux::mark::bind_udp_with_mark(bind, mark).await
}

#[cfg(not(target_os = "linux"))]
async fn bind_udp_marked(_bind: SocketAddr, _mark: u32) -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_MARK is only supported on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_dialer_connects_to_a_live_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let dialer = DirectDialer;
        let stream = dialer.dial(addr, Duration::from_secs(2)).await;
        assert!(stream.is_ok());
    }

    #[tokio::test]
    async fn direct_dialer_times_out_on_an_unreachable_destination() {
        // TEST-NET-1 (192.0.2.0/24, RFC 5737) is guaranteed unroutable.
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let dialer = DirectDialer;
        let result = dialer.dial(addr, Duration::from_millis(150)).await;
        assert!(result.is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn requesting_a_mark_off_linux_fails_closed() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = connect_tcp(addr, Duration::from_millis(200), Some(7)).await;
        assert!(matches!(
            result.map_err(|e| e.kind()),
            Err(io::ErrorKind::Unsupported)
        ));
    }
}
