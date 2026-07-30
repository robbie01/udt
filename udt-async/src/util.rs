//! Small helpers shared by the connection and endpoint code.

use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU32, Ordering};
pub(crate) use std::sync::{Mutex, MutexGuard, RwLock};
use std::time::Instant;

use udt_proto::PeerAddr;

/// Kernel UDP send buffer, in bytes.
///
/// Larger than it looks like it needs to be. With segmentation offload one
/// write is a whole coalesced run of up to 64 KiB, so at the obvious 64 KiB a
/// single write fills the buffer and every other connection sharing the socket
/// then waits on writability. Measured on Linux: at 64 KiB, adding a second
/// connection *dropped* combined throughput from 997 to 313 MB/s.
const UDP_SND_BUF: usize = 2 * 1024 * 1024;

/// Kernel UDP receive buffer, in packets.
const UDP_RCV_BUF_PKTS: usize = 8192;

/// Counter behind [`next_socket_id`], started somewhere unpredictable.
///
/// Randomising the origin rather than the whole value keeps identifiers unique
/// within a process — two connections must never share one — while making the
/// first identifier unguessable. Incrementing from a random start leaks the
/// count of connections opened, which is not worth defending.
static SOCKET_ID: LazyLock<AtomicU32> = LazyLock::new(|| AtomicU32::new(rand::random()));

/// A fresh socket identifier.
///
/// This is the only thing standing between an off-path attacker and a
/// connection. UDT has no authentication at all, so every control packet is
/// accepted on the strength of its destination identifier matching, and several
/// of them are fatal. Encrypting the payload does not help: control packets sit
/// beneath it.
///
/// It used to count up from 1, which made the first connection in a process
/// socket 1 and every later one easy to guess. Starting from a random value
/// makes it a 32-bit cookie, which is roughly what TCP gets from requiring an
/// injected `RST` to land inside the receive window.
pub(crate) fn next_socket_id() -> u32 {
    SOCKET_ID.fetch_add(1, Ordering::Relaxed)
}

/// Fixed point the protocol clock counts from.
///
/// Any origin will do, so this is just whenever the process first asked.
static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Microseconds since this process started.
///
/// Monotonic by construction, which the protocol requires: round-trip
/// estimation, the expiry timer and message TTLs all measure differences
/// between two readings, and a wall clock stepped by NTP would corrupt every
/// one of them. Costs the same as reading the wall clock — both are a vDSO
/// `clock_gettime` — so the hot path is unaffected.
pub(crate) fn now_us() -> u64 {
    EPOCH.elapsed().as_micros() as u64
}

/// Lock a connection or endpoint mutex, ignoring poisoning.
///
/// A panic while holding one of these leaves protocol state mid-update, which
/// no caller can do anything useful about. Propagating the poison would turn
/// one panicking task into a panic in every task touching the connection, so
/// take the data and let the connection fail on its own terms instead.
///
/// `parking_lot` was measured here and made no difference — these sections are
/// short and rarely contended, so spinning buys nothing.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn sockaddr_to_peer_addr(addr: SocketAddr) -> PeerAddr {
    match addr {
        SocketAddr::V4(a) => PeerAddr::from_v4(a.ip().octets(), a.port()),
        SocketAddr::V6(a) => PeerAddr::from_v6(a.ip().octets(), a.port()),
    }
}

pub(crate) fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "connection closed")
}

/// Whether a socket error is about a datagram rather than about the socket.
///
/// A UDP socket can report the fate of something it *already sent* on a later
/// call: an ICMP unreachable comes back, and the next `recv` or `send` surfaces
/// it. The socket is fine. Treating it as fatal throws away a working endpoint
/// because one peer went away.
///
/// This is not a hypothetical tidy-up. Windows raises `WSAECONNRESET` this way
/// on *unconnected* sockets, which is exactly what an endpoint's shared socket
/// is, and `quinn-udp` does not set `SIO_UDP_CONNRESET` to suppress it. With
/// four clients connecting to one listener at once, some datagram reaches a port
/// that has already gone, and the endpoint's reader — which used to return on
/// any error at all — died. Every connection on that port then failed at once:
/// `s6_multi_connection_same_listener` on `windows-latest` timed out on connect
/// and accept and saw a live connection report `BrokenPipe`.
///
/// Suppressing it at the socket would need `SIO_UDP_CONNRESET`, and there is no
/// safe API for that, so it is handled where it surfaces instead.
pub(crate) fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::Interrupted
    )
}

/// Size the kernel socket buffers before handing the socket to tokio.
///
/// This matters more than it looks. With the OS defaults — tens to a few
/// hundred KB — a burst at several hundred MB/s overruns the receive buffer
/// and the kernel silently drops datagrams. Each drop costs a full loss
/// detection and retransmission round trip, so throughput collapses long
/// before the network is the limit.
///
/// Best effort: the OS may clamp the request (macOS honours only up to
/// `kern.ipc.maxsockbuf`) and failing to grow the buffer is not fatal.
pub(crate) fn configure_udp_buffers(sock: &std::net::UdpSocket, mss: u32) {
    let s = socket2::SockRef::from(sock);
    let _ = s.set_recv_buffer_size(UDP_RCV_BUF_PKTS * mss as usize);
    let _ = s.set_send_buffer_size(UDP_SND_BUF);
}

/// Choose the local bind address for an outgoing `connect()` socket.
///
/// Reuses the endpoint's IP when it has a specific one, so outgoing traffic
/// leaves from the same interface. Otherwise takes the wildcard address for
/// the *peer's* family — binding `0.0.0.0` for an IPv6 peer would leave the
/// socket deaf to the replies.
pub(crate) fn outgoing_bind_addr(endpoint_addr: SocketAddr, peer: SocketAddr) -> SocketAddr {
    match (endpoint_addr, peer) {
        (SocketAddr::V4(la), SocketAddr::V4(_)) if !la.ip().is_unspecified() => {
            SocketAddr::V4(SocketAddrV4::new(*la.ip(), 0))
        }
        (SocketAddr::V6(la), SocketAddr::V6(_)) if !la.ip().is_unspecified() => {
            SocketAddr::V6(SocketAddrV6::new(*la.ip(), 0, 0, 0))
        }
        (_, SocketAddr::V4(_)) => {
            SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0))
        }
        (_, SocketAddr::V6(_)) => {
            SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        }
    }
}
