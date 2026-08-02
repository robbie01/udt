//! Small helpers shared by the connection and endpoint code.

use std::io;
use std::net::SocketAddr;
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

/// Bind an endpoint's socket so that [`per_destination_socket`] can later join
/// the same port.
///
/// Two sockets may share a port only if *both* asked to, so the flags have to be
/// set here even though it is the other function that needs them.
///
/// The plain bind first is not redundant. With the flags set, binding a port
/// something else already holds **succeeds**, so `Endpoint::bind` would stop
/// reporting the conflict it reports today — and on macOS the newcomer takes
/// the traffic rather than sharing it, which would turn a loud error into a
/// silent hijack. Asking without them first keeps that error, and costs one
/// socket created and dropped at startup.
///
/// Only when a port was actually named: with port 0 there is no conflict to
/// detect, and re-binding the port the probe was given would be a race for no
/// benefit.
pub(crate) fn bind_endpoint_socket(addr: SocketAddr, mss: u32) -> io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr = if addr.port() == 0 {
        addr
    } else {
        // Reports `AddrInUse` exactly as before if anything holds it.
        let probe = std::net::UdpSocket::bind(addr)?;
        let named = probe.local_addr()?;
        drop(probe);
        named
    };
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let shareable = (|| {
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        sock.bind(&addr.into())?;
        io::Result::Ok(std::net::UdpSocket::from(sock))
    })();
    // A platform that refuses the flags is not a failure to bind: fall back to
    // an ordinary socket and lose only the per-destination readers.
    let sock = match shareable {
        Ok(sock) => sock,
        Err(_) => std::net::UdpSocket::bind(addr)?,
    };
    sock.set_nonblocking(true)?;
    configure_udp_buffers(&sock, mss);
    Ok(sock)
}

/// A second socket on `local` — the address an endpoint is already bound to —
/// connected to `peer`, so the kernel delivers that peer's datagrams here
/// instead of to the endpoint's own socket.
///
/// This is what lets one port be read by more than one task. A connected UDP
/// socket names a full four-tuple, which is more specific than the endpoint's
/// wildcard binding, and the kernel matches the most specific socket. Measured
/// on macOS: the connected socket received its peer's datagrams and only those,
/// while another peer's went to the wildcard. That is a different mechanism from
/// `SO_REUSEPORT` load balancing, which macOS does not do at all — see the note
/// in `CLAUDE.md` — and it is why the receive funnel can be widened here when it
/// could not be widened that way.
///
/// `None` on any failure, and the caller must treat that as ordinary: nothing
/// here is required for correctness. The connection stays routed through the
/// endpoint's reader either way, so a platform that ignores the more specific
/// binding, or refuses `SO_REUSEPORT`, simply keeps the behaviour it had.
pub(crate) fn per_destination_socket(
    local: SocketAddr,
    peer: SocketAddr,
    mss: u32,
) -> Option<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    // Same family as the address actually bound, not as the peer: they agree
    // for any peer this could reach, and the bind is what has to succeed.
    let domain = match local {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    // Both, because the two platforms disagree about which one permits a second
    // bind to a live port.
    sock.set_reuse_address(true).ok()?;
    #[cfg(unix)]
    sock.set_reuse_port(true).ok()?;
    sock.bind(&local.into()).ok()?;
    // The connect is the whole point: it is what makes this binding more
    // specific than the endpoint's, and so what the kernel matches first.
    sock.connect(&peer.into()).ok()?;
    sock.set_nonblocking(true).ok()?;
    let sock: std::net::UdpSocket = sock.into();
    configure_udp_buffers(&sock, mss);
    Some(sock)
}
