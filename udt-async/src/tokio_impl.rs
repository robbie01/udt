use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::{mpsc, oneshot};

use crate::batch;
use udt_proto::{
    CcKind, Connection, Event, Listener as ProtoListener, ListenerEvent, PeerAddr, SendOutcome,
    SeqNo,
};

static SOCKET_ID: AtomicU32 = AtomicU32::new(1);

fn next_socket_id() -> u32 {
    SOCKET_ID.fetch_add(1, Ordering::Relaxed)
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

fn deadline_instant(conn: &Connection) -> tokio::time::Instant {
    let tok_now = tokio::time::Instant::now();
    match conn.next_deadline_us() {
        None => tok_now + Duration::from_secs(30),
        Some(d) => {
            let n = now_us();
            if d <= n { tok_now } else { tok_now + Duration::from_micros(d - n) }
        }
    }
}

fn sockaddr_to_peer_addr(addr: SocketAddr) -> PeerAddr {
    match addr {
        SocketAddr::V4(a) => PeerAddr::from_v4(a.ip().octets(), a.port()),
        SocketAddr::V6(a) => PeerAddr::from_v6(a.ip().octets(), a.port()),
    }
}

// ── Public constants ──────────────────────────────────────────────────────────

/// The path MTU assumed by default: 1500 bytes, standard Ethernet.
pub const DEFAULT_MTU: u32 = 1500;

/// Largest message that fits in a single packet at the default MTU: 1436 bytes.
///
/// Longer messages are split across packets and reassembled by the peer, so
/// this is a throughput consideration rather than a limit.
pub const MAX_PAYLOAD_SIZE: usize = max_payload_for_mtu(DEFAULT_MTU);

/// Largest message that fits in a single packet at the given path MTU.
///
/// Deducts worst-case IPv6 and UDP headers plus UDT's own 16-byte header, so
/// the answer holds for both address families.
pub const fn max_payload_for_mtu(mtu: u32) -> usize {
    const FIXED_OVERHEAD: u32 = 48 + udt_proto::UDT_HEADER_SIZE as u32;
    if mtu <= FIXED_OVERHEAD {
        0
    } else {
        (mtu - FIXED_OVERHEAD) as usize
    }
}

/// Maximum datagrams consumed per wakeup before returning to the event loop.
///
/// Draining in batches amortises the `select!` timer arm/disarm across many
/// packets instead of paying it per packet.  The cap keeps one busy connection
/// from starving the send path or the timer.
const RECV_BATCH: usize = 64;

/// Datagrams drained from a socket per wakeup before returning to the event
/// loop, across however many batch calls that takes.
const RECV_DRAIN_CAP: usize = 64;

/// Kernel UDP send buffer, in bytes.
///
/// C++ uses 64 KiB, but it emits one datagram per call. With segmentation
/// offload a single write is a whole coalesced run — up to
/// `MAX_COALESCE_BYTES` — so a 64 KiB buffer can be filled by one call, and
/// several connections sharing an endpoint socket then spend their time
/// waiting on writability instead of sending. Measured on Linux: at 64 KiB,
/// adding a second connection *dropped* combined throughput from 997 to
/// 313 MB/s.
const UDP_SND_BUF: usize = 2 * 1024 * 1024;

/// Kernel UDP receive buffer, in packets.  Matches C++, which sizes the socket
/// buffer as `m_iRcvBufSize (8192 packets) × MSS`.
const UDP_RCV_BUF_PKTS: usize = 8192;

/// Size the kernel socket buffers before handing the socket to tokio.
///
/// This matters far more than it looks: with the OS defaults (tens to a few
/// hundred KB) a burst at several hundred MB/s overruns the receive buffer and
/// the kernel silently drops datagrams.  Each drop then costs a full loss
/// detection and retransmission round trip, so throughput collapses long before
/// the network is the limit.
///
/// Best effort — the OS may clamp the request (macOS honours only up to
/// `kern.ipc.maxsockbuf`), and failing to grow the buffer is not fatal.
fn configure_udp_buffers(sock: &std::net::UdpSocket, mss: u32) {
    let s = socket2::SockRef::from(sock);
    let _ = s.set_recv_buffer_size(UDP_RCV_BUF_PKTS * mss as usize);
    let _ = s.set_send_buffer_size(UDP_SND_BUF);
}

// ── Send request (application → driver) ──────────────────────────────────────

enum SendReq {
    /// Normal data send.
    Data { payload: Bytes, ttl_ms: Option<u32>, in_order: bool },
    /// Flush barrier: resolved when all data queued *before* this marker
    /// has been acknowledged by the peer.
    Flush { notify: oneshot::Sender<()> },
}

/// A message the send buffer had no room for, held by the driver until space
/// frees up.  While one of these is outstanding the driver stops reading
/// `send_rx`, so backpressure reaches the application through the bounded
/// channel rather than data being dropped on the floor.
struct BlockedSend {
    payload: Bytes,
    ttl_ms: Option<u32>,
    in_order: bool,
}

// ── Endpoint mux commands ─────────────────────────────────────────────────────

/// Commands sent to the endpoint's single-reader mux task.
///
/// Only one task (`run_endpoint_mux`) ever calls `recv_from` on the shared
/// endpoint socket.  Both `listen()` and `connect_rendezvous()` register with
/// the mux rather than spinning up independent recv loops.
enum MuxCmd {
    /// Forward datagrams arriving from `peer` to `tx`.
    RegisterRoute { peer: SocketAddr, tx: mpsc::Sender<Bytes> },
    /// Start (or replace) the listener state machine on this endpoint.
    StartListener {
        accept_tx: flume::Sender<Socket>,
        secret: u64,
        socket_id: u32,
    },
}

// ── Socket ────────────────────────────────────────────────────────────────────

/// An established UDT connection.
///
/// UDT is message-oriented: each [`send`](Self::send) is delivered as exactly
/// one [`recv`](Self::recv) of the same length, never split or merged. In that
/// respect it behaves like a connected [`UdpSocket`], but delivery is reliable
/// and ordered by default.
///
/// All methods take `&self`, so a socket can be shared between tasks with
/// `Arc` — one task sending while another receives is fine. Concurrent
/// receivers each get whole messages, but which task gets which message is
/// unspecified.
///
/// The connection closes when the socket is dropped.
pub struct Socket {
    send_tx: mpsc::Sender<SendReq>,
    recv_rx: flume::Receiver<Bytes>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl Socket {
    /// Sends a message, preserving order relative to earlier sends.
    ///
    /// Waits if the connection's send buffer is full.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the connection has closed.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub async fn send(&self, buf: &[u8]) -> io::Result<()> {
        self.send_with(buf, SendOptions::new()).await
    }

    /// Sends a message with a time-to-live, or permission to arrive out of
    /// order. See [`SendOptions`].
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the connection has closed.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub async fn send_with(&self, buf: &[u8], opts: SendOptions) -> io::Result<()> {
        send_via_channel(&self.send_tx, buf, opts).await
    }

    /// Sends a message if the send buffer has room, without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::WouldBlock`] if the buffer is full, or
    /// [`ErrorKind::BrokenPipe`] if the connection has closed.
    ///
    /// [`ErrorKind::WouldBlock`]: std::io::ErrorKind::WouldBlock
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub fn try_send(&self, buf: &[u8]) -> io::Result<()> {
        self.try_send_with(buf, SendOptions::new())
    }

    /// [`try_send`](Self::try_send) with the options of
    /// [`send_with`](Self::send_with).
    ///
    /// # Errors
    ///
    /// As [`try_send`](Self::try_send).
    pub fn try_send_with(&self, buf: &[u8], opts: SendOptions) -> io::Result<()> {
        self.send_tx.try_send(opts.into_req(buf)).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "send buffer full")
            }
            mpsc::error::TrySendError::Closed(_) => closed(),
        })
    }

    /// Receives the next message into `buf`, returning its length.
    ///
    /// A message longer than `buf` is truncated and the excess discarded, as
    /// with a datagram socket. Size a buffer for the largest message the peer
    /// will send.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the connection has closed and no
    /// messages remain.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let msg = self.recv_rx.recv_async().await.map_err(|_| closed())?;
        Ok(copy_into(&msg, buf))
    }

    /// Receives the next message as an owned buffer, avoiding a copy.
    ///
    /// Prefer this to [`recv`](Self::recv) when the message does not need to
    /// land in a buffer you already own.
    ///
    /// # Errors
    ///
    /// As [`recv`](Self::recv).
    pub async fn recv_bytes(&self) -> io::Result<Bytes> {
        self.recv_rx.recv_async().await.map_err(|_| closed())
    }

    /// Receives a message if one is already available, without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::WouldBlock`] if no message is ready, or
    /// [`ErrorKind::BrokenPipe`] if the connection has closed.
    ///
    /// [`ErrorKind::WouldBlock`]: std::io::ErrorKind::WouldBlock
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.recv_rx.try_recv() {
            Ok(msg) => Ok(copy_into(&msg, buf)),
            Err(flume::TryRecvError::Empty) => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no message ready"))
            }
            Err(flume::TryRecvError::Disconnected) => Err(closed()),
        }
    }

    /// Waits until every message sent so far has been acknowledged by the peer.
    ///
    /// Messages sent after this call begins are not waited for.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the connection closes first.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub async fn flush(&self) -> io::Result<()> {
        flush_via_channel(&self.send_tx).await
    }

    /// The peer's address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// The local address this connection sends from.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

// ── Send options ──────────────────────────────────────────────────────────────

/// Per-message delivery options for [`Socket::send_with`].
///
/// The default is reliable, ordered delivery, the same as [`Socket::send`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SendOptions {
    ttl: Option<Duration>,
    unordered: bool,
}

impl SendOptions {
    /// Reliable, ordered delivery.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gives up on the message if it has not been delivered within `ttl`.
    ///
    /// The peer is told to skip it, and the connection continues with the next
    /// message. Without a TTL a message is retried until it arrives or the
    /// connection fails.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Lets the peer deliver this message as soon as it is complete, without
    /// waiting for earlier messages that are still in flight.
    ///
    /// Useful when messages are independent and latency matters more than
    /// order. The receiving application must be able to handle them arriving
    /// out of sequence.
    pub fn unordered(mut self) -> Self {
        self.unordered = true;
        self
    }

    fn into_req(self, buf: &[u8]) -> SendReq {
        SendReq::Data {
            payload: Bytes::copy_from_slice(buf),
            ttl_ms: self.ttl.map(|d| d.as_millis() as u32),
            in_order: !self.unordered,
        }
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "connection closed")
}

fn copy_into(msg: &[u8], buf: &mut [u8]) -> usize {
    let n = msg.len().min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    n
}

// ── Shared helpers for send/recv channel ops ──────────────────────────────────

async fn send_via_channel(
    tx: &mpsc::Sender<SendReq>,
    buf: &[u8],
    opts: SendOptions,
) -> io::Result<()> {
    tx.send(opts.into_req(buf)).await.map_err(|_| closed())
}

async fn flush_via_channel(tx: &mpsc::Sender<SendReq>) -> io::Result<()> {
    let (notify, rx) = oneshot::channel::<()>();
    tx.send(SendReq::Flush { notify }).await.map_err(|_| closed())?;
    rx.await.map_err(|_| closed())
}

// ── Listener ──────────────────────────────────────────────────────────────────

/// Accepts incoming UDT connections on a bound address.
///
/// Created by [`Endpoint::listen`]. Like [`Socket`], it takes `&self`
/// throughout, so several tasks can accept from one listener through an `Arc`.
/// Dropping it stops accepting; connections already returned by
/// [`accept`](Self::accept) stay open.
pub struct Listener {
    accept_rx: flume::Receiver<Socket>,
    local_addr: SocketAddr,
}

impl Listener {
    /// Waits for the next incoming connection.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the endpoint has shut down.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub async fn accept(&self) -> io::Result<Socket> {
        self.accept_rx.recv_async().await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "endpoint closed")
        })
    }

    /// The address this listener accepts on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

// ── Endpoint ──────────────────────────────────────────────────────────────────

/// Settings shared by every connection an [`Endpoint`] creates.
///
/// ```no_run
/// use udt_async::{CcKind, Endpoint, EndpointConfig};
/// # async fn f() -> std::io::Result<()> {
/// let cfg = EndpointConfig::new().mtu(9000).congestion(CcKind::LedbatPlusPlus);
/// let endpoint = Endpoint::bind_with("0.0.0.0:0", cfg).await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    mss: u32,
    congestion: CcKind,
}

impl EndpointConfig {
    /// Default settings: a 1500-byte path MTU and UDT congestion control.
    pub fn new() -> Self {
        EndpointConfig { mss: DEFAULT_MTU, congestion: CcKind::default() }
    }

    /// Sets the path MTU, in bytes.
    ///
    /// This is the size of the largest IP packet the network path can carry
    /// without fragmenting. 1500 is right for ordinary Ethernet and the
    /// internet at large; raise it to 9000 on a jumbo-frame network. Both
    /// peers negotiate down to the smaller of the two values during the
    /// handshake.
    ///
    /// [`max_payload_for_mtu`] gives the resulting largest single-packet
    /// message; larger messages are split across packets automatically.
    ///
    /// Values below 64 bytes are raised to 64.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mss = mtu.max(64);
        self
    }

    /// Selects the congestion control algorithm. See [`CcKind`].
    pub fn congestion(mut self, cc: CcKind) -> Self {
        self.congestion = cc;
        self
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// A bound local address that connections are made from and accepted on.
///
/// One endpoint can hold any number of connections. Use
/// [`connect`](Self::connect) to reach a peer that is listening,
/// [`listen`](Self::listen) to accept incoming connections, or
/// [`connect_rendezvous`](Self::connect_rendezvous) when both sides dial each
/// other at once to traverse a firewall.
///
/// ```no_run
/// use udt_async::Endpoint;
/// # async fn f() -> std::io::Result<()> {
/// let endpoint = Endpoint::bind("0.0.0.0:0").await?;
/// let socket = endpoint.connect("203.0.113.7:9000").await?;
/// socket.send(b"hello").await?;
/// # Ok(()) }
/// ```
///
/// # Sharing an endpoint
///
/// Outgoing [`connect`](Self::connect) calls each get their own kernel socket,
/// so they scale independently. Accepted and rendezvous connections instead
/// share the endpoint's bound port, since that is the address the peer is
/// sending to. On Linux the kernel hands those over in batches and sharing
/// costs nothing measurable; on platforms without batched receive (macOS,
/// Windows) several saturated connections on one endpoint will contend, so
/// give a handful of bulk rendezvous transfers an endpoint each.
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    mux_tx: mpsc::UnboundedSender<MuxCmd>,
    local_addr: SocketAddr,
    cfg: EndpointConfig,
}

impl Endpoint {
    /// Binds an endpoint to a local address, with default settings.
    ///
    /// Port 0 asks the operating system for an unused port; read the result
    /// back with [`local_addr`](Self::local_addr).
    ///
    /// # Errors
    ///
    /// Returns any error from resolving `addr` or binding the underlying UDP
    /// socket, such as [`ErrorKind::AddrInUse`].
    ///
    /// [`ErrorKind::AddrInUse`]: std::io::ErrorKind::AddrInUse
    pub async fn bind(addr: impl ToSocketAddrs) -> io::Result<Self> {
        Self::bind_with(addr, EndpointConfig::new()).await
    }

    /// Binds an endpoint with explicit settings. See [`EndpointConfig`].
    ///
    /// # Errors
    ///
    /// As [`bind`](Self::bind).
    pub async fn bind_with(addr: impl ToSocketAddrs, cfg: EndpointConfig) -> io::Result<Self> {
        let addr = resolve(addr).await?;
        let mss = cfg.mss;
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        configure_udp_buffers(&std_sock, mss);
        let socket = Arc::new(UdpSocket::from_std(std_sock)?);
        let local_addr = socket.local_addr()?;
        let (mux_tx, mux_rx) = mpsc::unbounded_channel::<MuxCmd>();
        tokio::spawn(run_endpoint_mux(Arc::clone(&socket), mux_rx, cfg.clone()));
        Ok(Endpoint { socket, mux_tx, local_addr, cfg })
    }

    /// Connects to a peer that is listening.
    ///
    /// Resolves once the handshake completes.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::TimedOut`] if the peer does not answer.
    ///
    /// [`ErrorKind::TimedOut`]: std::io::ErrorKind::TimedOut
    pub async fn connect(&self, peer: impl ToSocketAddrs) -> io::Result<Socket> {
        let peer = resolve(peer).await?;
        let std_sock = std::net::UdpSocket::bind(outgoing_bind_addr(self.local_addr, peer))?;
        std_sock.set_nonblocking(true)?;
        configure_udp_buffers(&std_sock, self.cfg.mss);
        let udp = Arc::new(UdpSocket::from_std(std_sock)?);
        let local_addr = udp.local_addr()?;

        let (send_tx, send_rx) = mpsc::channel::<SendReq>(256);
        let (recv_tx, recv_rx) = flume::bounded::<Bytes>(256);
        let (connected_tx, connected_rx) = oneshot::channel::<()>();

        let socket_id = next_socket_id();
        let isn = SeqNo::new(rand::random::<u32>() & 0x7FFF_FFFF);
        let conn =
            Connection::new_active(socket_id, isn, self.cfg.mss, now_us(), self.cfg.congestion);

        tokio::spawn(run_conn_driver(udp, conn, peer, None, send_rx, recv_tx, Some(connected_tx)));

        connected_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect handshake timed out"))?;

        Ok(Socket { send_tx, recv_rx, peer_addr: peer, local_addr })
    }

    /// Connects to a peer that is calling this at the same time.
    ///
    /// Both sides must know each other's address in advance and dial
    /// simultaneously. Because the first packets cross in flight, each side
    /// punches a hole in its own firewall or NAT for the other, which lets two
    /// peers connect with no listener in between.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::TimedOut`] if the peer never appears.
    ///
    /// [`ErrorKind::TimedOut`]: std::io::ErrorKind::TimedOut
    pub async fn connect_rendezvous(&self, peer: impl ToSocketAddrs) -> io::Result<Socket> {
        let peer = resolve(peer).await?;
        let (datagram_tx, datagram_rx) = mpsc::channel::<Bytes>(256);
        let (send_tx, send_rx) = mpsc::channel::<SendReq>(256);
        let (recv_tx, recv_rx) = flume::bounded::<Bytes>(256);
        let (connected_tx, connected_rx) = oneshot::channel::<()>();

        // Register the route *before* spawning so no incoming packet is missed.
        self.mux_tx
            .send(MuxCmd::RegisterRoute { peer, tx: datagram_tx })
            .map_err(|_| io::Error::other("endpoint closed"))?;

        let socket_id = next_socket_id();
        let isn = SeqNo::new(rand::random::<u32>() & 0x7FFF_FFFF);
        let conn =
            Connection::new_rendezvous(socket_id, isn, self.cfg.mss, now_us(), self.cfg.congestion);

        tokio::spawn(run_conn_driver(
            Arc::clone(&self.socket),
            conn,
            peer,
            Some(datagram_rx),
            send_rx,
            recv_tx,
            Some(connected_tx),
        ));

        connected_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "rendezvous timed out"))?;

        Ok(Socket { send_tx, recv_rx, peer_addr: peer, local_addr: self.local_addr })
    }

    /// Accepts incoming connections on this endpoint's address.
    ///
    /// `backlog` bounds how many completed connections wait to be picked up by
    /// [`Listener::accept`] before further handshakes are refused.
    ///
    /// An endpoint can listen and make outgoing connections at the same time.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint has shut down.
    pub fn listen(&self, backlog: usize) -> io::Result<Listener> {
        let (accept_tx, accept_rx) = flume::bounded::<Socket>(backlog.max(1));
        let secret: u64 = rand::random();
        let socket_id = next_socket_id();
        self.mux_tx
            .send(MuxCmd::StartListener { accept_tx, secret, socket_id })
            .map_err(|_| io::Error::other("endpoint closed"))?;
        Ok(Listener { accept_rx, local_addr: self.local_addr })
    }

    /// The address this endpoint is bound to, with any OS-assigned port
    /// filled in.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

async fn resolve(addr: impl ToSocketAddrs) -> io::Result<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to"))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Choose the local bind address for an outgoing active `connect()` socket.
///
/// Rules:
/// 1. If the endpoint is bound to a specific (non-wildcard) IP, reuse that IP
///    so all outgoing traffic leaves from the same interface.
/// 2. Use the wildcard address for the **peer's address family**.  Binding
///    `0.0.0.0` on a connection to an IPv6 peer would make `recv_from` deaf
///    to IPv6 packets.
fn outgoing_bind_addr(endpoint_addr: SocketAddr, peer: SocketAddr) -> SocketAddr {
    match (endpoint_addr, peer) {
        (SocketAddr::V4(la), SocketAddr::V4(_)) => {
            if !la.ip().is_unspecified() {
                SocketAddr::V4(SocketAddrV4::new(*la.ip(), 0))
            } else {
                SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0))
            }
        }
        (SocketAddr::V6(la), SocketAddr::V6(_)) => {
            if !la.ip().is_unspecified() {
                SocketAddr::V6(SocketAddrV6::new(*la.ip(), 0, 0, 0))
            } else {
                SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))
            }
        }
        // Address-family mismatch — use the any-address for the peer's family.
        (_, SocketAddr::V4(_)) => {
            SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0))
        }
        (_, SocketAddr::V6(_)) => {
            SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        }
    }
}

// ── Endpoint mux ─────────────────────────────────────────────────────────────
//
// Single task that is the *sole* caller of recv_from on the endpoint's shared
// socket.  It routes packets to the appropriate connection driver by source
// address.  Both the listener state machine and rendezvous connection drivers
// register here rather than each spinning up their own recv loops.
//
// Lifetime rules:
// • The mux keeps running after the Endpoint struct is dropped (cmd_rx closes)
//   so that connections accepted before the drop can finish exchanging data.
// • The mux exits only when:
//     - the socket recv loop encounters an I/O error, OR
//     - cmd_rx is closed AND all routes are gone AND there is no active listener.
// • A "stale" listener (Listener struct dropped → accept_tx closed) is detected
//   each iteration via Sender::is_closed() and cleared.

async fn run_endpoint_mux(
    socket: Arc<UdpSocket>,
    mut cmd_rx: mpsc::UnboundedReceiver<MuxCmd>,
    cfg: EndpointConfig,
) {
    let local_addr = match socket.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };
    // source address → datagram forwarder for established/rendezvous connections
    let mut routes: HashMap<SocketAddr, mpsc::Sender<Bytes>> = HashMap::new();
    // optional listener state machine
    let mut listener: Option<(ProtoListener, flume::Sender<Socket>)> = None;
    let mut listener_out: Vec<ListenerEvent> = Vec::new();
    let mut cmd_rx_closed = false;
    let mux_io = match batch::BatchIo::new(&socket) {
        Ok(io) => io,
        Err(_) => return,
    };
    let (mut rx_storage, mut rx_metas) = batch::recv_buffers(&mux_io);

    loop {
        // Prune stale listener (Listener struct was dropped by the caller).
        if let Some((_, accept_tx)) = &listener
            && accept_tx.is_disconnected()
        {
            listener = None;
        }
        // Prune stale routes (connection drivers that have already exited).
        routes.retain(|_, tx| !tx.is_closed());

        // Nothing left to serve and the Endpoint is gone → clean exit.
        if cmd_rx_closed && routes.is_empty() && listener.is_none() {
            return;
        }

        tokio::select! {
            // Only poll cmd_rx while the Endpoint (and thus mux_tx) is alive.
            maybe_cmd = cmd_rx.recv(), if !cmd_rx_closed => {
                match maybe_cmd {
                    Some(MuxCmd::RegisterRoute { peer, tx }) => {
                        routes.insert(peer, tx);
                    }
                    Some(MuxCmd::StartListener { accept_tx, secret, socket_id }) => {
                        listener = Some((
                            ProtoListener::new(socket_id, cfg.mss, now_us(), secret, cfg.congestion),
                            accept_tx,
                        ));
                    }
                    None => {
                        // Endpoint dropped.  Keep running to serve live connections.
                        cmd_rx_closed = true;
                    }
                }
            }
            result = mux_io.recv_batch(&socket, &mut rx_storage, &mut rx_metas) => {
                let Ok(count) = result else { return };

                // Split every buffer before routing. Enabling batched IO on a
                // connection also enables generic receive offload on this
                // shared socket, so a buffer may hold a whole run of datagrams
                // described by `stride` — reading it as one would hand the
                // decoder a blob and silently lose every packet after the
                // first.
                let mut unrouted: Option<(SocketAddr, Bytes)> = None;
                'outer: for i in 0..count {
                    let from = rx_metas[i].addr;
                    for dg in batch::split_run(&rx_storage[i], &rx_metas[i]) {
                        match routes.get(&from) {
                            Some(conn_tx) => {
                                match conn_tx.try_send(dg) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(bytes)) => {
                                        // Driver is behind: block so backpressure
                                        // is real rather than dropping silently.
                                        if conn_tx.send(bytes).await.is_err() {
                                            routes.remove(&from);
                                        }
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        routes.remove(&from);
                                    }
                                }
                            }
                            None => {
                                // Hand the first unknown source to the listener
                                // below; anything after it waits for the peer to
                                // retransmit, which is what a fresh connection
                                // does anyway.
                                unrouted = Some((from, dg));
                                break 'outer;
                            }
                        }
                    }
                }

                let Some((from, bytes)) = unrouted else { continue };

                // Unknown source → give to the listener state machine.
                if listener.is_some() {
                    // Phase 1: run the state machine (short-lived mutable borrow).
                    let peer_addr = sockaddr_to_peer_addr(from);
                    listener.as_mut().unwrap().0
                        .on_datagram(peer_addr, bytes, now_us(), &mut listener_out);

                    if !listener_out.is_empty() {
                        // Clone the sender so we can release the borrow before any
                        // await points (the borrow checker cannot prove the cloned
                        // handle is alive across an .await otherwise).
                        let accept_tx = listener.as_ref().unwrap().1.clone();
                        let mut listener_died = false;

                        for item in listener_out.drain(..) {
                            match item {
                                ListenerEvent::SendTo { data, .. } => {
                                    let _ = socket.send_to(&data, from).await;
                                }
                                ListenerEvent::Accept(conn, _pa) => {
                                    let (datagram_tx, datagram_rx) = mpsc::channel::<Bytes>(256);
                                    let (send_tx, send_rx) = mpsc::channel::<SendReq>(256);
                                    let (recv_tx, recv_rx) = flume::bounded::<Bytes>(256);
                                    routes.insert(from, datagram_tx);
                                    tokio::spawn(run_conn_driver(
                                        Arc::clone(&socket),
                                        *conn,
                                        from,
                                        Some(datagram_rx),
                                        send_rx,
                                        recv_tx,
                                        None,
                                    ));
                                    let sock = Socket {
                                        send_tx,
                                        recv_rx,
                                        peer_addr: from,
                                        local_addr,
                                    };
                                    if accept_tx.send_async(sock).await.is_err() {
                                        listener_died = true;
                                        break;
                                    }
                                }
                            }
                        }
                        listener_out.clear(); // discard any unprocessed items if we broke early
                        if listener_died {
                            listener = None;
                        }
                    }
                }
                // Unrouted packet with no listener → drop silently.
            }
        }
    }
}

// ── Connection driver (active + accepted connections) ─────────────────────────
//
// For accepted / rendezvous connections: datagram_rx = Some(channel from mux).
// For active connections: datagram_rx = None; reads directly from its own socket
//   (safe because each active connection has a dedicated ephemeral socket).

async fn run_conn_driver(
    socket: Arc<UdpSocket>,
    mut conn: Connection,
    peer_addr: SocketAddr,
    mut datagram_rx: Option<mpsc::Receiver<Bytes>>,
    mut send_rx: mpsc::Receiver<SendReq>,
    recv_tx: flume::Sender<Bytes>,
    mut connected_tx: Option<oneshot::Sender<()>>,
) {
    let mut out: Vec<Event> = Vec::new();
    // Batched IO. On platforms without segmentation offload this degrades to
    // one datagram per call, i.e. exactly the previous behaviour.
    let mut io = match batch::BatchIo::new(&socket) {
        Ok(io) => io,
        Err(_) => return,
    };
    // Consecutive datagrams awaiting a coalesced send.
    let mut pending: Vec<Bytes> = Vec::new();
    // Receive scratch: one buffer per datagram in a batch, each large enough to
    // hold a GRO-coalesced run.
    let (mut rx_storage, mut rx_metas) = batch::recv_buffers(&io);
    // Pending flush barrier: resolved once snd_buf drains.
    let mut pending_flush: Option<oneshot::Sender<()>> = None;
    // Message awaiting send-buffer space; see `BlockedSend`.
    let mut blocked: Option<BlockedSend> = None;

    // Trigger initial handshake send or keepalive.
    conn.on_timer(now_us(), &mut out);

    loop {
        // ── Drain accumulated outputs ─────────────────────────────────────────
        // Use mem::take so that processing an output (e.g. shutdown) can push
        // new outputs without them being silently dropped.
        let mut done = false;
        while !out.is_empty() {
            for item in std::mem::take(&mut out) {
                // Anything that is not a datagram ends the current run: flush
                // first so ordering against the other side effects is preserved.
                if !matches!(item, Event::SendDatagram(_)) && !pending.is_empty() {
                    let _ = io.send_all(&socket, peer_addr, &pending).await;
                    pending.clear();
                }
                match item {
                    Event::SendDatagram(bytes) => {
                        pending.push(bytes);
                    }
                    Event::DataReady => {
                        while let Some(msg) = conn.recv_msg() {
                            if recv_tx.send_async(msg).await.is_err() {
                                // Application dropped the recv half — shut down.
                                conn.shutdown(now_us(), &mut out);
                                done = true;
                                break;
                            }
                        }
                    }
                    Event::Connected => {
                        if let Some(tx) = connected_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                    Event::Disconnected(reason) => {
                        if std::env::var_os("UDT_DEBUG").is_some() {
                            eprintln!(
                                "[conn {}] disconnected: {reason:?} {:?}",
                                conn.stats().socket_id,
                                conn.stats(),
                            );
                        }
                        done = true;
                    }
                }
                if done { break; }
            }
            if done { break; }
        }
        // Flush any SendDatagrams that were queued after a Disconnected.
        for leftover in std::mem::take(&mut out) {
            if let Event::SendDatagram(bytes) = leftover {
                pending.push(bytes);
            }
        }
        if !pending.is_empty() {
            let _ = io.send_all(&socket, peer_addr, &pending).await;
            pending.clear();
        }

        // Retry a message that previously found the send buffer full.  ACKs
        // processed above may have freed the space it needs.
        if let Some(b) = blocked.take() {
            match conn.send_msg(b.payload.clone(), b.ttl_ms, b.in_order, now_us(), &mut out) {
                SendOutcome::Queued => {}
                SendOutcome::WouldBlock => blocked = Some(b),
                // Unsendable (oversized, or the connection is closing) — drop it
                // and let the loop wind down rather than retrying forever.
                SendOutcome::Rejected => {}
            }
            // Queuing may have produced more datagrams; go round again to flush
            // them before parking on the select below.
            if !out.is_empty() {
                continue;
            }
        }

        // Resolve any pending flush barrier once everything has drained — that
        // includes any message still waiting for buffer space.
        if let Some(notify) = pending_flush.take() {
            if conn.snd_buf_is_empty() && blocked.is_none() {
                let _ = notify.send(());
            } else {
                pending_flush = Some(notify);
            }
        }

        if done { return; }

        // ── Wait for the next event ───────────────────────────────────────────
        let deadline = deadline_instant(&conn);

        if let Some(ref mut drx) = datagram_rx {
            // Accepted / rendezvous: receive datagrams forwarded by the mux.
            tokio::select! {
                maybe = drx.recv() => {
                    match maybe {
                        Some(bytes) => {
                            conn.on_datagram(bytes, now_us(), &mut out);
                            // Drain whatever else is already queued in the same
                            // wakeup.  Re-entering the select per datagram costs
                            // a timer arm/disarm each time, which dominates at
                            // hundreds of thousands of packets per second.
                            let mut batched = 1;
                            while batched < RECV_BATCH {
                                match drx.try_recv() {
                                    Ok(b) => {
                                        conn.on_datagram(b, now_us(), &mut out);
                                        batched += 1;
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        None => {
                            return; // mux dropped the route
                        }
                    }
                }
                // Stop accepting new work while a message is waiting for buffer
                // space, so the bounded channel backpressures the application.
                maybe_req = send_rx.recv(), if blocked.is_none() => {
                    handle_send_req(
                        maybe_req, &mut conn, &mut pending_flush, &mut blocked, now_us(), &mut out,
                    );
                }
                _ = tokio::time::sleep_until(deadline) => {
                    conn.on_timer(now_us(), &mut out);
                    debug_tick(&conn, "mux", &blocked);
                }
            }
        } else {
            // Active connection: reads from the dedicated per-connection socket.
            tokio::select! {
                result = io.recv_batch(&socket, &mut rx_storage, &mut rx_metas) => {
                    let Ok(mut count) = result else { return };
                    // One call may return several datagrams (recvmmsg), and each
                    // buffer may itself hold several coalesced by generic
                    // receive offload. Where the platform has neither, drain in
                    // a loop so one wakeup does not cost one packet.
                    let mut drained = 0;
                    loop {
                        for i in 0..count {
                            if rx_metas[i].addr != peer_addr {
                                continue;
                            }
                            for dg in batch::split_run(&rx_storage[i], &rx_metas[i]) {
                                conn.on_datagram(dg, now_us(), &mut out);
                            }
                        }
                        drained += count;
                        if drained >= RECV_DRAIN_CAP {
                            break;
                        }
                        match io.try_recv_batch(&socket, &mut rx_storage, &mut rx_metas) {
                            Ok(n) if n > 0 => count = n,
                            _ => break,
                        }
                    }
                }
                // Stop accepting new work while a message is waiting for buffer
                // space, so the bounded channel backpressures the application.
                maybe_req = send_rx.recv(), if blocked.is_none() => {
                    handle_send_req(
                        maybe_req, &mut conn, &mut pending_flush, &mut blocked, now_us(), &mut out,
                    );
                }
                _ = tokio::time::sleep_until(deadline) => {
                    conn.on_timer(now_us(), &mut out);
                    debug_tick(&conn, "own", &blocked);
                }
            }
        }
    }
}

/// Periodic state dump, enabled by setting `UDT_DEBUG=1`.  Used to diagnose
/// stalls; compiled in but inert unless the variable is set.
fn debug_tick(conn: &Connection, tag: &str, blocked: &Option<BlockedSend>) {
    if std::env::var_os("UDT_DEBUG").is_none() {
        return;
    }
    let st = conn.stats();
    // Only report connections with outstanding work; otherwise idle sockets
    // drown out the one that is actually stuck.
    let has_work = st.snd_in_flight > 0
        || st.snd_pending > 0
        || st.snd_loss_len > 0
        || st.rcv_loss_len > 0
        || !st.connected;
    if !has_work {
        return;
    }
    eprintln!("[{tag}] {st:?} blocked={}", blocked.is_some());
}

/// Handle a `SendReq` option (Some = new request, None = channel closed → half-close).
fn handle_send_req(
    req: Option<SendReq>,
    conn: &mut Connection,
    pending_flush: &mut Option<oneshot::Sender<()>>,
    blocked: &mut Option<BlockedSend>,
    now_us: u64,
    out: &mut Vec<Event>,
) {
    match req {
        Some(SendReq::Data { payload, ttl_ms, in_order }) => {
            match conn.send_msg(payload.clone(), ttl_ms, in_order, now_us, out) {
                SendOutcome::Queued => {}
                // Hold the message; the driver loop retries it and stops
                // reading send_rx until it lands.
                SendOutcome::WouldBlock => {
                    *blocked = Some(BlockedSend { payload, ttl_ms, in_order });
                }
                SendOutcome::Rejected => {}
            }
        }
        Some(SendReq::Flush { notify }) => {
            // Resolve immediately if the buffer is already empty; otherwise
            // stash and resolve once the last ACK arrives.
            if conn.snd_buf_is_empty() && blocked.is_none() {
                let _ = notify.send(());
            } else {
                // If there's already a pending flush, resolve it now (caller
                // will get a spuriously-early completion for the old one, which
                // is acceptable — it was empty at the time the new one arrived).
                if let Some(old) = pending_flush.take() {
                    let _ = old.send(());
                }
                *pending_flush = Some(notify);
            }
        }
        None => {
            // Send channel closed: application is done sending.
            conn.half_close(now_us, out);
        }
    }
}
