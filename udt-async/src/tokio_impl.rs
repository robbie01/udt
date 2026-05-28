use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use udt_proto::{Connection, Output};
use udt_proto::listener::{ListenerState, ListenerOutput, PeerAddr};
use udt_proto::seq::SeqNo;

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

/// Size of the UDT packet header that precedes every payload (4 × u32 = 16 bytes).
pub const UDT_HEADER_SIZE: usize = udt_proto::UDT_HEADER_SIZE;

/// UDP encapsulation overhead for IPv4 (20-byte IP header + 8-byte UDP header).
pub const UDP_OVERHEAD_V4: u32 = 28;

/// UDP encapsulation overhead for IPv6 (40-byte IP header + 8-byte UDP header).
pub const UDP_OVERHEAD_V6: u32 = 48;

/// Default MSS advertised in the UDT handshake for a standard Ethernet network.
///
/// Follows the C++ UDT wire convention: `mss` = IP-layer MTU (including IP and
/// UDP headers).  The maximum application payload per UDT packet is therefore:
///   `DEFAULT_MSS − UDP_OVERHEAD_V6 − UDT_HEADER_SIZE = 1500 − 48 − 16 = 1436 bytes`
///
/// Note: the C++ implementation uses a fixed overhead of 48 bytes (IPv6-sized)
/// for both IPv4 and IPv6 to avoid a connection-setup dependency on the peer's
/// address family.  To maximise IPv4 throughput on a dedicated IPv4 network you
/// can pass a custom `mss` to [`Endpoint::bind_with_mss`].
pub const DEFAULT_MSS: u32 = 1500;

// ── Send request (application → driver) ──────────────────────────────────────

struct SendReq {
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
        accept_tx: mpsc::Sender<Socket>,
        secret: u64,
        socket_id: u32,
    },
}

// ── Socket ────────────────────────────────────────────────────────────────────

pub struct Socket {
    send_tx: mpsc::Sender<SendReq>,
    recv_rx: mpsc::Receiver<Bytes>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl Socket {
    pub async fn send(&self, buf: &[u8]) -> io::Result<()> {
        self.send_with(buf, None, false).await
    }

    pub async fn send_with(
        &self,
        buf: &[u8],
        ttl: Option<Duration>,
        in_order: bool,
    ) -> io::Result<()> {
        self.send_tx
            .send(SendReq {
                payload: Bytes::copy_from_slice(buf),
                ttl_ms: ttl.map(|d| d.as_millis() as u32),
                in_order,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let msg = self
            .recv_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;
        let n = msg.len().min(buf.len());
        buf[..n].copy_from_slice(&msg[..n]);
        Ok(n)
    }

    pub fn peer_addr(&self) -> SocketAddr { self.peer_addr }
    pub fn local_addr(&self) -> SocketAddr { self.local_addr }
}

// ── Listener ──────────────────────────────────────────────────────────────────

pub struct Listener {
    accept_rx: mpsc::Receiver<Socket>,
    local_addr: SocketAddr,
}

impl Listener {
    pub async fn accept(&mut self) -> io::Result<Socket> {
        self.accept_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "listener closed"))
    }

    pub fn local_addr(&self) -> SocketAddr { self.local_addr }
}

// ── Endpoint ──────────────────────────────────────────────────────────────────

pub struct Endpoint {
    /// Shared socket for the endpoint's bound address.
    /// The mux task is the sole *reader*; this handle is used for outbound sends
    /// from rendezvous/accepted connections.  Active (`connect`) connections get
    /// their own dedicated socket instead.
    socket: Arc<UdpSocket>,
    /// Command channel to the endpoint mux task that owns the recv loop.
    mux_tx: mpsc::UnboundedSender<MuxCmd>,
    local_addr: SocketAddr,
    /// MSS used for all connections created from this endpoint.
    mss: u32,
}

impl Endpoint {
    /// Bind with the default MSS (1500, standard Ethernet MTU).
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        Self::bind_with_mss(addr, DEFAULT_MSS)
    }

    /// Bind with an explicit MSS (IP-layer MTU).
    ///
    /// `mss` is the IP-layer MTU advertised in the UDT handshake, following the
    /// C++ UDT wire convention.  The maximum application payload per packet is:
    ///   `mss − UDP_OVERHEAD_V6(48) − UDT_HEADER_SIZE(16)`
    ///
    /// Example: jumbo-frame IPv4 network with 9000-byte MTU:
    /// ```ignore
    /// let ep = Endpoint::bind_with_mss("0.0.0.0:0".parse().unwrap(), 9000)?;
    /// // max payload = 9000 − 48 − 16 = 8936 bytes
    /// ```
    pub fn bind_with_mss(addr: SocketAddr, mss: u32) -> io::Result<Self> {
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(std_sock)?);
        let local_addr = socket.local_addr()?;
        let (mux_tx, mux_rx) = mpsc::unbounded_channel::<MuxCmd>();
        tokio::spawn(run_endpoint_mux(Arc::clone(&socket), mux_rx, mss));
        Ok(Endpoint { socket, mux_tx, local_addr, mss })
    }

    /// Connect to a remote UDT listener.
    ///
    /// Each `connect()` call binds a fresh ephemeral socket, so concurrent
    /// outgoing active connections from the same `Endpoint` are fully isolated.
    pub async fn connect(&self, peer: SocketAddr) -> io::Result<Socket> {
        let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        std_sock.set_nonblocking(true)?;
        let udp = Arc::new(UdpSocket::from_std(std_sock)?);
        let local_addr = udp.local_addr()?;

        let (send_tx, send_rx) = mpsc::channel::<SendReq>(64);
        let (recv_tx, recv_rx) = mpsc::channel::<Bytes>(64);
        let (connected_tx, connected_rx) = oneshot::channel::<()>();

        let socket_id = next_socket_id();
        let isn = SeqNo::new(rand::random::<u32>() & 0x7FFF_FFFF);
        let conn = Connection::new_active(socket_id, isn, self.mss, now_us());

        tokio::spawn(run_conn_driver(udp, conn, peer, None, send_rx, recv_tx, Some(connected_tx)));

        connected_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect handshake timed out"))?;

        Ok(Socket { send_tx, recv_rx, peer_addr: peer, local_addr })
    }

    /// Rendezvous connect: both sides call this simultaneously knowing each
    /// other's address.
    ///
    /// All rendezvous connections from the same `Endpoint` share the underlying
    /// socket through the endpoint mux, so there is exactly one `recv_from` call
    /// in flight at any time regardless of how many are active concurrently.
    pub async fn connect_rendezvous(&self, peer: SocketAddr) -> io::Result<Socket> {
        let (datagram_tx, datagram_rx) = mpsc::channel::<Bytes>(64);
        let (send_tx, send_rx) = mpsc::channel::<SendReq>(64);
        let (recv_tx, recv_rx) = mpsc::channel::<Bytes>(64);
        let (connected_tx, connected_rx) = oneshot::channel::<()>();

        // Register the route *before* spawning so no incoming packet is missed.
        self.mux_tx.send(MuxCmd::RegisterRoute { peer, tx: datagram_tx })
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "endpoint closed"))?;

        let socket_id = next_socket_id();
        let isn = SeqNo::new(rand::random::<u32>() & 0x7FFF_FFFF);
        let conn = Connection::new_rendezvous(socket_id, isn, self.mss, now_us());

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

    /// Start listening for incoming connections.
    ///
    /// The listener state machine runs inside the endpoint mux, so `listen()`
    /// and `connect_rendezvous()` can coexist on the same `Endpoint` without
    /// racing on the shared socket.
    pub fn listen(&self, backlog: usize) -> io::Result<Listener> {
        let (accept_tx, accept_rx) = mpsc::channel::<Socket>(backlog.max(1));
        let secret: u64 = rand::random();
        let socket_id = next_socket_id();
        self.mux_tx.send(MuxCmd::StartListener { accept_tx, secret, socket_id })
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "endpoint closed"))?;
        Ok(Listener { accept_rx, local_addr: self.local_addr })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
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
    mss: u32,
) {
    let local_addr = match socket.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };
    // source address → datagram forwarder for established/rendezvous connections
    let mut routes: HashMap<SocketAddr, mpsc::Sender<Bytes>> = HashMap::new();
    // optional listener state machine
    let mut listener: Option<(ListenerState, mpsc::Sender<Socket>)> = None;
    let mut listener_out: Vec<ListenerOutput> = Vec::new();
    let mut recv_buf = vec![0u8; 65536];
    let mut cmd_rx_closed = false;

    loop {
        // Prune stale listener (Listener struct was dropped by the caller).
        if let Some((_, accept_tx)) = &listener {
            if accept_tx.is_closed() {
                listener = None;
            }
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
                            ListenerState::new(socket_id, mss, now_us(), secret),
                            accept_tx,
                        ));
                    }
                    None => {
                        // Endpoint dropped.  Keep running to serve live connections.
                        cmd_rx_closed = true;
                    }
                }
            }
            result = socket.recv_from(&mut recv_buf) => {
                let (n, from) = match result {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let bytes = Bytes::copy_from_slice(&recv_buf[..n]);

                // Known peer → forward to its connection driver.
                if let Some(conn_tx) = routes.get(&from) {
                    if conn_tx.send(bytes).await.is_err() {
                        routes.remove(&from);
                    }
                    continue;
                }

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
                                ListenerOutput::SendTo { data, .. } => {
                                    let _ = socket.send_to(&data, from).await;
                                }
                                ListenerOutput::Accept(conn, _pa) => {
                                    let (datagram_tx, datagram_rx) = mpsc::channel::<Bytes>(64);
                                    let (send_tx, send_rx) = mpsc::channel::<SendReq>(64);
                                    let (recv_tx, recv_rx) = mpsc::channel::<Bytes>(64);
                                    routes.insert(from, datagram_tx);
                                    tokio::spawn(run_conn_driver(
                                        Arc::clone(&socket),
                                        conn,
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
                                    if accept_tx.send(sock).await.is_err() {
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
    recv_tx: mpsc::Sender<Bytes>,
    mut connected_tx: Option<oneshot::Sender<()>>,
) {
    let mut out: Vec<Output> = Vec::new();
    let mut recv_buf = vec![0u8; 65536];

    // Trigger initial handshake send or keepalive.
    conn.on_timer(now_us(), &mut out);

    loop {
        // ── Drain accumulated outputs ─────────────────────────────────────────
        // Use mem::take so that processing an output (e.g. shutdown) can push
        // new outputs without them being silently dropped.
        let mut done = false;
        while !out.is_empty() {
            for item in std::mem::take(&mut out) {
                match item {
                    Output::SendDatagram(bytes) => {
                        let _ = socket.send_to(&bytes, peer_addr).await;
                    }
                    Output::DataReady => {
                        while let Some(msg) = conn.recv_msg() {
                            if recv_tx.send(msg).await.is_err() {
                                // Application dropped the recv half — shut down.
                                conn.shutdown(now_us(), &mut out);
                                done = true;
                                break;
                            }
                        }
                    }
                    Output::Connected => {
                        if let Some(tx) = connected_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                    Output::Disconnected(_) => {
                        done = true;
                    }
                }
                if done { break; }
            }
            if done { break; }
        }
        // Flush any SendDatagrams that were queued after a Disconnected.
        for leftover in std::mem::take(&mut out) {
            if let Output::SendDatagram(bytes) = leftover {
                let _ = socket.send_to(&bytes, peer_addr).await;
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
                        }
                        None => {
                            return; // mux dropped the route
                        }
                    }
                }
                maybe_req = send_rx.recv() => {
                    match maybe_req {
                        Some(req) => conn.send_msg(&req.payload, req.ttl_ms, req.in_order, now_us(), &mut out),
                        None => conn.half_close(now_us(), &mut out),
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    conn.on_timer(now_us(), &mut out);
                }
            }
        } else {
            // Active connection: reads from the dedicated per-connection socket.
            tokio::select! {
                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((n, from)) if from == peer_addr => {
                            let bytes = Bytes::copy_from_slice(&recv_buf[..n]);
                            conn.on_datagram(bytes, now_us(), &mut out);
                        }
                        Ok(_) => {} // stray packet; re-loop
                        Err(_) => return,
                    }
                }
                maybe_req = send_rx.recv() => {
                    match maybe_req {
                        Some(req) => conn.send_msg(&req.payload, req.ttl_ms, req.in_order, now_us(), &mut out),
                        None => conn.half_close(now_us(), &mut out),
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    conn.on_timer(now_us(), &mut out);
                }
            }
        }
    }
}
