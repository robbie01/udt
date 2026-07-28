//! The bound local address, and the reader tasks that serve it.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::{Notify, mpsc};
use udt_proto::{CcKind, Connection, Listener as ProtoListener, ListenerEvent, SeqNo};

use crate::batch::{self, BatchIo};
use crate::conn::{ConnectionInner, Socket, wait_established};
use crate::driver;
use crate::util::{
    Mutex, RwLock, configure_udp_buffers, lock, next_socket_id, now_us, outgoing_bind_addr,
    sockaddr_to_peer_addr,
};

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
    if mtu <= FIXED_OVERHEAD { 0 } else { (mtu - FIXED_OVERHEAD) as usize }
}

/// Datagrams the reader may leave queued for one connection.
///
/// Deep enough that a driver briefly descheduled does not lose anything, and
/// shallow enough that a connection which has genuinely stopped keeping up
/// starts dropping rather than growing without bound — which is what an
/// overrun kernel socket buffer does, and what UDT's loss recovery expects.
const DATAGRAM_BACKLOG: usize = 1024;

/// Datagrams the reader takes per wakeup before dispatching them.
///
/// Bounds how long one busy peer can hold the reader before every other
/// connection on the endpoint gets a turn. Counts datagrams, not receive
/// calls: with receive offload one buffer can hold 64.
const RECV_DRAIN_CAP: usize = 256;

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
    /// This is the largest IP packet the network path can carry without
    /// fragmenting. 1500 is right for ordinary Ethernet and the internet at
    /// large; raise it to 9000 on a jumbo-frame network. Peers negotiate down
    /// to the smaller of the two values during the handshake.
    ///
    /// [`max_payload_for_mtu`] gives the resulting largest single-packet
    /// message. Larger messages are split across packets automatically.
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

// ── Shared endpoint state ─────────────────────────────────────────────────────

struct ListenerSlot {
    proto: ProtoListener,
    accept_tx: flume::Sender<Socket>,
}

/// State the reader tasks and the [`Endpoint`] handle share.
struct EndpointInner {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    cfg: EndpointConfig,
    /// Peer address to connection, for everything sharing the bound port.
    ///
    /// A read-write lock rather than a channel or a single owning task: the
    /// readers only ever look routes up, and taking a read lock lets several
    /// of them dispatch to different connections at once. Writes happen once
    /// per connection, at accept and at close.
    routes: RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>,
    listener: Mutex<Option<ListenerSlot>>,
    /// False once the `Endpoint` handle is dropped. Readers keep serving
    /// existing connections after that, and stop when the last one goes.
    handle_alive: AtomicBool,
    /// Poked whenever something that could end the readers changes.
    wind_down: Notify,
}

impl EndpointInner {
    /// Whether the readers have nothing left to serve.
    fn is_spent(&self) -> bool {
        !self.handle_alive.load(Ordering::Acquire)
            && lock(&self.listener).is_none()
            && self.routes.read().map(|r| r.is_empty()).unwrap_or(true)
    }

    fn remove_route(&self, peer: SocketAddr) {
        if let Ok(mut routes) = self.routes.write() {
            routes.remove(&peer);
        }
        self.wind_down.notify_waiters();
    }
}

// ── Listener ──────────────────────────────────────────────────────────────────

/// Accepts incoming UDT connections on a bound address.
///
/// Created by [`Endpoint::listen`]. Like [`Socket`] it takes `&self`
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
        self.accept_rx
            .recv_async()
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "endpoint closed"))
    }

    /// The address this listener accepts on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

// ── Endpoint ──────────────────────────────────────────────────────────────────

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
/// Dropping the endpoint does not disturb connections already made from it.
pub struct Endpoint {
    inner: Arc<EndpointInner>,
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
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        configure_udp_buffers(&std_sock, cfg.mss);
        let socket = Arc::new(UdpSocket::from_std(std_sock)?);
        let local_addr = socket.local_addr()?;

        let inner = Arc::new(EndpointInner {
            socket,
            local_addr,
            cfg,
            routes: RwLock::new(HashMap::new()),
            listener: Mutex::new(None),
            handle_alive: AtomicBool::new(true),
            wind_down: Notify::new(),
        });

        tokio::spawn(run_reader(Arc::clone(&inner)));
        Ok(Endpoint { inner })
    }

    /// Connects to a peer that is listening.
    ///
    /// Resolves once the handshake completes. The connection gets its own
    /// kernel socket, so it is unaffected by other traffic on this endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::TimedOut`] if the peer does not answer.
    ///
    /// [`ErrorKind::TimedOut`]: std::io::ErrorKind::TimedOut
    pub async fn connect(&self, peer: impl ToSocketAddrs) -> io::Result<Socket> {
        let peer = resolve(peer).await?;
        let std_sock = std::net::UdpSocket::bind(outgoing_bind_addr(self.inner.local_addr, peer))?;
        std_sock.set_nonblocking(true)?;
        configure_udp_buffers(&std_sock, self.inner.cfg.mss);
        let socket = Arc::new(UdpSocket::from_std(std_sock)?);
        let local_addr = socket.local_addr()?;

        let conn = Connection::new_active(
            next_socket_id(),
            random_isn(),
            self.inner.cfg.mss,
            now_us(),
            self.inner.cfg.congestion,
        );
        let inner = ConnectionInner::new(conn);
        tokio::spawn(driver::run_owned(Arc::clone(&inner), socket, peer));

        wait_established(&inner).await?;
        Ok(Socket { inner, peer_addr: peer, local_addr })
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
        let conn = Connection::new_rendezvous(
            next_socket_id(),
            random_isn(),
            self.inner.cfg.mss,
            now_us(),
            self.inner.cfg.congestion,
        );
        let inner = ConnectionInner::new(conn);
        spawn_shared(&self.inner, &inner, peer);

        match wait_established(&inner).await {
            Ok(()) => Ok(Socket { inner, peer_addr: peer, local_addr: self.inner.local_addr }),
            Err(e) => Err(e),
        }
    }

    /// Accepts incoming connections on this endpoint's address.
    ///
    /// `backlog` bounds how many completed connections wait to be picked up
    /// by [`Listener::accept`]. Connections completing while the backlog is
    /// full are refused rather than queued, so an application that stops
    /// accepting cannot hold up the traffic of connections already open.
    ///
    /// An endpoint can listen and make outgoing connections at the same time.
    /// Calling this again replaces the previous listener.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint has shut down.
    pub fn listen(&self, backlog: usize) -> io::Result<Listener> {
        let (accept_tx, accept_rx) = flume::bounded::<Socket>(backlog.max(1));
        let proto = ProtoListener::new(
            next_socket_id(),
            self.inner.cfg.mss,
            now_us(),
            rand::random(),
            self.inner.cfg.congestion,
        );
        *lock(&self.inner.listener) = Some(ListenerSlot { proto, accept_tx });
        Ok(Listener { accept_rx, local_addr: self.inner.local_addr })
    }

    /// The address this endpoint is bound to, with any OS-assigned port
    /// filled in.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.inner.handle_alive.store(false, Ordering::Release);
        self.inner.wind_down.notify_waiters();
    }
}

fn random_isn() -> SeqNo {
    SeqNo::new(rand::random::<u32>() & 0x7FFF_FFFF)
}

async fn resolve(addr: impl ToSocketAddrs) -> io::Result<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to"))
}

/// Route `peer` to a new connection and start driving it.
///
/// The channel is registered before the driver starts so that no reply can
/// arrive unrouted.
fn spawn_shared(ep: &Arc<EndpointInner>, inner: &Arc<ConnectionInner>, peer: SocketAddr) {
    let (datagram_tx, datagram_rx) = mpsc::channel::<Bytes>(DATAGRAM_BACKLOG);
    let Ok(mut routes) = ep.routes.write() else { return };
    routes.insert(peer, datagram_tx);
    drop(routes);

    let socket = Arc::clone(&ep.socket);
    let inner = Arc::clone(inner);
    let ep = Arc::clone(ep);
    tokio::spawn(driver::run_shared(inner, socket, peer, datagram_rx, move || {
        ep.remove_route(peer)
    }));
}

// ── Reader tasks ──────────────────────────────────────────────────────────────

/// Read the endpoint's socket and hand each datagram to the connection it
/// belongs to.
///
/// Exactly one of these runs per endpoint, and that is a correctness
/// requirement rather than a simplification. The kernel delivers a flow's
/// datagrams to a socket in order; two tasks reading the same socket would
/// race to the connection and feed them out of order, which UDT reads as loss.
/// Measured: four readers turned a 16 MB transfer that takes 0.08 s into one
/// that never finished, the receiver stuck retransmitting a perpetual
/// one-packet gap.
///
/// So the reader does as little as possible — route by peer address, forward,
/// and let each connection's own driver do the protocol work.
async fn run_reader(ep: Arc<EndpointInner>) {
    let Ok(io) = BatchIo::new(&ep.socket) else { return };
    let (mut storage, mut metas) = batch::recv_buffers(&io);
    // Datagrams arrive from one peer at a time, so they are accumulated into a
    // run and handed over when the peer changes. That takes each connection's
    // lock once per run rather than once per datagram, without the per-packet
    // hashing that grouping them into a map would cost.
    let mut run: Vec<Bytes> = Vec::new();
    let mut run_peer: Option<SocketAddr> = None;
    let mut route: Option<mpsc::Sender<Bytes>> = None;
    let mut unrouted: Vec<(SocketAddr, Bytes)> = Vec::new();

    loop {
        let mut count = tokio::select! {
            result = io.recv_batch(&ep.socket, &mut storage, &mut metas) => match result {
                Ok(n) => n,
                Err(_) => return,
            },
            _ = ep.wind_down.notified() => {
                if ep.is_spent() { return; }
                continue;
            }
        };

        // Drain whatever else is already queued in the same wakeup. On a
        // platform with no `recvmmsg` a batch call returns one datagram, so
        // without this a wakeup would cost a packet.
        let mut drained = 0;
        loop {
            for i in 0..count {
                let from = metas[i].addr;
                if run_peer != Some(from) {
                    if let Some(peer) = run_peer {
                        dispatch(peer, &route, &mut run, &mut unrouted);
                    }
                    run_peer = Some(from);
                    route = ep.routes.read().ok().and_then(|r| r.get(&from).cloned());
                }
                // A buffer can hold a run of datagrams coalesced by receive
                // offload; delivering it whole would hand the decoder a blob
                // and lose all but the first packet.
                let before = run.len();
                run.extend(batch::split_run(&storage[i], &metas[i]));
                drained += run.len() - before;
            }
            if drained >= RECV_DRAIN_CAP {
                break;
            }
            match io.try_recv_batch(&ep.socket, &mut storage, &mut metas) {
                Ok(n) if n > 0 => count = n,
                _ => break,
            }
        }
        if let Some(peer) = run_peer.take() {
            dispatch(peer, &route, &mut run, &mut unrouted);
            route = None;
        }

        for (from, datagram) in unrouted.drain(..) {
            handle_handshake(&ep, from, datagram).await;
        }

        if ep.is_spent() {
            return;
        }
    }
}

/// Hand one peer's run of datagrams to its connection.
fn dispatch(
    peer: SocketAddr,
    route: &Option<mpsc::Sender<Bytes>>,
    run: &mut Vec<Bytes>,
    unrouted: &mut Vec<(SocketAddr, Bytes)>,
) {
    match route {
        Some(tx) => {
            // Never block: this task serves every connection on the port, so
            // waiting on one that has stopped keeping up would stall all the
            // others. A full channel drops, as a full socket buffer would.
            for datagram in run.drain(..) {
                if tx.try_send(datagram).is_err() {
                    break;
                }
            }
            run.clear();
        }
        None => {
            // Unknown source: only a handshake can be legitimate. The rest of
            // the run waits for the peer to retransmit, which is what an
            // opening connection does anyway.
            if let Some(datagram) = run.first().cloned() {
                unrouted.push((peer, datagram));
            }
            run.clear();
        }
    }
}

/// Feed a datagram from an unrouted peer to the listener, if there is one.
async fn handle_handshake(ep: &Arc<EndpointInner>, from: SocketAddr, datagram: Bytes) {
    let mut events = Vec::new();
    {
        let mut guard = lock(&ep.listener);
        let Some(slot) = guard.as_mut() else { return };
        if slot.accept_tx.is_disconnected() {
            *guard = None;
            ep.wind_down.notify_waiters();
            return;
        }
        slot.proto.on_datagram(sockaddr_to_peer_addr(from), datagram, now_us(), &mut events);
    }

    for event in events {
        match event {
            ListenerEvent::SendTo { data, .. } => {
                let _ = ep.socket.send_to(&data, from).await;
            }
            ListenerEvent::Accept(conn, _) => {
                let accept_tx = {
                    let guard = lock(&ep.listener);
                    guard.as_ref().map(|slot| slot.accept_tx.clone())
                };
                let Some(accept_tx) = accept_tx else { return };

                let inner = ConnectionInner::new(*conn);
                spawn_shared(ep, &inner, from);
                let socket = Socket { inner, peer_addr: from, local_addr: ep.local_addr };

                // Never wait for the application to accept. This task serves
                // every connection on the port, so blocking here would let a
                // caller that has stopped calling `accept` -- or an attacker
                // filling the backlog -- stall every established connection
                // too. Over the backlog the connection is refused, which is
                // what a backlog is; dropping the socket closes it.
                match accept_tx.try_send(socket) {
                    Ok(()) => {}
                    Err(flume::TrySendError::Full(_)) => {}
                    Err(flume::TrySendError::Disconnected(_)) => {
                        *lock(&ep.listener) = None;
                        ep.wind_down.notify_waiters();
                        return;
                    }
                }
            }
        }
    }
}
