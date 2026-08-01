//! The bound local address, and the reader tasks that serve it.

use std::collections::HashMap;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::{Notify, mpsc, oneshot};
use udt_proto::{
    CcKind, Connection as ProtoConnection, Listener as ProtoListener, ListenerEvent, Route, Router,
    SeqNo,
};

use crate::batch::{BatchIo, Inbound, RecvBuffers};
use crate::conn::{Connecting, Connection, RECV_BACKLOG, SEND_BACKLOG, SendReq};
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
///
/// This describes the default MTU and this end of a connection. What an
/// established connection actually negotiated — possibly less, if the peer
/// offered a smaller MTU — is [`Connection::max_unsegmented_len`], and that is
/// the one to ask.
///
/// [`Connection::max_unsegmented_len`]: crate::Connection::max_unsegmented_len
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
/// Deep enough that a driver briefly descheduled loses nothing, shallow enough
/// that one which has genuinely stopped keeping up starts dropping rather than
/// growing without bound -- which is what an overrun socket buffer does, and
/// what the protocol's loss recovery expects.
const DATAGRAM_BACKLOG: usize = 256;

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
    /// fragmenting. 1500 is the default and is right for ordinary Ethernet and
    /// most of the internet; raise it to 9000 on a jumbo-frame network. Peers
    /// negotiate down to the smaller of the two values during the handshake.
    ///
    /// [`max_payload_for_mtu`] gives the resulting largest single-packet
    /// message. Larger messages are split across packets automatically.
    ///
    /// # When to lower it
    ///
    /// Some paths carry less than 1500 — tunnels, PPPoE, and IPv6 transition
    /// mechanisms commonly cap at 1400 to 1492 — and they discard anything
    /// larger without saying so. Since the handshake is small it still
    /// succeeds, so the symptom is a connection that opens and then moves no
    /// data.
    ///
    /// That case is detected rather than left to hang: sends fail with
    /// [`ErrorKind::InvalidInput`] and a message saying as much. The fix is to
    /// set this lower. 1400 clears the common cases and 1280 is the smallest
    /// any IPv6 path may be, at a cost of a few percent more packets for the
    /// same data.
    ///
    /// There is no automatic probing. UDT has no packet type for it, and
    /// inventing one would break interoperability with other implementations.
    ///
    /// Values below 64 bytes are raised to 64.
    ///
    /// [`ErrorKind::InvalidInput`]: std::io::ErrorKind::InvalidInput
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
    accept_tx: flume::Sender<Connection>,
}

/// State the reader tasks and the [`Endpoint`] handle share.
struct EndpointInner {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    cfg: EndpointConfig,
    /// Which connection an arriving datagram belongs to.
    ///
    /// The rules live in `udt-proto`, next to the wire format they come from;
    /// this holds the table and the lock.
    ///
    /// A read-write lock rather than a channel or a single owning task: the
    /// readers only ever look routes up, and taking a read lock lets several
    /// of them dispatch to different connections at once. Writes happen once
    /// per connection, at accept and at close.
    routes: RwLock<Router<SocketAddr, mpsc::Sender<Inbound>>>,
    listener: Mutex<Option<ListenerSlot>>,
    /// False once the `Endpoint` handle is dropped. Readers keep serving
    /// existing connections after that, and stop when the last one goes.
    handle_alive: AtomicBool,
    /// Poked whenever something that could end the readers changes.
    wind_down: Notify,
    /// One lock per peer address, held for the length of a rendezvous
    /// handshake. See [`Endpoint::connect_rendezvous`].
    rendezvous_locks: Mutex<HashMap<SocketAddr, Arc<tokio::sync::Mutex<()>>>>,
}

impl EndpointInner {
    /// Whether the readers have nothing left to serve.
    fn is_spent(&self) -> bool {
        !self.handle_alive.load(Ordering::Acquire)
            && lock(&self.listener).is_none()
            && self.routes.read().map(|r| r.is_empty()).unwrap_or(true)
    }

    fn remove_route(&self, socket_id: u32, peer: SocketAddr) {
        if let Ok(mut routes) = self.routes.write() {
            routes.remove(socket_id, &peer);
        }
        self.wind_down.notify_waiters();
    }
}

// ── Listener ──────────────────────────────────────────────────────────────────

/// Accepts incoming UDT connections on a bound address.
///
/// Created by [`Endpoint::listen`]. Like [`Connection`] it takes `&self`
/// throughout, so several tasks can accept from one listener through an `Arc`.
/// Dropping it stops accepting; connections already returned by
/// [`accept`](Self::accept) stay open.
pub struct Listener {
    accept_rx: flume::Receiver<Connection>,
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
    pub async fn accept(&self) -> io::Result<Connection> {
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
/// let conn = endpoint.connect("203.0.113.7:9000").await?.await?;
/// conn.send(b"hello").await?;
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
            routes: RwLock::new(Router::new()),
            listener: Mutex::new(None),
            handle_alive: AtomicBool::new(true),
            wind_down: Notify::new(),
            rendezvous_locks: Mutex::new(HashMap::new()),
        });

        tokio::spawn(run_reader(Arc::clone(&inner)));
        Ok(Endpoint { inner })
    }

    /// Begins connecting to a peer that is listening.
    ///
    /// Returns as soon as the handshake is under way, without waiting for it.
    /// Awaiting the [`Connecting`] yields the established [`Connection`]:
    ///
    /// ```no_run
    /// # async fn f(endpoint: udt_async::Endpoint) -> std::io::Result<()> {
    /// let conn = endpoint.connect("203.0.113.7:9000").await?.await?;
    /// # Ok(()) }
    /// ```
    ///
    /// The gap between the two is what [`Connecting::try_send`] is for: a
    /// message queued there travels with the handshake and reaches the peer a
    /// round trip before the connection is otherwise usable.
    ///
    /// The connection gets its own kernel socket, so it is unaffected by other
    /// traffic on this endpoint.
    ///
    /// # Errors
    ///
    /// Fails here if the address cannot be resolved or a socket cannot be
    /// bound. A handshake that never completes is reported by awaiting the
    /// [`Connecting`], as [`ErrorKind::TimedOut`].
    ///
    /// [`ErrorKind::TimedOut`]: std::io::ErrorKind::TimedOut
    pub async fn connect(&self, peer: impl ToSocketAddrs) -> io::Result<Connecting> {
        self.connect_inner(peer).await
    }

    async fn connect_inner(&self, peer: impl ToSocketAddrs) -> io::Result<Connecting> {
        let peer = resolve(peer).await?;
        let std_sock = std::net::UdpSocket::bind(outgoing_bind_addr(self.inner.local_addr, peer))?;
        std_sock.set_nonblocking(true)?;
        configure_udp_buffers(&std_sock, self.inner.cfg.mss);
        let socket = Arc::new(UdpSocket::from_std(std_sock)?);
        let local_addr = socket.local_addr()?;

        let conn = ProtoConnection::new_active(
            next_socket_id(),
            random_isn(),
            self.inner.cfg.mss,
            now_us(),
            self.inner.cfg.congestion,
        );
        let (send_tx, send_rx) = mpsc::channel::<SendReq>(SEND_BACKLOG);
        let (recv_tx, recv_rx) = flume::bounded::<Bytes>(RECV_BACKLOG);
        let (connected_tx, connected) = oneshot::channel::<()>();
        let shared = driver::Shared::default();
        tokio::spawn(driver::run_owned(
            conn,
            socket,
            peer,
            send_rx,
            recv_tx,
            Some(connected_tx),
            shared.clone(),
        ));

        Ok(Connecting {
            conn: Some(Connection {
                send_tx,
                recv_rx,
                peer_addr: peer,
                local_addr,
                reason: shared.reason,
                stats: shared.stats,
                max_unsegmented: shared.max_unsegmented,
            }),
            connected,
            gate: None,
        })
    }

    /// Connects to a peer that is calling this at the same time.
    ///
    /// Both sides must know each other's address in advance and dial
    /// simultaneously. Because the first packets cross in flight, each side
    /// punches a hole in its own firewall or NAT for the other, which lets two
    /// peers connect with no listener in between.
    ///
    /// Like [`connect`](Self::connect), this returns once the handshake is
    /// under way rather than once it has finished, so early data can be queued
    /// on the [`Connecting`] with [`try_send`](Connecting::try_send). Rendezvous
    /// sends a RESPONSE where the active role sends a conclusion, and early data
    /// rides that the same way.
    ///
    /// Awaiting it resolves to the established [`Connection`].
    ///
    /// # Errors
    ///
    /// Fails here if the address cannot be resolved. Awaiting the [`Connecting`]
    /// returns [`ErrorKind::TimedOut`] if the peer never appears.
    ///
    /// [`ErrorKind::TimedOut`]: std::io::ErrorKind::TimedOut
    pub async fn connect_rendezvous(&self, peer: impl ToSocketAddrs) -> io::Result<Connecting> {
        let peer = resolve(peer).await?;

        // One rendezvous handshake to a given peer at a time.
        //
        // Until a rendezvous peer has been told a socket id it addresses
        // handshakes to 0, so the only thing available to match one against is
        // the peer address. Two handshakes to the same address at the same time
        // are therefore indistinguishable, and both ends pair up wrongly: they
        // connect, and then data arrives on the wrong connection. Upstream has
        // the same hole -- `CRendezvousQueue::retrieve` scans by address with
        // `0 == id` as a wildcard -- and answers it by not supporting this.
        //
        // **This reduces the race but does not close it.** The two ends do not
        // finish together: if the local side completes and releases while the
        // peer is still finishing, the next handshake goes out and reaches a
        // peer whose address still maps to the connection just completed.
        // Driving two rendezvous pairs concurrently between one address pair
        // still fails roughly one run in five.
        //
        // Closing it properly needs the handshake to name which attempt it
        // belongs to, which the wire format has no field for. Until then,
        // establish rendezvous connections to a given peer one at a time.
        // Once established they carry real socket ids and route by them, so any
        // number can coexist on one address pair.
        let gate = {
            let mut locks = lock(&self.inner.rendezvous_locks);
            Arc::clone(locks.entry(peer).or_default())
        };
        // Owned, so it can travel in the `Connecting` and be released when the
        // handshake ends rather than when this call returns — which is now
        // before the handshake has even gone out. `lock_owned` consumes the
        // clone above, leaving the map's own reference the only other one.
        let held = gate.lock_owned().await;

        let conn = ProtoConnection::new_rendezvous(
            next_socket_id(),
            random_isn(),
            self.inner.cfg.mss,
            now_us(),
            self.inner.cfg.congestion,
        );
        let (socket, connected) = spawn_shared(&self.inner, conn, peer);
        Ok(Connecting {
            conn: Some(socket),
            connected,
            gate: Some(RendezvousGate { inner: Arc::clone(&self.inner), peer, held: Some(held) }),
        })
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
        let (accept_tx, accept_rx) = flume::bounded::<Connection>(backlog.max(1));
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

/// A rendezvous handshake's turn at a peer address, held for as long as the
/// handshake runs. See [`Endpoint::connect_rendezvous`] for what it protects.
///
/// It rides in the [`Connecting`] rather than in the call that started it,
/// because that call now returns the moment the handshake is under way. It is
/// released on completion, and on drop for a handshake abandoned before then.
pub(crate) struct RendezvousGate {
    inner: Arc<EndpointInner>,
    peer: SocketAddr,
    /// `None` once released. Owned rather than borrowed so it can outlive the
    /// call that took it.
    held: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for RendezvousGate {
    fn drop(&mut self) {
        // Release before counting, or our own reference keeps the count above
        // one and the entry is never collected.
        self.held = None;
        // Drop the entry once nobody else is waiting, so a long-lived endpoint
        // does not keep one per address it has ever dialled. Anyone already
        // queued holds an `Arc`, which keeps the count above one and leaves it
        // in place for them.
        let mut locks = lock(&self.inner.rendezvous_locks);
        if locks.get(&self.peer).is_some_and(|g| Arc::strong_count(g) == 1) {
            locks.remove(&self.peer);
        }
    }
}

/// Route `peer` to a new connection, start driving it, and hand back the
/// application's handle plus a signal for when the handshake completes.
///
/// The route is registered before the driver starts so that no reply can
/// arrive unrouted.
fn spawn_shared(
    ep: &Arc<EndpointInner>,
    conn: ProtoConnection,
    peer: SocketAddr,
) -> (Connection, oneshot::Receiver<()>) {
    let (datagram_tx, datagram_rx) = mpsc::channel::<Inbound>(DATAGRAM_BACKLOG);
    let (send_tx, send_rx) = mpsc::channel::<SendReq>(SEND_BACKLOG);
    let (recv_tx, recv_rx) = flume::bounded::<Bytes>(RECV_BACKLOG);
    let (connected_tx, connected) = oneshot::channel::<()>();

    let socket_id = conn.socket_id();
    if let Ok(mut routes) = ep.routes.write() {
        routes.insert(socket_id, peer, datagram_tx);
    }

    let udp = Arc::clone(&ep.socket);
    let owner = Arc::clone(ep);
    let shared = driver::Shared::default();
    // An accepted connection is already past its handshake, so the negotiated
    // size is known now and the driver will never emit `Connected` for it.
    if conn.is_connected() {
        let _ = shared.max_unsegmented.set(conn.max_unsegmented_len());
    }
    tokio::spawn(driver::run_shared(
        conn,
        udp,
        peer,
        datagram_rx,
        send_rx,
        recv_tx,
        Some(connected_tx),
        shared.clone(),
        move || owner.remove_route(socket_id, peer),
    ));

    let socket = Connection {
        send_tx,
        recv_rx,
        peer_addr: peer,
        local_addr: ep.local_addr,
        reason: shared.reason,
        stats: shared.stats,
        max_unsegmented: shared.max_unsegmented,
    };
    (socket, connected)
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
    let mut rx = RecvBuffers::new(&io);
    // Most datagrams belong to the same connection as the last; remembering
    // the previous route turns the hash lookup into an integer comparison.
    let mut cached: Option<(u32, mpsc::Sender<Inbound>)> = None;

    loop {
        let count = tokio::select! {
            result = io.recv_batch(&ep.socket, &mut rx.storage, &mut rx.metas) => match result {
                Ok(n) => n,
                // Every connection on this port depends on this task, so an
                // error about one departed peer must not end it.
                Err(e) if crate::util::is_transient(&e) => continue,
                Err(_) => return,
            },
            _ = ep.wind_down.notified() => {
                if ep.is_spent() { return; }
                continue;
            }
        };

        // Forwarded as they are read rather than accumulated first. Holding a
        // batch back delays the acknowledgements it would have produced, and
        // every connection on the port pays that: buffering up to 256
        // datagrams before dispatching any measured 28% slower across eight
        // connections.
        for i in 0..count {
            let from = rx.metas[i].addr;

            // A buffer can hold a run of datagrams coalesced by receive
            // offload; delivering it whole would hand the decoder a blob and
            // lose all but the first packet.
            //
            // Routing is per datagram, not per run. Coalescing groups by
            // address, and one address may hold several connections, so a run
            // can carry datagrams for different ones.
            let datagrams = rx.take_datagrams(i);
            let mut offered_handshake = false;
            for datagram in datagrams {
                let id = udt_proto::dst_socket_id(&datagram.bytes).unwrap_or(0);
                // Where it goes is `udt-proto`'s decision; this only carries
                // it there. The cache short-circuits the common case of a run
                // of datagrams for one connection.
                let mut fanout: Vec<mpsc::Sender<Inbound>> = Vec::new();
                let route = match &cached {
                    Some((cached_id, tx)) if id != 0 && *cached_id == id => Some(tx.clone()),
                    _ => match ep.routes.read() {
                        Ok(routes) => match routes.route(&datagram.bytes, &from) {
                            Route::Connection(tx) => {
                                cached = Some((id, tx.clone()));
                                Some(tx.clone())
                            }
                            Route::Unaddressed(list) => {
                                fanout.extend(list.iter().map(|(_, tx)| tx.clone()));
                                fanout.pop()
                            }
                            Route::Unknown => None,
                        },
                        Err(_) => None,
                    },
                };

                for extra in &fanout {
                    let _ = extra.try_send(datagram.clone());
                }
                match route {
                    Some(tx) => {
                        // Wait rather than drop when a connection's queue is
                        // full. Dropping looks right -- this task serves every
                        // connection on the port -- but a dropped datagram
                        // costs a retransmission round trip and under load that
                        // compounds: it measured 10x worse across eight
                        // connections, 530 MB/s against 4800. Real
                        // backpressure, reaching the peer through flow control,
                        // is cheaper than manufacturing loss.
                        if let Err(mpsc::error::TrySendError::Full(d)) = tx.try_send(datagram)
                            && tx.send(d).await.is_err()
                        {
                            break;
                        }
                    }
                    None => {
                        // Unknown destination: only a handshake can be
                        // legitimate. One per run, as before -- the rest wait
                        // for the peer to retransmit, which is what an opening
                        // connection does anyway, and it keeps a coalesced run
                        // from costing a handshake apiece.
                        if !offered_handshake {
                            offered_handshake = true;
                            handle_handshake(&ep, from, datagram.bytes).await;
                        }
                    }
                }
            }
        }

        if ep.is_spent() {
            return;
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

                // Already established, so the handshake signal is not needed.
                let (socket, _connected) = spawn_shared(ep, *conn, from);

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
