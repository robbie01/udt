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

const DEFAULT_MSS: u32 = 1472;

// ── Send request (application → driver) ──────────────────────────────────────

struct SendReq {
    payload: Bytes,
    ttl_ms: Option<u32>,
    in_order: bool,
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
    socket: Arc<UdpSocket>,
}

impl Endpoint {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_sock)?;
        Ok(Endpoint { socket: Arc::new(socket) })
    }

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
        let conn = Connection::new_active(socket_id, isn, DEFAULT_MSS, now_us());

        tokio::spawn(run_conn_driver(udp, conn, peer, None, send_rx, recv_tx, Some(connected_tx)));

        connected_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect handshake timed out"))?;

        Ok(Socket { send_tx, recv_rx, peer_addr: peer, local_addr })
    }

    pub async fn connect_rendezvous(&self, peer: SocketAddr) -> io::Result<Socket> {
        let local_addr = self.socket.local_addr()?;
        let (send_tx, send_rx) = mpsc::channel::<SendReq>(64);
        let (recv_tx, recv_rx) = mpsc::channel::<Bytes>(64);
        let (connected_tx, connected_rx) = oneshot::channel::<()>();

        let socket_id = next_socket_id();
        let isn = SeqNo::new(rand::random::<u32>() & 0x7FFF_FFFF);
        let conn = Connection::new_rendezvous(socket_id, isn, DEFAULT_MSS, now_us());

        tokio::spawn(run_conn_driver(
            Arc::clone(&self.socket),
            conn,
            peer,
            None,
            send_rx,
            recv_tx,
            Some(connected_tx),
        ));

        connected_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "rendezvous timed out"))?;

        Ok(Socket { send_tx, recv_rx, peer_addr: peer, local_addr })
    }

    pub fn listen(&self, backlog: usize) -> io::Result<Listener> {
        let socket = Arc::clone(&self.socket);
        let local_addr = socket.local_addr()?;
        let (accept_tx, accept_rx) = mpsc::channel::<Socket>(backlog.max(1));
        let secret: u64 = rand::random();
        tokio::spawn(run_listener_driver(socket, accept_tx, secret));
        Ok(Listener { accept_rx, local_addr })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

// ── Connection driver (shared for active + accepted connections) ──────────────

// For accepted connections: datagram_rx = Some(channel from listener).
// For active connections: datagram_rx = None (reads directly from socket filtered by peer_addr).
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

    // Trigger initial handshake or keepalive.
    conn.on_timer(now_us(), &mut out);

    loop {
        // ── Process accumulated outputs ──────────────────────────────────────
        // Use mem::take to handle cases where processing an output (e.g. shutdown)
        // pushes new outputs to `out`.
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
                                // Receiver dropped — shut down.
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
        // Flush any SendDatagrams that arrived after a Disconnected.
        for leftover in std::mem::take(&mut out) {
            if let Output::SendDatagram(bytes) = leftover {
                let _ = socket.send_to(&bytes, peer_addr).await;
            }
        }
        if done { return; }

        // ── Wait for next event ───────────────────────────────────────────────
        let deadline = deadline_instant(&conn);

        if let Some(ref mut drx) = datagram_rx {
            // Accepted connection: receive forwarded datagrams from the listener task.
            tokio::select! {
                maybe = drx.recv() => {
                    match maybe {
                        Some(bytes) => {
                            conn.on_datagram(bytes, now_us(), &mut out);
                        }
                        None => {
                            return; // listener dropped us
                        }
                    }
                }
                maybe_req = send_rx.recv() => {
                    match maybe_req {
                        Some(req) => conn.send_msg(&req.payload, req.ttl_ms, req.in_order, now_us(), &mut out),
                        None => conn.shutdown(now_us(), &mut out),
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    conn.on_timer(now_us(), &mut out);
                }
            }
        } else {
            // Active connection: receive directly from the shared socket.
            tokio::select! {
                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((n, from)) if from == peer_addr => {
                            let bytes = Bytes::copy_from_slice(&recv_buf[..n]);
                            conn.on_datagram(bytes, now_us(), &mut out);
                        }
                        Ok(_) => {} // stray packet from other source; re-loop
                        Err(_) => return,
                    }
                }
                maybe_req = send_rx.recv() => {
                    match maybe_req {
                        Some(req) => conn.send_msg(&req.payload, req.ttl_ms, req.in_order, now_us(), &mut out),
                        None => conn.shutdown(now_us(), &mut out),
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    conn.on_timer(now_us(), &mut out);
                }
            }
        }
    }
}

// ── Listener driver ───────────────────────────────────────────────────────────

async fn run_listener_driver(
    socket: Arc<UdpSocket>,
    accept_tx: mpsc::Sender<Socket>,
    secret: u64,
) {
    let local_addr = match socket.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };
    let mut listener = ListenerState::new(next_socket_id(), DEFAULT_MSS, now_us(), secret);
    let mut peers: HashMap<SocketAddr, mpsc::Sender<Bytes>> = HashMap::new();
    let mut out: Vec<ListenerOutput> = Vec::new();
    let mut recv_buf = vec![0u8; 65536];

    loop {
        let (n, from) = match socket.recv_from(&mut recv_buf).await {
            Ok(r) => r,
            Err(_) => return,
        };
        let bytes = Bytes::copy_from_slice(&recv_buf[..n]);

        // If we already have an established connection for this peer, forward.
        if let Some(conn_tx) = peers.get(&from) {
            if conn_tx.send(bytes).await.is_err() {
                peers.remove(&from);
            }
            continue;
        }

        // Otherwise let the listener state machine handle the handshake.
        let peer_addr = sockaddr_to_peer_addr(from);
        listener.on_datagram(peer_addr, bytes, now_us(), &mut out);

        for item in out.drain(..) {
            match item {
                ListenerOutput::SendTo { data, .. } => {
                    let _ = socket.send_to(&data, from).await;
                }
                ListenerOutput::Accept(conn, _pa) => {
                    let (datagram_tx, datagram_rx) = mpsc::channel::<Bytes>(64);
                    let (send_tx, send_rx) = mpsc::channel::<SendReq>(64);
                    let (recv_tx, recv_rx) = mpsc::channel::<Bytes>(64);

                    peers.insert(from, datagram_tx);

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
                        return; // Listener was dropped
                    }
                }
            }
        }
    }
}
