//! The task that owns a connection.
//!
//! One driver per connection, and it is the only thing that touches the state
//! machine. The application reaches it over channels; datagrams reach it
//! either from its own socket or, for connections sharing an endpoint's port,
//! from that endpoint's reader.
//!
//! Owning the state outright rather than sharing it behind a lock is what lets
//! a connection's two directions overlap — the driver can be decoding a batch
//! of arrivals while the application is still copying the next message in. See
//! [`crate::conn`] for the measurements.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use udt_proto::{Connection, DisconnectReason, Event, SendOutcome, TransmitBuf};

use crate::batch::{BatchIo, RecvBuffers};
use crate::conn::SendReq;
use crate::util::now_us;

/// Datagrams taken per wakeup before returning to the event loop.
///
/// Draining in bulk amortises the `select!`'s timer arm and disarm over many
/// packets rather than paying it per packet. Counts datagrams, not receive
/// calls: with offload one buffer can hold 64 of them.
const RECV_DRAIN_CAP: usize = 64;

/// Send requests taken per wakeup.
///
/// Without this the `select!` runs a full round trip per message, which at
/// small message sizes is most of the cost of sending one.
const SEND_DRAIN_CAP: usize = 32;

/// How long the driver parks when the state machine wants no timer at all.
const IDLE_TICK: std::time::Duration = std::time::Duration::from_secs(30);

/// Everything a driver needs, whatever its datagrams arrive on.
struct Driver {
    conn: Connection,
    peer: SocketAddr,
    socket: Arc<UdpSocket>,
    io: BatchIo,
    tx: TransmitBuf,
    events: Vec<Event>,
    recv_tx: flume::Sender<Bytes>,
    /// Signals `connect` that the handshake finished.
    connected_tx: Option<oneshot::Sender<()>>,
    /// A message the send buffer had no room for. While one is held the driver
    /// stops taking send requests, so backpressure reaches the application
    /// through its channel rather than data being dropped.
    blocked: Option<SendReq>,
    /// Resolved once the send buffer drains.
    pending_flush: Option<oneshot::Sender<()>>,
    done: bool,
}

impl Driver {
    fn new(
        conn: Connection,
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        recv_tx: flume::Sender<Bytes>,
        connected_tx: Option<oneshot::Sender<()>>,
        io: BatchIo,
    ) -> Self {
        Driver {
            conn,
            peer,
            socket,
            io,
            tx: TransmitBuf::new(),
            events: Vec::new(),
            recv_tx,
            connected_tx,
            blocked: None,
            pending_flush: None,
            done: false,
        }
    }

    /// Write everything the state machine queued, then hand completed messages
    /// to the application.
    async fn flush(&mut self) {
        for event in self.events.drain(..) {
            match event {
                Event::DataReady => {}
                Event::Connected => {
                    if let Some(tx) = self.connected_tx.take() {
                        let _ = tx.send(());
                    }
                }
                Event::Disconnected(reason) => {
                    debug_disconnect(&self.conn, reason);
                    self.done = true;
                }
            }
        }

        if !self.tx.is_empty() {
            if self.io.send_all(&self.socket, self.peer, &self.tx).await.is_err() {
                self.done = true;
            }
            self.tx.clear();
        }

        // Always try to read: `DataReady` is edge-triggered, and a message can
        // become deliverable without one when an earlier gap is filled.
        while let Some(msg) = self.conn.recv_msg() {
            if self.recv_tx.send_async(msg).await.is_err() {
                // The application dropped its handle.
                self.conn.shutdown(now_us(), &mut self.tx, &mut self.events);
                self.done = true;
                break;
            }
        }

        // Acknowledgements may have freed the space a blocked message needs.
        if let Some(req) = self.blocked.take() {
            self.handle_send(req);
        }
        if let Some(notify) = self.pending_flush.take() {
            if self.conn.snd_buf_is_empty() && self.blocked.is_none() {
                let _ = notify.send(());
            } else {
                self.pending_flush = Some(notify);
            }
        }
    }

    /// Offer one request to the state machine, holding it back if it will not
    /// fit yet.
    fn handle_send(&mut self, req: SendReq) {
        match req {
            SendReq::Data { payload, ttl_ms, in_order } => {
                let outcome =
                    self.conn.send_msg(payload.clone(), ttl_ms, in_order, now_us(), &mut self.tx);
                match outcome {
                    SendOutcome::Queued => {}
                    SendOutcome::WouldBlock => {
                        self.blocked = Some(SendReq::Data { payload, ttl_ms, in_order });
                    }
                    // Unsendable however long we wait, and the connection is
                    // winding down anyway.
                    SendOutcome::Rejected => {}
                }
            }
            SendReq::Flush { notify } => self.pending_flush = Some(notify),
        }
    }

    /// Take up to a batch of send requests that are already queued.
    fn drain_sends(&mut self, send_rx: &mut mpsc::Receiver<SendReq>) {
        let mut taken = 1;
        while taken < SEND_DRAIN_CAP && self.blocked.is_none() {
            match send_rx.try_recv() {
                Ok(req) => {
                    self.handle_send(req);
                    taken += 1;
                }
                Err(_) => break,
            }
        }
    }

    /// Run the protocol timers if any is already due.
    ///
    /// Worth doing straight after arrivals rather than waiting for the sleep
    /// below to fire. Acknowledgements and the packets they unblock both come
    /// out of `on_timer`, and a tokio sleep resolves at millisecond
    /// granularity — so on a path whose round trip is 0.1 ms that put a
    /// millisecond of dead time in every feedback round, and slow start opened
    /// its window ten times slower than the link allowed.
    ///
    /// Gated on the deadline rather than run unconditionally: at a million
    /// packets a second the full timer path on every receive batch costs more
    /// than it saves.
    fn run_due_timers(&mut self) {
        let now = now_us();
        if self.conn.next_deadline_us().is_some_and(|due| due <= now) {
            self.conn.on_timer(now, &mut self.tx, &mut self.events);
        }
    }

    fn deadline(&self) -> tokio::time::Instant {
        let now_tokio = tokio::time::Instant::now();
        match self.conn.next_deadline_us() {
            None => now_tokio + IDLE_TICK,
            Some(deadline_us) => {
                let now = now_us();
                if deadline_us <= now {
                    now_tokio
                } else {
                    now_tokio + std::time::Duration::from_micros(deadline_us - now)
                }
            }
        }
    }

    /// Every application handle is gone: finish what is queued, then close.
    fn half_close(&mut self) {
        self.conn.half_close(now_us(), &mut self.tx, &mut self.events);
    }
}

/// Drive a connection that owns its socket, reading it as well as writing it.
pub(crate) async fn run_owned(
    conn: Connection,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut send_rx: mpsc::Receiver<SendReq>,
    recv_tx: flume::Sender<Bytes>,
    connected_tx: Option<oneshot::Sender<()>>,
) {
    let Ok(io) = BatchIo::new(&socket) else { return };
    let mut rx = RecvBuffers::new(&io);
    let mut d = Driver::new(conn, socket, peer, recv_tx, connected_tx, io);
    let mut inbound: Vec<Bytes> = Vec::new();

    // Send the opening handshake.
    d.conn.on_timer(now_us(), &mut d.tx, &mut d.events);

    loop {
        d.flush().await;
        if d.done {
            return;
        }
        let deadline = d.deadline();

        tokio::select! {
            result = d.io.recv_batch(&d.socket, &mut rx.storage, &mut rx.metas) => {
                let Ok(mut count) = result else { return };
                // One call may return several datagrams via recvmmsg, and each
                // buffer several more coalesced by receive offload. Where the
                // platform has neither, this loop keeps one wakeup from costing
                // one packet.
                loop {
                    for i in 0..count {
                        if rx.metas[i].addr != d.peer {
                            continue;
                        }
                        inbound.extend(rx.take_datagrams(i));
                    }
                    if inbound.len() >= RECV_DRAIN_CAP {
                        break;
                    }
                    match d.io.try_recv_batch(&d.socket, &mut rx.storage, &mut rx.metas) {
                        Ok(n) if n > 0 => count = n,
                        _ => break,
                    }
                }
                for datagram in inbound.drain(..) {
                    d.conn.on_datagram(datagram, now_us(), &mut d.tx, &mut d.events);
                }
                d.run_due_timers();
            }
            // Stop taking new work while a message waits for buffer space, so
            // the channel carries backpressure to the application.
            req = send_rx.recv(), if d.blocked.is_none() => {
                match req {
                    Some(req) => {
                        d.handle_send(req);
                        d.drain_sends(&mut send_rx);
                    }
                    None => d.half_close(),
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                d.conn.on_timer(now_us(), &mut d.tx, &mut d.events);
                debug_tick(&d.conn, "owned");
            }
        }
    }
}

/// Drive a connection whose datagrams arrive from an endpoint's reader.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_shared(
    conn: Connection,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut datagrams: mpsc::Receiver<Bytes>,
    mut send_rx: mpsc::Receiver<SendReq>,
    recv_tx: flume::Sender<Bytes>,
    connected_tx: Option<oneshot::Sender<()>>,
    on_exit: impl FnOnce(),
) {
    let Ok(io) = BatchIo::new(&socket) else {
        on_exit();
        return;
    };
    let mut d = Driver::new(conn, socket, peer, recv_tx, connected_tx, io);

    d.conn.on_timer(now_us(), &mut d.tx, &mut d.events);

    loop {
        d.flush().await;
        if d.done {
            break;
        }
        let deadline = d.deadline();

        tokio::select! {
            first = datagrams.recv() => {
                let Some(first) = first else { break };
                d.conn.on_datagram(first, now_us(), &mut d.tx, &mut d.events);
                // Take whatever else the reader has already queued, so a busy
                // connection costs one wakeup per batch rather than per packet.
                let mut taken = 1;
                while taken < RECV_DRAIN_CAP {
                    match datagrams.try_recv() {
                        Ok(datagram) => {
                            d.conn.on_datagram(datagram, now_us(), &mut d.tx, &mut d.events);
                            taken += 1;
                        }
                        Err(_) => break,
                    }
                }
                d.run_due_timers();
            }
            req = send_rx.recv(), if d.blocked.is_none() => {
                match req {
                    Some(req) => {
                        d.handle_send(req);
                        d.drain_sends(&mut send_rx);
                    }
                    None => d.half_close(),
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                d.conn.on_timer(now_us(), &mut d.tx, &mut d.events);
                debug_tick(&d.conn, "shared");
            }
        }
    }

    on_exit();
}

fn debug_enabled() -> bool {
    static ENABLED: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| std::env::var_os("UDT_DEBUG").is_some());
    *ENABLED
}

fn debug_disconnect(conn: &Connection, reason: DisconnectReason) {
    if debug_enabled() {
        eprintln!("[conn {}] disconnected: {reason:?} {:?}", conn.socket_id(), conn.stats());
    }
}

/// Periodic state dump, enabled by setting `UDT_DEBUG=1`. Compiled in but
/// inert unless the variable is set.
fn debug_tick(conn: &Connection, tag: &str) {
    if !debug_enabled() {
        return;
    }
    let stats = conn.stats();
    // Only report connections with outstanding work, or idle sockets drown out
    // the one that is actually stuck.
    let has_work = stats.snd_in_flight > 0
        || stats.snd_pending > 0
        || stats.snd_loss_len > 0
        || stats.rcv_loss_len > 0
        || !stats.connected;
    if has_work {
        eprintln!("[{tag}] {stats:?}");
    }
}
