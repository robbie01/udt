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
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use udt_proto::{Connection, DisconnectReason, Event, SendOutcome, TransmitBuf};

use crate::batch::{BatchIo, Inbound};
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

/// The two things a driver publishes for its `Connection` to read.
///
/// Bundled because they are always created, cloned and passed together, and
/// threading them separately through both entry points pushed the argument
/// count past what is readable.
#[derive(Clone, Default)]
pub(crate) struct Shared {
    /// Why the connection ended, once it has.
    pub(crate) reason: Arc<OnceLock<DisconnectReason>>,
    /// Latest protocol state, republished each wakeup.
    pub(crate) stats: Arc<OnceLock<crate::util::Mutex<udt_proto::ConnectionStats>>>,
    /// Largest message that travels in one packet, once the handshake has
    /// settled it.
    ///
    /// Its own slot rather than a read of `stats`, because it is fixed for the
    /// connection's life and has to be readable the instant the application
    /// holds a handle. `stats` is republished on the driver's wakeups, so an
    /// accepted connection could be handed over before the first one and report
    /// nothing — which is what CI caught.
    pub(crate) max_unsegmented: Arc<OnceLock<usize>>,
}

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
    /// Set once the application's send channel is closed and drained.
    ///
    /// A closed `mpsc::Receiver` resolves to `None` immediately and for ever,
    /// so without this the arm that reads it stays permanently ready and the
    /// loop turns as fast as the thread allows for the whole wind-down --
    /// measured at 363,000 iterations a second, one core per connection, until
    /// the send buffer drains. `half_close` is idempotent but makes no progress
    /// after the first call, so re-running it only spins.
    send_closed: bool,
    /// A message the send buffer had no room for. While one is held the driver
    /// stops taking send requests, so backpressure reaches the application
    /// through its channel rather than data being dropped.
    blocked: Option<SendReq>,
    /// Resolved once the send buffer drains.
    pending_flush: Option<oneshot::Sender<()>>,
    /// What this driver reports back to its `Connection`.
    shared: Shared,
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
        shared: Shared,
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
            send_closed: false,
            blocked: None,
            pending_flush: None,
            shared,
            done: false,
        }
    }

    /// Republish protocol state where `Connection::stats` can read it.
    fn publish_stats(&self) {
        let snapshot = self.conn.stats();
        match self.shared.stats.get() {
            Some(m) => *crate::util::lock(m) = snapshot,
            None => {
                let _ = self.shared.stats.set(crate::util::Mutex::new(snapshot));
            }
        }
    }

    /// Write everything the state machine queued, then hand completed messages
    /// to the application.
    async fn flush(&mut self) {
        self.publish_stats();
        for event in self.events.drain(..) {
            match event {
                Event::DataReady => {}
                Event::Connected => {
                    let _ = self.shared.max_unsegmented.set(self.conn.max_unsegmented_len());
                    if let Some(tx) = self.connected_tx.take() {
                        let _ = tx.send(());
                    }
                }
                Event::Disconnected(reason) => {
                    debug_disconnect(&self.conn, reason);
                    // Recorded before the channels drop, so the application's
                    // next `send` or `recv` can say why rather than only that.
                    let _ = self.shared.reason.set(reason);
                    self.done = true;
                }
            }
        }

        if !self.tx.is_empty() {
            // A send can report an earlier datagram's ICMP response rather than
            // anything wrong here, so it is not on its own grounds to close.
            if let Err(e) = self.io.send_all(&self.socket, self.peer, &self.tx).await
                && !crate::util::is_transient(&e)
            {
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
                // Before the handshake finishes there is nothing to send on
                // yet, but there is a handshake packet to ride: `queue_early`
                // takes the message so it goes out beside one, a round trip
                // earlier than it otherwise could. It does not matter whether
                // the peer has answered already -- a message queued after that
                // rides the next retransmission -- so this needs no timing
                // luck. It refuses once the cap is reached, and then the
                // message is held like any that will not fit, to go out the
                // moment the connection completes.
                if !self.conn.is_connected() {
                    if self.conn.queue_early(payload.clone()) {
                        return;
                    }
                    self.blocked = Some(SendReq::Data { payload, ttl_ms, in_order });
                    return;
                }
                let outcome =
                    self.conn.send_msg(payload.clone(), ttl_ms, in_order, now_us(), &mut self.tx);
                match outcome {
                    SendOutcome::Queued => {}
                    SendOutcome::WouldBlock => {
                        self.blocked = Some(SendReq::Data { payload, ttl_ms, in_order });
                    }
                    // Unsendable however long we wait: the connection is
                    // closing, or the payload exceeds the send buffer entire.
                    // An empty message cannot reach here -- `Connection::send`
                    // refuses one at the boundary, where the caller can be
                    // told, because a refusal discarded here would look like
                    // success.
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

    /// Feed one arrival to the state machine, along with what the IP layer
    /// said about it.
    ///
    /// A CE mark means the path is congested, and the protocol cannot see IP
    /// headers, so it has to be told. The warning goes to the *peer* — the
    /// marking happened on the path carrying data to us, so it is the peer's
    /// rate that needs to come down.
    fn on_inbound(&mut self, datagram: Inbound) {
        // Only this connection's peer may drive it.
        //
        // A datagram is routed on the destination socket id alone, so anything
        // that can reach the port and name the id lands here -- no session
        // state, no sequence number, and no need to spoof a source address. A
        // 20-byte `Shutdown` was enough to tear down someone else's connection.
        //
        // The id is still the only secret, and unguessability is still what it
        // rests on. But requiring the address as well is what makes the
        // comparison with TCP honest: an off-path attacker there must guess a
        // window *and* forge an address that ingress filtering drops. Without
        // this, the address came free.
        //
        // The owned-socket driver always checked at its own recv; this is the same
        // rule for connections that share an endpoint's socket.
        if datagram.from != self.peer {
            return;
        }
        let now = now_us();
        if datagram.ce {
            self.conn.congestion_experienced(now, &mut self.tx);
        }
        self.conn.on_datagram(datagram.bytes, now, &mut self.tx, &mut self.events);
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

/// Drive a connection whose datagrams arrive from an endpoint's reader.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_shared(
    conn: Connection,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut datagrams: mpsc::Receiver<Inbound>,
    mut send_rx: mpsc::Receiver<SendReq>,
    recv_tx: flume::Sender<Bytes>,
    connected_tx: Option<oneshot::Sender<()>>,
    shared: Shared,
    on_exit: impl FnOnce(),
) {
    let Ok(io) = BatchIo::new(&socket) else {
        on_exit();
        return;
    };
    let mut d = Driver::new(conn, socket, peer, recv_tx, connected_tx, io, shared);

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
                d.on_inbound(first);
                // Take whatever else the reader has already queued, so a busy
                // connection costs one wakeup per batch rather than per packet.
                let mut taken = 1;
                while taken < RECV_DRAIN_CAP {
                    match datagrams.try_recv() {
                        Ok(datagram) => {
                            d.on_inbound(datagram);
                            taken += 1;
                        }
                        Err(_) => break,
                    }
                }
                d.run_due_timers();
            }
            req = send_rx.recv(), if d.blocked.is_none() && !d.send_closed => {
                match req {
                    Some(req) => {
                        d.handle_send(req);
                        d.drain_sends(&mut send_rx);
                    }
                    None => {
                        d.send_closed = true;
                        d.half_close();
                    }
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
