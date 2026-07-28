//! Connection state shared between the application and the IO tasks.
//!
//! The protocol state machine lives in a mutex that both sides reach into
//! directly. A `send` locks it, hands the payload to the state machine, and
//! takes away the datagrams that came back; a `recv` locks it and pulls a
//! message straight out of the reassembly buffer. Nothing copies application
//! data into a channel on the way past, and the two directions only contend
//! for the few microseconds either one holds the lock.
//!
//! Readiness travels the other way, as [`Notify`] wakeups: whoever advances
//! the state machine notifies whichever side that unblocked. Waiters use
//! tokio's register-then-check ordering ([`Notified::enable`]), so a wakeup
//! that lands between the check and the park is not lost.
//!
//! [`Notified::enable`]: tokio::sync::futures::Notified::enable

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::Notify;
use udt_proto::{Connection, DisconnectReason, Event, SendOutcome};

use crate::util::{Mutex, disconnect_err, lock, now_us};

/// Readiness signals for one connection.
///
/// Separate from [`State`] so a task can wait on one without holding the lock
/// that the task it is waiting for needs.
#[derive(Default)]
pub(crate) struct Shared {
    /// A message can be read.
    pub(crate) readable: Notify,
    /// The send buffer may have room, or has drained.
    pub(crate) writable: Notify,
    /// The handshake finished, or the connection failed.
    pub(crate) established: Notify,
    /// The driver has work: datagrams to write, or a deadline that moved.
    pub(crate) driver: Notify,
    /// Whether anyone is parked on `writable`.
    ///
    /// [`Notify::notify_waiters`] is not free — it takes an internal lock and
    /// walks a list — and the send buffer has room on all but a handful of the
    /// hundreds of thousands of acknowledgements a second a busy connection
    /// processes. This turns the common case into one relaxed atomic load.
    write_blocked: AtomicBool,
}

impl Shared {
    /// Announce that the send buffer may have room. Cheap when nobody cares.
    pub(crate) fn wake_writers(&self) {
        if self.write_blocked.swap(false, Ordering::AcqRel) {
            self.writable.notify_waiters();
        }
    }

    /// Called before checking whether a send can proceed, so that a wakeup
    /// arriving during the check is not lost.
    fn expect_writable(&self) {
        self.write_blocked.store(true, Ordering::Release);
    }
}

pub(crate) struct State {
    pub(crate) conn: Connection,
    /// Datagrams the state machine has produced and nobody has written yet.
    pub(crate) out: Vec<Bytes>,
    /// Scratch for [`Event`]s. Owned by the state so it keeps its capacity
    /// across calls instead of being reallocated per datagram.
    events: Vec<Event>,
    /// Set once the connection has ended; every later operation fails with it.
    pub(crate) error: Option<DisconnectReason>,
    pub(crate) connected: bool,
}

pub(crate) struct ConnectionInner {
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

impl ConnectionInner {
    pub(crate) fn new(conn: Connection) -> Arc<Self> {
        Arc::new(ConnectionInner {
            state: Mutex::new(State {
                conn,
                out: Vec::new(),
                events: Vec::new(),
                error: None,
                connected: false,
            }),
            shared: Shared::default(),
        })
    }
}

impl State {
    /// Turn the events the state machine just produced into queued datagrams
    /// and wakeups.
    ///
    /// Call after every entry into the state machine, with the lock still held.
    pub(crate) fn absorb(&mut self, shared: &Shared) {
        if self.events.is_empty() {
            return;
        }
        // Swapped out rather than drained in place so the loop can push to
        // `self.out`, and so the vector keeps its capacity.
        let mut events = std::mem::take(&mut self.events);
        let mut readable = false;
        for event in events.drain(..) {
            match event {
                Event::SendDatagram(datagram) => self.out.push(datagram),
                Event::DataReady => readable = true,
                Event::Connected => {
                    self.connected = true;
                    shared.established.notify_waiters();
                }
                Event::Disconnected(reason) => {
                    self.error.get_or_insert(reason);
                }
            }
        }
        self.events = events;

        if readable {
            shared.readable.notify_waiters();
        }
        if self.error.is_some() {
            // Nothing more will arrive, so release everyone rather than
            // leaving them parked until a timeout.
            shared.readable.notify_waiters();
            shared.writable.notify_waiters();
            shared.established.notify_waiters();
        }
    }

    /// Feed a run of datagrams to the state machine.
    ///
    /// The clock is read per datagram, not once for the batch. UDT estimates
    /// the path's capacity from how far apart probe packets arrive, so giving a
    /// whole batch one timestamp reports those probes as arriving together and
    /// collapses the estimate — with receive offload handing over 64 datagrams
    /// at a time, that throttled a 1 GB/s connection to 6 MB/s.
    pub(crate) fn feed<I: IntoIterator<Item = Bytes>>(&mut self, datagrams: I) {
        for datagram in datagrams {
            self.conn.on_datagram(datagram, now_us(), &mut self.events);
        }
    }

    pub(crate) fn on_timer(&mut self, now: u64) {
        self.conn.on_timer(now, &mut self.events);
    }

    /// The error to report to an application call, if the connection is over.
    ///
    /// Messages already reassembled stay readable after the peer closes, so
    /// this deliberately says nothing about whether data remains.
    fn app_error(&self) -> Option<io::Error> {
        self.error.map(disconnect_err)
    }
}

// ── Socket ────────────────────────────────────────────────────────────────────

/// An established UDT connection.
///
/// UDT is message-oriented: each [`send`](Self::send) arrives as exactly one
/// [`recv`](Self::recv) of the same length, never split or merged. In that
/// respect it behaves like a connected [`UdpSocket`], but delivery is reliable
/// and ordered by default.
///
/// Every method takes `&self`, so a socket can be shared between tasks through
/// an `Arc` — one sending while another receives is the expected pattern.
/// Concurrent receivers each get whole messages, but which task gets which is
/// unspecified.
///
/// Dropping the socket closes the connection once anything already sent has
/// been acknowledged.
///
/// [`UdpSocket`]: tokio::net::UdpSocket
pub struct Socket {
    pub(crate) inner: Arc<ConnectionInner>,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) local_addr: SocketAddr,
}

impl Socket {
    /// Sends a message, preserving order relative to earlier sends.
    ///
    /// Waits if the send buffer is full.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the connection has closed, or
    /// [`ErrorKind::InvalidInput`] if the message is larger than the send
    /// buffer can ever hold.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    /// [`ErrorKind::InvalidInput`]: std::io::ErrorKind::InvalidInput
    pub async fn send(&self, buf: &[u8]) -> io::Result<()> {
        self.send_bytes_with(Bytes::copy_from_slice(buf), SendOptions::new()).await
    }

    /// Sends a message with delivery options. See [`SendOptions`].
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send).
    pub async fn send_with(&self, buf: &[u8], opts: SendOptions) -> io::Result<()> {
        self.send_bytes_with(Bytes::copy_from_slice(buf), opts).await
    }

    /// Sends an owned buffer, avoiding a copy.
    ///
    /// Prefer this to [`send`](Self::send) when the payload is already
    /// [`Bytes`], such as a slice of a larger buffer.
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send).
    pub async fn send_bytes(&self, buf: Bytes) -> io::Result<()> {
        self.send_bytes_with(buf, SendOptions::new()).await
    }

    /// [`send_bytes`](Self::send_bytes) with the options of
    /// [`send_with`](Self::send_with).
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send).
    pub async fn send_bytes_with(&self, buf: Bytes, opts: SendOptions) -> io::Result<()> {
        loop {
            // Registered before the state is examined, so a wakeup arriving
            // while this task holds the lock is still delivered.
            let notified = self.inner.shared.writable.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.inner.shared.expect_writable();

            match self.try_queue(buf.clone(), opts)? {
                SendOutcome::Queued => return Ok(()),
                SendOutcome::WouldBlock => {}
                SendOutcome::Rejected => unreachable!("try_queue maps Rejected to an error"),
            }
            notified.await;
        }
    }

    /// Sends a message if the send buffer has room, without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::WouldBlock`] if the buffer is full, plus the
    /// errors of [`send`](Self::send).
    ///
    /// [`ErrorKind::WouldBlock`]: std::io::ErrorKind::WouldBlock
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
        match self.try_queue(Bytes::copy_from_slice(buf), opts)? {
            SendOutcome::Queued => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::WouldBlock, "send buffer full")),
        }
    }

    /// Hand one message to the state machine and wake the driver if it took it.
    fn try_queue(&self, payload: Bytes, opts: SendOptions) -> io::Result<SendOutcome> {
        let outcome = {
            let mut guard = lock(&self.inner.state);
            let state = &mut *guard;
            if let Some(e) = state.app_error() {
                return Err(e);
            }
            let outcome = state.conn.send_msg(
                payload,
                opts.ttl.map(|d| d.as_millis() as u32),
                !opts.unordered,
                now_us(),
                &mut state.events,
            );
            state.absorb(&self.inner.shared);
            outcome
        };
        match outcome {
            SendOutcome::Queued => {
                self.inner.shared.driver.notify_one();
                Ok(SendOutcome::Queued)
            }
            SendOutcome::WouldBlock => Ok(SendOutcome::WouldBlock),
            // Only returned for a message no buffer size could accept, or on a
            // connection that closed between the check above and here.
            SendOutcome::Rejected => {
                Err(self
                    .closed_or(io::Error::new(io::ErrorKind::InvalidInput, "message too large")))
            }
        }
    }

    fn closed_or(&self, otherwise: io::Error) -> io::Error {
        lock(&self.inner.state).app_error().unwrap_or(otherwise)
    }

    /// Receives the next message into `buf`, returning its length.
    ///
    /// A message longer than `buf` is truncated and the excess discarded, as
    /// with a datagram socket. Size the buffer for the largest message the
    /// peer will send, or use [`recv_bytes`](Self::recv_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the connection closed and no
    /// messages remain.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let msg = self.recv_bytes().await?;
        let n = msg.len().min(buf.len());
        buf[..n].copy_from_slice(&msg[..n]);
        Ok(n)
    }

    /// Receives the next message as an owned buffer, avoiding a copy.
    ///
    /// # Errors
    ///
    /// As [`recv`](Self::recv).
    pub async fn recv_bytes(&self) -> io::Result<Bytes> {
        loop {
            let notified = self.inner.shared.readable.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            match self.take_message()? {
                Some(msg) => return Ok(msg),
                None => notified.await,
            }
        }
    }

    /// Receives a message if one is ready, without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::WouldBlock`] if nothing is ready, plus the errors
    /// of [`recv`](Self::recv).
    ///
    /// [`ErrorKind::WouldBlock`]: std::io::ErrorKind::WouldBlock
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.take_message()? {
            Some(msg) => {
                let n = msg.len().min(buf.len());
                buf[..n].copy_from_slice(&msg[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "no message ready")),
        }
    }

    /// Take one reassembled message, or report why there is none.
    ///
    /// Messages that arrived before the peer closed stay readable afterwards,
    /// so the buffer is checked before the error.
    fn take_message(&self) -> io::Result<Option<Bytes>> {
        let mut guard = lock(&self.inner.state);
        match guard.conn.recv_msg() {
            Some(msg) => Ok(Some(msg)),
            None => match guard.app_error() {
                Some(e) => Err(e),
                None => Ok(None),
            },
        }
    }

    /// Waits until every message sent so far has been acknowledged.
    ///
    /// Messages sent after this call begins are not waited for.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the connection closes with data
    /// still unacknowledged.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub async fn flush(&self) -> io::Result<()> {
        loop {
            let notified = self.inner.shared.writable.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.inner.shared.expect_writable();
            {
                let state = lock(&self.inner.state);
                if state.conn.snd_buf_is_empty() {
                    return Ok(());
                }
                if let Some(e) = state.app_error() {
                    return Err(e);
                }
            }
            notified.await;
        }
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

impl Drop for Socket {
    fn drop(&mut self) {
        {
            let mut guard = lock(&self.inner.state);
            let state = &mut *guard;
            // Half-close rather than shutdown: a common pattern is to send and
            // immediately drop, and the data still has to reach the peer.
            state.conn.half_close(now_us(), &mut state.events);
            state.absorb(&self.inner.shared);
        }
        self.inner.shared.driver.notify_one();
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
    /// The peer is told to skip it and the connection carries on with the next
    /// message. Without a TTL a message is retried until it arrives or the
    /// connection fails.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Lets the peer deliver this message as soon as it is complete, without
    /// waiting for earlier messages still in flight.
    ///
    /// Worth using when messages are independent and latency matters more than
    /// order. The receiving application has to cope with them arriving out of
    /// sequence.
    pub fn unordered(mut self) -> Self {
        self.unordered = true;
        self
    }
}

/// Wait for the handshake to finish.
pub(crate) async fn wait_established(inner: &ConnectionInner) -> io::Result<()> {
    loop {
        let notified = inner.shared.established.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let state = lock(&inner.state);
            if state.connected {
                return Ok(());
            }
            if let Some(reason) = state.error {
                return Err(disconnect_err(reason));
            }
        }
        notified.await;
    }
}

/// Report a connection as failed from outside the state machine, e.g. when the
/// socket carrying it dies.
pub(crate) fn fail(inner: &ConnectionInner, reason: DisconnectReason) {
    let mut state = lock(&inner.state);
    state.error.get_or_insert(reason);
    inner.shared.readable.notify_waiters();
    inner.shared.writable.notify_waiters();
    inner.shared.established.notify_waiters();
}
