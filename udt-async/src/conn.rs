//! The application's handle on a connection.
//!
//! The protocol state machine is owned outright by the connection's driver
//! task, and this talks to it over channels. Nothing here touches it directly.
//!
//! That is deliberate, and it was measured both ways. Sharing the state behind
//! a mutex lets a send hand its payload straight to the state machine with no
//! channel in between, which is faster for a single connection — but the
//! driver's critical section is nearly all of its work, so every other task on
//! that connection blocks behind it and the two directions stop overlapping.
//! On Linux, with identical protocol tuning on both, that cost 35% at two
//! connections and 39% on a rendezvous pair, against a 20% gain on one.
//!
//! Application payloads still do not become an allocation per packet: the
//! state machine assembles its datagrams into a [`TransmitBuf`] the driver
//! owns and reuses.
//!
//! [`TransmitBuf`]: udt_proto::TransmitBuf

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use udt_proto::{ConnectionStats, DisconnectReason};

use crate::util::{Mutex, lock};

/// Work handed from the application to the driver.
pub(crate) enum SendReq {
    Data {
        payload: Bytes,
        ttl_ms: Option<u32>,
        in_order: bool,
    },
    /// Resolved once everything queued before it has been acknowledged.
    Flush {
        notify: oneshot::Sender<()>,
    },
}

/// Messages the driver may hold for the application before it stops taking
/// more off the network.
///
/// Once this fills, backpressure reaches the peer through the protocol's own
/// flow control, which is the mechanism meant to carry it.
pub(crate) const RECV_BACKLOG: usize = 256;

/// Send requests the application may queue before [`Connection::send`] waits.
pub(crate) const SEND_BACKLOG: usize = 256;

// ── Connection ────────────────────────────────────────────────────────────────────

/// An established UDT connection.
///
/// UDT is message-oriented: each [`send`](Self::send) arrives as exactly one
/// [`recv`](Self::recv) of the same length, never split or merged. In that
/// respect it behaves like a connected [`UdpSocket`], but delivery is reliable
/// and ordered by default.
///
/// Every method takes `&self`, so a connection can be shared between tasks through
/// an `Arc` — one sending while another receives is the expected pattern.
/// Concurrent receivers each get whole messages, but which task gets which is
/// unspecified.
///
/// Dropping it closes the connection once anything already sent has
/// been acknowledged.
///
/// [`UdpSocket`]: tokio::net::UdpSocket
pub struct Connection {
    pub(crate) send_tx: mpsc::Sender<SendReq>,
    pub(crate) recv_rx: flume::Receiver<Bytes>,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) local_addr: SocketAddr,
    /// Latest protocol state, republished by the driver as it runs.
    ///
    /// A mutex rather than a channel because a reader only ever wants the most
    /// recent value, and an unread channel would either grow or block the
    /// driver. Uncontended in practice: the driver writes once per wakeup and
    /// nothing reads it unless asked.
    pub(crate) stats: Arc<OnceLock<Mutex<ConnectionStats>>>,
    /// Why the connection ended, once it has.
    ///
    /// Written by the driver as it exits and read by every method that can
    /// report a closed connection. Without it all five causes arrive as one
    /// `BrokenPipe`, and an application cannot tell a peer closing cleanly from
    /// a path that will not carry its packets — which are opposite decisions:
    /// one says stop, the other says retry with a smaller MTU.
    pub(crate) reason: Arc<OnceLock<DisconnectReason>>,
    /// Largest message that travels in one packet, fixed once the handshake
    /// settles it. Its own slot rather than a field of `stats`, which is only
    /// republished on driver wakeups and so can be absent when a freshly
    /// accepted connection is handed over.
    pub(crate) max_unsegmented: Arc<OnceLock<usize>>,
}

/// Refuse an empty message before it is queued.
///
/// The protocol refuses one too, but a `send` here hands the request to the
/// driver and returns, so a refusal made there would be discarded and the
/// caller would still be told the message was on its way. Caught at the
/// boundary, where it can be reported.
///
/// Refused rather than carried because a message surfaces through
/// `recv(&mut buf) -> usize`, and zero there is how such an API says the
/// connection is done — an empty message would be indistinguishable from one.
fn empty_check(buf: &[u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an empty message cannot be sent; a zero-length recv means the connection closed",
        ));
    }
    Ok(())
}

/// Turn a recorded reason into the error a caller sees.
///
/// The kinds are a coarse hint for code that matches on them; the precise
/// answer is [`Connection::disconnect_reason`], which loses nothing.
pub(crate) fn closed_with(reason: Option<DisconnectReason>) -> io::Error {
    let (kind, msg) = match reason {
        Some(DisconnectReason::Shutdown) => {
            (io::ErrorKind::ConnectionAborted, "peer closed the connection")
        }
        Some(DisconnectReason::LocalClose) => {
            (io::ErrorKind::BrokenPipe, "connection closed locally")
        }
        Some(DisconnectReason::Timeout) => (io::ErrorKind::TimedOut, "peer stopped responding"),
        Some(DisconnectReason::PeerError) => {
            (io::ErrorKind::InvalidData, "peer sent something unusable, or rejected the handshake")
        }
        Some(DisconnectReason::PathMtu) => (
            io::ErrorKind::Other,
            "the path did not carry any full-size packet, though the peer answered — \
             retry with a smaller MTU",
        ),
        None => (io::ErrorKind::BrokenPipe, "connection closed"),
    };
    io::Error::new(kind, msg)
}

impl Connection {
    /// Why the connection ended, or `None` while it is still up.
    ///
    /// The errors returned by [`send`](Self::send) and [`recv`](Self::recv)
    /// carry a matching [`io::ErrorKind`], but several causes have no exact kind
    /// and this does not lose them. [`DisconnectReason::PathMtu`] in particular
    /// is worth acting on: the peer is reachable and the path will carry a
    /// smaller packet, so reconnecting with a lower
    /// [`EndpointConfig::mtu`](crate::EndpointConfig::mtu) is likely to work
    /// where retrying unchanged will not.
    pub fn disconnect_reason(&self) -> Option<DisconnectReason> {
        self.reason.get().copied()
    }

    /// A snapshot of the connection's protocol state.
    ///
    /// Round-trip estimate, congestion window, what is in flight, what is
    /// waiting to be retransmitted. `None` once the connection has closed.
    ///
    /// For logging and diagnosis, not for control: the field set follows
    /// whatever the protocol happens to track and is not stable.
    pub fn stats(&self) -> Option<ConnectionStats> {
        self.stats.get().map(|s| *lock(s))
    }

    /// Largest message that still travels in one packet, in bytes.
    ///
    /// Longer messages are split and reassembled by the peer, so this is not a
    /// limit — but a message a few bytes over it costs a whole second packet,
    /// so a sender that controls its own framing usually wants to stay under
    /// it.
    ///
    /// This is the value the two ends negotiated, which may be smaller than
    /// [`MAX_PAYLOAD_SIZE`] if the peer offered a lower MTU. Prefer it to that
    /// constant, which only describes the default MTU and this end of the
    /// connection. `None` before the handshake has settled.
    ///
    /// [`MAX_PAYLOAD_SIZE`]: crate::MAX_PAYLOAD_SIZE
    pub fn max_unsegmented_len(&self) -> Option<usize> {
        self.max_unsegmented.get().copied()
    }

    fn closed(&self) -> io::Error {
        closed_with(self.disconnect_reason())
    }

    /// Sends a message, preserving order relative to earlier sends.
    ///
    /// Waits if the send buffer is full.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the connection has closed.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
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
        empty_check(&buf)?;
        self.send_tx.send(opts.into_req(buf)).await.map_err(|_| self.closed())
    }

    /// Sends a message if there is room to queue it, without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::WouldBlock`] if there is not, or
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
        empty_check(buf)?;
        let req = opts.into_req(Bytes::copy_from_slice(buf));
        self.send_tx.try_send(req).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "send queue full")
            }
            mpsc::error::TrySendError::Closed(_) => self.closed(),
        })
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
        Ok(copy_into(&msg, buf))
    }

    /// Receives the next message as an owned buffer, avoiding a copy.
    ///
    /// # Errors
    ///
    /// As [`recv`](Self::recv).
    pub async fn recv_bytes(&self) -> io::Result<Bytes> {
        self.recv_rx.recv_async().await.map_err(|_| self.closed())
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
        match self.recv_rx.try_recv() {
            Ok(msg) => Ok(copy_into(&msg, buf)),
            Err(flume::TryRecvError::Empty) => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no message ready"))
            }
            Err(flume::TryRecvError::Disconnected) => Err(self.closed()),
        }
    }

    /// Waits until every message sent so far has been acknowledged.
    ///
    /// Messages sent after this call begins are not waited for.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BrokenPipe`] if the connection closes first.
    ///
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    pub async fn flush(&self) -> io::Result<()> {
        let (notify, done) = oneshot::channel();
        self.send_tx.send(SendReq::Flush { notify }).await.map_err(|_| self.closed())?;
        done.await.map_err(|_| self.closed())
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

fn copy_into(msg: &[u8], buf: &mut [u8]) -> usize {
    let n = msg.len().min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    n
}

// ── Send options ──────────────────────────────────────────────────────────────

/// Per-message delivery options for [`Connection::send_with`].
///
/// The default is reliable, ordered delivery, the same as [`Connection::send`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SendOptions {
    ttl: Option<Duration>,
    unordered: bool,
    best_effort: bool,
}

impl SendOptions {
    /// Reliable, ordered delivery.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sends the message once and never retries it.
    ///
    /// It goes out at the moment it is queued and is abandoned immediately
    /// after; the peer is told to skip it rather than left waiting, so a loss
    /// costs nothing and holds nothing else up. Ordered delivery of later
    /// messages is unaffected.
    ///
    /// This is the unreliable-datagram case: telemetry, position updates,
    /// anything where a fresher message is on the way and a stale one is not
    /// worth a round trip. If the send window has no room at that instant the
    /// message is dropped without going out at all, which is what best effort
    /// means.
    ///
    /// Overrides [`ttl`](Self::ttl) if both are set.
    pub fn best_effort(mut self) -> Self {
        self.best_effort = true;
        self
    }

    /// Gives up on the message if it has not been delivered within `ttl`.
    ///
    /// The peer is told to skip it and the connection carries on with the next
    /// message. Without a TTL a message is retried until it arrives or the
    /// connection fails.
    ///
    /// Resolution is one millisecond, and that is a floor rather than a round:
    /// a shorter deadline is treated as one millisecond. Zero is not reachable
    /// here on purpose, because it does not mean "no time" — it means send once
    /// and never retry, which [`best_effort`](Self::best_effort) asks for by
    /// name.
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

    fn into_req(self, payload: Bytes) -> SendReq {
        SendReq::Data {
            payload,
            // Clamped, not truncated. `as_millis() as u32` gets both ends
            // wrong: anything under a millisecond becomes 0, which the protocol
            // reads as "expire as soon as any time has passed" -- so asking for
            // a 500 us deadline dropped the message almost immediately instead
            // of trying hard and briefly. And anything past about 49 days
            // wrapped, which could turn a very long deadline into a very short
            // one. Both were silent.
            ttl_ms: if self.best_effort {
                // Zero is not "no deadline": it expires as soon as any time has
                // passed, and the only transmission happens before that. Hence
                // send-once.
                Some(0)
            } else {
                self.ttl.map(|d| d.as_millis().clamp(1, u32::MAX as u128) as u32)
            },
            in_order: !self.unordered,
        }
    }
}

/// A connection whose handshake is still in flight.
///
/// Returned by [`Endpoint::connect`], and a `Future` yielding the established
/// [`Connection`]. The point of holding it rather than awaiting straight away
/// is [`try_send`](Self::try_send): a message queued before the handshake
/// finishes travels *with* it and reaches the peer a round trip earlier than
/// anything sent afterwards could.
///
/// ```no_run
/// # async fn f(endpoint: udt_async::Endpoint, msg1: &[u8]) -> std::io::Result<()> {
/// let connecting = endpoint.connect("203.0.113.7:9000").await?;
/// connecting.try_send(msg1)?;
/// let conn = connecting.await?;
/// # Ok(()) }
/// ```
///
/// [`Endpoint::connect`]: crate::Endpoint::connect
pub struct Connecting {
    pub(crate) conn: Option<Connection>,
    pub(crate) connected: oneshot::Receiver<()>,
    /// A rendezvous handshake's turn at the peer address, released as soon as
    /// this settles. `None` for every other kind of connect, which needs no
    /// turn. See [`Endpoint::connect_rendezvous`](crate::Endpoint::connect_rendezvous).
    pub(crate) gate: Option<crate::endpoint::RendezvousGate>,
}

impl Connecting {
    /// Queues a message to travel with the handshake.
    ///
    /// Any number may be queued, up to what the opening congestion window can
    /// carry; past that they are held and go out the moment the connection
    /// completes, which is what would have happened to all of them anyway.
    /// Ordering is preserved throughout — a message queued here arrives before
    /// anything sent on the established connection.
    ///
    /// Not `async`, and deliberately: the only thing waiting could buy is room
    /// in the send window, and that is freed by acknowledgements, which cannot
    /// arrive until the handshake this is racing has finished. There is no
    /// `try_recv` for the mirror of that reason — the peer has nothing to say
    /// until it has accepted.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::WouldBlock`] if the queue is full, [`ErrorKind::BrokenPipe`]
    /// if the handshake has already failed, and [`ErrorKind::InvalidInput`] for
    /// an empty message.
    ///
    /// [`ErrorKind::WouldBlock`]: std::io::ErrorKind::WouldBlock
    /// [`ErrorKind::BrokenPipe`]: std::io::ErrorKind::BrokenPipe
    /// [`ErrorKind::InvalidInput`]: std::io::ErrorKind::InvalidInput
    pub fn try_send(&self, buf: &[u8]) -> io::Result<()> {
        self.try_send_with(buf, SendOptions::new())
    }

    /// [`try_send`](Self::try_send) with the options of
    /// [`Connection::send_with`].
    ///
    /// # Errors
    ///
    /// As [`try_send`](Self::try_send).
    pub fn try_send_with(&self, buf: &[u8], opts: SendOptions) -> io::Result<()> {
        self.conn.as_ref().expect("polled to completion").try_send_with(buf, opts)
    }

    /// The address being connected to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.conn.as_ref().expect("polled to completion").peer_addr()
    }
}

impl std::future::Future for Connecting {
    type Output = io::Result<Connection>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.connected).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                // Settled, so any turn taken to get here is over. Released
                // now rather than left to the drop, so the next rendezvous to
                // this peer starts without waiting on what the caller does
                // with the value it has just been handed.
                self.gate = None;
                let conn = self.conn.take().expect("polled after completion");
                Poll::Ready(Ok(conn))
            }
            Poll::Ready(Err(_)) => {
                self.gate = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connect handshake failed",
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ttl_of(req: SendReq) -> Option<u32> {
        match req {
            SendReq::Data { ttl_ms, .. } => ttl_ms,
            _ => panic!("expected a data request"),
        }
    }

    /// A deadline shorter than the wire's resolution must not become zero.
    ///
    /// Zero is a real value to the protocol — expire as soon as any time has
    /// passed — so truncating a sub-millisecond deadline to it inverts what the
    /// caller asked for, turning "try hard, briefly" into "drop at once".
    #[test]
    fn a_sub_millisecond_ttl_does_not_become_zero() {
        for micros in [1u64, 100, 500, 999] {
            let got = ttl_of(
                SendOptions::new().ttl(Duration::from_micros(micros)).into_req(Bytes::new()),
            );
            assert_eq!(got, Some(1), "{micros}us became {got:?}");
        }
    }

    /// And a deadline past what the field holds must not wrap into a short one.
    #[test]
    fn an_enormous_ttl_saturates_rather_than_wrapping() {
        let got = ttl_of(
            SendOptions::new().ttl(Duration::from_secs(60 * 60 * 24 * 365)).into_req(Bytes::new()),
        );
        assert_eq!(got, Some(u32::MAX));
    }

    #[test]
    fn a_millisecond_or_more_is_carried_as_given() {
        let got = ttl_of(SendOptions::new().ttl(Duration::from_millis(250)).into_req(Bytes::new()));
        assert_eq!(got, Some(250));
    }

    #[test]
    fn best_effort_asks_for_send_once() {
        assert_eq!(ttl_of(SendOptions::new().best_effort().into_req(Bytes::new())), Some(0));
        // And it is not reachable by accident from a very short duration.
        assert_eq!(ttl_of(SendOptions::new().ttl(Duration::ZERO).into_req(Bytes::new())), Some(1));
    }

    #[test]
    fn no_ttl_stays_none() {
        assert_eq!(ttl_of(SendOptions::new().into_req(Bytes::new())), None);
    }
}
