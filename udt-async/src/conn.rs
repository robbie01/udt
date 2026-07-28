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
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::util::closed;

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

/// Send requests the application may queue before [`Socket::send`] waits.
pub(crate) const SEND_BACKLOG: usize = 256;

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
    pub(crate) send_tx: mpsc::Sender<SendReq>,
    pub(crate) recv_rx: flume::Receiver<Bytes>,
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
        self.send_tx.send(opts.into_req(buf)).await.map_err(|_| closed())
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
        let req = opts.into_req(Bytes::copy_from_slice(buf));
        self.send_tx.try_send(req).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "send queue full")
            }
            mpsc::error::TrySendError::Closed(_) => closed(),
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
        self.recv_rx.recv_async().await.map_err(|_| closed())
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
            Err(flume::TryRecvError::Disconnected) => Err(closed()),
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
        self.send_tx.send(SendReq::Flush { notify }).await.map_err(|_| closed())?;
        done.await.map_err(|_| closed())
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

    fn into_req(self, payload: Bytes) -> SendReq {
        SendReq::Data {
            payload,
            ttl_ms: self.ttl.map(|d| d.as_millis() as u32),
            in_order: !self.unordered,
        }
    }
}
