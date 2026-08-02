//! A UDT client and server for [Tokio].
//!
//! UDT is a reliable, message-oriented transport that runs over UDP. It keeps
//! a datagram API — every [`send`] arrives as exactly one [`recv`] of the same
//! length — while adding retransmission, ordering and congestion control, and
//! it is tuned for moving large amounts of data over links where TCP's
//! window growth is the bottleneck.
//!
//! Start from an [`Endpoint`], which owns a local address and can hold any
//! number of connections:
//!
//! ```no_run
//! use udt_async::Endpoint;
//!
//! # async fn client() -> std::io::Result<()> {
//! let endpoint = Endpoint::bind("0.0.0.0:0").await?;
//! let conn = endpoint.connect("203.0.113.7:9000").await?.await?;
//!
//! conn.send(b"ping").await?;
//!
//! let mut buf = [0u8; 1500];
//! let n = conn.recv(&mut buf).await?;
//! assert_eq!(&buf[..n], b"pong");
//! # Ok(()) }
//! ```
//!
//! Serving is the mirror image:
//!
//! ```no_run
//! use udt_async::Endpoint;
//!
//! # async fn server() -> std::io::Result<()> {
//! let endpoint = Endpoint::bind("0.0.0.0:9000").await?;
//! let mut listener = endpoint.listen(128)?;
//!
//! while let Ok(conn) = listener.accept().await {
//!     tokio::spawn(async move {
//!         let mut buf = [0u8; 1500];
//!         while let Ok(n) = conn.recv(&mut buf).await {
//!             conn.send(&buf[..n]).await.ok();
//!         }
//!     });
//! }
//! # Ok(()) }
//! ```
//!
//! Two peers behind firewalls can also reach each other directly with
//! [`Endpoint::connect_rendezvous`], with no listener on either side. It
//! returns the same [`Connecting`], so early data rides a rendezvous handshake
//! too — in both directions at once.
//!
//! # Choosing message sizes
//!
//! Messages up to [`MAX_PAYLOAD_SIZE`] travel in one packet. Larger ones are
//! split and reassembled transparently, and sending in large messages rather
//! than many small ones is the single biggest throughput lever — a few hundred
//! kilobytes per `send` is a reasonable target for bulk transfer.
//!
//! At those sizes the copy in and out of a `&[u8]` starts to matter, so every
//! send and receive has a `_bytes` form taking or returning an owned [`Bytes`]
//! instead: [`Connection::send_bytes`], [`Connection::recv_bytes`] and their
//! `try_` and `_with` variants. The three choices — waiting or not, borrowed or
//! owned, with delivery options or without — are independent, so all twelve
//! combinations exist.
//!
//! # Feature flags
//!
//! * `tokio` *(enabled by default)* — the Tokio driver, everything documented
//!   here.
//!
//! [Tokio]: https://tokio.rs
//! [`send`]: Connection::send
//! [`recv`]: Connection::recv
//! # Security
//!
//! UDT has no encryption and no authentication, and this crate adds none. On a
//! path an attacker can read, every byte is in the clear; on one they can write
//! to, they can forge data and control packets. Run a Noise handshake or
//! similar over it, and note that this protects the payload only — the
//! transport's own control packets sit beneath it, as they do under TLS.
//!
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod batch;
mod conn;
mod driver;
mod endpoint;
mod util;

/// The owned buffer the `_bytes` sends and receives use.
///
/// Re-exported because half the message API names it, and a caller should not
/// have to take a dependency on `bytes` — at a matching version — to use it.
pub use bytes::Bytes;
pub use conn::{Connecting, Connection, SendOptions};
pub use endpoint::{
    DEFAULT_MTU, Endpoint, EndpointConfig, Listener, MAX_PAYLOAD_SIZE, max_payload_for_mtu,
};
/// How many messages [`Connecting::try_send`] can hand to the handshake before
/// the rest are held for the established connection.
pub use udt_proto::MAX_EARLY_MESSAGES;

pub use udt_proto::CcKind;
/// A snapshot of protocol state — see [`Connection::stats`].
pub use udt_proto::ConnectionStats;
/// Why a connection ended — see [`Connection::disconnect_reason`].
pub use udt_proto::DisconnectReason;
