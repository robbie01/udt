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
//! let socket = endpoint.connect("203.0.113.7:9000").await?;
//!
//! socket.send(b"ping").await?;
//!
//! let mut buf = [0u8; 1500];
//! let n = socket.recv(&mut buf).await?;
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
//! while let Ok(socket) = listener.accept().await {
//!     tokio::spawn(async move {
//!         let mut buf = [0u8; 1500];
//!         while let Ok(n) = socket.recv(&mut buf).await {
//!             socket.send(&buf[..n]).await.ok();
//!         }
//!     });
//! }
//! # Ok(()) }
//! ```
//!
//! Two peers behind firewalls can also reach each other directly with
//! [`Endpoint::connect_rendezvous`], with no listener on either side.
//!
//! # Choosing message sizes
//!
//! Messages up to [`MAX_PAYLOAD_SIZE`] travel in one packet. Larger ones are
//! split and reassembled transparently, and sending in large messages rather
//! than many small ones is the single biggest throughput lever — a few hundred
//! kilobytes per `send` is a reasonable target for bulk transfer.
//!
//! # Feature flags
//!
//! * `tokio` *(enabled by default)* — the Tokio driver, everything documented
//!   here.
//!
//! [Tokio]: https://tokio.rs
//! [`send`]: Socket::send
//! [`recv`]: Socket::recv
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "tokio")]
mod batch;
#[cfg(feature = "tokio")]
mod tokio_impl;

#[cfg(feature = "tokio")]
pub use tokio_impl::{
    max_payload_for_mtu, Endpoint, EndpointConfig, Listener, SendOptions, Socket, DEFAULT_MTU,
    MAX_PAYLOAD_SIZE,
};

#[cfg(feature = "tokio")]
pub use udt_proto::CcKind;
