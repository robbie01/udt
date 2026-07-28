//! The UDT protocol as a pair of sans-IO state machines.
//!
//! This crate implements UDT — a reliable, message-oriented transport that
//! runs over UDP — without owning any sockets, threads, or clock. You feed it
//! datagrams and the current time; it hands back datagrams to send and events
//! to act on. That makes it usable from any async runtime, from a blocking
//! thread, or from a simulation with virtual time.
//!
//! **Most applications want [`udt-async`] instead**, which wires this crate up
//! to Tokio and presents an ordinary socket API. Reach for `udt-proto`
//! directly when you need to supply your own IO.
//!
//! # Driving a connection
//!
//! A [`Connection`] is one peer-to-peer association. Four calls drive it:
//!
//! * [`on_datagram`] for each UDP payload that arrives from the peer,
//! * [`on_timer`] whenever [`next_deadline_us`] comes due,
//! * [`send_msg`] to queue application data,
//! * [`recv_msg`] to take delivered messages out.
//!
//! The first two append [`Event`]s to a caller-owned `Vec`, reused across
//! calls to keep the hot path allocation-free. Handle
//! [`Event::SendDatagram`] by writing the bytes to the peer, and
//! [`Event::DataReady`] by draining `recv_msg`.
//!
//! ```
//! use udt_proto::{CcKind, Connection, Event, SeqNo};
//!
//! # fn now_us() -> u64 { 0 }
//! # fn write_to_peer(_: &[u8]) {}
//! let mut conn = Connection::new_active(1, SeqNo::new(0), 1500, now_us(), CcKind::Udt);
//!
//! let mut events = Vec::new();
//! conn.on_timer(now_us(), &mut events);
//! for event in events.drain(..) {
//!     if let Event::SendDatagram(datagram) = event {
//!         write_to_peer(&datagram);
//!     }
//! }
//! ```
//!
//! # Accepting connections
//!
//! A [`Listener`] answers handshakes on one address and yields a fully formed
//! [`Connection`] per accepted peer, through [`ListenerEvent::Accept`]. It is
//! a state machine on the same terms: datagrams and a clock in, events out.
//!
//! # Time
//!
//! Every entry point takes `now_us`, a monotonic microsecond count. Any origin
//! will do, as long as it never goes backwards and stays consistent for the
//! lifetime of a connection.
//!
//! # Stability
//!
//! This API is public so that alternative IO layers can be written against it,
//! but it is **not stable** and does not yet follow semantic versioning. Types
//! and signatures will change without a major version bump. Pin an exact
//! version if you depend on it.
//!
//! [`udt-async`]: https://docs.rs/udt-async
//! [`on_datagram`]: Connection::on_datagram
//! [`on_timer`]: Connection::on_timer
//! [`next_deadline_us`]: Connection::next_deadline_us
//! [`send_msg`]: Connection::send_msg
//! [`recv_msg`]: Connection::recv_msg
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod congestion;
pub mod prelude;

/// Internals reachable by the fuzz targets.
///
/// Behind the `fuzzing` feature and hidden from the documentation: these are
/// implementation details with no stability promise whatsoever, exposed only so
/// that the code handling untrusted input can be fuzzed directly rather than
/// through several layers of state machine.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz {
    pub use crate::codec::decode;
}

mod ack_window;
mod codec;
mod connection;
mod handshake;
mod listener;
mod loss_list;
mod packet;
mod recv_buffer;
mod send_buffer;
mod seq;
mod time_window;

pub use congestion::{CcKind, CongestionControl};
pub use connection::{
    ConnMode, Connection, ConnectionStats, DisconnectReason, Event, SendOutcome, UDT_HEADER_SIZE,
};
pub use listener::{Listener, ListenerEvent, PeerAddr};
pub use seq::{AckSeqNo, MSG_MAX, MsgNo, SEQ_MAX, SeqNo};
