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
//! Outgoing bytes and events travel separately. Datagrams are written into a
//! [`TransmitBuf`] you own and reuse, so the hot path allocates nothing; the
//! same calls append [`Event`]s to a `Vec` for the things that are not bytes,
//! such as [`Event::DataReady`], which means [`recv_msg`] has something.
//!
//! ```
//! use udt_proto::{CcKind, Connection, Event, SeqNo, TransmitBuf};
//!
//! # fn now_us() -> u64 { 0 }
//! # fn write_to_peer(_: &[u8], _segment_size: usize) {}
//! let mut conn = Connection::new_active(1, SeqNo::new(0), 1500, now_us(), CcKind::default());
//! let mut transmit = TransmitBuf::new();
//! let mut events = Vec::new();
//!
//! conn.on_timer(now_us(), &mut transmit, &mut events);
//!
//! // Equal-sized datagrams come back grouped, ready for a segmented write.
//! for (bytes, segment_size) in transmit.runs() {
//!     write_to_peer(bytes, segment_size);
//! }
//! transmit.clear();
//!
//! for event in events.drain(..) {
//!     if matches!(event, Event::DataReady) {
//!         while let Some(_message) = conn.recv_msg() {}
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

pub mod congestion;

/// Internals reachable by the fuzz targets.
///
/// Behind the `fuzzing` feature and hidden from the documentation: these are
/// implementation details with no stability promise whatsoever, exposed only so
/// that the code handling untrusted input can be fuzzed directly rather than
/// through several layers of state machine.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz {
    use bytes::{Bytes, BytesMut};

    pub use crate::codec::decode;
    use crate::packet::MsgBoundary;
    use crate::seq::{MsgNo, SeqNo};

    /// Builds a well-formed data packet addressed to `dst_socket_id`.
    ///
    /// A target driving the receive path needs sequence numbers it chooses:
    /// waiting for random bytes to land on a valid header and the right
    /// destination socket spends the whole budget getting to the code that
    /// matters.
    pub fn data_packet(
        dst_socket_id: u32,
        seq_no: SeqNo,
        msg_no: u32,
        boundary_bits: u32,
        in_order: bool,
        payload: &[u8],
    ) -> Bytes {
        let header = crate::codec::encode_data_header(
            seq_no,
            MsgBoundary::from_bits(boundary_bits),
            in_order,
            MsgNo::new(msg_no),
            0,
            dst_socket_id,
        );
        let mut buf = BytesMut::with_capacity(header.len() + payload.len());
        buf.extend_from_slice(&header);
        buf.extend_from_slice(payload);
        buf.freeze()
    }

    /// Builds a well-formed message-drop request, the other way a peer moves
    /// the receiver's sequence bookkeeping.
    pub fn msg_drop_packet(dst_socket_id: u32, msg_no: u32, first: SeqNo, last: SeqNo) -> Bytes {
        let mut buf = BytesMut::new();
        crate::codec::encode_msg_drop(MsgNo::new(msg_no), first, last, 0, dst_socket_id, &mut buf);
        buf.freeze()
    }
}

mod ack_window;
mod codec;

/// The destination socket id in a datagram, for demultiplexing before decode.
pub use codec::dst_socket_id;
mod connection;
mod handshake;
mod listener;
mod loss_list;
mod packet;
mod recv_buffer;
mod send_buffer;
mod seq;
mod time_window;
mod transmit;

pub use congestion::{CcKind, CongestionControl};
pub use connection::{
    ConnMode, Connection, ConnectionStats, DisconnectReason, Event, SendOutcome, UDT_HEADER_SIZE,
};
pub use listener::{Listener, ListenerEvent, PeerAddr};
pub use seq::{AckSeqNo, MSG_MAX, MsgNo, SEQ_MAX, SeqNo};
pub use transmit::{Runs, TransmitBuf};
