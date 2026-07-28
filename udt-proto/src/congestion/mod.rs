//! Congestion control.
//!
//! Every connection is paced by an implementation of [`CongestionControl`].
//! Pick one with [`CcKind`]; the default, [`CcKind::Udt`], is UDT's own
//! rate-based algorithm and is what you want unless the transfer should get
//! out of other traffic's way, in which case use [`CcKind::LedbatPlusPlus`].
//!
//! Implementing the trait yourself is supported but the interface is not
//! stable — see the crate-level stability note.

pub mod ledbat;
pub mod udt_cc;
#[cfg(test)]
mod sim;

use crate::seq::SeqNo;

/// What the connection knows about the path, passed to every callback.
#[derive(Debug, Clone, Copy)]
pub struct CcContext {
    /// Path MTU in bytes, as negotiated in the handshake.
    pub mss: u32,
    /// Estimated path capacity, in packets per second.
    pub bandwidth_pps: u32,
    /// Rate the peer reports receiving at, in packets per second.
    pub rcv_rate_pps: u32,
    /// Smoothed round-trip time, in microseconds.
    pub rtt_us: u32,
    /// Highest sequence number sent so far.
    pub snd_curr_seq: SeqNo,
    /// Packets sent but not yet acknowledged.
    ///
    /// Delay-based controllers need this to bound the window against what the
    /// application is actually using: with no queue to sense, nothing else stops
    /// the window growing without limit. See RFC 6817 §2.4.2 `ALLOWED_INCREASE`.
    pub flight_size: u32,
    /// Flow-control window advertised by the receiver, in packets.
    pub flow_wnd: f64,
    /// UDT's fixed 10 ms control interval, in microseconds.
    pub syn_interval_us: u32,
    /// The current time, on the same clock the connection is driven with.
    pub now_us: u64,
}

/// What a controller decides after an event.
#[derive(Debug, Clone, Copy)]
pub struct CcOutput {
    /// Gap to leave between packets, in microseconds. 0 sends as fast as the
    /// window allows.
    pub pkt_snd_period_us: f64,
    /// Congestion window, in packets.
    pub cwnd: f64,
    /// Overrides how often ACKs are sent, in milliseconds. `None` keeps the
    /// default 10 ms.
    pub ack_period_ms: Option<u32>,
    /// Sends one ACK every N packets instead of on a timer. `None` keeps the
    /// timer.
    pub ack_interval_pkts: Option<u32>,
    /// Overrides the retransmission timeout, in microseconds. `None` derives
    /// it from the measured RTT.
    pub rto_us: Option<u32>,
}

/// Which congestion controller a connection should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CcKind {
    /// UDT's own rate-based controller, which paces sends to a measured
    /// estimate of the path's capacity. Competes on roughly even terms with
    /// TCP and is the right default for a transfer that should go fast.
    #[default]
    Udt,
    /// A delay-based controller that treats growing queues as a signal to back
    /// off, so a transfer using it gets out of the way of interactive traffic
    /// on the same link and uses only what is left over. Suits backups,
    /// syncing and prefetching. See [`ledbat`].
    LedbatPlusPlus,
}

impl CcKind {
    /// Builds a fresh controller of this kind.
    pub fn build(self) -> Box<dyn CongestionControl> {
        match self {
            CcKind::Udt => Box::new(udt_cc::UdtCc::new()),
            CcKind::LedbatPlusPlus => Box::new(ledbat::Ledbat::new()),
        }
    }
}

/// A congestion control algorithm.
///
/// Each callback returns the controller's current decision; the connection
/// applies it immediately.
//
// There are deliberately no per-packet hooks. An earlier revision had
// `on_pkt_sent` / `on_pkt_received` with no-op defaults, but assembling a
// `CcContext` for them cost a bandwidth-median computation on every packet in
// both directions, for a result nothing consumed. Reintroduce such a hook only
// together with an algorithm that needs it, and gate the context construction
// on that need.
pub trait CongestionControl: Send + 'static {
    /// Called once when the connection is established.
    fn init(&mut self, ctx: CcContext) -> CcOutput;

    /// Called when the peer acknowledges data up to and including `ack_seq`.
    fn on_ack(&mut self, ack_seq: SeqNo, ctx: CcContext) -> CcOutput;

    /// Called when the peer reports missing packets, as inclusive sequence
    /// ranges. An empty slice means loss was inferred rather than reported.
    fn on_loss(&mut self, loss: &[(SeqNo, SeqNo)], ctx: CcContext) -> CcOutput;

    /// Called when the retransmission timer expires with nothing heard from
    /// the peer.
    fn on_timeout(&mut self, ctx: CcContext) -> CcOutput;
}
