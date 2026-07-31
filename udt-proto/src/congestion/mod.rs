//! Congestion control.
//!
//! Every connection is paced by an implementation of [`CongestionControl`].
//! Pick one with [`CcKind`]. The default, [`CcKind::Cubic`], is what the rest
//! of the internet runs and shares a link predictably with it. Use
//! [`CcKind::LedbatPlusPlus`] for a transfer that should get out of other
//! traffic's way, and [`CcKind::Udt`] only where loss is frequent and the link
//! is not shared -- see its own note.
//!
//! Implementing the trait yourself is supported but the interface is not
//! stable — see the crate-level stability note.

pub mod cubic;
mod hystart;
pub mod ledbat;
#[cfg(test)]
mod sim;
pub mod udt_cc;

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
    /// estimate of the path's capacity.
    ///
    /// **Kept because it is UDT's own algorithm, not because it is a good
    /// choice.** A reimplementation of a protocol should be able to run that
    /// protocol's controller, and it is what to reach for when asking whether
    /// some behaviour is this crate's or the protocol's.
    ///
    /// It keeps a rate and a window and neither converges, and the clearest
    /// sign of that is what it does against a copy of itself: two `Udt` flows
    /// on one bottleneck split it **77/23**, measured on packets. Two `Cubic`
    /// flows split the same link 53/47. A controller that cannot share evenly
    /// with itself has no share to predict.
    ///
    /// It does lead `Cubic` on a lossy link with nothing else on it -- 40.8
    /// against 27.1 Mbit/s at 2% burst loss over 100 Mbit/50 ms -- because
    /// answering a drop with a 12.5% nudge to a rate recovers more gently than
    /// cutting a window by 30%. That is a narrow case to build on. Loss and an
    /// idle link rarely coincide: the paths that drop packets mostly drop them
    /// because something else is using them. And "nothing else is using this
    /// link" is not a property anyone can check and hold -- one competing
    /// download turns a link it had to itself into one it must share, and this
    /// controller has no defined answer to that.
    Udt,
    /// CUBIC (RFC 9438): one window, grown as a cubic function of the time
    /// since the last congestion event, with the send rate derived from it.
    /// What the rest of the internet runs, so its fairness is a known
    /// quantity. See [`cubic`].
    ///
    /// **The default.** It is the only controller here that converges to a
    /// share of a contended link: two CUBIC flows split a bottleneck 53/47 on
    /// real packets, where two [`Udt`](Self::Udt) flows split the same link
    /// 77/23.
    ///
    /// **Faster than [`Udt`](Self::Udt) on a clean link, slower on a lossy
    /// one, and how much slower depends heavily on what the loss looks like.**
    /// Measured over 5 MB on a bottleneck, six seeds, CUBIC against `Udt` in
    /// Mbit/s:
    ///
    /// | link | clean | 2% independent | 2% in bursts of 10 |
    /// |---|---|---|---|
    /// | 100 Mbit, 10 ms | 94.5 vs 93.9 | 8.2 vs 59.1 | 75.1 vs 85.8 |
    /// | 100 Mbit, 50 ms | 72.0 vs 58.0 | 2.0 vs 18.6 | 27.1 vs 40.8 |
    /// | 10 Mbit, 50 ms | 9.7 vs 7.2 | 1.9 vs 4.8 | **7.7 vs 6.2** |
    /// | 100 Mbit, 10 ms, 5 ms buffer | 65.1 vs 51.4 | 8.1 vs 39.4 | 29.0 vs 47.7 |
    ///
    /// The middle column is the one to distrust. Independent per-packet loss is
    /// the standard way to simulate a lossy link and it is close to the worst
    /// possible case for any loss-based controller, because it manufactures a
    /// separate congestion event out of every dropped packet. CUBIC reduces
    /// once per event; at 2% independent loss that is an event nearly every
    /// round trip, which puts it on the Mathis limit — about 4 Mbit/s at a
    /// 25 ms round trip, so the 2.0 there is the law being obeyed rather than
    /// broken.
    ///
    /// Real loss arrives in bursts. At the same 2% overall rate but in runs of
    /// ten, one burst is one congestion event, and most of the gap closes:
    /// nine times worse becomes one and a half times worse, and on the 10 Mbit
    /// link CUBIC comes out ahead.
    ///
    /// `Udt` still leads under loss because its response is a 12.5% nudge to a
    /// rate rather than a 30% cut to a window — the same choice that leaves it
    /// at 62% of a clean long fat pipe, and the reason it trails on every clean
    /// row above.
    ///
    /// Pick this for a path that is clean or whose loss comes in bursts, which
    /// is most real paths. Keep the default where loss is frequent and
    /// scattered, and measure rather than guessing which one you have:
    /// [`ConnectionStats::retransmit_fraction`] is what to measure it with.
    ///
    /// [`ConnectionStats::retransmit_fraction`]: crate::ConnectionStats::retransmit_fraction
    #[default]
    Cubic,
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
            CcKind::Cubic => Box::new(cubic::Cubic::new()),
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
