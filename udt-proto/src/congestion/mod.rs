pub mod udt_cc;
pub mod ledbat;

use crate::seq::SeqNo;

/// Context passed to every CC callback.
#[derive(Debug, Clone, Copy)]
pub struct CcContext {
    pub mss: u32,
    pub bandwidth_pps: u32,
    pub rcv_rate_pps: u32,
    pub rtt_us: u32,
    pub snd_curr_seq: SeqNo,
    /// Flow window size (packets), advertised by the receiver.
    pub flow_wnd: f64,
    /// SYN interval (µs) = 10_000.
    pub syn_interval_us: u32,
    pub now_us: u64,
}

/// Output from a CC decision.
#[derive(Debug, Clone, Copy)]
pub struct CcOutput {
    /// Inter-packet sending period (µs). 0 means "send as fast as possible".
    pub pkt_snd_period_us: f64,
    /// Congestion window size (packets).
    pub cwnd: f64,
    /// Override ACK timer period (ms). None = use default.
    pub ack_period_ms: Option<u32>,
    /// Send one ACK every N packets instead of on a timer. None = use timer.
    pub ack_interval_pkts: Option<u32>,
    /// Override RTO (µs). None = compute from RTT.
    pub rto_us: Option<u32>,
}

/// Which congestion controller a connection should use.
///
/// Exists because a `Box<dyn CongestionControl>` cannot be cloned, while a
/// listener needs to build a fresh controller per accepted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CcKind {
    /// UDT's native rate-based DAIMD controller. The default, and the only one
    /// that is wire-behaviour-compatible with the C++ reference.
    #[default]
    Udt,
    /// LEDBAT++, a delay-based "scavenger" that yields to competing traffic.
    /// Appropriate for background transfers. See [`ledbat`].
    LedbatPlusPlus,
}

impl CcKind {
    pub fn build(self) -> Box<dyn CongestionControl> {
        match self {
            CcKind::Udt => Box::new(udt_cc::UdtCc::new()),
            CcKind::LedbatPlusPlus => Box::new(ledbat::Ledbat::new()),
        }
    }
}

/// Pluggable congestion control algorithm.
///
/// Note there are deliberately no per-packet hooks. Earlier revisions had
/// `on_pkt_sent` / `on_pkt_received` with no-op defaults, but building a
/// [`CcContext`] for them cost a bandwidth-median computation on every packet
/// in both directions — for a result that was then discarded, since no
/// implementation overrode them. Add such a hook back only alongside an
/// algorithm that needs it, and gate the context construction on that need.
pub trait CongestionControl: Send + 'static {
    fn init(&mut self, ctx: CcContext) -> CcOutput;
    fn on_ack(&mut self, ack_seq: SeqNo, ctx: CcContext) -> CcOutput;
    fn on_loss(&mut self, loss: &[(SeqNo, SeqNo)], ctx: CcContext) -> CcOutput;
    fn on_timeout(&mut self, ctx: CcContext) -> CcOutput;
}
