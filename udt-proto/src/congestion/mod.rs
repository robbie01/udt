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

impl CcOutput {
    pub fn unchanged(pkt_snd_period_us: f64, cwnd: f64) -> Self {
        CcOutput { pkt_snd_period_us, cwnd, ack_period_ms: None, ack_interval_pkts: None, rto_us: None }
    }

    /// Sentinel meaning "leave the caller's CC state alone".
    ///
    /// Returned by the default `on_pkt_sent` / `on_pkt_received` hooks so that
    /// `apply_cc` can detect and skip the update.  Neither field will be negative
    /// in a valid output, so negative values serve as the sentinel.
    pub fn noop() -> Self {
        CcOutput { pkt_snd_period_us: -1.0, cwnd: -1.0, ack_period_ms: None, ack_interval_pkts: None, rto_us: None }
    }

    /// True when this is the noop sentinel (should not be applied).
    pub fn is_noop(&self) -> bool {
        self.pkt_snd_period_us < 0.0
    }
}

/// Pluggable congestion control algorithm.
pub trait CongestionControl: Send + 'static {
    fn init(&mut self, ctx: CcContext) -> CcOutput;
    fn on_ack(&mut self, ack_seq: SeqNo, ctx: CcContext) -> CcOutput;
    fn on_loss(&mut self, loss: &[(SeqNo, SeqNo)], ctx: CcContext) -> CcOutput;
    fn on_timeout(&mut self, ctx: CcContext) -> CcOutput;

    /// Called after each packet is sent.  Default: no-op (returns a sentinel
    /// that `apply_cc` ignores).  Override to track per-packet state.
    fn on_pkt_sent(&mut self, _seq: SeqNo, _len: usize, _ctx: CcContext) -> CcOutput {
        CcOutput::noop()
    }

    /// Called on each received data packet.  Default: no-op.
    fn on_pkt_received(&mut self, _ts_us: u32, _len: usize, _ctx: CcContext) -> CcOutput {
        CcOutput::noop()
    }
}
