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
}

/// Pluggable congestion control algorithm.
pub trait CongestionControl: Send + 'static {
    fn init(&mut self, ctx: CcContext) -> CcOutput;
    fn on_ack(&mut self, ack_seq: SeqNo, ctx: CcContext) -> CcOutput;
    fn on_loss(&mut self, loss: &[(SeqNo, SeqNo)], ctx: CcContext) -> CcOutput;
    fn on_timeout(&mut self, ctx: CcContext) -> CcOutput;

    fn on_pkt_sent(&mut self, _seq: SeqNo, _len: usize, ctx: CcContext) -> CcOutput {
        CcOutput::unchanged(ctx.syn_interval_us as f64 / ctx.bandwidth_pps.max(1) as f64, ctx.flow_wnd)
    }

    fn on_pkt_received(&mut self, _ts_us: u32, _len: usize, ctx: CcContext) -> CcOutput {
        CcOutput::unchanged(ctx.syn_interval_us as f64 / ctx.bandwidth_pps.max(1) as f64, ctx.flow_wnd)
    }
}
