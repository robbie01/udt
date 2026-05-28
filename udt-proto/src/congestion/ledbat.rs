/// LEDBAT congestion control — RFC 6817.
///
/// UDT measures RTT via ACK/ACK2. We use RTT/2 as an approximation of
/// one-way delay, which is the standard adaptation for protocols without
/// native OWD measurement. `base_delay` converges to min(RTT/2) over time;
/// `queuing_delay = rtt/2 - base_delay`.
use std::collections::VecDeque;
use super::{CcContext, CcOutput, CongestionControl};
use crate::seq::SeqNo;

const TARGET_US: f64    = 100_000.0; // 100 ms max queuing delay
const GAIN: f64         = 1.0;
const BASE_HISTORY: usize = 10;     // one-minute delay minima to retain
const CURRENT_FILTER: usize = 4;    // recent delay samples
const INIT_CWND_PKTS: f64 = 2.0;
const MIN_CWND_PKTS: f64 = 2.0;
const MINUTE_US: u64 = 60_000_000;

pub struct Ledbat {
    /// Per-minute delay minima (µs). Each entry covers one minute.
    base_delays: VecDeque<u32>,
    /// Recent delay samples for FILTER().
    current_delays: VecDeque<u32>,
    last_rollover_us: u64,
    /// Congestion window in bytes.
    cwnd_bytes: f64,
    /// Congestion timeout (µs); doubles on each timeout up to 60s.
    cto_us: u64,
    mss: u32,
}

impl Ledbat {
    pub fn new() -> Self {
        let mut base_delays = VecDeque::with_capacity(BASE_HISTORY);
        for _ in 0..BASE_HISTORY {
            base_delays.push_back(u32::MAX); // initialized to +infinity
        }
        let current_delays = VecDeque::with_capacity(CURRENT_FILTER);
        Ledbat {
            base_delays,
            current_delays,
            last_rollover_us: 0,
            cwnd_bytes: 0.0,
            cto_us: 1_000_000,
            mss: 1472,
        }
    }

    fn update_base_delay(&mut self, delay_us: u32, now_us: u64) {
        let cur_minute = now_us / MINUTE_US;
        let last_minute = self.last_rollover_us / MINUTE_US;
        if cur_minute != last_minute || self.last_rollover_us == 0 {
            self.last_rollover_us = now_us;
            // Rotate: push new entry, drop oldest
            if self.base_delays.len() >= BASE_HISTORY {
                self.base_delays.pop_front();
            }
            self.base_delays.push_back(delay_us);
        } else {
            let last = self.base_delays.back_mut().unwrap();
            if delay_us < *last {
                *last = delay_us;
            }
        }
    }

    fn update_current_delay(&mut self, delay_us: u32) {
        if self.current_delays.len() >= CURRENT_FILTER {
            self.current_delays.pop_front();
        }
        self.current_delays.push_back(delay_us);
    }

    fn filter_current(&self) -> u32 {
        // FILTER = MIN over recent samples
        self.current_delays.iter().copied().min().unwrap_or(u32::MAX)
    }

    fn min_base(&self) -> u32 {
        self.base_delays.iter().copied().min().unwrap_or(u32::MAX)
    }

    fn output(&self, ctx: CcContext) -> CcOutput {
        let cwnd_pkts = self.cwnd_bytes / ctx.mss as f64;
        // Convert cwnd to a sending period; if cwnd > 0 use bandwidth otherwise keep slow
        let period_us = if cwnd_pkts > 0.0 {
            (ctx.rtt_us as f64 / cwnd_pkts).max(1.0)
        } else {
            ctx.syn_interval_us as f64
        };
        CcOutput {
            pkt_snd_period_us: period_us,
            cwnd: cwnd_pkts,
            ack_period_ms: None,
            ack_interval_pkts: None,
            rto_us: None,
        }
    }
}

impl Default for Ledbat {
    fn default() -> Self { Self::new() }
}

impl CongestionControl for Ledbat {
    fn init(&mut self, ctx: CcContext) -> CcOutput {
        self.mss = ctx.mss;
        self.cwnd_bytes = INIT_CWND_PKTS * ctx.mss as f64;
        self.cto_us = 1_000_000;
        self.base_delays.clear();
        for _ in 0..BASE_HISTORY {
            self.base_delays.push_back(u32::MAX);
        }
        self.current_delays.clear();
        self.last_rollover_us = 0;
        self.output(ctx)
    }

    fn on_ack(&mut self, _ack_seq: SeqNo, ctx: CcContext) -> CcOutput {
        let delay_us = ctx.rtt_us / 2;
        self.update_base_delay(delay_us, ctx.now_us);
        self.update_current_delay(delay_us);

        let min_base = self.min_base();
        let filtered = self.filter_current();

        // queuing_delay can go negative if our base is stale; clamp to 0
        let queuing_delay = if filtered > min_base { (filtered - min_base) as f64 } else { 0.0 };
        let off_target = (TARGET_US - queuing_delay) / TARGET_US;

        // bytes_newly_acked: approximate as one packet (we don't track exact bytes here)
        let bytes_newly_acked = ctx.mss as f64;
        let cwnd_delta = GAIN * off_target * bytes_newly_acked * ctx.mss as f64 / self.cwnd_bytes.max(1.0);
        self.cwnd_bytes += cwnd_delta;
        self.cwnd_bytes = self.cwnd_bytes.max(MIN_CWND_PKTS * ctx.mss as f64);

        self.output(ctx)
    }

    fn on_loss(&mut self, _loss: &[(SeqNo, SeqNo)], ctx: CcContext) -> CcOutput {
        self.cwnd_bytes = (self.cwnd_bytes / 2.0).max(MIN_CWND_PKTS * ctx.mss as f64);
        self.output(ctx)
    }

    fn on_timeout(&mut self, ctx: CcContext) -> CcOutput {
        self.cwnd_bytes = ctx.mss as f64; // 1 packet
        self.cto_us = (self.cto_us * 2).min(60_000_000);
        self.output(ctx)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::CcContext;

    fn ctx_with_rtt(rtt_us: u32, now_us: u64) -> CcContext {
        CcContext {
            mss: 1472,
            bandwidth_pps: 0,
            rcv_rate_pps: 0,
            rtt_us,
            snd_curr_seq: SeqNo::new(0),
            flow_wnd: 25600.0,
            syn_interval_us: 10_000,
            now_us,
        }
    }

    #[test]
    fn cwnd_grows_when_below_target() {
        let mut cc = Ledbat::new();
        let mut ctx = ctx_with_rtt(1_000, 0); // very low RTT → tiny OWD → below target
        cc.init(ctx);
        let before = cc.cwnd_bytes;
        // Feed 10 ACKs, no loss
        for i in 1..=10u64 {
            ctx.now_us = i * 10_000;
            cc.on_ack(SeqNo::new(i as u32), ctx);
        }
        assert!(cc.cwnd_bytes > before, "cwnd should grow when below target");
    }

    #[test]
    fn cwnd_shrinks_on_loss() {
        let mut cc = Ledbat::new();
        let ctx = ctx_with_rtt(10_000, 0);
        cc.init(ctx);
        cc.cwnd_bytes = 100_000.0;
        let before = cc.cwnd_bytes;
        cc.on_loss(&[(SeqNo::new(5), SeqNo::new(5))], ctx);
        assert!(cc.cwnd_bytes < before);
    }

    #[test]
    fn base_delay_rotation() {
        let mut cc = Ledbat::new();
        // Feed samples in minute 0
        cc.update_base_delay(5000, 0);
        cc.update_base_delay(3000, 30_000_000); // still minute 0
        assert_eq!(cc.min_base(), 3000);
        // Advance to minute 1
        cc.update_base_delay(8000, 60_000_000);
        // Now we have a new entry; minimum should be 3000 (from history) or 8000
        assert!(cc.min_base() <= 8000);
    }
}
