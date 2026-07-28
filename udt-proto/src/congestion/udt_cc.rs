//! UDT's native congestion control.
//!
//! Rate-based rather than window-based: the controller estimates the path's
//! capacity from packet-pair timing and paces sends to match, rather than
//! filling a window until something drops. This is what makes UDT hold high
//! throughput on long fat links where TCP's window growth is the limit.

use super::{CcContext, CcOutput, CongestionControl};
use crate::seq::SeqNo;

/// UDT's rate-based DAIMD controller. Build one through [`CcKind::Udt`].
///
/// [`CcKind::Udt`]: crate::CcKind::Udt
pub struct UdtCc {
    rc_interval_us: u64, // = SYN_INTERVAL (10_000 µs)
    last_rc_time_us: u64,
    slow_start: bool,
    last_ack: SeqNo,
    loss_flag: bool,
    last_dec_seq: SeqNo,
    last_dec_period: f64,
    nak_count: u32,
    dec_random: u32,
    avg_nak_num: u32,
    dec_count: u32,
    // Current state
    pkt_snd_period_us: f64,
    cwnd: f64,
}

impl UdtCc {
    /// Creates a controller in slow start.
    pub fn new() -> Self {
        UdtCc {
            rc_interval_us: 0,
            last_rc_time_us: 0,
            slow_start: true,
            last_ack: SeqNo::new(0),
            loss_flag: false,
            last_dec_seq: SeqNo::new(0),
            last_dec_period: 1.0,
            nak_count: 0,
            dec_random: 1,
            avg_nak_num: 0,
            dec_count: 0,
            pkt_snd_period_us: 1.0,
            cwnd: 16.0,
        }
    }

    fn output(&self) -> CcOutput {
        CcOutput {
            pkt_snd_period_us: self.pkt_snd_period_us,
            cwnd: self.cwnd,
            ack_period_ms: None,
            ack_interval_pkts: None,
            rto_us: None,
        }
    }
}

impl Default for UdtCc {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionControl for UdtCc {
    fn init(&mut self, ctx: CcContext) -> CcOutput {
        self.rc_interval_us = ctx.syn_interval_us as u64;
        self.last_rc_time_us = ctx.now_us;
        self.slow_start = true;
        self.last_ack = ctx.snd_curr_seq;
        self.loss_flag = false;
        self.last_dec_seq = ctx.snd_curr_seq.prev();
        self.last_dec_period = 1.0;
        self.avg_nak_num = 0;
        self.nak_count = 0;
        self.dec_random = 1;
        self.cwnd = 16.0;
        self.pkt_snd_period_us = 1.0;
        CcOutput {
            pkt_snd_period_us: self.pkt_snd_period_us,
            cwnd: self.cwnd,
            ack_period_ms: Some((self.rc_interval_us / 1_000) as u32),
            ack_interval_pkts: None,
            rto_us: None,
        }
    }

    fn on_ack(&mut self, ack: SeqNo, ctx: CcContext) -> CcOutput {
        const MIN_INC: f64 = 0.01;

        if ctx.now_us.wrapping_sub(self.last_rc_time_us) < self.rc_interval_us {
            return self.output();
        }
        self.last_rc_time_us = ctx.now_us;

        if self.slow_start {
            let new_pkts = ack.offset_from(self.last_ack).max(0) as f64;
            self.cwnd += new_pkts;
            self.last_ack = ack;

            if self.cwnd > ctx.flow_wnd {
                self.slow_start = false;
                if ctx.rcv_rate_pps > 0 {
                    self.pkt_snd_period_us = 1_000_000.0 / ctx.rcv_rate_pps as f64;
                } else {
                    self.pkt_snd_period_us =
                        self.cwnd / (ctx.rtt_us as f64 + self.rc_interval_us as f64);
                }
            }
        } else {
            // The caller feeds us a smoothed delivery rate that is seeded at
            // 16 pkt/s and only updated from positive samples, so this cannot
            // collapse the window on a zero-rate report.
            self.cwnd = ctx.rcv_rate_pps as f64 / 1_000_000.0
                * (ctx.rtt_us as f64 + self.rc_interval_us as f64)
                + 16.0;
        }

        if self.slow_start {
            return self.output();
        }

        if self.loss_flag {
            self.loss_flag = false;
            return self.output();
        }

        let bw = ctx.bandwidth_pps as f64;
        let mut b = bw - 1_000_000.0 / self.pkt_snd_period_us;
        if self.pkt_snd_period_us > self.last_dec_period && bw / 9.0 < b {
            b = bw / 9.0;
        }

        let inc = if b <= 0.0 {
            MIN_INC
        } else {
            let v =
                10f64.powf((b * ctx.mss as f64 * 8.0).log10().ceil()) * 0.0000015 / ctx.mss as f64;
            v.max(MIN_INC)
        };

        self.pkt_snd_period_us = (self.pkt_snd_period_us * self.rc_interval_us as f64)
            / (self.pkt_snd_period_us * inc + self.rc_interval_us as f64);

        self.output()
    }

    fn on_loss(&mut self, loss: &[(SeqNo, SeqNo)], ctx: CcContext) -> CcOutput {
        if self.slow_start {
            self.slow_start = false;
            if ctx.rcv_rate_pps > 0 {
                self.pkt_snd_period_us = 1_000_000.0 / ctx.rcv_rate_pps as f64;
                return self.output();
            }
            self.pkt_snd_period_us = self.cwnd / (ctx.rtt_us as f64 + self.rc_interval_us as f64);
        }

        self.loss_flag = true;

        let first_loss =
            if let Some(&(start, _)) = loss.first() { start } else { return self.output() };

        if first_loss > self.last_dec_seq {
            self.last_dec_period = self.pkt_snd_period_us;
            self.pkt_snd_period_us = (self.pkt_snd_period_us * 1.125).ceil();

            self.avg_nak_num =
                ((self.avg_nak_num as f64 * 0.875 + self.nak_count as f64 * 0.125).ceil()) as u32;
            self.nak_count = 1;
            self.dec_count = 1;
            self.last_dec_seq = ctx.snd_curr_seq;

            // Randomize to avoid global sync
            let seed = self.last_dec_seq.raw();
            self.dec_random = lcg_rand(seed, self.avg_nak_num);
            if self.dec_random < 1 {
                self.dec_random = 1;
            }
        } else {
            self.dec_count += 1;
            self.nak_count += 1;
            if self.dec_count < 5 && self.nak_count.is_multiple_of(self.dec_random) {
                self.pkt_snd_period_us = (self.pkt_snd_period_us * 1.125).ceil();
                self.last_dec_seq = ctx.snd_curr_seq;
            }
        }

        self.output()
    }

    fn on_timeout(&mut self, ctx: CcContext) -> CcOutput {
        if self.slow_start {
            self.slow_start = false;
            if ctx.rcv_rate_pps > 0 {
                self.pkt_snd_period_us = 1_000_000.0 / ctx.rcv_rate_pps as f64;
            } else {
                self.pkt_snd_period_us =
                    self.cwnd / (ctx.rtt_us as f64 + self.rc_interval_us as f64);
            }
        }
        // The C++ onTimeout is commented out (only slow start handled, rest is no-op)
        self.output()
    }
}

/// Simple LCG-based randomization matching C++'s srand/rand usage.
fn lcg_rand(seed: u32, avg_nak: u32) -> u32 {
    // C's rand() is implementation-defined; use a simple LCG for determinism.
    // This doesn't need to match C's rand exactly — it just needs to be non-zero.
    let r = seed.wrapping_mul(1664525).wrapping_add(1013904223);
    let frac = r as f64 / u32::MAX as f64;
    ((avg_nak as f64 * frac).ceil() as u32).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::CcContext;

    fn ctx(now_us: u64) -> CcContext {
        CcContext {
            mss: 1472,
            bandwidth_pps: 1000,
            rcv_rate_pps: 900,
            rtt_us: 10_000,
            snd_curr_seq: SeqNo::new(100),
            flight_size: 100,
            flow_wnd: 25600.0,
            syn_interval_us: 10_000,
            now_us,
        }
    }

    #[test]
    fn init_then_slow_start() {
        let mut cc = UdtCc::new();
        let out = cc.init(ctx(0));
        assert_eq!(out.cwnd, 16.0);
        // During slow start, ACK advances cwnd
        let out2 = cc.on_ack(SeqNo::new(108), ctx(10_001));
        assert!(out2.cwnd > 16.0);
    }

    #[test]
    fn loss_increases_period() {
        let mut cc = UdtCc::new();
        cc.init(ctx(0));
        // Force out of slow start
        cc.slow_start = false;
        cc.pkt_snd_period_us = 100.0;
        let before = cc.pkt_snd_period_us;
        cc.on_loss(&[(SeqNo::new(200), SeqNo::new(200))], ctx(100_000));
        assert!(cc.pkt_snd_period_us >= before);
    }
}
