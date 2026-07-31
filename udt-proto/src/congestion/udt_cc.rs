//! UDT's native congestion control.
//!
//! Rate-based rather than window-based: the controller estimates the path's
//! capacity from packet-pair timing and paces sends to match, rather than
//! filling a window until something drops. This is what makes UDT hold high
//! throughput on long fat links where TCP's window growth is the limit.

use super::hystart::{CSS_GROWTH_DIVISOR, HyStart, HyStartVerdict};
use super::{CcContext, CcOutput, CongestionControl};
use crate::seq::SeqNo;

/// Packets a connection may have in flight before its first acknowledgement.
///
/// The reference implementation uses 16, which is 23 KB and costs two extra
/// doublings of slow start before the link is busy. On a path whose round trip
/// is short relative to its capacity -- which is what UDT exists for -- those
/// rounds are most of a small transfer: 0.4 MB took 5.1 ms at 16 and 2.6 ms at
/// 64, against the reference's 4.1.
///
/// 64 packets is 92 KB. That is a large opening burst by TCP's standards, where
/// 10 is usual, but it is in line with what content networks run on QUIC, and
/// UDT is explicitly for links where TCP's caution is the bottleneck. Loss
/// during slow start still halves the window as usual, so the exposure is one
/// burst.
const INIT_CWND: f64 = 64.0;

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
    /// Smallest round trip seen, µs, or `None` before the first sample.
    ///
    /// The window is sized from this rather than from the current round trip.
    /// See [`UdtCc::window_for`].
    min_rtt_us: Option<f64>,
    /// Delay-based slow-start exit. See [`HyStart`].
    hystart: HyStart,
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
            cwnd: INIT_CWND,
            min_rtt_us: None,
            hystart: HyStart::new(SeqNo::new(0)),
        }
    }

    /// Ends slow start, handing the rate over to what the receiver reports.
    ///
    /// The handover is the whole ballgame on a short transfer. DAIMD's increase
    /// works out to about 1000 pkt/s per second whatever the path, so taking a
    /// 100 Mbit link from half capacity to 95% takes 7.5 seconds — against a
    /// 5 MB transfer that lasts under one. Whatever rate slow start leaves
    /// behind is, in practice, the rate for the rest of the transfer.
    fn leave_slow_start(&mut self, ctx: &CcContext) {
        self.slow_start = false;
        if ctx.rcv_rate_pps > 0 {
            self.pkt_snd_period_us = 1_000_000.0 / ctx.rcv_rate_pps as f64;
        } else {
            // This matches `ccc.cpp:216`, and the reference's expression is
            // dimensionally inverted: `m_dCWndSize / (m_iRTT + m_iRCInterval)`
            // is packets divided by microseconds, assigned to a period in
            // microseconds. At a 677-packet window and a 57 ms round trip it
            // yields 0.01 µs, which is not pacing at all — the sender empties
            // its window as fast as it can build packets, and the window is
            // what actually limits it.
            //
            // Correcting it to `(rtt + interval) / cwnd` was tried and is
            // *worse*: measured over 5 MB on a bottleneck with 2% loss, goodput
            // fell from 19.3 to 14.0 Mbit/s on 100 Mbit/50 ms and 59.1 to 50.0
            // on 100 Mbit/10 ms. The reason is not the arithmetic. Slow start
            // on a lossy path exits on the first drop, part-way up the ramp, so
            // the rate it hands over is well below the path's — and DAIMD's
            // increase is far too slow to recover it inside a transfer. Leaving
            // the period near zero sidesteps that by keeping the sender
            // window-limited, where the window does track the path.
            //
            // So the inversion is load-bearing by accident. Untangling it means
            // fixing the handover rate, which is the high-bandwidth-delay item,
            // not this one. `scratchpad/rate-handover-experiment.patch` in the
            // session that found this has the attempted fix.
            self.pkt_snd_period_us = self.cwnd / (ctx.rtt_us as f64 + self.rc_interval_us as f64);
        }
    }

    /// Window for a flow receiving `rcv_rate_pps`, in packets.
    ///
    /// Sized from the *smallest* round trip seen, not the current one.
    ///
    /// The reference uses the current one, and that does not converge. A flow
    /// delivering `R` over a round trip `T` already has `R × T` in flight, so
    /// asking for `R × (T + SYN)` is a standing request for 10 ms of data more
    /// than the path holds. The excess becomes queue, the queue raises `T`, and
    /// the larger `T` asks for more still — a positive feedback loop whose only
    /// fixed point is a full buffer. Measured in the bottleneck model: 188 ms of
    /// queuing delay on a 50 ms link, overflowing in 3997 rounds out of 4000.
    ///
    /// The minimum is the path without a queue, so the same formula against it
    /// asks for a bounded amount and the loop is broken. Delay-based
    /// controllers all do some version of this.
    ///
    /// **It is a trade, not a free win**, and the fluid model overstates it.
    /// Against a packet-level bottleneck (`cost_on_a_bottleneck`, 5 MB over
    /// 100 Mbit/50 ms and 10 Mbit/50 ms links) it reliably buys lower queueing
    /// delay and fewer self-inflicted drops — 154 against 354 on the slow link
    /// with no link loss at all, and 25.8 ms of standing queue against 44.4 ms
    /// — and it costs goodput once the path is also losing packets, 19.5 Mbit/s
    /// against 29.6 in the worst case measured.
    ///
    /// Kept because a transfer that fills someone's uplink buffer degrades
    /// everything else sharing it, and this is meant for peer-to-peer use on
    /// connections their owners are also using. A deployment that wants the
    /// throughput instead should take `rtt_us` here and accept the queue.
    ///
    /// Neither choice addresses slow start, which overshoots the buffer on
    /// every link measured and accounts for most of the drops in the clean
    /// runs.
    fn window_for(&self, rcv_rate_pps: f64, rtt_us: f64) -> f64 {
        let base = self.min_rtt_us.unwrap_or(rtt_us);
        rcv_rate_pps / 1_000_000.0 * (base + self.rc_interval_us as f64) + 16.0
    }

    fn observe_rtt(&mut self, rtt_us: f64) {
        if rtt_us > 0.0 {
            self.min_rtt_us = Some(self.min_rtt_us.map_or(rtt_us, |m| m.min(rtt_us)));
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
        self.cwnd = INIT_CWND;
        // Not paced. Spreading the opening window over the handshake round
        // trip looks obviously right and is a trap here: this controller only
        // recomputes `pkt_snd_period_us` when slow start *ends*, so a period
        // set at init pins the send rate for the whole of slow start and cwnd
        // growth stops meaning anything. The fluid model showed it plainly --
        // peak queueing fell to 12 ms, not because the controller got gentler
        // but because it never ramped -- while the packet-level harness showed
        // no difference at all, bit for bit, because `transfer` feeds messages
        // in as they drain and neither limit ever binds.
        //
        // Pacing the opening window is still the right thing to do; it needs
        // the period to track the window during slow start first.
        self.pkt_snd_period_us = 1.0;
        self.min_rtt_us = None;
        self.hystart = HyStart::new(ctx.snd_curr_seq);
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

        self.observe_rtt(ctx.rtt_us as f64);

        // HyStart++ reads every acknowledgement, not one per rate-control tick.
        // Its whole job is to notice a queue forming, and on a path whose round
        // trip is near the 10 ms tick there are only one or two acknowledgements
        // per round to notice it in.
        let verdict = if self.slow_start {
            self.hystart.on_ack(ack, ctx.snd_curr_seq, ctx.rtt_us as u64)
        } else {
            HyStartVerdict::Grow
        };

        if ctx.now_us.wrapping_sub(self.last_rc_time_us) < self.rc_interval_us {
            return self.output();
        }
        self.last_rc_time_us = ctx.now_us;

        if self.slow_start {
            let new_pkts = ack.offset_from(self.last_ack).max(0) as f64;
            self.cwnd += match verdict {
                HyStartVerdict::Conservative => new_pkts / CSS_GROWTH_DIVISOR,
                _ => new_pkts,
            };
            self.last_ack = ack;

            // The flow-control window is the receiver's buffer, so exiting on it
            // means slow start ran until it overran *something*. It stays as the
            // backstop for a path that gives no usable delay signal.
            if verdict == HyStartVerdict::Exit || self.cwnd > ctx.flow_wnd {
                self.leave_slow_start(&ctx);
            }
        } else {
            // The caller feeds us a smoothed delivery rate that is seeded at
            // 16 pkt/s and only updated from positive samples, so this cannot
            // collapse the window on a zero-rate report.
            self.cwnd = self.window_for(ctx.rcv_rate_pps as f64, ctx.rtt_us as f64);
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
            let reported_rate = ctx.rcv_rate_pps > 0;
            self.leave_slow_start(&ctx);
            if reported_rate {
                return self.output();
            }
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
            self.leave_slow_start(&ctx);
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
        assert_eq!(out.cwnd, INIT_CWND);
        // During slow start, ACK advances cwnd
        let out2 = cc.on_ack(SeqNo::new(108), ctx(10_001));
        assert!(out2.cwnd > INIT_CWND);
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
