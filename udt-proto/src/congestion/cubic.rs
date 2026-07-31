//! CUBIC congestion control (RFC 9438).
//!
//! Window-based, with the send rate derived from the window rather than
//! controlled separately. That is the whole point of it here: UDT's own
//! controller keeps a rate *and* a window and neither converges — the rate is
//! set once when slow start ends and then moved by an increment that works out
//! to about 1000 pkt/s per second whatever the path, and the window is derived
//! from the receiver's reported rate, which is a lagging estimate of what the
//! sender already chose to send. Measured on a 100 Mbit, 50 ms bottleneck, that
//! pair settles at 62% of the link and stays there.
//!
//! CUBIC has one control. The window grows as a cubic function of the time
//! since the last congestion event, and the pacing period is whatever empties
//! that window over a round trip. Slow start is [`HyStart`], which is specified
//! for exactly this family — using it with UDT's native law was half of a
//! matched pair.

use super::hystart::{CSS_GROWTH_DIVISOR, HyStart, HyStartVerdict};
use super::{CcContext, CcOutput, CongestionControl};
use crate::seq::SeqNo;

/// Packets in flight before the first acknowledgement.
///
/// Matches [`udt_cc`](super::udt_cc)'s so that comparing the two measures the
/// growth law rather than the opening burst. Larger than the 10 that RFC 9438
/// assumes, and affordable here because the window is paced from the first
/// packet: the handshake round trip reaches `init`, so the opening window is
/// spread over a round trip instead of going out back to back.
const INIT_CWND: f64 = 64.0;

/// Scaling constant for the cubic function, RFC 9438 §4.2.
const C: f64 = 0.4;
/// Multiplicative decrease, RFC 9438 §4.6.
const BETA: f64 = 0.7;
/// `3·(1−β)/(1+β)`, the Reno-equivalent growth rate, RFC 9438 §4.3.
const ALPHA: f64 = 3.0 * (1.0 - BETA) / (1.0 + BETA);
/// Never pace below this many packets in flight.
const MIN_CWND: f64 = 2.0;

/// CUBIC. Build one through [`CcKind::Cubic`].
///
/// [`CcKind::Cubic`]: crate::CcKind::Cubic
pub struct Cubic {
    cwnd: f64,
    /// Window at the last congestion event — the target the cubic curve
    /// flattens out at.
    w_max: f64,
    /// `w_max` from the event before, for fast convergence (RFC 9438 §4.7).
    w_last_max: f64,
    /// Reno-equivalent window, run alongside so short paths are not held back
    /// by the cubic term (RFC 9438 §4.3).
    w_est: f64,
    /// When the current congestion-avoidance epoch began, µs.
    epoch_start_us: u64,
    /// Time from the start of the epoch to `w_max`, seconds.
    k: f64,
    slow_start: bool,
    hystart: HyStart,
    last_ack: SeqNo,
    /// Highest sequence sent when the last reduction happened. Loss at or below
    /// this is the same congestion event and must not reduce the window again.
    recovery_point: SeqNo,
    /// Latest round trip, µs.
    rtt_us: f64,
}

impl Cubic {
    /// Creates a controller in slow start.
    pub fn new() -> Self {
        Cubic {
            cwnd: INIT_CWND,
            w_max: 0.0,
            w_last_max: 0.0,
            w_est: 0.0,
            epoch_start_us: 0,
            k: 0.0,
            slow_start: true,
            hystart: HyStart::new(SeqNo::new(0)),
            last_ack: SeqNo::new(0),
            recovery_point: SeqNo::new(0),
            rtt_us: 0.0,
        }
    }

    /// Send period, µs: whatever empties the window over one round trip.
    ///
    /// Recomputed on every output rather than latched. Setting a period once
    /// and letting the window move underneath it is what pins UDT's native
    /// controller to whatever rate slow start happened to end at.
    fn period_us(&self) -> f64 {
        if self.rtt_us <= 0.0 {
            return 1.0;
        }
        (self.rtt_us / self.cwnd.max(MIN_CWND)).max(1.0)
    }

    fn output(&self) -> CcOutput {
        CcOutput {
            pkt_snd_period_us: self.period_us(),
            cwnd: self.cwnd.max(MIN_CWND),
            ack_period_ms: None,
            ack_interval_pkts: None,
            rto_us: None,
        }
    }

    /// Opens a new congestion-avoidance epoch, RFC 9438 §4.2.
    fn start_epoch(&mut self, now_us: u64) {
        self.epoch_start_us = now_us;
        self.k = if self.cwnd < self.w_max {
            ((self.w_max - self.cwnd) / C).cbrt()
        } else {
            // Already at or above the previous maximum: the curve starts in its
            // convex, probing half with nothing to recover.
            0.0
        };
        self.w_est = self.cwnd;
    }

    /// One congestion event: back off, and remember where to.
    fn reduce(&mut self, ctx: &CcContext) {
        // Fast convergence (RFC 9438 §4.7). A flow backing off from a lower
        // point than last time is losing ground to a new arrival, so it gives
        // up a little extra to let the newcomer find its share sooner.
        self.w_last_max = self.w_max;
        self.w_max =
            if self.cwnd < self.w_last_max { self.cwnd * (1.0 + BETA) / 2.0 } else { self.cwnd };
        self.cwnd = (self.cwnd * BETA).max(MIN_CWND);
        self.recovery_point = ctx.snd_curr_seq;
        self.slow_start = false;
        self.start_epoch(ctx.now_us);
    }
}

impl Default for Cubic {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionControl for Cubic {
    fn init(&mut self, ctx: CcContext) -> CcOutput {
        *self = Cubic::new();
        self.hystart = HyStart::new(ctx.snd_curr_seq);
        self.last_ack = ctx.snd_curr_seq;
        self.recovery_point = ctx.snd_curr_seq;
        self.rtt_us = ctx.rtt_us as f64;
        self.output()
    }

    fn on_ack(&mut self, ack: SeqNo, ctx: CcContext) -> CcOutput {
        if ctx.rtt_us > 0 {
            self.rtt_us = ctx.rtt_us as f64;
        }
        let acked = ack.offset_from(self.last_ack).max(0) as f64;
        self.last_ack = ack;
        if acked <= 0.0 {
            return self.output();
        }

        if self.slow_start {
            // Slow start doubles per round trip, so growth is capped at the
            // window itself however much one acknowledgement happens to cover.
            let grow = acked.min(self.cwnd);
            match self.hystart.on_ack(ack, ctx.snd_curr_seq, ctx.rtt_us as u64) {
                HyStartVerdict::Grow => self.cwnd += grow,
                HyStartVerdict::Conservative => self.cwnd += grow / CSS_GROWTH_DIVISOR,
                HyStartVerdict::Exit => {
                    // Left on a delay signal, not a drop, so there is no
                    // congestion event to back off from — only a window that
                    // has found roughly the right size. Treat where we are as
                    // the target the curve flattens at.
                    self.slow_start = false;
                    self.w_max = self.cwnd;
                    self.start_epoch(ctx.now_us);
                }
            }
            if self.cwnd > ctx.flow_wnd {
                self.slow_start = false;
                self.cwnd = ctx.flow_wnd;
                self.w_max = self.cwnd;
                self.start_epoch(ctx.now_us);
            }
            return self.output();
        }

        if self.epoch_start_us == 0 {
            self.start_epoch(ctx.now_us);
        }

        // The cubic target is evaluated one round trip ahead, so the window is
        // already the right size when the acknowledgements for it come back.
        let t = ctx.now_us.saturating_sub(self.epoch_start_us) as f64 / 1e6;
        let rtt_s = self.rtt_us / 1e6;
        let target = self.w_max + C * (t + rtt_s - self.k).powi(3);

        if target > self.cwnd {
            // Never past the target the curve names for this instant. The
            // per-acknowledgement form in RFC 9438 §4.2 assumes each one covers
            // about a segment; a cumulative acknowledgement covering a whole
            // window -- after a stall, or the first one on a connection --
            // multiplies the increment by that whole window and steps clean
            // over the curve. Measured before this clamp: a window of 700 with
            // a target of 749 went to 1396 on a single acknowledgement.
            let inc = ((target - self.cwnd) / self.cwnd * acked).min(target - self.cwnd);
            self.cwnd += inc;
        } else {
            // Below the curve: creep, do not stall.
            self.cwnd += 0.01 / self.cwnd * acked;
        }

        // Reno-equivalent window, run in parallel. On a short round trip this
        // is the faster of the two and is what keeps CUBIC from being slower
        // than plain Reno on the paths it was not tuned for.
        // Bounded for the same reason: one acknowledgement may not advance the
        // Reno-equivalent window by more than a round trip's worth of growth.
        self.w_est += (ALPHA * acked / self.cwnd.max(1.0)).min(ALPHA);
        if self.w_est > self.cwnd {
            self.cwnd = self.w_est;
        }

        if self.cwnd > ctx.flow_wnd {
            self.cwnd = ctx.flow_wnd;
        }
        self.output()
    }

    fn on_loss(&mut self, loss: &[(SeqNo, SeqNo)], ctx: CcContext) -> CcOutput {
        // One reduction per congestion event. Everything lost from a single
        // overflow reports separately, and halving once per report would take
        // the window to nothing on a burst.
        let first = match loss.first() {
            Some(&(start, _)) => start,
            // An empty slice means loss was inferred rather than reported;
            // treat it as a fresh event only if we are past the last one.
            None => ctx.snd_curr_seq,
        };
        if first > self.recovery_point {
            self.reduce(&ctx);
        }
        self.output()
    }

    fn on_timeout(&mut self, ctx: CcContext) -> CcOutput {
        // Nothing got through for a whole retransmission timeout, which is a
        // stronger signal than a drop: start over rather than back off.
        self.w_last_max = self.w_max;
        self.w_max = self.cwnd;
        self.cwnd = MIN_CWND;
        self.slow_start = true;
        self.hystart = HyStart::new(ctx.snd_curr_seq);
        self.epoch_start_us = 0;
        self.recovery_point = ctx.snd_curr_seq;
        self.output()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(now_us: u64, cwnd_seq: u32) -> CcContext {
        CcContext {
            mss: 1472,
            bandwidth_pps: 10_000,
            rcv_rate_pps: 9_000,
            rtt_us: 20_000,
            snd_curr_seq: SeqNo::new(cwnd_seq),
            flight_size: 100,
            flow_wnd: 25_600.0,
            syn_interval_us: 10_000,
            now_us,
        }
    }

    #[test]
    fn the_send_period_tracks_the_window() {
        let mut cc = Cubic::new();
        cc.init(ctx(0, 0));
        let start = cc.period_us();
        // Slow start opens the window; the period must follow it down without
        // waiting for slow start to end. Latching it at init is what pins UDT's
        // own controller to a stale rate.
        for i in 1..40u32 {
            cc.on_ack(SeqNo::new(i * 4), ctx(i as u64 * 1_000, i * 8));
        }
        assert!(cc.cwnd > INIT_CWND, "slow start should have opened the window");
        assert!(
            cc.period_us() < start,
            "period {} did not follow the window down from {}",
            cc.period_us(),
            start
        );
    }

    #[test]
    fn loss_backs_off_once_per_event() {
        let mut cc = Cubic::new();
        cc.init(ctx(0, 0));
        cc.slow_start = false;
        cc.cwnd = 200.0;
        cc.on_loss(&[(SeqNo::new(500), SeqNo::new(500))], ctx(1_000_000, 600));
        let after_one = cc.cwnd;
        assert!((after_one - 140.0).abs() < 1.0, "expected 0.7x, got {after_one}");

        // More reports from the same overflow land at or below the recovery
        // point and must not reduce again.
        cc.on_loss(&[(SeqNo::new(550), SeqNo::new(560))], ctx(1_001_000, 600));
        assert_eq!(cc.cwnd, after_one, "a second report of one event backed off twice");
    }

    #[test]
    fn the_window_recovers_after_a_loss() {
        let mut cc = Cubic::new();
        cc.init(ctx(0, 0));
        cc.slow_start = false;
        cc.cwnd = 200.0;
        cc.on_loss(&[(SeqNo::new(500), SeqNo::new(500))], ctx(1_000_000, 600));
        let low = cc.cwnd;

        let mut seq = 1_000u32;
        for i in 0..200u32 {
            seq += 10;
            cc.on_ack(SeqNo::new(seq), ctx(1_000_000 + i as u64 * 20_000, seq + 100));
        }
        assert!(cc.cwnd > low, "window did not recover: {} vs {low}", cc.cwnd);
    }

    /// The window must follow RFC 9438 §4.2's actual curve, not merely grow.
    ///
    /// This is the check that says the implementation is CUBIC rather than
    /// something cubic-shaped: after a congestion event at `W`, the window is
    /// `βW`, the time to climb back is `K = cbrt(W(1−β)/C)`, and at any point
    /// in between it sits on `W_cubic(t) = C(t−K)³ + W_max`. Every constant
    /// here comes from the RFC, not from this implementation.
    #[test]
    fn the_window_follows_the_cubic_curve_from_the_rfc() {
        const W: f64 = 1_000.0;
        const RTT_US: u64 = 20_000;

        let mut cc = Cubic::new();
        cc.init(ctx(0, 0));
        cc.slow_start = false;
        cc.cwnd = W;
        cc.rtt_us = RTT_US as f64;

        cc.on_loss(&[(SeqNo::new(500), SeqNo::new(500))], ctx(1_000_000, 600));
        assert!((cc.cwnd - W * BETA).abs() < 0.5, "β: expected {}, got {}", W * BETA, cc.cwnd);
        assert!((cc.w_max - W).abs() < 0.5, "W_max should be the window at the event");

        let k_expected = (W * (1.0 - BETA) / C).cbrt();
        assert!((cc.k - k_expected).abs() < 0.01, "K: expected {k_expected}, got {}", cc.k);

        // Walk the curve. The window is evaluated one round trip ahead, per
        // §4.2, so the reference value uses that too.
        //
        // Acknowledgements have to arrive at a realistic density. The RFC's
        // per-acknowledgement form converges on the curve only if a window's
        // worth of them arrives each round trip; feeding a handful per half
        // second makes the window lag by a tenth and says nothing about whether
        // the law is right.
        let epoch = 1_000_000u64;
        let rtt_s = RTT_US as f64 / 1e6;
        let mut seq = 600u32;
        cc.last_ack = SeqNo::new(seq);
        let mut worst = 0.0f64;
        for round in 1..=600u64 {
            let now = epoch + round * RTT_US;
            let per_round = cc.cwnd.round() as u32;
            let mut sent = 0u32;
            while sent < per_round {
                let chunk = 8.min(per_round - sent);
                seq += chunk;
                sent += chunk;
                cc.on_ack(SeqNo::new(seq), ctx(now, seq + 2_000));
            }
            let t = (now - epoch) as f64 / 1e6;
            if t < k_expected {
                let want = W + C * (t + rtt_s - k_expected).powi(3);
                worst = worst.max((cc.cwnd - want).abs() / want.max(1.0));
            }
        }
        assert!(worst < 0.05, "window strayed {:.1}% from the RFC curve at worst", worst * 100.0);

        // Past K the window must have climbed back to roughly where it was.
        assert!(cc.cwnd > W * 0.95, "never recovered to W_max: {:.0} vs {W}", cc.cwnd);
    }

    /// On a short round trip the Reno-equivalent window is the faster of the
    /// two and must be what drives growth (RFC 9438 §4.3). Without it CUBIC is
    /// slower than plain Reno on exactly the paths this protocol targets.
    #[test]
    fn the_reno_friendly_region_leads_on_a_short_path() {
        let mut cc = Cubic::new();
        cc.init(ctx(0, 0));
        cc.slow_start = false;
        cc.cwnd = 100.0;
        cc.rtt_us = 2_000.0;
        cc.on_loss(&[(SeqNo::new(500), SeqNo::new(500))], ctx(1_000_000, 600));

        let after_cut = cc.cwnd;
        let mut seq = 600u32;
        cc.last_ack = SeqNo::new(seq);
        // One second of a 2 ms path is 500 round trips; the cubic term over
        // that span is negligible next to Reno's one-per-round-trip.
        for step in 1..=500u64 {
            let now = 1_000_000 + step * 2_000;
            seq += 70;
            cc.on_ack(SeqNo::new(seq), ctx(now, seq + 200));
        }
        let t = 1.0;
        let cubic_only = cc.w_max + C * (t - cc.k).powi(3);
        assert!(
            cc.cwnd > cubic_only,
            "Reno-equivalent window is not leading: {:.0} vs cubic-only {:.0}",
            cc.cwnd,
            cubic_only
        );
        assert!(cc.cwnd > after_cut, "window did not grow at all");
    }

    #[test]
    fn a_timeout_restarts_slow_start() {
        let mut cc = Cubic::new();
        cc.init(ctx(0, 0));
        cc.slow_start = false;
        cc.cwnd = 500.0;
        cc.on_timeout(ctx(2_000_000, 900));
        assert!(cc.slow_start, "a timeout should return to slow start");
        assert_eq!(cc.cwnd, MIN_CWND);
    }
}
