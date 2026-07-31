//! LEDBAT++ — delay-based congestion control for background traffic.
//!
//! Implements [draft-irtf-iccrg-ledbat-plus-plus-02][draft], the variant
//! shipped as a TCP congestion provider in Windows. It is *not* RFC 6817; see
//! the conformance table below for exactly where and why it differs.
//!
//! [draft]: https://www.ietf.org/archive/id/draft-irtf-iccrg-ledbat-plus-plus-02.html
//!
//! # Why LEDBAT++ rather than RFC 6817
//!
//! RFC 6817 §2.4.1 requires *one-way* delay measurements. UDT's ACK carries no
//! field for them, and its packet timestamp is wall-clock microseconds
//! truncated to 32 bits — dominated by the inter-host clock offset and wrapping
//! roughly every 72 minutes. Carrying true one-way delay would need a wire
//! extension, which would not interoperate with the C++ reference.
//!
//! LEDBAT++ takes the approach shipping stacks do: measure round-trip delay and
//! compensate for the weaker signal with *periodic slowdowns* that re-measure
//! the base delay. Without those, a round-trip-based base estimate drifts
//! upward as the flow's own queue builds and the controller stops yielding —
//! the latecomer-advantage problem.
//!
//! # RFC 6817 conformance
//!
//! | Clause | Status |
//! |---|---|
//! | §2.4.1 one-way delay | **Deviates** — round-trip delay, per LEDBAT++ §3. No wire field for OWD exists. |
//! | §2.4.2 `TARGET` ≤ 100 ms | **Deviates** — 60 ms, per LEDBAT++ §3.1. Tighter than the RFC ceiling, so it yields sooner. |
//! | §2.4.2 `GAIN` | **Deviates** — dynamic `1/min(16, ceil(2·TARGET/base))` rather than a constant. |
//! | §2.4.2 linear increase | Met, via the dynamic gain. |
//! | §2.4.2 decrease on delay | **Extends** — multiplicative, floored at `-W/2`. |
//! | at most one backoff per RTT | Met — see `loss_guard_us`. |
//! | §2.4.2 `min_cwnd` = 2 | Met. |
//! | §2.5 base-delay history | **Deviates** — re-measured by periodic slowdown rather than kept in per-minute buckets. |
//! | §2.6 no worse than TCP | Met by construction: this controller only ever reduces the window. |
//!
//! # Known limitation
//!
//! The delay signal comes from [`CcContext::rtt_us`], the connection's smoothed
//! RTT, which on the sending side is the value the *peer* reports in its ACKs.
//! The draft asks for lightly-filtered per-ACK samples; a 7/8 EWMA is heavier
//! filtering than intended and blunts the queuing-delay transient. The periodic
//! slowdowns are what keep the base estimate honest despite this.

use super::{CcContext, CcOutput, CongestionControl};
use crate::seq::SeqNo;

/// Target queuing delay above the base, in µs. LEDBAT++ §3.1 (RFC 6817: 100 ms).
/// Ceiling on the queueing delay this controller will tolerate, per LEDBAT++
/// §3.1. See [`Ledbat::target_us`] for why it is a ceiling and not the target.
const TARGET_CEILING_US: f64 = 60_000.0;
/// Floor, so the target stays above ordinary jitter on a very short path.
const TARGET_FLOOR_US: f64 = 1_000.0;
/// How much queueing the target allows, as a multiple of the path's own base
/// delay. One means "do not more than double what the path already costs".
const TARGET_RTT_FRACTION: f64 = 1.0;
/// Cap on the dynamic gain divisor.
const GAIN_CAP: f64 = 16.0;
/// Multiplicative-decrease constant; the draft recommends 1.
const DECREASE_C: f64 = 1.0;
const MIN_CWND: f64 = 2.0;
const INIT_CWND: f64 = 2.0;
/// Window held during a slowdown while the base delay is re-measured.
const SLOWDOWN_CWND: f64 = 2.0;
/// Current-delay filter width, in samples.
const FILTER: usize = 4;
/// Slack above the flight size that the window may reach, in packets.
/// RFC 6817 §2.4.2 `ALLOWED_INCREASE`; XNU's `tcp_ledbat_allowed_increase`.
const ALLOWED_INCREASE: f64 = 8.0;
/// How far the window may exceed the flight size, as a left shift.
/// XNU's `tcp_ledbat_tether_shift`; 1 means "at most twice the flight size".
const TETHER_SHIFT: u32 = 1;
/// Floor on the interval between periodic slowdowns.
///
/// LEDBAT++ schedules slowdowns purely relative to RTT (next at 9x the
/// slowdown's own duration, itself 2 RTT). That is sensible at internet RTTs —
/// roughly a second apart at 50 ms — but degenerates on fast paths: at the
/// ~60 us RTT of loopback it fires about a thousand times a second, so the flow
/// spends its life pinned at two packets or ramping back, for no congestion
/// signal at all. Clamping to wall-clock time reproduces the intended cadence
/// instead of scaling it into absurdity.
const MIN_SLOWDOWN_INTERVAL_US: u64 = 1_000_000;
/// Ceiling, so a very long RTT cannot postpone base-delay re-measurement
/// indefinitely.
const MAX_SLOWDOWN_INTERVAL_US: u64 = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Initial slow start; exited on excess delay, loss, or the flow window.
    SlowStart,
    /// Normal operation.
    Steady,
    /// Window pinned low while the base delay is re-measured.
    Slowdown,
    /// Ramping back to `ssthresh` after a slowdown.
    Recovery,
}

/// A LEDBAT++ controller. Build one through [`CcKind::LedbatPlusPlus`].
///
/// [`CcKind::LedbatPlusPlus`]: crate::CcKind::LedbatPlusPlus
pub struct Ledbat {
    phase: Phase,
    cwnd: f64,
    ssthresh: f64,
    /// Minimum RTT seen in the current measurement epoch, µs.
    base_us: u32,
    /// Recent RTT samples; the filter takes their minimum.
    recent: [u32; FILTER],
    recent_len: usize,
    recent_ptr: usize,
    /// Highest sequence acknowledged, for counting newly-acked packets.
    last_ack: SeqNo,
    phase_started_us: u64,
    /// When the next slowdown is due; 0 means "not yet scheduled".
    next_slowdown_us: u64,
    last_slowdown_len_us: u64,
    /// Suppresses more than one multiplicative decrease per RTT.
    loss_guard_us: u64,
}

impl Default for Ledbat {
    fn default() -> Self {
        Self::new()
    }
}

impl Ledbat {
    /// Creates a controller in slow start, with no delay measurements yet.
    pub fn new() -> Self {
        Ledbat {
            phase: Phase::SlowStart,
            cwnd: INIT_CWND,
            ssthresh: f64::INFINITY,
            base_us: u32::MAX,
            recent: [u32::MAX; FILTER],
            recent_len: 0,
            recent_ptr: 0,
            last_ack: SeqNo::new(0),
            phase_started_us: 0,
            next_slowdown_us: 0,
            last_slowdown_len_us: 0,
            loss_guard_us: 0,
        }
    }

    fn record_delay(&mut self, rtt_us: u32) {
        self.recent[self.recent_ptr] = rtt_us;
        self.recent_ptr = (self.recent_ptr + 1) % FILTER;
        if self.recent_len < FILTER {
            self.recent_len += 1;
        }
        if rtt_us < self.base_us {
            self.base_us = rtt_us;
        }
    }

    /// Filtered current delay: minimum of the recent samples.
    fn filtered_us(&self) -> u32 {
        self.recent[..self.recent_len.max(1)].iter().copied().min().unwrap_or(u32::MAX)
    }

    /// Queuing delay above the base, µs.
    fn queuing_us(&self) -> f64 {
        let f = self.filtered_us();
        if f == u32::MAX || self.base_us == u32::MAX {
            return 0.0;
        }
        f.saturating_sub(self.base_us) as f64
    }

    /// Queueing delay this controller aims to keep the path at, in µs.
    ///
    /// LEDBAT++ §3.1 specifies a flat 60 ms, calibrated for internet paths. Used
    /// literally it makes the controller meaningless on a short one: on a 60 µs
    /// link 60 ms is a thousand times the path's own delay, so no queue this
    /// side of catastrophic ever reaches the target, nothing ever triggers the
    /// decrease term, and the "scavenger" behaves like a plain loss-based flow.
    /// That is not a hypothetical — after slow start was fixed, this controller
    /// was measurably *greedier* than the default one it is supposed to yield
    /// to.
    ///
    /// So 60 ms is treated as a ceiling and the target proper is a multiple of
    /// the base delay: a flow gets to add about as much latency as the path
    /// already has, no more, and never more than LEDBAT++ allows. The floor
    /// keeps it above jitter on a path short enough that a proportional target
    /// would be single-digit microseconds.
    fn target_us(&self) -> f64 {
        if self.base_us == u32::MAX {
            return TARGET_CEILING_US;
        }
        (self.base_us as f64 * TARGET_RTT_FRACTION).clamp(TARGET_FLOOR_US, TARGET_CEILING_US)
    }

    /// `GAIN = 1 / min(16, ceil(2·TARGET / base))` — LEDBAT++ §3.2.
    ///
    /// Scaling by the base delay keeps the ramp gentle on short paths, where a
    /// constant gain would overshoot the target within a single RTT.
    fn gain(&self) -> f64 {
        let target = self.target_us();
        let base = if self.base_us == u32::MAX { target } else { self.base_us as f64 };
        let divisor = (2.0 * target / base.max(1.0)).ceil().clamp(1.0, GAIN_CAP);
        1.0 / divisor
    }

    fn rtt_of(ctx: &CcContext) -> u64 {
        (ctx.rtt_us as u64).max(1)
    }

    /// Clamp an RTT-derived slowdown interval to sane wall-clock bounds.
    fn slowdown_gap(rtt_derived_us: u64) -> u64 {
        rtt_derived_us.clamp(MIN_SLOWDOWN_INTERVAL_US, MAX_SLOWDOWN_INTERVAL_US)
    }

    /// Cap the window against what the application is actually using.
    ///
    /// Without this a flow that is application-limited — or on a path with no
    /// queue to sense, such as loopback — grows its window without bound,
    /// because the delay signal that would otherwise stop it never fires. The
    /// window is then meaningless as a congestion estimate and the flow bursts
    /// the moment the application has data. RFC 6817 §2.4.2; XNU applies the
    /// same clamp in `tcp_ledbat_congestion_avd`.
    fn tethered(&self, ctx: &CcContext) -> f64 {
        let max_allowed = ALLOWED_INCREASE + ((ctx.flight_size << TETHER_SHIFT) as f64);
        self.cwnd.min(max_allowed).max(MIN_CWND)
    }

    /// Pace the window across one RTT rather than emitting it back to back —
    /// bursting builds exactly the queue this controller exists to avoid.
    fn output(&self, ctx: &CcContext) -> CcOutput {
        let cwnd = self.tethered(ctx);
        CcOutput {
            pkt_snd_period_us: (Self::rtt_of(ctx) as f64 / cwnd).max(1.0),
            cwnd,
            ack_period_ms: None,
            ack_interval_pkts: None,
            rto_us: None,
        }
    }

    /// Pin the window low so the queue drains and the base delay can be
    /// measured without this flow's own backlog inflating it.
    fn enter_slowdown(&mut self, now_us: u64) {
        self.ssthresh = self.cwnd;
        self.cwnd = SLOWDOWN_CWND;
        self.phase = Phase::Slowdown;
        self.phase_started_us = now_us;
        // Discard the delay history: it describes the pre-slowdown queue.
        self.base_us = u32::MAX;
        self.recent = [u32::MAX; FILTER];
        self.recent_len = 0;
        self.recent_ptr = 0;
    }
}

impl CongestionControl for Ledbat {
    fn init(&mut self, ctx: CcContext) -> CcOutput {
        self.phase = Phase::SlowStart;
        self.cwnd = INIT_CWND;
        self.ssthresh = f64::INFINITY;
        self.last_ack = ctx.snd_curr_seq;
        self.phase_started_us = ctx.now_us;
        self.next_slowdown_us = 0;
        self.output(&ctx)
    }

    fn on_ack(&mut self, ack: SeqNo, ctx: CcContext) -> CcOutput {
        let acked = ack.offset_from(self.last_ack).max(0) as f64;
        self.last_ack = ack;
        self.record_delay(ctx.rtt_us);

        let rtt = Self::rtt_of(&ctx);
        let queuing = self.queuing_us();
        let gain = self.gain();

        match self.phase {
            Phase::SlowStart => {
                self.cwnd += acked * gain;
                // "If the queuing delay is larger than 3/4ths of the target
                // delay, exit slow start" — LEDBAT++ §3.4.
                if queuing > 0.75 * self.target_us() || self.cwnd >= ctx.flow_wnd {
                    self.phase = Phase::Steady;
                    self.phase_started_us = ctx.now_us;
                    // First slowdown two RTTs after slow start completes.
                    self.next_slowdown_us = ctx.now_us + Self::slowdown_gap(2 * rtt);
                }
            }
            Phase::Steady => {
                if queuing <= self.target_us() {
                    // Linear increase, apportioned across the window so one
                    // window of ACKs adds GAIN. An earlier version fixed the
                    // acked amount at one packet regardless of what the
                    // cumulative ACK actually covered, making growth ~sqrt(n):
                    // reaching a 1000-packet window took over an hour.
                    self.cwnd += gain * acked / self.cwnd.max(1.0);
                } else {
                    // W += max(GAIN − C·W·(delay/target − 1), −W/2)
                    let over = queuing / self.target_us() - 1.0;
                    let delta = (gain - DECREASE_C * self.cwnd * over).max(-self.cwnd / 2.0);
                    self.cwnd += delta * (acked / self.cwnd.max(1.0)).min(1.0);
                }
                self.cwnd = self.cwnd.max(MIN_CWND);

                if self.next_slowdown_us != 0 && ctx.now_us >= self.next_slowdown_us {
                    self.enter_slowdown(ctx.now_us);
                }
            }
            Phase::Slowdown => {
                self.cwnd = SLOWDOWN_CWND;
                if ctx.now_us.saturating_sub(self.phase_started_us) >= 2 * rtt {
                    self.last_slowdown_len_us = ctx.now_us.saturating_sub(self.phase_started_us);
                    self.phase = Phase::Recovery;
                    self.phase_started_us = ctx.now_us;
                }
            }
            Phase::Recovery => {
                self.cwnd += acked * gain;
                if self.cwnd >= self.ssthresh {
                    self.cwnd = self.ssthresh;
                    self.phase = Phase::Steady;
                    self.phase_started_us = ctx.now_us;
                    // "the next slowdown is scheduled to occur at 9 times this
                    // duration" — LEDBAT++ §3.5.
                    self.next_slowdown_us =
                        ctx.now_us + Self::slowdown_gap(9 * self.last_slowdown_len_us.max(rtt));
                }
            }
        }

        self.output(&ctx)
    }

    fn on_loss(&mut self, _loss: &[(SeqNo, SeqNo)], ctx: CcContext) -> CcOutput {
        // At most one backoff per RTT. Every NAK arrives here and a single loss
        // episode commonly produces several; halving on each would collapse the
        // window far below what one congestion signal warrants.
        if ctx.now_us < self.loss_guard_us {
            return self.output(&ctx);
        }
        let rtt = Self::rtt_of(&ctx);
        self.loss_guard_us = ctx.now_us + rtt;

        self.cwnd = (self.cwnd / 2.0).max(MIN_CWND);
        self.ssthresh = self.cwnd;
        if self.phase == Phase::SlowStart {
            self.phase = Phase::Steady;
            self.phase_started_us = ctx.now_us;
            self.next_slowdown_us = ctx.now_us + Self::slowdown_gap(2 * rtt);
        }
        self.output(&ctx)
    }

    fn on_timeout(&mut self, ctx: CcContext) -> CcOutput {
        self.cwnd = MIN_CWND;
        self.phase = Phase::Steady;
        self.phase_started_us = ctx.now_us;
        self.output(&ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(now_us: u64, rtt_us: u32, snd: u32) -> CcContext {
        CcContext {
            mss: 1500,
            bandwidth_pps: 100_000,
            rcv_rate_pps: 50_000,
            rtt_us,
            snd_curr_seq: SeqNo::new(snd),
            flight_size: 8192,
            flow_wnd: 8192.0,
            syn_interval_us: 10_000,
            now_us,
        }
    }

    /// Growth must be linear in acknowledged packets. The previous
    /// implementation grew as sqrt(n) because it ignored how much each ACK
    /// covered — this asserts the *rate*, which a sign-only check cannot catch.
    #[test]
    fn steady_growth_is_linear_in_acked_packets() {
        let mut cc = Ledbat::new();
        cc.init(ctx(0, 1_000, 0));
        cc.phase = Phase::Steady;
        cc.next_slowdown_us = 0; // not scheduled
        cc.cwnd = 100.0;
        cc.base_us = 1_000;

        let before = cc.cwnd;
        let gain = cc.gain();
        // One full window of ACKs should add about GAIN.
        for i in 0..100u32 {
            cc.on_ack(SeqNo::new(i + 1), ctx(1_000 + u64::from(i) * 10, 1_000, i + 1));
        }
        let grew = cc.cwnd - before;
        assert!(
            grew > gain * 0.5 && grew < gain * 2.0,
            "one window of ACKs grew cwnd by {grew}, expected about {gain}",
        );
    }

    /// Queuing delay above target must shrink the window — the defining
    /// behaviour of a scavenger controller.
    #[test]
    fn cwnd_shrinks_when_over_target() {
        let mut cc = Ledbat::new();
        cc.init(ctx(0, 1_000, 0));
        cc.phase = Phase::Steady;
        cc.next_slowdown_us = 0;
        cc.cwnd = 100.0;
        cc.base_us = 1_000;

        let before = cc.cwnd;
        cc.on_ack(SeqNo::new(50), ctx(10_000, 200_000, 50));
        assert!(cc.cwnd < before, "cwnd {} did not shrink from {before}", cc.cwnd);
    }

    #[test]
    fn repeated_loss_within_one_rtt_backs_off_once() {
        let mut cc = Ledbat::new();
        cc.init(ctx(0, 10_000, 0));
        cc.phase = Phase::Steady;
        cc.cwnd = 100.0;

        cc.on_loss(&[], ctx(1_000_000, 10_000, 0));
        let after_first = cc.cwnd;
        for i in 1..5u64 {
            cc.on_loss(&[], ctx(1_000_000 + i * 1_000, 10_000, 0));
        }
        assert_eq!(cc.cwnd, after_first, "backed off more than once within an RTT");

        cc.on_loss(&[], ctx(1_020_000, 10_000, 0));
        assert!(cc.cwnd < after_first, "no backoff once the guard expired");
    }

    /// A slowdown pins the window and discards the stale base estimate — which
    /// is what stops the base drifting up behind this flow's own queue.
    #[test]
    fn slowdown_pins_window_and_resets_base() {
        let mut cc = Ledbat::new();
        cc.init(ctx(0, 1_000, 0));
        cc.phase = Phase::Steady;
        cc.cwnd = 500.0;
        cc.base_us = 5_000;
        cc.next_slowdown_us = 1_000;

        cc.on_ack(SeqNo::new(10), ctx(2_000, 5_000, 10));
        assert_eq!(cc.phase, Phase::Slowdown);
        assert_eq!(cc.cwnd, SLOWDOWN_CWND);
        // The ACK that triggers the slowdown also grows the window a little
        // first, so compare with tolerance rather than for equality.
        assert!(
            (cc.ssthresh - 500.0).abs() < 1.0,
            "pre-slowdown window not remembered: {}",
            cc.ssthresh,
        );
        assert_eq!(cc.base_us, u32::MAX, "stale base delay survived the slowdown");
    }

    #[test]
    fn slowdown_recovers_to_previous_window() {
        let mut cc = Ledbat::new();
        cc.init(ctx(0, 1_000, 0));
        cc.cwnd = 64.0;
        cc.enter_slowdown(0);

        let mut seq = 0u32;
        let mut t = 0u64;
        for _ in 0..2000 {
            t += 1_000;
            seq += 4;
            cc.on_ack(SeqNo::new(seq), ctx(t, 1_000, seq));
            if cc.phase == Phase::Steady {
                break;
            }
        }
        assert_eq!(cc.phase, Phase::Steady, "never finished recovering");
        assert_eq!(cc.cwnd, 64.0, "did not return to the pre-slowdown window");
        assert!(cc.next_slowdown_us > t, "next slowdown not scheduled");
    }

    #[test]
    fn window_floor_is_two_packets() {
        let mut cc = Ledbat::new();
        cc.init(ctx(0, 1_000, 0));
        cc.phase = Phase::Steady;
        cc.next_slowdown_us = 0;
        cc.cwnd = 3.0;
        cc.base_us = 1_000;
        for i in 0..20u32 {
            cc.on_ack(SeqNo::new(i + 1), ctx(10_000 + u64::from(i) * 1_000, 500_000, i + 1));
        }
        assert!(cc.cwnd >= MIN_CWND, "cwnd fell to {}", cc.cwnd);
        cc.on_timeout(ctx(100_000, 1_000, 0));
        assert!(cc.cwnd >= MIN_CWND, "timeout drove cwnd to {}", cc.cwnd);
    }
}
