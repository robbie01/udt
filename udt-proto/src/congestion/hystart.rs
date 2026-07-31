//! HyStart++ (RFC 9406): leaving slow start on a delay signal.
//!
//! Shared by every controller with a slow start. It is specified as the
//! slow-start phase *for* Reno and CUBIC, so a controller using it should be
//! handing off to a congestion-avoidance law of that family.

use crate::seq::SeqNo;

/// Smallest rise in round trip that counts as a queue building.
///
/// RFC 9406 says 4 ms, which suits the internet paths it was calibrated on and
/// is far too coarse here. UDT is for short-round-trip, high-capacity links, and
/// on a 5 ms path a 4 ms floor demands an 80% rise before it will believe in a
/// queue — by which time slow start has doubled again and overshot anyway.
/// Measured on 100 Mbit/10 ms, dropping the floor took goodput from 66.8 to
/// 93.9 Mbit/s and self-inflicted drops from 161 to 86.
///
/// Every value from 2 ms down measured identically on the links tested, because
/// below that the proportional term (`base / RTT_THRESH_DIVISOR`) is what binds;
/// this is picked to sit under that term on any path above ~8 ms while still
/// being a millisecond of real queueing rather than host jitter.
pub(super) const MIN_RTT_THRESH_US: u64 = 1_000;
/// Largest, so a long path does not need a proportionally huge rise.
pub(super) const MAX_RTT_THRESH_US: u64 = 16_000;
/// The rise that matters is a fraction of the path's own round trip.
pub(super) const RTT_THRESH_DIVISOR: u64 = 8;
/// Round-trip observations needed before a round's minimum is trusted.
///
/// RFC 9406 says eight, assuming TCP's per-packet acknowledgements. UDT acks
/// on a 10 ms timer plus once every 64 packets, so a round on a short path
/// carries one or two acknowledgements and eight is unreachable — the test
/// would never fire and slow start would never exit on delay. Two is what the
/// sparsest useful case supports.
pub(super) const N_RTT_SAMPLE: u32 = 2;
/// Slow start grows this much slower once a queue is suspected.
pub(super) const CSS_GROWTH_DIVISOR: f64 = 4.0;
/// Rounds to spend suspecting before believing it.
pub(super) const CSS_ROUNDS: u32 = 5;

/// HyStart++ (RFC 9406): leave slow start on a delay signal rather than on a
/// drop.
///
/// Slow start doubles until something stops it. With only loss to go on, the
/// thing that stops it is the bottleneck buffer overflowing, so every transfer
/// began by filling the buffer and taking the drops: measured over 5 MB on
/// links losing nothing of their own, 594 to 1006 self-inflicted drops and a
/// standing queue equal to the whole buffer.
///
/// A queue shows up as a rising round trip well before it overflows, which is
/// the signal used here. Conservative Slow Start (CSS) is the part that makes
/// it safe: a rise is treated as a suspicion first, growth is slowed rather
/// than stopped, and if the round trip falls back the suspicion is dropped and
/// slow start resumes. Only a rise that survives [`CSS_ROUNDS`] rounds ends
/// slow start.
pub(super) struct HyStart {
    /// Minimum round trip seen in the round now in progress.
    round_min_us: u64,
    /// The previous round's minimum, which a rise is measured against.
    last_round_min_us: u64,
    /// Acknowledging past this sequence number ends the round.
    round_end: SeqNo,
    /// Observations taken this round, against [`N_RTT_SAMPLE`].
    samples: u32,
    /// Rounds spent in CSS so far; 0 when not in CSS.
    css_round: u32,
    /// The round minimum that triggered CSS. Falling back below it means the
    /// rise was a transient and slow start should resume.
    css_entry_min_us: u64,
}

/// What [`HyStart::on_ack`] concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HyStartVerdict {
    /// No queue suspected; grow at full speed.
    Grow,
    /// A queue is suspected; grow at a quarter speed.
    Conservative,
    /// The rise held up across [`CSS_ROUNDS`]; slow start is over.
    Exit,
}

impl HyStart {
    pub(super) fn new(start: SeqNo) -> Self {
        HyStart {
            round_min_us: u64::MAX,
            last_round_min_us: u64::MAX,
            round_end: start,
            samples: 0,
            css_round: 0,
            css_entry_min_us: u64::MAX,
        }
    }

    pub(super) fn in_css(&self) -> bool {
        self.css_round > 0
    }

    /// Feeds one acknowledgement. `rtt_us` is the current round-trip estimate,
    /// `snd_curr` the highest sequence number sent so far.
    pub(super) fn on_ack(&mut self, ack: SeqNo, snd_curr: SeqNo, rtt_us: u64) -> HyStartVerdict {
        if rtt_us > 0 {
            self.round_min_us = self.round_min_us.min(rtt_us);
            self.samples += 1;
        }

        // A round ends when everything outstanding at its start is acked.
        if ack >= self.round_end {
            if self.in_css() {
                self.css_round += 1;
                if self.css_round > CSS_ROUNDS {
                    return HyStartVerdict::Exit;
                }
            }
            self.last_round_min_us = self.round_min_us;
            self.round_min_us = u64::MAX;
            self.samples = 0;
            self.round_end = snd_curr;
        }

        if self.samples < N_RTT_SAMPLE
            || self.round_min_us == u64::MAX
            || self.last_round_min_us == u64::MAX
        {
            return if self.in_css() { HyStartVerdict::Conservative } else { HyStartVerdict::Grow };
        }

        if self.in_css() {
            // The round trip came back down, so the rise that triggered CSS was
            // a transient — a reordered packet or a scheduling hiccup, not a
            // queue. RFC 9406 §4.2 returns to slow start rather than paying the
            // exit for it.
            if self.round_min_us < self.css_entry_min_us {
                self.css_round = 0;
                self.css_entry_min_us = u64::MAX;
                return HyStartVerdict::Grow;
            }
            return HyStartVerdict::Conservative;
        }

        let thresh = (self.last_round_min_us / RTT_THRESH_DIVISOR)
            .clamp(MIN_RTT_THRESH_US, MAX_RTT_THRESH_US);
        if self.round_min_us >= self.last_round_min_us.saturating_add(thresh) {
            self.css_round = 1;
            // The baseline is the round trip that *triggered* the suspicion,
            // not the quiet one before it (RFC 9406 §4.2 `cssBaselineMinRtt`).
            // Anchoring it to the quiet value instead means a path that simply
            // returns to where it was never clears the suspicion, because the
            // test is a strict `<`, and CSS then runs its full length on what
            // was a transient.
            self.css_entry_min_us = self.round_min_us;
            return HyStartVerdict::Conservative;
        }

        HyStartVerdict::Grow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Packets acknowledged per round in these tests.
    const PER_ROUND: u32 = 8;

    /// Drives one whole round at a fixed round trip and returns the verdict it
    /// ends on.
    ///
    /// Rounds matter: a round's minimum is taken over everything acknowledged
    /// inside it, so a rise part-way through one is invisible until the round
    /// turns over. Feeding a fixed count of acknowledgements that straddles a
    /// boundary tests nothing.
    fn round(hs: &mut HyStart, seq: &mut u32, rtt_us: u64) -> HyStartVerdict {
        let mut v = HyStartVerdict::Grow;
        for _ in 0..PER_ROUND {
            v = hs.on_ack(SeqNo::new(*seq), SeqNo::new(*seq + PER_ROUND), rtt_us);
            *seq += 1;
        }
        v
    }

    #[test]
    fn hystart_leaves_slow_start_when_the_round_trip_climbs() {
        let mut hs = HyStart::new(SeqNo::new(0));
        let mut seq = 0;
        // Two quiet rounds establish a baseline.
        assert_eq!(round(&mut hs, &mut seq, 20_000), HyStartVerdict::Grow);
        assert_eq!(round(&mut hs, &mut seq, 20_000), HyStartVerdict::Grow);

        // A rise past the threshold: 20 ms / 8 = 2.5 ms, so 24 ms clears it. It
        // should suspect first, not exit outright.
        assert_eq!(round(&mut hs, &mut seq, 24_000), HyStartVerdict::Conservative);

        // Held long enough, the suspicion becomes an exit.
        let mut verdict = HyStartVerdict::Conservative;
        for _ in 0..(CSS_ROUNDS + 2) {
            verdict = round(&mut hs, &mut seq, 24_000);
            if verdict == HyStartVerdict::Exit {
                break;
            }
        }
        assert_eq!(verdict, HyStartVerdict::Exit, "a sustained rise should end slow start");
    }

    #[test]
    fn hystart_forgives_a_transient_spike() {
        let mut hs = HyStart::new(SeqNo::new(0));
        let mut seq = 0;
        assert_eq!(round(&mut hs, &mut seq, 20_000), HyStartVerdict::Grow);
        assert_eq!(round(&mut hs, &mut seq, 20_000), HyStartVerdict::Grow);
        assert_eq!(round(&mut hs, &mut seq, 24_000), HyStartVerdict::Conservative);

        // The round trip comes back down before CSS_ROUNDS elapse. That was a
        // reordered packet or a scheduling hiccup, not a queue, and slow start
        // should resume rather than pay the exit.
        assert_eq!(round(&mut hs, &mut seq, 20_000), HyStartVerdict::Grow);
        assert!(!hs.in_css(), "returning to the baseline should clear the suspicion");
    }

    #[test]
    fn hystart_ignores_a_steady_path() {
        let mut hs = HyStart::new(SeqNo::new(0));
        // Sixty acknowledgements at an unchanging round trip must never suspect
        // a queue: a false exit here pins the rate for the whole transfer.
        let mut seq = 0;
        for r in 0..10 {
            assert_eq!(
                round(&mut hs, &mut seq, 20_000),
                HyStartVerdict::Grow,
                "round {r} suspected a queue on a steady path"
            );
        }
    }

    /// The floor must not swamp the proportional term on the short paths this
    /// protocol is for. See [`MIN_RTT_THRESH_US`].
    #[test]
    fn the_delay_threshold_scales_with_a_short_path() {
        let mut hs = HyStart::new(SeqNo::new(0));
        let mut seq = 0;
        assert_eq!(round(&mut hs, &mut seq, 5_000), HyStartVerdict::Grow);
        assert_eq!(round(&mut hs, &mut seq, 5_000), HyStartVerdict::Grow);
        // 5 ms base: a 1.4 ms rise is a real queue on this path. Under RFC
        // 9406's 4 ms floor this stays `Grow` and the buffer fills.
        assert_eq!(round(&mut hs, &mut seq, 6_400), HyStartVerdict::Conservative);
    }
}
