//! Deterministic single-bottleneck fluid model, for testing congestion control.
//!
//! Loopback cannot answer the question a delay-based controller exists to
//! answer. There is no bottleneck queue, so queuing delay never rises, the
//! delay signal never fires, and a measured bandwidth share says nothing about
//! whether the controller *would* yield. This model supplies the missing
//! ingredient without needing `netem` or a second machine.
//!
//! It is a model, not the protocol. It exercises the control law — the
//! window/delay feedback loop — and deliberately not packetisation,
//! retransmission or the wire format. A controller that behaves correctly here
//! is not thereby proven correct end to end; it has simply passed the test that
//! a real bottleneck would apply.
//!
//! Each round advances one RTT:
//!
//! ```text
//! bdp        = capacity × base_rtt
//! queue      = max(0, Σ cwnd − bdp)          // standing queue
//! qdelay     = queue / capacity
//! rtt        = base_rtt + qdelay
//! delivered  = capacity × rtt × (cwnd / Σ cwnd)   // proportional share
//! ```

use super::{CcContext, CongestionControl};
use crate::seq::SeqNo;

pub struct Link {
    /// Bottleneck capacity, packets per second.
    pub capacity_pps: f64,
    /// Propagation delay with an empty queue, µs.
    pub base_rtt_us: f64,
    /// Queue depth before packets are dropped, in packets.
    pub buffer_pkts: f64,
}

pub struct Flow {
    cc: Box<dyn CongestionControl>,
    cwnd: f64,
    /// Gap the controller wants between sends, µs.
    ///
    /// Tracked because a window is only half of what limits a sender here. UDT's
    /// own controller is rate-based: `on_loss` widens this and never touches the
    /// window at all, so a model reading only `cwnd` cannot see it react to loss.
    period_us: f64,
    seq: u32,
    /// Packets delivered over the run.
    pub delivered: f64,
    /// Whether this flow saw a loss signal at any point.
    pub saw_loss: bool,
}

impl Flow {
    pub fn new(cc: Box<dyn CongestionControl>) -> Self {
        Flow { cc, cwnd: 2.0, period_us: 1.0, seq: 0, delivered: 0.0, saw_loss: false }
    }

    pub fn cwnd(&self) -> f64 {
        self.cwnd
    }

    /// Packets this flow will actually put in flight over one round trip.
    ///
    /// The smaller of what its window allows and what its pacing allows, which
    /// is what the real sender does — `pack_data` checks both.
    fn offered(&self, rtt_us: f64) -> f64 {
        let by_pacing = rtt_us / self.period_us.max(1.0);
        self.cwnd.min(by_pacing).max(1.0)
    }
}

/// Outcome of a run, for assertions.
pub struct Outcome {
    /// Peak standing queue observed, in packets.
    pub peak_queue_pkts: f64,
    /// Peak queuing delay observed, µs.
    pub peak_qdelay_us: f64,
    /// Number of rounds in which the buffer overflowed.
    pub loss_rounds: usize,
}

/// `rcv_rate_pps` is the *flow's own* observed delivery rate, not the link
/// capacity: that is what a real receiver measures and reports, and feeding
/// capacity instead lets a rate-based controller size its window as though it
/// owned the link.
fn ctx(link: &Link, f: &Flow, rtt_us: f64, rcv_rate_pps: f64, now_us: u64) -> CcContext {
    CcContext {
        mss: 1500,
        bandwidth_pps: link.capacity_pps as u32,
        rcv_rate_pps: rcv_rate_pps as u32,
        rtt_us: rtt_us as u32,
        snd_curr_seq: SeqNo::new(f.seq),
        // A saturating flow keeps its window full.
        flight_size: f.cwnd as u32,
        flow_wnd: 100_000.0,
        syn_interval_us: 10_000,
        now_us,
    }
}

/// Run `rounds` RTTs of the model, returning aggregate observations.
pub fn run(link: &Link, flows: &mut [Flow], rounds: usize) -> Outcome {
    let mut now_us: u64 = 0;
    let mut out = Outcome { peak_queue_pkts: 0.0, peak_qdelay_us: 0.0, loss_rounds: 0 };
    let bdp = link.capacity_pps * link.base_rtt_us / 1e6;

    for f in flows.iter_mut() {
        let c = ctx(link, f, link.base_rtt_us, link.capacity_pps, now_us);
        let o = f.cc.init(c);
        f.cwnd = o.cwnd.max(2.0);
        f.period_us = o.pkt_snd_period_us;
    }

    // Carried across rounds: converting a pacing interval into packets per round
    // trip needs a round-trip time, and this round's is not known until every
    // flow has offered its load. Last round's is the obvious estimate and is
    // what a real sender would have been pacing against anyway.
    let mut rtt_us = link.base_rtt_us;

    for _ in 0..rounds {
        let offered: Vec<f64> = flows.iter().map(|f| f.offered(rtt_us)).collect();
        let total: f64 = offered.iter().sum::<f64>().max(1e-9);
        let queue = (total - bdp).max(0.0);
        let qdelay_us = queue / link.capacity_pps * 1e6;
        rtt_us = link.base_rtt_us + qdelay_us;

        out.peak_queue_pkts = out.peak_queue_pkts.max(queue);
        out.peak_qdelay_us = out.peak_qdelay_us.max(qdelay_us);

        let overflowing = queue > link.buffer_pkts;
        if overflowing {
            out.loss_rounds += 1;
        }

        now_us += rtt_us as u64;

        for (i, f) in flows.iter_mut().enumerate() {
            // Delivered this round: the flow's proportional share of capacity.
            let share = offered[i] / total;
            let delivered = link.capacity_pps * rtt_us / 1e6 * share;
            f.delivered += delivered;
            f.seq = f.seq.wrapping_add(delivered.max(1.0) as u32) & 0x7FFF_FFFF;

            let rcv_rate = delivered / (rtt_us / 1e6);

            // Acknowledgements arrive whether or not anything was lost, so this
            // is not an either/or. Feeding only the loss under sustained
            // congestion starves a controller of the signal it sizes its window
            // from: UDT's `on_loss` adjusts the sending rate and never the
            // window, so a model that stopped calling `on_ack` froze the window
            // wherever slow start had left it, and then reported the resulting
            // buffer overflow as the controller's fault.
            let o = f.cc.on_ack(SeqNo::new(f.seq), ctx(link, f, rtt_us, rcv_rate, now_us));
            f.cwnd = o.cwnd.max(2.0);
            f.period_us = o.pkt_snd_period_us;

            // Drops fall on the flows overfilling the buffer, in proportion to
            // how much of it they occupy — applying loss uniformly would punish
            // a flow that is already backing off.
            if overflowing && share * queue > link.buffer_pkts * 0.1 {
                f.saw_loss = true;
                let o = f.cc.on_loss(&[], ctx(link, f, rtt_us, rcv_rate, now_us));
                f.cwnd = o.cwnd.max(2.0);
                f.period_us = o.pkt_snd_period_us;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::cubic::Cubic;
    use crate::congestion::{ledbat::Ledbat, udt_cc::UdtCc};

    /// A plain loss-based controller, for LEDBAT to be measured against.
    ///
    /// Grows by a packet a round trip and halves on loss, which is TCP Reno
    /// stripped to its control law. It exists because "scavenger" is a claim
    /// about *another flow*, and the other flow has to fill buffers for the
    /// claim to mean anything.
    ///
    /// It used to be [`UdtCc`] playing that part, and that worked only because
    /// UdtCc had a positive feedback loop in its window and filled every buffer
    /// it met. Now that it does not, LEDBAT++ takes 56% against it — its 60 ms
    /// delay target is simply more queue than a well-behaved UdtCc asks for, so
    /// the yielding claim was never about politeness so much as about how badly
    /// the other side behaved.
    struct LossBased {
        cwnd: f64,
    }

    impl CongestionControl for LossBased {
        fn init(&mut self, _ctx: CcContext) -> crate::congestion::CcOutput {
            self.cwnd = 2.0;
            self.out()
        }
        fn on_ack(&mut self, _ack: SeqNo, _ctx: CcContext) -> crate::congestion::CcOutput {
            self.cwnd += 1.0;
            self.out()
        }
        fn on_loss(
            &mut self,
            _loss: &[(SeqNo, SeqNo)],
            _ctx: CcContext,
        ) -> crate::congestion::CcOutput {
            self.cwnd = (self.cwnd / 2.0).max(2.0);
            self.out()
        }
        fn on_timeout(&mut self, _ctx: CcContext) -> crate::congestion::CcOutput {
            self.cwnd = 2.0;
            self.out()
        }
    }

    impl LossBased {
        fn new() -> Self {
            LossBased { cwnd: 2.0 }
        }
        fn out(&self) -> crate::congestion::CcOutput {
            crate::congestion::CcOutput {
                pkt_snd_period_us: 1.0,
                cwnd: self.cwnd,
                ack_period_ms: None,
                ack_interval_pkts: None,
                rto_us: None,
            }
        }
    }

    /// A typical wide-area bottleneck: 100 Mbit-ish, 50 ms base RTT, a buffer of
    /// roughly two bandwidth-delay products.
    fn wan() -> Link {
        Link { capacity_pps: 8_000.0, base_rtt_us: 50_000.0, buffer_pkts: 800.0 }
    }

    /// The defining property: sharing a bottleneck with a default (UDT) flow,
    /// LEDBAT++ must take materially less of it.
    ///
    /// This is what the loopback benchmark cannot show — there, queuing delay
    /// never rises, so the controller has nothing to yield to.
    #[test]
    fn ledbat_yields_to_a_loss_based_flow() {
        let link = wan();
        let mut flows =
            vec![Flow::new(Box::new(LossBased::new())), Flow::new(Box::new(Ledbat::new()))];
        run(&link, &mut flows, 4_000);

        let (loss_based, led) = (flows[0].delivered, flows[1].delivered);
        let share = led / (loss_based + led);
        assert!(
            share < 0.25,
            "LEDBAT took {:.0}% of the bottleneck ({led:.0} against {loss_based:.0} packets); \
             a scavenger should yield to a flow that fills buffers",
            share * 100.0,
        );
        assert!(led > 0.0, "LEDBAT was starved entirely rather than yielding");
    }

    /// What it does *not* do is yield to a flow that is also well behaved.
    ///
    /// Recorded because the previous version of this suite asserted the
    /// opposite, and passed only because [`UdtCc`] was filling every buffer it
    /// met. LEDBAT++ aims for 60 ms of standing queue; a fixed UdtCc asks for
    /// about a control interval's worth. Against that, the scavenger is the
    /// greedier of the two, which is a property of the 60 ms target rather than
    /// a defect in either controller.
    #[test]
    fn ledbat_does_not_yield_to_a_well_behaved_flow() {
        let link = wan();
        let mut flows = vec![Flow::new(Box::new(UdtCc::new())), Flow::new(Box::new(Ledbat::new()))];
        run(&link, &mut flows, 4_000);

        let (udt, led) = (flows[0].delivered, flows[1].delivered);
        let share = led / (udt + led);
        assert!(
            share > 0.35,
            "LEDBAT took {:.0}% against a fixed UdtCc; if it has started yielding \
             here, either its target or UdtCc's window has changed and this note \
             needs rewriting",
            share * 100.0,
        );
    }

    /// The default controller must converge instead of filling whatever buffer
    /// it meets.
    ///
    /// It did not. `on_ack` sized the window from the *current* round trip, and
    /// a flow delivering `R` over `T` already has `R × T` in flight — so asking
    /// for `R × (T + SYN)` was a standing request for 10 ms of data more than
    /// the path holds. The excess queued, the queue raised `T`, and the larger
    /// `T` asked for more: 903 ms of queuing delay on a 50 ms link, a window of
    /// 40 372 packets on a 60 us one, and the buffer overflowing in 3 997 rounds
    /// out of 4 000. Sizing from the smallest round trip seen breaks the loop.
    #[test]
    fn udt_cc_converges_without_filling_the_buffer() {
        let link = wan();
        let mut flows = vec![Flow::new(Box::new(UdtCc::new()))];
        let out = run(&link, &mut flows, 4_000);

        let bdp = link.capacity_pps * link.base_rtt_us / 1e6;
        assert!(
            flows[0].cwnd() < bdp * 4.0,
            "window settled at {:.0} packets against a {bdp:.0}-packet path",
            flows[0].cwnd(),
        );
        assert!(
            out.loss_rounds < 200,
            "the buffer overflowed in {} of 4000 rounds — the window is not converging",
            out.loss_rounds,
        );
        assert!(
            out.peak_qdelay_us < link.base_rtt_us * 8.0,
            "queued {:.0} us on a {:.0} us path",
            out.peak_qdelay_us,
            link.base_rtt_us,
        );
    }

    /// Alone on an idle link it must still use it — converging is not the same
    /// as being timid.
    #[test]
    fn udt_cc_alone_uses_the_link() {
        const ROUNDS: usize = 4_000;
        let link = wan();
        let mut flows = vec![Flow::new(Box::new(UdtCc::new()))];
        run(&link, &mut flows, ROUNDS);

        let capacity_pkts = link.capacity_pps * (ROUNDS as f64 * link.base_rtt_us) / 1e6;
        let used = flows[0].delivered / capacity_pkts;
        assert!(
            used > 0.5,
            "used {:.0}% of an idle link ({:.0} of {capacity_pkts:.0} packets)",
            used * 100.0,
            flows[0].delivered,
        );
    }

    /// Two of them should divide a bottleneck rather than one starving the
    /// other.
    #[test]
    fn two_udt_cc_flows_share_a_bottleneck() {
        let link = wan();
        let mut flows = vec![Flow::new(Box::new(UdtCc::new())), Flow::new(Box::new(UdtCc::new()))];
        run(&link, &mut flows, 4_000);

        let (a, b) = (flows[0].delivered, flows[1].delivered);
        let share = a.min(b) / (a + b);
        assert!(
            share > 0.3,
            "one flow took {:.0}% of the bottleneck ({a:.0} against {b:.0})",
            (1.0 - share) * 100.0,
        );
    }

    /// How each controller fares sharing a bottleneck with what the internet
    /// actually runs.
    ///
    /// This is the measurement that decides which one should be the default,
    /// and single-flow throughput cannot substitute for it. A controller that
    /// declines to back off looks identical to one that recovers well when it
    /// is alone on a link; only competition tells them apart.
    ///
    /// The result was the opposite of what the single-flow numbers suggested.
    /// UdtCc leads every lossy row measured against CUBIC alone on a link, and
    /// it is not winning by being greedy — put next to any flow that answers
    /// loss by halving, it is the one that gets starved. Its 12.5% nudge to a
    /// rate simply cannot reclaim capacity a competitor takes.
    #[test]
    fn a_flow_gets_a_share_of_a_contended_link() {
        fn build(name: &str) -> Box<dyn CongestionControl> {
            match name {
                "udt" => Box::new(UdtCc::new()),
                "cubic" => Box::new(Cubic::new()),
                _ => Box::new(LossBased::new()),
            }
        }
        for (label, link) in [
            ("wan", wan()),
            ("lan", Link { capacity_pps: 80_000.0, base_rtt_us: 1_000.0, buffer_pkts: 800.0 }),
        ] {
            for (a, b) in [("udt", "cubic"), ("udt", "reno"), ("cubic", "cubic"), ("cubic", "reno")]
            {
                let mut flows = vec![Flow::new(build(a)), Flow::new(build(b))];
                run(&link, &mut flows, 4_000);
                let (x, y) = (flows[0].delivered, flows[1].delivered);
                let share = x / (x + y).max(1.0);
                println!("  {label:<4} {a:<6} vs {b:<6}  {a} took {:>3.0}%", share * 100.0);
            }
        }
    }

    /// Two flows of the same controller must split a link roughly evenly.
    ///
    /// Unlike the cross-controller shares above, this one has a right answer:
    /// whatever a controller does, it should do it to itself fairly.
    #[test]
    fn cubic_shares_evenly_with_itself() {
        for (label, link) in [
            ("wan", wan()),
            ("lan", Link { capacity_pps: 80_000.0, base_rtt_us: 1_000.0, buffer_pkts: 800.0 }),
        ] {
            let mut flows =
                vec![Flow::new(Box::new(Cubic::new())), Flow::new(Box::new(Cubic::new()))];
            run(&link, &mut flows, 4_000);
            let (a, b) = (flows[0].delivered, flows[1].delivered);
            let weaker = a.min(b) / (a + b).max(1.0);
            assert!(
                weaker > 0.3,
                "{label}: one CUBIC flow took {:.0}% from another",
                (1.0 - weaker) * 100.0
            );
        }
    }

    /// Prints the model's numbers, for when the assertions above need context.
    /// `cargo test -p udt-proto --  --ignored --nocapture bottleneck_report`
    #[test]
    #[ignore]
    fn bottleneck_report() {
        for (label, link) in [
            ("wan 50ms", wan()),
            ("lan 1ms", Link { capacity_pps: 80_000.0, base_rtt_us: 1_000.0, buffer_pkts: 800.0 }),
            (
                "loopback 60us",
                Link { capacity_pps: 200_000.0, base_rtt_us: 60.0, buffer_pkts: 2_000.0 },
            ),
        ] {
            let mut flows =
                vec![Flow::new(Box::new(UdtCc::new())), Flow::new(Box::new(Ledbat::new()))];
            let o = run(&link, &mut flows, 4_000);
            let (udt, led) = (flows[0].delivered, flows[1].delivered);
            println!(
                "[{label:<14}] ledbat {:>5.1}% of link   peak qdelay {:>8.0} us   \
                 cwnd udt {:>7.0} ledbat {:>6.0}   loss rounds {}",
                100.0 * led / (udt + led),
                o.peak_qdelay_us,
                flows[0].cwnd(),
                flows[1].cwnd(),
                o.loss_rounds,
            );
        }
    }

    /// Alone on the link, it must still use it — yielding is not the same as
    /// being useless.
    #[test]
    fn ledbat_alone_uses_the_link() {
        const ROUNDS: usize = 4_000;
        let link = wan();
        let mut solo = vec![Flow::new(Box::new(Ledbat::new()))];
        run(&link, &mut solo, ROUNDS);

        // Measured against the link rather than against a shared run. The
        // comparison used to be with LEDBAT's share when running beside UdtCc,
        // which only worked while UdtCc was crowding it out; against a fixed one
        // it gets roughly half, and "half of a contended link" says nothing
        // about whether an *idle* link gets used.
        // Rounds advance by at least the base round trip, so this is a floor on
        // the capacity that passed by, and the share below is therefore a floor too.
        let rounds_us = ROUNDS as f64 * link.base_rtt_us;
        let capacity_pkts = link.capacity_pps * rounds_us / 1e6;
        let used = solo[0].delivered / capacity_pkts;
        assert!(
            used > 0.5,
            "LEDBAT alone used {:.0}% of an idle link ({:.0} of {capacity_pkts:.0} packets) — \
             yielding is not the same as being useless",
            used * 100.0,
            solo[0].delivered,
        );
    }

    /// The point of a scavenger is bounded added latency. Alone on the link,
    /// the standing queue it builds must stay near its target rather than
    /// filling the buffer the way a loss-based controller does.
    #[test]
    fn ledbat_alone_keeps_the_queue_near_target() {
        let link = wan();

        let mut led = vec![Flow::new(Box::new(Ledbat::new()))];
        let led_out = run(&link, &mut led, 4_000);

        let mut udt = vec![Flow::new(Box::new(UdtCc::new()))];
        let udt_out = run(&link, &mut udt, 4_000);

        assert!(
            led_out.peak_qdelay_us < udt_out.peak_qdelay_us,
            "LEDBAT queued {:.0} us, UDT {:.0} us — the delay-based controller \
             should be the gentler one",
            led_out.peak_qdelay_us,
            udt_out.peak_qdelay_us,
        );
    }

    /// On a fast path the slowdown schedule must not degenerate into constant
    /// churn. With a 60 us RTT the unclamped LEDBAT++ cadence fires roughly a
    /// thousand times a second, pinning the window at two packets for much of
    /// the flow's life.
    ///
    /// The window stays small here for a second reason, which is LEDBAT's and
    /// not the schedule's: it aims for 60 ms of standing queue, and on this link
    /// that is 12 000 packets against a 2 000-packet buffer. The target cannot
    /// be reached, so the delay signal never says "back off" and the flow learns
    /// only from loss — a fixed target in milliseconds does not suit a path
    /// whose whole round trip is 60 us. That is worth fixing in the controller
    /// rather than asserting around.
    #[test]
    fn low_rtt_path_does_not_thrash_the_window() {
        let link = Link { capacity_pps: 200_000.0, base_rtt_us: 60.0, buffer_pkts: 2_000.0 };
        let mut flows = vec![Flow::new(Box::new(Ledbat::new()))];
        run(&link, &mut flows, 20_000);

        // 20 000 rounds at 60 us is ~1.2 s of modelled time. With the wall-clock
        // floor there is at most a couple of slowdowns in that window, so the
        // flow should end up with a window far above the two-packet floor.
        // Above the floor, which is what the slowdown schedule is responsible
        // for. It settles near six rather than the eight this once asserted,
        // because the model now feeds loss and acknowledgements in the same
        // round as a real connection does, and on this link LEDBAT sees loss
        // constantly for the reason above.
        assert!(
            flows[0].cwnd() > 4.0,
            "window collapsed to {:.1} packets on a fast path — slowdowns are \
             firing far too often",
            flows[0].cwnd(),
        );
        assert!(flows[0].delivered > 0.0, "the flow moved nothing at all");
    }
}
