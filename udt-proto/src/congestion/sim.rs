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
    seq: u32,
    /// Packets delivered over the run.
    pub delivered: f64,
    /// Whether this flow saw a loss signal at any point.
    pub saw_loss: bool,
}

impl Flow {
    pub fn new(cc: Box<dyn CongestionControl>) -> Self {
        Flow { cc, cwnd: 2.0, seq: 0, delivered: 0.0, saw_loss: false }
    }

    pub fn cwnd(&self) -> f64 {
        self.cwnd
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
    }

    for _ in 0..rounds {
        let total: f64 = flows.iter().map(|f| f.cwnd).sum::<f64>().max(1e-9);
        let queue = (total - bdp).max(0.0);
        let qdelay_us = queue / link.capacity_pps * 1e6;
        let rtt_us = link.base_rtt_us + qdelay_us;

        out.peak_queue_pkts = out.peak_queue_pkts.max(queue);
        out.peak_qdelay_us = out.peak_qdelay_us.max(qdelay_us);

        let overflowing = queue > link.buffer_pkts;
        if overflowing {
            out.loss_rounds += 1;
        }

        now_us += rtt_us as u64;

        for f in flows.iter_mut() {
            // Delivered this round: the flow's proportional share of capacity.
            let share = f.cwnd / total;
            let delivered = link.capacity_pps * rtt_us / 1e6 * share;
            f.delivered += delivered;
            f.seq = f.seq.wrapping_add(delivered.max(1.0) as u32) & 0x7FFF_FFFF;

            let rcv_rate = delivered / (rtt_us / 1e6);
            let c = ctx(link, f, rtt_us, rcv_rate, now_us);
            // Drops fall on the flows overfilling the buffer, in proportion to
            // how much of it they occupy — applying loss uniformly would punish
            // a flow that is already backing off.
            let o = if overflowing && share * queue > link.buffer_pkts * 0.1 {
                f.saw_loss = true;
                f.cc.on_loss(&[], c)
            } else {
                f.cc.on_ack(SeqNo::new(f.seq), c)
            };
            f.cwnd = o.cwnd.max(2.0);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::{ledbat::Ledbat, udt_cc::UdtCc};

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
    fn ledbat_yields_to_udt_cc_on_a_bottleneck() {
        let link = wan();
        let mut flows = vec![Flow::new(Box::new(UdtCc::new())), Flow::new(Box::new(Ledbat::new()))];
        run(&link, &mut flows, 4_000);

        let udt = flows[0].delivered;
        let led = flows[1].delivered;
        let share = led / (udt + led);
        assert!(
            share < 0.25,
            "LEDBAT took {:.0}% of the bottleneck ({led:.0} vs {udt:.0} packets); \
             a scavenger should yield",
            share * 100.0,
        );
        assert!(led > 0.0, "LEDBAT was starved entirely rather than yielding");
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
        let link = wan();
        let mut solo = vec![Flow::new(Box::new(Ledbat::new()))];
        run(&link, &mut solo, 4_000);

        let mut shared =
            vec![Flow::new(Box::new(UdtCc::new())), Flow::new(Box::new(Ledbat::new()))];
        run(&link, &mut shared, 4_000);

        assert!(
            solo[0].delivered > shared[1].delivered * 2.0,
            "LEDBAT alone delivered {:.0} but only {:.0} when sharing — it is not \
             using the idle link",
            solo[0].delivered,
            shared[1].delivered,
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
    #[test]
    fn low_rtt_path_does_not_thrash_the_window() {
        let link = Link { capacity_pps: 200_000.0, base_rtt_us: 60.0, buffer_pkts: 2_000.0 };
        let mut flows = vec![Flow::new(Box::new(Ledbat::new()))];
        run(&link, &mut flows, 20_000);

        // 20 000 rounds at 60 us is ~1.2 s of modelled time. With the wall-clock
        // floor there is at most a couple of slowdowns in that window, so the
        // flow should end up with a window far above the two-packet floor.
        assert!(
            flows[0].cwnd() > 8.0,
            "window collapsed to {:.1} packets on a fast path — slowdowns are \
             firing far too often",
            flows[0].cwnd(),
        );
    }
}
