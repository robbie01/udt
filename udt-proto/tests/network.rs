//! Two connections over a simulated network.
//!
//! Loopback never drops, reorders or delays a packet, so a test suite built on
//! it exercises almost none of what a transport is for. This drives two
//! [`Connection`]s against each other over a link that does all three, on
//! virtual time and a seeded generator, so a failure reproduces exactly.
//!
//! Everything here goes through the public API, which also keeps the crate
//! honest about being drivable without privileged access to its internals.

use std::collections::VecDeque;

use udt_proto::{CcKind, Connection, Event, SendOutcome, SeqNo, TransmitBuf};

/// Deterministic generator. Values are only ever compared against
/// probabilities, so a small linear congruential generator is plenty.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Any odd multiplier works; these are the Numerical Recipes constants.
        Rng(seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407))
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }

    /// True with probability `p`.
    fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            return false;
        }
        (self.next_u64() % 1_000_000) < (p * 1_000_000.0) as u64
    }

    fn range(&mut self, max: u64) -> u64 {
        if max == 0 { 0 } else { self.next_u64() % max }
    }
}

/// What the link does to packets crossing it.
#[derive(Clone, Copy)]
struct LinkConfig {
    /// Fraction of packets dropped outright.
    loss: f64,
    /// Fraction delivered twice.
    duplicate: f64,
    /// One-way delay, microseconds.
    delay_us: u64,
    /// Extra delay drawn uniformly from `0..jitter_us`. Non-zero jitter
    /// reorders packets, since a later one can draw a shorter delay.
    jitter_us: u64,
    /// Silently discard anything larger than this, modelling a path whose MTU
    /// is smaller than the connection negotiated.
    mtu_limit: Option<usize>,
}

impl LinkConfig {
    fn perfect() -> Self {
        LinkConfig { loss: 0.0, duplicate: 0.0, delay_us: 100, jitter_us: 0, mtu_limit: None }
    }

    fn lossy(loss: f64) -> Self {
        LinkConfig { loss, ..Self::perfect() }
    }

    fn reordering(jitter_us: u64) -> Self {
        LinkConfig { jitter_us, ..Self::perfect() }
    }

    /// A path that carries control packets but silently eats full-size data.
    fn mtu_limited(limit: usize) -> Self {
        LinkConfig { mtu_limit: Some(limit), ..Self::perfect() }
    }
}

/// One direction of the link.
struct Link {
    cfg: LinkConfig,
    rng: Rng,
    /// Datagrams in flight, as (arrival time, payload). Unsorted; jitter means
    /// arrival order is not send order.
    inflight: Vec<(u64, bytes::Bytes)>,
    sent: u64,
    dropped: u64,
}

impl Link {
    fn new(cfg: LinkConfig, seed: u64) -> Self {
        Link { cfg, rng: Rng::new(seed), inflight: Vec::new(), sent: 0, dropped: 0 }
    }

    fn send(&mut self, now: u64, datagram: bytes::Bytes) {
        self.sent += 1;
        if self.cfg.mtu_limit.is_some_and(|limit| datagram.len() > limit) {
            self.dropped += 1;
            return;
        }
        if self.rng.chance(self.cfg.loss) {
            self.dropped += 1;
            return;
        }
        let arrival = now + self.cfg.delay_us + self.rng.range(self.cfg.jitter_us);
        self.inflight.push((arrival, datagram.clone()));
        if self.rng.chance(self.cfg.duplicate) {
            let again = now + self.cfg.delay_us + self.rng.range(self.cfg.jitter_us);
            self.inflight.push((again, datagram));
        }
    }

    fn next_arrival(&self) -> Option<u64> {
        self.inflight.iter().map(|(t, _)| *t).min()
    }

    /// Take everything that has arrived by `now`, in arrival order.
    fn take_arrived(&mut self, now: u64) -> Vec<bytes::Bytes> {
        let mut due: Vec<(u64, bytes::Bytes)> = Vec::new();
        self.inflight.retain(|(t, d)| {
            if *t <= now {
                due.push((*t, d.clone()));
                false
            } else {
                true
            }
        });
        due.sort_by_key(|(t, _)| *t);
        due.into_iter().map(|(_, d)| d).collect()
    }
}

/// A pair of peers joined by a simulated link, driven on virtual time.
struct Sim {
    now: u64,
    a: Connection,
    b: Connection,
    a_to_b: Link,
    b_to_a: Link,
    /// Messages each side has delivered to its application.
    a_got: Vec<bytes::Bytes>,
    b_got: Vec<bytes::Bytes>,
    /// Outgoing datagrams, one buffer per side. Separate buffers are what let
    /// each side be fed and drained independently.
    a_tx: TransmitBuf,
    b_tx: TransmitBuf,
    events: Vec<Event>,
}

/// Ends the run rather than spinning forever if the protocol wedges.
const MAX_STEPS: usize = 4_000_000;
/// Virtual time limit, 120 seconds.
const MAX_TIME_US: u64 = 120_000_000;

impl Sim {
    fn new(cfg: LinkConfig, seed: u64) -> Self {
        Self::asymmetric(cfg, cfg, seed)
    }

    fn asymmetric(to_b: LinkConfig, to_a: LinkConfig, seed: u64) -> Self {
        let now = 1_000_000;
        // Rendezvous on both sides: it needs no listener, so the whole
        // handshake runs through the same two objects under test.
        let a = Connection::new_rendezvous(1, SeqNo::new(1000), 1500, now, CcKind::Udt);
        let b = Connection::new_rendezvous(2, SeqNo::new(9000), 1500, now, CcKind::Udt);
        Sim {
            now,
            a,
            b,
            a_to_b: Link::new(to_b, seed),
            b_to_a: Link::new(to_a, seed ^ 0x5DEECE66D),
            a_got: Vec::new(),
            b_got: Vec::new(),
            a_tx: TransmitBuf::new(),
            b_tx: TransmitBuf::new(),
            events: Vec::new(),
        }
    }

    /// Advance to the next thing that wants attention: an arrival or a timer.
    ///
    /// Returns false when nothing is left to do.
    fn step(&mut self) -> bool {
        let next = [
            self.a_to_b.next_arrival(),
            self.b_to_a.next_arrival(),
            self.a.next_deadline_us(),
            self.b.next_deadline_us(),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(next) = next else { return false };
        self.now = self.now.max(next);
        if self.now > MAX_TIME_US {
            return false;
        }

        for datagram in self.a_to_b.take_arrived(self.now) {
            self.b.on_datagram(datagram, self.now, &mut self.b_tx, &mut self.events);
        }
        self.drain(Side::B);
        for datagram in self.b_to_a.take_arrived(self.now) {
            self.a.on_datagram(datagram, self.now, &mut self.a_tx, &mut self.events);
        }
        self.drain(Side::A);

        self.a.on_timer(self.now, &mut self.a_tx, &mut self.events);
        self.drain(Side::A);
        self.b.on_timer(self.now, &mut self.b_tx, &mut self.events);
        self.drain(Side::B);
        true
    }

    /// Route one side's events: datagrams onto its outgoing link, messages
    /// into its delivered list.
    fn drain(&mut self, side: Side) {
        let (tx, link) = match side {
            Side::A => (&mut self.a_tx, &mut self.a_to_b),
            Side::B => (&mut self.b_tx, &mut self.b_to_a),
        };
        for datagram in tx.datagrams() {
            link.send(self.now, bytes::Bytes::copy_from_slice(datagram));
        }
        tx.clear();

        // Always try to read: DataReady is edge-triggered, and a message can
        // become deliverable without one when an earlier gap is filled.
        loop {
            let msg = match side {
                Side::A => self.a.recv_msg(),
                Side::B => self.b.recv_msg(),
            };
            match msg {
                Some(m) => match side {
                    Side::A => self.a_got.push(m),
                    Side::B => self.b_got.push(m),
                },
                None => break,
            }
        }
        self.events.clear();
    }

    fn connect(&mut self) {
        for _ in 0..MAX_STEPS {
            if self.a.is_connected() && self.b.is_connected() {
                return;
            }
            if !self.step() {
                break;
            }
        }
        panic!(
            "handshake did not complete (a={}, b={}, t={}us)",
            self.a.is_connected(),
            self.b.is_connected(),
            self.now
        );
    }

    /// Send `count` messages of `size` bytes from A, and run until B has them
    /// all. Returns the virtual microseconds the transfer took.
    fn transfer(&mut self, count: usize, size: usize, opts: SendOpts) -> u64 {
        let start = self.now;
        let mut queued = 0usize;
        let mut pending: Option<bytes::Bytes> = None;

        for step in 0..MAX_STEPS {
            while queued < count {
                let payload =
                    pending.take().unwrap_or_else(|| bytes::Bytes::from(message(queued, size)));
                match self.a.send_msg(
                    payload.clone(),
                    opts.ttl_ms,
                    opts.in_order,
                    self.now,
                    &mut self.a_tx,
                ) {
                    SendOutcome::Queued => queued += 1,
                    SendOutcome::WouldBlock => {
                        pending = Some(payload);
                        break;
                    }
                    SendOutcome::Rejected => panic!("send rejected at message {queued}"),
                }
            }
            self.drain(Side::A);

            if self.b_got.len() >= count {
                return self.now - start;
            }
            if !self.step() {
                panic!(
                    "transfer stalled: {} of {count} delivered after {}us ({step} steps)",
                    self.b_got.len(),
                    self.now - start
                );
            }
        }
        panic!("transfer exceeded {MAX_STEPS} steps");
    }
}

#[derive(Clone, Copy)]
enum Side {
    A,
    B,
}

#[derive(Clone, Copy, Default)]
struct SendOpts {
    ttl_ms: Option<u32>,
    in_order: bool,
}

impl SendOpts {
    fn ordered() -> Self {
        SendOpts { ttl_ms: None, in_order: true }
    }

    fn unordered() -> Self {
        SendOpts { ttl_ms: None, in_order: false }
    }
}

/// A message whose contents identify it, so misdelivery is detectable.
fn message(index: usize, size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size];
    let tag = (index as u32).to_be_bytes();
    v[..4].copy_from_slice(&tag);
    for (i, b) in v.iter_mut().enumerate().skip(4) {
        *b = (index as u8).wrapping_add(i as u8);
    }
    v
}

fn tag_of(msg: &[u8]) -> usize {
    u32::from_be_bytes(msg[..4].try_into().unwrap()) as usize
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn handshake_completes_over_a_clean_link() {
    let mut sim = Sim::new(LinkConfig::perfect(), 1);
    sim.connect();
}

#[test]
fn handshake_completes_when_half_the_packets_are_lost() {
    for seed in 0..8 {
        let mut sim = Sim::new(LinkConfig::lossy(0.5), seed);
        sim.connect();
    }
}

#[test]
fn transfer_survives_one_percent_loss() {
    let mut sim = Sim::new(LinkConfig::lossy(0.01), 42);
    sim.connect();
    sim.transfer(200, 4096, SendOpts::ordered());
    assert_eq!(sim.b_got.len(), 200);
    for (i, msg) in sim.b_got.iter().enumerate() {
        assert_eq!(tag_of(msg), i, "message {i} arrived out of order or corrupted");
        assert_eq!(msg.len(), 4096);
        assert_eq!(&msg[..], &message(i, 4096)[..], "message {i} corrupted");
    }
    assert!(sim.a_to_b.dropped > 0, "the test dropped nothing, so it proved nothing");
}

#[test]
fn transfer_survives_ten_percent_loss() {
    let mut sim = Sim::new(LinkConfig::lossy(0.10), 7);
    sim.connect();
    sim.transfer(100, 4096, SendOpts::ordered());
    assert_eq!(sim.b_got.len(), 100);
    for (i, msg) in sim.b_got.iter().enumerate() {
        assert_eq!(&msg[..], &message(i, 4096)[..], "message {i} corrupted");
    }
}

#[test]
fn ordered_delivery_holds_under_reordering() {
    let mut sim = Sim::new(LinkConfig::reordering(3_000), 11);
    sim.connect();
    sim.transfer(150, 4096, SendOpts::ordered());
    for (i, msg) in sim.b_got.iter().enumerate() {
        assert_eq!(tag_of(msg), i, "reordering leaked through to the application");
    }
}

#[test]
fn duplicates_are_not_delivered_twice() {
    let cfg = LinkConfig { duplicate: 0.10, ..LinkConfig::perfect() };
    let mut sim = Sim::new(cfg, 3);
    sim.connect();
    sim.transfer(100, 2048, SendOpts::ordered());
    assert_eq!(sim.b_got.len(), 100, "a duplicated packet produced a duplicate message");
}

#[test]
fn unordered_delivery_does_not_livelock_under_loss() {
    // The failure this guards against: a sender that keeps retransmitting
    // packets the receiver has already moved past, making no forward progress.
    let mut sim = Sim::new(LinkConfig::lossy(0.05), 23);
    sim.connect();
    sim.transfer(200, 8192, SendOpts::unordered());
    assert_eq!(sim.b_got.len(), 200);

    let mut seen: Vec<usize> = sim.b_got.iter().map(|m| tag_of(m)).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 200, "some messages were delivered more than once");
    for (i, msg) in sim.b_got.iter().enumerate() {
        let tag = tag_of(msg);
        assert_eq!(&msg[..], &message(tag, 8192)[..], "message at position {i} corrupted");
    }
}

#[test]
fn unordered_delivery_can_overtake_a_gap() {
    // Ordered delivery has to wait for a retransmission; unordered should not.
    let mut ordered = Sim::new(LinkConfig::lossy(0.05), 99);
    ordered.connect();
    let ordered_us = ordered.transfer(200, 8192, SendOpts::ordered());

    let mut unordered = Sim::new(LinkConfig::lossy(0.05), 99);
    unordered.connect();
    let unordered_us = unordered.transfer(200, 8192, SendOpts::unordered());

    // Same seed, same losses, so this compares like with like.
    assert!(
        unordered_us <= ordered_us,
        "unordered delivery was slower than ordered ({unordered_us}us vs {ordered_us}us)"
    );
}

#[test]
fn asymmetric_loss_on_the_acknowledgement_path() {
    // Data crosses cleanly but acknowledgements are lost, so the sender keeps
    // believing its window is full.
    let mut sim = Sim::asymmetric(LinkConfig::perfect(), LinkConfig::lossy(0.20), 5);
    sim.connect();
    sim.transfer(100, 4096, SendOpts::ordered());
    assert_eq!(sim.b_got.len(), 100);
}

/// A TTL shorter than the round trip means essentially every message expires,
/// so the sender emits a `MsgDrop` for each one. Those are single
/// unacknowledged datagrams: lose one and the receiver is left waiting for a
/// range that will never be sent, its acknowledgement point pinned behind the
/// gap. That used to kill the connection outright -- 26 of 100 messages
/// delivered, then the expiry timer gave up after 86 virtual seconds -- and it
/// only appears when loss and expiry coincide, which loopback never does.
#[test]
fn a_lost_msg_drop_does_not_strand_the_receiver() {
    let mut sim = Sim::new(LinkConfig::lossy(0.05), 17);
    sim.connect();

    let mut queued = 0;
    for _ in 0..MAX_STEPS {
        while queued < 100 {
            let payload = bytes::Bytes::from(message(queued, 8192));
            match sim.a.send_msg(payload, Some(5), false, sim.now, &mut sim.a_tx) {
                SendOutcome::Queued => queued += 1,
                SendOutcome::WouldBlock => break,
                SendOutcome::Rejected => panic!("send rejected"),
            }
        }
        sim.drain(Side::A);
        if queued == 100 && sim.a.snd_buf_is_empty() {
            break;
        }
        if !sim.step() {
            break;
        }
    }

    let stats = sim.a.stats();
    assert!(stats.connected, "connection died rather than skipping expired messages");
    assert!(sim.a.snd_buf_is_empty(), "send buffer never drained; expiry is not releasing");
    assert!(
        stats.snd_loss_len == 0,
        "{} sequences left on the loss list with nothing to send for them",
        stats.snd_loss_len
    );
}

#[test]
fn expired_messages_are_skipped_rather_than_stalling() {
    let mut sim = Sim::new(LinkConfig::lossy(0.05), 17);
    sim.connect();

    // Comfortably longer than the round trip, so most of these should survive.
    let opts = SendOpts { ttl_ms: Some(50), in_order: false };
    let mut queued = 0;
    for _ in 0..MAX_STEPS {
        while queued < 100 {
            let payload = bytes::Bytes::from(message(queued, 8192));
            match sim.a.send_msg(payload, opts.ttl_ms, opts.in_order, sim.now, &mut sim.a_tx) {
                SendOutcome::Queued => queued += 1,
                SendOutcome::WouldBlock => break,
                SendOutcome::Rejected => panic!("rejected"),
            }
        }
        sim.drain(Side::A);
        if queued == 100 && sim.a.snd_buf_is_empty() {
            break;
        }
        if !sim.step() {
            break;
        }
    }

    // The point is that the connection drains rather than wedging on a message
    // it can never deliver; how many survive is a timing matter.
    assert!(sim.a.snd_buf_is_empty(), "send buffer never drained -- expiry is not releasing");
    assert!(sim.b_got.len() <= 100);
    assert!(sim.b_got.len() >= 90, "only {} of 100 survived a generous TTL", sim.b_got.len());
}

#[test]
fn both_directions_at_once_under_loss() {
    let mut sim = Sim::new(LinkConfig::lossy(0.02), 31);
    sim.connect();

    const N: usize = 60;
    let mut a_queued = 0;
    let mut b_queued = 0;
    let mut queue: VecDeque<()> = VecDeque::new();
    queue.push_back(());

    for _ in 0..MAX_STEPS {
        while a_queued < N {
            let m = bytes::Bytes::from(message(a_queued, 4096));
            match sim.a.send_msg(m, None, true, sim.now, &mut sim.a_tx) {
                SendOutcome::Queued => a_queued += 1,
                _ => break,
            }
        }
        sim.drain(Side::A);
        while b_queued < N {
            let m = bytes::Bytes::from(message(b_queued, 4096));
            match sim.b.send_msg(m, None, true, sim.now, &mut sim.b_tx) {
                SendOutcome::Queued => b_queued += 1,
                _ => break,
            }
        }
        sim.drain(Side::B);

        if sim.a_got.len() >= N && sim.b_got.len() >= N {
            break;
        }
        if !sim.step() {
            break;
        }
    }

    assert_eq!(sim.a_got.len(), N, "A did not receive everything B sent");
    assert_eq!(sim.b_got.len(), N, "B did not receive everything A sent");
}

/// Loss should cost proportionally, not catastrophically.
///
/// This is the shape the C++ reference fails at: 2% loss costs it a factor of
/// 200 where it costs this implementation about 2.5. The bound is deliberately
/// loose, because the point is to catch a recovery path that has gone
/// quadratic, not to pin down a constant.
///
/// Averaged over several seeds, because one is not enough to judge by: the
/// same configuration ranges from 7x to 35x depending only on which packets
/// the generator happens to drop. The single-seed version of this test read as
/// a hard regression when the initial window was retuned, and it was noise.
#[test]
fn loss_recovery_is_not_catastrophic() {
    const SEEDS: [u64; 5] = [3, 17, 42, 77, 101];
    let mut total = 0.0;

    for seed in SEEDS {
        let mut clean = Sim::new(LinkConfig::perfect(), seed);
        clean.connect();
        let clean_us = clean.transfer(150, 8192, SendOpts::ordered());

        let mut lossy = Sim::new(LinkConfig::lossy(0.05), seed);
        lossy.connect();
        let lossy_us = lossy.transfer(150, 8192, SendOpts::ordered());

        total += lossy_us as f64 / clean_us as f64;
    }

    let mean = total / SEEDS.len() as f64;
    // Printed because the bound is loose on purpose -- a single seed ranges from
    // 7x to 35x on drop pattern alone, so the assert can only catch a collapse.
    // The number itself is what tells you whether a change to loss recovery did
    // anything, and `--nocapture` is how you see it.
    println!("[loss 5%] {mean:.1}x the clean transfer time, mean of {} seeds", SEEDS.len());
    assert!(mean < 50.0, "5% loss cost {mean:.1}x on average -- recovery is not proportional");
}

/// A path that carries small packets and silently discards large ones used to
/// hang the connection forever rather than failing it. The handshake is small,
/// so it completes; every data packet then vanishes; and the peer's keep-alives
/// keep resetting the expiry counter, so the hard timeout is never reached and
/// the sender retransmits into the void indefinitely.
#[test]
fn a_path_that_cannot_carry_full_size_packets_is_reported() {
    // Comfortably above a handshake, well below a full data packet.
    let mut sim = Sim::new(LinkConfig::mtu_limited(200), 4);
    sim.connect();

    let payload = bytes::Bytes::from(message(0, 8192));
    assert_eq!(sim.a.send_msg(payload, None, true, sim.now, &mut sim.a_tx), SendOutcome::Queued);
    sim.drain(Side::A);

    for _ in 0..MAX_STEPS {
        if sim.a.stats().connected {
            if !sim.step() {
                break;
            }
        } else {
            break;
        }
    }

    assert!(
        !sim.a.stats().connected,
        "the connection is still up after {}us with nothing delivered",
        sim.now
    );
    assert_eq!(sim.b_got.len(), 0, "something got through a link that drops everything large");
}

/// The same detection must not fire on a link that is merely slow and lossy,
/// where data does eventually get through.
#[test]
fn a_slow_lossy_path_is_not_mistaken_for_an_unusable_one() {
    let cfg = LinkConfig { loss: 0.20, delay_us: 50_000, ..LinkConfig::perfect() };
    let mut sim = Sim::new(cfg, 8);
    sim.connect();
    sim.transfer(20, 8192, SendOpts::ordered());
    assert_eq!(sim.b_got.len(), 20);
    assert!(sim.a.stats().connected, "a working connection was declared unusable");
}
