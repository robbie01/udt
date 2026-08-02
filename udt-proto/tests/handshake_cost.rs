//! What a handshake to a listener costs in packets, on paths of various length.

use bytes::Bytes;
use udt_proto::{CcKind, Connection, Listener, ListenerEvent, PeerAddr, SeqNo, TransmitBuf};

const MSS: u32 = 1500;

fn peer() -> PeerAddr {
    PeerAddr([9u8; 20])
}

fn split(tx: &TransmitBuf) -> Vec<Bytes> {
    tx.runs()
        .flat_map(|(b, seg)| b.chunks(seg.max(1)).map(Bytes::copy_from_slice).collect::<Vec<_>>())
        .collect()
}

/// Runs a clean client-to-listener handshake over a link with `one_way_us` of
/// delay. Returns how many datagrams the client sent, and when it connected.
fn handshake_cost(one_way_us: u64) -> (usize, u64) {
    let mut listener = Listener::new(0x3333, MSS, 0, 0xABCD_EF01_2345_6789, CcKind::default());
    let mut client = Connection::new_active(0x1111, SeqNo::new(1000), MSS, 0, CcKind::default());
    let mut now = 0u64;
    let mut events = Vec::new();
    let mut to_client: Vec<(u64, Bytes)> = Vec::new();
    let mut to_server: Vec<(u64, Bytes)> = Vec::new();
    let mut sent = 0usize;

    for _ in 0..200_000 {
        now += 1_000;

        let mut due: Vec<Bytes> = Vec::new();
        to_client.retain(|(at, d)| {
            if *at <= now {
                due.push(d.clone());
                false
            } else {
                true
            }
        });
        for datagram in due {
            let mut tx = TransmitBuf::new();
            client.on_datagram(datagram, now, &mut tx, &mut events);
            for d in split(&tx) {
                sent += 1;
                to_server.push((now + one_way_us, d));
            }
        }

        let mut tx = TransmitBuf::new();
        client.on_timer(now, &mut tx, &mut events);
        for d in split(&tx) {
            sent += 1;
            to_server.push((now + one_way_us, d));
        }

        let mut due: Vec<Bytes> = Vec::new();
        to_server.retain(|(at, d)| {
            if *at <= now {
                due.push(d.clone());
                false
            } else {
                true
            }
        });
        let mut accepted = false;
        for datagram in due {
            let mut out = Vec::new();
            listener.on_datagram(peer(), datagram, now, &mut out);
            for event in out {
                match event {
                    ListenerEvent::SendTo { data, .. } => to_client.push((now + one_way_us, data)),
                    ListenerEvent::Accept(..) => accepted = true,
                }
            }
        }
        if accepted && client.is_connected() {
            return (sent, now);
        }
        if client.is_connected() && to_client.is_empty() && to_server.is_empty() {
            return (sent, now);
        }
    }
    panic!("handshake never completed at {one_way_us}us one-way");
}

/// A clean path costs two packets from the client: the induction and the
/// conclusion. Anything more is a retransmission of something that was never
/// lost.
///
/// Dialling a listener used to be given the rendezvous backoff, whose first
/// retry is 25 ms — shorter than most round trips on the internet — so a clean
/// handshake cost four packets at 50 ms and more further out. A rendezvous
/// wants that schedule because its opening packets are *expected* to be
/// dropped while the firewall pinhole opens; a client dialling a listener has
/// no pinhole to open and so nothing to gain by asking again before an answer
/// could have arrived.
///
/// Two is also the floor at the near end: the first packet used to wait out an
/// interval before going anywhere, which a 2 ms path noticed as 29 ms.
#[test]
fn a_clean_handshake_to_a_listener_costs_two_packets() {
    // Every round trip shorter than the retransmit interval, which is what a
    // timer with no round-trip estimate has to guess with.
    for one_way_ms in [1u64, 10, 25, 50, 100] {
        let (sent, at) = handshake_cost(one_way_ms * 1_000);
        let rtt = one_way_ms * 2;
        eprintln!(
            "one-way {one_way_ms:>3}ms  rtt {rtt:>3}ms -> {sent} packets, connected at {at}us"
        );
        assert_eq!(sent, 2, "a clean {rtt}ms round trip cost {sent} handshake packets, not 2");
        // Two round trips is what the protocol costs; the slack is this
        // harness's one-millisecond tick, not the protocol's.
        assert!(
            at <= 2 * rtt * 1_000 + 5_000,
            "connecting took {at}us over a {rtt}ms round trip, which is more than two of them"
        );
    }
}

/// Past that interval a fixed timer cannot help: it has no round-trip estimate
/// to wait for, and the alternative is a first retry so long that genuine loss
/// on an ordinary path costs a second to notice. The C++ reference makes the
/// same trade at the same 250 ms. Recorded rather than fixed — what matters is
/// that it still completes.
#[test]
fn a_round_trip_longer_than_the_retransmit_interval_still_connects() {
    let (sent, at) = handshake_cost(150_000);
    eprintln!("rtt 300ms -> {sent} packets, connected at {at}us");
    assert!(sent >= 2, "impossibly cheap");
    assert!(at <= 1_500_000, "connecting took {at}us over a 300ms round trip");
}
