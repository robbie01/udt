//! Data sent with the handshake conclusion, a round trip before the connection
//! is usable.
//!
//! The handshake is driven by hand rather than through the simulator, because
//! the simulator pairs two rendezvous connections and this is the connect and
//! accept path — only the active role sends a conclusion for data to ride.

use bytes::Bytes;
use udt_proto::{CcKind, Connection, Event, Listener, ListenerEvent, PeerAddr, SeqNo, TransmitBuf};

const MSS: u32 = 1500;
const CLIENT_ID: u32 = 0x1111_2222;
const LISTENER_ID: u32 = 0x3333_4444;

fn peer() -> PeerAddr {
    PeerAddr([7u8; 20])
}

/// Runs the handshake to completion, returning the accepted connection and
/// every datagram the client sent along the way.
fn handshake(early: Option<&[u8]>) -> (Connection, Connection, Vec<Bytes>) {
    handshake_many(early.into_iter().collect())
}

/// As [`handshake`], with any number of early messages.
fn handshake_many(early: Vec<&[u8]>) -> (Connection, Connection, Vec<Bytes>) {
    let mut listener = Listener::new(LISTENER_ID, MSS, 0, 0xABCD_EF01_2345_6789, CcKind::default());
    let mut client = Connection::new_active(CLIENT_ID, SeqNo::new(1000), MSS, 0, CcKind::default());
    for bytes in early {
        assert!(client.queue_early(Bytes::copy_from_slice(bytes)), "early data refused");
    }

    let mut now = 0u64;
    let mut tx = TransmitBuf::new();
    let mut events = Vec::new();
    let mut accepted = None;
    let mut client_datagrams: Vec<Bytes> = Vec::new();

    for _ in 0..40 {
        now += 1_000;

        // Whatever the client wants to send, hand to the listener.
        tx.clear();
        client.on_timer(now, &mut tx, &mut events);
        let mut to_listener: Vec<Bytes> = Vec::new();
        for (bytes, segment) in tx.runs() {
            for chunk in bytes.chunks(segment.max(1)) {
                to_listener.push(Bytes::copy_from_slice(chunk));
            }
        }
        client_datagrams.extend(to_listener.iter().cloned());

        let mut listener_out = Vec::new();
        for datagram in to_listener {
            listener.on_datagram(peer(), datagram, now, &mut listener_out);
        }

        // And whatever the listener answers, back to the client. Anything the
        // client emits in response goes straight back — the conclusion, and the
        // early data beside it, are produced here rather than on a timer.
        for event in listener_out {
            match event {
                ListenerEvent::SendTo { data, .. } => {
                    let mut ctx = TransmitBuf::new();
                    client.on_datagram(data, now, &mut ctx, &mut events);
                    let mut replies: Vec<Bytes> = Vec::new();
                    for (bytes, segment) in ctx.runs() {
                        for chunk in bytes.chunks(segment.max(1)) {
                            replies.push(Bytes::copy_from_slice(chunk));
                        }
                    }
                    client_datagrams.extend(replies.iter().cloned());
                    let mut more = Vec::new();
                    for reply in replies {
                        listener.on_datagram(peer(), reply, now, &mut more);
                    }
                    for ev in more {
                        match ev {
                            ListenerEvent::SendTo { data, .. } => {
                                let mut c2 = TransmitBuf::new();
                                client.on_datagram(data, now, &mut c2, &mut events);
                            }
                            ListenerEvent::Accept(conn, _) => accepted = Some(*conn),
                        }
                    }
                }
                ListenerEvent::Accept(conn, _) => accepted = Some(*conn),
            }
        }

        if accepted.is_some() && client.is_connected() {
            break;
        }
    }

    let server = accepted.expect("handshake never completed");
    (client, server, client_datagrams)
}

/// The message must be readable the moment the connection is accepted, without
/// the client having sent anything after the handshake.
#[test]
fn early_data_arrives_with_the_conclusion() {
    const MSG: &[u8] = b"noise handshake message one";
    let (_client, mut server, _) = handshake(Some(MSG));

    let mut out = Vec::new();
    let mut tx = TransmitBuf::new();
    server.on_timer(1_000_000, &mut tx, &mut out);
    assert!(
        out.iter().any(|e| matches!(e, Event::DataReady)),
        "accepting a connection with early data should report it ready"
    );

    let got = server.recv_msg().expect("early data was not delivered");
    assert_eq!(&got[..], MSG);
}

/// A connection that sends none must behave exactly as before.
#[test]
fn no_early_data_changes_nothing() {
    let (_client, mut server, _) = handshake(None);
    let mut out = Vec::new();
    let mut tx = TransmitBuf::new();
    server.on_timer(1_000_000, &mut tx, &mut out);
    assert!(server.recv_msg().is_none(), "delivered a message that was never sent");
}

/// Early data is an *extra* transmission of an ordinary message, so the copy
/// the send buffer transmits afterwards must be discarded rather than delivered
/// a second time.
#[test]
fn the_ordinary_copy_is_not_delivered_twice() {
    const MSG: &[u8] = b"exactly once";
    let (mut client, mut server, _) = handshake(Some(MSG));

    // Let the client run on: it queued the same message normally at connect,
    // so it will send it again through the usual path.
    let mut now = 100_000u64;
    for _ in 0..40 {
        now += 10_000;
        let mut tx = TransmitBuf::new();
        let mut events = Vec::new();
        client.on_timer(now, &mut tx, &mut events);
        for (bytes, segment) in tx.runs() {
            for chunk in bytes.chunks(segment.max(1)) {
                let mut stx = TransmitBuf::new();
                let mut sev = Vec::new();
                server.on_datagram(Bytes::copy_from_slice(chunk), now, &mut stx, &mut sev);
            }
        }
    }

    let mut delivered = Vec::new();
    let mut tx = TransmitBuf::new();
    let mut out = Vec::new();
    server.on_timer(now, &mut tx, &mut out);
    while let Some(msg) = server.recv_msg() {
        delivered.push(msg);
    }
    assert_eq!(delivered.len(), 1, "the message was delivered {} times", delivered.len());
    assert_eq!(&delivered[0][..], MSG);
}

/// Refused after the handshake, when there is no conclusion left to ride, and
/// refused for a payload too large to travel in one packet.
#[test]
fn early_data_is_refused_when_it_cannot_be_sent() {
    let mut client = Connection::new_active(CLIENT_ID, SeqNo::new(1000), MSS, 0, CcKind::default());
    assert!(!client.queue_early(Bytes::new()), "an empty payload should be refused");
    assert!(
        !client.queue_early(Bytes::from(vec![0u8; MSS as usize * 2])),
        "a payload larger than one packet should be refused"
    );

    let (mut connected, _server, _) = handshake(None);
    assert!(
        !connected.queue_early(Bytes::from_static(b"too late")),
        "an established connection has no conclusion left to carry it"
    );
}

/// A peer that sends early data and then goes quiet must not hold its slot for
/// ever.
///
/// The table is bounded and an unverified peer can reach it, so without expiry
/// a few hundred packets would disable the feature permanently for everyone.
#[test]
fn abandoned_early_data_does_not_hold_the_table() {
    const MSG: &[u8] = b"noise handshake message one";

    // A genuine early-data packet, taken from a real handshake.
    let (_c, _s, sent) = handshake(Some(MSG));
    let early_pkt = sent
        .iter()
        .find(|d| d.len() > 16 && udt_proto::dst_socket_id(d).is_some_and(|id| id != 0))
        .expect("no early data packet was sent")
        .clone();

    let mut listener = Listener::new(LISTENER_ID, MSS, 0, 0x1234_5678_9ABC_DEF0, CcKind::default());
    let mut out = Vec::new();

    // Far past capacity, from peers that never say anything else.
    for i in 0..600u32 {
        let mut addr = [0u8; 20];
        addr[..4].copy_from_slice(&i.to_be_bytes());
        listener.on_datagram(PeerAddr(addr), early_pkt.clone(), 1_000, &mut out);
    }

    // Well past the expiry, a peer that does complete must still be served.
    let mut now = 90_000_000u64;
    let mut client =
        Connection::new_active(CLIENT_ID, SeqNo::new(1000), MSS, now, CcKind::default());
    assert!(client.queue_early(Bytes::from_static(MSG)));
    let mut tx = TransmitBuf::new();
    let mut events = Vec::new();
    let mut accepted = None;

    for _ in 0..40 {
        now += 1_000;
        tx.clear();
        client.on_timer(now, &mut tx, &mut events);
        let mut batch: Vec<Bytes> = Vec::new();
        for (bytes, seg) in tx.runs() {
            for chunk in bytes.chunks(seg.max(1)) {
                batch.push(Bytes::copy_from_slice(chunk));
            }
        }
        let mut evs = Vec::new();
        for d in batch {
            listener.on_datagram(peer(), d, now, &mut evs);
        }
        for ev in evs {
            match ev {
                ListenerEvent::SendTo { data, .. } => {
                    let mut ctx = TransmitBuf::new();
                    client.on_datagram(data, now, &mut ctx, &mut events);
                    let mut more = Vec::new();
                    for (bytes, seg) in ctx.runs() {
                        for chunk in bytes.chunks(seg.max(1)) {
                            listener.on_datagram(
                                peer(),
                                Bytes::copy_from_slice(chunk),
                                now,
                                &mut more,
                            );
                        }
                    }
                    for ev in more {
                        match ev {
                            ListenerEvent::SendTo { data, .. } => {
                                let mut c2 = TransmitBuf::new();
                                client.on_datagram(data, now, &mut c2, &mut events);
                            }
                            ListenerEvent::Accept(conn, _) => accepted = Some(*conn),
                        }
                    }
                }
                ListenerEvent::Accept(conn, _) => accepted = Some(*conn),
            }
        }
        if accepted.is_some() {
            break;
        }
    }

    let mut server = accepted.expect("handshake never completed");
    let mut out2 = Vec::new();
    let mut tx2 = TransmitBuf::new();
    server.on_timer(now + 1_000, &mut tx2, &mut out2);
    assert_eq!(
        server.recv_msg().as_deref(),
        Some(MSG),
        "early data was dropped because abandoned entries never expired"
    );
}

/// The queue is bounded, and says so rather than silently dropping.
#[test]
fn the_early_queue_is_bounded() {
    let mut c = Connection::new_active(CLIENT_ID, SeqNo::new(1000), MSS, 0, CcKind::default());
    for i in 0..udt_proto::MAX_EARLY_MESSAGES {
        assert!(c.queue_early(Bytes::from(vec![b'x'; 8])), "refused message {i} within the cap");
    }
    assert_eq!(c.early_queued(), udt_proto::MAX_EARLY_MESSAGES);
    assert!(!c.queue_early(Bytes::from_static(b"one too many")), "the cap was not enforced");
}

/// Queueing *after* the challenge has arrived must still be early.
///
/// The application and the peer reach the state machine on their own schedules,
/// and between the challenge and the peer's answer there is a whole round trip
/// in which the connection is still `Connecting` — so `queue_early` accepts the
/// message — but the packet it was going to ride has already gone. Loopback
/// hides this by making that window microseconds wide; on a 50 ms path it is
/// 50 ms, which is exactly when an application that does any work between
/// connecting and sending will call `try_send`.
///
/// Handled by bringing the conclusion's next retransmission forward, so the
/// message rides that copy instead. Without it the message waits for
/// `post_connect` and arrives a round trip late, having reported success.
#[test]
fn a_message_queued_after_the_challenge_still_goes_out_early() {
    const MSG: &[u8] = b"queued a round trip late";

    let mut listener = Listener::new(LISTENER_ID, MSS, 0, 0xABCD_EF01_2345_6789, CcKind::default());
    let mut client = Connection::new_active(CLIENT_ID, SeqNo::new(1000), MSS, 0, CcKind::default());
    let mut events = Vec::new();
    let mut tx = TransmitBuf::new();

    // Induction out, challenge back — and stop there, holding the connection in
    // the window. The conclusion has gone; the peer's answer has not arrived.
    let mut now = 0u64;
    let mut challenges = Vec::new();
    for _ in 0..40 {
        now += 1_000;
        tx.clear();
        client.on_timer(now, &mut tx, &mut events);
        let mut listener_out = Vec::new();
        for (bytes, segment) in tx.runs() {
            for chunk in bytes.chunks(segment.max(1)) {
                listener.on_datagram(peer(), Bytes::copy_from_slice(chunk), now, &mut listener_out);
            }
        }
        for event in listener_out {
            if let ListenerEvent::SendTo { data, .. } = event {
                challenges.push(data);
            }
        }
        if !challenges.is_empty() {
            break;
        }
    }
    assert!(!challenges.is_empty(), "the listener never issued a challenge");
    tx.clear();
    for challenge in challenges {
        client.on_datagram(challenge, now, &mut tx, &mut events);
    }
    assert!(!client.is_connected(), "the window closed before the test could use it");
    tx.clear();

    // Now the application gets its turn.
    assert!(client.queue_early(Bytes::from_static(MSG)), "early data refused mid-handshake");
    client.on_timer(now + 1_000, &mut tx, &mut events);

    let sent: Vec<Bytes> = tx
        .runs()
        .flat_map(|(bytes, segment)| {
            bytes.chunks(segment.max(1)).map(Bytes::copy_from_slice).collect::<Vec<_>>()
        })
        .collect();
    assert!(
        sent.iter().any(|d| d.ends_with(MSG)),
        "the message did not go out with the next handshake packet ({} datagrams)",
        sent.len()
    );

    // And it is early in the sense that matters: the listener holds it and
    // hands it over at accept, with no send from the established connection.
    let mut listener_out = Vec::new();
    for datagram in sent {
        listener.on_datagram(peer(), datagram, now + 1_000, &mut listener_out);
    }
    let mut server = None;
    for event in listener_out {
        if let ListenerEvent::Accept(conn, _) = event {
            server = Some(*conn);
        }
    }
    let mut server = server.expect("the conclusion did not complete the handshake");
    let mut out = Vec::new();
    server.on_timer(1_000_000, &mut TransmitBuf::new(), &mut out);
    assert_eq!(
        server.recv_msg().as_deref(),
        Some(MSG),
        "the accepted connection did not have the message already"
    );
}
