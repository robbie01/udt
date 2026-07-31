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
fn handshake(early: Option<&[u8]>) -> (Connection, Connection, usize) {
    let mut listener = Listener::new(LISTENER_ID, MSS, 0, 0xABCD_EF01_2345_6789, CcKind::default());
    let mut client = Connection::new_active(CLIENT_ID, SeqNo::new(1000), MSS, 0, CcKind::default());
    if let Some(bytes) = early {
        assert!(client.set_early_data(Bytes::copy_from_slice(bytes)), "early data refused");
    }

    let mut now = 0u64;
    let mut tx = TransmitBuf::new();
    let mut events = Vec::new();
    let mut accepted = None;
    let mut client_datagrams = 0usize;

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
        client_datagrams += to_listener.len();

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
                    client_datagrams += replies.len();
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
    assert!(!client.set_early_data(Bytes::new()), "an empty payload should be refused");
    assert!(
        !client.set_early_data(Bytes::from(vec![0u8; MSS as usize * 2])),
        "a payload larger than one packet should be refused"
    );

    let (mut connected, _server, _) = handshake(None);
    assert!(
        !connected.set_early_data(Bytes::from_static(b"too late")),
        "an established connection has no conclusion left to carry it"
    );
}
