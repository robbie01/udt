//! An established connection fed arbitrary datagrams.
//!
//! Decoding cleanly is not enough: a well-formed packet carrying hostile
//! sequence numbers, lengths or acknowledgement ranges reaches the loss lists,
//! the receive buffer and the congestion controller, all of which index and
//! arithmetic their way through it.
//!
//! Random bytes rarely decode into a data packet addressed to the right
//! socket, and never in a sequence that opens and closes gaps, so the input
//! also drives synthesised data and message-drop packets at sequence numbers
//! it picks relative to where the receiver currently is. The peer's initial
//! sequence number comes from the input too — it is the peer's to choose on a
//! real connection, and putting it just below the wrap is what makes the
//! receiver's gap arithmetic interesting.
//!
//! After every step the connection is asked whether its loss lists are still
//! sorted and non-overlapping. Both are searched by "first range containing
//! this sequence", so a duplicate entry survives the packet that should clear
//! it, and is NAKed or retransmitted for as long as it survives.

#![no_main]

use libfuzzer_sys::fuzz_target;
use udt_proto::{CcKind, Connection, SeqNo, TransmitBuf, fuzz};

const SOCKET_ID: u32 = 1;

/// A signed distance from the input, for `SeqNo::shift`. Landing behind the
/// receiver's cursor is a retransmission, and worth as much as a gap ahead.
fn delta(rest: &mut &[u8]) -> Option<i32> {
    u16_le(rest).map(|d| i32::from(d as i16))
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if rest.len() < n {
        return None;
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Some(head)
}

/// As much of the next `n` bytes as remain: a short tail makes a short
/// payload rather than ending the run.
fn take_upto<'a>(rest: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, tail) = rest.split_at(n.min(rest.len()));
    *rest = tail;
    head
}

fn u16_le(rest: &mut &[u8]) -> Option<u16> {
    take(rest, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let Some(header) = take(&mut rest, 5) else { return };
    let peer_isn = SeqNo::new(u32::from_le_bytes([header[0], header[1], header[2], header[3]]));

    // Two ways in. Half the inputs start from a socket still handshaking, so
    // the connect path stays covered; the other half start connected, which is
    // the only way an input this short reaches the receive path at all.
    let mut conn = if header[4] & 1 == 0 {
        Connection::new_active(SOCKET_ID, SeqNo::new(1000), 1500, 0, CcKind::Udt)
    } else {
        Connection::new_connected(
            SOCKET_ID,
            2,
            SeqNo::new(1000),
            peer_isn,
            1500,
            8192,
            0,
            CcKind::Udt.build(),
        )
    };

    let mut tx = TransmitBuf::new();
    let mut events = Vec::new();
    let mut now = 0u64;

    while let Some(op) = take(&mut rest, 1).map(|b| b[0]) {
        // Where the fuzzer's sequence numbers are measured from: the receiver
        // moves, and an offset from a fixed origin stops being interesting
        // after the first few packets.
        let cursor = SeqNo::new(conn.stats().rcv_curr_seq);
        let datagram = match op & 0b11 {
            0 => {
                // A raw datagram, framed by the input like the other targets.
                let Some(len) = u16_le(&mut rest) else { break };
                bytes::Bytes::copy_from_slice(take_upto(&mut rest, usize::from(len) % 2048))
            }
            1 => {
                let Some(at) = delta(&mut rest) else { break };
                let Some(len) = take(&mut rest, 1).map(|b| usize::from(b[0]) * 8) else { break };
                let payload = take_upto(&mut rest, len);
                fuzz::data_packet(
                    SOCKET_ID,
                    cursor.shift(at),
                    u32::from(op >> 5),
                    u32::from(op >> 2) & 0b11,
                    op & 0b1_0000 != 0,
                    payload,
                )
            }
            2 => {
                // A message drop retires a range outright, the other way the
                // peer moves the receiver's idea of where it is.
                let Some(at) = delta(&mut rest) else { break };
                let Some(span) = delta(&mut rest) else { break };
                let first = cursor.shift(at);
                fuzz::msg_drop_packet(SOCKET_ID, u32::from(op >> 2), first, first.shift(span))
            }
            _ => {
                // No packet — just let time pass, so the ACK, NAK and expiry
                // timers fire between arrivals rather than only after them.
                now += u64::from(op >> 2) * 1_000;
                conn.on_timer(now, &mut tx, &mut events);
                conn.assert_loss_lists_well_formed();
                events.clear();
                tx.clear();
                continue;
            }
        };

        now += 1000;
        conn.on_datagram(datagram, now, &mut tx, &mut events);
        conn.on_timer(now, &mut tx, &mut events);
        conn.assert_loss_lists_well_formed();
        events.clear();
        tx.clear();
        while conn.recv_msg().is_some() {}
    }
});
