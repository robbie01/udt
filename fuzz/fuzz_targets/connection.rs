//! An established connection fed arbitrary datagrams.
//!
//! Decoding cleanly is not enough: a well-formed packet carrying hostile
//! sequence numbers, lengths or acknowledgement ranges reaches the loss lists,
//! the receive buffer and the congestion controller, all of which index and
//! arithmetic their way through it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use udt_proto::{CcKind, Connection, SeqNo, TransmitBuf};

fuzz_target!(|data: &[u8]| {
    // Split the input into datagram-sized chunks, length-prefixed by a byte so
    // the fuzzer can control framing as well as content.
    let mut conn = Connection::new_active(1, SeqNo::new(1000), 1500, 0, CcKind::Udt);
    let mut tx = TransmitBuf::new();
    let mut events = Vec::new();
    let mut now = 0u64;
    let mut rest = data;

    while rest.len() > 2 {
        let len = usize::from(u16::from_le_bytes([rest[0], rest[1]])) % 2048;
        rest = &rest[2..];
        let take = len.min(rest.len());
        let (datagram, tail) = rest.split_at(take);
        rest = tail;

        now += 1000;
        conn.on_datagram(bytes::Bytes::copy_from_slice(datagram), now, &mut tx, &mut events);
        conn.on_timer(now, &mut tx, &mut events);
        events.clear();
        tx.clear();
        while conn.recv_msg().is_some() {}
    }
});
