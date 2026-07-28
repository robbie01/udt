//! The listener's handshake path against arbitrary datagrams from arbitrary
//! sources.
//!
//! This runs before any connection exists, so it is the most exposed surface in
//! the crate: anything that can reach the bound port reaches this code, and a
//! spoofed source address costs an attacker nothing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use udt_proto::{CcKind, Listener, PeerAddr};

fuzz_target!(|data: &[u8]| {
    let mut listener = Listener::new(1, 1500, 0, 0xDEAD_BEEF, CcKind::Udt);
    let mut events = Vec::new();
    let mut now = 0u64;
    let mut rest = data;

    while rest.len() > 3 {
        // First byte varies the source address, so one run can interleave
        // several apparent peers and exercise the pending-handshake table.
        let source = rest[0];
        let len = usize::from(u16::from_le_bytes([rest[1], rest[2]])) % 2048;
        rest = &rest[3..];
        let take = len.min(rest.len());
        let (datagram, tail) = rest.split_at(take);
        rest = tail;

        let addr = PeerAddr::from_v4([127, 0, 0, source], 9000 + u16::from(source));
        now += 1000;
        listener.on_datagram(addr, bytes::Bytes::copy_from_slice(datagram), now, &mut events);
        events.clear();
    }
});
