use bytes::{Bytes, BytesMut, BufMut};
use crate::seq::{SeqNo, MsgNo};
use crate::packet::MsgBoundary;

/// Outcome of [`RecvBuffer::add`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddResult {
    /// The packet was stored in the ring.
    Stored,
    /// A packet for this sequence number is already held, or the sequence has
    /// already been delivered to the application.
    Duplicate,
    /// Beyond the ring's window — nothing was stored.  The caller must not
    /// count this packet as received.
    OutOfWindow,
}

struct Slot {
    payload: Bytes,
    boundary: MsgBoundary,
    msg_no: MsgNo,
    /// Peer's delivery-order flag for this message.
    ///
    /// Currently recorded but not acted on: this buffer always delivers in
    /// sequence order. A clear flag means the sender permits early delivery
    /// ahead of still-missing earlier messages (which is what C++ `scanMsg`
    /// does), so ignoring it is conservative — correct, just without the
    /// latency benefit for peers that opt in.
    #[allow(dead_code)]
    in_order: bool,
}

/// Fixed-capacity receive buffer ring.
///
/// Slots are indexed by sequence number offset from the last-ACKed position.
/// Slots hold `Option<Slot>` — None means the packet hasn't arrived yet (a gap).
///
/// ## Ring addressing
///
/// The ring uses a physical `head` cursor so that `base_seq` can be advanced
/// without shifting data in memory.  The physical slot for logical offset `off`
/// (where `off = seq_no - base_seq`) is:
///
/// ```text
/// phys = (head + off) % capacity
/// ```
///
/// `add()` inserts a received packet.  `read_msg()` extracts the next complete
/// message.  `slide_window()` advances the ring after an ACK is sent,
/// recycling the physical slots occupied by already-delivered messages.
pub struct RecvBuffer {
    slots: Box<[Option<Slot>]>,
    capacity: usize,
    /// Absolute seq no of the first slot in the ring (the last-ACKed seq + 1).
    base_seq: SeqNo,
    /// Physical index of the slot for `base_seq` (logical offset 0).
    head: usize,
    /// Maximum populated logical offset + 1 (high-water mark; used for scans).
    max_off: usize,
    /// Read cursor: logical offset of the next slot to deliver to the application.
    read_off: usize,
    /// Number of complete messages ready to read.
    msg_ready: usize,
}

impl RecvBuffer {
    pub fn new(capacity: usize, initial_seq: SeqNo) -> Self {
        let slots = (0..capacity).map(|_| None).collect::<Vec<_>>().into_boxed_slice();
        RecvBuffer {
            slots,
            capacity,
            base_seq: initial_seq,
            head: 0,
            max_off: 0,
            read_off: 0,
            msg_ready: 0,
        }
    }

    /// Physical slot index for logical offset `off`.
    #[inline]
    fn phys(&self, off: usize) -> usize {
        (self.head + off) % self.capacity
    }

    /// Insert a received packet. `seq_no` identifies the slot.
    ///
    /// The caller **must** distinguish [`AddResult::OutOfWindow`] from
    /// [`AddResult::Duplicate`]: an out-of-window packet was not stored, so
    /// treating it as received would let the acknowledgement point advance past
    /// data the receiver does not actually hold.
    pub fn add(
        &mut self,
        seq_no: SeqNo,
        payload: Bytes,
        boundary: MsgBoundary,
        msg_no: MsgNo,
        in_order: bool,
    ) -> AddResult {
        let off = seq_no.offset_from(self.base_seq);
        if off < 0 {
            // Below the ring: already delivered to the application and freed.
            return AddResult::Duplicate;
        }
        let off = off as usize;
        // Already handed to the application.  Its slot was emptied by read_msg,
        // so it *looks* free — but repopulating it would deliver the same data
        // twice and leave live data in the region slide_window recycles.
        // Retransmissions land here routinely, since the read cursor runs ahead
        // of the acknowledgement point.
        if off < self.read_off {
            return AddResult::Duplicate;
        }
        if off >= self.capacity {
            return AddResult::OutOfWindow;
        }
        self.add_inner(off, payload, boundary, msg_no, in_order)
    }

    fn add_inner(
        &mut self,
        off: usize,
        payload: Bytes,
        boundary: MsgBoundary,
        msg_no: MsgNo,
        in_order: bool,
    ) -> AddResult {
        let phys = self.phys(off);
        if self.slots[phys].is_some() {
            return AddResult::Duplicate;
        }
        self.slots[phys] = Some(Slot { payload, boundary, msg_no, in_order });
        if off >= self.max_off {
            self.max_off = off + 1;
        }
        // Check if this arrival completes a message.
        if boundary == MsgBoundary::Solo {
            self.msg_ready += 1;
        } else if boundary.is_last() {
            // Walk backward: is the First (and all middles) already there?
            if let Some(first) = self.find_first_of_msg(off, msg_no)
                && self.all_slots_filled(first, off)
            {
                self.msg_ready += 1;
            }
        } else if boundary.is_first() {
            // Walk forward: is the Last (and all middles) already there?
            if let Some(last) = self.find_last_of_msg(off, msg_no)
                && self.all_slots_filled(off, last)
            {
                self.msg_ready += 1;
            }
        } else {
            // Middle: check if both First and Last are present with a complete run.
            if let Some(first) = self.find_first_of_msg(off, msg_no)
                && let Some(last) = self.find_last_of_msg(off, msg_no)
                && self.all_slots_filled(first, last)
            {
                self.msg_ready += 1;
            }
        }
        AddResult::Stored
    }

    fn find_first_of_msg(&self, last_off: usize, msg_no: MsgNo) -> Option<usize> {
        let mut off = last_off as isize;
        while off >= 0 {
            let phys = self.phys(off as usize);
            match &self.slots[phys] {
                Some(s) if s.msg_no == msg_no && s.boundary.is_first() => {
                    return Some(off as usize);
                }
                Some(s) if s.msg_no != msg_no => return None,
                None => return None,
                _ => { off -= 1; }
            }
        }
        None
    }

    fn find_last_of_msg(&self, first_off: usize, msg_no: MsgNo) -> Option<usize> {
        let mut off = first_off;
        while off < self.max_off {
            let phys = self.phys(off);
            match &self.slots[phys] {
                Some(s) if s.msg_no == msg_no && s.boundary.is_last() => return Some(off),
                Some(s) if s.msg_no == msg_no => { off += 1; }
                _ => return None,
            }
            if off - first_off >= self.capacity {
                return None;
            }
        }
        None
    }

    fn all_slots_filled(&self, from: usize, to: usize) -> bool {
        for off in from..=to {
            if self.slots[self.phys(off)].is_none() {
                return false;
            }
        }
        true
    }

    /// Extract the next complete message, if available.
    /// Returns None if no complete message is ready.
    pub fn read_msg(&mut self) -> Option<Bytes> {
        if self.msg_ready == 0 {
            return None;
        }
        // Find the boundary of the next message starting at read_off.
        let start = self.read_off;
        let first = self.slots[self.phys(start)].as_ref()?;
        if !first.boundary.is_first() {
            // Slot exists but is not a message start — shouldn't happen in normal
            // operation since we only deliver in-order, but guard defensively.
            return None;
        }
        // Walk forward to find the last packet of this message.
        let mut end = start;
        loop {
            match &self.slots[self.phys(end)] {
                Some(s) if s.boundary.is_last() => break,
                Some(_) => { end += 1; }
                None => return None, // gap — not complete yet
            }
            if end - start >= self.capacity {
                return None; // safety guard
            }
        }
        // Collect payload into a single Bytes.
        if start == end {
            // Solo or single-block message: return payload directly (zero-copy).
            let slot = self.slots[self.phys(start)].take().unwrap();
            self.advance_read(1);
            self.msg_ready -= 1;
            Some(slot.payload)
        } else {
            let total_len: usize = (start..=end)
                .map(|o| self.slots[self.phys(o)].as_ref().map_or(0, |s| s.payload.len()))
                .sum();
            let mut out = BytesMut::with_capacity(total_len);
            for off in start..=end {
                let slot = self.slots[self.phys(off)].take().unwrap();
                out.put_slice(&slot.payload);
            }
            self.advance_read(end - start + 1);
            self.msg_ready -= 1;
            Some(out.freeze())
        }
    }

    fn advance_read(&mut self, n: usize) {
        self.read_off += n;
    }

    /// Slide the receive window forward past all packets already delivered to
    /// the application.
    ///
    /// Must be called after emitting an ACK.  Advances `base_seq` and `head`
    /// by `read_off` (the number of slots freed by `read_msg` since the last
    /// slide), then resets `read_off` to 0.  This frees those physical slots
    /// for new incoming packets without disturbing any still-buffered data.
    ///
    /// **Safety invariant**: all `read_off` slots starting at `head` are `None`
    /// (they were taken by `read_msg`), so the physical slots can be safely
    /// re-used once `head` advances past them.
    pub fn slide_window(&mut self) {
        let n = self.read_off;
        if n == 0 {
            return;
        }
        // Debug-assert that freed slots really are None before we recycle them.
        #[cfg(debug_assertions)]
        for i in 0..n {
            debug_assert!(
                self.slots[(self.head + i) % self.capacity].is_none(),
                "slide_window: slot {} not freed (off={})",
                (self.head + i) % self.capacity,
                i,
            );
        }
        self.head = (self.head + n) % self.capacity;
        self.base_seq = self.base_seq.add(n as u32);
        self.read_off = 0;
        self.max_off = self.max_off.saturating_sub(n);
    }

    /// Drop a message (for MsgDrop requests). Marks affected slots as delivered.
    pub fn drop_msg(&mut self, msg_no: MsgNo) {
        let mut found_last = false;
        for off in 0..self.max_off {
            let phys = self.phys(off);
            if let Some(s) = &self.slots[phys]
                && s.msg_no == msg_no
            {
                if s.boundary.is_last() {
                    found_last = true;
                }
                self.slots[phys] = None;
            }
        }
        if found_last && self.msg_ready > 0 {
            self.msg_ready -= 1;
        }
    }

    /// Free space ahead of `ack_point`, in packets — how many further sequence
    /// numbers the ring can still accept.
    ///
    /// This is the value to advertise to the peer for flow control.  It is
    /// measured from the ring's base (the oldest byte the application has not
    /// read) rather than from occupancy, because unread data pins its slots
    /// even when later slots happen to be free.  Mirrors C++
    /// `CRcvBuffer::getAvailBufSize()`.
    pub fn avail_from(&self, ack_point: SeqNo) -> usize {
        let used = ack_point.offset_from(self.base_seq).max(0) as usize;
        self.capacity.saturating_sub(used)
    }

    pub fn msg_ready(&self) -> usize {
        self.msg_ready
    }

    pub fn base_seq(&self) -> SeqNo {
        self.base_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &[u8]) -> Bytes { Bytes::copy_from_slice(s) }
    fn seq(n: u32) -> SeqNo { SeqNo::new(n) }
    fn msg(n: u32) -> MsgNo { MsgNo::new(n) }

    #[test]
    fn solo_message() {
        let mut buf = RecvBuffer::new(256, seq(0));
        buf.add(seq(0), bytes(b"hello"), MsgBoundary::Solo, msg(0), false);
        let out = buf.read_msg().unwrap();
        assert_eq!(&out[..], b"hello");
        assert!(buf.read_msg().is_none());
    }

    #[test]
    fn multi_packet_message() {
        let mut buf = RecvBuffer::new(256, seq(0));
        buf.add(seq(0), bytes(b"abc"), MsgBoundary::First, msg(0), false);
        buf.add(seq(1), bytes(b"def"), MsgBoundary::Middle, msg(0), false);
        buf.add(seq(2), bytes(b"ghi"), MsgBoundary::Last, msg(0), false);
        let out = buf.read_msg().unwrap();
        assert_eq!(&out[..], b"abcdefghi");
    }

    #[test]
    fn out_of_order_reassembly() {
        let mut buf = RecvBuffer::new(256, seq(0));
        // Deliver last then first
        buf.add(seq(1), bytes(b"world"), MsgBoundary::Last, msg(0), false);
        assert!(buf.read_msg().is_none()); // not complete yet
        buf.add(seq(0), bytes(b"hello"), MsgBoundary::First, msg(0), false);
        let out = buf.read_msg().unwrap();
        assert_eq!(&out[..], b"helloworld");
    }

    #[test]
    fn duplicate_ignored() {
        let mut buf = RecvBuffer::new(256, seq(0));
        assert_eq!(buf.add(seq(0), bytes(b"a"), MsgBoundary::Solo, msg(0), false), AddResult::Stored);
        assert_eq!(
            buf.add(seq(0), bytes(b"b"), MsgBoundary::Solo, msg(0), false),
            AddResult::Duplicate,
        );
        let out = buf.read_msg().unwrap();
        assert_eq!(&out[..], b"a");
    }

    #[test]
    fn two_sequential_messages() {
        let mut buf = RecvBuffer::new(256, seq(0));
        buf.add(seq(0), bytes(b"first"), MsgBoundary::Solo, msg(0), false);
        buf.add(seq(1), bytes(b"second"), MsgBoundary::Solo, msg(1), false);
        assert_eq!(&buf.read_msg().unwrap()[..], b"first");
        assert_eq!(&buf.read_msg().unwrap()[..], b"second");
    }

    /// After delivering many messages the window must slide so that new arrivals
    /// beyond offset `capacity` are not rejected.
    #[test]
    fn slide_window_allows_many_messages() {
        let cap = 16usize;
        let mut buf = RecvBuffer::new(cap, seq(0));

        // Send 3 × cap packets as solo messages; each round requires a slide.
        for round in 0..3u32 {
            for i in 0..cap as u32 {
                let s = seq(round * cap as u32 + i);
                assert_eq!(
                    buf.add(s, bytes(b"x"), MsgBoundary::Solo, msg(round * cap as u32 + i), false),
                    AddResult::Stored,
                    "add failed at round={round} i={i} seq={s:?}",
                );
            }
            for _ in 0..cap {
                assert!(buf.read_msg().is_some());
            }
            buf.slide_window();
        }
        assert_eq!(buf.msg_ready(), 0);
    }

    /// Slide then receive more data that reuses the same physical slots.
    #[test]
    fn slide_then_receive_reuses_slots() {
        let mut buf = RecvBuffer::new(4, seq(100));
        // Fill first 4 slots.
        for i in 0u32..4 {
            buf.add(seq(100 + i), bytes(b"a"), MsgBoundary::Solo, msg(i), false);
        }
        for _ in 0..4 { buf.read_msg().unwrap(); }
        buf.slide_window(); // base_seq = 104, head = 0

        // Now receive 4 more at seq 104–107 (reuses physical slots 0–3).
        for i in 0u32..4 {
            assert_eq!(
                buf.add(seq(104 + i), bytes(b"b"), MsgBoundary::Solo, msg(4 + i), false),
                AddResult::Stored,
            );
        }
        for _ in 0..4 {
            let m = buf.read_msg().unwrap();
            assert_eq!(&m[..], b"b");
        }
    }

    /// A multi-packet message that straddles a window slide boundary should
    /// still be read correctly after the slide.
    #[test]
    fn multi_packet_after_slide() {
        let mut buf = RecvBuffer::new(8, seq(0));
        // Message A: solo at seq 0
        buf.add(seq(0), bytes(b"A"), MsgBoundary::Solo, msg(0), false);
        buf.read_msg().unwrap();
        buf.slide_window(); // base_seq = 1, head = 1

        // Message B: 3-packet at seq 1, 2, 3
        buf.add(seq(1), bytes(b"X"), MsgBoundary::First,  msg(1), false);
        buf.add(seq(2), bytes(b"Y"), MsgBoundary::Middle, msg(1), false);
        buf.add(seq(3), bytes(b"Z"), MsgBoundary::Last,   msg(1), false);
        let out = buf.read_msg().unwrap();
        assert_eq!(&out[..], b"XYZ");
    }
}
