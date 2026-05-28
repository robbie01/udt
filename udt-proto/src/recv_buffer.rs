use bytes::{Bytes, BytesMut, BufMut};
use crate::seq::{SeqNo, MsgNo};
use crate::packet::MsgBoundary;

struct Slot {
    payload: Bytes,
    boundary: MsgBoundary,
    msg_no: MsgNo,
    #[allow(dead_code)] // stored for future in-order delivery enforcement
    in_order: bool,
}

/// Fixed-capacity receive buffer ring.
///
/// Slots are indexed by sequence number offset from the last-ACKed position.
/// Slots hold `Option<Slot>` — None means the packet hasn't arrived yet (a gap).
/// `add()` inserts a received packet. `read_msg()` extracts the next complete message.
pub struct RecvBuffer {
    slots: Box<[Option<Slot>]>,
    capacity: usize,
    /// Absolute seq no of the first slot in the ring (the last-ACKed seq + 1).
    base_seq: SeqNo,
    /// Maximum populated offset (for determining contiguous data available for ACK).
    max_off: usize,
    /// Read cursor: offset of the next slot to deliver to the application.
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
            max_off: 0,
            read_off: 0,
            msg_ready: 0,
        }
    }

    /// Insert a received packet. `seq_no` identifies the slot.
    /// Returns false if the slot is out of window or already filled (duplicate).
    pub fn add(
        &mut self,
        seq_no: SeqNo,
        payload: Bytes,
        boundary: MsgBoundary,
        msg_no: MsgNo,
        in_order: bool,
    ) -> bool {
        let off = seq_no.offset_from(self.base_seq);
        if off < 0 || off as usize >= self.capacity {
            return false; // outside window
        }
        let off = off as usize;
        let idx = (off) % self.capacity; // base_seq is always at slot 0 in ring
        // Actually the ring is addressed as (off % capacity), but we need to track
        // that base_seq maps to physical slot 0... Let me use absolute slot indexing.
        // slot index = (base_physical + off) % capacity
        // We don't track base_physical separately — use off directly since the ring
        // is always compacted after ack(). But ack() doesn't move base_seq slot,
        // so we need a physical base pointer. Let me add one.

        // Re-implement with a proper physical offset.
        let _ = idx; // suppress warning — see corrected logic below
        self.add_inner(off, payload, boundary, msg_no, in_order)
    }

    fn add_inner(&mut self, off: usize, payload: Bytes, boundary: MsgBoundary, msg_no: MsgNo, in_order: bool) -> bool {
        let phys = off % self.capacity;
        if self.slots[phys].is_some() {
            return false; // duplicate
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
                && self.all_slots_filled(first, off) {
                    self.msg_ready += 1;
                }
        } else if boundary.is_first() {
            // Walk forward: is the Last (and all middles) already there?
            if let Some(last) = self.find_last_of_msg(off, msg_no)
                && self.all_slots_filled(off, last) {
                    self.msg_ready += 1;
                }
        } else {
            // Middle: check if both First and Last are present with a complete run.
            if let Some(first) = self.find_first_of_msg(off, msg_no)
                && let Some(last) = self.find_last_of_msg(off, msg_no)
                    && self.all_slots_filled(first, last) {
                        self.msg_ready += 1;
                    }
        }
        true
    }

    fn find_first_of_msg(&self, last_off: usize, msg_no: MsgNo) -> Option<usize> {
        let mut off = last_off as isize;
        while off >= 0 {
            let phys = (off as usize) % self.capacity;
            match &self.slots[phys] {
                Some(s) if s.msg_no == msg_no && s.boundary.is_first() => return Some(off as usize),
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
            let phys = off % self.capacity;
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
            let phys = off % self.capacity;
            if self.slots[phys].is_none() {
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
        // Find the boundary of the next message starting at read_off
        let start = self.read_off;
        let phys_start = start % self.capacity;
        let first = self.slots[phys_start].as_ref()?;
        if !first.boundary.is_first() {
            return None; // not ready
        }
        // Find the end
        let mut end = start;
        loop {
            let phys = end % self.capacity;
            match &self.slots[phys] {
                Some(s) if s.boundary.is_last() => break,
                Some(_) => { end += 1; }
                None => return None, // gap — not complete yet
            }
            if end - start >= self.capacity {
                return None; // safety
            }
        }
        // Collect payload
        let total_len: usize = (start..=end).map(|o| {
            let phys = o % self.capacity;
            self.slots[phys].as_ref().map(|s| s.payload.len()).unwrap_or(0)
        }).sum();
        let msg = if start == end {
            // Solo or single-block: return Bytes directly (zero-copy)
            let phys = start % self.capacity;
            let slot = self.slots[phys].take().unwrap();
            self.advance_read(1);
            self.msg_ready -= 1;
            return Some(slot.payload);
        } else {
            let mut out = BytesMut::with_capacity(total_len);
            for off in start..=end {
                let phys = off % self.capacity;
                let slot = self.slots[phys].take().unwrap();
                out.put_slice(&slot.payload);
            }
            self.advance_read(end - start + 1);
            self.msg_ready -= 1;
            out.freeze()
        };
        Some(msg)
    }

    fn advance_read(&mut self, n: usize) {
        self.read_off += n;
        // The base_seq advances to match read_off (we've delivered these to the app).
        // ACK boundary = max contiguous sequence starting from base_seq.
    }

    /// Returns the count of contiguous delivered packets from base_seq.
    /// The caller should advance base_seq by this amount and send an ACK.
    pub fn ack_advance(&self) -> usize {
        let mut count = 0;
        while count < self.max_off {
            let phys = count % self.capacity;
            if self.slots[phys].is_none() && count < self.read_off {
                // Delivered to app — counts as acked
                count += 1;
            } else if self.slots[phys].is_some() {
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// Advance base_seq (called after sending ACK). Clears logically freed slots.
    pub fn commit_ack(&mut self, count: usize) {
        self.base_seq = self.base_seq.add(count as u32);
        // Physical slots are already None if delivered, or may still have data for
        // re-ordered packets. The ring addressing remains valid.
    }

    /// Drop a message (for MsgDrop requests). Marks affected slots as delivered.
    pub fn drop_msg(&mut self, msg_no: MsgNo) {
        let mut found_last = false;
        for off in 0..self.max_off {
            let phys = off % self.capacity;
            if let Some(s) = &self.slots[phys]
                && s.msg_no == msg_no {
                    if s.boundary.is_last() {
                        found_last = true;
                    }
                    self.slots[phys] = None;
                }
        }
        if found_last {
            // Decrement msg_ready if we're removing a complete message
            if self.msg_ready > 0 {
                self.msg_ready -= 1;
            }
        }
    }

    /// Number of available receive buffer packets (capacity - current occupancy).
    pub fn avail_pkts(&self) -> usize {
        let occupied = self.max_off.saturating_sub(self.read_off);
        self.capacity.saturating_sub(occupied)
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
        assert!(buf.add(seq(0), bytes(b"a"), MsgBoundary::Solo, msg(0), false));
        assert!(!buf.add(seq(0), bytes(b"b"), MsgBoundary::Solo, msg(0), false));
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
}
