use crate::packet::MsgBoundary;
use crate::seq::{MsgNo, SeqNo};
use bytes::{BufMut, Bytes, BytesMut};

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
    /// The sender's delivery-order flag.
    ///
    /// `false` means the sender permits this message to be surfaced ahead of
    /// earlier ones that are still incomplete. See [`RecvBuffer::read_msg`].
    in_order: bool,
}

/// State of one ring slot.
enum SlotState {
    /// Nothing received for this sequence number yet.
    Empty,
    /// Received and not yet handed to the application.
    Filled(Slot),
    /// Handed to the application, but not yet reclaimable because an earlier
    /// message is still incomplete.
    ///
    /// This is the crux of out-of-order delivery. A delivered slot cannot
    /// simply become `Empty`: the ring reclaims space as a *prefix*, so a
    /// message delivered early leaves holes above the reclaim frontier. Marking
    /// the slot instead of clearing it keeps two properties that would
    /// otherwise break — a retransmission cannot repopulate an already-delivered
    /// slot, and the space is not advertised as free while it is still pinned.
    /// C++ calls this `m_iFlag == 2`.
    Delivered,
}

impl SlotState {
    fn is_occupied(&self) -> bool {
        !matches!(self, SlotState::Empty)
    }
}

/// Fixed-capacity receive buffer ring.
///
/// ## Ring addressing
///
/// A physical `head` cursor lets `base_seq` advance without moving data. The
/// physical slot for logical offset `off` (where `off = seq_no - base_seq`) is
/// `(head + off) % capacity`.
///
/// ## Delivery order
///
/// By default messages are surfaced in sequence order. A sender may clear the
/// per-message order flag to permit *early delivery*: the message is handed over
/// as soon as it is complete, even if an earlier message is still missing
/// packets. `read_msg` therefore scans for the first deliverable message rather
/// than only looking at the head of the ring.
pub struct RecvBuffer {
    slots: Box<[SlotState]>,
    capacity: usize,
    /// Absolute seq no of logical offset 0.
    base_seq: SeqNo,
    /// Physical index of the slot for `base_seq`.
    head: usize,
    /// One past the highest logical offset ever populated; bounds every scan.
    max_off: usize,
    /// Reclaim frontier: every slot in `[0, reclaimable)` is `Delivered` and
    /// will be recycled by the next [`reclaim`](Self::reclaim).
    ///
    /// Note this is *not* "next message to deliver" — with early delivery the
    /// two diverge, and it is the prefix property that the ring depends on.
    reclaimable: usize,
    /// Cleared when a scan finds nothing deliverable, set by anything that could
    /// change that. Without it, a stalled hole would make every arriving packet
    /// pay a full window scan.
    maybe_ready: bool,
    /// Held packets whose sender cleared the order flag.
    ///
    /// Only these can be delivered out of sequence, so when the count is zero
    /// the search for a deliverable message is just "does one start at the
    /// reclaim frontier" — no scan of the window at all. Counted per packet
    /// rather than per message because a message's packets may arrive in any
    /// order; the exact figure does not matter, only whether it is zero.
    unordered_pending: usize,
}

impl RecvBuffer {
    pub fn new(capacity: usize, initial_seq: SeqNo) -> Self {
        let slots = (0..capacity).map(|_| SlotState::Empty).collect::<Vec<_>>().into_boxed_slice();
        RecvBuffer {
            slots,
            capacity,
            base_seq: initial_seq,
            head: 0,
            max_off: 0,
            reclaimable: 0,
            maybe_ready: false,
            unordered_pending: 0,
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
            // Below the ring: reclaimed, so already delivered.
            return AddResult::Duplicate;
        }
        let off = off as usize;
        if off >= self.capacity {
            return AddResult::OutOfWindow;
        }
        let phys = self.phys(off);
        // Occupied covers both "already have it" and "already delivered it";
        // retransmissions of an early-delivered message land in the latter.
        if self.slots[phys].is_occupied() {
            return AddResult::Duplicate;
        }
        if !in_order {
            self.unordered_pending += 1;
        }
        self.slots[phys] = SlotState::Filled(Slot { payload, boundary, msg_no, in_order });
        if off >= self.max_off {
            self.max_off = off + 1;
        }
        self.maybe_ready = true;
        AddResult::Stored
    }

    /// Locate the next deliverable message as a logical `[start, end]` range.
    ///
    /// A message is deliverable when either:
    ///
    /// * it starts exactly at the reclaim frontier, so nothing before it is
    ///   still missing or undelivered — the ordinary in-order case; or
    /// * its sender cleared the order flag, permitting early delivery ahead of
    ///   whatever is still outstanding.
    ///
    /// C++ `CRcvBuffer::scanMsg` expresses the same gate as `!passack ||
    /// !getMsgOrderFlag()`, where `passack` means "extends beyond the
    /// acknowledgement point". Keying off the ACK point rather than the reclaim
    /// frontier is why the C++ receiver only makes data visible once it has
    /// ACKed it — a sender that goes quiet then waits on its ACK timer. Using
    /// the frontier is equivalent for ordering and delivers immediately.
    fn find_deliverable(&self) -> Option<(usize, usize)> {
        // Fast path: only a message starting at the reclaim frontier can be
        // delivered in sequence, so unless some sender has opted out of
        // ordering this is the entire search. Scanning the window here instead
        // costs O(window) on *every* arriving packet, which profiled as the
        // single hottest symbol in the whole implementation.
        if let Some(r) = self.message_at(self.reclaimable) {
            return Some(r);
        }
        if self.unordered_pending == 0 {
            return None;
        }

        let mut start: Option<usize> = None;
        for off in self.reclaimable..self.max_off {
            match &self.slots[self.phys(off)] {
                // A hole or an already-taken slot ends any candidate run.
                SlotState::Empty | SlotState::Delivered => start = None,
                SlotState::Filled(s) => {
                    if s.boundary.is_first() {
                        start = Some(off);
                    }
                    if s.boundary.is_last()
                        && let Some(begin) = start
                    {
                        let in_line = begin == self.reclaimable;
                        if in_line || !s.in_order {
                            return Some((begin, off));
                        }
                        // Complete, but must wait its turn. Keep scanning: a
                        // later message may have opted out of ordering.
                        start = None;
                    }
                }
            }
        }
        None
    }

    /// Extent of a complete message starting exactly at `off`, if there is one.
    fn message_at(&self, off: usize) -> Option<(usize, usize)> {
        if off >= self.max_off {
            return None;
        }
        match &self.slots[self.phys(off)] {
            SlotState::Filled(s) if s.boundary.is_first() => {}
            _ => return None,
        }
        let mut end = off;
        loop {
            match &self.slots[self.phys(end)] {
                SlotState::Filled(s) if s.boundary.is_last() => return Some((off, end)),
                SlotState::Filled(_) => end += 1,
                _ => return None,
            }
            if end >= self.max_off || end - off >= self.capacity {
                return None;
            }
        }
    }

    /// Extract the next deliverable message, if any.
    pub fn read_msg(&mut self) -> Option<Bytes> {
        if !self.maybe_ready {
            return None;
        }
        let Some((start, end)) = self.find_deliverable() else {
            self.maybe_ready = false;
            return None;
        };

        let msg = if start == end {
            // Solo or single-packet message: hand over the payload as-is.
            match std::mem::replace(&mut self.slots[self.phys(start)], SlotState::Delivered) {
                SlotState::Filled(s) => {
                    if !s.in_order {
                        self.unordered_pending -= 1;
                    }
                    s.payload
                }
                _ => unreachable!("find_deliverable returned a non-filled slot"),
            }
        } else {
            let total: usize = (start..=end)
                .map(|o| match &self.slots[self.phys(o)] {
                    SlotState::Filled(s) => s.payload.len(),
                    _ => 0,
                })
                .sum();
            let mut out = BytesMut::with_capacity(total);
            for off in start..=end {
                match std::mem::replace(&mut self.slots[self.phys(off)], SlotState::Delivered) {
                    SlotState::Filled(s) => {
                        if !s.in_order {
                            self.unordered_pending -= 1;
                        }
                        out.put_slice(&s.payload);
                    }
                    _ => unreachable!("find_deliverable returned a non-filled slot"),
                }
            }
            out.freeze()
        };

        self.advance_reclaimable();
        Some(msg)
    }

    /// Extend the reclaim frontier over any newly-contiguous delivered prefix.
    fn advance_reclaimable(&mut self) {
        while self.reclaimable < self.max_off
            && matches!(self.slots[self.phys(self.reclaimable)], SlotState::Delivered)
        {
            self.reclaimable += 1;
        }
    }

    /// Recycle the delivered prefix, advancing the ring.
    ///
    /// **Invariant**: every slot in `[0, reclaimable)` is `Delivered`, so those
    /// physical slots carry no live data once `head` moves past them.
    pub fn reclaim(&mut self) {
        let n = self.reclaimable;
        if n == 0 {
            return;
        }
        for i in 0..n {
            let phys = (self.head + i) % self.capacity;
            debug_assert!(
                matches!(self.slots[phys], SlotState::Delivered),
                "reclaim: slot {phys} (off={i}) is not Delivered",
            );
            self.slots[phys] = SlotState::Empty;
        }
        self.head = (self.head + n) % self.capacity;
        self.base_seq = self.base_seq.add(n as u32);
        self.reclaimable = 0;
        self.max_off = self.max_off.saturating_sub(n);
    }

    /// Discard a message the sender has given up on (a MsgDrop request).
    ///
    /// Dropped slots become `Delivered` rather than `Empty`: the sender will
    /// never retransmit them, so they must not block the reclaim prefix, and a
    /// late straggler must not repopulate them.
    pub fn drop_msg(&mut self, msg_no: MsgNo) {
        for off in self.reclaimable..self.max_off {
            let phys = self.phys(off);
            if let SlotState::Filled(s) = &self.slots[phys]
                && s.msg_no == msg_no
            {
                if !s.in_order {
                    self.unordered_pending -= 1;
                }
                self.slots[phys] = SlotState::Delivered;
            }
        }
        self.advance_reclaimable();
        self.maybe_ready = true;
    }

    /// Mark a whole sequence range as unreceivable, for a MsgDrop whose message
    /// number matches nothing held locally (the common case — the packets were
    /// lost, which is why the sender dropped them).
    ///
    /// Without this the range stays `Empty` and blocks the reclaim prefix
    /// forever, wedging the ring behind data that will never arrive.
    pub fn drop_range(&mut self, first: SeqNo, last: SeqNo) {
        let from = first.offset_from(self.base_seq);
        let to = last.offset_from(self.base_seq);
        if to < 0 {
            return;
        }
        let from = from.max(0) as usize;
        let to = (to as usize).min(self.capacity.saturating_sub(1));
        for off in from..=to {
            let phys = self.phys(off);
            if let SlotState::Filled(s) = &self.slots[phys]
                && !s.in_order
            {
                self.unordered_pending -= 1;
            }
            if !matches!(self.slots[phys], SlotState::Delivered) {
                self.slots[phys] = SlotState::Delivered;
            }
        }
        if to + 1 > self.max_off {
            self.max_off = to + 1;
        }
        self.advance_reclaimable();
        self.maybe_ready = true;
    }

    /// Free space ahead of `ack_point`, in packets — how many further sequence
    /// numbers the ring can still accept.
    ///
    /// This is the value to advertise for flow control. It is measured from the
    /// ring's base rather than from occupancy, because delivered-but-unreclaimed
    /// slots still pin space. C++ `getAvailBufSize()` omits exactly that, which
    /// is why upstream over-advertises its window during out-of-order delivery
    /// and then silently rejects the arrivals.
    pub fn avail_from(&self, ack_point: SeqNo) -> usize {
        let used = ack_point.offset_from(self.base_seq).max(0) as usize;
        // Delivered-but-pinned slots can sit above the ack point too.
        let pinned = self.max_off.max(used);
        self.capacity.saturating_sub(pinned)
    }

    /// How many packets the ring holds. Nothing further than this above the
    /// base can be stored, whoever asks.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[cfg(test)]
    pub fn base_seq(&self) -> SeqNo {
        self.base_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(n: u32) -> SeqNo {
        SeqNo::new(n)
    }
    fn msg(n: u32) -> MsgNo {
        MsgNo::new(n)
    }
    fn bytes(b: &[u8]) -> Bytes {
        Bytes::copy_from_slice(b)
    }

    #[test]
    fn solo_message() {
        let mut buf = RecvBuffer::new(16, seq(0));
        buf.add(seq(0), bytes(b"hello"), MsgBoundary::Solo, msg(0), true);
        assert_eq!(&buf.read_msg().unwrap()[..], b"hello");
        assert!(buf.read_msg().is_none());
    }

    #[test]
    fn multi_packet_message() {
        let mut buf = RecvBuffer::new(16, seq(0));
        buf.add(seq(0), bytes(b"abc"), MsgBoundary::First, msg(0), true);
        buf.add(seq(1), bytes(b"def"), MsgBoundary::Middle, msg(0), true);
        buf.add(seq(2), bytes(b"ghi"), MsgBoundary::Last, msg(0), true);
        assert_eq!(&buf.read_msg().unwrap()[..], b"abcdefghi");
    }

    #[test]
    fn out_of_order_reassembly() {
        let mut buf = RecvBuffer::new(16, seq(0));
        buf.add(seq(1), bytes(b"world"), MsgBoundary::Last, msg(0), true);
        assert!(buf.read_msg().is_none()); // not complete yet
        buf.add(seq(0), bytes(b"hello"), MsgBoundary::First, msg(0), true);
        assert_eq!(&buf.read_msg().unwrap()[..], b"helloworld");
    }

    #[test]
    fn duplicate_ignored() {
        let mut buf = RecvBuffer::new(16, seq(0));
        assert_eq!(
            buf.add(seq(0), bytes(b"a"), MsgBoundary::Solo, msg(0), true),
            AddResult::Stored
        );
        assert_eq!(
            buf.add(seq(0), bytes(b"b"), MsgBoundary::Solo, msg(0), true),
            AddResult::Duplicate,
        );
    }

    #[test]
    fn two_sequential_messages() {
        let mut buf = RecvBuffer::new(16, seq(0));
        buf.add(seq(0), bytes(b"first"), MsgBoundary::Solo, msg(0), true);
        buf.add(seq(1), bytes(b"second"), MsgBoundary::Solo, msg(1), true);
        assert_eq!(&buf.read_msg().unwrap()[..], b"first");
        assert_eq!(&buf.read_msg().unwrap()[..], b"second");
    }

    #[test]
    fn reclaim_allows_many_messages() {
        let cap = 16usize;
        let mut buf = RecvBuffer::new(cap, seq(0));
        for round in 0..3u32 {
            for i in 0..cap as u32 {
                let s = seq(round * cap as u32 + i);
                assert_eq!(
                    buf.add(s, bytes(b"x"), MsgBoundary::Solo, msg(round * cap as u32 + i), true),
                    AddResult::Stored,
                    "add failed at round={round} i={i}",
                );
            }
            for _ in 0..cap {
                assert!(buf.read_msg().is_some());
            }
            buf.reclaim();
        }
    }

    #[test]
    fn reclaim_then_receive_reuses_slots() {
        let mut buf = RecvBuffer::new(4, seq(100));
        for i in 0u32..4 {
            buf.add(seq(100 + i), bytes(b"a"), MsgBoundary::Solo, msg(i), true);
        }
        for _ in 0..4 {
            buf.read_msg().unwrap();
        }
        buf.reclaim();

        for i in 0u32..4 {
            assert_eq!(
                buf.add(seq(104 + i), bytes(b"b"), MsgBoundary::Solo, msg(4 + i), true),
                AddResult::Stored,
            );
        }
        for _ in 0..4 {
            assert_eq!(&buf.read_msg().unwrap()[..], b"b");
        }
    }

    #[test]
    fn multi_packet_after_reclaim() {
        let mut buf = RecvBuffer::new(8, seq(0));
        buf.add(seq(0), bytes(b"A"), MsgBoundary::Solo, msg(0), true);
        buf.read_msg().unwrap();
        buf.reclaim();

        buf.add(seq(1), bytes(b"X"), MsgBoundary::First, msg(1), true);
        buf.add(seq(2), bytes(b"Y"), MsgBoundary::Middle, msg(1), true);
        buf.add(seq(3), bytes(b"Z"), MsgBoundary::Last, msg(1), true);
        assert_eq!(&buf.read_msg().unwrap()[..], b"XYZ");
    }

    // ── Out-of-order (early) delivery ────────────────────────────────────────

    /// An ordered message must wait behind an incomplete earlier one, even
    /// though it is itself complete.
    #[test]
    fn ordered_message_waits_behind_a_hole() {
        let mut buf = RecvBuffer::new(16, seq(0));
        // Message 0 occupies seq 0..=1 but seq 0 never arrives.
        buf.add(seq(1), bytes(b"tail"), MsgBoundary::Last, msg(0), true);
        // Message 1 is complete at seq 2, ordered.
        buf.add(seq(2), bytes(b"later"), MsgBoundary::Solo, msg(1), true);

        // ACK point is 0: nothing is acknowledged, so message 1 is past-ack.
        assert!(buf.read_msg().is_none(), "ordered message jumped the queue");
    }

    /// The same message with the order flag cleared is delivered immediately.
    #[test]
    fn unordered_message_delivered_early() {
        let mut buf = RecvBuffer::new(16, seq(0));
        buf.add(seq(1), bytes(b"tail"), MsgBoundary::Last, msg(0), true);
        buf.add(seq(2), bytes(b"later"), MsgBoundary::Solo, msg(1), false);

        assert_eq!(&buf.read_msg().unwrap()[..], b"later");
        // Only that one; the hole still blocks message 0.
        assert!(buf.read_msg().is_none());
    }

    /// A retransmission must not repopulate a slot whose message was already
    /// delivered out of order.
    #[test]
    fn retransmit_of_early_delivered_slot_is_duplicate() {
        let mut buf = RecvBuffer::new(16, seq(0));
        buf.add(seq(1), bytes(b"tail"), MsgBoundary::Last, msg(0), true);
        buf.add(seq(2), bytes(b"later"), MsgBoundary::Solo, msg(1), false);
        assert_eq!(&buf.read_msg().unwrap()[..], b"later");

        assert_eq!(
            buf.add(seq(2), bytes(b"later"), MsgBoundary::Solo, msg(1), false),
            AddResult::Duplicate,
            "delivered slot was repopulated",
        );
    }

    /// Once the hole is filled, the earlier message is delivered and the whole
    /// prefix — including the early-delivered slot — becomes reclaimable.
    #[test]
    fn filling_the_hole_unblocks_reclaim() {
        let mut buf = RecvBuffer::new(16, seq(0));
        buf.add(seq(1), bytes(b"tail"), MsgBoundary::Last, msg(0), true);
        buf.add(seq(2), bytes(b"later"), MsgBoundary::Solo, msg(1), false);
        buf.read_msg().unwrap();

        buf.add(seq(0), bytes(b"head"), MsgBoundary::First, msg(0), true);
        assert_eq!(&buf.read_msg().unwrap()[..], b"headtail");

        let before = buf.base_seq();
        buf.reclaim();
        assert_eq!(buf.base_seq().offset_from(before), 3, "prefix not fully reclaimed");
    }

    /// Delivered-but-pinned slots must not be advertised as free space, or the
    /// peer overruns the window and its packets are silently rejected.
    #[test]
    fn pinned_slots_are_not_advertised_as_free() {
        let mut buf = RecvBuffer::new(8, seq(0));
        buf.add(seq(1), bytes(b"tail"), MsgBoundary::Last, msg(0), true);
        buf.add(seq(5), bytes(b"early"), MsgBoundary::Solo, msg(1), false);
        buf.read_msg().unwrap();

        // Offsets 0..=5 are pinned (a hole, a held packet and a delivered slot),
        // so at most 2 of the 8 slots remain usable.
        assert!(buf.avail_from(seq(0)) <= 2, "avail={}", buf.avail_from(seq(0)));
    }

    /// A MsgDrop for packets that never arrived must not leave the ring wedged.
    #[test]
    fn drop_range_unblocks_a_permanent_hole() {
        let mut buf = RecvBuffer::new(16, seq(0));
        buf.add(seq(2), bytes(b"after"), MsgBoundary::Solo, msg(1), true);
        // seq 0..=1 are lost for good; the sender says so.
        buf.drop_range(seq(0), seq(1));
        assert_eq!(&buf.read_msg().unwrap()[..], b"after");
        buf.reclaim();
        assert_eq!(buf.base_seq(), seq(3));
    }
}
