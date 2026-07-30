use crate::seq::SeqNo;

/// Inserts `[seq1, seq2]` into a list of ranges sorted by start and holding no
/// overlaps, and keeps it that way: whatever the new range touches or abuts is
/// merged into a single entry.
///
/// Both loss lists need that shape. Two entries covering the same sequence
/// number make `len()` count it twice, and the removal paths stop at the first
/// range containing a sequence, so the copy behind it is never cleared and the
/// sequence stays "lost" after it has arrived.
fn insert_merging(ranges: &mut Vec<(SeqNo, SeqNo)>, seq1: SeqNo, seq2: SeqNo) {
    let (start, end) = if seq1 <= seq2 { (seq1, seq2) } else { (seq2, seq1) };
    let pos = ranges.partition_point(|&(s, _)| s < start);
    // Extend the range before the insertion point when the new one touches or
    // abuts it, rather than adding a second entry for sequences it holds.
    let at = if pos > 0 && ranges[pos - 1].1.next() >= start {
        let prev_end = &mut ranges[pos - 1].1;
        if end > *prev_end {
            *prev_end = end;
        }
        pos - 1
    } else {
        ranges.insert(pos, (start, end));
        pos
    };
    coalesce_at(ranges, at);
    debug_assert!(
        is_sorted_disjoint(ranges),
        "inserting [{start:?}, {end:?}] left the list inconsistent: {ranges:?}"
    );
}

/// Absorbs every following range that `ranges[idx]` now reaches into it.
fn coalesce_at(ranges: &mut Vec<(SeqNo, SeqNo)>, idx: usize) {
    while idx + 1 < ranges.len() {
        let (_, cur_end) = ranges[idx];
        let (next_start, next_end) = ranges[idx + 1];
        if cur_end.next() >= next_start {
            let new_end = if next_end > cur_end { next_end } else { cur_end };
            ranges[idx].1 = new_end;
            ranges.remove(idx + 1);
        } else {
            break;
        }
    }
}

/// Removes `[first, last]` from a sorted, non-overlapping list of ranges,
/// trimming or splitting whatever it runs through.
///
/// The pair is normalised first, as in [`insert_merging`]. A `MsgDrop` names
/// its range on the wire, so a peer can send one that runs backwards, and the
/// straddle case below would then split a range into two halves that overlap —
/// leaving the list in the state the whole type is written to avoid.
fn remove_range_from(ranges: &mut Vec<(SeqNo, SeqNo)>, first: SeqNo, last: SeqNo) {
    let (first, last) = if first <= last { (first, last) } else { (last, first) };
    let mut i = 0;
    while i < ranges.len() {
        let (s, e) = ranges[i];
        if e < first || s > last {
            // No overlap — leave as-is.
            i += 1;
        } else if s >= first && e <= last {
            // Fully inside removal range — drop entirely.
            ranges.remove(i);
        } else if s < first && e > last {
            // Straddles — split into two.
            ranges[i] = (s, first.prev());
            ranges.insert(i + 1, (last.next(), e));
            i += 2;
        } else if s < first {
            // Overlaps on the right — trim end.
            ranges[i].1 = first.prev();
            i += 1;
        } else {
            // s <= last and e > last — overlaps on the left — trim start.
            ranges[i].0 = last.next();
            i += 1;
        }
    }
    debug_assert!(
        is_sorted_disjoint(ranges),
        "removing [{first:?}, {last:?}] left the list inconsistent: {ranges:?}"
    );
}

/// Whether `ranges` has the shape both loss lists promise: every range running
/// forwards, and every range starting after the one before it ends.
///
/// Ordering is `SeqNo`'s, so this is a statement about a window narrower than
/// half the sequence space — which a loss list, bounded by the receive buffer,
/// always is.
pub fn is_sorted_disjoint(ranges: &[(SeqNo, SeqNo)]) -> bool {
    ranges.iter().all(|&(s, e)| s <= e) && ranges.windows(2).all(|w| w[0].1 < w[1].0)
}

/// Send-side loss list: sorted, non-overlapping ranges of lost sequence numbers.
/// Pre-allocated at construction to avoid hot-path allocation.
pub struct SndLossList {
    ranges: Vec<(SeqNo, SeqNo)>, // sorted by start, (start, end) inclusive
}

impl SndLossList {
    pub fn new(capacity: usize) -> Self {
        SndLossList { ranges: Vec::with_capacity(capacity) }
    }

    /// Insert a loss range [seq1, seq2] (inclusive). Merges with existing ranges.
    pub fn insert(&mut self, seq1: SeqNo, seq2: SeqNo) {
        insert_merging(&mut self.ranges, seq1, seq2);
    }

    /// Remove all entries with seq_no <= ack (sender received ACK up to this point).
    pub fn remove_up_to(&mut self, ack: SeqNo) {
        self.ranges.retain(|&(_, e)| e > ack);
        if let Some((s, _)) = self.ranges.first_mut()
            && *s <= ack
        {
            *s = ack.next();
        }
    }

    /// Remove every entry in `[first, last]` — used when a message is dropped,
    /// so its sequence numbers are never retransmitted.
    pub fn remove_range(&mut self, first: SeqNo, last: SeqNo) {
        remove_range_from(&mut self.ranges, first, last);
    }

    /// Pop the lowest sequence number for retransmission.
    pub fn pop_front(&mut self) -> Option<SeqNo> {
        let (start, end) = self.ranges.first_mut()?;
        let seq = *start;
        if *start == *end {
            self.ranges.remove(0);
        } else {
            *start = start.next();
        }
        Some(seq)
    }

    pub fn len(&self) -> usize {
        self.ranges.iter().map(|(s, e)| e.offset_from(*s) as usize + 1).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Receive-side loss list: sorted ranges of packets the receiver has not yet received.
/// Pre-allocated at construction.
pub struct RcvLossList {
    ranges: Vec<(SeqNo, SeqNo)>,
}

impl RcvLossList {
    pub fn new(capacity: usize) -> Self {
        RcvLossList { ranges: Vec::with_capacity(capacity) }
    }

    /// Insert the gap `[seq1, seq2]` (inclusive). Merges with existing ranges.
    ///
    /// Nothing here should overlap to begin with: the receiver only records
    /// gaps above `rcv_curr_seq`, which is already above everything in the
    /// list. But that is a property of three files agreeing — the cursor only
    /// ever moving forwards, the ring bounding how far ahead an arrival can
    /// be, and the acknowledgement point filtering what is behind — and it has
    /// been wrong once already, when a peer that put the sequence wrap early in
    /// the connection could walk the cursor backwards and re-open a gap the
    /// list still held. The merge is one comparison on a path that runs once
    /// per gap. Getting it wrong costs a sequence NAKed after it has arrived,
    /// since `remove` clears only the first range holding it.
    pub fn insert(&mut self, seq1: SeqNo, seq2: SeqNo) {
        insert_merging(&mut self.ranges, seq1, seq2);
    }

    /// Remove a single received sequence number from the loss list.
    pub fn remove(&mut self, seq: SeqNo) -> bool {
        for i in 0..self.ranges.len() {
            let (start, end) = self.ranges[i];
            if seq < start || seq > end {
                continue;
            }
            if start == end {
                self.ranges.remove(i);
            } else if seq == start {
                self.ranges[i].0 = seq.next();
            } else if seq == end {
                self.ranges[i].1 = seq.prev();
            } else {
                // Split
                let new_end = seq.prev();
                let new_start = seq.next();
                self.ranges[i] = (start, new_end);
                self.ranges.insert(i + 1, (new_start, end));
            }
            return true;
        }
        false
    }

    /// Remove all entries in [seq1, seq2] (for MsgDrop).
    pub fn remove_range(&mut self, seq1: SeqNo, seq2: SeqNo) {
        remove_range_from(&mut self.ranges, seq1, seq2);
    }

    #[cfg(test)]
    pub fn contains(&self, seq: SeqNo) -> bool {
        self.ranges.iter().any(|&(s, e)| seq >= s && seq <= e)
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn ranges_snapshot(&self) -> &[(SeqNo, SeqNo)] {
        &self.ranges
    }

    pub fn first(&self) -> Option<SeqNo> {
        self.ranges.first().map(|&(s, _)| s)
    }

    pub fn len(&self) -> usize {
        self.ranges.iter().map(|(s, e)| e.offset_from(*s) as usize + 1).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Encode as NAK loss list payload (LE u32 words).
    /// `limit` is the max number of u32 words to emit.
    pub fn to_nak_payload(&self, limit: usize) -> Vec<u32> {
        let mut out = Vec::new();
        for &(start, end) in &self.ranges {
            if out.len() + 2 > limit {
                break;
            }
            if start == end {
                out.push(start.raw());
            } else {
                out.push(start.raw() | 0x8000_0000); // range flag
                out.push(end.raw());
            }
        }
        out
    }
}

impl SndLossList {
    pub fn ranges_snapshot(&self) -> &[(SeqNo, SeqNo)] {
        &self.ranges
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seq::{SEQ_MAX, SeqNo};

    fn s(n: u32) -> SeqNo {
        SeqNo::new(n)
    }

    #[test]
    fn snd_insert_and_pop() {
        let mut list = SndLossList::new(16);
        list.insert(s(5), s(10));
        list.insert(s(20), s(25));
        assert_eq!(list.pop_front(), Some(s(5)));
        assert_eq!(list.pop_front(), Some(s(6)));
    }

    #[test]
    fn snd_remove_up_to() {
        let mut list = SndLossList::new(16);
        list.insert(s(1), s(100));
        list.remove_up_to(s(50));
        assert_eq!(list.pop_front(), Some(s(51)));
    }

    #[test]
    fn snd_merge_ranges() {
        let mut list = SndLossList::new(16);
        list.insert(s(1), s(5));
        list.insert(s(6), s(10)); // adjacent, should merge
        assert_eq!(list.len(), 10);
        assert_eq!(list.pop_front(), Some(s(1)));
    }

    #[test]
    fn rcv_insert_remove() {
        let mut list = RcvLossList::new(16);
        list.insert(s(10), s(20));
        assert!(list.contains(s(15)));
        list.remove(s(15));
        assert!(!list.contains(s(15)));
        assert!(list.contains(s(14)));
        assert!(list.contains(s(16)));
    }

    #[test]
    fn rcv_nak_payload() {
        let mut list = RcvLossList::new(16);
        list.insert(s(10), s(20)); // range
        list.insert(s(30), s(30)); // single
        let nak = list.to_nak_payload(16);
        // range: [10|0x80000000, 20] then single [30]
        assert_eq!(nak[0], 10 | 0x8000_0000);
        assert_eq!(nak[1], 20);
        assert_eq!(nak[2], 30);
    }

    #[test]
    fn rcv_insert_merges_an_overlapping_range() {
        let mut list = RcvLossList::new(16);
        list.insert(s(10), s(20));
        list.insert(s(15), s(30));
        assert_eq!(list.ranges_snapshot(), [(s(10), s(30))]);
        // The intersection is counted once, not twice.
        assert_eq!(list.len(), 21);
    }

    #[test]
    fn rcv_insert_absorbs_a_nested_range() {
        let mut list = RcvLossList::new(16);
        list.insert(s(10), s(30));
        list.insert(s(15), s(20));
        assert_eq!(list.ranges_snapshot(), [(s(10), s(30))]);
    }

    #[test]
    fn rcv_insert_bridges_the_ranges_either_side() {
        let mut list = RcvLossList::new(16);
        list.insert(s(10), s(15));
        list.insert(s(40), s(45));
        list.insert(s(60), s(65));
        list.insert(s(12), s(50));
        assert_eq!(list.ranges_snapshot(), [(s(10), s(50)), (s(60), s(65))]);
    }

    #[test]
    fn rcv_insert_merges_across_the_wrap() {
        let mut list = RcvLossList::new(16);
        list.insert(s(SEQ_MAX - 10), s(SEQ_MAX));
        list.insert(s(SEQ_MAX - 5), s(5));
        assert_eq!(list.ranges_snapshot(), [(s(SEQ_MAX - 10), s(5))]);
        assert_eq!(list.len(), 17);
    }

    #[test]
    fn rcv_a_sequence_inserted_twice_is_cleared_once() {
        // The point of merging. `remove` returns at the first range holding the
        // sequence, so a second entry covering it would survive the packet's
        // arrival and be NAKed again — asking for what the receiver already has.
        let mut list = RcvLossList::new(16);
        list.insert(s(10), s(20));
        list.insert(s(10), s(20));
        assert!(list.remove(s(15)));
        assert!(!list.contains(s(15)));
    }

    #[test]
    fn rcv_remove_range() {
        let mut list = RcvLossList::new(16);
        list.insert(s(1), s(100));
        list.remove_range(s(20), s(80));
        assert!(!list.contains(s(50)));
        assert!(list.contains(s(10)));
        assert!(list.contains(s(90)));
    }

    #[test]
    fn rcv_remove_range_reads_a_backwards_pair_as_the_range_it_spans() {
        // A MsgDrop names both ends on the wire, so a peer can reverse them.
        // Taken literally the straddle case splits [1, 100] into [1, 79] and
        // [21, 100] — two ranges holding the same sixty sequences.
        let mut list = RcvLossList::new(16);
        list.insert(s(1), s(100));
        list.remove_range(s(80), s(20));
        assert_eq!(list.ranges_snapshot(), [(s(1), s(19)), (s(81), s(100))]);
    }
}
