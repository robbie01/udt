use crate::seq::SeqNo;

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
        let (start, end) = if seq1 <= seq2 { (seq1, seq2) } else { (seq2, seq1) };
        // Find insertion point
        let pos = self.ranges.partition_point(|&(s, _)| s < start);
        // Check if we can extend the previous range
        if pos > 0 {
            let (_, prev_end) = &mut self.ranges[pos - 1];
            if prev_end.next() >= start {
                // Merge into previous
                if end > *prev_end {
                    *prev_end = end;
                }
                self.coalesce_at(pos - 1);
                return;
            }
        }
        self.ranges.insert(pos, (start, end));
        self.coalesce_at(pos);
    }

    fn coalesce_at(&mut self, idx: usize) {
        while idx + 1 < self.ranges.len() {
            let (_, cur_end) = self.ranges[idx];
            let (next_start, next_end) = self.ranges[idx + 1];
            if cur_end.next() >= next_start {
                let new_end = if next_end > cur_end { next_end } else { cur_end };
                self.ranges[idx].1 = new_end;
                self.ranges.remove(idx + 1);
            } else {
                break;
            }
        }
    }

    /// Remove all entries with seq_no <= ack (sender received ACK up to this point).
    pub fn remove_up_to(&mut self, ack: SeqNo) {
        self.ranges.retain(|&(_, e)| e > ack);
        if let Some((s, _)) = self.ranges.first_mut() {
            if *s <= ack {
                *s = ack.next();
            }
        }
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

    pub fn insert(&mut self, seq1: SeqNo, seq2: SeqNo) {
        let (start, end) = if seq1 <= seq2 { (seq1, seq2) } else { (seq2, seq1) };
        let pos = self.ranges.partition_point(|&(s, _)| s < start);
        self.ranges.insert(pos, (start, end));
        // Note: receiver loss list entries should never overlap (we only insert
        // gaps we haven't seen), but coalesce defensively.
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
        let mut i = 0;
        while i < self.ranges.len() {
            let (s, e) = self.ranges[i];
            if e < seq1 || s > seq2 {
                // No overlap — leave as-is.
                i += 1;
            } else if s >= seq1 && e <= seq2 {
                // Fully inside removal range — drop entirely.
                self.ranges.remove(i);
            } else if s < seq1 && e > seq2 {
                // Straddles — split into two.
                self.ranges[i] = (s, seq1.prev());
                self.ranges.insert(i + 1, (seq2.next(), e));
                i += 2;
            } else if s < seq1 {
                // Overlaps on the right — trim end.
                self.ranges[i].1 = seq1.prev();
                i += 1;
            } else {
                // s <= seq2 and e > seq2 — overlaps on the left — trim start.
                self.ranges[i].0 = seq2.next();
                i += 1;
            }
        }
    }

    pub fn contains(&self, seq: SeqNo) -> bool {
        self.ranges.iter().any(|&(s, e)| seq >= s && seq <= e)
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

    pub fn ranges(&self) -> &[(SeqNo, SeqNo)] {
        &self.ranges
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
    use crate::seq::SeqNo;

    fn s(n: u32) -> SeqNo { SeqNo::new(n) }

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
    fn rcv_remove_range() {
        let mut list = RcvLossList::new(16);
        list.insert(s(1), s(100));
        list.remove_range(s(20), s(80));
        assert!(!list.contains(s(50)));
        assert!(list.contains(s(10)));
        assert!(list.contains(s(90)));
    }
}
