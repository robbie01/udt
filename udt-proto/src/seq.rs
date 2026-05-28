use std::cmp::Ordering;

pub const SEQ_MAX: u32 = 0x7FFF_FFFF;
const SEQ_TH: u32 = 0x3FFF_FFFF;

pub const MSG_MAX: u32 = 0x1FFF_FFFF;
const MSG_TH: u32 = 0x0FFF_FFFF;

/// 31-bit data sequence number with modular arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeqNo(u32);

/// 29-bit message number with modular arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MsgNo(u32);

/// 31-bit ACK sub-sequence number (independent space from data seqs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AckSeqNo(u32);

impl SeqNo {
    #[inline]
    pub fn new(v: u32) -> Self {
        SeqNo(v & SEQ_MAX)
    }

    #[inline]
    pub fn raw(self) -> u32 {
        self.0
    }

    #[inline]
    pub fn next(self) -> Self {
        SeqNo((self.0 + 1) & SEQ_MAX)
    }

    #[inline]
    pub fn prev(self) -> Self {
        SeqNo(self.0.wrapping_sub(1) & SEQ_MAX)
    }

    #[allow(clippy::should_implement_trait)] // `Add::add` would require a different signature
    #[inline]
    pub fn add(self, n: u32) -> Self {
        SeqNo((self.0 + n) & SEQ_MAX)
    }

    /// Signed offset: positive if self > other in sequence space.
    /// Uses the half-space rule (threshold = SEQ_TH) to handle wrap-around.
    #[inline]
    pub fn offset_from(self, base: SeqNo) -> i32 {
        let diff = self.0.wrapping_sub(base.0) & SEQ_MAX;
        if diff == 0 {
            0
        } else if diff <= SEQ_TH {
            diff as i32
        } else {
            -((SEQ_MAX + 1 - diff) as i32)
        }
    }

    /// Number of sequence numbers from `self` to `other` inclusive
    /// (self must be ≤ other in sequence space).
    #[inline]
    pub fn len_to(self, other: SeqNo) -> u32 {
        let off = other.offset_from(self);
        debug_assert!(off >= 0, "len_to called with other < self");
        off as u32 + 1
    }
}

impl PartialOrd for SeqNo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeqNo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.offset_from(*other).cmp(&0)
    }
}

impl MsgNo {
    #[inline]
    pub fn new(v: u32) -> Self {
        MsgNo(v & MSG_MAX)
    }

    #[inline]
    pub fn raw(self) -> u32 {
        self.0
    }

    #[inline]
    pub fn next(self) -> Self {
        MsgNo((self.0 + 1) & MSG_MAX)
    }

    /// Signed offset with half-space wrap detection.
    #[inline]
    pub fn offset_from(self, base: MsgNo) -> i32 {
        let diff = self.0.wrapping_sub(base.0) & MSG_MAX;
        if diff == 0 {
            0
        } else if diff <= MSG_TH {
            diff as i32
        } else {
            -((MSG_MAX + 1 - diff) as i32)
        }
    }
}

impl PartialOrd for MsgNo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MsgNo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.offset_from(*other).cmp(&0)
    }
}

impl AckSeqNo {
    #[inline]
    pub fn new(v: u32) -> Self {
        AckSeqNo(v & SEQ_MAX)
    }

    #[inline]
    pub fn raw(self) -> u32 {
        self.0
    }

    #[inline]
    pub fn next(self) -> Self {
        AckSeqNo((self.0 + 1) & SEQ_MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_ordering_no_wrap() {
        let a = SeqNo::new(100);
        let b = SeqNo::new(200);
        assert!(a < b);
        assert_eq!(b.offset_from(a), 100);
        assert_eq!(a.offset_from(b), -100);
    }

    #[test]
    fn seq_ordering_wrap() {
        let a = SeqNo::new(SEQ_MAX - 5);
        let b = SeqNo::new(10);
        // b is "after" a in sequence space (b wrapped around)
        assert!(a < b);
        assert_eq!(b.offset_from(a), 16);
        assert_eq!(a.offset_from(b), -16);
    }

    #[test]
    fn seq_next_wraps_at_max() {
        let a = SeqNo::new(SEQ_MAX);
        assert_eq!(a.next(), SeqNo::new(0));
    }

    #[test]
    fn seq_len_to() {
        let a = SeqNo::new(10);
        let b = SeqNo::new(20);
        assert_eq!(a.len_to(b), 11);
        assert_eq!(a.len_to(a), 1);
    }

    #[test]
    fn seq_equal() {
        let a = SeqNo::new(42);
        assert_eq!(a.offset_from(a), 0);
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn msg_ordering_wrap() {
        let a = MsgNo::new(MSG_MAX - 2);
        let b = MsgNo::new(3);
        assert!(a < b);
    }
}
