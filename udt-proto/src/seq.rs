//! Sequence and message numbers.
//!
//! UDT numbers packets in a 31-bit space and messages in a 29-bit one, both of
//! which wrap. The types here make that wrapping total: comparison and
//! subtraction interpret the smaller of the two possible distances as the real
//! one, so `SeqNo(0)` is correctly *after* `SeqNo(SEQ_MAX)`. Never compare the
//! raw integers.

use std::cmp::Ordering;

/// Largest data sequence number; the space wraps to 0 after this.
pub const SEQ_MAX: u32 = 0x7FFF_FFFF;

/// Half the sequence space, the point at which a difference is read as a
/// backwards wrap rather than a forwards jump.
const SEQ_TH: u32 = 0x3FFF_FFFF;

/// Largest message number; the space wraps to 0 after this.
pub const MSG_MAX: u32 = 0x1FFF_FFFF;

/// Half the message space. See [`SEQ_TH`].
const MSG_TH: u32 = 0x0FFF_FFFF;

/// A packet's position in the 31-bit data sequence space.
///
/// Ordering and arithmetic wrap: comparisons are only meaningful between
/// numbers less than half the space apart, which real connections always are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeqNo(u32);

/// A message's position in the 29-bit message space.
///
/// Wraps like [`SeqNo`]. One message may span many packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MsgNo(u32);

/// The number identifying one ACK, so its acknowledgement can be matched back.
///
/// A separate space from [`SeqNo`], incremented once per full ACK sent. The
/// round-trip time is measured from an ACK to the ACK2 quoting its number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AckSeqNo(u32);

impl SeqNo {
    /// Wraps `v` into the sequence space, discarding any high bits.
    #[inline]
    pub fn new(v: u32) -> Self {
        SeqNo(v & SEQ_MAX)
    }

    /// The underlying integer, as it appears on the wire.
    #[inline]
    pub fn raw(self) -> u32 {
        self.0
    }

    /// The next sequence number, wrapping past [`SEQ_MAX`].
    #[inline]
    pub fn next(self) -> Self {
        SeqNo((self.0 + 1) & SEQ_MAX)
    }

    /// The previous sequence number, wrapping below zero.
    #[inline]
    pub fn prev(self) -> Self {
        SeqNo(self.0.wrapping_sub(1) & SEQ_MAX)
    }

    /// This sequence number advanced by `n`, wrapping.
    #[allow(clippy::should_implement_trait)] // `Add::add` would require a different signature
    #[inline]
    pub fn add(self, n: u32) -> Self {
        SeqNo((self.0 + n) & SEQ_MAX)
    }

    /// This sequence number shifted by `n`, which may be negative. Wraps.
    ///
    /// The inverse of [`offset_from`](Self::offset_from), and the way back
    /// from an offset that has been clamped or compared as an integer — which
    /// is the only sound way to bound a sequence number that came off the
    /// wire, since ordering here means nothing across half the space.
    #[inline]
    pub fn shift(self, n: i32) -> Self {
        SeqNo(self.0.wrapping_add(n as u32) & SEQ_MAX)
    }

    /// How far `self` is ahead of `base`, negative if behind.
    ///
    /// A difference of more than half the sequence space is read as the short
    /// way round, so this stays correct across a wrap.
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

    /// How many sequence numbers the inclusive range `self..=other` covers.
    ///
    /// # Panics
    ///
    /// Debug builds panic if `other` is before `self`.
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
    /// Wraps `v` into the message space, discarding any high bits.
    #[inline]
    pub fn new(v: u32) -> Self {
        MsgNo(v & MSG_MAX)
    }

    /// The underlying integer, as it appears on the wire.
    #[inline]
    pub fn raw(self) -> u32 {
        self.0
    }

    /// The next message number, wrapping past [`MSG_MAX`].
    #[inline]
    pub fn next(self) -> Self {
        MsgNo((self.0 + 1) & MSG_MAX)
    }

    /// How far `self` is ahead of `base`, negative if behind. Wrap-aware, as
    /// [`SeqNo::offset_from`].
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
    /// Wraps `v` into the ACK sub-sequence space.
    #[inline]
    pub fn new(v: u32) -> Self {
        AckSeqNo(v & SEQ_MAX)
    }

    /// The underlying integer, as it appears on the wire.
    #[inline]
    pub fn raw(self) -> u32 {
        self.0
    }

    /// The next ACK sub-sequence number, wrapping.
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
    fn seq_shift_is_the_inverse_of_offset_from() {
        let base = SeqNo::new(1000);
        for n in [-2000, -1, 0, 1, 2000, 1 << 29] {
            assert_eq!(base.shift(n).offset_from(base), n, "shift by {n}");
        }
        // Wrapping both ways, not saturating.
        assert_eq!(SeqNo::new(2).shift(-5), SeqNo::new(SEQ_MAX - 2));
        assert_eq!(SeqNo::new(SEQ_MAX - 2).shift(5), SeqNo::new(2));
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
