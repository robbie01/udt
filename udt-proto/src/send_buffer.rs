use crate::packet::MsgBoundary;
use crate::seq::MsgNo;
use bytes::Bytes;

/// A single block in the send buffer.
pub struct Block {
    pub data: Bytes,
    pub msg_no: MsgNo,
    pub boundary: MsgBoundary,
    pub origin_us: u64,
    pub ttl_ms: Option<u32>,
    pub in_order: bool,
    /// Set once the message's TTL has elapsed. The block keeps its slot: this
    /// buffer maps block index to sequence number *positionally*, so removing
    /// it would shift every later block and make `read_at` serve the wrong
    /// payload under a live sequence number. It is freed normally by `ack`.
    pub dropped: bool,
}

/// Fixed-capacity send buffer ring.
///
/// Messages are split into payload-sized blocks at `add()` time.
/// `read_next()` advances through new blocks for first-time sends.
/// `read_at(offset)` fetches a specific block for retransmission (0 = first in-flight).
/// `ack(count)` frees the oldest `count` blocks.
pub struct SendBuffer {
    slots: Box<[Option<Block>]>,
    capacity: usize,
    /// Index of the first in-flight (unacked) block.
    head: usize,
    /// Total blocks in buffer (head..head+len, mod capacity).
    len: usize,
    /// Number of blocks sent but not yet ACKed (read cursor within the in-flight window).
    sent: usize,
    payload_size: usize,
    next_msg_no: MsgNo,
}

impl SendBuffer {
    /// `capacity` is the number of packet-sized blocks (e.g. 8192).
    /// `payload_size` is the max bytes per block (MSS - IP/UDP/UDT headers).
    pub fn new(capacity: usize, payload_size: usize) -> Self {
        let slots = (0..capacity).map(|_| None).collect::<Vec<_>>().into_boxed_slice();
        SendBuffer {
            slots,
            capacity,
            head: 0,
            len: 0,
            sent: 0,
            payload_size,
            next_msg_no: MsgNo::new(0),
        }
    }

    /// Enqueue a message. It is split into payload-sized blocks automatically.
    /// Returns `Err(())` if there is insufficient space.
    ///
    /// Takes an owned [`Bytes`] so the per-packet blocks can be cheap slices of
    /// the caller's buffer (a refcount bump each) rather than copies. Splitting
    /// a large message would otherwise memcpy the whole payload a second time.
    #[allow(clippy::result_unit_err)]
    pub fn add(
        &mut self,
        data: Bytes,
        ttl_ms: Option<u32>,
        in_order: bool,
        now_us: u64,
    ) -> Result<(), ()> {
        let n_chunks = data.len().div_ceil(self.payload_size);
        if n_chunks == 0 {
            return Ok(());
        }
        if self.len + n_chunks > self.capacity {
            return Err(());
        }
        let msg_no = self.next_msg_no;
        self.next_msg_no = self.next_msg_no.next();
        for i in 0..n_chunks {
            let start = i * self.payload_size;
            let end = (start + self.payload_size).min(data.len());
            let boundary = if n_chunks == 1 {
                MsgBoundary::Solo
            } else if i == 0 {
                MsgBoundary::First
            } else if i == n_chunks - 1 {
                MsgBoundary::Last
            } else {
                MsgBoundary::Middle
            };
            let idx = (self.head + self.len) % self.capacity;
            self.slots[idx] = Some(Block {
                data: data.slice(start..end),
                msg_no,
                boundary,
                origin_us: now_us,
                ttl_ms,
                in_order,
                dropped: false,
            });
            self.len += 1;
        }
        Ok(())
    }

    /// Read the next unsent block (new transmission). Returns None if no new data.
    pub fn read_next(&mut self) -> Option<&Block> {
        if self.sent >= self.len {
            return None;
        }
        let idx = (self.head + self.sent) % self.capacity;
        self.sent += 1;
        self.slots[idx].as_ref().filter(|b| !b.dropped)
    }

    /// Read a specific in-flight block by offset from the ACK boundary (0 = oldest unacked).
    /// Used for retransmission. Returns None if the offset is out of range or the
    /// message was dropped, in which case the caller must not retransmit it.
    pub fn read_at(&self, offset: usize) -> Option<&Block> {
        if offset >= self.sent {
            return None;
        }
        let idx = (self.head + offset) % self.capacity;
        self.slots[idx].as_ref().filter(|b| !b.dropped)
    }

    /// Offset of the next block that has not yet been transmitted.
    pub fn send_cursor(&self) -> usize {
        self.sent
    }

    /// If the block at in-flight offset `off` has outlived its TTL, mark that
    /// whole message dropped and report its extent as `(msg_no, first, last)`
    /// in block offsets.
    ///
    /// The offsets map to sequence numbers as `snd_last_ack + off`, so the
    /// caller can name the exact range in a MsgDrop. `sent` is advanced past the
    /// message so those sequence numbers are consumed rather than skipped —
    /// C++ instead advances `m_iSndCurrSeqNo` past sequence numbers with no
    /// backing block, which desynchronises this very mapping.
    ///
    /// Checked on first transmission as well as on retransmit. C++ only checks
    /// on retransmit, which is why at saturation — where queueing delay alone
    /// exceeds any sane TTL — essentially every block expires the moment it is
    /// reconsidered.
    pub fn expire_msg_at(&mut self, off: usize, now_us: u64) -> Option<(MsgNo, usize, usize)> {
        if off >= self.len {
            return None;
        }
        let b = self.slots[(self.head + off) % self.capacity].as_ref()?;
        if b.dropped {
            return None;
        }
        let ttl_us = u64::from(b.ttl_ms?) * 1_000;
        if now_us.saturating_sub(b.origin_us) <= ttl_us {
            return None;
        }
        let msg_no = b.msg_no;
        let (first, last) = self.msg_bounds(off, msg_no);
        for i in first..=last {
            if let Some(p) = self.slots[(self.head + i) % self.capacity].as_mut() {
                p.dropped = true;
            }
        }
        // Consume the sequence numbers these blocks occupy.
        self.sent = self.sent.max(last + 1);
        Some((msg_no, first, last))
    }

    /// The offsets a message spans, given any offset inside it.
    ///
    /// Messages occupy contiguous blocks, so this walks out in both directions.
    /// Walking *back* matters: part of the message may already have been sent,
    /// and those blocks have to be covered too or they sit on the loss list
    /// forever.
    fn msg_bounds(&self, off: usize, msg_no: MsgNo) -> (usize, usize) {
        let mut first = off;
        while first > 0 {
            match self.slots[(self.head + first - 1) % self.capacity].as_ref() {
                Some(p) if p.msg_no == msg_no => first -= 1,
                _ => break,
            }
        }
        let mut last = off;
        while last + 1 < self.len {
            match self.slots[(self.head + last + 1) % self.capacity].as_ref() {
                Some(p) if p.msg_no == msg_no => last += 1,
                _ => break,
            }
        }
        (first, last)
    }

    /// The message at `off` if it has already been given up on.
    ///
    /// Lets the caller re-notify a peer that is still asking for a range which
    /// was dropped, rather than leaving it waiting for packets that will never
    /// be sent.
    pub fn dropped_msg_at(&self, off: usize) -> Option<(MsgNo, usize, usize)> {
        if off >= self.len {
            return None;
        }
        let b = self.slots[(self.head + off) % self.capacity].as_ref()?;
        if !b.dropped {
            return None;
        }
        let (first, last) = self.msg_bounds(off, b.msg_no);
        Some((b.msg_no, first, last))
    }

    /// Acknowledge `count` blocks (freeing them from the head of the buffer).
    ///
    /// `count` must not exceed the number of in-flight blocks: acknowledging
    /// more than was sent means the caller's sequence bookkeeping has drifted
    /// out of step with this buffer, and freeing those blocks would silently
    /// discard unsent data and misalign every later `read_at`.
    pub fn ack(&mut self, count: usize) {
        debug_assert!(
            count <= self.sent,
            "ack({count}) exceeds in-flight block count ({}) — sequence bookkeeping has drifted",
            self.sent,
        );
        let count = count.min(self.sent);
        for i in 0..count {
            let idx = (self.head + i) % self.capacity;
            self.slots[idx] = None;
        }
        self.head = (self.head + count) % self.capacity;
        self.len -= count;
        self.sent -= count;
    }

    /// Largest message, in bytes, that could ever fit in an empty buffer.
    /// A message above this size can never be queued and must be rejected
    /// rather than retried.
    pub fn max_msg_bytes(&self) -> usize {
        self.capacity * self.payload_size
    }

    /// Number of blocks sent but not yet ACKed (in-flight).
    pub fn in_flight(&self) -> usize {
        self.sent
    }

    /// Number of blocks not yet sent (new data waiting).
    pub fn pending(&self) -> usize {
        self.len - self.sent
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_read_single_block() {
        let mut buf = SendBuffer::new(64, 1000);
        buf.add(Bytes::from_static(b"hello"), None, false, 0).unwrap();
        let block = buf.read_next().unwrap();
        assert_eq!(&block.data[..], b"hello");
        assert_eq!(block.boundary, MsgBoundary::Solo);
    }

    #[test]
    fn add_multi_block_message() {
        let mut buf = SendBuffer::new(64, 4);
        buf.add(Bytes::from_static(b"abcdefgh"), None, false, 0).unwrap(); // 2 blocks of 4
        let b0 = buf.read_next().unwrap();
        assert_eq!(b0.boundary, MsgBoundary::First);
        assert_eq!(&b0.data[..], b"abcd");
        let b1 = buf.read_next().unwrap();
        assert_eq!(b1.boundary, MsgBoundary::Last);
        assert_eq!(&b1.data[..], b"efgh");
        assert!(buf.read_next().is_none());
    }

    #[test]
    fn ack_frees_space() {
        let mut buf = SendBuffer::new(4, 1000);
        buf.add(Bytes::from_static(b"a"), None, false, 0).unwrap();
        buf.add(Bytes::from_static(b"b"), None, false, 0).unwrap();
        buf.add(Bytes::from_static(b"c"), None, false, 0).unwrap();
        buf.add(Bytes::from_static(b"d"), None, false, 0).unwrap();
        assert!(buf.add(Bytes::from_static(b"e"), None, false, 0).is_err()); // full
        buf.read_next();
        buf.read_next();
        buf.ack(2);
        assert!(buf.add(Bytes::from_static(b"e"), None, false, 0).is_ok());
    }

    #[test]
    fn read_at_for_retransmit() {
        let mut buf = SendBuffer::new(64, 1000);
        buf.add(Bytes::from_static(b"first"), None, false, 0).unwrap();
        buf.add(Bytes::from_static(b"second"), None, false, 0).unwrap();
        buf.read_next(); // advance sent cursor
        buf.read_next();
        let block = buf.read_at(0).unwrap();
        assert_eq!(&block.data[..], b"first");
        let block = buf.read_at(1).unwrap();
        assert_eq!(&block.data[..], b"second");
    }
}
