use bytes::Bytes;
use crate::seq::MsgNo;
use crate::packet::MsgBoundary;

/// A single block in the send buffer.
pub struct Block {
    pub data: Bytes,
    pub msg_no: MsgNo,
    pub boundary: MsgBoundary,
    pub origin_us: u64,
    pub ttl_ms: Option<u32>,
    pub in_order: bool,
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
    pub fn add(&mut self, data: &[u8], ttl_ms: Option<u32>, in_order: bool, now_us: u64) -> Result<(), ()> {
        let chunks = data.chunks(self.payload_size);
        let n_chunks = chunks.len();
        if n_chunks == 0 {
            return Ok(());
        }
        if self.len + n_chunks > self.capacity {
            return Err(());
        }
        let msg_no = self.next_msg_no;
        self.next_msg_no = self.next_msg_no.next();
        for (i, chunk) in data.chunks(self.payload_size).enumerate() {
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
                data: Bytes::copy_from_slice(chunk),
                msg_no,
                boundary,
                origin_us: now_us,
                ttl_ms,
                in_order,
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
        self.slots[idx].as_ref()
    }

    /// Read a specific in-flight block by offset from the ACK boundary (0 = oldest unacked).
    /// Used for retransmission. Returns None if offset is out of range.
    pub fn read_at(&self, offset: usize) -> Option<&Block> {
        if offset >= self.sent {
            return None;
        }
        let idx = (self.head + offset) % self.capacity;
        self.slots[idx].as_ref()
    }

    /// Acknowledge `count` blocks (freeing them from the head of the buffer).
    pub fn ack(&mut self, count: usize) {
        let count = count.min(self.sent);
        for i in 0..count {
            let idx = (self.head + i) % self.capacity;
            self.slots[idx] = None;
        }
        self.head = (self.head + count) % self.capacity;
        self.len -= count;
        self.sent -= count;
    }

    /// Number of blocks currently buffered (including sent-not-acked and unsent).
    pub fn buffered(&self) -> usize {
        self.len
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
        buf.add(b"hello", None, false, 0).unwrap();
        let block = buf.read_next().unwrap();
        assert_eq!(&block.data[..], b"hello");
        assert_eq!(block.boundary, MsgBoundary::Solo);
    }

    #[test]
    fn add_multi_block_message() {
        let mut buf = SendBuffer::new(64, 4);
        buf.add(b"abcdefgh", None, false, 0).unwrap(); // 2 blocks of 4
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
        buf.add(b"a", None, false, 0).unwrap();
        buf.add(b"b", None, false, 0).unwrap();
        buf.add(b"c", None, false, 0).unwrap();
        buf.add(b"d", None, false, 0).unwrap();
        assert!(buf.add(b"e", None, false, 0).is_err()); // full
        buf.read_next();
        buf.read_next();
        buf.ack(2);
        assert!(buf.add(b"e", None, false, 0).is_ok());
    }

    #[test]
    fn read_at_for_retransmit() {
        let mut buf = SendBuffer::new(64, 1000);
        buf.add(b"first", None, false, 0).unwrap();
        buf.add(b"second", None, false, 0).unwrap();
        buf.read_next(); // advance sent cursor
        buf.read_next();
        let block = buf.read_at(0).unwrap();
        assert_eq!(&block.data[..], b"first");
        let block = buf.read_at(1).unwrap();
        assert_eq!(&block.data[..], b"second");
    }
}
