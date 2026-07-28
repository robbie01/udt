//! The buffer outgoing datagrams are written into.

/// Datagrams the protocol has produced, waiting to be written to the network.
///
/// The caller owns this and reuses it, which is the point: the protocol appends
/// into memory that already exists instead of allocating a buffer per packet
/// and handing back something the allocator has to reclaim. Clear it after
/// sending and the steady state allocates nothing at all.
///
/// Datagrams land back to back, so a run of equal-sized ones is already
/// contiguous and can go to the kernel as a single segmented write. See
/// [`runs`](Self::runs).
///
/// ```
/// use udt_proto::{CcKind, Connection, SeqNo, TransmitBuf};
///
/// # fn now_us() -> u64 { 0 }
/// # fn write_to_peer(_: &[u8], _: usize) {}
/// let mut conn = Connection::new_active(1, SeqNo::new(0), 1500, now_us(), CcKind::Udt);
/// let mut tx = TransmitBuf::new();
/// let mut events = Vec::new();
///
/// conn.on_timer(now_us(), &mut tx, &mut events);
/// for (bytes, segment_size) in tx.runs() {
///     write_to_peer(bytes, segment_size);
/// }
/// tx.clear();
/// ```
#[derive(Debug, Default)]
pub struct TransmitBuf {
    bytes: bytes::BytesMut,
    /// Length of each datagram, in the order they were written.
    lens: Vec<u32>,
}

impl TransmitBuf {
    /// An empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty buffer with room for `bytes` bytes reserved up front.
    pub fn with_capacity(bytes: usize) -> Self {
        TransmitBuf { bytes: bytes::BytesMut::with_capacity(bytes), lens: Vec::new() }
    }

    /// Whether anything is waiting to be sent.
    pub fn is_empty(&self) -> bool {
        self.lens.is_empty()
    }

    /// How many datagrams are waiting.
    pub fn len(&self) -> usize {
        self.lens.len()
    }

    /// Total bytes waiting, across all datagrams.
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Drop everything, keeping the allocation for next time.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.lens.clear();
    }

    /// The datagrams, grouped into runs that can be sent as one segmented
    /// write.
    ///
    /// Each item is a contiguous slice and the size of the segments within it.
    /// Every datagram in a run is that size except possibly the last, which is
    /// the shape segmentation offload requires — and the shape a UDT message
    /// already has, since only its final packet is short.
    ///
    /// Callers without segmentation offload can ignore the grouping and use
    /// [`datagrams`](Self::datagrams) instead.
    pub fn runs(&self) -> Runs<'_> {
        Runs { buf: self, next: 0, offset: 0 }
    }

    /// The datagrams one at a time.
    pub fn datagrams(&self) -> impl Iterator<Item = &[u8]> + '_ {
        let mut offset = 0;
        self.lens.iter().map(move |&len| {
            let start = offset;
            offset += len as usize;
            &self.bytes[start..offset]
        })
    }

    /// Append a datagram, letting `write` fill it.
    pub(crate) fn push(&mut self, write: impl FnOnce(&mut bytes::BytesMut)) {
        let start = self.bytes.len();
        write(&mut self.bytes);
        let len = self.bytes.len() - start;
        if len == 0 {
            return;
        }
        self.lens.push(len as u32);
    }
}

/// Runs of equal-sized datagrams, from [`TransmitBuf::runs`].
#[derive(Debug)]
pub struct Runs<'a> {
    buf: &'a TransmitBuf,
    next: usize,
    offset: usize,
}

impl<'a> Iterator for Runs<'a> {
    /// The bytes of the run, and the size of the segments in it.
    type Item = (&'a [u8], usize);

    fn next(&mut self) -> Option<Self::Item> {
        let lens = &self.buf.lens;
        if self.next >= lens.len() {
            return None;
        }
        let segment = lens[self.next] as usize;
        let start = self.offset;
        let mut end = self.next + 1;
        let mut bytes = segment;

        // Equal-sized datagrams extend the run...
        while end < lens.len() && lens[end] as usize == segment {
            bytes += segment;
            end += 1;
        }
        // ...and one shorter datagram may ride along as the final segment.
        if end < lens.len() && (lens[end] as usize) < segment {
            bytes += lens[end] as usize;
            end += 1;
        }

        self.next = end;
        self.offset = start + bytes;
        Some((&self.buf.bytes[start..start + bytes], segment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf_of(lens: &[usize]) -> TransmitBuf {
        let mut tx = TransmitBuf::new();
        for (i, &len) in lens.iter().enumerate() {
            tx.push(|dst| dst.extend(std::iter::repeat_n(i as u8, len)));
        }
        tx
    }

    #[test]
    fn datagrams_come_back_as_written() {
        let tx = buf_of(&[10, 10, 4]);
        let got: Vec<usize> = tx.datagrams().map(|d| d.len()).collect();
        assert_eq!(got, vec![10, 10, 4]);
        assert_eq!(tx.len(), 3);
        assert_eq!(tx.byte_len(), 24);
    }

    #[test]
    fn equal_datagrams_group_into_one_run() {
        let tx = buf_of(&[10, 10, 10]);
        let runs: Vec<_> = tx.runs().map(|(b, s)| (b.len(), s)).collect();
        assert_eq!(runs, vec![(30, 10)]);
    }

    #[test]
    fn a_short_final_datagram_joins_the_run() {
        // The shape of a UDT message: full payloads and a short tail.
        let tx = buf_of(&[10, 10, 4]);
        let runs: Vec<_> = tx.runs().map(|(b, s)| (b.len(), s)).collect();
        assert_eq!(runs, vec![(24, 10)]);
    }

    #[test]
    fn a_longer_datagram_starts_a_new_run() {
        let tx = buf_of(&[10, 10, 20]);
        let runs: Vec<_> = tx.runs().map(|(b, s)| (b.len(), s)).collect();
        assert_eq!(runs, vec![(20, 10), (20, 20)]);
    }

    #[test]
    fn runs_cover_every_byte_exactly_once() {
        // Control packets interleaved with data, which is the real pattern.
        let tx = buf_of(&[40, 1400, 1400, 1400, 600, 40, 1400]);
        let total: usize = tx.runs().map(|(b, _)| b.len()).sum();
        assert_eq!(total, tx.byte_len());

        // And the concatenation of the runs is the concatenation of the
        // datagrams, so nothing is reordered or skipped.
        let from_runs: Vec<u8> = tx.runs().flat_map(|(b, _)| b.iter().copied()).collect();
        let from_datagrams: Vec<u8> = tx.datagrams().flatten().copied().collect();
        assert_eq!(from_runs, from_datagrams);
    }

    #[test]
    fn clearing_keeps_the_allocation() {
        let mut tx = buf_of(&[1400; 8]);
        let capacity = tx.bytes.capacity();
        tx.clear();
        assert!(tx.is_empty());
        assert_eq!(tx.bytes.capacity(), capacity, "clearing should not give the buffer back");
    }

    #[test]
    fn an_empty_write_adds_no_datagram() {
        let mut tx = TransmitBuf::new();
        tx.push(|_| {});
        assert!(tx.is_empty());
    }
}
