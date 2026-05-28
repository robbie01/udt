use crate::seq::{SeqNo, AckSeqNo};

const DEFAULT_SIZE: usize = 1024;

/// Fixed-capacity circular buffer tracking sent ACKs for RTT measurement.
/// When we send an ACK, we store (ack_sub_seq, data_ack_seq, send_time).
/// When we receive an ACK2, we look up the matching ack_sub_seq to get RTT.
pub struct AckWindow {
    entries: Box<[(AckSeqNo, SeqNo, u64)]>, // (ack_sub_seq, data_ack, timestamp_us)
    head: usize,
    tail: usize,
    size: usize,
}

impl AckWindow {
    pub fn new() -> Self {
        AckWindow::with_capacity(DEFAULT_SIZE)
    }

    pub fn with_capacity(n: usize) -> Self {
        let entries = (0..n)
            .map(|_| (AckSeqNo::new(0), SeqNo::new(0), 0u64))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        AckWindow { entries, head: 0, tail: 0, size: n }
    }

    /// Record a sent ACK.
    pub fn store(&mut self, ack_sub_seq: AckSeqNo, data_ack: SeqNo, now_us: u64) {
        self.entries[self.head] = (ack_sub_seq, data_ack, now_us);
        self.head = (self.head + 1) % self.size;
        if self.head == self.tail {
            // Overwrite oldest — advance tail
            self.tail = (self.tail + 1) % self.size;
        }
    }

    /// Look up by ACK sub-seq number (from an incoming ACK2).
    /// Returns `Some((rtt_us, data_ack_seq))` if found.
    pub fn acknowledge(&self, ack_sub_seq: AckSeqNo, now_us: u64) -> Option<(u32, SeqNo)> {
        let mut idx = self.head;
        loop {
            if idx == self.tail {
                return None;
            }
            idx = if idx == 0 { self.size - 1 } else { idx - 1 };
            let (stored_seq, data_ack, ts) = self.entries[idx];
            if stored_seq == ack_sub_seq {
                let rtt = (now_us.saturating_sub(ts)) as u32;
                return Some((rtt, data_ack));
            }
            if idx == self.tail {
                return None;
            }
        }
    }
}

impl Default for AckWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_retrieve() {
        let mut w = AckWindow::new();
        w.store(AckSeqNo::new(1), SeqNo::new(100), 1_000_000);
        w.store(AckSeqNo::new(2), SeqNo::new(200), 2_000_000);
        let (rtt, data_ack) = w.acknowledge(AckSeqNo::new(1), 1_100_000).unwrap();
        assert_eq!(rtt, 100_000);
        assert_eq!(data_ack, SeqNo::new(100));
    }

    #[test]
    fn missing_returns_none() {
        let mut w = AckWindow::new();
        w.store(AckSeqNo::new(1), SeqNo::new(100), 0);
        assert!(w.acknowledge(AckSeqNo::new(99), 100).is_none());
    }
}
