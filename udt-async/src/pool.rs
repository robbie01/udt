//! Reusable receive buffers.
//!
//! Datagrams reach the protocol as [`Bytes`], which is convenient — a
//! coalesced run is copied once and every datagram in it is a slice sharing
//! that one allocation — but refcounted memory can only go back to the
//! allocator, never to a pool. At a few gigabytes a second that is a copy and
//! an allocation per run, of every byte received.
//!
//! [`Bytes::from_owner`] removes both. A `Bytes` can be backed by anything that
//! looks like a byte slice, so it is backed here by a buffer whose `Drop`
//! returns it to a free list. The kernel writes into pooled memory, the
//! protocol slices it without copying, and when the last datagram from a run is
//! consumed the buffer comes back for the next receive.
//!
//! Retention is unchanged by this: a run was already held until its last
//! datagram was read, since they all shared one allocation.

use std::sync::{Arc, Mutex};

use bytes::Bytes;

/// A set of equally-sized receive buffers that are lent out and returned.
#[derive(Clone)]
pub(crate) struct BufferPool {
    inner: Arc<Inner>,
}

struct Inner {
    free: Mutex<Vec<Vec<u8>>>,
    buf_size: usize,
    /// Buffers kept when returned. Past this they are dropped, so a burst does
    /// not leave the pool holding its peak forever.
    max_free: usize,
}

impl BufferPool {
    pub(crate) fn new(buf_size: usize, max_free: usize) -> Self {
        BufferPool {
            inner: Arc::new(Inner {
                free: Mutex::new(Vec::new()),
                buf_size,
                max_free: max_free.max(1),
            }),
        }
    }

    /// A buffer to receive into, from the pool if one is spare.
    pub(crate) fn take(&self) -> Vec<u8> {
        let taken = self.inner.free.lock().unwrap_or_else(|e| e.into_inner()).pop();
        match taken {
            Some(buf) => buf,
            // Everything lent out at once: allocate rather than block or stall
            // the receive path. It joins the pool when it comes back.
            None => vec![0u8; self.inner.buf_size],
        }
    }

    /// Turn a filled buffer into its first `len` bytes, returning the buffer to
    /// the pool once every slice of it has been dropped.
    pub(crate) fn wrap(&self, buf: Vec<u8>, len: usize) -> Bytes {
        let len = len.min(buf.len());
        let loaned = Loaned { buf: Some(buf), pool: Arc::clone(&self.inner) };
        Bytes::from_owner(loaned).slice(..len)
    }

    #[cfg(test)]
    fn free_count(&self) -> usize {
        self.inner.free.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Inner {
    fn recycle(&self, mut buf: Vec<u8>) {
        if buf.len() != self.buf_size {
            return;
        }
        let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
        if free.len() < self.max_free {
            // The contents are meaningless until the next receive overwrites
            // them, so there is nothing to clear.
            buf.truncate(self.buf_size);
            free.push(buf);
        }
    }
}

/// A buffer on loan from a pool, returned when the last slice of it is dropped.
struct Loaned {
    buf: Option<Vec<u8>>,
    pool: Arc<Inner>,
}

impl AsRef<[u8]> for Loaned {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_deref().unwrap_or(&[])
    }
}

impl Drop for Loaned {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.recycle(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_buffer_returns_once_every_slice_is_gone() {
        let pool = BufferPool::new(64, 8);
        let buf = pool.take();
        assert_eq!(pool.free_count(), 0);

        let bytes = pool.wrap(buf, 64);
        let a = bytes.slice(0..16);
        let b = bytes.slice(16..32);
        drop(bytes);
        drop(a);
        assert_eq!(pool.free_count(), 0, "returned while a slice was still alive");
        drop(b);
        assert_eq!(pool.free_count(), 1, "not returned after the last slice went");
    }

    #[test]
    fn a_returned_buffer_is_handed_out_again() {
        let pool = BufferPool::new(64, 8);
        let first = pool.wrap(pool.take(), 64).as_ptr();
        // The wrap above is dropped immediately, so the buffer is back.
        let second = pool.wrap(pool.take(), 64).as_ptr();
        assert_eq!(first, second, "the pool allocated instead of reusing");
    }

    #[test]
    fn wrapping_exposes_only_the_filled_prefix() {
        let pool = BufferPool::new(64, 8);
        let mut buf = pool.take();
        buf[..4].copy_from_slice(b"abcd");
        let bytes = pool.wrap(buf, 4);
        assert_eq!(&bytes[..], b"abcd");
    }

    #[test]
    fn the_free_list_is_bounded() {
        let pool = BufferPool::new(64, 2);
        for buf in (0..8).map(|_| pool.take()).collect::<Vec<_>>() {
            drop(pool.wrap(buf, 64));
        }
        assert_eq!(pool.free_count(), 2, "the pool kept more than it was told to");
    }

    #[test]
    fn running_dry_allocates_rather_than_stalling() {
        let pool = BufferPool::new(64, 2);
        let held: Vec<_> = (0..100).map(|_| pool.take()).collect();
        assert_eq!(held.len(), 100);
        assert!(held.iter().all(|b| b.len() == 64));
    }
}
