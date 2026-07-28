//! Batched UDP send and receive.
//!
//! A saturated connection spends roughly 95% of its time in `sendto` and
//! `recvfrom`, and sends outnumber receives about two to one: the receive path
//! already drains everything queued per wakeup, while a plain UDP send costs
//! one syscall per datagram. Two kernel offloads close that gap where the
//! platform has them, both taken from [`quinn_udp`] so this crate keeps
//! `forbid(unsafe_code)`:
//!
//! * **Segmentation offload (GSO)** on send. Equal-sized datagrams bound for
//!   the same peer go to the kernel as one buffer plus a segment size, and are
//!   split below the syscall boundary. Every UDT data packet carries a full
//!   payload except the tail of a message, so runs are long and a whole
//!   message usually costs one transmit. The protocol writes its datagrams
//!   contiguously into a [`TransmitBuf`], so the buffer handed to the kernel is
//!   the one the packets were built in — nothing is copied to coalesce it.
//! * **`recvmmsg`** on receive, filling several buffers per call.
//!
//! Where neither exists (macOS, OpenBSD) `max_gso_segments()` reports 1 and
//! everything here falls back to the per-datagram behaviour it replaces.
//! Note that CI on macOS therefore exercises only the fallback: changes to the
//! batched paths need testing on Linux.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;

use bytes::Bytes;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use udt_proto::TransmitBuf;

/// Datagrams the platform can deliver from one receive call.
///
/// 32 where `recvmmsg` exists, 1 everywhere else. Taken from [`quinn_udp`]
/// rather than guessed: asking for 32 on a platform that fills one means
/// building 31 unused scatter-gather entries per call, which at several
/// hundred thousand packets a second is not free.
pub(crate) const RECV_BATCH: usize = quinn_udp::BATCH_SIZE;

/// Most bytes one segmented transmit may total.
///
/// The aggregate goes to the kernel as a single buffer, so it is bounded by
/// what a datagram can be regardless of how many segments the kernel will
/// split it into.
const MAX_GSO_BYTES: usize = 64 * 1024;

pub(crate) struct BatchIo {
    state: UdpSocketState,
    /// Segments the kernel will accept in one transmit; 1 means no offload.
    max_gso: usize,
}

impl BatchIo {
    pub(crate) fn new(sock: &UdpSocket) -> io::Result<Self> {
        let state = UdpSocketState::new(UdpSockRef::from(sock))?;
        let max_gso = state.max_gso_segments();
        Ok(BatchIo { state, max_gso })
    }

    /// Datagrams the kernel may coalesce into one receive buffer.
    pub(crate) fn gro_segments(&self) -> usize {
        self.state.gro_segments()
    }

    /// Write everything the protocol has queued for `peer`.
    ///
    /// The protocol lays its datagrams out back to back in `tx`, so a run of
    /// equal-sized ones is already contiguous and goes to the kernel as one
    /// segmented write with no copy at all. That is the whole reason the
    /// protocol writes into a caller-owned buffer: previously each packet was
    /// its own allocation and then had to be copied into a scratch buffer to be
    /// coalesced again.
    pub(crate) async fn send_all(
        &mut self,
        sock: &UdpSocket,
        peer: SocketAddr,
        tx: &TransmitBuf,
    ) -> io::Result<()> {
        if self.max_gso <= 1 {
            // No offload, so runs mean nothing: one datagram per call.
            for datagram in tx.datagrams() {
                self.send_raw(sock, peer, datagram, None).await?;
            }
            return Ok(());
        }

        for (bytes, segment_size) in tx.runs() {
            // A run longer than the kernel will segment in one go has to be
            // split, but the pieces are still slices of the same buffer.
            //
            // Two limits apply: how many segments the kernel will split, and
            // the 64 KiB an aggregate may total, since it travels as one
            // buffer. Whichever binds first is rounded down to a whole number
            // of segments, or the tail of a transmit would be a partial packet.
            let by_count = segment_size * self.max_gso;
            let by_bytes = (MAX_GSO_BYTES / segment_size.max(1)) * segment_size;
            let per_transmit = by_count.min(by_bytes).max(segment_size);
            let mut offset = 0;
            while offset < bytes.len() {
                let end = (offset + per_transmit).min(bytes.len());
                let chunk = &bytes[offset..end];
                let segmented = chunk.len() > segment_size;
                self.send_raw(sock, peer, chunk, segmented.then_some(segment_size)).await?;
                offset = end;
            }
        }
        Ok(())
    }

    async fn send_raw(
        &self,
        sock: &UdpSocket,
        peer: SocketAddr,
        data: &[u8],
        segment_size: Option<usize>,
    ) -> io::Result<()> {
        let transmit =
            Transmit { destination: peer, ecn: None, contents: data, segment_size, src_ip: None };
        sock.async_io(Interest::WRITABLE, || self.state.send(UdpSockRef::from(sock), &transmit))
            .await
    }

    /// Receive up to `storage.len()` datagrams in one call.
    ///
    /// Takes the backing buffers rather than `IoSliceMut`s so the caller is not
    /// left holding a borrow of them across the await, which would make the
    /// received data unreadable in the same scope.
    pub(crate) async fn recv_batch(
        &self,
        sock: &UdpSocket,
        storage: &mut [Vec<u8>],
        metas: &mut [RecvMeta],
    ) -> io::Result<usize> {
        // The single-buffer case is the whole of macOS and Windows, and it is
        // the one that runs per datagram rather than per batch — keep the
        // scatter-gather list on the stack so the hot path never allocates.
        if let [buf] = storage {
            let mut bufs = [IoSliceMut::new(buf.as_mut_slice())];
            return sock
                .async_io(Interest::READABLE, || {
                    self.state.recv(UdpSockRef::from(sock), &mut bufs, metas)
                })
                .await;
        }
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b.as_mut_slice())).collect();
        sock.async_io(Interest::READABLE, || {
            self.state.recv(UdpSockRef::from(sock), &mut bufs, metas)
        })
        .await
    }
}

impl BatchIo {
    /// Non-blocking variant of [`recv_batch`](Self::recv_batch).
    ///
    /// On platforms without `recvmmsg` (macOS, Windows) a batch call returns a
    /// single datagram, so callers loop on this to drain the socket rather than
    /// paying a wakeup per packet. Returns `WouldBlock` once it is empty.
    pub(crate) fn try_recv_batch(
        &self,
        sock: &UdpSocket,
        storage: &mut [Vec<u8>],
        metas: &mut [RecvMeta],
    ) -> io::Result<usize> {
        if let [buf] = storage {
            let mut bufs = [IoSliceMut::new(buf.as_mut_slice())];
            return self.state.recv(UdpSockRef::from(sock), &mut bufs, metas);
        }
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b.as_mut_slice())).collect();
        self.state.recv(UdpSockRef::from(sock), &mut bufs, metas)
    }
}

/// Receive storage sized for this socket's offload settings.
///
/// Each buffer must hold a full generic-receive-offload run rather than a
/// single datagram. Undersizing truncates the run and silently discards every
/// datagram after the first.
///
/// The buffers are reused across receives and the datagrams are copied out of
/// them. Handing them out from a pool and slicing them in place instead --
/// avoiding the copy -- was tried and measured 25% *slower*: a buffer holds a
/// whole offload run, so an empty pool costs a 128 KB zeroed allocation where
/// the copy allocates only the bytes that actually arrived, and the owner
/// vtable `Bytes::from_owner` needs makes every slice clone and drop more
/// expensive than a plain shared buffer.
pub(crate) struct RecvBuffers {
    pub(crate) storage: Vec<Vec<u8>>,
    pub(crate) metas: Vec<RecvMeta>,
}

impl RecvBuffers {
    pub(crate) fn new(io: &BatchIo) -> Self {
        let per_datagram = 2048;
        let size = per_datagram * io.gro_segments().max(1);
        RecvBuffers {
            storage: (0..RECV_BATCH).map(|_| vec![0u8; size]).collect(),
            metas: vec![RecvMeta::default(); RECV_BATCH],
        }
    }

    /// The datagrams the kernel put in buffer `index`.
    ///
    /// The run is copied once and the datagrams are slices sharing it, so the
    /// copy is per run rather than per packet -- up to 64 of them share one.
    pub(crate) fn take_datagrams(&mut self, index: usize) -> impl Iterator<Item = Bytes> + use<> {
        let meta = self.metas[index];
        let buf = &self.storage[index];
        let len = meta.len.min(buf.len());
        let run = Bytes::copy_from_slice(&buf[..len]);
        split_run(run, meta.stride)
    }
}

/// Split a received buffer into the datagrams the kernel coalesced into it.
///
/// With generic receive offload one buffer holds a run of datagrams described
/// by `stride`; without it there is exactly one. Either way the datagrams are
/// slices sharing the run, so this costs nothing per packet.
fn split_run(run: Bytes, stride: usize) -> impl Iterator<Item = Bytes> + use<> {
    let len = run.len();
    let stride = if stride == 0 { len.max(1) } else { stride };
    (0..len).step_by(stride.max(1)).map(move |off| run.slice(off..(off + stride).min(len)))
}
