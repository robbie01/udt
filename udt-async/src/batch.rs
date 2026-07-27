//! Batched UDP send/receive.
//!
//! The profile of a saturated single connection is roughly 95% `sendto` and
//! `recvfrom`, with `sendto` outnumbering `recvfrom` about two to one — the
//! receive path already drains everything queued per wakeup, while a plain UDP
//! send is one datagram per system call. This module closes that asymmetry
//! where the platform allows it.
//!
//! Two mechanisms, both from [`quinn_udp`], both behind a safe API so this
//! crate keeps `forbid(unsafe_code)`:
//!
//! * **Segmentation offload (GSO)** on send. A run of equal-sized datagrams to
//!   the same peer is handed to the kernel as one buffer plus a segment size,
//!   and split into individual packets below the syscall boundary. UDT data
//!   packets are all exactly one payload except the tail of each message, so
//!   runs are long — a full message is one transmit.
//! * **`recvmmsg`** on receive, filling several buffers per call.
//!
//! Where neither exists — macOS, OpenBSD — `max_gso_segments()` reports 1 and
//! the code below degrades to exactly the per-datagram behaviour it replaces.
//! That fallback is the path exercised by this repository's own test suite;
//! **the batched paths are compiled but not covered by any test run on macOS.**

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;

use bytes::Bytes;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Datagrams received in one batch.
pub(crate) const RECV_BATCH: usize = 32;

/// Upper bound on the scratch buffer used to coalesce a GSO run.
const MAX_COALESCE_BYTES: usize = 64 * 1024;

pub(crate) struct BatchIo {
    state: UdpSocketState,
    /// Segments the kernel will accept in one transmit; 1 means no offload.
    max_gso: usize,
    /// Coalescing buffer for a GSO run. Reused across sends.
    scratch: Vec<u8>,
}

impl BatchIo {
    pub(crate) fn new(sock: &UdpSocket) -> io::Result<Self> {
        let state = UdpSocketState::new(UdpSockRef::from(sock))?;
        let max_gso = state.max_gso_segments();
        Ok(BatchIo { state, max_gso, scratch: Vec::new() })
    }

    /// Datagrams the kernel may coalesce into one receive buffer.
    pub(crate) fn gro_segments(&self) -> usize {
        self.state.gro_segments()
    }

    /// Send every datagram in `out`, coalescing runs where possible.
    ///
    /// Coalescing is only worthwhile when the kernel will actually split the
    /// buffer for us; otherwise the copy into `scratch` would be pure overhead
    /// on top of the same number of syscalls.
    pub(crate) async fn send_all(
        &mut self,
        sock: &UdpSocket,
        peer: SocketAddr,
        out: &[Bytes],
    ) -> io::Result<()> {
        if self.max_gso <= 1 {
            for d in out {
                self.send_one(sock, peer, d, None).await?;
            }
            return Ok(());
        }

        let mut i = 0;
        while i < out.len() {
            let (run, seg) = self.plan_run(&out[i..]);
            if run == 1 {
                self.send_one(sock, peer, &out[i], None).await?;
            } else {
                self.scratch.clear();
                for d in &out[i..i + run] {
                    self.scratch.extend_from_slice(d);
                }
                // `scratch` is borrowed by the transmit, so the send cannot go
                // through `send_one`'s &mut self.
                let contents = std::mem::take(&mut self.scratch);
                let res = Self::send_raw(&self.state, sock, peer, &contents, Some(seg)).await;
                self.scratch = contents;
                res?;
            }
            i += run;
        }
        Ok(())
    }

    /// How many leading datagrams of `out` can go in one segmented transmit,
    /// and the segment size to use.
    ///
    /// GSO requires every segment to be the segment size except the last, which
    /// may be shorter — exactly the shape of a UDT message, whose packets are
    /// all one full payload but for the tail.
    fn plan_run(&self, out: &[Bytes]) -> (usize, usize) {
        let seg = out[0].len();
        if seg == 0 {
            return (1, seg);
        }
        let mut n = 1;
        let mut bytes = seg;
        while n < out.len()
            && n < self.max_gso
            && out[n].len() == seg
            && bytes + seg <= MAX_COALESCE_BYTES
        {
            bytes += seg;
            n += 1;
        }
        // A single shorter datagram may ride along as the final segment.
        if n < out.len()
            && n < self.max_gso
            && out[n].len() < seg
            && !out[n].is_empty()
            && bytes + out[n].len() <= MAX_COALESCE_BYTES
        {
            n += 1;
        }
        (n, seg)
    }

    async fn send_one(
        &mut self,
        sock: &UdpSocket,
        peer: SocketAddr,
        data: &[u8],
        segment_size: Option<usize>,
    ) -> io::Result<()> {
        Self::send_raw(&self.state, sock, peer, data, segment_size).await
    }

    async fn send_raw(
        state: &UdpSocketState,
        sock: &UdpSocket,
        peer: SocketAddr,
        data: &[u8],
        segment_size: Option<usize>,
    ) -> io::Result<()> {
        let transmit = Transmit {
            destination: peer,
            ecn: None,
            contents: data,
            segment_size,
            src_ip: None,
        };
        sock.async_io(Interest::WRITABLE, || state.send(UdpSockRef::from(sock), &transmit))
            .await
    }

    /// Receive up to `storage.len()` datagrams in one call.
    ///
    /// Takes the backing buffers rather than `IoSliceMut`s so the caller is not
    /// left holding a borrow of them across the await, which would make the
    /// received data unreadable in the same scope. The slice vector is rebuilt
    /// per call — one small allocation amortised over a whole batch, against a
    /// system call.
    pub(crate) async fn recv_batch(
        &self,
        sock: &UdpSocket,
        storage: &mut [Vec<u8>],
        metas: &mut [RecvMeta],
    ) -> io::Result<usize> {
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
    /// Where the platform has no `recvmmsg` — macOS, Windows — a batch call
    /// returns a single datagram, so draining with this in a loop is what keeps
    /// one wakeup from costing one packet. Returns `WouldBlock` when the socket
    /// is empty.
    pub(crate) fn try_recv_batch(
        &self,
        sock: &UdpSocket,
        storage: &mut [Vec<u8>],
        metas: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b.as_mut_slice())).collect();
        self.state.recv(UdpSockRef::from(sock), &mut bufs, metas)
    }
}

/// Allocate receive storage sized for this socket's offload settings.
///
/// Each buffer must hold a full generic-receive-offload run, not a single
/// datagram: undersizing it truncates the run and silently discards every
/// datagram after the first.
pub(crate) fn recv_buffers(io: &BatchIo) -> (Vec<Vec<u8>>, Vec<RecvMeta>) {
    let per_datagram = 2048;
    let cap = per_datagram * io.gro_segments().max(1);
    (
        (0..RECV_BATCH).map(|_| vec![0u8; cap]).collect(),
        vec![RecvMeta::default(); RECV_BATCH],
    )
}

/// Split one received buffer into its constituent datagrams.
///
/// With generic receive offload the kernel hands back a *run* of datagrams
/// coalesced into one buffer, described by `meta.stride`. The run is copied
/// once and the datagrams are zero-copy slices sharing that allocation —
/// copying each datagram separately costs an allocation and a memcpy per
/// packet where one per run will do, and up to 64 packets can share a run.
pub(crate) fn split_run(buf: &[u8], meta: &RecvMeta) -> impl Iterator<Item = Bytes> {
    let len = meta.len.min(buf.len());
    let stride = if meta.stride == 0 { len.max(1) } else { meta.stride };
    let run = Bytes::copy_from_slice(&buf[..len]);
    (0..len)
        .step_by(stride.max(1))
        .map(move |off| run.slice(off..(off + stride).min(len)))
}
