//! The IO tasks behind a connection.
//!
//! A connection always has a driver task, which writes queued datagrams and
//! runs the protocol timer. Where the datagrams come *from* depends on how the
//! connection was made:
//!
//! * [`Endpoint::connect`] gives each connection its own kernel socket, so its
//!   driver reads that socket itself.
//! * Accepted and rendezvous connections share the endpoint's bound port, so
//!   the endpoint's reader reads on their behalf and leaves datagrams in the
//!   connection's inbox. The driver picks them up from there, which keeps the
//!   protocol work for each connection on its own task. See
//!   [`crate::endpoint`].
//!
//! [`Endpoint::connect`]: crate::Endpoint::connect

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;
use udt_proto::DisconnectReason;

use crate::batch::{self, BatchIo};
use crate::conn::{ConnectionInner, State};
use crate::util::{lock, now_us};

/// Datagrams drained from a socket per wakeup before returning to the event
/// loop, across however many batch calls that takes.
///
/// Draining in bulk amortises the timer arm and disarm of the `select!` over
/// many packets rather than paying it per packet. The cap bounds two things:
/// how long one busy connection can starve the send path, and how long the
/// connection lock is held while the batch is fed to the state machine — a
/// sender blocking on that lock occupies a runtime thread, so the batch has to
/// stay small enough to be quick.
///
/// Count datagrams rather than receive calls. With receive offload a single
/// buffer can hold 64 of them, so counting calls would let this run to
/// thousands of packets on Linux while staying at 64 on macOS.
const RECV_DRAIN_CAP: usize = 64;

/// How long the driver parks when the state machine wants no timer at all.
const IDLE_TICK: std::time::Duration = std::time::Duration::from_secs(30);

/// What a driver learned from its last look at the connection.
struct Pass {
    finished: bool,
    deadline: tokio::time::Instant,
}

/// Collect the queued datagrams and the next deadline in one critical section.
///
/// Every driver path ends by calling this while it still holds the lock, so a
/// pass costs one acquisition rather than one per thing the driver wants. The
/// application contends for this lock on every send and every receive, and at
/// several hundred thousand packets a second the difference is measurable.
fn finish_pass(state: &mut State, scratch: &mut Vec<Bytes>) -> Pass {
    std::mem::swap(&mut state.out, scratch);
    Pass { finished: state.error.is_some(), deadline: deadline(state) }
}

/// Take a pass without any other work to do, acquiring the lock for it.
fn take_pass(inner: &ConnectionInner, scratch: &mut Vec<Bytes>) -> Pass {
    finish_pass(&mut lock(&inner.state), scratch)
}

/// Write a batch of datagrams to `peer`, returning whether the socket failed.
async fn write_out(
    io: &mut BatchIo,
    socket: &UdpSocket,
    peer: SocketAddr,
    scratch: &mut Vec<Bytes>,
) -> bool {
    if scratch.is_empty() {
        return false;
    }
    let failed = io.send_all(socket, peer, scratch).await.is_err();
    scratch.clear();
    failed
}

/// Deadline for the next timer call, as a tokio instant.
fn deadline(state: &State) -> tokio::time::Instant {
    let now_tokio = tokio::time::Instant::now();
    match state.conn.next_deadline_us() {
        None => now_tokio + IDLE_TICK,
        Some(deadline_us) => {
            let now = now_us();
            if deadline_us <= now {
                now_tokio
            } else {
                now_tokio + std::time::Duration::from_micros(deadline_us - now)
            }
        }
    }
}

/// Drive a connection whose datagrams arrive from somewhere else.
///
/// Used for accepted and rendezvous connections, where the endpoint's reader
/// tasks feed the state machine. This task only writes and keeps time.
pub(crate) async fn run_shared(
    inner: Arc<ConnectionInner>,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    on_exit: impl FnOnce(),
) {
    let Ok(mut io) = BatchIo::new(&socket) else {
        crate::conn::fail(&inner, DisconnectReason::PeerError);
        on_exit();
        return;
    };
    let mut scratch = Vec::new();
    kick(&inner);

    loop {
        // Registered before any state is examined, so a datagram or a send
        // arriving in between still wakes this task rather than leaving it to
        // wait for the timer.
        let notified = inner.shared.driver.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let (pass, had_input) = {
            let mut guard = lock(&inner.state);
            let state = &mut *guard;
            // Whatever the endpoint reader left for us, then whatever that
            // produced, then the datagrams to write — all under one lock.
            let had_input = state.drain_inbox();
            if had_input {
                state.absorb(&inner.shared);
            }
            (finish_pass(state, &mut scratch), had_input)
        };
        if had_input {
            // Acknowledgements may have freed send-buffer space.
            inner.shared.wake_writers();
        }

        if write_out(&mut io, &socket, peer, &mut scratch).await || pass.finished {
            break;
        }

        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep_until(pass.deadline) => {
                let mut guard = lock(&inner.state);
                let state = &mut *guard;
                state.on_timer(now_us());
                state.absorb(&inner.shared);
                debug_tick(state, "shared");
            }
        }
    }

    on_exit();
}

/// Drive a connection that owns its socket, reading it as well as writing it.
pub(crate) async fn run_owned(
    inner: Arc<ConnectionInner>,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
) {
    let Ok(mut io) = BatchIo::new(&socket) else {
        crate::conn::fail(&inner, DisconnectReason::PeerError);
        return;
    };
    let (mut storage, mut metas) = batch::recv_buffers(&io);
    let mut scratch = Vec::new();
    let mut inbound: Vec<Bytes> = Vec::new();
    kick(&inner);
    let mut pass = take_pass(&inner, &mut scratch);

    loop {
        let notified = inner.shared.driver.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if write_out(&mut io, &socket, peer, &mut scratch).await || pass.finished {
            break;
        }

        tokio::select! {
            result = io.recv_batch(&socket, &mut storage, &mut metas) => {
                let Ok(mut count) = result else { break };
                // One call may return several datagrams via recvmmsg, and each
                // buffer may hold several more coalesced by receive offload.
                // Where the platform has neither, this loop keeps one wakeup
                // from costing one packet.
                //
                // Everything is collected before the lock is taken: feeding
                // them one at a time would be a lock acquisition and a round of
                // wakeups per packet, which costs more than the syscall does.
                loop {
                    for i in 0..count {
                        if metas[i].addr != peer {
                            continue;
                        }
                        inbound.extend(batch::split_run(&storage[i], &metas[i]));
                    }
                    if inbound.len() >= RECV_DRAIN_CAP {
                        break;
                    }
                    match io.try_recv_batch(&socket, &mut storage, &mut metas) {
                        Ok(n) if n > 0 => count = n,
                        _ => break,
                    }
                }
                {
                    let mut guard = lock(&inner.state);
                    let state = &mut *guard;
                    state.feed(inbound.drain(..));
                    state.absorb(&inner.shared);
                    pass = finish_pass(state, &mut scratch);
                }
                // Acknowledgements may have freed send-buffer space.
                inner.shared.wake_writers();
            }
            _ = notified => {
                pass = take_pass(&inner, &mut scratch);
            }
            _ = tokio::time::sleep_until(pass.deadline) => {
                let mut guard = lock(&inner.state);
                let state = &mut *guard;
                state.on_timer(now_us());
                state.absorb(&inner.shared);
                debug_tick(state, "owned");
                pass = finish_pass(state, &mut scratch);
            }
        }
    }
}

/// Run the timer once so the opening handshake goes out immediately.
fn kick(inner: &ConnectionInner) {
    let mut guard = lock(&inner.state);
    let state = &mut *guard;
    state.on_timer(now_us());
    state.absorb(&inner.shared);
}

/// Periodic state dump, enabled by setting `UDT_DEBUG=1`. Compiled in but
/// inert unless the variable is set.
fn debug_tick(state: &State, tag: &str) {
    if std::env::var_os("UDT_DEBUG").is_none() {
        return;
    }
    let stats = state.conn.stats();
    // Only report connections with outstanding work, or idle sockets drown out
    // the one that is actually stuck.
    let has_work = stats.snd_in_flight > 0
        || stats.snd_pending > 0
        || stats.snd_loss_len > 0
        || stats.rcv_loss_len > 0
        || !stats.connected;
    if has_work {
        eprintln!("[{tag}] {stats:?}");
    }
}
