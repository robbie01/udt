//! The per-connection UDT state machine.

use std::cmp::Ordering;
use std::collections::VecDeque;

use crate::ack_window::AckWindow;
use crate::codec;
use crate::congestion::{CcContext, CcKind, CcOutput, CongestionControl};
use crate::handshake::{Handshake, SOCK_DGRAM, UDT_VERSION, req_type};
use crate::loss_list::{RcvLossList, SndLossList};
use crate::packet::{AckFull, ControlBody, Packet};
use crate::recv_buffer::{AddResult, RecvBuffer};
use crate::send_buffer::SendBuffer;
use crate::seq::{AckSeqNo, SEQ_MAX, SeqNo};
use crate::time_window::PktTimeWindow;
use bytes::{Bytes, BytesMut};

/// Size of the fixed UDT packet header (4 × u32) that precedes every payload.
pub const UDT_HEADER_SIZE: usize = 16;

// Overhead subtracted from the wire MSS to get the payload size.
//
// The C++ UDT reference implementation uses a fixed value of 48 for both IPv4
// and IPv6 (matching the larger IPv6 header size: 40 IP + 8 UDP = 48). We use
// the same constant to stay wire-compatible.  Users working with jumbo-frame or
// IPv4-only links may achieve slightly larger payloads with a custom MSS, but
// the default is tuned for broad compatibility.
const IP_AND_UDP_OVERHEAD: u32 = 48; // 40 (IPv6) + 8 (UDP) — used by C++ for all families

// Default MSS advertised in the UDT handshake.
//
// This follows the C++ convention: MSS = IP-layer MTU (i.e., the Ethernet
// payload including IP + UDP + UDT headers + data).  Standard Ethernet frames
// carry up to 1500-byte IP payloads.  The resulting per-packet data payload is:
//   1500 − IP_AND_UDP_OVERHEAD(48) − UDT_HEADER_SIZE(16) = 1436 bytes.
const DEFAULT_MSS: u32 = 1500;
const DEFAULT_FLIGHT_FLAG_SIZE: u32 = 25600;

/// Largest flow window a peer may advertise, in packets.
///
/// The handshake field is a peer-supplied `i32` and used to be trusted. It
/// bounds nothing on our side except how much we are willing to have in
/// flight, so clamping it costs nothing: no real receiver advertises a window
/// of millions of packets, and the value cannot make us send faster than
/// congestion control allows anyway.
const MAX_FLOW_WND: u32 = 1 << 20;

/// Smallest MTU a peer may negotiate.
///
/// Below this the payload left after headers is too small to make progress,
/// and a peer claiming an MTU of zero would leave `payload_size` at zero.
const MIN_MSS: u32 = IP_AND_UDP_OVERHEAD + UDT_HEADER_SIZE as u32 + 64;
/// Ranges reserved in each loss list up front. They grow past this as needed;
/// it is a starting size, not a limit.
const LOSS_LIST_RESERVE: usize = 128;

const DEFAULT_SND_BUF: usize = 8192;
const DEFAULT_RCV_BUF: usize = 8192;
const SYN_US: u32 = 10_000;
const LIGHT_ACK_INTERVAL: u32 = 64;
const EXP_MAX: u32 = 16;
/// Per-count minimum EXP interval (µs).  Mirrors C++ `m_ullMinExpInt = 300 000 µs`.
const MIN_EXP_PER_COUNT_US: u64 = 300_000;
/// After EXP_MAX expirations the connection is only torn down once it has been
/// silent for this long in total (matches C++ `5 000 000 µs` guard).
const EXP_HARD_TIMEOUT_US: u64 = 5_000_000;
/// Handshake retransmit backoff, in µs, then `HS_RESEND_US` thereafter.
///
/// A flat 250 ms — which is what the C++ reference uses — costs a full quarter
/// second every time an opening packet is dropped. That is routine rather than
/// exceptional on a path where a stateful firewall must see outbound traffic
/// before it will pass inbound: over IPv6 there is no NAT to punch, but the
/// filter still has to open, so the first packets in *both* directions are
/// dropped and a rendezvous needs several exchanges before anything gets
/// through. Front-loading the retries opens the pinhole in tens of
/// milliseconds instead of hundreds.
///
/// It costs nothing on a clean path: the handshake completes long before the
/// later attempts would fire.
const HS_BACKOFF_US: [u64; 4] = [25_000, 50_000, 100_000, 175_000];
/// Steady-state handshake retransmit interval once the backoff is exhausted.
const HS_RESEND_US: u64 = 250_000;

/// Interval before handshake attempt number `attempts`.
fn hs_interval_us(attempts: u32) -> u64 {
    HS_BACKOFF_US.get(attempts as usize).copied().unwrap_or(HS_RESEND_US)
}

/// How a connection was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnMode {
    /// One side dialled a listener.
    Active,
    /// Both sides dialled each other simultaneously.
    Rendezvous,
}

#[derive(Debug, Clone)]
enum ConnState {
    Connecting {
        mode: ConnMode,
        conn_req: Handshake,
        last_req_us: u64,
        /// Handshake retransmissions sent since the last state change; indexes
        /// [`HS_BACKOFF_US`]. Reset whenever the request type advances, so each
        /// leg of a rendezvous gets the same fast opening retries.
        attempts: u32,
        deadline_us: u64,
        last_peer_hs: Option<Handshake>,
    },
    Connected,
    Closed,
}

/// Something the caller must act on, produced by [`Connection::on_datagram`]
/// and [`Connection::on_timer`].
pub enum Event {
    /// Write these bytes to the peer as a single UDP datagram.
    ///
    /// Dropping one costs a retransmission but is not fatal; UDT assumes the
    /// network may lose packets anyway.
    SendDatagram(Bytes),
    /// At least one message can now be taken with [`Connection::recv_msg`].
    DataReady,
    /// The handshake finished. Data can be sent from here on.
    Connected,
    /// The connection is over and will emit nothing further.
    Disconnected(DisconnectReason),
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The peer closed cleanly.
    Shutdown,
    /// The peer stopped responding.
    Timeout,
    /// The peer sent something unusable, or rejected the handshake.
    PeerError,
    /// This side called [`Connection::shutdown`].
    LocalClose,
}

/// Result of offering a message to [`Connection::send_msg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The message was queued in full.
    Queued,
    /// The send buffer is full; retry the same payload once space frees up.
    WouldBlock,
    /// The message can never be queued — it exceeds the send buffer's total
    /// capacity, or the connection is no longer open.
    Rejected,
}

/// A point-in-time view of a connection's flow and congestion state.
///
/// Intended for logging, metrics and debugging. The exact set of fields is
/// not stable.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionStats {
    /// This side's socket identifier.
    pub socket_id: u32,
    /// Whether the handshake has completed.
    pub connected: bool,
    /// Highest sequence number the peer has acknowledged.
    pub snd_last_ack: u32,
    /// Highest sequence number sent.
    pub snd_curr_seq: u32,
    /// Packets sent and not yet acknowledged.
    pub snd_in_flight: usize,
    /// Packets queued but not yet sent.
    pub snd_pending: usize,
    /// Packets known lost and awaiting retransmission.
    pub snd_loss_len: usize,
    /// Highest sequence number acknowledged to the peer.
    pub rcv_last_ack: u32,
    /// Highest acknowledgement the peer has confirmed receiving.
    pub rcv_last_ack_ack: u32,
    /// Highest sequence number received.
    pub rcv_curr_seq: u32,
    /// Packets detected missing and awaiting retransmission from the peer.
    pub rcv_loss_len: usize,
    /// Complete messages waiting to be read.
    pub ready_msgs: usize,
    /// Congestion window, in packets.
    pub cwnd: f64,
    /// Flow-control window advertised by the peer, in packets.
    pub flow_wnd: u32,
    /// Rate at which the peer reports receiving data, in packets per second.
    pub delivery_rate_pps: u32,
    /// Estimated path capacity, in packets per second.
    pub bandwidth_pps: u32,
    /// Current pacing interval between sends, in microseconds.
    pub snd_period_us: f64,
    /// Smoothed round-trip time, in microseconds.
    pub rtt_us: i32,
    /// Consecutive expiry-timer firings without a response from the peer;
    /// the connection gives up at 16.
    pub exp_count: u32,
}

/// IO-free per-socket UDT connection state machine.
pub struct Connection {
    socket_id: u32,
    peer_id: u32,
    local_isn: SeqNo,

    mss: u32,
    payload_size: u32,
    flow_wnd: u32,

    state: ConnState,

    snd_buf: Option<SendBuffer>,
    snd_loss: SndLossList,
    snd_last_ack: SeqNo,
    snd_curr_seq: SeqNo,
    /// When true, the application has finished sending (send channel closed). We
    /// send a Shutdown once the send buffer drains (all data acknowledged).
    snd_half_closed: bool,

    rcv_buf: Option<RecvBuffer>,
    rcv_loss: RcvLossList,
    ack_win: AckWindow,
    rcv_last_ack: SeqNo,
    /// Highest ACK point the peer has confirmed back to us via ACK2.
    /// Mirrors C++ `m_iRcvLastAckAck`; used to suppress redundant ACKs.
    rcv_last_ack_ack: SeqNo,
    ack_seq: AckSeqNo,
    rcv_curr_seq: SeqNo,
    pkt_count: u32,
    /// Number of light ACKs emitted since the last full ACK (C++ `m_iLightACKCount`).
    light_ack_count: u32,

    // Staging queue for messages extracted from recv_buffer
    ready_msgs: VecDeque<Bytes>,

    next_ack_us: u64,
    next_nak_us: u64,
    next_snd_us: u64,
    last_rsp_us: u64,
    /// When the last full ACK was emitted, for re-ACK rate limiting.
    last_ack_us: u64,
    exp_count: u32,

    /// Last ACK sub-sequence we returned an ACK2 for, and when.
    /// ACK2s are rate limited to roughly one per SYN interval (C++
    /// `m_iSndLastAck2` / `m_ullSndLastAck2Time`).
    snd_last_ack2: AckSeqNo,
    snd_last_ack2_us: u64,

    /// Smoothed peer-reported delivery rate and link bandwidth, in packets/s.
    /// C++ keeps a 7/8 EWMA of these (`m_iDeliveryRate` / `m_iBandwidth`) and
    /// feeds the smoothed values to congestion control — using the raw
    /// per-ACK samples makes the rate estimate wildly noisy.
    delivery_rate_pps: u32,
    bandwidth_pps: u32,

    rtt_us: i32,
    rtt_var_us: i32,

    cc: Box<dyn CongestionControl>,
    snd_period_us: f64,
    cwnd: f64,
    /// CC-supplied overrides, applied by `apply_cc`. `None` means "use the
    /// protocol default" for each.
    cc_ack_period_us: Option<u64>,
    cc_ack_interval_pkts: Option<u32>,
    cc_rto_us: Option<u64>,

    rcv_tw: PktTimeWindow,
    snd_tw: PktTimeWindow,

    enc: BytesMut, // pre-allocated encode buffer

    /// Arena that outbound data packets are carved out of.
    ///
    /// Each packet is header + payload written into this buffer and split off
    /// as a `Bytes` sharing the same allocation, so assembly costs roughly one
    /// allocation per arena refill instead of one per packet.  The slices are
    /// handed straight to the driver and dropped after the send, so the arena
    /// does not stay pinned.
    pkt_arena: BytesMut,
}

/// Bytes reserved per packet-assembly arena refill (~64 full-size packets).
const PKT_ARENA_SIZE: usize = 96 * 1024;

impl Connection {
    /// Starts a connection to a peer that is listening.
    ///
    /// `socket_id` identifies this side and must be unique among the
    /// connections sharing a local address. `local_isn` is the initial
    /// sequence number, which should be random. `mss` is the path MTU in
    /// bytes; both sides negotiate down to the smaller value.
    ///
    /// Nothing is sent until the first [`on_timer`](Self::on_timer) call.
    pub fn new_active(socket_id: u32, local_isn: SeqNo, mss: u32, now_us: u64, cc: CcKind) -> Self {
        let req = Handshake {
            version: UDT_VERSION,
            sock_type: SOCK_DGRAM,
            isn: local_isn.raw() as i32,
            mss: mss as i32,
            flight_flag_size: DEFAULT_FLIGHT_FLAG_SIZE as i32,
            req_type: req_type::CONNECT,
            socket_id: socket_id as i32,
            cookie: 0,
            peer_ip: [0u32; 4],
        };
        let mut c = Self::skeleton(socket_id, mss, now_us);
        c.cc = cc.build();
        c.local_isn = local_isn;
        c.state = ConnState::Connecting {
            mode: ConnMode::Active,
            conn_req: req,
            last_req_us: 0,
            attempts: 0,
            deadline_us: now_us + 30_000_000,
            last_peer_hs: None,
        };
        c
    }

    /// Starts a connection to a peer that is calling this at the same time.
    ///
    /// Arguments are as [`new_active`](Self::new_active). Because neither side
    /// is listening, both must dial roughly simultaneously.
    pub fn new_rendezvous(
        socket_id: u32,
        local_isn: SeqNo,
        mss: u32,
        now_us: u64,
        cc: CcKind,
    ) -> Self {
        let req = Handshake {
            version: UDT_VERSION,
            sock_type: SOCK_DGRAM,
            isn: local_isn.raw() as i32,
            mss: mss as i32,
            flight_flag_size: DEFAULT_FLIGHT_FLAG_SIZE as i32,
            req_type: req_type::RENDEZVOUS,
            socket_id: socket_id as i32,
            cookie: 0,
            peer_ip: [0u32; 4],
        };
        let mut c = Self::skeleton(socket_id, mss, now_us);
        c.cc = cc.build();
        c.local_isn = local_isn;
        c.state = ConnState::Connecting {
            mode: ConnMode::Rendezvous,
            conn_req: req,
            last_req_us: 0,
            attempts: 0,
            deadline_us: now_us + 30_000_000,
            last_peer_hs: None,
        };
        c
    }

    /// Already-connected socket (listener path after successful handshake).
    #[allow(clippy::too_many_arguments)]
    pub fn new_connected(
        socket_id: u32,
        peer_id: u32,
        local_isn: SeqNo,
        peer_isn: SeqNo,
        mss: u32,
        flow_wnd: u32,
        now_us: u64,
        cc: Box<dyn CongestionControl>,
    ) -> Self {
        let mut c = Self::skeleton(socket_id, mss, now_us);
        c.local_isn = local_isn;
        c.peer_id = peer_id;
        c.cc = cc;
        c.state = ConnState::Connected;
        c.post_connect(peer_isn, mss, flow_wnd, now_us);
        c
    }

    fn skeleton(socket_id: u32, mss: u32, now_us: u64) -> Self {
        // mss is the IP-layer MTU (C++ wire convention).
        // payload_size = mss − IP/UDP overhead − UDT header (matches C++ formula).
        let payload_size = mss.saturating_sub(IP_AND_UDP_OVERHEAD + UDT_HEADER_SIZE as u32);
        Connection {
            socket_id,
            peer_id: 0,
            local_isn: SeqNo::new(0),
            mss,
            payload_size,
            flow_wnd: DEFAULT_FLIGHT_FLAG_SIZE,
            state: ConnState::Closed,
            snd_buf: None,
            snd_loss: SndLossList::new(DEFAULT_FLIGHT_FLAG_SIZE as usize * 2),
            snd_last_ack: SeqNo::new(0),
            snd_curr_seq: SeqNo::new(0),
            snd_half_closed: false,
            rcv_buf: None,
            rcv_loss: RcvLossList::new(DEFAULT_FLIGHT_FLAG_SIZE as usize),
            ack_win: AckWindow::new(),
            rcv_last_ack: SeqNo::new(0),
            rcv_last_ack_ack: SeqNo::new(0),
            ack_seq: AckSeqNo::new(0),
            rcv_curr_seq: SeqNo::new(0),
            pkt_count: 0,
            light_ack_count: 1,
            ready_msgs: VecDeque::new(),
            next_ack_us: now_us + SYN_US as u64,
            next_nak_us: now_us + SYN_US as u64 * 4,
            next_snd_us: now_us,
            last_rsp_us: now_us,
            last_ack_us: now_us,
            exp_count: 1,
            snd_last_ack2: AckSeqNo::new(0),
            snd_last_ack2_us: now_us,
            // C++ initialises the delivery-rate estimate to 16 pkt/s and the
            // bandwidth estimate to 1 pkt/s before any samples arrive.
            delivery_rate_pps: 16,
            bandwidth_pps: 1,
            rtt_us: 10_000,
            rtt_var_us: 0,
            cc: CcKind::default().build(),
            snd_period_us: 1.0,
            cwnd: 16.0,
            cc_ack_period_us: None,
            cc_ack_interval_pkts: None,
            cc_rto_us: None,
            rcv_tw: PktTimeWindow::new(),
            snd_tw: PktTimeWindow::new(),
            enc: BytesMut::with_capacity(DEFAULT_MSS as usize),
            pkt_arena: BytesMut::with_capacity(PKT_ARENA_SIZE),
        }
    }

    fn post_connect(&mut self, peer_isn: SeqNo, mss: u32, flow_wnd: u32, now_us: u64) {
        self.mss = mss;
        self.payload_size = mss.saturating_sub(IP_AND_UDP_OVERHEAD + UDT_HEADER_SIZE as u32);
        self.flow_wnd = flow_wnd;
        // Start one before ISN so the first pack_data increments to ISN.
        self.snd_curr_seq = self.local_isn.prev();
        // ...but the ACK point starts *at* ISN: it names the first unacknowledged
        // sequence number, which is also the block at send-buffer offset 0.
        // (C++: m_iSndLastAck = m_iISN, m_iSndCurrSeqNo = m_iISN - 1.)  Starting
        // it a slot early makes every ACK look one packet larger than it is, so
        // the send buffer frees a block that was never acknowledged and all
        // later retransmissions read the wrong payload.
        self.snd_last_ack = self.local_isn;
        self.rcv_last_ack = peer_isn;
        self.rcv_last_ack_ack = peer_isn;
        self.rcv_curr_seq = peer_isn.prev();
        self.snd_buf = Some(SendBuffer::new(DEFAULT_SND_BUF, self.payload_size as usize));
        self.rcv_buf = Some(RecvBuffer::new(DEFAULT_RCV_BUF, peer_isn));
        // Sized for the handful of ranges a loss list actually holds, not for
        // the flow window: these grow on demand, and reserving a window's worth
        // up front is what let a peer ask for a 64 GiB allocation.
        self.snd_loss = SndLossList::new(LOSS_LIST_RESERVE);
        self.rcv_loss = RcvLossList::new(LOSS_LIST_RESERVE);
        self.enc = BytesMut::with_capacity(mss as usize);
        let ctx = self.cc_ctx(now_us);
        let out = self.cc.init(ctx);
        self.apply_cc(out);
        self.last_rsp_us = now_us;
        self.last_ack_us = now_us;
        self.snd_last_ack2_us = now_us;
        self.next_ack_us = now_us + SYN_US as u64;
        self.next_nak_us = now_us + self.nak_int_us();
        self.next_snd_us = now_us;
    }

    // ── Entry points ──────────────────────────────────────────────────────

    /// Feeds one UDP payload received from the peer.
    ///
    /// Resulting work is appended to `out`; see [`Event`]. Reuse the same
    /// `Vec` across calls to avoid allocating. Datagrams that are malformed or
    /// addressed elsewhere are ignored.
    pub fn on_datagram(&mut self, datagram: Bytes, now_us: u64, out: &mut Vec<Event>) {
        let pkt = match codec::decode(datagram) {
            Some(p) => p,
            None => return,
        };
        // Check destination socket ID
        let ok = match &pkt {
            Packet::Data { header, .. } => header.dst_socket_id == self.socket_id,
            Packet::Control { header, .. } => {
                header.dst_socket_id == 0 || header.dst_socket_id == self.socket_id
            }
        };
        if !ok {
            return;
        }
        match pkt {
            Packet::Data { header, payload } => self.recv_data(header, payload, now_us, out),
            Packet::Control { header: _, body } => self.recv_ctrl(body, now_us, out),
        }
    }

    /// Advances time, appending any resulting work to `out`.
    ///
    /// Call this once at [`next_deadline_us`](Self::next_deadline_us), and
    /// again after every change to the connection, since sending or receiving
    /// can move that deadline. Calling it early is harmless.
    pub fn on_timer(&mut self, now_us: u64, out: &mut Vec<Event>) {
        match &self.state {
            ConnState::Closed => return,
            ConnState::Connecting { deadline_us, last_req_us, conn_req, attempts, .. } => {
                let deadline = *deadline_us;
                let last = *last_req_us;
                let gap = hs_interval_us(*attempts);
                let req = conn_req.clone();
                if now_us > deadline {
                    self.state = ConnState::Closed;
                    out.push(Event::Disconnected(DisconnectReason::Timeout));
                    return;
                }
                if now_us >= last + gap {
                    if let ConnState::Connecting { last_req_us, attempts, .. } = &mut self.state {
                        *last_req_us = now_us;
                        *attempts = attempts.saturating_add(1);
                    }
                    self.enc.clear();
                    codec::encode_handshake(&req, self.ts(now_us), 0, &mut self.enc);
                    out.push(Event::SendDatagram(self.enc.clone().freeze()));
                }
                return;
            }
            ConnState::Connected => {}
        }

        // Packet pacing — burst up to one SYN interval's worth of packets.
        // Using burst_end instead of now_us lets us batch all packets whose
        // scheduled send-time falls within the next SYN_US, compensating for
        // tokio's ~1 ms timer granularity on macOS/Linux.
        {
            self.next_snd_us = self.next_snd_us.min(now_us);
            let burst_end = now_us + SYN_US as u64;
            loop {
                if !self.pack_data(now_us, burst_end, out) {
                    // Nothing to send (cwnd full, no data, or not yet time).
                    // Back off to avoid a busy-wait spin on the next timer tick.
                    self.next_snd_us = now_us + SYN_US as u64;
                    break;
                }
            }
        }

        // Graceful half-close: shut down once the send buffer drains.
        if self.snd_half_closed && self.snd_buf_is_empty() {
            self.shutdown(now_us, out);
            return;
        }

        // ACK — full ACK on the SYN timer, cheap light ACKs in between when the
        // peer is sending fast enough to outrun it (C++ checkTimers).
        if now_us >= self.next_ack_us
            || self.cc_ack_interval_pkts.is_some_and(|n| self.pkt_count >= n)
        {
            self.emit_ack(now_us, false, out);
            self.next_ack_us = now_us + self.ack_int_us();
            self.pkt_count = 0;
            self.light_ack_count = 1;
        } else if self.pkt_count >= LIGHT_ACK_INTERVAL * self.light_ack_count {
            self.emit_ack(now_us, true, out);
            self.light_ack_count += 1;
        }

        // NAK
        if now_us >= self.next_nak_us && !self.rcv_loss.is_empty() {
            self.emit_nak(now_us, out);
            self.next_nak_us = now_us + self.nak_int_us();
        }

        // EXP — mirrors C++ checkTimers() logic; see `exp_int_us` for the
        // interval formula.
        //
        // After firing, `last_rsp_us` is reset to now so the timer does NOT
        // immediately re-fire (the C++ does the same: `m_ullLastRspTime = currtime`).
        //
        // Disconnect only when BOTH:
        //   • exp_count > EXP_MAX (16 expirations), AND
        //   • silence since last fire > EXP_HARD_TIMEOUT_US (5 s)
        if now_us >= self.last_rsp_us + self.exp_int_us() {
            // Hard timeout: peer has been silent for too long.
            if self.exp_count > EXP_MAX
                && now_us.saturating_sub(self.last_rsp_us) > EXP_HARD_TIMEOUT_US
            {
                self.state = ConnState::Closed;
                out.push(Event::Disconnected(DisconnectReason::Timeout));
                return;
            }

            // Sender side: on timeout, put every unacknowledged packet back on
            // the send loss list so it gets retransmitted.  Without this a lost
            // tail — or a lost NAK — is never recovered and the connection
            // stalls forever.  Only do so when the loss list is already empty,
            // otherwise the pending NAK-driven retransmissions still stand.
            // Mirrors C++ checkTimers().
            if !self.snd_buf_is_empty() {
                if self.snd_curr_seq.next() != self.snd_last_ack && self.snd_loss.is_empty() {
                    self.snd_loss.insert(self.snd_last_ack, self.snd_curr_seq);
                }
                let ctx = self.cc_ctx(now_us);
                let o = self.cc.on_timeout(ctx);
                self.apply_cc(o);
                // Restart transmission immediately rather than waiting a tick.
                self.next_snd_us = self.next_snd_us.min(now_us);
            } else {
                // Receiver side: keep-alive so the peer's EXP does not fire.
                self.enc.clear();
                codec::encode_keepalive(self.ts(now_us), self.peer_id, &mut self.enc);
                out.push(Event::SendDatagram(self.enc.clone().freeze()));
            }

            self.exp_count += 1;

            // Reset last_rsp_us so this EXP interval does not re-fire immediately
            // on the next on_timer call (C++: `m_ullLastRspTime = currtime`).
            self.last_rsp_us = now_us;
        }
    }

    /// Queues a message for transmission.
    ///
    /// Messages are all-or-nothing: the return value says whether this one was
    /// taken. On [`SendOutcome::WouldBlock`], retry the *same* payload once
    /// buffer space frees up — dropping it loses application data silently.
    ///
    /// `ttl_ms` gives up on the message after that many milliseconds and tells
    /// the peer to skip it. `in_order` set to `false` lets the peer deliver
    /// this message ahead of earlier ones that are still in flight.
    #[must_use = "a message that was not Queued must be retried or reported"]
    pub fn send_msg(
        &mut self,
        payload: Bytes,
        ttl_ms: Option<u32>,
        in_order: bool,
        now_us: u64,
        out: &mut Vec<Event>,
    ) -> SendOutcome {
        if !matches!(self.state, ConnState::Connected) {
            return SendOutcome::Rejected;
        }
        match self.snd_buf.as_mut() {
            Some(buf) => {
                if payload.len() > buf.max_msg_bytes() {
                    // Larger than the whole buffer — retrying can never help.
                    return SendOutcome::Rejected;
                }
                if buf.add(payload, ttl_ms, in_order, now_us).is_err() {
                    return SendOutcome::WouldBlock;
                }
            }
            None => return SendOutcome::Rejected,
        }
        // Allow immediate packing even if the pacing timer was backed off due to an empty buffer.
        self.next_snd_us = self.next_snd_us.min(now_us);
        let burst_end = now_us + SYN_US as u64;
        loop {
            if !self.pack_data(now_us, burst_end, out) {
                break;
            }
        }
        SendOutcome::Queued
    }

    /// The largest message this connection will ever accept, in bytes.
    ///
    /// Anything longer is [`SendOutcome::Rejected`] no matter how long you
    /// wait. Bounded by the send buffer, not the MTU: messages are split
    /// across packets automatically.
    pub fn max_msg_bytes(&self) -> usize {
        self.snd_buf.as_ref().map_or(0, |b| b.max_msg_bytes())
    }

    /// Takes the next complete message, if one is ready.
    ///
    /// Call this in a loop after [`Event::DataReady`] until it returns `None`.
    pub fn recv_msg(&mut self) -> Option<Bytes> {
        if let Some(msg) = self.ready_msgs.pop_front() {
            return Some(msg);
        }
        self.rcv_buf.as_mut()?.read_msg()
    }

    /// When [`on_timer`](Self::on_timer) next needs to be called.
    ///
    /// `None` once the connection is closed. Re-read this after every call
    /// into the connection, as most of them move it.
    pub fn next_deadline_us(&self) -> Option<u64> {
        match &self.state {
            ConnState::Closed => None,
            ConnState::Connecting { last_req_us, deadline_us, attempts, .. } => {
                Some((*last_req_us + hs_interval_us(*attempts)).min(*deadline_us))
            }
            ConnState::Connected => {
                let mut t = self.next_ack_us.min(self.next_snd_us);
                if !self.rcv_loss.is_empty() {
                    t = t.min(self.next_nak_us);
                }
                Some(t.min(self.last_rsp_us + self.exp_int_us()))
            }
        }
    }

    /// Closes immediately, telling the peer and discarding anything unsent.
    ///
    /// Use [`half_close`](Self::half_close) to let queued data drain first.
    pub fn shutdown(&mut self, now_us: u64, out: &mut Vec<Event>) {
        if !matches!(self.state, ConnState::Connected) {
            return;
        }
        self.enc.clear();
        codec::encode_shutdown(self.ts(now_us), self.peer_id, &mut self.enc);
        out.push(Event::SendDatagram(self.enc.clone().freeze()));
        self.state = ConnState::Closed;
        out.push(Event::Disconnected(DisconnectReason::LocalClose));
    }

    /// Closes once everything already queued has been acknowledged.
    ///
    /// Returns without closing if data is still outstanding; the shutdown then
    /// happens inside a later [`on_timer`](Self::on_timer). Incoming messages
    /// keep arriving until then.
    pub fn half_close(&mut self, now_us: u64, out: &mut Vec<Event>) {
        if !matches!(self.state, ConnState::Connected) {
            return;
        }
        if self.snd_buf.as_ref().map(|b| b.is_empty()).unwrap_or(true) {
            self.shutdown(now_us, out);
        } else {
            self.snd_half_closed = true;
        }
    }

    /// Whether every queued message has been acknowledged by the peer.
    pub fn snd_buf_is_empty(&self) -> bool {
        self.snd_buf.as_ref().map(|b| b.is_empty()).unwrap_or(true)
    }

    /// A snapshot of flow and congestion state. See [`ConnectionStats`].
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            socket_id: self.socket_id,
            connected: matches!(self.state, ConnState::Connected),
            snd_last_ack: self.snd_last_ack.raw(),
            snd_curr_seq: self.snd_curr_seq.raw(),
            snd_in_flight: self.snd_buf.as_ref().map_or(0, |b| b.in_flight()),
            snd_pending: self.snd_buf.as_ref().map_or(0, |b| b.pending()),
            snd_loss_len: self.snd_loss.len(),
            rcv_last_ack: self.rcv_last_ack.raw(),
            rcv_last_ack_ack: self.rcv_last_ack_ack.raw(),
            rcv_curr_seq: self.rcv_curr_seq.raw(),
            rcv_loss_len: self.rcv_loss.len(),
            ready_msgs: self.ready_msgs.len(),
            cwnd: self.cwnd,
            flow_wnd: self.flow_wnd,
            delivery_rate_pps: self.delivery_rate_pps,
            bandwidth_pps: self.bandwidth_pps,
            snd_period_us: self.snd_period_us,
            rtt_us: self.rtt_us,
            exp_count: self.exp_count,
        }
    }

    /// This side's socket identifier, as given to the constructor.
    pub fn socket_id(&self) -> u32 {
        self.socket_id
    }

    /// Whether the handshake has completed and data may be sent.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ConnState::Connected)
    }

    // ── Receive path ──────────────────────────────────────────────────────

    fn recv_data(
        &mut self,
        header: crate::packet::DataHeader,
        payload: Bytes,
        now_us: u64,
        out: &mut Vec<Event>,
    ) {
        // Rendezvous: data means the peer completed — try to complete too.
        self.try_rendezvous_complete(now_us, out);
        if !matches!(self.state, ConnState::Connected) {
            return;
        }

        self.last_rsp_us = now_us;
        self.exp_count = 1;

        let seq = header.seq_no;

        // Anything at or below the ACK point is a duplicate we have already
        // accounted for (C++ processData rejects the same range).
        if seq.offset_from(self.rcv_last_ack) < 0 {
            return;
        }

        let stored = match self.rcv_buf.as_mut() {
            Some(buf) => {
                buf.add(seq, payload.clone(), header.boundary, header.msg_no, header.in_order)
            }
            None => AddResult::OutOfWindow,
        };

        // No room in the ring — the packet is gone.  Return *before* touching
        // rcv_curr_seq: counting it as received would let the ACK point move
        // past data we do not hold, so the sender would free it and never
        // retransmit, wedging the connection.
        if stored == AddResult::OutOfWindow {
            return;
        }

        if stored == AddResult::Stored
            && let Some(buf) = self.rcv_buf.as_mut()
        {
            // Drain complete messages into the staging queue.  One DataReady is
            // enough however many messages became available — the driver drains
            // with recv_msg() until it returns None.
            let mut any = false;
            while let Some(msg) = buf.read_msg() {
                self.ready_msgs.push_back(msg);
                any = true;
            }
            if any {
                // Recycle the freed slots straight away.  Waiting for the next
                // ACK would let the ring fill up within a single 10 ms SYN
                // interval at high rates, after which every arrival is rejected
                // as out-of-window until the ACK finally lands.
                buf.reclaim();
                out.push(Event::DataReady);
            }
        }

        // Gap detection: sequences we haven't received between rcv_curr_seq and
        // this packet.  Report them immediately — waiting for the periodic NAK
        // timer costs a full NAK interval of recovery latency on every loss.
        let expected_next = self.rcv_curr_seq.next();
        if seq > expected_next {
            self.rcv_loss.insert(expected_next, seq.prev());
            self.emit_nak_range(expected_next, seq.prev(), now_us, out);
        }
        self.rcv_loss.remove(seq);

        if seq > self.rcv_curr_seq || self.rcv_curr_seq == SeqNo::new(0) {
            self.rcv_curr_seq = seq;
        }

        let probe_mod = seq.raw() & 0xF;
        if probe_mod == 0 {
            self.rcv_tw.probe1_arrival(now_us);
        } else if probe_mod == 1 {
            self.rcv_tw.probe2_arrival(now_us);
        }
        self.rcv_tw.on_pkt_arrival(now_us);

        // The ACK timer in on_timer decides when this count warrants a light
        // ACK; matching C++, which only counts here and acts in checkTimers.
        self.pkt_count += 1;

        // An odd-sized packet marks the end of a message — ACK it promptly so a
        // sender waiting on the tail of a transfer is not held up for a full
        // SYN interval (C++ processData nudges m_ullNextACKTime the same way).
        if payload.len() != self.payload_size as usize {
            self.next_ack_us = now_us;
        }
    }

    fn recv_ctrl(&mut self, body: ControlBody, now_us: u64, out: &mut Vec<Event>) {
        match body {
            ControlBody::Handshake(hs) => self.recv_handshake(hs, now_us, out),
            ControlBody::KeepAlive => {
                // A keep-alive during a rendezvous handshake means the peer has
                // already completed on its side, so we can too (C++ treats a
                // data *or* keep-alive packet as an implicit completion).
                self.try_rendezvous_complete(now_us, out);
                self.last_rsp_us = now_us;
                self.exp_count = 1;
            }
            ControlBody::Ack(asn, payload) => self.recv_ack(asn, payload, now_us, out),
            ControlBody::Nak(nak) => self.recv_nak(nak, now_us),
            ControlBody::Ack2(asn) => self.recv_ack2(asn, now_us),
            ControlBody::Shutdown => {
                self.state = ConnState::Closed;
                out.push(Event::Disconnected(DisconnectReason::Shutdown));
            }
            ControlBody::MsgDrop { msg_no, first, last } => {
                if let Some(buf) = self.rcv_buf.as_mut() {
                    // Retire the message by number where we hold it, and by
                    // sequence range regardless: the usual reason the sender
                    // dropped it is that those packets were lost, so there is
                    // nothing locally carrying that message number and the
                    // range would otherwise block the ring forever.
                    buf.drop_msg(msg_no);
                    buf.drop_range(first, last);
                }
                self.rcv_loss.remove_range(first, last);
                // Step the receive cursor over the dropped range, but only when
                // it actually abuts what we have. Without this the ACK point is
                // pinned below the hole forever: the next packet above the range
                // re-opens a gap and we re-NAK sequences the sender has already
                // given up on. Matches C++ processCtrl case 7.
                if first <= self.rcv_curr_seq.next() && last > self.rcv_curr_seq {
                    self.rcv_curr_seq = last;
                }
            }
            ControlBody::ErrorSignal { .. } => {
                self.state = ConnState::Closed;
                out.push(Event::Disconnected(DisconnectReason::PeerError));
            }
            ControlBody::CongestionWarning => {
                let ctx = self.cc_ctx(now_us);
                let o = self.cc.on_loss(&[], ctx);
                self.apply_cc(o);
            }
            _ => {}
        }
    }

    fn recv_handshake(&mut self, hs: Handshake, now_us: u64, out: &mut Vec<Event>) {
        match &self.state.clone() {
            ConnState::Connecting { mode: ConnMode::Active, conn_req, .. } => {
                let local_req = conn_req.clone();
                if hs.req_type == req_type::CONNECT {
                    // Server's cookie challenge (server also sends req_type=1 with cookie)
                    let mut new_req = local_req;
                    new_req.req_type = req_type::RESPONSE; // -1
                    new_req.cookie = hs.cookie;
                    if let ConnState::Connecting { conn_req, last_req_us, attempts, .. } =
                        &mut self.state
                    {
                        *conn_req = new_req.clone();
                        *last_req_us = 0; // resend immediately
                        *attempts = 0;
                    }
                    self.enc.clear();
                    codec::encode_handshake(&new_req, self.ts(now_us), 0, &mut self.enc);
                    out.push(Event::SendDatagram(self.enc.clone().freeze()));
                } else if hs.req_type == req_type::RESPONSE {
                    // Server confirmation — connection complete
                    self.do_post_connect(hs, now_us, out);
                } else if hs.req_type == req_type::REJECTED {
                    self.state = ConnState::Closed;
                    out.push(Event::Disconnected(DisconnectReason::PeerError));
                }
            }
            ConnState::Connecting { mode: ConnMode::Rendezvous, conn_req, .. } => {
                let local_req_type = conn_req.req_type;
                let recv_req_type = hs.req_type;

                // Regular connect from peer: reject
                if recv_req_type == req_type::CONNECT { return; }

                // RDVZ_DONE (-2): the peer already completed; complete here too.
                //
                // This happens when we were the slow side: the peer received our
                // -1, connected, and now answers our retransmissions with -2.
                // The -2 carries the peer's *own* ISN/MSS/socket id, so it is
                // sufficient on its own — do not depend on having previously
                // cached a handshake from the peer.  If every earlier packet
                // from the peer was lost, -2 is the only handshake we will ever
                // see and waiting for another would deadlock the connection.
                if recv_req_type == req_type::RDVZ_DONE {
                    self.do_post_connect(hs, now_us, out);
                    return;
                }

                if local_req_type == req_type::RENDEZVOUS || recv_req_type == req_type::RENDEZVOUS {
                    // At least one side still at 0 → advance to -1
                    let new_req = if let ConnState::Connecting { conn_req, .. } = &self.state {
                        let mut r = conn_req.clone();
                        r.req_type = req_type::RESPONSE;
                        r
                    } else { return };
                    if let ConnState::Connecting {
                        conn_req, last_req_us, attempts, last_peer_hs, ..
                    } = &mut self.state
                    {
                        *conn_req = new_req.clone();
                        *last_req_us = 0;
                        *attempts = 0;
                        *last_peer_hs = Some(hs.clone());
                    }
                    self.enc.clear();
                    codec::encode_handshake(&new_req, self.ts(now_us), 0, &mut self.enc);
                    out.push(Event::SendDatagram(self.enc.clone().freeze()));
                } else if local_req_type == req_type::RESPONSE && recv_req_type == req_type::RESPONSE {
                    // Both at -1 → complete
                    self.do_post_connect(hs, now_us, out);
                }
            }
            ConnState::Connected
                // Already connected, but the peer is still querying — it never
                // saw our completion.  Answer with -2 (C++ processCtrl case 0).
                if hs.req_type != req_type::RDVZ_DONE => {
                    // Advertise our *own* parameters, not the peer's echoed
                    // back: this packet may be the only handshake the peer ever
                    // receives from us, so it must carry everything needed to
                    // complete — above all our ISN.
                    let resp = Handshake {
                        version: UDT_VERSION,
                        sock_type: SOCK_DGRAM,
                        isn: self.local_isn.raw() as i32,
                        mss: self.mss as i32,
                        flight_flag_size: DEFAULT_FLIGHT_FLAG_SIZE as i32,
                        req_type: req_type::RDVZ_DONE,
                        socket_id: self.socket_id as i32,
                        cookie: 0,
                        peer_ip: [0u32; 4],
                    };
                    self.enc.clear();
                    codec::encode_handshake(&resp, self.ts(now_us), hs.socket_id as u32, &mut self.enc);
                    out.push(Event::SendDatagram(self.enc.clone().freeze()));
                }
            _ => {}
        }
    }

    /// Complete a pending rendezvous handshake using the peer handshake we
    /// already cached.
    ///
    /// Called when a data or keep-alive packet arrives mid-handshake: either
    /// proves the peer considers itself connected, so the negotiation is over.
    /// No-op unless we are mid-rendezvous with a cached peer handshake.
    fn try_rendezvous_complete(&mut self, now_us: u64, out: &mut Vec<Event>) {
        if let ConnState::Connecting { mode: ConnMode::Rendezvous, last_peer_hs, .. } = &self.state
            && let Some(hs) = last_peer_hs.clone()
        {
            self.do_post_connect(hs, now_us, out);
        }
    }

    fn do_post_connect(&mut self, hs: Handshake, now_us: u64, out: &mut Vec<Event>) {
        let peer_isn = SeqNo::new(hs.isn as u32 & SEQ_MAX);
        // Both of these are peer-supplied and reach allocation sizing, so they
        // are clamped before use rather than trusted.
        let mss = (hs.mss as u32).min(self.mss).max(MIN_MSS);
        let flow_wnd = (hs.flight_flag_size.max(1) as u32).min(MAX_FLOW_WND);
        self.peer_id = hs.socket_id as u32;
        self.state = ConnState::Connected;
        self.post_connect(peer_isn, mss, flow_wnd, now_us);
        out.push(Event::Connected);
    }

    fn recv_ack(
        &mut self,
        asn: AckSeqNo,
        payload: crate::packet::AckPayload,
        now_us: u64,
        out: &mut Vec<Event>,
    ) {
        self.last_rsp_us = now_us;
        self.exp_count = 1;

        let ack_seq = payload.data_ack_seq;

        // Reject an ACK for data we never sent — a corrupt or hostile peer must
        // not be able to advance our send buffer past the write cursor.
        if ack_seq > self.snd_curr_seq.next() {
            self.state = ConnState::Closed;
            out.push(Event::Disconnected(DisconnectReason::PeerError));
            return;
        }

        let adv = ack_seq.offset_from(self.snd_last_ack).max(0) as usize;

        if let Some(full) = &payload.full {
            let rtt = full.rtt_us;
            let rtt_var = (rtt - self.rtt_us).abs() / 8;
            self.rtt_us = (self.rtt_us * 7 + rtt) / 8;
            self.rtt_var_us = (self.rtt_var_us * 3 + rtt_var) / 4;
            if full.avail_buf_pkts > 0 {
                self.flow_wnd = (full.avail_buf_pkts as u32).min(MAX_FLOW_WND);
            }
            // Smooth the peer's rate reports (7/8 EWMA, ignoring non-positive
            // samples) before handing them to congestion control.  Raw per-ACK
            // samples are far too noisy — on loopback the receiver frequently
            // reports 0 pkt/s because every packet lands in the same
            // microsecond, which would otherwise collapse the window.
            if full.rcv_rate_pps > 0 {
                self.delivery_rate_pps =
                    (self.delivery_rate_pps * 7 + full.rcv_rate_pps as u32) / 8;
            }
            if full.bandwidth_pps > 0 {
                self.bandwidth_pps = (self.bandwidth_pps * 7 + full.bandwidth_pps as u32) / 8;
            }
            let ctx = self.cc_ctx_ex(now_us, self.delivery_rate_pps, self.bandwidth_pps);
            let o = self.cc.on_ack(ack_seq, ctx);
            self.apply_cc(o);

            // Answer every full ACK with an ACK2, promptly.
            //
            // The peer derives its entire RTT estimate from the round trip of
            // this packet, and it gates real behaviour on that estimate: the
            // C++ receiver refuses to re-send an unchanged ACK for
            // RTT + 4·RTTVar, and its idle sockets only get their timers
            // serviced every 100 ms.  Delaying ACK2s inflates the peer's RTT,
            // which widens that hold-off and costs ~100 ms stalls.
            //
            // C++ appears to rate limit here (`> m_iSYNInterval`), but it
            // compares a `rdtsc` reading against a microsecond constant, so on
            // platforms with a real TSC the test is effectively always true.
            // Sending one per full ACK matches its actual behaviour.
            self.snd_last_ack2 = asn;
            self.snd_last_ack2_us = now_us;
            self.enc.clear();
            codec::encode_ack2(asn, self.ts(now_us), self.peer_id, &mut self.enc);
            out.push(Event::SendDatagram(self.enc.clone().freeze()));
        }
        // A light ACK carries only the acknowledgement point: it advances the
        // send buffer (below) but triggers no RTT, CC or ACK2 processing.

        if adv > 0 {
            self.snd_last_ack = ack_seq;
            self.snd_loss.remove_up_to(ack_seq.prev());
            if let Some(buf) = self.snd_buf.as_mut() {
                buf.ack(adv);
            }
            // Window just opened — immediately try to pack more data rather than
            // waiting for the next on_timer tick.
            self.next_snd_us = self.next_snd_us.min(now_us);
            let burst_end = now_us + SYN_US as u64;
            loop {
                if !self.pack_data(now_us, burst_end, out) {
                    self.next_snd_us = now_us + SYN_US as u64;
                    break;
                }
            }
        }
    }

    fn recv_nak(&mut self, nak: crate::packet::NakList, now_us: u64) {
        for (s, e) in &nak.0 {
            self.snd_loss.insert(*s, *e);
        }
        let ranges: Vec<_> = self.snd_loss.ranges_snapshot().to_vec();
        let ctx = self.cc_ctx(now_us);
        let o = self.cc.on_loss(&ranges, ctx);
        self.apply_cc(o);
    }

    fn recv_ack2(&mut self, asn: AckSeqNo, now_us: u64) {
        if let Some((rtt_us, data_ack)) = self.ack_win.acknowledge(asn, now_us) {
            // Record how far the peer has confirmed, so emit_ack can suppress
            // ACKs that would tell it nothing new.
            if data_ack > self.rcv_last_ack_ack {
                self.rcv_last_ack_ack = data_ack;
            }
            let rtt_var = (rtt_us as i32 - self.rtt_us).abs() / 8;
            self.rtt_us = (self.rtt_us * 7 + rtt_us as i32) / 8;
            self.rtt_var_us = (self.rtt_var_us * 3 + rtt_var) / 4;
        }
    }

    /// Emit an ACK.
    ///
    /// A `light` ACK carries only the acknowledgement point and does not update
    /// any local state; it exists to keep a fast sender's window open between
    /// full ACKs.
    fn emit_ack(&mut self, now_us: u64, light: bool, out: &mut Vec<Event>) {
        // The acknowledgement point is the highest *contiguous* sequence number,
        // i.e. the first hole if there is one.  Acknowledging past a hole (i.e.
        // using rcv_curr_seq) tells the sender to free data the receiver never
        // got, so it is never retransmitted and the connection wedges.
        // Matches C++ CUDT::sendCtrl case 2.
        let data_ack = match self.rcv_loss.first() {
            Some(first_lost) => first_lost,
            None => self.rcv_curr_seq.next(),
        };

        // The peer has already confirmed this point via ACK2 — nothing to add.
        if data_ack == self.rcv_last_ack_ack {
            return;
        }

        if light {
            // Light ACK: 4-byte body, no ACK sub-sequence tracking.
            self.enc.clear();
            codec::encode_ack(
                AckSeqNo::new(0),
                data_ack,
                None,
                self.ts(now_us),
                self.peer_id,
                &mut self.enc,
            );
            out.push(Event::SendDatagram(self.enc.clone().freeze()));
            return;
        }

        match data_ack.cmp(&self.rcv_last_ack) {
            Ordering::Greater => {
                self.rcv_last_ack = data_ack;
                // Recycle the ring slots the application has already consumed.
                if let Some(buf) = self.rcv_buf.as_mut() {
                    buf.reclaim();
                }
            }
            Ordering::Equal => {
                // Re-ACK an unchanged point only after RTT + 4·RTTVar, so a
                // stalled receiver does not flood the peer with duplicate ACKs.
                let min_gap = (self.rtt_us + 4 * self.rtt_var_us).max(0) as u64;
                if now_us.saturating_sub(self.last_ack_us) < min_gap {
                    return;
                }
            }
            Ordering::Less => return,
        }

        // Nothing new beyond what the peer has already acknowledged.
        if self.rcv_last_ack <= self.rcv_last_ack_ack {
            return;
        }

        // A minimum window of 2 is advertised even when the buffer is full, to
        // break a potential deadlock where neither side can make progress.
        let avail =
            self.rcv_buf.as_ref().map_or(0, |b| b.avail_from(data_ack)).min(i32::MAX as usize)
                as i32;
        let full = AckFull {
            rtt_us: self.rtt_us,
            rtt_var_us: self.rtt_var_us,
            avail_buf_pkts: avail.max(2),
            rcv_rate_pps: self.rcv_tw.pkt_rcv_speed() as i32,
            bandwidth_pps: self.rcv_tw.bandwidth() as i32,
        };

        let asn = self.ack_seq;
        self.ack_win.store(asn, data_ack, now_us);
        self.ack_seq = self.ack_seq.next();
        self.last_ack_us = now_us;
        self.enc.clear();
        codec::encode_ack(asn, data_ack, Some(&full), self.ts(now_us), self.peer_id, &mut self.enc);
        out.push(Event::SendDatagram(self.enc.clone().freeze()));
    }

    /// Expire the message sitting at the send cursor, if its TTL has run out.
    ///
    /// Returns true if a message was retired, in which case the caller should
    /// treat this as productive work and come round again.
    fn expire_at_send_cursor(&mut self, now_us: u64, out: &mut Vec<Event>) -> bool {
        let cursor = match self.snd_buf.as_ref() {
            Some(b) => b.send_cursor(),
            None => return false,
        };
        self.expire_msg_at(cursor, now_us, out)
    }

    /// Expire the message covering in-flight block offset `off`, if its TTL has
    /// run out, and tell the peer to skip its sequence range.
    ///
    /// The dropped blocks keep their slots and their sequence numbers — the send
    /// buffer's block-to-sequence mapping is positional, so consuming the range
    /// is what keeps `read_at` serving the right payload for every later
    /// sequence number. The peer is told the exact inclusive range; C++ names
    /// one sequence number too many here, so both ends forget a packet
    /// belonging to the *next* message.
    fn expire_msg_at(&mut self, off: usize, now_us: u64, out: &mut Vec<Event>) -> bool {
        let Some((msg_no, first_off, last_off)) =
            self.snd_buf.as_mut().and_then(|b| b.expire_msg_at(off, now_us))
        else {
            return false;
        };

        let first = self.snd_last_ack.add(first_off as u32);
        let last = self.snd_last_ack.add(last_off as u32);
        if last > self.snd_curr_seq {
            self.snd_curr_seq = last;
        }
        // Nothing in the dropped range is worth retransmitting any more.
        self.snd_loss.remove_range(first, last);

        self.enc.clear();
        codec::encode_msg_drop(msg_no, first, last, self.ts(now_us), self.peer_id, &mut self.enc);
        out.push(Event::SendDatagram(self.enc.clone().freeze()));
        true
    }

    /// Re-announce a dropped message's range to a peer still asking for it.
    ///
    /// Returns whether anything was sent.
    fn resend_msg_drop_at(&mut self, off: u32, now_us: u64, out: &mut Vec<Event>) -> bool {
        let Some((msg_no, first_off, last_off)) =
            self.snd_buf.as_ref().and_then(|b| b.dropped_msg_at(off as usize))
        else {
            return false;
        };
        let first = self.snd_last_ack.add(first_off as u32);
        let last = self.snd_last_ack.add(last_off as u32);
        self.snd_loss.remove_range(first, last);

        self.enc.clear();
        codec::encode_msg_drop(msg_no, first, last, self.ts(now_us), self.peer_id, &mut self.enc);
        out.push(Event::SendDatagram(self.enc.clone().freeze()));
        true
    }

    /// Send a NAK for a single contiguous range, used for immediate loss
    /// reporting the moment a gap is spotted in the data stream.
    fn emit_nak_range(&mut self, start: SeqNo, end: SeqNo, now_us: u64, out: &mut Vec<Event>) {
        self.enc.clear();
        codec::encode_nak(&[(start, end)], self.ts(now_us), self.peer_id, &mut self.enc);
        out.push(Event::SendDatagram(self.enc.clone().freeze()));
    }

    fn emit_nak(&mut self, now_us: u64, out: &mut Vec<Event>) {
        let max_words = (self.payload_size / 4) as usize;
        let words = self.rcv_loss.to_nak_payload(max_words);
        if words.is_empty() {
            return;
        }
        let mut ranges = Vec::new();
        let mut i = 0;
        while i < words.len() {
            let w = words[i];
            if w >> 31 != 0 {
                let s = SeqNo::new(w & 0x7FFF_FFFF);
                let e = SeqNo::new(words.get(i + 1).copied().unwrap_or(w) & 0x7FFF_FFFF);
                ranges.push((s, e));
                i += 2;
            } else {
                let s = SeqNo::new(w & 0x7FFF_FFFF);
                ranges.push((s, s));
                i += 1;
            }
        }
        self.enc.clear();
        codec::encode_nak(&ranges, self.ts(now_us), self.peer_id, &mut self.enc);
        out.push(Event::SendDatagram(self.enc.clone().freeze()));
    }

    /// Try to pack one outbound data packet.
    ///
    /// `burst_end` is the maximum virtual send-time ceiling for this call.
    /// Callers pass `now_us + SYN_US` so that all packets due within the next
    /// SYN interval are batched in one loop.  This is necessary because tokio
    /// timers have ~1 ms granularity and cannot honour sub-millisecond
    /// `pkt_snd_period_us` values individually.
    fn pack_data(&mut self, now_us: u64, burst_end: u64, out: &mut Vec<Event>) -> bool {
        if burst_end < self.next_snd_us {
            return false;
        }

        // Retire any message at the send cursor whose TTL has run out, before
        // spending a transmission on it.
        if self.expire_at_send_cursor(now_us, out) {
            return true;
        }

        // Retransmission has priority and is deliberately *not* subject to the
        // congestion window.  Gating it deadlocks the connection: once cwnd
        // falls below the in-flight count the only way it can reopen is for the
        // missing packets to be repaired, which is exactly what the gate would
        // be blocking.  C++ packData() applies the window check to new data
        // only ("Loss retransmission always has higher priority").
        let mut retransmit = None;
        while let Some(s) = self.snd_loss.pop_front() {
            let off = s.offset_from(self.snd_last_ack);
            if off < 0 {
                continue; // already acknowledged since the loss was recorded
            }
            // A retransmission is also a chance to notice the TTL has expired.
            if self.expire_msg_at(off as usize, now_us, out) {
                continue; // dropped instead of resent; try the next loss entry
            }
            // Still being asked for a message that was already given up on,
            // which means the peer never got the MsgDrop -- it is a single
            // unacknowledged datagram, so any loss strands the receiver waiting
            // for a range that will never be sent. Say it again.
            if self.resend_msg_drop_at(off as u32, now_us, out) {
                continue;
            }
            // Copy the fields out to release the borrow before calling self.ts().
            let block = self
                .snd_buf
                .as_ref()
                .and_then(|b| b.read_at(off as usize))
                .map(|b| (b.boundary, b.in_order, b.msg_no, b.data.clone()));
            if let Some((boundary, in_order, msg_no, data)) = block {
                let hdr = codec::encode_data_header(
                    s,
                    boundary,
                    in_order,
                    msg_no,
                    self.ts(now_us),
                    self.peer_id,
                );
                retransmit = Some((hdr, data));
                break;
            }
            // Names a block we no longer hold (e.g. a stale NAK) — discard it
            // and try the next entry rather than stalling the pacing loop.
        }

        let (hdr_bytes, payload_bytes) = match retransmit {
            Some(v) => v,
            None => {
                // New data — this is what the congestion/flow window limits.
                let in_flight = self.snd_buf.as_ref().map_or(0, |b| b.in_flight());
                let max_flight = (self.cwnd.min(self.flow_wnd as f64)) as usize;
                if in_flight >= max_flight {
                    return false;
                }

                self.snd_curr_seq = self.snd_curr_seq.next();
                let seq = self.snd_curr_seq;
                // Extract fields before releasing the mutable borrow so we can call self.ts() after.
                let (boundary, in_order, msg_no, data) =
                    match self.snd_buf.as_mut().and_then(|b| b.read_next()) {
                        Some(block) => {
                            (block.boundary, block.in_order, block.msg_no, block.data.clone())
                        }
                        None => {
                            self.snd_curr_seq = self.snd_curr_seq.prev();
                            return false;
                        }
                    };
                let hdr = codec::encode_data_header(
                    seq,
                    boundary,
                    in_order,
                    msg_no,
                    self.ts(now_us),
                    self.peer_id,
                );
                (hdr, data)
            }
        };

        // Carve the packet out of the arena rather than allocating per packet.
        // `pkt_arena` is always empty here (the previous packet was split off),
        // so its capacity is the free space available.
        let total = UDT_HEADER_SIZE + payload_bytes.len();
        if self.pkt_arena.capacity() < total {
            self.pkt_arena = BytesMut::with_capacity(PKT_ARENA_SIZE.max(total));
        }
        self.pkt_arena.extend_from_slice(&hdr_bytes);
        self.pkt_arena.extend_from_slice(&payload_bytes);
        out.push(Event::SendDatagram(self.pkt_arena.split_to(total).freeze()));

        self.snd_tw.on_pkt_arrival(now_us);
        // Accumulate next_snd_us rather than resetting relative to now_us.
        // This allows the pacing loop to send all packets that are "due" in one
        // on_timer/send_msg call instead of stopping after the first packet.
        // Clamp to prevent stale credit accumulation after a long idle period.
        self.next_snd_us += self.snd_period_us.max(1.0) as u64;
        if self.next_snd_us + (SYN_US as u64) < now_us {
            self.next_snd_us = now_us - SYN_US as u64;
        }
        true
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    fn cc_ctx(&self, now_us: u64) -> CcContext {
        self.cc_ctx_ex(now_us, self.rcv_tw.pkt_rcv_speed(), self.rcv_tw.bandwidth())
    }

    fn cc_ctx_ex(&self, now_us: u64, rcv_rate: u32, bw: u32) -> CcContext {
        CcContext {
            mss: self.mss,
            bandwidth_pps: bw,
            rcv_rate_pps: rcv_rate,
            rtt_us: self.rtt_us as u32,
            snd_curr_seq: self.snd_curr_seq,
            flight_size: self.snd_buf.as_ref().map_or(0, |b| b.in_flight()) as u32,
            flow_wnd: self.flow_wnd as f64,
            syn_interval_us: SYN_US,
            now_us,
        }
    }

    fn apply_cc(&mut self, o: CcOutput) {
        self.snd_period_us = o.pkt_snd_period_us.max(1.0);
        self.cwnd = o.cwnd.max(2.0);
        // A CC may also drive ACK cadence and the retransmission timeout.
        // C++ reads m_iACKPeriod / m_iACKInterval in checkTimers and
        // m_bUserDefinedRTO / m_iRTO in its EXP calculation; mirror that rather
        // than leaving these outputs unread.
        self.cc_ack_period_us = o.ack_period_ms.map(|ms| ms as u64 * 1_000);
        self.cc_ack_interval_pkts = o.ack_interval_pkts;
        self.cc_rto_us = o.rto_us.map(|us| us as u64);
    }

    /// Interval until the next EXP (retransmission timeout) firing.
    ///
    /// Uses the CC's RTO if it supplies one, else the C++ formula:
    /// `max(count × (RTT + 4·RTTVar) + SYN, count × MIN_EXP_PER_COUNT)`.
    fn exp_int_us(&self) -> u64 {
        if let Some(rto) = self.cc_rto_us {
            return self.exp_count as u64 * rto;
        }
        let rtt_based = self.exp_count as u64 * (self.rtt_us as u64 + 4 * self.rtt_var_us as u64)
            + SYN_US as u64;
        let min_based = self.exp_count as u64 * MIN_EXP_PER_COUNT_US;
        rtt_based.max(min_based)
    }

    /// Interval between full ACKs — the CC's ACK period if it sets one.
    fn ack_int_us(&self) -> u64 {
        self.cc_ack_period_us.unwrap_or(SYN_US as u64)
    }

    fn nak_int_us(&self) -> u64 {
        (4 * self.rtt_us as u64).max(SYN_US as u64)
    }

    fn ts(&self, now_us: u64) -> u32 {
        now_us as u32
    }
}
