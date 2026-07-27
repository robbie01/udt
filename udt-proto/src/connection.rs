use std::cmp::Ordering;
use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};
use crate::codec;
use crate::congestion::{CcContext, CcOutput, CongestionControl};
use crate::congestion::udt_cc::UdtCc;
use crate::handshake::{req_type, Handshake, SOCK_DGRAM, UDT_VERSION};
use crate::loss_list::{RcvLossList, SndLossList};
use crate::ack_window::AckWindow;
use crate::time_window::PktTimeWindow;
use crate::send_buffer::SendBuffer;
use crate::recv_buffer::{AddResult, RecvBuffer};
use crate::packet::{AckFull, ControlBody, Packet};
use crate::seq::{AckSeqNo, SeqNo, SEQ_MAX};

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
// Handshake re-send interval ≈ 250ms
const HS_RESEND_US: u64 = 250_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnMode { Active, Rendezvous }

#[derive(Debug, Clone)]
enum ConnState {
    Connecting {
        mode: ConnMode,
        conn_req: Handshake,
        last_req_us: u64,
        deadline_us: u64,
        last_peer_hs: Option<Handshake>,
    },
    Connected,
    Closed,
}

pub enum Output {
    SendDatagram(Bytes),
    DataReady,
    Connected,
    Disconnected(DisconnectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason { Shutdown, Timeout, PeerError, LocalClose }

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

/// Snapshot of connection flow/congestion state for diagnostics.
#[derive(Debug, Clone, Copy)]
pub struct ConnDebug {
    pub socket_id: u32,
    pub connected: bool,
    pub snd_last_ack: u32,
    pub snd_curr_seq: u32,
    pub snd_in_flight: usize,
    pub snd_pending: usize,
    pub snd_loss_len: usize,
    pub rcv_last_ack: u32,
    pub rcv_last_ack_ack: u32,
    pub rcv_curr_seq: u32,
    pub rcv_loss_len: usize,
    pub ready_msgs: usize,
    pub cwnd: f64,
    pub flow_wnd: u32,
    pub delivery_rate_pps: u32,
    pub bandwidth_pps: u32,
    pub snd_period_us: f64,
    pub rtt_us: i32,
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
    pub fn new_active(socket_id: u32, local_isn: SeqNo, mss: u32, now_us: u64) -> Self {
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
        c.local_isn = local_isn;
        c.state = ConnState::Connecting {
            mode: ConnMode::Active,
            conn_req: req,
            last_req_us: 0,
            deadline_us: now_us + 30_000_000,
            last_peer_hs: None,
        };
        c
    }

    pub fn new_rendezvous(socket_id: u32, local_isn: SeqNo, mss: u32, now_us: u64) -> Self {
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
        c.local_isn = local_isn;
        c.state = ConnState::Connecting {
            mode: ConnMode::Rendezvous,
            conn_req: req,
            last_req_us: 0,
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
            cc: Box::new(UdtCc::new()),
            snd_period_us: 1.0,
            cwnd: 16.0,
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
        self.snd_loss = SndLossList::new(flow_wnd as usize * 2);
        self.rcv_loss = RcvLossList::new(flow_wnd as usize);
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

    pub fn on_datagram(&mut self, datagram: Bytes, now_us: u64, out: &mut Vec<Output>) {
        let pkt = match codec::decode(datagram) { Some(p) => p, None => return };
        // Check destination socket ID
        let ok = match &pkt {
            Packet::Data { header, .. } => header.dst_socket_id == self.socket_id,
            Packet::Control { header, .. } => header.dst_socket_id == 0 || header.dst_socket_id == self.socket_id,
        };
        if !ok { return; }
        match pkt {
            Packet::Data { header, payload } => self.recv_data(header, payload, now_us, out),
            Packet::Control { header: _, body } => self.recv_ctrl(body, now_us, out),
        }
    }

    pub fn on_timer(&mut self, now_us: u64, out: &mut Vec<Output>) {
        match &self.state {
            ConnState::Closed => return,
            ConnState::Connecting { deadline_us, last_req_us, conn_req, .. } => {
                let deadline = *deadline_us;
                let last = *last_req_us;
                let req = conn_req.clone();
                if now_us > deadline {
                    self.state = ConnState::Closed;
                    out.push(Output::Disconnected(DisconnectReason::Timeout));
                    return;
                }
                if now_us >= last + HS_RESEND_US {
                    if let ConnState::Connecting { last_req_us, .. } = &mut self.state {
                        *last_req_us = now_us;
                    }
                    self.enc.clear();
                    codec::encode_handshake(&req, self.ts(now_us), 0, &mut self.enc);
                    out.push(Output::SendDatagram(self.enc.clone().freeze()));
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
        if now_us >= self.next_ack_us {
            self.emit_ack(now_us, false, out);
            self.next_ack_us = now_us + SYN_US as u64;
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

        // EXP — mirrors C++ checkTimers() logic.
        //
        // Interval formula (matching C++):
        //   exp_int = max(count × MIN_EXP_PER_COUNT,
        //                 count × (RTT + 4×RTTVar) + SYN)
        //
        // After firing, `last_rsp_us` is reset to now so the timer does NOT
        // immediately re-fire (the C++ does the same: `m_ullLastRspTime = currtime`).
        //
        // Disconnect only when BOTH:
        //   • exp_count > EXP_MAX (16 expirations), AND
        //   • silence since last fire > EXP_HARD_TIMEOUT_US (5 s)
        let exp_int = {
            let rtt_based = self.exp_count as u64
                * (self.rtt_us as u64 + 4 * self.rtt_var_us as u64)
                + SYN_US as u64;
            let min_based = self.exp_count as u64 * MIN_EXP_PER_COUNT_US;
            rtt_based.max(min_based)
        };
        if now_us >= self.last_rsp_us + exp_int {
            // Hard timeout: peer has been silent for too long.
            if self.exp_count > EXP_MAX
                && now_us.saturating_sub(self.last_rsp_us) > EXP_HARD_TIMEOUT_US
            {
                self.state = ConnState::Closed;
                out.push(Output::Disconnected(DisconnectReason::Timeout));
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
                out.push(Output::SendDatagram(self.enc.clone().freeze()));
            }

            self.exp_count += 1;

            // Reset last_rsp_us so this EXP interval does not re-fire immediately
            // on the next on_timer call (C++: `m_ullLastRspTime = currtime`).
            self.last_rsp_us = now_us;
        }
    }

    /// Queue a message for transmission.
    ///
    /// A message is queued all-or-nothing; on [`SendOutcome::WouldBlock`] the
    /// caller must retry the *same* payload once buffer space frees up.
    /// Dropping a non-`Queued` message silently loses application data.
    #[must_use = "a message that was not Queued must be retried or reported"]
    pub fn send_msg(
        &mut self,
        payload: Bytes,
        ttl_ms: Option<u32>,
        in_order: bool,
        now_us: u64,
        out: &mut Vec<Output>,
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
            if !self.pack_data(now_us, burst_end, out) { break; }
        }
        SendOutcome::Queued
    }

    /// Largest message this connection can ever accept, in bytes.
    pub fn max_msg_bytes(&self) -> usize {
        self.snd_buf.as_ref().map_or(0, |b| b.max_msg_bytes())
    }

    /// Extract the next ready message. Returns None if none available.
    pub fn recv_msg(&mut self) -> Option<Bytes> {
        if let Some(msg) = self.ready_msgs.pop_front() {
            return Some(msg);
        }
        self.rcv_buf.as_mut()?.read_msg()
    }

    pub fn next_deadline_us(&self) -> Option<u64> {
        match &self.state {
            ConnState::Closed => None,
            ConnState::Connecting { last_req_us, deadline_us, .. } => {
                Some((*last_req_us + HS_RESEND_US).min(*deadline_us))
            }
            ConnState::Connected => {
                let mut t = self.next_ack_us.min(self.next_snd_us);
                if !self.rcv_loss.is_empty() { t = t.min(self.next_nak_us); }
                let exp_int = {
                    let rtt_based = self.exp_count as u64
                        * (self.rtt_us as u64 + 4 * self.rtt_var_us as u64)
                        + SYN_US as u64;
                    let min_based = self.exp_count as u64 * MIN_EXP_PER_COUNT_US;
                    rtt_based.max(min_based)
                };
                let exp = self.last_rsp_us + exp_int;
                Some(t.min(exp))
            }
        }
    }

    pub fn shutdown(&mut self, now_us: u64, out: &mut Vec<Output>) {
        if !matches!(self.state, ConnState::Connected) { return; }
        self.enc.clear();
        codec::encode_shutdown(self.ts(now_us), self.peer_id, &mut self.enc);
        out.push(Output::SendDatagram(self.enc.clone().freeze()));
        self.state = ConnState::Closed;
        out.push(Output::Disconnected(DisconnectReason::LocalClose));
    }

    /// Graceful half-close: the application has finished sending.
    ///
    /// If the send buffer is already empty, shuts down immediately.
    /// Otherwise sets a flag so `on_timer` will send the Shutdown once
    /// all queued data has been acknowledged by the peer.
    pub fn half_close(&mut self, now_us: u64, out: &mut Vec<Output>) {
        if !matches!(self.state, ConnState::Connected) { return; }
        if self.snd_buf.as_ref().map(|b| b.is_empty()).unwrap_or(true) {
            self.shutdown(now_us, out);
        } else {
            self.snd_half_closed = true;
        }
    }

    /// Returns true when all sent data has been acknowledged by the peer
    /// (or when no send buffer has been allocated yet).
    pub fn snd_buf_is_empty(&self) -> bool {
        self.snd_buf.as_ref().map(|b| b.is_empty()).unwrap_or(true)
    }

    /// Snapshot of the flow/congestion state, for diagnostics and tests.
    pub fn debug_state(&self) -> ConnDebug {
        ConnDebug {
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

    pub fn socket_id(&self) -> u32 { self.socket_id }
    pub fn is_connected(&self) -> bool { matches!(self.state, ConnState::Connected) }

    // ── Receive path ──────────────────────────────────────────────────────

    fn recv_data(
        &mut self,
        header: crate::packet::DataHeader,
        payload: Bytes,
        now_us: u64,
        out: &mut Vec<Output>,
    ) {
        // Rendezvous: data means the peer completed — try to complete too.
        self.try_rendezvous_complete(now_us, out);
        if !matches!(self.state, ConnState::Connected) { return; }

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
                buf.slide_window();
                out.push(Output::DataReady);
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
        if probe_mod == 0 { self.rcv_tw.probe1_arrival(now_us); }
        else if probe_mod == 1 { self.rcv_tw.probe2_arrival(now_us); }
        self.rcv_tw.on_pkt_arrival(now_us);

        let ctx = self.cc_ctx(now_us);
        let o = self.cc.on_pkt_received(header.timestamp_us, payload.len(), ctx);
        self.apply_cc(o);

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

    fn recv_ctrl(&mut self, body: ControlBody, now_us: u64, out: &mut Vec<Output>) {
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
                out.push(Output::Disconnected(DisconnectReason::Shutdown));
            }
            ControlBody::MsgDrop { msg_no, first, last } => {
                if let Some(buf) = self.rcv_buf.as_mut() { buf.drop_msg(msg_no); }
                self.rcv_loss.remove_range(first, last);
            }
            ControlBody::ErrorSignal { .. } => {
                self.state = ConnState::Closed;
                out.push(Output::Disconnected(DisconnectReason::PeerError));
            }
            ControlBody::CongestionWarning => {
                let ctx = self.cc_ctx(now_us);
                let o = self.cc.on_loss(&[], ctx);
                self.apply_cc(o);
            }
            _ => {}
        }
    }

    fn recv_handshake(&mut self, hs: Handshake, now_us: u64, out: &mut Vec<Output>) {
        match &self.state.clone() {
            ConnState::Connecting { mode: ConnMode::Active, conn_req, .. } => {
                let local_req = conn_req.clone();
                if hs.req_type == req_type::CONNECT {
                    // Server's cookie challenge (server also sends req_type=1 with cookie)
                    let mut new_req = local_req;
                    new_req.req_type = req_type::RESPONSE; // -1
                    new_req.cookie = hs.cookie;
                    if let ConnState::Connecting { conn_req, last_req_us, .. } = &mut self.state {
                        *conn_req = new_req.clone();
                        *last_req_us = 0; // resend immediately
                    }
                    self.enc.clear();
                    codec::encode_handshake(&new_req, self.ts(now_us), 0, &mut self.enc);
                    out.push(Output::SendDatagram(self.enc.clone().freeze()));
                } else if hs.req_type == req_type::RESPONSE {
                    // Server confirmation — connection complete
                    self.do_post_connect(hs, now_us, out);
                } else if hs.req_type == req_type::REJECTED {
                    self.state = ConnState::Closed;
                    out.push(Output::Disconnected(DisconnectReason::PeerError));
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
                    if let ConnState::Connecting { conn_req, last_req_us, last_peer_hs, .. } = &mut self.state {
                        *conn_req = new_req.clone();
                        *last_req_us = 0;
                        *last_peer_hs = Some(hs.clone());
                    }
                    self.enc.clear();
                    codec::encode_handshake(&new_req, self.ts(now_us), 0, &mut self.enc);
                    out.push(Output::SendDatagram(self.enc.clone().freeze()));
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
                    out.push(Output::SendDatagram(self.enc.clone().freeze()));
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
    fn try_rendezvous_complete(&mut self, now_us: u64, out: &mut Vec<Output>) {
        if let ConnState::Connecting { mode: ConnMode::Rendezvous, last_peer_hs, .. } = &self.state
            && let Some(hs) = last_peer_hs.clone()
        {
            self.do_post_connect(hs, now_us, out);
        }
    }

    fn do_post_connect(&mut self, hs: Handshake, now_us: u64, out: &mut Vec<Output>) {
        let peer_isn = SeqNo::new(hs.isn as u32 & SEQ_MAX);
        let mss = (hs.mss as u32).min(self.mss);
        let flow_wnd = hs.flight_flag_size as u32;
        self.peer_id = hs.socket_id as u32;
        self.state = ConnState::Connected;
        self.post_connect(peer_isn, mss, flow_wnd, now_us);
        out.push(Output::Connected);
    }

    fn recv_ack(
        &mut self,
        asn: AckSeqNo,
        payload: crate::packet::AckPayload,
        now_us: u64,
        out: &mut Vec<Output>,
    ) {
        self.last_rsp_us = now_us;
        self.exp_count = 1;

        let ack_seq = payload.data_ack_seq;

        // Reject an ACK for data we never sent — a corrupt or hostile peer must
        // not be able to advance our send buffer past the write cursor.
        if ack_seq > self.snd_curr_seq.next() {
            self.state = ConnState::Closed;
            out.push(Output::Disconnected(DisconnectReason::PeerError));
            return;
        }

        let adv = ack_seq.offset_from(self.snd_last_ack).max(0) as usize;

        if let Some(full) = &payload.full {
            let rtt = full.rtt_us;
            let rtt_var = (rtt - self.rtt_us).abs() / 8;
            self.rtt_us = (self.rtt_us * 7 + rtt) / 8;
            self.rtt_var_us = (self.rtt_var_us * 3 + rtt_var) / 4;
            if full.avail_buf_pkts > 0 {
                self.flow_wnd = full.avail_buf_pkts as u32;
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
            out.push(Output::SendDatagram(self.enc.clone().freeze()));
        }
        // A light ACK carries only the acknowledgement point: it advances the
        // send buffer (below) but triggers no RTT, CC or ACK2 processing.

        if adv > 0 {
            self.snd_last_ack = ack_seq;
            self.snd_loss.remove_up_to(ack_seq.prev());
            if let Some(buf) = self.snd_buf.as_mut() { buf.ack(adv); }
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
    fn emit_ack(&mut self, now_us: u64, light: bool, out: &mut Vec<Output>) {
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
            out.push(Output::SendDatagram(self.enc.clone().freeze()));
            return;
        }

        match data_ack.cmp(&self.rcv_last_ack) {
            Ordering::Greater => {
                self.rcv_last_ack = data_ack;
                // Recycle the ring slots the application has already consumed.
                if let Some(buf) = self.rcv_buf.as_mut() {
                    buf.slide_window();
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
        let avail = self
            .rcv_buf
            .as_ref()
            .map_or(0, |b| b.avail_from(data_ack))
            .min(i32::MAX as usize) as i32;
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
        out.push(Output::SendDatagram(self.enc.clone().freeze()));
    }

    /// Send a NAK for a single contiguous range, used for immediate loss
    /// reporting the moment a gap is spotted in the data stream.
    fn emit_nak_range(&mut self, start: SeqNo, end: SeqNo, now_us: u64, out: &mut Vec<Output>) {
        self.enc.clear();
        codec::encode_nak(&[(start, end)], self.ts(now_us), self.peer_id, &mut self.enc);
        out.push(Output::SendDatagram(self.enc.clone().freeze()));
    }

    fn emit_nak(&mut self, now_us: u64, out: &mut Vec<Output>) {
        let max_words = (self.payload_size / 4) as usize;
        let words = self.rcv_loss.to_nak_payload(max_words);
        if words.is_empty() { return; }
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
        out.push(Output::SendDatagram(self.enc.clone().freeze()));
    }

    /// Try to pack one outbound data packet.
    ///
    /// `burst_end` is the maximum virtual send-time ceiling for this call.
    /// Callers pass `now_us + SYN_US` so that all packets due within the next
    /// SYN interval are batched in one loop.  This is necessary because tokio
    /// timers have ~1 ms granularity and cannot honour sub-millisecond
    /// `pkt_snd_period_us` values individually.
    fn pack_data(&mut self, now_us: u64, burst_end: u64, out: &mut Vec<Output>) -> bool {
        if burst_end < self.next_snd_us { return false; }

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
            // Copy the fields out to release the borrow before calling self.ts().
            let block = self
                .snd_buf
                .as_ref()
                .and_then(|b| b.read_at(off as usize))
                .map(|b| (b.boundary, b.in_order, b.msg_no, b.data.clone()));
            if let Some((boundary, in_order, msg_no, data)) = block {
                let hdr = codec::encode_data_header(
                    s, boundary, in_order, msg_no, self.ts(now_us), self.peer_id,
                );
                retransmit = Some((s, hdr, data));
                break;
            }
            // Names a block we no longer hold (e.g. a stale NAK) — discard it
            // and try the next entry rather than stalling the pacing loop.
        }

        let (seq, hdr_bytes, payload_bytes) = match retransmit {
            Some(v) => v,
            None => {
                // New data — this is what the congestion/flow window limits.
                let in_flight = self.snd_buf.as_ref().map_or(0, |b| b.in_flight());
                let max_flight = (self.cwnd.min(self.flow_wnd as f64)) as usize;
                if in_flight >= max_flight { return false; }

                self.snd_curr_seq = self.snd_curr_seq.next();
                let seq = self.snd_curr_seq;
                // Extract fields before releasing the mutable borrow so we can call self.ts() after.
                let (boundary, in_order, msg_no, data) = match self.snd_buf.as_mut().and_then(|b| b.read_next()) {
                    Some(block) => (block.boundary, block.in_order, block.msg_no, block.data.clone()),
                    None => {
                        self.snd_curr_seq = self.snd_curr_seq.prev();
                        return false;
                    }
                };
                let hdr = codec::encode_data_header(seq, boundary, in_order, msg_no, self.ts(now_us), self.peer_id);
                (seq, hdr, data)
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
        out.push(Output::SendDatagram(self.pkt_arena.split_to(total).freeze()));

        let len = payload_bytes.len();
        let ctx = self.cc_ctx(now_us);
        let o = self.cc.on_pkt_sent(seq, len, ctx);
        self.apply_cc(o);
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
            flow_wnd: self.flow_wnd as f64,
            syn_interval_us: SYN_US,
            now_us,
        }
    }

    fn apply_cc(&mut self, o: CcOutput) {
        if o.is_noop() { return; }
        self.snd_period_us = o.pkt_snd_period_us.max(1.0);
        self.cwnd = o.cwnd.max(2.0);
    }

    fn nak_int_us(&self) -> u64 {
        (4 * self.rtt_us as u64).max(SYN_US as u64)
    }

    fn ts(&self, now_us: u64) -> u32 {
        now_us as u32
    }
}
