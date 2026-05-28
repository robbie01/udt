use bytes::{Bytes, BytesMut};
use crate::codec;
use crate::congestion::{CcContext, CcOutput, CongestionControl};
use crate::congestion::udt_cc::UdtCc;
use crate::handshake::{req_type, Handshake, SOCK_DGRAM, UDT_VERSION};
use crate::loss_list::{RcvLossList, SndLossList};
use crate::ack_window::AckWindow;
use crate::time_window::PktTimeWindow;
use crate::send_buffer::SendBuffer;
use crate::recv_buffer::RecvBuffer;
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
    ack_seq: AckSeqNo,
    rcv_curr_seq: SeqNo,
    pkt_count: u32,

    // Staging queue for messages extracted from recv_buffer
    ready_msgs: Vec<Bytes>,

    next_ack_us: u64,
    next_nak_us: u64,
    next_snd_us: u64,
    last_rsp_us: u64,
    exp_count: u32,

    rtt_us: i32,
    rtt_var_us: i32,

    cc: Box<dyn CongestionControl>,
    snd_period_us: f64,
    cwnd: f64,

    rcv_tw: PktTimeWindow,
    snd_tw: PktTimeWindow,

    enc: BytesMut, // pre-allocated encode buffer
}

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
            ack_seq: AckSeqNo::new(0),
            rcv_curr_seq: SeqNo::new(0),
            pkt_count: 0,
            ready_msgs: Vec::new(),
            next_ack_us: now_us + SYN_US as u64,
            next_nak_us: now_us + SYN_US as u64 * 4,
            next_snd_us: now_us,
            last_rsp_us: now_us,
            exp_count: 1,
            rtt_us: 10_000,
            rtt_var_us: 0,
            cc: Box::new(UdtCc::new()),
            snd_period_us: 1.0,
            cwnd: 16.0,
            rcv_tw: PktTimeWindow::new(),
            snd_tw: PktTimeWindow::new(),
            enc: BytesMut::with_capacity(DEFAULT_MSS as usize),
        }
    }

    fn post_connect(&mut self, peer_isn: SeqNo, mss: u32, flow_wnd: u32, now_us: u64) {
        self.mss = mss;
        self.payload_size = mss.saturating_sub(IP_AND_UDP_OVERHEAD + UDT_HEADER_SIZE as u32);
        self.flow_wnd = flow_wnd;
        // Start one before ISN so first pack_data increments to ISN (matching C++ behaviour).
        self.snd_curr_seq = self.local_isn.prev();
        self.snd_last_ack = self.local_isn.prev();
        self.rcv_last_ack = peer_isn;
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

        // Packet pacing
        while now_us >= self.next_snd_us {
            if !self.pack_data(now_us, out) {
                // Nothing to send right now; back off to avoid spin-looping.
                self.next_snd_us = now_us + SYN_US as u64;
                break;
            }
        }

        // Graceful half-close: shut down once the send buffer drains.
        if self.snd_half_closed && self.snd_buf_is_empty() {
            self.shutdown(now_us, out);
            return;
        }

        // ACK
        if now_us >= self.next_ack_us {
            self.emit_ack(now_us, out);
            self.next_ack_us = now_us + SYN_US as u64;
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

            let ctx = self.cc_ctx(now_us);
            let o = self.cc.on_timeout(ctx);
            self.apply_cc(o);
            self.exp_count += 1;

            // Reset last_rsp_us so this EXP interval does not re-fire immediately
            // on the next on_timer call (C++: `m_ullLastRspTime = currtime`).
            self.last_rsp_us = now_us;

            // Keep-alive to prevent peer's EXP
            self.enc.clear();
            codec::encode_keepalive(self.ts(now_us), self.peer_id, &mut self.enc);
            out.push(Output::SendDatagram(self.enc.clone().freeze()));
        }
    }

    pub fn send_msg(&mut self, payload: &[u8], ttl_ms: Option<u32>, in_order: bool, now_us: u64, out: &mut Vec<Output>) {
        if !matches!(self.state, ConnState::Connected) { return; }
        if let Some(buf) = self.snd_buf.as_mut() {
            let _ = buf.add(payload, ttl_ms, in_order, now_us);
        }
        // Allow immediate packing even if the pacing timer was backed off due to an empty buffer.
        self.next_snd_us = self.next_snd_us.min(now_us);
        while now_us >= self.next_snd_us {
            if !self.pack_data(now_us, out) { break; }
        }
    }

    /// Extract the next ready message. Returns None if none available.
    pub fn recv_msg(&mut self) -> Option<Bytes> {
        if !self.ready_msgs.is_empty() {
            return Some(self.ready_msgs.remove(0));
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
        // Rendezvous: data means peer completed — try to complete too
        if let ConnState::Connecting { mode: ConnMode::Rendezvous, last_peer_hs, .. } = &self.state {
            if let Some(hs) = last_peer_hs.clone() {
                self.do_post_connect(hs, now_us, out);
            }
            if !matches!(self.state, ConnState::Connected) { return; }
        }
        if !matches!(self.state, ConnState::Connected) { return; }

        self.last_rsp_us = now_us;
        self.exp_count = 1;

        let seq = header.seq_no;

        // Gap detection: sequences we haven't received between rcv_curr_seq and this packet
        let expected_next = self.rcv_curr_seq.next();
        if seq > expected_next {
            self.rcv_loss.insert(expected_next, seq.prev());
        }
        self.rcv_loss.remove(seq);

        if let Some(buf) = self.rcv_buf.as_mut() {
            let off = seq.offset_from(self.rcv_last_ack);
            if off >= 0 {
                buf.add(seq, payload.clone(), header.boundary, header.msg_no, header.in_order);
                // Drain complete messages into staging queue
                while let Some(msg) = buf.read_msg() {
                    self.ready_msgs.push(msg);
                    out.push(Output::DataReady);
                }
            }
        }

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

        self.pkt_count += 1;
        if self.pkt_count >= LIGHT_ACK_INTERVAL {
            self.emit_ack(now_us, out);
        }
    }

    fn recv_ctrl(&mut self, body: ControlBody, now_us: u64, out: &mut Vec<Output>) {
        match body {
            ControlBody::Handshake(hs) => self.recv_handshake(hs, now_us, out),
            ControlBody::KeepAlive => {
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

                // RDVZ_DONE (-2): peer already completed; complete on our side too.
                //
                // This happens when we were the slow side: peer received our -1,
                // completed, and is now sending RDVZ_DONE to acknowledge our late -1
                // retransmissions.  Use the cached peer handshake for post_connect.
                if recv_req_type == req_type::RDVZ_DONE {
                    let cached_hs = if let ConnState::Connecting { last_peer_hs, .. } = &self.state {
                        last_peer_hs.clone()
                    } else { None };
                    if let Some(peer_hs) = cached_hs {
                        self.do_post_connect(peer_hs, now_us, out);
                    }
                    // If no cached hs yet, drop the packet; peer will retransmit RDVZ_DONE.
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
                // Already connected; if rendezvous peer retransmits, ack with -2
                if hs.req_type != req_type::RDVZ_DONE => {
                    let mut resp = hs.clone();
                    resp.req_type = req_type::RDVZ_DONE;
                    resp.socket_id = self.socket_id as i32;
                    self.enc.clear();
                    codec::encode_handshake(&resp, self.ts(now_us), hs.socket_id as u32, &mut self.enc);
                    out.push(Output::SendDatagram(self.enc.clone().freeze()));
                }
            _ => {}
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
        let adv = ack_seq.offset_from(self.snd_last_ack).max(0) as usize;

        if let Some(full) = &payload.full {
            let rtt = full.rtt_us;
            let rtt_var = (rtt - self.rtt_us).abs() / 8;
            self.rtt_us = (self.rtt_us * 7 + rtt) / 8;
            self.rtt_var_us = (self.rtt_var_us * 3 + rtt_var) / 4;
            if full.avail_buf_pkts > 0 {
                self.flow_wnd = full.avail_buf_pkts as u32;
            }
            let ctx = self.cc_ctx_ex(now_us, full.rcv_rate_pps as u32, full.bandwidth_pps as u32);
            let o = self.cc.on_ack(ack_seq, ctx);
            self.apply_cc(o);
        } else {
            let ctx = self.cc_ctx(now_us);
            let o = self.cc.on_ack(ack_seq, ctx);
            self.apply_cc(o);
        }

        if adv > 0 {
            self.snd_last_ack = ack_seq;
            self.snd_loss.remove_up_to(ack_seq.prev());
            if let Some(buf) = self.snd_buf.as_mut() { buf.ack(adv); }
        }

        self.enc.clear();
        codec::encode_ack2(asn, self.ts(now_us), self.peer_id, &mut self.enc);
        out.push(Output::SendDatagram(self.enc.clone().freeze()));
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
        if let Some((rtt_us, _)) = self.ack_win.acknowledge(asn, now_us) {
            let rtt_var = (rtt_us as i32 - self.rtt_us).abs() / 8;
            self.rtt_us = (self.rtt_us * 7 + rtt_us as i32) / 8;
            self.rtt_var_us = (self.rtt_var_us * 3 + rtt_var) / 4;
        }
    }

    fn emit_ack(&mut self, now_us: u64, out: &mut Vec<Output>) {
        let data_ack = self.rcv_curr_seq.next();
        let avail = self.rcv_buf.as_ref().map(|b| b.avail_pkts() as i32).unwrap_or(0);
        let is_light = self.pkt_count == 0;
        let full = if is_light { None } else {
            Some(AckFull {
                rtt_us: self.rtt_us,
                rtt_var_us: self.rtt_var_us,
                avail_buf_pkts: avail,
                rcv_rate_pps: self.rcv_tw.pkt_rcv_speed() as i32,
                bandwidth_pps: self.rcv_tw.bandwidth() as i32,
            })
        };
        let asn = self.ack_seq;
        self.ack_win.store(asn, data_ack, now_us);
        self.ack_seq = self.ack_seq.next();
        self.pkt_count = 0;
        self.rcv_last_ack = data_ack;
        self.enc.clear();
        codec::encode_ack(asn, data_ack, full.as_ref(), self.ts(now_us), self.peer_id, &mut self.enc);
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

    fn pack_data(&mut self, now_us: u64, out: &mut Vec<Output>) -> bool {
        if now_us < self.next_snd_us { return false; }
        let in_flight = self.snd_buf.as_ref().map(|b| b.in_flight()).unwrap_or(0);
        let max_flight = (self.cwnd.min(self.flow_wnd as f64)) as usize;
        if in_flight >= max_flight { return false; }

        let (seq, hdr_bytes, payload_bytes) = if let Some(s) = self.snd_loss.pop_front() {
            // Retransmit
            let off = s.offset_from(self.snd_last_ack);
            if off < 0 { return self.pack_data(now_us, out); } // already acked
            let (hdr, data) = match self.snd_buf.as_ref().and_then(|b| b.read_at(off as usize)) {
                Some(block) => {
                    let hdr = codec::encode_data_header(s, block.boundary, block.in_order, block.msg_no, self.ts(now_us), self.peer_id);
                    (hdr, block.data.clone())
                }
                None => return false,
            };
            (s, hdr, data)
        } else {
            // New data
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
        };

        let mut pkt = BytesMut::with_capacity(16 + payload_bytes.len());
        pkt.extend_from_slice(&hdr_bytes);
        pkt.extend_from_slice(&payload_bytes);
        out.push(Output::SendDatagram(pkt.freeze()));

        let len = payload_bytes.len();
        let ctx = self.cc_ctx(now_us);
        let o = self.cc.on_pkt_sent(seq, len, ctx);
        self.apply_cc(o);
        self.snd_tw.on_pkt_arrival(now_us);
        self.next_snd_us = now_us + self.snd_period_us.max(1.0) as u64;
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
