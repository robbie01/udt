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
use crate::transmit::TransmitBuf;
use bytes::Bytes;

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

/// Received ranges reported in one ACK, at most.
///
/// The MTU bounds this too, but a cap keeps the cost of building and parsing an
/// ACK flat when the path is badly fragmented. Truncation is safe: the ranges
/// are advisory, the ones nearest the acknowledgement point are kept, and
/// whatever is dropped is reported by a later ACK.
const MAX_SACK_RANGES: usize = 32;

/// How often an otherwise idle connection sends a keep-alive.
///
/// Its job is to stop a NAT or stateful firewall forgetting the mapping, and
/// those hold UDP for tens of seconds — 30 s is the usual conservative figure.
/// Five seconds sits well inside that, and four missed in a row is what
/// [`EXP_HARD_TIMEOUT_US`] then treats as a dead peer.
///
/// It used to ride the retransmission timer, which meant an idle connection
/// exchanged **96 packets a second in each direction**: EXP fired at its floor,
/// sent a keep-alive, and the keep-alive reset the peer's `exp_count`, pinning
/// both ends at the floor forever. That is about a thousand times more than the
/// job needs, and a peer-to-peer process holding many idle connections pays it
/// per connection.
const KEEPALIVE_US: u64 = 5_000_000;

const DEFAULT_SND_BUF: usize = 8192;
const DEFAULT_RCV_BUF: usize = 8192;
const SYN_US: u32 = 10_000;
const LIGHT_ACK_INTERVAL: u32 = 64;
const EXP_MAX: u32 = 16;
/// Per-count minimum EXP interval (µs).  Mirrors C++ `m_ullMinExpInt = 300 000 µs`.
/// Expiries spent probing the tail before assuming the whole window is lost.
///
/// The escalation is really "has the peer stopped hearing us at all", and
/// `exp_count` is the only measure of that available -- it resets on any packet
/// from the peer. With the interval floored at one control period, one expiry
/// is 10 ms, so a single one is far too little to conclude that.
const PROBE_EXPIRIES: u32 = 3;

/// Floor on the repeat-NAK interval, in microseconds.
///
/// A floor exists so a noisy round-trip estimate cannot drive the timer down to
/// nothing, and so it cannot ask for a wakeup finer than the driver can
/// deliver. One millisecond is roughly tokio's timer granularity, so below this
/// the number would be a fiction.
///
/// Deliberately **not** [`SYN_US`], which had been serving as the floor: that is
/// how often UDT *acknowledges*, and re-asking about a gap is not an
/// acknowledgement. A lost NAK cost 10 ms to re-ask on a path whose round trip
/// was 200 µs — fifty round trips for a question answered in one.
///
/// This applies to the NAK timer only. The retransmission timeout has to respect
/// how long a peer may take to acknowledge, and shortening it broke a real peer:
/// see [`Connection::exp_int_us`].
const MIN_RECOVERY_US: u64 = 1_000;
/// Largest round-trip time a peer may report, in microseconds.
///
/// Ten seconds is far beyond any working path, and the value drives the
/// retransmission timer, so leaving it unbounded lets a peer stall the
/// connection by claiming an enormous one.
const MAX_REPORTED_RTT_US: i32 = 10_000_000;

/// Expiry firings with no data acknowledged before the path is declared
/// unusable.
const BLACK_HOLE_EXP_COUNT: u32 = 8;

/// How long that has to have been going on, as well.
///
/// The count alone used to imply a duration, back when firings were at least a
/// control interval apart. They are now [`MIN_RECOVERY_US`] apart on a fast
/// path, which turns eight of them into some tens of milliseconds — far too
/// eager a moment to declare a path broken and tear the connection down. So the
/// wall clock is checked too, and the count is left to mean what it says.
const BLACK_HOLE_MIN_US: u64 = 500_000;

/// After EXP_MAX expirations the connection is only torn down once it has been
/// silent for this long in total.
///
/// Four [`KEEPALIVE_US`] intervals. The two have to be chosen together: an idle
/// peer is only heard from once per keep-alive, so a timeout shorter than that
/// tears down connections that are working perfectly well. The reference uses
/// 5 s here and keeps alive far more often, which is the same relationship at a
/// much higher cost.
const EXP_HARD_TIMEOUT_US: u64 = 4 * KEEPALIVE_US;
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
///
/// Datagrams to send are not events. They are written into the
/// [`TransmitBuf`](crate::TransmitBuf) those calls take, which keeps the bytes
/// out of an enum the caller has to match on and lets them be built directly in
/// reusable memory.
pub enum Event {
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
    /// Nothing this side sent ever reached the peer, though the peer is
    /// answering.
    ///
    /// Almost always the path cannot carry packets of the negotiated size:
    /// control packets are small and get through, so the connection completes
    /// its handshake, and then every full-size data packet is silently
    /// discarded somewhere in the middle. Retry with a smaller MTU.
    PathMtu,
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
    /// Packets the peer reported receiving out of order, above the
    /// acknowledgement point. Tracked but not yet discounted from the window —
    /// see `pack_data`.
    pub snd_sacked_len: usize,
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
    /// Sequences above `snd_last_ack` the peer has reported receiving.
    ///
    /// Held so they can be discounted from the in-flight count: they are not on
    /// the path any more, so letting them occupy the congestion window stalls
    /// the sender behind a hole it has already worked around. Entries are
    /// dropped as `snd_last_ack` advances past them. Empty against any peer that
    /// does not send selective acknowledgements.
    snd_sacked: SndLossList,
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
    /// When an idle connection should next remind the path it exists.
    next_keepalive_us: u64,
    next_snd_us: u64,
    last_rsp_us: u64,
    /// Expiry firings since the last time an acknowledgement moved forward.
    ///
    /// Distinct from `exp_count`, which any packet from the peer resets. A peer
    /// whose keep-alives arrive while our data does not would hold `exp_count`
    /// at 1 forever, so on its own it cannot notice a path that carries small
    /// packets and drops large ones.
    exp_without_progress: u32,
    /// When that run of firings began, so the black-hole check can ask how long
    /// it has really been rather than inferring it from a count of firings
    /// whose spacing now depends on the path.
    no_progress_since_us: Option<u64>,
    /// Whether the peer has ever acknowledged a single byte of data.
    data_ever_acked: bool,
    /// When the last full ACK was emitted, for re-ACK rate limiting.
    last_ack_us: u64,
    exp_count: u32,

    /// Earliest time we may tell the peer the path is congested again, and the
    /// last time we acted on being told. Both are one round trip apart at most:
    /// congestion is a property of the path over an RTT, so reacting to every
    /// marked packet in a window would cut the rate once per packet.
    next_cwarn_us: u64,
    last_cwarn_react_us: u64,

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
    /// Whether [`rtt_us`](Self::rtt_us) has ever held a measurement rather than
    /// the opening guess.
    rtt_sampled: bool,

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
}

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
            snd_sacked: SndLossList::new(LOSS_LIST_RESERVE),
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
            next_keepalive_us: now_us + KEEPALIVE_US,
            next_snd_us: now_us,
            last_rsp_us: now_us,
            exp_without_progress: 0,
            no_progress_since_us: None,
            data_ever_acked: false,
            last_ack_us: now_us,
            exp_count: 1,
            next_cwarn_us: 0,
            last_cwarn_react_us: 0,
            snd_last_ack2: AckSeqNo::new(0),
            snd_last_ack2_us: now_us,
            // C++ initialises the delivery-rate estimate to 16 pkt/s and the
            // bandwidth estimate to 1 pkt/s before any samples arrive.
            delivery_rate_pps: 16,
            bandwidth_pps: 1,
            rtt_us: 10_000,
            rtt_var_us: 0,
            rtt_sampled: false,
            cc: CcKind::default().build(),
            snd_period_us: 1.0,
            cwnd: 16.0,
            cc_ack_period_us: None,
            cc_ack_interval_pkts: None,
            cc_rto_us: None,
            rcv_tw: PktTimeWindow::new(),
            snd_tw: PktTimeWindow::new(),
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
        self.snd_sacked = SndLossList::new(LOSS_LIST_RESERVE);
        self.rcv_loss = RcvLossList::new(LOSS_LIST_RESERVE);
        let ctx = self.cc_ctx(now_us);
        let out = self.cc.init(ctx);
        self.apply_cc(out);
        self.last_rsp_us = now_us;
        self.last_ack_us = now_us;
        self.snd_last_ack2_us = now_us;
        self.next_ack_us = now_us + SYN_US as u64;
        self.next_nak_us = now_us + self.nak_int_us();
        self.next_keepalive_us = now_us + KEEPALIVE_US;
        self.next_snd_us = now_us;
    }

    // ── Entry points ──────────────────────────────────────────────────────

    /// Feeds one UDP payload received from the peer.
    ///
    /// Resulting work is appended to `out`; see [`Event`]. Reuse the same
    /// `Vec` across calls to avoid allocating. Datagrams that are malformed or
    /// addressed elsewhere are ignored.
    pub fn on_datagram(
        &mut self,
        datagram: Bytes,
        now_us: u64,
        tx: &mut TransmitBuf,
        out: &mut Vec<Event>,
    ) {
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
            Packet::Data { header, payload } => self.recv_data(header, payload, now_us, tx, out),
            Packet::Control { header: _, body } => self.recv_ctrl(body, now_us, tx, out),
        }
    }

    /// Advances time, appending any resulting work to `out`.
    ///
    /// Call this once at [`next_deadline_us`](Self::next_deadline_us), and
    /// again after every change to the connection, since sending or receiving
    /// can move that deadline. Calling it early is harmless.
    pub fn on_timer(&mut self, now_us: u64, tx: &mut TransmitBuf, out: &mut Vec<Event>) {
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
                    tx.push(|dst| codec::encode_handshake(&req, self.ts(now_us), 0, dst));
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
                if !self.pack_data(now_us, burst_end, tx) {
                    // Nothing to send (cwnd full, no data, or not yet time).
                    // Back off to avoid a busy-wait spin on the next timer tick.
                    self.next_snd_us = now_us + SYN_US as u64;
                    break;
                }
            }
        }

        // Graceful half-close: shut down once the send buffer drains.
        if self.snd_half_closed && self.snd_buf_is_empty() {
            self.shutdown(now_us, tx, out);
            return;
        }

        // Keep-alive, on its own schedule rather than the retransmission timer's.
        //
        // Its only job is to stop a NAT or stateful firewall forgetting the
        // mapping, which wants seconds. Riding EXP meant an idle pair exchanged
        // 96 packets a second in each direction, because each keep-alive reset
        // the peer's `exp_count` and pinned both ends at the timer's floor.
        //
        // Serviced here rather than inside the expiry branch: this deadline is
        // reported by `next_deadline_us`, so a caller wakes for it, and leaving
        // it unserviced when the expiry timer is not also due means it is never
        // re-armed — which stalls a virtual clock outright and spins a real one.
        if now_us >= self.next_keepalive_us {
            self.next_keepalive_us = now_us + KEEPALIVE_US;
            if self.snd_buf_is_empty() {
                tx.push(|dst| codec::encode_keepalive(self.ts(now_us), self.peer_id, dst));
            }
        }

        // ACK — full ACK on the SYN timer, cheap light ACKs in between when the
        // peer is sending fast enough to outrun it (C++ checkTimers).
        if now_us >= self.next_ack_us
            || self.cc_ack_interval_pkts.is_some_and(|n| self.pkt_count >= n)
        {
            self.emit_ack(now_us, false, tx);
            // An acknowledgement point the peer has not confirmed is retried on
            // the round trip rather than on the control interval.
            //
            // `emit_ack` has a rule for exactly this — re-announce an unchanged
            // point after `RTT + 4·RTTVar` — and it was dead code, because
            // nothing called `emit_ack` again until this timer came round ten
            // milliseconds later. So a lost ACK shut the sender's window for a
            // control interval and the expiry timer was what eventually reopened
            // it: 10.4 ms of a 16.6 ms transfer, the last stall in the timeline.
            //
            // It costs no extra reverse traffic. Acknowledgements per forward
            // packet are unchanged at every loss rate measured, because the
            // transfer finishes sooner by more than the added cadence spends.
            self.next_ack_us = now_us
                + if self.rcv_last_ack > self.rcv_last_ack_ack {
                    let unconfirmed = (self.rtt_us + 4 * self.rtt_var_us).max(0) as u64;
                    self.ack_int_us().min(unconfirmed.max(MIN_RECOVERY_US))
                } else {
                    self.ack_int_us()
                };
            self.pkt_count = 0;
            self.light_ack_count = 1;
        } else if self.pkt_count >= LIGHT_ACK_INTERVAL * self.light_ack_count {
            self.emit_ack(now_us, true, tx);
            self.light_ack_count += 1;
        }

        // NAK
        if now_us >= self.next_nak_us && !self.rcv_loss.is_empty() {
            self.emit_nak(now_us, tx);
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

            if !self.snd_buf_is_empty() {
                self.exp_without_progress += 1;
                self.no_progress_since_us.get_or_insert(now_us);
            }

            // A peer that answers while nothing we send arrives means the path
            // carries small packets and drops large ones -- so the handshake
            // completed and every data packet since has vanished. Without this
            // the connection never fails: the peer's keep-alives keep resetting
            // `exp_count`, so the hard timeout is never reached and the sender
            // retransmits into the void indefinitely.
            let stalled_for =
                self.no_progress_since_us.map_or(0, |since| now_us.saturating_sub(since));
            if self.exp_without_progress >= BLACK_HOLE_EXP_COUNT
                && stalled_for >= BLACK_HOLE_MIN_US
                && !self.data_ever_acked
                && !self.snd_buf_is_empty()
            {
                // The path answers but carries nothing we send, so the packets
                // are too big for it. Try a smaller one before giving up.
                if self.shrink_path(now_us, tx) {
                    self.exp_count = 1;
                    self.exp_without_progress = 0;
                    self.no_progress_since_us = None;
                    self.last_rsp_us = now_us;
                    return;
                }
                self.state = ConnState::Closed;
                out.push(Event::Disconnected(DisconnectReason::PathMtu));
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
                    if self.exp_count <= PROBE_EXPIRIES {
                        // First expiry since the last forward progress: resend
                        // only the final packet, to ask the peer where it is.
                        //
                        // Almost always the reason nothing is moving is that
                        // the tail was lost -- a gap anywhere else is repaired
                        // by the NAK the following packet triggers, and only
                        // the last packet has nothing following it. One probe
                        // draws out an acknowledgement or a NAK, and ordinary
                        // recovery takes it from there.
                        //
                        // Assuming the whole window is lost instead costs real
                        // traffic: at 5% loss that put 6037 packets on the wire
                        // for 3.2 MB where 2500 sufficed.
                        self.snd_loss.insert(self.snd_curr_seq, self.snd_curr_seq);
                    } else {
                        // Still nothing after a second expiry, so the peer has
                        // genuinely stopped hearing us: resend everything.
                        self.snd_loss.insert(self.snd_last_ack, self.snd_curr_seq);
                    }
                }
                // A probe is not a congestion signal.
                //
                // `on_timeout` collapses the window, and while the tail is
                // merely being probed there is no evidence the path is
                // congested -- one packet went missing and we are asking about
                // it. Treating every probe as congestion costs real recovery
                // speed now that expiries are 10 ms apart rather than 300: it
                // measured 15% slower under 5% loss. RFC 8985 draws the same
                // line for TCP's tail loss probe.
                if self.exp_count > PROBE_EXPIRIES {
                    let ctx = self.cc_ctx(now_us);
                    let o = self.cc.on_timeout(ctx);
                    self.apply_cc(o);
                }
                // Restart transmission immediately rather than waiting a tick.
                self.next_snd_us = self.next_snd_us.min(now_us);
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
        tx: &mut TransmitBuf,
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
            if !self.pack_data(now_us, burst_end, tx) {
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
                t = t.min(self.last_rsp_us + self.exp_int_us());
                Some(t.min(self.next_keepalive_us))
            }
        }
    }

    /// Closes immediately, telling the peer and discarding anything unsent.
    ///
    /// Use [`half_close`](Self::half_close) to let queued data drain first.
    pub fn shutdown(&mut self, now_us: u64, tx: &mut TransmitBuf, out: &mut Vec<Event>) {
        if !matches!(self.state, ConnState::Connected) {
            return;
        }
        tx.push(|dst| codec::encode_shutdown(self.ts(now_us), self.peer_id, dst));
        self.state = ConnState::Closed;
        out.push(Event::Disconnected(DisconnectReason::LocalClose));
    }

    /// Closes once everything already queued has been acknowledged.
    ///
    /// Returns without closing if data is still outstanding; the shutdown then
    /// happens inside a later [`on_timer`](Self::on_timer). Incoming messages
    /// keep arriving until then.
    pub fn half_close(&mut self, now_us: u64, tx: &mut TransmitBuf, out: &mut Vec<Event>) {
        if !matches!(self.state, ConnState::Connected) {
            return;
        }
        if self.snd_buf.as_ref().map(|b| b.is_empty()).unwrap_or(true) {
            self.shutdown(now_us, tx, out);
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
            snd_sacked_len: self.snd_sacked.len(),
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

    /// Panics unless the loss lists still hold the shape the rest of the code
    /// reads them for: sorted by start and free of overlaps.
    ///
    /// For the fuzz targets, which call it after every step. Nothing in normal
    /// operation should need to ask.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn assert_loss_lists_well_formed(&self) {
        assert!(
            crate::loss_list::is_sorted_disjoint(self.rcv_loss.ranges_snapshot()),
            "receiver loss list is not sorted and disjoint: {:?}",
            self.rcv_loss.ranges_snapshot()
        );
        assert!(
            crate::loss_list::is_sorted_disjoint(self.snd_loss.ranges_snapshot()),
            "sender loss list is not sorted and disjoint: {:?}",
            self.snd_loss.ranges_snapshot()
        );
    }

    /// Halve the packet size and start the queued data again, for a path that
    /// answers control packets but swallows full-size ones.
    ///
    /// Returns whether it was worth trying. `false` means give up: either there
    /// is no room left to shrink into, or the data no longer fits.
    ///
    /// Only reachable while `data_ever_acked` is false — nothing this side sent
    /// has ever arrived — which is what makes restarting safe. Nothing the peer
    /// has delivered to its application can be disturbed, because it has
    /// delivered nothing.
    ///
    /// The sequence numbers already spent are the problem, not the data. Blocks
    /// are chunked at [`SendBuffer::add`] time and one block is one sequence
    /// number, so a smaller packet size means different blocks and different
    /// numbering. The peer is therefore told to skip everything already
    /// numbered, with the `MsgDrop` it already understands — otherwise the first
    /// small packet to arrive would open a gap below it that is NAKed forever.
    fn shrink_path(&mut self, now_us: u64, tx: &mut TransmitBuf) -> bool {
        let reduced = (self.mss / 2).max(MIN_MSS);
        if reduced >= self.mss {
            return false; // already as small as this will go
        }
        let payload_size = reduced.saturating_sub(IP_AND_UDP_OVERHEAD + UDT_HEADER_SIZE as u32);
        if payload_size == 0 {
            return false;
        }

        let Some(buf) = self.snd_buf.as_mut() else { return false };
        // Both numbers have to survive the rebuild. Sequence numbering continues
        // past what the peer is told to skip, and *message* numbering continues
        // too: `SendBuffer::new` would restart it at zero, handing a number the
        // peer has just been told to drop straight back to a live message, which
        // it would then discard as already retired.
        let abandoned_msg = buf.read_at(0).map(|b| b.msg_no);
        let resume_msg = buf.next_msg_no();
        let messages = buf.drain_messages();

        // Retire the range the peer must never wait for. Sent before the buffer
        // is rebuilt, while the numbering it refers to is still the live one.
        let (first, last) = (self.snd_last_ack, self.snd_curr_seq);
        if last >= first {
            // Names a message number that is genuinely being abandoned. The
            // sequence range is what does the work -- `drop_range` at the peer
            // covers every message in it -- but the number must not be one that
            // is about to be reused.
            let msg_no = abandoned_msg.unwrap_or(resume_msg);
            tx.push(|dst| {
                codec::encode_msg_drop(msg_no, first, last, self.ts(now_us), self.peer_id, dst)
            });
        }
        self.snd_loss.remove_range(first, last);
        self.snd_sacked.remove_up_to(last);

        self.mss = reduced;
        self.payload_size = payload_size;
        let mut rebuilt = SendBuffer::new(DEFAULT_SND_BUF, payload_size as usize);
        rebuilt.resume_msg_no_at(resume_msg);
        for (payload, ttl_ms, in_order) in messages {
            if rebuilt.add(payload, ttl_ms, in_order, now_us).is_err() {
                // The same bytes need more blocks at a smaller size, and no
                // longer fit. Failing here is honest; silently dropping a
                // message the application handed us is not.
                return false;
            }
        }
        self.snd_buf = Some(rebuilt);

        // Numbering continues forward from what the peer was told to skip.
        self.snd_last_ack = last.next();
        self.snd_curr_seq = last;
        self.next_snd_us = now_us;
        true
    }

    /// Report that a datagram arrived marked as having passed through
    /// congestion, and tell the peer so it can slow down.
    ///
    /// The IO layer calls this: ECN lives in the IP header, which a sans-IO
    /// protocol never sees. Pass `true` only for the CE codepoint — ECT(0) and
    /// ECT(1) merely say the sender asked for marking, and reacting to those
    /// would throttle every connection that opted in.
    ///
    /// This is a *signal to the peer*, not a brake on this side. The marking
    /// happened on the path carrying data towards us, and it is the peer's
    /// sending rate that needs to come down; ours is governed by whatever the
    /// other direction reports.
    ///
    /// Wire-compatible: it emits UDT's existing `CongestionWarning`, which the
    /// reference implementation already understands. Rate-limited to one per
    /// round trip, since congestion is a property of a path over an RTT and a
    /// marked window would otherwise produce a warning per packet.
    pub fn congestion_experienced(&mut self, now_us: u64, tx: &mut TransmitBuf) {
        if !matches!(self.state, ConnState::Connected) || now_us < self.next_cwarn_us {
            return;
        }
        let gap = (self.rtt_us.max(0) as u64).max(MIN_RECOVERY_US);
        self.next_cwarn_us = now_us + gap;
        let (ts, peer) = (self.ts(now_us), self.peer_id);
        tx.push(|dst| {
            codec::encode_control(
                crate::packet::ControlType::CongestionWarning,
                0,
                ts,
                peer,
                &[0u8; 4],
                dst,
            )
        });
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
        tx: &mut TransmitBuf,
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
            self.emit_nak_range(expected_next, seq.prev(), now_us, tx);
        }
        // Filling a hole is the one arrival that can move the acknowledgement
        // point a long way, so it is worth saying so at once.
        //
        // A full ACK blocked by that hole still resets the ACK timer and clears
        // the packet counter, as though it had reported something. So when the
        // hole is filled moments later there is no light ACK due and no full ACK
        // for another control interval, while the point could have jumped past
        // everything queued behind it. Both ends wait on that: the sender's
        // window cannot open, and ordered delivery holds every completed message
        // above the point. Measured as a 9.4 ms stall in a 16 ms transfer, with
        // 63 packets acknowledgeable and a packet count of 1.
        if self.rcv_loss.remove(seq) {
            self.next_ack_us = self.next_ack_us.min(now_us);
        }

        // Forwards only. This used to also take `seq` whenever the cursor read
        // zero, from when zero meant "nothing received yet" — but `post_connect`
        // has set the cursor to a real sequence long before any data arrives
        // here, and zero is a sequence like any other. A peer that puts the
        // wrap a few packets into the connection could reach it, and dragging
        // the cursor backwards re-opens gaps the loss list already holds.
        if seq > self.rcv_curr_seq {
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

    fn recv_ctrl(
        &mut self,
        body: ControlBody,
        now_us: u64,
        tx: &mut TransmitBuf,
        out: &mut Vec<Event>,
    ) {
        match body {
            ControlBody::Handshake(hs) => self.recv_handshake(hs, now_us, tx, out),
            ControlBody::KeepAlive => {
                // A keep-alive during a rendezvous handshake means the peer has
                // already completed on its side, so we can too (C++ treats a
                // data *or* keep-alive packet as an implicit completion).
                self.try_rendezvous_complete(now_us, out);
                self.last_rsp_us = now_us;
                self.exp_count = 1;
            }
            ControlBody::Ack(asn, payload) => self.recv_ack(asn, payload, now_us, tx),
            ControlBody::Nak(nak) => self.recv_nak(nak, now_us),
            ControlBody::Ack2(asn) => self.recv_ack2(asn, now_us),
            ControlBody::Shutdown => {
                self.state = ConnState::Closed;
                out.push(Event::Disconnected(DisconnectReason::Shutdown));
            }
            ControlBody::MsgDrop { msg_no, first, last } => {
                // Both ends of the range come off the wire, and the three
                // things below each read it their own way. Measured as
                // distances from the cursor rather than compared against it:
                // a peer can name sequences anywhere in the space, and
                // `SeqNo`'s ordering means nothing beyond half of it.
                //
                // What survives is a range that runs forwards and lies within
                // the ring's reach. A range running backwards is not a range —
                // the buffer would drop nothing, the loss list would trim by
                // the reversed pair, and the cursor would sit still. And
                // nothing beyond the ring can be held, so a range running past
                // it is honoured only as far as the ring reaches: stepping the
                // cursor out there would make the next arrival look like a gap
                // of half the sequence space.
                let reach = self.rcv_buf.as_ref().map_or(0, |b| b.capacity() as i32);
                let from = first.offset_from(self.rcv_curr_seq).max(-reach);
                let to = last.offset_from(self.rcv_curr_seq).min(reach);
                if to < from {
                    return;
                }
                let (first, last) = (self.rcv_curr_seq.shift(from), self.rcv_curr_seq.shift(to));
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
                // Ignored for the same reason as an out-of-range ACK: it is
                // unauthenticated and fatal, which is a one-packet kill for
                // anyone who can guess the socket identifier. The reference
                // never sends it, and a peer that genuinely cannot continue has
                // `Shutdown` and, failing that, our expiry timer.
                self.last_rsp_us = now_us;
                self.exp_count = 1;
            }
            ControlBody::CongestionWarning => {
                self.last_rsp_us = now_us;
                self.exp_count = 1;
                // Once per round trip, not once per warning. A peer marking a
                // whole window would otherwise cut the rate once per packet in
                // it, which is a collapse rather than a response — RFC 3168
                // §6.1.2 draws the same line for TCP.
                let gap = (self.rtt_us.max(0) as u64).max(MIN_RECOVERY_US);
                if now_us.saturating_sub(self.last_cwarn_react_us) < gap {
                    return;
                }
                self.last_cwarn_react_us = now_us;
                let ctx = self.cc_ctx(now_us);
                let o = self.cc.on_loss(&[], ctx);
                self.apply_cc(o);
            }
            _ => {}
        }
    }

    fn recv_handshake(
        &mut self,
        hs: Handshake,
        now_us: u64,
        tx: &mut TransmitBuf,
        out: &mut Vec<Event>,
    ) {
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
                    tx.push(|dst| codec::encode_handshake(&new_req, self.ts(now_us), 0, dst));
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
                    tx.push(|dst| codec::encode_handshake(&new_req, self.ts(now_us), 0, dst));
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
                    tx.push(|dst| codec::encode_handshake(&resp, self.ts(now_us), hs.socket_id as u32, dst));
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
        // Completing the handshake means a request went out and an answer came
        // back, which is a round trip and the only one available this early.
        // Taking it beats opening with a 10 ms guess on a path that is nowhere
        // near that.
        let handshake_rtt = match &self.state {
            ConnState::Connecting { last_req_us, .. } if *last_req_us > 0 => {
                Some(now_us.saturating_sub(*last_req_us))
            }
            _ => None,
        };
        self.state = ConnState::Connected;
        self.post_connect(peer_isn, mss, flow_wnd, now_us);
        if let Some(rtt) = handshake_rtt {
            self.feed_rtt(rtt, now_us);
        }
        out.push(Event::Connected);
    }

    fn recv_ack(
        &mut self,
        asn: AckSeqNo,
        payload: crate::packet::AckPayload,
        now_us: u64,
        tx: &mut TransmitBuf,
    ) {
        self.last_rsp_us = now_us;
        self.exp_count = 1;

        let ack_seq = payload.data_ack_seq;

        // An ACK for data we never sent is ignored, not fatal.
        //
        // Not advancing the send buffer past the write cursor is the point, and
        // returning achieves it. Closing as well handed an off-path attacker a
        // one-packet kill: UDT authenticates nothing, so anyone who can guess
        // the address pair and the socket identifier can forge this, and
        // *most* of the sequence space is out of range — no valid guess needed,
        // which inverts the usual difficulty of blind injection. TCP requires an
        // injected `RST` to land inside the receive window, and RFC 5961
        // hardened even that.
        //
        // A real peer does not send these, so dropping them costs a well-behaved
        // connection nothing.
        if ack_seq > self.snd_curr_seq.next() {
            return;
        }

        let adv = ack_seq.offset_from(self.snd_last_ack).max(0) as usize;
        if adv > 0 {
            // Real forward progress: whatever the path is doing, it is
            // carrying our data.
            self.exp_without_progress = 0;
            self.no_progress_since_us = None;
            self.data_ever_acked = true;
        }

        if let Some(full) = &payload.full {
            // Every field below is whatever the peer chose to put on the wire.
            // A negative or absurd round-trip time is meaningless, and feeding
            // it to the smoothing arithmetic unclamped overflows -- `i32::MIN`
            // both underflows the subtraction and panics `abs`. It also
            // reaches the retransmission timer, so a peer could stretch or
            // collapse our timers at will.
            self.feed_rtt(full.rtt_us.max(0) as u64, now_us);
            if full.avail_buf_pkts > 0 {
                self.flow_wnd = (full.avail_buf_pkts as u32).min(MAX_FLOW_WND);
            }
            // Smooth the peer's rate reports (7/8 EWMA, ignoring non-positive
            // samples) before handing them to congestion control.  Raw per-ACK
            // samples are far too noisy — on loopback the receiver frequently
            // reports 0 pkt/s because every packet lands in the same
            // microsecond, which would otherwise collapse the window.
            if full.rcv_rate_pps > 0 {
                let sample = full.rcv_rate_pps as u32;
                self.delivery_rate_pps = (self.delivery_rate_pps / 8) * 7 + sample / 8;
            }
            if full.bandwidth_pps > 0 {
                let sample = full.bandwidth_pps as u32;
                self.bandwidth_pps = (self.bandwidth_pps / 8) * 7 + sample / 8;
            }
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
            tx.push(|dst| codec::encode_ack2(asn, self.ts(now_us), self.peer_id, dst));
        }

        // Congestion control sees *every* acknowledgement, light ones included.
        //
        // Only full ACKs used to reach it, and those fire on a 10 ms timer, so
        // the window could not open until 10 ms after the first byte went out
        // however fast the path was. A connection began by sending its initial
        // window -- 16 packets, 23 KB -- and then stalling for a whole SYN
        // interval. Measured against the C++ reference on loopback, that was
        // an 11 ms fixed cost on every transfer: identical steady-state rates,
        // but a 0.4 MB transfer took 15 ms against their 3.8.
        //
        // Light ACKs arrive every 64 packets, which is the same "acknowledge
        // often enough to keep the window opening" role that acking every
        // other segment plays in TCP slow start. They carry the acknowledgement
        // point, which is all the controller needs; the RTT and rate estimates
        // it also reads keep their values from the last full ACK.
        if adv > 0 {
            let ctx = self.cc_ctx_ex(now_us, self.delivery_rate_pps, self.bandwidth_pps);
            let o = self.cc.on_ack(ack_seq, ctx);
            self.apply_cc(o);
        }

        if adv > 0 {
            self.snd_last_ack = ack_seq;
            self.snd_loss.remove_up_to(ack_seq.prev());
            self.snd_sacked.remove_up_to(ack_seq.prev());
            if let Some(buf) = self.snd_buf.as_mut() {
                buf.ack(adv);
            }
        }

        // Ranges the peer reports receiving above the acknowledgement point.
        //
        // Applied whether or not the cumulative point moved, because a repeated
        // ACK whose only new information is its selective ranges is exactly the
        // case this exists to unblock.
        let sacked = self.apply_sack(&payload.sack);

        if adv > 0 || sacked {
            // Window just opened — immediately try to pack more data rather than
            // waiting for the next on_timer tick.
            self.next_snd_us = self.next_snd_us.min(now_us);
            let burst_end = now_us + SYN_US as u64;
            loop {
                if !self.pack_data(now_us, burst_end, tx) {
                    self.next_snd_us = now_us + SYN_US as u64;
                    break;
                }
            }
        }
    }

    /// Record the ranges a peer says arrived above the acknowledgement point,
    /// returning whether any were new.
    ///
    /// Every range here is whatever the peer put on the wire, so each is bounded
    /// to what this side actually has outstanding before it is believed. A range
    /// above `snd_curr_seq` names data never sent; one at or below `snd_last_ack`
    /// names data already retired, and crediting either would let a peer talk the
    /// in-flight count down and the send rate up without bound.
    ///
    /// A bogus range is skipped rather than treated as an error. C++ tears the
    /// connection down on the equivalent in a NAK, but these are advisory —
    /// ignoring one costs a round trip of window, while disconnecting on a
    /// malformed tail would hand a peer a way to kill the connection outright.
    fn apply_sack(&mut self, sack: &[(SeqNo, SeqNo)]) -> bool {
        // As offsets from the acknowledgement point, exactly as `recv_nak`
        // treats its ranges: comparing the sequence numbers themselves says
        // nothing once a peer is free to name anything in the space, and the
        // acknowledgement point is not covered by its own ACK, so a range has
        // to start strictly above it.
        let outstanding = self.snd_curr_seq.offset_from(self.snd_last_ack);
        let mut any = false;
        for &(start, end) in sack {
            let from = start.offset_from(self.snd_last_ack).max(1);
            let to = end.offset_from(self.snd_last_ack).min(outstanding);
            if to < from {
                continue;
            }
            let (start, end) = (self.snd_last_ack.shift(from), self.snd_last_ack.shift(to));
            self.snd_sacked.insert(start, end);
            // Nothing that arrived needs retransmitting.
            self.snd_loss.remove_range(start, end);
            any = true;
        }
        any
    }

    fn recv_nak(&mut self, nak: crate::packet::NakList, now_us: u64) {
        // Every sequence named here becomes a retransmission that the pacing
        // loop walks one at a time, and both ends of each range come off the
        // wire. A NAK claiming a third of the sequence space is twenty bytes
        // to send and a billion iterations of `pop_front` to work through, so
        // a range is recorded only where it overlaps what is actually
        // outstanding. Anything else is stale or invented.
        //
        // As offsets from the acknowledgement point, since comparing the
        // sequence numbers themselves says nothing at these distances.
        let outstanding = self.snd_curr_seq.offset_from(self.snd_last_ack);
        for &(s, e) in &nak.0 {
            let from = s.offset_from(self.snd_last_ack).max(0);
            let to = e.offset_from(self.snd_last_ack).min(outstanding);
            if to < from {
                continue;
            }
            self.snd_loss.insert(self.snd_last_ack.shift(from), self.snd_last_ack.shift(to));
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
            self.feed_rtt(rtt_us as u64, now_us);
        }
    }

    /// Emit an ACK.
    ///
    /// A `light` ACK carries only the acknowledgement point and does not update
    /// any local state; it exists to keep a fast sender's window open between
    /// full ACKs.
    fn emit_ack(&mut self, now_us: u64, light: bool, tx: &mut TransmitBuf) {
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
            let (ts, peer) = (self.ts(now_us), self.peer_id);
            tx.push(|dst| codec::encode_ack(AckSeqNo::new(0), data_ack, None, &[], ts, peer, dst));
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

        // Which ranges above the acknowledgement point arrived, so the sender
        // can stop counting them against its window. Without this a single hole
        // pins its whole window until the hole is repaired, however much data
        // behind it got through — see docs/selective-ack.md.
        //
        // Bounded by what is left of the packet after the 24-byte body, and by
        // MAX_SACK_RANGES. Empty when there are no holes, which is the common
        // case and costs nothing: `data_ack` is then already past everything
        // received, and `received_ranges` returns without allocating.
        let room = (self.payload_size as usize).saturating_sub(24) / 8;
        let sack =
            self.rcv_loss.received_ranges(data_ack, self.rcv_curr_seq, room.min(MAX_SACK_RANGES));

        let asn = self.ack_seq;
        self.ack_win.store(asn, data_ack, now_us);
        self.ack_seq = self.ack_seq.next();
        self.last_ack_us = now_us;
        tx.push(|dst| {
            codec::encode_ack(asn, data_ack, Some(&full), &sack, self.ts(now_us), self.peer_id, dst)
        });
    }

    /// Expire the message sitting at the send cursor, if its TTL has run out.
    ///
    /// Returns true if a message was retired, in which case the caller should
    /// treat this as productive work and come round again.
    fn expire_at_send_cursor(&mut self, now_us: u64, tx: &mut TransmitBuf) -> bool {
        let cursor = match self.snd_buf.as_ref() {
            Some(b) => b.send_cursor(),
            None => return false,
        };
        self.expire_msg_at(cursor, now_us, tx)
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
    fn expire_msg_at(&mut self, off: usize, now_us: u64, tx: &mut TransmitBuf) -> bool {
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

        tx.push(|dst| {
            codec::encode_msg_drop(msg_no, first, last, self.ts(now_us), self.peer_id, dst)
        });
        true
    }

    /// Re-announce a dropped message's range to a peer still asking for it.
    ///
    /// Returns whether anything was sent.
    fn resend_msg_drop_at(&mut self, off: u32, now_us: u64, tx: &mut TransmitBuf) -> bool {
        let Some((msg_no, first_off, last_off)) =
            self.snd_buf.as_ref().and_then(|b| b.dropped_msg_at(off as usize))
        else {
            return false;
        };
        let first = self.snd_last_ack.add(first_off as u32);
        let last = self.snd_last_ack.add(last_off as u32);
        self.snd_loss.remove_range(first, last);

        tx.push(|dst| {
            codec::encode_msg_drop(msg_no, first, last, self.ts(now_us), self.peer_id, dst)
        });
        true
    }

    /// Send a NAK for a single contiguous range, used for immediate loss
    /// reporting the moment a gap is spotted in the data stream.
    fn emit_nak_range(&mut self, start: SeqNo, end: SeqNo, now_us: u64, tx: &mut TransmitBuf) {
        tx.push(|dst| codec::encode_nak(&[(start, end)], self.ts(now_us), self.peer_id, dst));
    }

    fn emit_nak(&mut self, now_us: u64, tx: &mut TransmitBuf) {
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
        tx.push(|dst| codec::encode_nak(&ranges, self.ts(now_us), self.peer_id, dst));
    }

    /// Try to pack one outbound data packet.
    ///
    /// `burst_end` is the maximum virtual send-time ceiling for this call.
    /// Callers pass `now_us + SYN_US` so that all packets due within the next
    /// SYN interval are batched in one loop.  This is necessary because tokio
    /// timers have ~1 ms granularity and cannot honour sub-millisecond
    /// `pkt_snd_period_us` values individually.
    fn pack_data(&mut self, now_us: u64, burst_end: u64, tx: &mut TransmitBuf) -> bool {
        if burst_end < self.next_snd_us {
            return false;
        }

        // Retire any message at the send cursor whose TTL has run out, before
        // spending a transmission on it.
        if self.expire_at_send_cursor(now_us, tx) {
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
            if self.expire_msg_at(off as usize, now_us, tx) {
                continue; // dropped instead of resent; try the next loss entry
            }
            // Still being asked for a message that was already given up on,
            // which means the peer never got the MsgDrop -- it is a single
            // unacknowledged datagram, so any loss strands the receiver waiting
            // for a range that will never be sent. Say it again.
            if self.resend_msg_drop_at(off as u32, now_us, tx) {
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
                //
                // Packets the peer has selectively acknowledged are discounted
                // here: they are off the path, so counting them would pin the
                // window behind a hole that has already been worked around.
                //
                // This was off for most of its life, and correctly so. While the
                // recovery stalls were in place the window was almost never what
                // limited this sender -- it sat idle on timers instead -- so
                // discounting could not help by its own mechanism, and measured
                // mixed in sign twice. With those fixed the window binds, and the
                // third measurement is unambiguous over 32 seeds:
                //
                //           off      on
                //    1%     1.42    1.10    23% better
                //    2%     1.78    1.30    27% better
                //    5%     3.11    1.88    40% better
                //   10%     5.05    5.26     4% worse
                //
                // Every secondary number agrees, which is what settles it after
                // two rejections: amplification comes down rather than up, so
                // the extra data in flight is not bought with retransmissions;
                // reverse traffic comes down; and the pacing interval comes down
                // too, where enabling this used to roughly double it. The 10%
                // case is inside the noise of a mean whose spread is wide.
                //
                // Saturating because the subtrahend traces back to a number the
                // peer chose. `apply_sack` bounds the ranges it will accept, and
                // this is the second line of defence behind that.
                let in_flight = self
                    .snd_buf
                    .as_ref()
                    .map_or(0, |b| b.in_flight())
                    .saturating_sub(self.snd_sacked.len());
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

        tx.push(|dst| {
            dst.extend_from_slice(&hdr_bytes);
            dst.extend_from_slice(&payload_bytes);
        });

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

    /// Fold a round-trip measurement into the estimate.
    ///
    /// The first one *replaces* the estimate rather than being averaged into it,
    /// per RFC 6298 §2.2. Without that the opening guess has to be smoothed away
    /// at 1/8 per sample, and the guess is 10 ms — the reference's
    /// `10 × SYN_INTERVAL`, chosen for a wide-area path.
    ///
    /// On a fast path that is catastrophic and it was measured so. Against a true
    /// round trip of 200 µs, reaching it from 10 ms needs about 29 samples, which
    /// at one per 10 ms acknowledgement is ~290 ms — longer than most of the
    /// transfers being measured. The estimate simply never arrived: it was still
    /// reading 3.5 ms and 7.4 ms mid-transfer, 18x and 37x high.
    ///
    /// That is not cosmetic, because every recovery timer is derived from it —
    /// the repeat-NAK interval is 4x it, the retransmission timeout is built on
    /// it, and the receiver's re-acknowledge hold-off is `RTT + 4·RTTVar`. A gap
    /// therefore sat unreported for tens of milliseconds, and the stall inflated
    /// the estimate further. `loss_timeline` shows what that cost: at 5% loss,
    /// three stalls of 11-38 ms were 67 ms of a 74 ms transfer.
    fn feed_rtt(&mut self, sample_us: u64, now_us: u64) {
        let sample = sample_us.min(MAX_REPORTED_RTT_US as u64) as i32;
        if sample <= 0 {
            return;
        }
        if !self.rtt_sampled {
            self.rtt_sampled = true;
            self.rtt_us = sample;
            self.rtt_var_us = sample / 2;
            // Correcting the estimate is not enough on its own: `post_connect`
            // has already armed the repeat-NAK timer at `now + 4 × RTT`, and at
            // that point RTT was still the 10 ms guess, so the first chance to
            // re-report a gap is forty milliseconds out. Until it comes round the
            // only loss report is the immediate one `recv_data` sends on spotting
            // a gap, so one lost NAK stalls the transfer for the rest of that
            // interval — 38.5 ms of a 74 ms transfer, measured.
            //
            // Pulled in rather than reset: a timer already sooner than this was
            // armed from something better than a guess.
            self.next_nak_us = self.next_nak_us.min(now_us + self.nak_int_us());
            return;
        }
        let var = (sample - self.rtt_us).abs() / 4;
        self.rtt_us = (self.rtt_us / 8) * 7 + sample / 8;
        self.rtt_var_us = (self.rtt_var_us / 4) * 3 + var;
    }

    /// Interval until the next EXP firing.
    ///
    /// Uses the CC's RTO if it supplies one, else the reference's formula:
    /// `max(count × (RTT + 4·RTTVar) + SYN, count × SYN)`.
    ///
    /// **[`SYN_US`] here is not a granularity term, and not a floor for its own
    /// sake — it is how long a peer is allowed to take to acknowledge.** UDT
    /// receivers acknowledge on a `SYN` timer, so a retransmission timeout
    /// shorter than that fires before the first ACK could possibly arrive, every
    /// time, on any transfer that lets the window drain. What follows is
    /// spurious: `on_timeout` probes, and once `exp_count` passes
    /// [`PROBE_EXPIRIES`] it re-sends the entire window into a peer that already
    /// has it.
    ///
    /// This was tried at 1 ms, on the reasoning that fifty round trips is a
    /// silly price for noticing a loss. The simulator liked it — under 4% either
    /// way — because a Rust receiver nudges its ACK forward on the odd-sized
    /// packet that ends a message and so answers almost at once. The C++
    /// reference does not, and `interop_message_boundaries_rust_to_cpp` began
    /// timing out after twenty seconds roughly one run in seven, its peer buried
    /// in duplicates. Nought in ten once this went back.
    ///
    /// The NAK interval is a different question and keeps its short floor: see
    /// [`nak_int_us`](Self::nak_int_us).
    fn exp_int_us(&self) -> u64 {
        if let Some(rto) = self.cc_rto_us {
            return self.exp_count as u64 * rto;
        }
        let ack_allowance = SYN_US as u64;
        let rtt_based = self.exp_count as u64 * (self.rtt_us as u64 + 4 * self.rtt_var_us as u64)
            + ack_allowance;
        let min_based = self.exp_count as u64 * ack_allowance;
        rtt_based.max(min_based)
    }

    /// Interval between full ACKs — the CC's ACK period if it sets one.
    fn ack_int_us(&self) -> u64 {
        self.cc_ack_period_us.unwrap_or(SYN_US as u64)
    }

    /// Interval between repeat NAKs for gaps still outstanding.
    ///
    /// The first NAK goes out the moment a gap is spotted, in `recv_data`; this
    /// paces the ones after it, and so it is what a *lost* NAK costs. Four round
    /// trips is the reference's figure and is kept; the floor beneath it is not,
    /// because at [`SYN_US`] a lost NAK on a fast path cost 10 ms — fifty round
    /// trips to re-ask a question whose answer takes one.
    fn nak_int_us(&self) -> u64 {
        (4 * self.rtt_us as u64).max(MIN_RECOVERY_US)
    }

    fn ts(&self, now_us: u64) -> u32 {
        now_us as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::MsgBoundary;
    use crate::seq::MsgNo;
    use bytes::BytesMut;

    /// A connection wound forward to Connected, bypassing the handshake, so a
    /// test can reach the steady-state paths directly.
    fn connected(now_us: u64) -> Connection {
        let mut c = Connection::new_connected(
            1,
            2,
            SeqNo::new(100),
            SeqNo::new(500),
            1500,
            8192,
            now_us,
            CcKind::Udt.build(),
        );
        // new_connected leaves the first timer call to the driver.
        c.on_timer(now_us, &mut TransmitBuf::new(), &mut Vec::new());
        c
    }

    /// Deliver one data packet from the peer, so there is something to
    /// acknowledge. A connection with nothing outstanding suppresses ACKs.
    fn feed_one_packet(c: &mut Connection, seq: u32, now_us: u64) {
        let mut buf = BytesMut::new();
        codec::encode_data(
            SeqNo::new(seq),
            MsgBoundary::Solo,
            true,
            MsgNo::new(1),
            0,
            c.socket_id(),
            b"payload",
            &mut buf,
        );
        c.on_datagram(buf.freeze(), now_us, &mut TransmitBuf::new(), &mut Vec::new());
    }

    fn decode_all(tx: &TransmitBuf) -> Vec<Packet> {
        tx.datagrams().filter_map(|d| codec::decode(Bytes::copy_from_slice(d))).collect()
    }

    #[test]
    fn a_queued_message_is_packed_into_data_packets() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        // Three payloads' worth, so it cannot come out as a single packet.
        let payload = Bytes::from(vec![0xABu8; 4000]);
        assert_eq!(c.send_msg(payload, None, true, 1_000_000, &mut tx), SendOutcome::Queued);

        let packets = decode_all(&tx);
        let data: Vec<_> = packets
            .iter()
            .filter_map(|p| match p {
                Packet::Data { header, payload } => Some((header, payload)),
                _ => None,
            })
            .collect();
        assert_eq!(data.len(), 3, "4000 bytes should span three 1436-byte payloads");

        assert!(data[0].0.boundary.is_first() && !data[0].0.boundary.is_last());
        assert!(!data[1].0.boundary.is_first() && !data[1].0.boundary.is_last());
        assert!(data[2].0.boundary.is_last() && !data[2].0.boundary.is_first());

        let total: usize = data.iter().map(|(_, p)| p.len()).sum();
        assert_eq!(total, 4000, "the payload was not reassembled to its original length");

        // Sequence numbers run consecutively from the initial one.
        assert_eq!(data[0].0.seq_no, SeqNo::new(100));
        assert_eq!(data[1].0.seq_no, SeqNo::new(101));
        assert_eq!(data[2].0.seq_no, SeqNo::new(102));
        // One message, so one message number throughout.
        assert_eq!(data[0].0.msg_no, data[2].0.msg_no);
    }

    #[test]
    fn a_message_larger_than_the_buffer_is_rejected_not_deferred() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        let huge = Bytes::from(vec![0u8; c.max_msg_bytes() + 1]);
        // Rejected, not WouldBlock: waiting would never help.
        assert_eq!(c.send_msg(huge, None, true, 1_000_000, &mut tx), SendOutcome::Rejected);
    }

    #[test]
    fn an_ack_is_suppressed_when_there_is_nothing_new_to_report() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        c.emit_ack(1_000_000, false, &mut tx);
        assert!(
            tx.is_empty(),
            "a connection with nothing outstanding should not repeat itself to the peer"
        );
    }

    /// A peer's selective ranges are bounded to what this side actually has
    /// outstanding. Crediting a range never sent, or one already retired, would
    /// let a peer talk the in-flight count down and the send rate up at will.
    #[test]
    fn a_sack_range_outside_the_send_window_is_ignored() {
        let mut c = connected(1_000_000);
        c.snd_last_ack = SeqNo::new(100);
        c.snd_curr_seq = SeqNo::new(200);

        // Wholly outside what is outstanding, either side of it, and running
        // backwards. Nothing survives clamping, so nothing is credited.
        assert!(!c.apply_sack(&[(SeqNo::new(201), SeqNo::new(300))]));
        assert!(!c.apply_sack(&[(SeqNo::new(50), SeqNo::new(99))]));
        assert!(!c.apply_sack(&[(SeqNo::new(150), SeqNo::new(120))]));
        assert_eq!(c.snd_sacked.len(), 0, "a bogus range was credited");

        // Overrunning the window is clamped to the part that is real rather
        // than thrown away whole, as in `recv_nak`: 150..=200 was sent, 201 was
        // not.
        assert!(c.apply_sack(&[(SeqNo::new(150), SeqNo::new(201))]));
        assert_eq!(c.snd_sacked.len(), 51, "150..=200 is 51 sequences");

        // Likewise at the bottom: the acknowledgement point itself is the first
        // sequence *not* covered by the ACK, so a range reaching down to it
        // starts at the one above.
        let mut c = connected(1_000_000);
        c.snd_last_ack = SeqNo::new(100);
        c.snd_curr_seq = SeqNo::new(200);
        assert!(c.apply_sack(&[(SeqNo::new(100), SeqNo::new(150))]));
        assert_eq!(c.snd_sacked.len(), 50, "101..=150 is 50 sequences");

        // Wholly inside the window, so taken as given.
        let mut c = connected(1_000_000);
        c.snd_last_ack = SeqNo::new(100);
        c.snd_curr_seq = SeqNo::new(200);
        assert!(c.apply_sack(&[(SeqNo::new(120), SeqNo::new(150))]));
        assert_eq!(c.snd_sacked.len(), 31);
    }

    /// The whole point: sequences known to have arrived stop occupying the
    /// congestion window, and stop being retransmitted.
    #[test]
    fn a_sacked_range_leaves_the_window_and_the_loss_list() {
        let mut c = connected(1_000_000);
        c.snd_last_ack = SeqNo::new(100);
        c.snd_curr_seq = SeqNo::new(200);
        c.snd_loss.insert(SeqNo::new(110), SeqNo::new(160));
        let before = c.snd_loss.len();

        assert!(c.apply_sack(&[(SeqNo::new(120), SeqNo::new(150))]));
        assert_eq!(c.snd_sacked.len(), 31, "arrived packets must be discounted");
        assert_eq!(
            c.snd_loss.len(),
            before - 31,
            "packets that arrived must not stay queued for retransmission"
        );
    }

    /// The acknowledgement point moving past a range retires it, so the
    /// discount is never counted twice.
    #[test]
    fn sacked_ranges_are_dropped_once_the_ack_point_passes_them() {
        let mut c = connected(1_000_000);
        c.snd_last_ack = SeqNo::new(100);
        c.snd_curr_seq = SeqNo::new(200);
        assert!(c.apply_sack(&[(SeqNo::new(120), SeqNo::new(150))]));

        c.snd_sacked.remove_up_to(SeqNo::new(160));
        assert_eq!(c.snd_sacked.len(), 0);
    }

    #[test]
    fn shrinking_the_path_requeues_the_data_and_renumbers_it() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        assert_eq!(
            c.send_msg(Bytes::from(vec![7u8; 8192]), None, true, 1_000_000, &mut tx),
            SendOutcome::Queued
        );
        // Send some, so sequences have been spent.
        let burst = 1_000_000 + SYN_US as u64;
        while c.pack_data(1_000_000, burst, &mut tx) {}
        let spent = c.snd_curr_seq;
        assert!(spent.offset_from(c.snd_last_ack) >= 0, "nothing was sent");
        tx.clear();

        let before_mss = c.mss;
        assert!(c.shrink_path(1_100_000, &mut tx), "should have room to shrink");
        assert!(c.mss < before_mss, "mss did not come down");

        eprintln!(
            "mss {} -> {}, payload {}, snd_last_ack {} snd_curr_seq {} spent {}",
            before_mss,
            c.mss,
            c.payload_size,
            c.snd_last_ack.raw(),
            c.snd_curr_seq.raw(),
            spent.raw()
        );

        // The peer is told to skip the old numbering.
        assert!(
            decode_all(&tx)
                .iter()
                .any(|p| matches!(p, Packet::Control { body: ControlBody::MsgDrop { .. }, .. })),
            "no MsgDrop retired the abandoned range"
        );
        tx.clear();

        // And the data goes back out, smaller, above the abandoned range.
        while c.pack_data(1_100_000, 1_100_000 + SYN_US as u64, &mut tx) {}
        let sent: Vec<_> = tx.datagrams().collect();
        assert!(!sent.is_empty(), "nothing was re-sent after shrinking");
        let biggest = sent.iter().map(|d| d.len()).max().unwrap();
        eprintln!("re-sent {} datagrams, largest {} bytes", sent.len(), biggest);
        assert!(
            biggest <= c.mss as usize - IP_AND_UDP_OVERHEAD as usize,
            "a packet larger than the reduced path went out: {biggest} bytes"
        );
        for p in decode_all(&tx) {
            if let Packet::Data { header, .. } = p {
                assert!(
                    header.seq_no.offset_from(spent) > 0,
                    "re-sent under an abandoned sequence {}",
                    header.seq_no.raw()
                );
            }
        }
    }

    /// A CE-marked arrival must tell the *peer* to slow down, using the control
    /// packet UDT already defines so a reference peer understands it.
    #[test]
    fn a_congestion_mark_warns_the_peer() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        c.congestion_experienced(1_000_000, &mut tx);

        assert!(
            decode_all(&tx)
                .iter()
                .any(|p| matches!(p, Packet::Control { body: ControlBody::CongestionWarning, .. })),
            "no congestion warning was sent"
        );
    }

    /// Once per round trip, not once per marked packet. A router marking a whole
    /// window would otherwise cut the peer's rate once per packet in it.
    #[test]
    fn congestion_warnings_are_limited_to_one_per_round_trip() {
        let mut c = connected(1_000_000);
        c.rtt_us = 20_000;
        let mut tx = TransmitBuf::new();

        let warnings = |tx: &TransmitBuf| {
            decode_all(tx)
                .iter()
                .filter(|p| {
                    matches!(p, Packet::Control { body: ControlBody::CongestionWarning, .. })
                })
                .count()
        };

        // A whole window's worth of marks inside one round trip.
        for i in 0..50 {
            c.congestion_experienced(1_000_000 + i * 100, &mut tx);
        }
        assert_eq!(warnings(&tx), 1, "a marked window produced a warning per packet");

        // A round trip later, the path is worth reporting on again.
        c.congestion_experienced(1_000_000 + 20_001, &mut tx);
        assert_eq!(warnings(&tx), 2, "the next round trip should be reportable");
    }

    /// The receiving half of the same rule: the rate comes down once per round
    /// trip however many warnings arrive.
    #[test]
    fn reacting_to_warnings_is_limited_to_one_per_round_trip() {
        let mut c = connected(1_000_000);
        c.rtt_us = 20_000;
        let mut tx = TransmitBuf::new();
        let mut out = Vec::new();

        let mut warn = BytesMut::new();
        codec::encode_control(
            crate::packet::ControlType::CongestionWarning,
            0,
            0,
            c.socket_id(),
            &[0u8; 4],
            &mut warn,
        );
        let warn = warn.freeze();

        c.on_datagram(warn.clone(), 1_000_000, &mut tx, &mut out);
        let after_one = c.stats().snd_period_us;

        for i in 1..20 {
            c.on_datagram(warn.clone(), 1_000_000 + i * 100, &mut tx, &mut out);
        }
        assert_eq!(
            c.stats().snd_period_us,
            after_one,
            "twenty warnings in one round trip cut the rate more than once"
        );
    }

    #[test]
    fn a_full_ack_reports_the_receive_state() {
        let mut c = connected(1_000_000);
        feed_one_packet(&mut c, 500, 1_000_000);
        let mut tx = TransmitBuf::new();
        c.emit_ack(1_000_100, false, &mut tx);

        let packets = decode_all(&tx);
        let ack = packets
            .iter()
            .find_map(|p| match p {
                Packet::Control { body: ControlBody::Ack(asn, payload), .. } => {
                    Some((asn, payload))
                }
                _ => None,
            })
            .expect("no ACK was emitted");
        let full = ack.1.full.as_ref().expect("a full ACK should carry the extended fields");
        assert!(full.avail_buf_pkts > 0, "the advertised window should not be zero");
        assert_eq!(
            ack.1.data_ack_seq,
            SeqNo::new(501),
            "should acknowledge one past the packet just received"
        );
    }

    #[test]
    fn a_light_ack_omits_the_extended_fields() {
        let mut c = connected(1_000_000);
        feed_one_packet(&mut c, 500, 1_000_000);
        let mut tx = TransmitBuf::new();
        c.emit_ack(1_000_100, true, &mut tx);
        let packets = decode_all(&tx);
        let ack = packets
            .iter()
            .find_map(|p| match p {
                Packet::Control { body: ControlBody::Ack(_, payload), .. } => Some(payload),
                _ => None,
            })
            .expect("no ACK was emitted");
        assert!(ack.full.is_none(), "a light ACK should carry only the sequence number");
    }

    /// An impossible acknowledgement is dropped and the connection carries on.
    ///
    /// Both halves matter. The send buffer must not advance past the write
    /// cursor, and the connection must not die, because nothing authenticates
    /// this packet: anyone who can guess the address pair and socket identifier
    /// can forge one, and most of the sequence space is out of range, so no
    /// valid guess is needed. Closing here was a one-packet kill from off path.
    #[test]
    fn an_acknowledgement_for_data_never_sent_is_ignored() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        let mut out = Vec::new();
        let before = c.stats();

        c.recv_ctrl(
            ControlBody::Ack(
                AckSeqNo::new(1),
                crate::packet::AckPayload {
                    data_ack_seq: SeqNo::new(9999),
                    full: None,
                    sack: Vec::new(),
                },
            ),
            1_000_000,
            &mut tx,
            &mut out,
        );

        assert!(c.is_connected(), "a forged acknowledgement closed the connection");
        assert!(
            !out.iter().any(|e| matches!(e, Event::Disconnected(_))),
            "a forged acknowledgement reported a disconnect"
        );
        assert_eq!(
            c.stats().snd_last_ack,
            before.snd_last_ack,
            "the send buffer advanced on data that was never sent"
        );
    }

    /// Same reasoning for the error signal: unauthenticated and fatal is a
    /// one-packet kill. The reference never sends it.
    #[test]
    fn an_error_signal_does_not_close_the_connection() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        let mut out = Vec::new();

        c.recv_ctrl(ControlBody::ErrorSignal { error_code: 1002 }, 1_000_000, &mut tx, &mut out);

        assert!(c.is_connected(), "a forged error signal closed the connection");
        assert!(!out.iter().any(|e| matches!(e, Event::Disconnected(_))));
    }

    #[test]
    fn shutdown_tells_the_peer_and_reports_locally() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        let mut out = Vec::new();
        c.shutdown(1_000_000, &mut tx, &mut out);

        assert!(
            decode_all(&tx)
                .iter()
                .any(|p| matches!(p, Packet::Control { body: ControlBody::Shutdown, .. })),
            "no shutdown was sent to the peer"
        );
        assert!(
            out.iter().any(|e| matches!(e, Event::Disconnected(DisconnectReason::LocalClose))),
            "the application was not told the connection closed"
        );
        assert!(!c.is_connected());
        assert_eq!(c.next_deadline_us(), None, "a closed connection should want no more timers");
    }

    #[test]
    fn the_expiry_interval_grows_with_consecutive_silences() {
        let mut c = connected(1_000_000);
        c.rtt_us = 10_000;
        c.rtt_var_us = 1_000;

        c.exp_count = 1;
        let first = c.exp_int_us();
        c.exp_count = 4;
        let fourth = c.exp_int_us();
        assert!(fourth > first, "the expiry timer should back off, not stay flat");
        assert!(first >= MIN_RECOVERY_US, "the interval should respect its floor");
    }

    /// The opening round-trip guess must not survive contact with a measurement.
    ///
    /// Every recovery timer is derived from `rtt_us`, and the guess is 10 ms.
    /// Smoothing that away at 1/8 a sample takes ~29 samples, which on a
    /// 10 ms acknowledgement cadence is longer than many transfers last — so the
    /// estimate stayed in the milliseconds on a 200 µs path and stretched every
    /// timer with it.
    #[test]
    fn the_first_round_trip_measurement_replaces_the_guess() {
        let mut c = connected(1_000_000);
        assert_eq!(c.rtt_us, 10_000, "the opening guess should be the reference's");

        // Armed from the guess, so forty milliseconds out.
        c.next_nak_us = 1_000_000 + c.nak_int_us();
        assert!(c.next_nak_us >= 1_040_000);

        c.feed_rtt(200, 1_000_000);
        assert_eq!(c.rtt_us, 200, "the first measurement should replace, not blend");
        assert!(
            c.next_nak_us <= 1_000_000 + c.nak_int_us(),
            "the NAK timer kept the interval it was armed with from the guess"
        );

        // Later ones are smoothed, so a single outlier cannot capture it.
        c.feed_rtt(10_000, 1_100_000);
        assert!(c.rtt_us < 1_500, "one slow sample moved the estimate to {}us", c.rtt_us);

        // Nonsense is ignored rather than folded in.
        let before = c.rtt_us;
        c.feed_rtt(0, 1_200_000);
        assert_eq!(c.rtt_us, before);
    }

    /// The retransmission timeout must never come in under the time a peer is
    /// allowed to take to acknowledge, however fast the path.
    ///
    /// UDT receivers acknowledge on a `SYN` timer, so an RTO below that fires
    /// before the first ACK could arrive — every time, on any transfer that lets
    /// the window drain — and once `exp_count` passes `PROBE_EXPIRIES` the whole
    /// window is re-sent to a peer that already has it. Tried at 1 ms; the
    /// simulator saw nothing wrong because a Rust receiver answers almost at
    /// once, and the C++ reference then timed out after twenty seconds about one
    /// interop run in seven.
    #[test]
    fn the_retransmission_timeout_allows_for_a_peer_acknowledging_on_its_timer() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        assert_eq!(
            c.send_msg(Bytes::from(vec![0u8; 64]), None, true, 1_000_000, &mut tx),
            SendOutcome::Queued
        );

        // Even on an implausibly fast path with a rock-steady estimate.
        for (rtt, var) in [(0, 0), (1, 0), (100, 10), (5_000, 500)] {
            c.rtt_us = rtt;
            c.rtt_var_us = var;
            c.exp_count = 1;
            assert!(
                c.exp_int_us() >= SYN_US as u64,
                "rtt={rtt} var={var} gave an RTO of {}us, under the {}us a peer \
                 may take to acknowledge",
                c.exp_int_us(),
                SYN_US
            );
        }

        // The NAK timer is the one that gets to be quick: re-asking about a gap
        // is not waiting for an acknowledgement.
        c.rtt_us = 100;
        assert!(c.nak_int_us() < SYN_US as u64, "the NAK interval lost its short floor");
    }

    #[test]
    fn a_congestion_controller_can_override_the_retransmission_timeout() {
        let mut c = connected(1_000_000);
        c.exp_count = 1;
        let derived = c.exp_int_us();
        c.cc_rto_us = Some(derived * 4);
        assert_eq!(c.exp_int_us(), derived * 4, "the controller's timeout was ignored");
    }

    #[test]
    fn the_nak_interval_tracks_the_round_trip() {
        let mut c = connected(1_000_000);
        c.rtt_us = 50_000;
        assert_eq!(c.nak_int_us(), 200_000, "should be four round trips");
        // ...down to the floor, which is the driver's timer granularity and
        // deliberately not the control interval: re-asking a question whose
        // answer takes one round trip should not cost fifty.
        c.rtt_us = 1;
        assert_eq!(c.nak_int_us(), MIN_RECOVERY_US);
        assert!(MIN_RECOVERY_US < SYN_US as u64);
    }

    /// The receiver only records gaps above `rcv_curr_seq`, which is what keeps
    /// its loss list free of overlaps — so the cursor must never move
    /// backwards. It used to, at exactly one sequence: `recv_data` read a
    /// cursor of zero as "nothing received yet" and let the next arrival win
    /// whichever way it pointed, and the gap above then re-opened over one the
    /// list already held. A peer picks the initial sequence number, so it can
    /// put the wrap a hundred packets into the connection and reach that at
    /// will.
    #[test]
    fn a_gap_re_opened_across_the_wrap_does_not_duplicate_a_loss_entry() {
        let peer_isn = SeqNo::new(SEQ_MAX - 100);
        let mut c = Connection::new_connected(
            1,
            2,
            SeqNo::new(100),
            peer_isn,
            1500,
            8192,
            1_000_000,
            CcKind::Udt.build(),
        );
        c.on_timer(1_000_000, &mut TransmitBuf::new(), &mut Vec::new());

        // In order: the first packet; one that wraps past 0, leaving a gap of a
        // hundred behind it; a retransmission inside that gap, which is where
        // the cursor used to be dragged back; and one more above.
        let mut highest = c.rcv_curr_seq;
        for (i, seq) in [SEQ_MAX - 100, 0, SEQ_MAX - 50, 1].into_iter().enumerate() {
            feed_one_packet(&mut c, seq, 1_000_000 + i as u64 * 1_000);
            assert!(
                c.rcv_curr_seq >= highest,
                "the cursor went backwards over sequence {seq}, to {}",
                c.rcv_curr_seq.raw()
            );
            highest = c.rcv_curr_seq;
        }

        let ranges = c.rcv_loss.ranges_snapshot().to_vec();
        assert!(
            crate::loss_list::is_sorted_disjoint(&ranges),
            "the receiver is tracking the same sequence in two ranges: {ranges:?}"
        );

        // Nothing survives being received. With a duplicate entry the second
        // copy outlives the packet's arrival, and the receiver goes on asking
        // the sender for data it is already holding.
        let mut now = 1_100_000;
        for (start, end) in ranges {
            let mut seq = start;
            loop {
                feed_one_packet(&mut c, seq.raw(), now);
                now += 1_000;
                if seq == end {
                    break;
                }
                seq = seq.next();
            }
        }
        assert!(
            c.rcv_loss.is_empty(),
            "sequences stayed lost after arriving: {:?}",
            c.rcv_loss.ranges_snapshot()
        );
        assert_eq!(c.stats().rcv_loss_len, 0);
    }

    /// Found by the `connection` fuzz target, as a unit that took twenty
    /// seconds. A NAK naming most of the sequence space is twenty bytes to
    /// send, and `pack_data` walks the loss list one sequence at a time
    /// looking for something to retransmit.
    #[test]
    fn a_nak_for_the_whole_sequence_space_is_not_a_billion_retransmissions() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        // Send something, so there is a window for a NAK to be about at all.
        let sent = c.send_msg(Bytes::from(vec![0u8; 4000]), None, true, 1_000_000, &mut tx);
        assert_eq!(sent, SendOutcome::Queued);
        tx.clear();

        // Three packets went out, from sequence 100. This asks for the repair
        // of a billion, all but three of which were never sent.
        let mut buf = BytesMut::new();
        codec::encode_nak(
            &[(SeqNo::new(1), SeqNo::new(1_000_000_000))],
            0,
            c.socket_id(),
            &mut buf,
        );
        c.on_datagram(buf.freeze(), 1_001_000, &mut tx, &mut Vec::new());

        // Only the overlap with what is outstanding is worth recording.
        assert_eq!(
            c.stats().snd_loss_len,
            3,
            "a NAK put {} sequences on the loss list; three packets were sent",
            c.stats().snd_loss_len
        );
        // And the pacing loop gets through it rather than grinding.
        c.on_timer(1_002_000, &mut tx, &mut Vec::new());
    }

    /// Found by the `connection` fuzz target. `remove_range`'s straddle case
    /// splits the range it lands in; fed a backwards pair it split one range
    /// into two overlapping halves, and the receiver then held the same
    /// sequence twice over.
    #[test]
    fn a_message_drop_whose_range_runs_backwards_is_ignored() {
        let mut c = connected(1_000_000);
        // Open a gap of 500..=598 by skipping straight to 599.
        feed_one_packet(&mut c, 500, 1_000_000);
        feed_one_packet(&mut c, 599, 1_001_000);
        let before = c.rcv_loss.ranges_snapshot().to_vec();
        assert_eq!(before, [(SeqNo::new(501), SeqNo::new(598))]);

        let mut buf = BytesMut::new();
        codec::encode_msg_drop(
            MsgNo::new(2),
            SeqNo::new(580),
            SeqNo::new(520),
            0,
            c.socket_id(),
            &mut buf,
        );
        c.on_datagram(buf.freeze(), 1_002_000, &mut TransmitBuf::new(), &mut Vec::new());

        assert_eq!(
            c.rcv_loss.ranges_snapshot(),
            before,
            "a backwards range should be dropped, not acted on"
        );
    }

    #[test]
    fn a_datagram_for_a_different_socket_is_ignored() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        let mut out = Vec::new();

        // A data packet addressed to socket 999, which is not us.
        let mut buf = BytesMut::new();
        codec::encode_data(
            SeqNo::new(500),
            MsgBoundary::Solo,
            true,
            MsgNo::new(1),
            0,
            999,
            b"not for you",
            &mut buf,
        );
        c.on_datagram(buf.freeze(), 1_000_000, &mut tx, &mut out);

        assert!(c.recv_msg().is_none(), "a misaddressed packet was delivered");
    }

    #[test]
    fn a_truncated_datagram_is_ignored_rather_than_panicking() {
        let mut c = connected(1_000_000);
        let mut tx = TransmitBuf::new();
        let mut out = Vec::new();
        for len in 0..16 {
            c.on_datagram(Bytes::from(vec![0xFFu8; len]), 1_000_000, &mut tx, &mut out);
        }
        assert!(c.is_connected(), "a short datagram should be dropped, not fatal");
    }
}
