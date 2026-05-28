use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use crate::codec;
use crate::congestion::udt_cc::UdtCc;
use crate::handshake::{req_type, Handshake, SOCK_DGRAM, UDT_VERSION};
use crate::connection::Connection;
use crate::seq::SeqNo;

/// An opaque peer address key (up to 20 bytes: 16 for IP + 4 for port).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerAddr(pub [u8; 20]);

impl PeerAddr {
    pub fn from_v4(ip: [u8; 4], port: u16) -> Self {
        let mut a = [0u8; 20];
        a[0..4].copy_from_slice(&ip);
        a[16..18].copy_from_slice(&port.to_le_bytes());
        PeerAddr(a)
    }

    pub fn from_v6(ip: [u8; 16], port: u16) -> Self {
        let mut a = [0u8; 20];
        a[0..16].copy_from_slice(&ip);
        a[16..18].copy_from_slice(&port.to_le_bytes());
        PeerAddr(a)
    }
}

pub enum ListenerOutput {
    /// Send this datagram back to the peer that sent a datagram to us.
    SendTo { addr: PeerAddr, data: Bytes },
    /// A new incoming connection is fully established.
    Accept(Connection, PeerAddr),
}

struct PendingConn {
    cookie: i32,
    their_hs: Handshake, // their initial req_type=1 handshake
}

pub struct ListenerState {
    socket_id: u32,
    mss: u32,
    flight_flag_size: i32,
    /// Pending connections awaiting the req_type=-1 echo (cookie challenge stage).
    pending: HashMap<PeerAddr, PendingConn>,
    /// Already-accepted connections (we resend our response if they retransmit).
    accepted: HashMap<PeerAddr, Handshake>, // peer addr → our final response hs
    /// Secret for cookie generation (random at listener creation).
    secret: u64,
    /// Start time for timestamp-based cookie rotation (µs).
    start_us: u64,
    enc: BytesMut,
}

impl ListenerState {
    pub fn new(socket_id: u32, mss: u32, now_us: u64, secret: u64) -> Self {
        ListenerState {
            socket_id,
            mss,
            flight_flag_size: 25600,
            pending: HashMap::new(),
            accepted: HashMap::new(),
            secret,
            start_us: now_us,
            enc: BytesMut::with_capacity(mss as usize),
        }
    }

    /// Process an incoming datagram from `addr`. Emits responses and/or accepts.
    pub fn on_datagram(
        &mut self,
        addr: PeerAddr,
        datagram: Bytes,
        now_us: u64,
        out: &mut Vec<ListenerOutput>,
    ) {
        // Must be a handshake control packet
        let pkt = match codec::decode(datagram) {
            Some(p) => p,
            None => return,
        };
        let (hs, ts) = match pkt {
            crate::packet::Packet::Control {
                header,
                body: crate::packet::ControlBody::Handshake(hs),
            } => (hs, header.timestamp_us),
            _ => return,
        };
        if hs.version != UDT_VERSION || hs.sock_type != SOCK_DGRAM {
            return;
        }

        if hs.req_type == req_type::CONNECT {
            // Step 1: Cookie challenge.
            // The C++ client checks that m_ConnRes.m_iISN == m_iISN (security check), so
            // we echo back the client's ISN unchanged. Only the cookie field is set by us.
            let cookie = self.compute_cookie(&addr, now_us);
            let resp = Handshake {
                version: UDT_VERSION,
                sock_type: SOCK_DGRAM,
                isn: hs.isn, // echo client's ISN back (C++ security check requires this)
                mss: self.mss as i32,
                flight_flag_size: self.flight_flag_size,
                req_type: req_type::CONNECT,
                socket_id: self.socket_id as i32,
                cookie,
                peer_ip: [0u32; 4],
            };
            self.pending.insert(addr.clone(), PendingConn { cookie, their_hs: hs.clone() });
            self.enc.clear();
            codec::encode_handshake(&resp, ts, hs.socket_id as u32, &mut self.enc);
            out.push(ListenerOutput::SendTo { addr, data: self.enc.clone().freeze() });
        } else if hs.req_type == req_type::RESPONSE {
            // Step 2: Cookie verification + accept
            let pending_info = self.pending.get(&addr).map(|p| (p.cookie, p.their_hs.clone()));
            if let Some((stored_cookie, _their_hs)) = pending_info {
                let prev_cookie = self.compute_cookie(&addr, now_us.saturating_sub(60_000_000));
                let valid = hs.cookie == stored_cookie || hs.cookie == prev_cookie;
                if !valid {
                    return;
                }
                // C++ server sets m_iISN = hs->m_iISN (client's ISN) and echoes it
                // back in the final response. The C++ client security check verifies
                // m_iISN == m_ConnRes.m_iISN, so we must echo the client's ISN here.
                let peer_isn = SeqNo::new(hs.isn as u32 & crate::seq::SEQ_MAX);
                let local_isn = peer_isn; // both directions share client's ISN (C++ wire compat)
                let neg_mss = (hs.mss as u32).min(self.mss);
                let flow_wnd = hs.flight_flag_size as u32;

                let our_resp = Handshake {
                    version: UDT_VERSION,
                    sock_type: SOCK_DGRAM,
                    isn: peer_isn.raw() as i32, // echo client's ISN (C++ security check)
                    mss: neg_mss as i32,
                    flight_flag_size: flow_wnd as i32,
                    req_type: req_type::RESPONSE,
                    socket_id: self.socket_id as i32,
                    cookie: stored_cookie,
                    peer_ip: [0u32; 4],
                };

                let conn = Connection::new_connected(
                    self.socket_id,
                    hs.socket_id as u32,
                    local_isn,
                    peer_isn,
                    neg_mss,
                    flow_wnd,
                    now_us,
                    Box::new(UdtCc::new()),
                );

                self.pending.remove(&addr);
                self.accepted.insert(addr.clone(), our_resp.clone());

                self.enc.clear();
                codec::encode_handshake(&our_resp, ts, hs.socket_id as u32, &mut self.enc);
                out.push(ListenerOutput::SendTo { addr: addr.clone(), data: self.enc.clone().freeze() });
                out.push(ListenerOutput::Accept(conn, addr));
            } else if let Some(saved_resp) = self.accepted.get(&addr).cloned() {
                // Duplicate req_type=-1: peer missed our response — resend it
                self.enc.clear();
                codec::encode_handshake(&saved_resp, ts, hs.socket_id as u32, &mut self.enc);
                out.push(ListenerOutput::SendTo { addr, data: self.enc.clone().freeze() });
            }
        }
    }

    fn compute_cookie(&self, addr: &PeerAddr, now_us: u64) -> i32 {
        let minute = now_us / 60_000_000;
        // Mix addr bytes + minute + secret with a simple hash
        let mut h: u64 = self.secret;
        for &b in &addr.0 {
            h = h.wrapping_mul(6364136223846793005).wrapping_add(b as u64 + minute);
        }
        h as i32
    }

}
