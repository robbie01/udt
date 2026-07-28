//! The handshake state machine for accepting incoming connections.

use crate::codec;
use crate::congestion::CcKind;
use crate::connection::Connection;
use crate::handshake::{Handshake, SOCK_DGRAM, UDT_VERSION, req_type};
use crate::seq::SeqNo;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;

/// A peer's address, in whatever form the IO layer uses.
///
/// [`Listener`] only ever compares these for equality and hands them back, so
/// the encoding is opaque: build one with [`from_v4`](Self::from_v4) or
/// [`from_v6`](Self::from_v6) and use it as a routing key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerAddr(pub [u8; 20]);

impl PeerAddr {
    /// Builds a key from an IPv4 address and port.
    pub fn from_v4(ip: [u8; 4], port: u16) -> Self {
        let mut a = [0u8; 20];
        a[0..4].copy_from_slice(&ip);
        a[16..18].copy_from_slice(&port.to_le_bytes());
        PeerAddr(a)
    }

    /// Builds a key from an IPv6 address and port.
    pub fn from_v6(ip: [u8; 16], port: u16) -> Self {
        let mut a = [0u8; 20];
        a[0..16].copy_from_slice(&ip);
        a[16..18].copy_from_slice(&port.to_le_bytes());
        PeerAddr(a)
    }
}

/// Something the caller must act on, produced by [`Listener::on_datagram`].
pub enum ListenerEvent {
    /// Write `data` to `addr` as a single UDP datagram.
    SendTo {
        /// Where to send it.
        addr: PeerAddr,
        /// The datagram.
        data: Bytes,
    },
    /// A peer completed the handshake. Route its future datagrams to this
    /// [`Connection`] and hand it to the application.
    Accept(Box<Connection>, PeerAddr),
}

struct PendingConn {
    cookie: i32,
    their_hs: Handshake, // their initial req_type=1 handshake
}

/// Answers handshakes on one address, producing a [`Connection`] per peer.
///
/// The listener owns no socket of its own: feed it every datagram that arrives
/// on the listening address and is not already routed to an established
/// connection, then act on the [`ListenerEvent`]s it returns.
pub struct Listener {
    socket_id: u32,
    mss: u32,
    /// Controller built fresh for each accepted connection.
    cc: CcKind,
    flight_flag_size: i32,
    /// Pending connections awaiting the req_type=-1 echo (cookie challenge stage).
    pending: HashMap<PeerAddr, PendingConn>,
    /// Already-accepted connections (we resend our response if they retransmit).
    accepted: HashMap<PeerAddr, Handshake>, // peer addr → our final response hs
    /// Secret for cookie generation (random at listener creation).
    secret: u64,
    enc: BytesMut,
}

impl Listener {
    /// Creates a listener.
    ///
    /// `socket_id` identifies the listening endpoint. `mss` is the path MTU
    /// offered to peers, `cc` the congestion controller each accepted
    /// connection gets, and `secret` seeds the handshake cookies that make
    /// spoofed connection attempts cheap to reject — pass a random value and
    /// do not reuse it across listeners.
    pub fn new(socket_id: u32, mss: u32, _now_us: u64, secret: u64, cc: CcKind) -> Self {
        Listener {
            socket_id,
            mss,
            cc,
            flight_flag_size: 25600,
            pending: HashMap::new(),
            accepted: HashMap::new(),
            secret,
            enc: BytesMut::with_capacity(mss as usize),
        }
    }

    /// Feeds one datagram received from `addr`.
    ///
    /// Resulting work is appended to `out`; see [`ListenerEvent`]. Anything
    /// that is not a valid handshake is ignored.
    pub fn on_datagram(
        &mut self,
        addr: PeerAddr,
        datagram: Bytes,
        now_us: u64,
        out: &mut Vec<ListenerEvent>,
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
            out.push(ListenerEvent::SendTo { addr, data: self.enc.clone().freeze() });
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
                    self.cc.build(),
                );

                self.pending.remove(&addr);
                self.accepted.insert(addr.clone(), our_resp.clone());

                self.enc.clear();
                codec::encode_handshake(&our_resp, ts, hs.socket_id as u32, &mut self.enc);
                out.push(ListenerEvent::SendTo {
                    addr: addr.clone(),
                    data: self.enc.clone().freeze(),
                });
                out.push(ListenerEvent::Accept(Box::new(conn), addr));
            } else if let Some(saved_resp) = self.accepted.get(&addr).cloned() {
                // Duplicate req_type=-1: peer missed our response — resend it
                self.enc.clear();
                codec::encode_handshake(&saved_resp, ts, hs.socket_id as u32, &mut self.enc);
                out.push(ListenerEvent::SendTo { addr, data: self.enc.clone().freeze() });
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
