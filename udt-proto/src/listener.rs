//! The handshake state machine for accepting incoming connections.

use crate::codec;
use crate::congestion::CcKind;
use crate::connection::Connection;
use crate::handshake::{Handshake, SOCK_DGRAM, UDT_VERSION, req_type};
use crate::seq::{MsgNo, SeqNo};
use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};

/// How many peers may have early data held for them at once.
///
/// Each entry is one packet, and a peer that never completes its handshake
/// holds one until it expires. Bounded rather than absent because an
/// unverified peer can reach it.
/// Data a peer sent before its handshake completed: when the first packet
/// arrived, and each packet's sequence number, message number and payload.
type EarlyHold = (u64, Vec<(SeqNo, MsgNo, Bytes)>);

const EARLY_DATA_SLOTS: usize = 256;

/// How long early data waits for the handshake it belongs to.
///
/// A conclusion arriving later than this is refused anyway, so anything still
/// held by then is never going to be claimed. Without an expiry the table fills
/// permanently and the feature stops working for everyone, which 256 packets
/// from an unverified peer would be enough to arrange.
const EARLY_DATA_TTL_US: u64 = 30_000_000;

/// How long a completed handshake is remembered.
///
/// Long enough to outlive any cookie a peer could still be echoing, which is
/// what stops a retransmitted handshake being mistaken for a new one.
const ACCEPT_MEMORY_US: u64 = 150_000_000;

/// Backstop on remembered handshakes, for a flood arriving faster than entries
/// age out.
const MAX_REMEMBERED_ACCEPTS: usize = 4096;

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
    /// Peers whose handshake completed, and the response to repeat if they
    /// ask again because ours went missing.
    ///
    /// Keyed by the peer's socket id as well as its address, because one
    /// address can hold several connections — that is the whole reason
    /// [`Router`](crate::Router) keys on the id — and an address alone would
    /// answer the second connection's conclusion with the first one's response.
    /// A peer dialling twice from one port would get one connection and a
    /// handshake that never completes.
    ///
    /// Bounded, and evicted oldest-first. Nothing here is required for
    /// correctness — a peer that retransmits after eviction simply redoes the
    /// cookie exchange — so a cap costs nothing and keeps a long-lived
    /// listener from growing one entry per connection it has ever seen.
    accepted: HashMap<(PeerAddr, u32), (u64, Handshake)>,
    /// Insertion order for `accepted`, for eviction.
    accepted_order: VecDeque<(PeerAddr, u32)>,
    /// Data received from a peer whose handshake has not completed yet, keyed
    /// by address, with the sequence number it claimed and when it arrived.
    early: HashMap<PeerAddr, EarlyHold>,
    /// Secret for cookie generation (random at listener creation).
    secret: u64,
    /// Counter behind [`Listener::mint_socket_id`].
    next_id: u32,
    enc: BytesMut,
}

impl Listener {
    /// A socket id for a newly accepted connection.
    ///
    /// Each accepted connection gets its own, which is what upstream does
    /// (`api.cpp`, `hs->m_iID = ns->m_SocketID`) and what lets more than one
    /// connection exist between the same pair of addresses. Upstream
    /// demultiplexes on `(peer, client socket id, client ISN)`; reusing the
    /// listener's id for every connection collapses that to one per address
    /// pair, which is what this used to do.
    ///
    /// Derived from the listener's secret rather than drawn from a random
    /// source, because this crate owns no clock and no entropy. Mixing the
    /// counter through the secret keeps ids unguessable to an off-path
    /// attacker, which the socket id is relied on for elsewhere — see the
    /// blind-injection note in the README. Never returns 0, which is reserved
    /// for a packet addressed to no connection in particular.
    fn mint_socket_id(&mut self) -> u32 {
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            let mixed = (self.secret ^ ((self.next_id as u64) << 32 | self.next_id as u64))
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let id = ((mixed >> 32) ^ mixed) as u32;
            if id != 0 && id != self.socket_id {
                return id;
            }
        }
    }

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
            next_id: 0,
            accepted: HashMap::new(),
            accepted_order: VecDeque::new(),
            early: HashMap::new(),
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
            // Data arriving before a connection exists is early data: a client
            // sending its first message beside the handshake conclusion, a
            // round trip before the connection is usable. Hold it against the
            // address and hand it over at accept.
            //
            // Held, not acted on. It is unverified at this point -- no cookie
            // has come back -- so it buys a slot and nothing else.
            crate::packet::Packet::Data { header, payload } => {
                if payload.is_empty() {
                    return;
                }
                // Expire before deciding there is no room. A peer that goes
                // quiet after sending early data must not hold a slot for ever,
                // or the table fills and stays full.
                if self.early.len() >= EARLY_DATA_SLOTS {
                    self.early.retain(|_, (at, _)| now_us.saturating_sub(*at) < EARLY_DATA_TTL_US);
                }
                // A peer may send several, so this is a list. Bounded by the
                // same cap the sender is: more than that could not have gone
                // out in the opening window anyway, and the rest of them arrive
                // by the ordinary path.
                let room = self.early.len() < EARLY_DATA_SLOTS;
                match self.early.get_mut(&addr) {
                    Some((_, held)) => {
                        if held.len() < crate::connection::MAX_EARLY_MESSAGES {
                            held.push((header.seq_no, header.msg_no, payload));
                        }
                    }
                    None if room => {
                        self.early
                            .insert(addr, (now_us, vec![(header.seq_no, header.msg_no, payload)]));
                    }
                    None => {}
                }
                return;
            }
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
            // Nothing is recorded here on purpose. The cookie is derived from
            // the address, the minute and our secret, so it can be checked
            // again from scratch when the peer echoes it -- which is the point
            // of a cookie. Remembering every address that has sent us an
            // opening handshake would let anyone grow this listener's memory
            // by spraying packets from spoofed sources, for free.
            self.enc.clear();
            codec::encode_handshake(&resp, ts, hs.socket_id as u32, &mut self.enc);
            out.push(ListenerEvent::SendTo { addr, data: self.enc.clone().freeze() });
        } else if hs.req_type == req_type::RESPONSE {
            // Step 2: cookie verification + accept.
            //
            // A peer we have already accepted gets its response repeated and
            // nothing more. This has to come first: the cookie it is echoing is
            // still valid, so falling through would hand out a second
            // connection for the same peer every time our response went
            // missing.
            if let Some((_, saved_resp)) =
                self.accepted.get(&(addr.clone(), hs.socket_id as u32)).cloned()
            {
                self.enc.clear();
                codec::encode_handshake(&saved_resp, ts, hs.socket_id as u32, &mut self.enc);
                out.push(ListenerEvent::SendTo { addr, data: self.enc.clone().freeze() });
                return;
            }

            // Recomputed rather than looked up. The previous minute is accepted
            // too, so a handshake that straddles the boundary is not rejected.
            let cookie = self.compute_cookie(&addr, now_us);
            let prev_cookie = self.compute_cookie(&addr, now_us.saturating_sub(60_000_000));
            if hs.cookie == cookie || hs.cookie == prev_cookie {
                let stored_cookie = hs.cookie;
                // C++ server sets m_iISN = hs->m_iISN (client's ISN) and echoes it
                // back in the final response. The C++ client security check verifies
                // m_iISN == m_ConnRes.m_iISN, so we must echo the client's ISN here.
                let peer_isn = SeqNo::new(hs.isn as u32 & crate::seq::SEQ_MAX);
                let local_isn = peer_isn; // both directions share client's ISN (C++ wire compat)
                let neg_mss = (hs.mss as u32).min(self.mss);
                let flow_wnd = hs.flight_flag_size as u32;

                // One id per connection, so the peer can address this one apart from
                // any other it has open to us. Minted before the response so both
                // carry the same value, and only on first accept -- a retransmitted
                // conclusion is answered from `accepted` with the id already sent.
                let new_id = self.mint_socket_id();
                let our_resp = Handshake {
                    version: UDT_VERSION,
                    sock_type: SOCK_DGRAM,
                    isn: peer_isn.raw() as i32, // echo client's ISN (C++ security check)
                    mss: neg_mss as i32,
                    flight_flag_size: flow_wnd as i32,
                    req_type: req_type::RESPONSE,
                    socket_id: new_id as i32,
                    cookie: stored_cookie,
                    peer_ip: [0u32; 4],
                };

                let mut conn = Connection::new_connected(
                    new_id,
                    hs.socket_id as u32,
                    local_isn,
                    peer_isn,
                    neg_mss,
                    flow_wnd,
                    now_us,
                    self.cc.build(),
                );

                // Hand over anything that arrived beside the conclusion. Done
                // before the connection leaves here, since afterwards there is
                // no way to reach it.
                if let Some((_, held)) = self.early.remove(&addr) {
                    for (seq, msg_no, payload) in held {
                        conn.inject_early_data(seq, msg_no, &payload, now_us);
                    }
                }

                self.remember_accepted(addr.clone(), hs.socket_id as u32, our_resp.clone(), now_us);

                self.enc.clear();
                codec::encode_handshake(&our_resp, ts, hs.socket_id as u32, &mut self.enc);
                out.push(ListenerEvent::SendTo {
                    addr: addr.clone(),
                    data: self.enc.clone().freeze(),
                });
                out.push(ListenerEvent::Accept(Box::new(conn), addr));
            }
        }
    }

    /// Record the response sent to `addr`, and retire entries that no peer can
    /// still be echoing a valid cookie for.
    ///
    /// Time-based rather than a plain size cap, because evicting a live entry
    /// early is not free: the peer's cookie would still verify, and it would be
    /// handed a second connection. Cookies stop verifying after two minutes, so
    /// nothing older than that can cause it. The count cap is a backstop
    /// against a flood arriving faster than entries age out.
    fn remember_accepted(&mut self, addr: PeerAddr, peer_id: u32, resp: Handshake, now_us: u64) {
        let key = (addr, peer_id);
        if self.accepted.insert(key.clone(), (now_us, resp)).is_none() {
            self.accepted_order.push_back(key);
        }
        while let Some(oldest) = self.accepted_order.front() {
            let expired = self
                .accepted
                .get(oldest)
                .is_none_or(|(t, _)| now_us.saturating_sub(*t) > ACCEPT_MEMORY_US);
            if !expired && self.accepted_order.len() <= MAX_REMEMBERED_ACCEPTS {
                break;
            }
            if let Some(oldest) = self.accepted_order.pop_front() {
                self.accepted.remove(&oldest);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::SendOutcome;
    use crate::transmit::TransmitBuf;

    fn peer() -> PeerAddr {
        PeerAddr::from_v4([127, 0, 0, 1], 5000)
    }

    fn handshake_datagram(hs: &Handshake, dst: u32) -> Bytes {
        let mut b = BytesMut::new();
        codec::encode_handshake(hs, 0, dst, &mut b);
        b.freeze()
    }

    fn decode_handshake(data: &Bytes) -> Handshake {
        match codec::decode(data.clone()) {
            Some(crate::packet::Packet::Control {
                body: crate::packet::ControlBody::Handshake(hs),
                ..
            }) => hs,
            other => panic!("expected a handshake, got {other:?}"),
        }
    }

    /// Runs the two-step handshake against a listener and returns the accepted
    /// connection, with the peer advertising `flight_flag_size`.
    fn accept_with_flight_flag(flight_flag_size: i32) -> Connection {
        let mut l = Listener::new(1, 1500, 0, 0xABCD_EF01_2345_6789, CcKind::Udt);
        let mut out = Vec::new();

        let opening = Handshake {
            version: UDT_VERSION,
            sock_type: SOCK_DGRAM,
            isn: 1000,
            mss: 1500,
            flight_flag_size,
            req_type: req_type::CONNECT,
            socket_id: 77,
            cookie: 0,
            peer_ip: [0u32; 4],
        };
        l.on_datagram(peer(), handshake_datagram(&opening, 0), 1_000_000, &mut out);
        let challenge = match out.drain(..).next() {
            Some(ListenerEvent::SendTo { data, .. }) => decode_handshake(&data),
            _ => panic!("no cookie challenge"),
        };

        let mut conclusion = opening.clone();
        conclusion.req_type = req_type::RESPONSE;
        conclusion.cookie = challenge.cookie;
        l.on_datagram(peer(), handshake_datagram(&conclusion, 1), 1_000_100, &mut out);

        out.into_iter()
            .find_map(|e| match e {
                ListenerEvent::Accept(conn, _) => Some(*conn),
                _ => None,
            })
            .expect("handshake did not produce a connection")
    }

    fn data_packets(tx: &TransmitBuf) -> usize {
        tx.datagrams().filter(|d| d.len() >= 16 && d[0] & 0x80 == 0).count()
    }

    /// A peer advertising a flow window of zero must not be able to wedge the
    /// connection it opens.
    ///
    /// The value comes straight off the wire and is the sender's window gate:
    /// `pack_data` will not send new data while `in_flight >= min(cwnd,
    /// flow_wnd)`, so at zero nothing may ever go out. Nothing recovers from
    /// that on its own — `flow_wnd` is only revised by an ACK, and the peer has
    /// no reason to send one when it is receiving nothing. `Connection`'s own
    /// handshake path clamps this with `.max(1)`; the listener does not.
    #[test]
    fn a_peer_advertising_a_zero_flow_window_cannot_wedge_the_connection() {
        let mut conn = accept_with_flight_flag(0);
        let mut tx = TransmitBuf::new();
        let mut events = Vec::new();
        conn.on_timer(1_000_200, &mut tx, &mut events);
        tx.clear();

        assert_eq!(
            conn.send_msg(Bytes::from_static(b"hello"), None, true, 1_000_300, &mut tx),
            SendOutcome::Queued
        );
        // Forty seconds of virtual time. Nothing goes out, and the connection
        // eventually gives up reporting `PathMtu` — "the path did not carry any
        // full-size packet, retry with a smaller MTU" — when in truth no packet
        // was ever offered to the path at all.
        for step in 1..4000u64 {
            conn.on_timer(1_000_300 + step * 10_000, &mut tx, &mut events);
        }
        assert!(
            data_packets(&tx) > 0,
            "a zero flow window left the connection unable to send anything at all"
        );
    }

    /// And the same field read as a huge one must not switch flow control off.
    #[test]
    fn a_peer_advertising_a_negative_flow_window_is_clamped() {
        let conn = accept_with_flight_flag(-1);
        assert!(
            conn.stats().flow_wnd <= 1 << 20,
            "flow window of {} accepted from the wire",
            conn.stats().flow_wnd
        );
    }
}
