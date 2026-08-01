//! Deciding which connection an arriving datagram belongs to.
//!
//! An IO layer has to answer that question for every datagram, and the answer
//! is protocol knowledge rather than plumbing: which header field names a
//! connection, what it means when that field names none, and when a datagram
//! can only be a new connection. That lives here so a second IO layer does not
//! have to rediscover it, and so the rules sit beside the wire format they come
//! from.
//!
//! What stays in the IO layer is everything about *how* a connection is
//! reached — channels, tasks, locks. This owns a table from the wire's
//! identifiers to whatever handle the caller wants to use, and nothing else.

use std::collections::HashMap;
use std::hash::Hash;

use crate::codec;

/// Where a datagram should go.
#[derive(Debug)]
pub enum Route<'a, T> {
    /// It names this connection.
    Connection(&'a T),
    /// It names no connection, which a handshake cannot: a peer has not been
    /// told an id yet. Offer it to every connection at this address and let
    /// them decide — one past its handshake ignores handshakes, so at most the
    /// one still negotiating acts on it.
    ///
    /// Pairs are `(socket id, handle)`.
    Unaddressed(&'a [(u32, T)]),
    /// Nothing here knows this datagram. Only a new connection can explain it,
    /// so it belongs to whatever answers handshakes.
    Unknown,
}

/// A table from the identifiers on the wire to an IO layer's connection
/// handles.
///
/// Keyed on the socket id first, because that is what a datagram names once a
/// peer has been told one, and it is the only key that can tell apart two
/// connections sharing an address — which UDT allows and this used not to.
/// Keyed on the address as well, because a handshake carries no id and can
/// only be matched that way.
pub struct Router<A, T> {
    by_id: HashMap<u32, T>,
    by_addr: HashMap<A, Vec<(u32, T)>>,
}

impl<A: Eq + Hash + Clone, T: Clone> Router<A, T> {
    /// An empty table.
    pub fn new() -> Self {
        Router { by_id: HashMap::new(), by_addr: HashMap::new() }
    }

    /// Registers a connection under the id a peer will address it by and the
    /// address it talks to.
    pub fn insert(&mut self, socket_id: u32, addr: A, handle: T) {
        self.by_id.insert(socket_id, handle.clone());
        self.by_addr.entry(addr).or_default().push((socket_id, handle));
    }

    /// Forgets a connection. Idempotent.
    pub fn remove(&mut self, socket_id: u32, addr: &A) {
        self.by_id.remove(&socket_id);
        if let Some(list) = self.by_addr.get_mut(addr) {
            list.retain(|(id, _)| *id != socket_id);
            if list.is_empty() {
                self.by_addr.remove(addr);
            }
        }
    }

    /// Whether any connection is registered.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Decides where a datagram goes.
    ///
    /// `datagram` need only be long enough to hold a header; anything shorter
    /// names nothing and is [`Route::Unknown`].
    pub fn route<'a>(&'a self, datagram: &[u8], from: &A) -> Route<'a, T> {
        // Zero is not a connection. It is what a peer sends before it has been
        // told an id, so it can only be a handshake.
        match codec::dst_socket_id(datagram) {
            Some(id) if id != 0 => {
                if let Some(handle) = self.by_id.get(&id) {
                    return Route::Connection(handle);
                }
            }
            _ => {}
        }
        match self.by_addr.get(from) {
            Some(list) if !list.is_empty() => Route::Unaddressed(list),
            _ => Route::Unknown,
        }
    }
}

impl<A: Eq + Hash + Clone, T: Clone> Default for Router<A, T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::MsgBoundary;
    use crate::seq::{MsgNo, SeqNo};

    fn datagram_for(id: u32) -> Vec<u8> {
        codec::encode_data_header(SeqNo::new(1), MsgBoundary::Solo, true, MsgNo::new(0), 0, id)
            .to_vec()
    }

    #[test]
    fn an_addressed_datagram_reaches_its_connection() {
        let mut r: Router<u8, &str> = Router::new();
        r.insert(7, 1, "seven");
        r.insert(9, 1, "nine");
        assert!(matches!(r.route(&datagram_for(7), &1), Route::Connection(&"seven")));
        assert!(matches!(r.route(&datagram_for(9), &1), Route::Connection(&"nine")));
    }

    /// Two connections on one address are the case an address-keyed table
    /// cannot serve, and the reason the socket id is the primary key.
    #[test]
    fn two_connections_on_one_address_stay_apart() {
        let mut r: Router<u8, &str> = Router::new();
        r.insert(7, 1, "seven");
        r.insert(9, 1, "nine");
        r.remove(7, &1);
        assert!(matches!(r.route(&datagram_for(7), &1), Route::Unaddressed(_)));
        assert!(matches!(r.route(&datagram_for(9), &1), Route::Connection(&"nine")));
        assert!(!r.is_empty());
        r.remove(9, &1);
        assert!(r.is_empty());
        assert!(matches!(r.route(&datagram_for(9), &1), Route::Unknown));
    }

    #[test]
    fn an_unaddressed_datagram_goes_to_everyone_at_that_address() {
        let mut r: Router<u8, &str> = Router::new();
        r.insert(7, 1, "seven");
        r.insert(9, 1, "nine");
        r.insert(11, 2, "eleven");
        match r.route(&datagram_for(0), &1) {
            Route::Unaddressed(list) => assert_eq!(list.len(), 2),
            other => panic!("expected every connection at the address, got {other:?}"),
        }
        // And not to connections at a different one.
        match r.route(&datagram_for(0), &2) {
            Route::Unaddressed(list) => assert_eq!(list.len(), 1),
            other => panic!("expected one, got {other:?}"),
        }
        assert!(matches!(r.route(&datagram_for(0), &3), Route::Unknown));
    }

    /// It reads attacker-supplied bytes before anything is validated.
    #[test]
    fn a_runt_names_nothing() {
        let mut r: Router<u8, &str> = Router::new();
        r.insert(7, 1, "seven");
        for n in 0..16 {
            let short = datagram_for(7)[..n].to_vec();
            assert!(
                matches!(r.route(&short, &1), Route::Unaddressed(_)),
                "a {n}-byte datagram named a connection"
            );
            assert!(matches!(r.route(&short, &2), Route::Unknown));
        }
    }
}
