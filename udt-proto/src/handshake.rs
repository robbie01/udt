/// UDT handshake payload: 48 bytes = 12 × LE i32.
/// All fields are little-endian on the wire (C++ uses raw host-order int32_t casts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub version: i32,           // must be 4
    pub sock_type: i32,         // must be 2 (SOCK_DGRAM)
    pub isn: i32,               // initial sequence number
    pub mss: i32,               // max segment size
    pub flight_flag_size: i32,  // flow control window (packets)
    pub req_type: i32,          // see ReqType constants
    pub socket_id: i32,
    pub cookie: i32,
    pub peer_ip: [u32; 4],      // peer address (IPv4 in [0], rest 0; or IPv6)
}

pub mod req_type {
    pub const CONNECT: i32     =  1;
    pub const RENDEZVOUS: i32  =  0;
    pub const RESPONSE: i32    = -1;
    pub const RDVZ_DONE: i32   = -2; // already-connected rendezvous retransmit ack
    pub const REJECTED: i32    = 1002;
}

pub const HANDSHAKE_SIZE: usize = 48;
pub const UDT_VERSION: i32 = 4;
pub const SOCK_DGRAM: i32 = 2;

impl Handshake {
    /// Serialize to exactly 48 bytes in LE byte order.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= HANDSHAKE_SIZE);
        let mut off = 0;
        let mut write_i32 = |v: i32| {
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
            off += 4;
        };
        write_i32(self.version);
        write_i32(self.sock_type);
        write_i32(self.isn);
        write_i32(self.mss);
        write_i32(self.flight_flag_size);
        write_i32(self.req_type);
        write_i32(self.socket_id);
        write_i32(self.cookie);
        for &w in &self.peer_ip {
            buf[off..off + 4].copy_from_slice(&w.to_le_bytes());
            off += 4;
        }
    }

    /// Deserialize from a byte slice. Returns None if too short or wrong version/type.
    pub fn read_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < HANDSHAKE_SIZE {
            return None;
        }
        let mut off = 0;
        let mut read_i32 = || {
            let v = i32::from_le_bytes(buf[off..off + 4].try_into().ok()?);
            off += 4;
            Some(v)
        };
        let version          = read_i32()?;
        let sock_type        = read_i32()?;
        let isn              = read_i32()?;
        let mss              = read_i32()?;
        let flight_flag_size = read_i32()?;
        let req_type         = read_i32()?;
        let socket_id        = read_i32()?;
        let cookie           = read_i32()?;
        let mut peer_ip = [0u32; 4];
        for slot in &mut peer_ip {
            *slot = u32::from_le_bytes(buf[off..off + 4].try_into().ok()?);
            off += 4;
        }
        Some(Handshake { version, sock_type, isn, mss, flight_flag_size, req_type, socket_id, cookie, peer_ip })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Handshake {
        Handshake {
            version: UDT_VERSION,
            sock_type: SOCK_DGRAM,
            isn: 12345678,
            mss: 1500,
            flight_flag_size: 25600,
            req_type: req_type::CONNECT,
            socket_id: 42,
            cookie: 0xDEADBEEFu32 as i32,
            peer_ip: [0x7F000001, 0, 0, 0],
        }
    }

    #[test]
    fn roundtrip() {
        let hs = sample();
        let mut buf = [0u8; HANDSHAKE_SIZE];
        hs.write_to(&mut buf);
        let hs2 = Handshake::read_from(&buf).unwrap();
        assert_eq!(hs, hs2);
    }

    #[test]
    fn le_layout() {
        let hs = sample();
        let mut buf = [0u8; HANDSHAKE_SIZE];
        hs.write_to(&mut buf);
        // version=4 in LE: bytes [04, 00, 00, 00]
        assert_eq!(&buf[0..4], &[4, 0, 0, 0]);
        // sock_type=2 in LE: bytes [02, 00, 00, 00]
        assert_eq!(&buf[4..8], &[2, 0, 0, 0]);
    }

    #[test]
    fn too_short_returns_none() {
        assert!(Handshake::read_from(&[0u8; 47]).is_none());
    }
}
