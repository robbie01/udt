use bytes::{Bytes, BytesMut, BufMut};
use crate::handshake::{Handshake, HANDSHAKE_SIZE};
use crate::seq::{AckSeqNo, MsgNo, SeqNo};
use crate::packet::{
    AckFull, AckPayload, ControlBody, ControlHeader, ControlType,
    DataHeader, MsgBoundary, NakList, Packet,
};

// The UDT packet header is 4 × u32, all in host byte order (== little-endian on x86/x86_64).
// There is no htonl/ntohl in the original C++ source — raw bit operations on uint32_t.

/// Decode a single UDT packet from a datagram.
/// The returned `Bytes` for data payloads slices into the provided `datagram`
/// (zero-copy via ref-count bump).
pub fn decode(datagram: Bytes) -> Option<Packet> {
    if datagram.len() < 16 {
        return None;
    }
    let word0 = read_le_u32(&datagram[0..4]);
    let word1 = read_le_u32(&datagram[4..8]);
    let word2 = read_le_u32(&datagram[8..12]);
    let word3 = read_le_u32(&datagram[12..16]);

    if word0 >> 31 == 0 {
        // Data packet
        let seq_no = SeqNo::new(word0 & 0x7FFF_FFFF);
        let boundary = MsgBoundary::from_bits(word1 >> 30);
        let in_order = (word1 >> 29) & 1 != 0;
        let msg_no = MsgNo::new(word1 & 0x1FFF_FFFF);
        let payload = datagram.slice(16..);
        Some(Packet::Data {
            header: DataHeader {
                seq_no,
                boundary,
                in_order,
                msg_no,
                timestamp_us: word2,
                dst_socket_id: word3,
            },
            payload,
        })
    } else {
        // Control packet
        let type_bits = (word0 >> 16) & 0x7FFF;
        let ext_bits  = word0 & 0xFFFF;
        let ctrl_type = ControlType::from_word(type_bits, ext_bits)?;
        let add_info  = word1;
        let hdr = ControlHeader {
            ctrl_type,
            additional_info: add_info,
            timestamp_us: word2,
            dst_socket_id: word3,
        };
        let payload_bytes = datagram.slice(16..);
        let body = decode_ctrl_body(&hdr, payload_bytes)?;
        Some(Packet::Control { header: hdr, body })
    }
}

fn decode_ctrl_body(hdr: &ControlHeader, payload: Bytes) -> Option<ControlBody> {
    match hdr.ctrl_type {
        ControlType::Handshake => {
            let hs = Handshake::read_from(&payload)?;
            Some(ControlBody::Handshake(hs))
        }
        ControlType::KeepAlive => Some(ControlBody::KeepAlive),
        ControlType::Ack => {
            if payload.len() < 4 {
                return None;
            }
            let data_ack = SeqNo::new(read_le_i32(&payload[0..4]) as u32);
            let full = if payload.len() >= 24 {
                Some(AckFull {
                    rtt_us:        read_le_i32(&payload[4..8]),
                    rtt_var_us:    read_le_i32(&payload[8..12]),
                    avail_buf_pkts:read_le_i32(&payload[12..16]),
                    rcv_rate_pps:  read_le_i32(&payload[16..20]),
                    bandwidth_pps: read_le_i32(&payload[20..24]),
                })
            } else {
                None
            };
            Some(ControlBody::Ack(
                AckSeqNo::new(hdr.additional_info),
                AckPayload { data_ack_seq: data_ack, full },
            ))
        }
        ControlType::Nak => {
            let nak = decode_nak_list(&payload)?;
            Some(ControlBody::Nak(nak))
        }
        ControlType::CongestionWarning => Some(ControlBody::CongestionWarning),
        ControlType::Shutdown => Some(ControlBody::Shutdown),
        ControlType::Ack2 => {
            Some(ControlBody::Ack2(AckSeqNo::new(hdr.additional_info)))
        }
        ControlType::MsgDrop => {
            if payload.len() < 8 {
                return None;
            }
            let first = SeqNo::new(read_le_i32(&payload[0..4]) as u32 & 0x7FFF_FFFF);
            let last  = SeqNo::new(read_le_i32(&payload[4..8]) as u32 & 0x7FFF_FFFF);
            Some(ControlBody::MsgDrop {
                msg_no: MsgNo::new(hdr.additional_info),
                first,
                last,
            })
        }
        ControlType::ErrorSignal => {
            Some(ControlBody::ErrorSignal { error_code: hdr.additional_info as i32 })
        }
        ControlType::UserDefined(ext_type) => {
            Some(ControlBody::UserDefined { ext_type, payload })
        }
    }
}

fn decode_nak_list(payload: &[u8]) -> Option<NakList> {
    if payload.len() % 4 != 0 {
        return None;
    }
    let mut ranges = Vec::new();
    let mut i = 0;
    while i + 4 <= payload.len() {
        let word = read_le_u32(&payload[i..i + 4]);
        i += 4;
        if word >> 31 != 0 {
            // Start of a range; next word is the end
            if i + 4 > payload.len() {
                return None;
            }
            let start = SeqNo::new(word & 0x7FFF_FFFF);
            let end_word = read_le_u32(&payload[i..i + 4]);
            let end = SeqNo::new(end_word & 0x7FFF_FFFF);
            i += 4;
            ranges.push((start, end));
        } else {
            let s = SeqNo::new(word & 0x7FFF_FFFF);
            ranges.push((s, s));
        }
    }
    Some(NakList(ranges))
}

// ── Encoder ─────────────────────────────────────────────────────────────────

/// Encode a full data packet into `dst`.
/// `header_words` are the 4 pre-built LE u32 words; `payload` is the data.
pub fn encode_data(
    seq_no: SeqNo,
    boundary: MsgBoundary,
    in_order: bool,
    msg_no: MsgNo,
    timestamp_us: u32,
    dst_socket_id: u32,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let word0 = seq_no.raw(); // bit31 = 0 (data)
    let word1 = (boundary.bits() << 30)
        | ((in_order as u32) << 29)
        | (msg_no.raw() & 0x1FFF_FFFF);
    dst.put_u32_le(word0);
    dst.put_u32_le(word1);
    dst.put_u32_le(timestamp_us);
    dst.put_u32_le(dst_socket_id);
    dst.put_slice(payload);
}

/// Encode the 16-byte header for a data packet into a fixed array (zero-alloc).
pub fn encode_data_header(
    seq_no: SeqNo,
    boundary: MsgBoundary,
    in_order: bool,
    msg_no: MsgNo,
    timestamp_us: u32,
    dst_socket_id: u32,
) -> [u8; 16] {
    let word0 = seq_no.raw();
    let word1 = (boundary.bits() << 30)
        | ((in_order as u32) << 29)
        | (msg_no.raw() & 0x1FFF_FFFF);
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&word0.to_le_bytes());
    out[4..8].copy_from_slice(&word1.to_le_bytes());
    out[8..12].copy_from_slice(&timestamp_us.to_le_bytes());
    out[12..16].copy_from_slice(&dst_socket_id.to_le_bytes());
    out
}

/// Encode a control packet into `dst`.
pub fn encode_control(
    ctrl_type: ControlType,
    additional_info: u32,
    timestamp_us: u32,
    dst_socket_id: u32,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let ext_bits = match ctrl_type {
        ControlType::UserDefined(e) => e as u32,
        _ => 0,
    };
    let word0 = 0x8000_0000u32
        | ((ctrl_type.type_bits() as u32) << 16)
        | ext_bits;
    dst.put_u32_le(word0);
    dst.put_u32_le(additional_info);
    dst.put_u32_le(timestamp_us);
    dst.put_u32_le(dst_socket_id);
    dst.put_slice(payload);
}

/// Encode a handshake control packet into `dst`.
pub fn encode_handshake(hs: &Handshake, timestamp_us: u32, dst_socket_id: u32, dst: &mut BytesMut) {
    let mut body = [0u8; HANDSHAKE_SIZE];
    hs.write_to(&mut body);
    encode_control(ControlType::Handshake, 0, timestamp_us, dst_socket_id, &body, dst);
}

/// Encode an ACK packet into `dst`. `full` is optional; if None a light ACK is sent.
pub fn encode_ack(
    ack_sub_seq: AckSeqNo,
    data_ack_seq: SeqNo,
    full: Option<&AckFull>,
    timestamp_us: u32,
    dst_socket_id: u32,
    dst: &mut BytesMut,
) {
    let mut body = BytesMut::with_capacity(if full.is_some() { 24 } else { 4 });
    body.put_i32_le(data_ack_seq.raw() as i32);
    if let Some(f) = full {
        body.put_i32_le(f.rtt_us);
        body.put_i32_le(f.rtt_var_us);
        body.put_i32_le(f.avail_buf_pkts);
        body.put_i32_le(f.rcv_rate_pps);
        body.put_i32_le(f.bandwidth_pps);
    }
    encode_control(ControlType::Ack, ack_sub_seq.raw(), timestamp_us, dst_socket_id, &body, dst);
}

/// Encode an ACK2 packet.
pub fn encode_ack2(ack_sub_seq: AckSeqNo, timestamp_us: u32, dst_socket_id: u32, dst: &mut BytesMut) {
    // ACK2 has a 4-byte padding payload (C++ uses __pad for iovec requirements)
    encode_control(ControlType::Ack2, ack_sub_seq.raw(), timestamp_us, dst_socket_id, &[0u8; 4], dst);
}

/// Encode a NAK packet from a list of (start, end) sequence ranges.
pub fn encode_nak(
    ranges: &[(SeqNo, SeqNo)],
    timestamp_us: u32,
    dst_socket_id: u32,
    dst: &mut BytesMut,
) {
    let mut body = BytesMut::with_capacity(ranges.len() * 8);
    for &(start, end) in ranges {
        if start == end {
            body.put_u32_le(start.raw()); // single, bit31 clear
        } else {
            body.put_u32_le(start.raw() | 0x8000_0000); // range start, bit31 set
            body.put_u32_le(end.raw());                  // range end, bit31 clear
        }
    }
    encode_control(ControlType::Nak, 0, timestamp_us, dst_socket_id, &body, dst);
}

/// Encode a keep-alive packet.
pub fn encode_keepalive(timestamp_us: u32, dst_socket_id: u32, dst: &mut BytesMut) {
    encode_control(ControlType::KeepAlive, 0, timestamp_us, dst_socket_id, &[0u8; 4], dst);
}

/// Encode a shutdown packet.
pub fn encode_shutdown(timestamp_us: u32, dst_socket_id: u32, dst: &mut BytesMut) {
    encode_control(ControlType::Shutdown, 0, timestamp_us, dst_socket_id, &[0u8; 4], dst);
}

/// Encode a message drop request.
pub fn encode_msg_drop(
    msg_no: MsgNo,
    first: SeqNo,
    last: SeqNo,
    timestamp_us: u32,
    dst_socket_id: u32,
    dst: &mut BytesMut,
) {
    let mut body = [0u8; 8];
    body[0..4].copy_from_slice(&(first.raw() as i32).to_le_bytes());
    body[4..8].copy_from_slice(&(last.raw() as i32).to_le_bytes());
    encode_control(ControlType::MsgDrop, msg_no.raw(), timestamp_us, dst_socket_id, &body, dst);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn read_le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

#[inline]
fn read_le_i32(b: &[u8]) -> i32 {
    i32::from_le_bytes(b[..4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{req_type, UDT_VERSION, SOCK_DGRAM};
    use bytes::Bytes;

    fn round_trip(pkt: Packet) -> Packet {
        let mut buf = BytesMut::new();
        match &pkt {
            Packet::Data { header: h, payload: p } => {
                encode_data(h.seq_no, h.boundary, h.in_order, h.msg_no,
                    h.timestamp_us, h.dst_socket_id, p, &mut buf);
            }
            Packet::Control { header: h, body } => {
                match body {
                    ControlBody::Handshake(hs) =>
                        encode_handshake(hs, h.timestamp_us, h.dst_socket_id, &mut buf),
                    ControlBody::KeepAlive =>
                        encode_keepalive(h.timestamp_us, h.dst_socket_id, &mut buf),
                    ControlBody::Ack(asn, payload) =>
                        encode_ack(*asn, payload.data_ack_seq, payload.full.as_ref(),
                            h.timestamp_us, h.dst_socket_id, &mut buf),
                    ControlBody::Nak(nak) =>
                        encode_nak(&nak.0, h.timestamp_us, h.dst_socket_id, &mut buf),
                    ControlBody::CongestionWarning =>
                        encode_control(ControlType::CongestionWarning, 0,
                            h.timestamp_us, h.dst_socket_id, &[0u8; 4], &mut buf),
                    ControlBody::Shutdown =>
                        encode_shutdown(h.timestamp_us, h.dst_socket_id, &mut buf),
                    ControlBody::Ack2(asn) =>
                        encode_ack2(*asn, h.timestamp_us, h.dst_socket_id, &mut buf),
                    ControlBody::MsgDrop { msg_no, first, last } =>
                        encode_msg_drop(*msg_no, *first, *last,
                            h.timestamp_us, h.dst_socket_id, &mut buf),
                    ControlBody::ErrorSignal { error_code } =>
                        encode_control(ControlType::ErrorSignal, *error_code as u32,
                            h.timestamp_us, h.dst_socket_id, &[], &mut buf),
                    ControlBody::UserDefined { ext_type, payload } =>
                        encode_control(ControlType::UserDefined(*ext_type), 0,
                            h.timestamp_us, h.dst_socket_id, payload, &mut buf),
                }
            }
        }
        decode(buf.freeze()).expect("round-trip decode failed")
    }

    #[test]
    fn data_packet_roundtrip() {
        let pkt = Packet::Data {
            header: DataHeader {
                seq_no: SeqNo::new(12345),
                boundary: MsgBoundary::Solo,
                in_order: true,
                msg_no: MsgNo::new(42),
                timestamp_us: 999_999,
                dst_socket_id: 7,
            },
            payload: Bytes::from_static(b"hello world"),
        };
        let rt = round_trip(pkt);
        if let Packet::Data { header, payload } = rt {
            assert_eq!(header.seq_no, SeqNo::new(12345));
            assert_eq!(header.boundary, MsgBoundary::Solo);
            assert!(header.in_order);
            assert_eq!(header.msg_no, MsgNo::new(42));
            assert_eq!(header.timestamp_us, 999_999);
            assert_eq!(header.dst_socket_id, 7);
            assert_eq!(&payload[..], b"hello world");
        } else {
            panic!("expected Data");
        }
    }

    #[test]
    fn handshake_roundtrip() {
        let hs = Handshake {
            version: UDT_VERSION,
            sock_type: SOCK_DGRAM,
            isn: 100,
            mss: 1500,
            flight_flag_size: 25600,
            req_type: req_type::CONNECT,
            socket_id: 1,
            cookie: 0,
            peer_ip: [127 | (0 << 8) | (0 << 16) | (1 << 24), 0, 0, 0],
        };
        let pkt = Packet::Control {
            header: ControlHeader {
                ctrl_type: ControlType::Handshake,
                additional_info: 0,
                timestamp_us: 0,
                dst_socket_id: 0,
            },
            body: ControlBody::Handshake(hs.clone()),
        };
        let rt = round_trip(pkt);
        if let Packet::Control { body: ControlBody::Handshake(hs2), .. } = rt {
            assert_eq!(hs, hs2);
        } else {
            panic!("expected Handshake");
        }
    }

    #[test]
    fn ack_light_roundtrip() {
        let pkt = Packet::Control {
            header: ControlHeader {
                ctrl_type: ControlType::Ack,
                additional_info: 77,
                timestamp_us: 5000,
                dst_socket_id: 3,
            },
            body: ControlBody::Ack(
                AckSeqNo::new(77),
                AckPayload { data_ack_seq: SeqNo::new(500), full: None },
            ),
        };
        let rt = round_trip(pkt);
        if let Packet::Control { body: ControlBody::Ack(asn, payload), .. } = rt {
            assert_eq!(asn, AckSeqNo::new(77));
            assert_eq!(payload.data_ack_seq, SeqNo::new(500));
            assert!(payload.full.is_none());
        } else {
            panic!("expected Ack");
        }
    }

    #[test]
    fn ack_full_roundtrip() {
        let full = AckFull { rtt_us: 1000, rtt_var_us: 200, avail_buf_pkts: 8192, rcv_rate_pps: 1000, bandwidth_pps: 5000 };
        let pkt = Packet::Control {
            header: ControlHeader {
                ctrl_type: ControlType::Ack,
                additional_info: 10,
                timestamp_us: 0,
                dst_socket_id: 0,
            },
            body: ControlBody::Ack(
                AckSeqNo::new(10),
                AckPayload { data_ack_seq: SeqNo::new(99), full: Some(full) },
            ),
        };
        let rt = round_trip(pkt);
        if let Packet::Control { body: ControlBody::Ack(_, payload), .. } = rt {
            let f = payload.full.unwrap();
            assert_eq!(f.rtt_us, 1000);
            assert_eq!(f.bandwidth_pps, 5000);
        } else {
            panic!("expected Ack");
        }
    }

    #[test]
    fn nak_roundtrip_ranges() {
        let ranges = vec![
            (SeqNo::new(10), SeqNo::new(20)),
            (SeqNo::new(50), SeqNo::new(50)),
            (SeqNo::new(100), SeqNo::new(200)),
        ];
        let pkt = Packet::Control {
            header: ControlHeader {
                ctrl_type: ControlType::Nak,
                additional_info: 0,
                timestamp_us: 0,
                dst_socket_id: 0,
            },
            body: ControlBody::Nak(NakList(ranges.clone())),
        };
        let rt = round_trip(pkt);
        if let Packet::Control { body: ControlBody::Nak(NakList(got)), .. } = rt {
            assert_eq!(got, ranges);
        } else {
            panic!("expected Nak");
        }
    }

    #[test]
    fn ack2_roundtrip() {
        let pkt = Packet::Control {
            header: ControlHeader {
                ctrl_type: ControlType::Ack2,
                additional_info: 55,
                timestamp_us: 0,
                dst_socket_id: 0,
            },
            body: ControlBody::Ack2(AckSeqNo::new(55)),
        };
        let rt = round_trip(pkt);
        if let Packet::Control { body: ControlBody::Ack2(asn), .. } = rt {
            assert_eq!(asn, AckSeqNo::new(55));
        } else {
            panic!("expected Ack2");
        }
    }

    #[test]
    fn msg_drop_roundtrip() {
        let pkt = Packet::Control {
            header: ControlHeader {
                ctrl_type: ControlType::MsgDrop,
                additional_info: 5,
                timestamp_us: 0,
                dst_socket_id: 0,
            },
            body: ControlBody::MsgDrop {
                msg_no: MsgNo::new(5),
                first: SeqNo::new(300),
                last: SeqNo::new(310),
            },
        };
        let rt = round_trip(pkt);
        if let Packet::Control { body: ControlBody::MsgDrop { msg_no, first, last }, .. } = rt {
            assert_eq!(msg_no, MsgNo::new(5));
            assert_eq!(first, SeqNo::new(300));
            assert_eq!(last, SeqNo::new(310));
        } else {
            panic!("expected MsgDrop");
        }
    }

    #[test]
    fn shutdown_keepalive_congestion_roundtrip() {
        for pkt in [
            Packet::Control {
                header: ControlHeader { ctrl_type: ControlType::Shutdown, additional_info: 0, timestamp_us: 1, dst_socket_id: 2 },
                body: ControlBody::Shutdown,
            },
            Packet::Control {
                header: ControlHeader { ctrl_type: ControlType::KeepAlive, additional_info: 0, timestamp_us: 1, dst_socket_id: 2 },
                body: ControlBody::KeepAlive,
            },
            Packet::Control {
                header: ControlHeader { ctrl_type: ControlType::CongestionWarning, additional_info: 0, timestamp_us: 1, dst_socket_id: 2 },
                body: ControlBody::CongestionWarning,
            },
        ] {
            let rt = round_trip(pkt);
            assert!(matches!(rt, Packet::Control { .. }));
        }
    }

    #[test]
    fn data_boundary_flags() {
        for (boundary, expected) in [
            (MsgBoundary::Solo,   0b11u32),
            (MsgBoundary::First,  0b10),
            (MsgBoundary::Last,   0b01),
            (MsgBoundary::Middle, 0b00),
        ] {
            let mut buf = BytesMut::new();
            encode_data(SeqNo::new(0), boundary, false, MsgNo::new(0), 0, 0, b"x", &mut buf);
            let word1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
            assert_eq!(word1 >> 30, expected, "boundary {:?}", boundary);
        }
    }
}
