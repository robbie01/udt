use crate::handshake::{HANDSHAKE_SIZE, Handshake};
use crate::packet::{
    AckFull, AckPayload, ControlBody, ControlHeader, ControlType, DataHeader, MsgBoundary, NakList,
    Packet,
};
use crate::seq::{AckSeqNo, MsgNo, SeqNo};
use bytes::{BufMut, Bytes, BytesMut};

// The UDT wire format uses NETWORK BYTE ORDER (big-endian) for:
//   • All 4 header words (both data and control packets)
//   • All 4-byte words in the bodies of CONTROL packets
// Data packet payloads are raw application bytes with no byte-order conversion.
// This matches what C++ channel.cpp does with htonl/ntohl before/after sendmsg/recvmsg.

/// The destination socket id in a datagram's header, without decoding the rest.
///
/// A demultiplexer needs this and nothing else, and it runs per datagram on the
/// receive path, so it is worth not decoding a whole packet to get it. `None`
/// means the datagram is too short to have a header at all.
///
/// Zero is a real value here and means "no particular connection" — a handshake
/// from a peer that does not yet know what id to use.
pub fn dst_socket_id(datagram: &[u8]) -> Option<u32> {
    datagram.get(12..16).map(read_be_u32)
}

/// Decode a single UDT packet from a datagram.
///
/// The returned `Bytes` for data payloads slices into the provided `datagram`
/// (zero-copy via ref-count bump).
pub fn decode(datagram: Bytes) -> Option<Packet> {
    if datagram.len() < 16 {
        return None;
    }
    let word0 = read_be_u32(&datagram[0..4]);
    let word1 = read_be_u32(&datagram[4..8]);
    let word2 = read_be_u32(&datagram[8..12]);
    let word3 = read_be_u32(&datagram[12..16]);

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
        let ext_bits = word0 & 0xFFFF;
        let ctrl_type = ControlType::from_word(type_bits, ext_bits)?;
        let add_info = word1;
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
            let data_ack = SeqNo::new(read_be_i32(&payload[0..4]) as u32);
            // UDT has three ACK sizes: 4 bytes is a lite ACK (acknowledgement
            // point only); 16 bytes adds RTT, RTT variance and the peer's free
            // buffer size; 24 bytes further adds its rate estimates.  C++ emits
            // the 16-byte form whenever a full ACK follows within one SYN
            // interval of the last one, so treating anything under 24 bytes as
            // lite would drop most flow-window updates on the floor.
            let full = if payload.len() >= 16 {
                Some(AckFull {
                    rtt_us: read_be_i32(&payload[4..8]),
                    rtt_var_us: read_be_i32(&payload[8..12]),
                    avail_buf_pkts: read_be_i32(&payload[12..16]),
                    // Absent in the 16-byte form.  Zero reads as "no sample"
                    // and is skipped by the rate estimators, as in C++.
                    rcv_rate_pps: if payload.len() >= 24 {
                        read_be_i32(&payload[16..20])
                    } else {
                        0
                    },
                    bandwidth_pps: if payload.len() >= 24 {
                        read_be_i32(&payload[20..24])
                    } else {
                        0
                    },
                })
            } else {
                None
            };
            // Selective acknowledgement, from a peer that sends it: bit31-tagged
            // ranges appended after the 24-byte full body, encoded as a NAK list
            // is. A malformed tail is dropped rather than failing the packet —
            // the acknowledgement point in front of it is still good, and some
            // later extension may put something here that is not ranges.
            let sack = if payload.len() > 24 {
                decode_seq_ranges(&payload[24..]).unwrap_or_default()
            } else {
                Vec::new()
            };
            Some(ControlBody::Ack(
                AckSeqNo::new(hdr.additional_info),
                AckPayload { data_ack_seq: data_ack, full, sack },
            ))
        }
        ControlType::Nak => {
            let nak = decode_nak_list(&payload)?;
            Some(ControlBody::Nak(nak))
        }
        ControlType::CongestionWarning => Some(ControlBody::CongestionWarning),
        ControlType::Shutdown => Some(ControlBody::Shutdown),
        ControlType::Ack2 => Some(ControlBody::Ack2(AckSeqNo::new(hdr.additional_info))),
        ControlType::MsgDrop => {
            if payload.len() < 8 {
                return None;
            }
            let first = SeqNo::new(read_be_i32(&payload[0..4]) as u32 & 0x7FFF_FFFF);
            let last = SeqNo::new(read_be_i32(&payload[4..8]) as u32 & 0x7FFF_FFFF);
            Some(ControlBody::MsgDrop { msg_no: MsgNo::new(hdr.additional_info), first, last })
        }
        ControlType::ErrorSignal => {
            Some(ControlBody::ErrorSignal { error_code: hdr.additional_info as i32 })
        }
        ControlType::UserDefined(ext_type) => Some(ControlBody::UserDefined { ext_type, payload }),
    }
}

fn decode_nak_list(payload: &[u8]) -> Option<NakList> {
    decode_seq_ranges(payload).map(NakList)
}

/// Decode bit31-tagged sequence ranges: a word with bit 31 set opens a range
/// whose end is the following word, and a bare word is a single sequence.
///
/// Shared by NAK bodies and the selective-acknowledgement tail of an ACK,
/// which use the same encoding.
fn decode_seq_ranges(payload: &[u8]) -> Option<Vec<(SeqNo, SeqNo)>> {
    if !payload.len().is_multiple_of(4) {
        return None;
    }
    let mut ranges = Vec::new();
    let mut i = 0;
    while i + 4 <= payload.len() {
        let word = read_be_u32(&payload[i..i + 4]);
        i += 4;
        if word >> 31 != 0 {
            // Start of a range; next word is the end
            if i + 4 > payload.len() {
                return None;
            }
            let start = SeqNo::new(word & 0x7FFF_FFFF);
            let end_word = read_be_u32(&payload[i..i + 4]);
            let end = SeqNo::new(end_word & 0x7FFF_FFFF);
            i += 4;
            ranges.push((start, end));
        } else {
            let s = SeqNo::new(word & 0x7FFF_FFFF);
            ranges.push((s, s));
        }
    }
    Some(ranges)
}

/// Append bit31-tagged sequence ranges, the encoding NAK bodies and the ACK
/// selective-acknowledgement tail share.
fn put_seq_ranges(ranges: &[(SeqNo, SeqNo)], body: &mut BytesMut) {
    for &(start, end) in ranges {
        if start == end {
            body.put_u32(start.raw()); // single, bit31 clear
        } else {
            body.put_u32(start.raw() | 0x8000_0000); // range start, bit31 set
            body.put_u32(end.raw()); // range end, bit31 clear
        }
    }
}

// ── Encoder ─────────────────────────────────────────────────────────────────

/// Encode a full data packet into `dst`.
///
/// The send path uses [`encode_data_header`] instead, writing the header and
/// payload into an arena separately; this whole-packet form exists for
/// round-trip tests.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
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
    let word1 = (boundary.bits() << 30) | ((in_order as u32) << 29) | (msg_no.raw() & 0x1FFF_FFFF);
    dst.put_u32(word0);
    dst.put_u32(word1);
    dst.put_u32(timestamp_us);
    dst.put_u32(dst_socket_id);
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
    let word1 = (boundary.bits() << 30) | ((in_order as u32) << 29) | (msg_no.raw() & 0x1FFF_FFFF);
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&word0.to_be_bytes());
    out[4..8].copy_from_slice(&word1.to_be_bytes());
    out[8..12].copy_from_slice(&timestamp_us.to_be_bytes());
    out[12..16].copy_from_slice(&dst_socket_id.to_be_bytes());
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
    let word0 = 0x8000_0000u32 | ((ctrl_type.type_bits() as u32) << 16) | ext_bits;
    dst.put_u32(word0);
    dst.put_u32(additional_info);
    dst.put_u32(timestamp_us);
    dst.put_u32(dst_socket_id);
    dst.put_slice(payload);
}

/// Encode a handshake control packet into `dst`.
pub fn encode_handshake(hs: &Handshake, timestamp_us: u32, dst_socket_id: u32, dst: &mut BytesMut) {
    let mut body = [0u8; HANDSHAKE_SIZE];
    hs.write_to(&mut body);
    encode_control(ControlType::Handshake, 0, timestamp_us, dst_socket_id, &body, dst);
}

/// Encode an ACK packet into `dst`. `full` is optional; if None a light ACK is sent.
///
/// `sack` appends selectively acknowledged ranges after the full body, and is
/// **ignored unless `full` is `Some`**. That is enforced here rather than left
/// to callers because getting it wrong is silent and remote: the C++ reference
/// reads its rate fields whenever the body runs past 16 bytes, so ranges hung
/// off a short ACK arrive as a delivery rate and a bandwidth estimate and go
/// straight into the peer's pacing. See `docs/selective-ack.md`.
pub fn encode_ack(
    ack_sub_seq: AckSeqNo,
    data_ack_seq: SeqNo,
    full: Option<&AckFull>,
    sack: &[(SeqNo, SeqNo)],
    timestamp_us: u32,
    dst_socket_id: u32,
    dst: &mut BytesMut,
) {
    let mut body = BytesMut::with_capacity(if full.is_some() { 24 + sack.len() * 8 } else { 4 });
    body.put_i32(data_ack_seq.raw() as i32);
    if let Some(f) = full {
        body.put_i32(f.rtt_us);
        body.put_i32(f.rtt_var_us);
        body.put_i32(f.avail_buf_pkts);
        body.put_i32(f.rcv_rate_pps);
        body.put_i32(f.bandwidth_pps);
        put_seq_ranges(sack, &mut body);
    }
    encode_control(ControlType::Ack, ack_sub_seq.raw(), timestamp_us, dst_socket_id, &body, dst);
}

/// Encode an ACK2 packet.
pub fn encode_ack2(
    ack_sub_seq: AckSeqNo,
    timestamp_us: u32,
    dst_socket_id: u32,
    dst: &mut BytesMut,
) {
    // ACK2 has a 4-byte padding payload (C++ uses __pad for iovec requirements)
    encode_control(
        ControlType::Ack2,
        ack_sub_seq.raw(),
        timestamp_us,
        dst_socket_id,
        &[0u8; 4],
        dst,
    );
}

/// Encode a NAK packet from a list of (start, end) sequence ranges.
pub fn encode_nak(
    ranges: &[(SeqNo, SeqNo)],
    timestamp_us: u32,
    dst_socket_id: u32,
    dst: &mut BytesMut,
) {
    let mut body = BytesMut::with_capacity(ranges.len() * 8);
    put_seq_ranges(ranges, &mut body);
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
    body[0..4].copy_from_slice(&(first.raw() as i32).to_be_bytes());
    body[4..8].copy_from_slice(&(last.raw() as i32).to_be_bytes());
    encode_control(ControlType::MsgDrop, msg_no.raw(), timestamp_us, dst_socket_id, &body, dst);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn read_be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

#[inline]
fn read_be_i32(b: &[u8]) -> i32 {
    i32::from_be_bytes(b[..4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    /// The cheap accessor must agree with a full decode, and must not panic on
    /// a runt. It reads attacker-supplied bytes before anything is validated.
    #[test]
    fn dst_socket_id_matches_a_full_decode() {
        let mut buf = BytesMut::new();
        encode_keepalive(1234, 0xDEAD_BEEF, &mut buf);
        let bytes = buf.freeze();
        assert_eq!(dst_socket_id(&bytes), Some(0xDEAD_BEEF));

        for n in 0..16 {
            assert_eq!(dst_socket_id(&bytes[..n]), None, "len {n} should have no header");
        }
    }

    use super::*;
    use crate::handshake::{SOCK_DGRAM, UDT_VERSION, req_type};
    use bytes::Bytes;

    fn round_trip(pkt: Packet) -> Packet {
        let mut buf = BytesMut::new();
        match &pkt {
            Packet::Data { header: h, payload: p } => {
                encode_data(
                    h.seq_no,
                    h.boundary,
                    h.in_order,
                    h.msg_no,
                    h.timestamp_us,
                    h.dst_socket_id,
                    p,
                    &mut buf,
                );
            }
            Packet::Control { header: h, body } => match body {
                ControlBody::Handshake(hs) => {
                    encode_handshake(hs, h.timestamp_us, h.dst_socket_id, &mut buf)
                }
                ControlBody::KeepAlive => {
                    encode_keepalive(h.timestamp_us, h.dst_socket_id, &mut buf)
                }
                ControlBody::Ack(asn, payload) => encode_ack(
                    *asn,
                    payload.data_ack_seq,
                    payload.full.as_ref(),
                    &payload.sack,
                    h.timestamp_us,
                    h.dst_socket_id,
                    &mut buf,
                ),
                ControlBody::Nak(nak) => {
                    encode_nak(&nak.0, h.timestamp_us, h.dst_socket_id, &mut buf)
                }
                ControlBody::CongestionWarning => encode_control(
                    ControlType::CongestionWarning,
                    0,
                    h.timestamp_us,
                    h.dst_socket_id,
                    &[0u8; 4],
                    &mut buf,
                ),
                ControlBody::Shutdown => encode_shutdown(h.timestamp_us, h.dst_socket_id, &mut buf),
                ControlBody::Ack2(asn) => {
                    encode_ack2(*asn, h.timestamp_us, h.dst_socket_id, &mut buf)
                }
                ControlBody::MsgDrop { msg_no, first, last } => encode_msg_drop(
                    *msg_no,
                    *first,
                    *last,
                    h.timestamp_us,
                    h.dst_socket_id,
                    &mut buf,
                ),
                ControlBody::ErrorSignal { error_code } => encode_control(
                    ControlType::ErrorSignal,
                    *error_code as u32,
                    h.timestamp_us,
                    h.dst_socket_id,
                    &[],
                    &mut buf,
                ),
                ControlBody::UserDefined { ext_type, payload } => encode_control(
                    ControlType::UserDefined(*ext_type),
                    0,
                    h.timestamp_us,
                    h.dst_socket_id,
                    payload,
                    &mut buf,
                ),
            },
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
            peer_ip: [127, 0, 0, 0], // 127.0.0.1 LE: first word = 127
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
                AckPayload { data_ack_seq: SeqNo::new(500), full: None, sack: Vec::new() },
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
        let full = AckFull {
            rtt_us: 1000,
            rtt_var_us: 200,
            avail_buf_pkts: 8192,
            rcv_rate_pps: 1000,
            bandwidth_pps: 5000,
        };
        let pkt = Packet::Control {
            header: ControlHeader {
                ctrl_type: ControlType::Ack,
                additional_info: 10,
                timestamp_us: 0,
                dst_socket_id: 0,
            },
            body: ControlBody::Ack(
                AckSeqNo::new(10),
                AckPayload { data_ack_seq: SeqNo::new(99), full: Some(full), sack: Vec::new() },
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

    fn ack_with_sack(sack: Vec<(SeqNo, SeqNo)>) -> Packet {
        Packet::Control {
            header: ControlHeader {
                ctrl_type: ControlType::Ack,
                additional_info: 10,
                timestamp_us: 0,
                dst_socket_id: 0,
            },
            body: ControlBody::Ack(
                AckSeqNo::new(10),
                AckPayload {
                    data_ack_seq: SeqNo::new(99),
                    full: Some(AckFull {
                        rtt_us: 1000,
                        rtt_var_us: 200,
                        avail_buf_pkts: 8192,
                        rcv_rate_pps: 1234,
                        bandwidth_pps: 5000,
                    }),
                    sack,
                },
            ),
        }
    }

    #[test]
    fn ack_sack_roundtrip() {
        let sack = vec![(SeqNo::new(105), SeqNo::new(140)), (SeqNo::new(150), SeqNo::new(150))];
        let rt = round_trip(ack_with_sack(sack.clone()));
        if let Packet::Control { body: ControlBody::Ack(_, payload), .. } = rt {
            assert_eq!(payload.sack, sack);
            // The fields in front of it must survive untouched.
            assert_eq!(payload.data_ack_seq, SeqNo::new(99));
            let f = payload.full.unwrap();
            assert_eq!(f.rcv_rate_pps, 1234);
            assert_eq!(f.bandwidth_pps, 5000);
        } else {
            panic!("expected Ack");
        }
    }

    /// The property the extension rests on: a decoder that knows nothing about
    /// selective acknowledgement must read the ACK in front of it exactly as it
    /// would a plain 24-byte one. This is what a C++ peer does, and getting it
    /// wrong corrupts its rate estimates rather than failing visibly.
    #[test]
    fn a_sack_tail_is_invisible_to_a_decoder_that_ignores_it() {
        let mut with = BytesMut::new();
        let mut without = BytesMut::new();
        let full = AckFull {
            rtt_us: 1000,
            rtt_var_us: 200,
            avail_buf_pkts: 8192,
            rcv_rate_pps: 1234,
            bandwidth_pps: 5000,
        };
        let sack = [(SeqNo::new(105), SeqNo::new(140))];
        encode_ack(AckSeqNo::new(10), SeqNo::new(99), Some(&full), &sack, 0, 0, &mut with);
        encode_ack(AckSeqNo::new(10), SeqNo::new(99), Some(&full), &[], 0, 0, &mut without);

        // Identical up to the end of the documented body, longer after it.
        assert_eq!(&with[..16 + 24], &without[..16 + 24]);
        assert_eq!(without.len(), 16 + 24);
        assert_eq!(with.len(), 16 + 24 + 8);
    }

    /// Ranges are dropped on a light ACK rather than written. A 4-byte body plus
    /// ranges would read as a full ACK to the C++ peer, which takes the rate
    /// fields from anything longer than 16 bytes — so the first two range words
    /// would land in its delivery-rate and bandwidth estimators.
    #[test]
    fn a_light_ack_never_carries_sack_ranges() {
        let mut buf = BytesMut::new();
        let sack = [(SeqNo::new(105), SeqNo::new(140))];
        encode_ack(AckSeqNo::new(0), SeqNo::new(99), None, &sack, 0, 0, &mut buf);
        assert_eq!(buf.len(), 16 + 4, "light ACK body grew: {buf:?}");

        let rt = decode(buf.freeze()).expect("decode");
        if let Packet::Control { body: ControlBody::Ack(_, payload), .. } = rt {
            assert!(payload.full.is_none());
            assert!(payload.sack.is_empty());
        } else {
            panic!("expected Ack");
        }
    }

    /// A tail that is not a whole number of words must not cost us the
    /// acknowledgement point in front of it.
    #[test]
    fn a_malformed_sack_tail_does_not_discard_the_ack() {
        let mut buf = BytesMut::new();
        let full = AckFull {
            rtt_us: 1000,
            rtt_var_us: 200,
            avail_buf_pkts: 8192,
            rcv_rate_pps: 1234,
            bandwidth_pps: 5000,
        };
        encode_ack(AckSeqNo::new(10), SeqNo::new(99), Some(&full), &[], 0, 0, &mut buf);
        buf.put_slice(&[0xAB, 0xCD, 0xEF]); // three bytes: not a word

        let rt = decode(buf.freeze()).expect("an odd tail must not fail the ACK");
        if let Packet::Control { body: ControlBody::Ack(_, payload), .. } = rt {
            assert_eq!(payload.data_ack_seq, SeqNo::new(99));
            assert_eq!(payload.full.unwrap().rcv_rate_pps, 1234);
            assert!(payload.sack.is_empty());
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
                header: ControlHeader {
                    ctrl_type: ControlType::Shutdown,
                    additional_info: 0,
                    timestamp_us: 1,
                    dst_socket_id: 2,
                },
                body: ControlBody::Shutdown,
            },
            Packet::Control {
                header: ControlHeader {
                    ctrl_type: ControlType::KeepAlive,
                    additional_info: 0,
                    timestamp_us: 1,
                    dst_socket_id: 2,
                },
                body: ControlBody::KeepAlive,
            },
            Packet::Control {
                header: ControlHeader {
                    ctrl_type: ControlType::CongestionWarning,
                    additional_info: 0,
                    timestamp_us: 1,
                    dst_socket_id: 2,
                },
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
            (MsgBoundary::Solo, 0b11u32),
            (MsgBoundary::First, 0b10),
            (MsgBoundary::Last, 0b01),
            (MsgBoundary::Middle, 0b00),
        ] {
            let mut buf = BytesMut::new();
            encode_data(SeqNo::new(0), boundary, false, MsgNo::new(0), 0, 0, b"x", &mut buf);
            let word1 = u32::from_be_bytes(buf[4..8].try_into().unwrap());
            assert_eq!(word1 >> 30, expected, "boundary {:?}", boundary);
        }
    }
}
