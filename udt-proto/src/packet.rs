//! Decoded UDT packet structures.
//!
//! These mirror the wire format one-to-one. A few fields are decoded but not
//! consumed by the current state machine — they are kept so the decoder stays
//! a faithful, testable model of the format rather than only of what we
//! happen to act on.

use crate::handshake::Handshake;
use crate::seq::{AckSeqNo, MsgNo, SeqNo};
use bytes::Bytes;

/// Message boundary flags (bits 31-30 of data packet word 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgBoundary {
    Solo = 0b11,   // complete single-packet message
    First = 0b10,  // first packet of a multi-packet message
    Last = 0b01,   // last packet
    Middle = 0b00, // middle packet
}

impl MsgBoundary {
    pub fn from_bits(v: u32) -> Self {
        match v & 0b11 {
            0b11 => MsgBoundary::Solo,
            0b10 => MsgBoundary::First,
            0b01 => MsgBoundary::Last,
            _ => MsgBoundary::Middle,
        }
    }

    pub fn bits(self) -> u32 {
        self as u32
    }

    pub fn is_first(self) -> bool {
        matches!(self, MsgBoundary::Solo | MsgBoundary::First)
    }

    pub fn is_last(self) -> bool {
        matches!(self, MsgBoundary::Solo | MsgBoundary::Last)
    }
}

/// Control packet type (bits 30-16 of control packet word 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlType {
    Handshake,         // 0x0000
    KeepAlive,         // 0x0001
    Ack,               // 0x0002
    Nak,               // 0x0003
    CongestionWarning, // 0x0004
    Shutdown,          // 0x0005
    Ack2,              // 0x0006
    MsgDrop,           // 0x0007
    ErrorSignal,       // 0x0008
    UserDefined(u16),  // 0x7FFF — extended type carried separately
}

impl ControlType {
    pub fn from_word(type_bits: u32, ext_bits: u32) -> Option<Self> {
        match type_bits {
            0x0000 => Some(ControlType::Handshake),
            0x0001 => Some(ControlType::KeepAlive),
            0x0002 => Some(ControlType::Ack),
            0x0003 => Some(ControlType::Nak),
            0x0004 => Some(ControlType::CongestionWarning),
            0x0005 => Some(ControlType::Shutdown),
            0x0006 => Some(ControlType::Ack2),
            0x0007 => Some(ControlType::MsgDrop),
            0x0008 => Some(ControlType::ErrorSignal),
            0x7FFF => Some(ControlType::UserDefined(ext_bits as u16)),
            _ => None,
        }
    }

    pub fn type_bits(self) -> u16 {
        match self {
            ControlType::Handshake => 0x0000,
            ControlType::KeepAlive => 0x0001,
            ControlType::Ack => 0x0002,
            ControlType::Nak => 0x0003,
            ControlType::CongestionWarning => 0x0004,
            ControlType::Shutdown => 0x0005,
            ControlType::Ack2 => 0x0006,
            ControlType::MsgDrop => 0x0007,
            ControlType::ErrorSignal => 0x0008,
            ControlType::UserDefined(_) => 0x7FFF,
        }
    }
}

/// A parsed data packet header (16 bytes).
#[derive(Debug, Clone)]
pub struct DataHeader {
    pub seq_no: SeqNo,
    pub boundary: MsgBoundary,
    pub in_order: bool,
    pub msg_no: MsgNo,
    #[allow(dead_code)]
    pub timestamp_us: u32,
    pub dst_socket_id: u32,
}

/// A parsed control packet header (16 bytes).
#[derive(Debug, Clone)]
pub struct ControlHeader {
    pub ctrl_type: ControlType,
    /// Word 1 ("additional info"). Meaning depends on ctrl_type:
    /// Ack/Ack2: ACK sub-sequence number; MsgDrop: message ID; Error: error code.
    pub additional_info: u32,
    pub timestamp_us: u32,
    pub dst_socket_id: u32,
}

/// Parsed loss list from a NAK packet.
#[derive(Debug, Clone)]
pub struct NakList(pub Vec<(SeqNo, SeqNo)>); // (start, end) inclusive ranges

/// ACK payload (variable; light ACK has only data_ack_seq, full ACK has all fields).
#[derive(Debug, Clone)]
pub struct AckPayload {
    pub data_ack_seq: SeqNo,
    pub full: Option<AckFull>,
    /// Ranges above `data_ack_seq` the peer says arrived, if it sends them.
    ///
    /// An extension: UDT has no selective acknowledgement, and a peer that
    /// does not implement it leaves this empty — which is every C++ peer. See
    /// `docs/selective-ack.md` for why appending them is compatible.
    pub sack: Vec<(SeqNo, SeqNo)>,
}

#[derive(Debug, Clone, Copy)]
pub struct AckFull {
    pub rtt_us: i32,
    pub rtt_var_us: i32,
    pub avail_buf_pkts: i32,
    pub rcv_rate_pps: i32,
    pub bandwidth_pps: i32,
}

/// A fully parsed UDT packet.
#[derive(Debug, Clone)]
pub enum Packet {
    Data { header: DataHeader, payload: Bytes },
    Control { header: ControlHeader, body: ControlBody },
}

/// Parsed control packet body.
#[derive(Debug, Clone)]
pub enum ControlBody {
    Handshake(Handshake),
    KeepAlive,
    Ack(AckSeqNo, AckPayload), // (ack_sub_seq_no, payload)
    Nak(NakList),
    CongestionWarning,
    Shutdown,
    Ack2(AckSeqNo), // ACK sub-seq no being acknowledged
    MsgDrop {
        msg_no: MsgNo,
        first: SeqNo,
        last: SeqNo,
    },
    ErrorSignal {
        #[allow(dead_code)]
        error_code: i32,
    },
    UserDefined {
        #[allow(dead_code)]
        ext_type: u16,
        #[allow(dead_code)]
        payload: Bytes,
    },
}
