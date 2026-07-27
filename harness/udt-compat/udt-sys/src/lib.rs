mod rpoll;
// mod list;

use std::os::raw::c_int;

use cxx::CxxString;
pub use rpoll::*;

#[repr(transparent)]
#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub struct Socket(c_int);

// Don't know how to do extern variables with cxx. Luckily this will never change.
pub const INVALID_SOCK: Socket = Socket(-1);

unsafe impl cxx::ExternType for Socket {
    type Id = cxx::type_id!("UDTSOCKET");
    type Kind = cxx::kind::Trivial;
}

pub const ENOSERVER: i32 = 1001;
pub const ECONNREJ: i32 = 1002;
pub const ESECFAIL: i32 = 1004;
pub const ECONNLOST: i32 = 2001;
pub const ENOCONN: i32 = 2002;
pub const EINVOP: i32 = 5000;
pub const EBOUNDSOCK: i32 = 5001;
pub const ECONNSOCK: i32 = 5002;
pub const EINVPARAM: i32 = 5003;
pub const EINVSOCK: i32 = 5004;
pub const EUNBOUNDSOCK: i32 = 5005;
pub const ENOLISTEN: i32 = 5006;
pub const ERDVNOSERV: i32 = 5007;
pub const ERDVUNBOUND: i32 = 5008;
pub const ESTREAMILL: i32 = 5009;
pub const EDGRAMILL: i32 = 5010;
pub const ELARGEMSG: i32 = 5012;
pub const EASYNCSND: i32 = 6001;
pub const EASYNCRCV: i32 = 6002;
pub const EPEERERR: i32 = 7000;

fn new_rpoll() -> Box<RPoll> {
    Box::default()
}

fn compute_md5(s: &CxxString, digest: &mut [u8; 16]) {
    use md5::Digest as _;

    *digest = md5::Md5::digest(s.as_bytes()).0;
}

#[cxx::bridge(namespace = "UDT")]
mod ffi {
    #![allow(clippy::missing_safety_doc)]

    #[repr(u32)]
    #[cxx_name = "UDTOpt"]
    enum SocketOption {
        #[rust_name = "Mss"]
        UDT_MSS,
        // #[rust_name = "SendSyn"]
        // UDT_SNDSYN,
        #[rust_name = "ConnSyn"]
        UDT_CONNSYN = 2,
        #[rust_name = "Cc"]
        UDT_CC,
        #[rust_name = "Fc"]
        UDT_FC,
        #[rust_name = "SendBuf"]
        UDT_SNDBUF,
        #[rust_name = "RecvBuf"]
        UDT_RCVBUF,
        // #[rust_name = "Linger"]
        // UDT_LINGER,
        #[rust_name = "UdpSendBuf"]
        UDP_SNDBUF = 8,
        #[rust_name = "UdpRecvBuf"]
        UDP_RCVBUF,
        #[rust_name = "MaxMsg"]
        UDT_MAXMSG,
        #[rust_name = "MsgTtl"]
        UDT_MSGTTL,
        #[rust_name = "Rendezvous"]
        UDT_RENDEZVOUS,
        // #[rust_name = "SendTimeout"]
        // UDT_SNDTIMEO,
        // #[rust_name = "RecvTimeout"]
        // UDT_RCVTIMEO,
        #[rust_name = "ReuseAddr"]
        UDT_REUSEADDR = 15,
        #[rust_name = "MaxBandwidth"]
        UDT_MAXBW,
        #[rust_name = "State"]
        UDT_STATE,
        #[rust_name = "Event"]
        UDT_EVENT,
        #[rust_name = "SendData"]
        UDT_SNDDATA,
        #[rust_name = "RecvData"]
        UDT_RCVDATA,
    }

    #[repr(u32)]
    #[cxx_name = "UDTSTATUS"]
    enum Status {
        #[rust_name = "Init"]
        INIT = 1,
        #[rust_name = "Opened"]
        OPENED,
        #[rust_name = "Listening"]
        LISTENING,
        #[rust_name = "Connecting"]
        CONNECTING,
        #[rust_name = "Connected"]
        CONNECTED,
        #[rust_name = "Broken"]
        BROKEN,
        #[rust_name = "Closing"]
        CLOSING,
        #[rust_name = "Closed"]
        CLOSED,
        #[rust_name = "Nonexistent"]
        NONEXIST
    }

    #[namespace = ""]
    struct CPerfMon {
        msTimeStamp: i64,
        pktSentTotal: i64,
        pktRecvTotal: i64,
        pktSndLossTotal: i32,
        pktRcvLossTotal: i32,
        pktRetransTotal: i32,
        pktSentACKTotal: i32,
        pktRecvACKTotal: i32,
        pktSentNAKTotal: i32,
        pktRecvNAKTotal: i32,
        usSndDurationTotal: i64,
        pktSent: i64,
        pktRecv: i64,
        pktSndLoss: i32,
        pktRcvLoss: i32,
        pktRetrans: i32,
        pktSentACK: i32,
        pktRecvACK: i32,
        pktSentNAK: i32,
        pktRecvNAK: i32,
        mbpsSendRate: f64,
        mbpsRecvRate: f64,
        usSndDuration: i64,
        usPktSndPeriod: f64,
        pktFlowWindow: i32,
        pktCongestionWindow: i32,
        pktFlightSize: i32,
        msRTT: f64,
        mbpsBandwidth: f64,
        byteAvailSndBuf: i32,
        byteAvailRcvBuf: i32
    }

    #[namespace = "rpoll"]
    extern "Rust" {
        type RPoll;

        fn new_rpoll() -> Box<RPoll>;
        #[cxx_name = "update_events"]
        fn update_events_cxx(&self, socket: Socket, events: u32, value: bool);
        fn remove_usock(&self, socket: Socket);
    }

    #[namespace = "rutil"]
    extern "Rust" {
        fn compute_md5(s: &CxxString, digest: &mut [u8; 16]);
    }

    extern "C++" {
        include!("udt.h");
        include!("bridge.h");

        #[namespace = ""]
        type sockaddr;

        type c_void;

        #[namespace = ""]
        #[cxx_name = "UDTOpt"]
        type SocketOption;

        #[namespace = ""]
        #[cxx_name = "UDTSTATUS"]
        type Status;
        
        #[namespace = ""]
        #[cxx_name = "UDTSOCKET"]
        type Socket = crate::Socket;

        unsafe fn startup() -> i32;
        unsafe fn cleanup() -> i32;
        unsafe fn socket(af: i32, type_: i32, _unused: i32) -> Socket;
        unsafe fn bind(u: Socket, name: *const sockaddr, namelen: i32) -> i32;
        unsafe fn listen(u: Socket, backlog: i32) -> i32;
        unsafe fn accept(u: Socket, addr: *mut sockaddr, addrlen: *mut i32) -> Socket;
        unsafe fn connect(u: Socket, name: *const sockaddr, namelen: i32) -> i32;
        unsafe fn close(u: Socket) -> i32;
        unsafe fn getpeername(u: Socket, name: *mut sockaddr, namelen: *mut i32) -> i32;
        unsafe fn getsockname(u: Socket, name: *mut sockaddr, namelen: *mut i32) -> i32;
        unsafe fn getsockopt(u: Socket, _unused: i32, optname: SocketOption, optval: *mut c_void, optlen: *mut i32) -> i32;
        unsafe fn setsockopt(u: Socket, _unused: i32, optname: SocketOption, optval: *const c_void, optlen: i32) -> i32;
        unsafe fn sendmsg(u: Socket, buf: *const c_char, len: i32, ttl_ms: i32, inorder: bool) -> i32;
        unsafe fn recvmsg(u: Socket, buf: *mut c_char, len: i32) -> i32;
        unsafe fn getlasterror_code() -> i32;
        unsafe fn getsockstate(u: Socket) -> Status;
        unsafe fn perfmon(u: Socket, perf: &mut CPerfMon, clear: bool) -> i32;
    }

    unsafe extern "C++" {
        unsafe fn getlasterror_desc<'a>() -> &'a CxxString;
        unsafe fn getrpoll<'a>() -> &'a RPoll;
    }
}

pub use ffi::*;