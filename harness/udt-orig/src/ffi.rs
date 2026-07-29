//! Raw cxx bridge to unmodified upstream UDT.
//!
//! Deliberately much smaller than `udt-compat/udt-sys`: there is no
//! `extern "Rust"` block, because upstream has neither the `rpoll::RPoll`
//! readiness bridge nor `rutil::compute_md5` — it uses its own `epoll.cpp` and
//! `md5.cpp`, which this crate compiles.
//!
//! The socket-option numbering below comes from **upstream's** `udt.h`, not the
//! fork's. The fork commented out `UDT_SNDSYN` and put `UDT_CONNSYN = 2` where
//! upstream has `UDT_RCVSYN`, so copying its numbering would silently set the
//! wrong option here.

// This module is the FFI boundary: every declaration in it is necessarily
// unsafe, so the allow sits here rather than on each item.
#![allow(unsafe_code)]

use std::os::raw::c_int;

#[repr(transparent)]
#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub struct Socket(pub c_int);

pub const INVALID_SOCK: Socket = Socket(-1);

unsafe impl cxx::ExternType for Socket {
    type Id = cxx::type_id!("UDTSOCKET");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge(namespace = "UDT")]
mod sys {
    #![allow(clippy::missing_safety_doc)]

    /// Upstream `UDTOpt`, in its original declaration order. Values are
    /// positional, so the whole enum must be listed even where unused.
    #[repr(u32)]
    #[cxx_name = "UDTOpt"]
    enum SocketOption {
        #[rust_name = "Mss"]
        UDT_MSS,
        #[rust_name = "SendSyn"]
        UDT_SNDSYN,
        #[rust_name = "RecvSyn"]
        UDT_RCVSYN,
        #[rust_name = "Cc"]
        UDT_CC,
        #[rust_name = "Fc"]
        UDT_FC,
        #[rust_name = "SendBuf"]
        UDT_SNDBUF,
        #[rust_name = "RecvBuf"]
        UDT_RCVBUF,
        #[rust_name = "Linger"]
        UDT_LINGER,
        #[rust_name = "UdpSendBuf"]
        UDP_SNDBUF,
        #[rust_name = "UdpRecvBuf"]
        UDP_RCVBUF,
        #[rust_name = "MaxMsg"]
        UDT_MAXMSG,
        #[rust_name = "MsgTtl"]
        UDT_MSGTTL,
        #[rust_name = "Rendezvous"]
        UDT_RENDEZVOUS,
        #[rust_name = "SendTimeout"]
        UDT_SNDTIMEO,
        #[rust_name = "RecvTimeout"]
        UDT_RCVTIMEO,
        #[rust_name = "ReuseAddr"]
        UDT_REUSEADDR,
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
        #[cxx_name = "UDTSOCKET"]
        type Socket = crate::ffi::Socket;

        unsafe fn startup() -> i32;
        unsafe fn cleanup() -> i32;
        unsafe fn socket(af: i32, type_: i32, protocol: i32) -> Socket;
        unsafe fn bind(u: Socket, name: *const sockaddr, namelen: i32) -> i32;
        unsafe fn listen(u: Socket, backlog: i32) -> i32;
        unsafe fn accept(u: Socket, addr: *mut sockaddr, addrlen: *mut i32) -> Socket;
        unsafe fn connect(u: Socket, name: *const sockaddr, namelen: i32) -> i32;
        unsafe fn close(u: Socket) -> i32;
        unsafe fn getsockname(u: Socket, name: *mut sockaddr, namelen: *mut i32) -> i32;
        unsafe fn setsockopt(
            u: Socket,
            level: i32,
            optname: SocketOption,
            optval: *const c_void,
            optlen: i32,
        ) -> i32;
        unsafe fn sendmsg(
            u: Socket,
            buf: *const c_char,
            len: i32,
            ttl_ms: i32,
            inorder: bool,
        ) -> i32;
        unsafe fn recvmsg(u: Socket, buf: *mut c_char, len: i32) -> i32;
        unsafe fn getlasterror_code() -> i32;
    }
}

pub use sys::*;
