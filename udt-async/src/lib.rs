//! Async runtime drivers for [`udt_proto`].
//!
//! `forbid(unsafe_code)` is deliberate and load-bearing: platform-specific IO
//! optimisations must arrive through a safe wrapper rather than raw syscalls
//! written here.
#![forbid(unsafe_code)]

#[cfg(feature = "tokio")]
mod tokio_impl;
#[cfg(feature = "tokio")]
pub use tokio_impl::{
    Endpoint, EndpointConfig, Listener, OwnedReadHalf, OwnedWriteHalf, ReadHalf, Socket, WriteHalf,
    DEFAULT_MSS, UDT_HEADER_SIZE, UDP_OVERHEAD_V4, UDP_OVERHEAD_V6,
};

/// Congestion-control selection for [`EndpointConfig`].
#[cfg(feature = "tokio")]
pub use udt_proto::CcKind;

/// Maximum application payload per UDT packet with the default MSS.
///
/// Equal to `DEFAULT_MSS − UDP_OVERHEAD_V6 − UDT_HEADER_SIZE = 1436 bytes`.
#[cfg(feature = "tokio")]
pub const MAX_PAYLOAD_SIZE: usize =
    DEFAULT_MSS as usize - UDP_OVERHEAD_V6 as usize - UDT_HEADER_SIZE;
