//! The packet decoder against arbitrary bytes.
//!
//! This is the first thing any datagram off the network touches, before the
//! peer has proved anything about itself. It must never panic, however
//! malformed the input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = udt_proto::fuzz::decode(bytes::Bytes::copy_from_slice(data));
});
