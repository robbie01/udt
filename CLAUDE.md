# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A pure-Rust reimplementation of the UDT (UDP-based Data Transfer) protocol, wire-compatible with the original C++ implementation. Only `SOCK_DGRAM` mode is implemented. The repo also keeps the original C++ implementation wrapped in `udt-compat` for cross-compatibility integration tests.

## Commands

```bash
# Build everything
cargo build

# Run all tests (includes C++ build via cxx-build)
cargo test

# Run a single integration test (useful during development)
cargo test -p udt-integration-tests s2_new_listener_old_connector_small -- --nocapture

# Run proto unit tests only (fast, no C++)
cargo test -p udt-proto

# Run all integration tests
cargo test -p udt-integration-tests

# Build udt-async with tokio feature (required — no default features)
cargo build -p udt-async --features tokio
```

The integration tests link against the C++ UDT library via `cxx-rs`; any change to `udt-compat/udt-sys/udt/*.cpp` triggers a C++ recompile via `build.rs`.

## Workspace layout

```
udt-proto/       IO-free state machine + codec (no runtime deps)
udt-async/       Tokio and async-io runtime drivers (feature-gated)
udt-compat/      Rust wrapper around the original C++ UDT library (for testing)
  udt-sys/       cxx-rs FFI + C++ source under udt-sys/udt/
udt-compio/      compio runtime driver (stub — not yet implemented)
tests/integration/  Wire-compat integration tests (all 5 scenarios)
```

## Architecture

### Layer model

```
Application
    ↓  async API (Endpoint / Listener / Socket)
udt-async  (tokio_impl.rs)
    ↓  calls
udt-proto  (IO-free state machine)
    ↓  emits Vec<Output>
Driver task  (sends via UdpSocket, forwards to channels)
```

### udt-proto: the IO-free core

Everything protocol-related lives here. It is deliberately zero-allocation in the hot path and has no async/runtime dependency.

**`Connection`** (`connection.rs`) is the central type. It is driven by three methods:
- `on_datagram(bytes, now_us, out)` — call for every received UDP datagram
- `on_timer(now_us, out)` — call when `next_deadline_us()` elapses
- `send_msg(payload, ttl_ms, in_order, now_us, out)` — enqueue application data

All three append to `out: &mut Vec<Output>`. The caller drains `out` after each call:
- `Output::SendDatagram(bytes)` → send via UDP
- `Output::DataReady` → call `conn.recv_msg()` to drain complete messages
- `Output::Connected` → connection handshake finished
- `Output::Disconnected(reason)` → clean up

**`ListenerState`** (`listener.rs`) is the IO-free listener state machine. It handles the SYN-cookie handshake and emits `ListenerOutput::Accept(Connection, PeerAddr)` when a connection is ready.

**Codec** (`codec.rs`): all header words and control-body words are **big-endian** on the wire (C++ `channel.cpp` uses `htonl`/`ntohl`). Data payloads are raw bytes with no byte-swap. `codec::decode` returns zero-copy `Bytes` slices into the original datagram buffer.

**Sequence numbers** (`seq.rs`): `SeqNo` is 31-bit (wraps at `0x7FFF_FFFF`); `MsgNo` is 29-bit; `AckSeqNo` is 31-bit but in an independent space. All three implement modular `PartialOrd` using the half-space threshold rule.

**Handshake** (`handshake.rs`): 48 bytes = 12 × big-endian i32. The listener echoes the client's ISN as its own (`m_iISN = hs->m_iISN` in the C++ server path); both `local_isn` and `peer_isn` are set to the client's ISN on accepted connections.

**Congestion control** (`congestion/`): pluggable via the `CongestionControl` trait. Two implementations: `UdtCc` (port of `CUDTCC` from `ccc.cpp`) and `Ledbat` (RFC 6817, using RTT/2 as OWD proxy since UDT lacks native OWD). The active default is `UdtCc`.

### udt-async: the tokio driver

`tokio_impl.rs` runs two task types:

**Listener driver** (`run_listener_driver`): owns the UDP socket. Reads datagrams in a loop. Packets from known peers are forwarded via `mpsc::Sender<Bytes>` channels directly to the connection driver; new-peer packets go to `ListenerState`.

**Connection driver** (`run_conn_driver`): shared between accepted connections (which receive forwarded datagrams via channel) and active connections (which read directly from a per-connection UDP socket). It `select!`s across three arms: incoming datagram/channel, send request from application, and timer deadline.

Public API types — `Endpoint`, `Listener`, `Socket` — are thin wrappers over channels to the driver tasks.

### udt-compat: C++ interop

`udt-sys` wraps the original UDT C++ source with `cxx-rs`. `rpoll.rs` implements a Rust-side epoll replacement using `tokio::sync::Notify` with `notify_one()` (not `notify_waiters()` — the latter doesn't store permits for future waiters, causing a race in `recv()`).

**Known C++ race fix** (`queue.cpp`): the C++ recv worker flushes `setNewEntry` registrations immediately after each `recvfrom` return (before routing), not only at the top of the loop. This prevents a race where a fast peer sends data before the C++ socket has been inserted into the routing hash.

### Integration tests

Five scenarios, each tested at small/medium/large payload sizes:

| Test | Listener | Connector |
|------|----------|-----------|
| S1   | Rust     | Rust      |
| S2   | Rust     | C++       |
| S3   | C++      | Rust      |
| S4   | Rust rendezvous | Rust rendezvous |
| S5   | C++ rendezvous  | Rust rendezvous |

All 15 scenarios (all three payload sizes for every scenario) pass.

## Wire format notes

- **Header**: 4 × 32-bit big-endian words for both data and control packets.
  - Data: `[seq_no | boundary+inorder+msg_no | timestamp_us | dst_socket_id]`
  - Control: `[ctrl=1 | type | ext_type | add_info | timestamp_us | dst_socket_id]`
- **Control bodies**: each 32-bit word is big-endian (C++ `htonl`s before send, `ntohl`s on receive).
- **Data payloads**: raw application bytes, no byte-swap.
- **Handshake payload**: 12 × big-endian i32 (48 bytes total).
- **ISN symmetry**: the server sets `m_iISN = client_ISN` (C++ `core.cpp` line ~771). The Rust listener mirrors this: `local_isn = peer_isn = client_isn`.
