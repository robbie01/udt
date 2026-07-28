# Fuzz targets

Three entry points, ordered by how exposed they are:

| target | what it feeds | why |
|---|---|---|
| `listener` | arbitrary datagrams from arbitrary sources | The most exposed surface here. It runs before any connection exists, so anything that can reach the bound port reaches this code, and a spoofed source address costs an attacker nothing. |
| `connection` | arbitrary datagrams to an established connection | Decoding cleanly is not enough — a well-formed packet carrying hostile sequence numbers, lengths or window sizes reaches the loss lists, the receive buffer and congestion control. |
| `decode` | arbitrary bytes to the packet parser | The first thing any datagram touches. |

Needs nightly, since libFuzzer does:

```bash
cargo +nightly fuzz run listener -- -max_total_time=60
```

## Found so far

**A one-packet remote denial of service.** A peer's handshake advertises its
flow window, and that `i32` was handed straight to `Vec::with_capacity` for the
loss lists. A handshake claiming `i32::MAX` asked for a 68 GB allocation. Now
clamped, with the crashing input kept in `corpus/connection/` and a regression
test in `udt-proto/tests/network.rs` that runs on stable.
