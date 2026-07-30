# Fuzz targets

Three entry points, ordered by how exposed they are:

| target | what it feeds | why |
|---|---|---|
| `listener` | arbitrary datagrams from arbitrary sources | The most exposed surface here. It runs before any connection exists, so anything that can reach the bound port reaches this code, and a spoofed source address costs an attacker nothing. |
| `connection` | arbitrary datagrams, and synthesised data and message-drop packets at chosen sequence numbers, to a connection whose peer chose its own initial sequence number | Decoding cleanly is not enough — a well-formed packet carrying hostile sequence numbers, lengths or window sizes reaches the loss lists, the receive buffer and congestion control. Random bytes almost never form a data packet addressed to the right socket, let alone a run of them that opens and closes gaps, so those are built from the input instead. After every step the loss lists are checked for the shape the rest of the code reads them for: sorted and non-overlapping. |
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

**A receiver loss list holding the same sequence twice.** `MsgDrop` names both
ends of its range on the wire. Run backwards, the straddle case in
`remove_range` split one range into two overlapping halves — and both loss
lists are searched by "first range containing this sequence", so the copy
behind survives the packet that should clear it and is NAKed for as long as it
lasts. A backwards range is now rejected as malformed, and `remove_range`
normalises its arguments the way `insert` always has. The input is kept in
`corpus/connection/`, with a regression test in `udt-proto/src/connection.rs`
that runs on stable.

**A twenty-byte NAK worth a billion retransmissions.** Nothing bounded the
ranges a NAK could name, and `pack_data` walks the send loss list one sequence
at a time looking for something to resend. One packet naming a third of the
sequence space held the sender in that loop for nineteen seconds. Reported
ranges are now recorded only where they overlap what is actually outstanding.
That input is in `corpus/connection/` too, and its regression test times
nothing — it asserts on the length of the loss list, which is what the runtime
was proportional to.
