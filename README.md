# UDT in Rust

A reimplementation of [UDT], the UDP-based bulk transfer protocol, as a sans-IO
state machine plus a Tokio driver. It speaks the wire format of the original C++
implementation, so the two interoperate.

UDT is reliable and message-oriented: every `send` arrives as exactly one `recv`
of the same length, in order, with congestion control. It is built for links
where TCP's window growth is the bottleneck rather than the network — long fat
pipes, high-latency paths, bulk transfer.

**Status: pre-release.** Nothing is published to crates.io, the version is
`0.0.0`, and `udt-proto`'s API is explicitly not stable yet. Windows has never
been compiled, let alone tested.

[UDT]: https://udt.sourceforge.io/

## Layout

| Crate | What it is |
|---|---|
| [`udt-proto`](udt-proto/) | The protocol as a pair of state machines. No sockets, no threads, no clock of its own — you feed it datagrams and the time, it hands back datagrams to send and events to act on. |
| [`udt-async`](udt-async/) | The Tokio driver, and what applications use. |
| [`tests/integration`](tests/integration/) | End-to-end tests and the benchmark suite. |
| [`fuzz`](fuzz/) | Fuzz targets for everything that parses untrusted input. |

The C++ reference implementations and the third-party comparison benchmarks live
on the [`harness`](../../tree/harness) branch, so this one stays purely Rust.
See its README for how to check it out beside this clone.

Both crates are `#![forbid(unsafe_code)]`. Where platform features are needed —
segmentation offload, `recvmmsg` — they come through [`quinn-udp`], which
provides them behind a safe API.

[`quinn-udp`]: https://docs.rs/quinn-udp

## Using it

```rust
use udt_async::Endpoint;

async fn client() -> std::io::Result<()> {
    let endpoint = Endpoint::bind("0.0.0.0:0").await?;
    let socket = endpoint.connect("203.0.113.7:9000").await?;

    socket.send(b"ping").await?;

    let mut buf = [0u8; 1500];
    let n = socket.recv(&mut buf).await?;
    println!("{:?}", &buf[..n]);
    Ok(())
}
```

Serving is the mirror image — `endpoint.listen(backlog)?` then
`listener.accept().await`. Two peers behind firewalls can also reach each other
directly with `connect_rendezvous`, no listener on either side.

Every method takes `&self`, so a socket is shared between tasks with an `Arc`:
one sending while another receives is the expected pattern.

Sending in large messages rather than many small ones is the single biggest
throughput lever — a few hundred kilobytes per `send` is a reasonable target for
bulk transfer.

## Development

```bash
cargo test --workspace                       # unit, protocol and integration tests
cargo test --workspace --release             # again: release catches timing paths debug hides
cargo test --workspace --release -- --ignored --nocapture --test-threads=1   # benchmarks
```

Run the suite in **both** profiles. Debug catches the `debug_assert!`s; release
catches the timing-dependent paths. Several bugs found here were one-in-three
flaky and only appeared under repeated concurrent load, so CI runs a
ten-iteration sweep and it is worth doing locally before trusting a change.

Fuzzing needs nightly:

```bash
cargo +nightly fuzz run listener -- -max_total_time=60
```

Targets are `listener`, `connection` and `decode`, in decreasing order of
exposure. `fuzz/README.md` explains what each one reaches and what they have
found.

### Testing against a network that misbehaves

Loopback delivers everything, in order, immediately, which exercises almost none
of what a transport is for. Two harnesses cover the rest:

- `udt-proto/tests/network.rs` drives two connections over a simulated link on
  virtual time with a seeded generator — loss, reordering, duplication,
  asymmetric loss, MTU black holes. A ninety-second transfer runs in
  milliseconds and a failure reproduces exactly.
- `tests/integration/src/relay.rs` puts a UDP relay between two real endpoints,
  so the driver itself — batching, offload, the pacing timer against a real
  clock — is tested under the same conditions.

Between them they have caught a permanently stranded receiver, a connection that
hung forever behind a path-MTU black hole, and a tail loss that cost a third of a
second to recover.

### Benchmarking

The numbers move by more than most changes do, so:

- **Compare interleaved builds, never runs taken minutes apart.** A machine's
  absolute throughput here has been seen to move 5× between sessions.
- **Check the binaries actually differ.** `cargo build` reuses artifacts, and
  `ls -t` on the output directory will happily hand back the previous revision.
  Diff the hashes.
- **Never `git reset --hard <ref>` while on a branch** to switch revisions for a
  build — it moves the branch. Use `git checkout --detach`.

Every one of those cost real time before it was written down.

`UDT_PERCONN=1` makes the scaling benchmark report per-connection completion
times. `UDT_DEBUG=1` dumps connection state on each timer tick, for stalls.

## Performance

Loopback, release, and comparative rather than absolute — the machine matters
more than the number does.

Against the C++ reference on the same host:

| | Rust | C++ |
|---|---|---|
| Stream, 128 MiB | 493 MB/s | 175 MB/s |
| Round trip, per message | 203 µs | 26,926 µs |
| Unordered through 2% loss | 54.9 MB/s | 0.4 MB/s |

The last row is the interesting one. C++ is competitive on a clean link and
collapses by a factor of a hundred under mild loss, pushing far more packets for
the same payload; the reproduction lives on the harness branch.

On a 24-core Linux host: 3.2 GB/s single connection, 4.5 GB/s on two, and about
5 GB/s across eight rendezvous connections, scaling roughly linearly. On an
Apple-silicon laptop: 530 MB/s single connection, 0.3 ms to establish a
rendezvous pair.

One known shortfall: on platforms without batched receive — macOS, Windows —
connections that share an endpoint's port are limited by a single reader task
doing one syscall per packet. Give bulk transfers an endpoint each there.
`EndpointConfig::mtu` and the `Endpoint` docs say more.

## Design notes

The protocol is sans-IO because the alternative is untestable. Everything
interesting — loss recovery, congestion control, reassembly — is reachable
without a socket, which is what makes the deterministic simulator above
possible, and what would let a second runtime driver be written without touching
the protocol.

Each connection's state machine is owned outright by one driver task, and
applications reach it over channels. Sharing it behind a mutex instead was
tried, measured, and reverted: it is faster for a single connection and
substantially slower for everything else, because the driver's critical section
is nearly all of its work and every other task waits behind it. That history is
on `archive/shared-state`, and `udt-async/src/conn.rs` carries the numbers.

Datagrams are built into a caller-owned buffer that the driver reuses, so a
saturated connection does not allocate per packet.

## Not done yet

Windows. ECN, which the UDP layer already plumbs and this discards. Connection
IDs, so a NAT rebind does not kill the connection. Path-MTU probing — black
holes are detected and reported, never probed around.

Selective acknowledgement is half-built on purpose. The wire half works and is
backward compatible: the receiver reports which ranges above the acknowledgement
point arrived, the sender tracks them, and both the C++ fork and pristine
upstream keep working against it — tested with a lossy relay and a count of
extended ACKs on the wire, on the harness branch. The half that would use it —
discounting those packets from the congestion window — is written, measured, and
deliberately switched off, because it is a bad trade:

| | before | after | |
|---|---|---|---|
| 1% loss | 2.41x | 3.60x | 49% worse |
| 2% loss | 11.85x | 19.19x | 62% worse |
| 5% loss | 30.58x | 24.25x | 21% better |
| 10% loss | 49.92x | 37.88x | 24% better |

Cost of loss as a multiple of the clean transfer time, meaned over five
simulator seeds. Real paths sit at the low end, so this loses more than it wins.
The cause is not yet understood — it is not receiver overrun and not the flow
window, both tested. `loss_cost_table` in `udt-proto/tests/network.rs` is the
measurement; [`docs/selective-ack.md`](docs/selective-ack.md) has the rest.
