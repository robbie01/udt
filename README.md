# UDT in Rust

A reimplementation of [UDT], the UDP-based bulk transfer protocol, as a sans-IO
state machine plus a Tokio driver. It speaks the wire format of the original C++
implementation, so the two interoperate.

UDT is reliable and message-oriented: every `send` arrives as exactly one `recv`
of the same length, in order, with congestion control. It is built for links
where TCP's window growth is the bottleneck rather than the network — long fat
pipes, high-latency paths, bulk transfer.

**Status: pre-release.** Nothing is published to crates.io and the version is
`0.0.0`; `udt-proto`'s API is explicitly not stable yet. Dual-licensed
MIT OR Apache-2.0. Minimum supported Rust is 1.88, which is where let-chains
stabilised.

Publishing goes `udt-proto` first, then `udt-async`: the second depends on the
first, and cargo resolves that from the registry rather than the path when it
packages, so `--dry-run` on `udt-async` cannot pass until `udt-proto` is up. CI
dry-runs the one it can.

[UDT]: https://udt.sourceforge.io/

## Security

**UDT has no encryption and no authentication.** Nothing here adds any. On a
path an attacker can read, every byte is in the clear; on a path an attacker can
write to, they can forge data and control packets. Treat this as you would
plain TCP: fine on a network you trust, not fine on the open internet by itself.

Run something over it. A Noise handshake on the message stream gives roughly
what TLS gives TCP, and suits peer-to-peer better because it needs no
certificate authority. What that does **not** cover is the transport's own
control packets — acknowledgements, loss reports, shutdown — which sit beneath
the payload and stay forgeable. TCP+TLS has the same seam, which is why `RST`
injection works there.

What this does do about that:

- The socket identifier a peer must match to be listened to is randomly chosen
  rather than counted up from one, so blind injection needs a 32-bit guess.
  Roughly what TCP gets by requiring an injected `RST` to land inside the
  receive window.
- No unauthenticated packet is fatal on its own. An acknowledgement for data
  that was never sent, or an error signal, is dropped rather than closing the
  connection — both were previously a one-packet kill from off path.
- The handshake is stateless behind a cookie, so an unverified peer cannot make
  a listener allocate anything, and the reply is no larger than the request.

An on-path attacker can still deny service by forging a `Shutdown`, exactly as
they can with a TCP `RST`. Nothing short of authenticating the control plane —
which would break wire compatibility — fixes that.

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
hung forever behind a path-MTU black hole, a tail loss that cost a third of a
second to recover, and a message-numbering collision that made a recovered
connection discard the data it had just re-sent.

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

One known shortfall: without `recvmmsg`, connections sharing an endpoint's port
funnel through a single reader task that gets one *call* per wakeup. Give bulk
transfers an endpoint each there. `EndpointConfig::mtu` and the `Endpoint` docs
say more.

That is macOS and Windows, but the two are not alike: Windows has no `recvmmsg`
yet does coalesce received datagrams, so one call there can still return up to 64
of them, where macOS has neither and gets one packet per call.

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

Windows is built and tested in CI now, on `windows-latest`, but has never run
in anger — treat it as unproven rather than unsupported.

Connections are tied to the address pair and stay that way; a NAT rebind ends
them, by choice.

Selective acknowledgement is in and on. The receiver reports which ranges above
the acknowledgement point arrived and the sender discounts them from its window,
so a hole no longer pins everything behind it. It is a compatible extension —
the ranges go after the documented ACK body, and both the C++ fork and pristine
upstream keep working against it, tested with a lossy relay and a count of
extended ACKs on the wire.

Loss costs much less than it did. As a multiple of the clean transfer time,
over sixteen simulator seeds **on a 200 µs path**:

| | at the start | now |
|---|---|---|
| 1% loss | 5.47x | 1.10x |
| 2% loss | 12.92x | 1.30x |
| 5% loss | 28.03x | 1.88x |
| 10% loss | 49.98x | 5.26x |

**Those are local-network numbers.** Lengthening the round trip alone
(`loss_cost_by_round_trip`) puts 2% loss at 7.2x and 5% at 8.3x, flat from 10 ms
out to 200 ms — which at least says the recovery timers scale with the path
rather than falling apart on a long one.

But a long link with no bottleneck is not a real path either. With a rate, a
serialisation delay and a buffer that drops (`cost_on_a_bottleneck`, 5 MB
transfers):

| link | 2% loss costs | goodput | standing queue | self-inflicted drops |
|---|---|---|---|---|
| 100 Mbit, 10 ms, 50 ms buffer | 1.28x | 59 Mbit/s | 14 ms | 77 |
| 100 Mbit, 50 ms, 50 ms buffer | 2.88x | 20 Mbit/s | 26 ms | 76 |
| 10 Mbit, 50 ms, 100 ms buffer | 1.51x | 5 Mbit/s | 77 ms | 86 |

Loss costs less than the no-bottleneck sweep suggests, because the link is
already the limit. The real problems that table shows are elsewhere: **a 100
Mbit, 50 ms path yields only about half its capacity**, and **slow start
overshoots the buffer on every link measured**, causing 594 to 1006 drops per
transfer on links dropping nothing of their own. Both are unfinished.

None of that came from congestion control, which is where it looked like it
would. Four explanations were measured and discarded — pacing, the congestion
window, retransmission waste, detection latency — before a delivery timeline
showed the cost was a handful of discrete stalls rather than a rate. Every one
of them was a timer scheduled from a value that was not yet known: an opening
round-trip guess that never converged, a NAK timer armed from that guess and
never corrected, an ACK blocked by a hole that reset its timer as though it had
reported something, and a re-announce rule that nothing ever reached. `loss_cost
_table` and `loss_timeline` in `udt-proto/tests/network.rs` are what found them,
and [`docs/selective-ack.md`](docs/selective-ack.md) has the rest.
