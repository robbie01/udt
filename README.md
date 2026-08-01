# UDT in Rust

A reimplementation of [UDT], the UDP-based bulk transfer protocol, as a sans-IO
state machine plus a Tokio driver. It speaks the wire format of the original C++
implementation, so the two interoperate.

UDT is reliable and message-oriented: every `send` arrives as exactly one `recv`
of the same length, in order, with congestion control.

Its original pitch was beating TCP's window growth on long fat pipes. That was a
claim about Reno-era TCP, and it does not survive contact with CUBIC — which is
now the default here, precisely because measurement said so. What is still worth
having is the rest of it: UDP underneath, so IPv6 firewall traversal is trivial
and a userspace deployment needs no privileges; a rendezvous connect, so two
peers behind NATs reach each other with no listener on either side; and message
framing rather than a byte stream.

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
    let conn = endpoint.connect("203.0.113.7:9000").await?;

    conn.send(b"ping").await?;

    let mut buf = [0u8; 1500];
    let n = conn.recv(&mut buf).await?;
    println!("{:?}", &buf[..n]);
    Ok(())
}
```

Serving is the mirror image — `endpoint.listen(backlog)?` then
`listener.accept().await`. Two peers behind firewalls can also reach each other
directly with `connect_rendezvous`, no listener on either side.

A connection can carry one message with its handshake, which arrives a round
trip before the connection is otherwise usable:

```rust
let conn = endpoint.connect_with_early_data(peer, &noise_msg1).await?;
```

It arrives as the connection's first `recv`, so a server needs no special
handling and cannot tell the difference. That is enough to fit a two-message
cryptographic handshake — Noise `IK`, `NK`, `KK` — inside establishment rather
than after it. It is an extra transmission of an ordinary message, so
acknowledgement, retransmission and de-duplication are the usual ones, and a
peer that ignores it costs one wasted packet.

Every method takes `&self`, so a connection is shared between tasks with an `Arc`:
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

Congestion control is where most of the recent work went, and the default
changed as a result. It is now CUBIC (RFC 9438), with UDT's own rate-based
controller still available. The reason is not throughput but sharing: UDT's
controller keeps a rate *and* a window and neither converges, so what it takes
of a contended bottleneck depends on the path rather than on the competition.
Two flows, one link:

| two flows sharing one 50 Mbit, 50 ms bottleneck | split |
|---|---|
| CUBIC against CUBIC | **53/47** |
| UDT's controller against itself | **77/23** |
| UDT's controller against CUBIC | 46/54 |

A controller that cannot divide a link evenly with a copy of itself has no
share to predict, and sharing a link is the normal condition for something
peer-to-peer.

On the link itself, 5 MB over a bottleneck, six seeds, against the same
measurement before any of this work:

| link | goodput | self-inflicted drops |
|---|---|---|
| 100 Mbit, 10 ms, 50 ms buffer | 75.4 → **94.5** Mbit/s | 594 → **137** |
| 100 Mbit, 50 ms, 50 ms buffer | 51.4 → **72.0** Mbit/s | 1006 → **0** |
| 10 Mbit, 50 ms, 100 ms buffer | 7.2 → **9.7** Mbit/s | 154 → **234** |
| 100 Mbit, 10 ms, 5 ms buffer | 51.4 → **65.1** Mbit/s | 1413 → **31** |

Slow start is the other half of it. It used to end only when the bottleneck
buffer overflowed, because loss was the only signal it had; it now leaves on a
delay signal (HyStart++, RFC 9406), which is what took those drop counts down.
RFC 9406's 4 ms floor on what counts as a queue had to go — on a 5 ms path it
demands an 80% rise before it will believe in one — so the threshold is
proportional to the path with a 1 ms floor.

**The default is a real trade, and loss is the side it loses.** On bottlenecked
links, CUBIC against UDT's controller in Mbit/s:

| link | 2% burst | 5% burst |
|---|---|---|
| 100 Mbit, 10 ms | 75.0 vs 85.8 | 21.3 vs **56.0** |
| 100 Mbit, 50 ms | 27.1 vs 40.8 | 5.3 vs **25.5** |
| 100 Mbit, 10 ms, 5 ms buffer | 28.3 vs 47.7 | 13.3 vs **35.7** |

The degradation is superlinear: a 1.5x gap at 2% becomes 2.6-4.8x at 5%. If you
know your paths are lossy, `CcKind::Udt` is measurably better and switching is
one line. In absolute terms CUBIC still costs only 1.9x the clean transfer time
at 5% burst loss — the gap is UDT's controller doing unusually well there, not
CUBIC falling over. The default is CUBIC because sharing a link is a condition every
peer-to-peer transfer meets constantly, while 5% loss is a bad path rather than
a normal one — and UDT's controller cannot divide a contended link evenly even
with itself.

Under loss the picture reverses, and how much depends entirely on what the loss
looks like. At 2% in bursts of ten, UDT's controller leads CUBIC 40.8 to 27.1
Mbit/s on the 50 ms path: answering a drop with a 12.5% nudge to a rate recovers
more gently than cutting a window by 30%. At 2% *independent* loss it looks far
worse than that — 18.6 against 2.0 — but that is mostly the model. Independent
per-packet loss manufactures a separate congestion event out of every drop,
which is close to the worst case for anything loss-based and nothing like a real
path. Both figures are in `CcKind`'s documentation, with the untrustworthy one
marked.

Loss recovery itself, separately from congestion control, costs much less than
it did. As a multiple of the clean transfer time, over sixteen simulator seeds
**on a 200 µs path**:

| | at the start | now |
|---|---|---|
| 1% loss | 5.47x | 1.10x |
| 2% loss | 12.92x | 1.30x |
| 5% loss | 28.03x | 1.88x |
| 10% loss | 49.98x | 5.26x |

**Those are local-network numbers, and on a link with no bottleneck.** A path
with no rate limit has no queue, so nothing there can overflow and every drop is
independent of what the sender does. That is useful for asking whether recovery
works and useless for asking what it costs — the figures below are kept for the
timer bugs they tracked, not as performance guidance. The bottleneck table above
is the one to read. Lengthening the round trip alone
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
already the limit. The real problems that table shows are elsewhere.

Slow start used to overshoot the buffer on every link measured, because with
only loss to go on the thing that ended it *was* the buffer overflowing. It now
leaves on a delay signal instead — HyStart++, RFC 9406 — and on a link losing
nothing of its own:

| link | goodput | self-inflicted drops | peak queue |
|---|---|---|---|
| 100 Mbit, 10 ms, 50 ms buffer | 75 → **94** Mbit/s | 594 → **86** | 50 ms |
| 100 Mbit, 50 ms, 50 ms buffer | 51 → **58** Mbit/s | 1006 → **0** | 50 → **15** ms |
| 10 Mbit, 50 ms, 100 ms buffer | 7.2 Mbit/s | 154 → **136** | 100 ms |

RFC 9406's 4 ms floor on what counts as a queue had to go: on a 5 ms path it
demands an 80% rise before it will believe in one, which is a whole extra
doubling. The threshold is proportional to the path's own round trip, as it is
in the RFC, but the floor under it is 1 ms.

The 10 Mbit link barely moves because its problem is upstream of slow start —
its bandwidth-delay product is 42 packets and the initial window is 64, so the
opening burst alone overfills it. Nothing that governs *growth* can fix a first
send that is already too large.

Still unfinished: **a 100 Mbit, 50 ms path yields well under its capacity**, and
under loss the picture is unchanged, because slow start there ends on a drop
before any delay signal arrives. Both come back to the same thing — the rate
slow start hands over is, in practice, the rate for the whole transfer, since
DAIMD's increase works out to about 1000 pkt/s per second whatever the path.
Taking a 100 Mbit link from half capacity to 95% takes 7.5 seconds; a 5 MB
transfer lasts under one.

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
