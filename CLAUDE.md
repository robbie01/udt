# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

A Rust reimplementation of UDT, wire-compatible with the original C++
implementation. See `README.md` for what the protocol is and what state it is
in; this file covers working in the tree.

## Commands

```bash
cargo test --workspace                       # debug: catches the debug_assert!s
cargo test --workspace --release             # release: catches timing paths debug hides
cargo clippy --workspace --all-targets
cargo fmt --all
```

**Run the suite in both profiles.** They catch different things, and CI runs
both. Several bugs here were one-in-three flaky and only showed up under
repeated concurrent load, so CI also runs ten release iterations in a row;
worth doing locally before trusting a change to timing or recovery.

Single tests:

```bash
cargo test -p udt-proto --test network <name>          # simulator tests
cargo test -p udt-proto congestion::                   # unit tests
cargo test -p udt-integration-tests --lib <name>       # end-to-end
```

Benchmarks and long-running measurements are `#[ignore]`d:

```bash
cargo test --workspace --release -- --ignored --nocapture --test-threads=1
```

`UDT_PERCONN=1` makes the scaling benchmark report per-connection completion
times. `UDT_DEBUG=1` dumps connection state on every timer tick, which is the
tool for a stall. `UDT_CC=udt|cubic|ledbat` reruns any simulator measurement
against another controller on the same link, seed and workload; without it the
simulator uses whatever the crate defaults to.

Fuzzing needs nightly, and `fuzz/` is deliberately excluded from the workspace:

```bash
cargo +nightly fuzz run listener -- -max_total_time=60
```

## Architecture

**`udt-proto` is sans-IO.** It owns no sockets, no threads and no clock. A
`Connection` is driven by four calls — `on_datagram`, `on_timer`, `send_msg`,
`recv_msg` — each taking `now_us`, and results leave by two separate channels:
datagrams are written into a caller-owned `TransmitBuf` (so the hot path
allocates nothing) and everything else is appended to a `Vec<Event>`. A
`Listener` is the same shape. This boundary is what makes the deterministic
simulator possible, and it is worth preserving: anything that reaches for the
clock or a socket inside `udt-proto` breaks it.

**`udt-async` owns each state machine outright in one driver task**, and
applications reach it over channels. Sharing it behind a mutex instead was
tried, measured and reverted — faster for a single connection, substantially
slower for everything else, because the driver's critical section is nearly all
of its work. That history is on `archive/shared-state`, with the numbers in
`udt-async/src/conn.rs`.

**Congestion control is entirely sender-local.** `congestion/mod.rs` defines the
trait; `CcOutput` carries both a pacing period and a window, and the connection
applies both. Nothing about congestion control touches the wire, so a CC change
carries **zero interop risk** — it is the safest place in the tree to make a
large change.

Three controllers. `cubic` (RFC 9438) is the default and the one to reach for;
`ledbat` is the scavenger; `udt_cc` is UDT's own, kept because a
reimplementation should be able to run the original's algorithm, not because it
is a good choice — it keeps a rate *and* a window and neither converges, which
is why it takes 3% of a contended 50 ms link and 85% of a 1 ms one. `hystart` is
shared slow start and is specified for the Reno/CUBIC family, so a controller
using it should hand off to one.

Two models, and they have opposite blind spots. `congestion/sim.rs` is a fluid
model that offers a whole window per round; `tests/network.rs` drives real
packets but feeds messages in as the connection drains them, so the sender never
holds a window at once. Pacing the initial window looked free in the second and
was a regression in the first. Check both.

**Wire compatibility is a hard constraint.** Anything touching `codec.rs`,
`packet.rs` or `handshake.rs` has to keep interoperating with two C++
references (below). Extensions have to be ignorable by a peer that does not
know them — selective ACK is the worked example, appending ranges after the
documented ACK body.

Both crates are `#![forbid(unsafe_code)]`. Platform features — segmentation
offload, `recvmmsg` — come through `quinn-udp`, which provides them safely.

## Testing against a network that misbehaves

Loopback delivers everything, in order, immediately, which exercises almost
nothing a transport is for. Two harnesses cover the rest:

- `udt-proto/tests/network.rs` — two connections over a simulated link on
  virtual time with a seeded generator: loss, reordering, duplication, MTU
  black holes, and `LinkConfig::bottleneck` for a real rate, serialisation
  delay and a buffer that drops. A ninety-second transfer runs in milliseconds
  and failures reproduce exactly.
- `tests/integration/src/relay.rs` — a UDP relay between two real endpoints, so
  the driver itself is tested under the same conditions.

A bug that only appears with a bottleneck will not appear without one — the
congestion-control work of note was invisible until `LinkConfig::bottleneck`
existed, and `LinkConfig::lossy` (no capacity, no queue, random drops) has
produced a wrong conclusion every time it has been used as evidence.

## Platform facts worth not re-deriving

- **macOS does not load-balance `SO_REUSEPORT` for UDP at all.** Four sockets on
  one port, 400 datagrams from 400 distinct source ports, and every one landed
  on the last socket bound: `[0, 0, 0, 400]`. So the one-reader-task receive
  funnel cannot be widened that way there, which is the direction that matters
  for a macOS client. Multiple sockets sharing a source port would still
  parallelise `sendmsg`, and that half is unexplored.

## The C++ references

They live on the `harness` branch, which references this one **by path**, so it
is checked out beside this clone rather than inside it:

```bash
git worktree list                            # ../udt-harness should be there
cd ../udt-harness && cargo test --release --workspace
```

It holds a modified fork (`udt-compat`) and pristine upstream (`udt-orig`).
Both matter: upstream is what says whether a change broke protocol behaviour
rather than just the fork. Never link the two C++ copies into one binary.

## Things that have cost real time here

- **Confirm the binary actually changed** before trusting an A/B measurement.
  `cargo build` reuses artifacts, and a benchmark has printed the previous
  revision's output from correct source more than once. Look for "Compiling
  udt-proto" in the output; `touch` the file if it is absent.
- **Compare interleaved builds, never runs minutes apart.** Absolute throughput
  on one machine has moved 5× between sessions.
- **Never `git reset --hard <ref>` while on a branch** to switch revisions for
  a build; it moves the branch. Use `git checkout --detach`. Relatedly,
  `git checkout HEAD -- <path>` discards uncommitted work silently — it has
  destroyed real edits here, twice producing commits whose messages describe
  changes they do not contain.
- **Kill runaway background tests.** A timer bug can spin the virtual clock
  forever; a test moved to the background on timeout is not dead.
- **A timer scheduled from a value that is not yet known** is the shape of
  nearly every recovery bug found so far — an opening RTT guess that never
  converged, a NAK timer armed from it, an ACK that reset its timer as though
  it had reported. `docs/selective-ack.md` records these and the measured dead
  ends, so hypotheses already disproved are not re-run.

## Measuring things here

More work has been lost to measuring the wrong thing than to writing wrong code.
Every item below cost a wrong conclusion that was reported before it was caught.

- **A result that is the exact complement of another result is a wiring bug, not
  a finding.** A fairness table showed "ledbat vs cubic 10%" beside "cubic vs
  reno 90%", and "ledbat vs reno 50%". Those are one flow against a copy of
  itself: the ledbat arm was falling through a `match` to the Reno stand-in.
  Suspiciously round numbers, exact complements, and bit-identical rows across a
  parameter sweep all mean the knob is not connected.
- **Confirm the harness measures what ships.** The bottleneck simulator
  hardcoded `CcKind::Udt`, so after the default changed every headline number
  described a controller nobody gets. It takes `CcKind::default()` now, with
  `UDT_CC` to override.
- **Compare against something that works.** A controller measured against a
  broken one tells you about the broken one. LEDBAT looked restrained beside
  `UdtCc`, which takes 85–93% of a short link; the min-RTT window looked like a
  win beside a version that had a worse bug. Both readings were wrong.
- **A single flow alone on a link cannot tell "recovers well" from "does not
  back off".** They are identical without a competitor. `a_flow_gets_a_share_of_
  a_contended_link` in `congestion/sim.rs` is where that gets settled.
- **The loss model decides the answer.** Independent per-packet loss manufactures
  a congestion event per drop and is close to the worst case for anything
  loss-based; real loss arrives in bursts. At 2% the two models put CUBIC 9×
  apart. `LinkConfig::bursty` is the realistic one, and any conclusion that turns
  on loss must be checked against it.
- **A link with no bottleneck is not a real path.** Retired the original 7–8×
  loss figures, and then got re-derived twice more from `LinkConfig::lossy`,
  which predates `bottleneck()` and models infinite capacity with random loss —
  a link that cannot physically exist.
- **`grep FAILED` is a false green.** A build that does not compile emits no
  failing tests. Check that something compiled and ran.
- **Scripted edits that write the file at the end lose everything when a later
  assertion fires.** That is how the `match` arm above went missing while its
  caller landed. Write once per edit, or verify the file afterwards rather than
  trusting the script's exit.
- **`sed` on a `const` name hits every test in the file.** One size sweep
  silently rewrote three unrelated measurements; `git diff` caught it.
