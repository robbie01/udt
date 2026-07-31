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
tool for a stall.

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
large change. `congestion/sim.rs` is a fluid model for comparing controllers,
separate from the packet-level simulator.

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

A bug that only appears with a bottleneck will not appear without one. Both
open congestion-control items were invisible until the bottleneck model existed.

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
