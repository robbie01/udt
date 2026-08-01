# Audit: `udt-proto`, `udt-async`, `tests/integration`

Correctness audit for race conditions, incorrect protocol behaviour and other
bugs. Four findings, all CONFIRMED with a reproducing test left in the tree.

**All four are now fixed.** The repro tests below are green and stay in the
tree as regression cover; the sections that follow are the original findings,
left as written. What each fix was:

| # | Fix |
|---|---|
| 1 | `Driver::on_inbound` drops datagrams whose source is not the connection's peer, which `run_owned` already did at its own recv. |
| 2 | `post_connect` clamps the advertised window to `1..=MAX_FLOW_WND`, so both the listener and the connecting side are correct by construction and no third caller can get it wrong. |
| 3 | The driver latches `send_closed` when the send channel first yields `None`, calls `half_close` once, and adds the flag to the arm's guard. |
| 4 | An empty message is refused rather than accepted and dropped — `SendOutcome::Rejected` in `udt-proto`, and `InvalidInput` at `udt-async`'s boundary, since a refusal made in the driver would be discarded and still look like success. Refused rather than encoded because a message surfaces through `recv(&mut buf) -> usize`, where zero is how such an API says the connection is done. |

Verified: `cargo test --workspace` and `--workspace --release` green, five
consecutive release runs clean, `-- --ignored` green,
`RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` clean,
`cargo doc` clean, and interop green against both C++ implementations (27 and
9).

The repro tests, all now passing:

| # | Repro test | Where |
|---|---|---|
| 1 | `source_address::a_shutdown_from_a_stranger_does_not_close_the_connection` | [tests/integration/src/lib.rs](tests/integration/src/lib.rs) |
| 2 | `listener::tests::a_peer_advertising_a_zero_flow_window_cannot_wedge_the_connection`, `…_negative_flow_window_is_clamped` | [udt-proto/src/listener.rs](udt-proto/src/listener.rs) |
| 3 | `wind_down::dropping_the_last_handle_does_not_spin_the_driver` | [tests/integration/src/lib.rs](tests/integration/src/lib.rs) |
| 4 | `connection::tests::an_empty_message_is_not_reported_as_queued_and_then_dropped` | [udt-proto/src/connection.rs](udt-proto/src/connection.rs) |

Baseline before any of these was added: `cargo test --workspace` and
`--workspace --release` both green, `RUSTFLAGS="-D warnings" cargo clippy
--workspace --all-targets` clean.

---

## 1. An accepted connection takes datagrams from any source address — CONFIRMED

**[udt-proto/src/router.rs:82](udt-proto/src/router.rs:82)** (lookup) and
**[udt-async/src/driver.rs:373](udt-async/src/driver.rs:373)** (`run_shared`).

`Router::route` resolves a datagram on its destination socket id alone and
never looks at `from`; the address map is consulted only when the id matches
nothing. `run_shared` — the driver every *accepted* connection runs — then
feeds what it is handed straight to the state machine without comparing the
sender against its peer. `run_owned`, which each outgoing connection uses, does
compare: [udt-async/src/driver.rs:308](udt-async/src/driver.rs:308) skips any
datagram whose `rx.metas[i].addr != d.peer`. So the check exists on one path
and is missing on the other.

**Failure scenario.** A server accepts a connection, which is assigned socket
id *N*. Any host that can reach the listening port sends a 20-byte UDT
`Shutdown` whose header names *N* — no valid sequence number, no session state,
and **no source-address spoofing**. The connection is torn down: the
application's next `recv` returns `ConnectionAborted`, "peer closed the
connection", while the real peer is still sending. The repro does exactly this
from an unrelated `127.0.0.1` socket and the connection dies every run (10/10
in the release loop).

UDT authenticates nothing, so the socket id is acknowledged as the whole
defence — [udt-async/src/util.rs:42](udt-async/src/util.rs:42) calls it "a
32-bit cookie … roughly what TCP gets from requiring an injected `RST` to land
inside the receive window". That comparison only holds while forging also
requires the peer's source address. TCP's off-path attacker must guess a window
*and* spoof an address that ingress filtering will drop; here the address is
free, which removes the one barrier that does not depend on guessing.

**Fix direction.** Have `run_shared` drop datagrams whose source is not its
peer, as `run_owned` already does — the address travels with the datagram, so
it is a field on `Inbound` and one comparison. Tightening `Router::route` to
require the address to match as well would close it at the routing layer
instead, but the handshake's unaddressed case has to keep working.

**Wire compatibility:** unaffected. No encoding changes; this is which
datagrams a receiver consents to act on.

## 2. The listener trusts the peer's advertised flow window — CONFIRMED

**[udt-proto/src/listener.rs:259](udt-proto/src/listener.rs:259)** —
`let flow_wnd = hs.flight_flag_size as u32;`

The field is a peer-supplied `i32` from the handshake, and it becomes the
connection's send-side window gate unaltered:
`Connection::new_connected` → `post_connect` assigns
`self.flow_wnd = flow_wnd` with no clamp
([udt-proto/src/connection.rs:599](udt-proto/src/connection.rs:599)), and
`pack_data` gates new data on
`max_flight = (self.cwnd.min(self.flow_wnd as f64)) as usize`
([udt-proto/src/connection.rs:2151](udt-proto/src/connection.rs:2151)).

The sibling path already knows this is untrusted input.
`do_post_connect`, which handles the same field on the connecting side, reads
`(hs.flight_flag_size.max(1) as u32).min(MAX_FLOW_WND)`
([udt-proto/src/connection.rs:1645](udt-proto/src/connection.rs:1645)). The
listener has neither half of that.

**Failure scenario, zero.** A peer completes a normal cookie handshake with
`flight_flag_size = 0`. The accepted connection gets `flow_wnd = 0`, so
`max_flight` is 0 and `in_flight >= max_flight` holds before anything is sent:
`pack_data` refuses every packet, for ever. Nothing recovers it — `flow_wnd` is
only revised by `full.avail_buf_pkts` on an incoming ACK, and a peer receiving
nothing has nothing to acknowledge. Measured over forty seconds of virtual
time: zero data packets emitted, then the connection tears itself down
reporting `DisconnectReason::PathMtu`, whose documented meaning is "the path did
not carry any full-size packet … retry with a smaller MTU". No packet was ever
offered to the path. So a server-side connection is silently unusable and the
diagnosis handed to the application points at the network.

**Failure scenario, negative.** `flight_flag_size = -1` becomes `flow_wnd =
4_294_967_295` (asserted by the second test). `MAX_FLOW_WND`'s clamp is skipped
entirely, so the peer's flow control is switched off until its first full ACK
arrives and supplies a real figure. The congestion window still bounds the
sender, which is why this is the less severe half.

**Fix direction.** Apply the same clamp the connecting side uses — the value
should pass through `.max(1)` and `MAX_FLOW_WND` on the way in. Clamping inside
`post_connect` rather than at each call site would make both paths correct by
construction and leave no third one to get wrong.

**Wire compatibility:** unaffected. Nothing on the wire changes; a
well-behaved peer advertising a sane window is treated exactly as before.

## 3. The driver spins after its last handle is dropped — CONFIRMED

**[udt-async/src/driver.rs:328](udt-async/src/driver.rs:328)** (`run_owned`)
and **[udt-async/src/driver.rs:391](udt-async/src/driver.rs:391)**
(`run_shared`) — the `req = send_rx.recv(), if d.blocked.is_none()` arm.

A closed-and-drained `mpsc::Receiver` resolves to `None` immediately and does
so for ever. Once the application drops its last `Connection`, that `select!`
arm is permanently ready, and its body — `None => d.half_close()` — makes no
progress after the first call: `half_close` sets `snd_half_closed` and returns
while the send buffer still holds data. The loop therefore turns as fast as the
thread allows until the buffer drains, which is however long the transfer takes.

**Failure scenario.** A client queues 400 small messages (fewer bytes than the
send buffer, so nothing is ever `blocked`), the peer stops reading so its
receive backlog fills and flow control pins the sender, and the client drops its
handle. Measured directly with a counter in the `None` arm: **363,000 iterations
per second, sustained for the full five-second observation window** with no
sign of stopping. One core at 100% for the whole wind-down, per connection —
which matters most for the peer-to-peer, many-idle-connections use this crate
documents.

The in-tree repro needs no instrumentation: `#[tokio::test]` runs everything on
one thread, so it times a fixed slice of co-scheduled work and compares it
against the same slice while the drivers are idle. A driver that parks costs
the probe nothing; measured is **2.19–2.25× in release and 6.75–7.00× in
debug**, each steady to within a few percent across runs. Release is lower only
because the driver's per-iteration work is cheaper, not because it spins less;
the test threshold of 1.8× fails in both profiles.

Two things narrow it, and neither is a fix. The `d.blocked.is_none()` guard
disables the arm whenever a message is waiting for buffer space, so an
application that overruns the send buffer before dropping its handle does not
see this. And progress still happens, because `select!` picks at random among
ready arms — the cost is CPU, not a hang.

**Fix direction.** The arm needs to stop being selected once the channel is
closed: latch a flag when `recv()` first yields `None`, call `half_close` once,
and add that flag to the arm's existing guard.

## 4. A zero-length message is reported as queued and then dropped — CONFIRMED

**[udt-proto/src/send_buffer.rs:63](udt-proto/src/send_buffer.rs:63)** —
`let n_chunks = data.len().div_ceil(self.payload_size); if n_chunks == 0 { return true; }`

An empty payload gives `n_chunks == 0`, the loop that fills slots does not run,
and `add` returns `true` — which `send_msg` turns into `SendOutcome::Queued`
([udt-proto/src/connection.rs:1026](udt-proto/src/connection.rs:1026)).

**Failure scenario.** `conn.send(b"")` — or `send_bytes(Bytes::new())` through
`udt-async` — returns success. No data packet is built (asserted: zero), no
sequence number is consumed, and the peer's `recv` never produces the message.
An application using an empty message as a heartbeat or an end-of-stream marker
waits indefinitely for something it was told had been sent. This contradicts the
API's stated contract, that "each `send` arrives as exactly one `recv` of the
same length"
([udt-async/src/conn.rs:58](udt-async/src/conn.rs:58)).

Lowest severity of the four: it needs the application to send empty messages,
and it is a clean failure rather than corruption.

**Fix direction.** Pick one and make it explicit. An empty message is
representable on the wire — a data packet with a zero-length payload and a
`Solo` boundary — so encoding it costs a sequence number and is the answer that
keeps the contract. Refusing it with `SendOutcome::Rejected` is also defensible;
reporting success and discarding it is the only option that loses data silently.

---

## What was checked and found sound

Read line by line, with the hypotheses that were tested and did not hold.

**Sequence arithmetic** (`seq.rs`, `loss_list.rs`, `ack_window.rs`). Ordering
and `offset_from` are correct across the wrap in both spaces. `insert_merging`
and `remove_range_from` normalise backwards pairs before acting, and both
assert `is_sorted_disjoint` afterwards in debug builds; the wrap-straddling
merge and the offset-based `received_ranges` walk are already covered by tests
that the wrap case would break. `AckWindow::acknowledge`'s reverse scan
terminates correctly when empty, when full, and across the ring wrap.

**Buffers** (`send_buffer.rs`, `recv_buffer.rs`). The positional block↔sequence
mapping holds through `expire_msg_at` (which consumes the range rather than
skipping it) and through `shrink_path` (which renumbers past what the peer was
told to drop). `SendBuffer::ack(adv)` can never exceed `sent`: `recv_ack` bounds
`ack_seq` by `snd_curr_seq.next()` first, and the three paths that move
`snd_curr_seq` move `sent` with it. `RecvBuffer`'s `Delivered` state correctly
stops a retransmission repopulating an early-delivered slot, and `drop_range`'s
clamping to `capacity` holds for ranges naming anything in the space.

**Timers** (`connection.rs`). Every computed deadline was checked against its
input still being the opening default. `feed_rtt` replaces rather than blends
the first sample and pulls the already-armed NAK timer in with it; `exp_int_us`
keeps its `SYN_US` allowance; `nak_int_us` floors at `MIN_RECOVERY_US`. The
keep-alive is serviced outside the expiry branch, so it is always re-armed. No
timer was found that can stop being rescheduled or re-arm for `now` — the
`pack_data` loop's exit sets `next_snd_us` a full control interval ahead, which
is what stops the busy-wait. The dead ends in `docs/selective-ack.md` were not
re-run.

**Congestion control.** Both halves of `CcOutput` are applied by `apply_cc`, and
so are `ack_period_ms`, `ack_interval_pkts` and `rto_us`, each with a reader.
`CcKind::build` dispatches to three distinct types with no fall-through arm —
the failure mode `CLAUDE.md` records. Cold-start division is guarded in every
controller (`Cubic::period_us` on `rtt_us <= 0`, `Ledbat::gain` via
`base.max(1.0)`, `UdtCc::leave_slow_start` on `rcv_rate_pps > 0`). HyStart hands
off to CUBIC and to `UdtCc`, and units are consistent (µs throughout,
packets for windows).

**Parsing** (`codec.rs`, `packet.rs`, `handshake.rs`). No panic path found on
malformed input: every fixed read is length-checked first, `decode_seq_ranges`
rejects a non-word-multiple tail, and the SACK tail is dropped rather than
failing the ACK in front of it. No attacker-controlled length sizes an
allocation — the loss lists are reserved at a fixed `LOSS_LIST_RESERVE` and grow
on demand, and `recv_nak`/`apply_sack` clamp peer ranges to what is actually
outstanding before recording them. Confirmed by fuzzing: `decode` (20,017,308
runs), `connection` (154,579) and `listener` (804,720), 60 s each, no new
artifacts — the four already in `fuzz/artifacts/connection/` predate this audit
by three days and were not re-triggered.

**Sans-IO.** `grep` for `Instant::now`, `SystemTime`, `std::thread`,
`UdpSocket`, `rand::` and `std::env` across `udt-proto/src` returns nothing
outside the simulator. The boundary is intact.

**`udt-async` concurrency, beyond findings 1 and 3.** No lost-wakeup pattern
found: the driver re-runs `flush` at the top of every loop iteration, so a
condition that becomes true between a check and an await is picked up on the
next turn. Backpressure is applied rather than dropped in both directions — the
reader waits on a full connection queue, and the driver stops taking send
requests while one is `blocked`. The accept path is the deliberate exception and
says so. `now_us` is monotonic by construction (a process-start `Instant`), so
the state machine cannot be handed a clock that goes backwards. One reader task
per endpoint is enforced structurally, which is the ordering requirement.

## How it was run

- `cargo test --workspace` and `--workspace --release` — green before the repro
  tests were added.
- Ten consecutive `cargo test --workspace --release` runs. The only failures
  were the repro tests, at 10/10 each; nothing else was flaky. Note that a
  failing binary ends the run, so the repros mask the later targets — remove
  them to re-check the rest of the suite under repetition.
- `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` — clean,
  including the added tests.
- `cargo +nightly fuzz run <target> -- -max_total_time=60` for `decode`,
  `connection` and `listener`; run counts above.
- Findings 3's spin rate was measured with a temporary `AtomicU64` in the
  driver's `None` arm, which has been reverted; `git diff udt-async/src` is
  empty.
