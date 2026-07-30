# Selective acknowledgement

**Status: shipped and enabled.**

The wire half went in first and the window discount was left off for a long
while, correctly: two measurements found it mixed in sign, and the mechanism
argument was against it because the window was almost never what limited the
sender. It sat idle on timers instead.

Once those stalls were fixed (see "What it was worth") the window does bind, and
the third measurement over 32 seeds is unambiguous — 23% better at 1% loss, 27%
at 2%, 40% at 5%, and 4% worse at 10%, inside the noise. Amplification, reverse
traffic and the pacing interval all improve with it on, where enabling it used to
roughly double the pacing. So it is on.

Compatibility is settled: both the fork and pristine upstream keep working
against a receiver whose ACKs carry ranges they know nothing about —
`cpp_tolerates_our_extended_acks` and `upstream_tolerates_our_extended_acks` on
the harness branch, each counting extended ACKs on the wire so a clean link
cannot pass for proof.

## The problem

A single lost packet stops the sender from sending new data, however much later
data arrived safely.

The send buffer is positional: block index maps to sequence number, and
`SendBuffer::ack(count)` frees only from the head, cumulatively. That is
deliberate — freeing out of order would shift every later block and make
`read_at` serve the wrong payload under a live sequence number, which the code
warns about at the call site. So `in_flight` is "sent minus cumulatively
acknowledged".

`pack_data` then gates new data on it:

```rust
let in_flight = self.snd_buf.as_ref().map_or(0, |b| b.in_flight());
let max_flight = (self.cwnd.min(self.flow_wnd as f64)) as usize;
if in_flight >= max_flight { return false; }
```

Lose packet *N* while *N+1 … N+1000* arrive, and `snd_last_ack` stays at *N*.
`in_flight` stays at ~1000. The window is full and nothing new goes out until
*N* is repaired — one round trip minimum, and on this implementation the tail
case used to be far worse.

This looked like why loss cost so much more than its rate suggested: 5% loss cost
about 30x the clean transfer time, and the drops themselves were a small fraction
of that.

The diagnosis was half right, and it took a long time to find out which half.
The stall is real and relieving it does help — but only once the sender is
actually held up by its window rather than by a timer, and for most of this
work it was held up by timers. See "What it was worth".

## What UDT already gives us

Enough to know *which* packets are missing, but not enough to know which arrived:

- The ACK carries a cumulative point, `data_ack_seq`.
- The NAK carries explicit missing ranges, bit31-tagged
  (`codec::encode_nak`), and the receiver already keeps them in
  `RcvLossList` as sorted `(SeqNo, SeqNo)` pairs.

The gap is that nothing reports the receiver's *highest* received sequence. Given
the cumulative point and the holes, the sender still cannot say where the
received region ends, so it cannot count anything above the ACK point as
delivered. Inferring it from NAKs alone is not sound either: a NAK is a snapshot,
and a lost NAK would silently inflate the sender's idea of what arrived.

## The fix

Do **not** free buffer slots out of order. Keep the positional mapping and
correct the *accounting* instead.

Most of this already exists. `loss_list.rs` has both halves of the range-set
machinery, and reading it closely shrinks the change to four small pieces:

1. **The receiver needs no new state.** `RcvLossList` holds the *gaps*; the
   ranges a SACK should report are that list's complement between the
   acknowledgement point and `rcv_curr_seq`. So this is one new method beside
   the existing `to_nak_payload`, walking the same `ranges` and emitting the
   spaces between them:

   ```rust
   /// Received ranges in `(from, upto]`, as the complement of the gaps.
   /// `limit` bounds the emitted u32 words, as in `to_nak_payload`.
   pub fn to_sack_payload(&self, from: SeqNo, upto: SeqNo, limit: usize) -> Vec<u32>
   ```

   Emit nearest the ACK point first: those are the ranges that let the window
   advance soonest, so truncation costs least.

2. **`snd_sacked` can be a second `SndLossList`.** It already has exactly the
   operations wanted, all covered by unit tests — a merging `insert`,
   `remove_up_to` to drop entries as the acknowledgement point passes them, and
   `len()` counting sequences rather than ranges, which is what the window gate
   needs. Reuse it rather than writing a third range set.

3. **The window gate** becomes, in `pack_data`:

   ```rust
   let in_flight = self.snd_buf.as_ref().map_or(0, |b| b.in_flight());
   let effective = in_flight.saturating_sub(self.snd_sacked.len());
   if effective >= max_flight { return false; }
   ```

   `saturating_sub` is not decoration. Both terms derive from peer-supplied
   integers, and this crate has already shipped one remote allocation bug and
   one arithmetic overflow reached through exactly this kind of arithmetic.

4. **Retransmission needs no new code path.** `SndLossList::remove_range(first,
   last)` already exists for `MsgDrop`, including the straddle-and-split case.
   Feeding it each newly SACKed range deletes precisely the sequences that must
   not be retransmitted, and `pop_front` then never offers them.

So the shape is: on a SACK-bearing ACK, for each reported range, `snd_sacked
.insert(a, b)` and `snd_loss.remove_range(a, b)`; on the cumulative point moving,
`snd_sacked.remove_up_to(ack)`; and one changed line in `pack_data`.

### The invariant the complement walk needs

Computing the complement in (1) is only correct if the gaps are sorted and free
of overlaps. That used to be a comment claiming `RcvLossList::insert` coalesced
defensively while it did no such thing; it is now enforced, shared with the send
side, and asserted after every insert and removal in debug builds.

One consequence for the walk: `insert` merges across the sequence-space wrap, so
a gap held here can run past the top of the space, and raw start order is not
offset order near the wrap. `received_ranges` therefore works in offsets from
the acknowledgement point and re-sorts before walking, rather than trusting
`SeqNo` ordering. `apply_sack` clamps the same way on the receiving end.

## Wire format

The ACK body is currently 4, 16, or 24 bytes and the decoder already switches on
length, ignoring anything beyond what it recognises:

```rust
let full = if payload.len() >= 16 { ... rtt, rtt_var, avail_buf ... };
// rcv_rate and bandwidth only if payload.len() >= 24
```

So ranges appended after byte 24 are invisible to a decoder that does not know
about them, and the encoding can reuse the NAK's bit31-tagged range format
verbatim.

The C++ reference looks like it tolerates the extra bytes. `processCtrl`'s ACK
case (`udt-compat/udt-sys/udt/core.cpp`, around line 1300) switches on length
like this:

```cpp
if (4 == ctrlpkt.getLength()) { /* lite ACK */ break; }
...
if (ctrlpkt.getLength() > 16) { /* read fields 4 and 5 */ }
```

Exactly four bytes is a lite ACK. Anything else takes the full path, reads fields
0–3 unconditionally and fields 4–5 when the body is longer than 16, and then
stops. There is no upper bound check and nothing that rejects a body for being
longer than expected, so a 24+4k-byte ACK is processed exactly as a 24-byte one
with the tail ignored.

**Constraint that falls out of this:** the test is `> 16`, not `== 24`. Append
ranges to a *16-byte* ACK and the peer reads the first two range words as
delivery rate and bandwidth and feeds them into its EWMAs, quietly wrecking its
own rate estimate. The extension may only ever be appended to a full 24-byte
ACK — never a short one, and the encoder needs to enforce that rather than
leave it to the caller.

Reading the source is a prior, not an answer, and it was read from the *fork*
rather than pristine upstream. Both were then run, on the harness branch:

- `cpp_tolerates_our_extended_acks` (cpp-interop, the fork)
- `upstream_tolerates_our_extended_acks` (upstream-compat, pristine `8272c25`)

Each puts a lossy relay between a C++ sender and a Rust receiver and transfers
with byte verification. Loss is what makes the receiver emit ranges at all, so
each test also has the relay count ACKs on the wire whose body runs past 24
bytes, and asserts the count is non-zero — otherwise a clean link would pass
while proving nothing. The fork run sees ten across 120 messages at 5% loss.

Both pass. The extension is backward compatible in practice, not just on paper.

No negotiation is needed, which is fortunate: the handshake has no field free
for a capability bit, and `version` is checked for equality against 4, so it
could not have carried one.

## What it was worth

Cost of loss as a multiple of the clean transfer time (`loss_cost_table`, which
prints the whole sweep under `--nocapture`):

| | at the start | now | with the discount |
|---|---|---|---|
| 1% loss | 5.47x | 1.42x | **1.10x** |
| 2% loss | 12.92x | 1.78x | **1.30x** |
| 5% loss | 28.03x | 3.11x | **1.88x** |
| 10% loss | 49.98x | 5.05x | 5.26x |

Almost none of that came from this feature, and that is the point worth
recording. The discount was measured three times. Twice it was mixed in sign and
was left off, because the window was rarely the constraint: the sender was idle
on timers. Four discrete stalls were found and fixed first —

- a round-trip estimate that opened at 10 ms and never converged, so every
  recovery timer derived from it was an order of magnitude too slow;
- a repeat-NAK timer armed from that guess and never corrected, putting the
  first chance to re-report a gap 40 ms out;
- a full ACK blocked by a hole that still reset its timer and cleared its packet
  counter, as though it had reported something, so the moment the hole filled
  there was nothing due to announce it;
- a rule for re-announcing an unconfirmed acknowledgement after `RTT + 4·RTTVar`
  that nothing ever reached, because the ACK timer only came round every 10 ms.

— and only then did the window start to bind, at which point the discount
measured 23–40% better at 1–5% loss and went on.

The lesson is in how they were found rather than in the numbers. Four
explanations for the cost were measured and discarded first: pacing (whose
interval tracked the slowdown almost one-for-one, and fixing it changed the
transfer time not at all), the congestion window, retransmission waste, and
detection latency. What worked was `loss_timeline`, which records when each
message arrives and prints the largest gaps, plus a dump of both peers' state
mid-stall. Aggregates hid all four bugs; the timeline showed each of them at a
glance.

### Dead ends, so they are not retried

Each of these was measured and is not the lever:

- **Receiver overrun.** An 8x receive ring changes nothing.
- **The flow window.** Discounting from the congestion window only — on the
  grounds that a packet held for reassembly still occupies the peer's buffer —
  changes nothing, because `flow_wnd` never binds at this transfer size.
- **Loss-list pruning.** Dropping the `snd_loss.remove_range` call leaves the
  numbers identical.
- **`LIGHT_ACK_INTERVAL`.** 64, 32 and 16 give bit-identical results. The
  threshold was never approached: during the stall the packet counter read 1,
  because a blocked full ACK had just cleared it.
- **Nudging the ACK timer on a large unacknowledged run.** Much worse — 8.40x to
  16.49x at 5% loss. Filling a hole is the right trigger; volume is not.
- **The pacing interval.** It tracked the slowdown almost one-for-one across loss
  rates, which is why it was so convincing. Fixing it dropped the interval 12x
  and left the transfer time bit-identical.

A single seed ranges from 1.6x to 53x at 5% loss on nothing but which packets get
dropped, so single-seed comparisons are meaningless — one nearly cost a correct
decision here, when five seeds said the discount made 1% loss 49% worse and
sixteen said 20% better. Sixteen is the floor; 32 for anything close.

## Interaction with what is already there

- **Tail loss probing** (`PROBE_EXPIRIES` in `connection.rs`) covers the case
  where the loss is the last packet and there is no later packet to trigger a
  NAK. Selective acknowledgement does not replace it: with nothing in flight
  behind the hole there is nothing to report as received.
- **Unordered delivery** already lets the *receiving application* move past a
  gap. This is the sending half of the same problem, and the two are
  independent — an ordered stream benefits just as much.
- **`MAX_FLOW_WND`** clamps the peer's advertised window; the new accounting
  must not let `in_flight - sacked` underflow, since both are attacker-influenced
  through the ACK.
