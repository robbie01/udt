# Selective acknowledgement

**Status: implemented, compatibility unconfirmed.** The design below is what
was built. Two things to know before reading it as a plan:

- **It helped less than expected.** 5% loss cost 30.6x the clean transfer time
  before and 24.2x after, meaned over five simulator seeds. The stalled window
  was a real cost but not the dominant one — most of what loss costs this
  protocol is the latency of noticing a hole and refilling it, which this does
  not touch. Anyone looking for the next big win on a lossy path should start
  there rather than here.
- **The interop test has not been run.** Everything below about C++ tolerating
  a longer ACK comes from reading its source, which is a prior and not a
  result. See "Wire format".

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

This is why loss costs so much more than its rate suggests. Measured on the
deterministic simulator, 5% loss costs roughly 25x the clean transfer time; the
loss itself accounts for a small fraction of that, and the stalled window for
the rest.

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

### Prerequisite: `RcvLossList::insert` does not coalesce

Computing the complement in (1) is only correct if the gap ranges are sorted and
non-overlapping. `RcvLossList::insert` sorts but does not merge — its trailing
comment says "coalesce defensively" and then no coalescing happens, unlike
`SndLossList::insert`, which calls `coalesce_at`. The comment describes
behaviour that is not implemented.

Whether overlap is reachable today is a separate question — the receiver only
inserts gaps it has not seen, which are disjoint in ordinary operation — but two
things follow regardless. It is the kind of invariant the fuzzer's `connection`
target should be made to attack, since `remove(seq)` returns after the *first*
matching range, so a sequence sitting in a second overlapping range would stay
"lost" and be NAKed forever; and `len()` would over-count, double-counting the
intersection. Settle it before building the complement walk on top of the
invariant: either enforce it in `insert` or prove it holds and correct the
comment.

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

Reading the source is a prior, not an answer; what matters is the shipped binary,
and this was read from the *fork*, not pristine upstream. Confirm it empirically
before building on it:

> Make the Rust side append a few dummy range words to every full ACK, then run
> the `cpp-interop` suite, and the `upstream-compat` suite against `udt-orig`
> as well — the fork is only near-stock in the packet layer, not identical.
> Passing unchanged means tolerated.

### If it turns out to need negotiating

The handshake has no field free for a capability bit, and `version` is checked
for equality against 4 by the C++ peer, so it cannot carry one. The workable
route is to opt in by demonstration: send extended ACKs speculatively and only
trust a peer's extended ACKs once it has sent one. That is only safe if
over-long ACKs are ignored rather than rejected — the same question again.

Failing that, it becomes a genuine wire break and should wait for whatever else
wants one (connection IDs, ECN, a defined timestamp epoch).

## What it was worth

**30.6x → 24.2x** the clean transfer time at 5% loss, meaned over five seeds of
the deterministic simulator (`loss_recovery_is_not_catastrophic`, which now
prints the figure under `--nocapture`). No measurable effect on a clean path,
where there are no gaps and the range list is empty.

That is about a fifth of the recovery cost, against a prediction — written in
this document before it was built — that the stalled window was *most* of it.
It was not. The remaining ~24x is dominated by how long a hole takes to be
noticed and refilled: NAK timing, the retransmission path, and the expiry timer.
That is where the next attempt should go.

Worth stating plainly because the number is easy to over-read in either
direction: measure with the mean over seeds, never one. A single seed on that
test ranges from 7x to 35x on nothing but which packets get dropped, so any
single-seed comparison of this change would have been meaningless.

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
