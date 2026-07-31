# Data on the first packet

UDT establishes in two round trips: the client sends `CONNECT`, the listener
answers with a cookie challenge, the client echoes the cookie in a `RESPONSE`,
and the listener accepts. Application data goes out after all of that, so the
first byte costs two round trips — 100 ms on a 50 ms path before anything moves.

The goal here is to carry opaque bytes on the *first* packet, so that whatever
sits above the transport can start its own handshake immediately rather than
waiting for this one to finish.

## The transport does not know what the bytes are

The motivating case is a Noise handshake — `NK`/`IK`/`NX` for client-to-server,
`XX` or `KK` for rendezvous. None of that belongs in this crate. The transport
carries an opaque `&[u8]`, hands it to the application at accept time, and has
no opinion about its contents.

That matters for more than tidiness: the replay and forward-secrecy properties
below depend on which pattern is chosen, and the transport cannot reason about
them. It can only state what it guarantees and let the layer above decide
whether that is enough.

## Budget

At a 1500-byte MTU, after 28 bytes of IP/UDP, a 16-byte UDT control header and
the 48-byte handshake body, **1408 bytes** remain. Every Noise handshake message
fits with room to spare — `IK` message 1 with a static key and a short payload is
under 150 bytes.

A cap well under the MTU is the right call. One packet, never fragmented, never
a second datagram before the connection exists.

## The tension this feature turns on

The listener is allocation-free against an unverified peer, and that is
deliberate: the cookie is stateless, derived from the peer address, a listener
secret and a coarse clock, with nothing recorded. The README promises it.

0-RTT data arrives on the first packet, before the cookie has come back. So a
stateless listener has nowhere to put it. Three ways out, and only one works:

**Client repeats the payload in the conclusion.** Listener stays stateless,
discards the first copy, reads the second. But then the first copy bought
nothing — this is data-on-the-conclusion with a wasted transmission. It saves
one round trip relative to today, not two, and does not need first-packet data
at all.

**Encode it into the cookie.** The cookie is a single `i32` field. Not remotely
enough for a Noise message. Dead.

**The listener holds bounded state.** The only option that delivers actual
0-RTT. It trades "allocates nothing" for "allocates a bounded, configurable
amount, and stops when pressed" — which is the trade QUIC makes for address
validation, where a server is stateful when it can afford to be and falls back
to a stateless Retry under load.

**Recommendation: bounded state, with the fallback.** Concretely:

- a fixed-capacity pool of pending 0-RTT payloads, sized at listener creation;
- one entry per peer address, so a single source cannot fill it;
- entries expire on the cookie's own lifetime, since a conclusion arriving after
  that is refused anyway;
- when the pool is full, fall back to today's behaviour — answer with the cookie
  challenge and drop the payload. The client then either resends its data after
  the handshake or, if the extension is negotiated, on the conclusion. Never
  fail the connection over it.

Under attack this degrades to exactly the current guarantee. That is the
property worth preserving, and it is stronger than "we allocate a bit".

## Amplification

An unverified peer must not be able to make the listener send more than it
received. Today that holds trivially: the challenge is no larger than the
request.

With a payload in flight the listener may want to answer with one — a Noise
`msg2` in the challenge would save the second round trip too. That is only safe
if the request was at least as large, so borrow QUIC's rule directly:

- **a `CONNECT` carrying 0-RTT data must be padded to a fixed minimum** (QUIC
  uses 1200 bytes for its Initial packets; the same number is a reasonable
  starting point here);
- the listener's reply to an unvalidated peer may not exceed what it received.

Padding costs a full-MTU packet on a path where a 76-byte one would have done.
That is the price of a response before address validation, and it should be the
application's choice, not a default.

## Replay

The cookie is stateless, so it is not single-use: a captured first packet can be
replayed for as long as the cookie remains valid, and the listener will accept
the payload again.

For a Noise handshake this is milder than it sounds but not nothing:

- The responder generates a fresh ephemeral per handshake, so a replayed message
  1 does not produce a duplicate session — it produces a *new* one that the
  original client cannot complete.
- What it does buy an attacker is work: each replay costs the responder a DH
  operation and a pool entry. The per-address cap above bounds that.
- For patterns where message 1 carries an encrypted payload under a static key —
  `IK`, `KK` — that payload is replayable and has no forward secrecy. The Noise
  specification says so directly about first-message payloads. An application
  putting anything non-idempotent there is making a mistake the transport cannot
  catch.

The transport's obligation is to document that a 0-RTT payload may be delivered
more than once, and to bound the work a replay costs. It cannot provide
exactly-once for a payload that arrives before any state exists.

## Wire compatibility

The handshake is a fixed-layout control packet. The intended trick is the one
selective ACK used: append the payload after the documented 48-byte body, so a
peer that does not know about it reads the fields it expects and ignores the
rest.

**This is unverified and is the first thing to establish.** Selective ACK proved
both C++ implementations tolerate trailing bytes on an *ACK*; a handshake is
parsed by different code, and `CHandShake::deserialize` may or may not care.
Test it against the fork and pristine upstream before anything else — if either
rejects an over-long handshake, the payload cannot ride along transparently and
the design changes to a capability flag negotiated in the handshake's spare
fields, with data only once both ends have agreed.

That test is cheap and the harness already exists.

## Sequencing

The payload is not stream data and must not consume a sequence number — the
connection's first data packet should still be the ISN. It is delivered
out-of-band, once, at accept time.

The listener currently builds its `Connection` *after* the handshake completes,
so a payload accepted on the first packet has to be held across that boundary
and attached to the connection when it is created.

## API shape

```rust
// client
let socket = endpoint.connect_with_data(peer, &noise_msg1).await?;

// server
let (socket, early) = listener.accept_with_data().await?;
```

`early` is `Option<Bytes>` — `None` when the peer sent nothing, or when the
listener was under pressure and dropped it. An application must handle `None` by
falling back to its normal handshake, because it will happen.

The existing `connect` and `accept` keep their signatures and behaviour.

## Rendezvous

Both peers send handshakes simultaneously and neither is a listener, so there is
no cookie challenge and no unverified-peer problem in the same shape — but also
no obvious "first" side. Both payloads would be carried, and an upper layer doing
`XX` or `KK` has to resolve which role each end takes.

Supporting it in the first version is optional and saying no is defensible. The
connect/accept path is where the round trips actually hurt.

## Order of work

1. Test whether both C++ implementations tolerate trailing bytes on a handshake.
   Everything below depends on the answer.
2. Decide the pool budget and whether the padding requirement is on by default.
3. Wire format and codec, with a fuzz target, since this parses attacker-supplied
   bytes before any validation has happened.
4. Listener state and the pressure fallback.
5. API, then rendezvous if wanted.
