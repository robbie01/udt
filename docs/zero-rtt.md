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

## Wire compatibility — the handshake packet cannot carry it

**Tested, and the answer is no.** Both C++ implementations reject a handshake
whose length is not exactly 48 bytes, before deserialising it:

| | | |
|---|---|---|
| pristine upstream | `core.cpp:2471` | `if (packet.getLength() != CHandShake::m_iContentSize) return 1004;` |
| the fork | `core.cpp:1771` | identical |

That is `CUDT::listen()`, which handles the induction *and* the conclusion. So
appending a payload to either one is not a compatible extension — it is a
connection that never establishes against an unmodified peer. Selective ACK's
trick does not transfer; an ACK is parsed by code that tolerates trailing bytes
and a handshake is not.

This kills the transparent-extension design for both variants, and the doc above
was written assuming it would work.

## What replaces it: a separate packet

Do not touch the handshake packet. Send the payload as its **own datagram**,
immediately after the `CONNECT`, as a distinct control type.

This sidesteps the length check completely, and it degrades correctly by
construction:

- An unmodified C++ peer receives a control packet of a type it does not know
  and drops it. Its handshake is byte-identical to today's, so interop is
  untouched and needs no negotiation at all.
- A Rust peer that receives it before the connection exists holds it against the
  pending handshake, under the same bounded pool described above.
- If the extra datagram is lost, nothing breaks. There is no 0-RTT payload, the
  handshake completes normally, and the application falls back — which it must
  handle anyway, since the listener may be under pressure and drop it.

Two consequences worth stating plainly.

**No negotiation is needed for safety**, only for efficiency. A client can always
send the payload; against a C++ peer it is wasted bandwidth, not a failure. If
that waste matters, the listener can advertise support in a spare handshake
field — but nothing is broken without it.

**The payload is now unauthenticated and unordered relative to the handshake.**
It is a lone datagram from an unverified source, arriving before any state
exists, possibly before or after the `CONNECT` it belongs to. It needs to carry
enough to be matched to a pending handshake — the client's socket id and ISN at
minimum — and every byte of it is attacker-controlled. It parses before
validation, so it wants a fuzz target from the first commit rather than a later
one.

## Who speaks first, and when

Time in round trips from the client's first packet. `→` is client to listener.

**Today**

```
0.0  →  CONNECT
0.5  ←  cookie challenge
1.0  →  RESPONSE (cookie)
1.5  ←  accept.                    listener may now send
2.0     client established.        client may now send
2.5  →  first client data arrives
3.0  ←  first listener data arrives
```

**Conclusion-phase variant** — payload rides with the `RESPONSE`

```
0.0  →  CONNECT
0.5  ←  cookie challenge
1.0  →  RESPONSE (cookie) + client payload
1.5  ←  accept + listener payload.  client payload has arrived
2.0     listener payload arrives
```

**First-packet variant** — payload rides with the `CONNECT`

```
0.0  →  CONNECT + client payload
0.5  ←  cookie challenge + listener payload.  client payload has arrived
1.0     listener payload arrives
```

The client is first in every variant. It has to be: the listener has nothing to
say until it has heard something, and at 0.5 in the conclusion variant it has
neither a validated peer nor any application data to respond to.

What changes between the variants is **when the listener can answer**, and that
is the whole difference:

- conclusion-phase saves one round trip in each direction — a two-message Noise
  pattern like `NK` or `IK` completes at 2.0 instead of 3.0;
- first-packet saves two — the same pattern completes at 1.0.

The listener answering at 0.5 is what makes the first-packet variant worth its
difficulty, and it is also exactly the moment the peer is unverified. That is
where the padding requirement earns its cost: without it, a listener replying at
0.5 is an amplifier. With it, the client has already paid for the bytes it is
about to receive.

For a rendezvous pair there is no listener and no challenge, so both sides are
at 0.0 and both may send a payload immediately. Which is the other reason that
path is the one to build first.

## Why the conclusion-phase variant is the one to build

A two-message Noise pattern — `NK`, `IK`, `KK`, `NX` — completes in one round
trip. Carried on the conclusion, that fits entirely inside the transport
handshake:

```
1.0  →  RESPONSE (cookie) + noise msg1 [+ payload]
1.5  ←  accept + noise msg2 [+ payload].   client data has arrived
2.0     server data arrives, session established both ways
```

The transport handshake finishes at 2.0 either way. The Noise handshake finishes
at 2.0 too. **Encryption costs zero additional round trips** — it is entirely
hidden inside establishment, and the first application bytes land at 1.5 and 2.0
where today they land at 2.5 and 3.0.

The first-packet variant would complete Noise at 1.0, which is genuinely earlier
but buys a round trip the transport cannot use for free: it costs speculative
allocation for unverified peers, a padding requirement, and a listener doing
Diffie-Hellman before it has validated an address. That is a lot of exposure to
finish a handshake ahead of the connection it belongs to.

So: **build the conclusion-phase variant.** It is the point where the security
handshake becomes free, and everything past it is paid for in attack surface.

Two consequences for pattern choice, which belong to the layer above but are
worth stating here:

- A payload in Noise message 1 — `IK` and `KK` carry one under a static key — is
  replayable and has no forward secrecy, as the Noise specification says. That
  is fine for a handshake message and not fine for application data that matters.
- `XX` is three messages, so it does not fit this shape: message 3 lands after
  the transport handshake is over. It still works, it just does not get the free
  ride.

## Ordering

The payload is now a separate datagram, so it can arrive before the `CONNECT`
it belongs to. Nothing about UDP prevents that and reordering is common.

It must therefore be **self-describing**: the client's socket id and ISN travel
in the payload datagram itself, and the listener never needs the handshake to
have arrived first in order to interpret it. Pool entries are keyed on
`(peer address, socket id)`, filled by whichever datagram lands first, and read
at accept time. Both orders then work, and the loss of either datagram costs
only the 0-RTT payload.

That fixes interpretation. It does not fix the exposure, and the exposure is
worse than the section above admits.

**Requiring the `CONNECT` to have been seen first buys nothing**, because the
listener holds no state at induction — that is the whole point of the stateless
cookie. There is nothing to check a payload against. So a payload arriving first
means allocating a pool entry for a peer that has not sent a handshake, has not
answered a challenge, and may not exist. One spoofed datagram, one entry.

For the conclusion-phase variant there is a clean answer: **put the cookie in
the payload datagram**. The listener can then verify it statelessly on arrival,
in any order, and only allocate for a peer that has demonstrably received a
challenge at that address. Spoofing stops working. The cost is that this is no
longer 0-RTT — it saves one round trip, not two.

For true first-packet 0-RTT there is no cookie yet, so no stateless check is
possible, and speculative allocation for unverified peers is not a detail of the
design but the whole of it. The bounded pool, per-address cap, expiry and
pressure fallback are the mitigations, and they are what makes it survivable
rather than what makes it safe.

**That argues for the feature being off by default**, with the conclusion-phase
variant as the one enabled without ceremony.

## Rendezvous is the easy case, not the hard one

The doc above treated rendezvous as an afterthought. It is the opposite, and for
a peer-to-peer system it is probably the path that matters.

Rendezvous sends `cookie: 0` — there is no challenge, and no address validation
of any kind. That sounds worse and is better, because of what it replaces:
**a rendezvous peer already holds state for the address it is connecting to.**
The application called `connect_rendezvous(peer)`, so a `Connection` exists,
pending, before anything is sent.

A payload arriving from that address is matched against state the local
application deliberately created. There is no pool, no speculative allocation,
and no new exposure — the number of pending rendezvous connections is bounded by
the local application's own behaviour, not by an attacker's. Reordering is a
non-issue for the same reason: the state to match against exists before either
datagram is sent.

So rendezvous gets true 0-RTT essentially for free, while connect/accept is
where all the difficulty lives. If the motivating use is peer-to-peer with a
Noise handshake over rendezvous, **that is the version to build first**, and it
can ship without resolving the pool question at all.

The remaining wrinkle is symmetry: both peers are initiators and both may send a
payload. A pattern like `XX` has to decide which end takes which role, and that
belongs above this layer — the transport delivers both and says nothing about
them.

## Sequencing## Sequencing

The payload is not stream data and must not consume a sequence number — the
connection's first data packet should still be the ISN. It is delivered
out-of-band, once, at accept time.

The listener currently builds its `Connection` *after* the handshake completes,
so a payload accepted on the first packet has to be held across that boundary
and attached to the connection when it is created.

## API

Modelled on quinn's, with the parts that do not apply removed.

Quinn splits connecting into a `Connecting` future that can be converted into an
early `Connection`, because QUIC 0-RTT depends on a resumption ticket and may be
refused — hence a fallible `into_0rtt()` that hands back the original, and a
`ZeroRttAccepted` future to learn the answer later. Neither applies here. There
is no ticket, nothing to resume, and no negotiation: a client can always attach a
payload, and the only question is whether the peer understood it.

### Client

```rust
// unchanged
let socket = endpoint.connect(peer).await?;

// new: start the handshake, attach bytes to it, then await as before
let mut connecting = endpoint.connect_early(peer)?;
connecting.send_early(&noise_msg1)?;
let socket = connecting.await?;
```

`connect_early` returns immediately — the handshake runs in the background, and
`Connecting` is a `Future<Output = io::Result<Socket>>`, so awaiting it is the
same as `connect` today. `send_early` queues one message to travel with the
conclusion; calling it after the conclusion has gone out is an error rather than
a silent normal send.

### Sharing the ordinary data path

The early payload should not be a parallel delivery mechanism. It should be an
**early transmission of a packet that also lives in the normal send buffer**.

The client enqueues the message the way it enqueues any message: into `snd_buf`,
as message 0, at sequence `ISN`. It then *additionally* emits it beside the
conclusion. Nothing about the send buffer's view changes — as far as it is
concerned the packet has been sent and is unacknowledged, exactly like any other.

Everything then falls out of machinery that already exists:

| | comes from |
|---|---|
| acknowledgement | the ordinary ACK. If the peer acks `ISN`, it arrived. |
| loss recovery | the ordinary NAK and RTO paths. `snd_buf` still holds it. |
| duplicate suppression | the receiver already discards a sequence it has. |
| ordering | it *is* sequence `ISN`; the receive buffer places it. |

The receiver's side needs nothing special either: its `rcv_buf` is created at
`peer_isn`, taken from the handshake, and the early packet carries exactly that
sequence number. It lands where the first data packet was always going to land.

### What this removes

**The acknowledgement question disappears.** There is no need for a listener to
confirm receipt, and no need for `early_data_accepted()`:

- peer received it → it acks `ISN` like anything else;
- packet lost → the ordinary retransmission timer resends it after the handshake
  completes, as an ordinary data packet;
- peer is a C++ implementation that dropped it → indistinguishable from loss, and
  handled by the same path.

That third case is the one worth pausing on. A peer that does not know the
extension is not a special case at all — it is loss, and loss is already solved.
The cost of talking to one is a single wasted packet and one retransmission
timeout, and no application code changes.

**`send_early` may not need to exist.** If any message queued before the
handshake completes is opportunistically sent early, the API reduces to
`connect_early` plus ordinary `send`. Worth deciding: an explicit call is clearer
about what rides along and bounds it to one message, while implicit means an
application that happens to send early gets the benefit for free.

### What still has to change

Sharing the data path is not free — it moves two things earlier:

- **The send buffer must exist before the handshake completes**, so the message
  has somewhere to live. It is created in `post_connect` today.
- **The listener must accept a data packet for a connection that does not exist
  yet**, hold it against the pending handshake, and feed it to the receive buffer
  at accept. Handshake packets are already demultiplexed by address, so the
  routing exists; what is new is holding a payload across the boundary.

Both are real, and both are smaller than reimplementing acknowledgement,
retransmission and duplicate suppression alongside the versions that already
work.

There is one wrinkle to check: at the point the conclusion goes out, the client
has not yet learned the listener's socket id — the challenge echoes the client's
own handshake with only the cookie filled in. Handshake packets already go out
with a destination socket id of 0 and are matched by address, so the early data
packet can do the same, but that means it cannot be an entirely ordinary data
packet on the wire. Whether that costs a distinct type or a reserved id is the
first thing to settle in the wire format.

### Server

**Nothing changes.** The payload is delivered as the connection's first message:

```rust
let socket = listener.accept().await?;
let n = socket.recv(&mut buf).await?;   // noise msg1, early or not
```

This falls out of the transport being message-oriented, and it is the best part
of the design. Server code is byte-identical whether the client used early data
or not — the message simply arrives a round trip sooner. Nothing to branch on,
no `Option`, no second accept path, and an application that never opts in cannot
be broken by a peer that does.

It also means the feature is testable without any API at all on one side.

### What is deliberately not offered

- **A stream of early data.** One message, because one message is what fits
  beside a handshake. Anything larger belongs after establishment.
- **Early data on `accept`.** The listener cannot speak before it has heard, so
  there is nothing for it to send early. Its reply rides the accept regardless.

## Rendezvous is the easy case, not the hard one

The doc above treated rendezvous as an afterthought. It is the opposite, and for
a peer-to-peer system it is probably the path that matters.

Rendezvous sends `cookie: 0` — there is no challenge, and no address validation
of any kind. That sounds worse and is better, because of what it replaces:
**a rendezvous peer already holds state for the address it is connecting to.**
The application called `connect_rendezvous(peer)`, so a `Connection` exists,
pending, before anything is sent.

A payload arriving from that address is matched against state the local
application deliberately created. There is no pool, no speculative allocation,
and no new exposure — the number of pending rendezvous connections is bounded by
the local application's own behaviour, not by an attacker's. Reordering is a
non-issue for the same reason: the state to match against exists before either
datagram is sent.

So rendezvous gets true 0-RTT essentially for free, while connect/accept is
where all the difficulty lives. If the motivating use is peer-to-peer with a
Noise handshake over rendezvous, **that is the version to build first**, and it
can ship without resolving the pool question at all.

The remaining wrinkle is symmetry: both peers are initiators and both may send a
payload. A pattern like `XX` has to decide which end takes which role, and that
belongs above this layer — the transport delivers both and says nothing about
them.

## Sequencing## Sequencing

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
