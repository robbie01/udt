# Data during the handshake

UDT establishes in two round trips. The client sends `CONNECT`, the listener
answers with a cookie challenge, the client echoes the cookie in a `RESPONSE`,
and the listener accepts. Application data goes out after all of that, so the
first byte costs two round trips — 100 ms on a 50 ms path before anything
useful moves.

Two things could be done about that, and they are not the same feature.

## Data on the conclusion (safe, one round trip saved)

Attach data to the client's `RESPONSE`, the packet that echoes the cookie.

The cookie is already proof that the client received the listener's challenge,
so the source address is verified by that point. A listener acting on this data
is not acting for an unverified peer, and the amplification and state-exhaustion
properties the cookie exists to provide are untouched.

This is the one worth doing first. It saves one of the two round trips and costs
nothing that is currently guaranteed.

## Data on the initial `CONNECT` (true 0-RTT, and it breaks something)

Attach data to the very first packet.

The README currently promises: *"The handshake is stateless behind a cookie, so
an unverified peer cannot make a listener allocate anything, and the reply is no
larger than the request."* Carrying data on the first packet contradicts that
directly — a spoofed source could make a listener buffer and deliver payload it
never verified anyone asked for.

TLS 1.3 has the same exposure and lives with it by restricting 0-RTT to
idempotent requests and adding anti-replay machinery. Doing this here means
accepting the same restriction and saying so in the security section, not
quietly widening what the transport promises.

**Recommendation: do the conclusion version, and treat the initial-packet
version as a separate decision with a security cost attached.**

## Replay

Both versions are replayable. An attacker who captures a conclusion packet can
send it again, and the listener will accept the data a second time unless the
cookie is single-use.

**Checked: it is not single-use.** The cookie is stateless by design — derived
from the peer address, a listener secret and a coarse clock, with nothing
recorded (`listener.rs`, "Nothing is recorded here on purpose"). That is what
makes the handshake allocation-free against an unverified peer, and it is a
property worth keeping.

It also means a captured conclusion packet can be replayed for as long as the
cookie stays valid, and the listener will accept the data again. Statelessness
and replay protection pull in opposite directions here: anything that remembers
which cookies have been used reintroduces the per-peer state the design
deliberately avoids.

Options, none free:

- Accept replay and restrict this to idempotent payloads, as TLS 1.3 does. Needs
  saying plainly in the API and the security section.
- Keep a small window of recently-used cookies. Bounded state, so bounded
  exposure, but no longer strictly allocation-free.
- Bind the cookie to something the replayer cannot reproduce. Nothing obvious
  is available without encryption, which the protocol does not have.

This is the decision the feature turns on, and it should be made before any code
is written.

## Wire compatibility

The handshake is a fixed-layout control packet. The extension is the selective
ACK trick again: append the payload after the documented body, so a peer that
does not know about it reads the fields it expects and ignores the rest.

**Unverified, and it is the first thing to establish:** whether the C++ fork and
pristine upstream both tolerate trailing bytes on a handshake packet. Selective
ACK proved they tolerate it on an ACK; nothing has tested it here, and a
handshake is parsed by different code. If either implementation rejects an
over-long handshake, this feature cannot be a compatible extension and the
design has to change — probably to a negotiated capability flag in the
handshake's spare fields, with data only after both sides confirm.

## Sequencing

The data needs a sequence number the receiver can place. The client's initial
sequence number is already in the handshake, so payload on the conclusion is
naturally the first packet of the stream. The receive buffer has to exist before
the accepted `Connection` is handed to the application, which it does, but the
listener path currently builds the connection *after* the handshake completes —
so the data has to be held across that boundary.

## Rendezvous

Both peers send handshakes simultaneously and there is no listener. Which side's
data is "first" is not defined the way it is for connect/accept, and both could
carry payload. Worth deciding whether rendezvous supports this at all in the
first version; saying no is defensible.
