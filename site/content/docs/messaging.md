+++
title = "Messaging"
description = "How a datagram becomes a protocol message: session lookup, decryption, replay detection, exchange routing and MRP — and why the order of those is fixed."
weight = 3
+++

Every protocol layer in this crate is sans-I/O, which leaves one question: what turns bytes
arriving on a socket into a message a protocol can act on? Specification §4.7 answers it in
two halves — "Message Transmission" and "Message Reception" — and `matter_kit::messaging` is
those two halves and nothing else.

```rust,ignore
let mut stack = Messaging::<MyConfig, SESSIONS, EXCHANGES>::new(
    rng.next_u16(), rng.next_u16(), rng.next_u32(),
);

// Inbound. `from` is a `Peer`: an IPv6 address, or a BLE connection handle.
match stack.receive(&mut datagram, from, now)? {
    Received::Message { exchange, header, payload, needs_ack } => { /* dispatch */ }
    Received::Duplicate { exchange, needs_ack } => { /* acknowledge, do not act */ }
    Received::Acknowledged { .. } => {}
}

// Outbound.
let (len, counter) = stack.send(exchange, opcode, reliable, payload, now, rng.next_u32(), &mut out)?;
```

## Reception is not a decode

It is tempting to write reception as a pure function from bytes to a message. It is not one:
three pieces of state move on the way through, and all three are security-relevant.

- The **session's replay window** (§4.6.5), which decides whether this counter is new.
- The **exchange's MRP state** (§4.12) — whether an acknowledgement is owed, and whether a
  retransmission is still outstanding.
- The **exchange table** itself, since an arriving message may open an exchange the peer
  initiated.

And the order in which they move is fixed: **find the session, decrypt, and only then touch
any counter.** A receiver that advanced a replay window before authenticating would let
anyone who can send a UDP packet move state they hold no key for — and the symptom is not a
crash, it is a legitimate peer being told its messages are replays.

## A duplicate is acknowledged and dropped

§4.12.2.2 is unusually blunt, and this is the rule most easily got wrong in the direction that
looks like it works:

> The receiver SHALL send an acknowledgment message to the sender for each instance of an
> authenticated, reliable message, including duplicates. The reliability layer SHALL only
> propagate the first instance of a message to the next higher layer.

Both halves matter. Drop a duplicate silently and the sender retransmits until it gives up —
because a retransmission means *its acknowledgement* was lost, not its message. Deliver it
twice and the application arms a fail-safe, or unlocks a door, twice. `Received::Duplicate` is
neither: acknowledged, not delivered.

## A retransmission is the same message

> Logical retransmission is of a given message as identified by its message counter.

So `Due::Retransmit` names a counter, not a payload to rebuild. Re-encoding would take a fresh
counter, which makes it a *different* message — and reuses the AEAD nonce of the one before
it. The caller keeps the bytes it sent and sends them again.

## Only an initiator opens an exchange

A message whose **I** flag is set may create the exchange it names. One claiming to be a
*response* to an exchange that was never opened is refused, because it is answering a question
nobody asked. Getting the inversion backwards — a message *from* the initiator belongs to the
exchange in which this node is the **responder** — is how a node ends up answering itself.

## ...but not every initiator gets one

That rule alone makes the exchange table something a stranger can allocate from. The table is
fixed-capacity by construction, the unsecured session is open to anyone who can reach the port —
it has to be, because that is where PASE and CASE begin — and §4.10.5.3 leaves closing an
exchange to "the application layer", which for an abandoned handshake is nobody. So *N*
datagrams with *N* different exchange ids, costing nothing and proving nothing, would end
session establishment on that node until it was restarted. Everything already connected keeps
working, which is what makes it hard to spot.

§4.10.5.2 has three rules, applied in order, and `matter-kit` adds a fourth:

| | Rule | Result |
|---|---|---|
| 1 | not a duplicate, **registered Protocol ID**, **I** flag set | a real exchange |
| 2 | otherwise, **R** flag set | an *ephemeral* exchange: acknowledged, then closed at once (§4.12.5.2.2) |
| 3 | otherwise | "processing of the message SHALL stop" — nothing allocated |
| 4 | idle for `EXCHANGE_IDLE_TIMEOUT` | reclaimed |

```rust,ignore
// §4.10.3.1: "Any message for a Protocol ID that is not registered with the Exchange Layer
// SHALL be dropped." The default is Secure Channel and the Interaction Model.
stack.register(Protocols::DEVICE.with(Protocols::BDX));
```

The fourth rule is not in the specification, and is the one that closes the hole. Sixty seconds
is taken from §5.5's own bound on the handshake most worth attacking. Reclamation runs inside
`poll`, which a node already calls to drive MRP, *and* again when the table is full — so a node
whose timers are slow still does not refuse a real peer on behalf of an entry that expired a
minute ago. An exchange still awaiting an acknowledgement is never reclaimed (§4.10.5.3 step 2b).

The published precedent is CVE-2024-3297: replayed Sigma1 messages at two or three a second
stopped devices answering Sigma1 at all, and the impact only became visible the next time a
controller tried to connect — a *delayed* denial of service.

## Privacy is a sender's choice

§4.9's **P** flag is only *required* on group messages. On a secure unicast session it is
optional, and `matter-kit` leaves it **off** by default: what it buys is hiding a message
counter that is already authenticated and readable by anyone holding the key, and what it
costs is depending on every peer having exercised its deobfuscation path. `set_privacy(true)`
turns it on where that trade is worth making.

Reception is not a choice. The flag is in the message, and `receive` honours it whatever the
local setting is.

## The transport decides whether MRP runs

§4.12.4: "Reliable messages sent over TCP, PAFTP, or BTP SHALL utilize the underlying
reliability mechanisms of those transports and SHOULD NOT set the R Flag." So `reliable` is a
request, not an instruction — an exchange whose peer is a `Peer::Ble` never sets the flag and
arms no retransmission timer, because [BTP](@/docs/bluetooth.md) has already delivered the
message or closed the session trying.

An exchange learns its peer from the first message that arrives on it, or is told up front
with `open_to`. Until it knows, it assumes UDP and runs MRP: that is right for UDP, and one
wasted round trip on anything else.

## What it does not do

It does not own the PASE or CASE state machines, the interaction model server, or your
clusters. Those stay the caller's, which is what lets the whole thing be driven from a test
without an executor — see `tests/commission_over_messaging.rs`, which pairs a commissioner
with a device and then invokes a cluster over the session PASE produced, with nothing building
a message header by hand.
