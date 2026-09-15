+++
title = "Large data"
description = "Matter over TCP, the Bulk Data Exchange protocol, the OTA Requestor and the TLS clusters — everything that does not fit in a 1280-octet datagram."
weight = 13
+++

Almost everything Matter does fits in one datagram. Core §4.4.4 caps a message at the IPv6
minimum MTU — 1280 octets, header included — and refuses to rely on fragmentation, which is
enough for turning a light on, reading a thermostat, or the whole of commissioning.

Four things do not fit: a firmware image, a diagnostic log, an X.509 certificate chain, and a
wildcard read of a large node. This page is about those.

## The length prefix, and only on a stream

A UDP datagram carries its own length, so a Matter message over UDP has no length field. A TCP
connection does not: it is a byte stream, and the receiver has to be told where each message
ends. Core §4.5:

> each Matter Message SHALL be prepended with a Message Length field. This field SHALL only be
> present when the message is being transmitted over a stream-oriented channel.

Four octets, little-endian, and — the part that is easy to get wrong and impossible to notice
locally — *not counting itself*. A framer written with the same mistake as the writer reads it
back happily, and the two nodes only disagree when one of them talks to somebody else.

```rust
use matter_kit::transport::tcp::{self, Framed, Framer};

// `N` is §4.15.2.3's Maximum Message Size: the largest message this node will accept.
let mut framer = Framer::<{ tcp::DEFAULT_MAX_MESSAGE }>::new();

let mut rest = bytes_from_socket;
while !rest.is_empty() {
    let taken = framer.push(rest)?;
    rest = &rest[taken..];
    while let Framed::Message(message) = framer.poll()? {
        stack.receive(message, peer, now)?;
    }
}
```

`push` takes as much as it can hold and says how much that was, so a read carrying two messages
and a half is offered in parts rather than dropped. The message `poll` returns borrows the
framer's own buffer and stays valid until the next call, which is also when it is dropped — a
caller that needs to keep one copies it, and a caller that does not pays nothing.

### A message too large closes the connection

§4.15.2.3:

> If a node receives a message header that indicates that the message is larger than the
> Maximum Message Size that it supports, then it SHALL close the connection, and SHOULD send a
> Status Report error message with a status code set to MESSAGE_TOO_LARGE.

Close, not skip. The length prefix is the *only* message boundary a stream has, so a receiver
that could not buffer the message has also lost its place — everything after it would be read
as a header. `Framer` latches the failure and refuses every later call;
`tcp::too_large` writes the report to send before hanging up.

### MRP does not run here

§4.15: "Since TCP already provides message transmission reliability, a node that is using TCP as
the underlying transport protocol SHALL NOT use MRP reliability semantics on its message
exchanges." Setting the **R** flag on a TCP message asks for an acknowledgement the peer is
under no obligation to send, and the sender then retransmits into a stream that had already
delivered it.

`Peer::Tcp` is what says so, the same way `Peer::Ble` does for BTP: the exchange layer reads
`Peer::is_reliable` rather than trusting every caller to remember. The same value answers the
other question a stream settles — `Peer::supports_large_payloads` is what an application passes
to `InteractionContext::with_large_messages`, so the data model's `L` quality is enforced
against the transport that is actually underneath rather than a build-time guess.

## BDX: moving a file

Core §11.22's Bulk Data Exchange protocol is how anything larger than a message moves: a
negotiation, a run of numbered blocks, and an acknowledgement that ends the session. It is what
an OTA image travels over and what `RetrieveLogsRequest` hands a diagnostic log to.

BDX names its ends twice over. **Sender** and **Receiver** say which way the data goes;
**Initiator** and **Responder** say who spoke first. A download — an OTA Requestor fetching an
image — is an Initiator that is the Receiver, so it opens with `ReceiveInit`; an upload opens
with `SendInit`. Either way exactly one end is the **Driver**, and it paces the transfer.

That is the point of the protocol. BDX does not retransmit: §11.22.4 requires a reliable
transport underneath, so `BlockAck` and `BlockQuery` are *flow control*, and a battery-powered
node uses Receiver drive to ask for each block when it is awake rather than being sent blocks
while it is not.

```rust
use matter_kit::bdx::{Direction, Init, Limits, Parameters, Receiver, Sender, negotiate};

// The Requestor proposes; the Provider answers with what it will actually do.
let mut proposal = Init::new(b"firmware.ota", 1024);
proposal.definite_length = Some(image.len() as u64);

let agreed = negotiate(Direction::Download, &proposal, &Limits {
    available: Some(image.len() as u64),
    ..Limits::default()
})?;
let accept = agreed.receive_accept(&[]);

let mut provider = Sender::new(agreed);
let mut requestor = Receiver::new(Parameters::from_receive_accept(&proposal, &accept)?);
```

`Sender` and `Receiver` do not encode anything — `bdx::message` does that — and they do not
touch a socket. What they enforce is §11.22.6.1, which is where a BDX implementation actually
goes wrong: block counters ascending and sequential modulo 2³², acknowledgements naming the
block they acknowledge, blocks within the negotiated size, and a transfer that ends exactly on
the length it promised. Each failure carries the §11.22.3.2 status code the peer has to be told,
because that is the whole content of a BDX failure:

```rust
assert_eq!(receiver.on_block(2, 64, false), Err(StatusCode::BadBlockCounter));
```

`bdx::report` turns one into the `StatusReport` to send, and §11.22.3.2 is clear about what
happens next: "the receiving peer SHALL terminate its processing of the transfer and invalidate
the exchange."

## The OTA Requestor

`clusters::ota_requestor` is the cluster on the device *being* updated (`0x002A`), the other
half of the Provider. It holds where to ask, says how far along an update is, and reports what
happened through §11.20.7.7's three events.

Two rules carry it. §11.20.7.5 allows **one provider per fabric**, enforced with
`CONSTRAINT_ERROR`: each fabric's administrator names its own, and the device asks each of them.
And the rule sitting next to it, which is the one that matters:

> Provider Locations obtained using the AnnounceOTAProvider command SHALL NOT overwrite values
> set in the DefaultOTAProviders attribute.

An announcement is a hint to query *sooner*. A device that let one rewrite the list would let
any administrator on the fabric redirect every later update — including after its own access had
been removed.

The nine states of §11.20.7.4.2 are the application's to move through, and
`OtaRequestor::transition` is how it says so. Three rules follow from that one call rather than
having to be remembered at nine sites: the `StateTransition` event fires only on an actual
change, `TargetSoftwareVersion` is non-null only while `Downloading`, `Applying` or
`RollingBack`, and `UpdateStateProgress` resets, because nothing has been reported yet about a
state just entered.

## The TLS clusters

Some application clusters — Camera AV Stream Management, WebRTC — reach outside the fabric over
TLS. Core chapter 14 is how an administrator provisions that, across two clusters that share one
set of tables:

* **TLS Certificate Management** (`0x0801`) holds the trust material: root CAs, and client
  certificate details created through a CSR the node signs with a key it generates itself.
* **TLS Client Management** (`0x0802`) holds the endpoints — a hostname, a port, and the
  certificates from the other cluster to use with them.

They are not independent, and the rules that link them are the ones to get right. §14.4.6.7
refuses to remove a root certificate an endpoint still names; §14.5.7.1 refuses to provision an
endpoint naming a certificate that does not exist. Each check has to see both tables, which is
why `TlsTables` holds all three and both clusters are views onto it.

Certificates do not live in RAM. §14.4.4.3 caps one at 3000 octets and §14.3.3.1 asks for five
root certificates *per fabric* — tens of kilobytes, which no `no_std` node keeps in a
fixed-capacity array. So the crate holds the index (ids, fingerprints, fabric associations,
reference counts) and `TlsCertificateHooks` owns the bytes, writing them straight into the
outgoing TLV rather than through a buffer in between.

### Where this ties back to TCP

§14.4 says it outright:

> Commands in this cluster uniformly use the Large Message qualifier, even when the command
> doesn't require it, to reduce the testing matrix.

So these commands need a stream underneath, and the interaction model enforces it: a command
with the `L` quality invoked over a datagram transport is answered `INVALID_TRANSPORT_TYPE`,
which tells the client to come back over TCP rather than to give up.

The attributes behave differently, and deliberately:

> When this field exists and is read over a Large Message capable transport, it SHALL be
> included. When this field exists and is read over a non Large Message capable transport, it
> SHALL NOT be included.

A read of `ProvisionedRootCertificates` over UDP returns the ids without the certificates. That
is not a truncation and not an error — it is the attribute having a different shape on a
transport that cannot carry the whole of it, with `FindRootCertificate` as the way to get the
rest.

## Read next

* [Messaging](@/docs/messaging.md) — what the layers underneath the transport do.
* [Controller](@/docs/controller.md) — the OTA Provider's side, and the commissioner.
* [Clusters](@/docs/clusters.md) — how a cluster handler is written.
