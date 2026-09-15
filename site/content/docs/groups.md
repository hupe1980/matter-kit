+++
title = "Groups"
description = "Groupcast: one multicast message to twenty lights, the keys that secure it, and the replay protection that replaces a session."
weight = 12
+++

A wall switch that controls twenty lights cannot send twenty messages. Core §4.16 is the
alternative: one IPv6 multicast datagram addressed by a 16-bit **Group ID**, encrypted under a
symmetric key every member holds.

That sentence is also the whole of the difficulty. A group message has no session, no exchange,
no acknowledgement and no reply — so everything a unicast session gives for free has to be
rebuilt.

## Which key?

§4.17.2 derives the key a message is actually encrypted under from an **epoch key** an
administrator installed, salted with the fabric's compressed identifier. The same epoch key
therefore gives different keys on different fabrics, and revoking a member is simply not sending
it the next one.

§4.17.3.6 then derives a 16-bit **Group Session ID** from that key and puts it in the message
header — but only as a hint:

> It SHALL NOT be used as the sole means to locate the associated Operational Group Key, since
> it MAY collide within the fabric.

So a receiver tries every installed key whose session id matches, until one authenticates.
`tests/groupcast.rs` constructs a collision on purpose and checks the right key still wins: a
receiver that stopped at the first candidate would drop one group's traffic entirely, and which
group would depend on the order the administrator installed the keys in.

```rust
use matter_kit::group::{self, keys::GroupKeys, peers::PeerTable, wire};

let key = keys.sending_key(fabric, compressed, group, now)?;
let n = sender.send(&key, group, &header, payload, false, &mut scratch, &mut out)?;
// …to group::multicast_address(fabric, group), or FF05::FA, on port 5540.
```

## Is it fresh?

There is no handshake to agree a starting counter, so §4.18 keeps one per sender in a
[`PeerTable`]. Which counter is trusted depends on the key's policy:

* **Trust-first** takes the first counter it sees. Low latency, and — the specification's own
  warning — "susceptible to accepting a replayed message after a Node has been rebooted".
* **Cache-and-sync** holds the message, runs MCSP's request/response over unicast, and only then
  processes it. Replay protection across a reboot, at the cost of a round trip.

One rule about that table is easy to miss and load-bearing (§4.16.1):

> that record SHALL NOT be deleted or recycled until the node reboots … Any message from a
> source that cannot be tracked SHALL be dropped.

A full table refuses new senders. That *is* the protection: an attacker who could push a real
peer out could then replay that peer's traffic.

## Who sent it?

§4.16.1's Groupcast Session Context — fabric, group, source node — is what the layer above is
given in place of a session, and it is built fresh on every message. A group is not something
that is established; it is a membership that happens to still hold.

## Configuring it

Two clusters, and in 1.6 a third that replaces both.

**Group Key Management** (§11.2) is where an administrator installs key sets and maps groups to
them. The rule that matters is what comes back out: §11.2.7.2 replaces every epoch key with null
in a `KeySetRead`. An administrator can write a key and learn that one exists; it cannot read it
back.

**Groupcast** (§11.27, provisional) is 1.6's replacement for the pair. `JoinGroup` takes the
group, the endpoints, the key set and the key in one command, and the node is immediately part of
the group at the message layer. Two of its rules are worth knowing:

* A **sender** joins with an empty endpoint list and a **listener** with at least one. §11.27.4.2:
  "Being a sender does not imply the ability to listen." Accepting either shape from either kind
  of device makes a group that looks configured and never works.
* Every group may share the IANA-assigned `FF05::FA`, so three groups cost one multicast
  subscription rather than three. `PerGroup` addresses stay available for listeners whose radio
  should do the filtering.

## Read next

* [Clusters](@/docs/clusters.md) — how a cluster handler is written.
* [Messaging](@/docs/messaging.md) — what the layers underneath do for unicast.
