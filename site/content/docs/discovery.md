+++
title = "Discovery"
description = "How a Matter node is found: DNS-SD records and TXT keys, the DNS wire format, and the mDNS probing, announcing and conflict-resolution schedule underneath."
weight = 10
+++

> Service Advertising and Discovery for Matter uses IETF Standard DNS-Based Service Discovery
> [RFC 6763]. **Matter requires no modifications to IETF Standard DNS-SD.**

That sentence is the shape of this crate's discovery layer. What Matter adds is a naming
convention and a set of TXT keys; everything else is ordinary DNS.

| Context | Service type | Instance name |
|---|---|---|
| Commissionable node | `_matterc._udp` | a random 64-bit value, 16 hex digits |
| Operational | `_matter._tcp` | `<compressed-fabric>-<node-id>` |
| Commissioner | `_matterd._udp` | the vendor's choice |

`_matter._tcp` is not a mistake: "the string `_tcp` is boilerplate text inherited from the
original DNS SRV specification … and doesn't necessarily mean that the advertised
application-layer protocol runs only over TCP". Matter's operational transport is UDP.

## The records

The specification prints the exact records a commissionable node publishes, which makes them
a test vector rather than an illustration:

```text
_matterc._udp.local.                    PTR   DD200C20D25AE5F7._matterc._udp.local.
_S3._sub._matterc._udp.local.           PTR   DD200C20D25AE5F7._matterc._udp.local.
_L840._sub._matterc._udp.local.         PTR   DD200C20D25AE5F7._matterc._udp.local.
_CM._sub._matterc._udp.local.           PTR   DD200C20D25AE5F7._matterc._udp.local.
DD200C20D25AE5F7._matterc._udp.local.   SRV   0 0 11111 B75AFB458ECD.local.
DD200C20D25AE5F7._matterc._udp.local.   TXT   "D=840" "CM=2"
B75AFB458ECD.local.                     AAAA  fe80::f515:576f:9783:3f30
```

**Two naming conventions that look alike and are not.** Every commissionable subtype is a
variable-length decimal number with leading zeroes omitted — `_L840`, `_S3`, `_V123`. The
operational one is exactly sixteen uppercase hexadecimal characters — `_I87E1B004E235A130`.
A subtype in the wrong form is a name nobody browses for, and the node is simply never found.

**The instance name is random, and it changes.** A new one is selected when the node boots
and whenever it enters commissioning mode. A stable name would be a tracking identifier —
the same sixteen hex digits on every network the device ever joins.

## Claiming a name

A node cannot simply start answering for a name. The specification delegates uniqueness to
RFC 6762: the instance name "SHALL be unique within the namespace of the local network", and
"name conflict detection is described in Section 9 ('Conflict Resolution') of the Multicast
DNS specification".

```text
start ──▶ 0–250 ms ──▶ Probe ──250ms──▶ Probe ──250ms──▶ Probe ──250ms──▶ Announce ──1s──▶ Announce
                         └──────────── a conflicting answer ────────────┘ ──▶ rename, start again
```

Two rules in there are easy to read backwards:

- **A conflict while *probing* renames; a conflict once *established* re-probes.** §8.1 says
  the probing host "MUST defer to the existing host, and SHOULD choose new names"; §9 says an
  established responder "MUST immediately reset its conflicted unique record to probing
  state". Renaming on every conflict gives up a name the device would have won; re-probing
  after a lost probe makes two devices loop against each other forever.
- **The name is not owned until 250 ms *after* the third probe** — not at it. A defence sent
  in that window still takes the name, so a responder that starts answering early is one that
  two devices can both be.

Simultaneous probes are broken by the §8.2 tiebreak: each probe carries its proposed records
in the Authority section, and the lexicographically later rdata wins — compared
**uncompressed**, because how a name was compressed is an artifact of the message it was
written into and not a property of the record.

The shared service PTR is never probed for. `_matterc._udp.local.` is owned by every Matter
device on the link at once, so probing for it finds a conflict as soon as there is a second
Matter device in the house.

## Sans-I/O

Both halves own no socket and no clock. The responder turns a query into a response as a pure
function; the schedule is polled — `poll(now)` yields an action, `wake_at()` says when to come
back. A 750 ms claim window is then testable in microseconds, which is why its edge cases
have tests at all.
