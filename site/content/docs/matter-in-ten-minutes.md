+++
title = "Matter in ten minutes"
description = "What Matter is, what a node, endpoint, cluster, fabric and commissioner are, and how a device joins a home — the background the rest of the documentation assumes."
weight = 1
+++

Matter is a smart-home application protocol published by the Connectivity Standards
Alliance. It is the layer that lets a light bulb from one vendor be controlled by a hub from
another, and it is what "Works with Apple Home / Google Home / Alexa / SmartThings" means
when a box says so. This crate targets **specification 1.6**, approved 2026-06-16.

Matter does not invent a radio. It runs over Wi-Fi, Ethernet and Thread, all carried on
IPv6, and uses Bluetooth Low Energy only to get a device onto a network in the first place.

## The shape of a device

Every Matter device is a **node** on a network. A node has **endpoints**, an endpoint has
**clusters**, and a cluster has **attributes**, **commands** and **events**.

```text
Node  (one device, one IPv6 address)
└── Endpoint 1                       a light
    ├── Cluster 0x0006  On/Off       attribute OnOff, commands On / Off / Toggle
    └── Cluster 0x0008  Level        attribute CurrentLevel, command MoveToLevel
```

An endpoint is roughly "one thing the user thinks of as a device". A two-gang switch is one
node with two endpoints. Endpoint 0 is special: it always exists and carries the clusters
that describe the node itself — its vendor and product, its network configuration, its
credentials.

A **device type** (a dimmable light, a thermostat, a door lock) is a named set of clusters
an endpoint must have. That is what makes cross-vendor control work: a hub that knows the
Dimmable Light device type knows exactly which attributes and commands to expect.

## Fabrics

A **fabric** is a security domain: a set of nodes that share a root certificate and can talk
to each other. Joining a fabric is what "adding a device to your home" actually does.

A node can be in several fabrics at once — that is how one light can be controlled by both
Apple Home and Google Home, with neither able to read the other's credentials. Each fabric
gives the node its own **operational certificate** and its own identity, and the node keeps
a separate access-control list per fabric.

This is also why so many rules in the specification are *fabric-scoped*: a list of
credentials, bindings or access entries is filtered to the fabric of whoever is asking, and
getting that filtering wrong leaks one administrator's configuration to another.

## Commissioning

**Commissioning** is the process that turns a factory-fresh device into a member of a
fabric. The short version:

1. **Discovery.** The device advertises itself — over Bluetooth LE if it has no network
   yet, over DNS-SD if it does.
2. **PASE.** The commissioner reads the eight-digit passcode from the device's label or QR
   code and runs SPAKE2+, a password-authenticated key exchange. The passcode never crosses
   the wire, and an attacker gets exactly one guess per attempt.
3. **Attestation.** The commissioner asks the device to prove it is a genuine certified
   product, using a certificate chain burned in at the factory and a Certification
   Declaration signed by the Alliance.
4. **Configuration.** Regulatory location, time, network credentials — and the device
   generates a key pair and returns a certificate signing request.
5. **Credentials.** The commissioner issues an operational certificate over that request
   and installs it along with the fabric's root.
6. **CASE.** The device and commissioner establish a fresh session using the new operational
   certificates, and the commissioner sends `CommissioningComplete`.

Everything from step 3 onward happens inside a **fail-safe**: a timer the commissioner arms
and must keep re-arming. If it lapses, the device rolls back every credential, key and
network setting the attempt created. Without it, an interrupted commissioning would leave a
device half-joined to a fabric that no longer exists.

## Talking to a device

Once there is a session, everything is the **interaction model**: read an attribute, write
an attribute, invoke a command, or subscribe to be told when something changes.

A **subscription** is the interesting one, because it is the only interaction where the
*device* decides when to speak. The subscriber names some paths and two intervals — a floor
and a ceiling — and the device reports changes no sooner than the floor and no later than
the ceiling. A battery-powered sensor and a wall-powered hub want opposite things from those
numbers, which is why they are negotiated rather than fixed.

Paths can be **wildcards**: "every attribute of every cluster on every endpoint" is a legal
read, and is how a hub learns the shape of a device it has never seen.

## Being found again

After commissioning, the device advertises over DNS-SD on the local network so controllers
can find it by fabric and node id. That is ordinary DNS Service Discovery — the
specification is explicit that "Matter requires no modifications to IETF Standard DNS-SD" —
with a naming convention and a set of TXT keys layered on top.

## Where to go next

- [Getting started](@/docs/getting-started.md) — put this crate to work.
- [The data model](@/docs/data-model.md) — how reads, writes, invokes and subscriptions are served.
- [Commissioning](@/docs/commissioning.md) — the flow above, in code.
- [Discovery](@/docs/discovery.md) — DNS-SD and the mDNS rules underneath it.
