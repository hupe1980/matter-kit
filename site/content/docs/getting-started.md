+++
title = "Getting started"
description = "Install matter-kit, size a node with the Config trait, serve a Read, and run the examples on a simulated network."
weight = 2
+++

## Install

```sh
cargo add matter-kit
```

The default build is the one a device ships: `no_std`, no allocation, UDP with the
Message Reliability Protocol, and the RustCrypto software backend.

| Feature | Default | What it adds |
|---|---|---|
| `rustcrypto` | ✅ | The software cryptographic backend. The algorithms are fixed by the specification; this selects the *implementation*. |
| `alloc` | | Growable collections, and the TCP transport with its large payloads. |
| `std` | | Sockets, a file-backed key-value store, `std::error::Error`. Implies `alloc`. |
| `log` / `defmt` | | Logging backends. Pick one. |
| `provisional` | | Specification §2.13 provisional items. Never certifiable; may change in a 1.6.x revision. |

Minimum supported Rust version is **1.88**, edition 2024.

## Size the node

Every table in the stack is a fixed-capacity array. The capacities come from one trait, and
the specification's minima are `const` assertions — a configuration that could not pass
certification fails to compile rather than failing certification.

```rust
use matter_kit::Config;

struct Light;
impl Config for Light {
    const FABRICS: usize = 5;      // Core §11.18.5.3 constrains this to 5..=254
    const SESSIONS: usize = 16;    // Core §4.14.2.8 wants ≥ 3 per fabric
    // …everything else defaults.
}
```

## Describe the device

A device's shape is `const` data — endpoints holding cluster descriptors, living in flash
and costing no RAM.

```rust,ignore
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node};
use matter_kit::im::Server;

const EP1: &[ClusterDescriptor] = &[ON_OFF, LEVEL_CONTROL];
const ENDPOINTS: &[Endpoint] = &[Endpoint { id: 1, clusters: EP1 }];

let server = Server::new(Node::new(ENDPOINTS), &acl, &clusters, 24);
```

One `ClusterHandler` supplies the behaviour. `write` and `invoke` default to refusing, so a
cluster that implements neither is read-only by construction rather than by accident.

```rust,ignore
let (bytes, _) = server.serve(paths, None, &mut scratch, &mut buf)?;              // Read
let (bytes, _) = server.serve_write(writes, &ctx, &mut buf)?;                     // Write
let (bytes, _) = server.serve_invoke(cmds, &ctx, false, &mut scratch, &mut buf)?; // Invoke
```

The same handler is how the node tells its clusters that something happened to *it*. A fabric
being removed reaches scenes, groups, bindings, group keys and access-control entries — each
owned by a different cluster, none of them visible from the one that ran `RemoveFabric` — so it
is delivered to every member of the tuple rather than routed to one:

```rust,ignore
use matter_kit::im::Lifecycle;

handler.on_lifecycle(Lifecycle::FabricRemoved(index));      // §11.18.6.12
handler.on_lifecycle(Lifecycle::FailSafeExpired { fabric }); // §11.10.7.2.2
handler.on_lifecycle(Lifecycle::CommissioningComplete(index)); // §11.10.7.6
```

`on_lifecycle` defaults to doing nothing, so a cluster with no fabric-scoped state writes no
code — and adding a cluster to a device adds it to the fan-out by construction. Fabric indices
are reused: an entry that outlives its fabric is inherited by whoever holds that index next.

## Answer a handshake

A commissioner's first message arrives on the Secure Channel protocol, and what it needs from
the node is not one handshake but the rules around it: one at a time, sixty seconds to finish,
twenty failures and commissioning mode ends — plus the verifier an open Enhanced window supplies
instead of the printed passcode, and the session that comes out the other end.

```rust,ignore
use matter_kit::sc::{Channel, ChannelBuffers, ChannelContext};

let mut channel = Channel::new();

// …per message, from the socket loop:
let answered = channel.on_message(
    &mut stack,
    header.opcode,
    &body,
    &ChannelContext { fabrics: &fabrics, keys: &keys, rng: &rng, window: &window,
                      verifier: &verifier, parameters: &parameters, now },
    &mut ChannelBuffers { reply: &mut payload, frame: &mut frame, evict: &mut evict },
)?;

if let Some(established) = answered.established {
    // The session is already installed, and §4.11.1.1's eviction has already happened if it
    // had to. `answered.evicted` is the report its peer is owed, framed and ready to send.
}
```

`None` in `answered.reply` means say nothing — a message for a handshake that is not running
tells a stranger nothing about the node, so it is dropped rather than answered.

## Read the wire

Everything Matter puts on the wire above the message header is TLV.

```rust
use matter_kit::tlv::{Pretty, Tag, TlvReader, TlvWriter};

// Core Table 128's example: { 0 = 42, 1 = -17 }
let bytes = [0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18];
TlvReader::validate(&bytes)?;
assert_eq!(format!("{}", Pretty(&bytes)), "{0 = 42, 1 = -17}");

let mut buf = [0u8; 32];
let mut w = TlvWriter::new(&mut buf);
w.start_structure(Tag::Anonymous)?;
w.signed(Tag::Context(0), 42)?;
w.signed(Tag::Context(1), -17)?;
w.end_container()?;
assert_eq!(w.finish()?, &bytes);
```

The writer refuses to produce invalid TLV: an anonymous member of a structure, a tagged
member of an array, or an unbalanced container are errors at the call rather than bytes a
peer has to reject.

## Run a real device

```sh
cargo run --example light --features std
```

A commissionable node on real sockets: UDP 5540 for Matter, mDNS 5353 so a commissioner can
find it, PASE from a printed passcode, and the commissioning clusters over the session it
produces. It prints what to point at it:

```text
chip-tool pairing onnetwork 1 20202021
```

`MATTER_IFINDEX` chooses the interface to advertise on. It defaults to loopback, which is
enough to see the node from the same machine and not enough to be found from another —
`ip link` or `ifconfig` gives the real index.

It is a real `On/Off Light`: On/Off with the Lighting feature on endpoint 1, plus the Identify,
Groups and Scenes Management clusters that device type also requires, and a `Descriptor` on
each of its two endpoints.

`examples/light.rs` is worth reading as well as running: it is the whole assembly in one file
with no framework, and it is the shortest answer to "what do I have to write myself?".

## Run the simulated examples

```sh
cargo run --example commission --features std        # a full PASE exchange, then a wrong passcode
cargo run --example reliable_exchange --features std # MRP over a lossy simulated link
cargo run --example bridge --features std            # one node presenting devices it does not contain
```

The first two run against an in-process network with a virtual clock, so neither touches a
socket and neither waits for a timer. `bridge` has no network at all: it builds a four-endpoint
node — Root Node, Aggregator, and two bridged lights — and reads it the way a commissioner
would, which is the part that is new. See [Clusters and conformance](@/docs/clusters.md#a-bridge).

## Write a controller

The other half of Matter: something that decides what to ask. `ca` issues the fabric's
certificates, `commissioning::commissioner` drives §5.5's flow, and `im::client` watches what it
commissioned — see [Controllers](@/docs/controller.md). `tests/commissioner.rs` is the shortest
worked example, because it runs this crate's commissioner against this crate's device end to
end.

## Build for a device

```sh
cargo build                                       # no_std, no alloc — the default
cargo build --target thumbv7em-none-eabihf        # Cortex-M4F
cargo build --target riscv32imac-unknown-none-elf
```

## Next

- [Matter in ten minutes](@/docs/matter-in-ten-minutes.md) if the vocabulary above was new.
- [Messaging](@/docs/messaging.md) for how a datagram finds its session and exchange.
- [The data model](@/docs/data-model.md) for what `serve` actually enforces.
- [Testing](@/docs/testing.md) for the simulated network.
