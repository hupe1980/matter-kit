# matter-kit

A [Matter](https://csa-iot.org/all-solutions/matter/) implementation in Rust: one crate,
`no_std`, no allocation, and no runtime of its own.

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Docs](https://img.shields.io/badge/docs-hupe1980.github.io%2Fmatter--kit-0b6bcb.svg)](https://hupe1980.github.io/matter-kit)

> 🚧 **Status: under construction.** A device can be commissioned into a fabric end to end —
> over IPv6, Bluetooth LE, Wi-Fi PAF or NFC — answer Reads, Writes and Invokes, hold
> subscriptions, enforce access control, take part in groupcast, and move a firmware image over
> TCP. The CHIP SDK's own `chip-tool` commissions the `light` example through the whole of
> §5.5 with attestation verified, and **eleven of the CSA Test Harness's certification cases
> pass** against it. The 1.6 cluster library is generated from the CSA data model with its
> conformance rules. What is missing is most of the application clusters' *behaviour*. See
> [Status](#status).

## 🏠 What Matter is, and why this exists

Matter is the CSA's smart-home standard — the protocol behind Apple Home, Google Home,
Alexa and SmartThings, running over Wi-Fi, Ethernet and Thread. This crate targets
**specification 1.6** (approved 2026-06-16).

The reference implementation is C++. There is a good Rust one,
[`rs-matter`](https://github.com/project-chip/rs-matter). This is a second Rust one, built
around four decisions that are hard to retrofit:

**📦 One crate.** Not a family to keep in version step. Everything optional is a Cargo
feature. The code generator is repository tooling (`cargo xtask`), not a dependency.

**📖 The cluster library is generated, and it knows its own rules.** All 135 clusters and 91
device types come from the CSA's machine-readable data model — the same files the Test Harness
reads — with the **conformance expression** for every element. So the crate can tell you that
`StartUpOnOff` is mandatory with the Lighting feature and forbidden without it, check your
device's descriptors against that, or simply build them for you:

```rust,ignore
use matter_kit::clusters::generated::on_off;
use matter_kit::dm::spec::{Conforming, Optional};

let light = Conforming::<8, 8, 4, 4>::new(
    &on_off::CLUSTER, on_off::feature::LIGHTING, &Optional::NONE,
)?;
// Five attributes and six commands, none of them written down anywhere.
```

**📏 Sizing is a type, not a build flag.** Every table — fabrics, sessions, exchanges,
subscriptions, access-control entries — is a fixed-capacity array whose length comes from a
`Config` trait. The specification's minima are `const` assertions, so a node that could not
pass certification does not compile:

```rust
use matter_kit::Config;

struct Light;
impl Config for Light {
    const FABRICS: usize = 5;      // Core §11.18.5.3 constrains this to 5..=254
    const SESSIONS: usize = 16;    // Core §4.14.2.8 wants ≥ 3 per fabric
}
```

Cargo features cannot do this: they are global and additive, so two crates in one binary
that want different sizes silently get the union, and nothing checks the result against the
specification.

**⚙️ No runtime is chosen for you.** The crate is `async` over `core::future` and reaches the
outside world through small traits — sockets, timers, randomness, storage. Embassy and
Tokio appear in examples, never in the dependency tree.

**🛡️ Nothing panics on network input.** `unwrap`, `expect`, `panic!` and slice indexing are
denied crate-wide; every parser returns an error. Resource exhaustion is a value, so a
device that runs out of exchanges answers `BUSY` rather than aborting.

<a id="status"></a>

## 📊 Status

Every layer below is built and tested against the sections that define it. The full
breakdown — sixty-odd rows, each citing its specification section — is on the
[status page](https://hupe1980.github.io/matter-kit/docs/status/).

| Area | What is built | 1.6 |
|---|---|---|
| Wire and message layer | TLV, the message frame, counters and the replay window, security and privacy, exchanges and MRP | Appendix A, §4.4–§4.12 |
| Transports | UDP, TCP with §4.5 stream framing, BLE/BTP, PAFTP over Wi-Fi Public Action Frames, NFC/NTL | §4.5, §4.15, §4.19–§4.21 |
| Secure channel | the ch. 3 cryptosuite, SPAKE2+, PASE, CASE with resumption, secure sessions, StatusReport | ch. 3, §4.11–§4.14 |
| Groupcast | operational group keys and epoch rotation, group sessions, the peer table, MCSP | §4.16–§4.18 |
| Credentials | Matter TLV certificates and exact X.509 regeneration, the DAC/PAI/PAA chain, the Certification Declaration, NOCSR, a certificate authority | ch. 6 |
| Commissioning | onboarding payloads, the fail-safe, both sides of §5.5's flow and its rules on admitting a PASE request, Network Recovery, Joint Fabric and Fabric Synchronization | ch. 5, ch. 12 |
| Interaction model | all ten messages and sixteen information blocks, Read/Write/Invoke, subscriptions and the reporting engine, events, atomic writes, cluster data versions, chunking both ways | ch. 7, ch. 8, ch. 10 |
| Access control | §6.6.6's algorithm clause by clause — CATs, fabric isolation, the two-stage check | §6.6 |
| Exchanges | the table, MRP's backoff curve, §4.10.3.1's protocol registration and §4.10.5.2's three rules for an unsolicited message — so a stranger cannot fill a fixed-capacity table and end session establishment | §4.10, §4.12 |
| Discovery | DNS-SD records and TXT keys, a responder, RFC 6762's probe/announce/conflict schedule | §4.3 |
| Large data | BDX and both OTA cluster halves, TLS Certificate and Client Management | §11.20, §11.22, ch. 14 |
| Clusters | the generated library with its conformance and TLV types, and thirty-four hand-written cluster modules — On/Off, Level Control, Groups, Scenes, Mode Base, the energy clusters, the diagnostics clusters including §11.16's Ethernet Network Diagnostics, the commissioning clusters | Application Cluster, Device Library |

**Not yet written:** most of the application clusters' *behaviour* behind the generated
descriptors, device attestation revocation and the DCL, the per-chip radio drivers, and the
typed client layer over the generated types.

1745 tests; twenty-seven fuzz targets clean; builds for `thumbv7em-none-eabihf` and
`riscv32imac-unknown-none-elf`; the feature powerset checked in full.

And one check worth more than the rest: `./interop/chip/run.sh` has the CHIP SDK's own
`chip-tool` — the controller every certified Matter product is paired by — commission
`examples/light` through the whole of Core §5.5, ending `Device commissioning completed with
success`. PASE, device attestation **verified rather than bypassed**, the CSR and `AddNOC`,
then mDNS resolution, CASE on the identity just issued, and `CommissioningComplete` over the
operational session. Both ends in containers on an IPv6 network — no hardware, no radio, no
C++ toolchain.

The same container carries the CSA Test Harness's own **603 certification cases**, and
`./interop/chip/python.sh TC_CGEN_2_1` runs them against the example — each one commissioning
the device itself before its first assertion. **Eleven pass**: `TC_CGEN_2_1`, `TC_OPCREDS_3_1`,
`TC_ACL_2_2`, `TC_ACL_2_4`, `TC_ACL_2_6`, `TC_ACL_2_10`, `TC_IDM_1_2`, `TC_IDM_1_4`,
`TC_IDM_2_2`, `TC_IDM_2_3` and `TC_IDM_4_2` — `TC_OPCREDS_3_1` across all eighty-five of its
steps, commissioning a second and a third fabric, rolling one back and reconnecting over PASE.

## 🔌 The wire format

Every byte Matter puts on the wire above the message header is TLV (Core Appendix A).

```rust
use matter_kit::tlv::{Pretty, Tag, TlvReader, TlvWriter};

// Core Table 128's example: { 0 = 42, 1 = -17 }
let bytes = [0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18];
TlvReader::validate(&bytes)?;
assert_eq!(format!("{}", Pretty(&bytes)), "{0 = 42, 1 = -17}");

// The writer refuses to produce invalid TLV: an anonymous member of a structure, a
// tagged member of an array or an unbalanced container are errors at the call.
let mut buf = [0u8; 32];
let mut w = TlvWriter::new(&mut buf);
w.start_structure(Tag::Anonymous)?;
w.signed(Tag::Context(0), 42)?;
w.signed(Tag::Context(1), -17)?;
w.end_container()?;
assert_eq!(w.finish()?, &bytes);
# Ok::<(), matter_kit::Error>(())
```

## 🧩 Serving a node

A device's shape is `const` data — endpoints holding cluster descriptors, in flash, costing
no RAM. A `Server` walks it and one `ClusterHandler` supplies the behaviour, with `write`
and `invoke` defaulting to refusal. A `Dispatcher` turns an arriving message into the reply,
applying the rules §8.7.2.3 and §8.8.2.3 put between an opcode and any work — the Timed
window, and the `MaxPathsPerInvoke` bound on how many commands one message may ask for.

```rust,ignore
use matter_kit::dm::{ClusterDescriptor, DataVersions, Endpoint, Node};
use matter_kit::im::{Dispatcher, ReadCursor, Request, Served, Server};

const EP1: &[ClusterDescriptor] = &[ON_OFF, LEVEL_CONTROL];
const ENDPOINTS: &[Endpoint] = &[Endpoint::new(1, EP1)];

// §7.10.3's cluster data versions. A report without one is an attribute the CHIP SDK's
// cache discards, so a node that omits them is conformant and uncommissionable.
let versions = DataVersions::<16>::new(rng.next_u32()?);
let server = Server::new(Node::new(ENDPOINTS), &acl, &clusters, 24)
    .with_data_versions(&versions);
let mut dispatcher: Dispatcher<4> = Dispatcher::new(product.max_paths_per_invoke);
let mut cursor = ReadCursor::START;

let request = Request::new(opcode, payload, session, exchange);
match dispatcher.dispatch(&server, request, &ctx, &mut cursor, &mut scratch, &mut buf)? {
    Served::Reply { opcode, len, more_chunks } => send(opcode, &buf[..len]),
    Served::Subscribe(request) => subscriptions.accept(request)?,
    Served::Silent => {}                       // suppressed, or groupcast
    Served::Unhandled { opcode } => { /* a response on an exchange this node opened */ }
}
```

## ⏱️ Testing a protocol that is mostly timers

Half of Matter is deadlines: MRP backs off over four seconds, a fail-safe expires, an
intermittently connected device sleeps for an hour. So time is a parameter, and
`platform::sim` is a supported platform — an in-process IPv6 network with a virtual clock
that jumps to the next deadline, and loss, duplication and jitter you set per test.

```rust
use matter_kit::platform::sim::{Impairment, SimNet, block_on};
use matter_kit::platform::{Timer, Duration};

let net = SimNet::new(42);              // seeded: same run, same result, every time
net.impair(Impairment::lossy(30));      // drop three datagrams in ten

let start = Timer::now(&net);
block_on(&net, async {
    net.sleep(Duration::from_secs(3600)).await;   // returns immediately
});
// An hour of virtual time has passed and no wall-clock time has.
assert_eq!(
    Timer::now(&net).saturating_duration_since(start),
    Duration::from_secs(3600)
);
```

## 🔨 Building

```sh
cargo test --features std          # the suite
cargo build                        # no_std, no alloc — the default
cargo build --target thumbv7em-none-eabihf
cargo +nightly fuzz run tlv        # needs cargo-fuzz; twenty-seven targets in fuzz/
```

### Run a device

```sh
cargo run --example light --features std
```

A commissionable node on real sockets: UDP 5540 for Matter, mDNS 5353 so a commissioner can
find it, PASE from a printed passcode, and the commissioning clusters over the session it
produces. It prints what to point at it:

```text
chip-tool pairing onnetwork 1 20202021
```

`MATTER_IFINDEX` picks the interface to advertise on — it defaults to loopback, which is
enough to see the node locally and not enough to be found from another machine.

Other examples: `--example commission` runs a full PASE exchange and then a wrong passcode;
`--example bridge` presents devices the node does not contain; `--example reliable_exchange`
drives MRP over a lossy simulated link.

## 📚 Documentation

- **[Guides and reference](https://hupe1980.github.io/matter-kit)** — what Matter is, how to
  serve a node, commissioning, discovery, and how a protocol made of timers gets tested.
- **[API reference](https://docs.rs/matter-kit)** — every module documents the rules it
  implements against the section that states them.

## 📖 Specification references

Claims in the source cite their section: `Core §4.12` is the Matter 1.6 Core
Specification, `App §1.5` the Application Cluster Specification, `DL §4.2` the Device
Library. The documents are free from
[csa-iot.org](https://csa-iot.org/developer-resource/specifications-download-request/) but
are **not redistributable**, so they are not in this repository.

<a id="license"></a>

## ⚖️ License

Dual-licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Apache-2.0 compatibility is deliberate: it lets code and test vectors flow
to and from `rs-matter` and the CHIP SDK.

---

Matter® is a registered trademark of the Connectivity Standards Alliance. This project is
not affiliated with or endorsed by the Alliance, and nothing here is a certified
implementation.
