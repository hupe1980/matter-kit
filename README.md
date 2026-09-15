# matter-kit

A [Matter](https://csa-iot.org/all-solutions/matter/) implementation in Rust: one crate,
`no_std`, no allocation, and no runtime of its own.

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **Status: under construction.** A commissioner and a device can now turn a printed
> passcode into an encrypted session — the whole of PASE, with SPAKE2+ checked against the
> specification's own published test vectors. There is no data model and no clusters yet,
> so there is nothing to *say* over that session, and no ecosystem can commission it. See
> [Status](#status) for exactly what exists.

## What Matter is, and why this exists

Matter is the CSA's smart-home standard — the protocol behind Apple Home, Google Home,
Alexa and SmartThings, running over Wi-Fi, Ethernet and Thread. This crate targets
**specification 1.6** (approved 2026-06-16).

The reference implementation is C++. There is a good Rust one,
[`rs-matter`](https://github.com/project-chip/rs-matter). This is a second Rust one, built
around four decisions that are hard to retrofit:

**One crate.** Not a family to keep in version step. Everything optional is a Cargo
feature; the code generator is a feature-gated binary of the same package.

**Sizing is a type, not a build flag.** Every table — fabrics, sessions, exchanges,
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

**No runtime is chosen for you.** The crate is `async` over `core::future` and reaches the
outside world through small traits — sockets, timers, randomness, storage. Embassy and
Tokio appear in examples, never in the dependency tree.

**Nothing panics on network input.** `unwrap`, `expect`, `panic!` and slice indexing are
denied crate-wide; every parser returns an error. Resource exhaustion is a value, so a
device that runs out of exchanges answers `BUSY` rather than aborting.

## Status

| Layer | Module | Specification | State |
|---|---|---|---|
| Wire format | `tlv` | Core Appendix A | ✅ |
| Message frame, counters, replay | `msg` | Core §4.4, §4.6 | ✅ |
| Message security and privacy | `msg::protect` | Core §4.8, §4.9 | ✅ |
| Exchanges, MRP | `exchange` | Core §4.10, §4.12 | ✅ |
| Cryptosuite, SPAKE2+, key custody | `crypto` | Core ch. 3 | ✅ |
| PASE, StatusReport | `sc` | Core §4.11, §4.14.1 | ✅ |
| Secure sessions | `session` | Core §4.13 | ✅ |
| Platform seams, simulator, `std` | `platform` | — | ✅ |
| Sizing | `Config` | Core §2.11 | ✅ |
| CASE | `sc::case` | Core §4.14.2 | 📐 |
| Commissioning, certificates, fabrics | `commissioning`, `cert`, `fabric` | Core ch. 5–6 | 📐 |
| Data and interaction models | `dm`, `im` | Core ch. 7–10 | 📐 |
| Clusters, device types | `clusters` | Application Cluster, Device Library | 📐 |

✅ built and tested · 📐 designed, not written

249 tests; four fuzz targets clean; builds for `thumbv7em-none-eabihf` and
`riscv32imac-unknown-none-elf`.

## Reading a payload

Every byte Matter puts on the wire above the message header is TLV.

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
```

## Commissioning from a printed passcode

The first thing any Matter device does is turn the eight-digit code on its label into an
encrypted session, using SPAKE2+ so that the passcode never crosses the wire and an
attacker gets exactly one guess per exchange.

```rust
use matter_kit::crypto::Spake2pVerifierData;
use matter_kit::sc::{PaseInitiator, PaseResponder, PbkdfParameters, ResponderConfig};
use matter_kit::msg::SessionId;

// What a factory burns in. The device stores (w0, L) and *not* the passcode: reading its
// flash does not tell you what is printed on the label.
let parameters = PbkdfParameters::new(1_000, b"SPAKE2P Key Salt")?;
let verifier =
    Spake2pVerifierData::from_passcode(20_202_021, &parameters.salt, parameters.iterations)?;

let mut device = PaseResponder::new(
    ResponderConfig { verifier, parameters: parameters.clone(), session_params: None },
    SessionId(1),
);
let mut commissioner = PaseInitiator::new(20_202_021, SessionId(2), Some(parameters), None);

// …five messages later, both ends hold I2RKey, R2IKey and an AttestationChallenge.
```

`cargo run --example commission --features std` runs the whole exchange and then tries a
wrong passcode, which fails at the confirmation step and tells the attacker nothing else.

The SPAKE2+ implementation reproduces all four of the specification's published test
vectors byte for byte (`tests/spake2p_vectors.rs`) — including the three with non-empty
identities, which Matter never uses but which exercise the transcript's length prefixes.

## Testing a protocol that is mostly timers

Half of Matter is deadlines: MRP backs off over four seconds, a fail-safe expires, an
intermittently-connected device sleeps for an hour. Testing that against a real clock means
waiting, which means those paths get tested rarely and flakily.

So time is a parameter, and `platform::sim` is a supported platform: an in-process IPv6
network with a virtual clock that jumps to the next deadline instead of waiting for it, and
loss, duplication and jitter you set per test.

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

`tests/mrp_over_sim.rs` drives the whole reliability layer through that: a lost message
retransmitted until it lands, a duplicate acknowledged but delivered once, a replay
rejected by the counter window, a dead peer abandoned after exactly five transmissions.
`tests/pase_over_sim.rs` does the same for commissioning, including the cases that matter
most — a wrong passcode, a forged confirmation, and keys used in the wrong direction.

## Building

```sh
cargo test --features std          # the suite
cargo build                        # no_std, no alloc — the default
cargo build --target thumbv7em-none-eabihf
cargo +nightly fuzz run tlv        # needs cargo-fuzz; also tlv_roundtrip, message, pase
```

## Specification references

Claims in the source cite their section: `Core §4.12` is the Matter 1.6 Core
Specification, `App §1.5` the Application Cluster Specification, `DL §4.2` the Device
Library. The documents are free from
[csa-iot.org](https://csa-iot.org/developer-resource/specifications-download-request/) but
are **not redistributable**, so they are not in this repository.

## License

Dual-licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Apache-2.0 compatibility is deliberate: it lets code and test vectors flow
to and from `rs-matter` and the CHIP SDK.

---

Matter® is a registered trademark of the Connectivity Standards Alliance. This project is
not affiliated with or endorsed by the Alliance, and nothing here is a certified
implementation.
