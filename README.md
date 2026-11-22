# matter-kit

A [Matter](https://csa-iot.org/all-solutions/matter/) 1.6 implementation in Rust: one crate,
`no_std`, no allocation, no runtime of its own.

[![Crates.io](https://img.shields.io/crates/v/matter-kit.svg)](https://crates.io/crates/matter-kit)
[![docs.rs](https://img.shields.io/docsrs/matter-kit)](https://docs.rs/matter-kit)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Docs](https://img.shields.io/badge/docs-hupe1980.github.io%2Fmatter--kit-0b6bcb.svg)](https://hupe1980.github.io/matter-kit)

> 🚧 **Pre-1.0.** A device commissions end to end over IPv6, BLE, Wi-Fi PAF or NFC, answers
> reads, writes, invokes and subscriptions, enforces access control and takes part in groupcast.
> The CHIP SDK's `chip-tool` commissions the `light` example with attestation verified, and
> eleven CSA Test Harness cases pass against it. Most application clusters' *behaviour* is not
> written yet. See [Status](#status).

```sh
cargo add matter-kit                    # no_std, no alloc, UDP + MRP
cargo add matter-kit --features std     # sockets, mDNS, a file-backed key-value store
```

## 🏠 Why this crate

The reference implementation is C++; [`rs-matter`](https://github.com/project-chip/rs-matter) is
the other Rust one. This one is built around a few decisions that are hard to retrofit:

- **📦 One crate.** Everything optional is a Cargo feature. The code generator is repository
  tooling (`cargo xtask`), not a dependency.
- **🔁 The sequence is a type.** `node::Runtime` owns what every device must do in order —
  chunked reads per exchange, the four-message subscribe, one report in flight per
  subscriber, retransmission, closing finished exchanges, and what follows `AddNOC`,
  `RemoveFabric` and a lapsed fail-safe. Your code supplies the clusters and the sockets.
- **📖 The cluster library is generated with its rules.** All <!-- stats:clusters -->135<!-- /stats --> clusters and <!-- stats:device-types -->91<!-- /stats -->
  device types come from the CSA's machine-readable data model, conformance expressions
  included, so descriptors are derived rather than written.
- **📏 Capacities are checked against the specification at compile time.** Every table is a
  fixed-capacity array with a `const` assertion naming the rule it must satisfy. A node that
  could not keep its per-fabric promises does not build.
- **🛡️ Nothing panics on network input.** `unsafe` is forbidden; `unwrap`, `expect`, indexing,
  unchecked arithmetic and truncating casts are denied crate-wide. Every parser is fuzzed.
- **⚙️ No executor.** `async` over `core::future` and small platform traits — sockets, timer,
  randomness, storage. `platform::os` and the simulated `platform::sim` implement them.

A whole light for an nRF52840 links into **<!-- stats:flash-kib -->90<!-- /stats --> KiB of flash and <!-- stats:ram-kib -->39<!-- /stats --> KiB of RAM**
(`./footprint/run.sh`; no radio in the image).

## 🚀 A device

```sh
cargo run --example light --features std
chip-tool pairing onnetwork 1 20202021
```

[`examples/light.rs`](examples/light.rs) is the whole device: it declares the endpoints and
clusters, builds the attestation chain and PASE verifier, and hands everything to the runtime.

```rust,ignore
use matter_kit::node::{Device, Mdns, Runtime};

let device = Device {
    node, handler: &handler,
    credentials: &opcreds, commissioning: &general_commissioning,
    access_control: &acl_cluster, group_keys: &group_keys,
    events: &events, versions: &versions,
    verifier: &verifier, parameters: &parameters,
    memberships: Some(&memberships),
};
let mut runtime = Runtime::<DefaultConfig>::new(&rng)?;
block_on(runtime.run(&device, &udp, Mdns { socket: &mdns, group, interface }, &mut advertiser, &timer, |n| log(n)));
```

Without the driver the runtime is sans-I/O: `receive` a datagram, `poll` on time, send what
`transmit` hands out, sleep until `next_deadline`. `notice` reports what happened as values.

## 🧪 Testing a protocol made of timers

`platform::sim` is an in-process IPv6 network with a virtual clock and seeded loss,
duplication and jitter, so an hour of MRP backoff runs in milliseconds and the same seed gives
the same run.

```rust
use matter_kit::platform::sim::{Impairment, SimNet, block_on};
use matter_kit::platform::{Duration, Timer};

let net = SimNet::new(42);
net.impair(Impairment::lossy(30));
let start = Timer::now(&net);
block_on(&net, async { net.sleep(Duration::from_secs(3600)).await });
assert_eq!(Timer::now(&net).saturating_duration_since(start), Duration::from_secs(3600));
```

<a id="status"></a>

## 📊 Status

| Area | Built | 1.6 |
|---|---|---|
| Wire and message layer | TLV, message frame, counters, replay window, privacy, exchanges, MRP | App. A, §4.4–§4.12 |
| Transports | UDP, TCP, BLE/BTP, Wi-Fi PAFTP, NFC/NTL | §4.5, §4.15, §4.19–§4.21 |
| Secure channel | SPAKE2+, PASE, CASE, sessions, §5.5 admission (`sc::Channel`) | ch. 3, §4.11–§4.14, §5.5 |
| Node runtime | the interaction loop, cascades and commissioning follow-ups (`node::Runtime`) | §4.10, §8.5, §10.2.3, §11.10, §11.18 |
| Groupcast | group keys, group sessions, MCSP, the receive path | §4.16–§4.18 |
| Credentials | Matter certificates, DAC/PAI/PAA, Certification Declaration, NOCSR, a CA | ch. 6 |
| Commissioning | onboarding payloads, fail-safe, both sides of §5.5, Network Recovery, Joint Fabric | ch. 5, ch. 12 |
| Interaction model | all messages, Read/Write/Invoke, subscriptions, events, atomic writes, chunking | ch. 7, 8, 10 |
| Access control | §6.6.6 clause by clause, CATs, fabric isolation | §6.6 |
| Discovery | DNS-SD records, responder, probe/announce schedule, the advertisement set | §4.3 |
| Large data | BDX, OTA provider and requestor, TLS certificate management | §11.20, §11.22, ch. 14 |
| Clusters | the generated library and <!-- stats:cluster-behaviours -->36<!-- /stats --> hand-written cluster behaviours | App. Clusters, Device Library |

**Not yet written:** most application-cluster behaviour, attestation revocation and the DCL,
per-chip radio drivers, a typed client layer.

<!-- stats:test-files -->77<!-- /stats --> test files and <!-- stats:fuzz-targets -->27<!-- /stats --> fuzz targets; builds for `thumbv7em-none-eabihf` and
`riscv32imac-unknown-none-elf`; the feature powerset is checked in full. The tests that matter
most have something other than this crate on the other end: `./interop/chip/run.sh` has the
CHIP SDK's `chip-tool` commission `examples/light`, and `./interop/chip/python.sh` runs the CSA
Test Harness cases against it. The [status page](https://hupe1980.github.io/matter-kit/docs/status/)
lists every case.

## 🔨 Building

```sh
cargo test --features std
cargo build --target thumbv7em-none-eabihf
cargo +nightly fuzz run tlv
```

## 📚 Documentation

- **[Guides](https://hupe1980.github.io/matter-kit)** — Matter in ten minutes, a first device,
  commissioning, discovery, testing.
- **[API reference](https://docs.rs/matter-kit)** — every module cites the sections it implements.
- **[Stability](https://hupe1980.github.io/matter-kit/docs/stability/)** and
  **[CHANGELOG.md](CHANGELOG.md)** — what a `0.x` release promises, and what moved.
- **[SECURITY.md](SECURITY.md)** — disclosure, guarantees and known limitations. Releases go out
  through crates.io Trusted Publishing with a CycloneDX SBOM.

Source comments cite the specification as `Core §4.12`, `App §1.5`, `DL §4.2` (Matter 1.6). The
documents are free from
[csa-iot.org](https://csa-iot.org/developer-resource/specifications-download-request/) and not
redistributable, so they are not in this repository.

<a id="license"></a>

## ⚖️ License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

---

Matter® is a registered trademark of the Connectivity Standards Alliance. This project is not
affiliated with or endorsed by the Alliance, and nothing here is a certified implementation.
