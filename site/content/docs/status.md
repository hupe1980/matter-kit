+++
title = "Status"
description = "What is built in matter-kit and what is not, layer by layer, mapped to the sections of Matter 1.6 that define it."
weight = 15
+++

**Under construction and pre-1.0.** A device can be commissioned into a fabric end to end —
over IPv6, Bluetooth LE, Wi-Fi PAF or NFC — answer Reads, Writes and Invokes against a `const`
data model, hold subscriptions, record **and report** events, take part in groupcast, and move a firmware
image over TCP. What is missing is most of the application clusters' behaviour.

✅ built and tested · 📐 designed, not written

## Transport and secure channel

| Layer | Specification | State |
|---|---|---|
| TLV wire format | Core Appendix A | ✅ |
| Message frame, counters, replay | Core §4.4, §4.6 | ✅ |
| Message security and privacy | Core §4.8, §4.9 | ✅ |
| Exchanges, Message Reliability Protocol | Core §4.10, §4.12 | ✅ |
| Cryptosuite, SPAKE2+, key custody | Core ch. 3 | ✅ |
| PASE, StatusReport | Core §4.11, §4.14.1 | ✅ |
| CASE, with resumption | Core §4.14.2 | ✅ |
| Secure sessions | Core §4.13 | ✅ |
| Session eviction, and CloseSession in both directions | Core §4.11.1.1, §4.11.1.4 | ✅ |
| Session parameters, all nine fields | Core §4.13.1 | ✅ |
| BTP: segmentation, receive window, keep-alive | Core §4.19 | ✅ |
| BLE GATT service, commissionable advertisement | Core §4.19.4.2, §5.4.2.5 | ✅ |
| TCP transport: stream framing, no MRP, large payloads | Core §4.5, §4.15 | ✅ |
| BDX: negotiation, block ordering, synchronous transfers | Core §11.22 | ✅ |
| Groupcast: keys, sessions, the peer table | Core §4.16, §4.17 | ✅ |
| Message Counter Synchronization Protocol | Core §4.18 | ✅ |
| PAFTP over Wi-Fi Public Action Frames | Core §4.20 | ✅ |
| NTL: Matter over NFC | Core §4.21 | ✅ |

## Credentials and commissioning

| Layer | Specification | State |
|---|---|---|
| Onboarding payload (QR, manual code) | Core §5.1 | ✅ |
| Fabrics and derived identifiers | Core §4.3.2.2, §4.17.2 | ✅ |
| DER, CMS and PKCS#10 | RFC 5280, 5652, 2986 | ✅ |
| Operational certificates, X.509, chains | Core §6.1, §6.4.5, §6.5 | ✅ |
| Attestation: DAC chain, CD, NOCSR | Core §6.2, §6.3, §6.4.6 | ✅ |
| The fail-safe | Core §11.10.7.2 | ✅ |
| Descriptor, Basic Information, General Commissioning | Core §9.5, §11.1, §11.10 | ✅ |
| Operational Credentials | Core §11.18, §6.4.10 | ✅ |
| Network Commissioning | Core §11.9 | ✅ |
| General Diagnostics, Software Diagnostics | Core §11.12, §11.13 | ✅ |
| Ethernet, Wi-Fi and Thread Network Diagnostics | Core §11.14–11.16 | ✅ |
| Administrator Commissioning | Core §11.19 | ✅ |
| Network Recovery | Core §5.9, §11.10 | ✅ |
| Joint Fabric: the CATs, cross-signing, the datastore | Core ch. 12, §11.24, §11.25 | ✅ |
| Revocation sets, distributed compliance ledger | Core §6.2.4 | 📐 |

## Data and interaction models

| Layer | Specification | State |
|---|---|---|
| Interaction model encoding | Core §8.10, ch. 10 | ✅ |
| Data model, wildcard expansion | Core §7.6, §7.10–7.13, §8.2.1.6 | ✅ |
| Identifier ranges (MEI) for clusters, device types, attributes | Core §7.21.2 | ✅ |
| Read, Write, Invoke processing | Core §8.4.3.2, §8.7.3.2, §8.8.2.3 | ✅ |
| Subscriptions, reporting engine | Core §8.5, §8.6 | ✅ |
| Event store, event reports | Core §7.14, §10.6.9 | ✅ |
| Timed transaction window | Core §8.7.4, §8.8.2.3 | ✅ |
| Chunked reports, oversized-list splitting | Core §10.2.3, §10.6.4.3.1 | ✅ |
| List writes: replace versus append | Core §10.6.4.3.1, §8.7.3.3 | ✅ |
| Access control algorithm, CASE Authenticated Tags | Core §6.6 | ✅ |
| Access Control cluster | Core §9.10 | ✅ |
| Message processing: sessions, exchanges, MRP composed | Core §4.7 | ✅ |
| Interaction model client: chunk reassembly | Core §10.2.3 | ✅ |
| Atomic writes | Core §7.15 | ✅ |
| Binding, Fixed Label, User Label | Core §9.6, §9.8, §9.9 | ✅ |
| Check-In Protocol | Core §4.22 | ✅ |
| ICD Management cluster | Core §9.16 | ✅ |
| Subscription persistence across reboot | Core §8.5 | ✅ |
| Generated cluster library: ids, features, enums, conformance | Application Cluster, Device Library | ✅ |
| Conformance engine, descriptor validation, derived descriptors | Core §7.3 | ✅ |
| Device-type validation | Device Library §9.2 | ✅ |
| On/Off, with its state machine | Application Cluster §1.5 | ✅ |
| Identify, Groups, Scenes Management, Level Control | Application Cluster §1.2–§1.6 | ✅ |
| Mode Base, once, for every cluster derived from it | Application Cluster §1.10 | ✅ |
| Device Energy Management, Energy EVSE, Water Heater Management | Application Cluster §9.2, §9.3, §9.5 | ✅ |
| Electrical Power and Energy Measurement, Power Topology | Application Cluster §2.12–§2.14 | ✅ |
| Multi-endpoint nodes: routing, `PartsList`, bridges | Core §9.2, §9.12 | ✅ |
| Bridged Device Basic Information | Core §9.13 | ✅ |
| TLS Certificate Management, TLS Client Management | Core §14.4, §14.5 | ✅ |
| Group Key Management | Core §11.2 | ✅ |
| Groupcast cluster (provisional) | Core §11.27 | ✅ |
| Thermostat suggestions | Application Cluster §4.3.7 | ✅ |
| Generated `ToTlv`/`FromTlv` structures and command payloads | Application Cluster | ✅ |
| The remaining clusters' behaviour | Application Cluster | 📐 |
| Endpoints added and removed while the node runs | Core §9.2 | 📐 |

## Controllers

| Layer | Specification | State |
|---|---|---|
| The fabric's certificate authority: RCAC, ICAC, NOC | Core §6.5 | ✅ |
| A development attestation chain: PAA, PAI, DAC | Core §6.2.2 | ✅ |
| The commissioner's side of the commissioning flow | Core §5.5, §6.2.3 | ✅ |
| Client subscriptions: intervals, keep-alives, liveness | Core §8.5 | ✅ |
| Fabric Synchronization's Commissioner Control | Core §11.26 | ✅ |
| OTA Software Update Provider | Core §11.20.6 | ✅ |
| OTA Software Update Requestor | Core §11.20.7 | ✅ |
| Multi-threaded controllers (`sync-mutex`) | — | ✅ |
| Device attestation revocation sets, the DCL | Core §6.2.4 | 📐 |

## Discovery and platform

| Layer | Specification | State |
|---|---|---|
| DNS-SD records, TXT keys, mDNS responder | Core §4.3 | ✅ |
| mDNS probing, announcing, conflict resolution, rate limits | RFC 6762 §6, §8, §9 | ✅ |
| Platform seams, simulator, `std` backends | — | ✅ |
| Compile-time sizing | Core §2.11 | ✅ |
| Operating-system mDNS backends, Thread SRP client | Core §4.3 | 📐 |
| ICD sleep scheduling and radio integration | Core §9.15 | 📐 |
| Per-chip BLE, Wi-Fi and Thread drivers | — | 📐 |

## Verification

A light linked for an nRF52840 occupies **<!-- stats:flash-kib -->88<!-- /stats --> KiB of flash and <!-- stats:ram-kib -->39<!-- /stats --> KiB of RAM** — `.text` 85 744,
`.rodata` 4 516, `.bss` 40 576 — measured by `./footprint/run.sh`, which builds the image,
reads the sections out of it and writes them where `cargo xtask stats` can check this page
against them. No radio is in that image.

1823 tests, <!-- stats:fuzz-targets -->27<!-- /stats --> fuzz targets clean, builds for `thumbv7em-none-eabihf` and
`riscv32imac-unknown-none-elf`, and a full feature powerset. See
[Testing](@/docs/testing.md) for what each of those actually checks.

Separately from all of it, `interop/chip/run.sh` has the CHIP SDK's own `chip-tool`
commission the `light` example in a container, with device attestation verified rather than
bypassed. It is the only check here with somebody else's implementation on the other end, and
it is the one that has found what the rest could not.
