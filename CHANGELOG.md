# Changelog

Notable changes to the published crate, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

`matter-kit` is `0.x`, so `0.y` is the compatibility unit: a breaking change raises the minor.
[The stability policy](https://hupe1980.github.io/matter-kit/docs/stability/) has the rest, and
`cargo-semver-checks` enforces it in CI.

## [0.2.0] — unreleased

Rules that name "the node" rather than any one table — and had therefore been left to the
application — moved into the library. That is what makes this release breaking.

### Added

- `sc::Channel` — the secure channel as a type. It owns both handshakes, applies Core §5.5's
  admission rules by construction (one handshake at a time), installs the session each produces
  and keeps the attestation challenge PASE comes with.
- `im::Lifecycle` and `ClusterHandler::on_lifecycle`, which has a default. Fabric removal,
  fail-safe expiry and commissioning completion now reach every cluster in a dispatch tuple.
- `Messaging::install_session`, `Messaging::close_session`, `Messaging::remove_fabric`, and
  `messaging::Evicted` — the `CloseSession` a node owes the peer it evicted.
- `clusters::wi_fi_network_diagnostics` (Core §11.15) and `clusters::thread_network_diagnostics`
  (§11.14), over `WiFiDriver` and `ThreadDriver`. Neither needs a radio to compile or to test.
- `sc::case::accept_sigma1`, `CaseResponder::accept_sigma3` and `Sigma2Randomness`: CASE now
  resolves the fabric a Sigma1 names and validates Sigma3 against that fabric's root.

### Changed

- **Breaking.** `messaging::Received` is `#[non_exhaustive]` and gained `Group` and
  `SessionClosed`. A `match` over it needs a catch-all arm.
- **Breaking.** Under `sync-mutex`, `sync::Shared` is backed by `RwLock` rather than `Mutex`,
  and `sync::Ref` / `sync::RefMut` are the matching guards. Two shared borrows can be live at
  once, which is what the single-threaded build always did.
- `clusters::Reading` moved out of `clusters::ethernet_network_diagnostics`, which re-exports
  it. Wi-Fi and Thread diagnostics share the vocabulary.

### Removed

- **Breaking.** `Config::ENDPOINTS`, `EVENT_BUF_BYTES`, `PACKET_BUFS`, `BTP_SESSIONS`,
  `KV_BLOB_MAX`, `RESOLVE_CANDIDATES` and `REPLAY_WINDOW`. Nothing read them, so they sized
  nothing; setting one had no effect.
- **Breaking.** `dm::Conformance::is_permitted` and `dm::Conformance::is_required`. Both
  answered `false` for `Described`, which reads as "forbidden" — a guess in the direction the
  verdict exists to refuse. Match on the `Conformance` variant instead.
- **Breaking.** `ExchangeTable::find_for_message_mut`, `Mrp::on_piggyback` and
  `im::Server::prime_chunk`, none of which had a caller.

### Fixed

- `RemoveFabric` reached two of the fourteen tables scoped to a fabric. Fabric indices are
  reused, so a surviving entry — an access-control entry, among others — was inherited by the
  next holder of that index.
- A full session table answered `NoSpace` instead of evicting (§4.11.1.1), so a node could be
  commissioned `Config::SESSIONS` times and never again.
- A session's exchanges outlived it, and a received `CloseSession` was ignored (§4.13.3.1,
  §4.11.1.4).
- An `InvokeRequest` that arrived by groupcast was answered rather than met with silence
  (§8.8.2.3).

## [0.1.0] — 2026-09-15

First release. Matter 1.6 from TLV up: the message layer with its counters, security and
privacy; exchanges and MRP; UDP, TCP, BLE/BTP, PAFTP and NFC/NTL; the secure channel with
SPAKE2+, PASE and CASE; Matter and X.509 certificates, attestation and a certificate authority;
commissioning and the fail-safe; the interaction model with subscriptions, events and chunking;
access control; DNS-SD discovery; BDX and OTA; groupcast; and the cluster library generated from
the CSA data model with the conformance expression for every element.

[0.2.0]: https://github.com/hupe1980/matter-kit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hupe1980/matter-kit/releases/tag/v0.1.0
