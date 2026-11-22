# Changelog

Notable changes to the published crate, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

`matter-kit` is `0.x`, so `0.y` is the compatibility unit: a breaking change raises the minor.
[The stability policy](https://hupe1980.github.io/matter-kit/docs/stability/) has the rest, and
`cargo-semver-checks` enforces it in CI.

## [0.4.0] — 2026-11-22

### Added

- `node::Runtime` — the interaction loop as a library type. It owns the messaging stack, the
  secure channel and the subscriptions, and keeps the sequence a device must: chunked reads per
  exchange, the four-message subscribe, one report in flight per subscription, retransmission,
  closing finished exchanges, cascades on session close, eviction and fabric removal, and the
  follow-ups to `AddNOC`, `CommissioningComplete` and a fail-safe rollback (including one that
  lapses with no command). Sans-I/O (`receive`, `poll`, `transmit`, `next_deadline`, `notice`)
  with `Runtime::run`, an `async` driver over `Udp` and `Timer`.
- `discovery::Advertiser` — the DNS-SD record set computed from fabrics and the commissioning
  window, with a random commissionable instance name.
- `OperationalCredentials::revert_update` and `commit_update`; `Messaging::is_awaiting_ack`.

### Fixed

- A fail-safe rollback after `UpdateNOC` now restores the previous NOC, ICAC, node id and key
  (§11.10.7.2.2 step 6). Previously the old key was destroyed at once.
- An exchange idle for exactly `EXCHANGE_IDLE_TIMEOUT` is reclaimed at the deadline
  `Messaging::wake_at` reports, so a loop woken at that deadline does not spin.
- A new Unsecured Session Context (§4.13.2.1) closes the previous one's exchanges. A second
  commissioner's first message could otherwise land on the first one's exchange and be refused.
- `platform::sim` no longer freezes virtual time on a datagram for a node that has stopped
  reading.
- The `log` and `defmt` features log every `node::Notice` at debug level; before, they enabled
  nothing.

### Changed

- **Breaking.** `UpdateNOC` keeps the replaced operational key until the fail-safe resolves;
  `CommissioningComplete` (through `Lifecycle`) destroys it. A device that does not route
  `Lifecycle` to `OperationalCredentials` keeps the old key until the next update.
- `examples/light` runs on `node::Runtime`: 519 lines, down from 2 235.

### Security

- `heapless` 0.9.4, `crypto-bigint` 0.7.11 and `ctutils` 0.4.8, for RUSTSEC-2026-0574 and -0575
  (unsound `heapless` APIs) and RUSTSEC-2026-0385 and -0387 (timing variability in constant-time
  operations).

### Migrating from 0.3

Replace a hand-written device loop with `node::Device` + `node::Runtime::run`. If you keep your
own loop, set `InteractionContext::on_session` on every interaction and take the attestation
challenge from the session (`SecureSession::keys`), not from `sc::Channel`.

## [0.3.0] — 2026-09-20

Three claims the crate made about itself turned out to be false, and are now enforced rather
than asserted: that a table's size is checked against the specification, that provisional
mechanisms are off by default, and that nothing hostile gets through a parser. None of the three
was found by a test — every test in this repository has matter-kit on both ends, and none of
these is visible from there.

### Capacity is declared once, and the specification checks it

`Config` carried fifteen constants, most naming a capacity it could not size: stable Rust cannot
write `heapless::Vec<T, { C::SESSIONS }>`, so the const generic parameter was always the real
length and the minima were asserted against the constant beside it. `Acl<DefaultConfig, 1, 1, 1>`
compiled while the crate asserted twenty entries, and three attributes reported numbers taken
from the wrong side of that gap.

- **Breaking.** `Config` now has eight constants, and every one is a *policy* the node
  advertises rather than a size: `FABRICS`, `SUBSCRIPTIONS_PER_FABRIC`, `ACL_ENTRIES_PER_FABRIC`,
  `GROUPS_PER_FABRIC`, `GROUP_KEYS_PER_FABRIC`, `ICD_CLIENTS_PER_FABRIC`, `READ_PATHS` and
  `ACL_AUXILIARY`. Removed:
  `SESSIONS`, `EXCHANGES_PER_SESSION`, `SUBSCRIPTIONS`, `SUB_PATHS`, `ACL_ENTRIES`,
  `ACL_SUBJECTS`, `ACL_TARGETS`, `GROUPS`, `GROUP_KEYS`, `MAX_TCP_MSG`. Each was a capacity, and
  a capacity now lives on the table that has it.
- **Breaking.** Every capacity-bearing type carries a `CHECK` associated const that its
  constructor instantiates, so a table too small to keep the node's promises is a build error
  naming the rule — `Acl`, `SessionTable`, `SubscriptionTable`, `FabricTable`, `GroupKeys`.
- Those types' const parameters now **default to the specification's own minima**, so
  `Acl<DefaultConfig>`, `SubscriptionTable<DefaultConfig>` and `GroupKeys<DefaultConfig>` are
  conformant with no numbers written at all.
- **Breaking.** `GroupKeys` is `GroupKeys<C, K, M>` and `GroupKeys::new()` takes no arguments;
  the per-fabric quotas it advertises are `Config`'s. `GroupKeyManagement` and `Groupcast` gained
  the same `C`.
- **Breaking.** `IcdManagement::new` and `with_stay_active` no longer take `clients_per_fabric`;
  §9.16.6.6's `ClientsSupportedPerFabric` is `Config::ICD_CLIENTS_PER_FABRIC`, and the
  registration table is checked against it.
- **Breaking.** `CapabilityMinima::from_config` is replaced by
  `CapabilityMinima::from_tables::<C, Sessions, Subs>()`. §11.1.4.4 says each field is "the
  **actual**" number the node supports, and only the table knows it.
- New `Capacity` and `SubscriptionCapacity` traits publish `TOTAL`, `PER_FABRIC` and `PATHS` from
  the table, which is where every attribute that states a capacity now reads it.

### The unsecured session had no context

§4.13.2.1 has an unsecured initiator "enclose" an Ephemeral Initiator Node ID as the Source Node
ID of every message. Nothing established one, so the commissioner's pre-key messages carried
neither a Source nor a Destination — which rule 1(c) tells a responder to discard. It was
invisible because the responder did not implement 1(c) either.

- **Breaking.** `Messaging::open` and `Messaging::open_to` refuse `SessionId::UNSECURED` with
  `InvalidState` unless a context exists. Use the new `Messaging::open_unsecured` and
  `Messaging::open_unsecured_to`, which open the exchange and establish the context together.
- **Fixed.** A received unsecured message that matches no context and carries no Source Node ID
  is discarded (§4.13.2.1 rule 1c) instead of being routed.
- New `NodeId::ephemeral`, which folds a caller's randomness into the Operational Node ID range
  §4.13.2.1 draws the id from.

### Provisional means off, and the validator says so

The `provisional` feature gated only the modules whose whole subject is provisional, so every
provisional element inside an otherwise certifiable cluster was served on a default build.

- **Breaking.** `dm::spec::Defect` gained `Provisional(Element)`; it is `#[non_exhaustive]` in
  effect for any exhaustive `match`. `Cluster::validate` reports it for a `P` element furnished
  by a build without the `provisional` feature.
- **Breaking.** `general_commissioning::cluster_with_recovery` is behind `provisional`. §5.9's
  Network Recovery is Core §2.13.6, and this constructor is the only thing that puts its two
  provisional attributes on an endpoint.
- New `dm::spec::PROVISIONAL_CLUSTERS`, the clusters the Application Cluster specification calls
  provisional **in prose** — Content Control, Temperature Alarm and Ambient Context Sensing. The
  data model marks only the third, so without this a default build could serve either of the
  other two and every check would call it conformant.
- New `dm::spec::PROVISIONAL_NOT_EXPRESSIBLE`, which names the two things a cluster id cannot
  reach — Dishwasher Alarm's five provisional alarm bits, and two device types — so that the
  table above reads as partial rather than as complete.

### Added

- **`TlvReader::first_empty_optional`** — the general form of a rule this crate keeps and the
  specification does not: an optional structure encoded with nothing in it is legal Appendix A
  and refused by every released CHIP SDK, which is how an empty `session-parameter-struct` once
  made this crate uncommissionable while every test passed. It reports the first container with
  no members under a context-specific tag. Only *structures*: an empty array is a value, and a
  node with nothing to write has to be able to say so. §4.14.1.2's `pbkdf_parameters` remains
  the one deliberate exception, and a test asserts it is still there.

### Tooling and release

- **The test suite runs under `--all-features` in CI.** It ran under `std` and under
  `--no-default-features` only, so sixty tests behind `provisional`, `paf`, `nfc` and
  `sync-mutex` — the Groupcast cluster, Wi-Fi PAF and NFC — were compiled by the feature
  powerset but never run.
- **The footprint gate measures an image again.** CI sets `RUSTFLAGS` for every job, and that
  environment variable *replaces* `target.<triple>.rustflags` rather than merging with it — so
  the linker script in `footprint/.cargo/config.toml` was dropped, rust-lld garbage-collected the
  program for want of `_start`, and the image held nothing but debug sections. `llvm-size` then
  exits 0 when it cannot read a section, bash turned the empty results into `0`, and a 0 KiB
  build passed both budgets: the gate had been reporting success while measuring nothing.
  `footprint/run.sh` now builds with a clean `RUSTFLAGS`, forces the link, checks the image
  exists and requires every section to parse; `stats` treats a 0 KiB image as a failed
  measurement rather than a fact.
- **`cargo xtask stats`** produces every measurement these documents make — clusters, device
  types, cluster behaviours, fuzz targets, test files, dependency counts, flash, RAM, and the
  size of the citation sweep — and `--check` fails CI when a document states a number the
  repository does not.
- **`cargo xtask coverage`** inverts the `§` references in `src/` into a specification index at
  `site/content/docs/coverage.md`, also `--check`ed in CI. It is an index rather than a score:
  what it is for is showing a chapter nothing names.
- **`cast_possible_truncation`, `cast_possible_wrap` and `cast_sign_loss` are `deny`**, with
  every deliberate cast carrying `#[expect(…, reason = "…")]`. `arithmetic_side_effects` already
  caught an overflow; nothing caught an `as` that drops the high bits, which is the class the
  manual pairing code's defect was in.
- **`SECURITY.md`** at the repository root: where to report a vulnerability and how long a reply
  takes, what is in scope, the properties the crate guarantees and how each is checked, the
  support policy, and the known limitations.
- The release workflow publishes through **crates.io Trusted Publishing** — no long-lived token
  — attaches a **CycloneDX SBOM**, and takes its release notes from this file rather than from a
  list of commits.

### Fixed

- **The manual pairing code accepted digit groups the specification bounds.** §5.1.4.1.4's
  Tables 63 and 64 give every group a range — 00000..=65535 for the two 16-bit groups, 0000..=8191
  for the 13-bit one — and a five-digit group holds up to 99999. The surplus fell off a mask or an
  `as`, so an invalid code decoded *silently* to a different device's discriminator, passcode or
  vendor id. They are refused now, and `push_digits` has always refused to write one — this is the
  reading half of a rule the writing half already kept.
- A `§6.5.11.7` cited in five places in `src/` and `tests/` does not exist. §6.5.11 ends at `.6`,
  "Future Extension"; every one of the five quoted the right sentence beside the wrong number.

## [0.2.0] — 2026-09-19

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
  nothing; setting one had no effect. (0.3.0 finished the job: the constants that *were* read
  turned out not to size anything either.)
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
  commissioned as many times as its session table was long, and never again.
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

[0.3.0]: https://github.com/hupe1980/matter-kit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hupe1980/matter-kit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/matter-kit/releases/tag/v0.1.0
