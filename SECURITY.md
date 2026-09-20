# Security

`matter-kit` implements a protocol that carries a device's operational identity, terminates two
key-agreement handshakes and parses certificates that arrive from the network. It is a
dependency of products, so this page is written for the two people who need it: somebody who has
found a defect, and somebody deciding whether to ship this crate.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting —
[**Report a vulnerability**](https://github.com/hupe1980/matter-kit/security/advisories/new) — which
opens a draft advisory only the maintainers can see.

What helps most, in order: the version, the feature flags, a message or input that triggers it,
and what you think the impact is. A proof of concept is welcome and not required; a description
precise enough to reproduce is enough.

`matter-kit` is maintained by one person, and these are the targets that implies rather than a
service-level agreement:

| | |
|---|---|
| Acknowledgement | within **3 working days** |
| First assessment — is it a vulnerability, and how severe | within **10 working days** |
| Fix or a dated plan | within **90 days** of the assessment, sooner for anything remotely triggerable without a session |
| Disclosure | coordinated; the advisory is published with the fix, and credits you unless you ask otherwise |

If a report is not acknowledged within three working days, please assume it was lost and open a
public issue saying only that you are waiting on a security response — no details.

### What is in scope

Anything reachable from the network or from a peer: the TLV reader and writer, the message layer,
MRP and the exchange table, PASE and CASE, certificate and attestation parsing, the interaction
model, access control, group messaging, BTP, PAFTP, NTL, the mDNS responder, and the persistence
format (a device's flash is reachable by anybody who can open the case).

Also in scope, because they are the crate's own claims: a panic, an out-of-bounds access or an
arithmetic overflow anywhere in the library; a `Config` or table combination that passes the
compile-time checks and is non-conformant; and any place where the crate accepts a message the
specification forbids or refuses one it requires.

### What is not

* **Anything in `examples/`, `footprint/` or `interop/`.** They are demonstrations and test
  harnesses. `examples/light` generates its own development attestation chain and prints its
  passcode; it is not a product and must not be shipped as one.
* **A missing feature.** An unimplemented mechanism is a gap, not a vulnerability — the status
  page says which are which.
* **The platform underneath.** Radios, secure elements, secure boot, flash encryption and the
  entropy source are the integrator's; this crate names them as traits and guarantees only that
  a key never passes through it in the clear.

## What this crate guarantees

| Property | How | Checked by |
|---|---|---|
| No memory-unsafe code | `unsafe_code = "forbid"` crate-wide, with **no exception** anywhere | the compiler, on every build |
| No panic on network input | `unwrap`, `expect`, `panic`, slice indexing and unchecked arithmetic are `deny` in the manifest; every parser returns an error | clippy in CI, and <!-- stats:fuzz-targets -->27<!-- /stats --> fuzz targets |
| Keys are handles | signing and ECDH happen behind `KeyStore`; an operational private key can live in a secure element and never enter the crate's address space | the type — there is no accessor that yields one |
| Secrets do not outlive their use | `zeroize` on every key type; `subtle` for every comparison that could leak a MIC one byte at a time | review, and the types themselves |
| Resource exhaustion is a value, not an abort | fixed-capacity tables answer `NoSpace`/`Busy`, which become `RESOURCE_EXHAUSTED` on the wire | the fuzz targets assert the tables stay inside their capacity |
| A build that cannot be certified does not compile | every table asserts, at compile time, that it can keep the per-fabric promises the node advertises | `tests/capacity.rs`, and a `compile_fail` doctest |
| Provisional mechanisms are off unless asked for | `Cluster::validate` reports a defect for any element the specifications call provisional, unless the `provisional` feature is on | `tests/provisional.rs` |
| Dependencies are few and checked | <!-- stats:deps-no-std -->12<!-- /stats --> crates in a `no_std` build, <!-- stats:deps-rustcrypto -->48<!-- /stats --> with the software cryptographic backend; `cargo-deny` gates licences and advisories, with `yanked = "deny"` | CI |
| Builds are hermetic | generated code is committed and diff-checked; no `build.rs`, no code generation and no network in `cargo build` | CI |

## Support and maintenance

`matter-kit` is `0.x`. The compatibility rules are in the
[stability policy](https://hupe1980.github.io/matter-kit/docs/stability/); this is the part that
is about *time* rather than about API shape.

* **Security fixes land on the latest minor release only.** Older `0.y` lines are not patched.
  While the crate is pre-1.0 this is the honest position: a backport to a line nobody is asked to
  stay on would be maintenance theatre.
* **Every release is supported until the next one.** There is no separate long-term line, and
  there will not be one before 1.0.
* **A dependency with an advisory is treated as a defect in this crate** and is bumped or
  replaced, not documented.

A product's own support period is the manufacturer's to declare — the Cyber Resilience Act and
the Alliance's Product Security specification both require one — and this crate's contribution to
it is the sentence above, so that a supplier writing theirs does not have to guess.

## Verifying a release

Every version is published by a tagged GitHub Actions run that has passed the whole of CI, using
**crates.io Trusted Publishing**: the workflow proves its identity to crates.io over OIDC and
receives a token that expires with the run, so there is no long-lived publishing credential to
steal. The release also carries a **CycloneDX SBOM** of the exact dependency set the published
version resolves.

To check what you have:

```sh
cargo tree --edges normal            # the tree this crate actually pulls in
cargo deny check                     # licences and advisories, using the repo's deny.toml
```

## Cryptography

The algorithms are not this crate's to choose. Core ch. 3 fixes them — "there is no cryptosuite
negotiation in this protocol" — so the `rustcrypto` feature selects an *implementation*, not a
suite. SPAKE2+ reproduces all four of the specification's published vectors byte for byte,
including the three with non-empty identities; peer-supplied points are refused if they are off
the curve or the identity.

What is **not** established: side-channel resistance. Each part is constant-time — `p256`'s
scalar arithmetic, a fixed-length Horner reduction, `subtle` for the confirmation — but a
composition of constant-time parts is not thereby constant-time, and nothing here has been
measured on hardware. A device whose threat model includes an attacker with physical access and a
probe should treat that as open.

## Known limitations

Stated rather than discovered later:

* **Device attestation has no revocation and no trust store.** `verify_dac_chain` takes the PAA
  as a parameter and does not decide what to trust; §6.2.4's revocation sets and the Distributed
  Compliance Ledger are not implemented. A commissioner built on this crate today treats
  cryptographic validity as attestation, which is not the same thing.
* **CASE resumption is implemented and nothing stores the state**, so no session is resumed. That
  is deliberate: the published formal analysis of Matter argues resumption is strictly weaker
  than a full handshake.
* **Traffic analysis is not mitigated.** Matter's message privacy protects the header, not the
  size or timing of what rides in it, and published work recovers device types and interactions
  from encrypted Matter traffic with high accuracy. No implementation choice available here
  changes that; it is a property of the protocol.
* **The commissioner half has never been read by another implementation.** Interoperability is
  proven in one direction — the reference controller commissions a device built here — and the
  reverse is not yet tested.
